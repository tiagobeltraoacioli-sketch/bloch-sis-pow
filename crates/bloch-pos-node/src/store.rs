// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence: an append-only block log plus a `meta` marker (§3.1's
//! refusal rule), deliberately **not** RocksDB yet.
//!
//! ## Why a log and not the §3.3 column families
//!
//! The integration plan's schema stores per-block post-states keyed by
//! `block_id`. `CommittedState` today is a plain in-memory value with no
//! serialization — adding one to the pure crate is a spec-visible change
//! (its byte layout would become consensus-adjacent, KAT territory), and
//! smuggling a private encoder in here would create a second byte layout for
//! committed state, the exact twin-derivation defect this repo keeps paying
//! for. So the devnet persists the **inputs** instead: the genesis manifest
//! digest plus every applied block envelope, in chain order. Restart = replay
//! through the same `Transition` that accepted the blocks live; determinism
//! of the transition (pinned by the pure crate's tests) makes the replayed
//! state bit-identical, and the node proves it by logging the head state root
//! on boot. Cost, stated: boot is O(chain length). Fine for a devnet; the
//! RocksDB layer with block-id-keyed state remains M-later work.
//!
//! Log frame: `u32 LE length ‖ envelope bytes` (codec::encode_envelope).
//! Appends are single `write_all` calls followed by fsync, so a crash leaves
//! at most one truncated trailing frame, which replay detects and drops.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bloch_pos_committee::header::BlockEnvelope;

const META_MAGIC: &[u8; 8] = b"BPOSMETA";

thread_local! {
    /// Frame-body bytes [`Store::blocks_after`] has actually read on this
    /// thread. Observability only; nothing branches on it.
    ///
    /// A **count**, not a timing, for the reason the rest of this tree gives:
    /// on a loaded box a timing cannot honestly separate "we stopped reading
    /// the whole log" from "the box was quieter this run", and this is
    /// precisely the kind of claim that has been withdrawn here before after
    /// a 409 s-vs-1757 s gap turned out to be machine variance. Bytes read is
    /// a property of the code and of nothing else.
    static SYNC_BODY_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The calling thread's [`SYNC_BODY_BYTES_READ`]. Observability only.
pub fn sync_body_bytes_read() -> u64 {
    SYNC_BODY_BYTES_READ.with(|c| c.get())
}

thread_local! {
    /// Log frames [`Store::blocks_after`] has parsed a header out of on this
    /// thread — the *other* half of the cost the body-skip fix did not
    /// remove. Observability only; nothing branches on it.
    static SYNC_FRAMES_SCANNED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The calling thread's [`SYNC_FRAMES_SCANNED`]. Observability only.
pub fn sync_frames_scanned() -> u64 {
    SYNC_FRAMES_SCANNED.with(|c| c.get())
}

// ── The slot → offset index (`blocks.idx`) ──────────────────────────────────
//
// Skipping frame BODIES made one answer cheap in bytes; it left the answer
// O(chain length) in *frames*, because the scan still started at byte zero
// and parsed one header per block until it found the window. A peer at the
// tip asking `after_slot = u64::MAX` still made this node walk every header
// in a >145 MB log to return nothing, once per request, with no per-peer
// limit and 2048 concurrent sync substreams allowed per connection. That is
// the amplifier: cheap to ask for, unbounded to answer.
//
// The index closes it. `blocks.idx` records, for every frame in `blocks.log`,
// the slot it carries and the byte offset it starts at, so the window is
// found with a binary search over a 20-byte record instead of a linear walk
// of the log.
//
// **It is derived state and is treated as such.** Nothing consensus-visible
// reads it; the frames served are still the log's own bytes, still filtered
// by the same `slot > after_slot` predicate over the header actually read
// back from the log. Every way it can be wrong ends in the same place — the
// full scan the code did before:
//
//   * missing, empty, wrong magic, or torn  → rebuilt on `open`;
//   * behind the log (crash between the log fsync and the index append, or
//     an index from an older binary) → the unindexed tail is scanned;
//   * ahead of the log, out of order, or pointing at a frame that does not
//     carry the slot it claims → distrusted, and the answer is scanned from
//     byte zero.
//
// The log is written first and fsynced first, so the index can only ever lag
// it. There is no state in which a lost or damaged index can make this node
// serve a block it does not have, hide one it does, or change the bytes.

/// Magic of the sidecar index. Bumping it invalidates every existing index
/// file, which costs exactly one boot rebuild.
const IDX_MAGIC: &[u8; 8] = b"BPOSIDX1";

/// One index record: `slot u64 LE ‖ offset u64 LE ‖ frame_len u32 LE`.
const IDX_ENTRY_LEN: u64 = 8 + 8 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdxEntry {
    slot: u64,
    /// Byte offset of the frame's 4-byte length prefix in `blocks.log`.
    offset: u64,
    /// Payload length. The whole frame is `4 + len` bytes.
    len: u32,
}

impl IdxEntry {
    fn encode(&self) -> [u8; IDX_ENTRY_LEN as usize] {
        let mut b = [0u8; IDX_ENTRY_LEN as usize];
        b[..8].copy_from_slice(&self.slot.to_le_bytes());
        b[8..16].copy_from_slice(&self.offset.to_le_bytes());
        b[16..20].copy_from_slice(&self.len.to_le_bytes());
        b
    }

    fn decode(b: &[u8; IDX_ENTRY_LEN as usize]) -> IdxEntry {
        IdxEntry {
            slot: u64::from_le_bytes(b[..8].try_into().unwrap()),
            offset: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            len: u32::from_le_bytes(b[16..20].try_into().unwrap()),
        }
    }

    /// First byte after this frame.
    fn end(&self) -> u64 {
        self.offset + 4 + self.len as u64
    }
}

/// Records in an open index file (the magic is not one).
fn idx_count(idx: &File) -> io::Result<u64> {
    let len = idx.metadata()?.len();
    Ok(if len < 8 { 0 } else { (len - 8) / IDX_ENTRY_LEN })
}

fn idx_read(idx: &mut File, i: u64) -> io::Result<IdxEntry> {
    idx.seek(SeekFrom::Start(8 + i * IDX_ENTRY_LEN))?;
    let mut b = [0u8; IDX_ENTRY_LEN as usize];
    idx.read_exact(&mut b)?;
    Ok(IdxEntry::decode(&b))
}

/// Index records for every **complete** frame in `blocks.log` at or after
/// `from`. Header-only reads: a rebuild of a 145 MB log touches one header
/// per block and no body.
///
/// A torn trailing frame (crash mid-append) ends the scan without an error,
/// exactly as `read_all` and `blocks_after` treat it — it is not indexed, so
/// it cannot be served, which is the same answer the log itself gives.
fn scan_index(log_path: &Path, from: u64) -> io::Result<Vec<IdxEntry>> {
    let log_len = fs::metadata(log_path)?.len();
    let mut f = io::BufReader::new(File::open(log_path)?);
    if from > 0 {
        f.seek(SeekFrom::Start(from))?;
    }
    let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
    let mut at = from;
    let mut out = Vec::new();
    let mut len4 = [0u8; 4];
    loop {
        match f.read_exact(&mut len4) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len4) as usize;
        // Garbage or a frame the log itself would refuse: stop indexing here
        // rather than fail. `blocks_after` scanning past this point is still
        // the authority on what the log holds.
        if len > crate::codec::MAX_FIELD_LEN || len < hdr_len {
            break;
        }
        if at + 4 + len as u64 > log_len {
            break; // truncated trailing frame
        }
        let mut hdr = vec![0u8; hdr_len];
        match f.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let Ok(header) = bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(&hdr)
        else {
            break;
        };
        out.push(IdxEntry { slot: header.slot, offset: at, len: len as u32 });
        if f.seek_relative((len - hdr_len) as i64).is_err() {
            break;
        }
        at += 4 + len as u64;
    }
    Ok(out)
}

/// Bring `idx` in line with a log of `log_len` bytes: rebuild it if it is
/// unusable, extend it if it is behind. Called on `open` (so a node that
/// upgrades into this code indexes its existing log once, during the boot
/// replay it already pays for) and after `rewrite`.
fn repair_index(idx: &mut File, log_path: &Path, log_len: u64) -> io::Result<()> {
    let idx_len = idx.metadata()?.len();
    let mut usable = idx_len >= 8;
    if usable {
        let mut magic = [0u8; 8];
        idx.seek(SeekFrom::Start(0))?;
        usable = idx.read_exact(&mut magic).is_ok() && &magic == IDX_MAGIC;
    }
    let mut covered = 0u64;
    if usable {
        let n = (idx_len - 8) / IDX_ENTRY_LEN;
        // A torn trailing record: the process died between the log append and
        // the index append. Cut it off; the tail scan below re-derives it.
        let exact = 8 + n * IDX_ENTRY_LEN;
        if exact != idx_len {
            idx.set_len(exact)?;
        }
        if n > 0 {
            let last = idx_read(idx, n - 1)?;
            covered = last.end();
            // An index that describes MORE log than exists cannot be trusted
            // to describe the part that does (the log was truncated, or this
            // is a different log entirely).
            if covered > log_len {
                usable = false;
            }
        }
    }
    if !usable {
        idx.set_len(0)?;
        idx.seek(SeekFrom::Start(0))?;
        idx.write_all(IDX_MAGIC)?;
        covered = 0;
    }
    if covered < log_len {
        let tail = scan_index(log_path, covered)?;
        let mut buf = Vec::with_capacity(tail.len() * IDX_ENTRY_LEN as usize);
        for e in &tail {
            buf.extend_from_slice(&e.encode());
        }
        idx.seek(SeekFrom::End(0))?;
        idx.write_all(&buf)?;
    }
    idx.sync_data()
}

/// Where an answer should start reading.
enum Start {
    /// The index covers the whole log and nothing in it is past the window:
    /// the answer is empty and the log is never opened. This is the
    /// `after_slot = u64::MAX` case — the one that used to force a full read
    /// to return zero bytes.
    Nothing,
    /// Seek here. `expect_slot` is what the index says the frame at that
    /// offset carries; a mismatch means the index lies and the caller falls
    /// back to the full scan.
    At { offset: u64, expect_slot: Option<u64> },
}

/// Consult the index. `Ok(None)` means "no usable index" — scan from zero.
fn index_start(dir: &Path, after_slot: u64, log_len: u64) -> io::Result<Option<Start>> {
    let mut idx = File::open(dir.join("blocks.idx"))?;
    if idx.metadata()?.len() < 8 {
        return Ok(None);
    }
    let mut magic = [0u8; 8];
    idx.read_exact(&mut magic)?;
    if &magic != IDX_MAGIC {
        return Ok(None);
    }
    let n = idx_count(&idx)?;
    if n == 0 {
        // Freshly created index over a log that may already have frames.
        return Ok(Some(Start::At { offset: 0, expect_slot: None }));
    }
    let last = idx_read(&mut idx, n - 1)?;
    let covered = last.end();
    if covered > log_len {
        return Ok(None);
    }
    // First record past the window. Chain order means slots increase, so this
    // is a binary search: ~17 twenty-byte reads over a 100k-block log, against
    // 100k header parses.
    let (mut lo, mut hi) = (0u64, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if idx_read(&mut idx, mid)?.slot > after_slot {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    if lo == n {
        // Nothing indexed is past the window. Whatever the index has not
        // caught up with yet still might be, so serve from there.
        return Ok(Some(if covered < log_len {
            Start::At { offset: covered, expect_slot: None }
        } else {
            Start::Nothing
        }));
    }
    // Sortedness check on the neighbour. If the record BEFORE the hit is also
    // past the window then the index is not ordered, and a binary search over
    // it would silently skip blocks this node holds — the one failure mode of
    // an index that a scan-forward cannot repair. Distrust it.
    if lo > 0 && idx_read(&mut idx, lo - 1)?.slot > after_slot {
        return Ok(None);
    }
    let hit = idx_read(&mut idx, lo)?;
    if hit.offset >= log_len {
        return Ok(None);
    }
    Ok(Some(Start::At { offset: hit.offset, expect_slot: Some(hit.slot) }))
}

pub struct Store {
    dir: PathBuf,
    log: File,
    /// Append handle for the derived slot → offset index. Written after the
    /// log's own fsync, so it can lag the log and never lead it.
    idx: File,
    /// Bytes in `blocks.log`, so an append knows the offset it is writing at
    /// without asking the filesystem.
    log_len: u64,
}

impl Store {
    /// Open (or initialize) a data dir for the network identified by
    /// `genesis_digest`. A dir initialized for any other genesis — or holding
    /// anything that is not a bloch-pos meta — is a **refusal, not a
    /// migration** (integration plan §3.1).
    pub fn open(dir: &Path, genesis_digest: &[u8; 32]) -> io::Result<Store> {
        fs::create_dir_all(dir)?;
        let meta_path = dir.join("meta.bin");
        match fs::read(&meta_path) {
            Ok(bytes) => {
                let ok = bytes.len() == 8 + 4 + 32
                    && &bytes[..8] == META_MAGIC
                    && bytes[8..12]
                        == bloch_pos_committee::header::VERSION_G4.to_le_bytes()
                    && &bytes[12..44] == genesis_digest;
                if !ok {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "data dir {} belongs to a different network or schema; refusing \
                             (delete it yourself if that is really what you want)",
                            dir.display()
                        ),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut out = Vec::with_capacity(44);
                out.extend_from_slice(META_MAGIC);
                out.extend_from_slice(&bloch_pos_committee::header::VERSION_G4.to_le_bytes());
                out.extend_from_slice(genesis_digest);
                fs::write(&meta_path, out)?;
            }
            Err(e) => return Err(e),
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(dir.join("blocks.log"))?;
        let log_len = log.metadata()?.len();
        // The index is rebuilt (or caught up) here, on the same boot that
        // already replays the whole log. A data dir written by a binary that
        // predates the index is therefore indexed the first time this one
        // opens it, with no migration step and no flag.
        let mut idx = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(dir.join("blocks.idx"))?;
        repair_index(&mut idx, &dir.join("blocks.log"), log_len)?;
        Ok(Store { dir: dir.to_path_buf(), log, idx, log_len })
    }

    /// Append one applied block. One write, then fsync — the block is only
    /// broadcast after this returns, so anything the network has seen from
    /// us is durable locally (the producer-side equivocation fence across
    /// restarts).
    pub fn append(&mut self, env: &BlockEnvelope) -> io::Result<()> {
        let payload = crate::codec::encode_envelope(env);
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        self.log.write_all(&frame)?;
        self.log.sync_data()?;
        // Index AFTER the log is durable. A crash in between leaves the index
        // one record short, which the next `open` fixes and which
        // `blocks_after` already tolerates by scanning the unindexed tail —
        // so this write is deliberately not fsynced. An index entry that
        // cannot be written is not worth failing an applied block over: log
        // it, and let the next open rebuild.
        let entry =
            IdxEntry { slot: env.header.slot, offset: self.log_len, len: payload.len() as u32 };
        self.log_len += frame.len() as u64;
        // Seek to the end explicitly rather than trusting the handle's cursor:
        // `repair_index` reads records through this same handle, and a record
        // written at a stale cursor would not append to the index, it would
        // OVERWRITE part of it.
        if let Err(e) =
            self.idx.seek(SeekFrom::End(0)).and_then(|_| self.idx.write_all(&entry.encode()))
        {
            eprintln!("store: block-index append failed ({e}); it will be rebuilt on next open");
        }
        Ok(())
    }

    /// Read every complete frame in the log, in order. A truncated trailing
    /// frame (crash mid-append) is dropped with a warning; a *corrupt* frame
    /// body is an error, because silently skipping mid-chain data would make
    /// replay diverge from what the network saw.
    pub fn read_all(&self) -> io::Result<Vec<BlockEnvelope>> {
        let mut f = File::open(self.dir.join("blocks.log"))?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 4 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            if len > crate::codec::MAX_FIELD_LEN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
            }
            if at + 4 + len > bytes.len() {
                eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
                break;
            }
            let env = crate::codec::decode_envelope(&bytes[at + 4..at + 4 + len])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            out.push(env);
            at += 4 + len;
        }
        if at + 4 > bytes.len() && at < bytes.len() {
            eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
        }
        Ok(out)
    }

    /// Replace the whole log with `envs` (a reorg adopted a different
    /// branch). Write-to-temp + rename, then reopen the append handle, so a
    /// crash mid-rewrite leaves either the old log or the new one — never a
    /// half-written file.
    pub fn rewrite(&mut self, envs: &[BlockEnvelope]) -> io::Result<()> {
        let tmp = self.dir.join("blocks.log.tmp");
        {
            let mut f = File::create(&tmp)?;
            for env in envs {
                let payload = crate::codec::encode_envelope(env);
                f.write_all(&(payload.len() as u32).to_le_bytes())?;
                f.write_all(&payload)?;
            }
            f.sync_data()?;
        }
        fs::rename(&tmp, self.dir.join("blocks.log"))?;
        self.log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(self.dir.join("blocks.log"))?;
        self.log_len = self.log.metadata()?.len();
        // A reorg replaces the log, so every offset in the index is now a lie
        // about a different branch. Throw it away and re-derive it from the
        // log that won.
        self.idx.set_len(0)?;
        repair_index(&mut self.idx, &self.dir.join("blocks.log"), self.log_len)?;
        Ok(())
    }

    /// Encoded blocks with slot strictly greater than `after_slot`, in chain
    /// order, at most `limit` of them — the answer to a `get-blocks`.
    ///
    /// Three properties, in the order they were paid for:
    ///
    /// 1. **A streaming scan, not `read_all().filter()`.** The naive version
    ///    decoded and re-encoded the entire chain on every request, which
    ///    turns serving a cold peer into O(chain²) work.
    /// 2. **Header-only reads while skipping.** The slot is all the filter
    ///    needs, so a frame that will be discarded is never read or allocated
    ///    past its header (pinned by
    ///    `serving_a_page_does_not_read_the_bodies_it_skips`).
    /// 3. **The window is found through the index, not by walking to it.**
    ///    (2) made each skipped frame cheap; it left the count of skipped
    ///    frames equal to the whole chain, on the server, per request, with
    ///    no per-peer limit above it. `GetBlocks { after_slot: u64::MAX }` —
    ///    eight bytes to ask for — walked every header in the log to return
    ///    nothing. Now the first frame past the window is located with a
    ///    binary search over `blocks.idx` and the log is opened at that
    ///    offset; when the index says nothing qualifies, the log is not
    ///    opened at all (pinned by `serving_past_the_tip_touches_no_frames`).
    ///
    /// What comes back is unchanged by all three: the log's own bytes, in log
    /// order, filtered by the same `slot > after_slot` predicate over headers
    /// read back from the log itself. The index is a hint about *where to
    /// start*; every way it can be wrong falls back to the full scan.
    ///
    /// Reads the log file fresh so a reader thread never touches the append
    /// handle.
    pub fn blocks_after(dir: &Path, after_slot: u64, limit: usize) -> io::Result<Vec<Vec<u8>>> {
        let log_path = dir.join("blocks.log");
        let log_len = fs::metadata(&log_path)?.len();
        // A missing or unreadable index is not an error: it is the state
        // every pre-index data dir is in, and the answer is the scan this
        // function has always done.
        match index_start(dir, after_slot, log_len).unwrap_or(None) {
            Some(Start::Nothing) => return Ok(Vec::new()),
            Some(Start::At { offset, expect_slot }) => {
                if let Some(page) =
                    Self::scan_page(&log_path, offset, expect_slot, after_slot, limit)?
                {
                    return Ok(page);
                }
                eprintln!(
                    "store: block index disagrees with the log at offset {offset}; \
                     serving from a full scan (it will be rebuilt on next open)"
                );
            }
            None => {}
        }
        Ok(Self::scan_page(&log_path, 0, None, after_slot, limit)?.unwrap_or_default())
    }

    /// The scan itself, from `from` to the cap. Returns `Ok(None)` — and only
    /// then — when `expect_slot` is set and the frame at `from` does not carry
    /// it, which is the caller's signal that the index is not describing this
    /// log and the answer must be re-derived from byte zero.
    fn scan_page(
        log_path: &Path,
        from: u64,
        expect_slot: Option<u64>,
        after_slot: u64,
        limit: usize,
    ) -> io::Result<Option<Vec<Vec<u8>>>> {
        let mut f = io::BufReader::new(File::open(log_path)?);
        if from > 0 {
            f.seek(SeekFrom::Start(from))?;
        }
        let mut expect = expect_slot;
        let mut out = Vec::new();
        let mut len4 = [0u8; 4];
        loop {
            if out.len() >= limit {
                break;
            }
            match f.read_exact(&mut len4) {
                Ok(()) => {}
                // A clean EOF is the end of the log; a partial one is the
                // truncated trailing frame `read_all` also tolerates.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let len = u32::from_le_bytes(len4) as usize;
            if len > crate::codec::MAX_FIELD_LEN {
                if expect.is_some() {
                    return Ok(None); // the index sent us into the middle of a frame
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
            }
            // Read the HEADER only, then decide. The slot is all the filter
            // needs, and it lives in the first `ENCODED_LEN` bytes of the
            // frame, so a frame that will be discarded never has to be read
            // or allocated past its header.
            //
            // Skipping with `seek` keeps the frames returned, their order and
            // their bytes exactly as they were: `out` is pushed from the same
            // predicate over the same headers. Only the reads that produced
            // nothing are gone. Not a consensus change -- this function
            // serves bytes off the log and computes no state.
            let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
            if len < hdr_len {
                if expect.is_some() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "log frame shorter than a header",
                ));
            }
            let mut hdr_buf = vec![0u8; hdr_len];
            match f.read_exact(&mut hdr_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let header =
                match bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(&hdr_buf) {
                    Ok(h) => h,
                    Err(_) if expect.is_some() => return Ok(None),
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "undecodable header in block log",
                        ))
                    }
                };
            SYNC_FRAMES_SCANNED.with(|c| c.set(c.get() + 1));
            // The index's claim, checked against the log, once. Everything
            // after this frame is the log's own chain order.
            if let Some(want) = expect.take() {
                if header.slot != want {
                    return Ok(None);
                }
            }
            let rest = len - hdr_len;
            if header.slot > after_slot {
                // Wanted: read the body and hand back the whole frame, byte
                // for byte identical to what the old path pushed.
                let mut payload = hdr_buf;
                payload.resize(len, 0);
                match f.read_exact(&mut payload[hdr_len..]) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
                SYNC_BODY_BYTES_READ.with(|c| c.set(c.get() + rest as u64));
                out.push(payload);
            } else {
                // Not wanted: skip the body without reading or allocating it.
                // `BufReader::seek_relative` discards buffered bytes it can
                // and seeks the rest, so this stays correct on a file the
                // writer is appending to.
                if let Err(e) = f.seek_relative(rest as i64) {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The from-genesis path, at the store level: `after_slot = 0` must return
    /// the chain from its beginning, and the cap must be a cap.
    #[test]
    fn blocks_after_serves_from_genesis_and_respects_the_cap() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");

        // Five blocks at slots 1..=5. Bodies are empty; only framing and the
        // header slot are under test here.
        let mut ids = Vec::new();
        for slot in 1..=5u64 {
            let env = sample_envelope(slot);
            ids.push(crate::codec::encode_envelope(&env));
            store.append(&env).expect("append");
        }

        let from_genesis = Store::blocks_after(&dir, 0, 100).expect("scan");
        assert_eq!(from_genesis.len(), 5, "a cold peer asking from slot 0 gets the whole chain");
        assert_eq!(from_genesis, ids, "served bytes are the logged bytes, verbatim");

        let capped = Store::blocks_after(&dir, 0, 2).expect("scan");
        assert_eq!(capped.len(), 2, "the cap bounds one answer");
        assert_eq!(capped, ids[..2], "and it is the FIRST two, so paging makes progress");

        let tail = Store::blocks_after(&dir, 3, 100).expect("scan");
        assert_eq!(tail.len(), 2, "slot > after_slot, strictly");

        let past_tip = Store::blocks_after(&dir, 99, 100).expect("scan");
        assert!(past_tip.is_empty(), "a peer at the tip is told there is nothing more");

        let _ = fs::remove_dir_all(&dir);
    }

    /// **Serving a page must not read the whole log.** This is the cold-sync
    /// bottleneck, pinned as an assertion rather than a timing.
    ///
    /// `blocks_after`'s own doc comment has always promised that a frame
    /// costs "a 4-byte length read plus a fixed-size header parse until the
    /// window is found". It did not: the body of every frame was read into a
    /// fresh allocation before the slot was consulted, so answering a peer
    /// deep in the chain read the entire log from byte zero. The comment was
    /// the specification and the code did not implement it; prose cannot go
    /// red, so this test is what makes the promise enforceable.
    ///
    /// The claim, in the shape that cannot pass vacuously: with fat bodies
    /// ahead of the window and one thin block inside it, the body bytes read
    /// while answering must be the bytes of the blocks actually RETURNED —
    /// not the bytes of the blocks skipped. The returned frames are compared
    /// against the log verbatim in the same test, so "reads less" can never
    /// be bought by serving less.
    #[test]
    fn serving_a_page_does_not_read_the_bodies_it_skips() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-skip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[9u8; 32]).expect("open");

        // Slots 1..=20 carry a fat body; slot 21 is thin. A request for
        // `after_slot = 20` returns only the thin one, so every fat body is
        // on the skip path.
        let mut fat_bytes = 0u64;
        let hdr = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN as u64;
        for slot in 1..=20u64 {
            let mut env = sample_envelope(slot);
            env.proposer_sig = vec![0xCD; 8192];
            let enc = crate::codec::encode_envelope(&env);
            fat_bytes += enc.len() as u64 - hdr;
            store.append(&env).expect("append");
        }
        let thin = sample_envelope(21);
        let thin_enc = crate::codec::encode_envelope(&thin);
        store.append(&thin).expect("append");

        let before = sync_body_bytes_read();
        let page = Store::blocks_after(&dir, 20, 100).expect("scan");
        let read = sync_body_bytes_read() - before;

        // It served the right thing, verbatim. Without this the byte
        // assertion below could be satisfied by returning nothing.
        assert_eq!(page.len(), 1, "only slot 21 is past the window");
        assert_eq!(page[0], thin_enc, "served bytes are the logged bytes, verbatim");

        let thin_body = thin_enc.len() as u64 - hdr;
        assert_eq!(
            read, thin_body,
            "answering read {read} body bytes but only {thin_body} were returned — the \
             skipped frames' bodies are being read again, which is the O(chain-length) \
             per-request scan that starves a cold sync ({fat_bytes} bytes of fat bodies \
             sit ahead of this window)"
        );
        assert!(
            read < fat_bytes,
            "the skip path read at least as much as the bodies it skipped"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// **THE regression test for H5.** Answering a peer that is already at the
    /// tip must not walk the log.
    ///
    /// `GetBlocks { after_slot: u64::MAX }` is eight bytes on the wire and
    /// returns zero blocks. Before the index it made this node open the log
    /// and parse one header per block — every block, every request, for an
    /// answer of nothing — with no per-peer limit above it and 2,048 sync
    /// substreams allowed per connection. The cost of asking and the cost of
    /// answering were orders of magnitude apart, which is what an amplifier
    /// is.
    ///
    /// The claim is counted, not timed: frames whose header `blocks_after`
    /// parsed. Timings on a shared box cannot separate "we stopped scanning"
    /// from "the box was quieter", and this tree has withdrawn a claim over
    /// exactly that before. A frame count is a property of the code.
    ///
    /// It cannot pass vacuously: the same test asserts that a page NEAR the
    /// tip comes back byte-for-byte correct while scanning only the frames it
    /// serves, so "scans less" can never be bought by serving less.
    #[test]
    fn serving_past_the_tip_touches_no_frames() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-tip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[11u8; 32]).expect("open");
        let mut logged = Vec::new();
        for slot in 1..=64u64 {
            let env = sample_envelope(slot);
            logged.push(crate::codec::encode_envelope(&env));
            store.append(&env).expect("append");
        }

        let before = sync_frames_scanned();
        let nothing = Store::blocks_after(&dir, u64::MAX, 128).expect("scan");
        let scanned = sync_frames_scanned() - before;
        assert!(nothing.is_empty(), "there is nothing past u64::MAX");
        assert_eq!(
            scanned, 0,
            "answering a peer at the tip parsed {scanned} block headers to return zero \
             blocks — that is the O(chain-length) scan per request, and it is free to ask for"
        );

        // The other half: a real page must still be exactly right, and must
        // scan only what it serves.
        let before = sync_frames_scanned();
        let page = Store::blocks_after(&dir, 60, 128).expect("scan");
        let scanned = sync_frames_scanned() - before;
        assert_eq!(page, logged[60..], "served bytes are the logged bytes, verbatim");
        assert_eq!(
            scanned, 4,
            "serving 4 blocks parsed {scanned} headers: the window is being walked to, not \
             looked up"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The index may lag the log by design — `append` fsyncs the log and then
    /// writes the index record, so a crash in between leaves the last blocks
    /// unindexed. Those blocks must still be served, or a node would go
    /// permanently silent about its own tip.
    #[test]
    fn an_index_behind_the_log_still_serves_the_unindexed_tail() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-lag-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[12u8; 32]).expect("open");
        let mut logged = Vec::new();
        for slot in 1..=10u64 {
            let env = sample_envelope(slot);
            logged.push(crate::codec::encode_envelope(&env));
            store.append(&env).expect("append");
        }
        drop(store);

        // Simulate the crash window: the last three records never reached the
        // index. No reopen, because `open` would repair it — this is the
        // state a live process is in between the two writes.
        let idx_path = dir.join("blocks.idx");
        let idx = OpenOptions::new().write(true).open(&idx_path).expect("open idx");
        let short = idx.metadata().unwrap().len() - 3 * IDX_ENTRY_LEN;
        idx.set_len(short).expect("truncate idx");
        drop(idx);

        let from_middle = Store::blocks_after(&dir, 3, 100).expect("scan");
        assert_eq!(
            from_middle,
            logged[3..],
            "the blocks past the index's reach were dropped from the answer"
        );
        let tail_only = Store::blocks_after(&dir, 9, 100).expect("scan");
        assert_eq!(tail_only, logged[9..], "the unindexed tip must still be served");

        let _ = fs::remove_dir_all(&dir);
    }

    /// An index that points somewhere the log does not agree with is a hint
    /// that is wrong, not a source of truth. The answer must be re-derived
    /// from the log, unchanged.
    #[test]
    fn a_lying_index_falls_back_to_the_full_scan() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-lie-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[13u8; 32]).expect("open");
        let mut logged = Vec::new();
        for slot in 1..=8u64 {
            let env = sample_envelope(slot);
            logged.push(crate::codec::encode_envelope(&env));
            store.append(&env).expect("append");
        }
        drop(store);

        // Record 5 (slot 6) now claims to start three bytes into the log —
        // the middle of the first frame.
        let idx_path = dir.join("blocks.idx");
        let mut raw = fs::read(&idx_path).expect("read idx");
        let at = 8 + 5 * IDX_ENTRY_LEN as usize;
        raw[at + 8..at + 16].copy_from_slice(&3u64.to_le_bytes());
        fs::write(&idx_path, &raw).expect("write idx");

        let page = Store::blocks_after(&dir, 5, 100).expect("scan");
        assert_eq!(page, logged[5..], "a wrong index changed the answer instead of being ignored");

        let _ = fs::remove_dir_all(&dir);
    }

    /// A reorg replaces the log, so every offset in the index describes a
    /// branch that is gone. `rewrite` must re-derive it — and the proof is
    /// that the new log is still served through the index (zero frames
    /// scanned past the new tip), not merely served correctly, which a
    /// distrusted index would also manage.
    #[test]
    fn a_reorg_rebuilds_the_index() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-reorg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[14u8; 32]).expect("open");
        for slot in 1..=9u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }

        // The branch that wins: shorter, and different bytes at every slot.
        let winner: Vec<BlockEnvelope> = (1..=4u64)
            .map(|slot| {
                let mut env = sample_envelope(slot);
                env.proposer_sig = vec![0xBB; 32];
                env
            })
            .collect();
        store.rewrite(&winner).expect("rewrite");
        let expect: Vec<Vec<u8>> =
            winner.iter().map(crate::codec::encode_envelope).collect();

        let all = Store::blocks_after(&dir, 0, 100).expect("scan");
        assert_eq!(all, expect, "the reorged log is what is served");

        let before = sync_frames_scanned();
        let nothing = Store::blocks_after(&dir, 4, 100).expect("scan");
        let scanned = sync_frames_scanned() - before;
        assert!(nothing.is_empty(), "nothing is past the new tip");
        assert_eq!(
            scanned, 0,
            "after a reorg the index was not re-derived: {scanned} headers were parsed to \
             answer a peer at the tip"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// A data dir written by a binary that predates the index has none. It is
    /// built on the next `open` — the same boot that already replays the
    /// whole log — with no migration step and no flag.
    #[test]
    fn open_indexes_a_data_dir_that_has_none() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-boot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[15u8; 32]).expect("open");
        let mut logged = Vec::new();
        for slot in 1..=12u64 {
            let env = sample_envelope(slot);
            logged.push(crate::codec::encode_envelope(&env));
            store.append(&env).expect("append");
        }
        drop(store);
        fs::remove_file(dir.join("blocks.idx")).expect("remove idx");

        let store = Store::open(&dir, &[15u8; 32]).expect("reopen");
        assert_eq!(store.read_all().expect("replay").len(), 12, "the log itself is untouched");

        let before = sync_frames_scanned();
        let nothing = Store::blocks_after(&dir, u64::MAX, 100).expect("scan");
        let scanned = sync_frames_scanned() - before;
        assert!(nothing.is_empty());
        assert_eq!(scanned, 0, "boot did not (re)build the block index");

        let page = Store::blocks_after(&dir, 8, 100).expect("scan");
        assert_eq!(page, logged[8..], "and the rebuilt index describes the right offsets");

        let _ = fs::remove_dir_all(&dir);
    }

    fn sample_envelope(slot: u64) -> BlockEnvelope {
        use bloch_pos_committee::header::{BlockHeaderV4, Body, VERSION_G4};
        BlockEnvelope {
            header: BlockHeaderV4 {
                version: VERSION_G4,
                parent: [1; 32],
                state_root: [2; 32],
                body_root: [3; 32],
                slot,
                proposer_index: 0,
                randao_reveal: [4; 32],
                randao_mix: [5; 32],
                justified_root: [6; 32],
                finalized_root: [7; 32],
                attestation_root: [8; 32],
                coherence_root: [9; 32],
            },
            proposer_sig: vec![0xAA; 32],
            body: Body { transactions: Vec::new(), attestations: Vec::new() },
        }
    }
}
