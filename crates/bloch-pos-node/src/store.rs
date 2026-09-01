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
use std::sync::{Arc, RwLock};

use bloch_pos_committee::header::BlockEnvelope;

const META_MAGIC: &[u8; 8] = b"BPOSMETA";

/// Where one logged block sits in `blocks.log`, and what slot it is for.
///
/// `offset` points at the frame's PAYLOAD, not at its 4-byte length prefix,
/// because the payload is what a `get-blocks` answer carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRef {
    pub slot: u64,
    pub offset: u64,
    pub len: u32,
}

/// The log's frame table, shared with the transport's reader threads.
///
/// # Why this exists
///
/// [`Store::blocks_after`] answers a peer's `get-blocks` by walking the log
/// **from byte 0**, parsing one header per frame until it has found the page.
/// The comment on it argues that this is already the cheap version, and
/// against `read_all().filter()` it is — but it is still O(chain) per request,
/// and the requester's cost is not the interesting one. The cost lands on a
/// peer, and the loop that asks is a timer: a node holding a sync slot re-asks
/// every five seconds for as long as it holds one, **including after it has
/// caught up**, when the honest answer is "nothing". So the steady state of a
/// healthy fleet is every node making two peers read their entire block log,
/// twelve times a minute, to return an empty page.
///
/// Measured end to end over the wire, on the live chain's own history
/// (2026-09-01, 33,063 blocks / 461 MB log, idle 2-core Edgevana box, log warm
/// in page cache — so these are the *best* case for the walk). Time to the
/// first block of a 512-block page:
///
/// ```text
///   after_slot        walk      index
///            0      2.1 ms     2.2 ms
///        13000     21.2 ms     2.5 ms
///        26000     28.6 ms     4.3 ms
///        40000     45.0 ms     2.7 ms
///        53400     77.1 ms     2.1 ms
/// ```
///
/// The walk is linear in the chain and the index is flat, which is the whole
/// point: the useful part of the answer is 512 blocks no matter how long the
/// chain is. The worst case is the one that is asked most often and does not
/// appear in the table at all — `after_slot = tip`, the empty page a
/// caught-up peer asks for twice every five seconds, for ever. That walks the
/// entire log to conclude there is nothing to send, **and then sends nothing**,
/// so it is invisible from both ends: the requester sees no reply either way.
/// Served from the table it opens no file at all.
///
/// It is not a cache and it cannot go stale in a way that changes an answer:
/// it is built from the log at `open`, appended to by `append`, rebuilt by
/// `rewrite`, and every byte it names is re-read from the file at serve time.
pub type FrameIndex = Arc<RwLock<Vec<FrameRef>>>;

pub struct Store {
    dir: PathBuf,
    log: File,
    frames: FrameIndex,
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
        let frames = Arc::new(RwLock::new(scan_frames(dir)?));
        Ok(Store { dir: dir.to_path_buf(), log, frames })
    }

    /// The frame table, for the transport's `get-blocks` handler.
    pub fn index(&self) -> FrameIndex {
        Arc::clone(&self.frames)
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
        // Where this frame's payload will land. Taken from the file itself,
        // not from a running total, so the index cannot drift away from the
        // bytes on disk if anything ever appends by another path.
        let at = self.log.seek(SeekFrom::End(0))?;
        self.log.write_all(&frame)?;
        self.log.sync_data()?;
        if let Ok(mut idx) = self.frames.write() {
            idx.push(FrameRef {
                slot: env.header.slot,
                offset: at + 4,
                len: payload.len() as u32,
            });
        }
        Ok(())
    }

    /// Read every complete frame in the log, in order.
    ///
    /// **Holds the entire chain in memory twice over and is not on the boot
    /// path any more** — see [`LogReader`], which is. This is kept for tests
    /// and for callers that genuinely want the whole vector; it is now a
    /// `collect` of the streaming reader, so there is one frame-walk
    /// definition and the tolerance rules cannot drift between them.
    pub fn read_all(&self) -> io::Result<Vec<BlockEnvelope>> {
        LogReader::open(&self.dir)?.collect()
    }

    /// Number of complete frames in the log, without decoding or allocating
    /// any of them — the frame walk with `seek` where [`LogReader`] would
    /// `read_exact` a payload.
    ///
    /// It exists so boot can print a progress denominator while replaying
    /// from a *stream* instead of from a materialized `Vec`. Silent by
    /// design: it applies exactly the tolerance rules `LogReader` applies, and
    /// the reader that follows is the one that reports a truncated tail, so
    /// the operator still sees that warning exactly once.
    pub fn count(dir: &Path) -> io::Result<usize> {
        let f = File::open(dir.join("blocks.log"))?;
        let end = f.metadata()?.len();
        let mut f = io::BufReader::with_capacity(1 << 16, f);
        let mut n = 0usize;
        let mut at = 0u64;
        loop {
            let mut len4 = [0u8; 4];
            if read_up_to(&mut f, &mut len4)? != 4 {
                return Ok(n);
            }
            at += 4;
            let len = u32::from_le_bytes(len4) as u64;
            if len > crate::codec::MAX_FIELD_LEN as u64 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
            }
            if at + len > end {
                return Ok(n); // truncated trailing frame
            }
            // Seek past the body rather than read it: a 4.6 KB hybrid
            // signature does not need to enter the process to be counted.
            at += len;
            f.seek(io::SeekFrom::Start(at))?;
            n += 1;
        }
    }

    /// Replace the whole log with `envs` (a reorg adopted a different
    /// branch). Write-to-temp + rename, then reopen the append handle, so a
    /// crash mid-rewrite leaves either the old log or the new one — never a
    /// half-written file.
    /// Takes an **iterator of references**, not a slice, and that is a memory
    /// decision rather than a stylistic one: the only caller is `do_reorg`,
    /// which used to `clone()` the whole canonical chain into a `Vec` to call
    /// this — momentarily doubling the largest allocation the node holds, at
    /// the one moment (a reorg) when it is already busy. The bytes written are
    /// the same bytes in the same order; nothing but the copy is gone.
    pub fn rewrite<'a, I>(&mut self, envs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = &'a BlockEnvelope>,
    {
        let tmp = self.dir.join("blocks.log.tmp");
        {
            let mut f = io::BufWriter::new(File::create(&tmp)?);
            for env in envs {
                let payload = crate::codec::encode_envelope(env);
                f.write_all(&(payload.len() as u32).to_le_bytes())?;
                f.write_all(&payload)?;
            }
            f.flush()?;
            f.into_inner()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
                .sync_data()?;
        }
        fs::rename(&tmp, self.dir.join("blocks.log"))?;
        self.log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(self.dir.join("blocks.log"))?;
        // Rebuilt, not patched: a reorg replaces the whole file, so every
        // offset the old table held is meaningless.
        let rebuilt = scan_frames(&self.dir)?;
        if let Ok(mut idx) = self.frames.write() {
            *idx = rebuilt;
        }
        Ok(())
    }

    /// Encoded blocks with slot strictly greater than `after_slot`, in chain
    /// order, at most `limit` of them — the answer to a `get-blocks`.
    ///
    /// Written as a **streaming scan**, not `read_all().filter()`, because the
    /// caller that matters is a node syncing from genesis. Such a node asks
    /// for slot 0, gets one capped page, asks for the next, and repeats until
    /// it reaches the tip; the naive version decoded and re-encoded the entire
    /// chain on every one of those requests, which turns serving a cold peer
    /// into O(chain²) work and makes the from-genesis path technically
    /// available but practically unusable. Here each frame costs a 4-byte
    /// length read plus a fixed-size header parse until the window is found,
    /// the bytes are copied verbatim (no decode/re-encode round trip — so what
    /// the peer receives is byte-identical to what was logged), and the scan
    /// stops as soon as `limit` blocks are in hand.
    ///
    /// Reads the log file fresh so a reader thread never touches the append
    /// handle.
    pub fn blocks_after(dir: &Path, after_slot: u64, limit: usize) -> io::Result<Vec<Vec<u8>>> {
        let mut f = io::BufReader::new(File::open(dir.join("blocks.log"))?);
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
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
            }
            let mut payload = vec![0u8; len];
            match f.read_exact(&mut payload) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            // Only the header is parsed while skipping: the slot is all the
            // filter needs, and the signatures/attestations behind it are the
            // expensive part.
            let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
            if payload.len() < hdr_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame shorter than a header"));
            }
            let header = bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(
                &payload[..hdr_len],
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "undecodable header in block log"))?;
            if header.slot > after_slot {
                out.push(payload);
            }
        }
        Ok(out)
    }
}

/// Walk `blocks.log` once and record where every complete frame is.
///
/// Framing only: the 4-byte length, then just enough of the payload to read
/// the header's slot, then a **seek** past the rest. Nothing is decoded and no
/// body is copied, so this reads a fixed number of bytes per block rather than
/// the whole file.
///
/// Tolerates exactly what [`Store::read_all`] and [`Store::blocks_after`]
/// tolerate and stops in the same places: a truncated trailing frame ends the
/// table, an over-cap length is an error. That equivalence is the whole
/// correctness argument for serving from this table, and
/// `indexed_and_scanned_answers_are_identical` is where it is checked rather
/// than asserted.
fn scan_frames(dir: &Path) -> io::Result<Vec<FrameRef>> {
    let path = dir.join("blocks.log");
    let file = match File::open(&path) {
        Ok(f) => f,
        // No log yet is not an error: a fresh data dir has an empty table.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    // Read once, up front. The per-frame alternative is a `metadata` syscall
    // per block, which on a 33,000-block log costs more than the scan.
    let file_len = file.metadata()?.len();
    let mut f = io::BufReader::with_capacity(1 << 16, file);
    let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
    let mut out = Vec::new();
    let mut at: u64 = 0;
    let mut len4 = [0u8; 4];
    let mut head = vec![0u8; hdr_len];
    loop {
        match f.read_exact(&mut len4) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len4) as usize;
        if len > crate::codec::MAX_FIELD_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
        }
        let end = at + 4 + len as u64;
        // The frame is not all there: a crash mid-append. The linear scan
        // stops here and drops it, so the table must not contain it either —
        // otherwise a peer is served bytes that are not a block. Checked
        // BEFORE the header is parsed, because a torn frame's first bytes
        // still parse.
        if end > file_len || len < hdr_len {
            break;
        }
        if f.read_exact(&mut head).is_err() {
            break;
        }
        let header = bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(&head)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "undecodable header in block log")
            })?;
        // The body is skipped, not read: only the slot is needed here, and the
        // bytes are re-read at serve time anyway.
        if f.seek_relative((len - hdr_len) as i64).is_err() {
            break;
        }
        out.push(FrameRef { slot: header.slot, offset: at + 4, len: len as u32 });
        at = end;
    }
    Ok(out)
}

/// The indexed answer to a `get-blocks`: the same bytes
/// [`Store::blocks_after`] returns, found by lookup instead of by walking.
///
/// The filter is applied to the TABLE, frame by frame in log order, with no
/// assumption that slots increase — the linear version tests every frame's
/// slot individually and this tests every entry's, so the two select the same
/// frames for any log, monotonic or not. Only the selected frames are read.
pub fn blocks_after_indexed(
    dir: &Path,
    index: &FrameIndex,
    after_slot: u64,
    limit: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let wanted: Vec<FrameRef> = match index.read() {
        Ok(idx) => idx
            .iter()
            .filter(|fr| fr.slot > after_slot)
            .take(limit)
            .copied()
            .collect(),
        // A poisoned lock is not a reason to serve a wrong answer; fall back
        // to the walk, which needs no shared state at all.
        Err(_) => return Store::blocks_after(dir, after_slot, limit),
    };
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let mut f = File::open(dir.join("blocks.log"))?;
    let mut out = Vec::with_capacity(wanted.len());
    for fr in wanted {
        f.seek(SeekFrom::Start(fr.offset))?;
        let mut payload = vec![0u8; fr.len as usize];
        match f.read_exact(&mut payload) {
            Ok(()) => out.push(payload),
            // The file shrank under us (a reorg rewrote it between the table
            // read and this one). Serving a short page is correct — the peer
            // asks again — and is what the walk would also have done.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Fill `buf` from `f`, returning how many bytes were actually available.
/// `read_exact` cannot answer that, and the difference between "0 bytes left"
/// (a clean end of log) and "1-3 bytes left" (a crash mid-append) is exactly
/// what decides whether the operator is warned.
fn read_up_to<R: Read>(f: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut at = 0usize;
    while at < buf.len() {
        match f.read(&mut buf[at..]) {
            Ok(0) => break,
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(at)
}

/// The block log, one envelope at a time.
///
/// # Why boot does not use `read_all`
///
/// `read_all` slurps the whole file into a `Vec<u8>` and then decodes it into
/// a `Vec<BlockEnvelope>`, and **both are live at the same moment** — the
/// bytes are not dropped until the decode finishes. On the live chain that is
/// 407 MiB of file plus ~440 MiB of envelopes, ~850 MiB standing before a
/// single block has been applied, and it is chain-linear: at 200,000 blocks it
/// is ~5.5 GiB, on boxes that have 8.
///
/// Nothing about boot needs that. `run()` moves envelopes into `Engine::blocks`
/// one at a time, in log order, and never looks back — so the log can be a
/// stream, and the peak drops to the map plus one frame. The whole chain still
/// ends up in `blocks`; what is gone is the *second* copy of it, which is the
/// cheapest gigabyte in the process to stop spending.
///
/// This is the same posture [`Store::blocks_after`] already documents for the
/// serving path, applied to the reading path.
///
/// # Tolerance
///
/// Byte-for-byte the rules `read_all` had, because replay must accept exactly
/// the logs it accepted before: a frame length over
/// [`crate::codec::MAX_FIELD_LEN`] is an error, an undecodable body is an
/// error, and a truncated trailing frame — a partial length prefix or a length
/// whose body runs past the end — is dropped with one warning.
pub struct LogReader {
    f: io::BufReader<File>,
    done: bool,
}

impl LogReader {
    pub fn open(dir: &Path) -> io::Result<LogReader> {
        Ok(LogReader {
            f: io::BufReader::with_capacity(1 << 16, File::open(dir.join("blocks.log"))?),
            done: false,
        })
    }
}

impl Iterator for LogReader {
    type Item = io::Result<BlockEnvelope>;

    fn next(&mut self) -> Option<io::Result<BlockEnvelope>> {
        if self.done {
            return None;
        }
        let mut len4 = [0u8; 4];
        let got = match read_up_to(&mut self.f, &mut len4) {
            Ok(n) => n,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        if got != 4 {
            self.done = true;
            // A partial length prefix is the crash-mid-append case `read_all`
            // warned about in its tail check; zero bytes is a clean end.
            if got > 0 {
                eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
            }
            return None;
        }
        let len = u32::from_le_bytes(len4) as usize;
        if len > crate::codec::MAX_FIELD_LEN {
            self.done = true;
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "log frame over cap",
            )));
        }
        let mut payload = vec![0u8; len];
        match read_up_to(&mut self.f, &mut payload) {
            Ok(n) if n == len => {}
            Ok(_) => {
                self.done = true;
                eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        }
        match crate::codec::decode_envelope(&payload) {
            Ok(env) => Some(Ok(env)),
            Err(e) => {
                self.done = true;
                Some(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))
            }
        }
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

    /// **The whole correctness argument for the index, as a test.**
    ///
    /// The indexed answer must equal the walked answer for every request, on
    /// logs that break the properties an index is tempting to assume. Each
    /// case below is a deliberate violation of one such assumption, and the
    /// control at the end shows the test can actually fail.
    #[test]
    fn indexed_and_scanned_answers_are_identical() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        // VIOLATION 1: slots are NOT monotonic, and NOT contiguous. A binary
        // search over the table would be wrong here; the filter is linear over
        // the table for exactly this reason.
        let slots = [4u64, 1, 9, 9, 2, 40, 7];
        {
            let mut store = Store::open(&dir, &[9u8; 32]).expect("open");
            for s in slots {
                store.append(&sample_envelope(s)).expect("append");
            }
        }
        let reopened = Store::open(&dir, &[9u8; 32]).expect("reopen");
        let idx = reopened.index();
        assert_eq!(
            idx.read().unwrap().len(),
            slots.len(),
            "the table rebuilt at open must hold every frame the log holds"
        );
        for after in [0u64, 1, 2, 4, 7, 9, 39, 40, 41, u64::MAX] {
            for limit in [0usize, 1, 3, 100] {
                let walked = Store::blocks_after(&dir, after, limit).expect("walk");
                let looked = blocks_after_indexed(&dir, &idx, after, limit).expect("lookup");
                assert_eq!(
                    walked, looked,
                    "indexed answer diverged from the walk at after={after} limit={limit}"
                );
            }
        }

        // VIOLATION 2: a truncated trailing frame (a crash mid-append). The
        // walk drops it; the table must not offer it either, or a peer is
        // served bytes that are not a block.
        {
            let path = dir.join("blocks.log");
            let full = fs::metadata(&path).expect("meta").len();
            let mut bytes = fs::read(&path).expect("read");
            bytes.extend_from_slice(&999u32.to_le_bytes());
            bytes.extend_from_slice(&[0xAB; 40]); // a length that is a lie
            fs::write(&path, &bytes).expect("write");
            assert!(fs::metadata(&path).expect("meta").len() > full);
        }
        let torn = Store::open(&dir, &[9u8; 32]).expect("reopen torn");
        let torn_idx = torn.index();
        assert_eq!(
            torn_idx.read().unwrap().len(),
            slots.len(),
            "a truncated trailing frame must not enter the table"
        );
        for after in [0u64, 2, 9, 40] {
            assert_eq!(
                Store::blocks_after(&dir, after, 100).expect("walk"),
                blocks_after_indexed(&dir, &torn_idx, after, 100).expect("lookup"),
                "indexed answer diverged from the walk on a torn log at after={after}"
            );
        }

        // CONTROL. If the two paths could not disagree, the assertions above
        // would prove nothing. Hand the lookup a table built for a DIFFERENT
        // log and it must produce a different answer — which is what makes the
        // agreement above evidence rather than a tautology.
        let other = dir.join("other");
        let _ = fs::remove_dir_all(&other);
        {
            let mut st = Store::open(&other, &[9u8; 32]).expect("open other");
            for s in [4u64, 1, 9, 9, 2, 40, 7] {
                let mut e = sample_envelope(s);
                e.header.parent = [0x5A; 32]; // different bytes, same framing
                st.append(&e).expect("append");
            }
        }
        let other_store = Store::open(&other, &[9u8; 32]).expect("reopen other");
        assert_ne!(
            blocks_after_indexed(&other, &other_store.index(), 0, 100).expect("lookup"),
            Store::blocks_after(&dir, 0, 100).expect("walk"),
            "control failed: the two logs are indistinguishable, so agreement proves nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A fresh temp dir per test, so the three below can run concurrently.
    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("bloch-pos-store-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// **The boot invariant.** `run()` prints `replay {i}/{n}` where `n` comes
    /// from [`Store::count`] and `i` counts what [`LogReader`] yielded. Those
    /// are two separate walks of the same file — one that seeks past frame
    /// bodies and one that decodes them — and if they ever disagree the
    /// operator's remaining-time estimate is wrong, or worse, the count is a
    /// silent claim about a chain the reader did not deliver.
    ///
    /// They agreed trivially when boot read a `Vec` and took its `len()`.
    /// Streaming is what makes this something to assert rather than observe.
    #[test]
    fn count_agrees_with_the_stream() {
        let dir = tmpdir("count");
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
        for slot in 1..=9u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }
        let streamed: Vec<BlockEnvelope> = LogReader::open(&dir)
            .expect("open reader")
            .collect::<io::Result<_>>()
            .expect("stream");
        assert_eq!(streamed.len(), 9, "the reader yields every appended frame");
        assert_eq!(Store::count(&dir).expect("count"), streamed.len());
        // And the frames are the ones that went in, in order.
        let slots: Vec<u64> = streamed.iter().map(|e| e.header.slot).collect();
        assert_eq!(slots, (1..=9).collect::<Vec<u64>>());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A crash mid-append leaves a frame whose length prefix is complete but
    /// whose body runs past the end. Both walks must drop it, and drop the
    /// SAME one — a denominator of 9 against a stream of 8 would leave boot
    /// reporting 89% forever.
    #[test]
    fn a_truncated_body_is_dropped_by_both_walks() {
        let dir = tmpdir("trunc-body");
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
        for slot in 1..=9u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }
        let path = dir.join("blocks.log");
        let full = fs::metadata(&path).expect("meta").len();
        // Chop the last frame's body in half, leaving its length prefix.
        let frame = 4 + crate::codec::encode_envelope(&sample_envelope(9)).len() as u64;
        let f = OpenOptions::new().write(true).open(&path).expect("open rw");
        f.set_len(full - frame / 2).expect("truncate");
        drop(f);

        let streamed = LogReader::open(&dir)
            .expect("open reader")
            .collect::<io::Result<Vec<_>>>()
            .expect("a truncated tail is tolerated, not an error");
        assert_eq!(streamed.len(), 8, "the torn frame is dropped");
        assert_eq!(Store::count(&dir).expect("count"), 8, "and the count drops the same one");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The other half of the crash window: the append died inside the 4-byte
    /// length prefix itself. `read_all` had a separate tail check for this
    /// (`at + 4 > len && at < len`); the streaming reader has to reproduce it
    /// from a short read, which is why `read_up_to` exists instead of
    /// `read_exact`.
    #[test]
    fn a_partial_length_prefix_is_dropped_by_both_walks() {
        let dir = tmpdir("trunc-len");
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
        for slot in 1..=4u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }
        let path = dir.join("blocks.log");
        let full = fs::metadata(&path).expect("meta").len();
        let f = OpenOptions::new().write(true).open(&path).expect("open rw");
        f.set_len(full + 2).expect("grow by a partial prefix"); // two zero bytes
        drop(f);

        let streamed = LogReader::open(&dir)
            .expect("open reader")
            .collect::<io::Result<Vec<_>>>()
            .expect("a partial prefix is tolerated, not an error");
        assert_eq!(streamed.len(), 4);
        assert_eq!(Store::count(&dir).expect("count"), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    /// `rewrite` takes an iterator of references now, so the caller need not
    /// clone the chain to call it. What it writes must still be what
    /// `read_all` reads back, frame for frame.
    #[test]
    fn rewrite_from_references_round_trips() {
        let dir = tmpdir("rewrite");
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
        for slot in 1..=3u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }
        let replacement: Vec<BlockEnvelope> = (10..=12u64).map(sample_envelope).collect();
        // Borrowed, exactly as `do_reorg` now calls it.
        store.rewrite(replacement.iter()).expect("rewrite");
        let back = store.read_all().expect("read back");
        let slots: Vec<u64> = back.iter().map(|e| e.header.slot).collect();
        assert_eq!(slots, vec![10, 11, 12], "the log is the branch that was adopted");
        // The append handle was reopened onto the new file.
        store.append(&sample_envelope(13)).expect("append after rewrite");
        assert_eq!(store.read_all().expect("read").len(), 4);
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
