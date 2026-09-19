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
//! Appends stream the prefix and encoded envelope under one exclusive writer,
//! then fsync, so a crash leaves at most one truncated trailing frame, which
//! replay detects and drops.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use bloch_pos_committee::header::BlockEnvelope;

const META_MAGIC: &[u8; 8] = b"BPOSMETA";

// Serving threads must not combine an index from one log generation with a
// replacement log. DirLock excludes external writers; this per-directory guard
// coordinates local readers without serializing unrelated stores. Weak entries
// are removed on lookup, so historical directories do not accumulate forever.
fn log_generation(dir: &Path) -> io::Result<std::sync::Arc<std::sync::RwLock<()>>> {
    use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
    static GENERATIONS: OnceLock<Mutex<std::collections::BTreeMap<PathBuf, Weak<RwLock<()>>>>> = OnceLock::new();
    let path = fs::canonicalize(dir)?;
    let mut generations = GENERATIONS.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
        .lock().map_err(|_| io::Error::other("log generation registry poisoned; restart required"))?;
    generations.retain(|_, generation| generation.strong_count() > 0);
    if let Some(generation) = generations.get(&path).and_then(Weak::upgrade) { return Ok(generation); }
    let generation = Arc::new(RwLock::new(()));
    generations.insert(path, Arc::downgrade(&generation));
    Ok(generation)
}


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
// recovery path below:
//
//   * missing, empty, wrong magic, or torn  → rebuilt on `open`;
//   * behind the log (crash between the log fsync and the index append, or
//     an index from an older binary) → the unindexed tail is scanned;
//   * ahead of the log, out of order, or pointing at a frame that does not
//     carry the slot it claims → distrusted, and serving fails closed until
//     `Store::open` rebuilds the disposable index.
//
// The log is written first and fsynced first, so the index can only ever lag
// it. There is no state in which a lost or damaged index can make this node
// serve a block it does not have, hide one it does, or change the bytes.

/// Magic of the sidecar index. Bumping it invalidates every existing index
/// file, which costs exactly one boot rebuild.
const IDX_MAGIC: &[u8; 8] = b"BPOSIDX1";

/// One index record: `slot u64 LE ‖ offset u64 LE ‖ frame_len u32 LE`.
const IDX_ENTRY_LEN: u64 = 8 + 8 + 4;
const INDEX_WRITE_BUFFER_BYTES: usize = 8 * 1024;

/// Maximum complete frames one network request may inspect beyond the last
/// valid index record. A normal crash window is one frame; 4,096 is over a day
/// of 30-second slots while still making a persistent index-append failure a
/// bounded local fault repaired by restart instead of remote O(chain) work.
const MAX_UNINDEXED_TAIL_SCAN_FRAMES: usize = 4_096;

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

    /// `b[..8]`, `b[8..16]` and `b[16..20]` are fixed sub-ranges of a
    /// `&[u8; 20]`, so each `try_into` always receives exactly the width it
    /// asks for and cannot fail; the `else` arms are unreachable but keep the
    /// conversion panic-free by construction rather than by an `unwrap`.
    fn decode(b: &[u8; IDX_ENTRY_LEN as usize]) -> io::Result<IdxEntry> {
        let corrupt = || io::Error::new(io::ErrorKind::InvalidData, "corrupt index record");
        let Ok(slot) = b[..8].try_into() else { return Err(corrupt()) };
        let Ok(offset) = b[8..16].try_into() else { return Err(corrupt()) };
        let Ok(len) = b[16..20].try_into() else { return Err(corrupt()) };
        Ok(IdxEntry {
            slot: u64::from_le_bytes(slot),
            offset: u64::from_le_bytes(offset),
            len: u32::from_le_bytes(len),
        })
    }

    /// First byte after this frame.
    fn end(&self) -> u64 {
        // `offset` and `len` are positions/lengths within a real file on
        // disk (bounded by its actual size, far below u64::MAX); saturating
        // is intended here regardless, because `end()` exists only to be
        // compared against `log_len` (`repair_index`, `index_start`) to
        // decide whether the index is trustworthy — a corrupt on-disk index
        // record that would otherwise wrap around to a small value instead
        // saturates to a value that reliably reads as "past the log", which
        // makes callers distrust the index and fail boundedly.
        self.offset.saturating_add(4).saturating_add(self.len as u64)
    }
}

/// Records in an open index file (the magic is not one).
fn idx_count(idx: &File) -> io::Result<u64> {
    let len = idx.metadata()?.len();
    // Removed by construction: `checked_sub` folds the `len < 8` guard and
    // the subtraction into one operation instead of a subtraction clippy
    // must trust is preceded by a check.
    Ok(len.checked_sub(8).map_or(0, |body| body / IDX_ENTRY_LEN))
}

fn idx_read(idx: &mut File, i: u64) -> io::Result<IdxEntry> {
    // `i` is always a count of 20-byte records in a real file on disk
    // (`0..idx_count(idx)`), so `i * IDX_ENTRY_LEN + 8` cannot overflow
    // u64 in practice — but rather than trust that across call sites,
    // `checked_mul`/`checked_add` make an overflow an explicit "corrupt
    // index" error instead of a wrapped seek position.
    let pos = i
        .checked_mul(IDX_ENTRY_LEN)
        .and_then(|p| p.checked_add(8))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "index record offset overflow"))?;
    idx.seek(SeekFrom::Start(pos))?;
    let mut b = [0u8; IDX_ENTRY_LEN as usize];
    idx.read_exact(&mut b)?;
    IdxEntry::decode(&b)
}

/// Stream one index record for every **complete** frame in `blocks.log` at or
/// after `from`. Header-only reads: a rebuild of a 145 MB log touches one
/// header per block and no body.
///
/// A torn trailing frame (crash mid-append) ends the scan without an error,
/// exactly as `read_all` and `blocks_after` treat it — it is not indexed, so
/// it cannot be served, which is the same answer the log itself gives.
fn scan_index_into<W: Write>(log_path: &Path, from: u64, writer: &mut W) -> io::Result<()> {
    let log_len = fs::metadata(log_path)?.len();
    let mut f = io::BufReader::new(File::open(log_path)?);
    if from > 0 {
        f.seek(SeekFrom::Start(from))?;
    }
    let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
    let mut at = from;
    let mut len4 = [0u8; 4];
    let mut hdr = [0u8; bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN];
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
        // `at` and `len` are both positions/lengths within a real file on
        // disk (`at <= log_len` is this loop's own invariant, re-established
        // below; `len <= MAX_FIELD_LEN` was just checked), so this cannot
        // overflow in practice — `checked_add` makes that explicit rather
        // than assumed, and treats the unreachable overflow case exactly
        // like a truncated trailing frame: stop indexing and let open-time
        // repair or a bounded serving error preserve the log as authority.
        let Some(frame_end) = at.checked_add(4).and_then(|v| v.checked_add(len as u64)) else {
            break;
        };
        if frame_end > log_len {
            break; // truncated trailing frame
        }
        match f.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let Ok(header) = bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(&hdr)
        else {
            break;
        };
        writer.write_all(&IdxEntry { slot: header.slot, offset: at, len: len as u32 }.encode())?;
        // `len >= hdr_len` was already checked above (the `len < hdr_len`
        // arm breaks first), so this subtraction cannot underflow; written
        // as `checked_sub` so that invariant is enforced, not assumed.
        let Some(body_rest) = len.checked_sub(hdr_len) else {
            break;
        };
        if f.seek_relative(body_rest as i64).is_err() {
            break;
        }
        at = frame_end;
    }
    Ok(())
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
        // Removed by construction: `usable` (just above) requires
        // `idx_len >= 8`, so `checked_sub` folds that guarantee into the
        // subtraction instead of clippy having to trust it across the `if`.
        let n = idx_len.checked_sub(8).map_or(0, |body| body / IDX_ENTRY_LEN);
        // A torn trailing record: the process died between the log append and
        // the index append. Cut it off; the tail scan below re-derives it.
        // `n = (idx_len - 8) / IDX_ENTRY_LEN` (above) means
        // `n * IDX_ENTRY_LEN <= idx_len - 8`, so `8 + n * IDX_ENTRY_LEN <=
        // idx_len` — bounded by this index file's own real size on disk.
        #[allow(clippy::arithmetic_side_effects)]
        let exact = 8 + n * IDX_ENTRY_LEN;
        if exact != idx_len {
            idx.set_len(exact)?;
        }
        if n > 0 {
            // Guarded by `n > 0` on this line: cannot underflow.
            #[allow(clippy::arithmetic_side_effects)]
            let last_idx = n - 1;
            let last = idx_read(idx, last_idx)?;
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
        idx.seek(SeekFrom::End(0))?;
        let mut buffered = BufWriter::with_capacity(INDEX_WRITE_BUFFER_BYTES, &mut *idx);
        scan_index_into(log_path, covered, &mut buffered)?;
        buffered.flush()?;
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
    /// offset carries; a mismatch means the index lies and serving fails
    /// closed until the next index rebuild.
    At { offset: u64, expect_slot: Option<u64> },
}

/// Consult the index. `Ok(None)` means "no usable index"; network serving
/// fails boundedly until `Store::open` rebuilds it.
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
        if log_len != 0 {
            // An open store always indexes every complete frame before it is
            // exposed. Magic without records beside a non-empty log is thus
            // either corruption or an index-append failure, not permission
            // for a remote request to scan the entire history.
            return Ok(None);
        }
        // A genuinely empty log and freshly created index agree.
        return Ok(Some(Start::At { offset: 0, expect_slot: None }));
    }
    // Guarded by the `n == 0` return just above: n >= 1 here.
    #[allow(clippy::arithmetic_side_effects)]
    let last_idx = n - 1;
    let last = idx_read(&mut idx, last_idx)?;
    let covered = last.end();
    if covered > log_len {
        return Ok(None);
    }
    // First record past the window. Chain order means slots increase, so this
    // is a binary search: ~17 twenty-byte reads over a 100k-block log, against
    // 100k header parses.
    let (mut lo, mut hi) = (0u64, n);
    while lo < hi {
        // Standard binary-search midpoint: `lo < hi` (loop guard) bounds
        // `hi - lo` and `lo + (hi - lo) / 2 <= hi <= n`, a real index-record
        // count on disk, far below u64::MAX.
        #[allow(clippy::arithmetic_side_effects)]
        let mid = lo + (hi - lo) / 2;
        if idx_read(&mut idx, mid)?.slot > after_slot {
            hi = mid;
        } else {
            // `mid < hi <= n`, so `mid + 1 <= n`: cannot overflow.
            #[allow(clippy::arithmetic_side_effects)]
            let next = mid + 1;
            lo = next;
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
    // `wrapping_sub` is exact here (never actually wraps): `lo > 0` is
    // checked in this same condition before the value is used, so this is
    // just a subtraction clippy cannot see is guarded by its own sibling
    // operand — `wrapping_sub` sidesteps the lint without an `allow`.
    if lo > 0 && idx_read(&mut idx, lo.wrapping_sub(1))?.slot > after_slot {
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
    /// After one append failure, retain a contiguous indexed prefix instead
    /// of burying its missing entry under later successful index appends.
    index_append_enabled: bool,
    /// Bytes in `blocks.log`, so an append knows the offset it is writing at
    /// without asking the filesystem.
    log_len: u64,
    /// Exclusive ownership of `dir`, held for as long as the store is. Never
    /// read; its `Drop` is the whole point. See [`DirLock`].
    _lock: DirLock,
    generation: std::sync::Arc<std::sync::RwLock<()>>,
    /// A whole-log replacement being written and published by the dedicated
    /// reorg writer. Ordinary appends join it first, preserving log order.
    pending_rewrite: Option<mpsc::Receiver<io::Result<u64>>>,
    /// Completion can be observed after an append had to join the writer.
    rewrite_completed: bool,
}

#[derive(Clone, Copy)]
struct PageBytes {
    max: usize,
    per_frame: usize,
    first_must_fit: bool,
}

impl Drop for Store {
    fn drop(&mut self) {
        // Keep the data-dir lock alive until a background publisher has
        // stopped touching the directory. Errors cannot be returned from
        // Drop; live operation observes them through poll/append and exits.
        let _ = self.finish_pending_rewrite();
    }
}

/// Exclusive ownership of a data dir, for the lifetime of this `Store`.
///
/// ## Why a data dir needs a lock at all
///
/// Two `bloch-pos` processes over one data dir is not a corrupt-log problem —
/// it is a **double-signing** problem. Both hold the same keystore, both reach
/// the same duty, both sign, and the two signatures are exactly the evidence
/// `slashing.rs` burns stake for. It is also the easiest mistake an operator
/// can make: a systemd unit that did not stop cleanly plus a manual
/// `bloch-pos --data-dir ...` in a shell is all it takes, and nothing in the
/// node said a word about it. The slashing-protection watermarks
/// ([`crate::slashprot`]) are per-process in-memory state in front of one
/// file; they close the restart window, and this closes the concurrent one.
///
/// ## Two mechanisms, deliberately
///
/// 1. `O_EXCL` creation of `dir/LOCK` — the portable half, and the one that
///    leaves a visible artifact an operator can see and reason about.
/// 2. `flock(LOCK_EX | LOCK_NB)` on that same file, on unix — the half that
///    is *honest about staleness*. A lock file alone cannot distinguish "a
///    node is running" from "a node was killed"; a node that refuses to boot
///    after every crash gets its lock file deleted by reflex, which trains
///    exactly the wrong habit. `flock` is released by the kernel when the
///    holder dies, so a stale `LOCK` from a dead process is *reclaimed
///    silently* while a live one is refused. Two file descriptors in the same
///    process conflict under `flock` too (the lock belongs to the open file
///    description), so this refuses a second `Store::open` in-process as well
///    — which is what the test can actually drive.
///
/// ## The lock file is never unlinked on unix (audit round 3, H-1)
///
/// An earlier revision removed `dir/LOCK` in `Drop` "on clean shutdown". That
/// re-opened the hazard the lock exists for, through a three-process race:
///
/// ```text
///   A holds LOCK (inode X, flocked).
///   B opens the existing path            -> descriptor on inode X, not yet flocked
///   A shuts down cleanly: unlink(LOCK)   -> X is now an orphan inode
///   B flock(X)                            -> succeeds: nobody holds X any more
///   C create_new(LOCK)                    -> succeeds: the path is free -> inode Y
///   C flock(Y)                            -> succeeds
///   B and C both run over one keystore.
/// ```
///
/// The invariant that closes it: **the lock is the inode the path names, and
/// this module never unlinks that inode.** `flock` already gives clean release
/// (the descriptor closes) and crash release (the kernel drops it), so there
/// was nothing for the unlink to add except the race. A stale file after a
/// crash is not stale under `flock`; it is simply free.
///
/// Belt and braces: after a successful `flock`, `acquire` compares the inode
/// it locked with the inode the path names *now*. If they differ (an operator
/// ran `rm LOCK` while a node was up, or an older binary's `Drop` ran), the
/// lock it holds is on an orphan that no future process can contend for, so it
/// is dropped and the acquisition retried against the file that the path now
/// names. Bounded retries; a path that keeps changing underneath us is a
/// refusal, not a spin.
///
/// ## Non-unix (documented degrade)
///
/// Without `flock` the `O_EXCL` file *is* the lock. There it is removed on a
/// clean `Drop` (otherwise every restart would be refused), and a crash leaves
/// a file the operator must remove by hand after confirming no node runs. The
/// fleet is Linux; this arm exists so the crate keeps compiling elsewhere, not
/// as a supported posture.
pub struct DirLock {
    path: PathBuf,
    /// Held open because `flock` lives on the open file description: closing
    /// this releases the lock, so this field is the lock. Never read after
    /// construction — which is exactly why the `allow` is here rather than a
    /// `_` name: dropping the field would compile and silently un-protect the
    /// data dir.
    #[allow(dead_code)]
    file: File,
}

/// How many open → `flock` → verify rounds [`DirLock::acquire`] makes before
/// it gives up. Each round only repeats when the path was replaced underneath
/// this process, which takes another actor doing so on purpose.
const LOCK_ACQUIRE_ATTEMPTS: u32 = 8;

/// What one round of open → `flock` → verify established.
enum Locked {
    /// The descriptor holds the lock on the inode the path names.
    Held(File),
    /// The descriptor holds a lock on an inode the path no longer names
    /// (unlinked or replaced after we opened it). Worthless: drop it, retry.
    Orphaned,
}

impl DirLock {
    /// Take the lock, or fail with the message an operator needs.
    pub fn acquire(dir: &Path) -> io::Result<DirLock> {
        let path = dir.join("LOCK");
        for _attempt in 0..LOCK_ACQUIRE_ATTEMPTS {
            let (file, fresh) = match open_lock_file(&path)? {
                Some(opened) => opened,
                // Vanished between `create_new` failing and `open`: someone
                // unlinked it in that window. Start over against the path.
                None => continue,
            };
            match lock_and_verify(file, &path, fresh)? {
                Locked::Held(mut file) => {
                    file.set_len(0)?;
                    file.write_all(format!("{}\n", std::process::id()).as_bytes())?;
                    file.sync_all()?;
                    return Ok(DirLock { path, file });
                }
                Locked::Orphaned => continue,
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "could not settle the data-dir lock {} after {LOCK_ACQUIRE_ATTEMPTS} attempts: \
                 the file keeps being replaced underneath this process. Refusing to start.",
                path.display()
            ),
        ))
    }

    /// Where the lock file lives. Public so a tool that must refuse to run
    /// beside a live node (`bloch-pos keys seal`) can name it in its refusal.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Open `path` for locking. `Ok(Some((file, fresh)))` where `fresh` says
/// whether this call created the file; `Ok(None)` when the file existed at
/// `create_new` time and was gone by `open` time (retry).
fn open_lock_file(path: &Path) -> io::Result<Option<(File, bool)>> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => Ok(Some((f, true))),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // A LOCK file exists. Whether it MEANS anything is what flock
            // answers below; without flock we have to assume it does.
            if !cfg!(unix) {
                return Err(held(path));
            }
            match OpenOptions::new().write(true).open(path) {
                Ok(f) => Ok(Some((f, false))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// `flock` the descriptor, then confirm it is the inode the path names.
///
/// The verification is what makes an external unlink harmless: a lock on an
/// orphan inode cannot exclude anyone, so it is reported as [`Locked::Orphaned`]
/// and never returned as held.
#[cfg(unix)]
fn lock_and_verify(file: File, path: &Path, fresh: bool) -> io::Result<Locked> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file` is an open, owned descriptor for the duration of this
    // call; flock(2) touches nothing else.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock || !fresh {
            // Someone else holds it. This is the case the lock exists for;
            // say so, and do NOT remove their file.
            return Err(held(path));
        }
        return Err(e);
    }
    let locked = file.metadata()?;
    match fs::metadata(path) {
        Ok(named) if named.ino() == locked.ino() && named.dev() == locked.dev() => {
            Ok(Locked::Held(file))
        }
        // The path now names another inode, or nothing at all: our lock is
        // on an orphan.
        Ok(_) => Ok(Locked::Orphaned),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Locked::Orphaned),
        Err(e) => Err(e),
    }
}

/// Non-unix: `O_EXCL` creation is the whole lock, so a successfully created
/// file is held by definition (an existing one was already refused in
/// [`open_lock_file`]).
#[cfg(not(unix))]
fn lock_and_verify(file: File, _path: &Path, _fresh: bool) -> io::Result<Locked> {
    Ok(Locked::Held(file))
}

fn held(path: &Path) -> io::Error {
    let holder = fs::read_to_string(path).unwrap_or_default();
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "data dir is already in use by another bloch-pos process (lock {}{}). Refusing to \
             start: two nodes over one data dir hold one keystore, reach the same duty \
             and both sign it, which is the equivocation evidence slashing burns stake \
             for. Stop the other process first.",
            path.display(),
            match holder.trim() {
                "" => String::new(),
                pid => format!(", pid {pid}"),
            }
        ),
    )
}

/// Non-unix only: without `flock` the file is the lock, so a clean shutdown
/// must remove it or every restart is refused. On unix there is deliberately
/// NO `Drop` — see the type docs (H-1): the descriptor closing releases the
/// `flock`, and unlinking the path is exactly the race that let two nodes run.
#[cfg(not(unix))]
impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// `fsync` a directory, so a `rename` into it is durable.
///
/// `rename` is atomic with respect to readers but not with respect to a
/// crash: until the directory's own metadata reaches the disk, a power loss
/// can bring back the old name → old inode mapping. For the block log that
/// means a reorg that was applied, announced and built on could be undone by
/// a reboot, and the node would come back on the branch it had abandoned
/// (audit round 3, M-6). Callers do the write-to-temp + fsync(file) + rename,
/// then this.
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Exclusive, private staging for a streamed atomic replacement. A legacy
/// predictable `.tmp` path is never opened or truncated. Cleanup owns only the
/// exact file successfully created by this value; publication disarms cleanup.
pub(crate) struct PrivateStagingFile {
    path: Option<PathBuf>,
    file: File,
}

impl PrivateStagingFile {
    pub(crate) fn create_for(destination: &Path) -> io::Result<Self> {
        let dir = destination.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent directory"))?;
        let suffix = format!(".write-{}-{}.tmp", std::process::id(), {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        });
        let mut name = destination.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing filename"))?.to_os_string();
        name.push(suffix);
        let path = dir.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok(Self { path: Some(path), file })
    }

    pub(crate) fn file_mut(&mut self) -> &mut File { &mut self.file }

    pub(crate) fn publish(mut self, destination: &Path) -> io::Result<()> {
        let dir = destination.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent directory"))?;
        self.file.sync_all()?;
        let path = self.path.as_ref().ok_or_else(|| io::Error::other("staging file already published"))?;
        fs::rename(path, destination)?;
        self.path = None;
        fsync_dir(dir)
    }
}

impl Drop for PrivateStagingFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() { let _ = fs::remove_file(path); }
    }
}

/// Persist a private file without exposing a truncated destination after a crash.
pub(crate) fn atomic_private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut staging = PrivateStagingFile::create_for(path)?;
    staging.file_mut().write_all(bytes)?;
    staging.publish(path)
}

/// A crash can leave an incomplete final frame. Remove only that frame before
/// any append; merely ignoring it during replay would bury later valid blocks
/// behind its unfinished length prefix on every subsequent restart.
fn repair_log_tail(log: &mut File, dir: &Path) -> io::Result<u64> {
    let length = log.metadata()?.len();
    let mut at = 0u64;
    while at < length {
        if length.saturating_sub(at) < 4 { break; }
        log.seek(SeekFrom::Start(at))?;
        let mut prefix = [0; 4]; log.read_exact(&mut prefix)?;
        let size = u32::from_le_bytes(prefix) as u64;
        if size > crate::codec::MAX_FIELD_LEN as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized block log frame; refusing automatic repair"));
        }
        let end = at.checked_add(4).and_then(|n| n.checked_add(size))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "block log length overflow"))?;
        if end > length { break; }
        at = end;
    }
    if at != length {
        // An index is not authoritative enough to justify deleting bytes, but
        // evidence of a later committed frame is enough to STOP automatic
        // repair. A corrupted earlier length prefix must not discard history.
        if let Ok(mut idx) = File::open(dir.join("blocks.idx")) {
            let mut magic = [0u8; 8];
            if idx.read_exact(&mut magic).is_ok() && &magic == IDX_MAGIC {
                let count = idx_count(&idx)?;
                if let Some(last) = count.checked_sub(1) {
                    if idx_read(&mut idx, last)?.end() > at {
                        return Err(io::Error::new(io::ErrorKind::InvalidData,
                            "incomplete frame overlaps indexed history; refusing automatic log truncation"));
                    }
                }
            }
        }
        eprintln!("store: removing {} incomplete trailing log bytes before append", length.saturating_sub(at));
        log.set_len(at)?;
        log.sync_all()?;
    }
    Ok(at)
}

/// Framing/codec diagnosis only: a decoded frame is not proof of valid consensus
/// execution. Inspect a stopped node or an immutable copy; never change the log.
#[derive(Debug, PartialEq, Eq)]
pub struct LogInspection {
    pub log_bytes: u64,
    pub decoded_frames: u64,
    pub valid_prefix_bytes: u64,
    pub issue: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LogRepair {
    pub original_bytes: u64,
    pub retained_bytes: u64,
    pub backup_bytes: u64,
}

pub fn inspect_log(dir: &Path) -> io::Result<LogInspection> {
    let mut log = File::open(dir.join("blocks.log"))?;
    let length = log.metadata()?.len();
    let mut report = LogInspection { log_bytes: length, decoded_frames: 0, valid_prefix_bytes: 0, issue: None };
    while report.valid_prefix_bytes < length {
        let remaining = length.saturating_sub(report.valid_prefix_bytes);
        if remaining < 4 {
            report.issue = Some("incomplete trailing length prefix".into());
            break;
        }
        let mut prefix = [0; 4];
        log.read_exact(&mut prefix)?;
        let size = u32::from_le_bytes(prefix) as usize;
        if size > crate::codec::MAX_FIELD_LEN {
            report.issue = Some("frame length exceeds codec cap; cannot infer a safe truncation".into());
            break;
        }
        if (size as u64) > remaining.saturating_sub(4) {
            report.issue = Some("incomplete frame body; may be a torn append or corrupted length, not permission to truncate".into());
            break;
        }
        let mut payload = vec![0; size];
        log.read_exact(&mut payload)?;
        if let Err(error) = crate::codec::decode_envelope(&payload) {
            report.issue = Some(format!("invalid envelope: {error}; preserve the original log and restore from a verified backup"));
            break;
        }
        report.valid_prefix_bytes = report.valid_prefix_bytes.saturating_add(4).saturating_add(size as u64);
        report.decoded_frames = report.decoded_frames.saturating_add(1);
    }
    if log.metadata()?.len() != length {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "block log changed during inspection; stop the node or inspect an immutable copy"));
    }
    Ok(report)
}

/// Offline, operator-confirmed recovery of an unambiguously damaged trailing
/// write. The ordinary log format remains unchanged and no decoded or
/// consensus-invalid complete frame is ever removed by this function.
///
/// `expected_prefix` must exactly match a fresh [`inspect_log`] result. The
/// removable suffix must be either an incomplete length/body or entirely
/// zero-filled after the last decodable frame. A durable, exclusively-created
/// backup of the removed raw bytes is completed before truncation.
pub fn repair_log_tail_offline(
    dir: &Path,
    expected_prefix: u64,
    backup_path: &Path,
) -> io::Result<LogRepair> {
    let _lock = DirLock::acquire(dir)?;
    let report = inspect_log(dir)?;
    if report.valid_prefix_bytes != expected_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "confirmed prefix {expected_prefix} does not match freshly inspected prefix {}",
                report.valid_prefix_bytes
            ),
        ));
    }
    let Some(issue) = report.issue.as_deref() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block log has no damaged tail",
        ));
    };
    if expected_prefix >= report.log_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inspection did not identify a non-empty damaged tail",
        ));
    }

    let mut log = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("blocks.log"))?;
    if log.metadata()?.len() != report.log_bytes {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "block log changed after inspection; retry against a stopped node",
        ));
    }
    log.seek(SeekFrom::Start(expected_prefix))?;
    let structurally_incomplete = issue == "incomplete trailing length prefix"
        || issue.starts_with("incomplete frame body;");
    let mut all_zero = true;
    let mut remaining = report.log_bytes.saturating_sub(expected_prefix);
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "damaged tail length does not fit memory indexing",
                )
            })?;
        log.read_exact(&mut buffer[..take])?;
        all_zero &= buffer[..take].iter().all(|byte| *byte == 0);
        remaining = remaining.saturating_sub(take as u64);
    }
    if !structurally_incomplete && !all_zero {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "refusing repair: suffix is not an incomplete frame or an all-zero power-loss tail",
        ));
    }

    let backup_parent = backup_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let reserved_name = matches!(
        backup_path.file_name().and_then(|name| name.to_str()),
        Some("blocks.log" | "blocks.idx" | "meta.bin" | "LOCK")
    );
    if reserved_name && fs::canonicalize(backup_parent)? == fs::canonicalize(dir)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup must not use a store-managed filename in the data directory",
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut backup = options.open(backup_path)?;
    log.seek(SeekFrom::Start(expected_prefix))?;
    let removed = report.log_bytes.saturating_sub(expected_prefix);
    let copied = io::copy(&mut (&log).take(removed), &mut backup)?;
    if copied != removed {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "block log changed while copying the damaged tail"));
    }
    backup.sync_all()?;
    fsync_dir(backup_parent)?;

    if log.metadata()?.len() != report.log_bytes {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "block log changed before truncation; backup retained, log unchanged by this tool",
        ));
    }
    log.set_len(expected_prefix)?;
    log.sync_all()?;
    fsync_dir(dir)?;
    Ok(LogRepair {
        original_bytes: report.log_bytes,
        retained_bytes: expected_prefix,
        backup_bytes: copied,
    })
}

fn write_log_envelope<W: Write>(
    writer: &mut W,
    env: &BlockEnvelope,
) -> io::Result<(usize, u32)> {
    // Full preflight before the prefix or any canonical field reaches the
    // writer. `encoded_envelope_len` includes every per-item length prefix,
    // so passing this 8 MiB cap also proves every component length and both
    // collection counts fit their u32 wire fields.
    let payload_len = crate::codec::encoded_envelope_len(env);
    if payload_len > crate::codec::MAX_FIELD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block envelope exceeds the existing 8 MiB log frame limit",
        ));
    }
    let payload_len_u32 = u32::try_from(payload_len).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "block log frame length exceeds u32")
    })?;
    let frame_len = 4usize.checked_add(payload_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "block log frame length overflow")
    })?;
    writer.write_all(&payload_len_u32.to_le_bytes())?;
    crate::codec::write_envelope(writer, env)?;
    Ok((frame_len, payload_len_u32))
}

/// Decode the complete prefix of a framed log without retaining a second,
/// whole-file byte buffer alongside the decoded envelopes. `length` is the
/// stable file length observed before the scan; the data-directory lock keeps
/// the normal writer out while boot replay reads it.
fn read_log_frames<R: Read>(reader: R, length: u64) -> io::Result<Vec<BlockEnvelope>> {
    let mut reader = io::BufReader::new(reader);
    let mut out = Vec::new();
    // `decode_envelope` owns every variable field it returns, so this raw
    // frame can be overwritten after each decode. Keep one high-water
    // allocation under the logical frame cap instead of allocating once per
    // historical block; allocator capacity itself is not an RSS bound.
    let mut payload = Vec::new();
    let mut at = 0u64;
    while length.saturating_sub(at) >= 4 {
        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix)?;
        let len = u32::from_le_bytes(prefix) as usize;
        if len > crate::codec::MAX_FIELD_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
        }
        let Some(frame_end) = at
            .checked_add(4)
            .and_then(|body_at| body_at.checked_add(len as u64))
        else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame length overflow"));
        };
        if frame_end > length {
            eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
            return Ok(out);
        }
        read_frame_payload(&mut reader, &mut payload, len)?;
        let env = crate::codec::decode_envelope(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        out.push(env);
        at = frame_end;
    }
    if at < length {
        eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
    }
    Ok(out)
}

fn read_frame_payload<R: Read>(
    reader: &mut R,
    payload: &mut Vec<u8>,
    len: usize,
) -> io::Result<()> {
    payload.resize(len, 0);
    reader.read_exact(payload)
}

/// Durable reorg publication using handles owned only by the writer thread.
/// Staging deliberately happens before the generation write lock, so bounded
/// sync readers remain available during the expensive encoding and write.
fn rewrite_files(
    dir: &Path,
    generation: &std::sync::Arc<std::sync::RwLock<()>>,
    envs: &[BlockEnvelope],
) -> io::Result<u64> {
    let destination = dir.join("blocks.log");
    let mut staging = PrivateStagingFile::create_for(&destination)?;
    for env in envs {
        write_log_envelope(staging.file_mut(), env)?;
    }
    staging.file_mut().sync_all()?;

    let index_path = dir.join("blocks.idx");
    let mut idx = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&index_path)?;
    publish_staged_rewrite(dir, generation, staging, &mut idx)
}

/// The short publication transaction shared by synchronous tests/tools and
/// the asynchronous live writer. Keeping this ordering in one function makes
/// the existing forced-index-failure regression cover both entry points.
fn publish_staged_rewrite(
    dir: &Path,
    generation: &std::sync::Arc<std::sync::RwLock<()>>,
    staging: PrivateStagingFile,
    idx: &mut File,
) -> io::Result<u64> {
    let destination = dir.join("blocks.log");
    let _generation = generation
        .write()
        .map_err(|_| io::Error::other("log generation guard poisoned; restart required"))?;
    // This ordering is the crash-safety contract: an old-generation index is
    // made durably unusable before the new authoritative log can appear.
    idx.set_len(0)?;
    idx.sync_all()?;
    staging.publish(&destination)?;
    let log_len = fs::metadata(&destination)?.len();
    idx.set_len(0)?;
    repair_index(idx, &destination, log_len)?;
    Ok(log_len)
}

impl Store {
    pub(crate) fn directory(&self) -> &Path { &self.dir }

    /// Open (or initialize) a data dir for the network identified by
    /// `genesis_digest`. A dir initialized for any other genesis — or holding
    /// anything that is not a bloch-pos meta — is a **refusal, not a
    /// migration** (integration plan §3.1).
    pub fn open(dir: &Path, genesis_digest: &[u8; 32]) -> io::Result<Store> {
        fs::create_dir_all(dir)?;
        // FIRST, before a single byte of this dir is read or written: a second
        // process over the same dir is a double-signing hazard, not a
        // file-format one. See [`DirLock`].
        let _lock = DirLock::acquire(dir)?;
        let generation = log_generation(dir)?;
        let _generation = generation.write()
            .map_err(|_| io::Error::other("log generation guard poisoned; restart required"))?;
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
                atomic_private_write(&meta_path, &out)?;
            }
            Err(e) => return Err(e),
        }
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(dir.join("blocks.log"))?;
        let log_len = repair_log_tail(&mut log, dir)?;
        // The index is rebuilt (or caught up) here, on the same boot that
        // already replays the whole log. A data dir written by a binary that
        // predates the index is therefore indexed the first time this one
        // opens it, with no migration step and no flag.
        let mut idx = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(dir.join("blocks.idx"))?;
        // The index is disposable: a crash after an older writer renamed a
        // reorg log can leave a perfectly sized index describing another chain.
        // Rebuild from header-only log reads; covered length is not identity.
        idx.set_len(0)?;
        repair_index(&mut idx, &dir.join("blocks.log"), log_len)?;
        Ok(Store {
            dir: dir.to_path_buf(),
            log,
            idx,
            index_append_enabled: true,
            log_len,
            _lock,
            generation: std::sync::Arc::clone(&generation),
            pending_rewrite: None,
            rewrite_completed: false,
        })
    }

    /// Append one applied block. Prefix and payload writes, then fsync — the block is only
    /// broadcast after this returns, so anything the network has seen from
    /// us is durable locally (the producer-side equivocation fence across
    /// restarts).
    pub fn append(&mut self, env: &BlockEnvelope) -> io::Result<()> {
        // A block applied after a reorg belongs after the replacement log.
        // Joining here preserves that order if it arrives before the writer's
        // normal completion poll. The consensus thread is otherwise free
        // while the rewrite runs.
        self.finish_pending_rewrite()?;
        let (frame_len, payload_len) = write_log_envelope(&mut self.log, env)?;
        self.log.sync_data()?;
        // Index AFTER the log is durable. A crash in between leaves the index
        // one record short, which the next `open` fixes and which
        // `blocks_after` already tolerates by scanning the unindexed tail —
        // so this write is deliberately not fsynced. An index entry that
        // cannot be written is not worth failing an applied block over: log
        // it, and let the next open rebuild.
        let entry = IdxEntry { slot: env.header.slot, offset: self.log_len, len: payload_len };
        // `log_len` tracks bytes actually fsynced to `blocks.log` on this
        // disk; reaching anywhere near u64::MAX (18 exabytes) is not a
        // condition a real deployment's storage can produce.
        #[allow(clippy::arithmetic_side_effects)]
        {
            self.log_len += frame_len as u64;
        }
        // Seek to the end explicitly rather than trusting the handle's cursor:
        // `repair_index` reads records through this same handle, and a record
        // written at a stale cursor would not append to the index, it would
        // OVERWRITE part of it.
        if self.index_append_enabled {
            if let Err(e) = self.idx.seek(SeekFrom::End(0)).and_then(|_| self.idx.write_all(&entry.encode())) {
                self.index_append_enabled = false;
                eprintln!("store: block-index append failed ({e}); retaining its valid prefix and scanning the unindexed tail until restart or reorg rebuild");
            }
        }
        Ok(())
    }

    /// Read every complete frame in the log, in order. A truncated trailing
    /// frame (crash mid-append) is dropped with a warning; a *corrupt* frame
    /// body is an error, because silently skipping mid-chain data would make
    /// replay diverge from what the network saw.
    pub fn read_all(&self) -> io::Result<Vec<BlockEnvelope>> {
        let file = File::open(self.dir.join("blocks.log"))?;
        let length = file.metadata()?.len();
        read_log_frames(file, length)
    }

    /// Replace the whole log with `envs` (a reorg adopted a different
    /// branch). Write-to-temp + rename, then reopen the append handle, so a
    /// crash mid-rewrite leaves either the old log or the new one — never a
    /// half-written file.
    pub fn rewrite(&mut self, envs: &[BlockEnvelope]) -> io::Result<()> {
        self.finish_pending_rewrite()?;
        let destination = self.dir.join("blocks.log");
        let mut staging = PrivateStagingFile::create_for(&destination)?;
        for env in envs {
            write_log_envelope(staging.file_mut(), env)?;
        }
        staging.file_mut().sync_all()?;
        let generation = std::sync::Arc::clone(&self.generation);
        publish_staged_rewrite(&self.dir, &generation, staging, &mut self.idx)?;
        self.reopen_after_rewrite()?;
        Ok(())
    }

    /// Start a durable whole-log replacement on a dedicated writer thread.
    ///
    /// The worker performs encoding, file writes, fsyncs, index invalidation,
    /// atomic publication and index reconstruction. The caller must poll with
    /// [`Store::poll_rewrite`] and fail-stop on an error. [`Store::append`]
    /// also joins the worker before writing, so a post-reorg block can never
    /// land in the old generation or before the replacement.
    pub fn rewrite_async(&mut self, envs: Vec<BlockEnvelope>) -> io::Result<()> {
        self.finish_pending_rewrite()?;
        let dir = self.dir.clone();
        let generation = std::sync::Arc::clone(&self.generation);
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("block-log-reorg-writer".into())
            .spawn(move || {
                let result = rewrite_files(&dir, &generation, &envs);
                let _ = tx.send(result);
            })?;
        self.pending_rewrite = Some(rx);
        Ok(())
    }

    pub fn rewrite_pending(&self) -> bool {
        self.pending_rewrite.is_some()
    }

    /// Poll the reorg writer without waiting. `true` means a rewrite became
    /// durable since the preceding poll (including one joined by `append`).
    pub fn poll_rewrite(&mut self) -> io::Result<bool> {
        if let Some(rx) = self.pending_rewrite.as_ref() {
            match rx.try_recv() {
                Ok(result) => {
                    self.pending_rewrite = None;
                    self.complete_rewrite(result?)?;
                }
                Err(mpsc::TryRecvError::Empty) => return Ok(false),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending_rewrite = None;
                    return Err(io::Error::other("block-log reorg writer terminated without a result"));
                }
            }
        }
        Ok(std::mem::take(&mut self.rewrite_completed))
    }

    /// Wait for durable reorg publication during an orderly shutdown.
    pub fn flush_rewrite(&mut self) -> io::Result<bool> {
        self.finish_pending_rewrite()?;
        Ok(std::mem::take(&mut self.rewrite_completed))
    }

    fn finish_pending_rewrite(&mut self) -> io::Result<()> {
        let Some(rx) = self.pending_rewrite.take() else { return Ok(()) };
        let result = rx.recv().map_err(|_| {
            io::Error::other("block-log reorg writer terminated without a result")
        })?;
        self.complete_rewrite(result?)
    }

    fn complete_rewrite(&mut self, log_len: u64) -> io::Result<()> {
        self.reopen_after_rewrite()?;
        if self.log_len != log_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published block-log length changed before writer completion",
            ));
        }
        self.rewrite_completed = true;
        Ok(())
    }

    fn reopen_after_rewrite(&mut self) -> io::Result<()> {
        self.log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(self.dir.join("blocks.log"))?;
        self.log_len = self.log.metadata()?.len();
        self.idx = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dir.join("blocks.idx"))?;
        self.idx.seek(SeekFrom::End(0))?;
        self.index_append_enabled = true;
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
    /// start*. Detected index/header discrepancies fail the request with a
    /// bounded error; startup rebuild and generation locking repair the
    /// disposable index without reopening a whole-history scan to callers.
    ///
    /// Reads the log file fresh so a reader thread never touches the append
    /// handle.
    pub fn blocks_after(dir: &Path, after_slot: u64, limit: usize) -> io::Result<Vec<Vec<u8>>> {
        Self::blocks_after_inner(dir, after_slot, limit, PageBytes {
            max: crate::codec::MAX_FIELD_LEN,
            per_frame: 0,
            first_must_fit: false,
        })
    }

    /// Read a directed libp2p page with its smaller, framing-aware budget.
    /// Unlike the generic page, its old post-filter also refused an oversized
    /// first frame; checking it here preserves that empty-page result without
    /// reading the body. Private so the public store/devnet page stays unchanged.
    pub(crate) fn blocks_after_p2p(
        dir: &Path,
        after_slot: u64,
        limit: usize,
        max_bytes: usize,
        per_frame_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        Self::blocks_after_inner(dir, after_slot, limit, PageBytes {
            max: max_bytes,
            per_frame: per_frame_bytes,
            first_must_fit: true,
        })
    }

    fn blocks_after_inner(
        dir: &Path,
        after_slot: u64,
        limit: usize,
        page_bytes: PageBytes,
    ) -> io::Result<Vec<Vec<u8>>> {
        let generation = log_generation(dir)?;
        let _generation = generation.read()
            .map_err(|_| io::Error::other("log generation guard poisoned; restart required"))?;
        let log_path = dir.join("blocks.log");
        let log_len = fs::metadata(&log_path)?.len();
        // `Store::open` creates or rebuilds this derived index before network
        // serving starts. A later missing/corrupt index is therefore a local
        // fault, not a reason to let a remote request reopen the historical
        // O(chain length) scan. Fail boundedly and let restart/open repair it.
        match index_start(dir, after_slot, log_len)? {
            Some(Start::Nothing) => return Ok(Vec::new()),
            Some(Start::At { offset, expect_slot }) => {
                if let Some(page) =
                    Self::scan_page(
                        &log_path,
                        offset,
                        expect_slot,
                        after_slot,
                        limit,
                        MAX_UNINDEXED_TAIL_SCAN_FRAMES,
                        page_bytes,
                    )?
                {
                    return Ok(page);
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "block index disagrees with the log at offset {offset}; \
                         restart to rebuild the derived index"
                    ),
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "block index is unusable; restart to rebuild the derived index",
                ));
            }
        }
    }

    /// The scan itself, from `from` to the page cap. A scan beyond the valid
    /// index prefix also has a frame-work cap; indexed hits are already bounded
    /// by the response count/byte limits and do not spend that allowance.
    /// Returns `Ok(None)` — and only then — when `expect_slot` is set and the
    /// frame at `from` does not carry it, which is the caller's signal that the
    /// index is not describing this log and serving must fail closed until the
    /// index is rebuilt.
    fn scan_page(
        log_path: &Path,
        from: u64,
        expect_slot: Option<u64>,
        after_slot: u64,
        limit: usize,
        max_unindexed_frames: usize,
        page_limit: PageBytes,
    ) -> io::Result<Option<Vec<Vec<u8>>>> {
        let mut f = io::BufReader::new(File::open(log_path)?);
        if from > 0 {
            f.seek(SeekFrom::Start(from))?;
        }
        let unindexed_tail = expect_slot.is_none();
        let mut expect = expect_slot;
        let mut unindexed_frames = 0usize;
        let mut out = Vec::new();
        let mut page_bytes = 0usize;
        let mut len4 = [0u8; 4];
        let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
        let mut hdr_buf = [0u8; bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN];
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
            if unindexed_tail && unindexed_frames >= max_unindexed_frames {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unindexed block-log tail exceeds the {max_unindexed_frames}-frame \
                         serving bound; restart to rebuild the derived index"
                    ),
                ));
            }
            unindexed_frames = unindexed_frames.saturating_add(1);
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
            if len < hdr_len {
                if expect.is_some() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "log frame shorter than a header",
                ));
            }
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
            // Observability counter (see the type's doc comment above):
            // saturating is the intended semantics.
            SYNC_FRAMES_SCANNED.with(|c| c.set(c.get().saturating_add(1)));
            // The index's claim, checked against the log, once. Everything
            // after this frame is the log's own chain order.
            if let Some(want) = expect.take() {
                if header.slot != want {
                    return Ok(None);
                }
            }
            // `len < hdr_len` already returned/errored above, so `len >=
            // hdr_len` here; `saturating_sub` makes that exact under the
            // guard, not merely assumed.
            let rest = len.saturating_sub(hdr_len);
            if header.slot > after_slot {
                let next_page_bytes = page_bytes.saturating_add(len).saturating_add(page_limit.per_frame);
                if (page_limit.first_must_fit || !out.is_empty()) && next_page_bytes > page_limit.max { break; }
                page_bytes = next_page_bytes;
                // Wanted: read the body and hand back the whole frame, byte
                // for byte identical to what the old path pushed.
                let mut payload = Vec::with_capacity(len);
                payload.extend_from_slice(&hdr_buf);
                payload.resize(len, 0);
                match f.read_exact(&mut payload[hdr_len..]) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
                // Observability counter: saturating is the intended
                // semantics.
                SYNC_BODY_BYTES_READ.with(|c| c.set(c.get().saturating_add(rest as u64)));
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

    struct BoundedRead {
        inner: io::Cursor<Vec<u8>>,
        max_request: usize,
        largest_request: usize,
    }

    impl Read for BoundedRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.len() > self.max_request {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "reader was asked for a whole-log-sized buffer",
                ));
            }
            self.largest_request = self.largest_request.max(buf.len());
            self.inner.read(buf)
        }
    }

    fn index_log_fixture(count: u64) -> (Vec<u8>, Vec<IdxEntry>) {
        let mut log = Vec::new();
        let mut entries = Vec::new();
        let mut offset = 0u64;
        for slot in 1..=count {
            let payload = crate::codec::encode_envelope(&sample_envelope(slot));
            entries.push(IdxEntry { slot, offset, len: payload.len() as u32 });
            log.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            log.extend_from_slice(&payload);
            offset = offset.saturating_add(4).saturating_add(payload.len() as u64);
        }
        (log, entries)
    }

    #[test]
    fn replay_log_decode_streams_bounded_frames_and_preserves_tail_refusals() {
        let envelopes: Vec<_> = (1..=128).map(sample_envelope).collect();
        let mut bytes = Vec::new();
        for envelope in &envelopes {
            let payload = crate::codec::encode_envelope(envelope);
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&payload);
        }
        assert!(bytes.len() > 8 * 1024, "fixture must exceed the bounded reader request");
        let mut reader = BoundedRead {
            inner: io::Cursor::new(bytes.clone()),
            max_request: 8 * 1024,
            largest_request: 0,
        };
        let decoded = read_log_frames(&mut reader, bytes.len() as u64).unwrap();
        assert_eq!(
            decoded.iter().map(|env| env.header.slot).collect::<Vec<_>>(),
            (1..=128).collect::<Vec<_>>(),
        );
        assert!(reader.largest_request <= reader.max_request);

        let mut torn = bytes.clone();
        torn.extend_from_slice(&[3, 0]);
        assert_eq!(read_log_frames(io::Cursor::new(&torn), torn.len() as u64).unwrap().len(), 128);

        let mut zero_frame = bytes;
        zero_frame.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            read_log_frames(io::Cursor::new(&zero_frame), zero_frame.len() as u64)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
            "a complete zero-length frame remains corruption, not a truncatable tail",
        );
    }

    #[test]
    fn replay_scratch_reuses_high_water_and_preserves_mixed_frames() {
        let empty = sample_envelope(201);
        let mut large = sample_envelope(202);
        large.body.transactions = vec![vec![0xA5; 1 << 20]];
        let mut small = sample_envelope(203);
        small.proposer_sig.extend_from_slice(&[0x5C; 31]);
        let expected = [empty, large, small];

        let mut log = Vec::new();
        for envelope in &expected {
            let encoded = crate::codec::encode_envelope(envelope);
            log.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            log.extend_from_slice(&encoded);
        }
        let decoded = read_log_frames(io::Cursor::new(&log), log.len() as u64)
            .expect("mixed replay frames");
        assert_eq!(decoded.len(), expected.len());
        for (actual, expected) in decoded.iter().zip(&expected) {
            assert_eq!(actual.header, expected.header);
            assert_eq!(actual.proposer_sig, expected.proposer_sig);
            assert_eq!(actual.body.transactions, expected.body.transactions);
            assert_eq!(actual.body.attestations, expected.body.attestations);
        }

        let large_raw = vec![0xD1; 1 << 20];
        let small_raw = vec![0xD2; 37];
        let mut raw = large_raw.clone();
        raw.extend_from_slice(&small_raw);
        let mut reader = io::Cursor::new(raw);
        let mut scratch = Vec::new();
        read_frame_payload(&mut reader, &mut scratch, large_raw.len()).unwrap();
        let high_water_ptr = scratch.as_ptr();
        let high_water_capacity = scratch.capacity();
        assert_eq!(scratch, large_raw);
        read_frame_payload(&mut reader, &mut scratch, small_raw.len()).unwrap();
        assert_eq!(scratch.as_ptr(), high_water_ptr, "smaller frame reallocated scratch");
        assert_eq!(scratch.capacity(), high_water_capacity);
        assert_eq!(scratch, small_raw);

        let over_cap = ((crate::codec::MAX_FIELD_LEN + 1) as u32).to_le_bytes();
        assert_eq!(
            read_log_frames(io::Cursor::new(over_cap), 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "over-cap prefix must fail before any payload read or resize",
        );
    }

    #[test]
    fn log_frame_writer_streams_prefix_then_payload_across_short_writes() {
        #[derive(Default)]
        struct ShortWriter {
            bytes: Vec<u8>,
            offered: Vec<usize>,
        }

        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.offered.push(bytes.len());
                let cap = if self.offered.len() <= 2 { 2 } else { 257 };
                let accepted = bytes.len().min(cap);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }

        let envelope = sample_envelope(11);
        let payload = crate::codec::encode_envelope(&envelope);
        let mut writer = ShortWriter::default();
        let (frame_len, payload_len) =
            write_log_envelope(&mut writer, &envelope).expect("stream frame");

        assert_eq!(frame_len, 4usize.saturating_add(payload.len()));
        assert_eq!(payload_len as usize, payload.len());
        assert_eq!(&writer.bytes[..4], &(payload.len() as u32).to_le_bytes());
        assert_eq!(&writer.bytes[4..], payload.as_slice());
        assert_eq!(
            writer.offered[..2],
            [4, 2],
            "canonical payload must begin only after the complete prefix",
        );
    }

    #[test]
    fn log_frame_writer_partial_canonical_failure_remains_a_recoverable_torn_tail() {
        struct PartialThenFail {
            bytes: Vec<u8>,
            remaining: usize,
        }

        impl Write for PartialThenFail {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.remaining == 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected body failure"));
                }
                let accepted = bytes.len().min(self.remaining);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                self.remaining = self.remaining.saturating_sub(accepted);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }

        let envelope = sample_envelope(12);
        let payload = crate::codec::encode_envelope(&envelope);
        let mut writer = PartialThenFail { bytes: Vec::new(), remaining: 41 };
        let error =
            write_log_envelope(&mut writer, &envelope).expect_err("body write must fail");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(&writer.bytes[..4], &(payload.len() as u32).to_le_bytes());
        assert_eq!(&writer.bytes[4..], &payload[..37]);
        assert!(
            read_log_frames(io::Cursor::new(&writer.bytes), writer.bytes.len() as u64)
                .expect("partial canonical tail remains recoverable")
                .is_empty(),
        );
    }

    #[test]
    fn persistence_refuses_oversized_frames_before_mutation_and_accepts_exact_limit() {
        let dir = std::env::temp_dir().join(format!("bloch-store-frame-cap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x77; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let before_log = fs::read(dir.join("blocks.log")).unwrap();
        let before_index = fs::read(dir.join("blocks.idx")).unwrap();
        let mut boundary = sample_envelope(2);
        let overhead = crate::codec::encode_envelope(&boundary).len() - boundary.proposer_sig.len();
        boundary.proposer_sig.resize(crate::codec::MAX_FIELD_LEN - overhead + 1, 0xAA);
        #[derive(Default)]
        struct CountingWriter(usize);
        impl Write for CountingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0 = self.0.saturating_add(bytes.len());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let mut untouched = CountingWriter::default();
        assert_eq!(
            write_log_envelope(&mut untouched, &boundary).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
        );
        assert_eq!(untouched.0, 0, "over-cap preflight must precede every write");
        assert_eq!(store.append(&boundary).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(store.rewrite(&[sample_envelope(3), boundary.clone()]).is_err());
        assert_eq!(fs::read(dir.join("blocks.log")).unwrap(), before_log);
        assert_eq!(fs::read(dir.join("blocks.idx")).unwrap(), before_index);
        assert!(!fs::read_dir(&dir).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().contains(".write-")));
        boundary.proposer_sig.pop();
        assert_eq!(crate::codec::encode_envelope(&boundary).len(), crate::codec::MAX_FIELD_LEN);
        store.append(&boundary).unwrap();
        drop(store);
        let reopened = Store::open(&dir, &[0x77; 32]).unwrap();
        let frames = reopened.read_all().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(crate::codec::encode_envelope(&frames[1]), crate::codec::encode_envelope(&boundary));
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_index_append_never_turns_a_later_entry_into_a_gap() {
        let dir = std::env::temp_dir().join(format!("bloch-store-index-gap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x76; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let working = std::mem::replace(&mut store.idx, File::open(dir.join("blocks.idx")).unwrap());
        store.append(&sample_envelope(2)).unwrap(); // log succeeds, index fails
        store.idx = working;
        store.append(&sample_envelope(3)).unwrap();
        let page = Store::blocks_after(&dir, 1, 10).unwrap();
        let slots: Vec<_> = page.iter().map(|bytes| crate::codec::decode_envelope(bytes).unwrap().header.slot).collect();
        assert!(!store.index_append_enabled);
        store.rewrite(&[sample_envelope(1), sample_envelope(2), sample_envelope(3)]).unwrap();
        assert!(store.index_append_enabled);
        store.append(&sample_envelope(4)).unwrap();
        assert_eq!(idx_count(&store.idx).unwrap(), 4);
        drop(store);
        let _ = fs::remove_dir_all(dir);
        assert_eq!(slots, vec![2, 3], "an index write failure must not hide the missing frame behind a later index entry");
    }

    #[test]
    fn index_repair_writer_is_fixed_bounded_and_byte_exact() {
        #[derive(Default)]
        struct RecordingWriter {
            bytes: Vec<u8>,
            largest: usize,
            writes: usize,
        }

        impl Write for RecordingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.largest = self.largest.max(bytes.len());
                self.writes = self.writes.saturating_add(1);
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }

        let dir = std::env::temp_dir().join(format!("bloch-index-stream-exact-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (log, entries) = index_log_fixture(1_000);
        let log_path = dir.join("blocks.log");
        fs::write(&log_path, log).unwrap();
        let mut expected = Vec::new();
        for entry in &entries { expected.extend_from_slice(&entry.encode()); }
        let mut writer = RecordingWriter::default();
        {
            let mut buffered = BufWriter::with_capacity(INDEX_WRITE_BUFFER_BYTES, &mut writer);
            scan_index_into(&log_path, 0, &mut buffered).expect("scan index entries");
            buffered.flush().expect("flush index entries");
        }

        assert_eq!(writer.bytes, expected, "buffering must not change index bytes or order");
        assert!(writer.largest <= INDEX_WRITE_BUFFER_BYTES);
        assert!(writer.writes > 1, "fixture must cross the fixed buffer boundary");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_buffered_index_record_is_truncated_and_rebuilt() {
        struct FailInsideRecord {
            bytes: Vec<u8>,
            remaining: usize,
        }

        impl Write for FailInsideRecord {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.remaining == 0 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected index failure"));
                }
                let accepted = bytes.len().min(self.remaining);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                self.remaining = self.remaining.saturating_sub(accepted);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }

        let dir = std::env::temp_dir().join(format!("bloch-index-buffer-fault-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (log, entries) = index_log_fixture(500);
        let log_path = dir.join("blocks.log");
        fs::write(&log_path, &log).unwrap();

        let mut failed = FailInsideRecord {
            bytes: Vec::new(),
            remaining: INDEX_WRITE_BUFFER_BYTES.saturating_add(7),
        };
        {
            let mut buffered = BufWriter::with_capacity(INDEX_WRITE_BUFFER_BYTES, &mut failed);
            scan_index_into(&log_path, 0, &mut buffered).expect("scan reaches final flush");
            assert_eq!(
                buffered.flush().unwrap_err().kind(),
                io::ErrorKind::BrokenPipe,
            );
        }
        assert_ne!(failed.bytes.len() % IDX_ENTRY_LEN as usize, 0, "fault must split a record");
        let idx_path = dir.join("blocks.idx");
        let mut damaged = IDX_MAGIC.to_vec();
        damaged.extend_from_slice(&failed.bytes);
        fs::write(&idx_path, damaged).unwrap();

        let mut idx = OpenOptions::new().read(true).write(true).open(&idx_path).unwrap();
        repair_index(&mut idx, &log_path, log.len() as u64).expect("repair partial index");
        let mut expected = IDX_MAGIC.to_vec();
        for entry in &entries { expected.extend_from_slice(&entry.encode()); }
        assert_eq!(fs::read(&idx_path).unwrap(), expected);

        drop(idx);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn streamed_index_scan_preserves_torn_and_corrupt_log_prefixes() {
        let dir = std::env::temp_dir().join(format!("bloch-index-stream-prefix-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (valid, entries) = index_log_fixture(2);
        let mut expected = IDX_MAGIC.to_vec();
        for entry in &entries { expected.extend_from_slice(&entry.encode()); }

        let mut torn = valid.clone();
        torn.extend_from_slice(&[5, 0, 0, 0, 0xAA]);
        let mut corrupt = valid;
        corrupt.extend_from_slice(&1u32.to_le_bytes());
        corrupt.push(0xFF);

        for (name, log) in [("torn", torn), ("corrupt", corrupt)] {
            let log_path = dir.join(format!("{name}.log"));
            let idx_path = dir.join(format!("{name}.idx"));
            fs::write(&log_path, &log).unwrap();
            let mut idx = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&idx_path)
                .unwrap();
            repair_index(&mut idx, &log_path, log.len() as u64).expect("repair valid prefix");
            assert_eq!(fs::read(&idx_path).unwrap(), expected, "{name} tail changed valid prefix");
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_staging_ignores_legacy_symlinks_and_cleans_only_its_own_file() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("bloch-store-private-stage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x75; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let victim = dir.join("unrelated-file");
        fs::write(&victim, b"must remain intact").unwrap();
        let legacy = dir.join("blocks.log.tmp");
        symlink(&victim, &legacy).unwrap();
        store.rewrite(&[sample_envelope(100)]).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"must remain intact");
        assert!(fs::symlink_metadata(&legacy).unwrap().file_type().is_symlink());
        assert_eq!(fs::metadata(dir.join("blocks.log")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(store.read_all().unwrap()[0].header.slot, 100);
        let destination = dir.join("abandoned-state");
        let staging = PrivateStagingFile::create_for(&destination).unwrap();
        let owned = staging.path.clone().unwrap();
        assert!(owned.exists());
        drop(staging);
        assert!(!owned.exists());
        assert!(legacy.is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"must remain intact");
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rewrite_refuses_before_publication_if_index_cannot_be_invalidated() {
        let dir = std::env::temp_dir().join(format!("bloch-store-index-invalidate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x74; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let before = fs::read(dir.join("blocks.log")).unwrap();
        // A real read-only descriptor forces set_len failure before log rename.
        store.idx = File::open(dir.join("blocks.idx")).unwrap();
        assert!(store.rewrite(&[sample_envelope(100)]).is_err());
        assert_eq!(fs::read(dir.join("blocks.log")).unwrap(), before);
        let page = Store::blocks_after(&dir, 0, 10).unwrap();
        assert_eq!(crate::codec::decode_envelope(&page[0]).unwrap().header.slot, 1);
        drop(store);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generation_guards_share_aliases_but_not_unrelated_stores() {
        let first = std::env::temp_dir().join(format!("bloch-store-generation-a-{}", std::process::id()));
        let second = std::env::temp_dir().join(format!("bloch-store-generation-b-{}", std::process::id()));
        fs::create_dir_all(&first).unwrap(); fs::create_dir_all(&second).unwrap();
        let a = log_generation(&first).unwrap();
        let alias = log_generation(&first.join(".")).unwrap();
        let b = log_generation(&second).unwrap();
        assert!(std::sync::Arc::ptr_eq(&a, &alias));
        assert!(!std::sync::Arc::ptr_eq(&a, &b));
        let held = a.write().unwrap();
        assert!(alias.try_read().is_err());
        assert!(b.try_read().is_ok(), "one store's rewrite must not block unrelated serving");
        drop(held); drop(a); drop(alias); drop(b);
        let _ = fs::remove_dir_all(first); let _ = fs::remove_dir_all(second);
    }

    #[test]
    fn asynchronous_rewrite_publishes_then_orders_the_next_append() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-store-async-rewrite-order-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x72; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();

        store.rewrite_async(vec![sample_envelope(100), sample_envelope(200)]).unwrap();
        // `append` must join the writer before it writes. This pins the
        // generation ordering even when the normal loop has not polled yet.
        store.append(&sample_envelope(300)).unwrap();
        assert!(store.poll_rewrite().unwrap(), "joined completion remains observable");
        assert!(!store.poll_rewrite().unwrap(), "completion is reported once");

        let slots: Vec<_> = store.read_all().unwrap().into_iter()
            .map(|env| env.header.slot).collect();
        assert_eq!(slots, vec![100, 200, 300]);
        let served: Vec<_> = Store::blocks_after(&dir, 0, 10).unwrap().into_iter()
            .map(|bytes| crate::codec::decode_envelope(&bytes).unwrap().header.slot)
            .collect();
        assert_eq!(served, slots, "rebuilt index and authoritative log agree");
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn asynchronous_rewrite_returns_before_durable_publication() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-store-async-rewrite-responsive-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x69; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let generation = std::sync::Arc::clone(&store.generation);
        let reader = generation.read().unwrap();

        // The writer can stage, but cannot enter its publication transaction
        // while this reader holds the generation. Returning here proves the
        // caller did not perform or wait for durable publication itself.
        store.rewrite_async(vec![sample_envelope(100)]).unwrap();
        assert!(store.rewrite_pending());
        assert!(!store.poll_rewrite().unwrap());
        drop(reader);
        while !store.poll_rewrite().unwrap() {
            std::thread::yield_now();
        }
        assert_eq!(store.read_all().unwrap()[0].header.slot, 100);
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn asynchronous_rewrite_reports_failure_without_replacing_the_log() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-store-async-rewrite-failure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x71; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let before_log = fs::read(dir.join("blocks.log")).unwrap();
        let before_index = fs::read(dir.join("blocks.idx")).unwrap();
        let mut oversized = sample_envelope(2);
        oversized.proposer_sig.resize(crate::codec::MAX_FIELD_LEN, 0xAA);

        store.rewrite_async(vec![oversized]).unwrap();
        let error = loop {
            match store.poll_rewrite() {
                Ok(false) => std::thread::yield_now(),
                Ok(true) => panic!("oversized asynchronous rewrite succeeded"),
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(dir.join("blocks.log")).unwrap(), before_log);
        assert_eq!(fs::read(dir.join("blocks.idx")).unwrap(), before_index);
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dropping_store_joins_the_reorg_writer_before_releasing_the_directory() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-store-async-rewrite-drop-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x70; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        let replacement: Vec<_> = (100..400).map(sample_envelope).collect();
        store.rewrite_async(replacement).unwrap();
        drop(store); // must not release DirLock while the worker still writes

        let reopened = Store::open(&dir, &[0x70; 32]).unwrap();
        let frames = reopened.read_all().unwrap();
        assert_eq!(frames.len(), 300);
        assert_eq!(frames.first().unwrap().header.slot, 100);
        assert_eq!(frames.last().unwrap().header.slot, 399);
        drop(reopened);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_rebuilds_same_length_index_left_by_interrupted_reorg() {
        let dir = std::env::temp_dir().join(format!("bloch-store-reorg-index-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x73; 32]).unwrap();
        store.append(&sample_envelope(1)).unwrap();
        store.append(&sample_envelope(2)).unwrap();
        let old_index = fs::read(dir.join("blocks.idx")).unwrap();
        let old_length = fs::metadata(dir.join("blocks.log")).unwrap().len();
        store.rewrite(&[sample_envelope(100), sample_envelope(200)]).unwrap();
        assert_eq!(fs::metadata(dir.join("blocks.log")).unwrap().len(), old_length);
        drop(store);
        // Exact crash residue: replacement log was published, old index had
        // not yet been invalidated. Its offsets and covered length still fit.
        fs::write(dir.join("blocks.idx"), old_index).unwrap();
        let store = Store::open(&dir, &[0x73; 32]).unwrap();
        let page = Store::blocks_after(&dir, 50, 10).unwrap();
        let slots: Vec<_> = page.iter().map(|bytes| crate::codec::decode_envelope(bytes).unwrap().header.slot).collect();
        drop(store);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(slots, vec![100, 200], "an index from the old log must not hide replacement blocks");
    }

    #[test]
    fn audit_log_diagnostic_is_bounded_and_does_not_repair_or_hide_corruption() {
        let dir = std::env::temp_dir().join(format!("bloch-store-diagnostic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocks.log");
        let payload = crate::codec::encode_envelope(&sample_envelope(1));
        let mut valid = (payload.len() as u32).to_le_bytes().to_vec();
        valid.extend_from_slice(&payload);
        fs::write(&path, &valid).unwrap();
        let good = inspect_log(&dir).unwrap();
        assert_eq!(good.decoded_frames, 1);
        assert_eq!(good.valid_prefix_bytes, valid.len() as u64);
        assert_eq!(good.issue, None);
        for suffix in [&[0u8][..], &[0u8; 4][..], &[255u8; 4][..], &[5, 0, 0, 0, 1][..]] {
            let mut damaged = valid.clone();
            damaged.extend_from_slice(suffix);
            fs::write(&path, &damaged).unwrap();
            let report = inspect_log(&dir).unwrap();
            assert_eq!(report.decoded_frames, 1);
            assert_eq!(report.valid_prefix_bytes, valid.len() as u64);
            assert!(report.issue.is_some());
            assert_eq!(fs::read(&path).unwrap(), damaged);
            assert!(!dir.join("LOCK").exists());
            assert!(!dir.join("blocks.idx").exists());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn offline_tail_repair_backs_up_only_confirmed_incomplete_or_zero_suffixes() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-store-tail-repair-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blocks.log");
        let payload = crate::codec::encode_envelope(&sample_envelope(1));
        let mut valid = (payload.len() as u32).to_le_bytes().to_vec();
        valid.extend_from_slice(&payload);

        let mut damaged = valid.clone();
        damaged.extend_from_slice(&[0u8; 12]);
        fs::write(&path, &damaged).unwrap();
        let backup = dir.join("zero-tail.backup");
        let live_lock = DirLock::acquire(&dir).unwrap();
        let live_error =
            repair_log_tail_offline(&dir, valid.len() as u64, &backup).unwrap_err();
        assert_eq!(live_error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(fs::read(&path).unwrap(), damaged);
        assert!(!backup.exists());
        drop(live_lock);

        let repaired = repair_log_tail_offline(&dir, valid.len() as u64, &backup).unwrap();
        assert_eq!(repaired.retained_bytes, valid.len() as u64);
        assert_eq!(repaired.backup_bytes, 12);
        assert_eq!(fs::read(&path).unwrap(), valid);
        assert_eq!(fs::read(&backup).unwrap(), [0u8; 12]);

        fs::write(&path, &damaged).unwrap();
        let existing = repair_log_tail_offline(&dir, valid.len() as u64, &backup).unwrap_err();
        assert_eq!(existing.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), damaged);

        let mut corrupt = valid.clone();
        corrupt.extend_from_slice(&[1, 0, 0, 0, 0xff]);
        fs::write(&path, &corrupt).unwrap();
        let refused_backup = dir.join("corrupt-tail.backup");
        let error =
            repair_log_tail_offline(&dir, valid.len() as u64, &refused_backup).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        assert!(!refused_backup.exists());

        let mut incomplete = valid.clone();
        incomplete.extend_from_slice(&[5, 0, 0, 0, 0xaa]);
        fs::write(&path, &incomplete).unwrap();
        let incomplete_backup = dir.join("incomplete-tail.backup");
        repair_log_tail_offline(&dir, valid.len() as u64, &incomplete_backup).unwrap();
        assert_eq!(fs::read(&path).unwrap(), valid);
        assert_eq!(fs::read(&incomplete_backup).unwrap(), [5, 0, 0, 0, 0xaa]);
        fs::remove_dir_all(dir).unwrap();
    }

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

    #[test]
    fn fixed_header_scan_preserves_skipped_and_served_frames_exactly() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-pos-fixed-header-scan-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x89; 32]).expect("open");
        let mut logged = Vec::new();
        for slot in 1..=6u64 {
            let mut env = sample_envelope(slot);
            env.proposer_sig = vec![slot as u8; slot as usize * 257];
            logged.push(crate::codec::encode_envelope(&env));
            store.append(&env).expect("append");
        }
        drop(store);

        let headers_before = sync_frames_scanned();
        let bodies_before = sync_body_bytes_read();
        let page = Store::scan_page(
            &dir.join("blocks.log"),
            0,
            None,
            3,
            100,
            MAX_UNINDEXED_TAIL_SCAN_FRAMES,
            PageBytes { max: crate::codec::MAX_FIELD_LEN, per_frame: 0, first_must_fit: false },
        )
        .expect("bounded scan")
        .expect("no index mismatch in an unindexed scan");

        assert_eq!(page, logged[3..], "served frames must remain byte-for-byte exact");
        assert_eq!(
            sync_frames_scanned() - headers_before,
            logged.len() as u64,
            "three skipped and three served frames must each parse exactly one header",
        );
        let header_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
        let returned_body_bytes: u64 = logged[3..]
            .iter()
            .map(|frame| frame.len().saturating_sub(header_len) as u64)
            .sum();
        assert_eq!(
            sync_body_bytes_read() - bodies_before,
            returned_body_bytes,
            "skipped bodies must remain seek-only while served bodies are read exactly once",
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn p2p_byte_preflight_matches_postfilter_and_skips_the_boundary_body() {
        let dir = std::env::temp_dir().join(format!("bloch-p2p-page-boundary-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x4A; 32]).expect("open");
        let first = sample_envelope(1);
        let mut second = sample_envelope(2);
        second.proposer_sig.extend_from_slice(&[0x5B; 257]);
        let first_bytes = crate::codec::encode_envelope(&first);
        let second_bytes = crate::codec::encode_envelope(&second);
        store.append(&first).expect("append first");
        store.append(&second).expect("append second");

        let overhead = 4usize;
        let exact_cap = first_bytes.len().saturating_add(overhead);
        let generic = Store::blocks_after(&dir, 0, 10).expect("generic page");
        assert_eq!(generic, vec![first_bytes.clone(), second_bytes]);
        let mut charged = 0usize;
        let oracle: Vec<_> = generic.into_iter().take_while(|frame| {
            let next = charged.saturating_add(frame.len()).saturating_add(overhead);
            if next > exact_cap { false } else { charged = next; true }
        }).collect();

        let headers_before = sync_frames_scanned();
        let bodies_before = sync_body_bytes_read();
        let bounded = Store::blocks_after_p2p(&dir, 0, 10, exact_cap, overhead).expect("bounded page");
        assert_eq!(bounded, oracle, "preflight must return the old post-filter prefix");
        assert_eq!(bounded, vec![first_bytes.clone()], "equality is admitted; the next frame is not");
        assert_eq!(sync_frames_scanned() - headers_before, 2, "only the rejected frame's header is needed");
        let header_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
        assert_eq!(
            sync_body_bytes_read() - bodies_before,
            first_bytes.len().saturating_sub(header_len) as u64,
            "the body rejected at the boundary must not be read",
        );

        let bodies_before = sync_body_bytes_read();
        let plus_one = Store::blocks_after_p2p(&dir, 0, 10, exact_cap.saturating_sub(1), overhead)
            .expect("one byte over");
        assert!(plus_one.is_empty(), "a first frame one byte over is refused");
        assert_eq!(sync_body_bytes_read() - bodies_before, 0, "a refused first body stays unread");

        drop(store);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn p2p_real_cap_first_oversized_is_empty_but_generic_wrapper_still_serves_it() {
        let dir = std::env::temp_dir().join(format!("bloch-p2p-first-oversized-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x4B; 32]).expect("open");
        let max = (crate::p2p::MAX_SYNC_FRAME as usize).saturating_sub(1024);
        let target_len = max.saturating_sub(4).saturating_add(1);
        let mut oversized = sample_envelope(1);
        let base = crate::codec::encode_envelope(&oversized).len();
        oversized.proposer_sig.resize(
            oversized.proposer_sig.len().saturating_add(target_len.saturating_sub(base)),
            0x6C,
        );
        let encoded = crate::codec::encode_envelope(&oversized);
        assert_eq!(encoded.len().saturating_add(4), max.saturating_add(1));
        assert!(encoded.len() <= crate::codec::MAX_FIELD_LEN);
        store.append(&oversized).expect("append historical frame");

        assert_eq!(
            Store::blocks_after(&dir, 0, 1).expect("generic page"),
            vec![encoded],
            "the public store/devnet first-frame behavior is unchanged",
        );
        let bodies_before = sync_body_bytes_read();
        let bounded = Store::blocks_after_p2p(&dir, 0, 1, max, 4).expect("p2p page");
        assert!(bounded.is_empty(), "the old p2p post-filter returned an empty page here");
        assert_eq!(sync_body_bytes_read() - bodies_before, 0, "the oversized first body stays unread");

        drop(store);
        let _ = fs::remove_dir_all(&dir);
    }

    /// **The data-dir lock.** A second `Store::open` over a dir this process
    /// already holds is refused.
    ///
    /// This is the concurrent half of slashing protection, and it is the half
    /// nothing in this node had. Two `bloch-pos` processes over one data dir
    /// share one keystore, reach the same duty and both sign it — the exact
    /// pair `slashing.rs` turns into a stake burn. Remove the
    /// `DirLock::acquire` line from `Store::open` and this test fails: the
    /// second open succeeds and returns a happily writable store.
    ///
    /// Same-process is what a unit test can drive, and it is not a weaker
    /// claim than cross-process: `flock` is held by the open file description,
    /// so a second descriptor conflicts whoever opened it.
    #[test]
    fn a_second_open_of_a_live_data_dir_is_refused() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let first = Store::open(&dir, &[3u8; 32]).expect("the first open takes the dir");
        assert!(dir.join("LOCK").exists(), "the lock is a visible artifact, on purpose");

        let second = Store::open(&dir, &[3u8; 32]);
        let err = second.err().expect(
            "a second process over one data dir holds one keystore and double-signs; \
             the second open must be refused",
        );
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "got: {err}");

        // Releasing it makes the dir usable again — a lock that never lets go
        // would just be a different outage. On unix the FILE stays: the lock
        // is the flock on its inode, and unlinking the path was the H-1 race
        // (see the next test). Reopening must therefore succeed WITH the
        // file present.
        drop(first);
        if cfg!(unix) {
            assert!(
                dir.join("LOCK").exists(),
                "H-1: a clean shutdown must NOT unlink the lock file on unix — the unlink is \
                 what let a pre-opened descriptor flock an orphan inode"
            );
        }
        let reopened = Store::open(&dir, &[3u8; 32]).expect("reopen after a clean release");
        drop(reopened);

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

    /// A `LOCK` left behind by a process that is gone must not brick the node.
    ///
    /// The counterpart to the test above, and the reason this is `flock` and
    /// not a bare lock file: refusing to boot after every crash teaches
    /// operators to delete the lock by reflex, which is how the protection
    /// gets removed on the day it matters.
    #[cfg(unix)]
    #[test]
    fn a_stale_lock_from_a_dead_process_is_reclaimed() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        // What a killed node leaves: the file, nobody holding it.
        fs::write(dir.join("LOCK"), b"999999\n").expect("write a stale lock");

        let store = Store::open(&dir, &[4u8; 32]).expect("a stale lock must be reclaimed");
        drop(store);

        let _ = fs::remove_dir_all(&dir);
    }

    /// **THE regression test for H-1 (audit round 3).** The open-then-unlink
    /// race, driven with two descriptors in one process, which is exactly the
    /// shape `flock` sees across processes.
    ///
    /// Process B opens the existing `LOCK` while A holds it (B has not yet
    /// flocked). A shuts down cleanly. B now takes the flock. C boots. With
    /// the old `Drop` (unlink on clean shutdown) A's release orphaned the
    /// inode B holds, so C's `create_new` made a fresh inode and C's flock
    /// succeeded: B and C both ran over one keystore. Without the unlink, C
    /// opens the same inode B holds and is refused.
    ///
    /// Restore `fs::remove_file(&self.path)` in a unix `Drop` and this test
    /// fails at the last assertion.
    #[cfg(unix)]
    #[test]
    fn a_pre_opened_descriptor_cannot_outlive_the_holder_into_a_second_node() {
        use std::os::unix::io::AsRawFd;
        let dir = std::env::temp_dir().join(format!("bloch-pos-h1-race-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("LOCK");

        let a = DirLock::acquire(&dir).expect("A takes the lock");
        // B: opened the existing path while A holds it, not yet flocked.
        let b = OpenOptions::new().write(true).open(&path).expect("B opens the live lock path");
        drop(a); // A shuts down cleanly.
        // B flocks whatever inode it opened. Under the old design this was an
        // orphan; under the new one it is the inode the path still names.
        let rc = unsafe { libc::flock(b.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "B takes the flock after A released it");

        // C boots. It must see B.
        let c = DirLock::acquire(&dir);
        let err = match c {
            Ok(_) => panic!(
                "H-1 regression: a third node acquired the data dir while a second holds the \
                 flock — the lock file was unlinked and re-created"
            ),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "got: {err}");

        drop(b);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A lock taken on an inode the path no longer names is worthless and is
    /// reported as such, so `acquire` retries against the current file rather
    /// than returning a "lock" nobody else can contend for.
    ///
    /// Drives the verification step directly: open, then unlink underneath
    /// it (an operator's `rm LOCK`, or an older binary's `Drop`), then lock.
    #[cfg(unix)]
    #[test]
    fn a_lock_on_an_unlinked_inode_is_reported_orphaned_and_reacquired() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-h1-orphan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("LOCK");

        let (file, fresh) = open_lock_file(&path).expect("open").expect("present");
        assert!(fresh);
        fs::remove_file(&path).expect("unlink underneath the open descriptor");
        match lock_and_verify(file, &path, fresh).expect("flock itself succeeds") {
            Locked::Held(_) => panic!("a flock on an orphan inode must not count as held"),
            Locked::Orphaned => {}
        }

        // And the public entry point recovers by itself: the path is free, so
        // the retry creates and locks a fresh inode that the path DOES name.
        let lock = DirLock::acquire(&dir).expect("acquire recovers from the orphan");
        assert!(path.exists());
        drop(lock);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The lock file is a stable artifact across releases (unix): two clean
    /// shutdowns in a row leave it in place and both reacquisitions succeed.
    #[cfg(unix)]
    #[test]
    fn the_lock_file_persists_across_clean_releases() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-h1-persist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        for _ in 0..3 {
            let lock = DirLock::acquire(&dir).expect("acquire");
            assert!(lock.path().exists());
            drop(lock);
            assert!(dir.join("LOCK").exists(), "clean release keeps the file (H-1)");
        }
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

    #[test]
    fn an_excessive_unindexed_tail_fails_at_the_scan_bound() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-pos-idx-tail-bound-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[15u8; 32]).expect("open");
        for slot in 1..=4u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }
        drop(store);

        // Leave one indexed frame and three valid log frames beyond it. The
        // production allowance is intentionally generous, so inject a bound
        // of two here to reach the same branch without creating thousands of
        // fsynced blocks in a unit test.
        let idx_path = dir.join("blocks.idx");
        let idx = OpenOptions::new().write(true).open(&idx_path).expect("open idx");
        idx.set_len(8 + IDX_ENTRY_LEN).expect("truncate idx");
        drop(idx);
        let mut idx = File::open(&idx_path).expect("read idx");
        let covered = idx_read(&mut idx, 0).expect("first record").end();

        let before = sync_frames_scanned();
        let error = Store::scan_page(
            &dir.join("blocks.log"),
            covered,
            None,
            u64::MAX,
            100,
            2,
            PageBytes { max: crate::codec::MAX_FIELD_LEN, per_frame: 0, first_must_fit: false },
        )
        .expect_err("the third unindexed frame must exceed the injected bound");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("restart to rebuild the derived index"));
        assert_eq!(
            sync_frames_scanned() - before,
            2,
            "the frame past the allowance must not have its header parsed",
        );

        // The same valid tail remains below the production allowance and is
        // served unchanged, preserving the ordinary one-append crash window.
        let page = Store::blocks_after(&dir, 1, 100).expect("short tail remains compatible");
        assert_eq!(page.len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    /// An index that points somewhere the log does not agree with is a local
    /// fault, not a source of truth and not permission for a remote caller to
    /// trigger a whole-history scan. Restart/open repairs the disposable
    /// index.
    #[test]
    fn a_lying_index_fails_boundedly_until_restart_rebuilds_it() {
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

        let before = sync_frames_scanned();
        let error = Store::blocks_after(&dir, 5, 100).unwrap_err();
        let scanned = sync_frames_scanned() - before;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("restart to rebuild"));
        assert!(scanned <= 1, "corrupt index reopened a whole-log scan: {scanned} frames");

        let store = Store::open(&dir, &[13u8; 32]).expect("restart rebuild");
        let page = Store::blocks_after(&dir, 5, 100).expect("serve after rebuild");
        assert_eq!(page, logged[5..], "rebuild changed the authoritative log answer");
        drop(store);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_or_bad_magic_index_never_reopens_the_full_scan() {
        let dir = std::env::temp_dir().join(format!("bloch-pos-idx-unusable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[0x13; 32]).expect("open");
        for slot in 1..=64u64 {
            store.append(&sample_envelope(slot)).expect("append");
        }
        drop(store);

        for replacement in [None, Some(b"BADINDEX".as_slice()), Some(IDX_MAGIC.as_slice())] {
            let idx_path = dir.join("blocks.idx");
            match replacement {
                None => fs::remove_file(&idx_path).expect("remove index"),
                Some(bytes) => fs::write(&idx_path, bytes).expect("replace index"),
            }
            let before = sync_frames_scanned();
            let error = Store::blocks_after(&dir, 32, 16).unwrap_err();
            assert!(matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::InvalidData));
            assert_eq!(
                sync_frames_scanned() - before,
                0,
                "unusable index must fail before any log-header scan"
            );
            let rebuilt = Store::open(&dir, &[0x13; 32]).expect("rebuild index on restart");
            drop(rebuilt);
        }

        let page = Store::blocks_after(&dir, 60, 16).expect("serve after rebuild");
        assert_eq!(page.len(), 4);
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

    #[test]
    fn recovery_never_truncates_indexed_history_after_length_corruption() {
        let dir = std::env::temp_dir().join(format!("bloch-length-corrupt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        {
            let mut store = Store::open(&dir, &[0; 32]).unwrap();
            store.append(&sample_envelope(1)).unwrap();
            store.append(&sample_envelope(2)).unwrap();
        }
        let path = dir.join("blocks.log");
        let mut bytes = fs::read(&path).unwrap();
        let corrupt_length = (bytes.len() + 1) as u32;
        bytes[..4].copy_from_slice(&corrupt_length.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert!(Store::open(&dir, &[0; 32]).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restart_repairs_torn_tail_before_accepting_new_blocks() {
        for tail in [vec![4u8, 0], vec![100, 0, 0, 0, 42]] {
            let dir = std::env::temp_dir().join(format!("bloch-tail-{}-{}", std::process::id(), tail.len()));
            let _ = fs::remove_dir_all(&dir);
            {
                let mut store = Store::open(&dir, &[0; 32]).unwrap();
                store.append(&sample_envelope(1)).unwrap();
            }
            OpenOptions::new().append(true).open(dir.join("blocks.log")).unwrap().write_all(&tail).unwrap();
            {
                let mut store = Store::open(&dir, &[0; 32]).unwrap();
                store.append(&sample_envelope(2)).unwrap();
                let blocks = store.read_all().unwrap();
                assert_eq!(blocks.iter().map(|b| b.header.slot).collect::<Vec<_>>(), vec![1, 2]);
            }
            let store = Store::open(&dir, &[0; 32]).unwrap();
            assert_eq!(store.read_all().unwrap().len(), 2);
            drop(store); fs::remove_dir_all(dir).unwrap();
        }
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
