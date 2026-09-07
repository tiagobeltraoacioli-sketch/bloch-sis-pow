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
        // is the same "distrust the index, fall back to a full scan"
        // behaviour those callers already give a merely-stale index.
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
        // `at` and `len` are both positions/lengths within a real file on
        // disk (`at <= log_len` is this loop's own invariant, re-established
        // below; `len <= MAX_FIELD_LEN` was just checked), so this cannot
        // overflow in practice — `checked_add` makes that explicit rather
        // than assumed, and treats the unreachable overflow case exactly
        // like a truncated trailing frame: stop indexing, the full scan in
        // `blocks_after` remains the authority.
        let Some(frame_end) = at.checked_add(4).and_then(|v| v.checked_add(len as u64)) else {
            break;
        };
        if frame_end > log_len {
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
        let tail = scan_index(log_path, covered)?;
        // Capacity hint only: saturating is the intended semantics (a
        // saturated hint under-reserves, it does not corrupt the buffer).
        let mut buf = Vec::with_capacity(tail.len().saturating_mul(IDX_ENTRY_LEN as usize));
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
    /// Bytes in `blocks.log`, so an append knows the offset it is writing at
    /// without asking the filesystem.
    log_len: u64,
    /// Exclusive ownership of `dir`, held for as long as the store is. Never
    /// read; its `Drop` is the whole point. See [`DirLock`].
    _lock: DirLock,
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

impl Store {
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
        Ok(Store { dir: dir.to_path_buf(), log, idx, log_len, _lock })
    }

    /// Append one applied block. One write, then fsync — the block is only
    /// broadcast after this returns, so anything the network has seen from
    /// us is durable locally (the producer-side equivocation fence across
    /// restarts).
    pub fn append(&mut self, env: &BlockEnvelope) -> io::Result<()> {
        let payload = crate::codec::encode_envelope(env);
        // Capacity hint only: saturating is the intended semantics.
        let mut frame = Vec::with_capacity(4usize.saturating_add(payload.len()));
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
        // `log_len` tracks bytes actually fsynced to `blocks.log` on this
        // disk; reaching anywhere near u64::MAX (18 exabytes) is not a
        // condition a real deployment's storage can produce.
        #[allow(clippy::arithmetic_side_effects)]
        {
            self.log_len += frame.len() as u64;
        }
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
        // `at` never exceeds `bytes.len()` (it only ever advances to a value
        // already checked against `bytes.len()` below), and `bytes.len()` is
        // this process's own in-memory copy of one local file — nowhere near
        // `usize::MAX`. So every `saturating_add` here is exact, never an
        // actual saturation; it is used instead of `+` purely to keep this
        // loop over on-disk bytes free of raw arithmetic operators clippy
        // must otherwise trust are pre-bounded.
        while bytes.len().saturating_sub(at) >= 4 {
            let body_at = at.saturating_add(4);
            // `body_at - at == 4` exactly (see above), so this slice is
            // always exactly 4 bytes and `try_into` cannot fail; the `else`
            // arm is unreachable but keeps the conversion panic-free by
            // construction.
            let Ok(len_bytes) = bytes[at..body_at].try_into() else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt log length prefix"));
            };
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > crate::codec::MAX_FIELD_LEN {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame over cap"));
            }
            let frame_end = body_at.saturating_add(len);
            if frame_end > bytes.len() {
                eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
                break;
            }
            let env = crate::codec::decode_envelope(&bytes[body_at..frame_end])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            out.push(env);
            at = frame_end;
        }
        if at.saturating_add(4) > bytes.len() && at < bytes.len() {
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
        // The rename must be durable too, or a crash can resurrect the
        // pre-reorg log (M-6). Same discipline as slashprot's watermark write.
        fsync_dir(&self.dir)?;
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
                // Wanted: read the body and hand back the whole frame, byte
                // for byte identical to what the old path pushed.
                let mut payload = hdr_buf;
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
