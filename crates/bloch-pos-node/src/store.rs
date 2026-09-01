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
//!
//! ## What the file is allowed to be
//!
//! Three methods write it — [`Store::append`] extends it, [`Store::rewrite`]
//! replaces it wholesale, [`Store::replace_tail`] swaps its tail — and between
//! clean returns from those, `blocks.log` is exactly `chain[1..]` (genesis is
//! synthesized, never logged).
//!
//! Across a crash that equality does not hold and never did: `append` is
//! called once per block, so a crash partway through a multi-block extension
//! already leaves a strict prefix. The rule that survives a crash, and the one
//! boot actually depends on, is weaker and covers all three writers:
//!
//! > `blocks.log` is a **prefix** of `chain[1..]` for some chain this node
//! > validated, followed by at most one torn frame.
//!
//! Torn frames are dropped by [`LogReader`] and [`Store::count`] alike. What
//! the rule forbids is a log **spliced** from two branches — frames of one
//! chain sitting under frames of another. Replay would not reject that; it
//! would stop applying at the seam and boot to a wrong head, silently. Keeping
//! it impossible is why `replace_tail` makes its truncation durable before it
//! writes past it, and why `rewrite` builds a temp file and renames.

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

    /// Keep the log's first `keep` frames, drop the rest, and append `tail` —
    /// a reorg as a **write of the branch**, not a rewrite of the chain.
    ///
    /// # Why this exists
    ///
    /// [`Store::rewrite`] re-encodes and re-writes every canonical block on
    /// every reorg. A reorg cannot change a block below the fork point, so
    /// every byte under it is written back identical to the byte already
    /// there — work whose size is the chain's, not the reorg's.
    ///
    /// **What that costs, and how often it is paid, are two separate
    /// questions and only the first one is settled here.** The cost is
    /// measured by `reorg_write_cost_on_a_real_log`, which runs both paths
    /// over a real data dir and prints the pair; the numbers it produced, the
    /// box they were produced on, and the command to reproduce them are in
    /// `docs/perf/REORG-WRITE-PATH.md`. Do not quote a figure for this that
    /// does not come from a run of that test — the reorg *rate* on the live
    /// fleet is recorded in the same file, from `journalctl`, and it is the
    /// number that decides whether the cost matters at all.
    ///
    /// # The precondition, checked rather than assumed
    ///
    /// A truncate-and-append is only correct if the log's first `keep` frames
    /// really are the chain's first `keep` blocks. `rewrite` never needed that
    /// to be true — it wrote the whole answer from the caller's own data — so
    /// nothing in this file has ever had to verify it. This does, on every
    /// call and from the bytes on disk: `last_kept` is the envelope the caller
    /// believes frame `keep - 1` holds, and the frame is read back and
    /// compared to it byte for byte before anything is truncated. One ~14 KB
    /// read against a whole-log write is not a cost; it is what turns "the frame
    /// table is in step with the chain" from an invariant into a test that
    /// runs in production. A mismatch is an `Err` and **the file is not
    /// touched** — `do_reorg` then falls back to `rewrite`, which needs no
    /// such precondition, so the worst case is exactly today's behaviour.
    ///
    /// # Crash safety
    ///
    /// The shrink is made durable (`sync_all`, metadata included) *before* a
    /// single byte is written past it. That ordering is the whole argument.
    /// Without it a crash could leave the old size with new frames written
    /// into the middle of it — a log spliced from two branches, which replay
    /// does not reject; it would silently stop applying and boot to a wrong
    /// head. With it, the reachable on-disk states are:
    ///
    /// ```text
    ///   truncate not durable    old chain, whole              (as before)
    ///   truncate durable        new chain's first `keep`      prefix
    ///   k of n tail frames      new chain's first keep+k      prefix
    ///   complete                new chain, whole              (as before)
    /// ```
    ///
    /// Every one is a **prefix of a chain this node validated**, optionally
    /// followed by one torn frame — and that is not a new class of state to
    /// recover from. [`Store::append`] already produces exactly it: a crash
    /// partway through applying a multi-block extension leaves a strict prefix
    /// too. So `blocks.log == chain[1..]` was never a crash-time invariant,
    /// only a clean-return one, and this preserves the clean-return one
    /// unchanged. What replaces the rest is:
    ///
    /// > **On disk, `blocks.log` is always a prefix of `chain[1..]` for some
    /// > chain this node held, plus at most one torn trailing frame.**
    ///
    /// Boot's contract already meets it: replay applies the frames that are
    /// there, lands on that prefix's head, and syncs forward — which is what
    /// a node that was merely behind does anyway. `a_kill_between_truncate_and_append_boots`
    /// is where this is demonstrated by killing the process rather than
    /// asserted in a comment.
    pub fn replace_tail<'a, I>(
        &mut self,
        keep: usize,
        last_kept: Option<&BlockEnvelope>,
        tail: I,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = &'a BlockEnvelope>,
    {
        // Held across the whole splice, so no reader can take a snapshot of
        // the table while the file it describes is half-changed.
        let mut idx = self
            .frames
            .write()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "frame table lock poisoned"))?;

        if keep > idx.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("reorg keeps {keep} frames but the log has {}", idx.len()),
            ));
        }
        let cut_at = match keep.checked_sub(1) {
            // Reorg back to genesis: genesis is synthesized and never logged,
            // so the whole file goes.
            None => 0u64,
            Some(last) => {
                let fr = idx[last];
                let env = last_kept.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "replace_tail needs the block it is cutting after",
                    )
                })?;
                let payload = crate::codec::encode_envelope(env);
                if fr.slot != env.header.slot || fr.len as usize != payload.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "frame {last} is slot {} / {} bytes, chain says slot {} / {} bytes",
                            fr.slot,
                            fr.len,
                            env.header.slot,
                            payload.len()
                        ),
                    ));
                }
                let mut on_disk = vec![0u8; payload.len()];
                self.log.seek(SeekFrom::Start(fr.offset))?;
                self.log.read_exact(&mut on_disk)?;
                if on_disk != payload {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("frame {last} on disk is not the block the chain names"),
                    ));
                }
                fr.offset + fr.len as u64
            }
        };

        // ── Shrink, durably, before anything is written past the cut ──
        if cut_at < self.log.metadata()?.len() {
            self.log.set_len(cut_at)?;
            // sync_all, not sync_data: it is the SIZE that has to survive.
            self.log.sync_all()?;
        }
        idx.truncate(keep);

        // ── Append the branch ──
        //
        // The handle is `O_APPEND`, so every write lands at the end of the
        // file the truncation just defined; the offsets recorded here are
        // computed from that same cut and are checked against a fresh scan by
        // `the_table_after_a_splice_matches_a_fresh_scan`.
        let mut at = cut_at;
        let mut wrote = false;
        for env in tail {
            let payload = crate::codec::encode_envelope(env);
            let mut frame = Vec::with_capacity(4 + payload.len());
            frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            frame.extend_from_slice(&payload);
            self.log.write_all(&frame)?;
            idx.push(FrameRef {
                slot: env.header.slot,
                offset: at + 4,
                len: payload.len() as u32,
            });
            at += frame.len() as u64;
            wrote = true;
        }
        if wrote {
            self.log.sync_data()?;
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


    // ── `replace_tail`: the reorg write path ────────────────────────────────

    /// Build a log of slots 1..=n and hand back the store.
    fn logged(tag: &str, n: u64) -> (PathBuf, Store) {
        let dir = tmpdir(tag);
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
        for slot in 1..=n {
            store.append(&sample_envelope(slot)).expect("append");
        }
        (dir, store)
    }

    /// **The equivalence that lets the fast path replace the slow one.**
    ///
    /// A reorg written as truncate-and-append must leave the file `rewrite`
    /// would have left — not an equivalent chain, the same bytes. Two stores
    /// are given identical histories and the same reorg by the two routes, and
    /// the files are compared whole. If the offset arithmetic is off by so
    /// much as the 4-byte length prefix this fails.
    #[test]
    fn a_spliced_tail_is_byte_identical_to_a_full_rewrite() {
        for keep in [0usize, 1, 4, 7] {
            let (fast_dir, mut fast) = logged(&format!("splice-fast-{keep}"), 7);
            let (slow_dir, mut slow) = logged(&format!("splice-slow-{keep}"), 7);

            // The branch that wins: three blocks at slots the old tail did not
            // use, so a stale byte anywhere would show.
            let branch: Vec<BlockEnvelope> = (90..=92u64).map(sample_envelope).collect();
            let kept: Vec<BlockEnvelope> = (1..=keep as u64).map(sample_envelope).collect();

            let last_kept = kept.last();
            fast.replace_tail(keep, last_kept, branch.iter()).expect("splice");

            let whole: Vec<BlockEnvelope> =
                kept.iter().chain(branch.iter()).cloned().collect();
            slow.rewrite(whole.iter()).expect("rewrite");

            assert_eq!(
                fs::read(fast_dir.join("blocks.log")).expect("read fast"),
                fs::read(slow_dir.join("blocks.log")).expect("read slow"),
                "keep={keep}: the spliced log is not the rewritten log, byte for byte"
            );
            let _ = fs::remove_dir_all(&fast_dir);
            let _ = fs::remove_dir_all(&slow_dir);
        }
    }

    /// The frame table must describe the file the splice produced, and the
    /// only trustworthy judge of that is a fresh walk of the bytes. The table
    /// is patched in place (truncate + push) rather than rebuilt, which is the
    /// whole point of reusing it — and also the only way it could drift.
    #[test]
    fn the_table_after_a_splice_matches_a_fresh_scan() {
        let (dir, mut store) = logged("splice-table", 6);
        let branch: Vec<BlockEnvelope> = (50..=53u64).map(sample_envelope).collect();
        let kept = sample_envelope(3);
        store.replace_tail(3, Some(&kept), branch.iter()).expect("splice");

        let patched = store.index().read().expect("lock").clone();
        let scanned = scan_frames(&dir).expect("scan");
        assert_eq!(patched, scanned, "the patched table drifted from the bytes");
        assert_eq!(patched.len(), 7, "3 kept + 4 branch");

        // And a subsequent `append` still lands where the table says.
        store.append(&sample_envelope(54)).expect("append after splice");
        assert_eq!(
            store.index().read().expect("lock").clone(),
            scan_frames(&dir).expect("rescan"),
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The precondition is a **refusal**, not a warning: if the block the
    /// caller says it is cutting after is not the block on disk, nothing may
    /// be truncated. `do_reorg` reads the `Err` and falls back to `rewrite`,
    /// so a wrongly-refused splice costs speed; a wrongly-*accepted* one would
    /// cost the chain.
    #[test]
    fn a_splice_whose_precondition_fails_does_not_touch_the_file() {
        let (dir, mut store) = logged("splice-refuse", 5);
        let before = fs::read(dir.join("blocks.log")).expect("read");
        let branch: Vec<BlockEnvelope> = vec![sample_envelope(80)];

        // Wrong slot at the cut.
        let err = store
            .replace_tail(3, Some(&sample_envelope(99)), branch.iter())
            .expect_err("a mismatched cut block must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Keeping more frames than the log holds.
        let err = store
            .replace_tail(9, Some(&sample_envelope(5)), branch.iter())
            .expect_err("keeping past the end must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // A body that differs from the logged one at the same slot and length:
        // the slot/length check passes and only the byte comparison catches it.
        let mut impostor = sample_envelope(3);
        impostor.header.state_root = [0xEE; 32];
        let err = store
            .replace_tail(3, Some(&impostor), branch.iter())
            .expect_err("a same-shape different-block cut must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        assert_eq!(
            fs::read(dir.join("blocks.log")).expect("read"),
            before,
            "a refused splice wrote to the log anyway"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// **The crash window, in the file.** A kill between the truncate and the
    /// append leaves the log at the fork point — a strict prefix of the chain
    /// that was being adopted. Both walks must read it as such, and the
    /// process that boots on it must land on the fork point's head, not on a
    /// splice of two branches.
    ///
    /// Simulated here by doing the truncate and skipping the append, which is
    /// exactly what the code does in that order. `a_kill_between_truncate_and_append_boots`
    /// (tests/reorg_crash.rs) does it by actually killing a process.
    #[test]
    fn a_crash_between_truncate_and_append_leaves_a_replayable_prefix() {
        let (dir, mut store) = logged("splice-crash", 9);
        let kept = sample_envelope(4);
        // The append half is an empty iterator: truncate happens, nothing
        // follows it.
        store
            .replace_tail(4, Some(&kept), std::iter::empty::<&BlockEnvelope>())
            .expect("truncate half");
        drop(store);

        let streamed: Vec<BlockEnvelope> = LogReader::open(&dir)
            .expect("reader")
            .collect::<io::Result<_>>()
            .expect("a prefix is a valid log");
        assert_eq!(
            streamed.iter().map(|e| e.header.slot).collect::<Vec<_>>(),
            vec![1, 2, 3, 4],
            "the log is the chain up to the fork point and nothing after it"
        );
        assert_eq!(Store::count(&dir).expect("count"), 4, "and the count agrees");

        // Reopening rebuilds the table from those bytes, so the node comes up
        // consistent with what it can actually read.
        let reopened = Store::open(&dir, &[7u8; 32]).expect("reopen");
        assert_eq!(reopened.index().read().expect("lock").len(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The other half of the new window: the truncate landed and some of the
    /// branch did, with the last frame torn. Still a prefix, still readable,
    /// and the torn frame is dropped by the rules that already existed.
    #[test]
    fn a_torn_frame_in_a_spliced_tail_is_dropped_like_any_other() {
        let (dir, mut store) = logged("splice-torn", 9);
        let kept = sample_envelope(4);
        let branch: Vec<BlockEnvelope> = (70..=72u64).map(sample_envelope).collect();
        store.replace_tail(4, Some(&kept), branch.iter()).expect("splice");
        drop(store);

        let path = dir.join("blocks.log");
        let full = fs::metadata(&path).expect("meta").len();
        let frame = 4 + crate::codec::encode_envelope(&sample_envelope(72)).len() as u64;
        let f = OpenOptions::new().write(true).open(&path).expect("open rw");
        f.set_len(full - frame / 2).expect("tear the last frame");
        drop(f);

        let streamed: Vec<BlockEnvelope> = LogReader::open(&dir)
            .expect("reader")
            .collect::<io::Result<_>>()
            .expect("a torn tail is tolerated");
        assert_eq!(
            streamed.iter().map(|e| e.header.slot).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 70, 71],
            "prefix plus the branch frames that made it, minus the torn one"
        );
        assert_eq!(Store::count(&dir).expect("count"), 6, "both walks drop the same frame");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A reorg all the way back to genesis empties the log — genesis is
    /// synthesized and has no frame — and the store keeps working afterwards.
    #[test]
    fn a_splice_to_genesis_empties_the_log() {
        let (dir, mut store) = logged("splice-genesis", 5);
        let branch: Vec<BlockEnvelope> = vec![sample_envelope(1), sample_envelope(2)];
        store.replace_tail(0, None, branch.iter()).expect("splice to genesis");
        assert_eq!(
            store.read_all().expect("read").iter().map(|e| e.header.slot).collect::<Vec<_>>(),
            vec![1, 2],
        );
        assert_eq!(store.index().read().expect("lock").clone(), scan_frames(&dir).expect("scan"));

        // And an empty branch at genesis leaves an empty, still-usable log.
        store.replace_tail(0, None, std::iter::empty::<&BlockEnvelope>()).expect("splice to nothing");
        assert_eq!(fs::metadata(dir.join("blocks.log")).expect("meta").len(), 0);
        store.append(&sample_envelope(1)).expect("append onto an emptied log");
        assert_eq!(Store::count(&dir).expect("count"), 1);
        let _ = fs::remove_dir_all(&dir);
    }


    // ── The kill test ───────────────────────────────────────────────────────

    /// How the child is told which crash to stage, and where.
    const CRASH_ENV: &str = "BLOCH_STORE_CRASH_TEST";

    /// A branch iterator that ends the process partway through, so the death
    /// happens **inside** `replace_tail` — after the truncate, and after `left`
    /// frames of the branch have been written — with no crash hook anywhere in
    /// the store itself. `replace_tail` pulls the branch from an
    /// `IntoIterator`, and that is the whole seam this needs.
    struct DieAfter<'a> {
        envs: std::slice::Iter<'a, BlockEnvelope>,
        left: usize,
    }

    impl<'a> Iterator for DieAfter<'a> {
        type Item = &'a BlockEnvelope;
        fn next(&mut self) -> Option<&'a BlockEnvelope> {
            if self.left == 0 {
                // `abort`, not `panic!`: a panic unwinds, runs destructors and
                // flushes. This is the process stopping where it stands, with
                // the fsync at the end of `replace_tail` never reached.
                std::process::abort();
            }
            self.left -= 1;
            self.envs.next()
        }
    }

    /// **Verify by violating.** The process is really killed in the window
    /// between the truncate and the append, and in the window inside the
    /// append, and what is left on disk must be a log the node can boot on.
    ///
    /// What this does and does not prove, stated because the difference
    /// matters: killing a process does not empty the page cache, so this tests
    /// that the *file* the store leaves behind is recoverable. It does not
    /// test power loss. The power-loss claim rests on the `sync_all` that
    /// makes the truncation durable before anything is written past it — the
    /// ordering, not the timing — and that ordering is checked at the syscall
    /// level on Linux (`docs/perf/REORG-WRITE-PATH.md`), not here.
    ///
    /// The child is this same test binary, re-run under an env var. If the
    /// filter ever stops matching, the child exits cleanly and the
    /// `code().is_none()` assertion fails — it cannot pass by doing nothing.
    #[test]
    fn a_kill_mid_splice_leaves_a_replayable_prefix() {
        if let Ok(spec) = std::env::var(CRASH_ENV) {
            let (mode, dir) = spec.split_once('=').expect("mode=dir");
            let mut store = Store::open(Path::new(dir), &[7u8; 32]).expect("child open");
            for slot in 1..=9u64 {
                store.append(&sample_envelope(slot)).expect("child append");
            }
            let branch: Vec<BlockEnvelope> = (70..=72u64).map(sample_envelope).collect();
            let kept = sample_envelope(4);
            let left = match mode {
                "before-append" => 0,
                "mid-append" => 1,
                other => panic!("unknown crash mode {other}"),
            };
            let _ = store.replace_tail(
                4,
                Some(&kept),
                DieAfter { envs: branch.iter(), left },
            );
            // Reached only if `DieAfter` failed to kill the process, which the
            // parent detects as a clean exit code.
            std::process::exit(0);
        }

        for mode in ["before-append", "mid-append"] {
            let dir = tmpdir(&format!("kill-{mode}"));
            fs::create_dir_all(&dir).expect("mkdir");
            let status = std::process::Command::new(
                std::env::current_exe().expect("current exe"),
            )
            .args([
                "--exact",
                "store::tests::a_kill_mid_splice_leaves_a_replayable_prefix",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CRASH_ENV, format!("{mode}={}", dir.display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn the child");
            assert!(
                status.code().is_none(),
                "{mode}: the child exited with {:?} instead of dying inside replace_tail \
                 — the crash was never staged, so this test proved nothing",
                status.code()
            );

            // What survived must be readable, and must be a PREFIX of the
            // chain that was being adopted — never a splice of the two
            // branches, which is the state the ordering exists to forbid.
            let survived: Vec<u64> = LogReader::open(&dir)
                .expect("reader")
                .collect::<io::Result<Vec<_>>>()
                .expect("the log a killed process left is still readable")
                .iter()
                .map(|e| e.header.slot)
                .collect();
            let adopted = [1u64, 2, 3, 4, 70, 71, 72];
            assert!(
                survived.len() >= 4 && adopted.starts_with(survived.as_slice()),
                "{mode}: left {survived:?}, which is not a prefix of {adopted:?}"
            );
            // The old branch's slots 5..=9 must be gone: if any survived, the
            // truncate was undone under the new frames and the log is spliced.
            assert!(
                survived.iter().all(|s| !(5..=9).contains(s)),
                "{mode}: {survived:?} still carries the abandoned branch"
            );
            assert_eq!(
                Store::count(&dir).expect("count"),
                survived.len(),
                "{mode}: the two walks disagree about the wounded log"
            );
            // And a node coming up on it rebuilds a table that matches.
            let reopened = Store::open(&dir, &[7u8; 32]).expect("reopen after the crash");
            assert_eq!(
                reopened.index().read().expect("lock").len(),
                survived.len(),
                "{mode}: boot's frame table does not describe the surviving log"
            );
            println!("kill/{mode}: survived {survived:?}");
            let _ = fs::remove_dir_all(&dir);
        }
    }


    // ── Measurement, on the live chain's own history ─────────────────────────

    /// Where a real data dir is, for the two `#[ignore]`d tests below.
    const BENCH_ENV: &str = "BLOCH_BENCH_DIR";

    /// Copy `blocks.log` and `meta.bin` out of a real data dir. **Never opens
    /// the original for writing** — every measurement runs on a copy, so a
    /// node's data dir handed to this cannot be damaged by it.
    fn copy_datadir(src: &Path, tag: &str) -> PathBuf {
        let dst = tmpdir(tag);
        fs::create_dir_all(&dst).expect("mkdir");
        fs::copy(src.join("meta.bin"), dst.join("meta.bin")).expect("copy meta");
        fs::copy(src.join("blocks.log"), dst.join("blocks.log")).expect("copy log");
        dst
    }

    fn digest_of(dir: &Path) -> [u8; 32] {
        let meta = fs::read(dir.join("meta.bin")).expect("read meta");
        meta[12..44].try_into().expect("32-byte genesis digest")
    }

    fn file_hash(path: &Path) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut f = io::BufReader::with_capacity(1 << 20, File::open(path).expect("open"));
        let mut h = Sha3_256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        h.finalize().into()
    }

    /// **The before/after, on real mainnet history.**
    ///
    /// For a reorg of depth `d` at the tip, both write paths are asked to
    /// produce the same log — the one that is already there, since the branch
    /// re-adopted is the tail that was already logged. That makes the
    /// equivalence check exact and free of any synthetic block: the file each
    /// path leaves must hash to what the untouched original hashes to.
    ///
    /// Then it reports what each cost. `rewrite` is chain-linear and
    /// `replace_tail` is depth-linear, which is the entire claim.
    ///
    /// Run it as:
    /// ```text
    ///   BLOCH_BENCH_DIR=/path/to/datadir <test-binary> --ignored --nocapture \
    ///       reorg_write_cost_on_a_real_log
    /// ```
    #[test]
    #[ignore = "needs a real block log; set BLOCH_BENCH_DIR to a data dir"]
    fn reorg_write_cost_on_a_real_log() {
        let src = PathBuf::from(std::env::var(BENCH_ENV).expect("BLOCH_BENCH_DIR"));
        let digest = digest_of(&src);
        let want = file_hash(&src.join("blocks.log"));
        let bytes = fs::metadata(src.join("blocks.log")).expect("meta").len();

        // The chain, as the engine holds it. Streamed in, so peak is the
        // envelopes and not the envelopes plus the file.
        let all: Vec<BlockEnvelope> = LogReader::open(&src)
            .expect("reader")
            .collect::<io::Result<_>>()
            .expect("the real log decodes");
        let n = all.len();
        println!(
            "log: {n} blocks, {:.1} MiB, sha3 {}",
            bytes as f64 / 1048576.0,
            crate::codec::hex8(&want)
        );
        println!("{:>7}  {:>12}  {:>12}  {:>9}", "depth", "rewrite", "replace_tail", "speedup");

        for d in [1usize, 2, 5, 13, 85] {
            if d >= n {
                continue;
            }
            let keep = n - d;

            let a = copy_datadir(&src, &format!("bench-rewrite-{d}"));
            let mut sa = Store::open(&a, &digest).expect("open a");
            let t0 = std::time::Instant::now();
            sa.rewrite(all.iter()).expect("rewrite");
            let t_rewrite = t0.elapsed();
            drop(sa);
            assert_eq!(file_hash(&a.join("blocks.log")), want, "rewrite changed the bytes");

            let b = copy_datadir(&src, &format!("bench-splice-{d}"));
            let mut sb = Store::open(&b, &digest).expect("open b");
            let t0 = std::time::Instant::now();
            sb.replace_tail(keep, Some(&all[keep - 1]), all[keep..].iter())
                .expect("replace_tail");
            let t_splice = t0.elapsed();
            drop(sb);
            assert_eq!(
                file_hash(&b.join("blocks.log")),
                want,
                "depth {d}: the spliced log is not the log a rewrite produces"
            );

            println!(
                "{d:>7}  {:>10.3} s  {:>10.3} s  {:>8.0}x",
                t_rewrite.as_secs_f64(),
                t_splice.as_secs_f64(),
                t_rewrite.as_secs_f64() / t_splice.as_secs_f64().max(1e-9),
            );
            let _ = fs::remove_dir_all(&a);
            let _ = fs::remove_dir_all(&b);
        }
    }

    /// The kill test, staged on a **real** log rather than nine synthetic
    /// frames: the process dies between the truncate and the append of a
    /// 30k-block chain, and what is left must still be a prefix that a node
    /// can boot on. The boot itself is done by the real `bloch-pos` binary
    /// against the dir this leaves behind — see `docs/perf/REORG-WRITE-PATH.md`.
    #[test]
    #[ignore = "needs a real block log; set BLOCH_BENCH_DIR to a data dir"]
    fn a_kill_mid_splice_on_a_real_log_leaves_a_prefix() {
        let src = PathBuf::from(std::env::var(BENCH_ENV).expect("BLOCH_BENCH_DIR"));
        let digest = digest_of(&src);

        if let Ok(spec) = std::env::var(CRASH_ENV) {
            let (mode, dir) = spec.split_once('=').expect("mode=dir");
            let mut store = Store::open(Path::new(dir), &digest).expect("child open");
            let n = store.index().read().expect("lock").len();
            let keep = n - 85;
            // The branch: the 85 blocks that are already there, re-adopted.
            let all: Vec<BlockEnvelope> = LogReader::open(Path::new(dir))
                .expect("reader")
                .collect::<io::Result<_>>()
                .expect("decode");
            let left = match mode {
                "before-append" => 0,
                "mid-append" => 40,
                other => panic!("unknown mode {other}"),
            };
            let _ = store.replace_tail(
                keep,
                Some(&all[keep - 1]),
                DieAfter { envs: all[keep..].iter(), left },
            );
            std::process::exit(0);
        }

        for mode in ["before-append", "mid-append"] {
            let dir = copy_datadir(&src, &format!("realkill-{mode}"));
            let before = Store::count(&dir).expect("count");
            let status = std::process::Command::new(
                std::env::current_exe().expect("current exe"),
            )
            .args([
                "--exact",
                "store::tests::a_kill_mid_splice_on_a_real_log_leaves_a_prefix",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CRASH_ENV, format!("{mode}={}", dir.display()))
            .env(BENCH_ENV, &src)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn child");
            assert!(
                status.code().is_none(),
                "{mode}: child exited {:?} instead of dying inside replace_tail",
                status.code()
            );

            let after = Store::count(&dir).expect("count after");
            let keep = before - 85;
            assert!(
                after >= keep && after <= before,
                "{mode}: {after} frames survived, outside the prefix range {keep}..={before}"
            );
            // The surviving frames must be the ORIGINAL bytes for the whole
            // prefix — anything else means the truncate was undone under the
            // new writes.
            let survivors: Vec<BlockEnvelope> = LogReader::open(&dir)
                .expect("reader")
                .collect::<io::Result<_>>()
                .expect("the wounded log still decodes");
            assert_eq!(survivors.len(), after, "the two walks disagree");
            let original: Vec<BlockEnvelope> = LogReader::open(&src)
                .expect("reader")
                .collect::<io::Result<_>>()
                .expect("decode");
            for (i, (a, b)) in survivors.iter().zip(original.iter()).enumerate() {
                assert_eq!(
                    crate::codec::encode_envelope(a),
                    crate::codec::encode_envelope(b),
                    "{mode}: frame {i} of the wounded log is not the block that was there"
                );
            }
            println!(
                "realkill/{mode}: {before} -> {after} frames (cut at {keep}); \
                 dir left at {} for the boot check",
                dir.display()
            );
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
