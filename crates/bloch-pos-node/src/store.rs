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
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bloch_pos_committee::header::BlockEnvelope;

const META_MAGIC: &[u8; 8] = b"BPOSMETA";

pub struct Store {
    dir: PathBuf,
    log: File,
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
        Ok(Store { dir: dir.to_path_buf(), log })
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
        self.log.sync_data()
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

    /// The same answer as [`Store::blocks_after`], without ever reading the
    /// body of a frame it is going to discard.
    ///
    /// Per frame: the 4-byte length, then exactly
    /// `BlockHeaderV4::ENCODED_LEN` bytes — the slot is all the filter needs —
    /// and then either the remaining `len - hdr_len` bytes (the frame is part
    /// of the answer and the peer must get the logged bytes verbatim) or a
    /// relative seek past them. The caller that matters is a node syncing from
    /// genesis: every frame before its window is a skip, so a page stops
    /// costing "read the whole chain" and starts costing 308 bytes per frame.
    ///
    /// ## The one invariant, and why it is not a `debug_assert!`
    ///
    /// The seek distance is `tail_len = len - hdr_len`. If it is wrong by a
    /// single byte the reader lands mid-frame, the next length prefix is
    /// garbage, and — this format carries no checksum — the scan silently
    /// desynchronizes and serves a syncing peer structurally plausible
    /// nonsense. It is pinned by tests
    /// (`blocks_after_limited_stays_synchronized_across_varied_frame_sizes`
    /// and the equivalence sweep against `blocks_after`), deliberately not by
    /// a `debug_assert!`: `[profile.release]` sets `overflow-checks` but not
    /// `debug-assertions`, so such an assertion is absent from the binary the
    /// fleet actually runs and would pin nothing where it counts.
    ///
    /// For the same reason the subtraction is [`usize::checked_sub`] and not
    /// `-`. With `overflow-checks = true` a `len < hdr_len` underflow *panics*
    /// in release, and this is the path that answers other peers'
    /// `get-blocks`: a corrupt byte in a local log would become a remotely
    /// triggerable crash. A checked subtraction turns it into the `io::Error`
    /// every caller of this function already handles.
    ///
    /// Uses [`io::BufReader::seek_relative`] rather than [`io::Seek::seek`] on
    /// purpose: `seek()` on a `BufReader` discards the whole buffer on every
    /// call, so skipping a 400-byte body would throw away the several
    /// kilobytes already read and force a fresh syscall for the next frame —
    /// making the "optimized" scan slower than the `read_exact` it replaces.
    /// `seek_relative` moves within the buffer when the target is already
    /// there, which for typical block sizes is most skips.
    ///
    /// Reads the log file fresh so a reader thread never touches the append
    /// handle.
    pub fn blocks_after_limited(
        dir: &Path,
        after_slot: u64,
        limit: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
        let mut f = io::BufReader::new(File::open(dir.join("blocks.log"))?);
        let mut out = Vec::new();
        let mut len4 = [0u8; 4];
        let mut hdr = vec![0u8; hdr_len];
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
            let tail_len = match len.checked_sub(hdr_len) {
                Some(tail_len) => tail_len,
                None => {
                    // A frame too short to hold a header. `blocks_after`
                    // reaches that verdict only *after* reading the frame, so
                    // a short frame that is also truncated is a clean break
                    // there and not an error — reproduce that exactly rather
                    // than diverge on malformed logs. The read is bounded by
                    // `hdr_len - 1` bytes, so the fidelity is free.
                    let mut short = vec![0u8; len];
                    match f.read_exact(&mut short) {
                        Ok(()) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "log frame shorter than a header",
                            ))
                        }
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(e),
                    }
                }
            };
            match f.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let header =
                bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(&hdr).map_err(
                    |_| io::Error::new(io::ErrorKind::InvalidData, "undecodable header in block log"),
                )?;
            if header.slot > after_slot {
                // Wanted: reassemble the frame byte-for-byte as it was logged.
                let mut payload = vec![0u8; len];
                payload[..hdr_len].copy_from_slice(&hdr);
                match f.read_exact(&mut payload[hdr_len..]) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
                out.push(payload);
            } else {
                // Not wanted: the body is never touched. `tail_len == 0` (a
                // frame that is exactly a header) makes this a no-op seek,
                // which is correct, not an error.
                let skip = i64::try_from(tail_len).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "log frame body too large to skip")
                })?;
                f.seek_relative(skip)?;
            }
        }
        Ok(out)
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

    // ── blocks_after_limited: the seek-past-the-body scan ───────────────────
    //
    // The existing test above appends envelopes with EMPTY bodies. That is
    // exactly the shape in which this function cannot be tested: with an empty
    // body every frame is the same size and `tail_len` is small and uniform,
    // so `len - hdr_len`, `len`, and `len - hdr_len - 1` all keep the reader
    // close enough to look right on some inputs. Everything below therefore
    // uses DELIBERATELY VARYING frame sizes, including the pathological ones:
    // a frame that is exactly a header (`tail_len == 0`), a frame one byte
    // longer than a header (`tail_len == 1`), and a megabyte frame.

    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

    /// A private dir per test. The pre-existing test keys its temp dir on the
    /// pid alone, which collides the moment two tests in this binary run
    /// concurrently — cargo runs them in threads of ONE process.
    fn fresh_dir(tag: &str) -> PathBuf {
        let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("bloch-pos-store-{}-{}-{}", tag, std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn hdr_len() -> usize {
        bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN
    }

    /// A compact stand-in for a list of frames: `(length, FNV-1a digest)` each.
    ///
    /// Asserted just BEFORE the raw byte comparison, purely so that a failure
    /// is readable. These frames run to a megabyte, and `assert_eq!` on the
    /// raw vectors prints every byte of both sides — the first mutation run
    /// against these tests produced a 383 KB failure message, which is a
    /// failure report nobody reads and therefore a defect in the test. The raw
    /// assertion still follows every one of these, so byte-identity remains
    /// the property under test; this only makes the diagnosis legible, and it
    /// names the frame that drifted instead of burying it.
    fn fingerprint(frames: &[Vec<u8>]) -> Vec<(usize, String)> {
        frames
            .iter()
            .map(|f| {
                let mut h: u64 = 0xcbf29ce484222325;
                for b in f {
                    h ^= *b as u64;
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
                (f.len(), format!("{h:016x}"))
            })
            .collect()
    }

    /// A frame payload of exactly `total_len` bytes carrying a real, decodable
    /// header for `slot` followed by filler.
    ///
    /// Filler bytes have the high bit set, so if the scan ever drifts into
    /// them the next "length prefix" it reads is >= 0x80808080 — far over
    /// `MAX_FIELD_LEN` — and desync surfaces as a loud error rather than as a
    /// plausible-looking short frame. (Byte-identity of the returned frames is
    /// the primary detector; this only makes the failure mode louder.)
    ///
    /// For `total_len == hdr_len()` the payload is a bare header, and for
    /// `hdr_len() + 1` it is a header plus one byte. Neither is a decodable
    /// *envelope* — `decode_envelope` would reject both — but neither scanner
    /// decodes envelopes: they parse the header and copy bytes. Framing is
    /// what is under test here, and these are the sizes at which the framing
    /// arithmetic breaks.
    fn synthetic_payload(slot: u64, total_len: usize) -> Vec<u8> {
        assert!(total_len >= hdr_len(), "a frame must at least hold a header");
        let hdr = sample_envelope(slot).header.canonical_serialize();
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&hdr);
        for i in 0..(total_len - hdr_len()) {
            out.push(0x80 | ((i as u8).wrapping_add(slot as u8) & 0x7f));
        }
        assert_eq!(out.len(), total_len);
        out
    }

    /// Write `blocks.log` as `u32 LE length ‖ payload` frames, plus an
    /// optional deliberately truncated trailing frame.
    fn write_log(dir: &Path, payloads: &[Vec<u8>], truncated_tail: Option<(u32, usize)>) {
        let mut bytes = Vec::new();
        for p in payloads {
            bytes.extend_from_slice(&(p.len() as u32).to_le_bytes());
            bytes.extend_from_slice(p);
        }
        if let Some((declared_len, present)) = truncated_tail {
            bytes.extend_from_slice(&declared_len.to_le_bytes());
            bytes.extend(std::iter::repeat(0xC3u8).take(present));
        }
        fs::write(dir.join("blocks.log"), &bytes).expect("write log");
    }

    /// 20 frames at slots 1..=20 with wildly different sizes, mixing real
    /// `encode_envelope` output with synthetic frames at the pathological
    /// sizes. Returns the payloads in log order.
    fn varied_log(dir: &Path) -> Vec<Vec<u8>> {
        let h = hdr_len();
        let sizes = [
            h,             // slot 1  — tail_len == 0 exactly
            h + 1,         // slot 2  — tail_len == 1, one byte over a header
            h + 2,         // slot 3
            0,             // slot 4  — real envelope (size chosen by the codec)
            317,           // slot 5
            1_000_000,     // slot 6  — pathologically large
            512,           // slot 7
            h,             // slot 8  — tail_len == 0 again, mid-log
            1023,          // slot 9
            4096,          // slot 10
            h + 1,         // slot 11
            999,           // slot 12
            0,             // slot 13 — real envelope
            8191,          // slot 14
            h,             // slot 15 — tail_len == 0, right before a big one
            65_537,        // slot 16
            307,           // slot 17
            60_000,        // slot 18
            h + 1,         // slot 19
            1_048_576,     // slot 20 — a full MiB, still under MAX_FIELD_LEN
        ];
        let payloads: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| {
                let slot = i as u64 + 1;
                if size == 0 {
                    crate::codec::encode_envelope(&sample_envelope(slot))
                } else {
                    synthetic_payload(slot, size)
                }
            })
            .collect();
        write_log(dir, &payloads, None);
        payloads
    }

    /// THE test this function exists for: after skipping N frames of differing
    /// sizes, is the reader still standing exactly on a frame boundary?
    ///
    /// A high `after_slot` makes almost every frame a skip, so the answer is
    /// produced only by seeks that all landed correctly. If `tail_len` is off
    /// by even one byte in either direction the reader lands mid-frame and the
    /// frames it eventually returns are garbage (or the scan errors) — this
    /// format has no checksum that would catch that in production.
    #[test]
    fn blocks_after_limited_stays_synchronized_across_varied_frame_sizes() {
        let dir = fresh_dir("sync");
        let payloads = varied_log(&dir);

        // 17 skips, then 3 frames — one 60 KB, one of hdr_len+1, one of 1 MiB.
        let tail = Store::blocks_after_limited(&dir, 17, 100).expect("scan");
        assert_eq!(tail.len(), 3, "slots 18, 19, 20 are strictly after 17");
        let want = payloads[17..20].to_vec();
        assert_eq!(
            fingerprint(&tail),
            fingerprint(&want),
            "after 17 skips over frames of 6 different sizes the served bytes must still be \
             the logged bytes, verbatim — anything else means the scan desynchronized"
        );
        assert_eq!(tail, want, "and byte-for-byte, not merely same-shaped");

        // 19 skips, one frame. The last skip is over the 60 KB frame, the one
        // before it over a hdr_len+1 frame, so a tail_len that is short by one
        // and a tail_len that is the whole frame both land somewhere else.
        let last = Store::blocks_after_limited(&dir, 19, 100).expect("scan");
        let want_last = payloads[19..].to_vec();
        assert_eq!(fingerprint(&last), fingerprint(&want_last), "19 skips, then the tip");
        assert_eq!(last, want_last, "19 skips, then the tip, verbatim");

        // Every frame is a skip: the scan must walk the whole log and report
        // nothing, without ever falling off a boundary.
        let none = Store::blocks_after_limited(&dir, 20, 100).expect("scan");
        assert!(none.is_empty(), "a peer at the tip is told there is nothing more");

        // And the whole log, unskipped, is still byte-identical.
        let all = Store::blocks_after_limited(&dir, 0, 100).expect("scan");
        assert_eq!(fingerprint(&all), fingerprint(&payloads), "from genesis");
        assert_eq!(all, payloads, "from genesis, verbatim");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Equivalence with the scanner it replaces, swept over every interesting
    /// `after_slot` and cap. This is the strongest oracle available: the old
    /// scan reads every frame in full and cannot drift, so any disagreement is
    /// the new one's fault.
    #[test]
    fn blocks_after_limited_matches_blocks_after_exactly() {
        let dir = fresh_dir("equiv");
        let payloads = varied_log(&dir);

        let mut saw_nonempty = false;
        for after_slot in 0..=21u64 {
            for limit in [0usize, 1, 2, 3, 7, 100] {
                let old = Store::blocks_after(&dir, after_slot, limit).expect("old scan");
                let new = Store::blocks_after_limited(&dir, after_slot, limit).expect("new scan");
                assert_eq!(
                    fingerprint(&old),
                    fingerprint(&new),
                    "divergence at after_slot={after_slot} limit={limit}"
                );
                assert_eq!(
                    old, new,
                    "byte-level divergence at after_slot={after_slot} limit={limit}"
                );
                if !new.is_empty() {
                    saw_nonempty = true;
                }
            }
        }
        assert!(saw_nonempty, "the sweep must not be vacuously equal on empty answers");

        // Spot-check the sweep against the source of truth, so that an
        // equivalence which held because BOTH scanners are broken would still
        // be caught.
        let from_genesis = Store::blocks_after_limited(&dir, 0, 100).expect("scan");
        assert_eq!(
            fingerprint(&from_genesis),
            fingerprint(&payloads),
            "both scanners agreeing is only meaningful if they agree with the log"
        );
        assert_eq!(from_genesis, payloads, "and agree with it byte-for-byte");

        let _ = fs::remove_dir_all(&dir);
    }

    /// A crash mid-append leaves one truncated trailing frame. It must be
    /// dropped, not turned into an error, on all three truncation points —
    /// including when the truncated frame is one the scan wanted to SKIP,
    /// where the seek runs past EOF.
    #[test]
    fn blocks_after_limited_tolerates_a_truncated_trailing_frame() {
        let complete = vec![
            synthetic_payload(1, hdr_len()),
            synthetic_payload(2, 4096),
            synthetic_payload(3, hdr_len() + 1),
        ];

        // Where the write was cut off: in the length prefix itself, inside the
        // header, or inside the tail past a complete header. `None` = the
        // prefix case, which `write_log` cannot express (it is half a length).
        let cases: [(&str, Option<(u32, usize)>); 3] =
            [("prefix", None), ("header", Some((5000, 100))), ("tail", Some((5000, 900)))];

        for (case, tail) in cases {
            let dir = fresh_dir(&format!("trunc-{case}"));
            match tail {
                Some(t) => write_log(&dir, &complete, Some(t)),
                None => {
                    write_log(&dir, &complete, None);
                    let mut bytes = fs::read(dir.join("blocks.log")).expect("read");
                    bytes.extend_from_slice(&[0x11, 0x22]); // half a length prefix
                    fs::write(dir.join("blocks.log"), &bytes).expect("write");
                }
            }

            // Wanted: every complete frame comes back, the torn one is gone.
            let got = Store::blocks_after_limited(&dir, 0, 100)
                .unwrap_or_else(|e| panic!("{case}: a torn trailing frame must not be an error: {e}"));
            assert_eq!(fingerprint(&got), fingerprint(&complete), "{case}: the complete frames");
            assert_eq!(got, complete, "{case}: the complete frames, verbatim");
            assert_eq!(got, Store::blocks_after(&dir, 0, 100).expect("old"), "{case}: agrees");

            // Skipped: the seek walks off the end of the file. That must end
            // the scan cleanly on the next length read, not error.
            let skipped = Store::blocks_after_limited(&dir, 99, 100)
                .unwrap_or_else(|e| panic!("{case}: skipping past a torn frame errored: {e}"));
            assert!(skipped.is_empty(), "{case}: nothing is after slot 99");
            assert_eq!(skipped, Store::blocks_after(&dir, 99, 100).expect("old"), "{case}: agrees");

            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// The two malformed-frame verdicts stay verdicts, and stay the SAME
    /// verdict the old scanner reaches — including the `len < hdr_len` case,
    /// where the difference between "error" and "clean break" is whether the
    /// short frame is also the truncated last one.
    #[test]
    fn blocks_after_limited_rejects_over_cap_and_sub_header_frames() {
        // Over the cap: an error, before any body is read.
        let dir = fresh_dir("overcap");
        let good = synthetic_payload(1, 512);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(good.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&good);
        bytes.extend_from_slice(&((crate::codec::MAX_FIELD_LEN as u32) + 1).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        fs::write(dir.join("blocks.log"), &bytes).expect("write");
        for after_slot in [0u64, 99] {
            assert!(
                Store::blocks_after_limited(&dir, after_slot, 100).is_err(),
                "a frame over MAX_FIELD_LEN is an error, skipped or not"
            );
            assert!(Store::blocks_after(&dir, after_slot, 100).is_err(), "as it always was");
        }
        let _ = fs::remove_dir_all(&dir);

        // Shorter than a header, and NOT the last frame: an error, and
        // specifically not a silent underflow. `overflow-checks = true` would
        // turn a bare `len - hdr_len` into a panic here — a remote DoS on the
        // get-blocks path — so this asserts an Err, not a catch_unwind.
        let dir = fresh_dir("subhdr");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 5]);
        bytes.extend_from_slice(&(good.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&good);
        fs::write(dir.join("blocks.log"), &bytes).expect("write");
        for after_slot in [0u64, 99] {
            let e = Store::blocks_after_limited(&dir, after_slot, 100)
                .expect_err("a frame too short to hold a header is malformed");
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert!(Store::blocks_after(&dir, after_slot, 100).is_err(), "as it always was");
        }
        let _ = fs::remove_dir_all(&dir);

        // Shorter than a header AND truncated at EOF: that is the crash
        // signature, so it is a clean break — matching `blocks_after`, which
        // only reaches the "too short" verdict after a read that fails first.
        let dir = fresh_dir("subhdr-torn");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(good.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&good);
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 2]);
        fs::write(dir.join("blocks.log"), &bytes).expect("write");
        assert_eq!(
            Store::blocks_after_limited(&dir, 0, 100).expect("torn short frame is a clean break"),
            vec![good.clone()],
        );
        assert_eq!(
            Store::blocks_after_limited(&dir, 0, 100).expect("new"),
            Store::blocks_after(&dir, 0, 100).expect("old"),
        );
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
