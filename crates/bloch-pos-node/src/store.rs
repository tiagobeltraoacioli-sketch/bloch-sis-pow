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
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use bloch_pos_committee::header::BlockEnvelope;

const META_MAGIC: &[u8; 8] = b"BPOSMETA";

/// One frame's source for [`Store::rewrite_frames`].
pub enum FrameSrc<'a> {
    /// Copy the frame that already sits at this offset in the current log,
    /// byte for byte. No decode, no re-encode.
    Logged(u64),
    /// Encode this envelope — a block the log does not have yet, which on the
    /// reorg path is exactly the adopted branch.
    Envelope(&'a BlockEnvelope),
}

pub struct Store {
    dir: PathBuf,
    log: File,
    /// Byte length of the log as this process believes it: the end of the last
    /// frame it has written or scanned.
    ///
    /// It exists because appends now return the offset they landed at, and
    /// `BlockMap` keys a block's bytes by that offset. `File::metadata().len()`
    /// would answer the same question one syscall later and one crash-torn
    /// tail sooner — see `repair_tail`.
    len: u64,
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
        let len = log.metadata()?.len();
        let mut store = Store { dir: dir.to_path_buf(), log, len };
        store.repair_tail()?;
        Ok(store)
    }

    /// Cut a crash-torn trailing frame off the log, physically.
    ///
    /// `read_all` has always *ignored* a truncated trailing frame ("crash
    /// mid-append") while leaving its bytes on disk. That was already a latent
    /// fault: the log is opened `O_APPEND`, so the next block written lands
    /// after the garbage, and the boot after that hits the torn length prefix
    /// mid-file — where the same code treats it as corruption and refuses,
    /// which is the correct response to a log it can no longer read in order.
    /// The window was narrow enough that it was never the reported symptom.
    ///
    /// It stops being narrow the moment a block's bytes are addressed by
    /// offset, because then "where does the log end" is not a detail of one
    /// scan but the anchor every later offset is measured from. So the tail is
    /// repaired here, once, before any offset is handed out: the file is
    /// truncated to the end of the last frame that is whole. Nothing readable
    /// is discarded — every dropped byte is a byte `read_all` already declined
    /// to decode.
    fn repair_tail(&mut self) -> io::Result<()> {
        let valid = self.scan_valid_end()?;
        if valid < self.len {
            eprintln!(
                "store: truncating {} byte(s) of torn trailing frame (crash mid-append)",
                self.len - valid
            );
            self.log.set_len(valid)?;
            self.log.sync_all()?;
            self.len = valid;
        }
        Ok(())
    }

    /// The offset just past the last whole frame, plus how many there are.
    /// Reads only the 4-byte length prefixes and seeks over the bodies.
    fn scan_valid_end(&self) -> io::Result<u64> {
        Ok(self.scan_frames()?.1)
    }

    /// `(frame count, valid end offset)`. Cheap: 30k length reads and 30k
    /// seeks over a 400 MB file, not 30k decodes of it.
    pub fn frame_census(&self) -> io::Result<(usize, u64)> {
        self.scan_frames()
    }

    fn scan_frames(&self) -> io::Result<(usize, u64)> {
        let mut f = match File::open(self.dir.join("blocks.log")) {
            Ok(f) => io::BufReader::new(f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e),
        };
        let mut at = 0u64;
        let mut n = 0usize;
        let mut len4 = [0u8; 4];
        loop {
            if at + 4 > self.len {
                break;
            }
            f.seek(io::SeekFrom::Start(at))?;
            match f.read_exact(&mut len4) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let len = u32::from_le_bytes(len4) as u64;
            if len > crate::codec::MAX_FIELD_LEN as u64 {
                // Not an error here, unlike in a decode: a torn tail can put
                // arbitrary bytes where a length belongs, and the whole job of
                // this scan is to find where the readable part stops.
                break;
            }
            let end = at + 4 + len;
            if end > self.len {
                break;
            }
            at = end;
            n += 1;
        }
        Ok((n, at))
    }

    /// Returns the byte offset the frame landed at — its 4-byte length
    /// prefix — so the caller can drop the envelope and address the bytes.
    pub fn append(&mut self, env: &BlockEnvelope) -> io::Result<u64> {
        let payload = crate::codec::encode_envelope(env);
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        let at = self.len;
        self.log.write_all(&frame)?;
        self.log.sync_data()?;
        self.len += frame.len() as u64;
        Ok(at)
    }

    /// Replace the whole log with the canonical chain (a reorg adopted a
    /// different branch). Each frame is either bytes already in the log, named
    /// by offset and copied verbatim, or an envelope that has to be encoded.
    ///
    /// This replaced a `rewrite(&[BlockEnvelope])`, which is now gone rather
    /// than kept beside it: leaving it would leave a way to ask the store for
    /// the whole chain as envelopes, which is the allocation this exists to
    /// remove.
    ///
    /// **Copying is not an optimisation, it is the point.** The old signature
    /// took `&[BlockEnvelope]`, so `do_reorg` materialised the entire canonical
    /// chain — every block from genesis, whole — into one `Vec` to rewrite the
    /// log. At Genesis-4's size that is a ~1.2 GiB allocation taken on a path
    /// that runs whenever weight moves to a sibling, on a box with 8 GiB and
    /// nine validators. Here the chain streams through a 1 MiB buffer and the
    /// bytes are never decoded at all, which also makes the new log
    /// byte-identical to the old one for every block that did not move.
    ///
    /// Returns the new offset of each frame, in order, for the caller to
    /// re-key its map by. Write-to-temp then rename, as before: a crash leaves
    /// the old log or the new one, never half of either.
    pub fn rewrite_frames(&mut self, frames: &[FrameSrc<'_>]) -> io::Result<Vec<u64>> {
        let tmp = self.dir.join("blocks.log.tmp");
        let mut offsets = Vec::with_capacity(frames.len());
        let mut end = 0u64;
        {
            let mut out = io::BufWriter::with_capacity(1 << 20, File::create(&tmp)?);
            // Opened once, and only if some frame is a copy: a rewrite of a
            // freshly-synced branch may name no offsets at all.
            let mut src: Option<io::BufReader<File>> = None;
            // Where `src` is positioned. Tracked so the common case — the
            // canonical chain, in chain order, which is the order the log is
            // already in — does not seek at all.
            //
            // This is not micro-tuning. `BufReader::seek` to an absolute
            // position DISCARDS the buffer, so seeking before every frame
            // makes each 13 KB block cost a fresh 1 MiB fill: ~29 GB of reads
            // to rewrite a 400 MB log. `seek_relative` keeps the buffer when
            // the target is inside it, and skipping the call entirely keeps it
            // always.
            let mut at = 0u64;
            let mut payload = Vec::new();
            for fr in frames {
                let bytes: &[u8] = match fr {
                    FrameSrc::Envelope(env) => {
                        payload = crate::codec::encode_envelope(env);
                        &payload
                    }
                    FrameSrc::Logged(off) => {
                        if src.is_none() {
                            src = Some(io::BufReader::with_capacity(
                                1 << 20,
                                File::open(self.dir.join("blocks.log"))?,
                            ));
                            at = 0;
                        }
                        let r = src.as_mut().expect("just filled");
                        if *off != at {
                            match i64::try_from(*off).and_then(|o| {
                                i64::try_from(at).map(|a| o - a)
                            }) {
                                Ok(d) => r.seek_relative(d)?,
                                Err(_) => {
                                    r.seek(io::SeekFrom::Start(*off))?;
                                }
                            }
                            at = *off;
                        }
                        let mut len4 = [0u8; 4];
                        r.read_exact(&mut len4)?;
                        let len = u32::from_le_bytes(len4) as usize;
                        if len > crate::codec::MAX_FIELD_LEN {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "log frame over cap",
                            ));
                        }
                        payload.clear();
                        payload.resize(len, 0);
                        r.read_exact(&mut payload)?;
                        at += 4 + len as u64;
                        &payload
                    }
                };
                offsets.push(end);
                out.write_all(&(bytes.len() as u32).to_le_bytes())?;
                out.write_all(bytes)?;
                end += 4 + bytes.len() as u64;
            }
            let f = out.into_inner().map_err(|e| e.into_error())?;
            f.sync_data()?;
        }
        fs::rename(&tmp, self.dir.join("blocks.log"))?;
        self.log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(self.dir.join("blocks.log"))?;
        self.len = end;
        Ok(offsets)
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

    /// A crash mid-append leaves a torn frame. The next boot must cut it, and
    /// the block written after that must be readable on the boot after THAT.
    ///
    /// `read_all` has always skipped a torn trailing frame while leaving its
    /// bytes in the file. That was survivable while the log was only ever read
    /// front-to-back in one pass; it is not survivable once a block's bytes are
    /// addressed by offset, because then the end of the log is the anchor every
    /// offset is measured from. The control below is the whole point: with the
    /// torn bytes left in place, the frame appended after them is unreachable
    /// and the file no longer parses.
    #[test]
    fn a_torn_trailing_frame_is_cut_so_the_next_append_is_still_readable() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-pos-store-torn-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        {
            let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
            for slot in 1..=3u64 {
                store.append(&sample_envelope(slot)).expect("append");
            }
        }
        let whole = fs::metadata(dir.join("blocks.log")).expect("stat").len();

        // The crash: a length prefix promising more body than was written.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join("blocks.log"))
                .expect("reopen to tear");
            f.write_all(&9_999u32.to_le_bytes()).expect("prefix");
            f.write_all(&[0xEE; 40]).expect("a fragment of a body");
            f.sync_data().expect("sync");
        }
        assert!(fs::metadata(dir.join("blocks.log")).expect("stat").len() > whole);

        // The control: what the OLD behaviour would have produced. Append a
        // fourth block AFTER the torn bytes, without repairing, and the file
        // stops being parseable — the fourth frame is behind a length prefix
        // that claims 9,999 bytes of the wrong thing.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join("blocks.log"))
                .expect("reopen");
            let payload = crate::codec::encode_envelope(&sample_envelope(4));
            f.write_all(&(payload.len() as u32).to_le_bytes()).expect("len");
            f.write_all(&payload).expect("body");
            f.sync_data().expect("sync");
        }
        let control: Vec<u64> = frames(&dir)
            .expect("iterate")
            .filter_map(|r| r.ok())
            .map(|(_, e)| e.header.slot)
            .collect();
        assert_eq!(
            control,
            vec![1, 2, 3],
            "control: with the torn bytes in place the block written after them is \
             unreachable — this is exactly the state the repair exists to prevent"
        );

        // Now the repair, on a fresh open, followed by the append it protects.
        {
            let mut store = Store::open(&dir, &[7u8; 32]).expect("reopen and repair");
            store.append(&sample_envelope(5)).expect("append after repair");
        }
        let after: Vec<u64> = frames(&dir)
            .expect("iterate")
            .filter_map(|r| r.ok())
            .map(|(_, e)| e.header.slot)
            .collect();
        assert_eq!(
            after,
            vec![1, 2, 3, 5],
            "the torn tail and everything stranded behind it are gone, and the block \
             appended after the repair reads back"
        );

        // And the offsets the repair leaves behind are the real ones.
        let offs: Vec<u64> = frames(&dir)
            .expect("iterate")
            .filter_map(|r| r.ok())
            .map(|(o, _)| o)
            .collect();
        assert_eq!(offs[0], 0);
        for w in offs.windows(2) {
            assert!(w[1] > w[0], "offsets ascend");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The rewrite copies frames by offset, and it must do that correctly
    /// whether or not the offsets ascend.
    ///
    /// Ascending is the common case and the one the reader is tuned for — it
    /// tracks its own position so the canonical chain, which the log is
    /// already in the order of, costs no seeks. This pins the other case,
    /// because "already in that order" stops being true exactly when it
    /// matters: a boot-replay reorg adopts a branch without rewriting the log
    /// (`live == false`), so from then until the next live rewrite the chain's
    /// order is not the file's. A reader that assumed monotone offsets would
    /// hand back the wrong block there, and would do it silently.
    #[test]
    fn the_rewrite_reads_frames_correctly_in_any_offset_order() {
        let dir = std::env::temp_dir().join(format!(
            "bloch-pos-store-order-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir, &[7u8; 32]).expect("open");
        let mut offs = Vec::new();
        for slot in 1..=6u64 {
            offs.push(store.append(&sample_envelope(slot)).expect("append"));
        }

        // Reverse, then a shuffle that jumps backwards past the read buffer
        // and forwards again.
        for order in [
            vec![5usize, 4, 3, 2, 1, 0],
            vec![3, 0, 5, 1, 4, 2],
            vec![0, 5, 0, 5, 0],
        ] {
            let mut probe = Store::open(&dir, &[7u8; 32]).expect("reopen");
            let srcs: Vec<FrameSrc<'_>> =
                order.iter().map(|i| FrameSrc::Logged(offs[*i])).collect();
            let new_offsets = probe.rewrite_frames(&srcs).expect("rewrite");
            assert_eq!(new_offsets.len(), order.len());

            let got: Vec<u64> = frames(&dir)
                .expect("iterate")
                .map(|r| r.expect("frame").1.header.slot)
                .collect();
            let want: Vec<u64> = order.iter().map(|i| *i as u64 + 1).collect();
            assert_eq!(got, want, "frames were copied in the order asked for");

            // And the offsets handed back really name those frames.
            for (k, off) in new_offsets.iter().enumerate() {
                let one = frames(&dir)
                    .expect("iterate")
                    .map(|r| r.expect("frame"))
                    .find(|(o, _)| o == off)
                    .expect("the returned offset is a real frame start");
                assert_eq!(one.1.header.slot, want[k]);
            }

            // Restore the file for the next order in the loop.
            let restore: Vec<BlockEnvelope> = (1..=6u64).map(sample_envelope).collect();
            let srcs: Vec<FrameSrc<'_>> = restore.iter().map(FrameSrc::Envelope).collect();
            offs = probe.rewrite_frames(&srcs).expect("restore");
        }
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


/// The log's frames, in order, each with the byte offset it starts at.
///
/// A free function over the directory rather than a method, because the boot
/// replay needs to stream the log **while** the engine that owns the `Store`
/// is being driven block by block — `store.for_each_frame(|..| engine.ingest(..))`
/// borrows the engine twice and does not compile, and an iterator that owns
/// its own read handle is the honest shape anyway: it is a reader, and the
/// append handle is a writer.
///
/// The whole point is what it does NOT do. `read_all` returned a
/// `Vec<BlockEnvelope>`: it read the entire 400 MB file into one `Vec<u8>`,
/// decoded every block out of it, and handed back a vector that stayed alive
/// for the whole replay — beside the map being built from it. Three
/// simultaneous copies of the chain. This keeps one block.
pub fn frames(dir: &Path) -> io::Result<FrameIter> {
    let file = match File::open(dir.join("blocks.log")) {
        Ok(f) => Some(io::BufReader::with_capacity(1 << 20, f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    Ok(FrameIter { r: file, at: 0, done: false })
}

pub struct FrameIter {
    r: Option<io::BufReader<File>>,
    at: u64,
    done: bool,
}

impl Iterator for FrameIter {
    type Item = io::Result<(u64, BlockEnvelope)>;

    fn next(&mut self) -> Option<io::Result<(u64, BlockEnvelope)>> {
        if self.done {
            return None;
        }
        let r = self.r.as_mut()?;
        let mut len4 = [0u8; 4];
        match r.read_exact(&mut len4) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
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
        match r.read_exact(&mut payload) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // `Store::open` truncates a torn tail before anything reads
                // the log, so reaching this is a file changing underneath a
                // reader rather than the ordinary crash case. Stop, do not
                // guess.
                eprintln!("store: dropping truncated trailing log frame (crash mid-append)");
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        }
        let env = match crate::codec::decode_envelope(&payload) {
            Ok(env) => env,
            Err(e) => {
                self.done = true;
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e.to_string(),
                )));
            }
        };
        let off = self.at;
        self.at += 4 + len as u64;
        Some(Ok((off, env)))
    }
}
