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
            // Read the HEADER only, then decide. The slot is all the filter
            // needs, and it lives in the first `ENCODED_LEN` bytes of the
            // frame, so a frame that will be discarded never has to be read
            // or allocated past its header.
            //
            // **This is the cold-sync bottleneck, and it was measured.**
            // Before this change the body of every frame was read into a
            // fresh `vec![0u8; len]` before the slot was even looked at, so
            // answering `after_slot = S` read and allocated the WHOLE log
            // from byte zero — every block ahead of S included. It is
            // O(chain length) per request, on the SERVER, for every peer,
            // every time, and it gets worse as the chain grows. Serving a
            // node at slot 38,000 of a 500 MB log meant reading 500 MB and
            // throwing away ~38,000 payloads to emit at most 512.
            //
            // Measured against the two published bootnodes on 2026-09-02,
            // asking for one page as a plain socket client: the answer
            // arrived at 1.9-22 blocks/s and varied by 10x between the two
            // hosts and between requests, while a cold node's own CPU sat at
            // 0-6% waiting for it. The requester is not the slow half.
            //
            // Skipping with `seek` keeps the frames returned, their order and
            // their bytes exactly as they were: `out` is pushed from the same
            // predicate over the same headers. Only the reads that produced
            // nothing are gone. Not a consensus change -- this function
            // serves bytes off the log and computes no state.
            let hdr_len = bloch_pos_committee::header::BlockHeaderV4::ENCODED_LEN;
            if len < hdr_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "log frame shorter than a header"));
            }
            let mut hdr_buf = vec![0u8; hdr_len];
            match f.read_exact(&mut hdr_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
            let header =
                bloch_pos_committee::header::BlockHeaderV4::canonical_deserialize(&hdr_buf)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "undecodable header in block log")
                    })?;
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
