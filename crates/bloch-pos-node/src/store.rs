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
    /// The data dir this store was opened on — the anchor for the node's
    /// sibling stores (snapshots, statesync partials).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

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

#[cfg(test)]
mod scan {
    //! One-shot replay-precondition scanner for the 2026-08-31 staking
    //! closure (the consensus rejection of tags `0x02`/`0x03`/`0x04`).
    //!
    //! The RPC exposes only `tx_count`, so whether any live block carries a
    //! staking message cannot be answered from outside the node. This test
    //! answers it with the node's own machinery — [`Store::read_all`]'s
    //! framing and `PosTransaction::from_canonical_bytes`, the same decode
    //! replay runs (`engine::body_transactions`) — never a byte grep, so a
    //! `0x02` inside a witness table or an evidence payload cannot be
    //! miscounted as a staking message.
    //!
    //! Run against a copied mainnet log (copy READ-ONLY off a fleet host):
    //!
    //! ```text
    //! mkdir -p /tmp/mainnet-scan && cp /tmp/mainnet-blocks.log /tmp/mainnet-scan/blocks.log
    //! SCAN_BLOCKS_LOG=/tmp/mainnet-scan cargo test -p bloch-pos-node --bins \
    //!     scan_block_log_for_staking_tags -- --ignored --nocapture
    //! ```
    //!
    //! `#[ignore]` because it needs a real chain log; it is a diagnostic,
    //! not a CI assertion. The final assert encodes the rollout question:
    //! it FAILS if any block anywhere carries tag 0x02, 0x03 or 0x04 —
    //! in which case the every-epoch rejection would strand replay at that
    //! block and must instead ship behind an activation gate above it.
    //!
    //! # THIS RESULT EXPIRES. It is a cutover precondition, not a fact.
    //!
    //! The known-clean answer was measured on **2026-08-31** and says nothing
    //! about the log on the day the fleet is rebuilt: a block log only grows,
    //! and one new block carrying any of those tags flips the verdict. So
    //! this must be re-run against a CURRENT mainnet log immediately before
    //! rollout — not read out of a commit message, a report, or this comment.
    //!
    //! Re-running it is one test. Not re-running it, on a log that has since
    //! gained such a block, stops every upgraded node at that block: the
    //! rejection is ungated, so there is no epoch at which replay gets past
    //! it. The operator-facing statement of the same rule, with the go/no-go
    //! criterion, is `docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` §11.0.

    use super::Store;
    use bloch_pos_committee::transition::{PosTransaction, TxDecodeError};
    use std::path::Path;

    #[test]
    #[ignore]
    fn scan_block_log_for_staking_tags() {
        let dir = std::env::var("SCAN_BLOCKS_LOG")
            .expect("set SCAN_BLOCKS_LOG to a directory containing blocks.log");
        // The digest only matters for a dir that already has a meta.bin;
        // a bare copied blocks.log gets a fresh marker and is read as-is.
        let store = Store::open(Path::new(&dir), &[0u8; 32]).expect("open scan dir");
        let envs = store.read_all().expect("read the block log");

        let mut blocks_with_txs = 0usize;
        let mut tx_total = 0usize;
        // Counts indexed by wire tag byte (first byte of the canonical
        // encoding), populated only after the REAL decoder has classified
        // the bytes.
        let mut by_tag: std::collections::BTreeMap<u8, usize> = std::collections::BTreeMap::new();
        // The rollout question: every staking-tagged transaction, located.
        let mut staking_hits: Vec<(usize, u64, u8)> = Vec::new(); // (log index, slot, tag)
        let mut undecodable: Vec<(usize, u64, String)> = Vec::new();

        for (i, env) in envs.iter().enumerate() {
            if env.body.transactions.is_empty() {
                continue;
            }
            blocks_with_txs += 1;
            for bytes in &env.body.transactions {
                tx_total += 1;
                let tag = *bytes.first().expect("empty tx bytes in a stored body");
                match PosTransaction::from_canonical_bytes(bytes) {
                    Ok(tx) => {
                        // Classify by the DECODED variant; then sanity-pin
                        // that the wire tag agrees with it.
                        let decoded_tag = match tx {
                            PosTransaction::Transfer { .. } => 0x01,
                            PosTransaction::Deposit { .. } => 0x02,
                            PosTransaction::Exit { .. } => 0x03,
                            PosTransaction::Delegate { .. } => 0x04,
                            PosTransaction::SlashingEvidence(_) => 0x05,
                            PosTransaction::TransferV2 { .. } => 0x06,
                            PosTransaction::DepositV2 { .. } => 0x07,
                            PosTransaction::Withdraw { .. } => 0x08,
                            PosTransaction::ExitV2(_) => 0x09,
                        };
                        assert_eq!(tag, decoded_tag, "wire tag vs decoded variant");
                        *by_tag.entry(tag).or_insert(0) += 1;
                        if matches!(tag, 0x02 | 0x03 | 0x04) {
                            staking_hits.push((i, env.header.slot, tag));
                        }
                    }
                    // Tag 0x05 is one-way by construction; a stored one
                    // would ALREADY break replay today. Count it, loudly.
                    Err(TxDecodeError::EvidenceNotDecodable) => {
                        *by_tag.entry(0x05).or_insert(0) += 1;
                        undecodable.push((i, env.header.slot, "evidence (0x05)".into()));
                    }
                    Err(e) => {
                        undecodable.push((i, env.header.slot, format!("{e:?} (tag {tag:#04x})")));
                    }
                }
            }
        }

        println!("blocks in log:            {}", envs.len());
        println!("blocks carrying txs:      {blocks_with_txs}");
        println!("transactions total:       {tx_total}");
        for (tag, n) in &by_tag {
            let name = match tag {
                0x01 => "Transfer",
                0x02 => "Deposit  (LEGACY STAKING)",
                0x03 => "Exit     (LEGACY STAKING)",
                0x04 => "Delegate (LEGACY STAKING)",
                0x05 => "SlashingEvidence",
                0x06 => "TransferV2",
                0x07 => "DepositV2",
                0x08 => "Withdraw",
                0x09 => "ExitV2",
                _ => "??",
            };
            println!("  tag {tag:#04x} {name:<26} {n}");
        }
        for (i, slot, tag) in &staking_hits {
            println!("STAKING TX IN LOG: log index {i}, slot {slot}, tag {tag:#04x}");
        }
        for (i, slot, why) in &undecodable {
            println!("UNDECODABLE TX: log index {i}, slot {slot}: {why}");
        }

        assert!(
            undecodable.is_empty(),
            "the log holds transactions replay cannot decode — see the lines above"
        );
        assert!(
            staking_hits.is_empty(),
            "REPLAY PRECONDITION FAILED: {} staking-tagged transaction(s) exist in the live \
             log (lines above). The every-epoch rejection of tags 0x02/0x03/0x04 would strand \
             every upgraded node at the first of those blocks; the rejection must ship behind \
             an activation gate keyed ABOVE the last of them instead.",
            staking_hits.len()
        );
    }
}
