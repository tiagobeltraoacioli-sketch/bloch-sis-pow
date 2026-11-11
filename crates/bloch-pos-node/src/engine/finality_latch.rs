// SPDX-License-Identifier: AGPL-3.0-or-later
//! The durable copy of the finality latch (security review 2026-11-10, PER-3).
//!
//! [`Engine::finalized_latch`] is the highest finalized checkpoint this node
//! ever adopted, and it is kept across reorgs on purpose: the state a reorg
//! adopts can report less finality than the state it replaced. It used to
//! live in memory only, on the claim that boot replay rebuilds it. That holds
//! only when the logged chain is the one that finalized it. After a reorg
//! whose fork point is at or above the latch block and below the block that
//! carried the finalizing votes, the log holds a branch whose every state
//! reports the older checkpoint, so a restart in that interval rebuilt the
//! latch lower and the node would then take a cut it had refused before.
//!
//! The latch is therefore also written to `finality_latch.bin`:
//!
//! - **When.** After the block log is durable through the block that raised
//!   it (`apply_canonical`, after the append), after a reorg's log rewrite
//!   has been published (the slot loop), and at boot. Never while a rewrite
//!   is pending: the latch block may be on the adopted branch, which is not
//!   on disk yet, and a crash would then leave a record the log contradicts.
//! - **Monotone.** A stored record is replaced only by a higher one.
//! - **At boot** ([`Engine::reconcile_finalized_latch`]) the stored record is
//!   compared with the replayed canonical chain. On the chain: the latch is
//!   the higher of the stored and the replayed one. Not on the chain (another
//!   block at that height, or the log ends below it): the node refuses to
//!   start, because every way of continuing is a way of following a chain
//!   below a checkpoint it already finalized. The existing operator override
//!   (`--allow-finality-rewind`) discards the record instead, loudly.
//!
//! Node-local: no block or transaction validity depends on this file.
use super::*;
use sha3::{Digest, Sha3_256};

const FILE: &str = "finality_latch.bin";
const MAGIC: &[u8; 8] = b"BPOSFLT1";
/// magic, manifest digest, height, slot, root, checksum of all before it.
const RECORD_LEN: usize = 8 + 32 + 8 + 8 + 32 + 32;
/// The record without its trailing checksum.
const BODY_LEN: usize = RECORD_LEN - 32;

/// The latch as stored: the canonical height, slot and id of the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StoredLatch {
    pub(super) height: u64,
    pub(super) slot: u64,
    pub(super) root: [u8; 32],
}

fn invalid(s: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s.to_string())
}

fn encode(manifest_digest: &[u8; 32], latch: &StoredLatch) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECORD_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(manifest_digest);
    bytes.extend_from_slice(&latch.height.to_le_bytes());
    bytes.extend_from_slice(&latch.slot.to_le_bytes());
    bytes.extend_from_slice(&latch.root);
    let checksum = Sha3_256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}

fn decode(manifest_digest: &[u8; 32], bytes: &[u8]) -> io::Result<StoredLatch> {
    if bytes.len() != RECORD_LEN {
        return Err(invalid("unexpected length"));
    }
    let (body, checksum) = bytes.split_at(BODY_LEN);
    if Sha3_256::digest(body).as_slice() != checksum {
        return Err(invalid("checksum mismatch"));
    }
    if &body[..8] != MAGIC {
        return Err(invalid("not a finality latch record"));
    }
    if &body[8..40] != manifest_digest {
        return Err(invalid("written for another network"));
    }
    let number = |at: usize| -> io::Result<u64> {
        let field: [u8; 8] = at.checked_add(8)
            .and_then(|to| body.get(at..to))
            .and_then(|f| f.try_into().ok())
            .ok_or_else(|| invalid("truncated field"))?;
        Ok(u64::from_le_bytes(field))
    };
    let root: [u8; 32] = body.get(56..88).and_then(|f| f.try_into().ok())
        .ok_or_else(|| invalid("truncated root"))?;
    Ok(StoredLatch { height: number(40)?, slot: number(48)?, root })
}

impl Engine {
    fn finality_latch_path(&self) -> PathBuf {
        self.store.directory().join(FILE)
    }

    fn manifest_digest(&self) -> [u8; 32] {
        Sha3_256::digest(self.manifest.encode()).into()
    }

    /// The stored record. `Ok(None)` when the file does not exist; an
    /// unreadable or foreign file is an error, never "no record".
    pub(super) fn stored_finalized_latch(&self) -> io::Result<Option<StoredLatch>> {
        match std::fs::read(self.finality_latch_path()) {
            Ok(bytes) => decode(&self.manifest_digest(), &bytes).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Replace the stored record with the canonical block at `height`.
    fn write_stored_latch(&self, height: u64, root: [u8; 32]) -> io::Result<()> {
        let slot = usize::try_from(height)
            .ok()
            .and_then(|h| self.chain.get(h))
            .filter(|(_, id)| id.as_bytes() == &root)
            .map(|(slot, _)| *slot)
            .ok_or_else(|| invalid("the finality latch does not name a canonical block"))?;
        let record = encode(&self.manifest_digest(), &StoredLatch { height, slot, root });
        crate::store::atomic_private_write(&self.finality_latch_path(), &record)
    }

    /// Raise the stored record to the in-memory latch. Returns whether the
    /// file was written. Never lowers it and never writes while a reorg's log
    /// rewrite is pending (see the module docs).
    fn raise_stored_latch(&self) -> io::Result<bool> {
        let Some((height, root)) = self.finalized_latch else { return Ok(false) };
        if self.store.rewrite_pending() {
            return Ok(false);
        }
        if self.stored_finalized_latch()?.is_some_and(|stored| stored.height >= height) {
            return Ok(false);
        }
        self.write_stored_latch(height, root)?;
        Ok(true)
    }

    /// The live call sites' form of [`Engine::raise_stored_latch`]. A failed
    /// write is reported and retried the next time the latch rises: the
    /// in-memory latch still guards this process, and stopping a validator
    /// over it would cost more than the restart window it protects.
    pub(super) fn persist_finalized_latch(&self) {
        if let Err(e) = self.raise_stored_latch() {
            eprintln!(
                "FINALITY_LATCH: could not persist the finalized checkpoint to {FILE}: {e}. \
                 Until it is written, a restart may rebuild a lower floor from the block log."
            );
        }
    }

    /// Boot: make the in-memory latch the higher of the stored record and
    /// the one replay rebuilt, or refuse to start when the stored record is
    /// not on the replayed canonical chain. Called once, after replay.
    pub(super) fn reconcile_finalized_latch(&mut self) -> io::Result<()> {
        let stored = match self.stored_finalized_latch() {
            Ok(stored) => stored,
            Err(e) => {
                return Err(crate::ws_boot::boot_refused(format!(
                    "{FILE} cannot be used ({e}). It records the highest checkpoint this node \
                     finalized, and without it a restart may follow a chain below that \
                     checkpoint. Restore the file, or delete it to accept the checkpoint \
                     rebuilt from the block log."
                )));
            }
        };
        let Some(stored) = stored else {
            // Nothing recorded yet: a first boot of a build that keeps the
            // record, or a chain that has not finalized anything.
            self.raise_stored_latch()?;
            return Ok(());
        };
        let local = usize::try_from(stored.height).ok().and_then(|h| self.chain.get(h));
        let on_chain = local
            .is_some_and(|(slot, id)| *slot == stored.slot && id.as_bytes() == &stored.root);
        if !on_chain {
            let found = match local {
                Some((slot, id)) => format!(
                    "the block log holds {} (slot {slot}) at that height",
                    crate::codec::hex8(id.as_bytes())
                ),
                None => format!("the block log ends at height {}", self.head_height()),
            };
            if self.finality_rewind_override {
                eprintln!(
                    "FINALITY_LATCH: BLOCH_ALLOW_FINALITY_REWIND is set — DISCARDING the stored \
                     finalized checkpoint {} (height {}, slot {}): {found}. The floor is now \
                     whatever the block log finalizes. This must only happen with a human \
                     operator's deliberate, informed consent.",
                    crate::codec::hex8(&stored.root),
                    stored.height,
                    stored.slot,
                );
                match self.finalized_latch {
                    Some((height, root)) => self.write_stored_latch(height, root)?,
                    None => std::fs::remove_file(self.finality_latch_path())?,
                }
                return Ok(());
            }
            return Err(crate::ws_boot::boot_refused(format!(
                "this node finalized checkpoint {} at height {} (slot {}) and recorded it in \
                 {FILE}, but {found}. Starting would let it follow a chain below a checkpoint \
                 it already finalized. If the block log was truncated, replaced or restored \
                 from an older copy, restore the log that matches; if a rewind below that \
                 checkpoint is intended, restart with --allow-finality-rewind \
                 (BLOCH_ALLOW_FINALITY_REWIND=1).",
                crate::codec::hex8(&stored.root),
                stored.height,
                stored.slot,
            )));
        }
        match self.finalized_latch {
            Some((height, _)) if height >= stored.height => {
                self.raise_stored_latch()?;
            }
            replayed => {
                println!(
                    "finality-latch: restored height {} ({}) from {FILE}; the replayed chain \
                     reports {}",
                    stored.height,
                    crate::codec::hex8(&stored.root),
                    replayed.map_or_else(|| "none".to_string(), |(h, _)| format!("height {h}")),
                );
                self.finalized_latch = Some((stored.height, stored.root));
                self.hollow_finalized_bodies();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Five proposed blocks, logged, with the latch armed by hand at
    /// `height` and written through the production path.
    fn latched_at(height: usize) -> (Engine, perf_support::TestDir, Vec<BlockEnvelope>) {
        let (mut engine, dir) = perf_support::proposing_engine();
        for slot in 1..=5 {
            engine.propose(slot);
        }
        assert_eq!(engine.chain.len(), 6, "five blocks over genesis");
        let logged: Vec<BlockEnvelope> = engine.chain[1..]
            .iter()
            .map(|(_, id)| engine.blocks[id.as_bytes()].clone())
            .collect();
        engine.finalized_latch = Some((height as u64, *engine.chain[height].1.as_bytes()));
        engine.persist_finalized_latch();
        (engine, dir, logged)
    }

    /// What a restart leaves of the engine before it replays its log.
    fn restart(engine: &mut Engine) {
        let genesis = engine.manifest.genesis_id();
        engine.state = StateCell::new(engine.manifest.genesis_state());
        engine.chain = vec![(0, genesis)];
        engine.canonical = BTreeSet::from([*genesis.as_bytes()]);
        engine.blocks.clear();
        engine.pool.clear();
        engine.recent_states.clear();
        engine.reorg_anchors = Default::default();
        engine.tx_slot_index.clear();
        engine.tx_slot_index_order.clear();
        engine.finalized_latch = None;
        engine.live = false;
    }

    fn replay(engine: &mut Engine, logged: &[BlockEnvelope]) {
        for env in logged {
            assert!(engine.ingest_replay(env.clone()), "the log replays");
        }
    }

    /// PER-3: the log's states report no finality (as after a reorg that
    /// dropped the finalizing votes), so replay alone rebuilds no latch. The
    /// stored record restores it and the cut it guards is still refused.
    #[test]
    fn a_restart_does_not_lower_the_latch() {
        let (mut engine, _dir, logged) = latched_at(3);
        let latch = engine.finalized_latch.expect("armed");
        assert_eq!(
            engine.stored_finalized_latch().expect("readable"),
            Some(StoredLatch { height: 3, slot: engine.chain[3].0, root: latch.1 }),
            "the latch is on disk"
        );

        restart(&mut engine);
        replay(&mut engine, &logged);
        assert!(
            engine.finalized_latch.is_none(),
            "fixture: replay of this log rebuilds no latch on its own"
        );
        engine.reconcile_finalized_latch().expect("the stored latch is on the replayed chain");
        engine.live = true;
        assert_eq!(engine.finalized_latch, Some(latch), "the latch survived the restart");

        let below = *engine.chain[2].1.as_bytes();
        let head = engine.head_id();
        assert!(!engine.do_reorg(below, Vec::new()), "a cut below the restored latch is refused");
        assert_eq!(engine.head_id(), head);
        assert_eq!(engine.finality_rewinds_refused, 1);
        let at = *engine.chain[3].1.as_bytes();
        assert!(engine.do_reorg(at, Vec::new()), "a cut at the latch stays legal");
    }

    /// A latch replay rebuilt higher than the stored one wins and is stored;
    /// a lower in-memory latch never lowers the file.
    #[test]
    fn the_stored_latch_only_moves_up() {
        let (mut engine, _dir, logged) = latched_at(3);
        let stored = engine.stored_finalized_latch().expect("readable").expect("stored");

        engine.finalized_latch = Some((2, *engine.chain[2].1.as_bytes()));
        engine.persist_finalized_latch();
        assert_eq!(engine.stored_finalized_latch().expect("readable"), Some(stored), "not lowered");

        restart(&mut engine);
        replay(&mut engine, &logged);
        let higher = (4u64, *engine.chain[4].1.as_bytes());
        engine.finalized_latch = Some(higher);
        engine.reconcile_finalized_latch().expect("consistent");
        assert_eq!(engine.finalized_latch, Some(higher), "the replayed latch is the higher one");
        assert_eq!(
            engine.stored_finalized_latch().expect("readable").map(|s| (s.height, s.root)),
            Some(higher),
            "and the file follows it up"
        );
    }

    /// The stored checkpoint is not on the local chain: refuse to boot,
    /// unless the operator override discards the record.
    #[test]
    fn a_stored_latch_the_local_chain_contradicts_refuses_boot() {
        let (mut engine, _dir, logged) = latched_at(3);
        let stored = engine.stored_finalized_latch().expect("readable");

        // The log ends below the recorded checkpoint.
        restart(&mut engine);
        replay(&mut engine, &logged[..2]);
        let err = engine.reconcile_finalized_latch().expect_err("log ends below the latch");
        assert!(crate::ws_boot::is_non_retryable(&err), "a refusal, not a retryable fault: {err}");
        assert!(engine.finalized_latch.is_none(), "nothing was adopted from the record");
        assert_eq!(engine.stored_finalized_latch().expect("readable"), stored, "record untouched");

        // Another block at the recorded height. Later slots: the fixture's
        // slashing protection has already signed slots 1 to 5.
        restart(&mut engine);
        engine.live = true;
        for slot in 6..=9 {
            engine.propose(slot);
        }
        assert_eq!(engine.chain.len(), 5, "fixture: the other chain reaches the recorded height");
        assert_ne!(engine.chain[3].0, logged[2].header.slot, "fixture: a different block at height 3");
        let err = engine.reconcile_finalized_latch().expect_err("a conflicting block at the height");
        assert!(crate::ws_boot::is_non_retryable(&err), "{err}");
        assert_eq!(engine.stored_finalized_latch().expect("readable"), stored, "record untouched");

        // The operator override accepts the local chain and drops the record.
        engine.finality_rewind_override = true;
        engine.reconcile_finalized_latch().expect("override accepts the local chain");
        assert_eq!(engine.stored_finalized_latch().expect("readable"), None);
    }

    /// A damaged record is a refusal, not "no record".
    #[test]
    fn a_damaged_record_refuses_boot() {
        let (mut engine, dir, logged) = latched_at(3);
        let path = dir.0.join(FILE);
        let mut bytes = std::fs::read(&path).expect("record exists");
        bytes[50] ^= 1;
        std::fs::write(&path, &bytes).expect("damage the record");
        restart(&mut engine);
        replay(&mut engine, &logged);
        let err = engine.reconcile_finalized_latch().expect_err("damaged record");
        assert!(crate::ws_boot::is_non_retryable(&err), "{err}");

        // A record of another network is refused the same way.
        let foreign = encode(&[7u8; 32], &StoredLatch { height: 1, slot: 1, root: [1; 32] });
        assert!(decode(&engine.manifest_digest(), &foreign).is_err());
    }

    /// The live path: a checkpoint this node finalizes on its own votes is
    /// on disk once the block that finalized it is logged.
    #[test]
    fn own_finality_is_persisted() {
        let (engine, _dir) = finality_latch_tests::engine_with_own_finality();
        let (height, root) = engine.finalized_latch.expect("finalizing arms the latch");
        assert_eq!(
            engine.stored_finalized_latch().expect("readable").map(|s| (s.height, s.root)),
            Some((height, root)),
        );
    }
}
