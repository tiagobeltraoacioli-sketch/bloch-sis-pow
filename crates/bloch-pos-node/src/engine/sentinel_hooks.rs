// SPDX-License-Identifier: AGPL-3.0-or-later

//! The engine half of the Bloch Sentinel hooks (`crate::sentinel`).
//!
//! **Read-only.** Every function here takes `&self`, reads values the engine
//! already holds, and hands copies to the Sentinel. None of them is called on
//! a path whose result feeds the state transition, a verdict, fork choice or
//! a state root, and each returns at its first line when the Sentinel is off
//! (the default). The tests at the bottom replay a chain with the Sentinel on
//! and compare it byte for byte with the same replay without it.

use super::*;
use crate::sentinel::{self, AdvertKind, ChainSnapshot, Observation};

/// The few header fields a peer "advertises", taken before the envelope is
/// moved into ingestion. `None` (and no hashing at all) when the Sentinel is
/// off.
pub(super) struct SeenHeader {
    source: Option<[u8; 32]>,
    finalized_root: [u8; 32],
    justified_root: [u8; 32],
    block_root: [u8; 32],
    slot: u64,
}

pub(super) fn header_seen(env: &BlockEnvelope, source: Option<[u8; 32]>) -> Option<SeenHeader> {
    if !sentinel::enabled() {
        return None;
    }
    Some(SeenHeader {
        source,
        finalized_root: env.header.finalized_root,
        justified_root: env.header.justified_root,
        block_root: *env.block_id().as_bytes(),
        slot: env.header.slot,
    })
}

/// Furthest the status roll goes past the head's epoch: the largest
/// finality-lag threshold. Beyond it (and whenever the node is not live) the
/// unrolled head is reported instead, flagged as such; rolling thousands of
/// epochs for a status line is not worth a slot.
const KES_VIEW_MAX_ROLL_EPOCHS: u64 = 64;

impl Engine {
    /// The state the signer decides the KES mode on, for the status: the
    /// head state rolled into `wall_epoch` — `Engine::duty_state`, the very
    /// function `attest_for`/`propose`/`submit_kes_rotation` take the state
    /// they hand to `prepare_kes` from (audit L1-01, review R-03). The mode
    /// is then read with `Engine::duty_signing_mode`, the signer's own call.
    /// Read-only: `duty_state` returns a shared derived value and never
    /// touches the canonical state.
    ///
    /// Returns the state and the epoch it stands in: `wall_epoch` when
    /// rolled, the head's epoch when the unrolled head is reported instead.
    fn sentinel_kes_state(&self, wall_epoch: u64) -> (Arc<CommittedState>, u64) {
        let head_epoch = epoch_of(self.state.slot());
        if self.live && wall_epoch.saturating_sub(head_epoch) <= KES_VIEW_MAX_ROLL_EPOCHS {
            (self.duty_state(wall_epoch), wall_epoch.max(head_epoch))
        } else {
            // `rolled_to` at or below the head's epoch is the head state.
            (self.duty_state(head_epoch), head_epoch)
        }
    }

    /// Once per wall slot: publish the snapshot `getsecuritystatus` reads.
    pub(super) fn sentinel_slot_tick(&self) {
        let Some(s) = sentinel::current() else { return };
        s.publish_chain(self.sentinel_snapshot());
    }

    pub(super) fn sentinel_snapshot(&self) -> ChainSnapshot {
        use bloch_pos_committee::kes::SigningMode;
        let fin = self.state.finality();
        let wall_epoch = epoch_of(self.wall_slot);
        let (kes_state, kes_state_epoch) = self.sentinel_kes_state(wall_epoch);
        let validator = self.duty_index(&kes_state);
        let (mode, period) = match validator {
            None => ("no_validator", None),
            Some(v) => match Self::duty_signing_mode(&*kes_state, v, wall_epoch) {
                SigningMode::Static => ("static", None),
                SigningMode::Kes(p) => ("kes", Some(p)),
                SigningMode::FailClosed => ("fail_closed", None),
            },
        };
        let (devnet_peers, libp2p_peers) = self.net.peer_counts();
        ChainSnapshot {
            wall_slot: self.wall_slot,
            wall_epoch,
            live: self.live,
            head_slot: self.head_slot_now(),
            head_height: self.head_height(),
            head_root: *self.head_id().as_bytes(),
            justified_epoch: fin.justified.epoch,
            justified_root: fin.justified.root,
            finalized_epoch: fin.finalized.epoch,
            finalized_root: fin.finalized.root,
            finalized_height: self.finalized_height(),
            latch: self.finalized_latch,
            transport: self.net.transport_name(),
            devnet_peers,
            libp2p_peers,
            doppelganger: sentinel::Doppelganger {
                observe_until_slot: self.doppelganger_observe_until,
                halted: self.doppelganger_halted,
            },
            kes: sentinel::KesView {
                validator,
                keystore_loaded: self.keys.is_some(),
                kes_key_loaded: self.kes.is_some(),
                mode,
                period,
                bind_epoch: KeyLookup::kes_enforced_from(&*kes_state),
                head_state_epoch: kes_state_epoch,
            },
        }
    }

    /// Classify the finalized checkpoint a peer's block advertised against
    /// this node's own, and record it if it is ahead of or conflicts with
    /// ours. Lookups only: `canonical`/`blocks` membership and the canonical
    /// slot index, each logarithmic.
    pub(super) fn sentinel_observe_block(&self, seen: SeenHeader, verdict: Verdict) {
        let Some(s) = sentinel::current() else { return };
        let Some(source) = seen.source else { return };
        // A provably invalid block advertises nothing.
        if verdict == Verdict::Reject {
            return;
        }
        match self.sentinel_classify(source, &seen, verdict) {
            Some(obs) => s.observe_advert(obs),
            // Only a block the engine accepted can withdraw an observation;
            // an unauthenticated header proves agreement no more than it
            // proves a split (review R-01).
            None if verdict == Verdict::Accept => s.advert_agrees(&source),
            None => {}
        }
    }

    fn sentinel_classify(&self, source: [u8; 32], seen: &SeenHeader, verdict: Verdict) -> Option<Observation> {
        let ours = self.state.finality().finalized;
        let advertised = seen.finalized_root;
        if advertised == ours.root {
            return None;
        }
        let (kind, root_slot) = if self.canonical.contains(&advertised) {
            let slot = self.slot_of_canonical_root(&advertised)?;
            let our_slot = self.slot_of_canonical_root(&ours.root).unwrap_or(0);
            if slot <= our_slot {
                // Behind us on our own chain: not a signal.
                return None;
            }
            (AdvertKind::Ahead, Some(slot))
        } else if let Some(env) = self.blocks.get(&advertised) {
            (AdvertKind::Conflicting, Some(env.header.slot))
        } else {
            (AdvertKind::UnknownRoot, None)
        };
        Some(Observation {
            source,
            kind,
            advertised_finalized: advertised,
            advertised_justified: seen.justified_root,
            block_root: seen.block_root,
            block_slot: seen.slot,
            root_slot,
            epoch_hint: root_slot.map(|s| s.div_ceil(SLOTS_PER_EPOCH)),
            our_finalized_epoch: ours.epoch,
            our_finalized_root: ours.root,
            verdict: sentinel::verdict_name(verdict),
            // `Accept` is the only verdict reached after the proposer
            // signature, the ancestry and the transition were all checked;
            // `Ignore` can be returned before any signature is looked at.
            verified: verdict == Verdict::Accept,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::Json;

    fn logged_chain(n: u64) -> (Engine, perf_support::TestDir, Vec<BlockEnvelope>) {
        let (mut engine, dir) = perf_support::proposing_engine();
        for slot in 1..=n {
            engine.propose(slot);
        }
        let logged: Vec<BlockEnvelope> =
            engine.chain[1..].iter().map(|(_, id)| engine.blocks[id.as_bytes()].clone()).collect();
        (engine, dir, logged)
    }

    fn reset(engine: &mut Engine) {
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

    /// Replay `logged`, optionally with every Sentinel hook firing as the
    /// live loop fires it, and return (chain, state root, block-count JSON).
    fn replay(engine: &mut Engine, logged: &[BlockEnvelope], hooks: bool) -> (Vec<(u64, BlockId)>, [u8; 32], String) {
        reset(engine);
        for env in logged {
            let seen = if hooks { header_seen(env, Some([0xab; 32])) } else { None };
            assert!(engine.ingest_replay(env.clone()), "the log replays");
            if hooks {
                engine.wall_slot = env.header.slot;
                engine.sentinel_slot_tick();
                if let Some(seen) = seen {
                    engine.sentinel_observe_block(seen, Verdict::Accept);
                }
            }
        }
        let root = engine.state.state_root();
        (engine.chain.clone(), root, engine.block_count_reply().to_string())
    }

    /// The flags-off parity proof: replaying the same canonical history with
    /// the Sentinel ON (every hook firing) yields the identical chain, state
    /// root and published summary as with it OFF.
    #[test]
    fn replay_is_byte_identical_with_and_without_the_sentinel() {
        let (mut engine, _dir, logged) = logged_chain(6);
        assert!(sentinel::current().is_none(), "off by default");
        let off = replay(&mut engine, &logged, false);
        let s = sentinel::test_sentinel(sentinel::Config { status: true, ..Default::default() });
        let on = sentinel::with_test_sentinel(s.clone(), || replay(&mut engine, &logged, true));
        assert_eq!(off, on, "a Sentinel hook changed replay");
        // And the hooks really ran.
        let status = s.status_json();
        assert_eq!(status.get("chain").and_then(|c| c.get("published")), Some(&Json::Bool(true)));
        assert_eq!(
            status.get("chain").and_then(|c| c.get("head")).and_then(|h| h.get("root")).and_then(Json::as_str),
            Some(crate::codec::hex32(on.0.last().unwrap().1.as_bytes()).as_str())
        );
    }

    #[test]
    fn hooks_are_inert_when_the_sentinel_is_off() {
        let (engine, _dir, logged) = logged_chain(2);
        assert!(header_seen(&logged[0], Some([1; 32])).is_none());
        engine.sentinel_slot_tick();
        assert!(sentinel::status_rpc().is_none(), "getsecuritystatus is method-not-found when off");
    }

    fn seen_with_finalized(engine: &Engine, finalized_root: [u8; 32]) -> SeenHeader {
        SeenHeader {
            source: Some([7; 32]),
            finalized_root,
            justified_root: [0; 32],
            block_root: *engine.head_id().as_bytes(),
            slot: engine.head_slot_now(),
        }
    }

    #[test]
    fn peer_finalized_ahead_is_classified_against_our_finality() {
        let (engine, _dir, _logged) = logged_chain(5);
        let s = sentinel::test_sentinel(sentinel::Config { status: true, events: None, ..Default::default() });
        let ours = engine.state.finality().finalized;
        sentinel::with_test_sentinel(s.clone(), || {
            // Same root as ours: nothing.
            assert!(engine.sentinel_classify([7; 32], &seen_with_finalized(&engine, ours.root), Verdict::Accept).is_none());
            // A canonical block above our finalized checkpoint: ahead.
            let canonical_above = *engine.chain[4].1.as_bytes();
            let obs = engine
                .sentinel_classify([7; 32], &seen_with_finalized(&engine, canonical_above), Verdict::Accept)
                .expect("ahead");
            assert_eq!(obs.kind, AdvertKind::Ahead);
            assert_eq!(obs.root_slot, Some(engine.chain[4].0));
            // A root we have never seen: unknown.
            let obs = engine
                .sentinel_classify([7; 32], &seen_with_finalized(&engine, [0x5a; 32]), Verdict::Ignore)
                .expect("unknown");
            assert_eq!(obs.kind, AdvertKind::UnknownRoot);
            assert_eq!(obs.verdict, "ignore");

            // Through the public hook: recorded, listed, evented once.
            engine.sentinel_observe_block(seen_with_finalized(&engine, canonical_above), Verdict::Accept);
            engine.sentinel_observe_block(seen_with_finalized(&engine, canonical_above), Verdict::Accept);
            let status = s.status_json();
            let pfa = status.get("peer_finalized_ahead").unwrap();
            assert_eq!(pfa.get("count").and_then(Json::as_u64), Some(1));
            let entry = pfa.get("entries").and_then(|e| e.at(0)).unwrap();
            assert_eq!(entry.get("kind").and_then(Json::as_str), Some("ahead"));
            assert_eq!(entry.get("count").and_then(Json::as_u64), Some(2));
            let events = sentinel::captured_events(&s);
            assert_eq!(events.iter().filter(|e| e.contains("\"peer_finalized_ahead\"")).count(), 1);

            // A rejected block advertises nothing; agreeing again clears it.
            engine.sentinel_observe_block(seen_with_finalized(&engine, [0x66; 32]), Verdict::Reject);
            engine.sentinel_observe_block(seen_with_finalized(&engine, ours.root), Verdict::Accept);
            let status = s.status_json();
            assert_eq!(status.get("peer_finalized_ahead").and_then(|p| p.get("count")).and_then(Json::as_u64), Some(0));
        });
    }

    /// R-01: an unsigned header (verdict `Ignore`) naming a side block we
    /// hold as its finalized root is listed as unverified and produces NO
    /// event; the same claim on an accepted block produces exactly one.
    #[test]
    fn an_unauthenticated_header_cannot_raise_a_conflicting_checkpoint_event() {
        let (engine, _dir, _fork_point, rival) = super::super::reorg_state_tests::forked(2);
        let rival_id = *rival.block_id().as_bytes();
        let s = sentinel::test_sentinel(sentinel::Config { status: true, ..Default::default() });
        sentinel::with_test_sentinel(s.clone(), || {
            for _ in 0..100 {
                engine.sentinel_observe_block(seen_with_finalized(&engine, rival_id), Verdict::Ignore);
            }
            assert!(sentinel::captured_events(&s).is_empty(), "unverified claims must not be evented");
            let status = s.status_json();
            let pfa = status.get("peer_finalized_ahead").unwrap();
            assert_eq!(pfa.get("count").and_then(Json::as_u64), Some(1));
            assert_eq!(pfa.get("conflicting_strong_count").and_then(Json::as_u64), Some(0));
            assert_eq!(pfa.get("unverified_observations_total").and_then(Json::as_u64), Some(100));
            let entry = pfa.get("entries").and_then(|e| e.at(0)).unwrap();
            assert_eq!(entry.get("evidence").and_then(Json::as_str), Some("unverified"));
            assert_eq!(entry.get("verified"), Some(&Json::Bool(false)));
            // An unauthenticated "agreeing" header does not clear anything either.
            let ours = engine.state.finality().finalized.root;
            engine.sentinel_observe_block(seen_with_finalized(&engine, ours), Verdict::Ignore);
            assert_eq!(s.status_json().get("peer_finalized_ahead").and_then(|p| p.get("count")).and_then(Json::as_u64), Some(1));

            engine.sentinel_observe_block(seen_with_finalized(&engine, rival_id), Verdict::Accept);
            engine.sentinel_observe_block(seen_with_finalized(&engine, rival_id), Verdict::Accept);
            let events = sentinel::captured_events(&s);
            assert_eq!(events.len(), 1, "{events:?}");
            assert!(events[0].contains("\"conflicting_finalized_checkpoint\"") && events[0].contains("\"evidence\":\"verified\""));
            let status = s.status_json();
            assert_eq!(
                status.get("peer_finalized_ahead").and_then(|p| p.get("conflicting_strong_count")).and_then(Json::as_u64),
                Some(1)
            );
        });
    }

    /// R-03: the KES view is read from the state rolled into the wall epoch
    /// (what the signer reads), not from the unrolled head.
    #[test]
    fn kes_view_is_computed_on_the_rolled_state() {
        let (mut engine, _dir, _logged) = logged_chain(2);
        engine.live = true;
        let head_epoch = epoch_of(engine.state.slot());
        engine.wall_slot = (head_epoch + 2) * SLOTS_PER_EPOCH;
        let snap = engine.sentinel_snapshot();
        assert_eq!(snap.kes.head_state_epoch, head_epoch + 2, "rolled into the wall epoch");
        let rolled = engine.rolled_to(head_epoch + 2);
        assert_eq!(snap.kes.bind_epoch, KeyLookup::kes_enforced_from(&*rolled));
        assert_eq!(snap.kes.validator, engine.duty_index(&rolled));
        // Not live, or too far behind: the unrolled head, flagged by its epoch.
        engine.live = false;
        assert_eq!(engine.sentinel_snapshot().kes.head_state_epoch, head_epoch);
        engine.live = true;
        engine.wall_slot = (head_epoch + KES_VIEW_MAX_ROLL_EPOCHS + 1) * SLOTS_PER_EPOCH;
        assert_eq!(engine.sentinel_snapshot().kes.head_state_epoch, head_epoch);
        // The canonical state did not move.
        assert_eq!(epoch_of(engine.state.slot()), head_epoch);
    }

    #[test]
    fn a_stored_side_block_as_finalized_root_is_conflicting() {
        let (engine, _dir, _fork_point, rival) = super::super::reorg_state_tests::forked(2);
        let rival_id = *rival.block_id().as_bytes();
        assert!(!engine.canonical.contains(&rival_id));
        assert!(engine.blocks.get(&rival_id).is_some(), "the fixture stores the rival");
        let obs = engine
            .sentinel_classify([9; 32], &seen_with_finalized(&engine, rival_id), Verdict::Ignore)
            .expect("conflicting");
        assert_eq!(obs.kind, AdvertKind::Conflicting);
        assert_eq!(obs.epoch_hint, Some(rival.header.slot.div_ceil(SLOTS_PER_EPOCH)));
    }
}
