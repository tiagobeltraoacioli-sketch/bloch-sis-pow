// SPDX-License-Identifier: AGPL-3.0-or-later
//! V1-2: a block parked because its proposer could not be authenticated is
//! judged again when the authority the door reads for it has changed, and the
//! door reads the parent's post-state when the reorg ring retains it.
use super::*;
use crate::genesis::ManifestValidator;

/// An engine at block 1 and the real, validly signed block 2 built on it
/// (produced, then rewound and forgotten).
fn engine_and_next_block() -> (Engine, perf_support::TestDir, BlockEnvelope) {
    let (mut engine, dir) = perf_support::proposing_engine();
    engine.propose(1);
    let parent = *engine.head_id().as_bytes();
    engine.propose(2);
    let next = engine.blocks[engine.head_id().as_bytes()].clone();
    assert_eq!(next.header.parent, parent);
    assert!(engine.do_reorg(parent, Vec::new()));
    engine.blocks.remove(next.block_id().as_bytes()).expect("the produced block was stored");
    assert_eq!(*engine.head_id().as_bytes(), parent);
    (engine, dir, next)
}

/// A state whose registry holds another key at index 0: what a head on a
/// branch with a different registration for that index looks like.
fn state_with_another_key(engine: &Engine) -> CommittedState {
    let (other_key, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[0x4B; 32]).unwrap();
    let manifest = Manifest {
        genesis_time_ms: engine.manifest.genesis_time_ms,
        slot_ms: engine.manifest.slot_ms,
        validators: engine.manifest.validators.iter().map(|v| ManifestValidator { pubkey: other_key.clone(), ..v.clone() }).collect(),
        cohort: Vec::new(),
        carryover: None,
        allocations: Vec::new(),
        carryover_entries: Vec::new(),
        format: crate::genesis::ManifestFormat::V1Unbound,
        pre_state_root: std::sync::OnceLock::new(),
    };
    manifest.genesis_state()
}

/// Parked under a head that names another key for the proposer, with the
/// parent already stored: nothing released it before the fix. It is judged
/// again once the head's authority for the proposer changes, and adopted.
#[test]
fn a_block_parked_for_its_proposers_authority_is_judged_again_when_it_changes() {
    let _clock = validator_lifecycle::clock_at(8);
    let (mut engine, _dir, next) = engine_and_next_block();
    let next_id = *next.block_id().as_bytes();
    let genuine = engine.state.arc();
    // Every index is "deposit-added" (O04): a failure is unjudgeable.
    engine.genesis_validator_indices.clear();
    engine.recent_states.clear();
    engine.state.set(state_with_another_key(&engine));

    let verdict = engine.ingest_judged(next.clone());
    assert!(matches!(verdict, Verdict::Ignore), "{verdict:?}");
    assert_eq!(engine.orphans.len(), 1, "parked: this head cannot judge the proposer");
    assert!(engine.authority_parked.judged.contains_key(&next_id));

    // Another block lands; the authority is the same. Nothing to re-judge.
    engine.schedule_unblocked_orphans([0x11; 32], false);
    assert_eq!(engine.orphans.len(), 1);
    assert!(engine.deferred_orphans.is_empty());

    // The head now names the key the block was signed with.
    engine.state.set_arc(genuine);
    engine.schedule_unblocked_orphans([0x11; 32], false);
    assert!(engine.orphans.is_empty(), "released for a new judgement");
    assert_eq!(engine.deferred_orphans.len(), 1);
    assert!(engine.authority_parked.judged.is_empty());

    engine.release_orphan_turn();
    assert!(engine.blocks.contains_key(&next_id), "authenticated and stored");
    assert_eq!(*engine.head_id().as_bytes(), next_id, "and the branch is adopted");
    assert_eq!(engine.rejected_unsigned, 0);
}

/// The door authenticates against the parent's post-state when the ring
/// holds it, so a head that names another key does not park the block.
#[test]
fn the_door_reads_the_proposers_authority_from_the_parents_retained_state() {
    let _clock = validator_lifecycle::clock_at(8);
    let (mut engine, _dir, next) = engine_and_next_block();
    let parent = next.header.parent;
    let genuine = engine.state.arc();
    engine.genesis_validator_indices.clear();
    engine.recent_states.clear();
    engine.recent_states.push_back((parent, Arc::clone(&genuine)));
    let other = Arc::new(state_with_another_key(&engine));
    assert!(Arc::ptr_eq(&engine.proposer_authority_state(&parent), &genuine));
    assert_ne!(
        bloch_pos_committee::kes::authority_fingerprint(&*other, 0, 0),
        bloch_pos_committee::kes::authority_fingerprint(&*genuine, 0, 0),
    );
    // A parent outside the ring falls back to the head.
    assert!(Arc::ptr_eq(&engine.proposer_authority_state(&[0x9A; 32]), &engine.state.arc()));

    // The parked record is taken against that same state: with the parent's
    // post-state retained, a forged signature is parked under ITS authority.
    let mut forged = next.clone();
    forged.proposer_sig.fill(0);
    let forged_id = *forged.block_id().as_bytes();
    assert!(matches!(engine.ingest_judged(forged), Verdict::Ignore));
    assert_eq!(
        engine.authority_parked.judged.get(&forged_id).copied(),
        Some(bloch_pos_committee::kes::authority_fingerprint(&*genuine, 0, 0)),
    );
}

/// The record map never outgrows the orphan pool.
#[test]
fn authority_parked_records_are_bounded_by_the_orphan_pool() {
    let _clock = validator_lifecycle::clock_at(8);
    let (mut engine, _dir, next) = engine_and_next_block();
    engine.genesis_validator_indices.clear();
    for i in 0..(ORPHAN_MAX as u64 + 40) {
        let mut forged = next.clone();
        forged.header.coherence_root = [0; 32];
        forged.header.state_root[..8].copy_from_slice(&i.to_le_bytes());
        forged.proposer_sig.fill(0);
        let id = *forged.block_id().as_bytes();
        engine.park_unjudgeable(id, forged, Source::Local, None);
    }
    assert!(engine.orphans.len() <= ORPHAN_MAX);
    assert!(engine.authority_parked.judged.len() <= ORPHAN_MAX);
    // Entries that left the pool are forgotten at the next comparison.
    engine.orphans.clear();
    engine.state.set_arc(engine.state.arc());
    assert!(engine.authority_parked_due().is_empty());
    assert!(engine.authority_parked.judged.is_empty());
}
