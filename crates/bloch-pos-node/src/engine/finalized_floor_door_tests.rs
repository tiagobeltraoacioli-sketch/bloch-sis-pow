// SPDX-License-Identifier: AGPL-3.0-or-later
//! Audit L1N-01: the block door has a finalized floor, and the inventory
//! sweep below that floor no longer runs after every accepted block.
//!
//! A validly signed side block below the finalized floor used to be verified,
//! stored, pruned in the same call and answered `Accept` on every delivery:
//! it vouched for whoever sent it and bought a walk of the whole block
//! inventory each time.
use super::*;

const GOSSIP_BLOCK: verification::VerificationLane = verification::VerificationLane::GossipBlock;
const DIRECTED_BLOCK: verification::VerificationLane = verification::VerificationLane::DirectedBlock;

/// A block of this fixture's proposer under `parent` at `slot`, with an
/// empty body, re-signed. Stands for any orphaned proposal ever broadcast.
fn side_block(engine: &Engine, template: &BlockEnvelope, parent: [u8; 32], slot: u64) -> BlockEnvelope {
    let mut env = template.clone();
    env.header.parent = parent;
    env.header.slot = slot;
    env.body.attestations.clear();
    env.body.transactions.clear();
    env.header.attestation_root = derive::attestation_root(&env.body.attestations);
    env.header.body_root = derive::body_root(&env.body.transactions);
    env.proposer_sig = engine
        .keys
        .as_ref()
        .expect("the proposing fixture holds a keystore")
        .sign(&env.header.proposal_signing_root());
    env
}

/// The finalizing fixture, its floor, the head block as a template, and a
/// test clock held at the head slot.
fn finalized_engine() -> (Engine, perf_support::TestDir, u64, BlockEnvelope, impl Drop) {
    let (engine, dir) = finality_latch_tests::engine_with_own_finality();
    let floor = engine.finalized_floor_slot().expect("the fixture finalized an epoch");
    assert!(floor > 2, "the fixture finalized past slot 2 (floor {floor})");
    let template = engine.blocks.get(engine.head_id().as_bytes()).unwrap().clone();
    let clock = validator_lifecycle::clock_at(template.header.slot);
    (engine, dir, floor, template, clock)
}

/// The canonical block at `slot`: the fixture proposes in every slot.
fn canonical_at(engine: &Engine, slot: u64) -> [u8; 32] {
    engine.chain.iter().map(|(_, id)| *id.as_bytes())
        .find(|id| engine.blocks.get(id).is_some_and(|env| env.header.slot == slot))
        .unwrap_or_else(|| panic!("the fixture has a canonical block at slot {slot}"))
}

/// The same stale frame, from any address and by either road, is `Ignore`:
/// it vouches for nobody, costs no signature verification, no fork-choice
/// pass and no sweep, and is never stored or parked.
#[test]
fn a_below_finality_side_block_is_ignored_before_any_work() {
    let (mut engine, _dir, _floor, template, _clock) = finalized_engine();
    let genesis = *engine.chain[0].1.as_bytes();
    let stale = side_block(&engine, &template, genesis, 2);
    let id = *stale.block_id().as_bytes();
    assert!(!engine.canonical.contains(&id) && !engine.blocks.contains_key(&id));
    let slot = engine.wall_slot();
    let head = *engine.head_id().as_bytes();
    let (stored, parked) = (engine.blocks.len(), engine.orphans.len());
    let (pruned, sweeps) = (engine.blocks_pruned, engine.finalized_sweeps);
    engine.gossip_verifier.set_panic_on_verification(true);
    for n in 0..5u8 {
        let source: std::net::IpAddr = format!("203.0.113.{}", 10 + n).parse().unwrap();
        let (origin, vouched) = net::test_mesh_origin(source);
        // Exactly what `engine::run` does with a block frame from the mesh.
        let verdict = engine.ingest_judged_from_source(stale.clone(), origin.verification_source());
        engine.net.report(&origin, verdict);
        assert_eq!(verdict, Verdict::Ignore, "delivery {n}");
        assert!(!vouched(), "delivery {n}: it vouches for nobody");
        assert_eq!(engine.rejected_below_finality, u64::from(n) + 1);
    }
    // A directed sync page carrying it is answered the same way.
    assert_eq!(engine.ingest_from_judged(stale.clone(), Source::Directed(Some([0x5A; 32]))), Verdict::Ignore);
    // And so is a parentless block below the floor: it is not parked.
    let parentless = side_block(&engine, &template, [0x71; 32], 2);
    assert_eq!(engine.ingest_judged_from_source(parentless, Some([0x5B; 32])), Verdict::Ignore);
    engine.gossip_verifier.set_panic_on_verification(false);

    assert_eq!(engine.gossip_verifier.lane_used_at(slot, GOSSIP_BLOCK), 0, "no proposer signature was verified");
    assert_eq!(engine.gossip_verifier.lane_used_at(slot, DIRECTED_BLOCK), 0);
    assert_eq!((engine.blocks.len(), engine.orphans.len()), (stored, parked));
    assert_eq!((engine.blocks_pruned, engine.finalized_sweeps), (pruned, sweeps), "no prune pass was bought");
    assert_eq!(*engine.head_id().as_bytes(), head);

    // Control: a block this node holds is still the ordinary duplicate.
    let (origin, vouched) = net::test_mesh_origin("203.0.113.99".parse().unwrap());
    let again = engine.ingest_judged_from_source(template, origin.verification_source());
    engine.net.report(&origin, again);
    assert_eq!(again, Verdict::Ignore);
    assert!(!vouched());
}

/// The door refuses nothing the node can need. A side block at or above the
/// floor is authenticated and stored as before (it is a reorg candidate the
/// fork choice and the finality latch judge), by gossip and by directed
/// sync, including one exactly at the floor slot.
#[test]
fn blocks_at_or_above_the_floor_pass_the_door() {
    let (mut engine, _dir, floor, template, _clock) = finalized_engine();
    let head_slot = template.header.slot;
    assert!(head_slot > floor + 2);
    let refused = engine.rejected_below_finality;

    // A sibling of the head's parent: one slot under the head, on the
    // canonical block before it. (Not a sibling of the head itself: that one
    // ties with the head in fork choice, and when it wins the tie it is
    // executed, found invalid and dropped, which is not what is under test.)
    let sibling = side_block(&engine, &template, canonical_at(&engine, head_slot - 2), head_slot - 1);
    let sibling_id = *sibling.block_id().as_bytes();
    assert!(!engine.canonical.contains(&sibling_id));
    assert_eq!(engine.ingest_judged_from_source(sibling, Some([0x61; 32])), Verdict::Accept);
    assert!(engine.blocks.contains_key(&sibling_id));

    // Exactly at the floor, by directed sync: the door's test is strict.
    let at_floor = side_block(&engine, &template, canonical_at(&engine, floor - 1), floor);
    let at_floor_id = *at_floor.block_id().as_bytes();
    assert_eq!(engine.ingest_from_judged(at_floor, Source::Directed(Some([0x62; 32]))), Verdict::Accept);
    assert!(engine.blocks.contains_key(&at_floor_id), "the sweep keeps what the door admits");

    // One slot lower is below the floor.
    let below = side_block(&engine, &template, canonical_at(&engine, floor - 2), floor - 1);
    assert_eq!(engine.ingest_from_judged(below, Source::Directed(Some([0x62; 32]))), Verdict::Ignore);
    assert_eq!(engine.rejected_below_finality, refused + 1, "only that one was refused by the floor");
}

/// Part 2: an accepted block no longer buys a walk of the block inventory.
/// The sweep runs when the floor moved, after a reorg, when a parked block
/// sits below the floor, and once per wall epoch.
#[test]
fn the_inventory_sweep_runs_only_when_it_can_have_work() {
    let (mut engine, _dir, floor, template, clock) = finalized_engine();
    let head_slot = template.header.slot;
    engine.prune_below_finalized_if_due();
    let sweeps = engine.finalized_sweeps;
    assert_eq!(engine.finalized_sweep, Some((floor, epoch_of(head_slot))));

    // Accepted blocks under an unchanged floor: no sweep.
    for n in 0..3u64 {
        let side = side_block(&engine, &template, canonical_at(&engine, head_slot - 1 - n), head_slot - n);
        if n == 0 { continue; } // the head itself, at n == 0, is a duplicate id
        assert_eq!(engine.ingest_judged_from_source(side, Some([0x63; 32])), Verdict::Accept, "side block {n}");
    }
    engine.prune_below_finalized_if_due();
    assert_eq!(engine.finalized_sweeps, sweeps, "accepted blocks under an unchanged floor buy no sweep");

    // Something a path other than the door left below the floor.
    let genesis = *engine.chain[0].1.as_bytes();
    let stale = side_block(&engine, &template, genesis, 2);
    let stale_id = *stale.block_id().as_bytes();
    engine.blocks.insert(stale_id, stale.clone());
    engine.prune_below_finalized_if_due();
    assert!(engine.blocks.contains_key(&stale_id), "not due: same floor, same epoch, no reorg");

    // A reorg forgets the last sweep (`do_reorg` clears it).
    engine.finalized_sweep = None;
    engine.prune_below_finalized_if_due();
    assert!(!engine.blocks.contains_key(&stale_id));
    assert_eq!(engine.finalized_sweeps, sweeps + 1);

    // A parked block below the floor makes the sweep due at once.
    let parked = side_block(&engine, &template, [0x72; 32], 3);
    let parked_id = *parked.block_id().as_bytes();
    let retained = crate::codec::encoded_envelope_len(&parked);
    engine.orphans.push_back((parked_id, parked, Source::Gossip(None), None, retained));
    engine.prune_below_finalized_if_due();
    assert!(engine.orphans.iter().all(|(id, _, _, _, _)| *id != parked_id));
    assert_eq!(engine.finalized_sweeps, sweeps + 2);

    // The next wall epoch sweeps once, whatever else happened.
    engine.blocks.insert(stale_id, stale);
    drop(clock);
    let _clock = validator_lifecycle::clock_at(head_slot + SLOTS_PER_EPOCH);
    engine.prune_below_finalized_if_due();
    assert!(!engine.blocks.contains_key(&stale_id));
    assert_eq!(engine.finalized_sweeps, sweeps + 3);
    engine.prune_below_finalized_if_due();
    assert_eq!(engine.finalized_sweeps, sweeps + 3);
}

/// The floor moving is what the sweep exists for: a side block admitted
/// above the floor is removed by the first accepted block after finality
/// passes it, with no direct call to the sweep.
#[test]
fn a_side_block_is_swept_once_finality_passes_it() {
    let (mut engine, _dir, floor, template, clock) = finalized_engine();
    let head_slot = template.header.slot;
    let side = side_block(&engine, &template, canonical_at(&engine, head_slot - 2), head_slot - 1);
    let side_id = *side.block_id().as_bytes();
    assert_eq!(engine.ingest_judged_from_source(side, Some([0x64; 32])), Verdict::Accept);
    assert!(engine.blocks.contains_key(&side_id));
    drop(clock);
    // The fixture's own loop: attest, then propose, until finality moves on.
    let mut slot = head_slot;
    while engine.finalized_floor_slot().is_some_and(|now| now <= head_slot - 1) {
        slot += 1;
        assert!(slot < head_slot + 4 * SLOTS_PER_EPOCH, "finality advances within a few epochs");
        engine.attest(slot);
        engine.propose(slot);
    }
    assert!(engine.finalized_floor_slot().unwrap() > floor);
    assert!(!engine.blocks.contains_key(&side_id), "the side block fell below the floor and was swept");
    assert!(engine.blocks_pruned >= 1);
}
