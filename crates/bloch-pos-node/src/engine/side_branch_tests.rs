// SPDX-License-Identifier: AGPL-3.0-or-later

//! Finding V1-1 (security review 2026-11-10, round 2): a stored side branch
//! whose votes this node cannot weigh is validated from its fork point
//! without being adopted, in bounded slices, so that its body votes become
//! eligible for fork choice once, and only once, its blocks have passed the
//! transition.
//!
//! Every block here is produced and judged by the production paths
//! (`propose`, `attest`, admission, the real transition and the real hybrid
//! verifier). Only fork-choice pool entries and the finality latch are set
//! by hand where a test says so.

use super::*;

/// Every validator of the fixture with its own slashing protection, so a
/// test can sign as any subset of them (as `finality_cert_tests` does).
type Validators = Vec<(Option<Keystore>, SlashingProtection)>;

fn validators(engine: &mut Engine, dir: &perf_support::TestDir, others: Vec<Keystore>) -> Validators {
    let first = engine.keys.take().expect("validator 0");
    std::iter::once(first)
        .chain(others)
        .enumerate()
        .map(|(i, keys)| {
            let sub = dir.0.join(format!("sp{i}"));
            std::fs::create_dir_all(&sub).expect("slashing protection dir");
            (Some(keys), SlashingProtection::open(&sub).expect("slashing protection"))
        })
        .collect()
}

/// Run `duty` once as each validator in `who`.
fn as_validators(engine: &mut Engine, vals: &mut Validators, who: &[usize], duty: &dyn Fn(&mut Engine)) {
    for &i in who {
        std::mem::swap(&mut engine.keys, &mut vals[i].0);
        std::mem::swap(&mut engine.slashprot, &mut vals[i].1);
        duty(engine);
        std::mem::swap(&mut engine.keys, &mut vals[i].0);
        std::mem::swap(&mut engine.slashprot, &mut vals[i].1);
    }
}

fn branch_above(engine: &Engine, height: usize) -> Vec<BlockEnvelope> {
    engine.chain[height + 1..]
        .iter()
        .map(|(_, id)| engine.blocks[id.as_bytes()].clone())
        .collect()
}

/// Spend whole wall slots of validation budget, starting at `from`, until
/// `done` holds. Returns how many slots it took. Asserts the per-turn and
/// per-slot bounds on the way.
fn validate_until(engine: &mut Engine, from: u64, max_slots: u64, done: &dyn Fn(&Engine) -> bool) -> u64 {
    for used in 0..max_slots {
        // More calls than the slot budget can serve: the surplus must be
        // refused by the budget, not served.
        for _ in 0..2 * SIDE_BRANCH_BLOCKS_PER_SLOT {
            let before = engine.reorg_anchors.side.spent;
            engine.validate_side_branch_turn(from + used);
            let side = &engine.reorg_anchors.side;
            assert!(
                side.spent <= SIDE_BRANCH_BLOCKS_PER_SLOT,
                "slot budget exceeded: {} block applications in one wall slot",
                side.spent
            );
            assert!(
                side.spent.saturating_sub(before) <= SIDE_BRANCH_BLOCKS_PER_TURN,
                "turn budget exceeded"
            );
            assert!(side.starts <= SIDE_BRANCH_STARTS_PER_SLOT, "branch-change budget exceeded");
            if done(engine) {
                return used + 1;
            }
        }
    }
    panic!("side-branch validation did not finish within {max_slots} wall slots");
}

/// The finding itself. Branch B is built by three of four validators and
/// carries their votes in its bodies; this node sits on branch A with the
/// fourth. B's votes never reach the pool (after a validator-set divergence
/// they are `NotInCommittee` under this node's roster, so the test simply
/// withholds them, which is the same input to fork choice), and since FC-1
/// B's unapplied bodies weigh nothing: the node holds A for ever. With the
/// validation turn B's blocks pass the transition from the fork point, their
/// votes count, and the node reorganises to B within a bounded number of
/// slots.
#[test]
fn a_heavier_branch_this_node_cannot_weigh_by_gossip_is_validated_and_adopted() {
    let (mut engine, dir, others) = perf_support::proposing_engine_n(&[], 4);
    let mut vals = validators(&mut engine, &dir, others);
    let everyone = [0usize, 1, 2, 3];
    let majority = [1usize, 2, 3];
    let minority = [0usize];

    // Common history: all of epoch 0.
    for slot in 1..SLOTS_PER_EPOCH {
        as_validators(&mut engine, &mut vals, &everyone, &|e| e.propose(slot));
    }
    let fork_point = *engine.head_id().as_bytes();
    let fork_height = engine.chain.len() - 1;
    assert_eq!(fork_height as u64, SLOTS_PER_EPOCH - 1, "fixture: every slot of epoch 0 has a block");

    // Branch B: epochs 1 and 2 as the majority saw them.
    let last = 3 * SLOTS_PER_EPOCH - 1;
    for slot in SLOTS_PER_EPOCH..=last {
        as_validators(&mut engine, &mut vals, &majority, &|e| e.attest(slot));
        as_validators(&mut engine, &mut vals, &majority, &|e| e.propose(slot));
    }
    let branch_b = branch_above(&engine, fork_height);
    let b_tip = *engine.head_id().as_bytes();
    let b_state_root = engine.state.state_root();
    // Each validator's latest vote carried by B, and whether it names a
    // block of B (a vote cast before B's first block names the fork point,
    // which weighs for neither branch).
    let mut latest: BTreeMap<u32, (u64, [u8; 32])> = BTreeMap::new();
    for att in branch_b.iter().flat_map(|b| b.body.attestations.iter()) {
        let entry = latest.entry(att.validator).or_insert((att.data.slot, att.data.head));
        if att.data.slot >= entry.0 {
            *entry = (att.data.slot, att.data.head);
        }
    }
    assert!(!latest.contains_key(&0), "fixture: validator 0 never voted on B");
    let on_b = latest.values().filter(|(_, head)| *head != fork_point).count();
    assert!(on_b >= 2, "fixture: B's bodies carry the votes of at least half the stake for B, got {on_b}");

    // This node never saw B: hand it back and forget its blocks and votes.
    assert!(engine.do_reorg(fork_point, Vec::new()), "B is handed back");
    for block in &branch_b {
        engine.blocks.remove(block.block_id().as_bytes()).expect("B was stored");
    }
    engine.pool.clear();

    // Branch A: the same slots as the minority saw them.
    for slot in SLOTS_PER_EPOCH..=last {
        as_validators(&mut engine, &mut vals, &minority, &|e| e.attest(slot));
        as_validators(&mut engine, &mut vals, &minority, &|e| e.propose(slot));
    }
    let a_tip = *engine.head_id().as_bytes();
    assert_ne!(a_tip, fork_point, "fixture: validator 0 extended A");
    assert!(!branch_b.iter().any(|b| b.block_id().as_bytes() == &a_tip));
    // Validator 0's latest message, pinned on A's tip: its own votes may
    // predate A's first block and name the fork point. A quarter of the
    // stake holds A; B has none that this node can count.
    let own = forkchoice_tests::attest(0, last + 1, a_tip);
    engine.pool.insert((own.validator, own.data.signing_root()), own);

    // B arrives as blocks only, through the gossip door. One wall slot per
    // block, so the per-slot verification allowance is not what is tested.
    for (i, block) in branch_b.iter().enumerate() {
        let _clock = validator_lifecycle::clock_at(last + 1 + i as u64);
        assert_eq!(
            engine.ingest_judged(block.clone()),
            Verdict::Accept,
            "fixture: B's block {i} passes admission and is stored"
        );
    }
    // The stranding, as FC-1 left it: B is stored, weighs nothing, and the
    // node stays on A although three quarters of the stake are on B.
    assert_eq!(*engine.head_id().as_bytes(), a_tip, "B's unapplied bodies must not move the head");
    for block in &branch_b {
        let id = block.block_id();
        assert!(!engine.blocks.is_validated(id.as_bytes()));
        assert!(!engine.blocks.has_indexed_votes(id.as_bytes()), "FC-1: no vote before the transition");
    }

    let wall = last + 1 + branch_b.len() as u64;
    let _clock = validator_lifecycle::clock_at(wall);
    let slots = validate_until(&mut engine, wall, 96, &|e| *e.head_id().as_bytes() == b_tip);
    println!("V1-1: reorganised to the heavier branch after {slots} wall slots of validation budget");

    assert_eq!(engine.state.state_root(), b_state_root, "the adopted state is B's own");
    assert!(!engine.canonical.contains(&a_tip), "A was given back");
    for block in &branch_b {
        assert!(engine.canonical.contains(block.block_id().as_bytes()));
    }
}

/// A single-validator chain `genesis, fork point, a1, a2` and a stored,
/// never-applied side branch of `len` valid blocks on the fork point. One
/// pool vote holds the head on `a2`, so the side branch is never the
/// heavier one and nothing but validation touches it.
fn held_head_with_side_branch(len: u64) -> (Engine, perf_support::TestDir, [u8; 32], Vec<[u8; 32]>) {
    let (mut engine, dir) = perf_support::proposing_engine();
    engine.propose(1);
    let fork_point = *engine.head_id().as_bytes();
    for slot in 2..2 + len {
        engine.propose(slot);
    }
    let side = branch_above(&engine, 1);
    assert_eq!(side.len() as u64, len);
    assert!(engine.do_reorg(fork_point, Vec::new()), "the side branch is handed back");
    for block in &side {
        engine.blocks.remove(block.block_id().as_bytes()).expect("stored");
    }
    // Past the first epoch, so the pool vote below survives the epoch prune.
    let first = (2 + len).max(SLOTS_PER_EPOCH);
    engine.propose(first);
    engine.propose(first + 1);
    assert_eq!(engine.chain.len(), 4, "genesis, the fork point and two blocks above it");
    let tip = *engine.head_id().as_bytes();
    let vote = forkchoice_tests::attest(0, first + 1, tip);
    engine.pool.insert((vote.validator, vote.data.signing_root()), vote);
    // Stored as admission stores them: connected, not applied.
    let ids: Vec<[u8; 32]> = side.iter().map(|b| *b.block_id().as_bytes()).collect();
    for (id, block) in ids.iter().zip(side) {
        engine.blocks.insert(*id, block);
    }
    assert_eq!(engine.forkchoice_head(), tip, "fixture: the pool vote holds the head");
    (engine, dir, tip, ids)
}

/// The bounds: no more than the turn budget per call, no more than the slot
/// budget per wall slot, one retained state, and never an adoption.
#[test]
fn validation_is_budgeted_per_turn_and_per_slot_and_adopts_nothing() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(40);
    // A fork point AT the latch is legal for a reorg, so it is validated.
    let fork_point = *engine.chain[1].1.as_bytes();
    engine.finalized_latch = Some((1, fork_point));
    let validated = |e: &Engine| side.iter().filter(|id| e.blocks.is_validated(id)).count();
    assert_eq!(validated(&engine), 0);

    // One wall slot: however often the turn is offered, the slot budget is
    // the ceiling, and the fold resumes from its cursor instead of
    // restarting.
    for _ in 0..4 * SIDE_BRANCH_BLOCKS_PER_SLOT {
        engine.validate_side_branch_turn(500);
    }
    let after_one_slot = validated(&engine);
    assert!(after_one_slot >= 1, "the first block of a slot is always attempted");
    assert!(after_one_slot <= SIDE_BRANCH_BLOCKS_PER_SLOT, "{after_one_slot} blocks in one wall slot");
    assert_eq!(engine.reorg_anchors.side.spent, after_one_slot, "nothing was re-executed");
    assert_eq!(engine.reorg_anchors.side.starts, 1, "one branch, started once");
    assert_eq!(
        engine.reorg_anchors.side.cursor.as_ref().map(|(id, _)| *id),
        Some(side[after_one_slot - 1]),
        "the cursor is the last validated block"
    );
    assert_eq!(*engine.head_id().as_bytes(), tip);

    let slots = validate_until(&mut engine, 501, 64, &|e| validated(e) == side.len());
    assert!(
        slots as usize >= (side.len() - after_one_slot).div_ceil(SIDE_BRANCH_BLOCKS_PER_SLOT),
        "a branch longer than the slot budget takes several slots"
    );
    assert_eq!(*engine.head_id().as_bytes(), tip, "a validated branch that is not heavier is not adopted");
    assert_eq!(engine.chain.len(), 4);
    for id in &side {
        assert!(!engine.canonical.contains(id));
    }

    // Nothing left: the cursor state is released and the turn is idle.
    assert!(!engine.validate_side_branch_turn(600));
    assert!(engine.reorg_anchors.side.cursor.is_none(), "the retained state is dropped");
    assert!(!engine.validate_side_branch_turn(600));
    assert_eq!(engine.reorg_anchors.side.spent, 0, "a new slot starts a new budget");
}

/// A branch whose fork point is below the finality latch can never be
/// adopted, and no transition work is spent on it.
#[test]
fn a_branch_forking_below_the_finality_latch_is_never_validated() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(3);
    engine.finalized_latch = Some((2, *engine.chain[2].1.as_bytes()));
    for slot in 700..704 {
        for _ in 0..4 {
            assert!(!engine.validate_side_branch_turn(slot));
        }
    }
    assert!(side.iter().all(|id| !engine.blocks.is_validated(id)));
    assert_eq!(engine.reorg_anchors.side.spent, 0, "no block application was spent");
    assert!(engine.reorg_anchors.side.cursor.is_none());
    assert_eq!(*engine.head_id().as_bytes(), tip);
}

/// FC-1 is preserved: a stored side block that fails the transition is
/// removed by the validation turn and its body votes are never indexed,
/// while the valid block below it is validated.
#[test]
fn a_side_block_that_fails_the_transition_never_votes() {
    let _clock = validator_lifecycle::clock_at(64);
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(1);
    let rival_id = side[0];
    let rival = engine.blocks[&rival_id].clone();

    // A child of the rival whose body claims a later vote by the only
    // validator for the rival's branch, under a signature that is not its.
    let slot = engine.head_slot_now() + 1;
    let forged = Attestation {
        validator: 0,
        data: AttestationData {
            slot,
            head: rival_id,
            source_epoch: 0,
            source_root: [0u8; 32],
            target_epoch: epoch_of(slot),
            target_root: rival_id,
        },
        signature: vec![0xA5; 64],
    };
    let mut carrier = rival;
    carrier.header.parent = rival_id;
    carrier.header.slot = slot;
    carrier.body.attestations = vec![forged];
    carrier.header.attestation_root = derive::attestation_root(&carrier.body.attestations);
    carrier.proposer_sig = engine
        .keys
        .as_ref()
        .expect("the proposing fixture holds a keystore")
        .sign(&carrier.header.proposal_signing_root());
    let carrier_id = *carrier.block_id().as_bytes();
    assert_eq!(engine.ingest_judged(carrier), Verdict::Accept, "fixture: stored by admission");
    assert!(engine.blocks.contains_key(&carrier_id));
    assert_eq!(*engine.head_id().as_bytes(), tip);

    for _ in 0..8 {
        engine.validate_side_branch_turn(900);
    }
    assert!(engine.blocks.is_validated(&rival_id), "the valid block below it passed");
    assert!(!engine.blocks.contains_key(&carrier_id), "the failing block is removed, as a reorg removes it");
    assert!(!engine.blocks.has_indexed_votes(&carrier_id), "its votes were never indexed");
    assert_eq!(engine.forkchoice_head(), tip, "and the head did not move");
    assert_eq!(*engine.head_id().as_bytes(), tip);
}

/// Which branch first: the one signed by more distinct proposers, not the
/// longer one. The candidate walk reads headers only, so the branches here
/// are header variants of a real block and are never executed.
#[test]
fn the_branch_signed_by_more_proposers_is_taken_first() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(1);
    let template = engine.blocks.remove(&side[0]).expect("stored");
    let fork_point = *engine.chain[1].1.as_bytes();
    let mut grow = |parent: [u8; 32], slot: u64, proposer: u32| {
        let mut block = template.clone();
        block.header.parent = parent;
        block.header.slot = slot;
        block.header.proposer_index = proposer;
        let id = *block.block_id().as_bytes();
        engine.blocks.insert(id, block);
        id
    };
    // Three blocks by one key.
    let long = [1u64, 2, 3].iter().fold(vec![fork_point], |mut ids, i| {
        let id = grow(ids[ids.len() - 1], 100 + i, 7);
        ids.push(id);
        ids
    });
    // Two blocks by two keys.
    let wide_1 = grow(fork_point, 200, 8);
    let wide_2 = grow(wide_1, 201, 9);

    assert_eq!(engine.side_branch_candidate(), Some((1, vec![wide_1, wide_2])));
    // Once that one is judged, the other is next.
    engine.blocks.mark_validated(&wide_1);
    engine.blocks.mark_validated(&wide_2);
    assert_eq!(engine.side_branch_candidate(), Some((1, long[1..].to_vec())));
    // Nothing above the floor: no candidate at all.
    engine.finalized_latch = Some((2, *engine.chain[2].1.as_bytes()));
    assert_eq!(engine.side_branch_candidate(), None);
}

/// Review W2-5 and W2-8 (1). A stored side block whose fork point is far
/// above the nearest retained state costs a replay of canonical blocks to
/// reach it: those count against the same budget, the cursor rests on a
/// canonical block between slots, and released bodies are read back from
/// the block log. When the block then fails the transition it is
/// remembered, so storing the same block again costs no block application
/// at all, while the memory never touches what is stored or adopted.
#[test]
fn a_failed_side_block_is_remembered_and_not_replayed_for_again() {
    let (mut engine, _dir) = perf_support::proposing_engine();
    for slot in 1..=30 {
        engine.propose(slot);
    }
    assert_eq!(engine.chain.len(), 31, "fixture: thirty blocks over genesis");
    let tip = *engine.head_id().as_bytes();
    // Bodies below height 6 are released, as below a finalized checkpoint.
    engine.finalized_latch = Some((6, *engine.chain[6].1.as_bytes()));
    engine.hollow_finalized_bodies();
    assert!(engine.blocks.is_hollow(engine.chain[5].1.as_bytes()), "fixture: released bodies on the way");

    let fork_height = 24usize;
    let fork_point = *engine.chain[fork_height].1.as_bytes();
    let (anchor_height, ..) = engine.reorg_anchor_at_or_below(fork_height).expect("fixture: an anchor below the fork point");
    assert!(anchor_height < 6, "fixture: the replay starts below the released bodies");
    let replayed = fork_height - anchor_height;
    assert!(replayed > SIDE_BRANCH_BLOCKS_PER_SLOT, "fixture: reaching the fork point takes more than one slot");

    // A sibling of the canonical block at height 25 that cannot pass the
    // transition, stored as admission stores a connected block.
    let mut invalid = engine.blocks[engine.chain[fork_height + 1].1.as_bytes()].clone();
    assert_eq!(invalid.header.parent, fork_point);
    invalid.header.state_root = [0xEE; 32];
    let invalid_id = *invalid.block_id().as_bytes();
    assert!(!engine.canonical.contains(&invalid_id));
    engine.blocks.insert(invalid_id, invalid.clone());

    // First slot: the whole slot budget goes into canonical blocks, and the
    // cursor is left on one of them.
    for _ in 0..2 * SIDE_BRANCH_BLOCKS_PER_SLOT {
        engine.validate_side_branch_turn(1_000);
    }
    assert_eq!(engine.reorg_anchors.side.spent, SIDE_BRANCH_BLOCKS_PER_SLOT, "canonical replays are budgeted");
    let cursor = engine.reorg_anchors.side.cursor.as_ref().map(|(id, _)| *id).expect("a cursor");
    assert_eq!(
        engine.height_of(&cursor),
        Some((anchor_height + SIDE_BRANCH_BLOCKS_PER_SLOT) as u64),
        "the cursor rests on the canonical block the slot budget reached"
    );
    assert!(engine.blocks.contains_key(&invalid_id), "not judged yet");

    // The following slots finish the replay and judge the block.
    let mut spent = SIDE_BRANCH_BLOCKS_PER_SLOT;
    for slot in 1_001..1_010 {
        for _ in 0..2 * SIDE_BRANCH_BLOCKS_PER_SLOT {
            engine.validate_side_branch_turn(slot);
        }
        spent += engine.reorg_anchors.side.spent;
        if !engine.blocks.contains_key(&invalid_id) {
            break;
        }
    }
    assert!(!engine.blocks.contains_key(&invalid_id), "the failing block is removed");
    assert_eq!(spent, replayed + 1, "every canonical block once, then the side block");
    assert_eq!(*engine.head_id().as_bytes(), tip);

    // The same block is stored again (a peer offers it again).
    engine.blocks.insert(invalid_id, invalid.clone());
    for slot in 2_000..2_004 {
        for _ in 0..4 {
            assert!(!engine.validate_side_branch_turn(slot));
        }
        assert_eq!(engine.reorg_anchors.side.spent, 0, "no block application for a block that already failed");
    }
    assert!(!engine.blocks.is_validated(&invalid_id));
    assert!(engine.blocks.contains_key(&invalid_id), "the memory removes nothing from the store");
    assert_eq!(*engine.head_id().as_bytes(), tip);
    // Nothing above it is a candidate either.
    let mut child = invalid.clone();
    child.header.parent = invalid_id;
    child.header.slot += 1;
    let child_id = *child.block_id().as_bytes();
    engine.blocks.insert(child_id, child);
    assert_eq!(engine.side_branch_candidate(), None);

    // A different stored side block is still judged: the memory is per block.
    let mut other = invalid;
    other.header.state_root = [0xDD; 32];
    let other_id = *other.block_id().as_bytes();
    engine.blocks.insert(other_id, other);
    assert_eq!(engine.side_branch_candidate(), Some((fork_height, vec![other_id])));

    // Bounded, oldest first.
    let side = &mut engine.reorg_anchors.side;
    for i in 0..SIDE_BRANCH_FAILED_REMEMBERED as u64 {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&i.to_le_bytes());
        id[31] = 1;
        side.remember_failed(id);
        side.remember_failed(id);
    }
    assert_eq!(side.failed.len(), SIDE_BRANCH_FAILED_REMEMBERED);
    assert_eq!(side.failed_index.len(), SIDE_BRANCH_FAILED_REMEMBERED);
    assert!(!side.failed_index.contains(&invalid_id), "the oldest entry was forgotten");
}

/// Review RC2-03: a block parked for its proposer's authority on a side
/// branch tip is judged again when the fold validates that tip, although
/// the head never moves, and the tip's exact post-state stays where the
/// door looks for it after the cursor is dropped.
///
/// The door parks such a block when it holds no exact state for its parent
/// (sibling branches of two or more blocks, the parent's own parent off the
/// chain) and so judged it on `fallback`. Until this fix only a change of
/// the head re-judged it (`authority_parked_due`), which a stalled network
/// never produces: it waited until eviction and a refetch.
#[test]
fn a_block_parked_on_a_side_tip_is_judged_again_when_the_fold_reaches_it() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    let mut child = engine.blocks[&side_tip].clone();
    child.header.parent = side_tip;
    child.header.slot += 1;
    let child_id = *child.block_id().as_bytes();
    let parked_under = bloch_pos_committee::kes::authority_fingerprint(
        &*engine.proposer_authority_state(&side_tip),
        child.header.proposer_index,
        epoch_of(child.header.slot),
    );
    engine.park_unjudgeable(child_id, child, Source::Gossip(Some([0x61; 32])), parked_under);
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child_id), "fixture: parked");
    assert!(engine.exact_parent_state(&side_tip).is_none(), "fixture: no exact state of its parent");
    assert!(engine.authority_parked_due().is_empty(), "the head-change trigger does not fire");

    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    assert_eq!(*engine.head_id().as_bytes(), tip, "the head did not move");
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == child_id), "out of the waiting pool");
    assert!(engine.deferred_orphans.iter().any(|(id, ..)| *id == child_id), "queued for the door again");
    let held = engine.exact_parent_state(&side_tip).expect("the tip's exact post-state is held");
    assert_eq!(held.state_root(), engine.blocks[&side_tip].header.state_root, "and it is the tip's own");

    // Nothing left to validate: the cursor goes, the retained state stays.
    engine.validate_side_branch_turn(600);
    engine.validate_side_branch_turn(600);
    assert!(engine.reorg_anchors.side.cursor.is_none(), "the cursor is dropped");
    assert!(engine.exact_parent_state(&side_tip).is_some(), "the retained state outlives it");

    // Released once the block it describes leaves the store.
    engine.blocks.remove(&side[1]);
    engine.validate_side_branch_turn(601);
    assert!(engine.reorg_anchors.side.tips.iter().all(|(id, _)| *id != side_tip));
}

/// Review RC3-01: the natural order. The fold validates a side branch and
/// drops its cursor BEFORE any block is offered on its tip (a block that
/// crosses the KES bind comes two empty epochs after its parent). The tip's
/// exact post-state is still where the door looks for it, so such a block
/// is judged on its parent's own state, although nothing waited on the tip
/// when it was validated and the head never moves.
#[test]
fn a_validated_side_tip_keeps_its_exact_state_after_the_cursor_is_dropped() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    assert!(engine.authority_parked.judged.is_empty(), "nothing is parked: nothing waits on the tip");
    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    engine.validate_side_branch_turn(600);
    engine.validate_side_branch_turn(600);
    assert!(engine.reorg_anchors.side.cursor.is_none(), "the cursor is dropped");
    assert_eq!(*engine.head_id().as_bytes(), tip, "the head did not move");
    let held = engine.exact_parent_state(&side_tip).expect("the tip's exact post-state is held");
    assert_eq!(held.state_root(), engine.blocks[&side_tip].header.state_root, "and it is the tip's own");
}

/// Review RC3-02: the retained side states are bounded, and an entry a
/// block queued for the door waits on is not evicted by later ones (nor by
/// states of blocks a junk header was parked on, which can only re-order
/// states of blocks that passed the transition). With every entry waited
/// on, a new state is not kept.
#[test]
fn retained_side_states_are_bounded_and_keep_what_a_queued_block_waits_on() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    let side_tip = side[1];
    let post = engine.exact_parent_state(&side_tip).expect("held");
    // A block queued for the door on the tip.
    let mut child = engine.blocks[&side_tip].clone();
    child.header.parent = side_tip;
    child.header.slot += 1;
    let child_id = *child.block_id().as_bytes();
    engine.deferred_orphans.push_back((child_id, child, Source::Gossip(Some([0x62; 32])), None, 0));
    for k in 0..2 * SIDE_TIP_STATES as u8 {
        engine.retain_side_state([0xD0 + k; 32], &post);
        assert!(engine.reorg_anchors.side.tips.len() <= SIDE_TIP_STATES, "bounded");
        assert!(engine.reorg_anchors.side.tips.iter().any(|(id, _)| *id == side_tip), "the waited-on tip stays");
    }
    // Every entry waited on: the next one is not kept.
    let queued: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    for (n, held) in queued.iter().enumerate() {
        let mut waiting = engine.blocks[&side_tip].clone();
        waiting.header.parent = *held;
        waiting.header.slot += 2 + n as u64;
        let id = *waiting.block_id().as_bytes();
        engine.deferred_orphans.push_back((id, waiting, Source::Gossip(Some([0x63; 32])), None, 0));
    }
    engine.retain_side_state([0xEE; 32], &post);
    let after: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    assert_eq!(after, queued, "nothing waited on was evicted, and the new state was not kept");
}

/// Validate the whole side branch of `held_head_with_side_branch`, drop the
/// cursor, then push `newer` later side states into the ring (as later
/// validations of other side blocks do), so that neither the tip's nor its
/// parent's exact post-state is held any more.
fn validated_side_branch_evicted_from_the_ring(
    engine: &mut Engine,
    side: &[[u8; 32]],
    newer: usize,
) {
    validate_until(engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    engine.validate_side_branch_turn(600);
    engine.validate_side_branch_turn(600);
    assert!(engine.reorg_anchors.side.cursor.is_none(), "the cursor is dropped");
    let post = engine.exact_parent_state(side.last().unwrap()).expect("the tip's state is held at first");
    for k in 0..newer as u8 {
        engine.retain_side_state([0xC0 + k; 32], &post);
    }
}

/// A block on `parent`, parked for its proposer's authority as the door
/// parks a block it judged on `fallback`.
fn park_on(engine: &mut Engine, parent: [u8; 32], bump: u64, source: u8) -> [u8; 32] {
    let proposer = engine.blocks[&parent].header.proposer_index;
    park_on_as(engine, parent, bump, source, proposer)
}

/// [`park_on`], signed (as far as the header says) by `proposer`.
fn park_on_as(engine: &mut Engine, parent: [u8; 32], bump: u64, source: u8, proposer: u32) -> [u8; 32] {
    let mut child = engine.blocks[&parent].clone();
    child.header.proposer_index = proposer;
    child.header.parent = parent;
    child.header.slot += bump;
    let id = *child.block_id().as_bytes();
    let parked_under = bloch_pos_committee::kes::authority_fingerprint(
        &*engine.proposer_authority_state(&parent),
        child.header.proposer_index,
        epoch_of(child.header.slot),
    );
    engine.park_unjudgeable(id, child, Source::Gossip(Some([source; 32])), parked_under);
    assert!(engine.orphans.iter().any(|(seen, ..)| *seen == id), "fixture: parked");
    id
}

/// Review RC4-01: SIDE_TIP_STATES newer side states evict the exact
/// post-states of a validated side tip AND of its parent before a block on
/// the tip arrives. The door then judges that block on `fallback` and parks
/// it; the tip is validated, so it is no longer a fold candidate, and the
/// head does not move, so nothing would ever judge the block again. With the
/// door's request (`want_parent_state_for`) the fold recomputes the tip's
/// state from the nearest exact ancestor within its budgets, keeps it, and
/// queues the block for the door again.
#[test]
fn a_wanted_side_state_evicted_from_the_ring_is_recomputed_and_its_parked_block_judged_again() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    assert!(engine.exact_parent_state(&side_tip).is_none(), "fixture: the tip's state was evicted");
    assert!(engine.exact_parent_state(&side[0]).is_none(), "fixture: and its parent's");
    let child = park_on(&mut engine, side_tip, 1, 0x64);

    // Without the request: the stall. Nothing re-judges the block.
    for slot in 700..708 {
        for _ in 0..2 * SIDE_BRANCH_BLOCKS_PER_SLOT {
            engine.validate_side_branch_turn(slot);
        }
    }
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child), "still parked: RC4-01");
    assert!(engine.exact_parent_state(&side_tip).is_none());

    // With it: recomputed within the fold's bounds, kept, and re-judged.
    engine.want_parent_state_for(child);
    let slots = validate_until(&mut engine, 800, 16, &|e| {
        e.deferred_orphans.iter().any(|(id, ..)| *id == child) && e.exact_parent_state(&side_tip).is_some()
    });
    assert!(slots <= 2, "a short branch is recomputed within a slot or two ({slots})");
    assert!(engine.reorg_anchors.side.want_starts <= SIDE_WANT_STARTS_PER_SLOT);
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == child), "out of the waiting pool");
    assert_eq!(*engine.head_id().as_bytes(), tip, "the head did not move");
    let held = engine.exact_parent_state(&side_tip).expect("the tip's exact post-state is held again");
    assert_eq!(held.state_root(), engine.blocks[&side_tip].header.state_root, "and it is the tip's own");
    assert!(engine.reorg_anchors.side.tips.len() <= SIDE_TIP_STATES + 1, "the ring stays bounded");
    // Served: nothing more is wanted, and the next turns do no work for it.
    engine.validate_side_branch_turn(900);
    engine.validate_side_branch_turn(900);
    assert!(engine.reorg_anchors.side.wanting.is_empty());
    assert!(engine.reorg_anchors.side.want_cursor.is_none() && engine.reorg_anchors.side.want_target.is_none());
    assert_eq!(engine.reorg_anchors.side.spent, 0, "no block was applied for nothing");
}

/// Review RC4-01, the bounds of the request: a request whose block is not
/// parked, or whose parent is canonical, not yet validated, or not stored,
/// costs no block application and is forgotten; a parent whose state is
/// held again is served without running anything.
#[test]
fn a_wanted_side_state_is_recomputed_only_for_a_parked_block_on_a_stored_validated_side_parent() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(2);
    // Not validated yet: the fold, not the request, is what reaches it.
    let early = park_on(&mut engine, side[1], 1, 0x65);
    engine.want_parent_state_for(early);
    // On the canonical head: a head change is what re-judges it.
    let on_head = park_on(&mut engine, tip, 1, 0x66);
    engine.want_parent_state_for(on_head);
    // Not parked at all.
    engine.want_parent_state_for([0x5A; 32]);
    assert!(engine.serve_wanted_side_state_turn().is_none(), "nothing to recompute");
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "every request was forgotten");
    assert_eq!(engine.reorg_anchors.side.spent, 0, "and none cost a block application");
    assert!(engine.orphans.iter().any(|(id, ..)| *id == on_head), "nothing was moved for them");

    // Validated, and its state is held: queued at once, nothing applied.
    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    engine.validate_side_branch_turn(600);
    engine.validate_side_branch_turn(600);
    let late = park_on(&mut engine, side[1], 2, 0x67);
    engine.want_parent_state_for(late);
    let spent = engine.reorg_anchors.side.spent;
    assert_eq!(engine.serve_wanted_side_state_turn(), None);
    assert_eq!(engine.reorg_anchors.side.spent, spent, "no block applied");
    assert!(engine.deferred_orphans.iter().any(|(id, ..)| *id == late), "queued for the door");
}

/// Review RC4-02: a block held in the orphan pool only until a spent
/// allowance renews keeps the side state it waits on in the ring, like one
/// already queued for the door.
#[test]
fn a_budget_parked_block_keeps_the_side_state_it_waits_on() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    let side_tip = side[1];
    let post = engine.exact_parent_state(&side_tip).expect("held");
    let mut child = engine.blocks[&side_tip].clone();
    child.header.parent = side_tip;
    child.header.slot += 1;
    let child_id = *child.block_id().as_bytes();
    engine.wall_slot = 601;
    engine.park_budget_limited_block(child_id, child, Source::Gossip(Some([0x68; 32])));
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child_id), "fixture: held in the pool");
    assert!(engine.gossip_verifier.is_budget_parked(&child_id), "fixture: for a spent allowance");
    for k in 0..2 * SIDE_TIP_STATES as u8 {
        engine.retain_side_state([0xB0 + k; 32], &post);
        assert!(engine.reorg_anchors.side.tips.len() <= SIDE_TIP_STATES, "bounded");
        assert!(engine.reorg_anchors.side.tips.iter().any(|(id, _)| *id == side_tip), "the waited-on tip stays");
    }
    // Once the allowance renews it is queued for the door: still kept.
    engine.requeue_budget_parked_blocks(602);
    assert!(engine.deferred_orphans.iter().any(|(id, ..)| *id == child_id));
    engine.retain_side_state([0xBF; 32], &post);
    assert!(engine.reorg_anchors.side.tips.iter().any(|(id, _)| *id == side_tip));
}

/// Reviews RC4-03 and RC5-04: with every entry waited on, an ordinary state
/// is not kept, but one recomputed because the door asked for it is, in the
/// one place reserved for it, so nothing a queued block waits on is
/// evicted; only when that place is waited on too does a further wanted
/// state take the oldest entry's place. The ring stays bounded.
#[test]
fn a_wanted_state_is_kept_even_when_every_entry_is_waited_on() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    let side_tip = side[1];
    let post = engine.exact_parent_state(&side_tip).expect("held");
    for k in 0..SIDE_TIP_STATES as u8 {
        engine.retain_side_state([0xA0 + k; 32], &post);
    }
    let held: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    for (n, of) in held.iter().enumerate() {
        let mut waiting = engine.blocks[&side_tip].clone();
        waiting.header.parent = *of;
        waiting.header.slot += 2 + n as u64;
        let id = *waiting.block_id().as_bytes();
        engine.deferred_orphans.push_back((id, waiting, Source::Gossip(Some([0x69; 32])), None, 0));
    }
    engine.retain_side_state([0xAE; 32], &post);
    let after: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    assert_eq!(after, held, "an ordinary state is not kept");
    engine.retain_side_state_as([0xAF; 32], &post, true);
    let after: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    assert_eq!(after.len(), SIDE_TIP_STATES + 1, "one place beyond the ring");
    assert_eq!(&after[..SIDE_TIP_STATES], &held[..], "RC5-04: nothing waited on was evicted");
    assert_eq!(after.last(), Some(&[0xAF; 32]), "the wanted one is kept");
    // An ordinary state still finds no room.
    engine.retain_side_state([0xAD; 32], &post);
    assert!(!engine.reorg_anchors.side.tips.iter().any(|(id, _)| *id == [0xAD; 32]));
    assert_eq!(engine.reorg_anchors.side.tips.len(), SIDE_TIP_STATES + 1);
    // A second wanted state replaces the first while nothing waits on it.
    engine.retain_side_state_as([0xB0; 32], &post, true);
    let after: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    assert_eq!(&after[..SIDE_TIP_STATES], &held[..]);
    assert_eq!(after.last(), Some(&[0xB0; 32]));
    // Once that one is waited on too, the oldest entry gives way.
    let mut waiting = engine.blocks[&side_tip].clone();
    waiting.header.parent = [0xB0; 32];
    waiting.header.slot += 40;
    let id = *waiting.block_id().as_bytes();
    engine.deferred_orphans.push_back((id, waiting, Source::Gossip(Some([0x69; 32])), None, 0));
    engine.retain_side_state_as([0xB1; 32], &post, true);
    let after: Vec<[u8; 32]> = engine.reorg_anchors.side.tips.iter().map(|(id, _)| *id).collect();
    assert_eq!(after.len(), SIDE_TIP_STATES + 1, "bounded");
    assert_eq!(&after[..SIDE_TIP_STATES - 1], &held[1..], "in the oldest entry's place");
    assert_eq!(&after[SIDE_TIP_STATES - 1..], &[[0xB0; 32], [0xB1; 32]]);
}

/// Review RC5-01, the regression: more blocks parked on the wanted parent
/// than the recomputation queues (an attacker's signed headers, or many
/// proposers' variants on a stalled network), all ahead of the honest block
/// in the pool. The recomputation queues [`SIDE_PARKED_REJUDGE_PER_BLOCK`]
/// of them per block it validates, here two (the parent and the
/// grandparent), so not the honest one. In 6b35aa94 the request for the
/// honest block was dropped with it, the state was then held, and nothing
/// ever queued the honest block again. Now the request stays until the
/// block has left the pool, and the next turns queue the rest from the held
/// state without any further block application.
#[test]
fn more_blocks_parked_on_a_wanted_parent_than_one_rejudge_queues_do_not_strand_the_last() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    assert!(engine.exact_parent_state(&side_tip).is_none() && engine.exact_parent_state(&side[0]).is_none());
    let ahead: Vec<[u8; 32]> = (0..2 * SIDE_PARKED_REJUDGE_PER_BLOCK as u64 + 1)
        .map(|k| park_on(&mut engine, side_tip, 1 + k, 0x70 + k as u8))
        .collect();
    let honest = park_on(&mut engine, side_tip, 40, 0x6F);
    engine.want_parent_state_for(honest);
    assert!(engine.reorg_anchors.side.wanting.contains(&honest), "fixture: the door asked for its parent's state");

    let slots = validate_until(&mut engine, 800, 4, &|e| {
        e.deferred_orphans.iter().any(|(id, ..)| *id == honest)
    });
    assert!(slots <= 2, "queued within a slot or two ({slots})");
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == honest), "out of the waiting pool");
    for id in &ahead {
        assert!(engine.deferred_orphans.iter().any(|(seen, ..)| seen == id), "every block ahead of it too");
    }
    assert_eq!(engine.reorg_anchors.side.want_starts, 1, "one recomputation");
    assert_eq!(engine.reorg_anchors.side.spent, side.len(), "each side block applied once, nothing more");
    assert_eq!(*engine.head_id().as_bytes(), tip);
    engine.validate_side_branch_turn(900);
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "served, the request is gone");
}

/// Review RC5-02: one proposer's blocks may ask for the states of at most
/// [`SIDE_WANTED_PARENTS_PER_PROPOSER`] distinct parents; further blocks of
/// it on those parents are still wanted, and another proposer is not
/// affected. A block that is not parked for its proposer's authority is
/// never wanted (review RC5-07).
#[test]
fn one_proposer_cannot_queue_more_than_its_share_of_recomputation_targets() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(3);
    let parents = [side[0], side[1], side[2]];
    let mine: Vec<[u8; 32]> =
        parents.iter().enumerate().map(|(k, p)| park_on_as(&mut engine, *p, 1, 0x80 + k as u8, 0)).collect();
    for id in &mine {
        engine.want_parent_state_for(*id);
    }
    let wanting = &engine.reorg_anchors.side.wanting;
    assert!(wanting.contains(&mine[0]) && wanting.contains(&mine[1]));
    assert!(!wanting.contains(&mine[2]), "a third parent is refused");
    let again = park_on_as(&mut engine, parents[1], 2, 0x84, 0);
    engine.want_parent_state_for(again);
    assert!(engine.reorg_anchors.side.wanting.contains(&again), "a parent already asked for is not a new target");
    let other = park_on_as(&mut engine, parents[2], 3, 0x85, 1);
    engine.want_parent_state_for(other);
    assert!(engine.reorg_anchors.side.wanting.contains(&other), "another proposer has its own share");

    // Not parked for authority: never wanted.
    let mut queued = engine.blocks[&parents[2]].clone();
    queued.header.parent = parents[2];
    queued.header.slot += 4;
    let queued_id = *queued.block_id().as_bytes();
    engine.park_orphan(queued_id, queued, Source::Gossip(Some([0x86; 32])));
    assert!(engine.orphans.iter().any(|(id, ..)| *id == queued_id), "fixture: in the pool");
    engine.want_parent_state_for(queued_id);
    assert!(!engine.reorg_anchors.side.wanting.contains(&queued_id), "RC5-07: not parked for its authority");
    engine.want_parent_state_for([0x5B; 32]);
    assert!(!engine.reorg_anchors.side.wanting.contains(&[0x5B; 32]), "nor a block that is not parked at all");
    assert_eq!(*engine.head_id().as_bytes(), tip);
}

/// Review RC5-08: a second recomputation that needs a start in the same
/// wall slot is refused without any work (review RC5-03: the turn closes
/// until the slot changes) and is served in the next slot.
#[test]
fn a_second_recomputation_start_waits_for_the_next_slot() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    let first = park_on(&mut engine, side_tip, 1, 0x90);
    engine.want_parent_state_for(first);
    for _ in 0..4 {
        engine.validate_side_branch_turn(800);
    }
    assert!(engine.deferred_orphans.iter().any(|(id, ..)| *id == first), "the first is served");
    assert_eq!(engine.reorg_anchors.side.want_starts, SIDE_WANT_STARTS_PER_SLOT);
    let spent = engine.reorg_anchors.side.spent;

    // The door judged it; its parent's state is evicted again.
    engine.deferred_orphans.retain(|(id, ..)| *id != first);
    let post = engine.exact_parent_state(&side_tip).expect("held after the recomputation");
    for k in 0..=SIDE_TIP_STATES as u8 {
        engine.retain_side_state([0xC8 + k; 32], &post);
    }
    assert!(engine.exact_parent_state(&side_tip).is_none() && engine.exact_parent_state(&side[0]).is_none());
    let second = park_on(&mut engine, side_tip, 2, 0x91);
    engine.want_parent_state_for(second);
    for _ in 0..8 {
        engine.validate_side_branch_turn(800);
    }
    assert!(engine.orphans.iter().any(|(id, ..)| *id == second), "no second start in the slot");
    assert!(engine.reorg_anchors.side.want_closed, "closed until the slot changes");
    assert_eq!(engine.reorg_anchors.side.spent, spent, "and no block applied for it");
    assert_eq!(engine.reorg_anchors.side.want_starts, SIDE_WANT_STARTS_PER_SLOT);

    let slots = validate_until(&mut engine, 801, 2, &|e| e.deferred_orphans.iter().any(|(id, ..)| *id == second));
    assert_eq!(slots, 1, "served in the next slot");
    assert!(!engine.reorg_anchors.side.want_closed);
}

/// Review RC5-08: a recomputation longer than one turn, from a canonical
/// state below the fork point (one canonical block replayed first), resumes
/// from its cursor turn after turn with a single start, applies every block
/// once, and ends on the tip's own state root.
#[test]
fn a_long_recomputation_resumes_across_turns_from_a_canonical_start() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(6);
    let side_tip = *side.last().unwrap();
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    let fork_point = *engine.chain[1].1.as_bytes();
    engine.recent_states.retain(|(id, _)| *id != fork_point);
    engine.reorg_anchors.pending = None;
    engine.reorg_anchors.base = None;
    assert!(engine.exact_parent_state(&fork_point).is_none(), "fixture: the fork point's state must be replayed");
    let (start, ..) = engine.side_fold_canonical_start(1, &[]).unwrap_or((0, engine.state.arc(), false));
    assert!(start < 1, "fixture: a canonical start below the fork point");
    let child = park_on(&mut engine, side_tip, 1, 0x92);
    engine.want_parent_state_for(child);

    let mut turns = 0;
    while engine.exact_parent_state(&side_tip).is_none() {
        assert!(turns < 16, "the recomputation finishes");
        engine.validate_side_branch_turn(800);
        turns += 1;
        let side_state = &engine.reorg_anchors.side;
        assert!(side_state.want_starts <= SIDE_WANT_STARTS_PER_SLOT, "one start");
        if engine.exact_parent_state(&side_tip).is_none() {
            assert!(side_state.want_cursor.is_some(), "resumes from its cursor");
            assert_eq!(side_state.want_target, Some(side_tip));
        }
    }
    assert!(engine.deferred_orphans.iter().any(|(id, ..)| *id == child), "queued (on its grandparent's way)");
    let applied = side.len() + 1 - start;
    assert_eq!(turns, applied.div_ceil(SIDE_BRANCH_BLOCKS_PER_TURN), "turn after turn");
    assert_eq!(engine.reorg_anchors.side.spent, applied, "the fork point and each side block once");
    let held = engine.exact_parent_state(&side_tip).expect("the tip's exact post-state is held again");
    assert_eq!(held.state_root(), engine.blocks[&side_tip].header.state_root, "and it is the tip's own");
    assert!(engine.reorg_anchors.side.want_cursor.is_none() && engine.reorg_anchors.side.want_target.is_none());
    assert_eq!(*engine.head_id().as_bytes(), tip);
}

/// Review RC5-08: requests nothing can serve are given up without a block
/// application (a fork point below the finality floor, a branch deeper than
/// [`SIDE_BRANCH_MAX_DEPTH`]) or after a local fault (a canonical block on
/// the way that will not replay); the blocks stay parked as before.
#[test]
fn a_wanted_state_is_given_up_below_the_floor_past_the_depth_and_when_stuck() {
    // Below the floor.
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    let child = park_on(&mut engine, side[1], 1, 0x93);
    engine.want_parent_state_for(child);
    engine.finalized_latch = Some((2, *engine.chain[2].1.as_bytes()));
    let spent = engine.reorg_anchors.side.spent;
    assert_eq!(engine.serve_wanted_side_state_turn(), Some(false));
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "given up");
    assert!(engine.reorg_anchors.side.want_target.is_none() && engine.reorg_anchors.side.want_cursor.is_none());
    assert_eq!(engine.reorg_anchors.side.spent, spent, "without a block application");
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child), "still parked");

    // Past the depth: header-only blocks, never run.
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(1);
    let template = engine.blocks[&side[0]].clone();
    let mut parent = side[0];
    for k in 0..SIDE_BRANCH_MAX_DEPTH as u64 {
        let mut block = template.clone();
        block.header.parent = parent;
        block.header.slot += 1 + k;
        parent = *block.block_id().as_bytes();
        engine.blocks.insert(parent, block);
        engine.blocks.mark_validated(&parent);
    }
    engine.blocks.mark_validated(&side[0]);
    let child = park_on(&mut engine, parent, 1, 0x94);
    engine.want_parent_state_for(child);
    let spent = engine.reorg_anchors.side.spent;
    assert_eq!(engine.serve_wanted_side_state_turn(), Some(false));
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "given up");
    assert_eq!(engine.reorg_anchors.side.spent, spent, "without a block application");
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child), "still parked");

    // Stuck: the canonical fork point must be replayed and is not stored.
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    let fork_point = *engine.chain[1].1.as_bytes();
    engine.recent_states.retain(|(id, _)| *id != fork_point);
    engine.reorg_anchors.pending = None;
    engine.reorg_anchors.base = None;
    engine.blocks.remove(&fork_point);
    let child = park_on(&mut engine, side[1], 1, 0x95);
    engine.want_parent_state_for(child);
    assert_eq!(engine.serve_wanted_side_state_turn(), Some(false));
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "given up on a local fault");
    assert!(engine.reorg_anchors.side.want_target.is_none() && engine.reorg_anchors.side.want_cursor.is_none());
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child), "still parked");
    assert!(engine.blocks.is_validated(&side[1]), "nothing is judged differently");
}

/// Review RC5-08: a block on the path that fails the transition during a
/// recomputation is removed and remembered, as the fold does, and the
/// request is given up: the parked block is not queued on any state.
#[test]
fn a_block_failing_the_transition_during_a_recomputation_is_removed_and_remembered() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    let mut bad = engine.blocks[&side[0]].clone();
    bad.header.state_root = [0xEE; 32];
    let bad_id = *bad.block_id().as_bytes();
    engine.blocks.insert(bad_id, bad);
    let mut above = engine.blocks[&side[1]].clone();
    above.header.parent = bad_id;
    let above_id = *above.block_id().as_bytes();
    engine.blocks.insert(above_id, above);
    // As if validated before (a store that went wrong, or a rule that
    // changed under it): the recomputation judges them again regardless.
    engine.blocks.mark_validated(&bad_id);
    engine.blocks.mark_validated(&above_id);
    let child = park_on(&mut engine, above_id, 1, 0x96);
    engine.want_parent_state_for(child);
    assert_eq!(engine.serve_wanted_side_state_turn(), Some(false));
    assert!(!engine.blocks.contains_key(&bad_id), "removed");
    assert!(engine.reorg_anchors.side.failed_index.contains(&bad_id), "and remembered");
    assert!(engine.exact_parent_state(&above_id).is_none(), "no state for what is above it");
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "the request is given up");
    assert!(engine.orphans.iter().any(|(id, ..)| *id == child), "the block is not queued");
    let (start, ..) = engine.side_fold_canonical_start(1, &[]).unwrap_or((0, engine.state.arc(), false));
    assert_eq!(engine.reorg_anchors.side.spent, 1 - start + 1, "the canonical replay, then the failing block");
}

// ---------------------------------------------------------------------------
// Independent review of 6b35aa94 (RC4) and 4f95205c (RC5), round L1R18.
// Each test below states a property the two commits are meant to give and
// FAILS on 4f95205c. They are regression tests for the fixes still to come;
// none of them changes production code.
// ---------------------------------------------------------------------------

/// Review L1R18-RC-01 (the RC5-01 defect, on the path RC5 did not touch).
///
/// RC5-01 keeps a block wanted until it is queued, but only a block the door
/// flagged (`JudgeWantingParentState`: its parent was ALREADY validated and
/// its state evicted). A block parked while its side-branch parent was still
/// unvalidated is never flagged; it relies on the single
/// `rejudge_parked_on` call the fold makes when it validates the parent (and
/// the parent's child), which moves at most
/// [`SIDE_PARKED_REJUDGE_PER_BLOCK`] blocks in pool order. Anything parked
/// ahead of the honest block beyond that cap (unauthenticated headers are
/// parked for authority too: an unknown or deposit-added index needs no
/// signature) strands it exactly as in RC5-01: the parent is validated, so
/// it is no longer a fold candidate, the head does not move, and nothing
/// queues the block again.
#[test]
fn l1r18_a_block_parked_on_an_unvalidated_side_tip_behind_more_than_the_rejudge_cap_is_still_queued() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    assert!(!engine.blocks.is_validated(&side_tip), "fixture: the fold has not reached the tip yet");
    // Two validations move blocks parked on the tip: the tip's parent (as
    // their parent's parent) and the tip itself.
    let ahead: Vec<[u8; 32]> = (0..2 * SIDE_PARKED_REJUDGE_PER_BLOCK as u64)
        .map(|k| park_on(&mut engine, side_tip, 1 + k, 0x70 + k as u8))
        .collect();
    let honest = park_on(&mut engine, side_tip, 40, 0x6F);
    assert!(!engine.reorg_anchors.side.wanting.contains(&honest), "fixture: parked before validation, not wanted");

    validate_until(&mut engine, 500, 16, &|e| side.iter().all(|id| e.blocks.is_validated(id)));
    for id in &ahead {
        assert!(engine.deferred_orphans.iter().any(|(seen, ..)| seen == id), "fixture: the blocks ahead are queued");
    }
    // The door judges what was queued; the head never moves. Give the fold
    // every chance to queue the honest block.
    let mut queued = false;
    for slot in 600..632 {
        for _ in 0..2 * SIDE_BRANCH_BLOCKS_PER_SLOT {
            engine.validate_side_branch_turn(slot);
            queued |= engine.deferred_orphans.iter().any(|(id, ..)| *id == honest);
        }
        engine.deferred_orphans.retain(|(id, ..)| *id == honest);
    }
    assert_eq!(*engine.head_id().as_bytes(), tip, "the head did not move");
    assert!(engine.exact_parent_state(&side_tip).is_some(), "its parent's exact state is even held");
    assert!(queued, "the honest block is stranded in the orphan pool: nothing queues it for the door again");
}

/// Review L1R18-RC-02: the per-proposer share of recomputation targets
/// (RC5-02) refuses a third parent, and the refusal is final: the request is
/// made only at the door, the pool deduplicates a re-offered envelope, and
/// nothing asks again once the proposer's first two requests were served.
/// The refused block is stranded although the share is free again.
#[test]
fn l1r18_a_request_refused_by_the_per_proposer_share_is_made_again_once_the_share_is_free() {
    let (mut engine, _dir, tip, side) = held_head_with_side_branch(6);
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    // Three parents no recomputation for another one passes by.
    let parents = [side[0], side[2], side[5]];
    for id in &side {
        assert!(engine.exact_parent_state(id).is_none(), "fixture: no side state is held");
    }
    let mine: Vec<[u8; 32]> =
        parents.iter().enumerate().map(|(k, p)| park_on_as(&mut engine, *p, 1, 0xA0 + k as u8, 0)).collect();
    for id in &mine {
        engine.want_parent_state_for(*id);
    }
    assert!(!engine.reorg_anchors.side.wanting.contains(&mine[2]), "fixture: the third parent is refused");

    let mut queued: BTreeSet<[u8; 32]> = BTreeSet::new();
    for slot in 800..832 {
        for _ in 0..2 * SIDE_BRANCH_BLOCKS_PER_SLOT {
            engine.validate_side_branch_turn(slot);
            queued.extend(engine.deferred_orphans.iter().map(|(id, ..)| *id));
        }
        // The door judges what was queued.
        engine.deferred_orphans.clear();
    }
    assert_eq!(*engine.head_id().as_bytes(), tip);
    assert!(queued.contains(&mine[0]) && queued.contains(&mine[1]), "the first two requests are served");
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "the proposer's share is free again");
    assert!(queued.contains(&mine[2]), "the refused block is stranded: nothing asks for its parent's state again");
}

/// Review L1R18-RC-03: a wanted block stays wanted until it has LEFT the
/// orphan pool at the start of a serving turn (RC5-01). A block the door
/// judges on the recomputed state and parks again (the state says static
/// mode: before the bind, or the failure is not provable) is back in the
/// pool before the next serving turn looks, so it is still wanted, its
/// parent's state is held, and it is queued for the door again: once per
/// engine turn, for as long as the state is held, each time through the
/// whole door (a hybrid signature verification on the source's lane).
#[test]
fn l1r18_a_wanted_block_the_door_parks_again_is_not_queued_on_every_turn() {
    let (mut engine, _dir, _tip, side) = held_head_with_side_branch(2);
    let side_tip = side[1];
    validated_side_branch_evicted_from_the_ring(&mut engine, &side, SIDE_TIP_STATES);
    let child = park_on(&mut engine, side_tip, 1, 0x64);
    engine.want_parent_state_for(child);
    validate_until(&mut engine, 800, 16, &|e| {
        e.deferred_orphans.iter().any(|(id, ..)| *id == child) && e.exact_parent_state(&side_tip).is_some()
    });

    // The engine loop: one promotion (the door), then one validation turn.
    let mut judged = 0usize;
    for slot in 900..904 {
        for _ in 0..8 {
            if let Some(at) = engine.deferred_orphans.iter().position(|(id, ..)| *id == child) {
                let (id, env, src, ..) = engine.deferred_orphans.remove(at).expect("queued");
                // Judged on its parent's exact state; still not judgeable
                // (the door does not ask for the state again: it is held).
                let under = bloch_pos_committee::kes::authority_fingerprint(
                    &*engine.proposer_authority_state(&side_tip),
                    env.header.proposer_index,
                    epoch_of(env.header.slot),
                );
                engine.park_unjudgeable(id, env, src, under);
                judged += 1;
            }
            engine.validate_side_branch_turn(slot);
        }
    }
    assert!(engine.exact_parent_state(&side_tip).is_some(), "the state was held throughout");
    assert_eq!(judged, 1, "judged once on the recomputed state; nothing changed since, so not again");
}
