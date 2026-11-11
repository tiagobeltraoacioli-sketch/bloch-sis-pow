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
