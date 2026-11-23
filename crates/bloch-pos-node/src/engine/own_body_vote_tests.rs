// SPDX-License-Identifier: AGPL-3.0-or-later
//! Votes of this node's own key that arrive inside blocks (audit L1C-31).
//!
//! Every block and vote is produced and judged by the production paths
//! (`attest`, `propose`, the block door, the real transition and verifier).
use super::*;

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

fn as_validators(engine: &mut Engine, vals: &mut Validators, who: &[usize], duty: &dyn Fn(&mut Engine)) {
    for &i in who {
        std::mem::swap(&mut engine.keys, &mut vals[i].0);
        std::mem::swap(&mut engine.slashprot, &mut vals[i].1);
        duty(engine);
        std::mem::swap(&mut engine.keys, &mut vals[i].0);
        std::mem::swap(&mut engine.slashprot, &mut vals[i].1);
    }
}

struct Fixture {
    engine: Engine,
    dir: perf_support::TestDir,
    vals: Validators,
    /// Three epochs of blocks, all proposed by validator 1, carrying
    /// validator 0's votes.
    branch: Vec<BlockEnvelope>,
    /// Validator 0's votes carried in `branch`.
    carried: Vec<Attestation>,
    last_slot: u64,
}

/// Two validators. Validator 0 attests (with the record `vals[0].1`),
/// validator 1 attests and proposes, so validator 0's votes travel in
/// validator 1's blocks. The engine is then put back at genesis without the
/// branch, as a node that has not received it.
fn votes_carried_in_blocks() -> Fixture {
    let (mut engine, dir, others) = perf_support::proposing_engine_n(&[], 2);
    let mut vals = validators(&mut engine, &dir, others);
    let genesis = *engine.manifest.genesis_id().as_bytes();
    let last_slot = 3 * SLOTS_PER_EPOCH - 1;
    for slot in 1..=last_slot {
        as_validators(&mut engine, &mut vals, &[0, 1], &|e| e.attest(slot));
        as_validators(&mut engine, &mut vals, &[1], &|e| e.propose(slot));
    }
    let branch: Vec<BlockEnvelope> =
        engine.chain[1..].iter().map(|(_, id)| engine.blocks[id.as_bytes()].clone()).collect();
    let carried: Vec<Attestation> =
        branch.iter().flat_map(|b| b.body.attestations.iter()).filter(|a| a.validator == 0).cloned().collect();
    assert!(carried.len() >= 2, "fixture: the blocks carry validator 0's votes");
    assert!(branch.iter().all(|b| b.header.proposer_index == 1), "fixture: only validator 1 proposed");
    assert!(engine.do_reorg(genesis, Vec::new()));
    for block in &branch {
        engine.blocks.remove(block.block_id().as_bytes());
    }
    engine.pool.clear();
    engine.att_pool = AttestationPool::new();
    Fixture { engine, dir, vals, branch, carried, last_slot }
}

fn fresh_record(dir: &perf_support::TestDir, name: &str) -> SlashingProtection {
    let sub = dir.0.join(name);
    std::fs::create_dir_all(&sub).unwrap();
    SlashingProtection::open(&sub).unwrap()
}

fn latest(votes: &[Attestation]) -> Attestation {
    votes.iter().max_by_key(|a| a.data.target_epoch).unwrap().clone()
}

/// A second instance of this key signed votes that reach this node only
/// inside blocks. Before the fix the node adopted the chain, was not
/// halted, kept an empty record and would sign the same target again.
#[test]
fn a_second_instances_votes_carried_in_blocks_stop_duties_and_raise_the_record() {
    let Fixture { mut engine, dir, mut vals, branch, carried, last_slot } = votes_carried_in_blocks();
    let theirs = latest(&carried);
    // This node: the same key, its own record, which never saw those duties.
    engine.keys = vals[0].0.take();
    engine.slashprot = fresh_record(&dir, "this-instance");
    assert!(engine.live, "the fixture is a live node");
    let wall = last_slot + 1;
    engine.start_doppelganger_observation(wall);
    for (i, block) in branch.iter().enumerate() {
        let _clock = validator_lifecycle::clock_at(wall + i as u64);
        assert_eq!(engine.ingest_judged(block.clone()), Verdict::Accept, "block {i}");
    }
    assert_eq!(*engine.head_id().as_bytes(), *branch.last().unwrap().block_id().as_bytes());
    assert!(engine.doppelganger_halted, "an authentic vote of this key that the record does not cover stops duties");
    let record = engine.slashprot.watermarks();
    assert_eq!(record.target_epoch, Some(theirs.data.target_epoch), "the record is raised to the other instance's votes");
    assert_eq!(record.attestation_slot, Some(theirs.data.slot));
    let mut signed = false;
    let refused = engine
        .slashprot
        .guard_attestation(theirs.data.slot, theirs.data.source_epoch, theirs.data.target_epoch, || signed = true)
        .is_err();
    assert!(refused && !signed, "the record no longer admits a second vote for target {}", theirs.data.target_epoch);
    // The halt holds after the observation window too.
    assert!(engine.doppelganger_blocks_duties(wall + 10 * DOPPELGANGER_OBSERVE_SLOTS));
}

/// The same votes arriving with a branch adopted by reorganization.
#[test]
fn votes_of_this_key_in_a_branch_adopted_by_reorg_are_seen_too() {
    let Fixture { mut engine, dir, mut vals, branch, carried, .. } = votes_carried_in_blocks();
    let theirs = latest(&carried);
    let genesis = *engine.manifest.genesis_id().as_bytes();
    engine.keys = vals[0].0.take();
    engine.slashprot = fresh_record(&dir, "this-instance");
    assert!(engine.do_reorg(genesis, branch.clone()), "the branch is valid");
    assert!(engine.doppelganger_halted);
    assert_eq!(engine.slashprot.watermarks().target_epoch, Some(theirs.data.target_epoch));
}

/// Boot replay is not live evidence: it raises the record before any duty
/// and does not halt.
#[test]
fn replayed_blocks_raise_the_record_without_stopping_duties() {
    let Fixture { mut engine, dir, mut vals, branch, carried, .. } = votes_carried_in_blocks();
    let theirs = latest(&carried);
    engine.keys = vals[0].0.take();
    engine.slashprot = fresh_record(&dir, "restored-data-dir");
    engine.live = false;
    for block in &branch {
        assert!(engine.ingest_replay(block.clone()));
    }
    assert!(!engine.doppelganger_halted, "replay is not evidence of a live duplicate");
    assert_eq!(engine.slashprot.watermarks().target_epoch, Some(theirs.data.target_epoch));
    assert_eq!(engine.slashprot.watermarks().attestation_slot, Some(theirs.data.slot));
}

/// The node's own votes come back to it in blocks all the time. With the
/// record that signed them nothing happens: not after the window, and not
/// inside it either (a node restarted within the slot it voted in reads its
/// own vote in the next block; the gossip-style window check would halt it).
#[test]
fn votes_the_record_covers_never_stop_duties_even_inside_the_observation_window() {
    let Fixture { mut engine, dir: _dir, mut vals, branch, carried, .. } = votes_carried_in_blocks();
    // This node IS the instance that signed: the key with its own record.
    engine.keys = vals[0].0.take();
    std::mem::swap(&mut engine.slashprot, &mut vals[0].1);
    let before = engine.slashprot.watermarks();
    assert_eq!(before.target_epoch, Some(latest(&carried).data.target_epoch));
    // Restarted in the slot of its FIRST vote: every carried vote is dated
    // inside the observation window.
    let wall = carried.iter().map(|a| a.data.slot).min().unwrap();
    engine.start_doppelganger_observation(wall);
    for (i, block) in branch.iter().enumerate() {
        // The block door's clock follows the blocks; the engine's own wall
        // slot (what the observation window is measured against) stays
        // where the restart put it, so every block is judged inside it.
        let _clock = validator_lifecycle::clock_at(block.header.slot.max(wall));
        assert_eq!(engine.ingest_judged(block.clone()), Verdict::Accept, "block {i}");
        assert!(!engine.doppelganger_halted, "block {i}");
    }
    assert!(engine.wall_slot < engine.doppelganger_observe_until.unwrap(), "still inside the window");
    assert!(!engine.doppelganger_halted, "its own covered votes are not a duplicate instance");
    assert_eq!(engine.slashprot.watermarks(), before, "and the record is not touched");
}

/// Another validator's node is not affected by votes that are not its own,
/// and an observer (no key) ignores bodies altogether.
#[test]
fn other_validators_votes_and_observers_are_unaffected() {
    let Fixture { mut engine, dir, mut vals, branch, .. } = votes_carried_in_blocks();
    // Validator 1's node with a fresh record: validator 1 proposed every
    // block, so it is halted by the PROPOSER check that already existed.
    // The point here is validator 0's votes: they are not validator 1's.
    engine.keys = vals[1].0.take();
    engine.slashprot = fresh_record(&dir, "validator-1");
    engine.live = false; // isolate the body hook from the live proposer check
    for block in &branch {
        assert!(engine.ingest_replay(block.clone()));
    }
    let record = engine.slashprot.watermarks();
    let own: Vec<&Attestation> =
        branch.iter().flat_map(|b| b.body.attestations.iter()).filter(|a| a.validator == 1).collect();
    assert_eq!(record.target_epoch, own.iter().map(|a| a.data.target_epoch).max(), "raised to validator 1's own votes only");
    assert_eq!(record.attestation_slot, own.iter().map(|a| a.data.slot).max());
    assert!(!engine.doppelganger_halted);
}

#[test]
fn an_observer_ignores_body_votes() {
    let Fixture { mut engine, dir: _dir, branch, .. } = votes_carried_in_blocks();
    engine.keys = None;
    let before = engine.slashprot.watermarks();
    for block in &branch {
        let _clock = validator_lifecycle::clock_at(block.header.slot);
        assert_eq!(engine.ingest_judged(block.clone()), Verdict::Accept);
    }
    assert!(!engine.doppelganger_halted);
    assert_eq!(engine.slashprot.watermarks(), before);
}

/// A forged body vote cannot halt a victim: the proposer (validator 1) puts
/// a vote under validator 0's index, with a far-future target, into an
/// otherwise real block and signs the header. The transition refuses the
/// block, so the hook never sees it.
#[test]
fn a_forged_body_vote_cannot_stop_a_victim_or_move_its_record() {
    let Fixture { mut engine, dir, mut vals, branch, carried, last_slot } = votes_carried_in_blocks();
    // The victim: validator 0's node, with the record that signed its votes.
    let proposer = vals[1].0.take().expect("validator 1's key");
    engine.keys = vals[0].0.take();
    std::mem::swap(&mut engine.slashprot, &mut vals[0].1);
    let (honest, tip) = branch.split_at(branch.len() - 1);
    for block in honest {
        let _clock = validator_lifecycle::clock_at(last_slot + 1);
        assert_eq!(engine.ingest_judged(block.clone()), Verdict::Accept);
    }
    let head_before = *engine.head_id().as_bytes();
    let before = engine.slashprot.watermarks();
    assert!(!engine.doppelganger_halted);
    // Forge: the last real vote of validator 0, re-dated far ahead, with a
    // signature validator 0 never made.
    let mut forged_vote = latest(&carried);
    forged_vote.data.target_epoch += 1_000;
    forged_vote.data.slot += 1_000 * SLOTS_PER_EPOCH;
    let mut forged = tip[0].clone();
    forged.body.attestations.push(forged_vote.clone());
    forged.header.attestation_root = derive::attestation_root(&forged.body.attestations);
    forged.proposer_sig = proposer.sign(&forged.header.proposal_signing_root());
    let _clock = validator_lifecycle::clock_at(last_slot + 1);
    let verdict = engine.ingest_judged(forged.clone());
    assert_ne!(verdict, Verdict::Accept, "a block with a forged vote is not valid");
    assert_eq!(*engine.head_id().as_bytes(), head_before, "and is not adopted");
    assert!(!engine.canonical.contains(forged.block_id().as_bytes()));
    assert!(!engine.doppelganger_halted, "the victim keeps its duties");
    assert_eq!(engine.slashprot.watermarks(), before, "and its record is not moved");
    // Same through a reorg candidate.
    let genesis = *engine.manifest.genesis_id().as_bytes();
    let mut candidate: Vec<BlockEnvelope> = honest.to_vec();
    candidate.push(forged);
    let _ = dir;
    assert!(!engine.do_reorg(genesis, candidate), "the forged block fails the transition");
    assert!(!engine.doppelganger_halted);
    assert_eq!(engine.slashprot.watermarks(), before);
}
