// SPDX-License-Identifier: AGPL-3.0-or-later
//! VAL-1: the producer includes a pooled vote only if it verifies under the
//! authority the block's pre-state names, and a vote the transition refuses
//! leaves the pool instead of costing every later proposal its slot.
use super::*;

/// A live single-validator engine whose head is in epoch 1, with validator
/// 0's duty slot in that epoch.
fn engine_in_epoch_one() -> (Engine, perf_support::TestDir, u64) {
    let (mut engine, dir) = perf_support::proposing_engine();
    engine.propose(1);
    engine.propose(32);
    engine.needs_sync = false;
    assert_eq!(epoch_of(engine.state.slot()), 1);
    let head = *engine.head_id().as_bytes();
    let seed = engine.seed_for_attestation(&head, 1).expect("the head's branch is held");
    let roster = engine.rolled_to(1).active_validators();
    let duty = (32..64)
        .find(|slot| committees::committee_for_slot(&seed, *slot, &roster).contains(&0))
        .expect("validator 0 attests once in the epoch");
    (engine, dir, duty)
}

/// Validator 0's vote for `slot`, signed by its static key. `salt` makes
/// distinct votes for one slot.
fn vote(engine: &Engine, slot: u64, target_epoch: u64, salt: u8) -> Attestation {
    let head = *engine.head_id().as_bytes();
    let mut source_root = *engine.manifest.genesis_id().as_bytes();
    source_root[0] ^= salt;
    let data = AttestationData { slot, head, source_epoch: 0, source_root, target_epoch, target_root: head };
    let signature = engine.keys.as_ref().expect("the fixture holds a keystore").sign(&data.signing_root());
    Attestation { data, validator: 0, signature }
}

/// The same vote carrying bytes its key did not sign: what a vote verified
/// under another authority looks like to the transition.
fn unverifiable(engine: &Engine, slot: u64, salt: u8) -> Attestation {
    let mut att = vote(engine, slot, epoch_of(slot), salt);
    att.signature = vote(engine, slot, epoch_of(slot), salt.wrapping_add(1)).signature;
    att
}

fn key(att: &Attestation) -> (u32, [u8; 32]) {
    (att.validator, att.data.signing_root())
}

fn pooled(engine: &mut Engine, att: &Attestation) {
    engine.pool.insert(key(att), att.clone());
}

/// Gossip: a vote whose target is not its slot's epoch is neither pooled nor
/// recorded, although its signature verifies; the honest form is.
#[test]
fn gossip_ignores_a_vote_whose_target_is_not_its_slots_epoch() {
    let (mut engine, _dir, duty) = engine_in_epoch_one();
    let _clock = validator_lifecycle::clock_at(duty);
    engine.wall_slot = duty;

    let off_target = vote(&engine, duty, 2, 0);
    engine.on_attestation(off_target.clone(), Origin::none(), 1);
    assert!(engine.pool.is_empty(), "a vote for another epoch than its slot's must not be pooled");
    assert!(engine.pool_authority.is_empty());

    let honest = vote(&engine, duty, 1, 0);
    engine.on_attestation(honest.clone(), Origin::none(), 1);
    assert!(engine.pool.contains_key(&key(&honest)), "the honest vote is pooled as before");
    let rolled = engine.rolled_to(1);
    assert_eq!(
        engine.pool_authority.get(&key(&honest)).copied(),
        bloch_pos_committee::kes::authority_fingerprint(&*rolled, 0, 1),
        "with the authority it was verified under",
    );
}

/// The producer: a pooled vote that does not verify under the block's
/// pre-state is evicted and the block is still produced and adopted. Before
/// the fix the vote was selected on the gossip verdict, the node refused its
/// own block, and the vote stayed for the next proposer.
#[test]
fn a_pooled_vote_the_transition_would_refuse_is_evicted_not_proposed() {
    let (mut engine, _dir, duty) = engine_in_epoch_one();
    let slot = duty.max(33);
    let good = vote(&engine, duty, 1, 0);
    let bad = unverifiable(&engine, duty, 1);
    let off_target = vote(&engine, duty, 2, 3);
    for att in [&good, &bad, &off_target] {
        pooled(&mut engine, att);
    }
    let before = *engine.head_id().as_bytes();

    engine.propose(slot);

    let head = *engine.head_id().as_bytes();
    assert_ne!(head, before, "the proposer's own block must be adopted");
    let block = engine.blocks.get(&head).expect("the head is stored");
    assert_eq!(block.header.slot, slot);
    assert_eq!(block.body.attestations, vec![good.clone()], "only the vote that verifies is carried");
    assert!(!engine.pool.contains_key(&key(&bad)), "the refused vote is gone from the pool");
    assert!(!engine.pool.contains_key(&key(&good)), "the included vote left on inclusion");
    assert!(engine.pool.contains_key(&key(&off_target)), "an off-target vote is skipped, not judged");
}

/// A vote whose recorded authority is not the one the pre-state names is
/// verified again: kept (and re-recorded) if it still verifies.
#[test]
fn a_vote_recorded_under_another_authority_is_verified_again() {
    let (mut engine, _dir, duty) = engine_in_epoch_one();
    let slot = duty.max(33);
    let good = vote(&engine, duty, 1, 0);
    pooled(&mut engine, &good);
    engine.pool_authority.insert(key(&good), [0x5A; 32]);
    let rolled = engine.rolled_to(1);
    let mut atts = vec![good.clone()];
    engine.retain_block_valid_votes(&mut atts, &rolled, 1);
    assert_eq!(atts, vec![good.clone()]);
    assert_eq!(
        engine.pool_authority.get(&key(&good)).copied(),
        bloch_pos_committee::kes::authority_fingerprint(&*rolled, 0, 1),
    );

    engine.propose(slot);
    let head = *engine.head_id().as_bytes();
    assert_eq!(engine.blocks.get(&head).expect("stored").body.attestations, vec![good]);
}

/// The work is bounded: one proposal verifies at most
/// `PROPOSAL_VOTE_REJUDGE_MAX` unrecorded votes, and still produces a block.
#[test]
fn one_proposal_verifies_a_bounded_number_of_unrecorded_votes() {
    let (mut engine, _dir, duty) = engine_in_epoch_one();
    let slot = duty.max(33);
    let extra = 6usize;
    for salt in 0..(PROPOSAL_VOTE_REJUDGE_MAX + extra) {
        // Even salts only: `unverifiable` borrows the signature of salt + 1.
        let att = unverifiable(&engine, duty, (salt * 2) as u8);
        pooled(&mut engine, &att);
    }
    assert_eq!(engine.pool.len(), PROPOSAL_VOTE_REJUDGE_MAX + extra);
    let before = *engine.head_id().as_bytes();

    engine.propose(slot);

    assert_ne!(*engine.head_id().as_bytes(), before, "a block is produced regardless");
    assert!(engine.blocks.get(engine.head_id().as_bytes()).expect("stored").body.attestations.is_empty());
    assert_eq!(engine.pool.len(), extra, "votes past the allowance wait for a later proposal");
}

/// Defence in depth: if a vote recorded as verified is refused by the real
/// transition anyway, the own-block refusal names it, evicts it and the next
/// proposal succeeds.
#[test]
fn a_vote_refused_in_the_own_block_is_evicted_and_the_next_proposal_succeeds() {
    let (mut engine, _dir, duty) = engine_in_epoch_one();
    let slot = duty.max(33);
    let good = vote(&engine, duty, 1, 0);
    let bad = unverifiable(&engine, duty, 1);
    let rolled = engine.rolled_to(1);
    let authority = bloch_pos_committee::kes::authority_fingerprint(&*rolled, 0, 1).expect("registered");
    for att in [&good, &bad] {
        pooled(&mut engine, att);
        // Stands in for a verdict the record wrongly vouches for.
        engine.pool_authority.insert(key(att), authority);
    }
    let before = *engine.head_id().as_bytes();

    engine.propose(slot);
    assert_eq!(*engine.head_id().as_bytes(), before, "the real verifier refuses the block");
    assert!(!engine.pool.contains_key(&key(&bad)), "and the diagnosis evicts the vote it failed on");
    assert!(engine.pool.contains_key(&key(&good)));
    assert!(!engine.pool_authority.contains_key(&key(&good)), "no record of that block is trusted again");

    engine.propose(slot + 1);
    let head = *engine.head_id().as_bytes();
    assert_ne!(head, before, "the next proposal is adopted");
    assert_eq!(engine.blocks.get(&head).expect("stored").body.attestations, vec![good]);
}
