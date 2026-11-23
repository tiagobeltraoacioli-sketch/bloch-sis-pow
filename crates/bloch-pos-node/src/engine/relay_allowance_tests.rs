// SPDX-License-Identifier: AGPL-3.0-or-later
//! Audit L1N-02: the relay verification allowance cannot be spent for free.
//!
//! Three rules, each with its regression below: votes verify under their own
//! lane; a transfer whose input a pending, admission-verified and still-backed
//! transaction holds is refused from the outpoint index before any signature
//! is verified; and a verification that ran and then admitted nothing is
//! charged to the source that asked for it. This node's own submissions keep
//! a small private share.
use super::proposal_revalidation_tests::{funds_of, spend};
use super::*;
use bloch_pos_committee::state_root::EutxoEntry;

const RELAY: verification::VerificationLane = verification::VerificationLane::Relay;
const VOTE: verification::VerificationLane = verification::VerificationLane::Vote;

/// `entry` paid to `to`: a different destination is a different transaction
/// identity with its own valid signature.
fn variant(entry: &EutxoEntry, to: u8, base: u128) -> PosTransaction {
    let mut redirected = entry.clone();
    redirected.script_hash = [to; 32];
    spend(&redirected, 9_000, 0, base)
}

/// Spend the whole relay lane the way eight sources do, without real
/// cryptography: distinct malformed inputs, each a reserved unit.
fn spend_relay_lane(engine: &Engine, slot: u64) {
    for n in 0..GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT {
        let mut source = [0xA0u8; 32];
        source[0] = (n / GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT) as u8;
        let mut root = [0u8; 32];
        root[..8].copy_from_slice(&(n as u64).to_le_bytes());
        let verifier = engine.gossip_verifier.budgeted_for_source(
            slot,
            GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT,
            Some(source),
            GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT,
        );
        assert!(!verifier.verify_with_key(b"malformed", &root, b"malformed"));
        assert!(!verifier.limited());
    }
    assert_eq!(engine.gossip_verifier.lane_used_at(slot, RELAY), GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT);
}

/// The transaction half. Conflicting variants of one pending transfer are
/// answered from the outpoint index: no signature is verified, no allowance
/// is spent, nobody is charged, and the pool is unchanged.
#[test]
fn conflicting_variants_of_a_pending_transfer_are_refused_before_any_verification() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds_of(2);
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    let slot = node.wall_slot();
    let first = spend(&funds[0], 9_000, 0, fee);
    assert_eq!(node.on_transaction_from(first.clone(), Some([0xA0; 32])), Ok(Admitted::New));
    let used = node.gossip_verifier.lane_used_at(slot, RELAY);
    assert_eq!(used, 1, "the admitted transfer cost one verification");

    let variants: Vec<_> = (0..12u8).map(|n| variant(&funds[0], 0x80 + n, fee)).collect();
    // Any verification from here on is a test failure.
    node.gossip_verifier.set_panic_on_verification(true);
    for (n, tx) in variants.into_iter().enumerate() {
        let source = [0xA0 + (n % 4) as u8; 32];
        assert_ne!(tx.txid(), first.txid(), "variant {n} is a different transaction");
        assert_eq!(
            node.on_transaction_from(tx, Some(source)),
            Err(Refusal::StateDependent(admission::INPUT_ALREADY_PENDING)),
            "variant {n} is refused as a lookup",
        );
        assert_eq!(node.gossip_verifier.source_failures_at(slot, RELAY, source), 0);
    }
    node.gossip_verifier.set_panic_on_verification(false);
    assert_eq!(node.gossip_verifier.lane_used_at(slot, RELAY), used, "no variant spent the shared allowance");
    assert_eq!(node.mempool.len(), 1);
    assert!(node.mempool.contains_key(&first.canonical_bytes()));

    // An unrelated transfer from another address is admitted as before.
    let honest = spend(&funds[1], 9_000, 0, fee);
    assert_eq!(node.on_transaction_from(honest, Some([0x11; 32])), Ok(Admitted::New));
    assert_eq!(node.gossip_verifier.lane_used_at(slot, RELAY), used + 1);
}

/// The property the lookup must keep: a pending transaction the current
/// state no longer backs refuses nothing, so its owner's replacement is
/// verified and takes its place.
#[test]
fn a_dead_pending_transfer_does_not_lock_its_owner_out_of_the_input() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds_of(2);
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    let dead = spend(&funds[1], 9_000, 0, fee);
    assert_eq!(node.on_transaction_from(dead.clone(), Some([0xB0; 32])), Ok(Admitted::New));
    // A real fee rise: a full block. The pending spend now underpays.
    let filler = spend(&funds[0], fee_market::max_block_tx_bytes(0), 101, fee);
    node.mempool.insert(filler.canonical_bytes(), filler);
    node.propose(1);
    let raised = node.state.next_base_fee_at(0);
    assert!(raised > fee);
    assert!(node.mempool.contains_key(&dead.canonical_bytes()), "the dead entry is still pending");
    assert!(node.pending_input_refusal(&spend(&funds[1], 9_000, 0, raised), 0).is_none());

    let replacement = spend(&funds[1], 9_000, 0, raised);
    assert_eq!(node.on_transaction_from(replacement.clone(), Some([0xB0; 32])), Ok(Admitted::New));
    assert!(!node.mempool.contains_key(&dead.canonical_bytes()), "the plan replaced the dead entry");
    assert!(node.mempool.contains_key(&replacement.canonical_bytes()));
    // And the live replacement now holds the input against the next variant.
    assert!(node.pending_input_refusal(&variant(&funds[1], 0x99, raised), 0).is_some());
}

/// A verification that ran, held, and then admitted nothing is charged to
/// its source. The holder here was placed without admission, so the lookup
/// before verification leaves it to the authenticated plan.
#[test]
fn a_verified_then_refused_transaction_is_charged_to_its_source() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds_of(2);
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    let slot = node.wall_slot();
    let holder = spend(&funds[0], 9_000, 0, fee);
    node.mempool.insert(holder.canonical_bytes(), holder);
    let noisy = [0xC1; 32];
    let allowance = GOSSIP_VERIFICATION_FAILURES_PER_SOURCE_PER_SLOT;

    for n in 0..allowance {
        let tx = variant(&funds[0], 0x40 + n as u8, fee);
        assert_eq!(
            node.on_transaction_from(tx, Some(noisy)),
            Err(Refusal::StateDependent(admission::INPUT_ALREADY_PENDING)),
            "variant {n}: verified, then refused by the plan",
        );
        assert_eq!(node.gossip_verifier.source_failures_at(slot, RELAY, noisy), n + 1);
    }
    assert_eq!(node.gossip_verifier.lane_used_at(slot, RELAY), allowance);

    // The allowance is spent: the next one is refused without verification.
    node.gossip_verifier.set_panic_on_verification(true);
    assert_eq!(
        node.on_transaction_from(variant(&funds[0], 0x7E, fee), Some(noisy)),
        Err(Refusal::GossipVerificationLimited { until_slot: slot + 1 }),
    );
    node.gossip_verifier.set_panic_on_verification(false);
    assert_eq!(node.gossip_verifier.lane_used_at(slot, RELAY), allowance, "nothing more was verified for it");

    // Another source is untouched, and an admitted transaction charges nobody.
    let honest = [0xC2; 32];
    assert_eq!(node.on_transaction_from(spend(&funds[1], 9_000, 0, fee), Some(honest)), Ok(Admitted::New));
    assert_eq!(node.gossip_verifier.source_failures_at(slot, RELAY, honest), 0);
    // The charge is to the transaction door only: the vote door stays open.
    assert_eq!(node.gossip_verifier.source_failures_at(slot, VOTE, noisy), 0);
}

/// The vote half: with the relay lane spent by transactions, a vote is still
/// verified and pooled in the same slot, on its own lane.
#[test]
fn votes_keep_their_own_allowance_when_transactions_spent_theirs() {
    let (mut engine, _dir) = perf_support::proposing_engine();
    engine.propose(1);
    engine.propose(32);
    engine.needs_sync = false;
    let head = *engine.head_id().as_bytes();
    let seed = engine.seed_for_attestation(&head, 1).expect("the head's branch is held");
    let roster = engine.rolled_to(1).active_validators();
    let duty = (32..64)
        .find(|slot| committees::committee_for_slot(&seed, *slot, &roster).contains(&0))
        .expect("validator 0 attests once in the epoch");
    let _clock = validator_lifecycle::clock_at(duty);
    engine.wall_slot = duty;
    spend_relay_lane(&engine, duty);

    let data = AttestationData {
        slot: duty,
        head,
        source_epoch: 0,
        source_root: *engine.manifest.genesis_id().as_bytes(),
        target_epoch: 1,
        target_root: head,
    };
    let signature = engine.keys.as_ref().unwrap().sign(&data.signing_root());
    let vote = Attestation { data, validator: 0, signature };
    let key = (vote.validator, vote.data.signing_root());
    engine.on_attestation(vote, Origin::none(), 1);
    assert!(engine.pool.contains_key(&key), "the vote is pooled although transactions spent their lane");
    assert_eq!(engine.gossip_verifier.lane_used_at(duty, VOTE), 1, "it was verified on the vote lane");
    assert_eq!(engine.gossip_verifier.lane_used_at(duty, RELAY), GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT);
}

/// With the shared relay lane spent, this node's own submission is still
/// verified from its private share; a frame or RPC call is not, with or
/// without an attributed source.
#[test]
fn own_submissions_keep_a_private_share_no_remote_source_can_spend() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds_of(3);
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    let slot = node.wall_slot();
    spend_relay_lane(&node, slot);

    let limited = Err(Refusal::GossipVerificationLimited { until_slot: slot + 1 });
    assert_eq!(node.on_transaction_from(spend(&funds[0], 9_000, 0, fee), Some([0x11; 32])), limited);
    assert_eq!(
        node.on_transaction_from(spend(&funds[0], 9_000, 0, fee), None),
        limited,
        "an unattributed frame is not this node's own submission",
    );
    assert_eq!(node.gossip_verifier.own_headroom_used_at(slot, RELAY), 0);

    assert_eq!(node.on_transaction(spend(&funds[1], 9_000, 0, fee)), Ok(Admitted::New));
    assert_eq!(node.gossip_verifier.own_headroom_used_at(slot, RELAY), 1);
    assert_eq!(node.gossip_verifier.lane_used_at(slot, RELAY), GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT);

    // The private share is itself bounded, and renews with the slot.
    for n in 1..OWN_SUBMISSION_VERIFICATIONS_PER_SLOT {
        let mut root = [0xEEu8; 32];
        root[..8].copy_from_slice(&(n as u64).to_le_bytes());
        let own = node.gossip_verifier
            .budgeted_for_source(slot, GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT, None, GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT)
            .with_own_headroom(OWN_SUBMISSION_VERIFICATIONS_PER_SLOT);
        assert!(!own.verify_with_key(b"malformed", &root, b"malformed"));
        assert!(!own.limited(), "own unit {n} is inside the private share");
    }
    assert_eq!(node.on_transaction(spend(&funds[2], 9_000, 0, fee)), limited, "the private share is spent");
    drop(_clock);
    let _clock = validator_lifecycle::clock_at(slot + 1);
    assert_eq!(node.on_transaction(spend(&funds[2], 9_000, 0, fee)), Ok(Admitted::New));
}

/// The outpoint index names exactly the pending entries that spend an
/// outpoint, through insertion, replacement and removal.
#[test]
fn the_outpoint_index_follows_the_pool() {
    let funds = funds_of(2);
    let a = spend(&funds[0], 9_000, 0, 1);
    let b = variant(&funds[0], 0x55, 1);
    let c = spend(&funds[1], 9_000, 0, 1);
    let point = |entry: &EutxoEntry| (entry.txid, entry.vout);
    let mut pool = admission::Mempool::default();
    assert!(pool.spenders_of(&point(&funds[0])).is_empty());
    for tx in [&a, &b, &c] {
        pool.insert_with_txid(tx.canonical_bytes(), tx.clone(), tx.txid());
    }
    let mut held: Vec<Vec<u8>> = pool.spenders_of(&point(&funds[0])).iter().map(|key| key.to_vec()).collect();
    held.sort();
    let mut expected = vec![a.canonical_bytes(), b.canonical_bytes()];
    expected.sort();
    assert_eq!(held, expected);
    assert_eq!(pool.spenders_of(&point(&funds[1])).len(), 1);
    let both = pool.entries_spending(&[point(&funds[0]), point(&funds[1])]);
    assert_eq!(both.len(), 3);
    assert!(both.keys().copied().eq(pool.keys().map(Vec::as_slice)), "in pool key order");

    // Re-inserting an entry does not list it twice.
    pool.insert_with_txid(a.canonical_bytes(), a.clone(), a.txid());
    assert_eq!(pool.spenders_of(&point(&funds[0])).len(), 2);
    pool.remove(&a.canonical_bytes());
    assert_eq!(pool.spenders_of(&point(&funds[0])).len(), 1);
    assert_eq!(&pool.spenders_of(&point(&funds[0]))[0][..], b.canonical_bytes().as_slice());
    pool.retain(|_, _| false);
    assert!(!pool.spends_outpoint(&point(&funds[0])));
    assert!(!pool.spends_outpoint(&point(&funds[1])));
    assert!(pool.is_empty());
}
