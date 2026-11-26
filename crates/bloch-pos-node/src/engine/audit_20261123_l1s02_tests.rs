// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUDIT-L1L2-20261123 L1S-02, node-local half: zero-fee messages get a
//! bounded share of a proposed block, and the mempool takes one credential
//! rotation and one commission update per validator per epoch.
use super::proposal_revalidation_tests::{funds_of, spend};
use super::*;
use bloch_pos_committee::transition::{ValidatorCommissionUpdate, WithdrawalCredentialRotation};

/// Past HF3 and the capacity metering of staking messages, as on mainnet.
const EPOCH: u64 = 9_000;

/// A suite-0x0003 rotation with signatures of the real size. Packing does
/// not verify signatures (admission did), so the bytes are padding.
fn rotation(validator: u32, tag: u8) -> (Vec<u8>, PosTransaction) {
    let key = |t: u8| {
        let mut k = vec![t; bloch_pos_committee::transition::pq_migration::SLH_SUITE_PUBKEY_BYTES];
        k[..4].copy_from_slice(&[0xb1, 0x0c, 0x03, 0x00]);
        k
    };
    let tx = PosTransaction::WithdrawalCredentialRotation(WithdrawalCredentialRotation {
        network_domain: [0x91; 32],
        epoch: EPOCH,
        validator,
        authorizing_pubkey: key(tag),
        new_pubkey: key(tag.wrapping_add(1)),
        authorizing_signature: vec![0x5a; 4 + 7_856 + 1_280],
        new_key_signature: vec![0x5a; 4 + 7_856 + 1_280],
    });
    (tx.canonical_bytes(), tx)
}

fn pack(txs: &[(Vec<u8>, PosTransaction)]) -> Vec<PosTransaction> {
    Engine::pack_transactions_on(EPOCH, [0; 32], txs.iter().map(|(k, tx)| (k, tx)).collect(), None)
}

fn usage(txs: &[PosTransaction]) -> (u64, u64) {
    txs.iter().fold((0, 0), |(gas, bytes), tx| {
        let charge = bloch_pos_committee::CommittedState::zero_fee_capacity(EPOCH, tx).expect("zero-fee");
        (gas + charge.gas, bytes + charge.tx_bytes)
    })
}

/// The finding's body: 23 free rotations filled a block (57M of 60M gas,
/// 506 kB of 512 kB) and every such block raised the base fee. The proposer
/// now packs what fits the free share: the block stays far below target.
#[test]
fn free_rotations_take_a_bounded_share_of_a_proposed_block() {
    let flood: Vec<(Vec<u8>, PosTransaction)> = (0..23).map(|v| rotation(v, 0x31)).collect();
    let one = usage(std::slice::from_ref(&flood[0].1));
    assert_eq!(one, (2_492_204, 21_999), "the measured weight of one rotation");
    let packed = pack(&flood);
    let (gas, bytes) = usage(&packed);
    assert_eq!(packed.len(), 1);
    assert!(gas <= fee_market::BLOCK_GAS_TARGET / 10 && bytes <= fee_market::block_tx_bytes_target(EPOCH) / 10);
    // Such a block lowers the price (or holds the floor): it never raises it.
    let parent = fee_market::BlockUsage { gas_used: gas, tx_bytes: bytes };
    assert!(fee_market::next_base_fee(1_000_000, parent, EPOCH) < 1_000_000);
}

/// One free message always fits, whatever its size, so nothing is
/// unpackable; and a repeatable free message is never what takes a block
/// above its byte target.
#[test]
fn a_free_message_is_never_unpackable_and_never_lifts_the_block_above_target() {
    let target = fee_market::block_tx_bytes_target(EPOCH);
    let funds = funds_of(1);
    let paying = |declared: u64| {
        let tx = spend(&funds[0], declared, 5, 10);
        (tx.canonical_bytes(), tx)
    };
    let free = rotation(0, 0x31);
    // Room below target: packed after the paying transfer.
    let roomy = paying(target - 30_000);
    assert_eq!(pack(&[roomy.clone(), free.clone()]), vec![roomy.1.clone(), free.1.clone()]);
    // The rotation would cross the target: left for a later block.
    let tight = paying(target - 10_000);
    assert_eq!(pack(&[tight.clone(), free.clone()]), vec![tight.1.clone()]);
    // A one-shot free message (an exit) is not held back by the target.
    let exit = PosTransaction::Withdraw { validator: 3 };
    let exit = (exit.canonical_bytes(), exit);
    assert_eq!(pack(&[tight.clone(), exit.clone()]), vec![tight.1.clone(), exit.1.clone()]);
}

fn commission(node: &Engine, epoch: u64, bps: u128) -> PosTransaction {
    PosTransaction::ValidatorCommissionUpdate(ValidatorCommissionUpdate {
        network_domain: node.state.admission_network_domain().unwrap_or([0; 32]),
        epoch,
        validator: 0,
        commission_bps: bps,
        signature: vec![1; 64],
    })
}

/// The pool's once-per-epoch record: keyed by kind and validator, set by an
/// admission or by a canonical block, and a repeat is refused before any
/// signature work with a retryable, non-barring refusal.
#[test]
fn the_pool_takes_one_rotation_and_one_commission_update_per_validator_per_epoch() {
    let (rot_key, rot_epoch) = once_per_epoch_key(&rotation(7, 0x31).1).unwrap();
    assert_eq!((rot_key, rot_epoch), ((0, 7), EPOCH));
    let mut pool = admission::Mempool::default();
    assert!(!pool.once_per_epoch_seen(rot_key, EPOCH));
    pool.note_once_per_epoch(rot_key, EPOCH);
    assert!(pool.once_per_epoch_seen(rot_key, EPOCH));
    assert!(!pool.once_per_epoch_seen(rot_key, EPOCH + 1), "the next epoch is open again");
    assert!(!pool.once_per_epoch_seen((1, 7), EPOCH), "a commission update is counted apart");
    assert!(!pool.once_per_epoch_seen((0, 8), EPOCH), "and so is another validator");
    pool.note_once_per_epoch(rot_key, EPOCH - 1);
    assert!(pool.once_per_epoch_seen(rot_key, EPOCH), "an older message does not reopen the epoch");

    // On a real engine: an update seen in a canonical block closes the epoch
    // for that validator at the mempool door.
    let (mut node, _dir) = perf_support::proposing_engine();
    // Wall clock past the funded-delegation flag day, so the door's own
    // "not active yet" refusal is not what answers.
    let epoch = 4_700u64;
    let _clock = validator_lifecycle::clock_at(epoch * SLOTS_PER_EPOCH + 1);
    let included = commission(&node, epoch, 500);
    let repeat = commission(&node, epoch, 700);
    let lane = node.gossip_verifier.lane_used_at(node.wall_slot(), verification::VerificationLane::Relay);
    const ONCE: &str = ONCE_PER_EPOCH_REFUSAL;
    // Before anything is recorded the door gets past the rule (and refuses
    // this unsigned fixture message for another reason).
    assert!(!matches!(node.on_transaction(repeat.clone()), Err(Refusal::StateDependent(ONCE))));
    node.note_tx_slots(1, std::slice::from_ref(&included));
    assert!(matches!(node.on_transaction(repeat), Err(Refusal::StateDependent(ONCE))));
    assert!(node.mempool.is_empty());
    assert_eq!(
        node.gossip_verifier.lane_used_at(node.wall_slot(), verification::VerificationLane::Relay),
        lane,
        "refused before any signature verification",
    );
    // The same validator's update for the next epoch is not held by it.
    assert!(!matches!(node.on_transaction(commission(&node, epoch + 1, 700)), Err(Refusal::StateDependent(ONCE))));
}

/// Review of b8f1b91d, the order: the rule is a lookup answered before any
/// signature of the newcomer is verified, for both kinds, and its refusal
/// is not charged to the source that delivered the repeat (after the merge
/// with L1N-02 it sat behind the verification and was charged like a
/// failure).
#[test]
fn a_repeat_is_refused_before_any_signature_and_costs_its_relay_nothing() {
    let (mut node, _dir) = perf_support::proposing_engine();
    let _clock = validator_lifecycle::clock_at(EPOCH * SLOTS_PER_EPOCH + 1);
    let source = [0x77u8; 32];
    let relay = verification::VerificationLane::Relay;
    let slot = node.wall_slot();
    let used = |node: &Engine| (
        node.gossip_verifier.lane_used_at(slot, relay),
        node.gossip_verifier.source_failures_at(slot, relay, source),
    );
    for (kind, tx) in [(0u8, rotation(7, 0x31).1), (1u8, commission(&node, EPOCH, 700))] {
        let (once, epoch) = once_per_epoch_key(&tx).unwrap();
        assert_eq!((once.0, epoch), (kind, EPOCH));
        // Not recorded: the door gets past the rule (these fixture messages
        // are then refused for their signatures or their state).
        assert!(!matches!(node.on_transaction_from(tx.clone(), Some(source)), Err(Refusal::StateDependent(ONCE_PER_EPOCH_REFUSAL))));
        let spent = used(&node);
        node.mempool.note_once_per_epoch(once, epoch);
        assert!(matches!(node.on_transaction_from(tx, Some(source)), Err(Refusal::StateDependent(ONCE_PER_EPOCH_REFUSAL))));
        assert_eq!(used(&node), spent, "kind {kind}: the repeat verified nothing and charged its relay nothing");
        node.mempool.release_once_per_epoch(once, epoch);
    }
    assert!(node.mempool.is_empty());
    // The rule sits in the door itself, ahead of the first verifier.
    let source_text = include_str!("../engine.rs");
    let door = source_text.find("    fn admit_transaction<R>(").expect("the admission door");
    let rule = door + source_text[door..].find("return Err(Refusal::StateDependent(ONCE_PER_EPOCH_REFUSAL));").expect("the rule");
    let first_verifier = door + source_text[door..].find("self.gossip_verifier.budgeted_for_source(").expect("the first verifier");
    assert!(rule < first_verifier, "the once-per-epoch lookup must precede every signature verification");
    assert_eq!(source_text.matches("Refusal::StateDependent(ONCE_PER_EPOCH_REFUSAL)").count(), 1, "one place decides it");
}

/// Review of b8f1b91d, the reorg: a rotation or commission update whose
/// block leaves canonical history no longer holds its validator's epoch.
/// The signer can submit it again in the same epoch; a pending message of
/// this pool, a newer epoch's record and other validators are untouched.
#[test]
fn a_reorged_out_message_releases_its_once_per_epoch_mark() {
    let (mut node, _dir) = perf_support::proposing_engine();
    let epoch = 4_700u64;
    let _clock = validator_lifecycle::clock_at(epoch * SLOTS_PER_EPOCH + 1);
    let included = commission(&node, epoch, 500);
    let (once, _) = once_per_epoch_key(&included).unwrap();
    let refused = |node: &mut Engine, bps: u128| {
        let tx = commission(node, epoch, bps);
        matches!(node.on_transaction(tx), Err(Refusal::StateDependent(ONCE_PER_EPOCH_REFUSAL)))
    };
    // Included in a canonical block: the epoch is used.
    node.note_tx_slots(40, std::slice::from_ref(&included));
    assert!(refused(&mut node, 700));
    // The block is reorganised out and the winning branch does not carry
    // the message: the epoch is open again.
    node.release_once_per_epoch_marks(std::slice::from_ref(&included));
    assert!(!node.mempool.once_per_epoch_seen(once, epoch));
    assert!(!refused(&mut node, 700));
    // The winning branch carries it again: marked again (the reorg notes
    // the adopted blocks after releasing the losing ones).
    node.note_tx_slots(41, std::slice::from_ref(&included));
    assert!(refused(&mut node, 700));
    // A record of a newer epoch is not released by an older block leaving.
    node.mempool.note_once_per_epoch(once, epoch + 1);
    node.release_once_per_epoch_marks(std::slice::from_ref(&included));
    assert!(node.mempool.once_per_epoch_seen(once, epoch + 1));
    node.mempool.release_once_per_epoch(once, epoch + 1);
    // A message of the same validator and epoch still pending in this pool
    // keeps the mark: the pool already holds this epoch's one message.
    node.mempool.note_once_per_epoch(once, epoch);
    let pending = commission(&node, epoch, 900);
    node.mempool.insert(pending.canonical_bytes(), pending);
    node.release_once_per_epoch_marks(std::slice::from_ref(&included));
    assert!(node.mempool.once_per_epoch_seen(once, epoch), "the pending message accounts for the mark");
    // Another validator's message leaving does not touch this one.
    let (other, other_tx) = (once_per_epoch_key(&rotation(7, 0x31).1).unwrap(), rotation(7, 0x31).1);
    node.mempool.note_once_per_epoch(other.0, other.1);
    node.release_once_per_epoch_marks(std::slice::from_ref(&other_tx));
    assert!(!node.mempool.once_per_epoch_seen(other.0, other.1));
    assert!(node.mempool.once_per_epoch_seen(once, epoch));

    // As wired: `do_reorg` releases the losing tail's marks after dropping
    // its index entries and before it notes the winning branch.
    let source_text = include_str!("../engine.rs");
    let reorg = source_text.find("    fn do_reorg(").expect("do_reorg");
    let body = &source_text[reorg..];
    let forget = body.find("self.forget_tx_slots_if_stale(slot, &txs);").expect("losing tail forgotten");
    let release = body.find("self.release_once_per_epoch_marks(&txs);").expect("losing tail's marks released");
    let adopt = body.find("for (slot, txs) in included_txs {").expect("winning branch noted");
    assert!(forget < release && release < adopt, "release the losing marks before the winning branch is noted");
}
