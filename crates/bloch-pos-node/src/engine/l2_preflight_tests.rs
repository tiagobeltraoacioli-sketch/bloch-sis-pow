// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node-local handling of L2 transactions between the mempool door and the
//! proposal (review EXE-1, EXE-2, EXE-3, V2-1), on a real engine: a pending
//! settlement follows the head, a refused transaction does not cost the block
//! the transactions it displaced, and deposits, DA batches and claims are
//! judged against committed state before they are admitted, selected or
//! allowed to hold an input.
use super::l2_async_admission_tests::{engine_with_frozen_source_funded, settlement, wire};
use super::proposal_revalidation_tests::{funds_of, spend};
use super::*;

const S: usize = bloch_pos_committee::l2_settlement::STATEMENT_TAG.len();

fn pending_settlements(node: &Engine) -> usize {
    node.mempool.values().filter(|tx| matches!(tx, PosTransaction::L2SettlementAsync(_))).count()
}

/// EXE-2: a settlement admitted against an earlier head (here: placed in the
/// pool with a statement that is not the successor of this head) is not the
/// proposer's selection, and is evicted when the next head is adopted, so it
/// no longer refuses newer proofs as "already pending".
#[test]
fn a_pending_settlement_the_head_moved_past_is_not_selected_and_is_evicted() {
    let _clock = validator_lifecycle::clock_at(3);
    let funds = funds_of(2);
    let (mut node, _dir) = engine_with_frozen_source_funded(&funds);
    let transfer = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(transfer.clone()), Ok(Admitted::New));

    let mut passed = settlement(&node, [2; 356]);
    passed.statement[S + 264] ^= 1;
    let stale = wire(passed);
    let stale_key = stale.canonical_bytes();
    node.mempool.insert(stale_key.clone(), stale);
    assert_eq!(pending_settlements(&node), 1);

    assert_eq!(node.select_transactions(0), vec![transfer.clone()]);
    node.propose(3);
    assert_eq!(node.state.slot(), 3);
    assert_eq!(node.tx_slot_index.get(&transfer.txid()), Some(&3), "the block carried the transfer");
    assert!(!node.mempool.contains_key(&stale_key), "evicted with the adopted head");
    assert_eq!(pending_settlements(&node), 0);
    assert!(!node.rejected.contains_key(&stale_key), "eviction is retention, never a bar");
}

/// EXE-2 keeps what can still apply: a settlement that matches the head stays
/// pending across the recheck and is the whole selection.
#[test]
fn a_pending_settlement_that_matches_the_head_is_kept_and_selected() {
    let _clock = validator_lifecycle::clock_at(3);
    let (mut node, _dir) = engine_with_frozen_source_funded(&[]);
    let matching = wire(settlement(&node, [2; 356]));
    let key = matching.canonical_bytes();
    node.mempool.insert(key.clone(), matching.clone());
    node.revalidate_lifecycle_mempool();
    assert!(node.mempool.contains_key(&key));
    assert_eq!(node.select_transactions(0), vec![matching]);
}

/// EXE-1 (re-selection): the probe refuses the one transaction that was the
/// whole selection. The proposer drops and bars it, selects again, and the
/// block carries the pending transfer instead of going out empty.
#[test]
fn a_transaction_the_probe_refuses_does_not_cost_the_block_its_transactions() {
    let _clock = validator_lifecycle::clock_at(3);
    let funds = funds_of(2);
    let (mut node, _dir) = engine_with_frozen_source_funded(&funds);
    let transfer = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(transfer.clone()), Ok(Admitted::New));
    // Statement matches the head; the proof does not verify (as if it had
    // reached the pool without admission).
    let unproven = wire(settlement(&node, [2; 356]));
    let key = unproven.canonical_bytes();
    node.mempool.insert(key.clone(), unproven.clone());
    assert_eq!(node.select_transactions(0), vec![unproven]);

    node.propose(3);
    assert_eq!(node.state.slot(), 3, "the block was produced");
    assert_eq!(
        node.tx_slot_index.get(&transfer.txid()),
        Some(&3),
        "the transfer displaced by the refused transaction is in the block",
    );
    assert!(!node.mempool.contains_key(&key));
    assert!(node.rejected.contains_key(&key), "the refused transaction is barred");
}
