// SPDX-License-Identifier: AGPL-3.0-or-later
//! Proposal-time checks use real funded, signed transfers and applied blocks.
use super::*;
use bloch_pos_committee::state_root::EutxoEntry;
use bloch_pos_committee::transition::{TransferInput, TransferOutput};

fn funds() -> Vec<EutxoEntry> {
    let (pk, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[71; 32]).unwrap();
    let script_hash: [u8; 32] = Sha3_256::digest(pk).into();
    (0..3).map(|vout| EutxoEntry { txid: [72; 32], vout, value: 1_000_000_000, script_hash }).collect()
}

fn spend(entry: &EutxoEntry, declared: u64, tip: u128, base: u128) -> PosTransaction {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[71; 32]).unwrap();
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, declared, base, tip);
    let fee: u64 = charge.base_fee_sat.checked_add(charge.priority_fee_sat).unwrap().try_into().unwrap();
    let mut tx = PosTransaction::Transfer {
        inputs: vec![TransferInput { txid: entry.txid, vout: entry.vout, pubkey: pk, signature: Vec::new() }],
        outputs: vec![TransferOutput { value: entry.value.checked_sub(fee).unwrap(), script_hash: entry.script_hash }],
        tx_bytes: declared,
        tip_millisat_per_gas: tip,
    };
    let signature = bloch_crypto::crypto::sign(&sk, &tx.spend_signing_root()).unwrap();
    if let PosTransaction::Transfer { inputs, .. } = &mut tx { inputs[0].signature = signature; }
    tx
}

#[test]
fn proposal_revalidation_tracks_fee_increase_and_retry_after_fee_falls() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds();
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let initial_fee = node.state.next_base_fee_at(0);
    let stale = spend(&funds[1], 9_000, 0, initial_fee);
    assert_eq!(node.on_transaction(stale.clone()), Ok(Admitted::New));
    let key = stale.canonical_bytes();
    // A consensus-valid full block raises the next price. This deliberately
    // bypasses wallet declaration-slack policy to exercise exact block usage.
    let filler = spend(&funds[0], fee_market::max_block_tx_bytes(0), 1, initial_fee);
    node.mempool.insert(filler.canonical_bytes(), filler);
    node.propose(1);
    assert_eq!(node.state.slot(), 1);
    let raised = node.state.next_base_fee_at(0);
    assert!(raised > initial_fee);
    assert!(node.mempool.contains_key(&key));
    // The activation epoch changes the byte target. Price from the proposed
    // epoch, not the parent's epoch, exactly as consensus does at a boundary.
    let activation = bloch_pos_committee::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;
    assert_eq!(node.state.next_base_fee_at(activation), initial_fee);
    assert_eq!(node.select_transactions(activation), vec![stale.clone()]);
    let fresh = spend(&funds[2], 9_000, 0, raised);
    assert_eq!(node.on_transaction(fresh.clone()), Ok(Admitted::New));
    assert_eq!(node.select_transactions(0), vec![fresh]);
    assert!(!node.rejected.contains_key(&key), "a changed fee is not a permanent transaction fault");
    node.propose(2);
    assert_eq!(node.state.slot(), 2, "the stale transaction must not poison the next proposal");
    assert_eq!(node.state.next_base_fee_at(0), initial_fee);
    assert_eq!(node.select_transactions(0), vec![stale], "the same signed bytes become eligible again");
}

#[test]
fn proposal_revalidation_packs_independent_spends_after_higher_tip_conflicts() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds();
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    let low = spend(&funds[0], 9_000, 0, fee);
    let high = spend(&funds[0], 9_000, 2, fee);
    let independent = spend(&funds[1], 9_000, 0, fee);
    for tx in [&low, &high, &independent] { assert_eq!(node.on_transaction(tx.clone()), Ok(Admitted::New)); }
    assert_eq!(node.select_transactions(0), vec![high, independent]);
    let low_key = low.canonical_bytes();
    assert!(node.mempool.contains_key(&low_key));
    node.propose(1);
    assert_eq!(node.state.slot(), 1);
    assert!(node.state.utxo(&funds[0].txid, funds[0].vout).is_none());
    assert!(node.state.utxo(&funds[1].txid, funds[1].vout).is_none());
    assert!(node.select_transactions(0).is_empty(), "a now-spent input must be rechecked before packing");
    assert!(!node.rejected.contains_key(&low_key), "selection conflicts must not mint rejection bars");
}
