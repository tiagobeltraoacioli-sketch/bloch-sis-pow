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

/// A real fee rise leaves an admitted high-tip transaction temporarily stale.
fn stale_pool() -> (Engine, perf_support::TestDir, Vec<EutxoEntry>, PosTransaction) {
    let funds = funds();
    let (mut node, dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    let stale = spend(&funds[1], 9_000, 100, fee);
    assert_eq!(node.on_transaction(stale.clone()), Ok(Admitted::New));
    let filler = spend(&funds[0], fee_market::max_block_tx_bytes(0), 101, fee);
    node.mempool.insert(filler.canonical_bytes(), filler);
    node.propose(1);
    assert_eq!(node.state.slot(), 1);
    assert!(node.state.next_base_fee_at(0) > fee);
    (node, dir, funds, stale)
}

#[test]
fn capacity_revalidation_reclaims_stale_high_tips_before_count_eviction() {
    let _clock = validator_lifecycle::clock_at(1);
    let (mut node, _dir, funds, stale) = stale_pool();
    // Zero-tip placeholders isolate capacity accounting; the stale spend above
    // entered through real authenticated admission before a real fee rise.
    for validator in 1..MEMPOOL_MAX as u32 {
        let placeholder = PosTransaction::Exit { validator };
        node.mempool.insert(placeholder.canonical_bytes(), placeholder);
    }
    assert_eq!(node.mempool.len(), MEMPOOL_MAX);
    let incoming = spend(&funds[2], 9_000, 0, node.state.next_base_fee_at(0));
    let before = node.mempool.bytes();
    let mut forged = incoming.clone();
    if let PosTransaction::Transfer { inputs, .. } = &mut forged { inputs[0].signature[0] ^= 1; }
    assert!(matches!(node.on_transaction(forged), Err(Refusal::Invalid(_))));
    assert_eq!(node.mempool.len(), MEMPOOL_MAX);
    assert_eq!(node.mempool.bytes(), before, "failed authentication must not commit cleanup");
    assert!(node.mempool.contains_key(&stale.canonical_bytes()));
    assert_eq!(node.on_transaction(incoming.clone()), Ok(Admitted::New));
    assert_eq!(node.mempool.len(), MEMPOOL_MAX);
    assert!(!node.mempool.contains_key(&stale.canonical_bytes()));
    assert!(node.mempool.contains_key(&incoming.canonical_bytes()));
    assert!(!node.rejected.contains_key(&stale.canonical_bytes()));
    assert!(!node.mempool_admitted_at.contains_key(&stale.canonical_bytes()));
    assert_eq!(node.mempool_evicted_low_fee, 0, "stale retention cleanup is not paid-fee replacement");
    let equally_priced = spend(&funds[2], 9_001, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(equally_priced), Err(Refusal::AtCapacity),
        "once stale entries are gone, equal-fee arrivals still cannot evict current payers");
}

#[test]
fn capacity_revalidation_reclaims_stale_bytes_without_a_rejection_bar() {
    let _clock = validator_lifecycle::clock_at(1);
    let (mut node, _dir, funds, stale) = stale_pool();
    let incoming = spend(&funds[2], 9_000, 0, node.state.next_base_fee_at(0));
    let reserved = stale.canonical_bytes().len().max(incoming.canonical_bytes().len());
    node.mempool.insert(vec![0; admission::MAX_MEMPOOL_BYTES - reserved], PosTransaction::Exit { validator: 9 });
    assert!(node.mempool.bytes() + incoming.canonical_bytes().len() > admission::MAX_MEMPOOL_BYTES);
    assert_eq!(node.on_transaction(incoming), Ok(Admitted::New));
    assert!(node.mempool.bytes() <= admission::MAX_MEMPOOL_BYTES);
    assert!(!node.mempool.contains_key(&stale.canonical_bytes()));
    assert!(!node.rejected.contains_key(&stale.canonical_bytes()));
}

#[test]
fn capacity_revalidation_reclaims_stale_source_slots_for_a_valid_same_owner() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds();
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let fee = node.state.next_base_fee_at(0);
    for tip in 1..=MEMPOOL_MAX_PER_SOURCE as u128 {
        assert_eq!(node.on_transaction(spend(&funds[1], 9_000, tip, fee)), Ok(Admitted::New));
    }
    let filler = spend(&funds[0], fee_market::max_block_tx_bytes(0), 101, fee);
    node.mempool.insert(filler.canonical_bytes(), filler);
    node.propose(1);
    assert_eq!(node.mempool.len(), MEMPOOL_MAX_PER_SOURCE);
    let incoming = spend(&funds[2], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(incoming.clone()), Ok(Admitted::New));
    assert_eq!(node.mempool.len(), MEMPOOL_MAX_PER_SOURCE);
    assert_eq!(node.mempool.source_count(&tx_source_hash(&incoming).unwrap()), MEMPOOL_MAX_PER_SOURCE);
    assert!(node.rejected.is_empty());
}

#[test]
fn transaction_finality_uses_named_checkpoint_not_its_epoch() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds();
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let tx = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(tx.clone()), Ok(Admitted::New));
    node.propose(1);
    assert_eq!(node.state.slot(), 1);
    assert_eq!(node.state.finality().finalized.epoch, 0);
    assert_eq!(node.tx_status(&tx.txid()), "included", "genesis finality does not cover its descendants");
    assert_eq!(node.finality_of(1, true), Finality::Canonical);

    // Real votes advance real checkpoints. Pin both sides of each checkpoint
    // using existing canonical slots, including the first block of its epoch.
    for slot in 2..=(4 * SLOTS_PER_EPOCH) {
        node.attest(slot);
        node.propose(slot);
        if node.state.finality().finalized.epoch >= 1 { break; }
    }
    let fin = node.state.finality();
    assert!(fin.finalized.epoch >= 1);
    let finalized_slot = node.slot_of_canonical_root(&fin.finalized.root).unwrap();
    assert!(finalized_slot >= 1);
    assert_eq!(node.tx_status(&tx.txid()), "finalized");
    // These synthetic index entries isolate reporting at real canonical block
    // boundaries; no finality state or checkpoint root is injected.
    let checkpoint_tx = PosTransaction::Exit { validator: 991 };
    let after_checkpoint_tx = PosTransaction::Exit { validator: 992 };
    let after_justified_tx = PosTransaction::Exit { validator: 993 };
    let justified_slot = node.slot_of_canonical_root(&fin.justified.root).unwrap();
    assert!(justified_slot > finalized_slot);
    node.note_tx_slots(finalized_slot, std::slice::from_ref(&checkpoint_tx));
    node.note_tx_slots(finalized_slot + 1, std::slice::from_ref(&after_checkpoint_tx));
    node.note_tx_slots(justified_slot + 1, std::slice::from_ref(&after_justified_tx));
    assert_eq!(node.tx_status(&checkpoint_tx.txid()), "finalized");
    assert_eq!(node.tx_status(&after_checkpoint_tx.txid()), "justified");
    assert_eq!(node.tx_status(&after_justified_tx.txid()), "included");
}

#[test]
fn failed_reorg_does_not_publish_candidate_transaction_inclusions() {
    let _clock = validator_lifecycle::clock_at(1);
    let funds = funds();
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds);
    let genesis = *node.head_id().as_bytes();
    let tx = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(tx.clone()), Ok(Admitted::New));
    node.propose(1);
    let first = node.blocks.get(node.head_id().as_bytes()).unwrap().clone();
    assert_eq!(first.body.transactions, vec![tx.canonical_bytes()]);
    node.propose(2);
    let mut invalid_second = node.blocks.get(node.head_id().as_bytes()).unwrap().clone();
    invalid_second.header.state_root = [0xff; 32];
    invalid_second.proposer_sig = node.keys.as_ref().unwrap().sign(&invalid_second.header.proposal_signing_root());
    assert!(node.do_reorg(genesis, Vec::new()));
    assert_eq!(node.tx_status(&tx.txid()), "unknown");
    let before_index = node.tx_slot_index.clone();
    let before_order = node.tx_slot_index_order.clone();
    let before_state = (*node.state).clone();
    assert!(!node.do_reorg(genesis, vec![first.clone(), invalid_second]));
    assert_eq!(*node.state, before_state);
    assert_eq!(*node.head_id().as_bytes(), genesis);
    assert_eq!(node.tx_slot_index, before_index);
    assert_eq!(node.tx_slot_index_order, before_order);
    assert_eq!(node.tx_status(&tx.txid()), "unknown");
    assert_eq!(node.on_transaction(tx.clone()), Ok(Admitted::New), "a rejected branch must not manufacture Duplicate");
    assert!(node.do_reorg(genesis, vec![first]));
    assert_eq!(node.tx_slot_index.get(&tx.txid()), Some(&1));
    assert_eq!(node.tx_slot_index_order.iter().filter(|id| **id == tx.txid()).count(), 1,
        "an old FIFO identity must not later evict the re-included transaction");
    assert_eq!(node.tx_status(&tx.txid()), "included");
}

#[test]
fn admission_negative_cache_retries_corrected_transfer_signature_root_and_key() {
    use bloch_pos_committee::transition::{TransferInputV2, WitnessKey};
    let funds = funds();
    let original = spend(&funds[0], 9_000, 0, 1);
    let PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } = original.clone() else { unreachable!() };
    let mut v2 = PosTransaction::TransferV2 {
        keys: vec![WitnessKey { pubkey: inputs[0].pubkey.clone(), signature: Vec::new() }],
        inputs: vec![TransferInputV2 { txid: inputs[0].txid, vout: inputs[0].vout, key_index: 0 }],
        outputs, tx_bytes, tip_millisat_per_gas,
    };
    let (_, secret) = bloch_crypto::crypto::generate_keypair_from_seed(&[71; 32]).unwrap();
    let v2_signature = bloch_crypto::crypto::sign(&secret, &v2.spend_signing_root()).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut v2 { keys[0].signature = v2_signature; }
    let activation = bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH;
    let set_signature = |tx: &mut PosTransaction, signature: Vec<u8>| match tx {
        PosTransaction::Transfer { inputs, .. } => inputs[0].signature = signature,
        PosTransaction::TransferV2 { keys, .. } => keys[0].signature = signature,
        _ => unreachable!(),
    };
    for valid in [original, v2] {
        let (verifier, calls) = verification::counted_hybrid();
        let mut forged = valid.clone();
        set_signature(&mut forged, vec![0; 4_700]);
        for _ in 0..16 { assert!(admissible_with_verifier(&forged, activation, &verifier).is_err()); }
        assert_eq!(calls.get(), 1, "an identical immutable failure must skip repeated cryptography");
        assert!(admissible_with_verifier(&valid, activation, &verifier).is_ok());
        assert_eq!(calls.get(), 2);
        let mut changed = valid.clone();
        match &mut changed {
            PosTransaction::Transfer { outputs, .. } | PosTransaction::TransferV2 { outputs, .. } => outputs[0].value -= 1,
            _ => unreachable!(),
        }
        assert!(admissible_with_verifier(&changed, activation, &verifier).is_err());
        assert_eq!(calls.get(), 3, "a changed signing root must be checked independently");
        let signature = bloch_crypto::crypto::sign(&secret, &changed.spend_signing_root()).unwrap();
        set_signature(&mut changed, signature);
        assert!(admissible_with_verifier(&changed, activation, &verifier).is_ok());
        let (new_key, new_secret) = bloch_crypto::crypto::generate_keypair_from_seed(&[73; 32]).unwrap();
        match &mut changed {
            PosTransaction::Transfer { inputs, .. } => inputs[0].pubkey = new_key,
            PosTransaction::TransferV2 { keys, .. } => keys[0].pubkey = new_key,
            _ => unreachable!(),
        }
        assert!(admissible_with_verifier(&changed, activation, &verifier).is_err());
        assert_eq!(calls.get(), 5, "a new public key must not inherit another key's cache result");
        let signature = bloch_crypto::crypto::sign(&new_secret, &changed.spend_signing_root()).unwrap();
        set_signature(&mut changed, signature);
        assert!(admissible_with_verifier(&changed, activation, &verifier).is_ok());
        assert_eq!(calls.get(), 6);
        assert_eq!(admissible(&changed, activation), admissible_with_verifier(&changed, activation, &verifier));
    }
}

#[test]
fn canonical_lookups_preserve_gaps_forks_reorgs_and_missing_envelope_fallback() {
    let _clock = validator_lifecycle::clock_at(1);
    let (mut node, _dir) = perf_support::proposing_engine_funded(&funds());
    let genesis = *node.head_id().as_bytes();
    assert_eq!(node.height_of(&genesis), Some(0));
    assert_eq!(node.slot_of_canonical_root(&genesis), Some(0));
    assert!(node.serve_rpc(RpcRequest::BlockBySlot(0)).is_ok());
    node.propose(1);
    let first = node.blocks[node.head_id().as_bytes()].clone();
    let first_id = *first.block_id().as_bytes();
    node.propose(3);
    let last = node.blocks[node.head_id().as_bytes()].clone();
    let last_id = *last.block_id().as_bytes();
    assert_eq!(node.serve_rpc(RpcRequest::BlockBySlot(2)).unwrap_err().code, rpc::SLOT_EMPTY);
    assert!(node.serve_rpc(RpcRequest::BlockBySlot(3)).is_ok());
    assert_eq!(node.height_of(&first_id), Some(1));
    assert_eq!(node.height_of(&last_id), Some(2));
    assert_eq!(node.slot_of_canonical_root(&last_id), Some(3));
    // A stored same-slot envelope is not a canonical identity. Its validity
    // is irrelevant to lookup; it must not inherit the canonical slot's height.
    let mut other = first.clone();
    other.header.state_root = [211; 32];
    let other_id = *other.block_id().as_bytes();
    node.blocks.insert(other_id, other);
    assert_eq!(node.height_of(&other_id), None);
    assert_eq!(node.slot_of_canonical_root(&other_id), None);
    assert_eq!(node.height_of(&[212; 32]), None);
    let saved = node.blocks.remove(&first_id).unwrap();
    assert_eq!(node.height_of(&first_id), Some(1));
    assert_eq!(node.slot_of_canonical_root(&first_id), Some(1));
    node.blocks.insert(first_id, saved);
    assert!(node.do_reorg(genesis, Vec::new()));
    assert_eq!(node.height_of(&first_id), None);
    assert_eq!(node.height_of(&last_id), None);
    assert!(node.do_reorg(genesis, vec![first, last]));
    for (height, (slot, id)) in node.chain.iter().enumerate() {
        assert_eq!(node.height_of(id.as_bytes()), Some(height as u64));
        assert_eq!(node.slot_of_canonical_root(id.as_bytes()), Some(*slot));
    }
    assert_eq!(node.height_of(&other_id), None);
}
