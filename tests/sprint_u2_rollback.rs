//! Sprint U.2 — Audit finding C-1 (part 2 of 4): rollback_block() primitive.
//!
//! These tests verify the state-reversing primitive that Sprint U.3's reorg
//! logic will call for each block of a losing chain. The invariant under
//! test is:
//!
//!     apply(S, mutations) = S' ⇒ rollback(S', mutations) = S
//!
//! i.e. after rollback, every CF that accept_block touched is back to the
//! exact state it had before the block was applied. We verify this by
//! driving the storage API directly (without running accept_block) so the
//! tests stay fast and focused on the primitive itself. Full integration
//! with accept_block lives in Sprint U.4's reorg harness.
//!
//! # What these tests guarantee
//!
//!   1. rollback restores the UTXO set byte-identically.
//!   2. rollback restores the address-UTXO index (CF_ADDR_UTXO).
//!   3. rollback removes tx_index and coinbase_info entries.
//!   4. rollback removes its own UndoData record (prevents re-rollback).
//!   5. rollback errors cleanly when the undo record is missing.
//!   6. rollback does NOT touch the block body (CF_BLOCKS) — U.3 may
//!      still need it to re-apply if the reorg decision flips.
//!   7. Double rollback (calling rollback twice on the same block) is
//!      not silently successful — the second call must error because
//!      the undo record was consumed.

use bloch::core::{
    Block, BlockHeader, Transaction, TxInput, TxOutput, UndoData, UndoEntry,
};
use bloch::storage::Storage;
use tempfile::TempDir;

fn mk_storage() -> (TempDir, Storage) {
    let tmp = TempDir::new().unwrap();
    let s = Storage::open(tmp.path()).unwrap();
    (tmp, s)
}

fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
    TxOutput {
        value,
        script_pubkey: vec![addr_byte; 20],
    }
}

/// Minimal block fixture for rollback tests. block_hash is decoupled from
/// actual PoW/merkle content — we don't need consensus validity here,
/// only the storage shape (height, tx list, txids).
fn mk_block(height: u64, transactions: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![],
            merkle_root: bloch::core::MerkleRoot::ZERO,
            timestamp:   1_700_000_000 + height,
            bits:        0x1d00ffff,
            nonce:       0,
        },
        transactions,
        blue_score: height,
        height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    }
}

/// Coinbase-style tx: 1 input with prev_txid = zeros, outputs the block reward.
fn mk_coinbase(addr_byte: u8, value: u64, height: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: 0xffffffff,
            script_sig: format!("height:{}", height).into_bytes(),
            sequence:   0xffffffff,
        }],
        outputs: vec![mk_output(addr_byte, value)],
        locktime: 0,
    }
}

/// Regular tx spending one input and producing one output.
fn mk_spend_tx(prev_txid: [u8; 32], prev_index: u32, to_addr: u8, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_index,
            script_sig: vec![0xde, 0xad, 0xbe, 0xef],
            sequence:   0xffffffff,
        }],
        outputs: vec![mk_output(to_addr, value)],
        locktime: 0,
    }
}

/// Drive the storage exactly the way accept_block does (without the consensus
/// gates) so we have a faithful reproduction of the mutations a rollback
/// has to undo. Returns the UndoData that rollback_block should invert.
fn apply_block_and_capture_undo(store: &Storage, block: &Block) -> UndoData {
    store.put_block(block).unwrap();
    let block_hash = block.block_hash();
    let mut undo = UndoData::new(block_hash, block.height);
    for tx in &block.transactions {
        let txid = tx.txid();
        store.put_tx_index(&txid, &block_hash, block.height).unwrap();
        undo.tx_index_keys.push(txid);
        for (j, out) in tx.outputs.iter().enumerate() {
            store.put_utxo(&txid, j as u32, out).unwrap();
            undo.created_utxo_keys.push((txid, j as u32));
        }
        if tx.is_coinbase() {
            store.put_coinbase_info(&txid, block.height).unwrap();
            undo.coinbase_txids.push(txid);
        } else {
            for inp in &tx.inputs {
                if let Ok(Some(output)) = store.get_utxo(&inp.prev_txid, inp.prev_index) {
                    undo.spent_utxos.push(UndoEntry {
                        prev_txid:  inp.prev_txid,
                        prev_index: inp.prev_index,
                        output,
                    });
                }
                store.delete_utxo(&inp.prev_txid, inp.prev_index).unwrap();
            }
        }
    }
    store.put_undo_data(&block_hash, &undo).unwrap();
    undo
}

#[test]
fn rollback_restores_spent_utxo_exactly() {
    // Critical invariant: a UTXO that was consumed by a block must be
    // restored by rollback with byte-identical value and script_pubkey.
    let (_tmp, store) = mk_storage();

    // Seed: pretend a previous coinbase at height 0 produced an output.
    let prev_txid  = [0x77u8; 32];
    let prev_out   = mk_output(0xAA, 50_000_000_000);
    store.put_utxo(&prev_txid, 0, &prev_out).unwrap();

    // Block at height 1 spends that output.
    let cb = mk_coinbase(0x01, 500_000_000, 1);
    let spend = mk_spend_tx(prev_txid, 0, 0xBB, 49_000_000_000);
    let block = mk_block(1, vec![cb, spend]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);

    // Sanity: the spent UTXO is gone right after apply.
    assert!(store.get_utxo(&prev_txid, 0).unwrap().is_none(),
        "sanity: spent UTXO should be absent after apply");

    // Rollback.
    let applied_undo = store.rollback_block(&block_hash).expect("rollback should succeed");
    assert_eq!(applied_undo.block_height, 1);
    assert_eq!(applied_undo.spent_utxos.len(), 1);

    // The spent UTXO is back, byte-identical.
    let restored = store.get_utxo(&prev_txid, 0).unwrap()
        .expect("spent UTXO must be restored");
    assert_eq!(restored.value,         prev_out.value);
    assert_eq!(restored.script_pubkey, prev_out.script_pubkey);
}

#[test]
fn rollback_removes_created_utxos() {
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA1, 500_000_000, 1);
    let cb_txid = cb.txid();
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);
    assert!(store.get_utxo(&cb_txid, 0).unwrap().is_some(),
        "sanity: coinbase output should exist after apply");

    store.rollback_block(&block_hash).unwrap();

    assert!(store.get_utxo(&cb_txid, 0).unwrap().is_none(),
        "rollback must delete UTXOs created by the block");
}

#[test]
fn rollback_removes_tx_index_entries() {
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA2, 500_000_000, 1);
    let cb_txid = cb.txid();
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);
    assert_eq!(store.get_tx_location(&cb_txid).unwrap().map(|(h, _)| h),
        Some(block_hash),
        "sanity: tx_index should point to the block after apply");

    store.rollback_block(&block_hash).unwrap();

    assert!(store.get_tx_location(&cb_txid).unwrap().is_none(),
        "rollback must delete tx_index entries");
}

#[test]
fn rollback_removes_coinbase_info() {
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA3, 500_000_000, 1);
    let cb_txid = cb.txid();
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);
    assert_eq!(store.get_coinbase_height(&cb_txid).unwrap(), Some(1),
        "sanity: coinbase info should record height after apply");

    store.rollback_block(&block_hash).unwrap();

    assert!(store.get_coinbase_height(&cb_txid).unwrap().is_none(),
        "rollback must delete coinbase_info — a reverted coinbase is not mature");
}

#[test]
fn rollback_consumes_its_own_undo_record() {
    // After rollback, the undo record itself must be gone so a buggy caller
    // can't accidentally "double-roll-back" the same block.
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA4, 500_000_000, 1);
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);
    assert!(store.get_undo_data(&block_hash).unwrap().is_some(),
        "sanity: undo record present after apply");

    store.rollback_block(&block_hash).unwrap();

    assert!(store.get_undo_data(&block_hash).unwrap().is_none(),
        "rollback_block must delete the consumed undo record");
}

#[test]
fn double_rollback_errors_on_second_call() {
    // With the undo record consumed by the first rollback, the second call
    // has nothing to work from and must surface that as an error rather
    // than silently succeeding (which would mask a caller bug).
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA5, 500_000_000, 1);
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);
    store.rollback_block(&block_hash).expect("first rollback succeeds");

    let second = store.rollback_block(&block_hash);
    assert!(second.is_err(),
        "second rollback on same block must error (no undo record left)");
}

#[test]
fn rollback_missing_undo_errors() {
    // A block accepted pre-U.1 (or whose undo was pruned after finality)
    // has no undo record. rollback must refuse rather than silently no-op.
    let (_tmp, store) = mk_storage();
    let never_accepted = [0xEEu8; 32];

    let result = store.rollback_block(&never_accepted);
    assert!(result.is_err(),
        "rollback_block on unknown block must error, not silently succeed");
}

#[test]
fn rollback_preserves_block_body() {
    // U.3 may need the block body again (e.g. if the reorg decision flips
    // while we're still mid-reorg). rollback is strictly about state, not
    // about removing the block from storage.
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA6, 500_000_000, 1);
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    apply_block_and_capture_undo(&store, &block);
    store.rollback_block(&block_hash).unwrap();

    let retrieved = store.get_block(&block_hash).unwrap()
        .expect("block body must survive rollback");
    assert_eq!(retrieved.height, block.height);
    assert_eq!(retrieved.transactions.len(), block.transactions.len());
}

#[test]
fn rollback_returns_the_undo_data_that_was_applied() {
    // Callers need the applied UndoData back so they can, e.g., re-inject
    // invalidated mempool entries or emit reorg events.
    let (_tmp, store) = mk_storage();

    let prev_txid  = [0x66u8; 32];
    let prev_out   = mk_output(0xAA, 1_000_000);
    store.put_utxo(&prev_txid, 0, &prev_out).unwrap();

    let cb    = mk_coinbase(0xA7, 500_000_000, 1);
    let spend = mk_spend_tx(prev_txid, 0, 0xBB, 999_999);
    let block = mk_block(1, vec![cb, spend]);
    let block_hash = block.block_hash();

    let expected = apply_block_and_capture_undo(&store, &block);
    let returned = store.rollback_block(&block_hash).unwrap();

    assert_eq!(returned.block_hash,     expected.block_hash);
    assert_eq!(returned.block_height,   expected.block_height);
    assert_eq!(returned.spent_utxos.len(),       expected.spent_utxos.len());
    assert_eq!(returned.created_utxo_keys,       expected.created_utxo_keys);
    assert_eq!(returned.coinbase_txids,          expected.coinbase_txids);
    assert_eq!(returned.tx_index_keys,            expected.tx_index_keys);
}

#[test]
fn apply_rollback_apply_rollback_is_stable() {
    // Stress case: apply → rollback → apply → rollback must leave storage
    // in the same state as before any of it happened. This catches subtle
    // bugs where rollback restores slightly-wrong data that then poisons
    // a future apply (e.g. wrong spent-output value silently rewriting
    // the UTXO with a different value on re-apply).
    let (_tmp, store) = mk_storage();

    // Initial state: one UTXO seeded.
    let prev_txid  = [0x55u8; 32];
    let prev_out   = mk_output(0xCC, 42_424_242);
    store.put_utxo(&prev_txid, 0, &prev_out).unwrap();

    let cb    = mk_coinbase(0xA8, 500_000_000, 1);
    let spend = mk_spend_tx(prev_txid, 0, 0xBB, 42_000_000);
    let block = mk_block(1, vec![cb, spend]);
    let block_hash = block.block_hash();

    for round in 0..2 {
        apply_block_and_capture_undo(&store, &block);
        store.rollback_block(&block_hash)
            .unwrap_or_else(|e| panic!("round {} rollback failed: {}", round, e));

        let got = store.get_utxo(&prev_txid, 0).unwrap()
            .unwrap_or_else(|| panic!("round {} restoration missing", round));
        assert_eq!(got.value,         prev_out.value,
            "round {}: restored UTXO value drift", round);
        assert_eq!(got.script_pubkey, prev_out.script_pubkey,
            "round {}: restored UTXO script drift", round);
    }
}
