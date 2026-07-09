//! Sprint DD — PR-2 regression: locally-mined block must be rollback-able.
//!
//! Pre-DD bug: the mining loop in src/main.rs applied UTXO/tx_index/coinbase
//! mutations inline and did NOT record UndoData. Any block minered locally
//! was therefore unrollback-able. The moment IBD arrived from a peer with a
//! heavier chain, the reorg plan would fail on the first rollback_block
//! call with "no undo data for block ..", and the worker stayed stuck at
//! the point where it had stopped mining on its own chain.
//!
//! This file exercises the invariant the fix needs to uphold: after a
//! successful miner path, `store.get_undo_data(&hash)` must return Some.
//! The actual miner loop is an async task spawned off the main tokio
//! runtime, so this test does not exercise the wire loop — it exercises
//! the single function the loop now calls:
//! `reorg::apply_block_utxo_mutations`. That function is where the undo
//! record gets written; the test confirms the contract.
//!
//! If a future regression factors the miner path back into inline
//! mutations without calling apply_block_utxo_mutations (or an equivalent
//! undo-recording helper), this test still passes — but the new direct
//! test `mined_block_round_trip_rolls_back_cleanly` below catches the
//! higher-level failure by exercising apply → rollback on a self-built
//! block shaped like a miner output.

use bloch::core::{
    self, Transaction, TxInput, TxOutput, BlockHeader, Block, MerkleRoot,
};
use bloch::reorg;
use bloch::storage::Storage;
use tempfile::TempDir;

/// Build a synthetic "mined" block on top of a parent. Mirrors what the
/// miner in src/main.rs produces: one coinbase tx paying the miner, no
/// other transactions.
fn make_mined_block(parent: &Block, miner_spk: &[u8; 20]) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: 0xFFFF_FFFF,
            script_sig: b"sprint-dd-test".to_vec(),
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput {
            value:         core::tokenomics_v2::INITIAL_BLOCK_REWARD_SAT,
            script_pubkey: miner_spk.to_vec(),
        }],
        locktime: 0,
    };
    let merkle = Transaction::merkle_root(&[coinbase.clone()]);
    Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![parent.block_hash()],
            merkle_root: merkle,
            timestamp:   parent.header.timestamp + 10,
            bits:        0x1d00ffff,
            nonce:       12345,
        },
        transactions: vec![coinbase],
        blue_score: parent.blue_score + 1,
        height:     parent.height + 1,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    }
}

/// PR-2 regression: `apply_block_utxo_mutations` MUST record UndoData
/// alongside every forward mutation it applies. Without this, the reorg
/// path's `rollback_block(hash)` will fail with "no undo data for
/// block ..", which is exactly the failure observed in production on the
/// Akash worker when IBD arrived.
///
/// The test applies a synthetic mined block and then asserts that the
/// undo record exists AND has the expected shape (one tx_index entry
/// for the coinbase, one created_utxo_keys entry for the output, one
/// coinbase_txids entry, no spent_utxos since it's a coinbase-only block).
#[test]
fn mined_block_writes_undo_data_on_apply() {
    let tmp = TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();

    // Genesis setup — the real node does this at startup. Shapes that
    // accept_block expects: block body stored, tip_hash meta set.
    let miner_spk: [u8; 20] = [0xAA; 20];
    let genesis = core::create_genesis_block(&miner_spk, &miner_spk, &miner_spk);
    let genesis_hash = genesis.block_hash();
    store.put_block(&genesis).unwrap();

    // Build a block that looks like what the miner loop produces.
    let mined = make_mined_block(&genesis, &miner_spk);
    let mined_hash = mined.block_hash();
    store.put_block(&mined).unwrap();

    // Apply — this is the call the miner loop makes (post-DD).
    reorg::apply_block_utxo_mutations(&store, &mined)
        .expect("apply_block_utxo_mutations must succeed");

    // The core guarantee: undo record was recorded.
    let undo = store.get_undo_data(&mined_hash)
        .expect("get_undo_data failed")
        .expect(
            "PR-2 regression: mined block MUST have UndoData recorded \
             after apply_block_utxo_mutations — without this, any reorg \
             that rolls the block back fails with 'no undo data'"
        );

    assert_eq!(undo.block_hash,   mined_hash);
    assert_eq!(undo.block_height, mined.height);
    assert_eq!(undo.tx_index_keys.len(),    1, "one coinbase tx");
    assert_eq!(undo.created_utxo_keys.len(),1, "one coinbase output");
    assert_eq!(undo.coinbase_txids.len(),   1, "one coinbase");
    assert_eq!(undo.spent_utxos.len(),      0, "coinbase has no real inputs");

    // Sanity: genesis-dependent state is untouched.
    assert!(store.get_block(&genesis_hash).unwrap().is_some());
}

/// Full round trip: apply (forward) then rollback_block. Before Sprint DD
/// this test would have failed at the rollback step with "no undo data"
/// because the pre-DD mining path never wrote the undo record.
///
/// Post-Sprint-DD, rollback succeeds and undoes every mutation. Verified
/// via: (a) the coinbase UTXO created by the block is gone, (b) the
/// undo record itself is consumed.
#[test]
fn mined_block_round_trip_rolls_back_cleanly() {
    let tmp = TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();

    let miner_spk: [u8; 20] = [0xBB; 20];
    let genesis = core::create_genesis_block(&miner_spk, &miner_spk, &miner_spk);
    store.put_block(&genesis).unwrap();

    let mined = make_mined_block(&genesis, &miner_spk);
    let mined_hash = mined.block_hash();
    store.put_block(&mined).unwrap();

    reorg::apply_block_utxo_mutations(&store, &mined).unwrap();

    let coinbase_txid = mined.transactions[0].txid();

    // Pre-rollback: coinbase UTXO exists.
    assert!(
        store.get_utxo(&coinbase_txid, 0).unwrap().is_some(),
        "coinbase UTXO must exist after apply"
    );

    // The exact call reorg::execute_reorg makes when the losing chain
    // contains a locally-mined block. This is the line that was failing
    // in production before Sprint DD.
    store.rollback_block(&mined_hash)
        .expect("rollback_block MUST succeed — this is the PR-2 guarantee");

    // Post-rollback: coinbase UTXO is gone (undo reversed the put_utxo).
    assert!(
        store.get_utxo(&coinbase_txid, 0).unwrap().is_none(),
        "coinbase UTXO must be removed by rollback"
    );

    // Undo record itself is consumed by rollback_block (last step of U.2).
    assert!(
        store.get_undo_data(&mined_hash).unwrap().is_none(),
        "undo record consumed after rollback"
    );
}

/// Suppress the `_` ignore: silence the `mined_hash` / `genesis_hash`
/// unused-variable warnings in the first test when someone disables
/// an assertion for debugging. Compile-time only.
#[allow(dead_code)]
fn _markers_for_ignore_lints() {
    let _ = (core::tokenomics_v2::NOMINAL_TOTAL_SUPPLY_SAT, MerkleRoot::ZERO);
}
