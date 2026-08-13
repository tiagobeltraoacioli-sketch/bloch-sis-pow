//! Sprint U.1 — Audit finding C-1 (part 1 of 4): persistence layer for
//! reorg undo data.
//!
//! These tests cover the new `UndoData` / `UndoEntry` types and their
//! storage round-trip. They intentionally do NOT drive accept_block —
//! the full integration test where an accepted block produces a correct
//! UndoData record lives alongside Sprint U.2's rollback_block() primitive,
//! because that's the first sub-sprint where we can actually verify the
//! undo record by replaying it.
//!
//! # What these tests guarantee
//!
//! 1. `UndoData` round-trips through RocksDB byte-identically (bincode +
//!    serde behave as expected for the new struct).
//! 2. Missing records return `Ok(None)` rather than erroring — this matters
//!    because pre-U.1 blocks on disk have no undo record and rollback must
//!    handle that gracefully.
//! 3. `delete_undo_data` actually removes the record (needed for U.3's
//!    finality-window pruning).
//! 4. The `mutation_count()` helper stays consistent with the four vectors
//!    it aggregates — a lightweight invariant that the rollback code can
//!    rely on for sanity checks without deserializing the full record.

use bloch::core::{TxOutput, UndoData, UndoEntry};
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

/// Build an UndoData with deterministic, non-trivial contents covering
/// every field. Used as the shared fixture for round-trip / delete tests.
fn mk_undo_fixture(block_hash: [u8; 32], height: u64) -> UndoData {
    let mut undo = UndoData::new(block_hash, height);

    // Two spent UTXOs (different prev_txids, different indices, different values)
    undo.spent_utxos.push(UndoEntry {
        prev_txid:  [0x11u8; 32],
        prev_index: 0,
        output:     mk_output(0xA1, 50_000_000),
    });
    undo.spent_utxos.push(UndoEntry {
        prev_txid:  [0x22u8; 32],
        prev_index: 7,
        output:     mk_output(0xA2, 123_456_789),
    });

    // Three newly created UTXOs
    undo.created_utxo_keys.push(([0x33u8; 32], 0));
    undo.created_utxo_keys.push(([0x33u8; 32], 1));
    undo.created_utxo_keys.push(([0x44u8; 32], 0));

    // One coinbase this block introduced
    undo.coinbase_txids.push([0x33u8; 32]);

    // tx_index entries: one per tx in the block (2 txs → 2 entries)
    undo.tx_index_keys.push([0x33u8; 32]);
    undo.tx_index_keys.push([0x44u8; 32]);

    undo
}

#[test]
fn undo_data_default_is_empty() {
    let u = UndoData::default();
    assert_eq!(u.block_hash, [0u8; 32]);
    assert_eq!(u.block_height, 0);
    assert!(u.spent_utxos.is_empty());
    assert!(u.created_utxo_keys.is_empty());
    assert!(u.coinbase_txids.is_empty());
    assert!(u.tx_index_keys.is_empty());
    assert_eq!(u.mutation_count(), 0);
}

#[test]
fn undo_data_new_preserves_identity_fields() {
    let hash = [0xAAu8; 32];
    let u = UndoData::new(hash, 12_345);
    assert_eq!(u.block_hash, hash);
    assert_eq!(u.block_height, 12_345);
    assert_eq!(u.mutation_count(), 0);
}

#[test]
fn mutation_count_sums_all_four_vectors() {
    let u = mk_undo_fixture([0xBBu8; 32], 1);
    // Fixture: 2 spent + 3 created + 1 coinbase + 2 tx_index = 8 mutations
    assert_eq!(u.mutation_count(), 2 + 3 + 1 + 2);
    assert_eq!(u.spent_utxos.len(),       2);
    assert_eq!(u.created_utxo_keys.len(), 3);
    assert_eq!(u.coinbase_txids.len(),    1);
    assert_eq!(u.tx_index_keys.len(),     2);
}

#[test]
fn put_then_get_returns_byte_identical_record() {
    let (_tmp, store) = mk_storage();
    let hash = [0xCCu8; 32];
    let original = mk_undo_fixture(hash, 42);

    store.put_undo_data(&hash, &original).expect("put must succeed");
    let got = store.get_undo_data(&hash).expect("get must succeed")
        .expect("record must be present after put");

    // Every field must survive the bincode round-trip unchanged.
    assert_eq!(got.block_hash,        original.block_hash);
    assert_eq!(got.block_height,      original.block_height);
    assert_eq!(got.spent_utxos.len(), original.spent_utxos.len());
    for (g, o) in got.spent_utxos.iter().zip(original.spent_utxos.iter()) {
        assert_eq!(g.prev_txid,             o.prev_txid);
        assert_eq!(g.prev_index,            o.prev_index);
        assert_eq!(g.output.value,          o.output.value);
        assert_eq!(g.output.script_pubkey,  o.output.script_pubkey);
    }
    assert_eq!(got.created_utxo_keys, original.created_utxo_keys);
    assert_eq!(got.coinbase_txids,    original.coinbase_txids);
    assert_eq!(got.tx_index_keys,     original.tx_index_keys);
    assert_eq!(got.mutation_count(),  original.mutation_count());
}

#[test]
fn get_missing_undo_returns_none_not_error() {
    // Critical: rollback_block must be able to tell "never recorded" apart
    // from "storage error". Pre-U.1 blocks on disk have no undo record.
    let (_tmp, store) = mk_storage();
    let unknown = [0xEEu8; 32];
    let got = store.get_undo_data(&unknown).expect("must not error");
    assert!(got.is_none(), "missing undo must yield Ok(None)");
}

#[test]
fn delete_undo_data_removes_the_record() {
    let (_tmp, store) = mk_storage();
    let hash = [0xDDu8; 32];
    let u = mk_undo_fixture(hash, 100);

    store.put_undo_data(&hash, &u).unwrap();
    assert!(store.get_undo_data(&hash).unwrap().is_some(), "sanity: put worked");

    store.delete_undo_data(&hash).expect("delete must succeed");
    assert!(
        store.get_undo_data(&hash).unwrap().is_none(),
        "delete_undo_data must actually remove the record"
    );
}

#[test]
fn delete_missing_undo_is_not_an_error() {
    // Idempotent delete matters for U.3's pruning loop — it may run multiple
    // times over the same finality-window boundary and we don't want the
    // second pass to fail.
    let (_tmp, store) = mk_storage();
    let unknown = [0x77u8; 32];
    assert!(store.delete_undo_data(&unknown).is_ok(),
        "deleting a non-existent record must be a no-op, not an error");
}

#[test]
fn multiple_blocks_undo_records_are_isolated() {
    // Verifies keys don't collide / overwrite across different block hashes.
    let (_tmp, store) = mk_storage();
    let h1 = [0x01u8; 32];
    let h2 = [0x02u8; 32];

    let mut u1 = UndoData::new(h1, 10);
    u1.coinbase_txids.push([0xAAu8; 32]);
    let mut u2 = UndoData::new(h2, 11);
    u2.coinbase_txids.push([0xBBu8; 32]);

    store.put_undo_data(&h1, &u1).unwrap();
    store.put_undo_data(&h2, &u2).unwrap();

    let got1 = store.get_undo_data(&h1).unwrap().unwrap();
    let got2 = store.get_undo_data(&h2).unwrap().unwrap();

    assert_eq!(got1.block_height,       10);
    assert_eq!(got1.coinbase_txids[0],  [0xAAu8; 32]);
    assert_eq!(got2.block_height,       11);
    assert_eq!(got2.coinbase_txids[0],  [0xBBu8; 32]);

    // Deleting one must not affect the other.
    store.delete_undo_data(&h1).unwrap();
    assert!(store.get_undo_data(&h1).unwrap().is_none());
    assert!(store.get_undo_data(&h2).unwrap().is_some(),
        "deleting h1's undo must not touch h2's");
}

#[test]
fn overwrite_replaces_previous_record() {
    // A block hash should never be re-submitted in practice (replay-protected
    // by the DAG), but if put_undo_data is called twice with the same key we
    // want last-write-wins semantics so this stays deterministic.
    let (_tmp, store) = mk_storage();
    let hash = [0xFFu8; 32];

    let mut v1 = UndoData::new(hash, 1);
    v1.coinbase_txids.push([0x01u8; 32]);
    store.put_undo_data(&hash, &v1).unwrap();

    let mut v2 = UndoData::new(hash, 1);
    v2.coinbase_txids.push([0x02u8; 32]);
    v2.coinbase_txids.push([0x03u8; 32]);
    store.put_undo_data(&hash, &v2).unwrap();

    let got = store.get_undo_data(&hash).unwrap().unwrap();
    assert_eq!(got.coinbase_txids.len(), 2, "must see v2's two entries");
    assert_eq!(got.coinbase_txids[0], [0x02u8; 32]);
    assert_eq!(got.coinbase_txids[1], [0x03u8; 32]);
}
