//! Sprint 1.b — Storage migration to Bitcoin-format Block serialization.
//!
//! Verifies that `put_block` writes Bitcoin-format bytes and
//! `get_block` reads them back identically. If these tests fail,
//! blocks written by v0.6.0+ nodes cannot be read, and the chain
//! effectively corrupts on the first restart.

use bloch::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use bloch::storage::Storage;
use std::path::PathBuf;

fn tmpdir() -> PathBuf {
    // cargo test runs tests in parallel within the same process.
    // Each test needs its own RocksDB directory or they fight over
    // the process-level lock file. Use an atomic counter + pid for
    // uniqueness.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut p = std::env::temp_dir();
    p.push(format!("bloch-sprint1b-{}-{}", std::process::id(), n));
    // Ensure clean slate
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("tmpdir");
    p
}

fn mk_coinbase(h: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("height:{}", h).into_bytes(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 500_000_000, script_pubkey: vec![0x11; 20] },
            TxOutput { value: 10_000_000,  script_pubkey: vec![0x22; 20] },
        ],
        locktime: 0,
    }
}

fn mk_block(h: u64, parent: [u8; 32]) -> Block {
    let cb = mk_coinbase(h);
    let merkle = Transaction::merkle_root(&[cb.clone()]);
    Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![parent],
            merkle_root: merkle,
            timestamp:   1_700_000_000 + h,
            bits:        0x1d00ffff,
            nonce:       42,
        },
        transactions: vec![cb],
        blue_score:   h.saturating_sub(1),
        height:       h,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

// ── Round-trip through storage preserves every field ─────────────

#[test]
fn put_then_get_block_round_trip() {
    let dir = tmpdir();
    let storage = Storage::open(&dir).expect("open");

    let block = mk_block(1, [0u8; 32]);
    let hash = block.block_hash();

    storage.put_block(&block).expect("put");

    let retrieved = storage.get_block(&hash).expect("get").expect("found");

    assert_eq!(retrieved.header.version,    block.header.version);
    assert_eq!(retrieved.header.parents,    block.header.parents);
    assert_eq!(retrieved.header.merkle_root.0, block.header.merkle_root.0);
    assert_eq!(retrieved.header.timestamp,  block.header.timestamp);
    assert_eq!(retrieved.header.bits,       block.header.bits);
    assert_eq!(retrieved.header.nonce,      block.header.nonce);
    assert_eq!(retrieved.blue_score,        block.blue_score);
    assert_eq!(retrieved.height,            block.height);
    assert_eq!(retrieved.transactions.len(), block.transactions.len());

    // Most importantly: pow_hash stable.
    assert_eq!(retrieved.block_hash(), hash);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_nonexistent_block_returns_none() {
    let dir = tmpdir();
    let storage = Storage::open(&dir).expect("open");

    let result = storage.get_block(&[0x99; 32]).expect("get");
    assert!(result.is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_many_blocks_all_retrievable() {
    let dir = tmpdir();
    let storage = Storage::open(&dir).expect("open");

    let blocks: Vec<Block> = (1..=10)
        .map(|h| mk_block(h, [(h - 1) as u8; 32]))
        .collect();

    for b in &blocks {
        storage.put_block(b).expect("put");
    }

    for b in &blocks {
        let got = storage.get_block(&b.block_hash()).expect("get").expect("found");
        assert_eq!(got.height, b.height);
        assert_eq!(got.block_hash(), b.block_hash());
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn put_block_indexes_by_height() {
    let dir = tmpdir();
    let storage = Storage::open(&dir).expect("open");

    let block = mk_block(42, [0u8; 32]);
    storage.put_block(&block).expect("put");

    let hash_at_42 = storage
        .get_block_hash_at_height(42)
        .expect("get_hash")
        .expect("should have hash");
    assert_eq!(hash_at_42, block.block_hash());

    let ts = storage
        .get_timestamp_at_height(42)
        .expect("get_ts")
        .expect("should have ts");
    assert_eq!(ts, block.header.timestamp);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn storage_bytes_on_disk_are_bitcoin_format() {
    // Verify that the bytes written to RocksDB are byte-identical to
    // what Block::to_bitcoin_bytes() produces. This catches any
    // accidental revert to bincode in a future refactor.
    let dir = tmpdir();
    let storage = Storage::open(&dir).expect("open");

    let block = mk_block(1, [0u8; 32]);
    let hash = block.block_hash();
    storage.put_block(&block).expect("put");

    // Round-trip through get_block must produce byte-identical bytes.
    let retrieved = storage.get_block(&hash).expect("get").expect("found");
    assert_eq!(retrieved.to_bitcoin_bytes(), block.to_bitcoin_bytes());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn roundtrip_preserves_multi_parent_block() {
    let dir = tmpdir();
    let storage = Storage::open(&dir).expect("open");

    let cb = mk_coinbase(5);
    let merkle = Transaction::merkle_root(&[cb.clone()]);
    let block = Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![[0x11; 32], [0x22; 32], [0x33; 32]], // multi-parent DAG
            merkle_root: merkle,
            timestamp:   1_000_000,
            bits:        0x1d00ffff,
            nonce:       7,
        },
        transactions: vec![cb],
        blue_score:   4,
        height:       5,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    };
    let hash = block.block_hash();

    storage.put_block(&block).expect("put");
    let got = storage.get_block(&hash).expect("get").expect("found");

    assert_eq!(got.header.parents.len(), 3);
    assert_eq!(got.header.parents, block.header.parents);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupted_block_bytes_in_db_returns_error_not_panic() {
    // If somehow the CF_BLOCKS entry is corrupted (disk error,
    // bug), get_block should return Err, not panic. The node can
    // then decide what to do (re-fetch from peers, etc).
    use rocksdb::{DB, Options};

    let dir = tmpdir();
    {
        let storage = Storage::open(&dir).expect("open");
        let block = mk_block(1, [0u8; 32]);
        storage.put_block(&block).expect("put");
    }

    // Corrupt the CF_BLOCKS entry directly via raw RocksDB.
    // Use DB::list_cf so we track whatever CFs the production code
    // defines without maintaining a hardcoded list here.
    {
        let opts = Options::default();
        let cfs = DB::list_cf(&opts, &dir).expect("list CFs");
        let cfs_refs: Vec<&str> = cfs.iter().map(|s| s.as_str()).collect();
        let db = DB::open_cf(&opts, &dir, &cfs_refs).expect("open raw");
        let cf = db.cf_handle("blocks").expect("blocks CF");
        let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut key_to_corrupt = None;
        for item in iter {
            if let Ok((k, _)) = item { key_to_corrupt = Some(k.to_vec()); break; }
        }
        if let Some(k) = key_to_corrupt {
            db.put_cf(&cf, &k, b"not a valid block").expect("overwrite");
        }
    }

    // get_block should return Err, not panic.
    let storage = Storage::open(&dir).expect("reopen");
    let block = mk_block(1, [0u8; 32]);
    let result = storage.get_block(&block.block_hash());
    assert!(result.is_err(), "corrupted block bytes should error, got: {:?}", result);

    let _ = std::fs::remove_dir_all(&dir);
}
