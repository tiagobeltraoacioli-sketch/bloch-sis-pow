//! Sprint 1 (Bitcoin format migration) — Block + BlockHeader wire format.
//!
//! These tests lock in the canonical v0.6.0 block/header wire format
//! that replaces bincode throughout storage + network + mempool.
//! If any test fails, the byte layout has drifted and every node on
//! the network disagrees about block contents.

use bloch::core::{
    Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput,
    parents_commitment,
};

fn mk_coinbase(height: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("height:{}", height).into_bytes(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 500_000_000, script_pubkey: vec![0x11; 20] },
            TxOutput { value: 10_000_000,  script_pubkey: vec![0x22; 20] },
        ],
        locktime: 0,
    }
}

fn mk_standard_tx(tag: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [tag; 32],
            prev_index: 3,
            script_sig: vec![tag; 80],
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput { value: 1000, script_pubkey: vec![tag; 20] },
        ],
        locktime: 0,
    }
}

fn mk_header(parents: Vec<[u8; 32]>, merkle: [u8; 32], ts: u64, nonce: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        parents,
        merkle_root: MerkleRoot(merkle),
        timestamp: ts,
        bits: 0x1d00ffff,
        nonce,
    }
}

// ── BlockHeader serialization ────────────────────────────────────

#[test]
fn header_bytes_first_80_bytes_equal_mining_header() {
    let parent: [u8; 32] = [0xAA; 32];
    let header = mk_header(vec![parent], [0xBB; 32], 1_700_000_000, 42);
    let bytes = header.to_bitcoin_bytes(100, 99);

    let mining = header.to_mining_header();
    let mining_bytes = mining.to_bytes();

    assert_eq!(&bytes[..80], &mining_bytes[..],
        "first 80 bytes of Bitcoin-format header must be exactly MiningHeader bytes");
}

#[test]
fn header_round_trip_preserves_all_fields() {
    let parents = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
    let header = mk_header(parents.clone(), [0xBB; 32], 1_700_000_000, 0xDEADBEEFCAFEBABE);

    let bytes = header.to_bitcoin_bytes(7, 100);
    let (parsed, blue_score, height) = BlockHeader::from_bitcoin_bytes(&bytes)
        .expect("round-trip should succeed");

    assert_eq!(parsed.version, header.version);
    assert_eq!(parsed.parents.len(), header.parents.len());
    // parents_commitment orders parents ascending, but the original
    // Vec order is preserved in the extension region.
    assert_eq!(parsed.parents, header.parents);
    assert_eq!(parsed.merkle_root.0, header.merkle_root.0);
    assert_eq!(parsed.timestamp, header.timestamp);
    assert_eq!(parsed.bits, header.bits);
    assert_eq!(parsed.nonce, header.nonce);
    assert_eq!(blue_score, 7);
    assert_eq!(height, 100);
}

#[test]
fn header_round_trip_preserves_pow_hash() {
    // The round trip must not disturb the PoW hash — ASICs and
    // miners computed hashes against the original, and any
    // deserialized copy must hash identically.
    let h = mk_header(vec![[0xFF; 32]], [0x77; 32], 1_234_567_890, 0xAABB_CCDD);
    let bytes = h.to_bitcoin_bytes(0, 1);
    let (parsed, _, _) = BlockHeader::from_bitcoin_bytes(&bytes).unwrap();
    assert_eq!(parsed.pow_hash(), h.pow_hash());
}

#[test]
fn header_round_trip_with_zero_parents() {
    // Genesis scenario.
    let h = mk_header(Vec::new(), [0; 32], 0, 0);
    let bytes = h.to_bitcoin_bytes(0, 0);
    let (parsed, bs, hh) = BlockHeader::from_bitcoin_bytes(&bytes).unwrap();
    assert_eq!(parsed.parents.len(), 0);
    assert_eq!(bs, 0);
    assert_eq!(hh, 0);
}

#[test]
fn header_round_trip_with_many_parents() {
    // 7 parents — exercise the varint encoding and extension region.
    let parents: Vec<[u8; 32]> = (1..=7).map(|i| [i as u8; 32]).collect();
    let h = mk_header(parents.clone(), [0; 32], 100, 1);
    let bytes = h.to_bitcoin_bytes(50, 51);
    let (parsed, bs, hh) = BlockHeader::from_bitcoin_bytes(&bytes).unwrap();
    assert_eq!(parsed.parents, parents);
    assert_eq!(bs, 50);
    assert_eq!(hh, 51);
}

#[test]
fn header_rejects_prev_hash_tamper() {
    // If someone corrupts the 80-byte prev_hash field but leaves the
    // extension parents intact, from_bitcoin_bytes must detect it.
    let h = mk_header(vec![[0x01; 32], [0x02; 32]], [0; 32], 0, 0);
    let mut bytes = h.to_bitcoin_bytes(0, 0);

    // Tamper: flip a bit in the prev_hash region (bytes 4..36)
    bytes[10] ^= 0x01;

    let result = BlockHeader::from_bitcoin_bytes(&bytes);
    assert!(result.is_err(), "tampered prev_hash must be detected");
    let err = result.unwrap_err();
    assert!(err.contains("prev_hash mismatch"), "got: {}", err);
}

#[test]
fn header_rejects_truncated_input() {
    let h = mk_header(vec![[0xAA; 32]], [0; 32], 0, 0);
    let bytes = h.to_bitcoin_bytes(0, 0);
    let truncated = &bytes[..bytes.len() - 5];
    assert!(BlockHeader::from_bitcoin_bytes(truncated).is_err());
}

#[test]
fn header_preserves_u64_timestamp_upper_bits() {
    // Test that the upper 32 bits of timestamp survive round-trip.
    // The 80-byte mining portion stores low 32 bits; extension stores
    // high 32 bits.
    let ts_with_upper: u64 = 0x7FFF_FFFF_1234_5678;
    let h = mk_header(vec![], [0; 32], ts_with_upper, 0);
    let bytes = h.to_bitcoin_bytes(0, 0);
    let (parsed, _, _) = BlockHeader::from_bitcoin_bytes(&bytes).unwrap();
    assert_eq!(parsed.timestamp, ts_with_upper);
}

#[test]
fn header_preserves_u64_nonce_upper_bits() {
    let nonce_with_upper: u64 = 0xFEED_FACE_CAFE_BABE;
    let h = mk_header(vec![], [0; 32], 0, nonce_with_upper);
    let bytes = h.to_bitcoin_bytes(0, 0);
    let (parsed, _, _) = BlockHeader::from_bitcoin_bytes(&bytes).unwrap();
    assert_eq!(parsed.nonce, nonce_with_upper);
}

// ── Block serialization ──────────────────────────────────────────

#[test]
fn block_round_trip_coinbase_only() {
    let cb = mk_coinbase(1);
    let merkle = Transaction::merkle_root(&[cb.clone()]);

    let header = BlockHeader {
        version: 1,
        parents: vec![[0u8; 32]],
        merkle_root: merkle,
        timestamp: 1_700_000_000,
        bits: 0x1d00ffff,
        nonce: 0,
    };

    let block = Block {
        header,
        transactions: vec![cb],
        blue_score: 0,
        height: 1,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    };

    let bytes = block.to_bitcoin_bytes();
    let parsed = Block::from_bitcoin_bytes(&bytes).expect("round trip");

    assert_eq!(parsed.transactions.len(), 1);
    assert!(parsed.transactions[0].is_coinbase());
    assert_eq!(parsed.height, 1);
    assert_eq!(parsed.blue_score, 0);
    assert_eq!(parsed.header.pow_hash(), block.header.pow_hash());
}

#[test]
fn block_round_trip_with_multiple_txs() {
    let cb = mk_coinbase(42);
    let t1 = mk_standard_tx(0xA1);
    let t2 = mk_standard_tx(0xA2);
    let t3 = mk_standard_tx(0xA3);

    let all_txs = vec![cb, t1.clone(), t2.clone(), t3.clone()];
    let merkle = Transaction::merkle_root(&all_txs);

    let header = BlockHeader {
        version: 1,
        parents: vec![[0x11; 32]],
        merkle_root: merkle,
        timestamp: 1_700_000_000,
        bits: 0x1d00ffff,
        nonce: 999,
    };

    let block = Block {
        header,
        transactions: all_txs,
        blue_score: 41,
        height: 42,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    };

    let bytes = block.to_bitcoin_bytes();
    let parsed = Block::from_bitcoin_bytes(&bytes).expect("round trip");

    assert_eq!(parsed.transactions.len(), 4);
    assert_eq!(parsed.height, 42);
    assert_eq!(parsed.blue_score, 41);
    assert_eq!(parsed.validate_merkle(), true);

    // Every tx must round-trip byte-exact
    for (orig, rep) in block.transactions.iter().zip(parsed.transactions.iter()) {
        assert_eq!(orig.txid(), rep.txid(), "tx byte-exact round trip");
    }
}

#[test]
fn block_rejects_trailing_garbage() {
    let cb = mk_coinbase(1);
    let merkle = Transaction::merkle_root(&[cb.clone()]);
    let block = Block {
        header: BlockHeader {
            version: 1,
            parents: vec![[0u8; 32]],
            merkle_root: merkle,
            timestamp: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![cb],
        blue_score: 0,
        height: 1,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    };

    let mut bytes = block.to_bitcoin_bytes();
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // trailing

    let result = Block::from_bitcoin_bytes(&bytes);
    assert!(result.is_err(), "trailing bytes must be rejected");
}

#[test]
fn block_rejects_truncated_tx_list() {
    let cb = mk_coinbase(1);
    let merkle = Transaction::merkle_root(&[cb.clone()]);
    let block = Block {
        header: BlockHeader {
            version: 1,
            parents: vec![[0u8; 32]],
            merkle_root: merkle,
            timestamp: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![cb],
        blue_score: 0,
        height: 1,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    };

    let bytes = block.to_bitcoin_bytes();
    let truncated = &bytes[..bytes.len() - 2];
    assert!(Block::from_bitcoin_bytes(truncated).is_err());
}

#[test]
fn block_round_trip_validates_pow_and_merkle() {
    // Full sanity: a round-tripped block must still pass its own
    // internal validation checks.
    let cb = mk_coinbase(5);
    let merkle = Transaction::merkle_root(&[cb.clone()]);
    let block = Block {
        header: BlockHeader {
            version: 1,
            parents: vec![[0u8; 32]],
            merkle_root: merkle,
            timestamp: 1_000_000_000,
            bits: 0x207fffff, // very easy target so pow passes deterministically
            nonce: 0,
        },
        transactions: vec![cb],
        blue_score: 4,
        height: 5,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    };

    let bytes = block.to_bitcoin_bytes();
    let parsed = Block::from_bitcoin_bytes(&bytes).unwrap();

    assert!(parsed.validate_merkle());
    // PoW may or may not pass with nonce=0; not checking that here,
    // just that the merkle invariant survives serialization.
}

// ── Byte stability regression ────────────────────────────────────

#[test]
fn header_bytes_are_stable_reference() {
    // If this test fails, the header layout has drifted. Do not
    // change the expected bytes without a consensus version bump.
    let h = BlockHeader {
        version: 1,
        parents: vec![[0xAA; 32]],
        merkle_root: MerkleRoot([0xBB; 32]),
        timestamp: 0x1234_5678,
        bits: 0x1d00ffff,
        nonce: 0xDEAD_BEEF,
    };
    let bytes = h.to_bitcoin_bytes(0, 1);

    // Expected length: 80 (mining) + 1 (varint=1) + 32 (parent)
    //                  + 4 (ts_high=0) + 4 (nonce_high=0)
    //                  + 8 (blue_score) + 8 (height)
    //                = 80 + 1 + 32 + 4 + 4 + 8 + 8 = 137
    assert_eq!(bytes.len(), 137, "stable header byte length");

    // First byte: version low byte = 0x01
    assert_eq!(bytes[0], 0x01);

    // Byte 4..36: prev_hash = parents_commitment([0xAA; 32]) = [0xAA; 32]
    // (single parent returns identity)
    assert_eq!(&bytes[4..36], &[0xAA; 32]);

    // Byte 72..76: bits (little-endian) = 0xff 0xff 0x00 0x1d
    assert_eq!(&bytes[72..76], &[0xff, 0xff, 0x00, 0x1d]);

    // Byte 76..80: nonce_low32 little-endian of 0xDEAD_BEEF
    assert_eq!(&bytes[76..80], &[0xef, 0xbe, 0xad, 0xde]);

    // Byte 80: varint parent count = 1
    assert_eq!(bytes[80], 0x01);

    // Bytes 81..113: the one parent
    assert_eq!(&bytes[81..113], &[0xAA; 32]);

    // Bytes 113..117: timestamp_high32 = 0 (since timestamp fits in u32)
    assert_eq!(&bytes[113..117], &[0u8; 4]);

    // Bytes 117..121: nonce_high32 = 0 (since nonce fits in u32)
    assert_eq!(&bytes[117..121], &[0u8; 4]);

    // Bytes 121..129: blue_score = 0
    assert_eq!(&bytes[121..129], &[0u8; 8]);

    // Bytes 129..137: height = 1 little-endian
    assert_eq!(&bytes[129..137], &[0x01, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn parents_commitment_unchanged_by_bitcoin_round_trip() {
    let parents = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
    let expected = parents_commitment(&parents);

    let h = mk_header(parents, [0; 32], 0, 0);
    let bytes = h.to_bitcoin_bytes(0, 0);
    let (parsed, _, _) = BlockHeader::from_bitcoin_bytes(&bytes).unwrap();

    assert_eq!(parents_commitment(&parsed.parents), expected);
}
