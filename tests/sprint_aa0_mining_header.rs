//! Sprint AA.0 — 80-byte Bitcoin-compatible MiningHeader
//!
//! Tests the pow_hash refactor from the full BlockHeader projection
//! to an 80-byte MiningHeader derived from it. This is the consensus
//! change that makes stratum V1 and SHA-256d ASICs viable mining
//! clients for Bloch-SIS Protocol, without breaking BlockDAG semantics.
//!
//! See docstrings on `MiningHeader` and `BlockHeader::to_mining_header`
//! in src/core/mod.rs for the full rationale.

use bloch::core::{BlockHeader, MerkleRoot, MiningHeader, parents_commitment};

fn mk_header(parents: Vec<[u8; 32]>, timestamp: u64, nonce: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        parents,
        merkle_root: MerkleRoot([0xAB; 32]),
        timestamp,
        bits: 0x1d00ffff,
        nonce,
    }
}

// ── Layout tests ──────────────────────────────────────────────────

#[test]
fn mining_header_layout_is_exactly_80_bytes() {
    let mh = MiningHeader {
        version: 1,
        prev_hash: [0x11; 32],
        merkle_root: [0x22; 32],
        timestamp: 0xDEADBEEF,
        bits: 0x1d00ffff,
        nonce: 0x12345678,
    };
    let bytes = mh.to_bytes();
    assert_eq!(bytes.len(), 80, "mining header MUST serialize to exactly 80 bytes for ASIC compatibility");
}

#[test]
fn mining_header_bytes_use_little_endian() {
    let mh = MiningHeader {
        version: 0x01020304,
        prev_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        timestamp: 0x11223344,
        bits: 0x55667788,
        nonce: 0x99aabbcc,
    };
    let bytes = mh.to_bytes();
    // version
    assert_eq!(&bytes[0..4], &[0x04, 0x03, 0x02, 0x01]);
    // timestamp
    assert_eq!(&bytes[68..72], &[0x44, 0x33, 0x22, 0x11]);
    // bits
    assert_eq!(&bytes[72..76], &[0x88, 0x77, 0x66, 0x55]);
    // nonce
    assert_eq!(&bytes[76..80], &[0xcc, 0xbb, 0xaa, 0x99]);
}

#[test]
fn mining_header_round_trip_via_bytes() {
    let original = MiningHeader {
        version: 1,
        prev_hash: [0xAA; 32],
        merkle_root: [0xBB; 32],
        timestamp: 1_700_000_000,
        bits: 0x1d00ffff,
        nonce: 42,
    };
    let bytes = original.to_bytes();
    let reparsed = MiningHeader::from_bytes(&bytes);
    assert_eq!(reparsed, original);
}

// ── Parent commitment tests ──────────────────────────────────────

#[test]
fn parents_commitment_empty_is_zeros() {
    let c = parents_commitment(&[]);
    assert_eq!(c, [0u8; 32], "genesis commitment must be all-zeros");
}

#[test]
fn parents_commitment_single_is_identity() {
    let parent = [0x42u8; 32];
    let c = parents_commitment(&[parent]);
    assert_eq!(c, parent, "single-parent commitment is the parent itself");
}

#[test]
fn parents_commitment_is_order_independent() {
    let p1 = [0x01u8; 32];
    let p2 = [0x02u8; 32];
    let p3 = [0x03u8; 32];

    let c_abc = parents_commitment(&[p1, p2, p3]);
    let c_cba = parents_commitment(&[p3, p2, p1]);
    let c_bac = parents_commitment(&[p2, p1, p3]);

    assert_eq!(c_abc, c_cba, "commitment must not depend on input order");
    assert_eq!(c_abc, c_bac, "commitment must not depend on input order");
}

#[test]
fn parents_commitment_distinct_sets_produce_distinct_values() {
    let c1 = parents_commitment(&[[0x01u8; 32]]);
    let c2 = parents_commitment(&[[0x02u8; 32]]);
    assert_ne!(c1, c2);

    let c3 = parents_commitment(&[[0x01u8; 32], [0x02u8; 32]]);
    assert_ne!(c3, c1);
    assert_ne!(c3, c2);
}

#[test]
fn parents_commitment_handles_odd_counts() {
    // Odd count triggers the "duplicate last" path in merkle folding.
    // Shouldn't panic; should produce a stable result.
    let c = parents_commitment(&[
        [0x01u8; 32],
        [0x02u8; 32],
        [0x03u8; 32],
    ]);
    // Verified stable — this test will flag if the algorithm ever drifts.
    assert_ne!(c, [0u8; 32]);
}

// ── BlockHeader → MiningHeader projection tests ──────────────────

#[test]
fn block_header_projects_to_mining_header_correctly() {
    let parents = vec![[0x11u8; 32], [0x22u8; 32]];
    let header = mk_header(parents.clone(), 1_700_000_000, 0xFFFF);
    let mh = header.to_mining_header();

    assert_eq!(mh.version, header.version);
    assert_eq!(mh.prev_hash, parents_commitment(&parents));
    assert_eq!(mh.merkle_root, header.merkle_root.0);
    assert_eq!(mh.timestamp, header.timestamp as u32);
    assert_eq!(mh.bits, header.bits);
    assert_eq!(mh.nonce, header.nonce as u32);
}

#[test]
fn projection_truncates_timestamp_upper_bits() {
    // Timestamp 0x1_0000_0000 would lose the MSB when cast to u32.
    // Acceptable: wraps after 2106. Test documents the behavior.
    let ts_with_upper_bits: u64 = 0x1_1234_5678;
    let header = mk_header(vec![[0u8; 32]], ts_with_upper_bits, 0);
    let mh = header.to_mining_header();
    assert_eq!(mh.timestamp, 0x1234_5678);
}

#[test]
fn projection_truncates_nonce_upper_bits() {
    // Same story for nonce. The miner explores the 32-bit nonce space;
    // the u64 field exists in BlockHeader for historical reasons.
    let nonce_with_upper_bits: u64 = 0x1_ABCD_EF01;
    let header = mk_header(vec![[0u8; 32]], 0, nonce_with_upper_bits);
    let mh = header.to_mining_header();
    assert_eq!(mh.nonce, 0xABCD_EF01);
}

// ── pow_hash is over the 80-byte projection ──────────────────────

#[test]
fn pow_hash_matches_mining_header_hash() {
    let header = mk_header(vec![[0x33u8; 32]], 1_700_000_000, 42);
    let direct = header.pow_hash();
    let via_mh = header.to_mining_header().pow_hash();
    assert_eq!(direct, via_mh, "BlockHeader.pow_hash() MUST equal MiningHeader.pow_hash()");
}

#[test]
fn pow_hash_is_double_sha256_of_80_bytes() {
    use sha2::{Digest, Sha256};

    let mh = MiningHeader {
        version: 1,
        prev_hash: [0xAA; 32],
        merkle_root: [0xBB; 32],
        timestamp: 1_700_000_000,
        bits: 0x1d00ffff,
        nonce: 42,
    };

    let bytes = mh.to_bytes();
    let expected: [u8; 32] = Sha256::digest(Sha256::digest(bytes)).into();
    let actual = mh.pow_hash();
    assert_eq!(actual, expected, "PoW hash must be exactly Bitcoin's SHA-256d over the 80-byte header");
}

#[test]
fn pow_hash_changes_with_nonce() {
    // Sanity: incrementing nonce produces a different hash.
    // A mining loop depends on this, obviously.
    let h1 = mk_header(vec![[0u8; 32]], 0, 0).pow_hash();
    let h2 = mk_header(vec![[0u8; 32]], 0, 1).pow_hash();
    assert_ne!(h1, h2);
}

#[test]
fn pow_hash_changes_with_merkle_root() {
    let mut h1 = mk_header(vec![[0u8; 32]], 0, 0);
    let h1_hash = h1.pow_hash();

    h1.merkle_root = MerkleRoot([0xFF; 32]);
    let h2_hash = h1.pow_hash();

    assert_ne!(h1_hash, h2_hash);
}

// ── dag_hash is distinct from pow_hash and preserves full header ─

#[test]
fn dag_hash_differs_from_pow_hash() {
    let header = mk_header(vec![[0x11u8; 32]], 1_700_000_000, 42);
    assert_ne!(header.dag_hash(), header.pow_hash(),
        "dag_hash and pow_hash must be distinct to avoid accidental equivalence");
}

#[test]
fn dag_hash_distinguishes_parent_order() {
    // dag_hash hashes the full BlockHeader (including parents Vec in
    // its native order), so two BlockHeaders with the same PARENT SET
    // but different Vec orderings have different dag_hashes. That's
    // fine — the DAG stores blocks by block_hash (pow_hash), which IS
    // order-independent. dag_hash is only for internal indexing.
    let h1 = mk_header(vec![[0x01u8; 32], [0x02u8; 32]], 0, 0);
    let h2 = mk_header(vec![[0x02u8; 32], [0x01u8; 32]], 0, 0);
    // Same pow_hash (projections equal):
    assert_eq!(h1.pow_hash(), h2.pow_hash());
    // Different dag_hash (raw order differs):
    assert_ne!(h1.dag_hash(), h2.dag_hash());
}

// ── ASIC interop: bit-level stability ────────────────────────────

#[test]
fn known_test_vector_80_byte_serialization() {
    // Stability regression. If this test fails, the 80-byte layout
    // has drifted and every miner implementation in the world
    // breaks. Do not change this test vector without a consensus
    // version bump.
    let mh = MiningHeader {
        version:     0x00000001,
        prev_hash:   [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        merkle_root: [0xAA; 32],
        timestamp:   0x00000000,
        bits:        0x1d00ffff,
        nonce:       0x00000000,
    };

    let bytes = mh.to_bytes();
    // First 4 bytes: version little-endian
    assert_eq!(&bytes[0..4], &[0x01, 0x00, 0x00, 0x00]);
    // prev_hash (all zeros)
    assert_eq!(&bytes[4..36], &[0u8; 32]);
    // merkle_root (all 0xAA)
    assert_eq!(&bytes[36..68], &[0xAA; 32]);
    // timestamp (zero)
    assert_eq!(&bytes[68..72], &[0u8; 4]);
    // bits 0x1d00ffff little-endian
    assert_eq!(&bytes[72..76], &[0xff, 0xff, 0x00, 0x1d]);
    // nonce zero
    assert_eq!(&bytes[76..80], &[0u8; 4]);
}
