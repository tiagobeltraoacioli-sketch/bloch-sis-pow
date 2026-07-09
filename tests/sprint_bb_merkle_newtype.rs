//! Sprint BB — L-2 MerkleRoot newtype regression tests.
//!
//! These are CONSENSUS GUARDS. The L-2 refactor changed
//! `BlockHeader::merkle_root` from `[u8; 32]` to a `MerkleRoot`
//! newtype. The refactor is safe ONLY if two invariants hold:
//!
//!   1. **Wire format invariance.** A `MerkleRoot` must serialize to
//!      the exact same bytes as the underlying `[u8; 32]`. Bincode
//!      encodes `BlockHeader` into the block payload stored in
//!      RocksDB; any drift here turns every pre-L-2 block in storage
//!      into garbage that cannot be decoded. The `#[serde(transparent)]`
//!      attribute on `MerkleRoot` is what guarantees this — this test
//!      pins the guarantee so a future edit cannot silently remove it.
//!
//!   2. **PoW hash invariance.** `BlockHeader::pow_bytes` must emit the
//!      same byte sequence before and after the refactor. The block
//!      hash derives from `pow_bytes`; every block already mined
//!      depends on that hash being stable. The pre-L-2 code used
//!      `extend_from_slice(&self.merkle_root)` where `merkle_root: [u8;32]`,
//!      which copies 32 bytes. The post-L-2 code uses
//!      `extend_from_slice(self.merkle_root.as_ref())`. Same 32 bytes,
//!      same order — this test verifies it empirically against a
//!      hand-computed reference.
//!
//! If either of these tests fails, the refactor has introduced a hard
//! fork. Revert immediately.

use bloch::core::{BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};

// ─── Invariant 1: serde transparent ────────────────────────────────────────

/// A `MerkleRoot(x)` must encode to byte-identical output to the bare
/// `[u8; 32]` `x`. This is what `#[serde(transparent)]` promises; we
/// verify it empirically rather than trust the attribute.
#[test]
fn merkle_root_serde_is_byte_identical_to_array() {
    let arr: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    let wrapped = MerkleRoot::from(arr);

    let arr_encoded = bincode::serde::encode_to_vec(
        &arr, bincode::config::standard()
    ).unwrap();
    let wrapped_encoded = bincode::serde::encode_to_vec(
        &wrapped, bincode::config::standard()
    ).unwrap();

    assert_eq!(
        arr_encoded, wrapped_encoded,
        "MerkleRoot must serialize to bytes identical to [u8; 32] — \
         otherwise the L-2 refactor is a hard fork against every \
         pre-L-2 block currently in RocksDB"
    );
}

/// A byte buffer produced by encoding a bare `[u8; 32]` under bincode
/// must decode cleanly as `MerkleRoot`. This covers the "read old
/// blocks" direction explicitly.
#[test]
fn merkle_root_decodes_from_legacy_array_bytes() {
    let arr: [u8; 32] = [0xDEu8; 32];
    let legacy_bytes = bincode::serde::encode_to_vec(
        &arr, bincode::config::standard()
    ).unwrap();

    let (decoded, _): (MerkleRoot, _) = bincode::serde::decode_from_slice(
        &legacy_bytes, bincode::config::standard()
    ).expect("legacy [u8;32] bytes must decode as MerkleRoot");

    assert_eq!(decoded, MerkleRoot::from([0xDEu8; 32]));
}

/// Full `BlockHeader` round trip. This is the highest-fidelity guard
/// — it reconstructs exactly what the RocksDB block CF holds. If the
/// round trip is stable, real production blocks are safe.
#[test]
fn block_header_round_trip_preserves_merkle_root() {
    let mut parent = [0u8; 32];
    parent[0] = 0xAA;

    let merkle_bytes: [u8; 32] = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xCA, 0xFE, 0xDE, 0xAD,
        0xBE, 0xEF, 0xFE, 0xED, 0xCA, 0xFE, 0xBA, 0xBE,
        0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE,
    ];
    let header = BlockHeader {
        version:     1,
        parents:     vec![parent],
        merkle_root: MerkleRoot::from(merkle_bytes),
        timestamp:   1_700_000_000,
        bits:        0x1d00ffff,
        nonce:       42,
    };

    let encoded = bincode::serde::encode_to_vec(
        &header, bincode::config::standard()
    ).unwrap();
    let (decoded, _): (BlockHeader, _) = bincode::serde::decode_from_slice(
        &encoded, bincode::config::standard()
    ).unwrap();

    assert_eq!(decoded.merkle_root, header.merkle_root);
    assert_eq!(decoded.merkle_root.into_inner(), merkle_bytes);
}

// ─── Invariant 2: PoW byte-identity ────────────────────────────────────────

/// Hand-assemble the 80-byte MiningHeader for a known BlockHeader and
/// compare SHA-256d against `pow_hash()`. Bit for bit.
///
/// UPDATED for Sprint AA.0 (hard fork v0.6.0): pow_hash now hashes the
/// 80-byte Bitcoin-compatible MiningHeader projection, not the variable-
/// length full-header serialization used pre-v0.6.0. This test locks
/// in the new invariant: if any byte of the 80-byte layout drifts,
/// every miner (ASIC or otherwise) breaks and this test catches it.
///
/// We test the *hash* rather than MiningHeader::to_bytes() directly
/// because the hash is the consensus-level observable.
#[test]
fn pow_hash_matches_hand_computed_reference() {
    use sha2::{Digest, Sha256};
    use bloch::core::parents_commitment;

    let parent: [u8; 32] = [0xAA; 32];
    let merkle_bytes: [u8; 32] = [0xBB; 32];

    let header = BlockHeader {
        version:     1,
        parents:     vec![parent],
        merkle_root: MerkleRoot::from(merkle_bytes),
        timestamp:   1_700_000_000u64,
        bits:        0x1d00ffffu32,
        nonce:       42u64,
    };

    // Reproduce the 80-byte MiningHeader layout by hand.
    // For single-parent, parents_commitment returns the parent unchanged.
    let prev_hash = parents_commitment(&[parent]);
    assert_eq!(prev_hash, parent, "single-parent commitment sanity");

    let mut reference = [0u8; 80];
    reference[0..4].copy_from_slice(&1u32.to_le_bytes());
    reference[4..36].copy_from_slice(&prev_hash);
    reference[36..68].copy_from_slice(&merkle_bytes);
    reference[68..72].copy_from_slice(&(1_700_000_000u32).to_le_bytes());
    reference[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
    reference[76..80].copy_from_slice(&42u32.to_le_bytes());

    let expected: [u8; 32] = Sha256::digest(Sha256::digest(reference)).into();
    let actual = header.pow_hash();

    assert_eq!(
        actual, expected,
        "pow_hash diverged from the hand-computed 80-byte reference. \
         Sprint AA.0 invariant broken — every stratum miner and ASIC \
         now disagrees with the node about block validity."
    );
}

// ─── Type-safety spot check ────────────────────────────────────────────────

/// The whole point of L-2: the compiler now keeps `MerkleRoot` and
/// `[u8; 32]` distinct. This is a compile-time property, so the test
/// itself is trivial — it verifies the conversions exist and round
/// trip, which is what downstream code needs.
#[test]
fn merkle_root_conversions_round_trip() {
    let arr = [0xFFu8; 32];
    let wrapped: MerkleRoot = arr.into();
    let back: [u8; 32] = wrapped.into();
    assert_eq!(arr, back);
    assert_eq!(wrapped, MerkleRoot::from(arr));
    assert_eq!(wrapped.as_ref(), &arr[..]);
}

// ─── Empty-list edge case ──────────────────────────────────────────────────

/// The pre-L-2 `Transaction::merkle_root` returned `[0u8; 32]` for an
/// empty transaction list. Post-L-2 it returns `MerkleRoot::ZERO`.
/// This test pins that mapping — `MerkleRoot::ZERO` IS `[0u8;32]`
/// under the hood, so no consensus behavior changed.
#[test]
fn empty_tx_list_yields_zero_merkle_root() {
    let empty: Vec<Transaction> = vec![];
    let root = Transaction::merkle_root(&empty);
    assert_eq!(root, MerkleRoot::ZERO);
    assert_eq!(root.into_inner(), [0u8; 32]);
}

/// Single-tx input has stable output — this is both a regression
/// guard and a reminder that a block with one coinbase-only tx
/// has `merkle_root == txid(coinbase)` (the bitcoin convention).
#[test]
fn single_tx_merkle_equals_that_tx_txid() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: 0xFFFF_FFFF,
            script_sig: b"test".to_vec(),
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput { value: 42, script_pubkey: vec![1u8; 20] }],
        locktime: 0,
    };
    let root = Transaction::merkle_root(&[tx.clone()]);
    assert_eq!(root.as_ref(), &tx.txid()[..]);
}
