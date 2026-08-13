//! Genesis-2 canonical genesis block — the Genesis2Devnet (SHA-256d) side.
//!
//! `node_chain_id()` is a process-wide OnceLock, so this file is its own test
//! binary: every test pins ChainId::Genesis2Devnet first. The mirror binary
//! tests/genesis2_genesis_block_mainnet.rs proves the SAME canonical block is
//! REJECTED under Mainnet (Module-SIS arm), so the genesis cannot leak onto
//! the live chain's validation path.
//!
//! These tests pin the MINED ceremony constants (GENESIS2_NONCE,
//! GENESIS2_EXPECTED_HASH, produced by bloch-mine-genesis2): if anyone edits
//! the carry-over constants, the timestamp, the bits, the coinbase text
//! derivation, or the miner script_pubkey, the nonce/hash stop matching and
//! this binary FAILS — the same fail-closed property the node's startup check
//! enforces at runtime.

use bloch::core::{
    create_genesis2_block, create_genesis2_block_with_params, genesis2_coinbase_script_sig,
    node_chain_id, pow_algorithm, set_node_chain_id, ChainId, PowAlgorithm,
    GENESIS2_BITS, GENESIS2_CARRYOVER_SNAPSHOT_ROOT, GENESIS2_CARRYOVER_SOURCE_HEIGHT,
    GENESIS2_CARRYOVER_UTXO_COUNT, GENESIS2_EXPECTED_HASH, GENESIS2_MINER_SCRIPT_PUBKEY,
    GENESIS2_NONCE, GENESIS2_TIMESTAMP,
};

/// Pin this process to Genesis2Devnet (idempotent; every test calls it first).
fn use_devnet() {
    set_node_chain_id(ChainId::Genesis2Devnet)
        .expect("this test binary must be the only chain-id writer in its process");
    assert_eq!(node_chain_id(), ChainId::Genesis2Devnet, "chain-id pin did not take");
    assert_eq!(pow_algorithm(node_chain_id()), PowAlgorithm::Sha256d);
}

/// The canonical genesis-2 block: ceremony constants + founder miner spk.
fn canonical() -> bloch::core::Block {
    create_genesis2_block(&GENESIS2_MINER_SCRIPT_PUBKEY)
}

/// The mined ceremony constants validate on the REAL path the node runs:
/// validate_pow (Sha256d arm) accepts, merkle validates, and the block hash
/// equals the published GENESIS2_EXPECTED_HASH byte-for-byte.
#[test]
fn canonical_genesis2_validates_and_hash_is_pinned() {
    use_devnet();
    let g = canonical();
    assert!(g.pow_solution.is_empty(), "SHA-256d genesis carries no witness");
    assert!(g.validate_merkle(), "genesis-2 merkle must validate");
    assert!(g.validate_pow(), "canonical genesis-2 must pass validate_pow (Sha256d arm)");
    assert_eq!(
        g.block_hash(),
        GENESIS2_EXPECTED_HASH,
        "canonical genesis-2 hash drifted from the published constant"
    );
    assert_eq!(g.height, 0);
    assert!(g.header.parents.is_empty(), "genesis has no parents");
}

/// Fail closed: a tampered nonce (the exact check the node's startup gate
/// runs before exit(1)) is REJECTED by validate_pow.
#[test]
fn tampered_nonce_is_rejected() {
    use_devnet();
    let bad = create_genesis2_block_with_params(
        &GENESIS2_MINER_SCRIPT_PUBKEY,
        GENESIS2_BITS,
        GENESIS2_TIMESTAMP,
        GENESIS2_NONCE + 1,
    );
    assert!(!bad.validate_pow(), "tampered nonce must not validate");
    assert_ne!(bad.block_hash(), GENESIS2_EXPECTED_HASH);
}

/// Fail closed: tampering with the carry-over COMMITMENT (script_sig bytes)
/// changes the merkle root, so the mined nonce no longer meets the target —
/// the commitment is bound by PoW, not just carried as a comment.
#[test]
fn tampered_commitment_is_rejected() {
    use_devnet();
    let mut g = canonical();
    // Flip one byte of the human-readable commitment.
    g.transactions[0].inputs[0].script_sig[0] ^= 0x01;
    // Rebuild the header merkle the way a forger would have to.
    let merkle = bloch::core::Transaction::merkle_root(&g.transactions);
    g.header.merkle_root = merkle;
    assert!(g.validate_merkle(), "forged block is internally consistent");
    assert!(
        !g.validate_pow(),
        "a different commitment with the ceremony nonce must fail PoW"
    );
}

/// Fail closed: a Module-SIS witness cannot be smuggled onto the SHA-256d
/// genesis — non-empty pow_solution is consensus-invalid on this chain even
/// though the hash itself still meets the target.
#[test]
fn smuggled_witness_is_rejected() {
    use_devnet();
    let mut g = canonical();
    g.pow_solution = vec![0i32; 256];
    assert!(!g.validate_pow(), "witness smuggling must be rejected");
}

/// The commitment text is derived from the carry-over constants (single
/// source of truth) and is human-readable: height, UTXO count, root prefix.
#[test]
fn commitment_text_is_human_readable_and_derived() {
    use_devnet();
    let sig = genesis2_coinbase_script_sig();
    let text = String::from_utf8(sig.clone()).expect("commitment must be valid UTF-8");
    assert_eq!(
        text,
        format!(
            "Bloch carry-over from height {}: {} UTXOs, root {}...",
            GENESIS2_CARRYOVER_SOURCE_HEIGHT,
            GENESIS2_CARRYOVER_UTXO_COUNT,
            &hex::encode(GENESIS2_CARRYOVER_SNAPSHOT_ROOT)[..16],
        )
    );
    assert!(text.contains("413743"), "height must be visible in the clear");
    assert!(text.contains("d3de5e51ee9dbbf3"), "root prefix must be visible in the clear");
    // And the canonical block actually carries these bytes.
    assert_eq!(canonical().transactions[0].inputs[0].script_sig, sig);
}

/// The 32-bit-nonce invariant the miner relies on: the ceremony nonce fits
/// the 80-byte MiningHeader projection with no truncation loss.
#[test]
fn ceremony_nonce_fits_32_bits() {
    use_devnet();
    assert_eq!(GENESIS2_NONCE >> 32, 0, "upper 32 bits must be zero");
}
