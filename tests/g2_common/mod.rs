//! Shared fixtures for the Genesis-2 PoW-switch integration tests.
//!
//! `node_chain_id()` is a process-wide OnceLock, so the two chain-id sides
//! live in SEPARATE test binaries (separate processes):
//!   * tests/genesis2_pow_devnet.rs  — pins ChainId::Genesis2Devnet
//!   * tests/genesis2_pow_mainnet.rs — pins ChainId::Mainnet
//! Both binaries build the SAME two blocks through the deterministic miners
//! below (fixed start nonces, threads = 1), so each side proves the opposite
//! accept/reject verdict on identical bytes.

use bloch::core::{Block, BlockHeader, MerkleRoot, GENESIS_BITS};

/// Compact bits for the SHA-256d fixture: core::bits_to_target(0x1f00ffff) =
/// 0x0000ffff… — ~2^-16 per hash, seconds to mine in debug.
pub const SHA_BITS: u32 = 0x1f00ffff;

pub fn sha_header() -> BlockHeader {
    BlockHeader {
        version:     1,
        parents:     vec![[7u8; 32]],
        merkle_root: MerkleRoot([9u8; 32]),
        timestamp:   1_777_000_000,
        bits:        SHA_BITS,
        nonce:       0,
    }
}

pub fn block_with(header: BlockHeader, height: u64, pow_solution: Vec<i32>) -> Block {
    Block {
        header,
        transactions: vec![],
        blue_score: 0,
        height,
        pow_solution,
        shielded_transactions: vec![],
    }
}

/// Deterministic SHA-256d-mined block: single-threaded scan from nonce 0, so
/// every process finds the SAME nonce and both test binaries judge identical
/// bytes.
pub fn mined_sha256d_block() -> Block {
    let mut header = sha_header();
    let nonce = bloch::pow::mine_sha256d(&header, header.bits, 0, 1 << 22, 1)
        .expect("~2^-16 target must be hit within 2^22 attempts");
    header.nonce = nonce;
    block_with(header, 0, Vec::new())
}

/// Deterministic k=4 Module-SIS-mined block at height 0 (below every k
/// activation ⇒ relaxed width), GENESIS_BITS aux target (near-max under the
/// crate's Target semantics ⇒ gated by the residual only). Single-threaded
/// solver from start nonce 0 ⇒ same witness in every process. This block
/// passes `validate_pow` today under Mainnet.
pub fn mined_sis_block() -> Block {
    let header = BlockHeader {
        version:     1,
        parents:     vec![],
        merkle_root: MerkleRoot([0u8; 32]),
        timestamp:   1_777_000_000,
        bits:        GENESIS_BITS,
        nonce:       0,
    };
    let (nonce, solution) =
        bloch::pow::mine_sis_pow(&header.pow_preimage(), header.bits, 0, 0, 20_000_000)
            .expect("k=4 relaxed regime must be brute-force mineable");
    let mut header = header;
    header.nonce = nonce;
    block_with(header, 0, solution.to_vec())
}
