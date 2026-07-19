//! Genesis-2 PoW switch — the Genesis2Devnet (SHA-256d) side.
//!
//! `node_chain_id()` is a process-wide OnceLock, so this file is its own test
//! binary (cargo integration tests = one process per file): every test here
//! FIRST pins the chain-id to Genesis2Devnet and asserts the pin took — the
//! mirror binary tests/genesis2_pow_mainnet.rs pins Mainnet and proves the
//! opposite verdicts on the very same deterministic blocks, so the two files
//! demonstrably exercise both dispatch arms (identical bytes, inverted
//! accept/reject) rather than testing one chain twice.

mod g2_common;

use bloch::core::{
    node_chain_id, pow_algorithm, set_node_chain_id, ChainId, PowAlgorithm,
};
use g2_common::{block_with, mined_sha256d_block, mined_sis_block, sha_header};

/// Pin this process to Genesis2Devnet (idempotent; every test calls it first).
fn use_devnet() {
    set_node_chain_id(ChainId::Genesis2Devnet)
        .expect("this test binary must be the only chain-id writer in its process");
    assert_eq!(node_chain_id(), ChainId::Genesis2Devnet, "chain-id pin did not take");
    assert_eq!(pow_algorithm(node_chain_id()), PowAlgorithm::Sha256d);
}

/// (b) positive half: a block mined by mine_sha256d validates under
/// validate_pow when node_chain_id() == Genesis2Devnet.
#[test]
fn sha256d_mined_block_validates_under_devnet() {
    use_devnet();
    let block = mined_sha256d_block();
    assert!(block.pow_solution.is_empty(), "SHA-256d blocks carry no witness");
    assert!(block.validate_pow(), "SHA-256d-mined block must validate on its own chain");
}

/// (c) negative half: the k=4 Module-SIS witness block that passes under
/// Mainnet (proven in the mirror binary) is REJECTED here — its non-empty
/// pow_solution alone is consensus-invalid on a SHA-256d chain.
#[test]
fn sis_witness_block_rejected_under_devnet() {
    use_devnet();
    let block = mined_sis_block();
    assert_eq!(block.pow_solution.len(), 256, "fixture must carry a real SIS witness");
    assert!(
        !block.validate_pow(),
        "a Module-SIS witness block must be rejected on the SHA-256d chain",
    );
}

/// Witness smuggling is rejected even when the SHA-256d PoW itself is valid:
/// take the validly mined SHA-256d block and attach a witness — must flip to
/// invalid.
#[test]
fn valid_sha256d_pow_with_smuggled_witness_rejected() {
    use_devnet();
    let mut block = mined_sha256d_block();
    assert!(block.validate_pow());
    block.pow_solution = vec![0i32; 256];
    assert!(
        !block.validate_pow(),
        "non-empty pow_solution must invalidate an otherwise-valid SHA-256d block",
    );
}

/// The pinned dispatcher routes the Sha256d arm here: mine_pow_parallel
/// returns an EMPTY witness and a nonce the validator accepts.
#[test]
fn mine_pow_parallel_routes_to_sha256d_arm() {
    use_devnet();
    let header = sha_header();
    let (nonce, solution) =
        bloch::pow::mine_pow_parallel(&header.pow_preimage(), header.bits, 0, 0, 1 << 22, 4)
            .expect("SHA-256d arm must find the ~2^-16 target");
    assert!(solution.is_empty(), "Sha256d arm must return an empty witness");
    assert!(nonce <= u32::MAX as u64, "upper 32 nonce bits must be zero");
    let mut header = header;
    header.nonce = nonce;
    let block = block_with(header, 0, solution);
    assert!(block.validate_pow(), "dispatcher-mined block must validate");
}
