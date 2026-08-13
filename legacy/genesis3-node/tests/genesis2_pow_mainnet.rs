//! Genesis-2 PoW switch — the Mainnet (Module-SIS) side.
//!
//! Mirror binary of tests/genesis2_pow_devnet.rs (separate process because
//! node_chain_id() is a process-wide OnceLock). This side pins Mainnet
//! EXPLICITLY (not just the default) and proves the inverted verdicts on the
//! same deterministic blocks: the SIS witness block is accepted, the
//! SHA-256d block is rejected — so the two binaries together exercise both
//! dispatch arms on identical bytes.

mod g2_common;

use bloch::core::{
    node_chain_id, pow_algorithm, set_node_chain_id, ChainId, PowAlgorithm,
};
use g2_common::{block_with, mined_sha256d_block, mined_sis_block};

/// Pin this process to Mainnet explicitly — proves we're not merely riding
/// the OnceLock default while the devnet binary silently also does.
fn use_mainnet() {
    set_node_chain_id(ChainId::Mainnet)
        .expect("this test binary must be the only chain-id writer in its process");
    assert_eq!(node_chain_id(), ChainId::Mainnet, "chain-id pin did not take");
    assert_eq!(pow_algorithm(node_chain_id()), PowAlgorithm::ModuleSis);
}

/// (c) positive half: the deterministic k=4 Module-SIS witness block passes
/// validate_pow today under Mainnet — the same bytes the devnet binary
/// rejects.
#[test]
fn sis_witness_block_validates_under_mainnet() {
    use_mainnet();
    let block = mined_sis_block();
    assert_eq!(block.pow_solution.len(), 256);
    assert!(block.validate_pow(), "k=4 SIS block must keep validating on Mainnet");
}

/// (b) negative half: the block mined by mine_sha256d (accepted by the devnet
/// binary) is REJECTED when node_chain_id() == Mainnet — its empty
/// pow_solution can never satisfy the Module-SIS arm (len != 256).
#[test]
fn sha256d_mined_block_rejected_under_mainnet() {
    use_mainnet();
    let block = mined_sha256d_block();
    assert!(block.pow_solution.is_empty());
    assert!(
        !block.validate_pow(),
        "a witness-less SHA-256d block must be rejected on the Module-SIS chain",
    );
}

/// The pinned dispatcher routes the ModuleSis arm here: mine_pow_parallel
/// returns a real 256-length witness and the block validates — byte-kind
/// identical to mine_sis_pow_parallel's output.
#[test]
fn mine_pow_parallel_routes_to_module_sis_arm() {
    use_mainnet();
    let block0 = mined_sis_block(); // deterministic single-thread reference
    let (nonce, solution) = bloch::pow::mine_pow_parallel(
        &block0.header.pow_preimage(),
        block0.header.bits,
        0,
        0,
        20_000_000,
        1, // single worker ⇒ identical deterministic scan as the reference
    )
    .expect("ModuleSis arm must mine the relaxed k=4 regime");
    assert_eq!(solution.len(), 256, "ModuleSis arm must return the witness vector");
    assert_eq!((nonce, &solution), (block0.header.nonce, &block0.pow_solution),
        "dispatcher must reproduce mine_sis_pow's deterministic result");
    let mut header = block0.header.clone();
    header.nonce = nonce;
    let block = block_with(header, 0, solution);
    assert!(block.validate_pow(), "dispatcher-mined SIS block must validate");
}
