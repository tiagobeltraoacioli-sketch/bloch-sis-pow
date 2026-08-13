//! Genesis-2 canonical genesis block — the Mainnet (Module-SIS) side.
//!
//! Own test binary (process-wide OnceLock chain-id): pins ChainId::Mainnet
//! and proves the canonical Genesis-2 block — the very bytes the devnet
//! binary accepts — is REJECTED by the live chain's validation path. The
//! Genesis-2 genesis carries NO Module-SIS witness (pow_solution empty), so
//! the ModuleSis arm fails closed on the length check alone: the new chain's
//! genesis can never be replayed onto the existing network.

use bloch::core::{
    create_genesis2_block, node_chain_id, pow_algorithm, set_node_chain_id, ChainId,
    PowAlgorithm, GENESIS2_MINER_SCRIPT_PUBKEY,
};

fn use_mainnet() {
    set_node_chain_id(ChainId::Mainnet)
        .expect("this test binary must be the only chain-id writer in its process");
    assert_eq!(node_chain_id(), ChainId::Mainnet, "chain-id pin did not take");
    assert_eq!(pow_algorithm(node_chain_id()), PowAlgorithm::ModuleSis);
}

#[test]
fn genesis2_block_is_rejected_on_mainnet() {
    use_mainnet();
    let g = create_genesis2_block(&GENESIS2_MINER_SCRIPT_PUBKEY);
    assert!(g.pow_solution.is_empty());
    assert!(
        !g.validate_pow(),
        "the Genesis-2 genesis must NOT validate under the live chain's Module-SIS rules"
    );
}
