//! Genesis-2 emission continuation (consensus proof, no networking/mining loop).
//!
//! Proves the validator (validate_coinbase_value) enforces that a Genesis-2 block
//! at LOCAL height 1 emits the subsidy for ABSOLUTE height 413,744 — i.e. emission
//! continues from the carried tip, 8,400 BLOCH/block until the first halving — and
//! that over-emission is rejected. The genesis anchor pays 0 (proven elsewhere).

use bloch_crypto::core::{
    self, set_node_chain_id, Block, BlockHeader, ChainId, Transaction, TxInput, TxOutput,
};
use bloch_crypto::core::tokenomics_v2::{block_subsidy_sat, SAT_PER_BLOCH};

fn coinbase(value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: b"height:1".to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value, script_pubkey: vec![0u8; 20] }],
        locktime: 0,
    }
}

fn block_at_height1(coinbase_value: u64) -> Block {
    let cb = coinbase(coinbase_value);
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![[1u8; 32]],
            merkle_root: Transaction::merkle_root(&[cb.clone()]),
            timestamp: core::GENESIS2_TIMESTAMP + 30,
            bits: core::GENESIS2_BITS,
            nonce: 0,
        },
        transactions: vec![cb],
        blue_score: 1,
        height: 1,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
    }
}

#[test]
fn genesis2_block1_emission_continues_at_8400() {
    set_node_chain_id(ChainId::Genesis2Devnet).expect("pin chain-id");

    // Local height 1 emits as ABSOLUTE height 413,744 (carried tip + 1)…
    assert_eq!(core::emission_height(1), 413_744, "offset must continue from the carried height");
    // …which is below the first halving (1,036,800), so 8,400 BLOCH.
    let subsidy = block_subsidy_sat(core::emission_height(1));
    assert_eq!(subsidy, 8_400 * SAT_PER_BLOCH, "block 1 subsidy must be 8,400 BLOCH");

    // The validator accepts exactly the continued subsidy…
    assert!(
        block_at_height1(subsidy).validate_coinbase_value(0).is_ok(),
        "block 1 paying the continued 8,400-BLOCH subsidy must validate",
    );
    // …and rejects any over-emission (no inflation past the schedule).
    assert!(
        block_at_height1(subsidy + 1).validate_coinbase_value(0).is_err(),
        "over-emission (subsidy + 1) must be rejected",
    );
}
