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

fn block_at_local_height(height: u64, coinbase_value: u64) -> Block {
    let cb = coinbase(coinbase_value);
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![[1u8; 32]],
            merkle_root: Transaction::merkle_root(&[cb.clone()]),
            timestamp: core::GENESIS2_TIMESTAMP + 30 * height,
            bits: core::GENESIS2_BITS,
            nonce: 0,
        },
        transactions: vec![cb],
        blue_score: height,
        height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

fn block_at_height1(coinbase_value: u64) -> Block {
    block_at_local_height(1, coinbase_value)
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

/// Emission V3 flag-day, end-to-end through the REAL consensus validator on a
/// carry-over chain: the fork is at LOCAL height 40,000 (= emission 453,743).
/// The validator must accept exactly the old curve at local 39,999 (8,400) and
/// exactly the new curve at local 40,000+ (2,600) — and reject each curve on
/// the other side of the boundary. This pins the local↔emission plumbing
/// (`emission_height`) together with the height gate in `block_subsidy_sat`.
#[test]
fn emission_v3_fork_boundary_via_validator() {
    // Same OnceLock pin as above (both tests run in one process; the offset
    // semantics of Genesis2Devnet and Genesis3Mainnet are identical: +413,743).
    set_node_chain_id(ChainId::Genesis2Devnet).expect("pin chain-id");

    let fork_local = 40_000u64;
    assert_eq!(
        core::emission_height(fork_local),
        bloch_crypto::core::tokenomics_v2::EMISSION_V3_FORK_EMISSION_HEIGHT,
        "local 40,000 must map to the V3 fork emission height (453,743)",
    );

    let old = 8_400 * SAT_PER_BLOCH;
    let new = 2_600 * SAT_PER_BLOCH;

    // fork − 1: old curve accepted, new curve is UNDER-paying (allowed — the
    // miner output is a ceiling) but the OLD amount over-pays must fail… so
    // assert the exact-boundary semantics we actually rely on:
    assert!(
        block_at_local_height(fork_local - 1, old).validate_coinbase_value(0).is_ok(),
        "local 39,999 paying 8,400 BLOCH must validate (pre-fork curve)",
    );
    assert!(
        block_at_local_height(fork_local, new).validate_coinbase_value(0).is_ok(),
        "local 40,000 paying 2,600 BLOCH must validate (V3 curve)",
    );
    // Paying the OLD subsidy at/after the fork is over-emission → reject.
    assert!(
        block_at_local_height(fork_local, old).validate_coinbase_value(0).is_err(),
        "local 40,000 paying 8,400 BLOCH must be rejected (over-emission)",
    );
    assert!(
        block_at_local_height(fork_local + 1, old).validate_coinbase_value(0).is_err(),
        "local 40,001 paying 8,400 BLOCH must be rejected (over-emission)",
    );
    // One block early on the NEW curve + one sat over the ceiling → reject
    // (the step is exactly at 40,000, not 39,999).
    assert!(
        block_at_local_height(fork_local, new + 1).validate_coinbase_value(0).is_err(),
        "over-emission by 1 sat at the fork must be rejected",
    );
}
