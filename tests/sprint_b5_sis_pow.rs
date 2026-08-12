//! Sprint B5b — Module-SIS PoW end-to-end at the Block level (testnet regime).
//!
//! Proves the flip works through the real consensus types (not just the raw
//! adapter): an unmined block fails PoW; mining a testnet solution and
//! attaching it makes `validate_pow` pass; a wrong nonce fails; and the block
//! identity binds the solution vector. ZERO security (relaxed testnet regime).

use bloch::core::{Block, BlockHeader, MerkleRoot};
use bloch::pow;

fn unmined_block() -> Block {
    let header = BlockHeader {
        version:     1,
        parents:     vec![],
        merkle_root: MerkleRoot::ZERO,
        timestamp:   1_700_000_000,
        // Easiest aux target so mining is gated only by the (relaxed) residual.
        bits:        pow::target_to_bits(&pow::Target::MAX),
        nonce:       0,
    };
    Block {
        header,
        transactions: vec![],
        blue_score:   0,
        height:       1,
        pow_solution: vec![],
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

#[test]
fn sis_pow_block_mines_and_validates() {
    let mut block = unmined_block();

    // Unmined: no solution → PoW invalid.
    assert!(!block.validate_pow(), "unmined block must fail PoW");

    // Mine a testnet Module-SIS solution and attach it.
    let preimage = block.header.pow_preimage();
    let bits = block.header.bits;
    let (nonce, solution) = pow::mine_sis_pow_testnet(&preimage, bits, 0, 20_000_000)
        .expect("relaxed testnet regime must be brute-force mineable");
    block.header.nonce = nonce;
    block.pow_solution = solution.to_vec();

    // Mined block validates under the SIS PoW.
    assert!(block.validate_pow(), "mined SIS block must validate");

    // Wrong nonce → different SIS instance → invalid.
    let good_nonce = block.header.nonce;
    block.header.nonce = good_nonce.wrapping_add(1);
    assert!(!block.validate_pow(), "wrong nonce must fail SIS PoW");
    block.header.nonce = good_nonce;
    assert!(block.validate_pow());
}

#[test]
fn block_identity_binds_the_solution() {
    let mut block = unmined_block();
    let preimage = block.header.pow_preimage();
    let bits = block.header.bits;
    let (nonce, solution) = pow::mine_sis_pow_testnet(&preimage, bits, 0, 20_000_000)
        .expect("mineable");
    block.header.nonce = nonce;
    block.pow_solution = solution.to_vec();

    let id_before = block.block_hash();
    // Change one coefficient to a different in-range value.
    block.pow_solution[0] = if block.pow_solution[0] == 2 { 1 } else { 2 };
    let id_after = block.block_hash();
    assert_ne!(id_before, id_after, "block identity must bind the PoW solution");
}

#[test]
fn canonical_genesis_validates() {
    // The hardcoded genesis carries a mined testnet Module-SIS witness and must
    // pass validate_pow for the canonical genesis (miner = FOUNDER_ADDRESS_HEX).
    let founder = hex::decode("e986db5149cff7499b282a048272a09aff0af4ff").unwrap();
    let genesis = bloch::core::create_genesis_block(&founder, &founder, &founder);
    assert!(genesis.validate_pow(), "canonical genesis must have valid SIS PoW");
}
