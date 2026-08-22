// SPDX-License-Identifier: AGPL-3.0-or-later
//! §7 and §9.1's last property. This crate defines **no gas constant of its
//! own** — `fee_market::TxClass::EvmPq` already prices this transaction. It
//! restates two constants for the precompile's charge, and these tests are
//! what stop the restatement from drifting into a second calibration.

mod common;

use bloch_l1_evm_auth::precompile::PQ_VERIFY_BASE_GAS;
use bloch_l1_evm_auth::{BlochTx, GAS_PER_BYTE, HYBRID_VERIFY_GAS};
use bloch_pos_committee::fee_market::{
    intrinsic_gas, TxClass, BLOCK_GAS_LIMIT, MAX_BLOCK_TX_BYTES_V2,
};
use common::{first_use_tx, repeat_use_tx, Key};

#[test]
fn the_restated_constants_still_equal_the_originals() {
    assert_eq!(
        HYBRID_VERIFY_GAS,
        bloch_pos_committee::fee_market::HYBRID_VERIFY_GAS,
        "the restatement has drifted from fee_market — one calibration, one place to edit"
    );
    assert_eq!(
        GAS_PER_BYTE,
        bloch_pos_committee::fee_market::GAS_PER_BYTE
    );
    assert_eq!(PQ_VERIFY_BASE_GAS, HYBRID_VERIFY_GAS);
}

#[test]
fn the_wire_sizes_are_what_the_public_number_is_derived_from() {
    // The honest numbers, measured rather than asserted in prose. Falcon's
    // signature is variable, so these are checked as bands around the
    // documented ≈ 4,700 B / ≈ 8,453 B.
    let key = Key::new(71);
    let mut steady = common::base_tx(&key);
    steady.data = Vec::new();
    let steady = common::sign_with(steady, &key, None);
    let steady_len = steady.encode().unwrap().len();

    let mut first = common::base_tx(&key);
    first.data = Vec::new();
    let first = common::sign_with(first, &key, Some(key.enveloped.clone()));
    let first_len = first.encode().unwrap().len();

    assert!(
        (4_600..=4_900).contains(&steady_len),
        "steady-state authorization measured {steady_len} B"
    );
    assert!(
        (8_300..=8_700).contains(&first_len),
        "first authorization measured {first_len} B"
    );
    // The pubkey is the whole difference, plus its presence/length prefix.
    assert_eq!(first_len - steady_len, key.enveloped.len() + 4);
}

#[test]
fn bytes_bind_before_gas() {
    // The dossier's "bytes, not cycles, are what gas must defend", as a
    // checkable inequality. If a future gas edit inverts it, signature bytes
    // become the cheap resource and this test goes red instead of the change
    // going unnoticed.
    let key = Key::new(72);
    let steady = repeat_use_tx(&key);
    let tx_bytes = steady.encode().unwrap().len() as u64;

    let by_bytes = MAX_BLOCK_TX_BYTES_V2 / tx_bytes;
    let by_gas = BLOCK_GAS_LIMIT / intrinsic_gas(TxClass::EvmPq, tx_bytes);

    assert!(
        by_bytes < by_gas,
        "bytes must bind first: {by_bytes} by bytes vs {by_gas} by gas"
    );
    // And the public number stays honest: ~111 authorizations per block, at
    // 30-second slots, IF the entire payload were EVM — which it is not.
    assert!(
        (100..=120).contains(&by_bytes),
        "authorizations per block measured {by_bytes}"
    );
}

#[test]
fn a_first_authorization_costs_more_gas_than_a_repeat_one() {
    let key = Key::new(73);
    let first = first_use_tx(&key).encode().unwrap().len() as u64;
    let repeat = repeat_use_tx(&key).encode().unwrap().len() as u64;
    assert!(
        intrinsic_gas(TxClass::EvmPq, first) > intrinsic_gas(TxClass::EvmPq, repeat),
        "revealing the pubkey must be paid for by the sender who reveals it"
    );
}

#[test]
fn the_decoder_budget_matches_the_live_cap_when_the_caller_passes_it() {
    // The crate never assumes the cap; this asserts only that the live value
    // is a workable budget for a real transaction, so a caller passing
    // `fee_market::max_block_tx_bytes(epoch)` gets sane behaviour.
    let key = Key::new(74);
    let bytes = first_use_tx(&key).encode().unwrap();
    assert!(BlochTx::decode(&bytes, MAX_BLOCK_TX_BYTES_V2).is_ok());
}
