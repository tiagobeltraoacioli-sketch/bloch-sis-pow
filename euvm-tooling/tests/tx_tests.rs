//! Integration tests for the `tx` component (`euvm_tooling::tx`), exercising its public
//! API from OUTSIDE the crate.
//!
//! Coverage:
//!   - `ext_output` / `ext_output_blch` hash-binding + field wiring (the invariant that a
//!     committed `validator_hash` always equals `validator_hash(program)`);
//!   - `TxBuilder` fluent construction, chaining, counts, and every field wiring through
//!     to the built `EuTx`;
//!   - round-trips through the real VM: a builder-produced spend tx that `validate_tx`
//!     ACCEPTS, plus the reject-cases (fail-closed) it must refuse — hash mismatch,
//!     value-not-conserved, validator-rejected;
//!   - `build_checked` structural resource-ceiling enforcement (accept + every reject).
//!
//! These tests only touch the public surface: `euvm_tooling::tx::{TxBuilder, ext_output,
//! ext_output_blch}` and the re-exported VM at `euvm_tooling::euvm`. The `tx` module does
//! no signing/network, so the VM round-trips use "always-true" / "always-false" integer
//! programs that never call a signature op; the local verifier below is a fail-closed stub.

use euvm_tooling::euvm;
use euvm_tooling::tx::{ext_output, ext_output_blch, TxBuilder};

/// A fail-closed [`euvm::SigVerifier`]: every signature check returns false. None of the
/// programs used here call `VerifySig`/`VerifyEcdsa`, so this only proves the round-trips
/// don't secretly depend on signatures. (`sim` owns the crate's real shared mock; a test
/// binary must define its own since `bloch-euvm`'s is `#[cfg(test)]`-private.)
struct RejectAll;
impl euvm::SigVerifier for RejectAll {
    fn verify(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// An "always true" validator: seeds nothing off the stack, just pushes a truthy Int, so
/// `spend` finishes with a non-empty stack topped by `Int(1)`.
fn always_true() -> Vec<euvm::Op> {
    vec![euvm::Op::PushInt(1)]
}

/// An "always false" validator: pushes `Int(0)` on top, so the spend finishes non-truthy
/// and `validate_tx` reports `ValidatorRejected`.
fn always_false() -> Vec<euvm::Op> {
    vec![euvm::Op::PushInt(0)]
}

// ---------------------------------------------------------------------------
// ext_output / ext_output_blch — the hash-binding choke point
// ---------------------------------------------------------------------------

#[test]
fn ext_output_derives_hash_from_program() {
    let program = always_true();
    let out = ext_output(euvm::blch(50), &program, euvm::Val::Int(7));

    // The committed hash is EXACTLY validator_hash(program) — never trusted/hand-set.
    assert_eq!(out.validator_hash, euvm::validator_hash(&program));
    assert_eq!(euvm::value_get(&out.value, &euvm::BLCH), 50);
    assert_eq!(out.datum, euvm::Val::Int(7));
}

#[test]
fn ext_output_preserves_multi_asset_value_and_bytes_datum() {
    let program = vec![euvm::Op::PushInt(1), euvm::Op::Dup];
    let other_asset: euvm::AssetId = [9u8; 32];

    let mut value = euvm::blch(100);
    value.insert(other_asset, 42);

    let datum = euvm::Val::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
    let out = ext_output(value, &program, datum.clone());

    assert_eq!(euvm::value_get(&out.value, &euvm::BLCH), 100);
    assert_eq!(euvm::value_get(&out.value, &other_asset), 42);
    assert_eq!(euvm::value_get(&out.value, &[1u8; 32]), 0); // absent asset -> 0
    assert_eq!(out.datum, datum);
    assert_eq!(out.validator_hash, euvm::validator_hash(&program));
}

#[test]
fn ext_output_blch_is_zero_datum_single_asset_shorthand() {
    let program = always_true();
    let out = ext_output_blch(25, &program);

    assert_eq!(euvm::value_get(&out.value, &euvm::BLCH), 25);
    assert_eq!(out.value.len(), 1);
    assert_eq!(out.datum, euvm::Val::Int(0));
    assert_eq!(out.validator_hash, euvm::validator_hash(&program));
}

#[test]
fn different_programs_yield_different_hashes() {
    let a = ext_output_blch(1, &vec![euvm::Op::PushInt(1)]);
    let b = ext_output_blch(1, &vec![euvm::Op::PushInt(2)]);
    assert_ne!(a.validator_hash, b.validator_hash);
}

// ---------------------------------------------------------------------------
// TxBuilder — field wiring, chaining, counts, defaults
// ---------------------------------------------------------------------------

#[test]
fn empty_builder_builds_empty_tx() {
    let tx = TxBuilder::new().build();
    assert!(tx.inputs.is_empty());
    assert!(tx.outputs.is_empty());
    assert_eq!(tx.fee, 0);
    assert!(tx.sighash.is_empty());
}

#[test]
fn builder_wires_every_field_through() {
    let program = always_true();
    let locked = ext_output(euvm::blch(100), &program, euvm::Val::Int(0));

    let tx = TxBuilder::new()
        .sighash(b"sighash-msg".to_vec())
        .fee(3)
        .spend_input(locked.clone(), program.clone(), vec![euvm::Val::Int(42)])
        .output(ext_output_blch(97, &program))
        .build();

    assert_eq!(tx.fee, 3);
    assert_eq!(tx.sighash, b"sighash-msg".to_vec());
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);

    let input = &tx.inputs[0];
    assert_eq!(input.redeemer, vec![euvm::Val::Int(42)]);
    assert_eq!(input.prev_output, locked);
    // The revealed validator hashes back to the consumed output's committed hash.
    assert_eq!(
        euvm::validator_hash(&input.validator),
        input.prev_output.validator_hash
    );
    assert_eq!(euvm::value_get(&tx.outputs[0].value, &euvm::BLCH), 97);
}

#[test]
fn last_fee_and_sighash_win() {
    let tx = TxBuilder::new()
        .fee(1)
        .sighash(b"first".to_vec())
        .fee(9)
        .sighash(b"second".to_vec())
        .build();
    assert_eq!(tx.fee, 9);
    assert_eq!(tx.sighash, b"second".to_vec());
}

#[test]
fn output_blch_sets_raw_hash_without_program() {
    let h = [7u8; 32];
    let tx = TxBuilder::new().output_blch(25, h).build();
    assert_eq!(tx.outputs[0].validator_hash, h);
    assert_eq!(euvm::value_get(&tx.outputs[0].value, &euvm::BLCH), 25);
    assert_eq!(tx.outputs[0].datum, euvm::Val::Int(0));
}

#[test]
fn counts_track_additions_in_order() {
    let program = always_true();
    let out = ext_output_blch(1, &program);
    let b = TxBuilder::new()
        .spend_input(out.clone(), program.clone(), vec![])
        .spend_input(out.clone(), program.clone(), vec![])
        .spend_input(out.clone(), program.clone(), vec![])
        .output(out.clone());
    assert_eq!(b.input_count(), 3);
    assert_eq!(b.output_count(), 1);
    let tx = b.build();
    assert_eq!(tx.inputs.len(), 3);
    assert_eq!(tx.outputs.len(), 1);
}

// ---------------------------------------------------------------------------
// Round-trips through the real VM (validate_tx) — ACCEPT
// ---------------------------------------------------------------------------

#[test]
fn builder_produces_tx_validate_tx_accepts() {
    let program = always_true();
    // Deploy: 100 BLCH locked by `program`.
    let locked = ext_output(euvm::blch(100), &program, euvm::Val::Int(0));

    // Spend: reveal program (empty redeemer), recreate 99 BLCH, pay 1 fee.
    // Conservation: in 100 == out 99 + fee 1.
    let tx = TxBuilder::new()
        .sighash(b"m".to_vec())
        .fee(1)
        .spend_input(locked, program.clone(), vec![])
        .output(ext_output_blch(99, &program))
        .build();

    let gas_used = euvm::validate_tx(&tx, &RejectAll, 1_000_000).expect("valid spend");
    assert!(gas_used > 0, "a spend must charge some gas");
}

#[test]
fn multi_input_conserving_tx_accepts() {
    let program = always_true();
    let a = ext_output(euvm::blch(60), &program, euvm::Val::Int(0));
    let b = ext_output(euvm::blch(40), &program, euvm::Val::Int(0));

    // in 60+40=100 == out 90 + fee 10.
    let tx = TxBuilder::new()
        .fee(10)
        .spend_input(a, program.clone(), vec![])
        .spend_input(b, program.clone(), vec![])
        .output(ext_output_blch(90, &program))
        .build();

    assert!(euvm::validate_tx(&tx, &RejectAll, 2_000_000).is_ok());
}

// ---------------------------------------------------------------------------
// Round-trips through the real VM — REJECT (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn revealing_wrong_validator_is_rejected_with_hash_mismatch() {
    let committed = always_true();
    // Output commits to `committed`, but the spend reveals a DIFFERENT program.
    let locked = ext_output(euvm::blch(100), &committed, euvm::Val::Int(0));
    let wrong = vec![euvm::Op::PushInt(2)];
    assert_ne!(euvm::validator_hash(&wrong), locked.validator_hash);

    let tx = TxBuilder::new()
        .fee(1)
        .spend_input(locked, wrong, vec![]) // reveal the wrong program
        .output(ext_output_blch(99, &committed))
        .build();

    match euvm::validate_tx(&tx, &RejectAll, 1_000_000) {
        Err(euvm::TxError::Vm(0, euvm::VmError::ValidatorHashMismatch)) => {}
        other => panic!("expected Vm(0, ValidatorHashMismatch), got {other:?}"),
    }
}

#[test]
fn non_conserving_value_is_rejected() {
    let program = always_true();
    let locked = ext_output(euvm::blch(100), &program, euvm::Val::Int(0));

    // in 100 != out 98 + fee 1 -> not conserved.
    let tx = TxBuilder::new()
        .fee(1)
        .spend_input(locked, program.clone(), vec![])
        .output(ext_output_blch(98, &program))
        .build();

    match euvm::validate_tx(&tx, &RejectAll, 1_000_000) {
        Err(euvm::TxError::ValueNotConserved { asset, in_sum, out_plus_fee }) => {
            assert_eq!(asset, euvm::BLCH);
            assert_eq!(in_sum, 100);
            assert_eq!(out_plus_fee, 99);
        }
        other => panic!("expected ValueNotConserved, got {other:?}"),
    }
}

#[test]
fn falsy_validator_is_rejected() {
    let program = always_false();
    let locked = ext_output(euvm::blch(100), &program, euvm::Val::Int(0));

    // Conservation holds (100 == 99 + 1); the validator itself finishes non-truthy.
    let tx = TxBuilder::new()
        .fee(1)
        .spend_input(locked, program.clone(), vec![])
        .output(ext_output_blch(99, &program))
        .build();

    match euvm::validate_tx(&tx, &RejectAll, 1_000_000) {
        Err(euvm::TxError::ValidatorRejected(0)) => {}
        other => panic!("expected ValidatorRejected(0), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// build_checked — structural resource ceilings
// ---------------------------------------------------------------------------

#[test]
fn build_checked_accepts_small_tx() {
    let program = always_true();
    let locked = ext_output(euvm::blch(10), &program, euvm::Val::Int(0));
    let res = TxBuilder::new()
        .spend_input(locked, program.clone(), vec![])
        .output(ext_output_blch(9, &program))
        .fee(1)
        .build_checked();
    assert!(res.is_ok());
}

#[test]
fn build_checked_accepts_empty_tx() {
    // No inputs/outputs is structurally fine (conservation/validators aren't checked here).
    assert!(TxBuilder::new().build_checked().is_ok());
}

#[test]
fn build_checked_rejects_too_many_inputs() {
    let program = always_true();
    let out = ext_output_blch(1, &program);

    let mut b = TxBuilder::new();
    for _ in 0..(euvm::MAX_TX_INPUTS + 1) {
        b = b.spend_input(out.clone(), program.clone(), vec![]);
    }
    assert_eq!(b.input_count(), euvm::MAX_TX_INPUTS + 1);

    match b.build_checked() {
        Err(euvm::TxError::ResourceLimit { what }) => assert_eq!(what, "too many inputs"),
        other => panic!("expected ResourceLimit, got {other:?}"),
    }
}

#[test]
fn build_checked_rejects_too_many_outputs() {
    let program = always_true();
    let out = ext_output_blch(1, &program);

    let mut b = TxBuilder::new();
    for _ in 0..(euvm::MAX_TX_OUTPUTS + 1) {
        b = b.output(out.clone());
    }
    assert_eq!(b.output_count(), euvm::MAX_TX_OUTPUTS + 1);

    match b.build_checked() {
        Err(euvm::TxError::ResourceLimit { what }) => assert_eq!(what, "too many outputs"),
        other => panic!("expected ResourceLimit, got {other:?}"),
    }
}

#[test]
fn build_checked_rejects_value_with_too_many_assets() {
    let program = always_true();

    // A single output whose value bundle carries more than MAX_TX_DISTINCT_ASSETS entries.
    let mut value: euvm::Value = euvm::Value::new();
    for i in 0..=(euvm::MAX_TX_DISTINCT_ASSETS as u32) {
        let mut id = [0u8; 32];
        id[0..4].copy_from_slice(&i.to_le_bytes());
        value.insert(id, 1);
    }
    assert!(value.len() > euvm::MAX_TX_DISTINCT_ASSETS);

    let out = ext_output(value, &program, euvm::Val::Int(0));
    match TxBuilder::new().output(out).build_checked() {
        Err(euvm::TxError::ResourceLimit { what }) => assert_eq!(what, "value has too many assets"),
        other => panic!("expected ResourceLimit, got {other:?}"),
    }
}

#[test]
fn build_checked_rejects_operand_bytes_over_ceiling() {
    let program = always_true();
    // A datum whose byte length alone exceeds the total-bytes ceiling.
    let huge = euvm::Val::Bytes(vec![0u8; euvm::MAX_TX_BYTES + 1]);
    let out = ext_output(euvm::blch(1), &program, huge);

    match TxBuilder::new().output(out).build_checked() {
        Err(euvm::TxError::ResourceLimit { what }) => {
            assert_eq!(what, "transaction operand bytes exceed ceiling")
        }
        other => panic!("expected ResourceLimit, got {other:?}"),
    }
}

#[test]
fn build_and_build_checked_agree_on_contents_for_valid_tx() {
    // build_checked only adds a structural gate; on a valid tx the produced EuTx is
    // identical in shape to build().
    let program = always_true();
    let locked = ext_output(euvm::blch(5), &program, euvm::Val::Int(0));

    let unchecked = TxBuilder::new()
        .fee(1)
        .spend_input(locked.clone(), program.clone(), vec![])
        .output(ext_output_blch(4, &program))
        .build();

    let checked = TxBuilder::new()
        .fee(1)
        .spend_input(locked, program.clone(), vec![])
        .output(ext_output_blch(4, &program))
        .build_checked()
        .expect("valid");

    assert_eq!(unchecked.fee, checked.fee);
    assert_eq!(unchecked.inputs.len(), checked.inputs.len());
    assert_eq!(unchecked.outputs.len(), checked.outputs.len());
    assert_eq!(unchecked.outputs[0], checked.outputs[0]);
}
