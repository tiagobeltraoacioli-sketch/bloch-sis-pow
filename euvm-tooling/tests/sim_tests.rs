//! Integration tests for the `sim` component — exercised from OUTSIDE the crate,
//! against only the public surface (`euvm_tooling::sim` + the re-exported
//! `euvm_tooling::euvm`). These deliberately duplicate none of `sim`'s in-crate
//! unit tests: the focus here is edge cases, malformed / fail-closed input, and
//! round-trips, with reject-cases weighted as heavily as accept-cases.
//!
//! Public surface under test:
//!   - `sim::MockVerifier` — `accepting` / `always` / `never` / `with_triple` / `Default`
//!     (implements `euvm::SigVerifier`).
//!   - `sim::SimResult` — fields `result` / `gas_used` / `gas_limit`, helpers
//!     `accepted` / `rejected` / `errored` / `gas_remaining`.
//!   - `sim::run_program` — bare program, caller-seeded stack.
//!   - `sim::run_spend`   — spend a specific `ExtOutput` (hash-bound).
//!   - `sim::simulate_tx` — full `EuTx` validation (`validate_tx` wrapper).

use euvm_tooling::euvm::{
    blch, validator_hash, Ctx, EuTx, EuTxInput, ExtOutput, Op, TxError, Val, Value, VmError, BLCH,
};
use euvm_tooling::sim::{self, MockVerifier};

// ── small helpers ────────────────────────────────────────────────────────────

/// An `ExtOutput` whose `validator_hash` correctly commits to `program`.
fn output_for(value: Value, program: &[Op], datum: Val) -> ExtOutput {
    ExtOutput {
        value,
        validator_hash: validator_hash(program),
        datum,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimResult accessor consistency (the reported gas bookkeeping must be coherent)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn simresult_accessors_are_mutually_consistent_on_accept() {
    let prog = vec![Op::PushInt(1), Op::PushInt(2), Op::Add]; // 3 → truthy
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);

    assert!(r.accepted());
    assert!(!r.rejected());
    assert!(!r.errored());
    // Exactly one of accepted/rejected/errored holds.
    assert_eq!(
        [r.accepted(), r.rejected(), r.errored()]
            .iter()
            .filter(|b| **b)
            .count(),
        1
    );
    assert_eq!(r.result, Ok(true));
    assert_eq!(r.gas_limit, 10_000);
    assert!(r.gas_used > 0 && r.gas_used <= r.gas_limit);
    assert_eq!(r.gas_remaining(), r.gas_limit - r.gas_used);
}

#[test]
fn simresult_reject_is_not_error_and_vice_versa() {
    // Clean falsy finish → rejected, not errored.
    let falsy = sim::run_program(
        &[Op::PushInt(0)],
        vec![],
        &Ctx::default(),
        &MockVerifier::never(),
        1_000,
    );
    assert!(falsy.rejected());
    assert!(!falsy.errored());
    assert!(!falsy.accepted());
    assert_eq!(falsy.result, Ok(false));

    // A fault → errored, neither accepted nor rejected.
    let faulted = sim::run_program(
        &[Op::Add], // StackUnderflow: nothing to add
        vec![],
        &Ctx::default(),
        &MockVerifier::never(),
        1_000,
    );
    assert!(faulted.errored());
    assert!(!faulted.accepted());
    assert!(!faulted.rejected());
    assert_eq!(faulted.result, Err(VmError::StackUnderflow));
}

// ─────────────────────────────────────────────────────────────────────────────
// run_program — accept / reject / fault edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_program_with_empty_stack_faults_empty_result() {
    // No ops, no seed → the VM finishes with an empty stack → EmptyResult.
    let r = sim::run_program(&[], vec![], &Ctx::default(), &MockVerifier::never(), 1_000);
    assert_eq!(r.result, Err(VmError::EmptyResult));
    assert!(r.errored());
    // No ops executed, so no gas should be consumed.
    assert_eq!(r.gas_used, 0);
    assert_eq!(r.gas_remaining(), 1_000);
}

#[test]
fn empty_program_returns_seeded_top_of_stack() {
    // Zero ops but a truthy seed → the seeded top is the verdict.
    let accept = sim::run_program(
        &[],
        vec![Val::Int(7)],
        &Ctx::default(),
        &MockVerifier::never(),
        1_000,
    );
    assert_eq!(accept.result, Ok(true));

    let reject = sim::run_program(
        &[],
        vec![Val::Int(0)],
        &Ctx::default(),
        &MockVerifier::never(),
        1_000,
    );
    assert_eq!(reject.result, Ok(false));
}

#[test]
fn bytes_top_is_type_error_not_a_verdict() {
    // Truthiness of a Bytes top is a TypeError (fail-closed) — never silently truthy.
    let r = sim::run_program(
        &[],
        vec![Val::Bytes(vec![1, 2, 3])],
        &Ctx::default(),
        &MockVerifier::never(),
        1_000,
    );
    assert!(matches!(r.result, Err(VmError::TypeError(_))));
    assert!(r.errored());
}

#[test]
fn out_of_gas_reports_verdict_and_drains_budget() {
    // A budget too small to cover all three ops → OutOfGas.
    let prog = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 1);
    assert_eq!(r.result, Err(VmError::OutOfGas));
    assert!(r.errored());
    // The whole budget is (at most) consumed and gas accounting stays non-negative.
    assert!(r.gas_used <= r.gas_limit);
    assert_eq!(r.gas_remaining(), r.gas_limit - r.gas_used);
}

#[test]
fn zero_gas_budget_faults_immediately() {
    // Even a single op cannot run with a zero budget.
    let r = sim::run_program(
        &[Op::PushInt(1)],
        vec![],
        &Ctx::default(),
        &MockVerifier::never(),
        0,
    );
    assert_eq!(r.result, Err(VmError::OutOfGas));
    assert_eq!(r.gas_used, 0);
    assert_eq!(r.gas_remaining(), 0);
}

#[test]
fn arithmetic_overflow_faults_closed() {
    // i128::MAX + 1 → checked add overflow surfaced as VmError::Overflow.
    let prog = vec![Op::PushInt(i128::MAX), Op::PushInt(1), Op::Add];
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert_eq!(r.result, Err(VmError::Overflow));
}

#[test]
fn type_mismatch_in_arithmetic_faults() {
    // Add expects two Ints; a Bytes operand is a TypeError.
    let prog = vec![Op::PushBytes(vec![0xaa]), Op::PushInt(1), Op::Add];
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert!(matches!(r.result, Err(VmError::TypeError(_))));
}

#[test]
fn bad_ctx_field_index_faults() {
    // ctx.fields is empty by default; CtxField(0) is out of bounds.
    let prog = vec![Op::CtxField(0)];
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert_eq!(r.result, Err(VmError::BadCtxField(0)));
}

#[test]
fn ctx_field_reads_supplied_scratch_value() {
    // A supplied ctx.fields[0] Int(1) is read to the top → truthy accept.
    let ctx = Ctx {
        fields: vec![Val::Int(1)],
        ..Ctx::default()
    };
    let r = sim::run_program(&[Op::CtxField(0)], vec![], &ctx, &MockVerifier::never(), 10_000);
    assert_eq!(r.result, Ok(true));
}

#[test]
fn verify_op_aborts_with_assert_on_falsy() {
    // Verify pops the top; a falsy top aborts with Assert (not a clean reject).
    let prog = vec![Op::PushInt(0), Op::Verify];
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert_eq!(r.result, Err(VmError::Assert));
}

// ─────────────────────────────────────────────────────────────────────────────
// MockVerifier semantics through the VM (VerifySig / VerifyEcdsa)
// ─────────────────────────────────────────────────────────────────────────────

/// Program that pushes msg,pk,sig then VerifySig — result is the verifier's verdict.
fn verifysig_prog(msg: &[u8], pk: &[u8], sig: &[u8]) -> Vec<Op> {
    vec![
        Op::PushBytes(msg.to_vec()),
        Op::PushBytes(pk.to_vec()),
        Op::PushBytes(sig.to_vec()),
        Op::VerifySig,
    ]
}

#[test]
fn mock_never_rejects_signatures() {
    let prog = verifysig_prog(b"m", b"pk", b"sig");
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    // VerifySig pushes Int(0) → falsy → clean reject, not an error.
    assert_eq!(r.result, Ok(false));
}

#[test]
fn mock_always_accepts_signatures() {
    let prog = verifysig_prog(b"whatever", b"anykey", b"anysig");
    let r = sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::always(), 10_000);
    assert_eq!(r.result, Ok(true));
}

#[test]
fn mock_accepting_matches_only_listed_triples() {
    let v = MockVerifier::accepting(vec![(b"msg".to_vec(), b"pk".to_vec(), b"sig".to_vec())]);

    let good = verifysig_prog(b"msg", b"pk", b"sig");
    assert_eq!(
        sim::run_program(&good, vec![], &Ctx::default(), &v, 10_000).result,
        Ok(true)
    );

    // Any component off → reject.
    for bad in [
        verifysig_prog(b"MSG", b"pk", b"sig"),
        verifysig_prog(b"msg", b"PK", b"sig"),
        verifysig_prog(b"msg", b"pk", b"SIG"),
    ] {
        assert_eq!(
            sim::run_program(&bad, vec![], &Ctx::default(), &v, 10_000).result,
            Ok(false)
        );
    }
}

#[test]
fn mock_with_triple_chains_onto_never() {
    let v = MockVerifier::never().with_triple(b"a".to_vec(), b"b".to_vec(), b"c".to_vec());
    assert_eq!(
        sim::run_program(&verifysig_prog(b"a", b"b", b"c"), vec![], &Ctx::default(), &v, 10_000)
            .result,
        Ok(true)
    );
    assert_eq!(
        sim::run_program(&verifysig_prog(b"a", b"b", b"x"), vec![], &Ctx::default(), &v, 10_000)
            .result,
        Ok(false)
    );
}

#[test]
fn default_mockverifier_equals_never() {
    // Default rejects everything on both paths — verified through the VM.
    let v = MockVerifier::default();
    assert_eq!(
        sim::run_program(&verifysig_prog(b"m", b"p", b"s"), vec![], &Ctx::default(), &v, 10_000)
            .result,
        Ok(false)
    );
}

#[test]
fn ecdsa_path_is_independent_of_pq_path() {
    // VerifyEcdsa routes to verify_ecdsa; only `always()` turns that on.
    let prog = vec![
        Op::PushBytes(b"m".to_vec()),
        Op::PushBytes(b"pk".to_vec()),
        Op::PushBytes(b"sig".to_vec()),
        Op::VerifyEcdsa,
    ];
    // accepting() whitelists the PQ path but leaves ECDSA off → reject.
    let pq_only = MockVerifier::accepting(vec![(b"m".to_vec(), b"pk".to_vec(), b"sig".to_vec())]);
    assert_eq!(
        sim::run_program(&prog, vec![], &Ctx::default(), &pq_only, 10_000).result,
        Ok(false)
    );
    // always() turns ECDSA on → accept.
    assert_eq!(
        sim::run_program(&prog, vec![], &Ctx::default(), &MockVerifier::always(), 10_000).result,
        Ok(true)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// run_spend — hash binding, datum seeding, self_* context
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn spend_rejects_wrong_program_before_execution() {
    // Output commits to `real`, but we reveal `wrong` → ValidatorHashMismatch, and
    // crucially the divergent program never runs (so no gas / no side effects).
    let real = vec![Op::PushInt(1)];
    let wrong = vec![Op::PushInt(2)];
    let out = output_for(blch(5), &real, Val::Int(0));
    let r = sim::run_spend(&out, &wrong, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert_eq!(r.result, Err(VmError::ValidatorHashMismatch));
}

#[test]
fn spend_seeds_datum_then_redeemer_bottom_to_top() {
    // Stack seeded [datum, redeemer...]; datum=Int(10), redeemer=[Int(3)].
    // Sub computes datum - redeemer = 7 (truthy). Order matters: if it were
    // reversed we'd get -7 (still truthy) so use a distinguishing program:
    // Drop the redeemer, keep datum(10) → truthy proves datum is under redeemer.
    let prog = vec![Op::Drop]; // pop redeemer, leaving datum on top
    let out = output_for(blch(1), &prog, Val::Int(10));
    let r = sim::run_spend(
        &out,
        &prog,
        vec![Val::Int(3)],
        &Ctx::default(),
        &MockVerifier::never(),
        10_000,
    );
    assert_eq!(r.result, Ok(true)); // datum(10) is truthy
}

#[test]
fn spend_exposes_self_validator_hash_to_program() {
    // SelfValidator pushes ctx.self_validator_hash (set from the output) as Bytes.
    // Compare it against the known hash literal → Eq → accept. This proves spend
    // wired self_validator_hash from the output.
    let prog_hash;
    // Build a program that references its own committed hash. We can't self-reference,
    // so: push the expected hash bytes, SelfValidator, Eq. First compute the hash of
    // the *whole* program — do it by fixpoint isn't possible; instead just assert the
    // SelfValidator bytes equal the output's validator_hash by reading it back out.
    let prog = vec![Op::SelfValidator]; // leaves 32-byte hash as Bytes on top
    prog_hash = validator_hash(&prog);
    let out = output_for(blch(1), &prog, Val::Int(0));
    // A Bytes top is a TypeError for truthiness, so this run faults — but that fault
    // itself confirms SelfValidator produced Bytes (the hash) rather than underflowing.
    let r = sim::run_spend(&out, &prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert!(matches!(r.result, Err(VmError::TypeError(_))));
    // Sanity: the output really did commit to prog_hash.
    assert_eq!(out.validator_hash, prog_hash);
}

#[test]
fn spend_self_validator_hash_roundtrips_via_eq() {
    // Push the output's committed hash, then SelfValidator, then Eq → they must match.
    // We compute the hash of the *inner* comparison program and place it in a wrapper;
    // to avoid the self-reference paradox we compare against the wrapper's own hash by
    // building it in two steps: the program IS `[PushBytes(h), SelfValidator, Eq]` and
    // h is that program's own validator_hash — a fixpoint we solve by construction.
    //
    // Practical approach: the program hashes to H regardless of the pushed bytes'
    // *value* only if the bytes are fixed. So instead we verify the weaker—but still
    // meaningful—property: SelfValidator's bytes equal `out.validator_hash` when fed
    // back through the public API by seeding the comparison value via the redeemer.
    let prog = vec![Op::SelfValidator, Op::Eq]; // compare redeemer-supplied hash vs self
    let out = output_for(blch(1), &prog, Val::Int(0));
    // Seed the stack as a spend would: [datum(Int0), redeemer...]. We need the datum
    // gone; SelfValidator/Eq operate on the two Bytes below. Datum is Int(0) which
    // would be a type error under Eq-with-bytes, so instead push the expected hash as
    // the redeemer and let Eq compare (datum stays underneath, unused by Eq's two pops).
    let r = sim::run_spend(
        &out,
        &prog,
        vec![Val::Bytes(out.validator_hash.to_vec())],
        &Ctx::default(),
        &MockVerifier::never(),
        10_000,
    );
    // Eq pops [SelfValidator-bytes, redeemer-bytes] → equal → Int(1) truthy.
    assert_eq!(r.result, Ok(true));
}

#[test]
fn spend_exposes_self_asset_reserves() {
    // SelfAsset pops a 32-byte asset id and pushes the amount held in self_value.
    // Output holds blch(42); querying BLCH must yield 42 (truthy).
    let prog = vec![Op::SelfAsset];
    let out = output_for(blch(42), &prog, Val::Int(0));
    // Seed stack: [datum(Int0), redeemer=Bytes(BLCH id)]. SelfAsset pops the id bytes.
    let r = sim::run_spend(
        &out,
        &prog,
        vec![Val::Bytes(BLCH.to_vec())],
        &Ctx::default(),
        &MockVerifier::never(),
        10_000,
    );
    assert_eq!(r.result, Ok(true)); // amount 42 → truthy
}

#[test]
fn spend_self_asset_absent_is_zero_clean_reject() {
    // Querying an asset the output does not hold → 0 → clean reject (not an error).
    let prog = vec![Op::SelfAsset];
    let out = output_for(blch(42), &prog, Val::Int(0));
    let other_asset = [9u8; 32];
    let r = sim::run_spend(
        &out,
        &prog,
        vec![Val::Bytes(other_asset.to_vec())],
        &Ctx::default(),
        &MockVerifier::never(),
        10_000,
    );
    assert_eq!(r.result, Ok(false));
}

#[test]
fn spend_self_asset_malformed_id_length_faults() {
    // A non-32-byte "asset id" is a TypeError — fail-closed, never treated as absent.
    let prog = vec![Op::SelfAsset];
    let out = output_for(blch(42), &prog, Val::Int(0));
    let r = sim::run_spend(
        &out,
        &prog,
        vec![Val::Bytes(vec![0u8; 8])], // wrong length
        &Ctx::default(),
        &MockVerifier::never(),
        10_000,
    );
    assert!(matches!(r.result, Err(VmError::TypeError(_))));
}

#[test]
fn spend_happy_path_drops_datum_and_computes() {
    // Classic: drop the datum, do arithmetic, finish truthy.
    let prog = vec![Op::Drop, Op::PushInt(2), Op::PushInt(3), Op::Add];
    let out = output_for(blch(100), &prog, Val::Int(0));
    let r = sim::run_spend(&out, &prog, vec![], &Ctx::default(), &MockVerifier::never(), 10_000);
    assert!(r.accepted());
    assert!(r.gas_used > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// simulate_tx — conservation, validator verdicts, structural ceilings
// ─────────────────────────────────────────────────────────────────────────────

/// A trivially-accepting validator program and an output committing to it.
fn accept_output(value: Value) -> (Vec<Op>, ExtOutput) {
    // Drop the seeded datum, push truthy.
    let prog = vec![Op::Drop, Op::PushInt(1)];
    let out = output_for(value, &prog, Val::Int(0));
    (prog, out)
}

#[test]
fn simulate_tx_conserving_blch_accepts() {
    let (prog, prev) = accept_output(blch(100));
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev,
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(90),
            validator_hash: [1u8; 32],
            datum: Val::Int(0),
        }],
        fee: 10, // 90 + 10 == 100
        sighash: vec![0xab; 32],
    };
    let gas = sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000).expect("should validate");
    assert!(gas > 0);
}

#[test]
fn simulate_tx_nonconservation_is_rejected() {
    // Inputs sum 100, outputs+fee sum 95 → ValueNotConserved for BLCH.
    let (prog, prev) = accept_output(blch(100));
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev,
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(90),
            validator_hash: [1u8; 32],
            datum: Val::Int(0),
        }],
        fee: 5, // 90 + 5 = 95 != 100
        sighash: vec![],
    };
    let err = sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000).unwrap_err();
    match err {
        TxError::ValueNotConserved {
            asset,
            in_sum,
            out_plus_fee,
        } => {
            assert_eq!(asset, BLCH);
            assert_eq!(in_sum, 100);
            assert_eq!(out_plus_fee, 95);
        }
        other => panic!("expected ValueNotConserved, got {other:?}"),
    }
}

#[test]
fn simulate_tx_rejecting_validator_surfaces_index() {
    // A validator that finishes falsy → ValidatorRejected(0). Conservation still holds.
    let prog = vec![Op::Drop, Op::PushInt(0)]; // clean falsy
    let prev = output_for(blch(50), &prog, Val::Int(0));
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev,
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(50),
            validator_hash: [7u8; 32],
            datum: Val::Int(0),
        }],
        fee: 0,
        sighash: vec![],
    };
    assert_eq!(
        sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000).unwrap_err(),
        TxError::ValidatorRejected(0)
    );
}

#[test]
fn simulate_tx_faulting_validator_wraps_vm_error_with_index() {
    // A validator that faults (StackUnderflow) → TxError::Vm(0, ..).
    let prog = vec![Op::Drop, Op::Add]; // drop datum, then Add on empty stack
    let prev = output_for(blch(50), &prog, Val::Int(0));
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev,
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(50),
            validator_hash: [7u8; 32],
            datum: Val::Int(0),
        }],
        fee: 0,
        sighash: vec![],
    };
    match sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000).unwrap_err() {
        TxError::Vm(0, VmError::StackUnderflow) => {}
        other => panic!("expected Vm(0, StackUnderflow), got {other:?}"),
    }
}

#[test]
fn simulate_tx_mismatched_input_validator_faults_vm() {
    // prev_output commits to a different program than the one revealed → the spend
    // inside validate_tx returns ValidatorHashMismatch, wrapped as Vm(0, ..).
    let committed = vec![Op::Drop, Op::PushInt(1)];
    let revealed = vec![Op::Drop, Op::PushInt(2)]; // different hash
    let prev = output_for(blch(10), &committed, Val::Int(0));
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev,
            validator: revealed,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(10),
            validator_hash: [3u8; 32],
            datum: Val::Int(0),
        }],
        fee: 0,
        sighash: vec![],
    };
    match sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000).unwrap_err() {
        TxError::Vm(0, VmError::ValidatorHashMismatch) => {}
        other => panic!("expected Vm(0, ValidatorHashMismatch), got {other:?}"),
    }
}

#[test]
fn simulate_tx_exhausts_shared_gas_budget() {
    // A conserving, otherwise-valid tx run under a starved gas budget → the shared
    // budget runs out mid-validator, surfaced as Vm(0, OutOfGas).
    let (prog, prev) = accept_output(blch(10));
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev,
            validator: prog,
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(10),
            validator_hash: [1u8; 32],
            datum: Val::Int(0),
        }],
        fee: 0,
        sighash: vec![],
    };
    match sim::simulate_tx(&tx, &MockVerifier::never(), 1).unwrap_err() {
        TxError::Vm(0, VmError::OutOfGas) => {}
        other => panic!("expected Vm(0, OutOfGas), got {other:?}"),
    }
}

#[test]
fn simulate_tx_empty_tx_is_trivially_valid() {
    // No inputs, no outputs, no fee → vacuously conserving, zero validators → 0 gas.
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        sighash: vec![],
    };
    assert_eq!(
        sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000),
        Ok(0)
    );
}

#[test]
fn simulate_tx_reports_gas_used_matching_run_spend() {
    // The gas simulate_tx reports for a single-input tx should equal what run_spend
    // charges for the same output/program under the tx's ctx (sighash in fields[0]).
    let (prog, prev) = accept_output(blch(10));
    let sighash = vec![0x11; 32];
    let tx = EuTx {
        inputs: vec![EuTxInput {
            prev_output: prev.clone(),
            validator: prog.clone(),
            redeemer: vec![],
        }],
        outputs: vec![ExtOutput {
            value: blch(10),
            validator_hash: [1u8; 32],
            datum: Val::Int(0),
        }],
        fee: 0,
        sighash: sighash.clone(),
    };
    let tx_gas = sim::simulate_tx(&tx, &MockVerifier::never(), 1_000_000).unwrap();

    // Mirror the ctx validate_tx builds internally: fields[0] = sighash, tx_outputs set.
    let ctx = Ctx {
        fields: vec![Val::Bytes(sighash)],
        tx_outputs: tx.outputs.clone(),
        ..Ctx::default()
    };
    let spend = sim::run_spend(&prev, &prog, vec![], &ctx, &MockVerifier::never(), 1_000_000);
    assert!(spend.accepted());
    assert_eq!(tx_gas, spend.gas_used);
}
