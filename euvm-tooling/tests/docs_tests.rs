//! Integration tests for the `docs` component (`DOCS.md` — the developer guide &
//! opcode reference), driven entirely through the crate's **public** API from
//! outside the crate.
//!
//! `DOCS.md` is Markdown, not a Rust module, so "testing the docs component" means
//! one thing: proving that every factual and behavioral claim the guide makes is
//! actually true of the shipped API. If a documented gas number, stack effect, tag
//! byte, error, or code walkthrough drifts from the real `bloch-euvm` / `euvm-tooling`
//! surface, one of these tests fails — the docs cannot silently lie.
//!
//! The tests are grouped by the section of `DOCS.md` they pin down. Reject-cases and
//! malformed input (the "fail-closed" claims) are exercised as heavily as accept-cases.
//!
//! NOTE ON A DOC/API DISCREPANCY these tests encode: `DOCS.md` §6/§7 show
//! `TxBuilder::ext_output(...)` (an associated fn). The real API exposes `ext_output`
//! as a FREE function `euvm_tooling::tx::ext_output`. These tests use the real path.

use euvm_tooling::asm::Asm;
use euvm_tooling::encode::{self, EncodeError};
use euvm_tooling::euvm::{self, Ctx, ExtOutput, Op, SigVerifier, TxError, Val, VmError};
use euvm_tooling::sim::{self, MockVerifier};
use euvm_tooling::tx::{self, TxBuilder};

use sha2::{Digest, Sha256};

/// Local reference SHA-256d, independent of the VM, to cross-check `validator_hash`
/// and to derive hash-lock commitments in the walkthrough test.
fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(Sha256::digest(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ───────────────────────────────────────────────────────────────────────────
// §1–2  The mental model & value types
// ───────────────────────────────────────────────────────────────────────────

/// §2: `BLCH` is the all-zero asset id; `blch(n)` == `{BLCH: n}`, but an EMPTY map
/// when `n == 0`; `value_get` returns 0 for an absent asset.
#[test]
fn doc_s2_value_helpers_and_blch_zero_is_empty() {
    assert_eq!(euvm::BLCH, [0u8; 32]);

    let five = euvm::blch(5);
    assert_eq!(euvm::value_get(&five, &euvm::BLCH), 5);
    assert_eq!(five.len(), 1);

    // The documented edge: n == 0 yields an EMPTY bundle, not {BLCH: 0}.
    let zero = euvm::blch(0);
    assert!(zero.is_empty());
    assert_eq!(euvm::value_get(&zero, &euvm::BLCH), 0);

    // Absent native asset → 0, no panic.
    let some_asset = [7u8; 32];
    assert_eq!(euvm::value_get(&five, &some_asset), 0);
}

/// §2: truthiness rules. `Int(n)` truthy iff `n != 0`; a program that finishes with
/// a `Bytes` on top has NO truthiness and faults with the documented `TypeError`.
#[test]
fn doc_s2_truthiness_int_and_bytes_typeerror() {
    let ctx = Ctx::default();
    let v = MockVerifier::never();

    // Int(1) truthy → accept; Int(0) falsy → clean reject (not an error).
    assert_eq!(
        sim::run_program(&[Op::PushInt(1)], vec![], &ctx, &v, 1_000).result,
        Ok(true)
    );
    assert_eq!(
        sim::run_program(&[Op::PushInt(0)], vec![], &ctx, &v, 1_000).result,
        Ok(false)
    );

    // A Bytes on top of the final stack is a TypeError (the exact documented message).
    assert_eq!(
        sim::run_program(&[Op::PushBytes(vec![1])], vec![], &ctx, &v, 1_000).result,
        Err(VmError::TypeError("expected Int for truthiness"))
    );
}

// ───────────────────────────────────────────────────────────────────────────
// §3  Opcode reference — stack effects
// ───────────────────────────────────────────────────────────────────────────

fn run_ok(program: &[Op], initial: Vec<Val>) -> Result<bool, VmError> {
    let ctx = Ctx::default();
    let v = MockVerifier::never();
    sim::run_program(program, initial, &ctx, &v, 100_000).result
}

/// §3: arithmetic (`Add`/`Sub`/`Mul`) computes checked `i128`; the results feed a
/// following `Eq`/`PushInt` round-trip so the numeric value is actually pinned.
#[test]
fn doc_s3_arithmetic_values() {
    // 2 + 3 == 5
    assert_eq!(
        run_ok(
            &[Op::PushInt(2), Op::PushInt(3), Op::Add, Op::PushInt(5), Op::Eq],
            vec![]
        ),
        Ok(true)
    );
    // 5 - 3 == 2
    assert_eq!(
        run_ok(
            &[Op::PushInt(5), Op::PushInt(3), Op::Sub, Op::PushInt(2), Op::Eq],
            vec![]
        ),
        Ok(true)
    );
    // 4 * 5 == 20
    assert_eq!(
        run_ok(
            &[Op::PushInt(4), Op::PushInt(5), Op::Mul, Op::PushInt(20), Op::Eq],
            vec![]
        ),
        Ok(true)
    );
}

/// §3: `Overflow` on checked-arithmetic wrap — fail-closed, never a silent wrap.
#[test]
fn doc_s3_arithmetic_overflow_is_fail_closed() {
    assert_eq!(
        run_ok(&[Op::PushInt(i128::MAX), Op::PushInt(1), Op::Add], vec![]),
        Err(VmError::Overflow)
    );
    assert_eq!(
        run_ok(&[Op::PushInt(i128::MAX), Op::PushInt(2), Op::Mul], vec![]),
        Err(VmError::Overflow)
    );
}

/// §3: `Eq` is structural equality over `Int` OR `Bytes`; `Lt` is Ints-only and
/// `TypeError`s on `Bytes`; `Not` is logical negation of an `Int`.
#[test]
fn doc_s3_eq_lt_not() {
    // Eq on Bytes: equal → 1, unequal → 0.
    assert_eq!(
        run_ok(&[Op::PushBytes(vec![1, 2]), Op::PushBytes(vec![1, 2]), Op::Eq], vec![]),
        Ok(true)
    );
    assert_eq!(
        run_ok(&[Op::PushBytes(vec![1, 2]), Op::PushBytes(vec![9]), Op::Eq], vec![]),
        Ok(false)
    );

    // Lt on Ints: 1 < 2 → true.
    assert_eq!(run_ok(&[Op::PushInt(1), Op::PushInt(2), Op::Lt], vec![]), Ok(true));
    // Lt on Bytes → TypeError (documented "Ints only").
    assert_eq!(
        run_ok(&[Op::PushBytes(vec![1]), Op::PushBytes(vec![2]), Op::Lt], vec![]),
        Err(VmError::TypeError("expected Int"))
    );

    // Not: 0 → 1, nonzero → 0.
    assert_eq!(run_ok(&[Op::PushInt(0), Op::Not], vec![]), Ok(true));
    assert_eq!(run_ok(&[Op::PushInt(5), Op::Not], vec![]), Ok(false));
}

/// §3: stack-shuffling ops. `Dup`, `Drop`, `Swap`, and `Pick(0) == Dup` /
/// `Pick(1)` copy-from-depth, verified by their effect on a subsequent computation.
#[test]
fn doc_s3_stack_shuffling() {
    // Dup: 5 == 5
    assert_eq!(run_ok(&[Op::PushInt(5), Op::Dup, Op::Eq], vec![]), Ok(true));
    // Drop: [1,0] Drop → top 1 (truthy); [0,1] Drop → top 0 (falsy).
    assert_eq!(run_ok(&[Op::PushInt(1), Op::PushInt(0), Op::Drop], vec![]), Ok(true));
    assert_eq!(run_ok(&[Op::PushInt(0), Op::PushInt(1), Op::Drop], vec![]), Ok(false));
    // Swap changes operand order: [3,10] Swap → [10,3], Sub == 7.
    assert_eq!(
        run_ok(
            &[Op::PushInt(3), Op::PushInt(10), Op::Swap, Op::Sub, Op::PushInt(7), Op::Eq],
            vec![]
        ),
        Ok(true)
    );
    // Pick(0) == Dup.
    assert_eq!(run_ok(&[Op::PushInt(5), Op::Pick(0), Op::Eq], vec![]), Ok(true));
    // Pick(1) copies the element one below the top to the top.
    assert_eq!(run_ok(&[Op::PushInt(9), Op::PushInt(0), Op::Pick(1)], vec![]), Ok(true));
    // Pick underflow → StackUnderflow (fail-closed).
    assert_eq!(run_ok(&[Op::PushInt(1), Op::Pick(5)], vec![]), Err(VmError::StackUnderflow));
}

/// §3: `Size` pushes the byte-length of the top `Bytes` as an `Int`.
#[test]
fn doc_s3_size() {
    assert_eq!(
        run_ok(&[Op::PushBytes(vec![0u8; 4]), Op::Size, Op::PushInt(4), Op::Eq], vec![]),
        Ok(true)
    );
    // Size on an Int is a TypeError (expects Bytes).
    assert_eq!(
        run_ok(&[Op::PushInt(1), Op::Size], vec![]),
        Err(VmError::TypeError("expected Bytes"))
    );
}

/// §3: `Sha256d` matches the crate's independent double-SHA-256 and yields 32 bytes.
#[test]
fn doc_s3_sha256d_matches_reference_and_len32() {
    let preimage = b"abc".to_vec();
    let expect = sha256d(&preimage).to_vec();
    // Program: hash the top, then Eq against the reference hash → truthy.
    assert_eq!(
        run_ok(&[Op::Sha256d, Op::PushBytes(expect.clone()), Op::Eq], vec![Val::Bytes(preimage.clone())]),
        Ok(true)
    );
    // Output width is 32 bytes.
    assert_eq!(
        run_ok(&[Op::Sha256d, Op::Size, Op::PushInt(32), Op::Eq], vec![Val::Bytes(preimage)]),
        Ok(true)
    );
}

/// §3: context introspection. `CtxField(i)` reads `ctx.fields[i]` and faults
/// `BadCtxField(i)` when out of bounds; `TxOutDatum(i)` faults `BadTxOut(i)`;
/// `SelfValidator` pushes a 32-byte hash; `SelfAsset` reads the spent output's reserves.
#[test]
fn doc_s3_context_ops_and_oob_faults() {
    let v = MockVerifier::never();

    // CtxField(0) present → the pushed Int(1) is truthy.
    let ctx = Ctx { fields: vec![Val::Int(1)], ..Default::default() };
    assert_eq!(sim::run_program(&[Op::CtxField(0)], vec![], &ctx, &v, 1_000).result, Ok(true));

    // CtxField out of bounds → BadCtxField (documented, fail-closed).
    let empty = Ctx::default();
    assert_eq!(
        sim::run_program(&[Op::CtxField(5)], vec![], &empty, &v, 1_000).result,
        Err(VmError::BadCtxField(5))
    );
    // TxOutDatum out of bounds → BadTxOut.
    assert_eq!(
        sim::run_program(&[Op::TxOutDatum(0)], vec![], &empty, &v, 1_000).result,
        Err(VmError::BadTxOut(0))
    );

    // SelfValidator pushes a 32-byte Bytes.
    assert_eq!(
        sim::run_program(
            &[Op::SelfValidator, Op::Size, Op::PushInt(32), Op::Eq],
            vec![],
            &empty,
            &v,
            1_000
        )
        .result,
        Ok(true)
    );

    // SelfAsset: pop a 32-byte asset id → push its amount in self_value.
    let ctx = Ctx { self_value: euvm::blch(500), ..Default::default() };
    assert_eq!(
        sim::run_program(
            &[Op::PushBytes(euvm::BLCH.to_vec()), Op::SelfAsset, Op::PushInt(500), Op::Eq],
            vec![],
            &ctx,
            &v,
            1_000
        )
        .result,
        Ok(true)
    );
    // SelfAsset with a non-32-byte "asset id" → fail-closed TypeError.
    assert_eq!(
        sim::run_program(&[Op::PushBytes(vec![0u8; 5]), Op::SelfAsset], vec![], &ctx, &v, 1_000).result,
        Err(VmError::TypeError("asset id must be 32 bytes"))
    );
}

/// §3: signatures push a boolean and do NOT abort; `Verify` DOES abort with `Assert`
/// on a falsy value; `VerifyEcdsa` defaults false unless the verifier opts in.
#[test]
fn doc_s3_signatures_and_verify() {
    let ctx = Ctx::default();
    // Stack seeded bottom→top as [msg, pk, sig] (VerifySig pops sig, pk, msg).
    let seed = || vec![Val::Bytes(b"m".to_vec()), Val::Bytes(b"pk".to_vec()), Val::Bytes(b"sig".to_vec())];

    // never() → sig invalid → VerifySig pushes 0 (a clean reject, not a fault).
    assert_eq!(
        sim::run_program(&[Op::VerifySig], seed(), &ctx, &MockVerifier::never(), 5_000).result,
        Ok(false)
    );
    // always() → pushes 1.
    assert_eq!(
        sim::run_program(&[Op::VerifySig], seed(), &ctx, &MockVerifier::always(), 5_000).result,
        Ok(true)
    );

    // VerifyEcdsa defaults false: never()/accepting() leave the ECDSA path off.
    assert_eq!(
        sim::run_program(&[Op::VerifyEcdsa], seed(), &ctx, &MockVerifier::never(), 5_000).result,
        Ok(false)
    );
    assert_eq!(
        sim::run_program(&[Op::VerifyEcdsa], seed(), &ctx, &MockVerifier::always(), 5_000).result,
        Ok(true)
    );

    // Verify on falsy → Assert abort (a VmError, documented in §8).
    assert_eq!(
        sim::run_program(&[Op::Verify], vec![Val::Int(0)], &ctx, &MockVerifier::never(), 1_000).result,
        Err(VmError::Assert)
    );
    // Verify on a Bytes → TypeError (no truthiness).
    assert_eq!(
        sim::run_program(&[Op::Verify], vec![Val::Bytes(vec![1])], &ctx, &MockVerifier::never(), 1_000).result,
        Err(VmError::TypeError("expected Int for truthiness"))
    );
    // Verify on truthy passes; the trailing PushInt(1) leaves an accept.
    assert_eq!(
        sim::run_program(&[Op::Verify, Op::PushInt(1)], vec![Val::Int(1)], &ctx, &MockVerifier::never(), 1_000).result,
        Ok(true)
    );
}

// ───────────────────────────────────────────────────────────────────────────
// §4  The gas model — the exact documented numbers
// ───────────────────────────────────────────────────────────────────────────

/// §4: the length-independent base schedule from `gas_cost`.
#[test]
fn doc_s4_gas_cost_base_schedule() {
    assert_eq!(euvm::gas_cost(&Op::VerifySig), 1000);
    assert_eq!(euvm::gas_cost(&Op::VerifyEcdsa), 1000);
    assert_eq!(euvm::gas_cost(&Op::Sha256d), 60);
    assert_eq!(euvm::gas_cost(&Op::Shake256), 60);
    assert_eq!(euvm::gas_cost(&Op::Add), 4);
    assert_eq!(euvm::gas_cost(&Op::Sub), 4);
    assert_eq!(euvm::gas_cost(&Op::Mul), 4);
    // "everything else → 1"
    assert_eq!(euvm::gas_cost(&Op::PushInt(0)), 1);
    assert_eq!(euvm::gas_cost(&Op::Dup), 1);
    assert_eq!(euvm::gas_cost(&Op::Eq), 1);
    assert_eq!(euvm::gas_cost(&Op::CtxField(0)), 1);
}

/// §4: `sim::run_program` reports `gas_used = gas_limit − remaining`, and the actual
/// per-op charge is base + one gas per 32-byte word for byte-copying/hashing ops.
#[test]
fn doc_s4_actual_gas_charges() {
    let ctx = Ctx::default();
    let v = MockVerifier::never();

    // A single PushInt costs exactly 1.
    let r = sim::run_program(&[Op::PushInt(1)], vec![], &ctx, &v, 1_000);
    assert_eq!(r.gas_used, 1);
    assert_eq!(r.gas_limit, 1_000);
    assert_eq!(r.gas_remaining(), 999);

    // Composite: PushInt(1) + PushInt(2) + Add(4) + PushInt(3) + Eq(1) = 8.
    let r = sim::run_program(
        &[Op::PushInt(1), Op::PushInt(2), Op::Add, Op::PushInt(3), Op::Eq],
        vec![],
        &ctx,
        &v,
        1_000,
    );
    assert_eq!(r.result, Ok(true));
    assert_eq!(r.gas_used, 8);

    // The doc's worked example: hashing a 100-byte blob costs 60 + ⌈100/32⌉ = 64.
    // (The op leaves 32 Bytes on top, so the run itself faults on final truthiness —
    // but the gas charge for Sha256d is what we are pinning.)
    let r = sim::run_program(&[Op::Sha256d], vec![Val::Bytes(vec![0u8; 100])], &ctx, &v, 10_000);
    assert_eq!(r.gas_used, 64);
    assert_eq!(r.result, Err(VmError::TypeError("expected Int for truthiness")));

    // PushBytes length term: 32 bytes → 1 + 1 = 2; 33 bytes → 1 + 2 = 3.
    let r = sim::run_program(&[Op::PushBytes(vec![0u8; 32])], vec![], &ctx, &v, 10_000);
    assert_eq!(r.gas_used, 2);
    let r = sim::run_program(&[Op::PushBytes(vec![0u8; 33])], vec![], &ctx, &v, 10_000);
    assert_eq!(r.gas_used, 3);
}

/// §4: gas is charged up-front and underflow is `OutOfGas` (fail-closed).
#[test]
fn doc_s4_out_of_gas() {
    let ctx = Ctx::default();
    let v = MockVerifier::never();
    // Program costs 1+1+4 = 6; a budget of 5 cannot pay for the Add.
    let prog = [Op::PushInt(1), Op::PushInt(2), Op::Add];
    assert_eq!(sim::run_program(&prog, vec![], &ctx, &v, 5).result, Err(VmError::OutOfGas));
    // Exactly enough succeeds.
    assert_eq!(sim::run_program(&prog, vec![], &ctx, &v, 6).result, Ok(true));
}

/// §4: the hard ceiling constants carry the documented values, and a program past
/// `MAX_PROGRAM_OPS` is rejected `ProgramTooLarge` before executing an op.
#[test]
fn doc_s4_ceilings() {
    assert_eq!(euvm::MAX_OPERAND_BYTES, 16 * 1024 * 1024);
    assert_eq!(euvm::MAX_PROGRAM_OPS, 100_000);
    assert_eq!(euvm::MAX_TOTAL_BYTES, 32 * 1024 * 1024);
    assert_eq!(euvm::MAX_TX_INPUTS, 1024);
    assert_eq!(euvm::MAX_TX_OUTPUTS, 1024);
    assert_eq!(euvm::MAX_TX_DISTINCT_ASSETS, 4096);
    assert_eq!(euvm::MAX_TX_BYTES, 1024 * 1024);

    let ctx = Ctx::default();
    let v = MockVerifier::never();
    let too_big: Vec<Op> = std::iter::repeat_with(|| Op::PushInt(1))
        .take(euvm::MAX_PROGRAM_OPS + 1)
        .collect();
    assert_eq!(
        sim::run_program(&too_big, vec![], &ctx, &v, u64::MAX).result,
        Err(VmError::ProgramTooLarge)
    );
}

/// §4: `fee_burn` — EIP-1559-style split, `burn_bps` capped at 10 000.
#[test]
fn doc_s4_fee_burn() {
    // 20% of 1000 burned (the harness's EUVM_BURN_BPS).
    assert_eq!(euvm::fee_burn(1_000, 2_000), (200, 800));
    // 0 bps → nothing burned.
    assert_eq!(euvm::fee_burn(1_000, 0), (0, 1_000));
    // Over-cap bps is clamped to 10 000 (100%): whole fee burned, miner gets 0.
    assert_eq!(euvm::fee_burn(1_000, 20_000), (1_000, 0));
}

// ───────────────────────────────────────────────────────────────────────────
// §5  The validator_hash binding rule + tag bytes
// ───────────────────────────────────────────────────────────────────────────

/// §5: `validator_hash(p) == SHA-256d(encode_program(p))`, cross-checked against an
/// independent double-SHA-256.
#[test]
fn doc_s5_validator_hash_is_sha256d_of_encoding() {
    let prog = vec![Op::PushInt(7), Op::Dup, Op::Add, Op::PushInt(14), Op::Eq];
    let encoded = euvm::encode_program(&prog);
    assert_eq!(euvm::validator_hash(&prog), sha256d(&encoded));
}

/// §5: identical programs share a hash; different programs differ; and because
/// `Op` has no `Eq`, `encode::program_to_hex` equality is the canonical compare path.
#[test]
fn doc_s5_program_identity_and_hex_compare() {
    let a = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
    let b = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
    let c = vec![Op::PushInt(1), Op::PushInt(3), Op::Add];

    assert_eq!(euvm::validator_hash(&a), euvm::validator_hash(&b));
    assert_ne!(euvm::validator_hash(&a), euvm::validator_hash(&c));

    assert_eq!(encode::program_to_hex(&a), encode::program_to_hex(&b));
    assert_ne!(encode::program_to_hex(&a), encode::program_to_hex(&c));
}

/// §5: revealing the wrong program is `ValidatorHashMismatch`, raised BEFORE any op
/// executes — even a program that would otherwise fault never runs.
#[test]
fn doc_s5_wrong_program_is_hash_mismatch_before_execution() {
    let real = vec![Op::PushInt(1)];
    // `wrong` would StackUnderflow on Drop if it ever ran — but it must not run.
    let wrong = vec![Op::Drop, Op::Drop, Op::Drop];
    let out = ExtOutput {
        value: euvm::blch(1),
        validator_hash: euvm::validator_hash(&real),
        datum: Val::Int(0),
    };
    let ctx = Ctx::default();
    let r = sim::run_spend(&out, &wrong, vec![], &ctx, &MockVerifier::never(), 10_000);
    assert_eq!(r.result, Err(VmError::ValidatorHashMismatch));
}

/// §5: the op tag-byte table and operand layout (`PushInt` = 0x01 + 16-byte LE i128;
/// `PushBytes` = 0x02 + u32 LE len + bytes; index ops = 1 byte).
#[test]
fn doc_s5_tag_bytes_and_operand_layout() {
    // Representative single-op encodings from the documented table.
    assert_eq!(euvm::encode_program(&[Op::Dup]), vec![0x10]);
    assert_eq!(euvm::encode_program(&[Op::Drop]), vec![0x11]);
    assert_eq!(euvm::encode_program(&[Op::Swap]), vec![0x12]);
    assert_eq!(euvm::encode_program(&[Op::Add]), vec![0x20]);
    assert_eq!(euvm::encode_program(&[Op::Eq]), vec![0x30]);
    assert_eq!(euvm::encode_program(&[Op::Sha256d]), vec![0x40]);
    assert_eq!(euvm::encode_program(&[Op::VerifySig]), vec![0x60]);
    assert_eq!(euvm::encode_program(&[Op::Verify]), vec![0x61]);
    assert_eq!(euvm::encode_program(&[Op::SelfValidator]), vec![0x73]);
    assert_eq!(euvm::encode_program(&[Op::SelfAsset]), vec![0x74]);

    // Index op carries a single u8.
    assert_eq!(euvm::encode_program(&[Op::Pick(3)]), vec![0x13, 3]);
    assert_eq!(euvm::encode_program(&[Op::CtxField(2)]), vec![0x50, 2]);
    assert_eq!(euvm::encode_program(&[Op::TxOutAsset(1)]), vec![0x75, 1]);

    // PushInt: 0x01 + i128 little-endian (16 bytes).
    let mut expect_pi = vec![0x01u8];
    expect_pi.extend_from_slice(&1i128.to_le_bytes());
    assert_eq!(euvm::encode_program(&[Op::PushInt(1)]), expect_pi);
    assert_eq!(euvm::encode_program(&[Op::PushInt(1)]).len(), 17);

    // PushBytes: 0x02 + u32 LE length + payload.
    assert_eq!(
        euvm::encode_program(&[Op::PushBytes(vec![0xaa, 0xbb])]),
        vec![0x02, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb]
    );
}

// ───────────────────────────────────────────────────────────────────────────
// §6  The tooling modules — the documented snippets behave as shown
// ───────────────────────────────────────────────────────────────────────────

/// §6 `asm`: the fluent builder produces a `Vec<Op>` and `hash()` == `validator_hash`.
#[test]
fn doc_s6_asm_builder_and_hash() {
    let pubkey = b"a-pubkey".to_vec();
    let pkh = sha256d(&pubkey).to_vec();

    let program = Asm::new()
        .push_bytes(pubkey.clone())
        .sha256d()
        .push_bytes(pkh.clone())
        .eq()
        .verify()
        .build();
    assert_eq!(program.len(), 5);

    let mut a = Asm::new();
    a.push_int(1);
    assert_eq!(a.hash(), euvm::validator_hash(&[Op::PushInt(1)]));
    assert_eq!(a.encode(), euvm::encode_program(&[Op::PushInt(1)]));
}

/// §6 `asm`: the `prog!` macro yields the same program as the equivalent builder.
#[test]
fn doc_s6_prog_macro_matches_builder() {
    let via_macro = euvm_tooling::prog![push_int(2), push_int(2), add(), push_int(4), eq(), verify()];
    let via_builder = Asm::new()
        .push_int(2)
        .push_int(2)
        .add()
        .push_int(4)
        .eq()
        .verify()
        .build();
    assert_eq!(via_macro.len(), 6);
    assert_eq!(encode::program_to_hex(&via_macro), encode::program_to_hex(&via_builder));
}

/// §6 `encode`: `parse_val` accepts the documented `int:` / `hex:` (and `bytes:`)
/// forms, and round-trips through `val_to_string`; malformed specs fail cleanly.
#[test]
fn doc_s6_encode_parse_val_roundtrip_and_rejects() {
    assert_eq!(encode::parse_val("int:42").unwrap(), Val::Int(42));
    assert_eq!(encode::parse_val("hex:ab12").unwrap(), Val::Bytes(vec![0xab, 0x12]));
    assert_eq!(encode::parse_val("bytes:ab12").unwrap(), Val::Bytes(vec![0xab, 0x12]));

    // Round-trip both variants.
    for v in [Val::Int(-999), Val::Bytes(vec![0, 1, 255])] {
        assert_eq!(encode::parse_val(&encode::val_to_string(&v)).unwrap(), v);
    }

    // Malformed → typed errors, never a panic.
    assert!(matches!(encode::parse_val("weird:x"), Err(EncodeError::BadValSpec(_))));
    assert!(matches!(encode::parse_val("int:notanumber"), Err(EncodeError::BadInt(_))));
}

/// §6 `encode`: hash hex round-trips, tolerates `0x`, and rejects a wrong length.
#[test]
fn doc_s6_encode_hash_hex() {
    let h = euvm::validator_hash(&[Op::PushInt(1), Op::PushInt(2), Op::Add]);
    let s = encode::hash_to_hex(&h);
    assert_eq!(s.len(), 64);
    assert_eq!(encode::hex_to_hash(&s).unwrap(), h);
    assert_eq!(encode::hex_to_hash(&format!("0x{s}")).unwrap(), h);
    // Wrong length is a fail-closed BadLength (not a truncation).
    assert!(matches!(encode::hex_to_hash("ab"), Err(EncodeError::BadLength(32, 1))));
    // Non-hex is BadHex.
    assert!(matches!(encode::hex_to_bytes("zz"), Err(EncodeError::BadHex(_))));
}

/// §6 `encode`: `decode_program` is the documented inverse of `encode_program`, with
/// a byte-exact round trip, plus the three documented decode failure modes.
#[test]
fn doc_s6_encode_decode_program_roundtrip_and_rejects() {
    let prog = vec![
        Op::PushInt(-7),
        Op::PushBytes(vec![0xde, 0xad, 0xbe, 0xef]),
        Op::Pick(3),
        Op::Sha256d,
        Op::CtxField(0),
        Op::TxOutAsset(2),
        Op::SelfValidator,
    ];
    let hexed = encode::program_to_hex(&prog);
    let back = encode::hex_to_program(&hexed).expect("decode");
    // Op has no Eq — compare via canonical encoding.
    assert_eq!(encode::program_to_hex(&back), hexed);

    // Unknown tag byte.
    assert!(matches!(encode::decode_program(&[0xff]), Err(EncodeError::UnknownTag(0xff))));
    // A PushInt tag whose 16-byte operand is truncated.
    assert!(matches!(encode::decode_program(&[0x01, 0x00]), Err(EncodeError::UnexpectedEof)));
    // A PushBytes length prefix claiming more than is present.
    assert!(matches!(
        encode::decode_program(&[0x02, 0x10, 0x00, 0x00, 0x00]),
        Err(EncodeError::OperandTooShort { .. })
    ));
}

/// §6 `sim`: the three `MockVerifier` construction modes behave as documented, and
/// `SimResult`'s accessors report accept / reject / error and the gas fields.
#[test]
fn doc_s6_sim_mockverifier_and_simresult() {
    let always = MockVerifier::always();
    assert!(always.verify(b"m", b"pk", b"s"));
    assert!(always.verify_ecdsa(b"m", b"pk", b"s"));

    let never = MockVerifier::never();
    assert!(!never.verify(b"m", b"pk", b"s"));
    assert!(!never.verify_ecdsa(b"m", b"pk", b"s"));

    let sel = MockVerifier::accepting(vec![(b"m".to_vec(), b"pk".to_vec(), b"s".to_vec())]);
    assert!(sel.verify(b"m", b"pk", b"s"));
    assert!(!sel.verify(b"m", b"pk", b"other"));

    let ctx = Ctx::default();
    let r = sim::run_program(&[Op::PushInt(1)], vec![], &ctx, &never, 1_000);
    assert!(r.accepted() && !r.rejected() && !r.errored());
    let r = sim::run_program(&[Op::PushInt(0)], vec![], &ctx, &never, 1_000);
    assert!(r.rejected() && !r.accepted() && !r.errored());
    // A program that finishes with an EMPTY final stack → EmptyResult (DOCS §"errors").
    // (`Drop` alone would underflow mid-execution — StackUnderflow — before the
    // end-of-program empty check; push-then-drop reaches that check with nothing left.)
    let r = sim::run_program(&[Op::PushInt(1), Op::Drop], vec![], &ctx, &never, 1_000);
    assert!(r.errored()); // empty final stack → EmptyResult
    assert_eq!(r.result, Err(VmError::EmptyResult));
}

/// §6 `tx`: `ext_output` binds `validator_hash = validator_hash(program)` so the
/// output and the program that must later be revealed can never desync. (Real API is
/// the free fn `tx::ext_output`, NOT `TxBuilder::ext_output` as the doc snippet shows.)
#[test]
fn doc_s6_tx_ext_output_binds_hash() {
    let program = vec![Op::PushInt(1)];
    let out = tx::ext_output(euvm::blch(50), &program, Val::Int(7));
    assert_eq!(out.validator_hash, euvm::validator_hash(&program));
    assert_eq!(euvm::value_get(&out.value, &euvm::BLCH), 50);
    assert_eq!(out.datum, Val::Int(7));

    // The builder wires every field through, and the revealed validator hashes back.
    let tx = TxBuilder::new()
        .sighash(b"sighash".to_vec())
        .fee(1)
        .spend_input(out.clone(), program.clone(), vec![Val::Int(42)])
        .output(tx::ext_output_blch(49, &program))
        .build();
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.fee, 1);
    assert_eq!(
        euvm::validator_hash(&tx.inputs[0].validator),
        tx.inputs[0].prev_output.validator_hash
    );
}

// ───────────────────────────────────────────────────────────────────────────
// §7  "Write your first contract" — the walkthrough, executed end to end
// ───────────────────────────────────────────────────────────────────────────

/// §7 Steps 1–2: assemble the hash-lock, then simulate it — the correct preimage is
/// accepted, a wrong preimage is a clean `Ok(false)` (not a fault), and the spend
/// costs more than the 60-gas Sha256d floor.
#[test]
fn doc_s7_hashlock_assemble_and_simulate() {
    let preimage = b"the-secret-preimage".to_vec();
    let lock = sha256d(&preimage);

    let program = Asm::new().sha256d().push_bytes(lock.to_vec()).eq().build();

    let v = MockVerifier::never();
    let ctx = Ctx::default();

    let ok = sim::run_program(&program, vec![Val::Bytes(preimage.clone())], &ctx, &v, 1_000);
    assert_eq!(ok.result, Ok(true));
    assert!(ok.gas_used > 60); // Sha256d(60+words) + PushBytes + Eq

    let bad = sim::run_program(&program, vec![Val::Bytes(b"wrong".to_vec())], &ctx, &v, 1_000);
    assert_eq!(bad.result, Ok(false));
}

/// §7 Step 3: lock 100 BLCH behind the hash-lock, build the unlocking tx (90 out +
/// 10 fee = 100, conserved), and validate the whole transaction through `simulate_tx`.
#[test]
fn doc_s7_hashlock_lock_and_spend_tx() {
    let preimage = b"the-secret-preimage".to_vec();
    let lock = sha256d(&preimage);
    let program = Asm::new().sha256d().push_bytes(lock.to_vec()).eq().build();

    let locked = tx::ext_output(euvm::blch(100), &program, Val::Bytes(lock.to_vec()));
    let spend_tx = TxBuilder::new()
        .spend_input(locked, program.clone(), vec![Val::Bytes(preimage.clone())])
        .output(tx::ext_output(euvm::blch(90), &program, Val::Int(0)))
        .fee(10)
        .sighash(b"sighash".to_vec())
        .build();

    let v = MockVerifier::never();
    let gas_used = sim::simulate_tx(&spend_tx, &v, 50_000).expect("valid spend");
    assert!(gas_used > 0);
}

// ───────────────────────────────────────────────────────────────────────────
// §8  Errors — the key distinctions the guide calls out
// ───────────────────────────────────────────────────────────────────────────

/// §8: a validator that RETURNS false surfaces as `TxError::ValidatorRejected(i)` —
/// it is NOT a `VmError`. (Value is conserved so only the validator can be at fault.)
#[test]
fn doc_s8_validator_rejected() {
    // Drop the datum, push 0 → the validator finishes falsy (Ok(false)).
    let program = vec![Op::Drop, Op::PushInt(0)];
    let locked = tx::ext_output(euvm::blch(100), &program, Val::Int(0));
    let tx = TxBuilder::new()
        .spend_input(locked, program.clone(), vec![])
        .output(tx::ext_output_blch(90, &program))
        .fee(10)
        .sighash(b"s".to_vec())
        .build();
    let v = MockVerifier::never();
    assert_eq!(sim::simulate_tx(&tx, &v, 50_000), Err(TxError::ValidatorRejected(0)));
}

/// §8: an assertion abort inside a validator surfaces as `TxError::Vm(i, Assert)`.
#[test]
fn doc_s8_vm_error_wraps_input_index() {
    // Drop the datum, push 0, Verify → aborts with Assert.
    let program = vec![Op::Drop, Op::PushInt(0), Op::Verify];
    let locked = tx::ext_output(euvm::blch(100), &program, Val::Int(0));
    let tx = TxBuilder::new()
        .spend_input(locked, program.clone(), vec![])
        .output(tx::ext_output_blch(90, &program))
        .fee(10)
        .sighash(b"s".to_vec())
        .build();
    let v = MockVerifier::never();
    assert_eq!(sim::simulate_tx(&tx, &v, 50_000), Err(TxError::Vm(0, VmError::Assert)));
}

/// §8 / §4: value that does not conserve is `TxError::ValueNotConserved` (checked
/// before validators; here the validator would pass, so conservation is the only fault).
#[test]
fn doc_s8_value_not_conserved() {
    let program = vec![Op::Drop, Op::PushInt(1)]; // always accepts
    let locked = tx::ext_output(euvm::blch(100), &program, Val::Int(0));
    // 90 out + 5 fee = 95 ≠ 100 in.
    let tx = TxBuilder::new()
        .spend_input(locked, program.clone(), vec![])
        .output(tx::ext_output_blch(90, &program))
        .fee(5)
        .sighash(b"s".to_vec())
        .build();
    let v = MockVerifier::never();
    match sim::simulate_tx(&tx, &v, 50_000) {
        Err(TxError::ValueNotConserved { asset, in_sum, out_plus_fee }) => {
            assert_eq!(asset, euvm::BLCH);
            assert_eq!(in_sum, 100);
            assert_eq!(out_plus_fee, 95);
        }
        other => panic!("expected ValueNotConserved, got {other:?}"),
    }
}

/// §8: an empty final stack is `EmptyResult`; a `Bytes` on top is a `TypeError`;
/// a hash mismatch is raised before execution. (Consolidated fail-closed roundup.)
#[test]
fn doc_s8_empty_result_and_type_error() {
    let ctx = Ctx::default();
    let v = MockVerifier::never();
    // Seed one value, Drop it → empty stack → EmptyResult.
    assert_eq!(
        sim::run_program(&[Op::Drop], vec![Val::Int(1)], &ctx, &v, 1_000).result,
        Err(VmError::EmptyResult)
    );
    // Underflow when popping from an empty stack.
    assert_eq!(
        sim::run_program(&[Op::Drop], vec![], &ctx, &v, 1_000).result,
        Err(VmError::StackUnderflow)
    );
}

/// §6 `tx`: `build_checked` enforces the structural ceilings; a well-formed small tx
/// passes it (the reject path — too many inputs/outputs — is bounded by consts in §4).
#[test]
fn doc_s6_tx_build_checked_accepts_small_tx() {
    let program = vec![Op::PushInt(1)];
    let locked = tx::ext_output(euvm::blch(10), &program, Val::Int(0));
    let res = TxBuilder::new()
        .spend_input(locked, program.clone(), vec![])
        .output(tx::ext_output_blch(9, &program))
        .fee(1)
        .build_checked();
    assert!(res.is_ok());
}

// ───────────────────────────────────────────────────────────────────────────
// §6/§7  The examples gallery the guide points at actually accepts its green paths
// ───────────────────────────────────────────────────────────────────────────

/// §6/§7: the referenced `examples` demos all accept their valid witness, confirming
/// the "assemble → simulate → build-tx" pipeline the docs describe end to end.
#[test]
fn doc_examples_demos_accept_green_paths() {
    use euvm_tooling::examples;
    assert_eq!(examples::demo_hashlock().result, Ok(true));
    assert_eq!(examples::demo_p2pkh().result, Ok(true));
    assert_eq!(examples::demo_multisig_n_of_m().result, Ok(true));
    assert_eq!(examples::demo_continuation_counter().result, Ok(true));
    assert_eq!(examples::demo_constant_product_amm().result, Ok(true));
    assert_eq!(examples::demo_absolute_timelock().result, Ok(true));
    assert_eq!(examples::demo_relative_timelock().result, Ok(true));
}

/// §7 "what to reach for next": the hash-lock reference program from `examples`
/// accepts the correct preimage and rejects a wrong one.
#[test]
fn doc_examples_hashlock_reference_accepts_and_rejects() {
    use euvm_tooling::examples;
    let preimage = b"open-sesame".to_vec();
    let program = examples::hashlock(sha256d(&preimage));
    let ctx = Ctx::default();
    let v = MockVerifier::never();
    assert_eq!(
        sim::run_program(&program, vec![Val::Bytes(preimage)], &ctx, &v, 10_000).result,
        Ok(true)
    );
    assert_eq!(
        sim::run_program(&program, vec![Val::Bytes(b"nope".to_vec())], &ctx, &v, 10_000).result,
        Ok(false)
    );
}

// ───────────────────────────────────────────────────────────────────────────
// §9  Foundation modules — the documented pointers resolve to the stated values
// ───────────────────────────────────────────────────────────────────────────

/// §9: `harness` activation-hook constants and gating carry the documented values.
#[test]
fn doc_s9_harness_constants() {
    use euvm_tooling::euvm::harness;
    assert_eq!(harness::EUVM_ACTIVATION_HEIGHT, 10);
    assert_eq!(harness::EUVM_BURN_BPS, 2_000);
    assert_eq!(harness::DEFAULT_GAS_CEILINGS.per_tx, 10_000_000);
    assert_eq!(harness::DEFAULT_GAS_CEILINGS.block, 100_000_000);
    // is_feature_active: height >= EUVM_ACTIVATION_HEIGHT.
    assert!(!harness::is_feature_active(9));
    assert!(harness::is_feature_active(10));
    assert!(harness::is_feature_active(11));
}

/// §9: `minting` — a policy's `policy_asset_id` equals its `validator_hash`.
#[test]
fn doc_s9_minting_policy_asset_id_is_validator_hash() {
    use euvm_tooling::euvm::minting;
    let policy = minting::fixed_supply_cap_policy(1_000);
    assert_eq!(minting::policy_asset_id(&policy), euvm::validator_hash(&policy));
}

/// §1/§9: the re-export path is real — `euvm_tooling::euvm` IS `bloch_euvm`, so the
/// canonical single path in the docs resolves to the VM's own items.
#[test]
fn doc_reexport_path_is_the_vm() {
    assert_eq!(euvm_tooling::euvm::BLCH, euvm::BLCH);
    let a = euvm_tooling::euvm::validator_hash(&[Op::PushInt(1)]);
    let b = euvm::validator_hash(&[Op::PushInt(1)]);
    assert_eq!(a, b);
}
