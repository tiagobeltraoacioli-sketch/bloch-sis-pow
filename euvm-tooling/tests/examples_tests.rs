//! Integration tests for the `examples` component — exercised from OUTSIDE the crate
//! (this file is compiled as its own crate, so it only touches the *public* surface:
//! `euvm_tooling::examples`, `euvm_tooling::sim`, and the re-exported `euvm_tooling::euvm`).
//!
//! Philosophy: **reject-cases matter as much as accept-cases.** Each headline contract
//! (N-of-M multisig, absolute/relative time-lock, minimal Ustav charter) plus the ported
//! foundation validators (P2PKH, hash-lock, continuation counter, constant-product AMM)
//! is probed on three axes:
//!   * green path — a valid witness must accept (`Ok(true)`),
//!   * clean reject — a wrong-but-well-formed witness must reject (`Ok(false)`),
//!   * fail-closed fault — malformed/degenerate input must *fault or reject*, never
//!     silently authorize (`Err(Assert)`, `StackUnderflow`, `BadCtxField`, `BadTxOut`,
//!     `TypeError`, `ValidatorHashMismatch`).
//! Plus determinism / round-trip identity of the compiled programs.

use euvm_tooling::euvm::{blch, validator_hash, AssetId, Ctx, ExtOutput, Op, Val, Value, VmError};
use euvm_tooling::examples;
use euvm_tooling::sim::{self, MockVerifier, SimResult};

use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers (the ones examples.rs keeps private — re-created here at arm's length)
// ─────────────────────────────────────────────────────────────────────────────

/// Double-SHA256 — matches `Op::Sha256d` and the `validator_hash` preimage convention.
fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(Sha256::digest(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Ctx carrying only the sighash in `fields[FIELD_SIGHASH = 0]`.
fn ctx_sig(sighash: &[u8]) -> Ctx {
    Ctx {
        fields: vec![Val::Bytes(sighash.to_vec())],
        ..Default::default()
    }
}

/// Ctx carrying the sighash and a block height in `fields[FIELD_HEIGHT = 1]`.
fn ctx_h(sighash: &[u8], height: i128) -> Ctx {
    Ctx {
        fields: vec![Val::Bytes(sighash.to_vec()), Val::Int(height)],
        ..Default::default()
    }
}

/// Ctx with a single continuation output at `tx_outputs[0]`.
fn ctx_out(out: ExtOutput) -> Ctx {
    Ctx {
        tx_outputs: vec![out],
        ..Default::default()
    }
}

fn value_of(pairs: &[(AssetId, u64)]) -> Value {
    pairs.iter().cloned().collect()
}

const SIGHASH: &[u8] = b"euvm-tooling::examples_tests::sighash";

fn run(program: &[Op], initial: Vec<Val>, ctx: &Ctx, v: &dyn euvm_tooling::euvm::SigVerifier) -> SimResult {
    sim::run_program(program, initial, ctx, v, 200_000)
}

// ═════════════════════════════════════════════════════════════════════════════
// (0) The public demos are all green (sanity that the cookbook accepts)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn all_demos_accept() {
    assert!(examples::demo_multisig_n_of_m().accepted(), "multisig demo");
    assert!(examples::demo_absolute_timelock().accepted(), "abs timelock demo");
    assert!(examples::demo_relative_timelock().accepted(), "rel timelock demo");
    assert!(examples::demo_ustav_charter().accepted(), "ustav demo");
    assert!(examples::demo_p2pkh().accepted(), "p2pkh demo");
    assert!(examples::demo_hashlock().accepted(), "hashlock demo");
    assert!(examples::demo_continuation_counter().accepted(), "counter demo");
    assert!(examples::demo_constant_product_amm().accepted(), "amm demo");
    // Gas accounting is meaningful on the green path.
    let r = examples::demo_p2pkh();
    assert!(r.gas_used > 0 && r.gas_remaining() == r.gas_limit - r.gas_used);
}

// ═════════════════════════════════════════════════════════════════════════════
// (1) N-of-M multisig
// ═════════════════════════════════════════════════════════════════════════════

fn govs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec())
}

#[test]
fn multisig_accepts_exactly_at_threshold() {
    let (p1, p2, p3) = govs();
    let (s1, s3) = (b"s1".to_vec(), b"s3".to_vec());
    let prog = examples::multisig_n_of_m(&[p1.clone(), p2.clone(), p3.clone()], 2);
    let v = MockVerifier::accepting(vec![
        (SIGHASH.to_vec(), p1, s1.clone()),
        (SIGHASH.to_vec(), p3, s3.clone()),
    ]);
    // slots in member order; member 2 unsigned → placeholder
    let redeemer = vec![Val::Bytes(s1), Val::Bytes(b"none".to_vec()), Val::Bytes(s3)];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(true));
}

#[test]
fn multisig_accepts_above_threshold() {
    let (p1, p2, p3) = govs();
    let (s1, s2, s3) = (b"s1".to_vec(), b"s2".to_vec(), b"s3".to_vec());
    let prog = examples::multisig_n_of_m(&[p1.clone(), p2.clone(), p3.clone()], 2);
    let v = MockVerifier::accepting(vec![
        (SIGHASH.to_vec(), p1, s1.clone()),
        (SIGHASH.to_vec(), p2, s2.clone()),
        (SIGHASH.to_vec(), p3, s3.clone()),
    ]);
    let redeemer = vec![Val::Bytes(s1), Val::Bytes(s2), Val::Bytes(s3)];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(true));
}

#[test]
fn multisig_rejects_below_threshold() {
    let (p1, p2, p3) = govs();
    let s1 = b"s1".to_vec();
    let prog = examples::multisig_n_of_m(&[p1.clone(), p2, p3], 2);
    // Only one signature verifies → count 1 < threshold 2.
    let v = MockVerifier::accepting(vec![(SIGHASH.to_vec(), p1, s1.clone())]);
    let redeemer = vec![Val::Bytes(s1), Val::Bytes(b"x".to_vec()), Val::Bytes(b"y".to_vec())];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_rejects_zero_valid_signatures() {
    let (p1, p2, p3) = govs();
    let prog = examples::multisig_n_of_m(&[p1, p2, p3], 1);
    let v = MockVerifier::never();
    let redeemer = vec![Val::Bytes(b"a".to_vec()), Val::Bytes(b"b".to_vec()), Val::Bytes(b"c".to_vec())];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_rejects_signatures_in_wrong_slots() {
    // Both members signed, but the redeemer places each sig under the *other* member's
    // pubkey slot → neither (msg, pk_i, sig_i) triple matches → count 0.
    let (p1, p2, p3) = govs();
    let (s1, s2) = (b"s1".to_vec(), b"s2".to_vec());
    let prog = examples::multisig_n_of_m(&[p1.clone(), p2.clone(), p3], 2);
    let v = MockVerifier::accepting(vec![
        (SIGHASH.to_vec(), p1, s1.clone()),
        (SIGHASH.to_vec(), p2, s2.clone()),
    ]);
    // swap slot 0 and slot 1
    let redeemer = vec![Val::Bytes(s2), Val::Bytes(s1), Val::Bytes(b"z".to_vec())];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_threshold_greater_than_m_is_unsatisfiable() {
    // 4-of-3: not caught by the fail-closed guards (threshold != 0, no dups, m ≤ 253),
    // but a valid program that can never reach the count — even with every sig valid.
    let (p1, p2, p3) = govs();
    let (s1, s2, s3) = (b"s1".to_vec(), b"s2".to_vec(), b"s3".to_vec());
    let prog = examples::multisig_n_of_m(&[p1, p2, p3], 4);
    let v = MockVerifier::always();
    let redeemer = vec![Val::Bytes(s1), Val::Bytes(s2), Val::Bytes(s3)];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_1_of_1() {
    let pk = b"solo".to_vec();
    let sig = b"solo-sig".to_vec();
    let prog = examples::multisig_n_of_m(&[pk.clone()], 1);
    let good = MockVerifier::accepting(vec![(SIGHASH.to_vec(), pk, sig.clone())]);
    assert_eq!(run(&prog, vec![Val::Bytes(sig)], &ctx_sig(SIGHASH), &good).result, Ok(true));
    // wrong sig → reject
    let bad = MockVerifier::never();
    assert_eq!(
        run(&prog, vec![Val::Bytes(b"forged".to_vec())], &ctx_sig(SIGHASH), &bad).result,
        Ok(false)
    );
}

/// The unspendable sentinel a degenerate config compiles to.
fn sentinel_hash() -> [u8; 32] {
    validator_hash(&[Op::PushInt(0)])
}

#[test]
fn multisig_fail_closed_duplicate_signers_is_sentinel() {
    let prog = examples::multisig_n_of_m(&[b"k".to_vec(), b"k".to_vec()], 1);
    assert_eq!(validator_hash(&prog), sentinel_hash(), "dup signers must emit the sentinel");
    // Even the most permissive verifier + witnesses cannot spend it.
    let v = MockVerifier::always();
    let redeemer = vec![Val::Bytes(b"a".to_vec()), Val::Bytes(b"b".to_vec())];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_fail_closed_zero_threshold_with_members_is_sentinel() {
    let prog = examples::multisig_n_of_m(&[b"a".to_vec(), b"b".to_vec()], 0);
    assert_eq!(validator_hash(&prog), sentinel_hash());
    let v = MockVerifier::always();
    assert_eq!(run(&prog, vec![], &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_fail_closed_m_over_253_is_sentinel() {
    // 254 distinct keys → the first slot's Pick depth would truncate in the u8 cast,
    // so the emitter refuses and returns the unspendable sentinel.
    let keys: Vec<Vec<u8>> = (0u16..254).map(|i| vec![i as u8, (i >> 8) as u8]).collect();
    let prog = examples::multisig_n_of_m(&keys, 1);
    assert_eq!(validator_hash(&prog), sentinel_hash());
    let v = MockVerifier::always();
    assert_eq!(run(&prog, vec![], &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn multisig_empty_signers_is_trivially_spendable() {
    // Documented edge: 0-of-0 (empty signer set, threshold 0) is NOT the degenerate guard
    // case — it keeps the trivial "count 0 >= 0" behaviour and finishes truthy.
    let prog = examples::multisig_n_of_m(&[], 0);
    assert_ne!(validator_hash(&prog), sentinel_hash(), "empty set is not the sentinel");
    let v = MockVerifier::never();
    assert_eq!(run(&prog, vec![], &ctx_sig(SIGHASH), &v).result, Ok(true));
}

#[test]
fn multisig_is_deterministic_and_order_sensitive() {
    let (p1, p2, p3) = govs();
    let a = examples::multisig_n_of_m(&[p1.clone(), p2.clone(), p3.clone()], 2);
    let b = examples::multisig_n_of_m(&[p1.clone(), p2.clone(), p3.clone()], 2);
    assert_eq!(validator_hash(&a), validator_hash(&b), "same inputs ⇒ same program");
    // member order is significant → different validator identity
    let c = examples::multisig_n_of_m(&[p3, p2, p1], 2);
    assert_ne!(validator_hash(&a), validator_hash(&c), "reordered members ⇒ different program");
}

// ═════════════════════════════════════════════════════════════════════════════
// (2) Time-locks — absolute & relative
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn absolute_timelock_boundary_and_reject() {
    let prog = examples::absolute_timelock(100);
    let v = MockVerifier::never();
    // height == unlock accepts (>=)
    assert_eq!(run(&prog, vec![], &ctx_h(SIGHASH, 100), &v).result, Ok(true));
    // height > unlock accepts
    assert_eq!(run(&prog, vec![], &ctx_h(SIGHASH, 101), &v).result, Ok(true));
    // height < unlock rejects (clean, not a fault)
    assert_eq!(run(&prog, vec![], &ctx_h(SIGHASH, 99), &v).result, Ok(false));
}

#[test]
fn absolute_timelock_zero_and_negative_unlock_always_open() {
    let v = MockVerifier::never();
    assert_eq!(run(&examples::absolute_timelock(0), vec![], &ctx_h(SIGHASH, 0), &v).result, Ok(true));
    assert_eq!(run(&examples::absolute_timelock(-5), vec![], &ctx_h(SIGHASH, 0), &v).result, Ok(true));
}

#[test]
fn absolute_timelock_fail_closed_missing_height_field() {
    // ctx has no FIELD_HEIGHT (index 1) → BadCtxField, never a silent accept.
    let prog = examples::absolute_timelock(100);
    let v = MockVerifier::never();
    let r = run(&prog, vec![], &ctx_sig(SIGHASH), &v);
    assert!(matches!(r.result, Err(VmError::BadCtxField(_))), "got {:?}", r.result);
}

#[test]
fn relative_timelock_boundary_and_reject_via_spend() {
    let prog = examples::relative_timelock(20);
    let mk_out = |creation: i128| ExtOutput {
        value: blch(10),
        validator_hash: validator_hash(&prog),
        datum: Val::Int(creation),
    };
    let v = MockVerifier::never();
    // age == min_age accepts (creation 100, height 120 → age 20)
    let r = sim::run_spend(&mk_out(100), &prog, vec![], &ctx_h(SIGHASH, 120), &v, 50_000);
    assert_eq!(r.result, Ok(true), "boundary age == min_age");
    // age > min_age accepts
    let r = sim::run_spend(&mk_out(100), &prog, vec![], &ctx_h(SIGHASH, 130), &v, 50_000);
    assert_eq!(r.result, Ok(true));
    // age < min_age rejects (creation 100, height 110 → age 10)
    let r = sim::run_spend(&mk_out(100), &prog, vec![], &ctx_h(SIGHASH, 110), &v, 50_000);
    assert_eq!(r.result, Ok(false));
}

#[test]
fn relative_timelock_zero_min_age_always_open() {
    let prog = examples::relative_timelock(0);
    let out = ExtOutput { value: blch(1), validator_hash: validator_hash(&prog), datum: Val::Int(50) };
    let v = MockVerifier::never();
    let r = sim::run_spend(&out, &prog, vec![], &ctx_h(SIGHASH, 50), &v, 50_000);
    assert_eq!(r.result, Ok(true));
}

#[test]
fn relative_timelock_fail_closed_missing_creation_datum() {
    // Run the raw program with an EMPTY stack: it needs the creation height seeded first
    // (CtxField(HEIGHT) then Swap over two elements) → StackUnderflow, never a silent pass.
    let prog = examples::relative_timelock(20);
    let v = MockVerifier::never();
    let r = run(&prog, vec![], &ctx_h(SIGHASH, 130), &v);
    assert!(matches!(r.result, Err(VmError::StackUnderflow)), "got {:?}", r.result);
}

#[test]
fn relative_timelock_fail_closed_non_int_creation_datum() {
    // A Bytes datum where an Int creation height is required → TypeError in Sub.
    let prog = examples::relative_timelock(20);
    let v = MockVerifier::never();
    let r = run(&prog, vec![Val::Bytes(b"not-an-int".to_vec())], &ctx_h(SIGHASH, 130), &v);
    assert!(matches!(r.result, Err(VmError::TypeError(_))), "got {:?}", r.result);
}

// ═════════════════════════════════════════════════════════════════════════════
// (3) Minimal Ustav token-charter
// ═════════════════════════════════════════════════════════════════════════════

fn issuer() -> Vec<u8> {
    b"ustav-issuer".to_vec()
}
fn governors() -> [Vec<u8>; 3] {
    [b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec()]
}

#[test]
fn charter_shape_supply_then_governance() {
    let charter = examples::minimal_ustav_charter("USTAV", 1_000_000, issuer(), governors());
    assert_eq!(charter.token_name, b"USTAV".to_vec());
    assert_eq!(charter.modules.len(), 2);
    let compiled = examples::compile_minimal_ustav_charter("USTAV", 1_000_000, issuer(), governors());
    let kinds: Vec<&str> = compiled.validators.iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec!["supply", "governance"]);
    // policy id is the Supply validator's hash.
    let supply = compiled.validators.iter().find(|m| m.kind == "supply").unwrap();
    assert_eq!(compiled.policy_id(), Some(supply.validator_hash));
}

#[test]
fn charter_is_deterministic() {
    let a = examples::compile_minimal_ustav_charter("USTAV", 1_000_000, issuer(), governors());
    let b = examples::compile_minimal_ustav_charter("USTAV", 1_000_000, issuer(), governors());
    assert_eq!(a.charter_id, b.charter_id);
    for (ma, mb) in a.validators.iter().zip(b.validators.iter()) {
        assert_eq!(ma.validator_hash, mb.validator_hash);
    }
}

#[test]
fn charter_name_and_cap_are_domain_separated() {
    let base = examples::compile_minimal_ustav_charter("USTAV", 1_000_000, issuer(), governors());
    let renamed = examples::compile_minimal_ustav_charter("OTHER", 1_000_000, issuer(), governors());
    assert_ne!(base.charter_id, renamed.charter_id, "name folds into charter id");

    let recapped = examples::compile_minimal_ustav_charter("USTAV", 2_000_000, issuer(), governors());
    let sup_a = base.validators.iter().find(|m| m.kind == "supply").unwrap();
    let sup_b = recapped.validators.iter().find(|m| m.kind == "supply").unwrap();
    assert_ne!(sup_a.validator_hash, sup_b.validator_hash, "cap changes the Supply program");
}

fn supply_program(cap: u64) -> Vec<Op> {
    let compiled = examples::compile_minimal_ustav_charter("USTAV", cap, issuer(), governors());
    compiled.validators.into_iter().find(|m| m.kind == "supply").unwrap().program
}

#[test]
fn charter_supply_accepts_within_cap_and_at_boundary() {
    let sig = b"issuer-sig".to_vec();
    let v = MockVerifier::accepting(vec![(SIGHASH.to_vec(), issuer(), sig.clone())]);
    let prog = supply_program(1_000_000);
    // seed [datum, requested:Int, sig:Bytes]
    let within = vec![Val::Int(0), Val::Int(500_000), Val::Bytes(sig.clone())];
    assert_eq!(run(&prog, within, &ctx_sig(SIGHASH), &v).result, Ok(true));
    // requested == cap passes (<=)
    let boundary = vec![Val::Int(0), Val::Int(1_000_000), Val::Bytes(sig)];
    assert_eq!(run(&prog, boundary, &ctx_sig(SIGHASH), &v).result, Ok(true));
}

#[test]
fn charter_supply_fail_closed_over_cap() {
    // requested = cap + 1 → the cap-gate Verify aborts (a FAULT, not a silent false).
    let prog = supply_program(1_000_000);
    let sig = b"issuer-sig".to_vec();
    let v = MockVerifier::accepting(vec![(SIGHASH.to_vec(), issuer(), sig.clone())]);
    let over = vec![Val::Int(0), Val::Int(1_000_001), Val::Bytes(sig)];
    let r = run(&prog, over, &ctx_sig(SIGHASH), &v);
    assert_eq!(r.result, Err(VmError::Assert), "over-cap mint must abort, got {:?}", r.result);
}

#[test]
fn charter_supply_rejects_forged_issuer_sig() {
    // Within cap, but the issuer signature does not verify → clean reject.
    let prog = supply_program(1_000_000);
    let v = MockVerifier::never();
    let redeemer = vec![Val::Int(0), Val::Int(1), Val::Bytes(b"forged".to_vec())];
    assert_eq!(run(&prog, redeemer, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

fn gov_program() -> Vec<Op> {
    let compiled = examples::compile_minimal_ustav_charter("USTAV", 1_000_000, issuer(), governors());
    compiled.validators.into_iter().find(|m| m.kind == "governance").unwrap().program
}

#[test]
fn charter_governance_is_2_of_3() {
    let [g1, _g2, g3] = governors();
    let (s1, s3) = (b"g1s".to_vec(), b"g3s".to_vec());
    let prog = gov_program();
    let v = MockVerifier::accepting(vec![
        (SIGHASH.to_vec(), g1, s1.clone()),
        (SIGHASH.to_vec(), g3, s3.clone()),
    ]);
    // Governance seed: [datum, sig_1, sig_2, sig_3]
    let two_valid = vec![Val::Int(0), Val::Bytes(s1.clone()), Val::Bytes(b"none".to_vec()), Val::Bytes(s3)];
    assert_eq!(run(&prog, two_valid, &ctx_sig(SIGHASH), &v).result, Ok(true));

    // Only one signature verifies → reject.
    let v1 = MockVerifier::accepting(vec![(SIGHASH.to_vec(), governors()[0].clone(), s1.clone())]);
    let one_valid = vec![Val::Int(0), Val::Bytes(s1), Val::Bytes(b"x".to_vec()), Val::Bytes(b"y".to_vec())];
    assert_eq!(run(&prog, one_valid, &ctx_sig(SIGHASH), &v1).result, Ok(false));
}

// ═════════════════════════════════════════════════════════════════════════════
// Foundation reference validators
// ═════════════════════════════════════════════════════════════════════════════

// ── P2PKH ─────────────────────────────────────────────────────────────────────

#[test]
fn p2pkh_accepts_valid_reveal_and_sig() {
    let pubkey = b"pk".to_vec();
    let sig = b"sig".to_vec();
    let prog = examples::p2pkh(sha256d(&pubkey));
    let v = MockVerifier::accepting(vec![(SIGHASH.to_vec(), pubkey.clone(), sig.clone())]);
    let seed = vec![Val::Bytes(pubkey), Val::Bytes(sig)];
    assert_eq!(run(&prog, seed, &ctx_sig(SIGHASH), &v).result, Ok(true));
}

#[test]
fn p2pkh_rejects_bad_signature() {
    // Right pubkey (hash matches), wrong signature → validator returns false, not a fault.
    let pubkey = b"pk".to_vec();
    let prog = examples::p2pkh(sha256d(&pubkey));
    let v = MockVerifier::never();
    let seed = vec![Val::Bytes(pubkey), Val::Bytes(b"bad".to_vec())];
    assert_eq!(run(&prog, seed, &ctx_sig(SIGHASH), &v).result, Ok(false));
}

#[test]
fn p2pkh_fail_closed_wrong_pubkey() {
    // Reveal a pubkey that does NOT hash to the committed value → the hash-check Verify
    // aborts (a fault) before any signature is even considered.
    let committed = sha256d(b"the-real-pubkey");
    let prog = examples::p2pkh(committed);
    let v = MockVerifier::always(); // even an all-accepting verifier can't rescue it
    let seed = vec![Val::Bytes(b"impostor".to_vec()), Val::Bytes(b"sig".to_vec())];
    let r = run(&prog, seed, &ctx_sig(SIGHASH), &v);
    assert_eq!(r.result, Err(VmError::Assert), "got {:?}", r.result);
}

#[test]
fn p2pkh_fail_closed_missing_witness() {
    let prog = examples::p2pkh(sha256d(b"pk"));
    let v = MockVerifier::never();
    let r = run(&prog, vec![], &ctx_sig(SIGHASH), &v);
    assert!(matches!(r.result, Err(VmError::StackUnderflow)), "got {:?}", r.result);
}

// ── Hash-lock / HTLC ─────────────────────────────────────────────────────────

#[test]
fn hashlock_accepts_correct_preimage() {
    let preimage = b"the-secret".to_vec();
    let prog = examples::hashlock(sha256d(&preimage));
    let v = MockVerifier::never();
    assert_eq!(run(&prog, vec![Val::Bytes(preimage)], &Ctx::default(), &v).result, Ok(true));
}

#[test]
fn hashlock_rejects_wrong_preimage() {
    let prog = examples::hashlock(sha256d(b"the-secret"));
    let v = MockVerifier::never();
    assert_eq!(run(&prog, vec![Val::Bytes(b"guess".to_vec())], &Ctx::default(), &v).result, Ok(false));
}

#[test]
fn hashlock_fail_closed_non_bytes_preimage() {
    // An Int where the preimage Bytes are expected → Sha256d type-errors, never accepts.
    let prog = examples::hashlock(sha256d(b"x"));
    let v = MockVerifier::never();
    let r = run(&prog, vec![Val::Int(42)], &Ctx::default(), &v);
    assert!(matches!(r.result, Err(VmError::TypeError(_))), "got {:?}", r.result);
}

#[test]
fn hashlock_fail_closed_empty_stack() {
    let prog = examples::hashlock(sha256d(b"x"));
    let v = MockVerifier::never();
    let r = run(&prog, vec![], &Ctx::default(), &v);
    assert!(matches!(r.result, Err(VmError::StackUnderflow)), "got {:?}", r.result);
}

#[test]
fn hashlock_commitment_round_trips() {
    // The lock derived here must be exactly what the VM's Sha256d recomputes and accepts.
    let preimage = b"round-trip-secret".to_vec();
    let lock = sha256d(&preimage);
    let prog = examples::hashlock(lock);
    let v = MockVerifier::never();
    assert_eq!(run(&prog, vec![Val::Bytes(preimage)], &Ctx::default(), &v).result, Ok(true));
    // Two builds of the same lock are byte-identical programs.
    assert_eq!(validator_hash(&prog), validator_hash(&examples::hashlock(lock)));
}

// ── Continuation counter ──────────────────────────────────────────────────────

#[test]
fn counter_accepts_correct_increment() {
    let prog = examples::continuation_counter();
    let vh = validator_hash(&prog);
    let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
    let ctx = ctx_out(ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(42) });
    let v = MockVerifier::never();
    assert_eq!(sim::run_spend(&input, &prog, vec![], &ctx, &v, 50_000).result, Ok(true));
}

#[test]
fn counter_rejects_wrong_increment() {
    let prog = examples::continuation_counter();
    let vh = validator_hash(&prog);
    let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
    // +2 instead of +1 → clean reject.
    let ctx = ctx_out(ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(43) });
    let v = MockVerifier::never();
    assert_eq!(sim::run_spend(&input, &prog, vec![], &ctx, &v, 50_000).result, Ok(false));
}

#[test]
fn counter_fail_closed_contract_not_continued() {
    // The continuation output is guarded by a DIFFERENT validator → the self-recreation
    // Verify aborts (fault): the counter cannot be spent into a foreign contract.
    let prog = examples::continuation_counter();
    let vh = validator_hash(&prog);
    let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
    let ctx = ctx_out(ExtOutput { value: blch(10), validator_hash: [9u8; 32], datum: Val::Int(42) });
    let v = MockVerifier::never();
    let r = sim::run_spend(&input, &prog, vec![], &ctx, &v, 50_000);
    assert_eq!(r.result, Err(VmError::Assert), "got {:?}", r.result);
}

#[test]
fn counter_fail_closed_no_continuation_output() {
    // No tx_outputs[0] at all → BadTxOut, never a silent accept.
    let prog = examples::continuation_counter();
    let vh = validator_hash(&prog);
    let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
    let v = MockVerifier::never();
    let r = sim::run_spend(&input, &prog, vec![], &Ctx::default(), &v, 50_000);
    assert!(matches!(r.result, Err(VmError::BadTxOut(_))), "got {:?}", r.result);
}

#[test]
fn spend_fail_closed_validator_hash_mismatch() {
    // Reveal a program that does not hash to the prevout's validator_hash → the spend
    // rejects before any execution (the identity binding is enforced).
    let prog = examples::continuation_counter();
    let wrong_out = ExtOutput {
        value: blch(10),
        validator_hash: validator_hash(&examples::hashlock([0u8; 32])),
        datum: Val::Int(41),
    };
    let ctx = ctx_out(wrong_out.clone());
    let v = MockVerifier::never();
    let r = sim::run_spend(&wrong_out, &prog, vec![], &ctx, &v, 50_000);
    assert_eq!(r.result, Err(VmError::ValidatorHashMismatch), "got {:?}", r.result);
}

// ── Constant-product AMM ──────────────────────────────────────────────────────

const AMM_A: AssetId = [1u8; 32];
const AMM_B: AssetId = [2u8; 32];

fn amm_pool(prog: &[Op], a: u64, b: u64) -> ExtOutput {
    ExtOutput {
        value: value_of(&[(AMM_A, a), (AMM_B, b)]),
        validator_hash: validator_hash(prog),
        datum: Val::Int(0),
    }
}

#[test]
fn amm_accepts_when_invariant_grows() {
    let prog = examples::constant_product_amm(AMM_A, AMM_B);
    let vh = validator_hash(&prog);
    let pool = amm_pool(&prog, 1000, 1000);
    // 1100 * 910 = 1_001_000 >= 1_000_000
    let ctx = ctx_out(ExtOutput { value: value_of(&[(AMM_A, 1100), (AMM_B, 910)]), validator_hash: vh, datum: Val::Int(0) });
    let v = MockVerifier::never();
    assert_eq!(sim::run_spend(&pool, &prog, vec![], &ctx, &v, 80_000).result, Ok(true));
}

#[test]
fn amm_accepts_when_invariant_exactly_preserved() {
    let prog = examples::constant_product_amm(AMM_A, AMM_B);
    let vh = validator_hash(&prog);
    let pool = amm_pool(&prog, 1000, 1000);
    // 1000 * 1000 == 1000 * 1000 → new_k >= old_k holds at the boundary.
    let ctx = ctx_out(ExtOutput { value: value_of(&[(AMM_A, 1000), (AMM_B, 1000)]), validator_hash: vh, datum: Val::Int(0) });
    let v = MockVerifier::never();
    assert_eq!(sim::run_spend(&pool, &prog, vec![], &ctx, &v, 80_000).result, Ok(true));
}

#[test]
fn amm_rejects_when_pool_is_drained() {
    let prog = examples::constant_product_amm(AMM_A, AMM_B);
    let vh = validator_hash(&prog);
    let pool = amm_pool(&prog, 1000, 1000);
    // 1100 * 800 = 880_000 < 1_000_000 → clean reject, pool protected.
    let ctx = ctx_out(ExtOutput { value: value_of(&[(AMM_A, 1100), (AMM_B, 800)]), validator_hash: vh, datum: Val::Int(0) });
    let v = MockVerifier::never();
    assert_eq!(sim::run_spend(&pool, &prog, vec![], &ctx, &v, 80_000).result, Ok(false));
}

#[test]
fn amm_fail_closed_contract_not_continued() {
    let prog = examples::constant_product_amm(AMM_A, AMM_B);
    let pool = amm_pool(&prog, 1000, 1000);
    // continuation guarded by a foreign validator → self-recreation Verify aborts.
    let ctx = ctx_out(ExtOutput { value: value_of(&[(AMM_A, 1100), (AMM_B, 910)]), validator_hash: [7u8; 32], datum: Val::Int(0) });
    let v = MockVerifier::never();
    let r = sim::run_spend(&pool, &prog, vec![], &ctx, &v, 80_000);
    assert_eq!(r.result, Err(VmError::Assert), "got {:?}", r.result);
}

#[test]
fn amm_fail_closed_no_continuation_output() {
    let prog = examples::constant_product_amm(AMM_A, AMM_B);
    let pool = amm_pool(&prog, 1000, 1000);
    let v = MockVerifier::never();
    let r = sim::run_spend(&pool, &prog, vec![], &Ctx::default(), &v, 80_000);
    assert!(matches!(r.result, Err(VmError::BadTxOut(_))), "got {:?}", r.result);
}

#[test]
fn amm_is_deterministic_and_asset_ordered() {
    let ab = examples::constant_product_amm(AMM_A, AMM_B);
    let ab2 = examples::constant_product_amm(AMM_A, AMM_B);
    assert_eq!(validator_hash(&ab), validator_hash(&ab2));
    // swapping the asset roles yields a distinct pool contract
    let ba = examples::constant_product_amm(AMM_B, AMM_A);
    assert_ne!(validator_hash(&ab), validator_hash(&ba));
}
