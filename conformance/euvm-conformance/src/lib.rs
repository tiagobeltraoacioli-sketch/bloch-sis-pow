//! # euvm-conformance — CAVP known-answer harness for the bloch-euvm hash opcodes
//!
//! ## What this is, and what it is NOT
//!
//! bloch-euvm is its own reference: it is an eUTXO stack machine with its own ISA
//! (crates/bloch-euvm/src/lib.rs:1-24), not an EVM, so there is no external
//! implementation to run differentially against — "conformance" in the
//! ethereum/tests sense is a category error here (see
//! docs/specs/BLOCH-VM-DIFFERENTIAL-CONFORMANCE.md §0). What CAN be anchored to an
//! external oracle is the cryptography its opcodes expose: `Op::Shake256` and
//! `Op::Sha256d` (crates/bloch-euvm/src/lib.rs:418-432). NIST CAVP publishes
//! known-answer vectors for SHA-256 and SHAKE256; this crate drives them through
//! the VM's REAL execution path (`bloch_euvm::run`, gas metering and all), not
//! through the underlying rust-crypto crates directly — a KAT that bypasses the
//! VM would not notice an opcode-plumbing bug (truncated XOF read, single instead
//! of double application, wrong pop/push order).
//!
//! ## Independence argument, stated precisely
//!
//! - `Op::Shake256` reads a FIXED 32 bytes of XOF output. CAVP SHAKE256
//!   ShortMsg/LongMsg vectors are generated with Outputlen = 256 bits = exactly
//!   32 bytes, so the comparison `vm_output == NIST_output` is FULLY independent:
//!   the expected value comes from NIST, nothing in the chain is computed by the
//!   code under test. The VariableOut file only contributes its Outputlen==256
//!   rows; the rest are excluded with a named reason (the opcode cannot express
//!   other output lengths — see tests/cavp_shake256.rs).
//! - `Op::Sha256d` is SHA-256 applied twice; CAVP has no double-SHA-256 file, so
//!   the expected value is `Sha256(MD)` where MD is the NIST-GIVEN digest (read
//!   from the .rsp file, never recomputed from Msg). The outer application is
//!   computed by the `sha2` crate — the same crate the VM links — so on its own
//!   that would be self-referential. It is anchored in two steps: (1) every KAT
//!   first asserts `sha2::Sha256(Msg) == MD` against NIST, which validates the
//!   linked primitive on the SAME input distribution, and (2) the outer
//!   application only ever runs `sha2` on 32-byte inputs, a length the CAVP
//!   ShortMsg file itself covers (its Len = 256 vector). The only residual
//!   assumption is "sha2 is correct on 32-byte inputs", which step (1) verifies
//!   against NIST directly. What remains genuinely tested about the OPCODE is
//!   exactly what only the opcode controls: that it applies the (NIST-validated)
//!   primitive exactly twice, on the popped operand, pushing all 32 bytes.
//!
//! ## Why the comparison happens INSIDE the VM
//!
//! Each KAT program is `[HashOp, PushBytes(expected), Eq]` over a seeded stack
//! `[msg]`, and the harness only looks at `run(..) == Ok(true)`. This exercises
//! the full interpreter loop (gas charge, stack discipline, `Eq` semantics)
//! rather than fishing bytes out of a debug hook the production path never uses.
//! The obvious failure mode — a broken `Eq` that always answers 1 would turn
//! every positive KAT into a tautology — is closed by the mandatory CONTROL half:
//! every vector is also run with a corrupted expected value and MUST come back
//! `Ok(false)`. A mutation that breaks `Eq`, the hash op, or this harness's
//! parser kills the suite (proven by the campaign in ../mutation — see
//! results/2026-08-22-harness-gate.tsv).

#![forbid(unsafe_code)]

use bloch_euvm::{run, Ctx, Op, SigVerifier, Val, VmError};

/// Gas budget per KAT run. The largest CAVP message here is 110688 bits ≈ 13.8 KiB
/// (SHAKE256LongMsg), so the byte-proportional charge (bloch-euvm op_gas, ~1 gas
/// per 32-byte word per copying/hashing op) stays far below this. A KAT must
/// never fail on gas — OutOfGas here would mean the harness, not the VM, is
/// mis-sized, so the helpers surface it as a panic instead of `Ok(false)`.
pub const KAT_GAS: u64 = 10_000_000;

/// Verifier that accepts nothing. Hash KATs never reach `VerifySig`/`VerifyEcdsa`;
/// fail-closed is the right default for a stub (same posture as the VM itself).
pub struct NopVerifier;
impl SigVerifier for NopVerifier {
    fn verify(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// Run `[hash_op, PushBytes(expected), Eq]` over the seeded stack `[msg]` through
/// the VM's real `run()` and report whether the VM judged them equal.
/// Errors (gas, stack, type) panic with context: in a KAT they are harness bugs,
/// not vector outcomes, and MUST NOT be silently folded into "false".
pub fn vm_hash_matches(hash_op: Op, msg: &[u8], expected: &[u8]) -> bool {
    unwrap_kat(vm_hash_run(hash_op, Val::Bytes(msg.to_vec()), expected))
}

/// The ONE place a KAT turns a `Result` into a verdict. Single site on purpose:
/// it is what mutant H07 targets (conformance/mutation/run_mutation_campaign.py),
/// and a rule with two copies is a rule with a copy nobody mutates.
/// A `VmError` here is a HARNESS bug — wrong gas budget, wrong operand type —
/// and folding it into `false` would report a broken harness as a failing
/// vector, i.e. exactly the fabricated conformance number this front forbids.
fn unwrap_kat(r: Result<bool, VmError>) -> bool {
    match r {
        Ok(b) => b,
        Err(e) => panic!("VM error in KAT (harness bug, not a vector outcome): {e:?}"),
    }
}

/// Build and run `[hash_op, PushBytes(expected), Eq]` over a one-value seeded
/// stack, returning the raw `Result` (verdict-vs-error decision left to callers).
fn vm_hash_run(hash_op: Op, seed: Val, expected: &[u8]) -> Result<bool, VmError> {
    let program = [hash_op, Op::PushBytes(expected.to_vec()), Op::Eq];
    let ctx = Ctx::default();
    let mut gas = KAT_GAS;
    run(&program, vec![seed], &ctx, &NopVerifier, &mut gas)
}

/// Same, but any VmError is returned — used by the gas-sizing sanity test only.
pub fn vm_hash_matches_res(hash_op: Op, msg: &[u8], expected: &[u8], gas: u64) -> Result<bool, VmError> {
    let program = [hash_op, Op::PushBytes(expected.to_vec()), Op::Eq];
    let ctx = Ctx::default();
    let mut g = gas;
    run(&program, vec![Val::Bytes(msg.to_vec())], &ctx, &NopVerifier, &mut g)
}

/// One parsed CAVP vector: message bytes and the NIST-given digest/output bytes.
#[derive(Debug, Clone)]
pub struct KatVector {
    /// Message length in BITS as declared by the file (kept to enforce the
    /// byte-oriented invariant `len % 8 == 0` and the Len=0 special case).
    pub len_bits: u64,
    pub msg: Vec<u8>,
    pub expected: Vec<u8>,
}

/// Parse a CAVP `.rsp` file of `Len = / Msg = / (MD|Output) =` records
/// (SHA256ShortMsg/LongMsg, SHAKE256ShortMsg/LongMsg all share this shape).
///
/// The one trap in the format, and the reason this parser must be under the
/// mutation gate: for `Len = 0` the file still prints `Msg = 00`, but the message
/// is EMPTY — feeding the literal zero byte instead silently turns the empty-
/// message KAT into a hash of `[0x00]`, which passes nothing and (worse) would
/// "fail" the VM for a harness bug. `len_bits` is authoritative for truncation.
pub fn parse_rsp(text: &str) -> Vec<KatVector> {
    let mut out = Vec::new();
    let mut len_bits: Option<u64> = None;
    let mut msg: Option<Vec<u8>> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some(v) = line.strip_prefix("Len = ") {
            len_bits = Some(v.parse().expect("Len must be an integer"));
        } else if let Some(v) = line.strip_prefix("Msg = ") {
            msg = Some(hex::decode(v).expect("Msg must be hex"));
        } else if let Some(v) = line.strip_prefix("MD = ").or_else(|| line.strip_prefix("Output = ")) {
            let lb = len_bits.take().expect(".rsp record missing Len before MD/Output");
            assert!(lb % 8 == 0, "byte-oriented vectors only (Len={lb} not a multiple of 8)");
            let mut m = msg.take().expect(".rsp record missing Msg before MD/Output");
            // Len is authoritative: truncate the (possibly `00`-padded) Msg field.
            m.truncate((lb / 8) as usize);
            out.push(KatVector {
                len_bits: lb,
                msg: m,
                expected: hex::decode(v).expect("MD/Output must be hex"),
            });
        }
    }
    out
}

/// Parse the CAVP `SHAKE256VariableOut.rsp` shape (`COUNT / Outputlen / Msg /
/// Output`), returning ONLY the rows whose Outputlen is exactly `keep_bits`, plus
/// the total row count. The caller asserts both numbers, so a parser mutation
/// that drops rows — applicable or not — is caught by the count, not hidden by a
/// smaller (still all-green) sample. Rows with other lengths are EXCLUDED, reason
/// OUTPUTLEN-MISMATCH: `Op::Shake256` performs a fixed 32-byte XOF read
/// (crates/bloch-euvm/src/lib.rs:424-432) and cannot express any other length.
pub fn parse_variable_out(text: &str, keep_bits: u64) -> (Vec<KatVector>, usize) {
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut outputlen: Option<u64> = None;
    let mut msg: Option<Vec<u8>> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some(v) = line.strip_prefix("Outputlen = ") {
            outputlen = Some(v.parse().expect("Outputlen must be an integer"));
        } else if let Some(v) = line.strip_prefix("Msg = ") {
            msg = Some(hex::decode(v).expect("Msg must be hex"));
        } else if let Some(v) = line.strip_prefix("Output = ") {
            total += 1;
            let ol = outputlen.take().expect("record missing Outputlen");
            let m = msg.take().expect("record missing Msg");
            if ol == keep_bits {
                kept.push(KatVector {
                    len_bits: (m.len() as u64) * 8,
                    msg: m,
                    expected: hex::decode(v).expect("Output must be hex"),
                });
            }
        }
    }
    (kept, total)
}

/// Corrupt an expected value for the CONTROL half of a KAT (flip one bit of the
/// first byte). Every negative control uses this, so a mutation that removes the
/// corruption turns controls into duplicates of the positive half and they fail
/// their `!matches` assertion — the control of the control.
pub fn corrupt(expected: &[u8]) -> Vec<u8> {
    let mut c = expected.to_vec();
    c[0] ^= 0x01;
    c
}

/// Same shape as [`vm_hash_matches`] but seeds an `Int` instead of `Bytes`, so
/// the hash op hits [`VmError::TypeError`]. Exists ONLY so a test can prove the
/// error path panics rather than reporting `false` — see the H07 mutant in
/// conformance/mutation/run_mutation_campaign.py. Kept next to
/// [`vm_hash_matches`] so the two share the error-handling arm they are about.
pub fn vm_hash_matches_int_seed(hash_op: Op, seed: i128, expected: &[u8]) -> bool {
    unwrap_kat(vm_hash_run(hash_op, Val::Int(seed), expected))
}
