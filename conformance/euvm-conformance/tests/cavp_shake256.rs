//! NIST CAVP known-answer tests for `Op::Shake256`, run through the VM's real
//! `run()` path (gas, stack, `Eq` — see euvm-conformance/src/lib.rs for the
//! design and the independence argument).
//!
//! Oracle: SHAKE256 ShortMsg + LongMsg (Outputlen = 256 bits = the opcode's fixed
//! 32-byte XOF read — a DIRECT, fully external comparison), plus the
//! Outputlen==256 rows of VariableOut. All other VariableOut rows are EXCLUDED,
//! reason OUTPUTLEN-MISMATCH (the opcode cannot express other lengths); the
//! exclusion is COUNTED and asserted, never silent, per the report discipline of
//! BLOCH-VM-DIFFERENTIAL-CONFORMANCE.md §5.
//!
//! Vector provenance: vectors/cavp/MANIFEST.toml (NIST CAVP shakebytetestvectors.zip,
//! sha256 debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7).

use bloch_euvm::{Op, VmError};
use euvm_conformance::{corrupt, parse_rsp, parse_variable_out, vm_hash_matches, vm_hash_matches_res};

const SHORT: &str = include_str!("../vectors/cavp/SHAKE256ShortMsg.rsp");
const LONG: &str = include_str!("../vectors/cavp/SHAKE256LongMsg.rsp");
const VAROUT: &str = include_str!("../vectors/cavp/SHAKE256VariableOut.rsp");

/// The parser is itself under test: a mutation that drops records (the Len=0
/// trap, a skipped line) must not shrink the corpus silently. Counts were
/// measured from the NIST files at import time (2026-08-22).
#[test]
fn corpus_counts_are_exactly_the_nist_counts() {
    assert_eq!(parse_rsp(SHORT).len(), 273, "SHAKE256ShortMsg must yield 273 vectors");
    assert_eq!(parse_rsp(LONG).len(), 100, "SHAKE256LongMsg must yield 100 vectors");
    let (kept, total) = parse_variable_out(VAROUT, 256);
    assert_eq!(total, 1246, "SHAKE256VariableOut must yield 1246 records in total");
    assert_eq!(kept.len(), 5, "exactly 5 VariableOut records have Outputlen=256");
}

/// The Len=0 record prints `Msg = 00` but means the EMPTY message — the classic
/// .rsp trap. Pin it explicitly: parsed msg must be empty and its NIST output is
/// the well-known SHAKE256("") 32-byte prefix. A parser mutation that feeds the
/// literal zero byte dies here first, with a legible failure.
#[test]
fn len_zero_vector_is_the_empty_message() {
    let vs = parse_rsp(SHORT);
    let v0 = vs.iter().find(|v| v.len_bits == 0).expect("Len=0 vector present");
    assert!(v0.msg.is_empty(), "Len=0 must parse to an EMPTY message, not [0x00]");
    assert_eq!(
        hex::encode(&v0.expected),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
    assert!(vm_hash_matches(Op::Shake256, &v0.msg, &v0.expected));
}

/// Positive + CONTROL halves for every applicable vector. 373 direct KATs
/// (273 short + 100 long) + 5 applicable VariableOut rows = 378; each also runs
/// with a corrupted expectation that MUST come back false (closes the
/// "Eq always answers 1" hole — negative-test discipline rule 2).
#[test]
fn shake256_opcode_matches_nist_for_all_applicable_vectors() {
    let mut vectors = parse_rsp(SHORT);
    vectors.extend(parse_rsp(LONG));
    let (kept, _total) = parse_variable_out(VAROUT, 256);
    vectors.extend(kept);
    assert_eq!(vectors.len(), 378, "applicable corpus must be 378 vectors");

    for v in &vectors {
        assert!(
            vm_hash_matches(Op::Shake256, &v.msg, &v.expected),
            "SHAKE256 KAT failed for Len={} bits", v.len_bits
        );
        assert!(
            !vm_hash_matches(Op::Shake256, &v.msg, &corrupt(&v.expected)),
            "CONTROL failed (corrupted expectation accepted) for Len={} bits", v.len_bits
        );
    }
}

/// Gas-sizing sanity: the largest message in the corpus must run WELL within
/// KAT_GAS (a KAT failing on gas would be a harness bug reported as a VM bug),
/// and — control half — a starved budget must fail with OutOfGas, proving the
/// harness really routes through the metered interpreter and not a stub.
#[test]
fn kats_run_metered_and_within_budget() {
    let vs = parse_rsp(LONG);
    let biggest = vs.iter().max_by_key(|v| v.msg.len()).unwrap();
    assert_eq!(
        vm_hash_matches_res(Op::Shake256, &biggest.msg, &biggest.expected, euvm_conformance::KAT_GAS),
        Ok(true)
    );
    assert_eq!(
        vm_hash_matches_res(Op::Shake256, &biggest.msg, &biggest.expected, 10),
        Err(VmError::OutOfGas),
        "a starved budget must abort: the KAT path IS the metered path"
    );
}

/// **Harness self-check (kills mutant H07).** `vm_hash_matches` MUST surface a
/// VmError as a panic, never fold it into `false`: folding would let a VM that
/// *errors* on every input read as "all vectors mismatch" — a harness bug
/// reported as a conformance result, which is the failure mode this whole front
/// exists to prevent. The green path never errors, so without this test the
/// distinction is unobservable and the mutation campaign recorded H07 as a
/// survivor (conformance/mutation/results/2026-08-22-harness-gate.tsv, first run).
/// Driven by a type error (Int operand to a Bytes-only op) reached through the
/// same public helper the KATs use.
#[test]
#[should_panic(expected = "VM error in KAT")]
fn harness_surfaces_vm_errors_instead_of_reporting_them_as_mismatches() {
    // Program `[Shake256, PushBytes, Eq]` over a stack seeded with an Int: the
    // hash op pops a non-Bytes value -> VmError::TypeError.
    let program = [Op::Shake256, Op::PushBytes(vec![0u8; 32]), Op::Eq];
    let ctx = bloch_euvm::Ctx::default();
    let mut gas = euvm_conformance::KAT_GAS;
    // Mirror of vm_hash_matches' error handling, exercised via the real helper
    // below; this direct call only proves the seed really does error.
    assert!(matches!(
        bloch_euvm::run(&program, vec![bloch_euvm::Val::Int(7)], &ctx, &euvm_conformance::NopVerifier, &mut gas),
        Err(bloch_euvm::VmError::TypeError(_))
    ));
    // CONTROL side of the same fact: the helper must PANIC on that input, not
    // return false. `#[should_panic]` is the assertion.
    euvm_conformance::vm_hash_matches_int_seed(Op::Shake256, 7, &[0u8; 32]);
}
