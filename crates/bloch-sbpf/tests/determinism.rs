//! D-series (spec §10): bit-identical re-execution and golden vectors over
//! the canonical Outcome encoding (§12-D).
//!
//! The golden hashes pin, all at once: the cost table (any SBPF_COST_* drift
//! without a COST_TABLE_VERSION bump), wrap/zero-extend semantics, the fault
//! encoding, the log encoding, and the heap/stack capture rules. Drift in ANY
//! of them breaks a pin loudly — that is their job. If a change is
//! INTENTIONAL, it is a spec amendment + version bump, and only then a new
//! vector.

mod common;
use common::*;

use sha3::{Digest, Sha3_256};

fn outcome_hash(container: &[u8], input: &[u8], budget: u64) -> String {
    let o = run(container, input, budget);
    let h = Sha3_256::digest(o.canonical_bytes());
    h.iter().map(|b| format!("{b:02x}")).collect()
}

// ── D1: same program + input, fresh VMs → byte-identical Outcome ──

#[test]
fn d1_reexecution_is_byte_identical() {
    // A fixture that exercises alu + lddw + heap store + log + sha3 so the
    // comparison covers every Outcome field.
    let [h1, h2] = lddw(3, HEAP_BASE);
    let c = simple(&[
        h1, h2,
        mov64_imm(2, 3),
        call_sys(SYS_SHA3),  // heap[0..32] = sha3(input[0..3])
        call_sys(SYS_LOG),   // log input[0..3]
        mov64_imm(4, 0xab),
        stxb(3, 4, 100),
        mov64_imm(0, 77),
        exit(),
    ]);
    let a = run(&c, b"abc", 100_000);
    let b = run(&c, b"abc", 100_000);
    assert_eq!(a, b);
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_eq!(a.result, Ok(77));
}

// ── D2: golden vectors, ≥ 5 fixtures, SHA3-256 pinned in-repo ──

/// Fixture 1: pure ALU arithmetic, success path.
fn fx1() -> Vec<u8> {
    let [l1, l2] = lddw(2, 0x1122_3344_5566_7788);
    simple(&[l1, l2, be(2, 64), mov64_reg(0, 2), add32_imm(0, 1), exit()])
}

/// Fixture 2: div-by-zero fault (fault encoding + total-fault discard).
fn fx2() -> Vec<u8> {
    simple(&[mov64_imm(0, 9), div64_imm(0, 0), exit()])
}

/// Fixture 3: syscalls — log + sha3 over the input, heap capture.
fn fx3() -> Vec<u8> {
    let [h1, h2] = lddw(3, HEAP_BASE);
    simple(&[h1, h2, mov64_imm(2, 16), call_sys(SYS_LOG), call_sys(SYS_SHA3), exit()])
}

/// Fixture 4: budget exhaustion in an unbounded loop (meter encoding).
fn fx4() -> Vec<u8> {
    simple(&[ja(-1)])
}

/// Fixture 5: recursion with per-frame stack stores (call convention +
/// stack capture).
fn fx5() -> Vec<u8> {
    let t = text(&[
        mov64_imm(6, 5),    // 0
        call_fn(1),         // 1
        mov64_reg(0, 6),    // 2
        exit(),             // 3
        stxdw(10, 6, -8),   // 4 (fn 1): frame-local copy of the counter
        jeq_imm(6, 0, 2),   // 5 → 8
        add64_imm(6, -1),   // 6
        call_fn(1),         // 7
        exit(),             // 8
    ]);
    bsc0(0, &[(0, 0), (1, 32)], &t, &[])
}

#[test]
fn d2_golden_vectors_pinned() {
    // (name, container, input, budget, expected SHA3-256 of canonical bytes)
    let vectors: [(&str, Vec<u8>, &[u8], u64, &str); 5] = [
        ("fx1-alu", fx1(), b"", 1_000,
         "12f9d3fdecb29139a8ab12a0f98d6a2e5eb739ecab5b8050782eefb2e169ad6a"),
        ("fx2-divzero", fx2(), b"", 1_000,
         "af27c9ee654d630feaf5d4b6e3a0473fd4b1d9a63cc55877e4752f4b33a703de"),
        ("fx3-syscalls", fx3(), b"sixteen bytes!!!", 10_000,
         "baef0f9e70c7d0a32dceb065853da050f70dcaab48d6da34d607658779d21e2e"),
        ("fx4-budget", fx4(), b"", 4_242,
         "72a71fdd8689138797b5eaa5bb1f21cd1bcac1e099a8caccc62b18b43d40e41f"),
        ("fx5-recursion", fx5(), b"", 10_000,
         "3f19219bf2843cabd22d6880d069ecdd8d7018f65c072bbb5449546e48f363a0"),
    ];
    let mut drifted = String::new();
    for (name, container, input, budget, want) in vectors {
        let got = outcome_hash(&container, input, budget);
        if got != want {
            drifted.push_str(&format!("  {name}: got {got}, pinned {want}\n"));
        }
    }
    assert!(
        drifted.is_empty(),
        "golden vectors drifted — if intentional, this is a spec amendment + \
         COST_TABLE_VERSION bump, not a hash update:\n{drifted}"
    );
}

#[test]
fn d2_canonical_bytes_carry_cost_table_version() {
    // First 4 bytes are COST_TABLE_VERSION LE (§12-D) — the versioning hook
    // that makes silent cost drift loud.
    let o = run(&fx1(), b"", 1_000);
    assert_eq!(&o.canonical_bytes()[..4], &1u32.to_le_bytes());
}

#[test]
fn d2_fault_outcome_encodes_empty_rw_regions() {
    let o = run(&fx2(), b"", 1_000);
    let bytes = o.canonical_bytes();
    // tail: log n=0 (4B) + heap len=0 (4B) + stack len=0 (4B)
    assert_eq!(&bytes[bytes.len() - 12..], &[0u8; 12]);
}
