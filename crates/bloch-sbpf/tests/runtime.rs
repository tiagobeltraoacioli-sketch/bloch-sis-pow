//! Runtime tests — spec §10 R-series (memory), M-series (meter), syscalls,
//! and total-fault semantics. Negative/control pairs throughout.

mod common;
use common::*;

use bloch_sbpf::{execute, load, FaultKind, SyscallRegistry};

// ── R1: region permissions ──

#[test]
fn r1_store_into_text_faults() {
    let [l1, l2] = lddw(2, TEXT_BASE);
    let c = simple(&[l1, l2, stxb(2, 0, 0), exit()]);
    let o = run(&c, &[], 100);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::AccessViolation { va: TEXT_BASE, len: 1, write: true });
    assert_eq!(f.pc, 2);
    // Total fault (§3): memory effects discarded.
    assert!(o.heap.is_empty() && o.stack.is_empty());
}

#[test]
fn r1_control_same_store_into_stack_runs() {
    // Minimally different: the base VA is STACK_BASE-side (via r10) instead.
    let c = simple(&[mov64_imm(3, 0x5a), stxb(10, 3, -1), ldxb(0, 10, -1), exit()]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(0x5a));
    // The byte IS in the captured stack region: r10(frame 1) = STACK_BASE +
    // 4096, so offset -1 = stack[4095].
    assert_eq!(o.stack[4095], 0x5a);
}

#[test]
fn r1_store_into_input_faults_v0_readonly() {
    // §5: INPUT is read-only in v0 (no writeback contract yet).
    let c = simple(&[stb(1, 0, 7), exit()]);
    let o = run(&c, b"abc", 100);
    assert_eq!(
        o.result.unwrap_err().kind,
        FaultKind::AccessViolation { va: INPUT_BASE, len: 1, write: true }
    );
}

// ── R2: unmapped addresses ──

#[test]
fn r2_load_below_first_region_faults() {
    // VA 0 — there is no page 0 (§5).
    let c = simple(&[mov64_imm(2, 0), ldxdw(0, 2, 0), exit()]);
    let o = run(&c, &[], 100);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::AccessViolation { va: 0, len: 8, write: false });
    assert_eq!(f.pc, 1);
}

#[test]
fn r2_control_load_from_input_runs() {
    let c = simple(&[ldxdw(0, 1, 0), exit()]);
    let o = run(&c, &0x0102_0304_0506_0708u64.to_le_bytes(), 100);
    assert_eq!(o.result, Ok(0x0102_0304_0506_0708));
}

// ── R3: off-by-one at a region end ──

#[test]
fn r3_load_one_byte_past_input_end_faults() {
    // 16-byte input: an 8-byte load at +9 ends at +17 — one past the end.
    let c = simple(&[ldxdw(0, 1, 9), exit()]);
    let o = run(&c, &[0u8; 16], 100);
    assert_eq!(
        o.result.unwrap_err().kind,
        FaultKind::AccessViolation { va: INPUT_BASE + 9, len: 8, write: false }
    );
}

#[test]
fn r3_control_one_address_lower_runs() {
    // +8 ends exactly at the end: legal. Pins the bound as `<=`, not `<`.
    let mut input = [0u8; 16];
    input[8..].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let c = simple(&[ldxdw(0, 1, 8), exit()]);
    let o = run(&c, &input, 100);
    assert_eq!(o.result, Ok(0x1122_3344_5566_7788));
}

// ── R4: div by zero ──

#[test]
fn r4_div_by_zero_faults() {
    let c = simple(&[mov64_imm(0, 10), mov64_imm(2, 0), div64_reg(0, 2), exit()]);
    let o = run(&c, &[], 100);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::DivByZero);
    assert_eq!(f.pc, 2);
    assert_eq!(o.cu_used, 3); // charge includes the faulting instruction (§3)
}

#[test]
fn r4_control_divisor_one_runs() {
    let c = simple(&[mov64_imm(0, 10), mov64_imm(2, 1), div64_reg(0, 2), exit()]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(10));
    assert_eq!(o.cu_used, 4);
}

#[test]
fn r4_div_by_zero_imm_faults_mod_too() {
    let c = simple(&[mov64_imm(0, 10), div64_imm(0, 0), exit()]);
    assert_eq!(run(&c, &[], 100).result.unwrap_err().kind, FaultKind::DivByZero);
    let c = simple(&[mov64_imm(0, 10), mod64_imm(0, 0), exit()]);
    assert_eq!(run(&c, &[], 100).result.unwrap_err().kind, FaultKind::DivByZero);
}

// ── R5: call depth ──

/// Recursion fixture (§12-B convention): entry sets r6 = n and calls fn 1,
/// which recurses while r6 > 0. Max depth reached = n + 2.
fn recursion(n: i32) -> Vec<u8> {
    let t = text(&[
        mov64_imm(6, n),   // 0
        call_fn(1),        // 1
        mov64_reg(0, 6),   // 2  r0 = r6 AFTER return: proves restore (§12-B)
        exit(),            // 3
        jeq_imm(6, 0, 2),  // 4 (fn 1)  → 7
        add64_imm(6, -1),  // 5
        call_fn(1),        // 6
        exit(),            // 7
    ]);
    bsc0(0, &[(0, 0), (1, 32)], &t, &[])
}

#[test]
fn r5_depth_65_faults() {
    // n = 63 → attempts frame 65.
    let o = run(&recursion(63), &[], 100_000);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::CallDepthExceeded);
    assert_eq!(f.pc, 6);
}

#[test]
fn r5_control_depth_64_runs_and_restores_r6() {
    // n = 62 → max depth exactly 64; entry's r6 must come back as 62 even
    // though the recursion drove its own copies to 0.
    let o = run(&recursion(62), &[], 100_000);
    assert_eq!(o.result, Ok(62));
}

#[test]
fn r5_frame_pointer_isolated_per_frame() {
    // Callee writes *(r10 - 8); caller's *(r10 - 8) must be untouched —
    // frames are disjoint 4 KiB windows (§5, §12-B).
    let t = text(&[
        mov64_imm(3, 7),   // 0
        stxdw(10, 3, -8),  // 1  caller frame slot = 7
        call_fn(1),        // 2
        ldxdw(0, 10, -8),  // 3  read back caller slot
        exit(),            // 4
        mov64_imm(3, 9),   // 5 (fn 1)
        stxdw(10, 3, -8),  // 6  callee frame slot = 9 (different window)
        exit(),            // 7
    ]);
    let c = bsc0(0, &[(0, 0), (1, 40)], &t, &[]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(7));
    // Both frames visible in the captured stack: frame1 top-8 and frame2 top-8.
    assert_eq!(o.stack[4096 - 8], 7);
    assert_eq!(o.stack[8192 - 8], 9);
}

// ── M1/M2: the meter ──

#[test]
fn m1_unbounded_loop_exhausts_budget_pinned() {
    // ja -1 → jumps to itself forever.
    let c = simple(&[ja(-1)]);
    let o = run(&c, &[], 10_000);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::ComputeBudgetExceeded);
    assert_eq!(o.cu_used, 10_000, "§6 pins cu_used == budget on exhaustion");
    assert_eq!(f.pc, 0, "faulting PC must be bit-identical on every node");
}

#[test]
fn m1_control_counted_loop_exact_cu() {
    // mov(1) + 100 × (add + jne)(2) + exit(1) = 202 CU.
    let c = simple(&[mov64_imm(2, 100), add64_imm(2, -1), jne_imm(2, 0, -2), exit()]);
    let o = run(&c, &[], 10_000);
    assert_eq!(o.result, Ok(0));
    assert_eq!(o.cu_used, 202);
}

#[test]
fn m2_budget_boundary_charge_then_execute() {
    // Program needs exactly 2 CU (mov + exit).
    let c = simple(&[mov64_imm(0, 5), exit()]);
    // Budget N: succeeds with cu_used == N.
    let o = run(&c, &[], 2);
    assert_eq!(o.result, Ok(5));
    assert_eq!(o.cu_used, 2);
    // Budget N−1: the exit is charged BEFORE executing → clean fault at its
    // pc, no partial effect (§6's off-by-one argument).
    let o = run(&c, &[], 1);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::ComputeBudgetExceeded);
    assert_eq!(f.pc, 1);
    assert_eq!(o.cu_used, 1);
}

#[test]
fn m2_zero_budget_first_instruction_faults() {
    let c = simple(&[exit()]);
    let o = run(&c, &[], 0);
    assert_eq!(o.result.unwrap_err().kind, FaultKind::ComputeBudgetExceeded);
    assert_eq!(o.cu_used, 0);
}

// ── Running off the end of text (§3) ──

#[test]
fn falling_off_text_end_faults() {
    let c = simple(&[mov64_imm(0, 1)]); // no exit
    let o = run(&c, &[], 100);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::TextOverrun);
    assert_eq!(f.pc, 1); // first nonexistent slot
}

// ── Syscalls (§7, §12-C/I) ──

#[test]
fn syscall_abort_faults_with_charge() {
    let c = simple(&[call_sys(SYS_ABORT), exit()]);
    let o = run(&c, &[], 1000);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::Aborted);
    assert_eq!(f.pc, 0);
    assert_eq!(o.cu_used, 101); // call insn (1) + abort base (100)
}

#[test]
fn syscall_missing_from_registry_faults_deterministically() {
    // Verifies fine (id 2 IS a pinned v0 id, §12-C) — the runtime gap is the
    // deterministic fault, not a panic.
    let c = simple(&[mov64_imm(2, 1), call_sys(SYS_LOG), exit()]);
    let p = load(&c).unwrap();
    let o = execute(&p, b"x", 1000, &SyscallRegistry::empty());
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::UnknownSyscall { id: SYS_LOG });
    assert_eq!(f.pc, 1);
}

#[test]
fn syscall_log_over_per_call_cap_faults() {
    // len 1025 > 1 KiB cap → LogLimitExceeded, AFTER the CU charge (§12-I).
    let c = simple(&[mov64_imm(2, 1025), call_sys(SYS_LOG), exit()]);
    let o = run(&c, &vec![0u8; 2048], 10_000);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::LogLimitExceeded);
    assert_eq!(o.cu_used, 1 + 1 + 100 + 1025); // movs+call insns + charged cost
    assert!(o.log.is_empty());
}

#[test]
fn syscall_log_control_at_per_call_cap_runs() {
    let c = simple(&[mov64_imm(2, 1024), call_sys(SYS_LOG), exit()]);
    let o = run(&c, &vec![7u8; 1024], 10_000);
    assert_eq!(o.result, Ok(0));
    assert_eq!(o.log.len(), 1);
    assert_eq!(o.log[0], vec![7u8; 1024]);
}

/// Loop fixture: `iters` log calls of `len` bytes each.
fn log_loop(iters: i32, len: i32) -> Vec<u8> {
    simple(&[
        mov64_imm(2, len),        // 0
        mov64_imm(6, iters),      // 1
        call_sys(SYS_LOG),        // 2
        add64_imm(6, -1),         // 3
        jne_imm(6, 0, -3),        // 4 → 2
        exit(),                   // 5
    ])
}

#[test]
fn syscall_log_total_cap_faults_on_33rd_kib() {
    // 33 × 1024 = 33 792 > 32 768: the 33rd call faults; 32 entries stand —
    // the log survives a fault (§12-D: observability, already CU-paid).
    let o = run(&log_loop(33, 1024), &vec![0u8; 1024], 100_000);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::LogLimitExceeded);
    assert_eq!(f.pc, 2);
    assert_eq!(o.log.len(), 32);
}

#[test]
fn syscall_log_total_cap_control_32_kib_runs() {
    let o = run(&log_loop(32, 1024), &vec![0u8; 1024], 100_000);
    assert_eq!(o.result, Ok(0));
    assert_eq!(o.log.len(), 32);
}

#[test]
fn syscall_sha3_known_answer_and_cost() {
    // sha3_256(INPUT[0..3] = "abc") → HEAP[0..32]; cost 85 + ceil(3/2) = 87.
    let [l1, l2] = lddw(3, HEAP_BASE);
    let c = simple(&[mov64_imm(2, 3), l1, l2, call_sys(SYS_SHA3), exit()]);
    let o = run(&c, b"abc", 1000);
    assert_eq!(o.result, Ok(0));
    // Independent expectation: SHA3-256("abc"), the standard KAT value.
    let expect = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    let got: String = o.heap[..32].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, expect);
    assert_eq!(o.cu_used, 4 + 87); // mov+lddw+call+exit insns + syscall term
}

#[test]
fn syscall_sha3_output_into_readonly_faults() {
    // out_ptr in INPUT (read-only): the write is refused by the SAME memory
    // path instructions use — syscalls get no privileged access.
    let c = simple(&[mov64_imm(2, 3), mov64_reg(3, 1), call_sys(SYS_SHA3), exit()]);
    let o = run(&c, b"abc", 1000);
    assert_eq!(
        o.result.unwrap_err().kind,
        FaultKind::AccessViolation { va: INPUT_BASE, len: 32, write: true }
    );
}

#[test]
fn syscall_log_huge_len_saturates_charge_to_budget_exhaustion() {
    // len = u64::MAX via lddw r2: the 100+len charge saturates and exhausts
    // ANY budget deterministically — no wrap into a cheap log (§12-I).
    let [l1, l2] = lddw(2, u64::MAX);
    let c = simple(&[l1, l2, call_sys(SYS_LOG), exit()]);
    let o = run(&c, &[], 1_000_000);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::ComputeBudgetExceeded);
    assert_eq!(o.cu_used, 1_000_000);
}

// ── Total-fault semantics (§3, §12-D) ──

#[test]
fn fault_discards_heap_but_keeps_log() {
    let [l1, l2] = lddw(3, HEAP_BASE);
    let c = simple(&[
        l1, l2,
        mov64_imm(4, 0x77),
        stxb(3, 4, 0),        // heap[0] = 0x77
        mov64_imm(2, 3),
        call_sys(SYS_LOG),    // log "abc"
        div64_imm(0, 0),      // then fault
        exit(),
    ]);
    let o = run(&c, b"abc", 10_000);
    assert_eq!(o.result.unwrap_err().kind, FaultKind::DivByZero);
    assert!(o.heap.is_empty(), "memory effects discarded on fault");
    assert!(o.stack.is_empty());
    assert_eq!(o.log, vec![b"abc".to_vec()], "log survives (§12-D)");
}

#[test]
fn success_captures_heap_and_stack() {
    let [l1, l2] = lddw(3, HEAP_BASE);
    let c = simple(&[l1, l2, mov64_imm(4, 0x42), stxb(3, 4, 5), exit()]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(0));
    assert_eq!(o.heap.len(), 32 * 1024);
    assert_eq!(o.heap[5], 0x42);
    assert_eq!(o.stack.len(), 256 * 1024);
}

// ── Address arithmetic: no wrap-around trick (§5) ──

#[test]
fn wraparound_address_faults() {
    // VA = u64::MAX with an 8-byte load: `va + len` WRAPS to 7. Without the
    // `checked_add` in mem.rs::translate, the range test `va >= base && end <=
    // base + size` would pass (huge va ≥ base, tiny end ≤ end-of-region) and
    // the offset `va - base` would index far past the region. checked_add
    // makes the wrap itself the fault.
    let [l1, l2] = lddw(2, u64::MAX);
    let c = simple(&[l1, l2, ldxdw(0, 2, 0), exit()]);
    let o = run(&c, &[0u8; 16], 100);
    assert_eq!(
        o.result.unwrap_err().kind,
        FaultKind::AccessViolation { va: u64::MAX, len: 8, write: false }
    );
}

#[test]
fn wraparound_address_control_one_region_lower_runs() {
    // Same shape at a legal VA: proves the fixture faults for the wrap, not
    // for being an 8-byte load through r2.
    let [l1, l2] = lddw(2, INPUT_BASE);
    let c = simple(&[l1, l2, ldxdw(0, 2, 0), exit()]);
    assert_eq!(run(&c, &[7u8; 16], 100).result, Ok(0x0707_0707_0707_0707));
}

// ── Zero-initialization is a determinism requirement (§5) ──

#[test]
fn heap_and_stack_are_zero_initialized() {
    // A program that touches nothing must still report all-zero RW regions:
    // uninitialized memory would be per-machine entropy in the Outcome.
    let c = simple(&[exit()]);
    let o = run(&c, &[], 10);
    assert!(o.heap.iter().all(|&b| b == 0));
    assert!(o.stack.iter().all(|&b| b == 0));
    // And a program CAN read them back as zero.
    let c = simple(&[ldxdw(0, 10, -8), exit()]);
    assert_eq!(run(&c, &[], 10).result, Ok(0));
}
