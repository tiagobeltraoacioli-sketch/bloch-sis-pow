//! # bloch-sbpf — deterministic sBPF-style execution core (FOUNDATION, Front 1)
//!
//! Implements docs/specs/BLOCH-SBPF-CORE.md: a load-time **verifier** and a
//! deterministic, compute-metered **interpreter** for a declared subset of the
//! sBPF/eBPF instruction set, plus the BSC-0 program container.
//!
//! Honest scope, stated before anything else (spec §0):
//!
//! - **NOT "Solana compatible"** and forbidden from claiming so until the §9
//!   gate (a real `cargo build-sbf` program running under a pinned toolchain)
//!   is passed. No ELF loader, no sol_* syscalls, no loaders, no Sealevel.
//!   The public name of this work is "sBPF-style execution core (foundation)".
//! - **NOT a consensus change.** This crate is standalone — the exact posture
//!   `bloch-euvm` holds. It is NOT a dependency of bloch-pos-node or
//!   bloch-pos-committee and must never become one in passing: consensus
//!   wiring collides with ADR-040 (EVM at L1) and the SR-2 single-re-freeze
//!   rule (BLOCH-L1-EXECUTION-PLAN.md) and is a founder decision.
//! - **NOT a JIT.** The interpreter IS the candidate semantics; any future
//!   JIT must be proven bit-equivalent by differential testing.
//!
//! Security order of the two halves (spec item b): the **verifier is the
//! sandbox boundary** — `execute()` only accepts a [`VerifiedProgram`], whose
//! only constructor is [`load`], so running unverified bytecode is
//! unrepresentable by construction. A correct interpreter over a broken
//! verifier would be worthless; the verifier's checks are therefore each
//! pinned by a negative/control test pair AND a mutation proof (spec §10).
//!
//! Determinism inventory (spec item c) — where non-determinism could enter,
//! and how each door is closed:
//!
//! - **Host floating point** — closed three ways (§3-FP): the whitelist has
//!   no FP opcode (the ISA has none), the syscall surface has no math
//!   helper, and program-side soft-float compiles to integer instructions,
//!   which are deterministic anyway.
//! - **Map iteration order** — only `BTreeMap` in this crate (verify.rs
//!   function table, syscall.rs registry); no `HashMap` anywhere.
//! - **Host memory addresses** — programs only see the fixed virtual
//!   constants of mem.rs (0x1/2/3/4_0000_0000); no host pointer is
//!   observable, so ASLR cannot reach state.
//! - **Uninitialized memory** — STACK and HEAP are zeroed per execution
//!   (§5); uninitialized memory is per-machine entropy.
//! - **Alignment traps** — unaligned access is a checked byte copy (§3);
//!   no host alignment behaviour can leak through.
//! - **Integer overflow** — `wrapping_*` IS the defined semantics (§3); the
//!   workspace-wide `overflow-checks = true` profile makes any UNintended
//!   arithmetic fail identically on every profile.
//!
//! Bounded cost (spec item d): a caller-set `budget` is debited
//! charge-then-execute, 1 CU per instruction + per-byte syscall terms
//! (meter.rs); allocations are static ceilings only (text ≤ 65 536 slots,
//! rodata ≤ 512 KiB, stack 256 KiB, heap 32 KiB, log ≤ 32 KiB). Nothing
//! grows without a limit, and termination is the METER's job by design —
//! the verifier deliberately does no halting analysis (§4).

#![forbid(unsafe_code)]

pub mod container;
pub mod isa;
pub mod interp;
pub mod mem;
pub mod meter;
pub mod syscall;
pub mod verify;

pub use interp::{Fault, FaultKind, Outcome, VmCtx};
pub use syscall::{Syscall, SyscallRegistry, SYSCALL_ABORT, SYSCALL_LOG, SYSCALL_SHA3_256};
pub use verify::{VerifiedProgram, VerifyError};

/// Verify a BSC-0 container once at load (spec §1). The returned
/// [`VerifiedProgram`] is the ONLY token [`execute`] accepts.
pub fn load(container: &[u8]) -> Result<VerifiedProgram, VerifyError> {
    verify::load(container)
}

/// Execute a verified program against `input` under `budget` CU with the
/// given syscall registry. Infallible by signature: every failure is a
/// deterministic [`Fault`] inside the [`Outcome`], never a panic.
pub fn execute(
    p: &VerifiedProgram,
    input: &[u8],
    budget: u64,
    syscalls: &SyscallRegistry,
) -> Outcome {
    interp::execute(p, input, budget, syscalls)
}
