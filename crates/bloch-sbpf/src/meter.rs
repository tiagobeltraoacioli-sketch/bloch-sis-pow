//! Compute meter + cost table v0 (spec §6) — the consensus clock.
//!
//! Cost is a pure function of the instruction stream executed, never of the
//! machine executing it: no wall-clock, no cache effects, no measured costs.
//! Termination is THIS module's job and only this module's — the verifier
//! deliberately does no loop analysis (§4).
//!
//! Changing ANY constant here without bumping `COST_TABLE_VERSION` is
//! semantically a hard-fork of anything that ever consumes this VM under
//! consensus (§6). The version is serialized into every canonical `Outcome`
//! (§12-D), so the D2 golden vectors make silent drift loud.

use crate::interp::FaultKind;

/// v0 cost table version — pinned into `Outcome` bytes and golden vectors.
pub const COST_TABLE_VERSION: u32 = 1;

/// Every §2-IN instruction costs 1 CU flat (the Solana base). Sound HERE
/// because no whitelisted instruction moves more than 8 bytes (`lddw`
/// included — 1 CU total, §12-H); all variable-length work enters through
/// syscalls, which carry per-byte terms below. This argument must be re-made
/// if any variable-length instruction is ever whitelisted (§6).
pub const SBPF_COST_INSN: u64 = 1;

/// `abort()` — flat base (§12-C, same base as log).
pub const SBPF_COST_SYSCALL_ABORT: u64 = 100;
/// `log(ptr, len)` — 100 + len. bloch-euvm's F2 lesson: length-dependent
/// work MUST have length-dependent cost, or one cheap op with a huge operand
/// buys unbounded machine work.
pub const SBPF_COST_SYSCALL_LOG_BASE: u64 = 100;
/// `sha3_256(ptr, len, out)` — 85 + ceil(len/2) (§6).
pub const SBPF_COST_SYSCALL_SHA3_BASE: u64 = 85;

/// Charge-then-execute meter (§6): the full cost of an instruction/syscall is
/// debited BEFORE it executes. Charging after would let one extra
/// instruction's side effects slip past the budget boundary — an off-by-one
/// that would become a consensus rule by accident.
pub struct Meter {
    budget: u64,
    used: u64,
}

impl Meter {
    pub fn new(budget: u64) -> Self {
        Meter { budget, used: 0 }
    }

    /// Debit `cost`; on exhaustion `used` snaps to exactly `budget` (§6 pins
    /// `cu_used == budget` on `ComputeBudgetExceeded`) and the fault is
    /// returned for the interpreter to make total.
    pub fn charge(&mut self, cost: u64) -> Result<(), FaultKind> {
        // self.used <= self.budget is an invariant, so the subtraction below
        // cannot underflow; written as checked anyway to be fail-closed under
        // the workspace-wide overflow-checks profile.
        let remaining = self.budget.checked_sub(self.used).unwrap_or(0);
        if cost > remaining {
            self.used = self.budget;
            return Err(FaultKind::ComputeBudgetExceeded);
        }
        self.used += cost;
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.used
    }
}
