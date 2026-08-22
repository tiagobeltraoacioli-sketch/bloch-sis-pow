// SPDX-License-Identifier: AGPL-3.0-or-later

//! The compute meter (spec §6.3): deterministic integer accounting, charged
//! **before** each unit of work.
//!
//! Charge-then-do is the load-bearing rule: exhaustion cannot depend on how
//! far a non-deterministic "do" got, because the refused charge never did
//! anything. The reading at refusal is therefore exact and reproducible —
//! §8-5 pins it across thread counts and repeated runs.
//!
//! The cost schedule (params.rs) is v0-honest: calibrated well enough to
//! bound worst-case block time, NOT claimed equivalent to Solana's CU
//! schedule (spec §11). Overflow anywhere in the meter = typed abort, never
//! wrap (§6.3) — and the workspace's `overflow-checks = true` (root
//! Cargo.toml, the euvm F3 lesson) backstops even that with a panic rather
//! than a silent wrap, but this module never reaches the backstop: every
//! addition is `checked_add`.

use crate::errors::MeterError;

/// The per-transaction compute meter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeMeter {
    budget: u32,
    consumed: u32,
}

impl ComputeMeter {
    /// A meter holding the transaction's declared budget (§5.1: declared,
    /// not discovered).
    pub fn new(budget: u32) -> Self {
        ComputeMeter { budget, consumed: 0 }
    }

    /// Charge `cost` units, or refuse. On refusal `consumed` is unchanged —
    /// that is what makes the exhaustion reading exact: the failed charge
    /// left no trace, so every node that replays the same instruction stream
    /// refuses at the identical reading.
    pub fn charge(&mut self, cost: u32) -> Result<(), MeterError> {
        let next = self.consumed.checked_add(cost).ok_or(MeterError::Overflow)?;
        if next > self.budget {
            return Err(MeterError::Exhausted {
                requested: cost,
                consumed: self.consumed,
                budget: self.budget,
            });
        }
        self.consumed = next;
        Ok(())
    }

    /// Charge a byte-proportional cost: `base + per_byte * len`, computed in
    /// u64 and refused as [`MeterError::Overflow`] if it exceeds u32 — a
    /// hostile length must exhaust the meter, not wrap it.
    pub fn charge_bytes(&mut self, base: u32, per_byte: u32, len: usize) -> Result<(), MeterError> {
        let total = u64::from(base)
            .checked_add(u64::from(per_byte).saturating_mul(len as u64))
            .ok_or(MeterError::Overflow)?;
        let total: u32 = total.try_into().map_err(|_| MeterError::Overflow)?;
        self.charge(total)
    }

    /// Units consumed so far — the reading the abort path records.
    pub fn consumed(&self) -> u32 {
        self.consumed
    }

    /// The declared budget.
    pub fn budget(&self) -> u32 {
        self.budget
    }

    /// Units still available.
    pub fn remaining(&self) -> u32 {
        // Total: consumed ≤ budget is an invariant of `charge`.
        self.budget.saturating_sub(self.consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §8-5 core: exhaustion refuses at an exact, unchanged reading.
    /// **Control:** a budget of exactly the next step's cost completes.
    #[test]
    fn charge_then_do_is_exact() {
        let mut m = ComputeMeter::new(250);
        assert!(m.charge(100).is_ok());
        assert!(m.charge(100).is_ok());
        // 200 consumed; 100 more would cross 250.
        assert_eq!(
            m.charge(100),
            Err(MeterError::Exhausted { requested: 100, consumed: 200, budget: 250 })
        );
        // The refused charge left no trace — the reading did not move.
        assert_eq!(m.consumed(), 200);
        // Control: exactly the remaining 50 completes.
        assert!(m.charge(50).is_ok());
        assert_eq!(m.consumed(), 250);
        assert_eq!(m.remaining(), 0);
    }

    /// Overflow is a typed refusal, never a wrap (§6.3).
    #[test]
    fn overflow_aborts_never_wraps() {
        let mut m = ComputeMeter::new(u32::MAX);
        assert!(m.charge(u32::MAX - 1).is_ok());
        assert_eq!(m.charge(u32::MAX), Err(MeterError::Overflow));
        assert_eq!(m.consumed(), u32::MAX - 1, "refused charge left no trace");
        // charge_bytes with a hostile length refuses the same way.
        let mut m2 = ComputeMeter::new(u32::MAX);
        assert_eq!(m2.charge_bytes(1, u32::MAX, usize::MAX), Err(MeterError::Overflow));
    }

    /// charge_bytes arithmetic is the documented base + per_byte * len.
    #[test]
    fn byte_charges_are_linear() {
        let mut m = ComputeMeter::new(1_000);
        assert!(m.charge_bytes(100, 10, 5).is_ok());
        assert_eq!(m.consumed(), 150);
    }
}
