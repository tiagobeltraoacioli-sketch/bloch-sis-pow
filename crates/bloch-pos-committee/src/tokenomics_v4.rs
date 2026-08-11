// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tokenomics V4 — Genesis-4 relaunch constants.
//!
//! Spec: `docs/specs/BLOCH-TOKENOMICS-V4.md`. Supersedes `tokenomics_v2.rs`
//! (21 B nominal, perpetual tail) and the ADR-035 emission V3 floor.
//!
//! **Nothing here is active.** These constants live in the standalone PoS crate
//! and are not referenced by the node. Genesis-4 is a fresh chain, so there is
//! no activation height to gate — the constants take effect only if and when a
//! new genesis is produced from them.
//!
//! ## The u64 hazard, front and centre
//!
//! 100 B BLCH at 8 decimals is 10^19 satoshis — **54.21% of `u64::MAX`**
//! (today's 21 B nominal is 11.38%). The total fits in a `u64`, but the sum of
//! any two large balances does not. Every quantity here is `u128`, and the
//! compile-time assertions below fail the build if a future edit walks the
//! supply back into the range where a single addition can wrap. A wrapped
//! consensus value is a chain split, and release builds wrap silently.

/// Satoshis per BLCH. Unchanged from V2 — divisibility is preserved; the
/// overflow question is answered with `u128`, not by dropping decimal places.
pub const SAT_PER_BLOCH: u128 = 100_000_000;

/// Fixed total supply. Hard-capped, unlike V2's perpetual tail.
pub const TOTAL_SUPPLY_BLOCH: u128 = 100_000_000_000;
pub const TOTAL_SUPPLY_SAT: u128 = TOTAL_SUPPLY_BLOCH * SAT_PER_BLOCH;

// ── Allocations ─────────────────────────────────────────────────────────────

pub const FOUNDER_BLOCH: u128 = 17_000_000_000; // 17%
pub const VC_BLOCH: u128 = 10_000_000_000; // 10%
pub const TEAM_BLOCH: u128 = 10_000_000_000; // 10%
pub const MARKETING_BLOCH: u128 = 4_000_000_000; //  4%
pub const LIQUIDITY_BLOCH: u128 = 5_000_000_000; //  5%

/// Hard ceiling on carried-over non-founder balances.
///
/// Measured floor from `carryover.tsv.gz` is 181,104,000 BLCH across four
/// non-founder addresses; third-party mining since Genesis-3 pushes the real
/// figure up continuously, so this cap is expected to bind (§3 of the spec).
pub const HOLDER_CARRYOVER_CAP_BLOCH: u128 = 300_000_000;

/// Validator emission — the remainder, spread over 40 years.
pub const VALIDATOR_EMISSION_BLOCH: u128 = TOTAL_SUPPLY_BLOCH
    - FOUNDER_BLOCH
    - VC_BLOCH
    - TEAM_BLOCH
    - MARKETING_BLOCH
    - LIQUIDITY_BLOCH
    - HOLDER_CARRYOVER_CAP_BLOCH;

// ── Time ────────────────────────────────────────────────────────────────────

/// Slots per day at a 30 s slot.
pub const SLOTS_PER_DAY: u64 = 2_880;
/// Slots per year, using 365.25 days.
pub const SLOTS_PER_YEAR: u64 = 1_051_920;
/// Emission runs for 40 years.
pub const EMISSION_YEARS: u64 = 40;
/// 42,076,800 slots.
pub const EMISSION_SLOTS: u64 = EMISSION_YEARS * SLOTS_PER_YEAR;

// ── Founder vesting: 2-year cliff, then 10-year linear ───────────────────────

pub const FOUNDER_CLIFF_SLOTS: u64 = 2 * SLOTS_PER_YEAR;
pub const FOUNDER_VESTING_SLOTS: u64 = 10 * SLOTS_PER_YEAR;
pub const FOUNDER_VESTING_END_SLOT: u64 = FOUNDER_CLIFF_SLOTS + FOUNDER_VESTING_SLOTS;

/// Founder satoshis unlocked by `slot`.
///
/// Linear **per slot** rather than in monthly tranches (V2 used 480 monthly
/// steps). A step function creates 480 moments where a large block of stake
/// becomes spendable at once — under PoS that is 480 scheduled opportunities to
/// move the stake distribution discontinuously, and every one of them is a
/// visible, game-able date. Per-slot linear has no such edges.
///
/// Integer division truncates, so the last slot is special-cased to release the
/// exact remainder. Without that, up to `FOUNDER_VESTING_SLOTS - 1` satoshis
/// would be permanently unspendable — harmless economically, but it would make
/// the supply accounting fail to balance, and a supply invariant that is
/// "nearly" satisfied is not an invariant.
pub const fn founder_vested_sat(slot: u64) -> u128 {
    let total = FOUNDER_BLOCH * SAT_PER_BLOCH;
    if slot < FOUNDER_CLIFF_SLOTS {
        return 0;
    }
    if slot >= FOUNDER_VESTING_END_SLOT {
        return total;
    }
    let elapsed = (slot - FOUNDER_CLIFF_SLOTS) as u128;
    total * elapsed / FOUNDER_VESTING_SLOTS as u128
}

// ── Validator emission ──────────────────────────────────────────────────────

/// Flat per-slot validator reward.
///
/// One of the three candidate curves in §6 of the spec (flat / halving / smooth
/// decay); the choice is **not yet made**. Flat is implemented here because it
/// is the only one that needs no further parameters, so it can serve as the
/// reference against which the others are compared.
pub const fn validator_reward_sat(slot: u64) -> u128 {
    if slot >= EMISSION_SLOTS {
        return 0; // fee-only from here on
    }
    (VALIDATOR_EMISSION_BLOCH * SAT_PER_BLOCH) / EMISSION_SLOTS as u128
}

/// Total emitted to validators by `slot`, used for supply accounting.
pub const fn validator_emitted_by(slot: u64) -> u128 {
    let s = if slot > EMISSION_SLOTS { EMISSION_SLOTS } else { slot };
    validator_reward_sat(0) * s as u128
}

// ── Carryover scale-down ────────────────────────────────────────────────────

/// Scale one non-founder balance to fit under [`HOLDER_CARRYOVER_CAP_BLOCH`].
///
/// Pro-rata, deterministic, no discretion: if measured non-founder holdings
/// exceed the cap, every balance is multiplied by `cap / total`. It treats a
/// holder identically regardless of when they acquired the coins, which a
/// first-come or per-address rule would not.
///
/// `u128` throughout because `balance_sat * cap_sat` is the product of two
/// numbers each up to ~10^19 — that overflows `u64` by twenty orders of
/// magnitude, and it is exactly the kind of expression that looks harmless.
pub fn scaled_carryover_sat(balance_sat: u128, total_non_founder_sat: u128) -> u128 {
    let cap_sat = HOLDER_CARRYOVER_CAP_BLOCH * SAT_PER_BLOCH;
    if total_non_founder_sat <= cap_sat || total_non_founder_sat == 0 {
        return balance_sat;
    }
    balance_sat * cap_sat / total_non_founder_sat
}

// ── Invariants checked at compile time ──────────────────────────────────────

const _: () = assert!(
    FOUNDER_BLOCH
        + VC_BLOCH
        + TEAM_BLOCH
        + MARKETING_BLOCH
        + LIQUIDITY_BLOCH
        + HOLDER_CARRYOVER_CAP_BLOCH
        + VALIDATOR_EMISSION_BLOCH
        == TOTAL_SUPPLY_BLOCH,
    "as alocacoes nao somam o supply total"
);

const _: () = assert!(
    VALIDATOR_EMISSION_BLOCH == 53_700_000_000,
    "resto para validadores mudou — reveja a especificacao antes de aceitar"
);

const _: () = assert!(EMISSION_SLOTS == 42_076_800, "grade de tempo mudou");

/// The reason every quantity above is `u128`: the supply does not fit in a
/// `u64` with room to add. If a future edit lowers the supply enough that it
/// would fit safely, this assertion is the place to reconsider — deliberately,
/// not by accident.
const _: () = assert!(
    TOTAL_SUPPLY_SAT > (u64::MAX as u128) / 2,
    "supply agora cabe com folga em u64 — reavalie a escolha de u128 explicitamente"
);
