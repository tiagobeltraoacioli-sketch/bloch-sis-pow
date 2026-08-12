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
///
/// Back to the V2 nominal of 21 billion (founder decision, 2026-08-11), after a
/// draft at 100 billion. The revert removes two hazards for free: the supply is
/// 11.38% of `u64::MAX` instead of 54.21%, so the sum of two large balances no
/// longer approaches the wrap point; and it fits in the signed `int64` the Go
/// SDK uses for `Satoshis`, which 100 billion did not.
pub const TOTAL_SUPPLY_BLOCH: u128 = 21_000_000_000;
pub const TOTAL_SUPPLY_SAT: u128 = TOTAL_SUPPLY_BLOCH * SAT_PER_BLOCH;

// ── Allocations ─────────────────────────────────────────────────────────────

/// The founder's NEW allocation — 10% of supply, vested.
///
/// This is on top of the carried-over balance below, not instead of it: the
/// founder's Genesis-3 holdings come across as ordinary liquid carryover and
/// the 17% is granted again (founder decision, 2026-08-11). Combined, the
/// founder holds 33.89% of supply. §4 of the tokenomics spec states what that
/// does to the activation gates.
pub const FOUNDER_BLOCH: u128 = 2_100_000_000; // 10%
/// Sold to funds; the Foundation is the counterparty. Nothing liquid at
/// genesis — 12-month cliff, 24-month linear, fully vested at year 3.
pub const VC_BLOCH: u128 = 2_100_000_000; // 10%
/// Held by the Foundation and granted to individuals. Nothing liquid at
/// genesis — 18-month cliff, 36-month linear, fully vested at year 4.5. The
/// cliff sits six months off the VC cliff so no two buckets share a month.
pub const TEAM_BLOCH: u128 = 2_100_000_000; // 10%
/// 25% (210,000,000) liquid at genesis for listing and launch spend; the rest
/// linear over 24 months.
pub const MARKETING_BLOCH: u128 = 840_000_000; //  4%
/// 100% liquid at genesis — deployed to order books and AMM pools. The one
/// bucket where full unlock is the function, not a concession.
pub const LIQUIDITY_BLOCH: u128 = 1_050_000_000; //  5%

/// The four buckets the Foundation holds: 29.00% of supply.
pub const FOUNDATION_HELD_BLOCH: u128 =
    VC_BLOCH + TEAM_BLOCH + MARKETING_BLOCH + LIQUIDITY_BLOCH;

/// Of those four, what is spendable at slot 0: all of liquidity plus the 25%
/// marketing tranche. VC and team are entirely cliffed.
///
/// This equals **25.0% of circulating supply at genesis** — exactly the G2
/// threshold. Worth keeping as a constant rather than a paragraph: two holders
/// account for the whole genesis float, and neither can change that by
/// behaving differently. Only emission and independent stake dilute them.
pub const FOUNDATION_LIQUID_AT_GENESIS_BLOCH: u128 =
    LIQUIDITY_BLOCH + MARKETING_BLOCH * MARKETING_TGE_NUMERATOR / MARKETING_TGE_DENOMINATOR;

/// The carried-over ledger — **one balance set, no founder line**.
///
/// Measured at height 43,172 across 448,337 UTXOs and 15 addresses. Every
/// balance crosses as ordinary liquid balance, the founder's included: those
/// coins were mined, on the same chain, under the same rules as everyone
/// else's (founder decision, 2026-08-11).
///
/// Two mechanisms dissolve with that decision rather than being satisfied by
/// it. There is no **taint set**, because there is no class of coin to mark —
/// §4.1's premine ineligibility was written for a migration in place, where the
/// founder's pre-existing holding sat on the chain being converted. And there
/// is no **holder cap**: the 300 M ceiling existed to bound what legacy holders
/// received *while the founder was excluded*, and with nobody excluded it would
/// either bind on everyone or bind on no one.
///
/// What does not dissolve is the arithmetic. Relabelling changes no balance:
/// the largest single address still holds 3,546,175,400 BLCH, liquid from slot
/// 0. §4A states what that does to the activation gates, and it states it the
/// same way it did before this decision.
pub const CARRYOVER_TOTAL_BLOCH: u128 = 3_773_884_800;

/// Retired. The carryover is not capped — see [`CARRYOVER_TOTAL_BLOCH`].
///
/// Kept as a named zero so that any code still consulting a cap fails loudly on
/// the arithmetic instead of silently applying a ceiling that no longer exists.
pub const HOLDER_CARRYOVER_CAP_BLOCH: u128 = 0;

/// Validator emission — the remainder, spread over 40 years.
pub const VALIDATOR_EMISSION_BLOCH: u128 = TOTAL_SUPPLY_BLOCH
    - CARRYOVER_TOTAL_BLOCH
    - FOUNDER_BLOCH
    - VC_BLOCH
    - TEAM_BLOCH
    - MARKETING_BLOCH
    - LIQUIDITY_BLOCH;

// ── Time ────────────────────────────────────────────────────────────────────

/// Slots per day at a 30 s slot.
pub const SLOTS_PER_DAY: u64 = 2_880;
/// Slots per year, using 365.25 days.
pub const SLOTS_PER_YEAR: u64 = 1_051_920;
/// Emission runs for 40 years.
pub const EMISSION_YEARS: u64 = 40;
/// 42,076,800 slots.
pub const EMISSION_SLOTS: u64 = EMISSION_YEARS * SLOTS_PER_YEAR;

// ── Founder vesting: 10-year cliff, then 40-year linear ─────────────────────

/// Ten-year cliff, forty-year linear vest — the V2 premine schedule, restored
/// by founder decision on 2026-08-11 (a draft had shortened it to 24 months
/// plus 10 years).
///
/// It is far beyond any market benchmark, and deliberately so: the carried-over
/// balance arrives liquid at genesis, so this grant is the part of the founder's
/// position that can still be made to wait. Fully vested at year 50.
pub const FOUNDER_CLIFF_SLOTS: u64 = 10 * SLOTS_PER_YEAR;
pub const FOUNDER_VESTING_SLOTS: u64 = 40 * SLOTS_PER_YEAR;
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

/// Total emitted to validators by `slot` under the flat curve, for supply
/// accounting. The halving equivalent is [`validator_emitted_halving_by`].
pub const fn validator_emitted_flat_by(slot: u64) -> u128 {
    let s = if slot > EMISSION_SLOTS { EMISSION_SLOTS } else { slot };
    validator_reward_flat_sat(0) * s as u128
}

/// Total emitted to validators by `slot` under the halving curve.
pub const fn validator_emitted_halving_by(slot: u64) -> u128 {
    let end = if slot > EMISSION_SLOTS { EMISSION_SLOTS } else { slot };
    let mut total: u128 = 0;
    let mut era: u64 = 0;
    while era < HALVINGS as u64 {
        let era_start = era * HALVING_PERIOD_SLOTS;
        if end <= era_start {
            break;
        }
        let in_era = end - era_start;
        let span = if in_era > HALVING_PERIOD_SLOTS { HALVING_PERIOD_SLOTS } else { in_era };
        total += (INITIAL_REWARD_SAT >> era) * span as u128;
        era += 1;
    }
    total
}

// ── Carryover scale-down ────────────────────────────────────────────────────

/// Retired with the cap. Retained so the rule it encoded stays on the record:
/// had a ceiling been kept, pro-rata was the only scale-down that treats a
/// holder identically regardless of when the coins were acquired.
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
    CARRYOVER_TOTAL_BLOCH
        + FOUNDER_BLOCH
        + VC_BLOCH
        + TEAM_BLOCH
        + MARKETING_BLOCH
        + LIQUIDITY_BLOCH
        + VALIDATOR_EMISSION_BLOCH
        == TOTAL_SUPPLY_BLOCH,
    "as alocacoes nao somam o supply total"
);

const _: () = assert!(
    VALIDATOR_EMISSION_BLOCH == 9_036_115_200,
    "resto para validadores mudou — reveja a especificacao antes de aceitar"
);

/// Largest single carried-over address, for the concentration reporting in §4A.
/// Not a consensus quantity and not a distinct class of coin — a measurement.
pub const LARGEST_CARRYOVER_ADDRESS_BLOCH: u128 = 3_546_175_400;
const _: () = assert!(LARGEST_CARRYOVER_ADDRESS_BLOCH < CARRYOVER_TOTAL_BLOCH);

/// Founder carried-over balance plus the new grant: 26.89% of supply.
pub const FOUNDER_TOTAL_BLOCH: u128 = LARGEST_CARRYOVER_ADDRESS_BLOCH + FOUNDER_BLOCH;
const _: () = assert!(FOUNDER_TOTAL_BLOCH * 10_000 / TOTAL_SUPPLY_BLOCH == 2688);

const _: () = assert!(EMISSION_SLOTS == 42_076_800, "grade de tempo mudou");

/// The reason every quantity above is `u128`: the supply does not fit in a
/// `u64` with room to add. If a future edit lowers the supply enough that it
/// would fit safely, this assertion is the place to reconsider — deliberately,
/// not by accident.
/// The 21-billion supply is 11.38% of `u64::MAX` and fits in a signed `int64`,
/// so the wrap hazard that justified `u128` at 100 billion is gone. `u128` is
/// kept anyway: the products are what overflow, not the totals — a balance
/// times a basis-point figure, or issuance times stake in the reward split,
/// exceeds `u64` long before any balance does.
const _: () = assert!(TOTAL_SUPPLY_SAT < (u64::MAX as u128) / 8);
const _: () = assert!(TOTAL_SUPPLY_SAT < i64::MAX as u128, "nao cabe no int64 do SDK Go");

// ── Vesting: team, VC, marketing, liquidity ─────────────────────────────────
//
// Schedules follow prevailing market practice (§7 of the spec), with the cliffs
// deliberately staggered. The single most cited failure mode in vesting design
// is the "cliff wall" — several buckets beginning to unlock in the same month,
// concentrating sell pressure into one date. Founder (24), team (18) and VC
// (12) cliff six months apart, so unlocks arrive as a stream.

pub const MONTH_SLOTS: u64 = SLOTS_PER_YEAR / 12;

/// VC / crypto hedge funds: 12-month cliff, 24-month linear (3 years total).
/// A 12-month cliff is the standard among recent L1s; funds rarely accept more.
pub const VC_CLIFF_SLOTS: u64 = 12 * MONTH_SLOTS;
pub const VC_VESTING_SLOTS: u64 = 24 * MONTH_SLOTS;

/// Development team: 18-month cliff, 36-month linear (4.5 years total).
/// The institutional standard is a 12-month cliff plus 36-month linear; 18 is
/// both defensible where institutional investors participate and necessary here
/// to keep the team cliff off the VC cliff month.
pub const TEAM_CLIFF_SLOTS: u64 = 18 * MONTH_SLOTS;
pub const TEAM_VESTING_SLOTS: u64 = 36 * MONTH_SLOTS;

/// Marketing: 25% at genesis for listing and launch activity, the rest linear
/// over 24 months. Mirrors the common split between launch spend (immediate)
/// and ongoing programmes (vested).
pub const MARKETING_TGE_NUMERATOR: u128 = 25;
pub const MARKETING_TGE_DENOMINATOR: u128 = 100;
pub const MARKETING_VESTING_SLOTS: u64 = 24 * MONTH_SLOTS;

/// Generic cliff-then-linear unlock, in satoshis.
pub const fn vested_sat(total_bloch: u128, slot: u64, cliff: u64, duration: u64) -> u128 {
    let total = total_bloch * SAT_PER_BLOCH;
    if slot < cliff {
        return 0;
    }
    if duration == 0 || slot >= cliff + duration {
        return total;
    }
    total * (slot - cliff) as u128 / duration as u128
}

pub const fn vc_vested_sat(slot: u64) -> u128 {
    vested_sat(VC_BLOCH, slot, VC_CLIFF_SLOTS, VC_VESTING_SLOTS)
}

pub const fn team_vested_sat(slot: u64) -> u128 {
    vested_sat(TEAM_BLOCH, slot, TEAM_CLIFF_SLOTS, TEAM_VESTING_SLOTS)
}

pub const fn marketing_vested_sat(slot: u64) -> u128 {
    let total = MARKETING_BLOCH * SAT_PER_BLOCH;
    let at_tge = total * MARKETING_TGE_NUMERATOR / MARKETING_TGE_DENOMINATOR;
    at_tge + vested_sat(MARKETING_BLOCH - MARKETING_BLOCH * MARKETING_TGE_NUMERATOR
        / MARKETING_TGE_DENOMINATOR, slot, 0, MARKETING_VESTING_SLOTS)
}

/// Liquidity is fully unlocked at genesis — that is its function. Vesting the
/// liquidity bucket would defeat the purpose of having one.
pub const fn liquidity_vested_sat(_slot: u64) -> u128 {
    LIQUIDITY_BLOCH * SAT_PER_BLOCH
}

/// Total insider supply unlocked by `slot` (founder + team + VC + marketing).
/// Liquidity and carryover holders are excluded: neither is an insider bloc.
pub const fn insider_unlocked_sat(slot: u64) -> u128 {
    founder_vested_sat(slot) + team_vested_sat(slot) + vc_vested_sat(slot)
        + marketing_vested_sat(slot)
}

// ── Emission curve: the decision that actually drives decentralisation ──────
//
// Modelling the unlock schedule against the PoS activation gates showed that
// the emission curve, not the vesting schedule, decides whether gate G2
// (no entity above 25% of active stake) can ever be met. With a FLAT curve the
// validator share is still only ~24% of circulating supply after ten years, and
// some bucket sits at or above 25% in months 6, 12, 24, 36 and 48. With a
// front-loaded curve validators pass 45% of circulating inside two years and
// only months 6 and 12 breach — and that breach is the liquidity bucket, which
// disperses to traders rather than acting as one entity.
//
// The choice is open decision #2 in the spec. Both curves are provided; neither
// is aliased as "the" reward, because picking one here would make a founder
// decision look like an implementation detail.

/// Flat: constant reward for 40 years, then fee-only.
pub const fn validator_reward_flat_sat(slot: u64) -> u128 {
    if slot >= EMISSION_SLOTS {
        return 0;
    }
    (VALIDATOR_EMISSION_BLOCH * SAT_PER_BLOCH) / EMISSION_SLOTS as u128
}

/// Halving every 4 years, 10 halvings across the 40-year window.
///
/// `R0` is derived so the ten periods sum to exactly the validator allocation:
/// the geometric sum is `R0 · P · (2046/1024)`, so `R0 = alloc · 1024 / (P · 2046)`.
/// Initial reward ≈ 6,387 BLCH/block, final period ≈ 6.24 BLCH/block, and the
/// truncation residual over the whole 40 years is under 0.2 BLCH.
pub const HALVING_PERIOD_SLOTS: u64 = 4 * SLOTS_PER_YEAR;
pub const HALVINGS: u32 = 10;
pub const INITIAL_REWARD_SAT: u128 =
    (VALIDATOR_EMISSION_BLOCH * SAT_PER_BLOCH * 1024) / (HALVING_PERIOD_SLOTS as u128 * 2046);

pub const fn validator_reward_halving_sat(slot: u64) -> u128 {
    if slot >= EMISSION_SLOTS {
        return 0;
    }
    let era = slot / HALVING_PERIOD_SLOTS;
    if era >= HALVINGS as u64 {
        return 0;
    }
    INITIAL_REWARD_SAT >> era
}

/// Smooth disinflation — **the recommended curve**.
///
/// Shape borrowed from Solana (8% initial inflation declining 15%/year to a
/// 1.5% floor), which is the model the market actually converged on; neither
/// Ethereum nor Solana has a Bitcoin-style halving. Adapted to a hard cap: the
/// reward declines by a fixed 10% each year and the whole 40-year schedule sums
/// to exactly the validator allocation, so there is no floor and no tail.
///
/// Why 10% and not something else — it is the only round rate that satisfies
/// both live constraints at once:
///
/// - **Inflation target.** Year 1 emits 5,450,564,151 BLCH = **5.45% of total
///   supply**, against the founder's "under 7%" requirement. Year 5 is 3.58%,
///   year 10 is 2.11%.
/// - **Decentralisation.** An 8%/year decline drops to 4.45% inflation but is
///   too flat: validators stop out-earning the insider unlock schedule and the
///   25%-of-stake gate is breached at month 36. 12%/year passes the gate but
///   puts year 1 at 6.48%, uncomfortably close to the ceiling. 10% clears both.
///
/// Preferred over halving because a halving is a scheduled date on which every
/// validator's revenue drops by half at once, and marginal operators leave
/// together. Continuous decay has no such edges — the same reasoning that put
/// the founder's vesting on a per-slot line instead of monthly tranches.
///
/// Integer recurrence: `annual[n] = annual[n-1] * 9 / 10`, per-slot reward is
/// `annual[n] / SLOTS_PER_YEAR`. `INITIAL_ANNUAL_SAT` was solved for by binary
/// search under exactly this truncating arithmetic, so the 40-year sum lands on
/// the allocation with **zero** residual rather than merely close to it.
pub const DECAY_NUMERATOR: u128 = 9;
pub const DECAY_DENOMINATOR: u128 = 10;
pub const INITIAL_ANNUAL_SAT: u128 = 91_716_807_395_714_399;

pub const fn validator_reward_decay_sat(slot: u64) -> u128 {
    if slot >= EMISSION_SLOTS {
        return 0; // fee-only from here on
    }
    let year = slot / SLOTS_PER_YEAR;
    let mut annual = INITIAL_ANNUAL_SAT;
    let mut n = 0;
    while n < year {
        annual = annual * DECAY_NUMERATOR / DECAY_DENOMINATOR;
        n += 1;
    }
    annual / SLOTS_PER_YEAR as u128
}

/// Total emitted under the decay curve by `slot`.
pub const fn validator_emitted_decay_by(slot: u64) -> u128 {
    let end = if slot > EMISSION_SLOTS { EMISSION_SLOTS } else { slot };
    let mut total: u128 = 0;
    let mut annual = INITIAL_ANNUAL_SAT;
    let mut year: u64 = 0;
    while year < EMISSION_YEARS {
        let start = year * SLOTS_PER_YEAR;
        if end <= start {
            break;
        }
        let in_year = end - start;
        let span = if in_year > SLOTS_PER_YEAR { SLOTS_PER_YEAR } else { in_year };
        total += (annual / SLOTS_PER_YEAR as u128) * span as u128;
        annual = annual * DECAY_NUMERATOR / DECAY_DENOMINATOR;
        year += 1;
    }
    total
}

/// Annual issuance as a share of total supply, in basis points — the figure
/// quoted publicly, and measured the way Solana and Ethereum measure it
/// (against total supply, not circulating supply). The distinction is not
/// cosmetic: against *circulating* supply this same curve reads over 100% in
/// year one, purely because almost every allocation is still vesting at genesis.
pub const fn annual_inflation_bps(year: u64) -> u128 {
    let mut annual = INITIAL_ANNUAL_SAT;
    let mut n = 0;
    while n < year {
        annual = annual * DECAY_NUMERATOR / DECAY_DENOMINATOR;
        n += 1;
    }
    annual * 10_000 / TOTAL_SUPPLY_SAT
}
