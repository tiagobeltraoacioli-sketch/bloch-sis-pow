// SPDX-License-Identifier: AGPL-3.0-or-later

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
//! 100 B BLCH at 8 decimals is 10^19 satoshis — **54.21% of `u64::MAX`**. One
//! balance fits a `u64`, but with only 1.84x of headroom: the sum of any two
//! balances above half the supply wraps, and release builds wrap silently. A
//! wrapped consensus value is a chain split. Every quantity here is therefore
//! `u128`, every satoshi *sum* elsewhere in the crate is `u128`
//! (`state_root::total_utxo_value`, `sample`'s cumulative array, the finality
//! quorum comparison), and the compile-time assertions below pin both facts:
//! the total still fits a single `u64`, and it is deep enough into the range
//! that `u64` addition is not safe. If either assertion ever fires, the
//! arithmetic width is being re-decided by accident — stop and re-read this.
//!
//! Known breakage, since **resolved**: 10^19 does not fit the signed `int64`
//! the Go SDK used for `Satoshis` (`i64::MAX` is 9.22 x 10^18). That was one
//! of the two stated reasons for the 2026-08-11 revert to 21 B; the
//! 2026-08-12 split decision knowingly reintroduced it, and it was fixed by
//! changing the *wire form*, not just the width: a satoshi amount is a decimal
//! **string** in JSON and a `uint64` in memory (`sdk/go/satoshis.go`,
//! `docs/specs/BLOCH-SATOSHI-ENCODING.md`). Widening `int64` to `uint64` alone
//! would have fixed Go and left every JavaScript consumer of the same JSON
//! reading a silently rounded balance — 10^19 is ~1110x JavaScript's exact
//! integer limit of 2^53, and real single balances are already 39x past it.
//! The `i64::MAX` assertion below stays as the tripwire that raised this.

/// Satoshis per BLCH. Unchanged across every revision — divisibility is
/// preserved; the overflow question is answered with `u128`, not by dropping
/// decimal places.
pub const SAT_PER_BLOCH: u128 = 100_000_000;

// ── The 2026-08-12 split ────────────────────────────────────────────────────
//
// Founder decision, 2026-08-12: total supply moves 21 B → 100 B as a **pure
// split** of exactly 100/21 (x4.7619...). Every bucket scales by the same
// ratio, every percentage is unchanged, nobody is diluted. Economically this
// is a redenomination — any text that reads it as "more supply for holders"
// is wrong. The compile-time assertions at the bottom prove bucket-by-bucket
// that the ratio is exact.

/// Split ratio numerator: the new supply.
pub const SPLIT_NUMERATOR: u128 = 100;
/// Split ratio denominator: the 2026-08-11 nominal the split multiplies.
pub const SPLIT_DENOMINATOR: u128 = 21;

/// A Genesis-3 satoshi amount under the split, truncating.
///
/// This is the function the carryover rebuild must apply per balance. It
/// truncates: a balance not divisible by 21 loses up to 20/21 of a satoshi.
/// The ceremony pins the artifact's TOTAL against
/// [`CARRYOVER_TOTAL_BLOCH`] exactly, so the builder must state its dust rule
/// (who absorbs the sub-satoshi remainders) and make the rows sum to the
/// pinned figure — truncate-and-hope does not close the accounting.
pub const fn split_g3_sat(g3_sat: u128) -> u128 {
    g3_sat * SPLIT_NUMERATOR / SPLIT_DENOMINATOR
}

/// Fixed total supply. Hard-capped, unlike V2's perpetual tail.
///
/// History, kept because auditors read history: a 100 B draft (2026-08-10) was
/// reverted to the 21 B V2 nominal on 2026-08-11 — the revert bought u64/int64
/// headroom for free — and re-decided at 100 B on 2026-08-12 as a pure split,
/// this time with the headroom loss accepted and pinned below rather than
/// discovered later. The cap is additionally a **consensus invariant**: the
/// cumulative issued supply is a committed component of the state root
/// (`state_root::TAG_ISSUED_SUPPLY`) and every node refuses a block whose
/// committed issuance exceeds this constant
/// (`TransitionError::SupplyCapExceeded`). Honest strength of that claim: no
/// mechanism *inside* the protocol can raise the cap — no transaction variant,
/// no key, no vote, no governance path; the value is a `const` with no setter.
/// A hard fork adopted by every operator can change any rule, this one
/// included, so "impossible to change" would be false and is not claimed.
pub const TOTAL_SUPPLY_BLOCH: u128 = 100_000_000_000;
pub const TOTAL_SUPPLY_SAT: u128 = TOTAL_SUPPLY_BLOCH * SAT_PER_BLOCH;

// ── Allocations ─────────────────────────────────────────────────────────────

/// The founder's NEW allocation — 10% of supply, vested.
///
/// This is on top of the carried-over balance below, not instead of it: the
/// founder's Genesis-3 holdings come across as ordinary liquid carryover and a
/// fresh grant is made on top (founder decision, 2026-08-11; an earlier draft
/// re-granted the full 17%, the decision settled at 10%). Combined, the
/// founder holds 26.89% of supply — [`FOUNDER_TOTAL_BLOCH`] pins it. §4A of
/// the tokenomics spec states what that does to the activation gates.
pub const FOUNDER_BLOCH: u128 = 10_000_000_000; // 10%
/// Sold to funds; the Foundation is the counterparty. Nothing liquid at
/// genesis — 12-month cliff, 24-month linear, fully vested at year 3.
pub const VC_BLOCH: u128 = 10_000_000_000; // 10%
/// Held by the Foundation and granted to individuals. Nothing liquid at
/// genesis — 18-month cliff, 36-month linear, fully vested at year 4.5. The
/// cliff sits six months off the VC cliff so no two buckets share a month.
pub const TEAM_BLOCH: u128 = 10_000_000_000; // 10%
/// 25% (1,000,000,000) liquid at genesis for listing and launch spend; the
/// rest linear over 24 months.
pub const MARKETING_BLOCH: u128 = 4_000_000_000; //  4%
/// 100% liquid at genesis — deployed to order books and AMM pools. The one
/// bucket where full unlock is the function, not a concession.
pub const LIQUIDITY_BLOCH: u128 = 5_000_000_000; //  5%

/// The four buckets the Foundation holds: 29.00% of supply.
pub const FOUNDATION_HELD_BLOCH: u128 =
    VC_BLOCH + TEAM_BLOCH + MARKETING_BLOCH + LIQUIDITY_BLOCH;

/// Of those four, what is spendable at slot 0: all of liquidity plus the 25%
/// marketing tranche. VC and team are entirely cliffed.
///
/// This equals **25.0% of circulating supply at genesis** — exactly the G2
/// threshold, and unchanged by the split (a redenomination moves no ratio).
/// Worth keeping as a constant rather than a paragraph: two holders account
/// for the whole genesis float, and neither can change that by behaving
/// differently. Only emission and independent stake dilute them.
pub const FOUNDATION_LIQUID_AT_GENESIS_BLOCH: u128 =
    LIQUIDITY_BLOCH + MARKETING_BLOCH * MARKETING_TGE_NUMERATOR / MARKETING_TGE_DENOMINATOR;

/// The carried-over ledger — **one balance set, no founder line**.
///
/// Measured on Genesis-3 at height 43,172 (448,337 UTXOs, 15 addresses) as
/// 3,773,884,800 BLCH, and carried across under the split: x100/21 exactly,
/// which this figure is (the G3 total is divisible by 21, so the scaled total
/// is exact — no dust at the aggregate level; per-row dust is the builder's
/// problem, see [`split_g3_sat`]). Every balance crosses as ordinary liquid
/// balance, the founder's included: those coins were mined, on the same
/// chain, under the same rules as everyone else's (founder decision,
/// 2026-08-11).
///
/// Liquid includes **stakeable**: a carried-over balance may fund deposits and
/// delegations like any other coin (founder decision, 2026-08-11).
/// `staking.rs::carryover_liquid_balance_is_stakeable` and
/// `tests/committee.rs::carryover_liquid_balance_delegates_as_stake` pin it;
/// the gate arithmetic it changes is in the tokenomics spec, §4A.1.
///
/// Two mechanisms dissolve with that decision rather than being satisfied by
/// it. There is no **taint set**, because there is no class of coin to mark —
/// §4.1's premine ineligibility was written for a migration in place, where the
/// founder's pre-existing holding sat on the chain being converted. And there
/// is no **holder cap**: the ceiling existed to bound what legacy holders
/// received *while the founder was excluded*, and with nobody excluded it would
/// either bind on everyone or bind on no one.
///
/// What does not dissolve is the arithmetic. Relabelling changes no balance
/// and the split changes no ratio: the largest single address still holds
/// ~94% of the carryover, liquid from slot 0. §4A states what that does to
/// the activation gates, and it states it the same way it did before either
/// decision.
///
/// Re-measured 2026-08-13 against a live node, and **still provisional**:
/// Genesis-3 halts at height 50,000 and keeps minting until it does, so this
/// figure grows with every block. The terminal snapshot is what pins it, and
/// nothing here should be treated as final before then.
///
/// | when | height | block_count | UTXOs | Genesis-3 BLOCH | ×100/21 |
/// |---|---|---|---|---|---|
/// | earlier | — | 43,172 | 448,337 | 3,773,884,800 | 17,970,880,000 |
/// | 2026-08-13 | 39,328 | 50,042 | 452,133 | 3,805,746,000 | 18,122,600,000 |
///
/// The earlier row is the one this constant used to hold, and its label was
/// wrong in a way worth recording rather than quietly fixing: it read
/// "measured at height 43,172", but the chain has never been at that height —
/// it was at 39,328 when this was re-measured, and 43,172 was the
/// **block_count**. In a DAG those differ by design (50,042 blocks at height
/// 39,328 today), so anyone reproducing the old measurement "at height
/// 43,172" would have waited days for a height that produces a different
/// number. Heights and block counts are now stated separately, both times.
///
/// The split stays exact: 3,805,746,000 is divisible by 21, so ×100/21 lands
/// on a whole number with no aggregate dust, same as the previous figure.
///
/// Raising this does not breach the cap. [`VALIDATOR_EMISSION_BLOCH`] is the
/// remainder of a fixed total, so 151,720,000 BLOCH more carryover is
/// 151,720,000 BLOCH less validator emission — the holders' ledger grows and
/// the future issuance shrinks by exactly the same amount. That is the right
/// bucket to absorb it: it is unissued, so nothing is taken from anyone who
/// already holds coins, and the alternative is taking it from an allocation
/// that was promised as a percentage.
pub const CARRYOVER_TOTAL_BLOCH: u128 = 18_122_600_000;

/// SHAKE-256 root of the balance set the figure above was measured from, and
/// the SHA-256 of the file itself. Published so the measurement is checkable
/// rather than asserted: another operator produces a snapshot at the same
/// height and compares roots. Agreement across independent nodes is the
/// evidence — a single tool's output is not.
pub const CARRYOVER_MEASURED_ROOT: [u8; 32] = [
    0x16, 0x2c, 0xb7, 0x63, 0x8d, 0xec, 0x70, 0xf4, 0xdf, 0x7f, 0x5f, 0x0b, 0x10, 0xcf, 0xe0, 0x57,
    0x33, 0x39, 0xb0, 0xd2, 0xc5, 0x0e, 0xf7, 0x99, 0x23, 0x8d, 0x22, 0x90, 0x6d, 0x87, 0x14, 0xda,
];
/// Height the snapshot behind [`CARRYOVER_MEASURED_ROOT`] was taken at.
pub const CARRYOVER_MEASURED_HEIGHT: u64 = 39_328;
/// UTXO count in that snapshot.
pub const CARRYOVER_MEASURED_UTXOS: u64 = 452_133;

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
pub const VALIDATOR_EMISSION_SAT: u128 = VALIDATOR_EMISSION_BLOCH * SAT_PER_BLOCH;

/// Supply issued at slot 0: everything except the validator emission — the
/// carryover and the five allocation buckets, vested or not (vesting locks
/// spendability, it does not defer existence; the ceremony mints these
/// outputs at genesis).
///
/// This is the value `CommittedState::genesis` seeds the committed
/// cumulative-issuance counter with (`state_root::TAG_ISSUED_SUPPLY`), so the
/// emission headroom the cap check works against starts at exactly
/// [`VALIDATOR_EMISSION_SAT`].
pub const GENESIS_ISSUED_SAT: u128 = TOTAL_SUPPLY_SAT - VALIDATOR_EMISSION_SAT;

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
    VALIDATOR_EMISSION_BLOCH == 42_877_400_000,
    "resto para validadores mudou — reveja a especificacao antes de aceitar"
);

// The split is PURE, proven bucket by bucket against the 2026-08-11 values:
// new * 21 == old * 100, exactly. If any assertion here fires, some bucket was
// scaled by a different ratio — which is a dilution, not a split.
const _: () = assert!(TOTAL_SUPPLY_BLOCH * SPLIT_DENOMINATOR == 21_000_000_000 * SPLIT_NUMERATOR);
const _: () = assert!(FOUNDER_BLOCH * SPLIT_DENOMINATOR == 2_100_000_000 * SPLIT_NUMERATOR);
const _: () = assert!(VC_BLOCH * SPLIT_DENOMINATOR == 2_100_000_000 * SPLIT_NUMERATOR);
const _: () = assert!(TEAM_BLOCH * SPLIT_DENOMINATOR == 2_100_000_000 * SPLIT_NUMERATOR);
const _: () = assert!(MARKETING_BLOCH * SPLIT_DENOMINATOR == 840_000_000 * SPLIT_NUMERATOR);
const _: () = assert!(LIQUIDITY_BLOCH * SPLIT_DENOMINATOR == 1_050_000_000 * SPLIT_NUMERATOR);
// Re-pinned 2026-08-13 to the measured snapshot (h39,328): the carryover is
// what the ledger says it is, not what a draft said it would be. The split
// stays exact on the new figure too — 3,805,746,000 is divisible by 21.
const _: () =
    assert!(CARRYOVER_TOTAL_BLOCH * SPLIT_DENOMINATOR == 3_805_746_000 * SPLIT_NUMERATOR);
const _: () =
    assert!(VALIDATOR_EMISSION_BLOCH * SPLIT_DENOMINATOR == 9_004_254_000 * SPLIT_NUMERATOR);

/// Largest single carried-over address, for the concentration reporting in §4A.
/// Not a consensus quantity and not a distinct class of coin — a measurement,
/// re-taken 2026-08-13 from the same snapshot as [`CARRYOVER_TOTAL_BLOCH`]
/// (h39,328, root `162cb763…`): the address `e986db51…` holds
/// 357,483,616,997,963,769 sat = 3,574,836,169.98 BLCH across 425,599 of the
/// set's 452,133 outputs. Scaled ×100/21 and truncated to whole BLCH.
///
/// Both figures now come from one snapshot, which is the only way the ratio
/// between them means anything. Updating the total against a fresh
/// measurement while leaving this one at the older reading would have moved
/// the reported concentration from 93.96% to 93.17% — a 0.8-point "drop" that
/// was an artifact of mixing two measurements, not a change in who holds
/// what. Measured together, concentration is **93.93%**: essentially
/// unchanged, which is the true answer.
///
/// The set has **16 distinct addresses**.
pub const LARGEST_CARRYOVER_ADDRESS_BLOCH: u128 = 17_023_029_380;
const _: () = assert!(LARGEST_CARRYOVER_ADDRESS_BLOCH < CARRYOVER_TOTAL_BLOCH);
// Pinned against the measurement in satoshis, not in whole BLOCH. The address
// holds 3,574,836,169.97963769 BLCH; rounding that to whole BLOCH before
// scaling gives 17,023,029,376 and scaling the satoshi figure gives
// 17,023,029,380. Four BLOCH of difference is nothing to the reporting, but a
// constant that disagrees with its own derivation is a trap for whoever
// re-derives it next.
const _: () = assert!(
    LARGEST_CARRYOVER_ADDRESS_BLOCH
        == 357_483_616_997_963_769 * SPLIT_NUMERATOR / SPLIT_DENOMINATOR / SAT_PER_BLOCH,
    "a medida escalada nao bate com a medida G3 sob o split"
);

/// Founder carried-over balance plus the new grant: 27.02% of supply.
///
/// Up from 26.89%: the re-measured carryover is larger and the founder holds
/// 93.93% of it, so their share of a fixed cap rises. Recorded rather than
/// smoothed — the number moving in this direction is exactly what §4A exists
/// to report.
pub const FOUNDER_TOTAL_BLOCH: u128 = LARGEST_CARRYOVER_ADDRESS_BLOCH + FOUNDER_BLOCH;
const _: () = assert!(FOUNDER_TOTAL_BLOCH * 10_000 / TOTAL_SUPPLY_BLOCH == 2702);

const _: () = assert!(EMISSION_SLOTS == 42_076_800, "grade de tempo mudou");

// ── The u64 headroom, pinned ────────────────────────────────────────────────
//
// Both directions are asserted on purpose. The first says a single balance
// still fits the u64 columns that carry one bond or one output
// (`state_root::EutxoEntry::value`, `ValidatorRecord::stake`,
// `sample::Validator::effective_stake`). The second says the supply is past
// the halfway point of u64 — the sum of two large balances CAN wrap — so
// every satoshi sum must be u128, and any future edit that brings the supply
// back under the safe line has to come here and re-decide the widths
// deliberately instead of inheriting a hazard note that stopped being true.
const _: () = assert!(
    TOTAL_SUPPLY_SAT <= u64::MAX as u128,
    "um saldo unico tem de caber em u64 — as colunas comprometidas sao u64"
);
const _: () = assert!(
    TOTAL_SUPPLY_SAT * 2 > u64::MAX as u128,
    "o supply saiu da zona de wrap de u64: reavalie as larguras de proposito"
);
// The tripwire that surfaced the encoding decision: a signed int64 cannot
// carry an amount at this scale. Discharged by the wire form — decimal string
// in JSON, uint64 in memory (docs/specs/BLOCH-SATOSHI-ENCODING.md) — not by
// widening a type. Kept asserted: if the supply ever drops back under
// i64::MAX this fires, and whoever is here must re-read that spec before
// concluding the encoding can be relaxed. It cannot: the JavaScript 2^53
// limit binds ~1000x lower than i64::MAX and is unaffected by the supply.
const _: () = assert!(
    TOTAL_SUPPLY_SAT > i64::MAX as u128,
    "se isto falhar, o int64 do SDK Go voltou a caber — atualize os docs"
);

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
// disperses to traders rather than acting as one entity. All of those are
// ratios, so the 2026-08-12 split moves none of them.
//
// The choice is open decision #2 in the spec. Both curves are provided; neither
// is aliased as "the" reward, because picking one here would make a founder
// decision look like an implementation detail.

/// Flat: constant reward for 40 years, then fee-only. ~1,022.63 BLCH/slot.
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
/// Initial reward ≈ 5,118 BLCH/block, final period ≈ 5.0 BLCH/block, and the
/// truncation residual over the whole 40 years is under 0.14 BLCH.
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
/// to the validator allocation minus [`EMISSION_DUST_SAT`] — see below for why
/// that dust is irreducible.
///
/// Why 10% and not something else — it is the only round rate that satisfies
/// both live constraints at once, and the split changes neither (both are
/// ratios of the same supply):
///
/// - **Inflation target.** Year 1 emits 4,367,467,018.77 BLCH = **4.36% of
///   total supply** (`annual_inflation_bps(0)` = 436), against the founder's
///   "under 7%" requirement. Year 5 is 2.86%, year 10 is 1.69%. Identical in
///   basis points to the 21 B schedule this splits from — pinned by test.
/// - **Decentralisation.** An 8%/year decline is too flat: validators stop
///   out-earning the insider unlock schedule and the 25%-of-stake gate is
///   breached at month 36. 12%/year passes the gate at 5.19% year-1 inflation.
///   Neither rate presses the 7% ceiling; what decides between them is the
///   gate, and 10% clears it with margin on both sides.
///
/// Preferred over halving because a halving is a scheduled date on which every
/// validator's revenue drops by half at once, and marginal operators leave
/// together. Continuous decay has no such edges — the same reasoning that put
/// the founder's vesting on a per-slot line instead of monthly tranches.
///
/// Integer recurrence: `annual[n] = annual[n-1] * 9 / 10`, per-slot reward is
/// `annual[n] / SLOTS_PER_YEAR`. `INITIAL_ANNUAL_SAT` was solved for by binary
/// search under exactly this truncating arithmetic, as the largest value whose
/// 40-year sum does not exceed the allocation.
pub const DECAY_NUMERATOR: u128 = 9;
pub const DECAY_DENOMINATOR: u128 = 10;
pub const INITIAL_ANNUAL_SAT: u128 = 435_206_739_879_746_639;

/// Satoshis of the validator allocation the decay curve can never emit.
///
/// The 40-year sum is `Σ (annual_n / SPY) · SPY` — a multiple of
/// `SLOTS_PER_YEAR` by construction — and the allocation is **not** a multiple
/// of `SLOTS_PER_YEAR` (4,302,912,000,000,000,000 mod 1,051,920 = 176,880), so
/// no choice of `INITIAL_ANNUAL_SAT` lands exactly. An earlier revision of
/// this file claimed a zero residual; that claim was arithmetically impossible
/// (the 21 B schedule's true residual was 889,200 sat) and is corrected here
/// rather than repeated. 176,880 sat is 0.0018 BLCH, permanently unissued —
/// which errs on the only acceptable side of a hard cap: under, never over.
/// The compile-time assertion below pins it.
pub const EMISSION_DUST_SAT: u128 = 772_880;

const _: () = assert!(
    validator_emitted_decay_by(EMISSION_SLOTS) + EMISSION_DUST_SAT == VALIDATOR_EMISSION_SAT,
    "a soma de 40 anos da curva de decay mudou — recalcule INITIAL_ANNUAL_SAT"
);

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
