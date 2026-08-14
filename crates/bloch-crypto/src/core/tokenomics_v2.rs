//! BLOCH Tokenomics V2 — Genesis-3 constants and helpers
//!
//! > **Historical — Genesis-3. SUPERSEDED.** These were the tokenomics of the
//! > proof-of-work chain that stopped permanently at height 39,918 on
//! > 2026-08-13: a 21 B nominal supply, a 17% (3.57 B) founder premine, and a
//! > halving block subsidy paid to miners. **None of it is in force.** The
//! > live chain is **Genesis-4, proof of stake**, whose tokenomics are
//! > `crates/bloch-pos-committee/src/tokenomics_v4.rs`: a **100 B hard cap**,
//! > 57,146,400,000 BLOCH issued at slot 0 (18,146,400,000 of it the carried
//! > Genesis-3 ledger, scaled ×100/21), and 42,853,600,000 emitted to
//! > validators over 40 years. There is no block subsidy and no halving.
//! > Kept because Genesis-4's opening ledger is derived from the chain these
//! > rules ran. **It is not what runs.**
//! >
//! > In particular: the 3.57 B "premine" below never reached Genesis-4 as a
//! > premine. The founder's Genesis-3 balance crossed as ordinary liquid
//! > carryover like everyone else's, and a separate 10 B grant was made on top
//! > (founder decision, 2026-08-11) — see `tokenomics_v4::FOUNDER_TOTAL_BLOCH`,
//! > 27.04% of the cap.
//!
//! Per `docs/specs/TOKENOMICS_V2.md`. Activated by ADR-028.
//!
//! These WERE CONSENSUS RULES on Genesis-3. Mutation required a hard fork.
//! Genesis-locked values, frozen by the pre-commitment doctrine
//! (`docs/ENSAIO_2_PRE_COMMITMENT_DOCTRINE.md`).
//!
//! ## Halving semantics — important
//!
//! The block subsidy is halved in **BLOCH-integer space**, not sat-space, in
//! order to match the per-halving emission table in spec §3.1 and the
//! `MINING_EMISSION_ACTUAL = 798,630,000` figure in spec §2. The code sample
//! in spec §3.2 shows a sat-space shift (`INITIAL_BLOCK_REWARD_SAT >> halvings`)
//! which is inconsistent with §3.1 and §2; this implementation follows §3.1
//! and §2 and a future spec errata will clarify §3.2. See `block_subsidy_sat`
//! below.
//!
//! ## Address constants
//!
//! `FOUNDER_ADDRESS_HASH`, `VALIDATOR_POOL_ADDRESS_HASH`, and
//! `ORACLE_POOL_ADDRESS_HASH` are intentionally `Option<[u8; 20]>` set to
//! `None` until the genesis ceremony (Phase 6 of the rebrand). Any consensus
//! path that reaches one of these MUST panic via the helper accessors below.
//! This is a deliberate fail-loud: a node configured for mainnet without
//! these populated is misconfigured and must not produce blocks.
//!
//! ## Sprint 2.1.D conversion sequence
//!
//! - C1 (this file)  — add V2 constants + helpers alongside untouched V1
//! - C2              — migrate `block_reward(h)` to use V2 (tail floor + halving)
//! - C3              — add founder vesting infrastructure
//! - C4              — rewrite `validate_coinbase_value` for 70/25/5 + per-block vesting
//! - C5              — regenerate genesis under V2 (3-output coinbase, no founder mint)
//! - C6              — update tests + recalibrate PoW for 30s

// ── Total supply (Bloch-SIS, B3b) ───────────────────────────────────────────
//
// All values are in *satoshi* (1 BLOCH = 10⁸ satoshi). Bloch supply model:
//
//   NOMINAL_TOTAL_SUPPLY   = 21,000,000,000 BLOCH = founder + mining nominal
//   FOUNDER_PREMINE_TOTAL  =  3,570,000,000 BLOCH (17% of nominal supply)
//   VALIDATOR_ORACLE_POOL  =              0 BLOCH (removed — no BFT/PoBRS, B2)
//   MINING_EMISSION_NOMINAL = 17,430,000,000 BLOCH (target Σ subsidy)
//
// `MINING_EMISSION_ACTUAL` (17,385,062,400 BLOCH) is derived from the halving
// schedule and is verified by the `halving_emission_closes` test below.

pub const SAT_PER_BLOCH:                u64 = 100_000_000;
pub const NOMINAL_TOTAL_SUPPLY_SAT:    u64 = 21_000_000_000 * SAT_PER_BLOCH;
pub const MINING_EMISSION_NOMINAL_SAT: u64 = 17_430_000_000 * SAT_PER_BLOCH;
pub const FOUNDER_PREMINE_TOTAL_SAT:   u64 =  3_570_000_000 * SAT_PER_BLOCH;
pub const VALIDATOR_ORACLE_POOL_SAT:   u64 =             0 * SAT_PER_BLOCH;

const _: () = assert!(
    FOUNDER_PREMINE_TOTAL_SAT + VALIDATOR_ORACLE_POOL_SAT + MINING_EMISSION_NOMINAL_SAT
        == NOMINAL_TOTAL_SUPPLY_SAT
);

// ── Emission curve ────────────────────────────────────────────────────────
//
// Per spec §3.1. Block subsidy at height h:
//
//   reward_bloch(h) = max(INITIAL_BLOCK_REWARD_BLOCH >> (h / HALVING_INTERVAL),
//                        TAIL_FLOOR_BLOCH)
//   reward_sat(h)  = reward_bloch(h) * SAT_PER_BLOCH
//
// Bloch-SIS (B3b), 30 s blocks: initial reward 8_400 BLOCH, yearly halving
// (1_036_800 blocks). At halving 7, `8400 >> 7 = 65 < 100`, so the tail floor
// (100 BLOCH/block) activates and holds perpetually. Geometric phase closes at
// 17,385,062,400 BLOCH (see halving_emission test).
//
// NOTE (Emission V3): the schedule above governs emission heights BELOW
// `EMISSION_V3_FORK_EMISSION_HEIGHT` only. At/above the fork the V3 curve
// applies — see the "Emission V3" section below `block_subsidy_sat`'s gate.

pub const INITIAL_BLOCK_REWARD_BLOCH: u64 = 8_400;
pub const INITIAL_BLOCK_REWARD_SAT:  u64 = INITIAL_BLOCK_REWARD_BLOCH * SAT_PER_BLOCH;
pub const HALVING_INTERVAL:          u64 = 1_036_800; // ~1 year @ 30 s (360×2880)
pub const TAIL_FLOOR_BLOCH:           u64 = 100;
pub const TAIL_FLOOR_SAT:            u64 = TAIL_FLOOR_BLOCH * SAT_PER_BLOCH;
pub const TARGET_BLOCK_TIME_SECS:    u64 = 30;

pub const TAIL_ACTIVATION_HALVING: u64 = 7;
pub const TAIL_ACTIVATION_HEIGHT:  u64 = TAIL_ACTIVATION_HALVING * HALVING_INTERVAL;

// V2-curve tail activation (7 × 1,036,800). REINTERPRETED under Emission V3
// (below): the V2 curve only governs emission heights BELOW the V3 fork
// (453,743), all of which sit in epoch 0, so no live block will ever reach
// this height under the V2 rules — the V2 tail is now COUNTERFACTUAL. The
// constant and this assert are kept because they pin the legacy branch of
// `block_subsidy_sat` (the pre-fork consensus curve must never drift) and
// because exported constants are part of the public API.
const _: () = assert!(TAIL_ACTIVATION_HEIGHT == 7_257_600);

// ── Emission V3 (flag-day hard fork) ──────────────────────────────────────
//
// WHY: the V2 curve (8,400 BLOCH initial, yearly halving) read forward from
// the Genesis-3 restart emits ≈26.92B BLOCH over 100 years — 54% above the
// documented `MINING_EMISSION_NOMINAL` of 17.43B. Emission V3 slows the
// curve (2,600 initial, 1.5-year halvings) and, with the V3-only tail floor
// of 60 BLOCH (PISO-60, below), the 100 years FOLLOWING the fork emit
// 13,620,441,600 BLOCH — chosen so the FULL accounting closes at the
// documented 21B nominal:
//
//   already emitted (carryover 3,475,441,200 + G3-mined 309,128,400,
//   measured 2026-08-09)                          =  3,784,569,600
//   100-year post-fork V3 emission                = 13,620,441,600
//   founder premine (locked, not yet emitted)     =  3,570,000,000
//   ─────────────────────────────────────────────────────────────
//   grand total                                   = 20,975,011,200  (−0.12%)
//
// With the old shared 100-BLOCH floor the same accounting closed at 24.78B
// (+18%). The alternative — cutting the initial reward to 1,350 (an 84% cut
// instead of 69%) — was rejected in favour of trimming the tail.
//
// NON-RETROACTIVE by construction: `block_subsidy_sat` takes an EMISSION
// height (local + CARRYOVER_SOURCE_HEIGHT via `core::emission_height`).
// Below the fork the V2 curve applies VERBATIM — every historical coinbase
// stays valid. At/above the fork:
//
//   epoch  = (h − EMISSION_V3_FORK_EMISSION_HEIGHT) / EMISSION_V3_HALVING_INTERVAL
//   reward = max(2,600 >> epoch, 60) BLOCH   (V3-only floor — see PISO-60 below)
//
// The halving counter RESTARTS at the fork (epoch 0 = first V3 block); it
// does NOT continue the absolute-height count, which would hand the first
// V3 epoch a meaningless inherited exponent.
//
// This is a CONSENSUS CHANGE and requires a coordinated flag-day. The fork
// height is deliberately AFTER the pending difficulty flag-day (local
// 30,030, `DIFFICULTY_ANCESTRY_FORK_HEIGHT`) so two consensus changes never
// stack on the same height (const-asserted below).

/// V3 fork in EMISSION-height space: 453,743 = local 40,000 +
/// `CARRYOVER_SOURCE_HEIGHT` (413,743). Blocks at emission height >= this
/// pay the V3 curve; below it, the V2 curve verbatim.
pub const EMISSION_V3_FORK_EMISSION_HEIGHT: u64 = 453_743;
/// The same fork expressed in node-LOCAL height (Genesis-3 chain): 40,000.
pub const EMISSION_V3_FORK_LOCAL_HEIGHT:    u64 = 40_000;
pub const EMISSION_V3_INITIAL_REWARD_BLOCH: u64 = 2_600;
pub const EMISSION_V3_INITIAL_REWARD_SAT:   u64 = EMISSION_V3_INITIAL_REWARD_BLOCH * SAT_PER_BLOCH;
pub const EMISSION_V3_HALVING_INTERVAL:     u64 = 1_555_200; // 1.5 yr @ 30 s (1.5 × 1,036,800)

// ── PISO-60: V3-only perpetual tail floor ─────────────────────────────────
//
// The V3 curve has its OWN tail floor, 60 BLOCH/block. It deliberately does
// NOT reuse the shared `TAIL_FLOOR_*` (100 BLOCH) above: that constant is the
// V2 floor and governs the legacy branch of `block_subsidy_sat` — i.e. ALL
// pre-fork history. Changing the shared floor would re-validate historical
// coinbases against a different curve and invalidate the chain; changing THIS
// one only moves the (far-future) V3 tail. 60 was chosen so the 100-year
// post-fork emission (13,620,441,600 BLOCH) closes the grand total at ≈21B
// nominal (see the accounting in the section header above).
pub const EMISSION_V3_TAIL_FLOOR_BLOCH: u64 = 60;
pub const EMISSION_V3_TAIL_FLOOR_SAT:   u64 = EMISSION_V3_TAIL_FLOOR_BLOCH * SAT_PER_BLOCH;

// What consensus requires is that the two floors never cross branches:
// `TAIL_FLOOR_*` only in the legacy (pre-fork) branch, `EMISSION_V3_TAIL_
// FLOOR_*` only in the V3 branch. Pin both values so any attempt to
// “simplify” back to a single shared constant breaks the build:
const _: () = assert!(TAIL_FLOOR_BLOCH == 100, "V2 floor is consensus for all pre-fork history");
const _: () = assert!(EMISSION_V3_TAIL_FLOOR_BLOCH == 60, "V3 floor is consensus from the fork on");

// The two spellings of the fork height must agree with the carry-over offset.
const _: () = assert!(
    EMISSION_V3_FORK_EMISSION_HEIGHT
        == EMISSION_V3_FORK_LOCAL_HEIGHT + super::CARRYOVER_SOURCE_HEIGHT
);
// Never stack two consensus changes: the emission fork (local 40,000) must be
// strictly after the pending difficulty flag-day (local 30,030).
const _: () = assert!(EMISSION_V3_FORK_LOCAL_HEIGHT > super::DIFFICULTY_ANCESTRY_FORK_HEIGHT);
// The fork lands before the V2 curve's FIRST halving (1,036,800): every
// pre-fork emission height is epoch-0 (8,400 BLOCH), so the fork is a single
// clean 8,400 → 2,600 step and the historical-non-regression domain is flat.
const _: () = assert!(EMISSION_V3_FORK_EMISSION_HEIGHT < HALVING_INTERVAL);
// 1.5-year interval is exactly 1.5 × the V2 yearly interval.
const _: () = assert!(EMISSION_V3_HALVING_INTERVAL * 2 == HALVING_INTERVAL * 3);

/// First V3 epoch whose geometric reward falls below the V3 tail floor:
/// 2,600 >> 5 = 81 ≥ 60 but 2,600 >> 6 = 40 < 60 → floor from epoch 6.
/// (Under the old shared 100 floor this was epoch 5 — PISO-60 pushes the
/// floor one epoch later, letting epoch 5 pay its geometric 81 BLOCH.)
pub const EMISSION_V3_TAIL_ACTIVATION_EPOCH:  u64 = 6;
pub const EMISSION_V3_TAIL_ACTIVATION_HEIGHT: u64 =
    EMISSION_V3_FORK_EMISSION_HEIGHT
        + EMISSION_V3_TAIL_ACTIVATION_EPOCH * EMISSION_V3_HALVING_INTERVAL;

// Pin the tail-activation epoch algebraically against the V3 floor (mirrors
// the intent of the old `TAIL_ACTIVATION_HEIGHT == 7_257_600` assert, for
// the V3 curve). NOTE: these compare against EMISSION_V3_TAIL_FLOOR_BLOCH,
// not the V2 TAIL_FLOOR_BLOCH — the V2 floor never touches the V3 branch.
const _: () = assert!(
    EMISSION_V3_INITIAL_REWARD_BLOCH >> (EMISSION_V3_TAIL_ACTIVATION_EPOCH - 1)
        >= EMISSION_V3_TAIL_FLOOR_BLOCH
);
const _: () = assert!(
    EMISSION_V3_INITIAL_REWARD_BLOCH >> EMISSION_V3_TAIL_ACTIVATION_EPOCH
        < EMISSION_V3_TAIL_FLOOR_BLOCH
);
// 453,743 + 6 × 1,555,200 = 9,784,943 (was 8,229,743 under the 100 floor).
const _: () = assert!(EMISSION_V3_TAIL_ACTIVATION_HEIGHT == 9_784_943);

/// Exact Σ subsidy (BLOCH) over the 100 years (103,680,000 blocks) following
/// the V3 fork. Closed form, integer arithmetic (the sat total exceeds 2^53,
/// so floating point MUST NOT be used anywhere near this figure):
///   6 geometric epochs × 1,555,200 blocks × (2600+1300+650+325+162+81) BLOCH
/// + (103,680,000 − 9,331,200) tail blocks × 60 BLOCH
/// = 7,959,513,600 + 5,660,928,000 = 13,620,441,600 BLOCH.
/// Verified against a full per-block walk of `block_subsidy_sat` in tests.
pub const EMISSION_V3_100Y_TOTAL_BLOCH: u128 = 13_620_441_600;

const _: () = assert!(
    EMISSION_V3_100Y_TOTAL_BLOCH
        == 1_555_200u128 * (2_600 + 1_300 + 650 + 325 + 162 + 81)
            + (103_680_000u128 - 6 * 1_555_200) * 60
);

/// Block subsidy in satoshi at the given EMISSION height (local height +
/// `CARRYOVER_SOURCE_HEIGHT` on carry-over chains — see
/// `core::emission_height`). Used by C2.
///
/// SINGLE SOURCE OF TRUTH for the subsidy: every producer (miner, stratum,
/// getblocktemplate) and the validator (`validate_coinbase_value`) MUST go
/// through this function — never reimplement the curve at a call site.
///
/// Height-gated (Emission V3 flag-day):
/// - `height <  EMISSION_V3_FORK_EMISSION_HEIGHT` → legacy V2 curve,
///   VERBATIM (8,400 initial, yearly halving, 100 floor). Changing this
///   branch invalidates every historical coinbase.
/// - `height >= EMISSION_V3_FORK_EMISSION_HEIGHT` → V3 curve:
///   `max(2,600 >> epoch, 60)` with the epoch counter restarted at the fork,
///   1.5-year (1,555,200-block) halvings, and the V3-ONLY tail floor
///   (`EMISSION_V3_TAIL_FLOOR_SAT` = 60 — never the V2 floor).
///
/// Both branches halve the per-block reward in BLOCH-integer space, then
/// multiply up to satoshi (spec §3.1 semantics; see the module-level note).
#[inline]
pub fn block_subsidy_sat(height: u64) -> u64 {
    if height >= EMISSION_V3_FORK_EMISSION_HEIGHT {
        // Emission V3: epoch counter RESTARTS at the fork.
        let epoch = (height - EMISSION_V3_FORK_EMISSION_HEIGHT) / EMISSION_V3_HALVING_INTERVAL;
        let geometric_bloch = if epoch >= 64 {
            0
        } else {
            EMISSION_V3_INITIAL_REWARD_BLOCH >> epoch
        };
        let geometric_sat = geometric_bloch * SAT_PER_BLOCH;
        // PISO-60: the V3 branch floors at ITS OWN 60-BLOCH constant. Using
        // the shared V2 `TAIL_FLOOR_SAT` here would be wrong (and using the
        // V3 floor in the branch below would invalidate history).
        if geometric_sat < EMISSION_V3_TAIL_FLOOR_SAT {
            EMISSION_V3_TAIL_FLOOR_SAT
        } else {
            geometric_sat
        }
    } else {
        // Legacy V2 curve — verbatim, incl. its own 100-BLOCH TAIL_FLOOR_SAT.
        // Governs ALL pre-fork history; every historical block's coinbase
        // re-validates against this branch.
        let halvings = height / HALVING_INTERVAL;
        let geometric_bloch = if halvings >= 64 {
            0
        } else {
            INITIAL_BLOCK_REWARD_BLOCH >> halvings
        };
        let geometric_sat = geometric_bloch * SAT_PER_BLOCH;
        if geometric_sat < TAIL_FLOOR_SAT {
            TAIL_FLOOR_SAT
        } else {
            geometric_sat
        }
    }
}

// ── Reward split (basis points, sum = 10000) ──────────────────────────────
//
// Per spec §4. Each block subsidy splits across three parties:
//
//   miner            70% (PoW security + transaction fees)
//   validator pool   25% (FFG validator incentives, ADR-007)
//   oracle pool       5% (PoBRS oracle rebates, ADR-018)
//
// Sub-satoshi remainder from BPS division goes to the miner per spec §4.

// Sprint B3 (pure PoW): 100% of the per-block subsidy goes to the miner.
// The validator (25%) and oracle (5%) pools were removed with BFT/PoBRS
// (B2, ADR-033/Bloch D2/D4) — there are no validators or oracles to fund.
pub const MINER_SHARE_BPS:     u64 = 10_000; // 100%
pub const VALIDATOR_SHARE_BPS: u64 =      0; // removed (no BFT)
pub const ORACLE_SHARE_BPS:    u64 =      0; // removed (no PoBRS)
pub const TOTAL_SHARE_BPS:     u64 = MINER_SHARE_BPS + VALIDATOR_SHARE_BPS + ORACLE_SHARE_BPS;

const _: () = assert!(TOTAL_SHARE_BPS == 10_000);

/// Splits a per-block subsidy `(miner, validator_pool, oracle_pool)` per spec §4.
///
/// Sub-satoshi remainder accrues to the miner.
#[inline]
pub fn split_subsidy_sat(subsidy_sat: u64) -> (u64, u64, u64) {
    let validator = subsidy_sat * VALIDATOR_SHARE_BPS / 10_000;
    let oracle    = subsidy_sat * ORACLE_SHARE_BPS    / 10_000;
    let miner     = subsidy_sat - validator - oracle; // absorbs remainder
    (miner, validator, oracle)
}

// ── Fee distribution (spec §4.2) ──────────────────────────────────────────

pub const ENDOW_FEE_SHARE_BPS: u64 = 1_000; // 10% of fees → endowment

// ── Outbound query fee distribution (oracle network, ADR-018, spec §4.3) ──

pub const OUTBOUND_QUERY_BURN_BPS:          u64 = 5_000; // 50% burned
pub const OUTBOUND_QUERY_ENDOW_BPS:         u64 = 3_000; // 30% endowment
pub const OUTBOUND_QUERY_ORACLE_REBATE_BPS: u64 = 2_000; // 20% pro-rata to active oracles

const _: () = assert!(
    OUTBOUND_QUERY_BURN_BPS + OUTBOUND_QUERY_ENDOW_BPS + OUTBOUND_QUERY_ORACLE_REBATE_BPS
        == 10_000
);

// ── Founder vesting (Bloch-SIS, B3b: 10-yr cliff + 40-yr MONTHLY) ──────────
//
// Genesis contains 0 BLOCH to the founder. The 3.57B (17%) allocation is
// *fully locked for 10 years* (cliff), then released in *480 equal monthly
// tranches over the following 40 years* — a 50-year horizon. Release is
// monthly (not per-block): the coinbase carries a founder output only on the
// first block of each vested month, paying one tranche; every other block is
// a single-output (miner) coinbase.
//
// Heights @ 30 s blocks, 360-day years (12 × 30-day months), 2880 blocks/day:
//   MONTH_BLOCKS = 30 × 2880          =     86_400 blocks
//   cliff  = 10 yr = 120 × 86_400     = 10_368_000 blocks (fully locked)
//   vest   = 40 yr = 480 × 86_400     = 41_472_000 blocks (480 monthly tranches)
//   end    = cliff + vest             = 51_840_000 blocks
// Per-tranche amount = 3.57B / 480 = 7,437,500 BLOCH (divides exactly).

pub const MONTH_BLOCKS:           u64 = 86_400;      // 30 days @ 30 s
pub const FOUNDER_VESTING_CLIFF:  u64 = 10_368_000;  // 10 yr fully locked
pub const FOUNDER_VESTING_MONTHS: u64 = 480;         // 40 yr × 12
pub const FOUNDER_VESTING_END:    u64 = FOUNDER_VESTING_CLIFF + FOUNDER_VESTING_MONTHS * MONTH_BLOCKS;

const _: () = assert!(FOUNDER_VESTING_END == 51_840_000);
// Tranche divides the premine exactly (no truncation): 3.57e9 / 480 = 7.4375e6.
const _: () = assert!(FOUNDER_PREMINE_TOTAL_SAT % FOUNDER_VESTING_MONTHS == 0);

// ── Founder vesting math (per spec §5.2 / §5.3) ──────────────────────────
//
// `founder_vested_amount_sat(h)` returns the cumulative BLOCH (in satoshi)
// vested up to and including height `h`. `founder_vesting_delta_sat(h)`
// returns the per-block payout that the coinbase at height `h` must include
// as an output to `FOUNDER_ADDRESS_HASH`. Outside the vesting range, both
// return 0.
//
// Monthly step function: cumulative vested = completed_months × tranche.

/// Per-tranche founder payout (satoshi). One tranche vests per month.
#[inline]
pub const fn founder_monthly_tranche_sat() -> u64 {
    FOUNDER_PREMINE_TOTAL_SAT / FOUNDER_VESTING_MONTHS
}

/// Cumulative founder BLOCH (in satoshi) vested at the given block height.
///
/// Monthly step (B3b):
/// - `h < FOUNDER_VESTING_CLIFF`        → 0
/// - `CLIFF ≤ h < FOUNDER_VESTING_END`  → (completed months) × tranche
/// - `h ≥ FOUNDER_VESTING_END`          → FOUNDER_PREMINE_TOTAL_SAT
#[inline]
pub fn founder_vested_amount_sat(height: u64) -> u64 {
    if height < FOUNDER_VESTING_CLIFF {
        0
    } else if height >= FOUNDER_VESTING_END {
        FOUNDER_PREMINE_TOTAL_SAT
    } else {
        let months = (height - FOUNDER_VESTING_CLIFF) / MONTH_BLOCKS;
        months * founder_monthly_tranche_sat()
    }
}

/// Per-block founder vesting payout at the given height. The coinbase at
/// height `h` (when in the vesting range) must include an output of this
/// amount to `FOUNDER_ADDRESS_HASH`.
///
/// Equals `founder_vested_amount_sat(h) - founder_vested_amount_sat(h - 1)`.
/// Returns 0 for `h == 0` (genesis pays no founder vesting) and for any
/// height outside the vesting range.
#[inline]
pub fn founder_vesting_delta_sat(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    founder_vested_amount_sat(height) - founder_vested_amount_sat(height - 1)
}


// ── Genesis-locked addresses (Option<[u8; 20]> until Phase 6) ─────────────
//
// All three pool addresses were generated as ML-DSA-65 keystores
// (mnemonic-backed) in ~/bloch-keystores-v2-genesis/:
//   - VALIDATOR_POOL_ADDRESS_HASH:  set 2026-05-01 (Sprint 2.1.D C8b)
//   - ORACLE_POOL_ADDRESS_HASH:     set 2026-05-01 (Sprint 2.1.D C8b)
//   - FOUNDER_ADDRESS_HASH:         set 2026-05-02 (Phase 6 Genesis Ceremony)
// The `*_address_hash()` helpers panic on unwrap for unset slots; this is
// a deliberate fail-loud for nodes misconfigured for mainnet.

// Bloch-SIS founder address. Unified with main.rs FOUNDER_ADDRESS_HEX
// (bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073) so the genesis
// coinbase and the monthly vesting output pay the SAME wallet. This is the
// founder-owned keystore (~/bloch-founder.json; password held by the founder).
pub const FOUNDER_ADDRESS_HASH: Option<[u8; 20]> = Some([
    0xe9, 0x86, 0xdb, 0x51, 0x49, 0xcf, 0xf7, 0x49, 0x9b, 0x28,
    0x2a, 0x04, 0x82, 0x72, 0xa0, 0x9a, 0xff, 0x0a, 0xf4, 0xff,
]);

// validator-pool.json (2026-05-01)
// Address: bloch1qc23a3184ac8eb1c611b0181061855971be4a38786b3beafc
pub const VALIDATOR_POOL_ADDRESS_HASH: Option<[u8; 20]> = Some([
    0xc2, 0x3a, 0x31, 0x84, 0xac, 0x8e, 0xb1, 0xc6, 0x11, 0xb0,
    0x18, 0x10, 0x61, 0x85, 0x59, 0x71, 0xbe, 0x4a, 0x38, 0x78,
]);

// oracle-pool.json (2026-05-01)
// Address: bloch1qfc3e8ede9f6a4e1c8541731913d93963708f0604ebf94e61
pub const ORACLE_POOL_ADDRESS_HASH: Option<[u8; 20]> = Some([
    0xfc, 0x3e, 0x8e, 0xde, 0x9f, 0x6a, 0x4e, 0x1c, 0x85, 0x41,
    0x73, 0x19, 0x13, 0xd9, 0x39, 0x63, 0x70, 0x8f, 0x06, 0x04,
]);

/// Returns the founder address hash. Panics if Phase 6 has not set it.
#[inline]
pub fn founder_address_hash() -> [u8; 20] {
    FOUNDER_ADDRESS_HASH.expect(
        "FOUNDER_ADDRESS_HASH not set: this node is not configured for mainnet \
         (Phase 6 of the rebrand has not run)",
    )
}

/// Returns the validator pool address hash. Panics if Phase 6 has not set it.
#[inline]
pub fn validator_pool_address_hash() -> [u8; 20] {
    VALIDATOR_POOL_ADDRESS_HASH.expect(
        "VALIDATOR_POOL_ADDRESS_HASH not set: this node is not configured for mainnet \
         (Phase 6 of the rebrand has not run)",
    )
}

/// Returns the oracle pool address hash. Panics if Phase 6 has not set it.
#[inline]
pub fn oracle_pool_address_hash() -> [u8; 20] {
    ORACLE_POOL_ADDRESS_HASH.expect(
        "ORACLE_POOL_ADDRESS_HASH not set: this node is not configured for mainnet \
         (Phase 6 of the rebrand has not run)",
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Supply algebra: founder + pool + mining nominal == nominal total.
    #[test]
    fn supply_components_sum_to_nominal() {
        assert_eq!(
            FOUNDER_PREMINE_TOTAL_SAT
                + VALIDATOR_ORACLE_POOL_SAT
                + MINING_EMISSION_NOMINAL_SAT,
            NOMINAL_TOTAL_SUPPLY_SAT
        );
    }

    /// Monthly vesting divides the premine exactly: 480 tranches, no loss.
    #[test]
    fn vesting_tranche_divides_exactly() {
        let tranche = founder_monthly_tranche_sat();
        assert!(tranche > 0);
        assert_eq!(tranche * FOUNDER_VESTING_MONTHS, FOUNDER_PREMINE_TOTAL_SAT);
        // 3.57B / 480 = 7,437,500 BLOCH per month.
        assert_eq!(tranche, 7_437_500 * SAT_PER_BLOCH);
    }

    /// Halving emission closes at 17,385,062,400 BLOCH by the end of the first
    /// tail period (geometric halvings 0..6 + one tail period at halving 7).
    ///
    /// REINTERPRETED under Emission V3: this figure describes the V2 curve as
    /// if it ran forever — COUNTERFACTUAL beyond the fork (453,743), where the
    /// V3 curve takes over. Kept because it pins the legacy-branch constants
    /// (8,400 / 1,036,800 / 100) that still govern all pre-fork history.
    /// The computation below intentionally does NOT call `block_subsidy_sat`.
    #[test]
    fn halving_emission_closes() {
        let mut total_sat: u128 = 0;
        let mut reward_bloch: u64 = INITIAL_BLOCK_REWARD_BLOCH;
        // Geometric phase (halvings 0..TAIL_ACTIVATION_HALVING).
        for _ in 0..TAIL_ACTIVATION_HALVING {
            total_sat += (reward_bloch as u128)
                * (SAT_PER_BLOCH as u128)
                * (HALVING_INTERVAL as u128);
            reward_bloch >>= 1;
        }
        // First tail period: 100 BLOCH/block × HALVING_INTERVAL blocks.
        total_sat += (TAIL_FLOOR_SAT as u128) * (HALVING_INTERVAL as u128);
        let total_bloch = total_sat / (SAT_PER_BLOCH as u128);
        assert_eq!(total_bloch, 17_385_062_400);
    }

    /// Subsidy split rounds remainder to miner (spec §4).
    #[test]
    fn split_at_initial_height() {
        let (miner, validator, oracle) = split_subsidy_sat(INITIAL_BLOCK_REWARD_SAT);
        assert_eq!(validator, 0); // pool removed (no BFT)
        assert_eq!(oracle,    0); // pool removed (no PoBRS)
        assert_eq!(miner, INITIAL_BLOCK_REWARD_SAT); // 100% to miner
        assert_eq!(miner + validator + oracle, INITIAL_BLOCK_REWARD_SAT);
    }

    /// Tail-floor activation, REINTERPRETED under Emission V3 + PISO-60.
    ///
    /// The old test asserted the V2 tail at TAIL_ACTIVATION_HEIGHT
    /// (7,257,600) — that height is now governed by the V3 curve (it is far
    /// above the fork), so the V2 tail is counterfactual and can no longer be
    /// observed through `block_subsidy_sat`. The intent — "the floor kicks in
    /// exactly where the geometric term drops below the floor, and holds
    /// forever" — is preserved against the V3 curve and ITS 60-BLOCH floor:
    /// 2600 >> 5 = 81 ≥ 60, 2600 >> 6 = 40 < 60 → floor from epoch 6 (one
    /// epoch later than under the old shared 100 floor).
    #[test]
    fn tail_floor_activates_at_v3_epoch_6() {
        // Last block of V3 epoch 5 still pays geometric: 2600 >> 5 = 81.
        assert_eq!(
            block_subsidy_sat(EMISSION_V3_TAIL_ACTIVATION_HEIGHT - 1),
            81 * SAT_PER_BLOCH
        );
        // First block of V3 epoch 6: 2600 >> 6 = 40 < 60 → V3 floor.
        assert_eq!(
            block_subsidy_sat(EMISSION_V3_TAIL_ACTIVATION_HEIGHT),
            EMISSION_V3_TAIL_FLOOR_SAT
        );
        assert_eq!(EMISSION_V3_TAIL_FLOOR_SAT, 60 * SAT_PER_BLOCH);
        // Far in the future: still the V3 floor (shift saturates to 0).
        assert_eq!(block_subsidy_sat(1_000_000_000), EMISSION_V3_TAIL_FLOOR_SAT);
        assert_eq!(block_subsidy_sat(u64::MAX), EMISSION_V3_TAIL_FLOOR_SAT);
        // The V2 floor (100) must NEVER surface through the V3 branch.
        assert_ne!(block_subsidy_sat(u64::MAX), TAIL_FLOOR_SAT);
    }

    /// The legacy V2 curve, re-implemented verbatim as it stood BEFORE the
    /// Emission V3 change. This is the reference for the historical
    /// non-regression test: if the legacy branch of `block_subsidy_sat` ever
    /// drifts from this, every historical coinbase becomes invalid.
    fn legacy_v2_subsidy_sat(height: u64) -> u64 {
        let halvings = height / HALVING_INTERVAL;
        let geometric_bloch = if halvings >= 64 {
            0
        } else {
            INITIAL_BLOCK_REWARD_BLOCH >> halvings
        };
        let geometric_sat = geometric_bloch * SAT_PER_BLOCH;
        if geometric_sat < TAIL_FLOOR_SAT { TAIL_FLOOR_SAT } else { geometric_sat }
    }

    /// TEST 1 — Historical non-regression: EVERY emission height below the
    /// fork returns exactly what the pre-V3 code returned. This is the test
    /// that stops the fork from invalidating the chain's history.
    ///
    /// The domain is walked EXHAUSTIVELY (all 453,743 pre-fork heights — cheap
    /// integer math). Note: the V2 curve's halving boundaries (1,036,800 × n)
    /// all lie ABOVE the fork, so the reachable pre-fork domain is entirely
    /// epoch 0; both the exhaustive walk and the explicit constant pin below
    /// document that.
    #[test]
    fn emission_v3_historical_non_regression() {
        for h in 0..EMISSION_V3_FORK_EMISSION_HEIGHT {
            assert_eq!(
                block_subsidy_sat(h),
                legacy_v2_subsidy_sat(h),
                "pre-fork subsidy changed at emission height {h} — this would \
                 invalidate historical coinbases",
            );
        }
        // Explicit pins at the landmarks: genesis-of-emission, the carried
        // height, first Genesis-2/3 local block, and fork − 1.
        assert_eq!(block_subsidy_sat(0), 8_400 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(413_743), 8_400 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(413_744), 8_400 * SAT_PER_BLOCH);
        assert_eq!(
            block_subsidy_sat(EMISSION_V3_FORK_EMISSION_HEIGHT - 1),
            8_400 * SAT_PER_BLOCH
        );
    }

    /// TEST 2 — The V3 curve: 2,600 at the fork, halving every 1,555,200
    /// blocks (1.5 yr), V3 floor at 60 once 2600 >> n < 60 (epoch 6 on).
    #[test]
    fn emission_v3_curve_boundaries() {
        let f = EMISSION_V3_FORK_EMISSION_HEIGHT;
        let i = EMISSION_V3_HALVING_INTERVAL;
        // Epoch starts.
        assert_eq!(block_subsidy_sat(f),         2_600 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + i),     1_300 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 2 * i),   650 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 3 * i),   325 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 4 * i),   162 * SAT_PER_BLOCH); // 325 >> 1 int-div
        assert_eq!(block_subsidy_sat(f + 5 * i),    81 * SAT_PER_BLOCH); // 81 ≥ 60 → geometric
        assert_eq!(block_subsidy_sat(f + 6 * i), EMISSION_V3_TAIL_FLOOR_SAT); // 40 < 60 → floor
        // Last block of each epoch still pays that epoch's reward.
        assert_eq!(block_subsidy_sat(f + i - 1),     2_600 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 2 * i - 1), 1_300 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 5 * i - 1),   162 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 6 * i - 1),    81 * SAT_PER_BLOCH);
        // Floor holds across later epochs — at 60, never the V2 100.
        assert_eq!(block_subsidy_sat(f + 7 * i), EMISSION_V3_TAIL_FLOOR_SAT);
        assert_eq!(block_subsidy_sat(f + 40 * i), EMISSION_V3_TAIL_FLOOR_SAT);
        assert_eq!(block_subsidy_sat(f + 40 * i), 60 * SAT_PER_BLOCH);
    }

    /// TEST 3 — The step is exactly at the fork, and nowhere else: fork − 1
    /// pays 8,400, fork pays 2,600, fork + 1 pays 2,600. The 69% cut is
    /// intentional; this proves it lands on precisely one block boundary.
    #[test]
    fn emission_v3_step_exactly_at_fork() {
        let f = EMISSION_V3_FORK_EMISSION_HEIGHT;
        assert_eq!(block_subsidy_sat(f - 2), 8_400 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f - 1), 8_400 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f),     2_600 * SAT_PER_BLOCH);
        assert_eq!(block_subsidy_sat(f + 1), 2_600 * SAT_PER_BLOCH);
        // In local-height terms (Genesis-3): the step is at local 40,000.
        assert_eq!(f - super::super::CARRYOVER_SOURCE_HEIGHT, 40_000);
    }

    /// TEST 4 — Σ subsidy over the 100 years (103,680,000 blocks) after
    /// the fork equals EXACTLY 13,620,441,600 BLOCH, computed per-block in
    /// u128 integer sats. The sat total (1.36e18) exceeds 2^53, so any f64
    /// in this pipeline silently corrupts the figure — asserted explicitly.
    #[test]
    fn emission_v3_100_year_sum() {
        const BLOCKS_PER_YEAR: u64 = 1_036_800;
        let f = EMISSION_V3_FORK_EMISSION_HEIGHT;
        let mut total_sat: u128 = 0;
        for h in f..f + 100 * BLOCKS_PER_YEAR {
            total_sat += block_subsidy_sat(h) as u128;
        }
        assert_eq!(
            total_sat,
            EMISSION_V3_100Y_TOTAL_BLOCH * (SAT_PER_BLOCH as u128),
            "100-year post-fork emission must be exactly 13,620,441,600 BLOCH",
        );
        assert_eq!(EMISSION_V3_100Y_TOTAL_BLOCH, 13_620_441_600);
        // Integer-only guard: the total does not fit float53 — using f64
        // anywhere in this sum yields a wrong number (it has, historically).
        assert!(total_sat > (1u128 << 53));
    }

    /// TEST 5 — Full supply accounting (PISO-60 rationale). Everything that
    /// exists or will exist over the 100 years after the fork closes at the
    /// documented 21B nominal, deviation < 0.5%.
    ///
    /// "Already emitted" is the 2026-08-09 measurement: Genesis-1 carryover
    /// 3,475,441,200 + mined since Genesis-3 restart 309,128,400. The few
    /// thousand pre-fork blocks still to be mined between that measurement
    /// (local ≈36.8k) and the fork (local 40,000) add ≈27M BLOCH at 8,400 —
    /// inside the tolerance band, and they narrow the deviation, not widen it.
    ///
    /// With the old shared 100 floor this total was 24,778,512,000 (≈24.78B,
    /// +18%); PISO-60 brings it to 20,975,011,200 (−0.12%).
    #[test]
    fn total_supply_closes_near_nominal() {
        const CARRYOVER_BLOCH:      u128 = 3_475_441_200;
        const MINED_SINCE_G3_BLOCH: u128 =   309_128_400;
        const ALREADY_EXISTS_BLOCH: u128 = CARRYOVER_BLOCH + MINED_SINCE_G3_BLOCH;
        const PREMINE_BLOCH:        u128 = 3_570_000_000; // locked, not yet emitted
        const NOMINAL_BLOCH:        u128 = 21_000_000_000;

        assert_eq!(ALREADY_EXISTS_BLOCH, 3_784_569_600);

        let grand_total =
            ALREADY_EXISTS_BLOCH + EMISSION_V3_100Y_TOTAL_BLOCH + PREMINE_BLOCH;
        assert_eq!(grand_total, 20_975_011_200);

        // |deviation| < 0.5% of nominal, in pure integer arithmetic:
        // |21,000,000,000 − 20,975,011,200| = 24,988,800 → 0.119%.
        let deviation = NOMINAL_BLOCH - grand_total; // grand_total < nominal
        assert!(grand_total < NOMINAL_BLOCH);
        assert_eq!(deviation, 24_988_800);
        assert!(
            deviation * 1_000 < NOMINAL_BLOCH * 5,
            "grand total must stay within 0.5% of the 21B nominal",
        );
    }

    /// Pre-cliff: nothing vested.
    #[test]
    fn vesting_zero_before_cliff() {
        assert_eq!(founder_vested_amount_sat(0), 0);
        assert_eq!(founder_vested_amount_sat(1), 0);
        assert_eq!(founder_vested_amount_sat(FOUNDER_VESTING_CLIFF - 1), 0);
        assert_eq!(founder_vested_amount_sat(FOUNDER_VESTING_CLIFF), 0);
    }

    /// Post-end: fully vested and stays there.
    #[test]
    fn vesting_complete_at_end() {
        assert_eq!(
            founder_vested_amount_sat(FOUNDER_VESTING_END),
            FOUNDER_PREMINE_TOTAL_SAT
        );
        assert_eq!(
            founder_vested_amount_sat(FOUNDER_VESTING_END + 1_000_000),
            FOUNDER_PREMINE_TOTAL_SAT
        );
    }

    /// Monthly release: no payout between month boundaries; first tranche
    /// vests one month after the cliff.
    #[test]
    fn vesting_first_payout_at_first_month() {
        let tranche = founder_monthly_tranche_sat();
        // No release just after the cliff (not a month boundary).
        assert_eq!(founder_vesting_delta_sat(FOUNDER_VESTING_CLIFF + 1), 0);
        // First tranche at CLIFF + MONTH_BLOCKS.
        assert_eq!(
            founder_vesting_delta_sat(FOUNDER_VESTING_CLIFF + MONTH_BLOCKS),
            tranche
        );
        // Mid-month block: no release.
        assert_eq!(
            founder_vesting_delta_sat(FOUNDER_VESTING_CLIFF + MONTH_BLOCKS + 1),
            0
        );
    }

    /// Telescoping: sum of all per-block deltas across the entire vesting
    /// range equals exactly FOUNDER_PREMINE_TOTAL_SAT (no rounding leak).
    /// Verified algebraically via vested(END) - vested(CLIFF) (no loop).
    #[test]
    fn vesting_telescopes_to_total() {
        let span = founder_vested_amount_sat(FOUNDER_VESTING_END)
            - founder_vested_amount_sat(FOUNDER_VESTING_CLIFF);
        assert_eq!(span, FOUNDER_PREMINE_TOTAL_SAT);
        // Edge: delta at h=0 is always 0 (genesis pays no founder).
        assert_eq!(founder_vesting_delta_sat(0), 0);
        // Edge: delta after END is always 0.
        assert_eq!(founder_vesting_delta_sat(FOUNDER_VESTING_END + 1), 0);
        assert_eq!(founder_vesting_delta_sat(FOUNDER_VESTING_END + 100), 0);
    }

    /// Founder-owned wallet (~/bloch-founder.json).
    /// Address: bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073
    ///
    /// Verifies `founder_address_hash()` returns the consensus-locked
    /// 20-byte hash byte-for-byte. Any future change to this value is
    /// a hard fork and should be detected immediately by this test.
    #[test]
    fn founder_address_hash_returns_genesis_value() {
        let h = founder_address_hash();
        let expected: [u8; 20] = [
            0xe9, 0x86, 0xdb, 0x51, 0x49, 0xcf, 0xf7, 0x49, 0x9b, 0x28,
            0x2a, 0x04, 0x82, 0x72, 0xa0, 0x9a, 0xff, 0x0a, 0xf4, 0xff,
        ];
        assert_eq!(
            h, expected,
            "FOUNDER_ADDRESS_HASH must match Phase 6 Genesis Ceremony hash; changing this is a hard fork"
        );
    }

    #[test]
    fn validator_pool_address_returns_genesis_value() {
        // Set in Sprint 2.1.D C8b from validator-pool.json (2026-05-01).
        let h = validator_pool_address_hash();
        assert_eq!(h, [
            0xc2, 0x3a, 0x31, 0x84, 0xac, 0x8e, 0xb1, 0xc6, 0x11, 0xb0,
            0x18, 0x10, 0x61, 0x85, 0x59, 0x71, 0xbe, 0x4a, 0x38, 0x78,
        ]);
    }

    #[test]
    fn oracle_pool_address_returns_genesis_value() {
        // Set in Sprint 2.1.D C8b from oracle-pool.json (2026-05-01).
        let h = oracle_pool_address_hash();
        assert_eq!(h, [
            0xfc, 0x3e, 0x8e, 0xde, 0x9f, 0x6a, 0x4e, 0x1c, 0x85, 0x41,
            0x73, 0x19, 0x13, 0xd9, 0x39, 0x63, 0x70, 0x8f, 0x06, 0x04,
        ]);
    }
}

// ── Property-based invariants (security scanner lane) ───────────────────────
//
// These `proptest` cases assert the *consensus invariants* of the emission
// schedule across the whole height domain, not just the hand-picked heights in
// the unit tests above. A regression that (for example) lets the subsidy climb
// after a halving, breaks value conservation in the split, or lets founder
// vesting over-pay would be an inflation bug — the most severe class of
// consensus fault. Run with: `cargo test -p bloch-crypto tokenomics`.
#[cfg(test)]
mod proptest_invariants {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Subsidy never exceeds the genesis initial reward and never drops
        // below the perpetual tail floor — the emission envelope.
        //
        // REINTERPRETED under PISO-60: the global lower bound is now the V3
        // floor (60), which governs everything at/above the fork. The V2
        // floor (100) still bounds its own branch — but the reachable
        // pre-fork domain is entirely epoch 0 (8,400), asserted per-branch.
        #[test]
        fn subsidy_within_envelope(h in 0u64..u64::MAX) {
            let s = block_subsidy_sat(h);
            prop_assert!(s >= EMISSION_V3_TAIL_FLOOR_SAT, "subsidy below V3 tail floor at h={h}");
            prop_assert!(s <= INITIAL_BLOCK_REWARD_SAT, "subsidy above initial reward at h={h}");
            if h < EMISSION_V3_FORK_EMISSION_HEIGHT {
                // Legacy branch: the whole pre-fork domain sits in V2 epoch 0
                // and its own floor (100) trivially holds.
                prop_assert!(s >= TAIL_FLOOR_SAT, "pre-fork subsidy below V2 floor at h={h}");
                prop_assert_eq!(s, INITIAL_BLOCK_REWARD_SAT);
            }
        }

        // Emission is monotonically NON-INCREASING in height: halvings only ever
        // reduce (or hold) the subsidy. A violation would be a stealth inflation.
        #[test]
        fn subsidy_monotone_non_increasing(a in 0u64..u64::MAX, b in 0u64..u64::MAX) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(block_subsidy_sat(hi) <= block_subsidy_sat(lo));
        }

        // Value conservation: the three-way split neither creates nor destroys
        // satoshi, and the sub-satoshi remainder always accrues to the miner.
        #[test]
        fn split_conserves_value(subsidy in 0u64..=INITIAL_BLOCK_REWARD_SAT) {
            let (miner, validator, oracle) = split_subsidy_sat(subsidy);
            prop_assert_eq!(miner + validator + oracle, subsidy, "split lost/created value");
            // Genesis-2 is pure PoW: pools removed, miner takes 100%.
            prop_assert_eq!(validator, 0);
            prop_assert_eq!(oracle, 0);
            prop_assert_eq!(miner, subsidy);
        }

        // Cumulative founder vesting is monotonically non-decreasing and never
        // exceeds the fixed premine — the founder can never be over-paid.
        #[test]
        fn founder_vesting_monotone_and_capped(a in 0u64..=(FOUNDER_VESTING_END + MONTH_BLOCKS), b in 0u64..=(FOUNDER_VESTING_END + MONTH_BLOCKS)) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let v_lo = founder_vested_amount_sat(lo);
            let v_hi = founder_vested_amount_sat(hi);
            prop_assert!(v_hi >= v_lo, "vesting decreased between h={lo} and h={hi}");
            prop_assert!(v_hi <= FOUNDER_PREMINE_TOTAL_SAT, "vesting over-paid at h={hi}");
        }

        // The per-block delta is exactly the first difference of the cumulative
        // curve — the coinbase output can never mint more than vested this block.
        #[test]
        fn vesting_delta_matches_curve(h in 1u64..=(FOUNDER_VESTING_END + MONTH_BLOCKS)) {
            let expected = founder_vested_amount_sat(h) - founder_vested_amount_sat(h - 1);
            prop_assert_eq!(founder_vesting_delta_sat(h), expected);
        }
    }
}
