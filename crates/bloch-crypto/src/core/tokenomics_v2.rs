//! BLOCH Tokenomics V2 — Genesis-locked Constants and Helpers
//!
//! Per `docs/specs/TOKENOMICS_V2.md`. Activated by ADR-028.
//!
//! These are CONSENSUS RULES. Mutation requires a hard fork. Genesis-locked
//! values, frozen by the pre-commitment doctrine
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

pub const INITIAL_BLOCK_REWARD_BLOCH: u64 = 8_400;
pub const INITIAL_BLOCK_REWARD_SAT:  u64 = INITIAL_BLOCK_REWARD_BLOCH * SAT_PER_BLOCH;
pub const HALVING_INTERVAL:          u64 = 1_036_800; // ~1 year @ 30 s (360×2880)
pub const TAIL_FLOOR_BLOCH:           u64 = 100;
pub const TAIL_FLOOR_SAT:            u64 = TAIL_FLOOR_BLOCH * SAT_PER_BLOCH;
pub const TARGET_BLOCK_TIME_SECS:    u64 = 30;

pub const TAIL_ACTIVATION_HALVING: u64 = 7;
pub const TAIL_ACTIVATION_HEIGHT:  u64 = TAIL_ACTIVATION_HALVING * HALVING_INTERVAL;

const _: () = assert!(TAIL_ACTIVATION_HEIGHT == 7_257_600);

/// Block subsidy in satoshi at the given height. Used by C2.
///
/// Halves the per-block reward in BLOCH-integer space, then multiplies up to
/// satoshi. This matches spec §3.1 table and §2 `MINING_EMISSION_ACTUAL`. See
/// the module-level note on halving semantics.
#[inline]
pub fn block_subsidy_sat(height: u64) -> u64 {
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

    /// Tail-floor activates at halving 7 (height 7,257,600).
    #[test]
    fn tail_floor_activates_at_halving_7() {
        // First block of halving 7 (= TAIL_ACTIVATION_HEIGHT) is the first tail block:
        // 8400 >> 7 = 65 < 100, so the 100-BLOCH floor applies.
        assert_eq!(block_subsidy_sat(TAIL_ACTIVATION_HEIGHT), TAIL_FLOOR_SAT);
        // Last block of halving 6 still pays geometric: 8400 >> 6 = 131 BLOCH.
        assert_eq!(block_subsidy_sat(TAIL_ACTIVATION_HEIGHT - 1), 131 * SAT_PER_BLOCH);
        // Far in the future: still tail floor.
        assert_eq!(block_subsidy_sat(1_000_000_000), TAIL_FLOOR_SAT);
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
