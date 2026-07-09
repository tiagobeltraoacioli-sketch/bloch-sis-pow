# ADR-010: Tokenomics, Emission Curve, and Endowment Buffer

**Sprint:** 2.2 (calibration) / 2.3 (implementation) / 2.4 (integration)
**Status:** Proposed (revision 1 — distribution split updated by ADR-010-Addendum-1; premine model finalized by ADR-010-A; ready for commit pre-2026-05-15)
**Date:** 2026-04-29 (rev1 same day)
**Author:** BLOCH Core
**Related:** ADR-001 (FFG epoch=6), ADR-005 (Committee era), ADR-006 (Block time), ADR-010-A (Founder Premine — 17%/30y), ADR-010-Addendum-1 (70/25/5 distribution including oracle pool), ADR-018 (Oracle Network)

**Changelog rev1 (2026-04-29):**
1. §4 — Distribution split updated from 70/30 (miner/validator) to 70/25/5 (miner/validator/oracle) per ADR-010-Addendum-1.
2. §5.2 — Constants `MINER_SHARE_BPS`, `VALIDATOR_SHARE_BPS`, `ORACLE_SHARE_BPS` reflect the new split.
3. §6.3 R3 — Premine arithmetic resolved by ADR-010-A: 170M founder + 30M pool = 200M total premine; 800M mining = 1B total supply.
4. §9 — ADR-010-A and ADR-010-Addendum-1 marked as resolved (no longer "pending").

---

## 1. Context

Sprints 1.5–2.1 (closed) built the technical infrastructure of BLOCH: PoBRS, FFG committee 21-of-21, ML-DSA-65, CommitteeRegistry. **Tokenomics remained a conceptual gap** — declarations of "1B supply, 97% miners / 3% validator+oracle pool / 0% treasury" + "founder premine 10%" were arithmetically inconsistent (summing to 110%) and incomplete (did not specify post-emission behavior).

This ADR closes the gap by specifying:

1. **Emission model** — per-block reward curve over the chain's lifetime, including post-halving behavior.
2. **Endowment buffer** — accumulating on-chain pool funded by fees.
3. **Emergency boost mode** — conditional subsidy mechanism to defend security budget in adverse periods.
4. **Distribution among miners, validators, and oracles** — fraction of each block flowing to each party.
5. **Calibrated parameters** based on ~50,000 Monte Carlo trajectories.

Decisions out of scope of this ADR (referenced):
- **Premine vs Founder's Reward** → ADR-010-A (resolved: 17% founder, 30-year linear vesting with 12-month cliff).
- **Founder vesting** → ADR-011 (FFG activation block height; vesting cliff aligned with first halving + activation).
- **Validator+oracle pool distribution of 30M** → ADR-012 (decision pending).

## 2. Decision Drivers

- **D1.** Mainnet-readiness: tokenomics is part of the genesis specification; without it, mainnet cannot be audited or launched.
- **D2.** Regulatory defensibility: MiCA Art.6 (whitepaper) and SEC Howey defense require a precise, auditable, and justifiable description of emission.
- **D3.** Long-term sustainability: chain must have viable security budget for decades, not only during active mining.
- **D4.** Fair-launch + finite supply narrative: BLOCH's competitive positioning as "post-quantum Bitcoin" requires low and predictable inflation.
- **D5.** Adverse scenario robustness: crypto winters (5–10 years) and black swans are sector reality; tokenomics must survive them.
- **D6.** Compatibility with ADR-005/ADR-006: model must compensate miners (PoW) and FFG validators (BFT) without unbalancing either.
- **D7.** Auditability: parameters must be mathematically interpretable, without ML in consensus rules.
- **D8.** Mining attractiveness: bootstrap (years 0–10) must be viable even in median scenarios.

## 3. Considered Options

Four models were extensively evaluated via Monte Carlo (reference: PDFs `BLOCH_Tokenomics_MonteCarlo.pdf`, `BLOCH_Hybrid_MonteCarlo.pdf`, `BLOCH_Scenarios_MonteCarlo.pdf`, `BLOCH_Adverse_Scenarios.pdf` — total ~50,000 stochastic trajectories).

### 3.1 M1 — Bitcoin-style (baseline)

Pure Bitcoin halving, no tail, no endowment. 100% reward to miner. Fees go to miner.

**Monte Carlo performance:** collapses in 100% of simulations under any price scenario. Pedagogical model only — not viable in production.

### 3.2 M2 — Monero-style tail

Halving until reward reaches floor (50 BLOCH/block), then perpetual floor. Inflation ~0.1%/year post-emission. 70/30 distribution miner/validator over emission + fees.

**Monte Carlo performance:**
- Median scenario: $10.33M security budget year 50; collapse risk 27.5%.
- Crypto Winter: $0.34M security budget; collapse risk 59.9%.
- Cumulative inflation over 50 years: +58% (1.58B BLOCH).

**Pros:** highest absolute security budget across all scenarios. Greater resilience in adverse cases. Production-validated Monero prior art for 8+ years.
**Cons:** breaks finite-supply narrative more aggressively. High cumulative inflation.

### 3.3 M3 — Pure Endowment

15% of fees → endowment during active mining. Post-emission: 3% yield paid to miners/validators. Conditional tail activates only if yield insufficient.

**Monte Carlo performance:**
- Median scenario: $2.48M security budget year 50; collapse risk 41.1%.
- Crypto Winter: $0.08M; collapse risk 72.6%.
- Cumulative inflation: +17% (1.17B BLOCH).

**Pros:** preserves finite-supply narrative (very low inflation). Elegant mechanism.
**Cons:** significantly smaller security budget. Validators receive nothing during active mining (design bug in original pure model — corrected in simulated variant). No production prior art.

### 3.4 M4 — Smooth Adaptive (ML-informed)

Sigmoid function activating tail emission based on stress index. Continuous endowment accumulation. Higher code complexity.

**Monte Carlo performance:**
- Median scenario: $2.17M security budget year 50; collapse risk 42.1%.
- Performance similar to M3, with ~3x more code to audit.

**Pros:** responds earlier to stress. Interesting concept.
**Cons:** no prior art. High audit complexity. Insufficient cost-benefit for v1.

### 3.5 M5 — Hybrid (M2 + M3 calibrated) ✅ SELECTED

Combines:
- **Low tail emission** (25 BLOCH/block — half of pure M2). Asymptotic inflation ~0.05%/year.
- **Endowment buffer** (10% of fees → pool perpetually).
- **Emergency boost mode** (sigmoid; activates when rolling annual security < $1M).
- **70/25/5 distribution** miner/validator/oracle over emission + 90% of fees (revised by ADR-010-Addendum-1).

**Monte Carlo performance:**
- Median scenario: $5.17M security budget year 50; collapse risk 33.9%.
- Crypto Winter: $0.17M; collapse risk 64.5%.
- Black Swan: $2.19M; collapse risk 41.7%.
- Cumulative inflation: +35% (1.35B BLOCH).

**Pros:**
- Dominates M3 in all scenarios where tokenomics matters.
- 40% lower inflation than pure M2.
- Boost mode genuinely useful — activates in ~34% of simulations year 50.
- Stable calibration (3×3 sensitivity shows that small variations do not materially change the outcome).

**Cons:**
- Higher complexity than pure M2 (but significantly lower than M4).
- No exact prior art — Monero (tail) + Decred treasury (endowment) are analogies, not copies.

## 4. Decision Outcome

**Adopt M5 (Hybrid) as BLOCH v1 official tokenomics.**

Calibrated parameters:

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Initial reward | per TOKENOMICS_V2.md §3 (calibrated to close at 798,630,000 BLOCH pre-tail; the 2,381 BLOCH/block figure was from the V1 draft superseded by ADR-028) | Compatible with 800M mining target via halvings, with perpetual 25 BLOCH/block tail thereafter |
| Halving interval | 210,000 blocks (~1 year) | Bitcoin-style, production-validated |
| Tail floor | 25 BLOCH/block | Sensitivity: balance point between security and inflation |
| Endowment fee share | 10% | Sensitivity: 5% insufficient, 15% steals from validators |
| Endowment yield | 3%/year | Norway Pension Fund analog |
| Boost threshold | $1M USD annual | Tier-3 chain reference (Decred/Vertcoin scale) |
| Boost cap | 50% of yield | Preserves endowment for prolonged stress |
| Miner share | 70% | Compensates physical cost (electricity + hardware) |
| Validator share | 25% | Compensates attestation + DKG cost (revised by ADR-010-Addendum-1) |
| Oracle share | 5% | PoBRS oracle compensation Stream 1 (per ADR-018) |
| Boost warmup | 12 months | Avoids false positives during bootstrap |

## 5. Technical Implementation

### 5.1 Module structure (Rust)

```
src/tokenomics/
├── mod.rs              # re-exports and tests
├── types.rs            # constants and structs
├── reward.rs           # calculate_block_reward(height) -> u64
├── distribution.rs     # distribute(reward, fees, state) -> Distribution
├── endowment.rs        # EndowmentState (consensus rule, no wallet)
├── boost.rs            # boost_trigger(rolling_security, threshold)
└── price_oracle.rs     # consume PoBRS oracle for USD threshold
```

### 5.2 Constants (`src/tokenomics/types.rs`)

```rust
use std::time::Duration;

/// Initial per-block reward in "satoshis" (1 BLOCH = 10^8 sats).
pub const INITIAL_REWARD_SATS: u64 = /* per TOKENOMICS_V2.md §3; the 2381 figure was from the V1 draft superseded by ADR-028 */;

/// Permanent tail emission floor.
pub const TAIL_REWARD_SATS: u64 = 25 * 100_000_000;

/// Halving interval in blocks (~1 year).
pub const HALVING_INTERVAL_BLOCKS: u64 = 210_000;

/// Final cap of halvings (after this point, reward = TAIL).
pub const MAX_HALVINGS: u64 = 32;

/// Fraction of fees directed to endowment (10% in basis points).
pub const ENDOW_FEE_SHARE_BPS: u64 = 1_000;

/// Annual endowment yield in basis points (3% = 300 bps).
pub const ENDOW_YIELD_BPS: u64 = 300;

/// Annual USD security budget threshold for boost trigger.
pub const BOOST_THRESHOLD_USD_CENTS: u64 = 100_000_000; // $1M

/// Boost amount cap (% of yield).
pub const BOOST_MAX_PCT_BPS: u64 = 5_000; // 50%

/// Warmup before boost can activate (in blocks = ~12 months).
pub const BOOST_WARMUP_BLOCKS: u64 = 210_000;

/// Base distribution: miner (70%).
pub const MINER_SHARE_BPS: u64 = 7_000;

/// Base distribution: validator (25%) — revised from 30% by ADR-010-Addendum-1.
pub const VALIDATOR_SHARE_BPS: u64 = 2_500;

/// Base distribution: oracle (5%) — added by ADR-010-Addendum-1 (PoBRS Stream 1).
pub const ORACLE_SHARE_BPS: u64 = 500;

/// Rolling window for annual security budget calculation (in blocks).
pub const ROLLING_SECURITY_WINDOW_BLOCKS: u64 = 210_000;
```

### 5.3 Main reward function

```rust
// src/tokenomics/reward.rs

use crate::tokenomics::types::*;

/// Calculates the base per-block reward in sats.
/// Bitcoin-style halving until reaching TAIL_REWARD_SATS.
pub fn calculate_block_reward(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL_BLOCKS;

    if halvings >= MAX_HALVINGS {
        return TAIL_REWARD_SATS;
    }

    let halved = INITIAL_REWARD_SATS >> halvings;
    halved.max(TAIL_REWARD_SATS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_reward() {
        assert_eq!(calculate_block_reward(0), INITIAL_REWARD_SATS);
    }

    #[test]
    fn test_first_halving() {
        let after = calculate_block_reward(HALVING_INTERVAL_BLOCKS);
        assert_eq!(after, INITIAL_REWARD_SATS / 2);
    }

    #[test]
    fn test_tail_floor_reached() {
        // After ~7 halvings (2381 → ~18.6), tail floor of 25 should dominate.
        let height = HALVING_INTERVAL_BLOCKS * 7;
        let r = calculate_block_reward(height);
        assert_eq!(r, TAIL_REWARD_SATS);
    }

    #[test]
    fn test_max_halvings_returns_tail() {
        let height = HALVING_INTERVAL_BLOCKS * MAX_HALVINGS;
        assert_eq!(calculate_block_reward(height), TAIL_REWARD_SATS);
    }
}
```

### 5.4 Per-block distribution

```rust
// src/tokenomics/distribution.rs

use crate::tokenomics::{types::*, endowment::EndowmentState, boost::BoostState};

#[derive(Debug, Clone)]
pub struct Distribution {
    pub miner_sats: u64,
    pub validator_pool_sats: u64,
    pub oracle_pool_sats: u64,
    pub endowment_addition_sats: u64,
    pub boost_amount_sats: u64,
}

pub fn distribute(
    reward_sats: u64,
    fees_sats: u64,
    endow: &mut EndowmentState,
    boost: &BoostState,
    height: u64,
) -> Distribution {
    // 10% of fees to endowment
    let endow_addition = fees_sats * ENDOW_FEE_SHARE_BPS / 10_000;
    let net_fees = fees_sats - endow_addition;
    endow.deposit(endow_addition);

    // Monthly endowment yield (calculated proportionally per block)
    let yield_sats = endow.calculate_yield_for_block();

    // Boost: activates only if warmup passed and security < threshold
    let boost_amount = if height >= BOOST_WARMUP_BLOCKS && boost.is_active() {
        let max_boost = yield_sats * BOOST_MAX_PCT_BPS / 10_000;
        endow.withdraw(max_boost);
        max_boost
    } else {
        0
    };

    // Base distribution (emission + 90% of fees + boost)
    // Split: 70/25/5 (miner/validator/oracle) per ADR-010-Addendum-1
    let total_to_distribute = reward_sats + net_fees + boost_amount;
    let miner_sats = total_to_distribute * MINER_SHARE_BPS / 10_000;
    let validator_pool_sats = total_to_distribute * VALIDATOR_SHARE_BPS / 10_000;
    let oracle_pool_sats = total_to_distribute - miner_sats - validator_pool_sats;

    Distribution {
        miner_sats,
        validator_pool_sats,
        oracle_pool_sats,
        endowment_addition_sats: endow_addition,
        boost_amount_sats: boost_amount,
    }
}
```

### 5.5 EndowmentState — consensus rule

```rust
// src/tokenomics/endowment.rs

use serde::{Serialize, Deserialize};
use crate::tokenomics::types::*;

/// Endowment state as a consensus variable.
/// NO KEY, NO WALLET — only on-chain balance governed by immutable rules.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EndowmentState {
    /// Current balance in sats.
    pub balance_sats: u64,
    /// Total cumulative deposited (audit).
    pub total_deposited_sats: u64,
    /// Total cumulative distributed via yield + boost.
    pub total_distributed_sats: u64,
    /// Last processed block.
    pub last_block_height: u64,
}

impl EndowmentState {
    pub fn deposit(&mut self, amount_sats: u64) {
        self.balance_sats = self.balance_sats.saturating_add(amount_sats);
        self.total_deposited_sats =
            self.total_deposited_sats.saturating_add(amount_sats);
    }

    pub fn withdraw(&mut self, amount_sats: u64) {
        let actual = amount_sats.min(self.balance_sats);
        self.balance_sats -= actual;
        self.total_distributed_sats =
            self.total_distributed_sats.saturating_add(actual);
    }

    /// Per-block yield = balance × annual_rate / blocks_per_year
    pub fn calculate_yield_for_block(&self) -> u64 {
        // 3% per year divided by 210k blocks = ~14.3 ppm per block
        self.balance_sats * ENDOW_YIELD_BPS / (10_000 * HALVING_INTERVAL_BLOCKS)
    }
}
```

### 5.6 BoostState — conditional trigger

```rust
// src/tokenomics/boost.rs

use serde::{Serialize, Deserialize};
use crate::tokenomics::types::*;

/// Boost mode state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BoostState {
    /// Rolling buffer of security USD (12 months = 12 monthly entries).
    /// Circular index.
    pub rolling_security_usd_cents: [u64; 12],
    pub rolling_index: u8,
    /// Boost active since which block (0 = inactive).
    pub active_since_block: u64,
}

impl BoostState {
    /// Updates the rolling buffer with current block security USD.
    pub fn update(&mut self, security_usd_cents: u64, current_block: u64) {
        // Accumulates in current slot; rotates monthly
        let blocks_per_month = HALVING_INTERVAL_BLOCKS / 12;
        let month = ((current_block / blocks_per_month) % 12) as u8;

        if month != self.rolling_index {
            // New month: zero current slot before accumulating
            self.rolling_index = month;
            self.rolling_security_usd_cents[month as usize] = 0;
        }
        self.rolling_security_usd_cents[month as usize] =
            self.rolling_security_usd_cents[month as usize]
                .saturating_add(security_usd_cents);
    }

    /// Total of last 12 months.
    pub fn rolling_annual_usd_cents(&self) -> u64 {
        self.rolling_security_usd_cents.iter().sum()
    }

    /// Boost active if rolling annual < threshold.
    pub fn is_active(&self) -> bool {
        self.rolling_annual_usd_cents() < BOOST_THRESHOLD_USD_CENTS
    }
}
```

### 5.7 Integration with Price Oracle (PoBRS)

Boost trigger requires USD value, which requires a price oracle. We reuse PoBRS infrastructure (Sprint 1.5 — k-of-n BLS 7-of-12 bonded oracles).

```rust
// src/tokenomics/price_oracle.rs

use crate::pobrs::OracleAttestation;

/// Consume oracle attestation to convert BLOCH sats to USD cents.
/// 7-of-12 aggregation with deterministic fallback if quorum not reached.
pub fn entl_sats_to_usd_cents(
    sats: u64,
    attestation: &OracleAttestation,
) -> Result<u64, OracleError> {
    let price_usd_cents_per_bloch = attestation.aggregated_price_cents()?;

    // sats / 10^8 = BLOCH; BLOCH × price = USD cents
    let usd_cents = (sats as u128 * price_usd_cents_per_bloch as u128 / 100_000_000)
        .min(u64::MAX as u128) as u64;

    Ok(usd_cents)
}

#[derive(Debug)]
pub enum OracleError {
    NoQuorum,
    PriceOutOfRange,
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoQuorum => write!(f, "oracle quorum not reached"),
            Self::PriceOutOfRange => write!(f, "price out of expected range"),
        }
    }
}

impl std::error::Error for OracleError {}
```

### 5.8 Hook in consensus loop

```rust
// src/consensus/block_producer.rs (extension)

pub fn finalize_block(
    block: &Block,
    state: &mut ChainState,
) -> Result<BlockReceipt, ConsensusError> {
    // ... existing validation ...

    let height = block.header.height;
    let reward = tokenomics::reward::calculate_block_reward(height);
    let fees = block.total_fees();

    // Get oracle attestation for boost USD calc (PoBRS)
    let oracle_att = state.pobrs.latest_attestation()?;

    // Update boost state with previous block's security
    let prev_distribution = state.tokenomics.last_distribution.clone();
    let prev_security_usd = tokenomics::price_oracle::entl_sats_to_usd_cents(
        prev_distribution.miner_sats
            + prev_distribution.validator_pool_sats
            + prev_distribution.oracle_pool_sats,
        &oracle_att,
    )?;
    state.tokenomics.boost.update(prev_security_usd, height);

    // Distribute rewards and fees
    let dist = tokenomics::distribution::distribute(
        reward,
        fees,
        &mut state.tokenomics.endowment,
        &state.tokenomics.boost,
        height,
    );

    // Apply distribution
    state.balances.credit(block.miner_address, dist.miner_sats);
    state.validator_pool.credit(dist.validator_pool_sats);
    state.oracle_pool.credit(dist.oracle_pool_sats);

    state.tokenomics.last_distribution = dist.clone();
    state.tokenomics.endowment.last_block_height = height;

    Ok(BlockReceipt::new(block, dist))
}
```

## 6. Consequences

### 6.1 Positive

- **Empirically validated long-term sustainability.** ~50,000 Monte Carlo trajectories show that the model delivers a median security budget of $5.17M year 50 in the Median scenario, with 33.9% collapse risk.
- **Reasonable resilience to adverse conditions.** In Crypto Winter (7-year bear), the model retains operational security budget ($0.17M/year) — not ideal but does not collapse to zero.
- **Controlled inflation.** Cumulative +35% over 50 years = ~0.6% effective per year. Defensible regulatorily as "necessary for post-quantum security sustainability".
- **Endowment buffer grows naturally.** Median of 6M BLOCH by year 50, without need for governance or manual allocation.
- **Boost mode is genuinely useful.** Activates in ~34% of simulations year 50; not idle allocation.
- **Total auditability.** All rules are deterministic, on-chain computable, with no ML in consensus rules.
- **Compatible with ADR-005 (committee era).** FFG validators are compensated from day 1 via 25% emission share.
- **Oracle network funded sustainably.** 5% emission share + per-query fees (per ADR-018) eliminates dependency on grants or ad hoc funding.
- **No wallet/multisig dependency for endowment.** Pure consensus rule — anti-theft, anti-capture.

### 6.2 Negative

- **Partially breaks "finite supply" narrative.** Perpetual tail emission adds asymptotic inflation. Mitigation: communicate as "1B base + post-quantum security insurance tail" in whitepaper.
- **Sensitive to price collapse.** Adverse analysis shows that tokenomics alone does not defend against prolonged crypto winter — depends on exogenous demand.
- **Bootstrap of first 10 years requires external subsidy.** Median mining attractiveness of 0.68x at year 10 implies foundation must cover the gap via grants/listings/BD.
- **Higher complexity than pure M2.** Five modules (~600 LOC expected) vs ~150 LOC for pure tail. Audit cost ~30% higher.
- **Price oracle dependency.** Boost trigger requires functional PoBRS oracle attestation. Oracle failure = boost does not activate when it should.

### 6.3 Open Risks

- **R1.** Adversarial oracle can falsely trigger/suppress boost. Mitigation: PoBRS slashing + 7-of-12 threshold. Even so, oracle attack vector persists. Consider fallback: if oracle invalid, boost holds last known value for max 30 blocks, then deactivates for safety.
- **R2.** Crypto Winter can deplete endowment if prolonged >10 years. Mitigation: 50% boost cap preserves reserve. If chain enters prolonged winter post-emission, 25 BLOCH/block tail emission + endowment yield maintains minimum baseline, but insufficient vs real costs.
- **R3.** ~~1B arithmetic requires resolution of premine issue.~~ **RESOLVED by ADR-010-A:** 170M founder + 30M pool = 200M total premine; 800M mining = 1B total supply. Arithmetic now consistent.
- **R4.** Future hardfork to adjust parameters is a capture vector. Mitigation: `TAIL_REWARD_SATS` and `ENDOW_FEE_SHARE_BPS` are constants; change requires explicit hardfork with broad social governance.
- **R5.** Model has never been tested in production. Closest prior art is Monero (tail) + Decred (treasury), neither exactly this. Risk of discovering issue only post-mainnet.

## 7. Implementation Plan

### Sprint 2.2 — Final calibration and unit tests (2026-05-15 to 2026-06-15)

- [ ] Re-run final Monte Carlo with consolidated parameters of this ADR (regression validation).
- [ ] Implement `src/tokenomics/types.rs` with all constants.
- [ ] Implement `src/tokenomics/reward.rs` + 10+ unit tests.
- [ ] Implement `src/tokenomics/endowment.rs` with `EndowmentState`.
- [ ] Property tests via `proptest`: invariants (balance never negative, total_deposited monotonic, etc.).

### Sprint 2.3 — Distribution and Boost (2026-06-15 to 2026-07-15)

- [ ] Implement `src/tokenomics/boost.rs` with rolling buffer.
- [ ] Implement `src/tokenomics/distribution.rs` with `distribute()` (70/25/5 split).
- [ ] Integration with `src/consensus/block_producer.rs::finalize_block`.
- [ ] End-to-end tests: simulate 1000 blocks with varied fees, validate distribution.

### Sprint 2.4 — Oracle and internal audit (2026-07-15 to 2026-08-15)

- [ ] Implement `src/tokenomics/price_oracle.rs` integrated with PoBRS.
- [ ] Adversarial tests: oracle reporting invalid price, no quorum, etc.
- [ ] Internal code review + coverage metrics (target: 95%+).
- [ ] Tokenomics dashboard on devnet (endowment balance, boost active, etc.).

### Sprint 2.5 — Pre-mainnet (2026-08-15 to 2026-09-15)

- [ ] External audit specific to tokenomics (NCC or ToB; budget ~$80k).
- [ ] Whitepaper update with calibrated tokenomics section.
- [ ] Stress tests on devnet with simulated scenarios (compressed Crypto Winter).
- [ ] Final freeze of constants for genesis.

## 8. Post-Mainnet Validation Metrics

The decision will be considered validated if, in the first 24 months post-mainnet:

| Metric | Target | Revision threshold |
|--------|--------|--------------------|
| Average hashrate | Quarter-over-quarter growth | Stagnation for 2+ quarters |
| Endowment balance | Growing | Sustained drainage (>50% loss in 6 months) |
| Boost activations | < 5% of epochs | > 25% sustained = revise threshold |
| Realized annual inflation | ~ curve baseline | Deviation > 20% |
| Validator participation | > 90% per epoch | < 70% sustained |
| Mining attractiveness (USD) | Growing trend in 12m | Sustained decreasing |

If 2+ metrics fall outside thresholds for 6+ months, open ADR for parameter revision (not this ADR — a new one).

## 9. Future Work / Dependent ADRs

- **ADR-010-A** — ✅ **RESOLVED.** Founder premine: 17%/30y vesting (170M BLOCH).
- **ADR-010-Addendum-1** — ✅ **RESOLVED.** Distribution split 70/25/5 including oracle pool.
- **ADR-011** — Founder vesting via consensus rules: cliff 12m + linear 348m implemented as on-chain transaction restriction. FFG activation block height also defined here.
- **ADR-012** — Validator+oracle pool distribution of 30M BLOCH: governance, unlock schedule, eligibility.
- **ADR-013** — Tokenomics hardfork governance: who can propose constant changes; threshold; process.
- **ADR-014** — Burn mechanisms (optional v1.5+): possible addition of EIP-1559-style fee burn for deflation pressure during high-usage periods.
- **ADR-018** — ✅ **RESOLVED.** Oracle Network specification.

## 10. Empirical Validation — Cross-References

This ADR is grounded in ~50,000 Monte Carlo trajectories documented in four analytical PDFs:

- `BLOCH_Tokenomics_MonteCarlo.pdf` — initial comparison of 4 models (1,000 paths).
- `BLOCH_Hybrid_MonteCarlo.pdf` — hybrid calibration + 3×3 sensitivity + stress tests (~36,000 paths).
- `BLOCH_Scenarios_MonteCarlo.pdf` — conditional analysis 3 scenarios × 3 models (9,000 paths).
- `BLOCH_Adverse_Scenarios.pdf` — addition of Crypto Winter + Black Swan (15,000 paths).

Simulation source code:
- `simulation.py` — initial 4-model comparison.
- `sim_hybrid.py` — calibration + sensitivity + stress.
- `sim_scenarios.py` — scenarios × models.
- `sim_adverse.py` — systemic adverse.

Reproducible with `numpy` 1.26+, `matplotlib` 3.8+, seed=42.

## 11. External References

- Carlsten, Kalodner, Weinberg, Narayanan (2016) — *On the Instability of Bitcoin Without the Block Reward*. Demonstrates that fee-only is unstable.
- Buterin (2022) — *Endgame*. Argues for minimum viable issuance.
- Lewis-Pye, Roughgarden (2023) — *Permissionless Consensus*. Sustainability conditions.
- Decker, Wattenhofer (2013) — *Information Propagation in the Bitcoin Network*. Orphan rate model (referenced in ADR-006).
- Monero CCS — Tail emission proposal (2018). Closest prior art for tail floor.
- Decred whitepaper (2016) — Treasury model. Prior art for endowment governance.
- Norway Government Pension Fund — Annual reports. Macro analog for endowment endurance.
- BLOCH Sprint 2.1 architectural decision document (2026-04-29) — FFG context.

## 12. Required Approvals

This ADR requires approval before Sprint 2.2 begins:

- [ ] **BLOCH Core** — author and primary maintainer.
- [ ] **External auditor (proposed: NCC or ToB)** — pre-implementation review.
- [ ] **Legal counsel (US securities + EU MiCA)** — regulatory defensibility of parameters.
- [ ] **Whitepaper team** — alignment with public narrative.

---

## Revision History

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-04-29 | Initial draft based on ~50k Monte Carlo trajectories. |
| 1.0 | 2026-04-29 | rev1: Distribution split updated to 70/25/5 (Addendum-1); premine arithmetic resolved (ADR-010-A); cross-references to ADR-018 added. Translated to English (BLOCH convention). |
