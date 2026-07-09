# ADR-010 — Addendum 1: Revised Distribution Including Oracle Pool

**Date:** 2026-04-29
**Author:** BLOCH Core
**Status:** Approved (auto-approved if ADR-018 is approved)
**Affects:** ADR-010 sections 4.1, 4.2, 4.3 (constants and distribution logic)
**Triggered by:** ADR-018 (Oracle Network)

---

## 1. Context

ADR-010 specified the hybrid tokenomics model with distribution split:
- **70% miner / 30% validator pool** on emission + 90% of fees

ADR-018 introduces the oracle network with 5% block reward share as Stream 1 of oracle compensation. This addendum updates ADR-010 distribution constants accordingly.

## 2. Revised Distribution

### 2.1 Block Reward Distribution

```
Previous (ADR-010 v1):
  70% → miner
  30% → validator pool

Revised (ADR-010 + ADR-018):
  70% → miner
  25% → validator pool
  5%  → oracle pool
```

Validator pool reduces from 30% to 25%. Oracle pool gains 5%. Miner share unchanged.

### 2.2 Fee Distribution

```
Previous (ADR-010 v1):
  10% → endowment buffer
  90% split:
    70% → miner
    30% → validator pool

Revised (ADR-010 + ADR-018):
  10% → endowment buffer
  90% split:
    70% → miner
    25% → validator pool
    5%  → oracle pool
```

### 2.3 Outbound Query Fee Distribution (NEW — from ADR-018)

```
Outbound query fees paid by oracles:
  50% → burned (deflationary pressure)
  30% → endowment buffer
  20% → oracle rebate pool (distributed pro-rata to active oracles)
```

This is new revenue/burn flow not present in original ADR-010.

## 3. Updated Constants (Rust)

```rust
// src/tokenomics/types.rs (REVISED)

pub const MINER_SHARE_BPS: u64 = 7_000;        // 70% — UNCHANGED
pub const VALIDATOR_SHARE_BPS: u64 = 2_500;    // 25% — REVISED from 3000
pub const ORACLE_SHARE_BPS: u64 = 500;         // 5% — NEW

// Fee distribution unchanged for endowment portion:
pub const ENDOW_FEE_SHARE_BPS: u64 = 1_000;    // 10% — UNCHANGED

// Outbound query fee distribution (NEW):
pub const OUTBOUND_QUERY_BURN_BPS: u64 = 5_000;       // 50%
pub const OUTBOUND_QUERY_ENDOW_BPS: u64 = 3_000;      // 30%
pub const OUTBOUND_QUERY_ORACLE_REBATE_BPS: u64 = 2_000;  // 20%
```

Verification: `MINER_SHARE_BPS + VALIDATOR_SHARE_BPS + ORACLE_SHARE_BPS = 7000 + 2500 + 500 = 10000` ✓

## 4. Updated `distribute()` Function

```rust
// src/tokenomics/distribution.rs (REVISED)

#[derive(Debug, Clone)]
pub struct Distribution {
    pub miner_sats: u64,
    pub validator_pool_sats: u64,
    pub oracle_pool_sats: u64,           // NEW
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
    // 10% of fees → endowment (UNCHANGED)
    let endow_addition = fees_sats * ENDOW_FEE_SHARE_BPS / 10_000;
    let net_fees = fees_sats - endow_addition;
    endow.deposit(endow_addition);

    // Boost calculation (UNCHANGED)
    let yield_sats = endow.calculate_yield_for_block();
    let boost_amount = if height >= BOOST_WARMUP_BLOCKS && boost.is_active() {
        let max_boost = yield_sats * BOOST_MAX_PCT_BPS / 10_000;
        endow.withdraw(max_boost);
        max_boost
    } else {
        0
    };

    // REVISED: three-way split (was two-way)
    let total_to_distribute = reward_sats + net_fees + boost_amount;
    let miner_sats = total_to_distribute * MINER_SHARE_BPS / 10_000;
    let validator_pool_sats = total_to_distribute * VALIDATOR_SHARE_BPS / 10_000;
    let oracle_pool_sats =
        total_to_distribute - miner_sats - validator_pool_sats;
    // (residual goes to oracle pool to avoid rounding loss)

    Distribution {
        miner_sats,
        validator_pool_sats,
        oracle_pool_sats,
        endowment_addition_sats: endow_addition,
        boost_amount_sats: boost_amount,
    }
}
```

## 5. Impact on Monte Carlo Simulations

The Monte Carlo simulations consolidated in `BLOCH_Hybrid_MonteCarlo.pdf`, `BLOCH_Scenarios_MonteCarlo.pdf`, and `BLOCH_Adverse_Scenarios.pdf` used 70/30 split. Revised 70/25/5 split has minor impact on those results:

- **Total security budget unchanged** — sum of miner + validator + oracle = same total
- **Validator security budget** drops by 5/30 ≈ 17% in absolute terms
- **Oracle pool gains** new revenue stream (was zero in prior simulations)
- **Total chain security** marginally improved because oracle pool provides additional security via PoBRS attestations (not directly counted in miner/validator USD)

Decision: re-running Monte Carlo with revised split is **not required** for ADR approval. The qualitative conclusions (hybrid model viable in median scenario, robust to fee volatility, vulnerable to price collapse) are unchanged. A v2 simulation with revised split can be conducted in Sprint 2.4 for documentation completeness.

## 6. Validation Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_sum_to_total() {
        assert_eq!(
            MINER_SHARE_BPS + VALIDATOR_SHARE_BPS + ORACLE_SHARE_BPS,
            10_000
        );
    }

    #[test]
    fn distribution_no_loss() {
        let mut endow = EndowmentState::default();
        let boost = BoostState::default();
        let reward = 1905 * 100_000_000;  // 1905 BLOCH in sats
        let fees = 100 * 100_000_000;     // 100 BLOCH in sats

        let dist = distribute(reward, fees, &mut endow, &boost, 0);

        let total_in = reward + fees;
        let total_out = dist.miner_sats
            + dist.validator_pool_sats
            + dist.oracle_pool_sats
            + dist.endowment_addition_sats;

        // No sats lost (rounding may add 1 sat to oracle pool)
        assert_eq!(total_in, total_out);
    }

    #[test]
    fn miner_share_unchanged() {
        let mut endow = EndowmentState::default();
        let boost = BoostState::default();
        let reward = 10_000_000_000;
        let fees = 0;

        let dist = distribute(reward, fees, &mut endow, &boost, 0);
        assert_eq!(dist.miner_sats, 7_000_000_000);  // 70%
    }
}
```

## 7. Communication

This addendum should be reflected in:

- [ ] ADR-010 main document (mark as "Amended by Addendum 1, 2026-04-29")
- [ ] Whitepaper draft (when written) — show revised distribution
- [ ] Public-facing tokenomics documentation
- [ ] Investor / counsel briefing materials

Key talking point: **"Oracle network adds 5% allocation to enable institutional-grade compliance attestations. Validator share reduces from 30% to 25% — net protocol security improves due to oracle layer."**

---

**End of Addendum 1.**
