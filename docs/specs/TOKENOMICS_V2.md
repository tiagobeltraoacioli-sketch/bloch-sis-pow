# BLOCH Tokenomics V2 — Specification

**Status:** Genesis-locked, pre-commitment doctrine — supersedes V1
**Version:** 2.0
**Date:** 2026-05-01
**Author:** BLOCH Founder
**Supersedes:** `docs/specs/historical/TOKENOMICS_V1_SUPERSEDED.md`
**Related ADRs:** ADR-006 (Block time + dual finality), ADR-010 (Tokenomics), ADR-010-A (Founder premine), ADR-010-Addendum-1 (Oracle pool), ADR-018 (Oracle network), ADR-028 (V1 → V2 transition)

> *"Tudo o que pode ser parametrizado por governance pode ser corrompido por governance."*
>
> — Doutrina BLOCH, *Ensaio 2 — Pre-Commitment Doctrine*

---

## 1. Preamble

This document specifies the complete economic model of the Bloch-SIS Protocol (BLOCH) blockchain. Every parameter herein is **genesis-locked** — meaning the values are compiled into the Rust source code as `pub const` constants, become consensus rules at genesis block production, and can only be changed by hard fork. There is no on-chain governance mechanism that can alter these parameters. There is no voting. There is no DAO.

V2 supersedes V1 (preserved as `docs/specs/historical/TOKENOMICS_V1_SUPERSEDED.md`). The reason for the V1 → V2 transition is documented in ADR-028. Briefly: V1 specified a 4% founder premine without on-chain vesting, with a 93/5/2 reward split and 10-second block time. V2 aligns the spec with the architecturally-decided model in ADRs 006, 010, 010-A, and 010-Addendum-1: 17% founder premine with on-chain vesting (10-year lock + 40-year linear, per ADR-033 §8), 70/25/5 reward split, and 150-second block time.

The numbers in this document are not proposals. They are commitments.

---

## 2. Total Supply

```
MINING_EMISSION_NOMINAL  =   800,000,000 BLOCH  (target Σ subsidy as halvings → 0)
MINING_EMISSION_ACTUAL   =   798,630,000 BLOCH  (sum after integer truncation, +tail forever)
FOUNDER_PREMINE          =   170,000,000 BLOCH  (17% of 1,000,000,000 nominal supply)
VALIDATOR_ORACLE_POOL    =    30,000,000 BLOCH  (3% of 1,000,000,000 nominal supply)
NOMINAL_TOTAL_SUPPLY     = 1,000,000,000 BLOCH  (founder + pool + mining nominal)
DECIMALS                 = 8
ATOMIC_UNIT              = 1 BLOCH × 10⁻⁸ = 1 satoshi
```

The **nominal** total supply of 1B BLOCH is the genesis design target. The **actual** supply at any block height is:

```
actual_supply(h) = founder_vested(h) + pool_distributed(h) + mining_emitted(h) + tail_emitted(h)
```

Where:
- `founder_vested(h)`: cumulative founder premine vested per §6 (caps at 170M after block 10,368,000; ADR-033 §8)
- `pool_distributed(h)`: cumulative validator/oracle pool distribution (mechanism in ADR-012, separate document)
- `mining_emitted(h)`: cumulative subsidy emitted per §3 + §4 (caps at ~798.63M after halving 11)
- `tail_emitted(h)`: cumulative tail emission per §3.4 (grows perpetually at 25 BLOCH/block after halving 7)

After ~10 years of mainnet (the geometric phase), `actual_supply ≈ 970M`. After 100 years, supply approaches 1.32B (geometric phase + 95 years of tail @ 25 BLOCH/block).

The 1.37M BLOCH gap between `MINING_EMISSION_NOMINAL` (800M) and `MINING_EMISSION_ACTUAL` (798.63M) is an unavoidable rounding consequence of integer-shift halving from a non-power-of-two initial reward. The alternative — fractional BLOCH block rewards — would introduce floating-point determinism risks across heterogeneous node implementations and is rejected on consensus-safety grounds.

---

## 3. Block Subsidy

### 3.1 Geometric phase

```
INITIAL_BLOCK_REWARD    = 1,905 BLOCH per block
HALVING_INTERVAL        = 210,000 blocks
TARGET_BLOCK_TIME       = 150 seconds
EMISSION_CURVE          = geometric (each halving cuts reward in half via integer shift)
```

The geometric phase emits subsidy as follows. With block time of 150s, one halving interval of 210,000 blocks corresponds to approximately 365.0 days (210,000 × 150 / 86,400 ≈ 364.58 days; in practice slightly more due to PoW variance).

Per-halving emission:

| Halving | Reward (BLOCH/block) | Block range | Emitted | Cumulative | Approx. age |
|---:|---:|---:|---:|---:|---:|
| 0 | 1905 | 0 – 209,999 | 400,050,000 | 400,050,000 | year 0 |
| 1 | 952 | 210,000 – 419,999 | 199,920,000 | 599,970,000 | year 1 |
| 2 | 476 | 420,000 – 629,999 | 99,960,000 | 699,930,000 | year 2 |
| 3 | 238 | 630,000 – 839,999 | 49,980,000 | 749,910,000 | year 3 |
| 4 | 119 | 840,000 – 1,049,999 | 24,990,000 | 774,900,000 | year 4 |
| 5 | 59 | 1,050,000 – 1,259,999 | 12,390,000 | 787,290,000 | year 5 |
| 6 | 29 | 1,260,000 – 1,469,999 | 6,090,000 | 793,380,000 | year 6 |
| 7 | 14 → 25 (tail) | 1,470,000 – ... | (see §3.4) | (see §3.4) | year 7+ |

### 3.2 Reward computation

```rust
fn block_subsidy(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let geometric = if halvings >= 64 {
        0
    } else {
        INITIAL_BLOCK_REWARD_SAT >> halvings  // integer shift
    };
    if geometric < TAIL_FLOOR_SAT {
        TAIL_FLOOR_SAT
    } else {
        geometric
    }
}
```

### 3.3 Halving boundary

The halving boundary applies to the block at the *new* halving height. Block 210,000 is the first block of halving 1, paying 952 BLOCH. Block 209,999 is the last block of halving 0, paying 1905 BLOCH.

### 3.4 Tail floor

```
TAIL_FLOOR              = 25 BLOCH per block (perpetual)
TAIL_ACTIVATION_HALVING = 7
TAIL_ACTIVATION_HEIGHT  = 1,470,000 (= 7 × HALVING_INTERVAL, approx. year 7)
```

When the geometric subsidy `INITIAL_BLOCK_REWARD >> halvings` would fall below the tail floor (which happens at halving 7, where 1905 >> 7 = 14 < 25), the actual reward becomes the tail floor. This is consensus-binding: nodes that compute geometric-only reward at heights ≥ 1,470,000 will diverge from the chain.

Tail emission rate: 25 BLOCH × (31,536,000 / 150) = **5,256,000 BLOCH/year**.

Note: ADR-010 §3.5 quotes "asymptotic inflation ~0.05%/year". The actual tail-driven inflation rate against the 1B nominal supply is approximately 0.526%/year (5.256M / 1B). The ADR-010 figure appears to contain an order-of-magnitude error or assumes a different supply baseline; V2 uses the math above directly.

The tail floor exists for security-budget reasons. Without tail emission, post-geometric-phase block rewards drop to 0 and miner economics depend entirely on transaction fees. Monte Carlo trajectories in `BLOCH_Tokenomics_MonteCarlo.pdf` showed tail-floor models produce significantly more robust security budgets in adverse scenarios (ADR-010 §3.5 M5 selection rationale).

---

## 4. Block Reward Split (CONSENSUS RULE)

```
MINER_SHARE_BPS        = 7,000  (70%)
VALIDATOR_SHARE_BPS    = 2,500  (25%)
ORACLE_SHARE_BPS       =   500  (5%)
TOTAL_BPS              = 10,000 (100%)
```

Every block subsidy is split deterministically across three parties:

```rust
fn split_subsidy(subsidy: u64) -> (u64, u64, u64) {
    let miner    = subsidy * MINER_SHARE_BPS     / 10_000;
    let validator = subsidy * VALIDATOR_SHARE_BPS / 10_000;
    let oracle   = subsidy * ORACLE_SHARE_BPS    / 10_000;
    // Rounding: any sub-satoshi remainder goes to miner (smallest share + most-deserving)
    let assigned = miner + validator + oracle;
    (miner + (subsidy - assigned), validator, oracle)
}
```

This split is enforced by `accept_block` consensus validation. Coinbase transactions that violate the split — by under-paying validators or oracles, or over-paying miner — are rejected.

### 4.1 Recipient addresses

- **Miner output:** the bech32 address that authorized the SV1/SV2 mining session that submitted the winning block.
- **Validator output:** a fixed protocol-controlled address per ADR-007 (validator pool). The pool distributes to active validators per ADR-005 era + Phragmén selection.
- **Oracle output:** a fixed protocol-controlled address per ADR-018 (oracle pool). The pool distributes to active oracles per ADR-018 §6 (PoBRS rebate mechanism).

### 4.2 Fees

Transaction fees are split identically:

```
ENDOW_FEE_SHARE_BPS    = 1,000  (10% to endowment buffer)
REMAINING_FEE_PCT      = 9,000  (90% to participants)
  ├─ MINER_SHARE_BPS     = 7,000 (70%)
  ├─ VALIDATOR_SHARE_BPS = 2,500 (25%)
  └─ ORACLE_SHARE_BPS    =   500 (5%)
```

### 4.3 Outbound query fees (oracle network)

When an oracle submits an outbound query per ADR-018, the fee paid by the oracle is split:

```
OUTBOUND_QUERY_BURN_BPS         = 5,000  (50% — burned)
OUTBOUND_QUERY_ENDOW_BPS        = 3,000  (30% — endowment buffer)
OUTBOUND_QUERY_ORACLE_REBATE_BPS = 2,000 (20% — pro-rata to active oracles)
```

---

## 5. Founder Premine Vesting (CONSENSUS RULE)

The founder premine is allocated 170,000,000 BLOCH at genesis but **not** liquid at genesis. Vesting is enforced by consensus per ADR-010-A.

### 5.1 Schedule

```
FOUNDER_PREMINE_TOTAL_SAT  = 17,000,000,000,000,000   (170M BLOCH × 10⁸)
FOUNDER_VESTING_CLIFF      = 207,260 blocks (~12 months @ 150s/block, founder-specified)
FOUNDER_VESTING_LINEAR     = 6,013,440 blocks (~348 months = 28.6 years)
FOUNDER_VESTING_END        = 6,220,700 blocks (= cliff + linear, ~29.6 years total)
```

> **Cliff number — founder-specified.** The founder selected 207,260 blocks for the cliff. This corresponds to approximately 359.83 days at 150s block time (≈11.99 calendar months of 30 days each). Mathematically clean alternatives would be 207,360 blocks (exactly 12 × 30 days = 360 days) or 210,384 blocks (exactly 12 solar months = 365.25 days). The founder's choice of 207,260 is honored as a constitutional commitment per the pre-commitment doctrine (§1).

### 5.2 Vesting math

Per-block vesting after cliff:

```
PER_BLOCK_VESTING_SAT = FOUNDER_PREMINE_TOTAL_SAT / FOUNDER_VESTING_LINEAR
                      = 17,000,000,000,000,000 / 6,013,440
                      = 2,827,000,851 sat per block
                      ≈ 28.27 BLOCH per block
```

Truncation loss across all 6,013,440 vesting blocks: 2,562,560 sat ≈ 0.026 BLOCH (rounding artifact, retained by chain — does not change consensus rule).

Total vested at height `h`:

```rust
fn founder_vested_amount_sat(h: u64) -> u64 {
    if h < FOUNDER_VESTING_CLIFF {
        0  // cliff period, nothing vested
    } else if h >= FOUNDER_VESTING_END {
        FOUNDER_PREMINE_TOTAL_SAT  // fully vested
    } else {
        let blocks_post_cliff = h - FOUNDER_VESTING_CLIFF;
        FOUNDER_PREMINE_TOTAL_SAT * blocks_post_cliff / FOUNDER_VESTING_LINEAR
    }
}
```

### 5.3 Vesting payout mechanism

Founder vesting is paid out via a **per-block coinbase output**: every coinbase transaction at height `h ≥ FOUNDER_VESTING_CLIFF` includes an additional output paying `founder_vested_amount_sat(h) - founder_vested_amount_sat(h-1)` to the founder address.

The founder address is genesis-locked at the constant `FOUNDER_ADDRESS_HASH` (20-byte hash, ML-DSA-65 keystore stored 3-2-1 per memory entry of 2026-04-26). Coinbase transactions that omit, under-pay, or mis-address this output are rejected by `accept_block`.

This produces approximately 6,013,440 founder vesting outputs over 28.6 linear years. Each output is small (~28.27 BLOCH) but on-chain auditable. Operators can verify the cumulative founder vesting at any height matches the schedule by summing the outputs to `FOUNDER_ADDRESS_HASH`.

### 5.4 Genesis handling

The founder allocation is **not** minted at genesis. Genesis block contains 0 BLOCH to the founder. Vesting begins at block 207,260 and proceeds linearly until block 6,220,700. This differs from V1 which minted the entire 4% premine at genesis as a single coinbase output.

---

## 6. Validator/Oracle Pool

```
VALIDATOR_ORACLE_POOL_TOTAL_SAT = 3,000,000,000,000,000  (30M BLOCH × 10⁸)
```

The 30M BLOCH pool allocation is reserved for validator and oracle incentive distribution per ADR-012 (pending design — distribution mechanism within the pool is not specified by V2 tokenomics).

V2 tokenomics specifies only the existence and amount of this pool. Distribution mechanism is consensus-binding once ADR-012 lands.

---

## 7. Constants Block (Rust)

```rust
//! src/core/tokenomics_v2.rs — V2 tokenomics constants
//!
//! Per docs/specs/TOKENOMICS_V2.md
//! Genesis-locked. Mutation requires hard fork.

// ── Total supply ─────────────────────────────────────────────────────
pub const NOMINAL_TOTAL_SUPPLY:        u64 = 1_000_000_000 * 100_000_000;
pub const FOUNDER_PREMINE_TOTAL_SAT:   u64 =   170_000_000 * 100_000_000;
pub const VALIDATOR_ORACLE_POOL_SAT:   u64 =    30_000_000 * 100_000_000;
pub const MINING_EMISSION_NOMINAL_SAT: u64 =   800_000_000 * 100_000_000;

// ── Emission curve ───────────────────────────────────────────────────
pub const INITIAL_BLOCK_REWARD_SAT: u64 = 1_905 * 100_000_000;
pub const HALVING_INTERVAL:         u64 = 210_000;
pub const TAIL_FLOOR_SAT:           u64 =    25 * 100_000_000;
pub const TARGET_BLOCK_TIME_SECS:   u64 = 150;

// ── Reward split (basis points; sum = 10000) ─────────────────────────
pub const MINER_SHARE_BPS:     u64 = 7_000;  // 70%
pub const VALIDATOR_SHARE_BPS: u64 = 2_500;  // 25%
pub const ORACLE_SHARE_BPS:    u64 =   500;  //  5%

// ── Fee distribution ─────────────────────────────────────────────────
pub const ENDOW_FEE_SHARE_BPS: u64 = 1_000;  // 10% of fees → endowment

// ── Outbound query fee distribution (oracle network) ─────────────────
pub const OUTBOUND_QUERY_BURN_BPS:           u64 = 5_000;  // 50%
pub const OUTBOUND_QUERY_ENDOW_BPS:          u64 = 3_000;  // 30%
pub const OUTBOUND_QUERY_ORACLE_REBATE_BPS:  u64 = 2_000;  // 20%

// ── Founder vesting (schedule amended by ADR-033 §8) ─────────────────
// 10-year full lock (cliff), then 40-year linear release. 50-yr horizon.
pub const FOUNDER_VESTING_CLIFF:       u64 = 2_073_600;  // 10 yr locked (120 × 30 days @ 150s)
pub const FOUNDER_VESTING_LINEAR:      u64 = 8_294_400;  // 40 yr linear (480 × 30 days @ 150s)
pub const FOUNDER_VESTING_END:         u64 = 10_368_000; // = cliff + linear

// ── Other (unchanged from V1) ────────────────────────────────────────
pub const COINBASE_MATURITY:   u64 = 100;
pub const MAX_BLOCK_SIZE:      usize = 1_000_000;
pub const DUST_THRESHOLD:      u64 = 546;
pub const MAX_FUTURE_SECS:     u64 = 7_200;

// ── Difficulty (recalibrated for 150s block time) ────────────────────
pub const DIFFICULTY_WINDOW:   u64 = 2_016;  // unchanged; means 2016 × 150s = 84h retarget
pub const MAX_RETARGET_FACTOR: u64 = 4;

// ── Founder address (genesis-locked) ─────────────────────────────────
// Hash of the founder ML-DSA-65 public key, stored 3-2-1 backed up.
// This MUST be set before genesis ceremony; setting after genesis = hard fork.
pub const FOUNDER_ADDRESS_HASH: [u8; 20] = [0u8; 20]; // PLACEHOLDER — set at genesis
```

---

## 8. Consensus enforcement

The following are CONSENSUS RULES as of the V2 activation block (genesis block or designated hard-fork height):

1. **Subsidy** — every block coinbase pays `block_subsidy(height)` total across miner, validator, oracle outputs (§3, §4).
2. **Split** — split satisfies `MINER_SHARE_BPS / VALIDATOR_SHARE_BPS / ORACLE_SHARE_BPS = 7000 / 2500 / 500` exactly.
3. **Recipients** — miner output to authorized session address; validator output to validator pool address (ADR-007); oracle output to oracle pool address (ADR-018).
4. **Founder vesting** — coinbase at height `h ∈ [2073600, 10368000)` includes additional output to `FOUNDER_ADDRESS_HASH` paying the per-block delta (10-yr cliff + 40-yr linear; ADR-033 §8).
5. **Tail floor** — at heights `h ≥ 1470000`, subsidy is at least `TAIL_FLOOR_SAT`.
6. **Total supply check** — at any height, summed supply across all coinbase outputs ≤ `actual_supply(h)` per §2.

Violation of any consensus rule causes the block to be rejected by `accept_block` and not propagated by P2P.

---

## 9. Migration from V1

This document supersedes V1 (`docs/specs/historical/TOKENOMICS_V1_SUPERSEDED.md`). Migration is documented in:

- `docs/MIGRATION-TOKENOMICS-V1-TO-V2.md` (engineering checklist)
- `docs/adr/ADR-028-tokenomics-v2-activation.md` (architectural decision record)

**No backward compatibility is required** because mainnet has not activated. V1 was specified but not deployed; V2 is the actual genesis configuration. Test networks running V1 will be torn down before V2 mainnet activation.

---

## 10. Outstanding questions for ADR-010 reconciliation

The following discrepancies between ADR-010 and this V2 spec require resolution before mainnet activation. They do not block V2 implementation but should be addressed in a future ADR-010 revision (rev2):

1. **Asymptotic inflation rate** — ADR-010 §3.5 says "~0.05%/year", actual math is 0.526%/year (§3.4 of this spec). Possibly an order-of-magnitude typo or different baseline assumption in ADR-010.
2. **Endowment buffer mechanism** — ADR-010 §3.5 mentions "endowment buffer (10% of fees)" and "emergency boost mode" but specific contract code and accounting are not yet implemented. ADR-010 should be revised with concrete state schema and activation criteria, or those features deferred to ADR-010-B.
3. **Validator pool distribution** — ADR-012 (validator/oracle pool internal distribution) is marked "pending" in ADR-010 §1. V2 specifies the existence of the 30M pool but not how it distributes to individual validators/oracles. This is a Sprint 11+ deliverable.

---

## 11. Document control

- **Version:** 2.0 — initial
- **Date:** 2026-05-01
- **Owner:** Founder (custodial) until Phase 3, Foundation thereafter (ADR-023, 026)
- **License:** Same as repository
- **Cross-references:** ROADMAP.md (must be updated to reflect V2 numbers), ADRs 006/010/010-A/010-Add-1/018/028
