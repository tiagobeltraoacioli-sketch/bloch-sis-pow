# ADR-006: Block Time and Dual Finality Exposure (Soft/Hard)

**Sprint:** 2.2 (calibration) / 2.3 (RPC)
**Status:** Proposed (revision 1 — 2 adjustments applied, ready for commit pre-2026-05-15)
**Date:** 2026-04-29 (rev1 same day)
**Author:** BLOCH Core
**Related:** ADR-001 (FFG epoch=6), ADR-005 (committee era)

**Changelog rev1 (2026-04-29):**
1. §4.2 — `FinalityStatus` gains `epoch: u64` field (which FFG epoch the block belongs to). Useful for integrators on cross-era queries.
2. §4.4 — Orphan rate criterion extended with `p99 reorg depth ≤ 1 block` over a 7-day window (more sensitive than mean orphan rate; captures heavy propagation tails).

---

## 1. Context

ADR-001 established FFG epoch = 6 blocks and Casper-style finality at 2 epochs (justified → finalized). With Bitcoin-style block time (10 min), this yields finality ~2h. Conservative review (3 epochs for margin) leads to ~3h perceived.

For BLOCH to compete with Cosmos (~6s), Polkadot (~12-60s), Sui (~3s) while still preserving PoW + post-quantum FFG as the base, both factors composing finality must be addressed:

```
finality_time = epochs_to_finalize × blocks_per_epoch × block_time
```

ADR-001 fixed `epochs_to_finalize = 2` and `blocks_per_epoch = 6`. What remains is calibrating `block_time` and exposing intermediate confidence levels.

The comparative analysis of BFT models (Sprint 2.1 document, 2026-04-29) identified five possible levers:

| # | Lever | Status v1 |
|---|-------|-----------|
| 1 | Reduce `block_time` (10min → 2-3min) | **ADOPT** |
| 2 | Reduce `blocks_per_epoch` (6 → 3) | Defer to v1.5+ |
| 3 | Experimental Single-Slot Finality | Defer to v2+ (paper) |
| 4 | HotStuff pipeline | **REJECT** (FFG sunk cost) |
| 5 | Expose soft/hard finality in RPC | **ADOPT** |

This ADR formalizes Levers 1 and 5.

## 2. Decision Drivers

- **D1.** Finality ~2h is uncomfortable for RWA, exchange, and bridge use cases; competitors deliver < 1 min.
- **D2.** PoW block time is a fundamental parameter; changing it post-mainnet requires hardfork — calibrate now.
- **D3.** Orphan rate grows with reduced block time; safety margin must be preserved.
- **D4.** Mining decentralization suffers with very short block times (advantage to pools with low network latency).
- **D5.** Soft finality = supermajority reached = 95%+ probability of hard finalization. Useful for the majority of UX use cases.
- **D6.** Soft/hard exposure is technically free — the state already exists in `CommitteeRegistry`, only the API is missing.
- **D7.** Calibration requires realistic network simulation; `bloch-calibrate` (existing binary) is the indicated tool.

## 3. Considered Options

### 3.1 Block time

| Option | Block time | Hard finality (2 epochs × 6 blocks) | Expected orphan rate | Assessment |
|--------|-----------|-------------------------------------|----------------------|------------|
| A1 | 10 min (Bitcoin-style) | ~2 h | < 0.5% | ADR-001 default; too slow |
| A2 | 5 min | ~1 h | < 1% | Marginal improvement |
| **A3** | **2.5 min** | **~30 min** | **~1.5%** | **Sweet spot** |
| A4 | 1 min (Litecoin-style) | ~12 min | ~3-4% | Mining centralization risk |
| A5 | 15 s (Kaspa DAG) | ~3 min | N/A (DAG) | Incompatible with linear chain |
| A6 | 400 ms (Solana) | N/A | N/A | Infeasible for PoW |

### 3.2 Finality model exposed in RPC

| Option | Exposed states | Assessment |
|--------|----------------|------------|
| B1 | Hard only (1 state) | Simple, but users must wait 30+ min |
| **B2** | **Soft + hard (2 states)** | **Solana/Polygon standard; adequate UX** |
| B3 | Probabilistic confirmations (Bitcoin-style) | Of little value in BFT model |
| B4 | 4+ states (proposed/justified/soft-final/hard-final) | Unnecessary complexity |

### 3.3 Soft finality criterion

| Option | Criterion | Latency | Guarantee |
|--------|-----------|---------|-----------|
| C1 | Block included (PoW only) | ~2.5 min | PoW reorgs common |
| **C2** | **1 FFG epoch (justified)** | **~15 min** | **14-of-21 supermajority reached** |
| C3 | 1.5 epochs (custom) | ~22 min | No clear benefit vs. C2 |

### 3.4 Hard finality criterion

| Option | Criterion | Latency | Guarantee |
|--------|-----------|---------|-----------|
| **D1** | **2 FFG epochs (finalized)** | **~30 min** | **Full Casper FFG (ADR-001)** |
| D2 | 3 epochs (conservative) | ~45 min | Extra margin; worse UX |

## 4. Decision Outcome

**Consolidated decision:** A3 + B2 + C2 + D1.

Formal calibration of block time = **150 seconds (2.5 min)** as target. Validation via `bloch-calibrate` on testnet with simulated network latency p95 = 3s. Accept up to `[120s, 180s]` if simulations reveal pressure from orphan rate.

### 4.1 Constants (in `src/consensus/types.rs`)

```rust
use std::time::Duration;

/// Target time between PoW blocks.
/// Calibrated to minimize orphan rate given p95 propagation ~3s.
pub const TARGET_BLOCK_TIME: Duration = Duration::from_secs(150);

/// Blocks per FFG epoch (ADR-001, preserved).
pub const BLOCKS_PER_EPOCH: u64 = 6;

/// Epochs for soft finality.
pub const SOFT_FINALITY_EPOCHS: u64 = 1;

/// Epochs for hard finality (full Casper FFG).
pub const HARD_FINALITY_EPOCHS: u64 = 2;

/// Expected duration of an epoch.
pub const EPOCH_DURATION: Duration = Duration::from_secs(900);  // 15 min

/// Expected soft finality latency.
pub const SOFT_FINALITY_LATENCY: Duration = EPOCH_DURATION;

/// Expected hard finality latency.
pub const HARD_FINALITY_LATENCY: Duration = Duration::from_secs(1800);  // 30 min
```

### 4.2 New types

```rust
// src/ffg/finality.rs

use serde::{Serialize, Deserialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalityLevel {
    /// Block included on the canonical chain (PoW only). May be reverted.
    Included,
    /// Epoch containing the block was justified (14-of-21 attested).
    SoftFinalized,
    /// Epoch + 1 also justified → finalized (Casper FFG).
    HardFinalized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityStatus {
    pub block_height: u64,
    pub block_hash: [u8; 32],
    /// FFG epoch the block belongs to (height / BLOCKS_PER_EPOCH).
    /// Added in rev1 (2026-04-29) to allow integrators to identify
    /// which `committee_root`'s `FinalityCertificate` applies to the
    /// block — particularly useful for cross-era queries.
    pub epoch: u64,
    pub level: FinalityLevel,
    /// Timestamp of when the block entered each level.
    /// Some(t) if reached; None if not yet.
    pub included_at: Option<u64>,
    pub soft_finalized_at: Option<u64>,
    pub hard_finalized_at: Option<u64>,
}
```

### 4.3 RPC API (extension)

#### `entl_getFinalityStatus`

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "entl_getFinalityStatus",
  "params": ["0x<block_hash>"],
  "id": 1
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "blockHeight": 12345,
    "blockHash": "0x...",
    "epoch": 2057,
    "level": "SoftFinalized",
    "includedAt": 1729000000,
    "softFinalizedAt": 1729000900,
    "hardFinalizedAt": null
  },
  "id": 1
}
```

#### WebSocket subscriptions

```
entl_subscribe(["softFinalized"])
entl_subscribe(["hardFinalized"])
```

Each event delivers a `FinalityStatus` payload when the level is reached.

#### Ethereum-style RPC compatibility

For integrators familiar with Ethereum:

```
eth_getBlockByNumber("finalized", ...) → most recent hard-finalized block.
entl_getBlockByNumber("soft-finalized", ...) → most recent soft-finalized block.
```

### 4.4 Calibration via `bloch-calibrate`

Orphan rate model (Decker & Wattenhofer 2013, adapted):

```
P(orphan) ≈ 1 - exp(-propagation_p95 / block_time)
```

For `block_time = 150s` and `propagation_p95 = 3s` (realistic testnet):

```
P(orphan) ≈ 1 - exp(-3/150) ≈ 1 - 0.9802 ≈ 1.98%
```

Acceptable (target < 2%). Calibration procedure:

```bash
# 1. Baseline with 50 geographically distributed nodes
bloch-calibrate \
  --nodes 50 \
  --geo-distribution global \
  --block-time-candidates 120,150,180,240 \
  --duration 6h \
  --metric orphan-rate \
  --output calibration-2026-05.json

# 2. Validate safety: no reorgs > 2 blocks in 1000 blocks.
bloch-calibrate \
  --validate-safety \
  --block-time 150 \
  --duration 24h
```

Acceptance criteria:
- Orphan rate < 2% in p95 network scenarios (rolling 24h mean).
- **p99 reorg depth ≤ 1 block** over 7 continuous days (i.e., 99% of observed reorgs have depth ≤ 1, AND no reorg of depth > 2 in 24h — see line below). This metric is more sensitive than pure orphan rate and captures heavy propagation tails.
- Reorgs of depth > 2 blocks: zero occurrences in 24h.
- Mining centralization (Gini): variation < 5% vs. 10min baseline.

If any criterion fails, reassess `[120s, 180s]`. If all fail at 180s, open ADR to reduce `BLOCKS_PER_EPOCH`.

### 4.5 Integrator documentation

Canonical table for `docs/integrators/finality.md`:

| Use case | Recommended level | Latency |
|----------|-------------------|---------|
| UI display balance | Included | ~2.5 min |
| DEX swap small (< $1k) | SoftFinalized | ~15 min |
| DEX swap large / RWA settlement | HardFinalized | ~30 min |
| Bridge withdrawal | HardFinalized + 6 block margin | ~45 min |
| Exchange deposit credit (small) | SoftFinalized | ~15 min |
| Exchange deposit credit (large) | HardFinalized | ~30 min |

## 5. Consequences

### 5.1 Positive

- **Competitive finality.** Soft 15 min, hard 30 min. Better than Bitcoin (~60 min for 6 confirms), comparable to Cosmos hub for hard, worse than Solana — but with stronger guarantees.
- **Superior UX.** Soft finality covers 95%+ of use cases at acceptable latency.
- **Data-based calibration.** `bloch-calibrate` replaces guesswork with simulation.
- **Ethereum-RPC compatibility.** Integrators migrating from ETH have clear semantics (`finalized` = hard).
- **No change to ADR-001.** Epoch and supermajority preserved.

### 5.2 Negative

- **Orphan rate of ~2% vs. ~0.5% in Bitcoin-style.** Small miners lose a larger fraction of blocks. Mitigation: GHOST-like uncle reward (to be specified in mining rewards ADR).
- **Mining centralization rises slightly.** Pools with low network latency gain advantage. Mitigation: monitor Gini coefficient monthly.
- **Larger API surface.** More fields = more bugs in wallets/integrations. Mitigation: official SDK in Rust + TypeScript with helper functions.
- **Future hardfork if v1 calibration is wrong.** Block time is a consensus parameter.

### 5.3 Open risks

- **R1.** Production orphan rate > 3% (model underestimated propagation). Plan: hardfork to 180s in Q2 post-mainnet.
- **R2.** Soft finality being mistaken for hard by integrators → losses. Plan: explicit documentation + alerts in SDK.
- **R3.** Attacker attempts long-range reorg exploiting hard-finality latency. Plan: weak subjectivity checkpoint every 100 epochs (future ADR).

## 6. Implementation Plan

### Sprint 2.2 — Calibration

- [ ] Extend `bloch-calibrate` with `--block-time-candidates` and `--validate-safety` flags.
- [ ] Set up testnet of 50 nodes (cloud spread across US/EU/AP).
- [ ] Run calibration for 7 continuous days.
- [ ] Publish `calibration-2026-05.json` + analysis report.
- [ ] Decide final block time within `[120s, 180s]`.

### Sprint 2.3 — RPC and types

- [ ] Create `src/ffg/finality.rs` with `FinalityLevel`, `FinalityStatus`.
- [ ] Extend `CommitteeRegistry` with `compute_finality_level(block_hash) -> FinalityLevel`.
- [ ] Implement RPC `entl_getFinalityStatus` in `src/rpc/methods/finality.rs`.
- [ ] WebSocket subscriptions `softFinalized` / `hardFinalized`.
- [ ] Ethereum-style compatibility aliases.

### Sprint 2.4 — SDK and docs

- [ ] Rust SDK: `bloch-client` crate with `wait_for_finality(level)`.
- [ ] TypeScript SDK: `@bloch/sdk` on npm.
- [ ] `docs/integrators/finality.md` (§4.5).
- [ ] Examples: bridge, exchange, RWA platform.

### Future work (open ADRs)

- Mining rewards ADR: GHOST uncle reward to mitigate orphan loss.
- Weak subjectivity ADR: checkpoint every 100 epochs.
- v1.5 ADR: assess reduction of `BLOCKS_PER_EPOCH` to 3 based on production metrics.
- v2+ ADR: post-quantum SSF with ML-DSA-65 aggregate (academic paper).

## 7. Post-Mainnet Validation Metrics

- Orphan rate over 30 days: < 2.5% (target), < 3% (limit).
- Average time to soft finality: < 18 min (p95).
- Average time to hard finality: < 35 min (p95).
- Reorgs of depth > 2: zero in 90 days.
- Adoption of `softFinalized` RPC by integrators: > 50% of queries within 6 months.
- Incidents of soft mistaken for hard: zero (preventive documentation + SDK).

## 8. References

- ADR-001 — FFG epoch=6, committee 21, supermajority 14
- ADR-005 — Committee era and rotation
- Decker, Wattenhofer (2013) — *Information Propagation in the Bitcoin Network*
- Sompolinsky, Zohar (2015) — GHOST protocol
- Solana commitment levels — `processed` / `confirmed` / `finalized`
- Polygon checkpoint model — 2-tier finality
- Casper FFG paper (Buterin & Griffith, 2017)
- Sprint 2.1 architectural decision document (BLOCH Core, 2026-04-29)
