# ADR-035: Emission V3 — flag-day reward re-scale (8,400 → 2,600 BLOCH, 1.5-year halvings)

**Status:** Accepted — armed in the fleet binary, activates at local height 40,000
**Date:** 2026-08-09
**Related:** `docs/specs/TOKENOMICS_V3.md` (normative spec), ADR-028 (V2 activation), ADR-010 lineage (historical emission doctrine)
**Supersedes:** the emission curve of ADR-028 / `docs/specs/TOKENOMICS_V2.md` from emission height 453,743 onward
**Code:** commit `8538dea` (`crates/bloch-crypto/src/core/tokenomics_v2.rs`)

---

## 1. Context

Genesis-3 restarted the chain at local height 0 with the prior ledger as a
carry-over opening balance, and kept the B3b V2 emission parameters (8,400
BLOCH initial reward, 1,036,800-block yearly halving, 100 BLOCH perpetual
tail). Re-anchoring the curve at the restart without re-scaling it changed
its integral: read forward from the restart, the V2 curve emits **≈26.92B
BLOCH over 100 years — 54% above the documented `MINING_EMISSION_NOMINAL`
of 17.43B**.

## 2. Decision

A height-gated flag-day hard fork, **Emission V3**:

- **Fork height:** emission height **453,743** = node-local height
  **40,000** (+ `CARRYOVER_SOURCE_HEIGHT` = 413,743). Const-asserted to be
  strictly after the difficulty-ancestry flag-day (local 30,030 — never
  stack two consensus changes) and before the V2 curve's first halving
  (single clean step, flat pre-fork domain).
- **Below the fork:** V2 curve **verbatim** — every historical coinbase
  stays valid; the fork is non-retroactive by construction.
- **At/above the fork:** `reward = max(2,600 >> epoch, 100)` BLOCH, with
  `epoch = (h − 453,743) / 1,555,200`. The epoch counter **restarts at the
  fork**; halvings move to every **1,555,200 blocks (~1.5 years @ 30 s)**.
  The 100 BLOCH tail floor is unchanged and perpetual — the 21B nominal
  remains **not a hard cap**.
- **Single choke point:** every producer (internal miner, Stratum V1/V2,
  `getblocktemplate`, `createauxblock`) and the validator call
  `tokenomics_v2::block_subsidy_sat(emission_height)`. Two call sites that
  passed the LOCAL height (latent while both heights sat in the 8,400
  epoch) were fixed in the same commit; `getblocktemplate` now exposes
  `emission_height` for external pools.

## 3. Consequences

- One-time **69% reward cut** at local 40,000 (8,400 → 2,600 BLOCH/block).
- Summed per height, the 100 years following the fork yield exactly
  **17,423,942,400 BLOCH** (integer-verified in `u128`; the geometric phase
  closes at 7,833,542,400, tail from emission height 8,229,743). Realized
  emission is paid per accepted DAG block and can slightly exceed the
  per-height sum — the figure is a floor, not a cap.
- CONSENSUS CHANGE: nodes on binaries without commit `8538dea` fork off the
  network at local height 40,000 — coordinated flag-day deployment of the
  fleet and public release before that height is mandatory.
- Tests pin: exhaustive pre-fork non-regression (all 453,743 heights), the
  step exactly at the fork, epoch boundaries, the 100-year sum, and a
  validator end-to-end at the 39,999/40,000 boundary.
