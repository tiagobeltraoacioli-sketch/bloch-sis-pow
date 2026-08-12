# ADR-035: Emission V3 — flag-day reward re-scale (8,400 → 2,600 BLOCH, 1.5-year halvings)

**Status:** Accepted — armed in the fleet binary, activates at local height 40,000
**Date:** 2026-08-09
**Related:** `legacy/specs/TOKENOMICS_V3.md` (normative spec), ADR-028 (V2 activation), ADR-010 lineage (historical emission doctrine)
**Supersedes:** the emission curve of ADR-028 / `legacy/specs/TOKENOMICS_V2.md` from emission height 453,743 onward
**Code:** commits `8538dea` (V3 fork) + `a85b0e0` (PISO-60 tail floor) (`crates/bloch-crypto/src/core/tokenomics_v2.rs`)

---

> **AMENDMENT (2026-08-10, owner decision — PISO-60).** The V3 tail floor
> decided below (100 BLOCH/block, entering at epoch 5) was revised to
> **60 BLOCH/block entering at epoch 6** (~9 years after the fork; epoch 5
> pays the true halving value **81**). It is implemented as a V3-specific
> floor (`EMISSION_V3_TAIL_FLOOR_BLOCH = 60`); the V2 floor of 100 still
> governs all pre-fork history, so no historical block is invalidated. The
> 100-year post-fork sum changes 17,423,942,400 → **13,620,441,600 BLOCH**
> (mining total incl. pre-fork emission: 17,405,011,200; plus premine:
> 20,975,011,200 — within ~0.5% of the 17.43B/21B nominals, measured
> 2026-08-09). Shipped in the mandatory release
> `genesis3-node-emission-v3-floor60-20260810` (`bloch` sha256
> `dfc6962df85bd87a780a4a15ccf330dc08ae860dd9cf4e3ad647b5e9c79601a8`).
> The decision body below has been updated in place to the 60-floor
> parameters; this note records that the change happened pre-activation and
> why. `legacy/specs/TOKENOMICS_V3.md` (amended) is the normative spec.

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
- **At/above the fork:** `reward = max(2,600 >> epoch, 60)` BLOCH, with
  `epoch = (h − 453,743) / 1,555,200`. The epoch counter **restarts at the
  fork**; halvings move to every **1,555,200 blocks (~1.5 years @ 30 s)**.
  V3 carries its **own** tail floor of **60 BLOCH/block**
  (`EMISSION_V3_TAIL_FLOOR_BLOCH`); the V2 floor of 100 is untouched and
  governs pre-fork history only. Epoch 5 therefore pays the true halving
  value 81 (2,600 >> 5 = 81 ≥ 60) and the floor first binds at **epoch 6**
  (2,600 >> 6 = 40 < 60), ~9 years after the fork. The tail is perpetual —
  the 21B nominal remains **not a hard cap**.

  The floor moved from 100 to 60 before activation, in the same pre-fork
  window, once the accounting was done against what already exists: with a
  100 floor the 100-year total came to ≈24.78B against a 21B nominal. At 60
  it reconciles — see §Reconciliation.
- **Single choke point:** every producer (internal miner, Stratum V1/V2,
  `getblocktemplate`, `createauxblock`) and the validator call
  `tokenomics_v2::block_subsidy_sat(emission_height)`. Two call sites that
  passed the LOCAL height (latent while both heights sat in the 8,400
  epoch) were fixed in the same commit; `getblocktemplate` now exposes
  `emission_height` for external pools.

## 3. Consequences

- One-time **69% reward cut** at local 40,000 (8,400 → 2,600 BLOCH/block).
- Summed per height, the 100 years following the fork yield exactly
  **13,620,441,600 BLOCH** (integer-verified in `u128`; the geometric phase
  closes at 7,959,513,600, tail 60 from emission height 9,784,943).
  Realized emission is paid per accepted DAG block and can slightly exceed
  the per-height sum — the figure is a floor, not a cap.
- CONSENSUS CHANGE: nodes on binaries without commit `a85b0e0` fork off the
  network at local height 40,000 — coordinated flag-day deployment of the
  fleet and public release before that height is mandatory.
- Tests pin: exhaustive pre-fork non-regression (all 453,743 heights), the
  step exactly at the fork, epoch boundaries, the 100-year sum, and a
  validator end-to-end at the 39,999/40,000 boundary.
