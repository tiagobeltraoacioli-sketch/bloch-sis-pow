# BLOCH Emission V3 — Tokenomics Specification (Genesis-3 mainnet)

**Status:** Consensus rule — live schedule of the Genesis-3 mainnet
**Date:** 2026-08-09
**Amended:** 2026-08-10 — owner decision: the V3 tail floor is **60 BLOCH/block entering at epoch 6** (epoch 5 pays the true halving value 81), not 100 at epoch 5 as first drafted. Implemented as a V3-specific floor (PISO-60; the V2 floor of 100 still governs all pre-fork history) and shipped in the mandatory release **`genesis3-node-emission-v3-floor60-20260810`** (`bloch` sha256 `dfc6962df85bd87a780a4a15ccf330dc08ae860dd9cf4e3ad647b5e9c79601a8`); all earlier binaries (incl. `6ffc5f12…`/`c21e09d`) are superseded.
**Consensus source of truth:** `crates/bloch-crypto/src/core/tokenomics_v2.rs` (`block_subsidy_sat` and the `EMISSION_V3_*` constants — const-asserted and exhaustively tested)
**Activation:** flag-day hard fork at **emission height 453,743 = node-local height 40,000** (commit `8538dea`)
**Supersedes:** the emission curve of `docs/specs/TOKENOMICS_V2.md` (both its original 1B parameter set and the B3b 21B re-basing) — see ADR-035

> Every number in this document is read from the code constants or from the
> const-asserts/tests that pin them. If this document and
> `tokenomics_v2.rs` ever disagree, the code is the consensus truth.

---

## 1. Heights: emission height vs local height

Genesis-3 is a carry-over chain: it restarted at local height 0 with the
prior ledger ingested as an opening balance (413,743 UTXOs — see
`docs/CARRYOVER.md`). The emission schedule is keyed to the **emission
height**, which continues the pre-restart count:

```
emission_height = local_height + CARRYOVER_SOURCE_HEIGHT
                = local_height + 413,743
```

`getblocktemplate` exposes `emission_height` so external pools never have to
recompute the offset. All heights below are given in both spaces where it
matters.

## 2. Supply model

```
NOMINAL_TOTAL_SUPPLY    = 21,000,000,000 BLOCH   (nominal — NOT a hard cap, §5)
FOUNDER_PREMINE_TOTAL   =  3,570,000,000 BLOCH   (17% of nominal; §6)
MINING_EMISSION_NOMINAL = 17,430,000,000 BLOCH   (target Σ subsidy)
VALIDATOR_ORACLE_POOL   =              0 BLOCH   (removed — pure PoW, no pools)
DECIMALS                = 8                       (1 BLOCH = 10⁸ sat)
```

100% of every block subsidy goes to the miner. There is no validator pool,
no oracle pool, no treasury and no fee burn on the base layer.

The existing supply at any moment is **carry-over + everything mined on
Genesis-3** — always state both parts explicitly:

- carry-over opening balance: **3,475,441,200 BLOCH exactly**
  (413,743 UTXOs × 8,400; consensus constant `CARRYOVER_TOTAL_SAT`);
- Genesis-3 coinbases since local height 0 (one per accepted **DAG block**,
  which exceeds the chain height — measure via RPC, and note that
  `getsupplydistribution` reports only the mined side and **omits the
  carry-over**).

## 3. The emission curve

`block_subsidy_sat(emission_height)` is the single choke point: every
producer (internal miner, Stratum V1/V2, `getblocktemplate`,
`createauxblock`) and the validator go through it.

### 3.1 Below the fork — V2 curve, verbatim (emission h < 453,743)

```
reward = max(8,400 >> (h / 1,036,800), 100) BLOCH
```

Every pre-fork emission height sits in epoch 0 (the first V2 halving at
1,036,800 is never reached), so **every historical block pays 8,400 BLOCH**
and every historical coinbase stays valid — the fork is non-retroactive by
construction.

### 3.2 At/above the fork — Emission V3 (emission h ≥ 453,743, local ≥ 40,000)

```
epoch  = (h − 453,743) / 1,555,200
reward = max(2,600 >> epoch, 60) BLOCH
```

- **Initial reward: 2,600 BLOCH/block** — a single clean 8,400 → 2,600 step
  at the fork (a 69% cut).
- **Halving interval: 1,555,200 blocks ≈ 1.5 years** at the 30 s target
  (1.5 × the old 1,036,800 yearly interval).
- **The epoch counter restarts at the fork** (the first V3 block is epoch 0);
  it does not inherit the absolute-height count.
- **Tail floor: 60 BLOCH/block, perpetual** (`EMISSION_V3_TAIL_FLOOR_BLOCH`
  — a V3-specific floor; the V2 floor of 100 governs only pre-fork
  history). Epoch 5 pays the true halving value **81** (2,600 >> 5 = 81 ≥
  60); the geometric reward first falls below the floor at **epoch 6**
  (2,600 >> 6 = 40 < 60), i.e. from emission height **9,784,943** (local
  9,371,200, ~9 years after the fork) the reward is a flat 60 BLOCH/block
  forever (const-asserted: `EMISSION_V3_TAIL_ACTIVATION_EPOCH = 6`,
  `EMISSION_V3_TAIL_ACTIVATION_HEIGHT = 9_784_943`).

### 3.3 V3 halving table

| Epoch | Reward (BLOCH) | Emission heights | Local heights | Emitted in epoch |
|---:|---:|---|---|---:|
| 0 | 2,600 | 453,743 – 2,008,942 | 40,000 – 1,595,199 | 4,043,520,000 |
| 1 | 1,300 | 2,008,943 – 3,564,142 | 1,595,200 – 3,150,399 | 2,021,760,000 |
| 2 | 650 | 3,564,143 – 5,119,342 | 3,150,400 – 4,705,599 | 1,010,880,000 |
| 3 | 325 | 5,119,343 – 6,674,542 | 4,705,600 – 6,260,799 | 505,440,000 |
| 4 | 162 | 6,674,543 – 8,229,742 | 6,260,800 – 7,815,999 | 251,942,400 |
| 5 | 81 | 8,229,743 – 9,784,942 | 7,816,000 – 9,371,199 | 125,971,200 |
| 6+ | 60 (tail) | 9,784,943 → ∞ | 9,371,200 → ∞ | 60/block, perpetual |

Geometric phase total: **7,959,513,600 BLOCH**. Summed over the 100 years
(103,680,000 heights) following the fork, the curve yields exactly
**13,620,441,600 BLOCH** (`EMISSION_V3_100Y_TOTAL_BLOCH`) — verified
per-height in `u128` by test (the sat total exceeds 2⁵³; no floating point
is used anywhere near these figures):

```
1,555,200 × (2,600 + 1,300 + 650 + 325 + 162 + 81)
+ (103,680,000 − 6 × 1,555,200) × 60
= 7,959,513,600 + 5,660,928,000 = 13,620,441,600
```

**Curve sum vs realized emission:** coinbases are paid per accepted **DAG
block**, and a BlockDAG accepts side ("red") blocks beyond the selected
chain — so realized emission runs slightly **above** the per-height curve
sum. Treat 13,620,441,600 as the exact 100-year value of the curve and a
floor on realized emission, not a cap. (Same trap when measuring: RPC
`getblockcount` counts DAG blocks, not chain height — the height that gates
this fork is `getdaginfo → tip_height` / `getblocktemplate → height`.)

## 4. Why the fork exists

The V2 curve (8,400 BLOCH initial, yearly halving), read forward from the
Genesis-3 restart, would have emitted **≈26.92B BLOCH over 100 years — 54%
above the documented `MINING_EMISSION_NOMINAL` of 17.43B**. The restart
re-anchored the curve without re-scaling it. Emission V3 slows the curve
and moves halvings to every 1.5 years, **realigning emission with the
documented nominals (17.43B mining / 21B total) to within ~0.5%** — always
stated with the full decomposition (measured 2026-08-09):

| Component | BLOCH |
|---|---:|
| Carry-over (Genesis-1, 413,743 UTXOs × 8,400) | 3,475,441,200 |
| Mined since Genesis-3 (36,801 coinbases × 8,400) | 309,128,400 |
| + Future V3 emission over 100 yr (floor 60 from epoch 6) | 13,620,441,600 |
| = Mining total (nominal 17,430,000,000) | **17,405,011,200** |
| + Founder premine | 3,570,000,000 |
| = Total (nominal 21,000,000,000) | **20,975,011,200** |

The mined-side figure keeps growing at 8,400/coinbase until the fork
(≈17.50B mining total at the fork, ≈ +0.4% over nominal) — anchor any
restatement to its measurement date, and remember every figure is a floor
(per-DAG-block coinbases, perpetual tail), never a cap.

Deployment discipline (const-asserted in code):

- the fork height (local 40,000) is **strictly after** the
  difficulty-ancestry flag-day (local 30,030) — two consensus changes are
  never stacked on the same height;
- the fork lands **before** the V2 curve's first halving, so the pre-fork
  domain is flat (one clean 8,400 → 2,600 step);
- both spellings of the fork height are pinned:
  453,743 = 40,000 + `CARRYOVER_SOURCE_HEIGHT`.

## 5. The 21B nominal is NOT a hard cap

There is **no maximum supply**. The 60 BLOCH/block V3 tail floor is
perpetual (Monero-style): ≈ 62M BLOCH/year at the 30 s target (≈0.3%/year
against the 21B nominal, asymptotically → 0%). "Nominal supply" is a design target that
the geometric phase approaches — not a ceiling the chain enforces. Any
document, listing form or integration that describes BLOCH as "hard-capped"
or "fixed supply" is wrong. (And the unit is **billions** — 21,000,000,000
BLOCH — not the Bitcoin-familiar 21 million.)

## 6. Founder premine (context)

The 17% founder allocation (3,570,000,000 BLOCH) is consensus-locked and
**not yet emitted — do not add it to the existing supply**. Per the
constants in `tokenomics_v2.rs` it vests through coinbase outputs, keyed to
the **emission height**: fully locked for a 10-year cliff
(`FOUNDER_VESTING_CLIFF = 10,368,000`), then **480 monthly tranches of
7,437,500 BLOCH** (86,400 blocks per month) over 40 years, ending at
emission height 51,840,000. Today the live block template carries
`founder_vesting_sat: 0`. Independently of the premine schedule, the
founder holds most of the current existing supply through the carry-over
opening balance — disclosed, and orthogonal to the emission curve this
document specifies.

## 7. Document lineage

- `docs/specs/historical/TOKENOMICS_V1_SUPERSEDED.md` — V1 (never mainnet).
- `docs/specs/TOKENOMICS_V2.md` — the original V2 spec (1B nominal, 1,905
  reward, 150 s blocks, 70/25/5). Its parameter set was re-based by the
  Bloch-SIS B3b revision (21B nominal, 8,400 reward, 30 s blocks, 100%
  miner) directly in `tokenomics_v2.rs`; the emission curve is now
  superseded by this document from the fork onward. Historical record only.
- `docs/adr/ADR-035-emission-v3-schedule.md` — the decision record for this
  fork.
