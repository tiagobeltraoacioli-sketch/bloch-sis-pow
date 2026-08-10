# BLOCH Emission V3 — Tokenomics Specification (Genesis-3 mainnet)

**Status:** Consensus rule — live schedule of the Genesis-3 mainnet
**Date:** 2026-08-09
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
reward = max(2,600 >> epoch, 100) BLOCH
```

- **Initial reward: 2,600 BLOCH/block** — a single clean 8,400 → 2,600 step
  at the fork (a 69% cut).
- **Halving interval: 1,555,200 blocks ≈ 1.5 years** at the 30 s target
  (1.5 × the old 1,036,800 yearly interval).
- **The epoch counter restarts at the fork** (the first V3 block is epoch 0);
  it does not inherit the absolute-height count.
- **Tail floor: 100 BLOCH/block, perpetual** (unchanged from V2). The
  geometric reward falls below the floor at epoch 5 (2,600 >> 5 = 81 < 100),
  i.e. from emission height **8,229,743** (local 7,816,000) the reward is a
  flat 100 BLOCH/block forever.

### 3.3 V3 halving table

| Epoch | Reward (BLOCH) | Emission heights | Local heights | Emitted in epoch |
|---:|---:|---|---|---:|
| 0 | 2,600 | 453,743 – 2,008,942 | 40,000 – 1,595,199 | 4,043,520,000 |
| 1 | 1,300 | 2,008,943 – 3,564,142 | 1,595,200 – 3,150,399 | 2,021,760,000 |
| 2 | 650 | 3,564,143 – 5,119,342 | 3,150,400 – 4,705,599 | 1,010,880,000 |
| 3 | 325 | 5,119,343 – 6,674,542 | 4,705,600 – 6,260,799 | 505,440,000 |
| 4 | 162 | 6,674,543 – 8,229,742 | 6,260,800 – 7,815,999 | 251,942,400 |
| 5+ | 100 (tail) | 8,229,743 → ∞ | 7,816,000 → ∞ | 100/block, perpetual |

Geometric phase total: **7,833,542,400 BLOCH**. Summed over the 100 years
(103,680,000 heights) following the fork, the curve yields exactly
**17,423,942,400 BLOCH** — verified per-height in `u128` by test (the sat
total exceeds 2⁵³; no floating point is used anywhere near these figures):

```
1,555,200 × (2,600 + 1,300 + 650 + 325 + 162)
+ (103,680,000 − 5 × 1,555,200) × 100
= 7,833,542,400 + 9,590,400,000 = 17,423,942,400
```

**Curve sum vs realized emission:** coinbases are paid per accepted **DAG
block**, and a BlockDAG accepts side ("red") blocks beyond the selected
chain — so realized emission runs slightly **above** the per-height curve
sum. Treat 17,423,942,400 as the exact 100-year value of the curve and a
floor on realized emission, not a cap. (Same trap when measuring: RPC
`getblockcount` counts DAG blocks, not chain height — the height that gates
this fork is `getdaginfo → tip_height` / `getblocktemplate → height`.)

## 4. Why the fork exists

The V2 curve (8,400 BLOCH initial, yearly halving), read forward from the
Genesis-3 restart, would have emitted **≈26.92B BLOCH over 100 years — 54%
above the documented `MINING_EMISSION_NOMINAL` of 17.43B**. The restart
re-anchored the curve without re-scaling it. Emission V3 slows the curve so
that the 100 years following the fork emit ≈ the documented nominal
(17,423,942,400 BLOCH) and moves halvings to every 1.5 years.

Deployment discipline (const-asserted in code):

- the fork height (local 40,000) is **strictly after** the
  difficulty-ancestry flag-day (local 30,030) — two consensus changes are
  never stacked on the same height;
- the fork lands **before** the V2 curve's first halving, so the pre-fork
  domain is flat (one clean 8,400 → 2,600 step);
- both spellings of the fork height are pinned:
  453,743 = 40,000 + `CARRYOVER_SOURCE_HEIGHT`.

## 5. The 21B nominal is NOT a hard cap

There is **no maximum supply**. The 100 BLOCH/block tail floor is perpetual
(Monero-style): ≈ 104M BLOCH/year at the 30 s target (0.5%/year against the
21B nominal, asymptotically → 0%). "Nominal supply" is a design target that
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
