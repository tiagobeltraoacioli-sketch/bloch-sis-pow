<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Stake Accumulation Speed — Is 9% per Epoch Defensible? (F8)

> **Genesis-4 is live.** Bloch has been running under **proof of stake** since
> 21:31:19 UTC on 2026-08-13, when Genesis-3 (proof of work) stopped
> permanently at height **39,918**. 30 s slots, 32-slot epochs, Casper-style
> justification/finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024
> signatures on every consensus path. Nothing in this document that describes
> mining, hashrate, difficulty, retargeting or proof-of-work depth describes
> the current network.
>
> **The live security question is concentration, not hashrate.** All 64
> validators are operated by a single entity; 93.94% of the carryover
> (17,046,829,380 of 18,146,400,000 BLOCH) sits at one address and carried
> balances are stakeable, so if that balance stakes the Nakamoto coefficient
> is 1; and 56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0 is
> held by the founder and the Foundation, leaving 1.92% of genesis supply in
> third-party hands. One operator can halt the chain and one holder can outvote
> every other. The live transport is a point-to-point TCP full mesh with a
> fixed peer list, **no discovery and no authentication**, and
> `Deposit`/`Delegate` are refused at every node's mempool — which is why a
> third party cannot yet join the network or become a validator.

```
Document:   BLOCH-POS-STAKE-CHURN
Status:     ACCEPTED AND APPLIED (founder decision, 2026-08-11) — the
            recommendation below landed in delegation.rs: WARMUP_RATE_BPS
            900 -> 25 and churn floor MIN_DELEGATION_SAT -> MIN_CHURN_SAT
            (= MIN_DEPOSIT_SAT). The 900-bps figures in the body are the
            OLD values, kept as the record of why they were retired
Created:    2026-08-11
Owner:      A6
Responds:   BLOCH-POS-THREAT-MODEL.md §F8
Reads:      crates/bloch-pos-committee/src/{delegation,staking,params,
            tokenomics_v4}.rs
```

## The finding, confirmed

`WARMUP_RATE_BPS = 900` (`delegation.rs:46`): at most 9% of active stake may
activate per epoch, and since the F3 fix the ceiling holds absolutely (sliced
activation, no head-of-queue escape). An epoch is 32 × 30 s = **16 minutes**.

If an attacker consumes the whole budget every epoch, their share after `k`
epochs is `f(k) = 1 − 1.09^(−k)`. Reaching the finality-stall threshold of
one third requires `1.09^(−k) = 2/3`, i.e.

```
k = ln(1.5) / ln(1.09) = 4.7 epochs ≈ 75 minutes.
```

From zero to the power to stall finality in an hour and a quarter. The
activation queue is public, but no human process reacts in 75 minutes.
Confirmed; the threat model's "~5 epochs, a bit over an hour" is right.

## Why 9% is not defensible: the numeral was ported, the clock was not

The 9% is Solana's warm-up rate, and the module says so. But a Solana epoch is
~432,000 slots × ~0.4 s ≈ **two days**. Bloch kept the numeral and shrank the
epoch **~180×**, so the wall-clock rate is ~180× Solana's:

| | rate/epoch | epoch length | zero → 1/3 of stake |
|---|---|---|---|
| Solana | 9% | ~48 h | ~4.7 epochs ≈ **9 days** |
| Bloch today | 9% | 16 min | 4.7 epochs ≈ **75 minutes** |
| Ethereum (Deneb) | ~256 ETH ≈ 0.0008% | 6.4 min | ~66,000 epochs ≈ **10 months** |

A churn limit defends in *wall-clock time* — the time it gives operators,
exchanges, and the social layer to see a hostile queue and react. Epochs are
the unit of accounting, not the unit of defense. Ethereum's limit is an
absolute per-epoch cap (a validator *count*, `max(4, N/65536)` capped at 8
activations since Deneb), which has a second property worth noting: because
the cap is absolute, the wall-clock cost of the attack **grows with the size
of the network**, while any pure percentage rate keeps it constant forever.

Note also what the neighbouring throttle does not do:
`MAX_ACTIVATIONS_PER_EPOCH = 4` (`staking.rs:93`) bounds new validator
*identities*, not stake — delegation to existing validators bypasses it
entirely (F8's Sybil timeline). The warm-up budget is the only thing bounding
stake, which is why this one constant carries the whole defense.

## What any rate limit can and cannot buy — stated before the alternatives

No rate stops an attacker who has the coins. Beneficial ownership is invisible
on-chain: the 1% cap is Sybil-bypassed by splitting, the operator-view gates
(G2/G3) cannot see one owner behind many operators, and the coins themselves
are a market purchase away. What a rate limit buys is **time during which a
takeover-in-progress is publicly visible** in the activation queue. Its value
is therefore measured in one number: how long between "attack begins" and
"attack has 1/3", compared against how long detection and response take.
Everything below is that trade, priced.

## Alternatives, with the arithmetic

Time from zero to 1/3 is `ln(1.5)/ln(1 + r)` epochs, × 16 min:

| `WARMUP_RATE_BPS` | zero → 1/3 | equivalent context |
|---|---|---|
| 900 (today) | 4.7 epochs ≈ **1.3 h** | Solana's numeral on a 180× faster clock |
| 100 | 41 epochs ≈ **10.9 h** | still inside one operator's night of sleep |
| 50 | 81 epochs ≈ **21.7 h** | |
| **25 (proposed)** | 162 epochs ≈ **43 h** | ~2 days of a publicly visible hostile queue |
| 10 | 406 epochs ≈ **4.5 d** | |
| 5 | 811 epochs ≈ **9.0 d** | Solana's actual wall-clock rate |
| ~0.4 + absolute cap | months | Ethereum's regime |

## Proposal

**Lower `WARMUP_RATE_BPS` from 900 to 25** (0.25% of active stake per epoch,
≈ 25% per day compounded), keeping the epoch-0 genesis exemption and the
sliced activation/cool-down of the F3 fix. Two companion adjustments:

1. **Raise the budget floor from `MIN_DELEGATION_SAT` (10 BLCH) to
   `MIN_DEPOSIT` (100,000 BLCH) per epoch.** At 25 bps the proportional
   budget only exceeds 100k BLCH once active stake passes 40M BLCH; below
   that, a 10-BLCH floor would strangle a young network. One validator's
   worth of stake per epoch is the natural minimum churn (Ethereum's floor is
   the same idea: 4 validators). The floor keeps the drain-termination
   property the current floor exists for.
2. **Phase 2, once active stake is meaningful: add an absolute cap**
   (`budget = clamp(total × 25bps, MIN_CHURN, MAX_CHURN)`), so attack time
   grows with the network as it does on Ethereum instead of staying constant
   at 43 hours forever. Sizing `MAX_CHURN` needs real staking data; it is
   flagged, not sized, here.

Why 43 hours and not more: past roughly one day, each further halving of the
rate buys diminishing security (the queue is already visible for multiple
operator working days, and the real barrier has shifted to acquiring the
coins) while the liveness costs below keep growing linearly. 25 bps is the
knee, not a sacred number; the table is the dial.

## The liveness bill, itemised (the honest cost of lowering)

Warm-up and cool-down share the budget, so every cost is symmetric:

- **Honest onboarding slows ~36×.** A new participant bringing stake equal to
  10% of the active set: ~18 minutes today, **~11 hours** at 25 bps. An
  exchange or the foundation standing up validators plans in days, not
  minutes.
- **Growing the set takes days.** Doubling total active stake from a full
  queue: ~2 hours today, **~3.1 days** at 25 bps
  (`ln 2 / ln 1.0025 ≈ 278 epochs`). For a young network hungry for stake,
  this is the largest real cost.
- **Exit is equally slow, and that cost lands on honest validators.** Today
  a third of the set can drain out in ~1 hour; at 25 bps it takes **~43
  hours**, plus the 32-epoch cool-down before withdrawal. After a slashing
  scare, a key-compromise disclosure, or a client bug, stake stays bonded and
  slashable for ~2 days instead of one hour. This is the price of the cap
  holding in both directions (the F3 lesson: emptying the set fast is as
  dangerous as filling it fast), but it must be stated: lowering the rate
  extends honest exposure exactly as much as it delays attackers.
- **Bootstrap is unaffected.** Epoch 0 is exempt, and the 100k-BLCH floor
  admits at least one validator's stake per epoch at any network size.

Interlock with existing mechanisms, for completeness: the genesis-cohort
declining cap bounds the *founding* cohort's share and does nothing against
new outside capital — the warm-up rate is the only brake on that; conversely
the rate does nothing about cohort concentration. They are complementary, not
redundant. The weak-subjectivity window (2048 epochs ≈ 22.8 days) comfortably
contains a 162-epoch attack, so checkpoint cadence needs no change.

## Decision needed

Change `WARMUP_RATE_BPS` 900 → 25 and the floor `MIN_DELEGATION_SAT` →
`MIN_DEPOSIT`-per-epoch in `delegation.rs`, with the tests re-pinned to the
new constants. Both are consensus parameters; this document recommends and
prices the change but does not apply it. If the founder prefers a different
point on the dial, the table above is the whole trade — the only
non-negotiable conclusion is that **900 bps on a 16-minute epoch is a
transcription error, not a design choice**, and it turns the committee's
stake-weighting into a same-day takeover for anyone holding the coins.
