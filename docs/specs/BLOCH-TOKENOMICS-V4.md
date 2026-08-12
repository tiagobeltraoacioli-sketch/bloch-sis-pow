<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — Tokenomics V4 (Genesis-4 relaunch with carryover)

```
Document:   BLOCH-TOKENOMICS-V4
Status:     DRAFT — founder decision recorded, parameters not frozen
Created:    2026-08-10
Supersedes: tokenomics_v2.rs (21 B nominal, uncapped tail) and ADR-035 emission V3
Relates to: BLOCH-POS-SHA3-LATTICE-MIGRATION.md (§4 distribution gates)
```

---

## 1. Decision

Relaunch from a fresh genesis with a **fixed 100,000,000,000 BLCH** supply — the
V2 nominal, after a draft at 100 billion.

**The whole carryover comes across as one balance set, with no founder line.**
Those coins were mined, on the same chain, under the same rules as everyone
else's — so they are carried the same way, as ordinary liquid balance, and
liquid includes stakeable (decided 2026-08-11, §4A.1). The founder additionally
receives a new 10% grant under a 10-year cliff and 40-year linear vest — the V2
premine schedule, at 10% rather than the V2 17%.

Returning to 100 billion removes two hazards the 100-billion draft created, at no
cost: the supply is **54.21% of `u64::MAX`** rather than the earlier draft's 54.21%, so the sum of
two large balances is nowhere near the wrap point; and it **fits in the signed
`int64`** the Go SDK uses for `Satoshis` (`sdk/go/models.go:16`), which 100
billion overflowed by 8%.

| Destination | BLCH | Share | Unlock |
|---|---:|---:|---|
| Carryover — the whole ledger | 17,970,880,000 | 17.97% | **liquid at genesis** |
| Founder — new grant | 10,000,000,000 | 10.00% | 10-year cliff, then 40-year linear |
| VC / crypto hedge funds | 10,000,000,000 | 10.00% | 12-month cliff, then 24-month linear |
| Development team | 10,000,000,000 | 10.00% | 18-month cliff, then 36-month linear |
| Marketing | 4,000,000,000 | 4.00% | 25% at genesis, remainder linear over 24 months |
| Liquidity | 5,000,000,000 | 5.00% | 100% liquid at genesis |
| **Validators** | **43,029,120,000** | **43.03%** | emitted over 40 years |
| **Total** | **100,000,000,000** | **100.00%** | |

**Founder total: 26.89%** — the carried-over balance plus the new grant. The
grant was cut from 17% to 10% on 2026-08-11 and the 1,470,000,000 difference
went to validators, the only reallocation so far that moved supply *away* from
an insider bucket.

<figure style="margin:1.4em 0">
<svg viewBox="0 0 690 356" width="100%" role="img" aria-label="Distribuicao do supply de 100 bilhoes de BLCH em sete destinos" style="max-width:690px;font-family:Charter,Georgia,serif">
<title>Distribuição do supply — 100.000.000.000 BLCH</title>
<path d="M 170.00 178.00 L 171.18 28.00 A 150 150 0 0 1 234.68 313.34 Z" fill="#2a78d6"/>
<path d="M 170.00 178.00 L 232.55 314.34 A 150 150 0 0 1 75.30 294.32 Z" fill="#eb6834"/>
<path d="M 170.00 178.00 L 73.48 292.82 A 150 150 0 0 1 25.01 216.44 Z" fill="#1baf7a"/>
<path d="M 170.00 178.00 L 24.42 214.16 A 150 150 0 0 1 30.10 123.88 Z" fill="#eda100"/>
<path d="M 170.00 178.00 L 30.97 121.69 A 150 150 0 0 1 88.63 51.99 Z" fill="#e87ba4"/>
<path d="M 170.00 178.00 L 90.62 50.72 A 150 150 0 0 1 131.56 33.01 Z" fill="#008300"/>
<path d="M 170.00 178.00 L 133.84 32.42 A 150 150 0 0 1 168.82 28.00 Z" fill="#4a3aa7"/>
<text x="266.6" y="156.5" text-anchor="middle" dominant-baseline="middle" font-size="13" font-weight="700" fill="#ffffff">43.03%</text>
<text x="157.5" y="276.2" text-anchor="middle" dominant-baseline="middle" font-size="13" font-weight="700" fill="#ffffff">17.97%</text>
<text x="86.4" y="231.0" text-anchor="middle" dominant-baseline="middle" font-size="13" font-weight="700" fill="#ffffff">10.00%</text>
<text x="71.2" y="171.8" text-anchor="middle" dominant-baseline="middle" font-size="13" font-weight="700" fill="#ffffff">10.00%</text>
<text x="93.7" y="114.9" text-anchor="middle" dominant-baseline="middle" font-size="13" font-weight="700" fill="#ffffff">10.00%</text>
<text x="372" y="24" font-size="10" fill="#5c6169" letter-spacing="0.09em">DESTINO</text>
<text x="608" y="24" font-size="10" fill="#5c6169" letter-spacing="0.09em" text-anchor="end">BLCH</text>
<text x="676" y="24" font-size="10" fill="#5c6169" letter-spacing="0.09em" text-anchor="end">%</text>
<rect x="372" y="32" width="12" height="12" rx="3" fill="#2a78d6"/>
<text x="392" y="42" font-size="12.5" fill="#14161a" dominant-baseline="middle">Validadores</text>
<text x="608" y="42" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">43.029.120.000</text>
<text x="676" y="42" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">43.03</text>
<rect x="372" y="62" width="12" height="12" rx="3" fill="#eb6834"/>
<text x="392" y="72" font-size="12.5" fill="#14161a" dominant-baseline="middle">Carryover</text>
<text x="608" y="72" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">17.970.850.000</text>
<text x="676" y="72" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">17.97</text>
<rect x="372" y="92" width="12" height="12" rx="3" fill="#1baf7a"/>
<text x="392" y="102" font-size="12.5" fill="#14161a" dominant-baseline="middle">Fundador — concessão</text>
<text x="608" y="102" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">10.000.000.000</text>
<text x="676" y="102" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">10.00</text>
<rect x="372" y="122" width="12" height="12" rx="3" fill="#eda100"/>
<text x="392" y="132" font-size="12.5" fill="#14161a" dominant-baseline="middle">VC</text>
<text x="608" y="132" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">10.000.000.000</text>
<text x="676" y="132" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">10.00</text>
<rect x="372" y="152" width="12" height="12" rx="3" fill="#e87ba4"/>
<text x="392" y="162" font-size="12.5" fill="#14161a" dominant-baseline="middle">Time</text>
<text x="608" y="162" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">10.000.000.000</text>
<text x="676" y="162" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">10.00</text>
<rect x="372" y="182" width="12" height="12" rx="3" fill="#008300"/>
<text x="392" y="192" font-size="12.5" fill="#14161a" dominant-baseline="middle">Liquidez</text>
<text x="608" y="192" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">5.000.000.000</text>
<text x="676" y="192" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">5.00</text>
<rect x="372" y="212" width="12" height="12" rx="3" fill="#4a3aa7"/>
<text x="392" y="222" font-size="12.5" fill="#14161a" dominant-baseline="middle">Marketing</text>
<text x="608" y="222" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">4.000.000.000</text>
<text x="676" y="222" font-size="12.5" fill="#3c4149" text-anchor="end" dominant-baseline="middle">4.00</text>
<line x1="372" y1="240" x2="676" y2="240" stroke="#d5d9df"/>
<text x="392" y="254" font-size="12.5" font-weight="700" fill="#14161a" dominant-baseline="middle">Total</text>
<text x="608" y="254" font-size="12.5" font-weight="700" fill="#14161a" text-anchor="end" dominant-baseline="middle">100.000.000.000</text>
<text x="676" y="254" font-size="12.5" font-weight="700" fill="#14161a" text-anchor="end" dominant-baseline="middle">100,00</text>
</svg>
<figcaption style="font-size:9.5pt;color:#5c6169;margin-top:.5em">
Distribution of the 100,000,000,000 BLCH supply. Slices carry a direct label
only where one fits; every figure is in the legend, which is also the table
view — three buckets sit at exactly 10% — a pie cannot show that as well as the
number does, which is why the legend carries both.
</figcaption>
</figure>


Validator emission runs for 40 years and is supplemented by transaction fees.
**After the 21 B is fully issued, validators are paid 100% from fees.**

---

## 2. What the carryover actually contains — measured live

Not estimated. A read-only UTXO snapshot was taken on node4 at **height
43,172** with `bloch-snapshot-utxo`, then aggregated by address:

| | |
|---|---|
| UTXOs | 448,337 |
| Addresses | 15 |
| **Total carried over** | **17,970,880,000 BLCH** |
| Snapshot root (SHAKE-256) | `280d604b32525f03…` |
| Carryover digest (SHAKE-256) | `92918209a106f297…` |

**All of it crosses.** There is no founder line and no exclusion list: those
coins were mined, on the same chain, under the same rules as everyone else's.

The distribution inside the set is what it is, and is worth stating rather than
leaving to be discovered:

| | BLCH | Share of carryover |
|---|---:|---:|
| Largest single address | 16,886,549,523 | 93.96% |
| The other 14 | 227,709,400 | 6.04% |

An earlier draft of this section reported 413,743 UTXOs across five addresses,
from the Genesis-1 file rather than the live chain. Ten more addresses have
accumulated balances by mining since Genesis-3, and the totals moved with them.
Anything quoted from the older figures is stale.

---

## 3. The cap, retired

Earlier drafts capped carried-over balances at 300 M and excluded the founder
from the carryover, and §3 tracked how close that cap was to binding. Both went
with the single-set decision (§1): the cap existed to bound what legacy holders
received *while the founder was excluded*, so with nobody excluded it would
either bind on everyone — scaling every balance down by roughly 92% — or on no
one.

Three things follow, and the third is the one worth keeping:

1. No pro-rata scale-down runs. Every holder keeps 100% of their position.
2. The measurement that mattered — whether third-party mining would push the
   non-founder total past 300 M before the terminal height — no longer decides
   anything. It was going to be close: measured 227.7 M at height 43,172 against
   a 300 M ceiling, growing about 4 M/day.
3. **The exclusion list is gone, and with it an unaudited power.** An earlier
   draft flagged that whoever writes the list decides who counts as founder, that
   nothing in the protocol checks it, and that it should therefore be published
   for challenge before the height passed. There is now no list to write. That
   concern was not mitigated — it ceased to exist, which is the only one of this
   document's risks that got resolved rather than traded.

### 3.1 Snapshot height — decided: 50,000

Measured at height **40,424**: non-founder holdings ≈ **236.8 M BLCH**, 79% of
the cap, growing **≈ 3.97 M/day**. On the central estimate the cap binds around
height **86,300**, roughly 16 days out.

**The height must land before the cap binds, and that is the whole argument.**
Below the cap every holder keeps 100% of their position and no scale-down runs
at all. Above it, the 300 M becomes a fixed pot shared pro-rata, and every coin
mined after that point dilutes everyone — individually rational to chase,
collectively worthless, and a pure race.

| Height | Days out | Preserved at r=12% | r=16% | r=20% | r=25% |
|---:|---:|---:|---:|---:|---:|
| 60,000 | 6.8 | 100% | 100% | 100% | 98% |
| 70,000 | 10.3 | 100% | 100% | 100% | 91% |
| **50,000** | **13.7** | **100%** | **100%** | **95%** | 86% |
| 86,000 | 15.8 | 100% | 100% | 92% | 83% |
| 100,000 | 20.7 | 100% | 94% | 86% | 77% |

`r` is the share of emission going to third-party miners. The central estimate,
16.4%, is derived from a single prior measurement rather than a fresh audit, so
the table spans the plausible range.

**50,000** gives about two weeks of notice — the recognisable norm for a
snapshot — on a round, legible number, and preserves every holder in full
unless third-party mining is running well above the estimate.

**Longer notice is actively worse here, which is counterintuitive.** Holders
need do nothing: balances are captured on-chain automatically, there is no
claim and no migration. So the notice period buys transparency, not time to
act — and the one action it does enable is accumulating more coins before the
cut, which dilutes everybody. The usual "give people plenty of warning" instinct
inverts.

**Before announcing**, measure the non-founder total against live balances
rather than trusting the 16.4% estimate. If the real rate is above ~20%, drop
to 70,000.

### 3.2 The chain halts at the snapshot

**Height 50,000 is a terminal height, not just a measurement point.** The
current chain stops producing blocks there; Genesis-4 launches from the
snapshot roughly six months later, after code review.

This resolves the dead-period problem rather than mitigating it. Had the chain
kept running, the 166 days between snapshot and launch would have meant
4,016 M BLCH mined by people receiving nothing — and, worse, a rational miner
switches off the day after the snapshot, leaving the network without hashrate
during exactly the six months it still has users, wallets and an explorer
pointed at it. Halting removes both: nobody mines coins with no future, and
nobody buys into a chain with no future.

Two things must exist **before** height 50,000, which is about two weeks away.

#### 3.2.1 The halt has to be a consensus rule

A chain does not stop because it was announced. Blocks above the terminal
height must be **invalid**, shipped in a release and running on the fleet
before the height arrives. Otherwise miners simply continue and the "halt" is a
fork nobody agreed to.

This is a flag day in reverse and it inherits every flag-day hazard this project
has already lived through: the release must actually be the binary the fleet
runs. Anyone who does not upgrade will keep mining past 50,000 on a fork; that
is tolerable, but only if the canonical snapshot is fixed at 50,000 and said so
publicly.

#### 3.2.2 After the halt, the chain's own history stops being evidence

This is the non-obvious one. PoW security is bought with ongoing hashrate. The
moment mining stops, the cost of rewriting history from below height 50,000
collapses toward zero — anyone with modest hashrate can produce an alternative
chain ending at 50,000 with different balances, and after a few months of no
honest mining, it may carry more accumulated work than the real one.

Therefore the **signed snapshot artifact is canonical, not the chain**. At the
halt, produce the balance set, hash it, sign it, and publish the digest widely
enough that it cannot be quietly replaced — the same pattern already used for
`carryover.tsv.gz` and its `.sha256`. Genesis-4 must be built from that
artifact, and the artifact's digest should appear in the Genesis-4 genesis
block itself. A chain nobody is defending is not a record.

**One trust point, named.** The taint list — which addresses count as founder —
is set by the founder. Nothing in the protocol stops founder-controlled coins
from being presented as third-party holdings and capturing part of the 300 M.
The list should be published with the announcement so it can be argued with
before the height passes, not after.

---

## 3.3 Genesis bootstrap — who produces block 1

The adversarial review found a gap the halt decision opened and nothing closed.
The original migration design seeded the validator set during a **hybrid PoW
phase**: miners kept producing while deposits accumulated, so PoS activated onto
an existing, funded validator set. Halting Genesis-3 and launching Genesis-4
from a snapshot deleted that phase. Genesis-4 has no PoW, and deposits are
transactions — which need blocks, which need validators.

**The chain cannot start.** This is not a subtle failure: without an initial
validator set there is no proposer for slot 0.

### The fix: a genesis validator set

The genesis block carries an initial validator set the same way it carries the
allocations — as consensus data, active from slot 0, with no deposit
transaction required because there is no chain yet to carry one. Every later
validator joins through the ordinary deposit path.

Three things this must satisfy, and one it must not pretend to.

**It must be funded from a named bucket.** Liquid supply at genesis is
23,970,850,000 BLCH: the whole carryover (17.97%), liquidity (5%) and the
marketing TGE tranche (1%). VC, team and the founder's new grant are entirely
cliffed.

That leaves two candidate sources, and the choice is not neutral. Genesis
validators can stake from the **Foundation's** liquid holdings, or from the
**carryover** — which in practice means the largest carried-over address, since
it holds 93.96% of the set. Funding them from the carryover would put the
founder's balance directly into consensus at slot 0, which is the §4.2 problem
in its most concentrated form. Funding them from the Foundation keeps that door
shut and is the assumption the rest of this section makes. Either way it has to
be said plainly rather than shown as an unexplained line in the genesis file.

**It must be large enough to be meaningful and small enough to be honest.** The
partition in §6.5.3 cuts the active set into 32 committees, so a set below 32
leaves empty committees and slots with no attesters. A floor of **64 genesis
validators** gives every slot at least two.

**It must be replaceable.** Genesis validators exit through the ordinary path as
independent stake arrives. Nothing in consensus privileges them after genesis.

### 3.3.1 Who operates them, and the one-year rule

**The founder funds and operates the genesis cohort** (founder decision,
2026-08-11). There was no alternative that did not amount to the same thing:
liquidity and marketing are the Foundation's, and the Foundation is the founder
until the board exists.

The commitment attached to it is that the start does not persist: **within one
year the founder's consensus weight falls below one third**, and that is written
as a consensus rule rather than a promise
(`crates/bloch-pos-committee/src/genesis_cohort.rs`).

**Why one third and not something rounder.** It is the share that can stall a
two-thirds quorum. Above it the founder can freeze the chain unilaterally;
below it the founder cannot. The rule says, in one number: *after year one, the
founder cannot halt Bloch alone.* Note what it does not say — one third is the
**liveness** threshold, not the safety one, which is two thirds. Falling under a
third stops the founder stalling finality; it was never what stopped anyone
finalising a bad state.

**How it is enforced.** The cohort is a fixed set published in the genesis
block, which can only shrink — members leave by exiting and nothing can be
added. Their combined weight is capped, and the cap tapers linearly from the
whole set at genesis to one third at one year, then holds:

| Month | Cohort cap |
|---:|---:|
| 0 | 100.0% |
| 3 | 83.3% |
| 6 | 66.7% |
| 9 | 50.0% |
| **12** | **33.3%** |

The taper is deliberate. A step from 100% to 33% on one epoch boundary would
eject two thirds of the chain's consensus weight in sixteen minutes — the chain
would stop the moment the rule bit. Tapering gives independent stake a year of
steadily rising room instead of a single deadline.

**Where enforcement stops, plainly.** The cap binds the *cohort*. Nothing
prevents funding new validators after genesis under addresses that are not in
it, and no on-chain rule can see beneficial ownership behind an address. Past
the cohort, one third is a commitment verified externally — by the Foundation's
reporting rule and by whoever is watching. The enforceable part is real and
bounded; claiming more would be claiming that consensus can see through an
address, and it cannot.

### What it must not pretend

**Genesis-validator stake does not count toward gates G1–G4.** A Foundation-
funded set spread across 64 records reads as 64 independent participants to
`top_share_bps` and `nakamoto_coefficient`, which measure the operator view —
they cannot see one beneficial owner behind many records, and no on-chain metric
can. The same reporting rule already written for the delegation program
(`BLOCH-ENTITY-STRUCTURE.md` §5.1) applies here and for the same reason: the
gates are measured on stake whose beneficial owner is not the Foundation, the
founder, or Postern Labs.

So the honest statement of the launch is: **the chain starts centralised, by
construction, and the gates measure the distance from there.** A hybrid PoW
phase would have bought a genuinely independent initial set; the halt bought a
clean break instead. That was a defensible trade, but it was made without
noticing this was part of the price.

---

## 4. What this does to existing holders

Stated plainly, because it affects parties who are not in the room:

| | Today | After V4 |
|---|---:|---:|
| Coins carried over | 3,475,441,200 (G-1 file) | 17,970,880,000 (measured live) |
| Non-founder **share of network** | 5.21% | **≤ 0.30%** |

Holders keep their coins in absolute terms and lose roughly **17×** of their
relative position. That is the arithmetic consequence of preserving absolute
balances while the supply stays at 21 B. It is a
legitimate choice — it is what "preserved in absolute terms" means — but it
should be published in exactly these terms rather than as "your balance is
preserved", which is true and misleading at the same time.

---

## 4A. Concentration under the carried-over balance

The carried-over founder balance is **liquid at slot 0**, so the answer to §0.1
changes and it should be stated in numbers rather than characterised.

| | |
|---|---|
| Circulating at slot 0 | 23,970,850,000 BLCH (carryover 3.77 B + liquidity 1.05 B + marketing TGE 0.21 B) |
| Founder liquid at slot 0 | 16,886,549,523 BLCH |
| **Founder share of circulating** | **70.4%** |

Gate G2 requires the largest holder to hold under 25% of active stake. On this
schedule:

| | Founder share of circulating |
|---:|---:|
| Year 1 | 58.0% |
| Year 2 | 41.6% |
| Year 3 | 31.5% |
| Year 5 | 25.2% |
| Year 10 | 20.0% |
| Year 40 | 16.9% |

**G2 is not met until roughly year five**, and only if every other bucket
unlocks and the validator emission accrues to independent parties as modelled.
A draft that cliffed the founder's entire position bought a genesis where the
founder held no spendable stake at all; carrying the balance across liquid gives
that up.

One thing softens it and should be said alongside the number: the new 10%
grant is locked for a decade and vests across forty years — far beyond any
market benchmark, and the strictest schedule on the chain. A second lever was
formally open until 2026-08-11 — **liquid** was not the same as **stakeable**,
and a carried-over balance could have been spendable while remaining
ineligible to stake. It is open no longer:

### 4A.1 Stakeable — decided 2026-08-11

**A carried-over balance that is liquid is also stakeable.** Founder decision,
2026-08-11. The carryover crosses as one undifferentiated set — the founder's
balance included, because those coins were mined on the same chain under the
same rules — and no provenance criterion survives anywhere in the admission
path: a deposit or delegation funded from carryover is bounded by size
(minimum, per-validator cap) and by nothing else. Two tests pin the decision
so it cannot be reverted silently:
`crates/bloch-pos-committee/src/staking.rs::carryover_liquid_balance_is_stakeable`
and
`crates/bloch-pos-committee/tests/committee.rs::carryover_liquid_balance_delegates_as_stake`.

What the decision does to the activation gates is arithmetic, and it should be
read before anyone quotes "year five" as a forecast.

**G1 (independent eligible stake ≥ 15% of circulating) — the conserved-share
bound.** Rewards are pro-rata to stake (§6.3), so compounding preserves stake
*shares*: if the founder stakes the carried-over balance and re-stakes rewards
like everyone else, the independent share of active stake stays where it
started —

    227,709,400 / 17,970,880,000 = 6.03%

— at every horizon. Active stake can never exceed circulating supply, so
independent stake can never exceed 6.03% of circulating either: **under this
scenario G1 is not late, it is unreachable** — not at year five, not at year
forty — from emission alone. (The 1% per-validator cap and the genesis-cohort
cap do redirect rewards away from over-cap stake, but both are Sybil-bypassable
by splitting, per their own documentation, so share conservation is the
conservative assumption.) The only thing that moves G1 is coins changing
hands.

**The same bound if the founder abstains.** If the carried-over founder
balance stays out of stake — permitted to enter, voluntarily kept out — the
independents can capture the whole emission. Solving

    227,709,400 + E(t) = 0.15 × (23,970,850,000 + E(t) + U(t))

with year-one emission flow E(t) = 917,168,074·t (the decay curve's first
year) and unlock flow U(t) = 315,000,000·t (the marketing tranche; VC and team
are inside their cliffs) gives t ≈ 0.72 years — the earliest arithmetic G1
crossing is **about month 9**. That is a bound, not a forecast: the genesis
cohort is founder-operated and earns much of the early emission, so the
realistic date is later. But it is measured in months, not in five years.

**G2 (largest entity < 25% of active stake).** Measured against *active*
stake, staking the carryover is strictly worse than the 70.4%-of-circulating
figure above: at genesis the founder would hold 16,886,549,523 of 17,970,880,000
staked — **94.0% of active stake**, a Nakamoto coefficient of 1. Under
conserved shares that figure does not decay either.

The honest summary. The decision removes the last consensus-enforced
distinction between the founder's coins and anyone else's, and in exchange the
gates stop being a schedule and become a measurement of behaviour: whether
G1–G4 are met before year five — or ever — is now decided by whether the
founder's carryover stakes and whether coins actually distribute, and
consensus constrains neither. That is the same trade §3.3.1 made for the
genesis cohort: the enforceable part is real and bounded, and the rest is a
public commitment verified by measurement, not a rule.

---

## 5. What this does to the concentration problem

This section argued that the relaunch was the strongest answer to the
concentration objection. Two later decisions changed the answer, and both
weakened it — so the honest version replaces the argument rather than restating
it.

The PoS migration design opens (§0.1) with the objection that ~94% of supply
sits at one address, so stake-weighted consensus would hand the chain to the
founder. Where V4 now lands:

| | Genesis-3 today | V4 at genesis | V4 at year 50 |
|---|---:|---:|---:|
| Founder — spendable | 94.3% | **16.89%** (carryover, liquid) | 26.89% |
| Founder — locked | — | 10.00% (10-yr cliff, 40-yr vest) | 0% |
| Insiders total | 94.3% | 25.0% liquid (Foundation) + 16.89% | 55.97% |
| Validators (earned) | — | 0%, growing | 43.03% |

An earlier draft cliffed the founder's whole position and could claim **no
spendable founder stake at genesis** — a consensus-enforced answer, and a much
stronger one than this. Carrying the balance across liquid gave it up: the
founder holds 16.89% of supply, spendable from slot 0, and 70.4% of what is
actually circulating then.

What remains true is narrower and still worth something. The relaunch takes the
founder from 94.3% of supply to 16.89% spendable, which is a 5.6× reduction in
concentration that no amount of coin-marking on the live chain could have
achieved. And the new grant carries the strictest schedule on the chain — ten
years locked, forty vesting, fully vested at year 50.


---

## 6. Emission

- Validator allocation: **43,029,120,000 BLCH** over **40 years**.
- At 30 s slots: 42,076,800 slots in 40 years.
- **Average 1,022 BLCH per block.**

### 6.1 Curve — decided: 10% annual disinflation

Founder constraint: **annual inflation under 7%**. Combined with the
decentralisation requirement from §7A, that pins the curve almost exactly.

| Curve | Year-1 inflation | Decentralisation gate |
|---|---:|---|
| Flat, 1,022 BLCH/block | 1.08% | **Fails** — validators never outpace insider unlocks |
| Halving every 4 years | 5.38% | Passes, but revenue halves on scheduled dates |
| Decay, 8%/year decline | 3.56% | **Fails at month 36** — too flat |
| **Decay, 10%/year decline** | **4.37%** | **Passes** |
| Decay, 12%/year decline | 5.19% | Passes, but the shape, not the ceiling, is what rules it out |

**Adopted: reward declines 10% per year**, constant within each year, summing
to exactly the 43,029,120,000 allocation across 40 years.

| Year | BLCH/block | Inflation (of total supply) |
|---:|---:|---:|
| 1 | 4,151.90 | 4.37% |
| 5 | 2,724.05 | 2.87% |
| 10 | 1,608.52 | 1.69% |
| 20 | 560.86 | 0.59% |
| 40 | 68.19 | 0.07% |

Truncation residual across the whole 40-year schedule: **889,200 sat
(0.0089 BLCH)** — under the allocation, never over.

**The denominator is load-bearing.** These figures are issuance over **total
supply**, which is how Solana and Ethereum report inflation. Measured against
*circulating* supply the same curve reads over 100% in year one — not because
issuance is high, but because almost every allocation is still vesting at
genesis, so the float is only ~6.3 B. Any public figure must say which
denominator it uses.

A hard 7%-of-*circulating* rule was modelled and rejected: it emits only 0.44 B
in year 1 and 6.65 B by year 5, so validators never outpace the insider unlock
schedule, and the concentration gate fails outright.

### 6.2 Why not a halving

Neither Ethereum nor Solana has one — halving is essentially a Bitcoin
convention. Ethereum's issuance is dynamic (it scales with total ETH staked,
with base fees burned on top, so net issuance can go negative); Solana runs
smooth disinflation, 8% initial declining 15%/year to a 1.5% floor. The curve
adopted here is the Solana shape adapted to a hard cap: no floor, no tail, the
schedule simply ends.

Beyond convention, a halving is a scheduled date on which every validator's
revenue drops by half at once, and marginal operators exit together. Continuous
decay has no such edges — the same reasoning that put founder vesting on a
per-slot line rather than monthly tranches.

**Hard cap — a reversal worth recording.** The current design is explicitly
*not* hard-capped: `tokenomics_v2.rs` runs a perpetual 100 BLCH tail
(Monero-style), and ADR-035 lowered that floor to 60. V4 replaces it with a
fixed cap and a fee-only end state. That is a deliberate and defensible choice,
but it inherits the fee-only security-budget question: after year 40, the
entire cost of consensus must be covered by fee revenue, and if fees are thin
the validator set shrinks to whatever fees sustain. The tail existed to avoid
exactly that. The reversal should be recorded in an ADR that retracts the tail
rationale rather than silently superseding it.

---

## 6.3 Validator revenue — Solana model

Adopted: validator revenue mirrors Solana's, which has three parts.

| Stream | Rule | Note |
|---|---|---|
| **Inflation rewards** | Pro-rata to **all active stake**, scaled by attestation credits earned; validator takes a **commission** on delegated stake only | Producing blocks is not how you get paid — being staked behind a performing validator is |
| **Base fee** | **50% burned**, 50% to the block producer | Solana's split |
| **Priority fee** | **100% to the block producer** | Solana moved from 50/50 to 100% with SIMD-0096 |

Commission is uncapped by consensus (Solana allows 0–100%; single digits in
practice). A cap is trivially evaded by an operator running its own delegation
front-end, so the rule is disclosure rather than limitation: wallets and the
explorer must surface the rate prominently.

**Yield versus inflation.** These are different numbers and both get quoted. At
year-1 issuance with two thirds of supply staked — Solana's rough ratio — the
nominal staking yield is **6.55%**, against **4.37%** inflation. A staker's
real position is what remains after dilution; a non-staker is diluted by the
full 4.37%.

For reference, Bloch's year-1 inflation of 4.37% sits just below Solana's
current 5.5–5.9%.

### 6.3.1 Delegation — implemented (`crates/bloch-pos-committee/src/delegation.rs`)

Commission is meaningless without delegated stake, and pro-rata-to-all-stake
rewards only make sense if stake can sit behind an operator without running
one. **The Solana revenue model cannot be adopted without adding delegation**,
which the PoS design does not currently have: validators deposit directly with
a 25,000 BLCH minimum.

Four rules make delegation safe to add:

| Rule | Value | Why |
|---|---|---|
| Warm-up / cool-down rate limit | `WARMUP_RATE_BPS` = 25 bps (0.25%) of active stake per epoch, floor `MIN_CHURN_SAT` | Committees are stake-weighted, so instant activation is instant control. Was 9% (Solana's numeral) until 2026-08-11; a Solana epoch is ~48 h and a Bloch epoch 16 min, so the same rate ran ~180x faster in wall-clock time — zero to a stalling third in 75 minutes. See `BLOCH-POS-STAKE-CHURN.md` |
| Delegated stake counts toward the per-validator cap | 1% of active stake | Delegation must not be a route around §4.1 |
| Delegators are exposed to slashing | pro-rata | Otherwise delegation is all yield and no risk, and nobody cares who they delegate to |
| Tainted coins cannot delegate | — | §4.1 follows coins, not accounts; otherwise delegation launders eligibility |

Two implementation findings worth recording, because both were wrong in the
first cut:

- **The cap must be resolved by fixed-point iteration, not measured against the
  uncapped total.** Against the uncapped total, an operator holding 90% of raw
  stake among a hundred is clamped to 9.99M versus 1M for everyone else — still
  ten times any peer, 9.2% of effective weight, present in over half of all
  committees. The cap's strength degrades exactly as concentration rises, which
  is when it is needed. Iterating to a fixed point clamps that same operator to
  1.0%, level with a normal validator: a ninefold improvement. The iteration is
  safe to specify — clamping only lowers the total, which only lowers the cap,
  so it is monotone and converges — and the round count is fixed so every node
  stops at the same number.
- **The rate limit needs a liveness escape — and the first one was a hole.** A
  strict budget deadlocks forever on any single delegation larger than the
  budget, which on a young network is most of them, and deadlocks at genesis
  where active stake is zero. The first fix let the head of the queue through
  **whole, whatever its size**, which bought liveness by selling the cap: one
  large delegation activated entirely in a single epoch, exactly the "instant
  activation is instant control" the limit exists to stop. It is now **partial
  activation** — an oversized delegation enters in slices across epochs, so the
  cap holds absolutely — plus a genesis exemption and the `MIN_CHURN_SAT` floor
  that guarantees a drain terminates (a budget proportional to a shrinking total
  decays geometrically and never reaches zero).

**Decentralisation cuts both ways**, and this is now measurable rather than
asserted: `Registry::top_share_bps` and `Registry::nakamoto_coefficient` compute
gates G2 and G3 directly from the delegation set, closing the gap §7A left open.
The Nakamoto coefficient is computed at the **one-third** threshold — the point
at which a two-thirds quorum can be stalled — not one half, which would flatter
the figure.

The honest limit: those metrics see the *operator* view, which is what consensus
sees. They cannot see one beneficial owner standing behind several delegators,
and no on-chain metric can.

#### What a delegator risks — read this before delegating

"Exposed to slashing, pro-rata" (rule 3 above) is not an abstraction. Wired
end-to-end in the state transition
(`transition.rs::apply_slashing_evidence` → `slashing.rs` → `delegation.rs::apply_slash`),
it means concretely:

- **If your operator provably equivocates — two signed headers for one slot,
  a double vote, or a surround vote — you lose coins**, in the same
  proportion as the operator's own bond. The base rate is
  `SLASH_PROPOSER_EQUIV_BPS` / `SLASH_SURROUND_VOTE_BPS` (slashing.rs); when
  many validators are slashed inside one `CORRELATION_WINDOW_EPOCHS` window
  the rate is amplified by `CORRELATION_MULTIPLIER` up to **the entire
  delegated amount** — coordinated attacks are priced to forfeit everything,
  and your coins sit in that blast radius if you delegated to a participant.
- **The loss applies to bonded coins in every lifecycle state except
  withdrawn.** A delegation still warming up, or draining through cool-down,
  is still bonded and still slashable. Only stake that has completed
  cool-down before the evidence lands is out of reach — and cool-down takes
  `COOLDOWN_EPOCHS` plus the churn-limited drain, by design.
- **The loss is committed on-chain the moment the evidence transaction is
  included**, in a per-account ledger
  (`CommittedState::delegator_slash_loss_sat`); wallets net it out of your
  bonded amount at withdrawal. There is no appeal path: evidence is two
  signatures your operator provably made, re-verified by every node.
- **You are not punished for the operator's mere downtime** — an offline
  operator forfeits rewards (yours included), but only provable equivocation
  burns principal. Choosing an operator is therefore a real decision: the
  yield is priced by the risk that the operator's keys are mismanaged, and
  that risk is yours by rule 3, on purpose.

### 6.3.2 Fee policy — decided: two eras

| Era | Base fee | Priority fee |
|---|---|---|
| **During emission** (40 years) | 50% burned, 50% to producer | 100% to producer |
| **After emission** | **100% to producer, no burn** | 100% to producer |

The burn is the deflationary counterweight that gives the hard cap meaning
while new supply is still arriving. Once issuance stops, fees are the entire
security budget, and burning part of the only remaining revenue would shrink
the validator set for no gain. The switch is at exactly the slot emission
stops, so there is never a window with both issuance and a burn, nor one with
neither.

**Consequence for the supply figure — this changes what "100 billion" means.**
Burned fees are permanently destroyed, so total supply never reaches
100,000,000,000. The correct statement is:

> 100,000,000,000 BLCH is the **maximum ever issued**. Circulating supply
> settles at that figure minus everything burned during the 40-year emission
> era, and is fixed thereafter.

Any published supply number must use "maximum issued", not "total supply" —
the two diverge from the first burned fee onward, and the gap only grows.

**A cliff worth naming.** At the era boundary, validator revenue loses the
year-40 emission (85.10 BLCH/block) and gains only the other half of the base
fee. Unless fee revenue by year 40 is comparable to 85 BLCH/block, this is a
step down in validator income, and it is inherent to any hard cap rather than
to this fee policy — the perpetual tail in V2 existed precisely to avoid it.
Whether fee revenue reaches that level by year 40 is unknowable now; what is
knowable is that the chain should be monitoring the ratio long before it
matters.

---

## 7. Vesting — schedules and their basis

Schedules follow prevailing market practice for recent L1 launches.

| Bucket | Genesis | Cliff | Linear | Total | Market basis |
|---|---:|---:|---:|---:|---|
| Founder — new grant (10%) | 0% | **120 mo** (10 yr) | **480 mo** (40 yr) | 50 yr | The V2 premine schedule, restored. Far beyond any market benchmark and the strictest on the chain — deliberately, since the carried-over balance arrives liquid and this grant is the part that can still be made to wait |
| VC / hedge funds | 0% | **12 mo** | 24 mo | 3 yr | 12-month cliff is the standard among recent L1s (Sui Series A and B both cliff at 12 months); investor vests typically run 2–3 years |
| Team | 0% | **18 mo** | 36 mo | 4.5 yr | Institutional standard is 12-month cliff + 36-month linear; 18 months is "defensible and increasingly expected" where institutional investors participate, and it keeps the team cliff off the VC cliff month |
| Marketing | **25%** | — | 24 mo | 2 yr | Listing and launch spend is commonly unlocked at TGE for launch momentum; ongoing programmes vest over ~24–25 months |
| Liquidity | **100%** | — | — | — | Liquidity is conventionally 100% unlocked at TGE — vesting it defeats its purpose |
| Holders | **100%** | — | — | — | Founder decision: carried-over balances are not vested |

**Cliffs are staggered on purpose.** The most cited failure mode in vesting
design is the *cliff wall* — several buckets beginning to unlock in the same
month, concentrating sell pressure on one date. VC (12), team (18) and founder
(24) are six months apart, so unlocks arrive as a stream.

**Where this sits against peers.** Insider share here (founder + VC + team +
marketing = 41%) falls between Aptos (~32.5% team plus investors) and Celestia
(~53%). The VC allocation at 10% is below Sui's 14.1% for private investors.

---

## 7B. The four Foundation buckets, one by one

VC, team, marketing and liquidity are held by the Foundation
(`BLOCH-ENTITY-STRUCTURE.md` §3). Together they are **29,000,000,000 BLCH —
29.00% of supply**, of which **6,000,000,000 is liquid at genesis**.

### VC / crypto hedge funds — 10,000,000,000 (10.00%)

Sold to funds; the Foundation is the counterparty of the round. **Nothing is
liquid at genesis**: 12-month cliff, then 24 months linear, fully vested at
year 3. This is the allocation that makes the Phase-0 legal review blocking
rather than precautionary — selling to investors with a return expectation is
what moved BLCH toward the centre of the investment-contract test, and it is
why ADR-036 retracted the ownerless thesis.

### Development team — 10,000,000,000 (10.00%)

Held by the Foundation and granted to individuals; once granted, individuals
hold their own. **Nothing liquid at genesis**: 18-month cliff, then 36 months
linear, fully vested at year 4.5. The cliff sits 6 months after the VC cliff on
purpose — the *cliff wall*, several buckets unlocking in the same month, is the
most cited failure mode in vesting design, so VC (12), team (18) and founder
(120) never share a month.

### Marketing — 4,000,000,000 (4.00%)

**1,000,000,000 liquid at genesis** (25%), for listing fees and launch spend; the
remaining 630,000,000 vests linearly over 24 months. The split follows ordinary
practice: launch spend is immediate by nature, ongoing programmes are not.

### Liquidity — 5,000,000,000 (5.00%)

**100% liquid at genesis.** Deployed to exchange order books and AMM pools.
Vesting a liquidity bucket defeats the purpose of having one, so this is the one
allocation where full unlock is not a concession but the function.

### Consolidated

| Bucket | BLCH | Share | Liquid at genesis | Fully vested |
|---|---:|---:|---:|---|
| VC | 10,000,000,000 | 10.00% | 0 | year 3 |
| Team | 10,000,000,000 | 10.00% | 0 | year 4.5 |
| Marketing | 4,000,000,000 | 4.00% | 1,000,000,000 | year 2 |
| Liquidity | 5,000,000,000 | 5.00% | 5,000,000,000 | genesis |
| **Total** | **29,000,000,000** | **29.00%** | **6,000,000,000** | |

### The number worth noticing

Circulating supply at slot 0 is 23,970,850,000 BLCH — the carryover plus these
6,000,000,000. So the Foundation's liquid holding is **exactly 25.0% of
circulating at genesis**, sitting precisely on the G2 threshold, and the
carryover is the other 75.0%.

Two entities therefore account for the entire genesis float, and the
concentration gates cannot be met by either of them changing behaviour — only
by validator emission and independent stake diluting both. That is the same
conclusion §4A reaches from the carryover side, arrived at from the Foundation
side.

---

## 7A. The unlock model, run against the PoS gates

Modelling the schedules month by month, treating each bucket as a single
entity (worst case), against gate **G2 — no entity above 25% of active stake**:

**With the flat emission curve:**

| Month | Circulating (B) | Validators | Largest bucket | Insiders |
|---:|---:|---:|---:|---:|
| 6 | 7.7 | 8.7% | **64.8%** | 22.7% |
| 12 | 9.1 | 14.7% | **54.7%** | 27.3% |
| 24 | 18.7 | 14.4% | **26.8%** | 57.2% |
| 36 | 30.0 | 13.4% | **33.3%** | 68.9% |
| 60 | 41.1 | 16.3% | 24.3% | 70.8% |
| 120 | 56.3 | 23.8% | 24.1% | 66.8% |

**G2 fails for roughly the first five years, and insiders peak near 71% of
circulating supply.** The vesting schedule alone does not fix concentration —
it reschedules it. The cause is structural: insiders unlock 41 B over ~12 years
while validators earn only 1.34 B/year under a flat curve.

**With a front-loaded curve (halving every 4 years):**

| Month | Circulating (B) | Validators | Largest bucket | Insiders |
|---:|---:|---:|---:|---:|
| 6 | 10.4 | 32.3% | 48.0% | 16.8% |
| 12 | 14.5 | 46.3% | 34.4% | 17.2% |
| 24 | 29.4 | 45.7% | **17.0%** | 36.3% |
| 36 | 46.2 | 43.7% | **21.7%** | 44.8% |
| 60 | 64.6 | 46.8% | **15.5%** | 45.0% |
| 120 | 86.6 | 50.4% | **15.7%** | 43.4% |

Validators cross 45% of circulating supply inside two years, the largest bucket
stays under 25% from month 24 onward, and insiders peak near 45% rather than
71%. The only breaches are months 6 and 12 — and there the largest bucket is
**liquidity**, which disperses to traders and exchanges rather than acting as a
single entity.

**Conclusion: the emission curve, not the vesting schedule, is the lever that
decides whether PoS can ever activate.** Open decision #2 in §9 is therefore
not a free parameter — it is the most consequential number left in V4, and the
recommendation is a front-loaded curve.

Halving parameters, if adopted: initial reward **1,075 BLCH/block**, halving
every 4 years, 10 halvings across the 40-year window.

---

## 8. Engineering hazards

### 8.1 u64 headroom — must be addressed before any code lands

At 8 decimal places, 21 B BLCH is **2.1 × 10^18 satoshis — 54.21% of
`u64::MAX`**, and it fits inside the signed `int64` the Go SDK uses for
`Satoshis` (`sdk/go/models.go:16`).

An earlier draft put the supply at 100 B, which is 10^19 satoshis: **54.21% of
`u64::MAX`**, so the sum of two large balances approached the wrap point, and it
**overflowed `int64` by 8%**, silently turning Go SDK aggregates negative.
Returning to the V2 nominal removed both hazards at no cost — they were created
by the supply figure, not by the design.

The arithmetic stays `u128` regardless, because the danger was never the totals:
it is the **products**. A balance times a basis-point figure, or epoch issuance
times stake in the reward split, exceeds `u64` long before any balance does.

Options:

| Option | Effect | Cost |
|---|---|---|
| **Keep 8 decimals, move all accumulators to `u128`** (recommended) | Divisibility unchanged; overflow impossible in accounting paths | Audit of every summation over balances; `u64` stays for individual values |
| Reduce to 6 decimals | Supply becomes 0.54% of `u64::MAX` | Loses two orders of divisibility; changes every address/amount format |

Recommended: keep 8 decimals, `u128` for every accumulator, plus a
`const _: () = assert!(...)` pinning the invariant so a future supply change
cannot quietly re-enter the danger zone. This is the same discipline already
applied in `crates/bloch-pos-committee/src/sample.rs`, where cumulative stake is
`u128` for exactly this reason.

### 8.2 Genesis allocation outputs

Six allocations must appear in the genesis block as consensus-recognised
outputs with their unlock schedules enforced by consensus, not by promise —
the same standard §4.1 of the migration design applies to the old premine. A
vesting schedule that lives in a spreadsheet is not a vesting schedule.

---

## 9. Open decisions

1. ~~Vesting for VC, team, marketing, liquidity~~ — **decided**, §7.
2. ~~Emission curve~~ — **decided**: 10%/year smooth disinflation (§6.1).
3. Snapshot height, announced in advance (§3).
4. Confirmation of pro-rata scale-down for the over-cap case (§3).
5. Decimal places and the `u128` accumulator audit (§8.1).
6. ADR retracting the perpetual-tail rationale (§6).
7. ~~Delegation~~ — **implemented**, §6.3.1, with the concentration gates now
   computed from the delegation set.
8. ~~Fee burn versus "100% of fees"~~ — **decided**, §6.3.2.
9. ~~**Genesis validator set** — who operates them.~~ **Decided** (§3.3.1): the
   founder funds and operates the cohort, under a consensus-enforced cap that
   tapers to one third within a year.
10. ~~The VC allocation against the ownerless thesis~~ — **resolved**: the
   ownerless thesis is retracted and a Solana-style foundation adopted
   ([ADR-036](../adr/ADR-036-retract-ownerless-adopt-foundation.md)). What
   remains is execution: rewrite the public copy before any announcement, and
   treat the Phase 0 legal review as blocking rather than precautionary.
