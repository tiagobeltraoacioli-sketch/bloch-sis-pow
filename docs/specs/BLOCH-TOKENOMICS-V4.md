<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

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

Relaunch from a fresh genesis with a **fixed 100,000,000,000 BLCH** supply.
Balances held today by parties other than the founder are carried over in
**absolute** terms, capped at 300,000,000 BLCH. The founder's current holding is
not carried over; it is replaced by a new, vested 17% allocation.

| Destination | BLCH | Share | Unlock |
|---|---:|---:|---|
| Founder | 17,000,000,000 | 17.00% | 24-month cliff, then 120-month linear |
| VC / crypto hedge funds | 10,000,000,000 | 10.00% | 12-month cliff, then 24-month linear |
| Development team | 10,000,000,000 | 10.00% | 18-month cliff, then 36-month linear |
| Marketing | 4,000,000,000 | 4.00% | 25% at genesis, remainder linear over 24 months |
| Liquidity | 5,000,000,000 | 5.00% | 100% liquid at genesis |
| Carryover holders | ≤ 300,000,000 | ≤ 0.30% | 100% liquid at genesis, no vesting |
| **Validators** | **53,700,000,000** | **53.70%** | emitted over 40 years |
| **Total** | **100,000,000,000** | **100.00%** | |

Validator emission runs for 40 years and is supplemented by transaction fees.
**After the 100 B is fully emitted, validators are paid 100% from fees.**

---

## 2. What the carryover actually contains — measured

From `carryover.tsv.gz` (413,743 UTXOs, SHA-256 pinned in-repo), aggregated by
address hash. The set has exactly **five** addresses:

| Address hash | BLCH | Share of carryover | UTXOs |
|---|---:|---:|---:|
| `e986db51…` (founder) | 3,294,337,200 | 94.79% | 392,183 |
| `be7c81e1…` | 177,063,600 | 5.10% | 21,079 |
| `5b4a5303…` | 3,158,400 | 0.09% | 376 |
| `5b00d538…` | 470,400 | 0.01% | 56 |
| `5d493bc4…` | 411,600 | 0.01% | 49 |
| **Total** | **3,475,441,200** | 100% | 413,743 |

**Non-founder total: 181,104,000 BLCH — 5.21%.** The founder's "the 5% others
hold" is accurate to two significant figures.

That figure is the **floor**, not the final number: it covers only the
Genesis-1 carryover. Coins mined since Genesis-3 by third parties must be added
at snapshot time. The chain stands at height **40,144**, so 337,209,600 BLCH
have been emitted since Genesis-3 (40,144 × 8,400).

---

## 3. The 300 M cap is close to binding — and moving

Headroom against the measured carryover floor is 118,896,000 BLCH. But
third-party miners accrue continuously.

A measurement recorded at height 18,809 had non-founder holdings at ≈ 207 M
against a carryover floor of 181.1 M, implying roughly **16% of emission has
been going to third parties**. Carrying that rate forward:

| | |
|---|---|
| Estimated non-founder holdings at h40,144 | ≈ 236 M BLCH |
| Remaining headroom under the cap | ≈ 64 M BLCH |
| Third-party accrual at 8,400 BLCH/block, 2,880 blocks/day, ~16% share | ≈ 4.0 M BLCH/day |
| **Estimated time until the cap binds** | **≈ 2 weeks** |

The 16% figure is an estimate derived from a single prior measurement, not a
fresh audit — it should be re-measured against live balances before anything is
frozen. But the order of magnitude is the point: **the cap is not comfortable
headroom, it is a deadline.**

Two consequences that need a decision now:

1. **The snapshot height must be announced in advance and fixed.** Otherwise the
   cap creates an incentive to mine hard right before an unannounced snapshot,
   and the choice of height becomes a discretionary act that redistributes value
   between third parties.
2. **A rule is needed for the over-cap case.** The proposal here is
   **pro-rata scale-down**: if measured non-founder holdings exceed 300 M, every
   non-founder balance is multiplied by `300_000_000 / total_non_founder`. It is
   neutral, needs no discretion, and it is the only rule that treats a holder's
   position the same regardless of when they acquired it. A first-come or
   by-address cut would not.

---

## 4. What this does to existing holders

Stated plainly, because it affects parties who are not in the room:

| | Today | After V4 |
|---|---:|---:|
| Non-founder coins | 181.1 M (carryover) | ≤ 300 M |
| Non-founder **share of network** | 5.21% | **≤ 0.30%** |

Holders keep their coins in absolute terms and lose roughly **17×** of their
relative position. That is the arithmetic consequence of preserving absolute
balances while multiplying total supply by ~27× (3.475 B → 100 B). It is a
legitimate choice — it is what "preserved in absolute terms" means — but it
should be published in exactly these terms rather than as "your balance is
preserved", which is true and misleading at the same time.

---

## 5. What this does to the concentration problem

This is the strongest argument for the relaunch, and it is worth stating.

The PoS migration design opens (§0.1) with the objection that ~94% of supply
sits at one address, so stake-weighted consensus would hand the chain to the
founder. V4 changes that materially:

| | Today | V4 at genesis | V4 after founder vesting completes |
|---|---:|---:|---:|
| Founder | 94.3% | **0%** (2-year cliff) | 17% |
| Insiders total (founder + VC + team + marketing) | 94.3% | depends on §7 | 41% |
| Validators (earned) | — | grows to 53.7% | 53.7% |

With a 2-year cliff, the founder holds **no spendable stake at genesis**. That
is a genuine, consensus-enforceable answer to §0.1 — far stronger than the
taint-propagation machinery in §4.1 of the migration design, which exists
precisely because the current distribution could not be fixed any other way.

**But it depends entirely on §7.** If VC, team and marketing (24% combined)
unlock at or near genesis, the concentration problem returns in a different
costume: a 24% bloc against a validator allocation that starts at zero and
takes years to accumulate. The gates G1–G4 would fail on day one.

---

## 6. Emission

- Validator allocation: **53,700,000,000 BLCH** over **40 years**.
- At 30 s slots: 42,076,800 slots in 40 years.
- **Average 1,276 BLCH per block.**

### 6.1 Curve — decided: 10% annual disinflation

Founder constraint: **annual inflation under 7%**. Combined with the
decentralisation requirement from §7A, that pins the curve almost exactly.

| Curve | Year-1 inflation | Decentralisation gate |
|---|---:|---|
| Flat, 1,276 BLCH/block | 1.34% | **Fails** — validators never outpace insider unlocks |
| Halving every 4 years | 6.72% | Passes, but revenue halves on scheduled dates |
| Decay, 8%/year decline | 4.45% | **Fails at month 36** — too flat |
| **Decay, 10%/year decline** | **5.45%** | **Passes** |
| Decay, 12%/year decline | 6.48% | Passes, but close to the 7% ceiling |

**Adopted: reward declines 10% per year**, constant within each year, summing
to exactly the 53.7 B allocation across 40 years.

| Year | BLCH/block | Inflation (of total supply) |
|---:|---:|---:|
| 1 | 5,181.54 | 5.45% |
| 5 | 3,399.61 | 3.58% |
| 10 | 2,007.43 | 2.11% |
| 20 | 699.95 | 0.74% |
| 40 | 85.10 | 0.09% |

Truncation residual across the whole 40-year schedule: **67,200 sat
(0.000672 BLCH)** — under the allocation, never over.

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
nominal staking yield is **8.17%**, against **5.45%** inflation. A staker's
real position is what remains after dilution; a non-staker is diluted by the
full 5.45%.

For reference, Bloch's year-1 inflation of 5.45% lands almost exactly on
Solana's current 5.5–5.9%.

### 6.3.1 Delegation — implemented (`crates/bloch-pos-committee/src/delegation.rs`)

Commission is meaningless without delegated stake, and pro-rata-to-all-stake
rewards only make sense if stake can sit behind an operator without running
one. **The Solana revenue model cannot be adopted without adding delegation**,
which the PoS design does not currently have: validators deposit directly with
a 100,000 BLCH minimum.

Four rules make delegation safe to add:

| Rule | Value | Why |
|---|---|---|
| Warm-up / cool-down rate limit | 9% of active stake per epoch | Committees are stake-weighted, so instant activation is instant control. Matches Solana |
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
- **The rate limit needs a liveness escape.** A strict 9% budget deadlocks
  forever on any single delegation larger than 9% of active stake, which on a
  young network is most of them, and deadlocks at genesis where active stake is
  zero. Genesis is unlimited, and thereafter the head of the queue always
  progresses even if it exceeds the budget — bounding disruption to one record
  per epoch while guaranteeing the queue drains.

**Decentralisation cuts both ways**, and this is now measurable rather than
asserted: `Registry::top_share_bps` and `Registry::nakamoto_coefficient` compute
gates G2 and G3 directly from the delegation set, closing the gap §7A left open.
The Nakamoto coefficient is computed at the **one-third** threshold — the point
at which a two-thirds quorum can be stalled — not one half, which would flatter
the figure.

The honest limit: those metrics see the *operator* view, which is what consensus
sees. They cannot see one beneficial owner standing behind several delegators,
and no on-chain metric can.

### 6.3.2 Conflict to resolve: fee burn versus "100% of fees"

§1 states that after the 100 B is emitted, validators are paid **100% from
fees**. The Solana model **burns half the base fee**, so validators never
receive 100% of fees. The two statements cannot both hold as written.

Reconcilable options:

1. Burn during emission, stop burning when emission ends — honours both, at
   different times.
2. Never burn; 100% of all fees to producers — abandons the deflationary
   counterweight that makes the hard cap meaningful.
3. Always burn 50% of base fee — abandons the "100% of fees" statement.

This must be decided explicitly rather than settled by whichever document is
read last.

---

## 7. Vesting — schedules and their basis

Schedules follow prevailing market practice for recent L1 launches.

| Bucket | Genesis | Cliff | Linear | Total | Market basis |
|---|---:|---:|---:|---:|---|
| Founder | 0% | 24 mo | 120 mo | 12 yr | Far above market; a founder decision, not a benchmark |
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

Halving parameters, if adopted: initial reward **6,387 BLCH/block**, halving
every 4 years, 10 halvings across the 40-year window, final period 6.24
BLCH/block, truncation residual under 0.2 BLCH over the whole schedule.

---

## 8. Engineering hazards

### 8.1 u64 headroom — must be addressed before any code lands

At 8 decimal places, 100 B BLCH is **10^19 satoshis, which is 54.21% of
`u64::MAX`**. Today's 21 B nominal is 11.38%.

The supply itself fits. The danger is that **any addition of two large values
overflows**: a supply-accounting check, a treasury-plus-allocation comparison,
a sum over a large UTXO set. In debug builds that panics; in release builds it
wraps silently, and a silently wrapped consensus value is a chain split.

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
7. **Delegation** (§6.3.1) — required by the Solana revenue model, absent from
   the current PoS design, and not yet reflected in the concentration model.
8. **Fee burn versus "100% of fees" after emission** (§6.3.2).
9. **The VC allocation against the ownerless thesis.** ADR-033 restored an
   ownerless position; ADR-034 records a founder anonymisation/relinquishment
   pact; the public posture is a civic node movement, "coins don't vote", not a
   security. A 10% allocation sold to funds introduces investors with a return
   expectation and, in practice, an issuer. That is a coherent thing to want,
   but it cannot coexist unstated with the current public documents — one of the
   two has to be retracted, in writing, before either is published.
