<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — site copy

```
Document:  docs/site/COPY.md
Status:    DRAFT for founder review — not published
Created:   2026-08-12
Direction: scratchpad bloch-site.html (approved design preview)
Sources:   BLOCH-POS-SHA3-LATTICE-MIGRATION.md, BLOCH-TOKENOMICS-V4.md,
           COHERENCE-C1.md, COHERENCE-C1.1.md,
           FLEET-BRIEF-2026-08-11.md, FLEET-BRIEF-CERTIK-2026-08-12.md
```

Every block below is final English copy, ready to paste into the page named in
its heading. Anything in `{curly braces}` is a live value the page must fetch
or the publisher must fill at publish time — never hardcode a stale number.

---

## The copy rule (applies to every page, every sentence)

**Every claim ships with its cost.** If a sentence states a strength and no
sentence next to it states what that strength costs, the claim is not done. A
protocol page that only lists advantages is marketing, and an auditor will read
the page precisely for what it leaves out.

Banned everywhere on the site:

- Hype vocabulary: "excited", "thrilled", "revolutionary", "game-changing",
  "to the moon", "huge".
- Emoji.
- Any statement about the price, value, or investment merit of BLCH. Not
  softened versions either ("opportunity", "early", "upside").
- Any launch date for Genesis-4. There is none. If a date exists someday, it
  will appear here first, signed.
- The supply figure "100 billion" in any form. The published figure is
  100,000,000,000, marked *under review* (see Supply page note).
- Round numbers presented as measurements. Every figure is either **measured**
  (and says where and when) or **planned** (and says so).

---

# Page: Protocol

**Nav label:** Protocol
**Route:** `/protocol` (also serves as home)

## Hero

**Eyebrow:** Post-quantum layer one

**H1:** A chain built for after the qubit.

**Lede:**
Every signature that secures Bloch is lattice-based: ML-DSA-65 and
Falcon-1024, verified together, on every block. No elliptic curves anywhere on
the critical path — not in consensus, not in the shielded pool. The cost of
that sentence is real and stated on this page: signatures near 4.6 KB, no
hardware-wallet support, and finality measured in tens of minutes.

**Primary button:** Read the migration plan → `/migration`
**Secondary button:** Run a node → `/build`

## Status strip

Labels and sublabels; values live from `{rpc}` where marked.

- **Genesis-3 height:** `{height}` — *measured now*
- **Halts at:** 50,000 — *consensus rule; mining ends there*
- **Block time:** `{trailing_avg}` s — *trailing average*
- **Signature:** ML-DSA-65 ‖ Falcon-1024 — *both must verify*

## Section: Three commitments, and what each one costs

**Eyebrow:** What it is
**Intro line:**
Stated with the trade-off attached, because a protocol page that only lists
benefits is marketing.

### Card 1 — Signatures: Hybrid, not hedged

ML-DSA-65 and Falcon-1024 both have to verify — AND, not OR. Breaking one
lattice family is not enough to forge a Bloch signature.

**The cost:** ≈ 4.6 KB per signature against Bitcoin's 64 bytes, a 3,745-byte
public key, and no hardware wallet implements either scheme. Under proof of
stake, Falcon also moves from occasional offline signing to signing every slot
on an internet-facing machine — a materially harder side-channel target, and an
open review item, not a solved one.

### Card 2 — Privacy: Hash-based shielded pool

Coherence uses SHAKE-256 commitments and raw FRI-STARK proofs. No trusted
setup, no elliptic-curve ZK — the Groth16 proof-compression wrapper most STARK
stacks use is forbidden here because it would silently reintroduce a curve.

**The cost:** proofs run tens to hundreds of kilobytes, proving is not
practical on a phone, and the pool carries **no privacy claim until it is
independently audited**. Today value cannot yet enter or leave the pool at
all: the shield/unshield bridge is designed, not built.

### Card 3 — Consensus: Moving to proof of stake

Genesis-4 is a proof-of-stake chain: 30-second slots, 32-slot epochs, every
validator attesting once per epoch, Casper-style finality — all under the same
post-quantum signatures.

**The cost:** finality takes about 32 minutes, which is what a 4.6 KB
signature buys you; the proposer schedule is public a full epoch ahead
(no post-quantum VRF exists, so sortition cannot be private), which is a
known denial-of-service surface; and the validator set starts concentrated —
see the Supply page for the number, which we publish rather than wait to be
asked.

## Section: The parts in more detail

### Hashing

SHA3-256 and SHAKE-256, domain-separated per use, across block identity,
Merkle commitments, state and randomness. Grover's algorithm gives a quantum
attacker only a quadratic speedup against a hash — that is the strongest
post-quantum statement anyone can honestly make about any hash function, and
it is the one we make. SHA-256d survives only for verifying pre-halt history.

### Randomness

A hash-based commit-reveal beacon (RANDAO-style). Preimage binding gives the
uniqueness that lattice signatures cannot — an ML-DSA signature is randomized,
so hashing one would be grindable, and any chain that does that has a broken
beacon. **The cost:** a proposer can still bias the beacon by withholding its
reveal — one bit of influence per skipped slot, paid for by forfeiting that
slot's reward. Bounded, not eliminated.

### Finality

Two-round BFT finality over checkpoints, one per epoch, at a two-thirds stake
quorum. Deterministic — a finalized block does not reorganize without slashing
at least a third of stake. **The cost:** ≈ 32 minutes to finality, and the
quorum math is only as decentralized as the stake behind it, which at launch
is not decentralized at all (see Supply).

### The devnet disclaimer, verbatim

The proof-of-stake node exists and runs: it produces, attests and finalizes
across real processes. It has no transactions, no peer-to-peer stack and no
public RPC yet. It is a devnet. **There is no Genesis-4 launch date, and
anyone quoting one is guessing.**

### Audit status

No external audit has been performed on this codebase. A pre-audit dossier is
being prepared for a CertiK code audit; the dossier's rule is that a gap
stated by us is worth more than a gap found by them. The chain's own history
includes real consensus failures — including a 2026-08-08 divergence caused by
order-dependent difficulty validation — and the post-mortems are public in the
repository. We would rather you read them there than hear about them
elsewhere.

---

# Page: Migration

**Nav label:** Migration
**Route:** `/migration`

## Header

**Eyebrow:** Migration
**H2:** Genesis-3 ends. Genesis-4 starts from its snapshot.
**Intro:**
These are ordered steps, not a list — each one begins only when the one above
it has finished. Only the first two have dates. The rest do not, and this page
will not pretend otherwise.

## Phase 1 — Proof of work, running — LIVE

The chain produces blocks under SHA-256d with merged mining against Bitcoin.
Nothing about it changes until height 50,000.

## Phase 2 — Height 50,000: the chain halts

Blocks above height 50,000 are invalid. That is a consensus rule compiled into
every node — not a switch anyone throws, and not something a miner can opt out
of on the canonical chain.

**Mining revenue ends at that height. Permanently.** If you point hashrate at
Bloch, your income from it stops at block 50,000, and ASICs mining Bloch have
no further use on this chain. We are saying this plainly because it is the
kind of fact projects usually leave implicit until it lands on someone.

Two more honest costs of this step:

- The halt height was lowered from 50,000 to 50,000 on 2026-08-12. The notice
  period is therefore measured in **days, not months**. Holders lose nothing
  by short notice — balances are captured automatically — but miners planning
  around the earlier height lost planning time, and that is on us.
- Anyone who does not upgrade can keep mining past 50,000 **on a fork**. The
  canonical snapshot is fixed at 50,000. Coins mined past it on any fork are
  not in the snapshot and will not exist on Genesis-4.

A signed snapshot of every balance is taken at the halt height.

## Phase 3 — The gap: months with no chain

Between the halt and Genesis-4 there is no Bloch chain producing blocks.
Balances sit in the signed snapshot; the explorer keeps serving history. This
is the plan, not a failure — the time is for code review before a chain
restarts under different consensus.

**One consequence we state because almost nobody would:** once mining stops,
the halted chain's own history stops being trustworthy evidence. With no
ongoing hashrate defending it, rewriting proof-of-work history becomes cheap.
That is why **the canonical record of who owns what is the signed snapshot
artifact, not the chain** — its digest is published widely, and Genesis-4
embeds that digest in its genesis block. Verify the digest, not a chain
nobody is defending.

## Phase 4 — Genesis-4: proof of stake, from the snapshot

Balances carry across untouched, at full value, automatically.

**There is nothing for you to do.** No claim to file, no contract to
interact with, no wallet to connect, no deadline to meet, nothing to send
anyone.

> **Anyone who asks you to "migrate your tokens", "register for the
> snapshot", connect a wallet to a site, or send coins anywhere in order to
> "cross over" is stealing from you.** No exceptions. Postern Labs will never
> ask. If a message like that appears to come from us, it does not.

There is **no launch date** for Genesis-4. The interval is expected to be
months; it ends when review ends, and review is not on a clock. When a date
exists it will be announced here and signed.

## What carries and what does not

| Carries across | Does not carry across |
|---|---|
| Every balance in the height-50,000 snapshot, in full | Mining. There is no proof of work on Genesis-4 |
| The shielded pool's commitments and nullifiers, unbroken — a note shielded before the halt stays spendable after it, with no re-shielding (re-shielding would deanonymize the pool, so continuity here is a privacy requirement, not a convenience) | Coins mined on any post-50,000 fork |
| The hybrid signature scheme, unchanged | The pool, stratum endpoints and merged-mining infrastructure — decommissioned |
| Chain history, served read-only by the explorer | The 30-second block cadence as a probabilistic thing — replaced by slots and deterministic finality |

---

# Page: Supply

**Nav label:** Supply
**Route:** `/supply`

## Header

**Eyebrow:** Supply
**H2:** 100,000,000,000 BLCH, fixed — figure under review.
**Intro:**
Genesis-4 issues against a fixed total of 100,000,000,000 BLCH. **This figure
is under review**: a redenomination of the unit — same percentages for every
holder, more units per holder, economically a stock split and nothing else —
is under consideration and is currently blocked on an open integer-arithmetic
question in the implementation. Until that is resolved, 100,000,000,000 is the
only number this site publishes. If the figure changes, every allocation below
scales by the same factor and **nobody's share moves**. Any description of a
redenomination as "more money" is wrong, and you should distrust whoever
says it.

"Fixed" means: every node rejects any block whose cumulative issuance would
exceed the cap, and no mechanism inside the protocol — no vote, no key, no
governance path — can raise it. Stated at its true strength and no stronger:
a hard fork adopted by every operator can change any rule of any chain,
including this one. "Impossible to change" would be a lie; "no in-protocol
mechanism can change it" is the claim, and it is checkable in the source.

One more precision most projects skip: because a share of fees is burned
during the emission era, circulating supply never actually reaches the cap.
The correct sentence is "100,000,000,000 is the **maximum ever issued**", not
"the total supply" — the two diverge from the first burned fee onward.

## Allocation table

*All figures planned, from the Tokenomics V4 draft; parameters not frozen;
total under review as above.*

| Allocation | BLCH | Share | Unlock |
|---|---:|---:|---|
| Validator emission — 40 years | 43,029,120,000 | 43.03% | emitted per slot, declining 10%/year |
| Carried over from Genesis-3 | 17,970,880,000 | 17.97% | liquid at genesis |
| Founder — new grant | 10,000,000,000 | 10.00% | 10-year cliff, then 40-year linear vest |
| VC / crypto funds | 10,000,000,000 | 10.00% | 12-month cliff, then 24-month linear |
| Team | 10,000,000,000 | 10.00% | 18-month cliff, then 36-month linear |
| Liquidity | 5,000,000,000 | 5.00% | liquid at genesis |
| Marketing | 4,000,000,000 | 4.00% | 25% at genesis, remainder over 24 months |
| **Total** | **100,000,000,000** | **100.00%** | |

*Carryover figures were measured on a live node at height 43,172 (448,337
UTXOs across 15 addresses). The binding set is fixed by the signed snapshot at
height 50,000, so the final figures will differ slightly from these.*

## Card: Say it before you are asked — the supply is concentrated

**93.96% of the carried-over balance sits at one address: the founder's,
who mined it.** That is 16,886,549,523 of 17,970,880,000 BLCH measured at
height 43,172. Counting the new grant, the founder's total allocation is
26.89% of supply — 16.89% liquid at genesis plus 10% locked for a decade.

It is worse than that at the start, and here is the arithmetic rather than the
framing: at slot 0, circulating supply is about 5.03 billion BLCH (carryover
plus the liquid Foundation buckets), of which the founder's liquid balance is
**70.4%**. If the founder stakes that balance — which the rules permit —
it is **about 94% of active stake, a Nakamoto coefficient of 1**. For
reference, an exchange-listed token drew a centralization warning from CertiK
at a 39% holder ratio. There is no framing under which our number passes that
test, so we are not offering one.

What actually bounds it, and what each bound does *not* reach:

- **The genesis validator cohort is founder-operated by construction** (there
  is no one else at slot 0), and a consensus rule tapers its combined weight
  to one third within a year. One third is the threshold below which the
  founder cannot stall finality alone. It is the *liveness* threshold, not the
  *safety* one — it does not, by itself, stop anyone finalizing anything.
- **A 1% cap per validator and a churn limit of 0.25% of active stake per
  epoch** make any large move into consensus slow and visible for days before
  it lands. Both are honest about their limit: they bind addresses, and an
  owner willing to split stake across many addresses can route around them.
  No on-chain rule can see who stands behind an address, and any project
  claiming its protocol "solves" concentration is claiming exactly that.
- **Activation gates.** Genesis-4's own design gates full decentralization
  claims on measured thresholds — independent stake ≥ 15% of supply, no
  entity above 25% of active stake, Nakamoto coefficient ≥ 7. **None are met
  at launch.** And the arithmetic is published, not hidden: if the founder
  stakes the carried-over balance, pro-rata rewards preserve stake shares, so
  independent stake stays pinned near 6% — the 15% gate is then unreachable
  from emission alone, forever. It moves only if coins actually change hands.
  The gates are a measurement of behavior, not a schedule.

The honest summary: **the chain starts centralized, by construction, and the
published gates measure the distance from there.** Nothing on this page claims
otherwise.

## Section: What the relaunch does to existing holders

Your balance carries over in full — and your **relative** position changes,
because the supply around it grows. Non-founder Genesis-3 holders together
hold about 5.2% of today's network; after Genesis-4 issues its allocations,
the same coins are at most 0.3% of the network — roughly a **17× reduction in
relative share**. "Your balance is preserved" is true; said alone it would be
misleading, so here is both halves.

## Section: Emission

43,029,120,000 BLCH to validators over 40 years, declining 10% per year —
roughly 872 BLCH per block in year one, 14 by year 40. Year-one issuance is
4.37% of *total* supply.

**The denominator is load-bearing.** Measured against *circulating* supply at
genesis — which is small, because most allocations are vesting — the same
year-one issuance reads as over 100% inflation. Both numbers describe the
same curve. Any published inflation figure that does not name its denominator
is doing something to you.

After year 40, issuance ends and validators are paid entirely from fees.
**Named cost:** at that boundary, validator revenue steps down unless fee
revenue has grown to replace the final year's emission. Whether it will is
unknowable from here; a hard cap buys credibility of supply at the price of an
open question about the year-40 security budget, and we took that trade with
eyes open.

---

# Page: Explorer

**Nav label:** Explorer
**Route:** `/explorer` (links out to `blochl1.com`)

## Header

**Eyebrow:** Explorer
**H2:** Every block, every balance, and the seams left visible.

**Intro:**
The explorer at **blochl1.com** serves the Genesis-3 chain live: blocks,
transactions, addresses, the DAG structure, and the countdown to the terminal
height. After the halt at 50,000 it keeps running read-only, serving history.

## What to check with it

- Your balance, before and after the snapshot. What the snapshot contains is
  what the explorer shows at height 50,000 — if these ever disagree, the
  signed snapshot artifact wins, not the website.
- The terminal height approaching. Blocks stop at 50,000; the explorer will
  show exactly that, not an outage.
- Published digests. The snapshot digest and the carryover digest are
  reproducible from public data; the explorer links both.

## What the explorer is not

Stated because block explorers borrow more trust than they have earned:

- **It is not an authority.** It is a convenience service operated by Postern
  Labs — a single, centralized read path over the chain. The chain's rules are
  enforced by nodes, and the post-halt record is the signed snapshot artifact.
  Verify digests yourself; do not treat a webpage — including this one — as
  proof of anything.
- **It can be wrong.** Explorer-level aggregate figures have been wrong before
  (an earlier supply endpoint omitted the carried-over balance and
  understated supply by billions). Discrepancies get fixed and documented,
  but the correct posture toward any explorer, ours included, is trust in the
  chain, verification against the chain.
- **It goes stale by design.** After the halt there are no new blocks, so
  "live" data ends at 50,000. A Genesis-4 explorer requires a Genesis-4
  chain, which does not exist yet and has no date.

---

# Page: Brand

**Nav label:** Brand
**Route:** `/brand`

## Header

**Eyebrow:** Brand kit
**H2:** Bloch Protocol
**Intro:**
White ground, one accent spent deliberately, and a serif that signals a
project which publishes specifications rather than slogans. Everything here
may be used to write about Bloch without asking us; nothing here may be used
to imply we endorse what you wrote.

## Name

**Bloch Protocol.** Named for the Bloch sphere — the geometric representation
of a single qubit's state space. "Bloch" alone in running text after first
use; the ticker is **BLCH**. Do not write "Bloch coin", "Bloch token", or
"$BLCH" — the dollar-sign convention belongs to trading culture, and this site
does not speak it.

## Colors

- **Emerald** `#0E6E5A` — accent. Spent on actions and key data, nothing else.
- **Ink** `#0D1B17` — text.
- **Violet** `#4B3FA8` — quantum annotations only.
- **Amber** `#B4630F` — caution and cost callouts. Every "the cost:" line on
  this site is amber territory; that is deliberate.
- **Surface** `#F1F4F3` — section grounds.
- **Ground** `#FFFFFF` — page.

Dark-theme equivalents ship in the site tokens; both themes are first-class.

## Type

- **Display:** Charter (fallbacks: Bitstream Charter, Iowan Old Style,
  Source Serif Pro, Georgia) — a chain you can read the source of.
- **Body:** system sans, 17px, ~66-character measure — pages people finish.
- **Data:** monospace, tabular figures — `ML-DSA-65 ‖ Falcon-1024`,
  `height 50,000`.

## The logo

A circle for the Bloch sphere, a faint equator ellipse, and a state vector
with an emerald point. Keep the vector off vertical — a pure |0⟩ or |1⟩ is a
classical bit, and the entire point of the mark is superposition. Minimum
size 16 px; do not recolor, rotate, or attach it to price content.

## Voice — the part of the brand that is not decoration

**Every claim ships with its cost.** That is the house rule, and it is a
brand asset precisely because it is expensive to keep: the signatures card
must say "no hardware wallet implements either scheme", the consensus card
must say "the validator set starts concentrated", the supply page must lead
with the 94% figure. Copy that states a strength without its cost does not
ship, whoever wrote it.

Also binding: no hype, no emoji, no superlatives, no "excited to announce",
no promise of value, nothing that reads as investment advice, all public copy
in English. Figures are either measured (say where and when) or planned (say
so). The word "soon" is banned; a date exists or it does not.

---

# Page: Build

**Nav label:** Build
**Route:** `/build`

## Header

**Eyebrow:** Participate
**H2:** What running a validator will take — and what it will not get you.

## Card: Bond — planned

Minimum validator deposit: **25,000 BLCH** in the current draft, explicitly
under review — it may be lowered together with the supply-figure decision so
that the bond stays a comparable fraction of supply to Ethereum's 32 ETH.

A bond lowers who *may* validate. It does nothing about who *does* — the
active set at launch is founder-operated regardless of the bond, and no bond
parameter fixes that. Do not let anyone, including us, describe the bond as a
decentralization mechanism.

## Card: Delegation — planned. Read the risk before the yield.

Stake behind an operator without running hardware. The design is Solana-like:
rewards pro-rata to stake, operator takes a disclosed commission.

**And you share the operator's slashing risk, pro-rata. That exposure is the
point** — delegation without risk would make operator choice meaningless.
Concretely, in the current draft:

- If your operator provably equivocates — two signed blocks for one slot, a
  double vote, a surround vote — **you lose coins**, at the same rate as the
  operator's own bond (5% base), amplified up to the **entire delegated
  amount** when many validators are slashed in the same window. Coordinated
  attacks are priced to forfeit everything, and delegated coins sit inside
  that blast radius on purpose.
- Stake still warming up or cooling down is still slashable. Exit takes a
  cool-down plus a rate-limited drain measured in weeks, by design — that
  delay is the weak-subjectivity margin, not bureaucracy.
- Mere downtime costs you rewards, never principal. Only provable
  equivocation burns coins, and the evidence is two signatures re-verified by
  every node. There is no appeal path.
- Operator commission is disclosed, not capped — a cap is trivially evaded by
  an operator running its own delegation front-end, so the honest rule is
  disclosure.

## Card: The node today — not ready

The proof-of-stake node is a **devnet**. It produces, attests and finalizes
across real processes; it has no transactions, no peer-to-peer stack, and no
public RPC. You cannot stake today. You cannot run a mainnet validator today,
because there is no mainnet to validate.

**There is no Genesis-4 launch date. Anyone quoting one is guessing**, and
anyone selling you access, allocations, or "early validator slots" is lying —
validator entry, when it exists, is a permissionless deposit transaction, not
a sale.

## Section: The code

Everything is source-available under **AGPL-3.0-or-later** — the node, the
consensus crates, the specifications, and the post-mortems of our own
failures. The honest costs here too: this is a **single implementation**
(client diversity is a formally tracked gap, not an aspiration we forgot to
mention), written and reviewed by a small team, with **no external audit
completed**. Reproducible-build tooling exists because this project has
already once shipped a release binary that did not match what the fleet ran,
and we would rather institutionalize that lesson than hope you never find the
post-mortem. It is in the repository; read it.

If you build on Bloch: hold your work to the same copy rule. State what your
tool costs its users. We will link to projects that do and not to projects
that do not.

---

# Page: Docs

**Nav label:** Docs
**Route:** `/docs`

## Header

**Eyebrow:** Documentation
**H2:** The specifications are the product. Read them adversarially.
**Intro:**
Every document below is public, versioned, and licensed AGPL-3.0-or-later.
Status labels are real: DRAFT means parameters can change; nothing marked
DRAFT should be built against as if frozen. Several documents record
decisions we later reversed — the reversals are kept in the text, dated,
because a spec that hides its own history is advertising.

## Index

- **Migration to Proof of Stake (SHA-3 + Lattice)** — DRAFT. The complete
  Genesis-4 design: slots, finality, sortition, staking lifecycle, and the
  go/no-go gates. Opens with the design's single largest risk (stake
  concentration) rather than burying it, and states which gates are not met.
- **Tokenomics V4** — DRAFT, parameters not frozen. The 100,000,000,000
  allocation (figure under review), vesting, emission curve, and the measured
  concentration arithmetic — including the founder-unfavorable results, which
  are the part most worth reading.
- **Coherence C1 / C1.1** — RATIFIED formats. The shielded pool: SHAKE-256
  commitments and nullifiers, the spend statement, raw FRI-STARK proving, and
  the C1.1 nullifier-set commitment. Also states, in its own header: **no
  privacy claim until audited.**
- **Threat models** — the PoS threat models and the weak-subjectivity
  analysis: long-range attacks, sortition grinding, the public-schedule DoS
  surface, Falcon online-signing exposure. If you want to attack Bloch,
  start here; that is what these documents are for.
- **Post-mortems** — real failures on the running chain, written up:
  consensus divergence from order-dependent difficulty validation
  (2026-08-08), a network stall from a backfill flood, a release/fleet binary
  mismatch, and others. We publish these because a chain's failure record is
  the only part of its documentation you can be sure is true.
- **ADRs** — architecture decisions with their reversals intact, including
  ADR-036, which retracts the earlier "ownerless" positioning in favor of a
  foundation structure. What changed and why is recorded, not rewritten.

## Contribution note

Corrections are welcome and credited, including — especially — corrections
that make the project look worse. A finding you are unsure of, labeled
unsure, is worth more to us than a confident one that is wrong.

---

# Page section: Questions a skeptic would ask

**Placement:** bottom of `/docs`, linked from the footer of every page as
"Hard questions".
**Eyebrow:** No spin
**H2:** Questions a skeptic would ask, answered the way we answer auditors.

**Q: Who actually controls this chain?**
At launch: the founder, and it is not close. One address holds 93.96% of the
carried-over supply, about 70% of what circulates at genesis, and the genesis
validator cohort is founder-funded and founder-operated because at slot 0
there is nobody else. A consensus rule tapers the cohort's weight to one
third within a year, and published gates measure independent participation —
but the rules bind addresses, not people, and cannot see beneficial
ownership. Decentralization here is a measurable claim about the future, not
a description of the present. Anyone telling you otherwise about this chain —
or, frankly, about most young chains — is marketing.

**Q: So isn't proof of stake exactly the wrong choice for this distribution?**
It is the choice that makes the distribution matter most, yes — under PoW the
founder's coins were just coins; under PoS they are potential consensus
weight. The design's own migration document opens with this as its single
largest risk. The mitigations (cohort cap, 1% validator cap, churn limits,
activation gates) are real, bounded, and individually insufficient; the
published arithmetic shows that if the founder stakes the carried-over
balance, the independence gate is unreachable from emission alone. What
resolves it is coins changing hands, and nothing on-chain forces that. You
should weigh the chain accordingly.

**Q: Why should I believe the snapshot won't be manipulated?**
Don't believe — check. The snapshot is a deterministic function of public
chain state at height 50,000; anyone running a node can recompute it and
compare digests. The artifact is signed, its digest is published in multiple
venues, and Genesis-4's genesis block embeds it. The residual trust is real
and named: Postern operates the dominant infrastructure today, and between
halt and launch the old chain's history stops being self-defending — which is
exactly why the digest, not the chain, is the canonical record. If your
recomputation disagrees with our artifact, publish it; that is what the
review window is for.

**Q: Is BLCH a security?**
We do not know, and we will not pretend to. Honestly stated: staking rewards
paid to bonded holders, plus a planned allocation sold to funds, strengthen
an investment-contract reading compared to pure mined PoW — the project's own
internal documents say so in those words, and legal review is a blocking
gate for the migration, not a formality. What we can control: nothing on this
site is investment advice, nothing here promises value, and BLCH is presented
as what it is — the fee and staking asset of a post-quantum chain, whose
market price, if any, is not our subject.

**Q: You had Bitcoin's hashrate securing you via merged mining. Why throw
that away?**
Because we chose deterministic finality and an end to the emission race, and
that trade has a loser: merged mining was the cheapest real security Bloch
will ever have, and abandoning it also abandons the Bitcoin-miner community
we courted. We think the post-quantum-PoS position is worth more than
borrowed SHA-256d hashrate over the long run. That is a judgment, not a
theorem; the cost side of it is stated here so you can disagree with the
actual trade rather than a sanitized one.

**Q: When does Genesis-4 launch?**
There is no date. The gap between halt and launch is expected to be months
and ends when code review ends. Any date you see anywhere — a Telegram
message, a listing site, a "leak" — is fabricated. When a date exists it will
be published here, signed.

**Q: Will my hardware wallet work? Will MetaMask?**
No, and no. Ledger, Trezor and every mainstream hardware wallet sign
secp256k1/Ed25519; Bloch's base chain accepts only hybrid ML-DSA-65 ‖
Falcon-1024, which no hardware wallet implements — post-quantum hardware
signing is research-grade industry-wide, not a Bloch gap someone else has
closed. MetaMask speaks EVM and secp256k1; an EVM execution surface for Bloch
is in design and unshipped, and every option for it carries a real cost —
the obvious one (accepting secp256k1 accounts) would reintroduce exactly the
quantum-vulnerable path this project exists to remove. Until that is decided
and shipped: key management is software, and the keys are yours to secure.

**Q: Is the shielded pool private?**
Treat it as not private. The design has no trusted setup and no
elliptic-curve ZK, which we consider the right foundation — but the pool
carries **no privacy claim until an independent audit says otherwise**, and
that is printed in the specification itself, not just here. Today the
question is moot in practice: the value bridge into and out of the pool is
not built, so there is nothing you could shield yet. When there is, the
absence of an audit will still be stated wherever the feature is offered.

**Q: I mine Bloch. What happens to me?**
Your revenue ends at block 50,000, full stop. Coins you mined and hold at the
snapshot carry over in full and become liquid on Genesis-4 — mined coins are
treated identically to everyone else's, founder's included. Your hardware
does not carry over: Genesis-4 has no proof of work, and SHA-256d ASICs have
no role on it. If you keep mining past 50,000 you are mining a fork whose
coins will not exist in the snapshot. We also acknowledge the notice was
short — the halt height was lowered days before the event — and that this
cost miners planning time.

**Q: My balance is "preserved". What aren't you telling me?**
The other half of the sentence: preserved in absolute terms, diluted in
relative terms. Non-founder Genesis-3 holders go from about 5.2% of the old
network to at most 0.3% of the new one — roughly 17× less relative share —
because Genesis-4 issues new allocations around the carried balances. Both
halves are true; either alone would mislead. This is that rare table where
the founder's row and yours move the same direction: the founder's 94% of the
old supply becomes 26.89% of the new one.

**Q: Why is the total supply "under review"? That seems basic.**
Because the alternative was publishing a number with a known unresolved
defect behind it. A unit redenomination is under consideration; at one
candidate figure, supply in base units consumes enough of the 64-bit integer
range that balance sums approach overflow, and it exceeds the signed-64-bit
type one of our own SDKs uses. Until the arithmetic is closed — wider
accumulators audited end to end — the published figure stays 100,000,000,000.
A supply number is a consensus invariant; we would rather mark it "under
review" than revise it after the fact.

**Q: Has any of this been audited?**
No. No external audit has been completed on the node, the PoS crates, or the
shielded pool. A CertiK code audit is being prepared for, and the internal
rule for that preparation is that every gap goes in our dossier before their
report. Until an audit exists, the correct trust level for this codebase is
the one you would assign any unaudited consensus code: read it, or wait.

**Q: What has actually gone wrong so far?**
On the record, among others: a consensus divergence where identical binaries
disagreed because difficulty validation depended on local state
(2026-08-08); a network-wide production stall triggered by a peer flooding
old blocks; a published release binary that did not match what the fleet ran;
a block-identity keying bug that stalled tip selection. Each has a public
post-mortem, and several directly shaped the Genesis-4 design — the PoS state
model exists in its current form specifically because of the first one. A
project that cannot show you its failure list has one anyway; it is just
somewhere you cannot read it.

---

# Shared microcopy

## Footer (every page)

Postern Labs Ltda. Nothing on this site is investment advice, and no page
here will ever tell you BLCH is worth anything.

Code and documentation: AGPL-3.0-or-later.

Every figure on this site is either measured — and labelled with where and
when — or planned, and labelled as such.

Hard questions → `/docs#skeptic`

## Scam banner (site-wide, dismissible, reappears each session until Genesis-4)

There is no token migration. You never need to send coins, connect a wallet,
or register anywhere to keep your balance across Genesis-4. Anyone asking is
stealing.

## 404 page

No block at this height. The page you asked for does not exist — like blocks
above 50,000, this is by rule, not by accident. → Home

