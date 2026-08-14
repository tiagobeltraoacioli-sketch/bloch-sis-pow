<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — site copy

```
Document:  docs/site/COPY.md
Status:    DRAFT for founder review — not published
Created:   2026-08-12 (before the halt)
Revised:   2026-08-14 — Genesis-3 halted at height 39,918 on 2026-08-13 and
           Genesis-4 went live under proof of stake at 21:31:19 UTC the same
           day. Copy written before that date described a migration as
           forthcoming; it has happened.
Direction: scratchpad bloch-site.html (approved design preview)
Sources:   crates/bloch-pos-committee/src/tokenomics_v4.rs and params.rs
           (authoritative for every number),
           BLOCH-POS-SHA3-LATTICE-MIGRATION.md, COHERENCE-C1.md,
           docs/GENESIS4-MIGRATION-RUNBOOK.md
```

Every block below is final English copy, ready to paste into the page named in
its heading. Anything in `{curly braces}` is a live value the page must fetch
or the publisher must fill at publish time — never hardcode a stale number.

> **Publisher's note — the facts this copy now rests on.** Genesis-4 is **live**,
> under **proof of stake**, since 21:31:19 UTC on 2026-08-13: 30 s slots,
> 32-slot epochs, 128-validator committees, Casper-style justification and
> finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024 on every consensus path.
> Genesis-3, the proof-of-work chain, **stopped permanently at chain height
> 39,918** — *not* at the 50,000 ceiling earlier copy quoted, because it was
> stopped rather than left to reach it. Public read RPC:
> `https://posternlabs.com/g4rpc`.
>
> Three consequences for anyone editing this file:
> 1. **No page may address miners as a current audience.** There is no mining on
>    Genesis-4 and no hashrate to point anywhere.
> 2. **Never state a settlement rule in confirmations.** Genesis-4 has no
>    confirmation count. The rule is finality.
> 3. **The concentration figures below are final, not provisional.** The
>    "under review" flag on the supply is retired.

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
- Any *future* launch date for Genesis-4. It launched at 21:31:19 UTC on
  2026-08-13; that timestamp is a fact and may be stated. Anything framed as an
  upcoming launch, or as a date for staking or validator entry opening, may not.
- The supply figure "100 billion" written as prose. Always the digits:
  100,000,000,000. It is final and is no longer marked under review.
- Any settlement instruction phrased in confirmations or block depth. Genesis-4
  has no confirmation count; the rule is the `finalized` boolean.
- Any copy addressing miners as a current audience, or any mention of hashrate,
  difficulty, ASICs, stratum or pools as live infrastructure. All of that ended
  with Genesis-3 on 2026-08-13 and may only appear in the past tense.
- The word "devnet" applied to the chain, the network, the binary or the stage.
  It is a mainnet. "Devnet" is correct **only** as the name of the transport
  (`Transport::Devnet`), and if you use it that way you must say what it is: a
  point-to-point TCP full mesh with a fixed peer list, no discovery and no
  authentication.
- The word "signed" applied to the carryover snapshot. It is hash-committed and
  independently reproducible. There is no signing mechanism.
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

- **Genesis-4 slot:** `{slot}` — *measured now*
- **Finalized height:** `{finalized_height}` — *the settled line; not `height`*
- **Slot time:** 30 s — *fixed; not an average*
- **Signature:** ML-DSA-65 ‖ Falcon-1024 — *both must verify*

Second row, static:

- **Genesis-3 stopped at:** 39,918 — *2026-08-13; proof of work ended there*

> **Publisher's rule for this strip**, from BRAND-KIT §"Status strip": every
> figure is either measured and labelled as such, or planned and labelled as
> such. `{slot}` and `{finalized_height}` come live from
> `https://posternlabs.com/g4rpc` via `getchaininfo`. Do not hardcode them.
> **Do not show `height` on its own** — under proof of stake it is the number
> that is *not* the guarantee.

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

### Card 3 — Consensus: Proof of stake, live

Genesis-4 is a proof-of-stake chain and has been running since 21:31:19 UTC on
2026-08-13: 30-second slots, 32-slot epochs, 128-validator committees, every
validator attesting once per epoch, Casper-style finality — all under the same
post-quantum signatures. Proof of work ended with Genesis-3 at height 39,918.

**The cost:** finality takes about 32 minutes, which is what a 4.6 KB
signature buys you; the proposer schedule is public a full epoch ahead
(no post-quantum VRF exists, so sortition cannot be private), which is a
known denial-of-service surface; and **the validator set is concentrated —
all 64 validators are run by one entity, so one operator can halt the chain.**
See the Supply page for the holdings figure, which we publish rather than wait
to be asked.

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
at least a third of stake. **The cost:** ≈ 32 minutes to finality (≈ 48 in the
worst case, for a block early in an epoch), and the quorum math is only as
decentralized as the stake behind it, which today is not decentralized at all
(see Supply).

**There is no confirmation count on this chain, and asking for one is the wrong
question.** Depth is not security where there is no difficulty: nothing prices a
reorg in work. Every block the node returns carries a `finalized` boolean, and
that boolean is the entire settlement rule. Waiting further blocks past
finalisation buys nothing.

### The limitation disclaimer, verbatim

The proof-of-stake node runs on mainnet: 64 validators producing, attesting,
justifying and finalizing, with a JSON-RPC server, real transfers, and
persistence that replays deterministically on restart. Read it yourself at
`https://posternlabs.com/g4rpc`.

**What you still cannot do, stated plainly.** You cannot join this network, and
you cannot stake. The live transport is a point-to-point TCP full mesh with a
fixed peer list, no discovery and no authentication — there is no way to dial
in. And deposit and delegation transactions are refused at every node's mempool,
because bonding is not yet funded from the UTXO set. Transfers work; becoming a
validator does not. **Anyone selling you access, allocations, or "early
validator slots" is lying — there is nothing to sell.**

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
**H2:** Genesis-3 ended. Genesis-4 runs from its snapshot.
**Intro:**
This migration has happened. It is written up as ordered steps because that is
how it ran, and because the last step is the one still in progress. Every date
below is a date, not a projection.

## Phase 1 — Proof of work — ENDED 2026-08-13

Genesis-3 produced blocks under SHA-256d, merged-mined against Bitcoin, from
its genesis until 2026-08-13. That is the entire proof-of-work history of this
project, and it is finished.

## Phase 2 — Chain height 39,918: the chain stopped — DONE

Genesis-3 stopped permanently at **chain height 39,918** on 2026-08-13. It
produces no further blocks.

Note the number, because earlier versions of this page said 50,000. A terminal
height of 50,000 was compiled into the nodes, but the chain was **stopped
before it got there** — so the coins between 39,918 and that ceiling were never
minted, and 39,918 is the real, measured end. Two different counts describe
that moment and they are not the same thing: the **chain height was 39,918**
and the **DAG block count was 50,690**. Genesis-3 was a DAG, so it always had
more blocks than the selected chain was tall.

**Mining revenue ended there. Permanently.** There is no proof of work on
Genesis-4, SHA-256d ASICs have no role on it, and no hashrate points anywhere
useful. Anyone who kept mining past the halt was mining a fork whose coins are
not in the snapshot and do not exist on Genesis-4.

The honest cost of how this ran, which we are not going to quietly drop now
that it is over: the halt height was lowered from 80,000 to 50,000 on
2026-08-12, and the chain was then stopped at 39,918. Notice to miners was
measured in **days, not months**. Holders lost nothing — balances were captured
automatically — but anyone planning around the earlier height lost planning
time, and that was on us.

A snapshot of every balance was taken at the halt: **452,726 outputs,
18,146,400,000 BLCH after the ×100/21 redenomination**, from a Genesis-3 total
of 3,810,744,000 BLCH.

## Phase 3 — The handover — DONE, same day

There was no months-long gap. Genesis-4 started at **21:31:19 UTC on
2026-08-13**, hours after the halt.

**One consequence we state because almost nobody would:** now that mining has
stopped, the halted chain's own history is no longer self-defending. With no
hashrate behind it, rewriting Genesis-3's proof-of-work history is cheap. That
is why **the canonical record of who owns what is the snapshot artifact, not
the old chain** — its digest is published, and Genesis-4 embeds it in its
genesis. Verify the digest, not a chain nobody is defending.

Two precisions on that artifact, because the word "signed" was used loosely in
earlier copy: **the snapshot is hash-committed, not cryptographically signed.**
There is no signing mechanism. Its integrity rests on **independent
reproduction** — anyone with an archive node can rebuild it and compare roots,
and agreement across independent parties is the evidence. One tool agreeing
with itself proves nothing.

## Phase 4 — Genesis-4: proof of stake, running

Balances carried across untouched, at full value, automatically. This is done.

**There was nothing for you to do, and there still is not.** No claim to file,
no contract to interact with, no wallet to connect, no deadline to meet,
nothing to send anyone.

> **Anyone who asks you to "migrate your tokens", "register for the
> snapshot", connect a wallet to a site, or send coins anywhere in order to
> "cross over" is stealing from you.** No exceptions. Postern Labs will never
> ask. If a message like that appears to come from us, it does not.

**What is still in progress**, so nobody reads "live" as "finished": you cannot
yet run a Genesis-4 node or stake. The transport has a fixed peer list and no
discovery, and deposit and delegation transactions are refused at every node's
mempool because bonding is not yet funded from the UTXO set. Read access is
open at `https://posternlabs.com/g4rpc`.

## What carries and what does not

| Carried across | Did not carry across |
|---|---|
| Every balance in the height-39,918 snapshot, in full — 452,726 outputs, 18,146,400,000 BLCH after the split | Mining. There is no proof of work on Genesis-4 |
| The shielded pool's commitments and nullifiers, unbroken — a note shielded before the halt stays spendable after it, with no re-shielding (re-shielding would deanonymize the pool, so continuity here is a privacy requirement, not a convenience) | Coins mined on any post-halt fork |
| The hybrid signature scheme, unchanged — ML-DSA-65 ‖ Falcon-1024, both must verify | The pool, stratum endpoints and merged-mining infrastructure — decommissioned |
| Addresses and key material, unchanged — the same address holds the same coins | GhostDAG, blue_score, difficulty and retargeting — Genesis-4 is a linear chain with fixed 30 s slots |
| Genesis-3 chain history, served read-only for provenance | Confirmation depth as a settlement rule — replaced by finality, which is a different kind of claim, not a bigger number |

---

# Page: Supply

**Nav label:** Supply
**Route:** `/supply`

## Header

**Eyebrow:** Supply
**H2:** 100,000,000,000 BLCH, fixed.
**Intro:**
Genesis-4 issues against a fixed total of 100,000,000,000 BLCH. **This figure
is final.** It was reached by redenominating the unit at the relaunch — the
same percentages for every holder, more units per holder, economically a stock
split and nothing else. Every allocation below scaled by the same factor and
**nobody's share moved**. Any description of that redenomination as "more
money" is wrong, and you should distrust whoever says it. An earlier version of
this page carried an "under review" flag on the total; that review is closed.

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

*Final figures, from `crates/bloch-pos-committee/src/tokenomics_v4.rs`. The
carryover row is a measurement taken at the halt, not an estimate.*

| Allocation | BLCH | Share | Unlock |
|---|---:|---:|---|
| Validator emission — 40 years | 42,853,600,000 | 42.85% | emitted per slot over 40 years; **unissued at genesis** |
| Carried over from Genesis-3 | 18,146,400,000 | 18.15% | liquid at genesis |
| Founder — new grant | 10,000,000,000 | 10.00% | 10-year cliff, then 40-year linear vest |
| VC / crypto funds | 10,000,000,000 | 10.00% | 12-month cliff, then 24-month linear |
| Team | 10,000,000,000 | 10.00% | 18-month cliff, then 36-month linear |
| Liquidity | 5,000,000,000 | 5.00% | liquid at genesis |
| Marketing | 4,000,000,000 | 4.00% | 25% at genesis, remainder over 24 months |
| **Total** | **100,000,000,000** | **100.00%** | |

**Issued at slot 0: 57,146,400,000 BLCH** — everything above except the
validator emission, which is the unissued remainder.

*The carryover was measured at the halt: Genesis-3 chain height **39,918**,
across **452,726 outputs**, totalling 3,810,744,000 BLCH on the Genesis-3 side,
which is 18,146,400,000 after the ×100/21 redenomination — exactly, with no
aggregate dust. These are final.*

> **On an earlier number you may have seen.** This page previously published
> 17,970,880,000 BLCH "measured at height 43,172 (448,337 UTXOs)". Both parts
> were wrong, and we would rather correct them in public than quietly swap
> them. The total was a provisional pre-halt reading that grew with every
> subsequent block. And **43,172 was never a height — it was a block count.**
> Genesis-3 was a DAG, so it always had more blocks than the selected chain was
> tall; the chain was never 43,172 blocks tall, and anyone trying to reproduce
> the measurement "at height 43,172" would have been waiting for a height that
> yields a different number. The two measurements are now always stated
> separately: at the halt the **chain height was 39,918** and the **DAG block
> count was 50,690**.

## Card: Say it before you are asked — the supply is concentrated

**93.94% of the carried-over balance sits at one address: the founder's, who
mined it.** That is 17,046,829,380 of 18,146,400,000 BLCH, measured at the halt
at Genesis-3 height 39,918. Counting the new grant, the founder's total
holding is **27.04% of supply** — 27,046,829,380 BLCH, pinned by a compile-time
assertion in the source.

It is worse than one number suggests, and here is the arithmetic rather than
the framing. Of the **57,146,400,000 BLCH issued at slot 0**, the founder holds
27,046,829,380 and the Foundation a further 29.00% across five buckets — VC,
team, marketing, liquidity and the rest. **Together that is 56,046,829,380 of
57,146,400,000, leaving 1,099,570,620 BLCH — 1.92% of genesis supply — in every
other hand combined.**

Carried balances are **stakeable**. If the founder stakes that balance, which
the rules permit, it is the overwhelming majority of active stake and the
**Nakamoto coefficient is 1**. For reference, an exchange-listed token drew a
centralization warning from CertiK at a 39% holder ratio. There is no framing
under which our number passes that test, so we are not offering one.

**And it is not only the coins.** All **64 Genesis-4 validators are operated by
a single entity**. There is no independent validator on this chain. **One
operator can halt it.**

One precision, so nobody over-reads the figure in either direction: the 27.04%
is the *founder's*, and it is pinned in the source. The remaining 29.00% is
*Foundation*-held across five separate allocation buckets. "Founder and
Foundation together hold 56.05 billion" is verified arithmetic. "One key holds
56.05 billion" is not, and we are not claiming it.

What actually bounds it, and what each bound does *not* reach:

- **The genesis validator cohort is founder-operated by construction** — all 64
  of them, because there is no one else — and a consensus rule tapers its
  combined weight to one third within a year. One third is the threshold below which the
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
  entity above 25% of active stake, Nakamoto coefficient ≥ 7. **None of them
  are met today.** And the arithmetic is published, not hidden: if the founder
  stakes the carried-over balance, pro-rata rewards preserve stake shares, so
  independent stake stays pinned near 6% — the 15% gate is then unreachable
  from emission alone, forever. It moves only if coins actually change hands.
  The gates are a measurement of behavior, not a schedule.

The honest summary: **the chain is centralized today, by construction, and the
published gates measure the distance from there.** Nothing on this page claims
otherwise.

**And there is no permissionless way in yet.** Even if you wanted to dilute
this by validating, you cannot: the network's transport has a fixed peer list
and no discovery, so a third party cannot connect; and deposit and delegation
transactions are refused at every node's mempool, because bonding is not yet
funded from the UTXO set. Distribution cannot improve through staking until
both of those change.

## Section: What the relaunch did to existing holders

Your balance carried over in full — and your **relative** position changed,
because the supply around it grew. Non-founder Genesis-3 holders together held
about 5.2% of the old network; after Genesis-4 issued its allocations, the same
coins are at most 0.3% — roughly a **17× reduction in relative share**. "Your
balance is preserved" is true; said alone it would be misleading, so here is
both halves.

## Section: Emission

42,853,600,000 BLCH to validators over 40 years, declining 10% per year. This
is the one allocation that was **not** issued at slot 0 — it is the unissued
remainder of the cap, paid out per slot. Year-one issuance is roughly 4.35% of
*total* supply.

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
The explorer at **blochl1.com** serves the **Genesis-3 archive**, read-only:
blocks, transactions, addresses and the DAG structure of the proof-of-work
chain, frozen at its terminal height of 39,918. It is a history browser now.
It stopped being a live view of anything on 2026-08-13.

For the live chain, the node's own RPC is the authority:
**`https://posternlabs.com/g4rpc`**. `getchaininfo` returns the current slot,
epoch, `height` and — the one that matters — `finalized_height`.

## What to check with it

- Your Genesis-3 balance as of the halt. What the snapshot contains is what
  the explorer shows at height 39,918 — if these ever disagree, the snapshot
  artifact wins, not the website.
- The terminal state. Blocks stop at 39,918; that is the chain ending, not an
  outage. Note that the explorer's DAG **block count** reads 50,690 at that
  point — a DAG has more blocks than the selected chain has height, and the two
  numbers are not interchangeable.
- Published digests. The snapshot digest and the carryover digest are
  reproducible from public data; the explorer links both. Reproduce them
  yourself — they are hash commitments, not signatures, and independent
  reproduction is the whole trust model.

## What the explorer is not

Stated because block explorers borrow more trust than they have earned:

- **It is not an authority.** It is a convenience service operated by Postern
  Labs — a single, centralized read path. The chain's rules are enforced by
  nodes, and the post-halt record is the snapshot artifact, which is
  hash-committed rather than signed. Verify digests yourself; do not treat a
  webpage — including this one — as proof of anything.
- **It can be wrong.** Explorer-level aggregate figures have been wrong before
  (an earlier supply endpoint omitted the carried-over balance and
  understated supply by billions). Discrepancies get fixed and documented,
  but the correct posture toward any explorer, ours included, is trust in the
  chain, verification against the chain.
- **It is now an archive, and it will not update.** Genesis-3 produced its last
  block at height 39,918. There is no Genesis-3 data after that and there never
  will be.
- **It does not show you the live chain.** A Genesis-4 explorer is not built
  yet. Until one exists, read Genesis-4 state directly from
  `https://posternlabs.com/g4rpc`, and gate anything that matters on the
  `finalized` boolean — not on the block height, and not on a count of blocks
  since. There is no confirmation count on this chain.

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
  `height 39,918`.

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
**H2:** What running a validator will take — and why you cannot do it yet.

> **Read this first.** Genesis-4 is live, but **validator entry is not open.**
> You cannot stake, delegate, or run a node on this network today. Everything
> below describes how it is designed to work, not something you can do. The two
> specific blockers are named in "The node today". Publish this card above the
> fold on the page; do not let the bond and delegation cards read as a
> prospectus.

## Card: Bond — designed, not open

Minimum validator deposit: **25,000 BLCH**, set so the bond is a comparable
fraction of supply to Ethereum's 32 ETH. *Publisher: cite this from
`crates/bloch-pos-committee/src/staking.rs` at publish time rather than
hardcoding it — the repository has carried more than one value for this
constant and the code is the authority.*

A bond bounds who *may* validate. It does nothing about who *does* — all 64
validators are founder-operated regardless of the bond, and no bond parameter
fixes that. Do not let anyone, including us, describe the bond as a
decentralization mechanism.

## Card: Delegation — designed, not open. Read the risk before the yield.

Stake behind an operator without running hardware. The design is Solana-like:
rewards pro-rata to stake, operator takes a disclosed commission.

**And you share the operator's slashing risk, pro-rata. That exposure is the
point** — delegation without risk would make operator choice meaningless.
Concretely, as designed:

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

## Card: The node today — live, but closed

The proof-of-stake node runs on mainnet. It has been producing, attesting,
justifying and finalizing since 21:31:19 UTC on 2026-08-13, across 64
validators, with a JSON-RPC server, real transfer transactions, and persistence
that replays deterministically on restart. You can read it right now at
`https://posternlabs.com/g4rpc`.

**You still cannot join it, and you cannot stake. Two specific reasons, both
checkable in the source:**

1. **The network has no door.** The live transport is a point-to-point TCP full
   mesh with a **fixed peer list, no discovery and no authentication**. There is
   no address to dial and no handshake to complete. This is not a policy; it is
   what the transport is.
2. **Bonding is not funded yet.** Deposit and delegation transactions are
   **refused at every node's mempool** —
   `crates/bloch-pos-node/src/engine.rs:1900-1906` — because bonding is not yet
   funded from the UTXO set. A deposit names an amount, carries no signature and
   spends no output, so accepting one today would create bonded stake out of
   nothing. Refusing it is correct, and it is why there is no permissionless
   path to validating.

Transfers work. Validating does not. We would rather say that in this many
words than let "mainnet is live" do work it has not earned.

**Anyone selling you access, allocations, or "early validator slots" is
lying** — validator entry, when it opens, is a permissionless deposit
transaction, not a sale, and there is nobody with slots to sell.

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
- **Tokenomics V4** — the 100,000,000,000 allocation, now final and running:
  vesting, emission curve, and the measured concentration arithmetic —
  including the founder-unfavorable results, which are the part most worth
  reading. The authority is the code
  (`crates/bloch-pos-committee/src/tokenomics_v4.rs`), not the document; where
  they disagree, quote the constants and the compile-time assertions, never the
  surrounding comments.
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
The founder, and it is not close. One address holds **93.94% of the
carried-over supply** — 17,046,829,380 of 18,146,400,000 BLCH. Of the
**57,146,400,000 BLCH issued at slot 0**, the founder holds 27,046,829,380
(27.04% of the 100 B cap) and the Foundation a further 29.00%; together
**56,046,829,380 of 57,146,400,000, leaving 1.92% in every other hand
combined.** And **all 64 validators are operated by a single entity** — there
is no independent validator, so **one operator can halt this chain.** The
Nakamoto coefficient is 1.

A consensus rule tapers the genesis cohort's weight to one third within a
year, and published gates measure independent participation — but the rules
bind addresses, not people, and cannot see beneficial ownership. Nor is there
any way in yet: the transport has a fixed peer list and no discovery, and
deposit and delegation transactions are refused at every node's mempool, so
nobody outside can currently dilute this even if they wanted to.
Decentralization here is a measurable claim about the future, not a
description of the present. Anyone telling you otherwise about this chain —
or, frankly, about most young chains — is marketing.

**Q: So isn't proof of stake exactly the wrong choice for this distribution?**
It is the choice that makes the distribution matter most, yes — under proof of
work the founder's coins were just coins; under proof of stake they are
potential consensus weight, and carried balances are explicitly stakeable. The
design's own migration document opens with this as its single largest risk. The mitigations (cohort cap, 1% validator cap, churn limits,
activation gates) are real, bounded, and individually insufficient; the
published arithmetic shows that if the founder stakes the carried-over
balance, the independence gate is unreachable from emission alone. What
resolves it is coins changing hands, and nothing on-chain forces that. You
should weigh the chain accordingly.

**Q: Why should I believe the snapshot wasn't manipulated?**
Don't believe — check. The snapshot is a deterministic function of public
chain state at Genesis-3 height **39,918**: 452,726 outputs, 18,146,400,000
BLCH after the ×100/21 split. Anyone with an archive node can recompute it and
compare roots.

One correction we owe you, because earlier copy on this site got it wrong:
**the artifact is not signed.** No signing mechanism exists. It is
*hash-committed* — a SHAKE-256 root over the balance set plus a hash of the
file itself — and the trust model is **independent reproduction**, not a
signature. Several parties rebuilding it and getting the same root is the
evidence; one tool agreeing with itself is not. Describe it to anyone who
asks as hash-committed and independently reproducible, and if we ever say
"signed snapshot" again, hold us to this paragraph.

The residual trust is real and named: Postern operates effectively all of the
infrastructure, and now that mining has stopped the old chain's history is no
longer self-defending — which is exactly why the digest, not the chain, is the
canonical record. If your recomputation disagrees with our artifact, publish
it.

**Q: Is BLCH a security?**
We do not know, and we will not pretend to. Honestly stated: staking rewards
paid to bonded holders, plus a planned allocation sold to funds, strengthen
an investment-contract reading compared to pure mined PoW — the project's own
internal documents say so in those words, and legal review is a blocking
gate for the migration, not a formality. What we can control: nothing on this
site is investment advice, nothing here promises value, and BLCH is presented
as what it is — the fee and staking asset of a post-quantum chain, whose
market price, if any, is not our subject.

**Q: You had Bitcoin's hashrate securing you via merged mining. Why did you
give that up?**
Because we chose deterministic finality and an end to the emission race, and
that trade had a loser: merged mining was the cheapest real security Bloch
ever had, and giving it up also gave up the Bitcoin-miner community we
courted. We think the post-quantum-PoS position is worth more than borrowed
SHA-256d hashrate over the long run. That is a judgment, not a theorem; the
cost side of it is stated here so you can disagree with the actual trade
rather than a sanitized one.

The honest follow-up, which we would rather state than have you infer: what
replaced borrowed hashrate is **not** a broader security base. It is a
validator set of 64 keys operated by one entity. The security question moved
from "who has the hashrate" to "who holds the stake", and today the answer to
the second is more concentrated than the answer to the first ever was.

**Q: When did Genesis-4 launch?**
**21:31:19 UTC on 2026-08-13**, hours after Genesis-3 stopped at height
39,918. There was no months-long gap; an earlier version of this page said
there would be one and that anyone quoting a date was guessing. That was our
expectation at the time and it was wrong — the correction is that the date now
exists and is the one above.

What has *not* launched is participation: you cannot run a node or stake yet
(see Build). And the anti-scam rule is unchanged and is the part to keep:
**nobody needs your coins, your keys, or your signature for anything to do
with Genesis-4.** Anyone who says otherwise is stealing.

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

**Q: I mined Bloch. What happened to me?**
Your revenue ended when Genesis-3 stopped at height 39,918 on 2026-08-13, full
stop. Coins you mined and held at the snapshot carried over in full and are
liquid on Genesis-4 — mined coins are treated identically to everyone else's,
the founder's included. Your hardware did not carry over: Genesis-4 has no
proof of work, and SHA-256d ASICs have no role on it. If you kept mining past
the halt you were mining a fork whose coins are not in the snapshot and do not
exist on Genesis-4.

We acknowledge the notice was short. The halt height was lowered from 80,000
to 50,000 on 2026-08-12 and the chain was then stopped at 39,918 the next day.
That cost miners planning time, and it was avoidable.

**Q: My balance is "preserved". What aren't you telling me?**
The other half of the sentence: preserved in absolute terms, diluted in
relative terms. Non-founder Genesis-3 holders went from about 5.2% of the old
network to at most 0.3% of the new one — roughly 17× less relative share —
because Genesis-4 issued new allocations around the carried balances. Both
halves are true; either alone would mislead. This is that rare table where the
founder's row and yours move the same direction: the founder's ~94% of the old
supply became **27.04%** of the new one. It is still, by a wide margin, the
largest holding on the chain, and the Foundation holds a further 29.00%
alongside it.

**Q: The total supply used to be marked "under review". What happened?**
It is settled. The review was about a unit redenomination and the integer
arithmetic behind it — at one candidate figure, supply in base units consumes
enough of the 64-bit range that balance sums approach overflow, and it exceeds
the signed-64-bit type one of our own SDKs uses. That is closed: the cap is
**100,000,000,000 BLCH**, base units are 10^19 satoshis, which is 54.21% of an
unsigned 64-bit integer and roughly 1,110× JavaScript's safe-integer limit. The
consequence you should care about if you are writing code against this chain:
**amounts travel as decimal strings, not JSON numbers.** Parse them as big
integers or you will silently lose precision.

A supply number is a consensus invariant, and marking it "under review" rather
than revising it after the fact was the right call at the time. It is not under
review now.

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

## Scam banner (site-wide, dismissible, reappears each session)

There was no token migration and there is nothing to claim. You never needed to
send coins, connect a wallet, or register anywhere to keep your balance across
Genesis-4 — balances carried over automatically on 2026-08-13. Anyone asking is
stealing.

> **Publisher's note:** the earlier trigger condition on this banner was "until
> Genesis-4", which has now fired. **Keep the banner running.** The migration
> being finished is precisely when impersonation gets easiest — "you missed the
> snapshot, claim here" is the obvious next scam, and it is a lie: nothing was
> missed and there is nothing to claim.

## 404 page

No block at this height. The page you asked for does not exist — like blocks
above 39,918, this is by rule, not by accident. → Home

