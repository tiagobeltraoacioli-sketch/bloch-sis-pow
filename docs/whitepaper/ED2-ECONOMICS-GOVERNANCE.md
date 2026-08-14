<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — Institutional Dossier, Edition 2

## Economics & Governance

```
Document:    ED2-ECONOMICS-GOVERNANCE
Replaces:    Edition 1 chapters 4 (The Ownerless Commons),
             16 (Economics & Tokenomics), 19 (Governance & Roadmap)
Status:      DRAFT for Edition 2 assembly. Revised 2026-08-14: the transition
             this chapter anticipated has happened. Genesis-3 (PoW) stopped
             permanently at height 39,918 on 2026-08-13; **Genesis-4 (PoS) has
             been the live chain since 21:31:19 UTC that day**, and the
             Tokenomics V4 constants described here are the live chain's
Sources:     docs/adr/ADR-036-retract-ownerless-adopt-foundation.md
             docs/adr/ADR-034-founder-anonymization-relinquishment-pact.md
             docs/specs/BLOCH-ENTITY-STRUCTURE.md
             docs/specs/BLOCH-TOKENOMICS-V4.md
             docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md (§4, gates)
             crates/bloch-pos-committee/src/tokenomics_v4.rs
             crates/bloch-pos-committee/src/staking.rs
             crates/bloch-pos-committee/src/delegation.rs
             crates/bloch-pos-committee/src/genesis_cohort.rs
Created:     2026-08-12
```

**Reading rule, inherited from Edition 1 and applied without exception:
designed ≠ built ≠ booted.** An earlier draft of this chapter said that
everything in it concerning Genesis-4 — the allocations, the vesting, the
emission curve, the validator bond, delegation — was "at most *built*" and
"none of it is booted". **That is no longer true and is withdrawn.** The
Tokenomics V4 constants, the vesting functions, the emission curve and the
supply-cap consensus invariant are **booted**: they are the rules of a live
mainnet, and the opening ledger was minted from them on 2026-08-13.

What is *not* booted, and must keep its label:

- **Delegation and the staking lifecycle are built and unusable.** `Deposit`
  and `Delegate` transactions are refused at every node's mempool
  (`crates/bloch-pos-node/src/engine.rs:1900-1907`) because bonding is not yet
  funded from the eUTXO set, so no one — insider or otherwise — can currently
  bond or delegate stake.
- **The entity structure is at most *designed*.** `BLOCH-ENTITY-STRUCTURE.md`
  is marked DRAFT and the Bloch Foundation does not exist as a legal person,
  while holding 29% of supply in the live genesis allocation.
- **Nothing here has been audited by a third party.**

And the operating fact that governs how §3 should be read: **all 64 Genesis-4
validators are operated by a single entity**, on a transport with a fixed peer
list, no discovery and no authentication, so no third party can join.

**Source-of-truth rule.** This chapter does not restate consensus constants;
it cites the files that define them. Where a specification's prose and a
compiled constant disagree — and they do in several places, because the
specs were written before the terminal snapshot — **the compiled constant
governs**, because it is pinned by compile-time assertions that fail the build
if the arithmetic drifts, and prose is pinned by nothing. In particular the
carryover is **18,146,400,000 BLOCH** measured at Genesis-3 height **39,918**
across **452,726** outputs and 16 addresses (`CARRYOVER_TOTAL_BLOCH`,
`CARRYOVER_MEASURED_HEIGHT`, `CARRYOVER_MEASURED_UTXOS`), not the provisional
17,970,880,000 the specs quote "at height 43,172" — a figure whose height
label was a **block count**, not a height.

---

## 1. The retraction of the ownerless commons

### 1.1 What Edition 1 asserted

Edition 1 did not mention ownerlessness in passing; it made it the load-bearing
premise of the entire document. Chapter 4 ("The Ownerless Commons") asserted,
as structural properties and not marketing posture:

- that the protocol has **no owner, no foundation, and no official company
  site** presenting it as a corporate product;
- that there was **no token sale** — "public, private, or otherwise" — no
  listing effort, and no market-making arrangement (Chapter 16.1);
- that there is **no issuer, no promoter, and no counterparty** "who could
  make representations about BLCH's value even if they wished to" (Chapter
  16.1, Note);
- that Postern Labs is a builder *on* the protocol in exactly the sense a
  wallet vendor builds on Bitcoin, with no special standing (Chapter 4.3);
- that "no foundation collects fees, controls a treasury on participants'
  behalf, or issues binding protocol directives" (Chapter 4.4);
- that there is "no legal entity chartered to steward the protocol, hold a
  treasury on its behalf, fund development on its behalf, or speak for it"
  (Chapter 19.2).

These statements were true when written, of the chain they described. They are
**retracted** as descriptions of the project going forward.

### 1.2 What changed, and where it is recorded

**ADR-036** (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`,
accepted 2026-08-10) retracts the ownerless thesis in writing. It formally
retracts ADR-033 (the decentralisation model that restored the ownerless
position) and **ADR-034** — the founder anonymisation and relinquishment pact,
which had committed the founder to withdrawing from all forward-facing
materials and retaining no governance or operational authority from launch.
ADR-036's own words: "ADR-033 and ADR-034 no longer describe the project."

What replaced them:

- **A sponsoring organisation and an issuer.** The governance model adopted is
  Solana's two-entity split: a non-profit **Bloch Foundation** (to be created)
  holding and distributing the non-founder allocations and stewarding the
  network, beside **Postern Labs Ltda**, the Brazilian development company
  that builds the node, the OS, the apps, and the wallet
  (`docs/specs/BLOCH-ENTITY-STRUCTURE.md` §2).
- **A VC allocation.** Tokenomics V4 allocates 10% of supply for sale to
  crypto funds, with the Foundation as counterparty of the round
  (`BLOCH-TOKENOMICS-V4.md` §7B; `VC_BLOCH` in `tokenomics_v4.rs`). At the
  time of writing this is a *planned* sale — an allocation and a vesting
  schedule exist in code; no round has closed.
- **A founder grant** replacing ADR-034's relinquishment: a new 10%-of-supply
  grant under a 10-year cliff and 40-year linear vest (`FOUNDER_BLOCH`,
  `founder_vested_sat` in `tokenomics_v4.rs`), on top of the founder's
  carried-over balance. ADR-036 is explicit that this "should be described as
  what it is."

### 1.3 Why it changed

ADR-036 gives the reasons plainly, and they are worth repeating because they
are reasons, not rationalisations:

1. **Tokenomics V4 is not compatible with ownerlessness.** A 10% allocation
   sold to funds introduces investors with a return expectation and, in
   practice, an issuer. Carrying both positions at once — an ownerless thesis
   and a VC round — was flagged internally as an inconsistency that had to be
   resolved in writing before anything was published. The retraction is that
   resolution.
2. **Weak subjectivity needs a signer.** The PoS migration design identified
   "who signs the checkpoint in an ownerless system?" as its sharpest
   unresolved conflict. With a Foundation there is an answer — the Foundation
   publishes weak-subjectivity checkpoints. ADR-036 calls this what it is: "a
   real centralisation cost, honestly stated — and it is a cost the ownerless
   design could not pay at all."
3. **Listing needs a counterparty.** Exchange integration was blocked in part
   because no legal person existed to sign an agreement. Now one will.
   (Post-quantum custody remains a separate, harder blocker, unaffected by
   any of this.)

### 1.4 What the retraction does *not* retract

Retracting the ownerless thesis does not silently convert the protocol into
an administered system, and the distinction matters for the governance
chapter (§4 below):

- **Consensus rules still change only by operator adoption.** No transaction
  variant, key, vote, or governance path inside the protocol can alter the
  supply cap or any other consensus rule; the cap is a `const` with no setter
  (`TOTAL_SUPPLY_BLOCH` documentation in `tokenomics_v4.rs`). A hard fork
  adopted by every operator can change any rule — that was true under the
  ownerless thesis and remains true; "impossible to change" was never claimed
  and is not claimed now.
- **The codebase remains AGPL-3.0-or-later**, and authorship remains
  disclosed.
- **ADR-034's honest-scope section was already candid** that the founder
  retained economic weight ("anonymity ≠ absence of stake") and that entities
  persisted. What is retracted is the relinquishment of control and the
  anonymisation — not the honesty norms of that document, which this Edition
  keeps.

### 1.5 The securities register, restated for Edition 2

Edition 1 stated: "BLCH is not a security and is not marketed as an asset,"
and could support that statement with three facts — no sale, no issuer, no
listing effort. **Those three supporting facts are gone**, and Edition 2 does
not pretend otherwise. ADR-036 records the consequence without euphemism:
"Selling to investors with a return expectation, plus staking yield, plus an
identifiable issuer and promoter, is close to the centre of the
investment-contract test rather than the edge of it." The Phase-0 legal
review is therefore classified as *blocking*, not precautionary.

What this dossier can still say, and says: **this document makes no value
claim, contains no offer or solicitation, sets no price target, and does not
market BLCH as an investment asset.** That register — factual description
with no promise of value — is retained from Edition 1 in full. What is no
longer said is that no one *could* make such representations: an issuer will
exist, and whether the planned sale makes BLCH a security in any given
jurisdiction is exactly the question the blocking legal review exists to
answer. This dossier does not pre-judge that answer in either direction.

### 1.6 Why the retraction is written as a retraction

A document that quietly rewrites its Chapter 4 invites the accusation that it
would quietly rewrite anything. Edition 1's credibility rested on disclosure
discipline — the same discipline now requires stating that the central
governance claim of Edition 1 was made, was meant, and was withdrawn, with
the ADR trail (`ADR-033` → `ADR-034` → `ADR-036`) left intact and citable.
The history is kept because auditors read history.

---

## 2. Tokenomics V4

Source of record: `docs/specs/BLOCH-TOKENOMICS-V4.md` (design and decisions)
and `crates/bloch-pos-committee/src/tokenomics_v4.rs` (the constants,
schedules, and compile-time invariants). Status: **booted** — Genesis-4 was
produced from these constants on 2026-08-13 and enforces them.

### 2.1 The 100,000,000,000 figure is a redenomination, not new supply

On 2026-08-12 total supply moved from the 21 B nominal to 100 B as a **pure
split of exactly 100/21** (`SPLIT_NUMERATOR` / `SPLIT_DENOMINATOR` in
`tokenomics_v4.rs`). Every bucket scales by the same ratio; every percentage
is unchanged; **nobody is diluted**. The code's own comment states the
reading rule: "any text that reads it as 'more supply for holders' is wrong."
This is not asserted on trust — `tokenomics_v4.rs` carries a compile-time
assertion per bucket proving `new × 21 == old × 100` exactly; if any bucket
were ever scaled by a different ratio, that would be a dilution, and the
build would fail.

Three costs of the split are recorded rather than absorbed (see also
`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`, 2026-08-12 entry):

- the supply in satoshis no longer fits the Go SDK's signed `int64`; the SDK
  must migrate (asserted in `tokenomics_v4.rs` so it cannot be forgotten);
- per-address conversion cannot be exact, because 100/21 never divides a
  power of ten — `split_g3_sat` truncates, and the ceremony must state its
  dust rule and close the accounting against the pinned total;
- the emission curve was re-derived, since scaling the old one overshot the
  allocation.

### 2.2 Allocations

The buckets, each named by its constant in `tokenomics_v4.rs` (shares are
ratios and therefore survive the split unchanged; the BLCH figures live in
the file, not here):

| Bucket | Constant | Share | Unlock |
|---|---|---:|---|
| Carryover (the whole Genesis-3 ledger) | `CARRYOVER_TOTAL_BLOCH` | **18.15%** (18,146,400,000 BLOCH) | Liquid at genesis |
| Founder — new grant | `FOUNDER_BLOCH` | 10% | 10-yr cliff, 40-yr linear (`founder_vested_sat`) |
| VC / crypto funds | `VC_BLOCH` | 10% | 12-mo cliff, 24-mo linear (`vc_vested_sat`) |
| Development team | `TEAM_BLOCH` | 10% | 18-mo cliff, 36-mo linear (`team_vested_sat`) |
| Marketing | `MARKETING_BLOCH` | 4% | 25% at genesis, rest over 24 mo (`marketing_vested_sat`) |
| Liquidity | `LIQUIDITY_BLOCH` | 5% | 100% liquid at genesis (`liquidity_vested_sat`) |
| Validators | `VALIDATOR_EMISSION_BLOCH` | **42.85%** (42,853,600,000 BLOCH) | Emitted over 40 years — never in anyone's custody |

A compile-time assertion pins the sum to `TOTAL_SUPPLY_BLOCH`. Everything
except the validator emission existed at slot 0: **57,146,400,000 BLOCH**
(`GENESIS_ISSUED_SAT`). The Foundation holds the VC, team, marketing, and
liquidity buckets — **29.00%** of supply (`FOUNDATION_HELD_BLOCH`). The
founder's total position is the carried-over balance plus the new grant:
**27.04% of supply — 27,046,829,380 BLOCH** (`FOUNDER_TOTAL_BLOCH`, pinned by
assertion at 2704 bps; the earlier 26.89% was computed against the provisional
carryover and is superseded). **Together the founder and the Foundation hold
56,046,829,380 of the 57,146,400,000 issued at slot 0 — leaving 1,099,570,620
BLOCH, 1.92% of genesis supply, in third-party hands.** Stated that way on
purpose: the repository pins the founder figure, and does not pin recipient
keys for the Foundation's four buckets, so "one key holds 56 B" would be
unverified and is not claimed. The grant was cut from 17% to
10% on 2026-08-11 with the difference reallocated to validators — the only
reallocation to date that moved supply *away* from an insider bucket
(`BLOCH-TOKENOMICS-V4.md` §1).

The carryover crosses as **one balance set, with no founder line, no taint
list, and no holder cap** (founder decision 2026-08-11; the retired cap is
kept as a named zero, `HOLDER_CARRYOVER_CAP_BLOCH`, so stale code fails
loudly). Those coins were mined on the same chain under the same rules as
everyone else's; and liquid includes **stakeable** — see §3, where the
consequences are stated in numbers.

### 2.3 Vesting

Schedules are consensus-enforced unlock functions, not promises: each bucket
has a `*_vested_sat(slot)` function in `tokenomics_v4.rs`, and §8.2 of the
spec sets the standard — "a vesting schedule that lives in a spreadsheet is
not a vesting schedule." Cliffs are deliberately staggered (VC at 12 months,
team at 18, founder at 120) so no two buckets begin unlocking in the same
month — the "cliff wall" is the most cited failure mode in vesting design.
The founder's vest is linear **per slot**, not in monthly tranches: a step
function would create hundreds of scheduled moments where a block of stake
becomes spendable at once, each a visible, game-able date.

The founder grant's 10-year cliff and 40-year vest is far beyond any market
benchmark, and deliberately so — the carried-over balance arrives liquid, so
the grant is the part of the founder's position that can still be made to
wait. It is not, however, the whole position, and Edition 1's description of
the founder allocation as "structurally passive" **does not carry over**: it
was true of a design in which the founder's entire position sat behind the
cliff, and it is not true of V4, where **17.05% of total supply — the
founder's entire 17,046,829,380-BLOCH carried balance — is liquid at slot 0**,
and stakeable.
That sentence from Edition 1 Chapter 16.3 must not be quoted as if it
described V4.

### 2.4 Emission

The validator allocation is emitted over 40 years
(`EMISSION_YEARS`, `EMISSION_SLOTS` in `tokenomics_v4.rs`). The spec adopts
**smooth disinflation at 10% per year** (`BLOCH-TOKENOMICS-V4.md` §6.1):
year-one issuance is 4.36–4.37% of total supply, declining every year, summing
to the allocation minus an irreducible dust residual (`EMISSION_DUST_SAT` —
under the allocation, never over; an earlier claim of a zero residual was
arithmetically impossible and is corrected in the file rather than repeated).
The code provides three curves (`validator_reward_flat_sat`,
`validator_reward_halving_sat`, `validator_reward_decay_sat`) with the decay
curve marked recommended; the spec records the 10% decay as decided. An earlier
draft ended "no curve is yet wired into a running consensus — that is a
Genesis-4 act"; **Genesis-4 launched on 2026-08-13, so a curve is now the
issuance rule of a live chain.** Note what that emission currently funds: the
validator set receiving it is 64 validators operated by one entity, and no
third party can enter it while deposits are refused at the mempool.

Two register rules the spec imposes on any public figure, kept here:

- **The denominator is load-bearing.** Inflation figures are issuance over
  *total* supply (how Solana and Ethereum report). Against *circulating*
  supply the same curve reads over 100% in year one, purely because almost
  everything is still vesting at genesis. Any published figure must name its
  denominator (`annual_inflation_bps` in `tokenomics_v4.rs`).
- **"Maximum ever issued", not "total supply."** Base fees are 50% burned
  during the emission era (§6.3.2), so circulating supply never reaches the
  cap; the two figures diverge from the first burned fee onward.

The emission curve, not the vesting schedule, is what decides whether the
concentration gates can ever be met — the spec's month-by-month model (§7A)
shows a flat curve failing gate G2 for roughly five years while a
front-loaded curve clears it from month 24. That is why the curve is treated
as the most consequential economic parameter in V4.

### 2.5 The cap as a consensus invariant

V4 is hard-capped, reversing V2's perpetual tail — a reversal recorded as
such (`BLOCH-TOKENOMICS-V4.md` §6.2 flags that the tail existed to fund
security after emission, and that an ADR retracting the tail rationale is
still owed). The cap is not a documentation figure: cumulative issued supply
is a committed component of the state root (`state_root::TAG_ISSUED_SUPPLY`),
and every node refuses a block whose committed issuance exceeds
`TOTAL_SUPPLY_BLOCH` (`TransitionError::SupplyCapExceeded`). The honest
strength of the claim, quoted from the constant's own documentation: no
mechanism *inside* the protocol can raise the cap — no transaction variant,
no key, no vote, no governance path — and a hard fork adopted by every
operator can change any rule, this one included, "so 'impossible to change'
would be false and is not claimed."

The fee-only end state inherits the question the tail existed to avoid: after
year 40 the entire security budget is fee revenue, and there is a named
revenue cliff at the era boundary (§6.3.2). Whether fees suffice by then is
unknowable now; that it must be monitored long before then is knowable and
stated.

---

## 3. Concentration

Edition 1 did not have this chapter. Edition 2 has it because the numbers
exist, they are measurable by anyone, and a dossier that leaves them for an
auditor to discover has chosen its readers' side against itself.

### 3.1 The measurement

Measured on Genesis-3 at the **terminal** height **39,918** — 452,726 outputs,
16 addresses — and carried under the split (`tokenomics_v4.rs`,
`LARGEST_CARRYOVER_ADDRESS_BLOCH`, `CARRYOVER_TOTAL_BLOCH`,
`CARRYOVER_MEASURED_HEIGHT`, `CARRYOVER_MEASURED_UTXOS`, all pinned by
assertion, with the set root and both file digests published so the
measurement is checkable rather than asserted):

- The largest single address holds **17,046,829,380 of 18,146,400,000 BLOCH —
  93.94% of the carryover**, which is itself the entire circulating float apart
  from the Foundation's liquid tranche.
- The founder's carried-over balance is **70.60% of everything circulating at
  slot 0** (24,146,400,000 BLOCH = carryover + liquidity 5 B + marketing TGE
  1 B); the Foundation's liquid holding is the other **24.85%**. Two holders
  account for the whole genesis float (`BLOCH-TOKENOMICS-V4.md` §4A, §7B).
- Across the whole genesis issuance: founder **27.04%** + Foundation
  **29.00%** = **56,046,829,380 of 57,146,400,000 (98.08%)**, leaving
  **1,099,570,620 BLOCH — 1.92%** — with everyone else.

**A note on the earlier numbers, because they were published and must not be
quietly replaced.** Previous drafts read "measured at height 43,172",
17,970,880,000 BLOCH, largest address 16,886,549,523, concentration 93.96%,
founder total 26.89%, founder 70.4% of circulating. Two things were wrong.
**The height label was a block count** — the chain was never at height 43,172,
and in a DAG heights and block counts differ by design, so nobody could have
reproduced that measurement. **And the reading was provisional**, because
Genesis-3 kept minting until it halted. The terminal figures above supersede
them. **The correction is not an improvement**: 93.96% → 93.94% is noise on a
94% number, and the founder's share of eventual supply moved *up*, 26.89% →
27.04%. Nothing was distributed.

**And the fact that outranks all of the above on a live chain: all 64
Genesis-4 validators are operated by a single entity.** Coin concentration is
what the numbers above measure. Operator concentration is total, and it is not
conditional on anyone's staking decision. No third party can join the validator
set today: the live transport has a fixed peer list with no discovery and no
authentication, and `Deposit`/`Delegate` are refused at every node's mempool.

### 3.2 If the founder stakes: the §4A.1 arithmetic

`BLOCH-TOKENOMICS-V4.md` §4A.1 works the consequences of the 2026-08-11
decision that a carried-over balance that is liquid is also stakeable — a
decision pinned by tests
(`staking.rs::carryover_liquid_balance_is_stakeable`,
`tests/committee.rs::carryover_liquid_balance_delegates_as_stake`) so it
cannot be reverted silently. The arithmetic, which should be read before
anyone quotes a decentralisation date as a forecast:

- **Staked at genesis, the founder's balance is ~94% of active stake — a
  Nakamoto coefficient of 1.** Gate G2 (largest entity < 25% of active
  stake) fails outright, and because rewards are pro-rata to stake, the
  shares are *conserved* under compounding: the figure does not decay with
  time.
- **Gate G1 is unreachable from emission alone if the founder stakes.** G1
  requires independent eligible stake ≥ 15% of circulating supply
  (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §4). Share conservation holds the
  independent share of active stake at its starting point — **6.06%**
  (1,099,570,620 of 18,146,400,000) — at every horizon, and active stake can never exceed circulating supply. Under this
  scenario G1 is "not late, it is unreachable — not at year five, not at
  year forty — from emission alone. The only thing that moves G1 is coins
  changing hands" (§4A.1).
- **If the founder abstains**, the earliest arithmetic G1 crossing is a
  bound of about month 9 — a bound, not a forecast, since the
  founder-operated genesis cohort earns much of the early emission.

The honest summary the spec itself draws, adopted here as the Edition 2
position: the stakeability decision removed the last consensus-enforced
distinction between the founder's coins and anyone else's, and in exchange
**the gates stop being a schedule and become a measurement of behaviour** —
whether G1–G4 are ever met is decided by whether the founder's carryover
stakes and whether coins actually distribute, and consensus constrains
neither.

### 3.3 The three mechanisms, and what each one does not reach

Three consensus mechanisms bound concentration. Each is real; each has a
stated limit; **none can see beneficial ownership**, because no on-chain
metric can see who stands behind an address.

**The genesis-cohort declining cap**
(`crates/bloch-pos-committee/src/genesis_cohort.rs`). The chain starts with a
founder-funded, founder-operated validator cohort — there is no other option
on a fresh genesis with no PoW phase (`BLOCH-TOKENOMICS-V4.md` §3.3). The
cohort is a fixed set published in the genesis block, shrink-only, and its
combined weight is capped by a linear taper from 100% at genesis to one third
at one year (`cohort_cap_bps`), where it holds. One third is chosen because
it is the finality-*stall* threshold: below it the founder cannot halt the
chain alone. What it does not say: one third is the liveness threshold, not
the safety one (two thirds), and — stated in the module's own docs — nothing
prevents funding *new* validators after genesis under addresses outside the
cohort. Past the cohort, the one-third figure is a commitment verified
externally, not a rule.

**The 1% per-validator cap**
(`crates/bloch-pos-committee/src/delegation.rs`, `MAX_VALIDATOR_STAKE_BPS`,
resolved by fixed-point iteration over a fixed round count
(`CAP_FIXPOINT_ROUNDS`) rather than against the uncapped total, precisely so
the cap's strength does not degrade as concentration rises).
What it does not reach: it is Sybil-bypassable by splitting stake across
validators, per its own documentation, which is why §4A.1 treats share
conservation, not the cap, as the conservative assumption.

**The churn limit**
(`delegation.rs`, `WARMUP_RATE_BPS` with the `MIN_CHURN_SAT` floor and
partial activation; history in `BLOCH-POS-STAKE-CHURN.md`). At most a small
fraction of active stake activates per epoch, so a takeover requires
publicly visible queue traffic over many epochs rather than one block. What
it does not reach: it slows entry; it does not distinguish whose stake is
entering, and it cannot.

An earlier fourth mechanism — taint-based ineligibility of founder coins —
**no longer exists**: with the single-set carryover decision there is no
class of coin to mark, and no provenance criterion survives anywhere in the
admission path (`CARRYOVER_TOTAL_BLOCH` docs in `tokenomics_v4.rs`). The
spec's earlier delegation rule "tainted coins cannot delegate" is stale
against that decision. The dissolution cuts both ways and both are recorded:
an unaudited list-writing power ceased to exist, and a consensus-enforced
exclusion of founder stake ceased to exist with it.

### 3.4 The gates, and who is not counted

The activation gates (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §4): G1 —
independent eligible stake ≥ 15% of circulating; G2 — no entity above 25% of
active stake, top-3 below 50%; G3 — Nakamoto coefficient ≥ 7; G4 — ≥ 200
active validators, ≥ 50 unaffiliated with Postern Labs. The metrics that
compute G2/G3 (`Registry::top_share_bps`, `Registry::nakamoto_coefficient`,
with the Nakamoto coefficient computed at the one-third threshold, not one
half, which would flatter it) measure the **operator** view — what consensus
sees. Foundation stake delegated across forty operators reads as forty
independent participants; a genesis cohort of 64 founder-funded records reads
as 64. Therefore the reporting rule, written down before the numbers become
convenient (`BLOCH-ENTITY-STRUCTURE.md` §5.1, extended to the genesis cohort
in `BLOCH-TOKENOMICS-V4.md` §3.3): **stake whose beneficial owner is the
Foundation, the founder, or Postern Labs does not count toward G1–G4.** That
is a reporting rule, not a protocol rule, and it is labelled as such.

The launch statement Edition 2 adopts, verbatim from the spec: **the chain
starts centralised, by construction, and the gates measure the distance from
there.** Edition 2 must add what the spec could not know: **Genesis-4 launched
on 2026-08-13 with none of G1–G4 met** — independent stake 0%, one entity
operating 64 of 64 validators, Nakamoto coefficient 1, zero unaffiliated
operators — and with no external audit. The gates were written as Go/No-Go
conditions on the transition. They did not gate it. That is a governance
finding and this chapter records it as one rather than continuing to describe
the gates in the future tense.

---

## 4. Governance today

### 4.1 The two entities

Per `docs/specs/BLOCH-ENTITY-STRUCTURE.md` (DRAFT — structure proposed,
jurisdiction and board not decided):

| | Bloch Foundation *(to be created)* | Postern Labs Ltda *(exists)* |
|---|---|---|
| Form | Non-profit; jurisdiction open | Brazilian limited company |
| Purpose | Steward the protocol; hold and distribute the non-founder allocations | Build the node, the OS, the apps, the wallet |
| Holds | 29% of supply at genesis, most of it vesting | — |
| Protocol authority | Publishes specs, GIPs, weak-subjectivity checkpoints | **None** |

Signing authority is split so the split means something: the Foundation signs
listing agreements, VC subscriptions, grants, and checkpoints; Postern Labs
employs the engineers and signs node releases — "whoever builds, signs"
(§4 of the entity spec). The Foundation deliberately has no product revenue
and Postern Labs deliberately has no protocol authority.

### 4.2 Who can change the rules

Three different kinds of power, kept distinct because conflating them is how
governance descriptions mislead:

1. **Consensus rules** still change only the way they always did: candidate
   software, published, adopted or not by node operators. ADR-036 created no
   protocol lever; the supply cap has no setter (§2.5); there is no
   governance token and no on-chain voting on rules. Stake in the PoS design
   orders blocks and finalises checkpoints — it does not vote on rule
   changes. On this point Edition 1's Chapter 19 remains accurate.
2. **Real, named powers the Foundation holds** that are not consensus rules
   but shape the network: publishing weak-subjectivity checkpoints (under a
   phased m-of-n with a client-enforced external-signer minimum and a
   12-month review, `BLOCH-WEAK-SUBJECTIVITY.md` §6 via the entity spec
   §5.3); administering 29% of supply including the delegation program;
   being the counterparty for listings and the VC round; publishing the
   genesis artifact. Each is a centralisation point and is named as one.
3. **Product decisions** belong to Postern Labs and bind nobody's node.

### 4.3 The honest clause

Until the independent board of `BLOCH-ENTITY-STRUCTURE.md` §5.2 exists —
a majority of members unaffiliated with Postern Labs and with the founder,
recusal of conflicted members from grant votes, published grant amounts and
terms — **the two entities are the same people.** The spec says it itself,
in the genesis-cohort context: "the Foundation is the founder until the
board exists" (`BLOCH-TOKENOMICS-V4.md` §3.3.1). The Anza spin-out criticism
that the entity spec opens with — "the same people, a new letterhead" — is
the failure mode this structure reproduces by default, and the §5.2 controls
are the only thing that would make it otherwise. They are, at the time of
writing, designed and not built: no jurisdiction, no board, no foundation.

What the structure does not fix, quoted from its own §7: a foundation makes
concentration easier to **administer** — it does not make concentrated stake
decentralised, and Foundation-delegated stake counted naively toward the
gates is the specific way the structure could be used to appear to meet them
without meeting them.

Open questions the spec routes to counsel rather than guessing: Foundation
jurisdiction (with real Brazilian CFC/transfer-pricing exposure), who sells
to the funds (Foundation directly or an SPV — the securities-sensitive act),
board composition, and whether a third entity is ever warranted.

---

## 5. Validator bond and delegation

### 5.1 The bond: 25,000 BLCH

`crates/bloch-pos-committee/src/staking.rs`, `MIN_DEPOSIT_SAT` (founder
decision, 2026-08-12; was 100,000 under the 21 B nominal). The figure is
derived, not inherited: it is the fraction of supply Ethereum's 32-ETH bond
represents, applied to the V4 supply and rounded **down** — exactly
`supply / 4,000,000` — "on purpose: down is cheaper, and cheaper widens who
*may* validate, which is the only direction a rounding choice on a bond
should ever err" (the constant's own documentation). A pure ×100/21 split of
the old floor would have landed at 19× the Ethereum-equivalent bond, so this
constant deliberately does not follow the split; it is re-derived from the
benchmark.

**What it solves:** the entry cost to *operating* a validator is pinned to
the most widely accepted benchmark in staking, instead of an arbitrary
number that would gate validation on wealth.

**What it does not solve**, stated in the file itself and repeated here
because it is the sentence a promotional document would omit: "lowering the
bond widens who MAY validate and does nothing about who DOES. It is not a
fix for stake concentration and must not be described as one." The
concentration facts of §3 are unmoved by any bond value.

### 5.2 Delegation

`crates/bloch-pos-committee/src/delegation.rs` — **built, and not usable**.
The rules are live consensus, but no delegation can be made: `Delegate`
transactions are refused at every node's mempool
(`crates/bloch-pos-node/src/engine.rs:1900-1907`) because bonding is not yet
funded from the eUTXO set, so a delegation would create stake without spending
coins. Delegation exists because the adopted revenue
model (Solana's: pro-rata inflation rewards scaled by attestation credits,
commission on delegated stake, 50% base-fee burn during emission, priority
fees to the producer — `BLOCH-TOKENOMICS-V4.md` §6.3) is meaningless without
stake that can sit behind an operator without running one.

What makes it safe to add, each with its limit:

- **Rate-limited warm-up and cool-down** (`WARMUP_RATE_BPS`, floor
  `MIN_CHURN_SAT`, partial activation for oversized delegations) — instant
  activation would be instant control of stake-weighted committees. Limit:
  it slows entry, it does not vet it.
- **Delegated stake counts toward the 1% per-validator cap**, resolved by
  fixed-point iteration — delegation must not be a route around the cap.
  Limit: Sybil-splittable, as §3.3 states.
- **Delegators are exposed to slashing, pro-rata** — wired end-to-end
  (`transition.rs::apply_slashing_evidence` → `slashing.rs` →
  `delegation.rs::apply_slash`), with correlation amplification up to the
  entire delegated amount for coordinated equivocation. Otherwise delegation
  is all yield and no risk, and nobody cares who they delegate to. A
  delegator's principal is at risk for the operator's provable equivocation,
  not for mere downtime; there is no appeal path, because the evidence is
  two signatures the operator provably made.
- **Commission is uncapped and must be disclosed** — a cap is trivially
  evaded by an operator running its own delegation front-end, so the rule is
  disclosure (wallets and explorers must surface the rate), not limitation.

**What delegation solves:** it lets the validator set grow beyond the set of
people willing to run infrastructure, it makes the Solana revenue model
coherent, and — through the Foundation's delegation program — it solves the
real bootstrap problem of a young validator set.

**What it does not solve, and can make worse if misread:** delegation makes
the operator view *more* dispersed while beneficial ownership can remain
exactly as concentrated as §3 measures. That is why Foundation-delegated
stake is excluded from the gates by the §5.1 reporting rule, and why the
gate metrics' own documentation concedes they "cannot see one beneficial
owner standing behind several delegators, and no on-chain metric can."

---

## 6. Status ledger for this chapter

In the Edition 1 idiom, applied to everything above:

| Item | Status | Meaning here |
|---|---|---|
| ADR-036 retraction; ADR-033/034 retracted | Decided and recorded | A documentation and governance act — in force as a matter of record |
| Genesis-3 chain (PoW, SHA-256d, GhostDAG) | **Ended** | Stopped permanently at height 39,918 on 2026-08-13. Historical; the provenance of Genesis-4's opening ledger, not what runs |
| Genesis-4 chain (PoS, 30 s slots, 32-slot epochs) | **Booted** | The live network since 21:31:19 UTC, 2026-08-13. Public read RPC `https://posternlabs.com/g4rpc` |
| Tokenomics V4 constants, split, vesting functions, emission curve | **Booted** | The live chain's issuance and unlock rules; the opening ledger was minted from them |
| Supply-cap enforcement (`SupplyCapExceeded`) | **Booted** | Enforced in validation by every node against the committed `TAG_ISSUED_SUPPLY` leaf (`transition.rs:2307-2311`) |
| Transfers | **Booted** | Execute on the live chain; submitted via `sendrawtransaction` |
| Deposits and delegations | Built, **refused** | Rejected at every node's mempool (`bloch-pos-node/src/engine.rs:1900-1907`) — bonding is not yet funded from the eUTXO set, so nobody can bond or delegate stake |
| Per-validator cap, churn limit, slashing rules | Booted as rules; **not binding in practice** | The validator set they constrain is 64 records operated by one entity, and cannot become plural while deposits are refused |
| Genesis validator cohort and declining cap | **Booted** | `genesis_cohort.rs`; the taper reduces one operator's share of a set containing no one else |
| Network transport | **Devnet mesh in production** | `Transport::Devnet` is the fleet's transport and the default: fixed peer list, no discovery, no authentication — the reason a third party cannot join. A libp2p stack exists in-tree and is not what runs |
| Distribution gates G1–G4 | **Not met — and did not gate the launch** | Observed today: independent stake 0%; 64 of 64 validators one entity; Nakamoto coefficient 1; 0 unaffiliated operators |
| Bloch Foundation, board, jurisdiction | Designed | DRAFT spec; no legal entity exists — while holding 29.00% of supply in the live genesis allocation |
| VC round | Designed | An allocation and vesting schedule in code and now on-chain; no counterparty exists yet to sign, no round closed |
| Weak-subjectivity checkpoint regime (m-of-n) | Designed / partially built | Parameters adopted on paper (`BLOCH-WEAK-SUBJECTIVITY.md` §6); checkpoint format and verification exist, the fresh-node sync path that would consume them does not |
| Phase-0 securities review | Not done — blocking | Reclassified from precautionary to blocking by ADR-036; the chain launched before it concluded |
| Third-party audit of the PoS crate or the node | **Not done — and the chain launched anyway** | A pre-audit dossier exists (`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`); it was written to gate a launch that did not wait for it. Gate G7 (external review of the Falcon online-signing path) was likewise unmet at launch |

Nothing in this chapter is financial, legal, or investment advice; nothing in
it is an offer; and no statement in it should be read as a claim about the
present or future value of BLCH.
