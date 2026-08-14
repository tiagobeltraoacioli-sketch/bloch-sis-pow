<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch PoS (Genesis-4 / Bell) — Threat Model, second pass

> ## The threat, stated first
>
> **The dominant risk on the live Genesis-4 network is concentration, not any
> finding numbered in this document.** All 64 validators are operated by a
> single entity; 93.94% of the carryover (17,046,829,380 of 18,146,400,000
> BLOCH) sits at one address and carried balances are stakeable, so if that
> balance stakes the Nakamoto coefficient is 1; and 56,046,829,380 of the
> 57,146,400,000 BLOCH issued at slot 0 is held by the founder and the
> Foundation, leaving 1.92% of genesis supply in third-party hands. One
> operator can halt the chain and one holder can outvote every other.
>
> A third party cannot yet join: the live transport is a fixed-peer TCP mesh
> with no discovery and no authentication, and `Deposit`/`Delegate` are refused
> at every node's mempool. Genesis-3 (proof of work) stopped permanently at
> height 39,918 on 2026-08-13; there is no hashrate in this threat model
> because there is no mining.
>
> The findings below are a **design** review dated 2026-08-11, retained for
> its reasoning. Several of its premises changed; the ones that changed are
> annotated in place.

> **Premissa de churn SUPERADA — 2026-08-11.** Este passe foi escrito com
> `WARMUP_RATE_BPS = 900` e piso `MIN_DELEGATION_SAT`. Depois dele o fundador
> aceitou a proposta de `BLOCH-POS-STAKE-CHURN.md`: hoje `WARMUP_RATE_BPS =
> 25` e o piso e `MIN_CHURN_SAT` (= `MIN_DEPOSIT_SAT`, 100k BLCH) em
> `delegation.rs`. O achado **G4** muda de natureza, nao desaparece: a
> observacao estrutural (o piso domina a taxa em rede pequena) agora vale por
> DESENHO na escala de 100k BLCH — custo de liveness aceito e itemizado no
> doc de churn — e o numeral antigo (~111 BLCH) perdeu o objeto. A aritmetica
> de "9%" no corpo descreve o valor antigo. Texto mantido como registro.

```
Document:   BLOCH-POS-THREAT-MODEL-2
Status:     PARTIALLY SUPERSEDED — adversarial re-review of the design as it
            stood on 2026-08-11. G1 is closed (see below). Not a threat model
            of the live network; the live risk is in the box above.
Created:    2026-08-11
Revised:    2026-08-14
Owner:      A4 (Adversarial review & security)
Predecessor: BLOCH-POS-THREAT-MODEL.md (partially superseded; read its seal first)
Reviews:    crates/bloch-pos-committee/src/{committees,genesis_cohort,delegation,
            forkchoice,sample,beacon,finality,schedule,params,tokenomics_v4}.rs
Scope:      only what changed since the first pass — the partition, the genesis
            cohort cap, partial activation + churn floor, whole-equivocator
            discard, and the sample dedup. Everything else is the first doc's.
```

## How to read this

Same contract as the first pass. Each finding gives **the attack**, the **code
path**, the **attacker cost**, and **what would close it**, tagged `[CONFIRMED]`
(I read the code and it behaves as described) or `[SPECULATION]` (reasoning about
wiring not present in this crate). Where a vector is clean I say so and stop,
rather than pad it.

~~The crate is still **UNAUDITED and not wired into the node** (`lib.rs` §Status).
That matters more than usual this pass: two of the corrections landed as modules
that **nothing calls**, which is itself the headline finding.~~

**No longer true as of 2026-08-13.** `crates/bloch-pos-committee` is a direct
path-dependency of `crates/bloch-pos-node`, the binary the Genesis-4 fleet
runs; `lib.rs` §Status now reads "THIS IS THE LIVE CHAIN'S CONSENSUS". The
crate remains **UNAUDITED** — that half of the sentence stands, and it matters
more now that it is load-bearing rather than less.

## Severity index

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| G1 | ~~**Critical**~~ **CLOSED** | The partition (F1/F2 fix) was dead code: `committees.rs` unwired, the finality gadget still sampling 128. **Wired on 2026-08-11 via `finality::votes_from_partition` (`finality.rs:768`)**; the quorum denominator is total active stake. Finding retained below as the record of why | CONFIRMED, then FIXED |
| G2 | **High** | The genesis-cohort cap zeroes the whole chain when non-cohort stake `O` is zero or tiny — the closed form is right, the operational result is a self-inflicted halt ~1.3 h after genesis | CONFIRMED |
| G3 | **Medium** | Partition is seeded from the same trailing-slot-grindable beacon mix as the proposer roster; it adds no seed-lookahead, so F6 persists over committee membership too | CONFIRMED (no lookahead in-crate); SPECULATION (magnitude, wiring absent) |
| G4 | **Low/Medium** | Churn floor `MIN_DELEGATION_SAT` overrides the 9% rate below ~111 BLCH of active stake — the "no single-epoch control shift" invariant is proportional to network size; compounds G2 | CONFIRMED |
| — | Partial activation | Examined; no exploit. Partial stake carries weight while reporting `Activating` (intended), slashing uses the full amount (conservative), deactivating records are skipped by the activation loop (old F13 oscillation is gone) | CONFIRMED clean |
| — | Whole-equivocator discard | The determinism fix is correct and order-independent. Framing an honest validator is not reachable through the reviewed functions. One latent boundary risk: `forkchoice::observe` authenticates nothing itself and bans permanently | CONFIRMED (fix); SPECULATION (boundary) |
| — | `sample.rs` dedup | Keeps the first occurrence after the index sort — order-independent and total. Clean | CONFIRMED clean |

---

## G1 — ~~Critical~~ **CLOSED**: the partition that fixes F1/F2 was dead code; finality still sampled 128

> **Closed 2026-08-11.** `finality::votes_from_partition` (`finality.rs:768`)
> is the caller that was missing; the justification quorum is taken over the
> whole active set. The finding is kept in full because "a correction that is
> not wired is not a correction" is the lesson, not the incident.

**Attack / failure.** `committees.rs` is exactly the fix F1 asked for: partition
the active set into `SLOTS_PER_EPOCH` committees so their union is the whole set,
making the ⅔ denominator "total active stake" reachable and unambiguous
(`committees.rs:59-174`). It is correct in isolation — Fisher-Yates over the
canonicalised index list, rejection-reduced draws, contiguous chunks, and an
integer `is_supermajority` (`:172-174`).

But **nothing consumes it.** Grepping the crate:

- `epoch_committees`, `committee_for_slot`, `committees::total_active_stake`,
  `committees::is_supermajority` have **no caller** anywhere but their own module.
- `committees` and `genesis_cohort` are declared `pub mod` in `lib.rs:44,46` but
  are **not** in the `pub use` re-export block (`lib.rs:59-80`), unlike every
  other module.
- The live finality path is unchanged. `finality.rs` still takes
  `EpochVotes.committee: &[Validator]` and documents it as "the caller draws it
  via `epoch_committee()`" (`finality.rs:90`) — that is the **sampled** k=128 draw
  still exported from `lib.rs:107-109`, not the partition. `finality.rs` then
  computes the quorum as `weight·3 ≥ total_active·2` where `total_active` is the
  **sum over that 128-member committee** (`finality.rs:200, 267`).

So the finality gadget is still "⅔ of a 128-validator stake sample" — precisely
**F1 reading-2** from the first pass. Its exploit is unchanged: with committee
stake ~Bin(128, p) for an adversary holding fraction p of network stake, a ~30%
adversary exceeds ⅓ of the *sampled* committee in roughly one epoch in five and
withholds to stall the ⅔ quorum — a censorship/liveness lever well under the
nominal ⅓ safety line. The partition would have removed exactly this by making
the committee the whole set; written but not wired, it removes nothing.

There is a second, quieter consequence. `finality.rs`'s module prose ("The full
epoch committee of 128 votes once", `:6-11`) and `committees.rs`'s prose ("the
union of an epoch's committees **is** the active set", `:24-27`) now describe two
mutually exclusive designs in the same crate. Whichever the node integrator wires
decides whether F1 is closed, and the crate does not force the safe one.

**Code path.** `committees.rs` (whole file, no external caller); `lib.rs:44-80,
107-109`; `finality.rs:6-11, 85-96, 194-274`.

**Cost.** Reading-2 stall: ~⅓−ε of stake, made cheaper by sampling variance
(<⅓ suffices ~19% of epochs). Zero if the integrator wires `epoch_committee()`
believing F1 was fixed — the dangerous default, because the fix *looks* present.

**What closes it.** Wire the partition and delete the sampled `epoch_committee`
path, or make `finality::EpochVotes` consume the partition union and
`committees::total_active_stake` as the denominator. Add a KAT that fails if the
finality committee is not the whole active set, and re-export `committees` so the
absence of a caller is visible in the public surface. Until then F1 is **open**,
not fixed — the status seal on the first doc claiming "F1 corrected by partition"
is premature.

---

## G2 — High: the cohort cap zeroes the whole chain when independent stake is absent

**Attack / failure.** `apply_cohort_cap` caps the founder cohort's combined weight
to a share `s` of stake *after* capping, solved in closed form as
`cap = O · bps / (10_000 − bps)` where `O` = non-cohort ("others") stake and
`bps` is the tapering target (`genesis_cohort.rs:121-122`). The algebra is right:
for target share `s`, `cohort' = s/(1−s)·O`, and at `s=⅓` that is `O/2`.

The problem is the **domain**. `O` is not the founder's variable — it is however
much stake *other people* have staked. And the taper does not wait for `O`:

- `cohort_cap_bps` drops below 10,000 (i.e. the cap engages) at the first epoch
  where `span·epoch / EPOCHS_PER_YEAR ≥ 1`. With `span = 6667` and
  `EPOCHS_PER_YEAR = 1,051,920/32 = 32,872`, that is **epoch 5** — about
  **1.33 hours after genesis** (5 × 32 × 30 s). `[CONFIRMED numerically.]`
- At genesis the cohort *is* the whole set (§module docs), so `O = 0`. If no
  independent validator has staked by epoch 5 — a fresh genesis where deposits
  need blocks that need the cohort (the bootstrap gap from pass 1, §Genesis) —
  then `O = 0`, `cap = 0`, and every cohort member is scaled to `effective_stake
  = 0` (`genesis_cohort.rs:127-139`). The cohort is the whole set, so **the whole
  active set goes to zero effective stake.** `total_active_stake` becomes 0, no
  committee has weight, and the chain cannot produce or finalize. The rule meant
  to decentralize the founder **halts the network** the moment it first bites.
- With `O` merely *tiny* it is nearly as bad. At epoch 5, `bps = 9999`, so
  `10_000 − bps = 1` and `cap = 9999·O`. One small independent validator with
  10 BLCH gives `cap ≈ 99,990 BLCH`; the founder's billions are scaled down to
  that combined ceiling — a ~99.99%+ ejection of consensus weight in one epoch
  boundary (16 min), collapsing the set below gate G4 (≥ 200 validators) and
  stalling finality. As `bps` falls toward the 3,333 floor over the year the
  ceiling tightens to `O/2`; the cohort's allowed weight is *pinned to a multiple
  of whatever outsiders happen to hold*, with no floor keeping it able to sign a
  block.

The module's own text says "Stake above the cap earns nothing and carries no
weight; it is not confiscated" (`:38-39`) — but when `O→0` *all* of the cohort's
stake is above the cap, so "not confiscated" is cold comfort: the chain still
stops. The closed form is correct; the design assumes `O` grows on a schedule the
protocol never enforces, and an adversary need do nothing but wait — the honest
default at low adoption is a halt.

**Code path.** `genesis_cohort.rs:75-140`; `tokenomics_v4.rs:115` (`SLOTS_PER_YEAR`).
No caller yet (module unwired), so this is a latent design bug, not a live one.

**Cost.** Zero — it is a self-inflicted liveness failure triggered by *lack* of
adversary participation. An adversary that wants to *induce* it only needs
independent staking to be slow through epoch 5, which is the expected state of a
cold launch.

**What closes it.** The cap needs a floor that keeps the cohort able to produce
until real independent stake exists: e.g. do not engage the taper until `O`
exceeds a threshold (independent-stake-gated, not purely time-gated), or clamp
`cap ≥ min(cohort_stake, liveness_floor)` so the set can never be driven below a
producing quorum. Guard `O == 0` explicitly and decide what it means (today it
silently means "eject everyone"). And resolve the pass-1 genesis-bootstrap gap
first — G2 is that gap wearing the decentralization rule as a trigger.

---

## G3 — Medium: the partition inherits F6; it adds no seed look-ahead

**Attack.** Were the partition wired, `epoch_committees` seeds its shuffle from
`SHAKE-256(DS_SORTITION ‖ beacon_mix ‖ epoch ‖ ROLE_PARTITION)`
(`committees.rs:95-102`) — the *same* `beacon_mix` that seeds the proposer roster
(`schedule.rs:152-153, 200-218`) and the per-slot subcommittees. `schedule.rs`
states the binding: "the beacon mix that seeds epoch `E` is fixed when epoch
`E-1` closes" (`:47-51`, echoed in `beacon.rs:220-231`). That is a **one-epoch
horizon with zero look-ahead margin**: the proposers of the trailing slots of
`E-1` are the ones who fold the last reveals into that mix, and each can reveal or
withhold (`beacon.rs:245-251`, the one-bit last-revealer choice). A run of `t`
controlled trailing slots yields `2^t` candidate mixes, and the grinder picks the
one whose epoch-`E` schedule best suits it — exactly finding F6, now also steering
which slot each of its validators lands in under the partition, and who proposes.

What the partition *does* remove: grinding cannot change the adversary's **finality
weight**, because the partition is by count, not stake, and every validator still
votes once — the union is invariant under the shuffle. So the grind buys
per-slot fork-choice control (concentrate your validators into one slot's
committee to dominate its LMD-GHOST weight, or scatter them to withhold several
slots' weight) and proposer-slot bias, not a finality quorum. That is the same
severity as F6: a reorg/censorship lever, not a safety break.

The honest point for this pass: the partition was sold partly as tightening the
committee story, and it does **not** introduce the seed look-ahead
(Ethereum's `MIN_SEED_LOOKAHEAD`, which finalizes the seed *before* the
adversary's slots) that F6 asked for. The grindability is unchanged and now spans
committee membership as well as the proposer roster.

**Code path.** `committees.rs:95-102`; `schedule.rs:47-51, 190-218`;
`beacon.rs:220-251`.

**Cost.** Forfeited proposer rewards for withheld trailing slots — cheap relative
to steering a slot's fork-choice committee; more stake ⇒ more trailing slots to
withhold.

**What closes it.** Same as F6: seed epoch `E`'s partition *and* roster from a mix
fixed at least one epoch before `E` begins (close of `E-2`, not `E-1`), so no slot
the adversary proposes can influence it; retain enough randao history; write the
residual-bias analysis. `[CONFIRMED]` that the crate carries no look-ahead and the
documented binding is close-of-`E-1`; `[SPECULATION]` on magnitude only because
the mix→epoch wiring lives outside this crate.

---

## G4 — Low/Medium: the churn floor overrides the 9% rate in a small network

**Attack.** The warm-up/cool-down budget is `max(total_active · 9%,
MIN_DELEGATION_SAT)` (`delegation.rs:182-184`). The floor is load-bearing for
*termination* — without it a geometric drain strands dust forever
(`:169-181`, documented with the 937,812-sat stuck-remainder test) — and
`MIN_DELEGATION_SAT = 10 BLCH` (`:50`) is the natural choice. That reasoning is
sound.

But the floor is an **absolute** amount, so as a *fraction* of the set it is
unbounded below a certain size. The 9% term dominates only while
`total_active ≥ MIN_DELEGATION_SAT / 0.09 ≈ 111 BLCH`. Below that, the budget is
the flat 10 BLCH, and the fraction of the set that can activate — or deactivate —
in a single epoch rises without limit: at `total_active = 20 BLCH` the floor is
50%/epoch; at 10 BLCH it is 100%/epoch. The invariant the module advertises —
"an actor holding idle coins could not move the entire validator set in a single
epoch" (`:13-17`) and "the set cannot be emptied at speed" — holds only above
~111 BLCH of active stake and degrades to nothing as the set shrinks.

At mainnet scale this never bites: the genesis cohort alone is billions of BLCH,
so `total_active · 9%` dwarfs the floor. The finding is **Low on its own**. It is
**Medium in combination with G2**: once the cohort cap collapses the set to a tiny
`O`, `total_active` is small, the floor takes over, and the surviving handful of
BLCH can be reconfigured wholesale per epoch — a fast set-reconfiguration lever
opening exactly when the chain is already fragile.

**Code path.** `delegation.rs:50, 166-184`.

**Cost.** Only reachable when `total_active < ~111 BLCH`, i.e. a nearly-empty or
collapsed network; no cost beyond holding a modest position in that state.

**What closes it.** Cap the per-epoch churn as a fraction of the set even when the
floor is active — e.g. `min(max(rate, MIN_DELEGATION_SAT), total_active)` is not
enough; the fix is to keep the *fractional* bound while guaranteeing at least one
`MIN_DELEGATION` can always move, e.g. by allowing the floor to admit only when
the 9% rate would strand a sub-`MIN_DELEGATION` tail, not on every small-network
epoch. Or accept it and document that the single-epoch-shift bound is
`max(9%, MIN_DELEGATION/total_active)` and only meaningful above ~111 BLCH.

---

## Vectors examined with no finding (stated, not padded)

### Partial activation — clean `[CONFIRMED]`

The window the brief asked about does not open into anything.

- A partially-activated delegation contributes `activated[i]` satoshis to
  `total_active` and to its validator's stake (`delegation.rs:206-217`), so it
  **does** carry consensus weight while `state_of` still reports `Activating`
  (`:405-409`). That is intended and internally consistent: `activated_sat`
  sums to `total_active`, which the fully-admitted set does not (`:378-389`).
  Consensus sees the real stake; the wallet sees the ramp. No double-count.
- Slashing uses `d.amount_sat` — the **full** bonded amount, not the activated
  slice (`apply_slash`, `:432`). A half-warmed delegation whose operator
  misbehaves is slashed on the whole amount: conservative, favors safety.
- The old F13 oscillation is gone. The activation loop skips any record with
  `deactivate_epoch <= e` (`:203`), so a deactivating delegation is never
  re-admitted and cannot soak the budget by oscillating. The activation-epoch
  ambiguity that drove F13 is closed by tracking `activated[i]` per record.
- Determinism holds: the queue is ordered by `(requested_epoch, validator,
  delegator, amount_sat)` with `amount_sat` now in the key (`:97-99`), closing
  the tie-break-by-caller-order consensus bug the comment documents.

I could not construct a state where partial activation grants weight faster than
9%/epoch, hides stake from the cap, or diverges between two nodes with identical
delegation sets.

### Whole-equivocator discard — fix is correct; one latent boundary risk

- The determinism fix is real `[CONFIRMED]`. Both `forkchoice::observe`
  (`:71-90`) and `finality::process_epoch` (`:221-239`) drop **both** halves of a
  conflicting pair. The outcome depends only on whether a conflicting pair exists
  in the node's message set, never on which half arrived first — the property the
  old "first-seen-wins" broke. `finality.rs`'s tests
  (`no_two_conflicting_checkpoints_in_one_epoch`,
  `equivocator_counts_for_no_target_and_is_reported`) pin it.
- **Framing an honest validator is not reachable through these functions.**
  Marking `V` an equivocator requires two messages attributed to `V` with the
  same slot/target and different roots. `finality.rs` takes only
  signature-verified attestations (`:77-80`, stated as the reason it takes bare
  `(validator, data)` pairs), and an honest `V` signs exactly one epoch-boundary
  vote per epoch and one per-slot attestation per assigned slot (one committee
  per epoch under the partition). An attacker cannot forge `V`'s ML-DSA‖Falcon
  signature to mint the second, conflicting message, and replaying `V`'s single
  genuine message is identical data, not a conflict (`duplicate_identical_vote_
  is_not_equivocation`). So the drop cannot be weaponized against a validator that
  behaves. `[CONFIRMED clean for finality.]`
- **The one latent risk is at the fork-choice boundary** `[SPECULATION — wiring
  absent]`. `forkchoice::Store::observe` (`:71-90`) authenticates *nothing* — it
  trusts the caller to have verified the signature, and unlike `finality.rs` it
  carries no comment saying so. Its ban is **permanent and in-RAM**
  (`equivocators` HashSet, "excluded from weight forever", `:34-36`). If the node
  wiring ever feeds it an unverified or replayed conflicting pair, an attacker
  evicts any validator from fork-choice weight permanently at zero cost. Close it
  by giving `observe` the same "signature-verified upstream" contract `finality`
  states explicitly, and consider scoping the ban to a slashing record in
  committed state rather than an unbounded process-local set. (A transient
  cross-node disagreement while only one half of a pair has propagated is
  inherent to equivocation handling and self-heals as gossip completes — not a
  new bug.)

### `sample.rs` index dedup — clean `[CONFIRMED]`

`sample` sorts eligible validators by index, then `dedup_by_key(index)`
(`sample.rs:88, 103`). Keeping the first occurrence after an index sort is
order-independent (the sort key *is* the dedup key), and the function stays total
— it rejects a malformed duplicate registry instead of panicking or, worse,
summing the stakes and granting the duplicate two ranges. The partition shuffle
applies the same `sort_unstable(); dedup()` (`committees.rs:88-89`). Correct.

---

## Recommended gate additions for A4 sign-off (G7), this pass

1. **G1 is a Phase-1 blocker and re-opens F1.** Wire the partition into
   `finality` (or delete the sampled committee) and add a KAT asserting the
   finality denominator is the whole active set. The status seal claiming "F1
   corrected" must not stand while `committees.rs` has no caller.
2. **Resolve G2 before any devnet launch.** The cohort cap must not be able to
   drive the active set to zero; gate the taper on realized independent stake,
   not on wall-clock epochs, and settle the genesis-bootstrap mechanism the
   fresh-genesis decision deleted. G2 and the pass-1 bootstrap gap are one problem.
3. Specify the beacon seed look-ahead (G3 = F6) as close-of-`E-2`, and add the
   grinding KAT — the partition did not supply this.
4. Give `forkchoice::observe` the explicit signature-verified contract
   `finality` has, and bound the equivocator ban.
5. Document the churn-floor fractional bound (G4) and treat it as live only in
   combination with G2.
