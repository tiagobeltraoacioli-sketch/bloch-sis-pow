<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ADR-041 — Delegation is off. Whether it stays off is a founder decision

- **Status:** **Proposed.** Nothing here has been decided. The *current* off
  state is documented and defended (see "What was actually done"), but that is
  a hold, not a ruling.
- **Decision owner:** founder. This is a consensus-visible decentralisation
  parameter, not an engineering preference.
- **Relates to:** `crates/bloch-pos-committee/src/delegation.rs`,
  `crates/bloch-pos-committee/src/genesis_cohort.rs`,
  `crates/bloch-pos-committee/src/transition.rs`
  (`CommittedState::apply_delegation`, the tag-`0x04` arm),
  `crates/bloch-pos-committee/src/params.rs`
  (`FUNDED_STAKING_ACTIVATION_EPOCH`),
  `docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` §11.1/§11.3, ADR-037 (carried coin is
  stakeable), ADR-038 (churn), ADR-033 (decentralisation model)

---

## 1. Context — an accident and a recommendation that happen to agree

Delegation does not exist on the Genesis-4 network. Three separate facts, each
verified rather than assumed:

1. **`CommittedState::apply_delegation` has zero production call sites.**
   Counted against the crate's source with the test modules cut off at the
   top-level `#[cfg(test)]`: every mention before that boundary is a doc
   comment or the definition itself. Every actual call is a test.
2. **The legacy carrier is dead and cannot be revived.** Wire tag `0x04`
   (`PosTransaction::Delegate`) is consensus-rejected in `apply_transaction` at
   *every* epoch, with both successor flag days forced open. Its own doc gives
   the reason: it names a `delegator: u32` and an `amount_sat` with no
   signature and no output spent — delegated consensus weight minted from
   nothing, which any committee member could have put in its own block.
3. **No funded successor exists.** The deposit got one (`DepositV2`, tag
   `0x07`, coins actually spent, proof of possession checked). Delegation did
   not — not in this tree, and not, on the searches recorded in §7, in any
   unmerged branch or worktree.

None of that was decided. It is an accident: the funded-format work stream
shipped the deposit half and never wrote the delegation half.

Separately, a security review recommended turning delegation **off on
purpose**, on the grounds set out in §2.

The accident and the recommendation agree, and that agreement is the whole
problem this ADR exists to name. An accident is invisible; the next person to
read `apply_delegation` sees a finished, tested function with no caller, files
it as a loose end, and helpfully wires it up — closing a security question
nobody knew was open. So the off state has been made explicit and defended
(§6), and the actual decision is put to the founder here.

---

## 2. The case for leaving delegation off

### 2.1 It is the cheapest route through the one blind spot the cohort cap names

The genesis-cohort cap (`genesis_cohort.rs`) is the only enforceable
decentralisation rule Genesis-4 has. It works on a **fixed, published** set —
the founder-operated launch validators — whose combined effective stake tapers
linearly from 100% at genesis to `COHORT_CAP_FLOOR_BPS` = **33.33%** at one
year and holds there. One third is not a round number: it is the share that can
stall a two-thirds quorum, so the rule says, as consensus rather than as a
promise, that after year one the founder cannot halt Bloch alone. The
corollary is the 66.67% figure: external stake takes two thirds of finality
weight in year one, regardless of how few external operators actually arrive.

That module already states its own limit, in its own words: *nothing prevents
the founder from funding new validators after genesis under addresses that are
not in the cohort, and no on-chain rule can see beneficial ownership behind
them.*

Delegation does not create that hole. It makes walking through it nearly free:

- The founder holds **17,046,829,380 BLCH** of the **18,146,400,000 BLCH**
  carryover — **93.9%** of the coin that exists and is liquid today
  (`LARGEST_CARRYOVER_ADDRESS_BLOCH` / `CARRYOVER_TOTAL_BLOCH`; 27.04% of the
  eventual 100 B supply, most of which is unissued).
- **ADR-037** settled that carried-over coin is stakeable like any other.
- The §4.1 taint set is retired and empty (founder decision, 2026-08-11), so
  `apply_delegation` writes `eligible: true` **unconditionally, by
  construction**, for anything it is handed. There is no provenance rule left
  that could refuse founder coin.

Funding validators outside the cohort requires 25,000 BLCH per deposit, keys,
machines and an operator identity per validator, all maintained. Delegation
requires none of that: the coins stay put, somebody else runs the box, and the
weight is attributed to *their* validator — an operator who may be entirely
honest and entirely unaware of being used as a front.

### 2.2 It does not merely evade the cap — it inverts it

This is the part that is easy to miss. The cap is a fraction of **total**
active stake, and delegated weight lands on **non-cohort** validators. So
delegating enlarges the base the cap is taken against, and therefore **raises
the founder's own permitted cohort weight**.

Write `C` for cohort weight (at the cap), `H` for genuinely independent stake,
`D` for founder-controlled stake delegated to non-cohort validators, `T = C + H
+ D`. At the floor, `C = 0.3333·T`, so `0.6667·T = H + D` and the
founder-controlled share is

```
F = (C + D) / T = 0.3333 + 0.6667 · D / (H + D)
```

| `D` (as a multiple of honest stake `H`) | founder-controlled finality weight |
|---|---|
| 0 | 33.3% — the rule working as designed |
| `H/3` | **50.0%** |
| `H` | **66.7% — the safety threshold** |

Delegating one third of the honest external stake takes the founder to a
majority. Delegating an amount merely *equal* to it reaches two thirds — where
the constraint stops being "cannot stall finality" and becomes "can finalise
whatever it likes". With 93.9% of the liquid supply in hand, `D` is not the
binding constraint; the only brake is the warm-up churn limit
(`WARMUP_RATE_BPS` = 25, ADR-038), which buys roughly 43 hours of publicly
visible queue and nothing else.

And consensus cannot tell any of this apart from success. Delegated weight
counted as non-cohort is exactly what a genuinely decentralising network looks
like. `delegation.rs` says the honest part itself: the concentration metrics
measure the *operator* view, and no on-chain metric can see beneficial
ownership behind several delegators.

### 2.3 The cohort cap is the control the whole 66.67% commitment rests on

If external stake is going to be 66.67% of finality weight in year one, that
number has to mean *independent*. A mechanism that manufactures apparent
independence does not weaken the cap at the margin; it makes the cap's output
uninterpretable. The security review's framing was: the cohort cap is the one
control that matters, so a mechanism that defeats it should not be built.

---

## 3. The case against — leaving it off has a real decentralisation cost

This side is not a formality, and it should not be read as one.

### 3.1 Without delegation, consensus participation requires 25,000 BLCH and a server

`MIN_DEPOSIT_SAT` = **25,000 BLCH** and a validator you operate yourself.
`MIN_DELEGATION_SAT` = **10 BLCH**. That is a 2,500× difference in the entry
ticket, plus the difference between running infrastructure and not. Delegation
is the only mechanism in the design by which a holder who is not an operator
takes part in consensus at all. Disabling it permanently means: **to have any
say in Bloch's finality, be rich enough and technical enough.** That is a
centralising force too, pointed the other way, and it is not smaller than the
one in §2 merely because it is diffuse.

### 3.2 It removes the growth path the cohort cap depends on

The cap does not decentralise anything by itself — it only *caps*. Somebody
still has to show up with independent stake, and the taper is a deadline:
33.33% by **2027-08-13**. The published concern is precisely that external
operators may not arrive in the numbers required. Delegation is the mechanism
that lets stake arrive without a matching number of *operators* — it decouples
"capital participating" from "people running servers", which is the harder of
the two to recruit. Turning it off narrows the funnel on exactly the
constraint that is already the binding one.

### 3.3 The commission and reward model assumes it

`delegation.rs` opens by saying so: commission is meaningless without delegated
stake, and pro-rata rewards to all stake only make sense if stake can sit
behind an operator without running one. Permanently off means the validator
economics are a different design from the one written down, and `rewards.rs`,
the commission field on `ValidatorRecord`, and the fee-registry resolution
become vestigial.

### 3.4 The rules that make delegation safe are already written and tested

This is not a feature that would have to be designed under time pressure. The
warm-up/cool-down rate limit (25 bps, wall-clock-justified in ADR-038), the
per-validator 1% cap applying to delegated stake, pro-rata slashing exposure of
delegators, the eligibility door, and the concentration metrics all exist, are
tested, and were argued through. What is missing is one wire format.

### 3.5 The §2 attack does not actually require delegation

Honest statement of the limit of my own argument: the founder can already fund
non-cohort validators and operate them, and `genesis_cohort.rs` says so.
Delegation lowers the cost and improves the disguise; it does not open a door
that is otherwise shut. Anyone claiming that keeping delegation off *prevents*
founder capture is overstating it.

---

## 4. A finding that cuts across both sides, and should be settled first

**`apply_cohort_cap` also has zero production call sites.**

Searched across every crate: `apply_cohort_cap` and `cap_status` appear only in
`crates/bloch-pos-committee/tests/committee.rs`. The single mention in
`crates/bloch-pos-node/src/main.rs` is inside `self_check()` and asserts the
*shape of the curve* (`cohort_cap_bps(0) == 10_000`, floor at one year) — it
does not apply the cap to any validator set the chain uses.

So the control that §2 is protecting is, today, **not enforced by the running
network**. This matters in both directions and should not be spun:

- It weakens §2 as an *urgent* argument: delegation cannot defeat a cap that is
  not yet biting.
- It strengthens §2 as a *sequencing* argument: enabling delegation before the
  cap is enforced means shipping the evasion before the rule, and after that
  the cap arrives into a stake distribution already shaped by it.

Either way, "is the cohort cap actually wired into the transition?" is a
higher-priority question than "should delegation be on?", and the answer
changes the weight of everything in §2. It is recorded here because it was
found while writing this ADR and would otherwise evaporate.

---

## 5. Options

- **A — Permanently off.** Delete `apply_delegation`, `delegation.rs`'s
  activation surface, and the delegation fields from committed state. Honest,
  irreversible without a hard fork, and pays the full §3 cost. Not recommended:
  it discards working, argued-through code to solve a problem §3.5 says it does
  not fully solve.
- **B — Off until the cohort cap is enforced and the taper has completed.**
  Keep the current state (no carrier, defended by test and docs). Revisit at
  the earlier of (i) `apply_cohort_cap` being wired into the transition with
  its own flag day, and (ii) 2027-08-13, the taper deadline.
- **C — Build the funded format now, with mitigations.** A signed delegation
  authorised by the delegator and spending real outputs, plus at least: the
  delegator's script hash committed on-chain (so concentration metrics can be
  computed over *funders*, not only operators), and a published, enforced
  exclusion of the genesis-cohort-adjacent addresses from delegating. Costs the
  most engineering and still cannot see beneficial ownership.
- **D — Off, and say so publicly.** B plus a statement in the release notes and
  on the site that delegation is not available and why, so nobody sizes a
  position on it.

## 6. Recommendation

**B, combined with D, and with §4 promoted ahead of both.**

Reasoning, stated so it can be argued with:

- The §3 cost is real but is **deferred, not paid**. Option B keeps the code,
  the rules and the argument intact; option A is the one that forecloses. There
  is no benefit to foreclosing today.
- The §2 risk is **asymmetric in time**. Enabling delegation is easy to do and
  effectively impossible to undo once stake has moved — unwinding it means
  ejecting real delegators. Leaving it off is reversible at any moment by
  writing the carrier that was going to be written anyway.
- §4 says the security argument's premise is not yet live. That is an argument
  for **fixing the premise first**, not for acting while it is unknown.
- The taper deadline (2027-08-13) is far enough away that B does not, by
  itself, put the 33.33% commitment at risk — but it is close enough that if
  external operators are not arriving by mid-2027, C stops being optional and
  the ADR must be reopened on schedule rather than in a hurry.

**What the founder is actually being asked to decide:** whether delegation is
permanently renounced (A), deferred with a named review trigger (B/D), or built
with mitigations (C). This ADR does not decide it, and the code does not decide
it either — it merely stops the question being answered by accident.

---

## 7. What was actually done, and what was searched

**Documented** (the security reason, not just the fact), at the three places a
developer hits the question:

- `transition.rs` — `CommittedState::apply_delegation`: a "DELIBERATELY
  UNREACHABLE, DO NOT WIRE IT UP" block with the §2 argument and a pointer
  here.
- `transition.rs` — the tag-`0x04` rejection arm: the same, correcting the
  previous comment, which said the flag day "will activate" a funded successor
  and so read as a plan.
- `params.rs` — `FUNDED_STAKING_ACTIVATION_EPOCH`: arming this constant does
  not and must not enable delegation.
- `delegation.rs` — module header: status note, since the file otherwise reads
  as a live subsystem.
- `docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` §11.1 (gate #7) and §11.3 (its arming
  preconditions).

**Defended** by `delegation_is_unreachable_and_may_not_be_wired_by_accident`
(`transition.rs`, source-scanning, in the shape of
`the_partition_coverage_guard_survives_into_a_release_build`). It checks, over
production source only — every crate file cut at its own top-level
`#[cfg(test)]`, since `apply_delegation` is `pub(crate)` and the committed
`delegations` field is private, making the crate the whole surface:

1. zero call sites of `apply_delegation`;
2. exactly one site that grows the delegation set, inside `apply_delegation`
   (this is the check that survives a rename or a carrier that bypasses the
   function);
3. the three notes recording *why* still exist.

Verified by breaking it, not by reading it. Mutation 1 wired the `Delegate` arm
to `apply_delegation`: red on check 1. Mutation 2 pushed a `Delegation` record
directly, never naming the function: red on check 2. Both reverted; the file is
byte-identical to before the mutations and the test is green.

**Searched**, for a funded delegation format, before asserting there is none —
recorded so the negative is auditable rather than assumed. See §8.
