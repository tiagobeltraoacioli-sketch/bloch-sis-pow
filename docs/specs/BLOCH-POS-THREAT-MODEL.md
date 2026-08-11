<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bloch PoS (Genesis-4 / Bell) — Threat Model

```
Document:   BLOCH-POS-THREAT-MODEL
Status:     DRAFT — adversarial review, Assistant A4
Created:    2026-08-11
Owner:      A4 (Adversarial review & security)
Reviews:    BLOCH-POS-SHA3-LATTICE-MIGRATION.md, BLOCH-TOKENOMICS-V4.md,
            crates/bloch-pos-committee/src/{sample,attestation,forkchoice,
            delegation,rewards,tokenomics_v4,params,interfaces}.rs
Scope:      consensus & economic design; the committee crate as written today.
```

## How to read this

Each finding states: **the attack**, the **code path or spec section**, the
**attacker cost**, and **what would close it**. Every finding is tagged
`[CONFIRMED]` (I read the code/arithmetic and it behaves as described) or
`[SPECULATION]` (design-level reasoning about parts not present in the reviewed
crate — the beacon, the taint oracle, the state-transition function, all owned
by DEV-1/2/3 and only present here as unimplemented traits).

The crate is explicitly **UNAUDITED and not wired into the node** (`lib.rs`), so
none of this is live. That is the right time to find it.

Two structural facts frame everything below:

- **Finality rests on a 128-validator *sample*, not on all validators.** The
  epoch committee is drawn by `sample::sample` (stake-weighted, 128 distinct
  validators). This is not Ethereum's model, where the per-epoch union of all
  slot committees is the *entire* validator set. That difference is the root of
  the two most serious findings (F1, F2).
- **The anti-capture story changed substrate but the code did not.** §4.1's
  taint machinery was built for a *flag-day fork* that carried the founder's 94%
  forward. Tokenomics V4 (§8-SUPERSEDED of the migration doc) replaces that with
  a *fresh genesis* where the founder holding is a new **untainted** vested
  allocation. So the taint code now guards coins that mostly no longer exist,
  while the real new concentration (17% founder + 24% other insiders, all
  untainted genesis allocations) sits entirely **outside** the taint set. The
  defense that actually binds in V4 is **vesting**, not taint (F4).

---

## Severity index

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | **Critical** | Finality quorum denominator is unspecified; both readings break (unreachable finality, or sub-⅓ stall) | CONFIRMED (ambiguity), SPECULATION (which was intended) |
| F2 | **High** | Per-slot and epoch attestations share one struct + one signing domain → honest validators self-slash on `DoubleVote`; cross-role replay | CONFIRMED |
| F3 | **High** | Delegation warm-up "head-of-queue always progresses" defeats the 9% rate limit for any single large record, both directions | CONFIRMED |
| F4 | **Medium** | Taint-based eligibility is defeated by an ordinary market/OTC coin swap; "taint actually binds" is overstated | CONFIRMED (design) |
| F5 | **Medium** | Taint *propagation* rule is never precisely defined; if not "any tainted input ⇒ all outputs tainted", mixing launders | SPECULATION (oracle not in crate) |
| F6 | **Medium** | RANDAO look-ahead depth unspecified → trailing-slot withholding can bias the *next epoch's finality committee*, not just one proposer slot | SPECULATION (beacon not in crate) |
| F7 | **Medium** | Public sortition + `SLOT_SUBCOMMITTEE_SIZE = 8` → cheap targeted DoS re-opens intra-epoch reorgs | CONFIRMED (design) |
| F8 | **Medium** | Concentration weaponization timeline: throttles slow but don't prevent; cap is Sybil-bypassed; ~hours to committee dominance | CONFIRMED |
| F9 | **Low** | `apply_slash` is a flat-penalty primitive with no correlation term → invites the exact non-amplified slashing §7.3 warns against | CONFIRMED |
| F10 | **Low** | Weak-subjectivity: 2048 epochs = 22.76 days is a checkpoint-age budget, not a "window"; spec phrasing conflates them; Foundation cadence dependency | CONFIRMED (math) |
| F11 | **Low/Note** | G2/G3 gate metrics computed on *uncapped* stake — safe direction, but inconsistent with the capped weight consensus samples | CONFIRMED |
| F12 | **Low/Note** | No assertion ties the emission-curve 40-year sum to `VALIDATOR_EMISSION`; only the allocation sum is pinned | CONFIRMED |
| F13 | **Low/Note** | `Registry::resolve` re-admits deactivated records in later epochs (reused `admitted` flag) → budget griefing; final state consistent | CONFIRMED |
| — | Genesis bootstrap | At Genesis-4 block 0 almost no stakeable float exists (validator emission = 0); who produces the first blocks / meets G1? | CONFIRMED (design gap) |

**Vectors where I found nothing to report** (stated explicitly, not padded):
grinding *of the sortition draw itself* (F-none, see §Grinding); u64/u128
**overflow** in the accounting paths (see §Overflow — clean); the fixed-point
**stake cap** against a single large operator (it binds as advertised, see F8).

---

## F1 — Critical: the finality quorum is a 128-sample, and the denominator is undefined

**Attack / failure.** `FinalityGadget::is_supermajority(stake_for_sat,
total_active_sat)` (`interfaces.rs:543-547`) asks "does `stake_for` reach ≥ ⅔ of
`total_active`?" `process_epoch_votes` (`:556-563`) is fed `stake_on_target_sat`
(sum of **epoch-committee** members who voted the target) and `total_active_sat`.
`StateReader::total_active_stake_sat` (`:391`) is the **network-wide** active
stake. The design never says whether the ⅔ denominator is *network* total or
*committee* total, and the two readings fail in opposite ways:

- **Denominator = network total active stake (the natural reading of the
  types).** Only 128 validators vote at the epoch boundary
  (`COMMITTEE_SIZE = 128`, `params.rs:17`; `FinalityGadget` doc: "Only the epoch
  committee's votes count here", `:539-542`). Their stake sums to at most
  `128 × cap`. With the **1% per-validator cap** (`delegation.rs:53`) and the
  dispersion the go/no-go gates *require* (G4 ≥ 200 validators, G3 Nakamoto ≥ 7),
  the 128 richest-sampled validators cannot hold ⅔ of network stake. Concretely:
  1000 validators at ~0.1% each → any 128-subset holds ~12.8% ≪ 66.7%.
  **Finality can never justify. The chain runs but never finalizes** — and the
  inactivity leak (`interfaces.rs:570`, §5.1) then starts bleeding stake because
  "finality has stalled" is permanently true. This directly contradicts §6.5.2's
  own contrast with Ethereum: Ethereum's per-epoch committee *union* is every
  validator, so ⅔-of-total is reachable; Bloch's epoch committee is a **sample**,
  so it is not.

- **Denominator = committee total stake.** Then finality is ⅔ of a 128-member
  stake sample, and **sampling variance lets a sub-⅓ adversary stall finality**.
  Back-of-envelope: an adversary with 30% of active stake, committee ~Bin(128,
  0.30), mean 38.4, sd 5.18; P(committee share ≥ 43/128 = ⅓) ≈ 19%. So in
  roughly one epoch in five, a 30%-stake adversary controls > ⅓ of the sampled
  committee and can withhold to block the ⅔ quorum — a liveness/censorship lever
  well below the nominal ⅓ safety threshold. (False *finalization* is hard: a
  40% adversary needs ≥ 86/128, ~6 sd out, negligible. The exploitable side is
  stalling, not forging.)

**Code path.** `interfaces.rs:391, 543-563`; `params.rs:17`; `delegation.rs:53`;
migration §5.1, §6.5.2.

**Cost.** Reading 1: zero — it is a latent liveness failure of the honest
system under the dispersion the project is *trying* to achieve. Reading 2: owning
~⅓ − ε of stake (which the gates try to prevent, but variance makes < ⅓ enough).

**What closes it.** Decide the denominator explicitly and prove the quorum is
both *reachable* and *safe* for the target validator count. If finality must be
⅔ of network stake, the epoch "committee" cannot be a 128-sample — it must be a
partition of the whole set (Ethereum's approach) or use vote aggregation
(§6.5.1) so *all* validators can sign. If it stays a 128-sample, pick a committee
size from an explicit failure-probability target (128 is far too small for a ⅓
safety margin — Ethereum uses thousands per epoch for exactly this), and the ⅔
must be of committee stake with the variance budget written down. This is a
Phase-1 blocker: it is the single most important number in the design and it is
currently undefined.

---

## F2 — High: honest validators self-slash because per-slot and epoch attestations are indistinguishable

**Attack (self-inflicted, and weaponizable).** There is **one**
`AttestationData` struct for both roles, and the crate says so:
"A per-slot subcommittee attestation and an epoch-boundary attestation use the
same struct" (`attestation.rs:18-20`). The slashing predicate is:

```rust
// attestation.rs:65-67
pub fn is_double_vote(&self, other: &AttestationData) -> bool {
    self.target_epoch == other.target_epoch && self != other
}
```

and `Offence::DoubleVote` = "Two distinct attestations with the same target
epoch" (`interfaces.rs:214-218`, classified by `SlashingRules::classify_
attestations`, `:663-666`).

Per-slot subcommittees are **independent stake-weighted draws per slot**
(`lib.rs:56-57`, `sample(beacon_mix, slot, …)`). A validator near the cap is
drawn in *many* slots of the same 32-slot epoch (with 8 seats over ~100
validators, ~2-3 slots/epoch is routine). Each of those attestations is for the
same `target_epoch = E` and differs in `slot`/`head`, so **any two of them
satisfy `is_double_vote`** (equal target, `self != other` because `slot`
differs). A validator that also serves on the epoch committee produces yet
another attestation with target `E`. Every honest validator that is sampled more
than once in an epoch is therefore **slashable evidence against itself**, and
anyone can harvest that evidence for the whistleblower reward (§7.3).

Even two *identical-intent* votes (same head/source/target) at different slots
trip it, because `self != other` is true whenever `slot` differs.

**Secondary — cross-role signature replay.** Both roles sign
`SHA3-256(DS_ATTEST ‖ …)` with the *same* construction (`attestation.rs:42-52`;
one domain tag `DS_ATTEST`, `params.rs:48`). A per-slot fork-choice signature
and an epoch finality signature over matching fields are byte-identical, so one
can be replayed as the other.

**Code path.** `attestation.rs:18-20, 42-52, 59-67`; `interfaces.rs:214-221,
663-666`; `lib.rs:55-63`; `params.rs:48`.

**Cost.** Zero — it fires on honest behavior. As an active attack: submit
evidence transactions harvesting other validators' routine multi-slot
attestations and collect ¹⁄₃₂ of each penalty while ejecting honest validators.

**What closes it.** Fork-choice (per-slot) attestations must be a *distinct
message class* from finality (epoch) attestations: a separate domain tag, and
the slashing predicates must only ever compare finality attestations to finality
attestations. Equivalently, forbid `target`/`source` on per-slot messages (they
carry only `slot`/`head` for LMD-GHOST) so they cannot be read as finality
votes. Either way the current single-struct/single-domain design is unsafe and
A2's fuzzers should include "same validator, multiple slots, one epoch."

---

## F3 — High: the warm-up rate limit's liveness escape defeats the rate limit

**Attack.** The 9%-of-active-stake-per-epoch warm-up (`WARMUP_RATE_BPS = 900`,
`delegation.rs:46`) exists so "an actor holding idle coins could **not** move the
entire validator set in a single epoch" (`:13-17`). But the queue admits the
head unconditionally:

```rust
// delegation.rs:151-166 (activation)
for (i, d) in queue.iter().enumerate() {
    ...
    if used + d.amount_sat > budget && any_admitted {
        continue;               // <-- only skipped once something is already in
    }
    used = used.saturating_add(d.amount_sat);
    any_admitted = true;
    admitted[i] = true;
    total_active += d.amount_sat;
    ...
}
```

The first eligible delegation each epoch is admitted **no matter how large**
(`any_admitted` is false at that point, so the guard is short-circuited). The
doc frames this as "bounding disruption to one record per epoch" (`:143-147`) —
but **one record can be an arbitrarily large fraction of stake**. An attacker
consolidates its position into a single delegation, ensures it sits at the queue
head (lowest `(requested_epoch, validator, delegator)`, `:84-86`), and it
activates **whole, in one epoch**. The 9% limit is bypassed. The cool-down path
has the identical escape (`:179`, `if released + d.amount_sat > budget &&
any_released`), so a single large record can also **deactivate in one epoch**,
defeating "the set cannot be emptied at speed" (`:17-18`).

**Code path.** `delegation.rs:46, 84-86, 148-166, 168-192`.

**Cost.** One delegation transaction for an attacker who already holds untainted
liquid stake. No extra coins, no waiting.

**What closes it.** The liveness escape should cap the *oversized* admission at
the budget and carry the remainder to later epochs (partial activation of a
single record), or split large deposits across a bounded per-epoch stake
ceiling. The invariant the module claims — "no single-epoch control shift" —
requires bounding admitted **stake** per epoch, not admitted **record count**.
Note this is partly masked by the per-validator cap (a single operator is
clamped to 1% effective weight anyway), which is why this is High and not
Critical — but see F8: with Sybil the cap does not save you.

---

## F4 — Medium: taint eligibility is laundered by an ordinary coin swap

**Attack.** §6.6.3 closes the *shielded-pool* laundering path (shield rejected on
tainted input; deposit rejected on shielded input — enumerated cleanly in
`interfaces.rs:279-339`, `DepositReject::{TaintedInput, ShieldedInput}`). But
tainted coins are, by explicit design, "fully spendable, transferable, and
identical for every other purpose" (migration §6.6.3). Taint follows the UTXO
graph, **not the economic actor**. So a tainted whale swaps: it sends tainted
UTXOs to a counterparty (an exchange, an OTC desk, a DEX) and receives the
counterparty's **untainted** UTXOs in return. The untainted coins it now holds
carry no taint and are freely stakeable. The market *is* the laundry, and §4.1
rule 4 ("tainted coins cannot delegate", `delegation.rs:76-77`, the `eligible`
flag) never triggers because the staking coins were never the tainted ones.

The migration doc claims "Taint propagation (rules 1 and 2) is the only one of
the four that actually binds" (§4.1). That is **overstated**: it binds the
*coins*, not the *wealth*. Whether it binds an adversary depends entirely on
whether enough untainted float exists to swap into — which is exactly the
distribution gate the design already gates on. So taint adds nothing the
distribution gate does not already provide, at the cost of a permanent
two-class-coin fungibility hit.

**And under Tokenomics V4 it is largely moot anyway.** The fresh genesis
replaces the founder's carried balance with a *new untainted* vested allocation
(17%), and the other insider buckets (VC/team/marketing, 24%) are likewise
untainted genesis outputs. The real Genesis-4 concentration is entirely outside
the taint set; the anti-capture defense that actually operates is **vesting**
(founder 0 spendable at genesis, `tokenomics_v4.rs:65-94`), not taint.

**Code path.** migration §4.1, §6.6.3; `delegation.rs:76-77, 122-124, 311`;
`interfaces.rs:279-339`.

**Cost.** Market friction / slippage on the swapped volume, bounded by available
untainted float. No protocol cost.

**What closes it.** Nothing at the protocol layer can, while tainted coins stay
transferable — this is inherent. The honest fix is documentary: stop claiming
taint "binds", state that taint == coin-tracking that a swap defeats, and rest
the anti-capture case on vesting + the distribution gate, which is where V4
already puts it. If taint is kept, it should be justified as *friction/visibility*
(rules 3-4 language), not as a binding control.

---

## F5 — Medium: the taint propagation rule is never defined

**Attack.** Everything above assumes the "obvious" propagation rule: *any tainted
input taints all outputs.* The specs never state it. §4.1.2 only says
"eligibility is tracked by taint propagation over the UTXO graph." The crate
delegates the whole question to an opaque oracle
(`StakeEligibility::deposit_input_status`, `interfaces.rs:361-363`;
`DepositInputStatus`, `:327-339`) — there is no propagation code to review. If
DEV-3 implements anything weaker than all-outputs-taint (e.g. taint only the
"change" output, or a value-proportional rule), then a single transaction mixing
1 sat of tainted with untainted inputs launders the untainted outputs, or
splits taint away from value. This is the classic taint-tracking pitfall and it
is undecided.

**Code path.** migration §4.1.2; `interfaces.rs:327-363`. No implementation
present.

**Cost.** One transaction, if the rule is weak.

**What closes it.** Specify the propagation rule normatively (recommend:
*any tainted input ⇒ every output tainted*, monotone, computed over full
ancestry at shield/deposit time), give it a KAT (A1), and fuzz mixing
transactions (A2). Until written, F4+F5 together mean taint provides no
guarantee that can be reasoned about.

---

## F6 — Medium: the beacon look-ahead lets trailing-slot withholding grind the *committee*, not just a proposer

**Attack.** §6.4/§6.3 correctly argue the sortition *draw* is not grindable: the
reveal is a preimage down a committed hash chain, so there is exactly one valid
`r_i` per slot and the proposer cannot re-sign for a better output (`interfaces.rs:
495-528`, `RandomnessBeacon`). Withholding (skipping your slot) remains, and the
spec bounds it at "one bit per withheld slot." **What the spec under-counts is
what that bit buys.** The next epoch's *entire* 128-member finality committee and
its per-slot subcommittees are drawn from the accumulated `beacon_mix`
(`sample::sample` seed = `DS_SORTITION ‖ beacon_mix ‖ index ‖ role`,
`sample.rs:108-115`). If epoch N's committee is derived from the mix as of the
**end of epoch N-1**, then whoever proposes the last `t` slots of epoch N-1 can,
by choosing to reveal-or-skip, grind `2^t` candidate mixes and pick the one whose
epoch-N committee contains the most of *their own* validators. Biasing the body
that decides finality is far more valuable than biasing one proposer slot, and
given the concentration the design already worries about, controlling a run of
trailing slots is realistic.

The migration doc never specifies the **seed look-ahead depth** (Ethereum's
`MIN_SEED_LOOKAHEAD` exists precisely to make the committee-deciding mix
finalized *before* the adversary's slots). `StateReader::randao_mix_at` keeps
only the "last 2 epochs" (`interfaces.rs:396-398`), which is not enough margin to
state a safe look-ahead.

**Code path.** `sample.rs:108-115`; `interfaces.rs:394-398, 495-528`; migration
§6.3, §6.4.

**Cost.** Forfeited proposer rewards for the withheld trailing slots — cheap
relative to steering a finality committee, and the more stake you hold the more
trailing slots you can withhold.

**What closes it.** Specify that the committee/proposer schedule for epoch N is
seeded by a mix fixed at least one epoch *before* N begins (so no slot the
adversary proposes can influence it), retain enough randao history to compute it,
and write a grinding analysis quantifying the residual bias as a function of
trailing-slot control. `[SPECULATION]` only because the beacon wiring is not in
this crate — but the sortition seed *is* here and it consumes `beacon_mix`
blindly, so the risk depends entirely on a look-ahead choice that is currently
unwritten.

---

## F7 — Medium: public sortition + an 8-node per-slot target re-opens cheap reorgs

**Attack.** Sortition is public by design (§6.4; `ProposerDuties` doc,
`interfaces.rs:405-416`): anyone computes the full schedule one epoch (~16 min)
ahead. `is_selected` (`sample.rs:167-176`) is a pure public function of committed
state. The per-slot fork-choice weight comes from just
`SLOT_SUBCOMMITTEE_SIZE = 8` validators (`params.rs:27`). An attacker who knows,
16 minutes ahead, exactly which 8 nodes carry slot S's fork-choice weight can
DoS those 8 for that slot. If they succeed, slot S contributes **no** LMD-GHOST
weight — which re-opens precisely the cheap intra-epoch reorg that §6.5.2 says
the subcommittee exists to prevent ("intra-epoch reorgs become cheap … ordering
would rest on slot number and the proposer signature alone"). The mitigation
"identity is an index, not an address" erodes over time: a validator's index
appears in every attestation it emits (`Attestation.validator`,
`attestation.rs:72-78`), and network-origin correlation deanonymizes index→IP.

**Code path.** `params.rs:27`; `sample.rs:167-176`; `attestation.rs:72-78`;
`interfaces.rs:405-416`; migration §6.4, §6.5.2.

**Cost.** Enough transient DoS capacity to knock out 8 known targets per 30 s
slot — modest, and the schedule hands the attacker the target list for free.

**What closes it.** This is an accepted surface, but the *size* is the lever:
8 is small enough that per-slot griefing is cheap. Options — raise
`SLOT_SUBCOMMITTEE_SIZE`, require sentry-node deployment as a G-gate rather than
a suggestion, and add a fork-choice rule that tolerates a few weightless slots
without cheap reorgs (e.g. proposer-boost-style weighting). At minimum, quantify
the reorg cost when the whole subcommittee for a slot is offline.

---

## F8 — Medium: how fast a large untainted position becomes committee-dominant

**Confirmed sub-results.**

- **The fixed-point cap binds a single operator, as advertised** `[CONFIRMED]`.
  `Registry::cap_sat` (`delegation.rs:226-243`) iterates `cap ← 1% ·
  Σ min(sᵢ, cap)`. I checked the recurrence: it is monotonically decreasing
  (lowering `cap` only lowers each `min`, hence the sum, hence the next `cap`),
  bounded below by 0, so it converges; the 32-round bound is deterministic and
  identical on every node. For one operator holding 90% of raw stake among 100,
  it converges to `cap ≈ 0.01·(cap + 0.1·T)` ⇒ `cap ≈ 0.00101·T`, i.e. the
  operator ends at **1.0% of the *capped* total**, level with a normal
  validator. The doc's ninefold-improvement claim is correct.

- **But the cap is Sybil-bypassed** `[CONFIRMED, and acknowledged in §4.1]`.
  Split that 90% across 900 identities of 0.001·T each; none exceeds the ~0.01·T
  cap, so nothing is clamped and the Sybil controls ~90% of effective weight.
  Cost is ~`MIN_DEPOSIT` per identity (`MIN_DEPOSIT_BLCH = 100,000`) or
  `MIN_DELEGATION_SAT = 10 BLCH` per delegation (`delegation.rs:50`) — trivial
  for a whale spending its own coins.

**The timeline.** Combine the Sybil bypass with F3 and the throttles: the
per-*validator*-count throttle `MAX_ACTIVATIONS_PER_EPOCH = 4`
(`interfaces.rs:612-617`) does **not** bound stake delegated to *existing*
validators, and the 9% warm-up is escapable per-record (F3). So an attacker with
a large untainted liquid position spreads it across dozens of Sybil validators
and activates ~9%+ of total stake per epoch; a 30% position reaches full
activation in ~4 epochs ≈ **1 hour**, each Sybil sitting just under the 1% cap,
for ~30% effective committee weight. The gates (G2 ≤ 25%, G3 Nakamoto ≥ 7) are
measured on the *operator* view (`top_share_bps`, `nakamoto_coefficient`,
`delegation.rs:279-307`) and, as the module itself admits (`:34-39`), cannot see
one owner behind many operators.

**Code path.** `delegation.rs:46, 50, 53, 226-307`; `interfaces.rs:612-617`;
migration §4.1.

**Cost.** The coins (must be untainted — the only real barrier, and F4 shows
that barrier is a market swap away) plus dust deposits per Sybil identity.

**What closes it.** Nothing on-chain resolves beneficial ownership; the honest
posture is that the gates measure operators and the true figure can be worse.
Practical hardening: fix F3 so the warm-up actually rate-limits stake; consider
a global per-epoch *stake* activation ceiling (not just a validator-count one);
and treat the operator-view gates as necessary-not-sufficient in the G-gate
sign-off language.

---

## F9 — Low: `apply_slash` is a flat penalty with no correlation term

`delegation::apply_slash` (`delegation.rs:336-351`) applies a caller-supplied
flat `penalty_bps` pro-rata across delegators. It has **no** correlation
amplification. §7.3 requires correlated-slashing amplification precisely so
"an entity running a thousand validators is punished no more per coin than one
unlucky solo operator" does **not** hold. The correlation *is* present in the
frozen interface — `SlashingRules::penalty_sat(offence, offender_stake,
correlated_slashed_sat, total_active)` (`interfaces.rs:689-695`) — but that trait
is unimplemented, and the only concrete slashing primitive shipped
(`apply_slash`) is flat. The risk is that callers wire the concrete flat
function and never compute the correlation, silently dropping the one mechanism
that makes coordinated (Sybil) equivocation cost more than solo bad luck.

**What closes it.** Make `apply_slash` take the correlation context (or delete it
in favor of the interface method), and give A1 a KAT where N coordinated
validators slashed in one window pay super-linearly.

---

## F10 — Low: weak-subjectivity math, and a phrasing that hides the real requirement

**The math** `[CONFIRMED]`. `SLOTS_PER_EPOCH = 32` × `SLOT_DURATION_SECS = 30`
= 960 s/epoch (16 min). `WITHDRAWAL_DELAY_EPOCHS = 2048` ⇒ 2048 × 960 s =
1,966,080 s = **22.76 days** (spec says ~22.8 ✓).

**The problem with the framing.** §7.2 and `interfaces.rs:636-641` say the
withdrawal delay "must exceed the window in which an exited validator could sign
a conflicting history at no cost." It does not *exceed* that window — it *is the
start of it.* An exited validator's stake is slashable during [exit, exit +
2048 epochs]; after withdrawal it can sign an alternative history for free, so
the free-signing window is [exit + 2048, ∞). What 2048 epochs actually sets is
the **maximum age of a weak-subjectivity checkpoint**: a node syncing from a
checkpoint older than 22.76 days can be fooled by a long-range fork built with
since-withdrawn keys. That is fine *only if* fresh checkpoints are published at
least every ~22 days. ADR-036 assigns checkpoint publication to the Foundation,
so weak subjectivity is not eliminated — it is a standing operational dependency
on an m-of-n Foundation key (§14.5). This should be stated as "requires a
checkpoint no older than 22.76 days," not as a self-securing "window."

22.76 days is on the **short** side (it forces frequent checkpoints and long-
offline nodes cannot fast-sync). That is a defensible trade, but the online
safety of the chain does **not** depend on it — only sync does — so no honest
online node is at risk. `[CONFIRMED]` the direction; the parameter is a policy
choice, not a bug.

---

## F11 — Note: gate metrics use uncapped stake (safe, but inconsistent)

`top_share_bps` (`delegation.rs:279-284`) and `nakamoto_coefficient` (`:292-307`)
compute G2/G3 from the **uncapped** `self.stakes` / `total_active`, whereas
consensus samples from **capped** `validators()` (`:251-267`). The uncapped view
is the *more conservative* one (it reports concentration consensus has already
flattened), so the gates fail safe. Worth a one-line spec note so a future editor
doesn't "fix" the inconsistency in the unsafe direction by switching G2/G3 to the
capped weight.

---

## F12 — Note: the emission curve's sum is not pinned to the allocation

`tokenomics_v4.rs:145-171` asserts, at compile time, that the *allocations* sum
to `TOTAL_SUPPLY` and that `VALIDATOR_EMISSION == 53.7 B`. Nothing asserts that
the chosen reward **curve** actually emits that much over 40 years. The decay
curve (`validator_reward_decay_sat`, `:319-331`; `INITIAL_ANNUAL_SAT`, `:317`)
is documented as binary-searched to zero residual, and truncation under-emits, so
today it is safe. But a future edit to `DECAY_NUMERATOR` / `HALVINGS` /
`INITIAL_REWARD_SAT` could silently over-emit past `VALIDATOR_EMISSION`,
breaking the supply invariant at runtime rather than at build. Add a
`const _: () = assert!(validator_emitted_*_by(EMISSION_SLOTS) <=
VALIDATOR_EMISSION_SAT)` for each curve.

---

## F13 — Note: `Registry::resolve` re-admits deactivated records

In `resolve` the `admitted` vector doubles as "currently active" (`delegation.rs:
129`). Cool-down sets `admitted[i] = false` (`:184`); the next epoch's activation
loop sees `admitted[i] == false && requested_epoch <= e` and **re-admits** the
already-deactivated record (`:151-166`), which the same epoch's cool-down loop
then releases again (`:171-192`). I traced this: the final `total_active` /
`stakes` at the target epoch are consistent (re-admit +amt then release −amt nets
zero), so it is **not** a state-corruption bug. But each oscillation consumes
activation `budget` (`used += d.amount_sat`), so a holder parking many large
deactivating-but-not-withdrawn delegations can soak the per-epoch budget and
**delay honest activations** (queue griefing). The module's own comment flags
this as reference-only (`:116-121`); a production impl carrying the activation
epoch in committed state avoids it. Flag it so the production version does not
inherit the oscillation.

---

## Genesis bootstrap gap

At Genesis-4 block 0, validator emission is 0 (it accrues over 40 years,
`tokenomics_v4.rs:100-103, 258-331`) and the only liquid float is Liquidity (5%)
+ Marketing TGE (25% of 4% = 1%) + carryover (≤ 0.3%) ≈ **6.3%**, most of which
is not staked. Yet a PoS chain needs a staked, attesting validator set to
produce and finalize block 1. G1 requires ≥ 15% untainted eligible stake
*deposited* — unreachable at launch from a fresh genesis with everything vesting.
The migration doc's answer (hybrid PoW phase seeding the set, §4.3, §10.3) was
**superseded** by the fresh-genesis decision (§8-SUPERSEDED), which removed the
hybrid phase — but nothing replaced the bootstrap mechanism. Who validates the
first epochs, and against which gate, is currently unspecified. This compounds
F1: a thin genesis validator set makes the 128-committee finality quorum even
harder to satisfy.

---

## Vectors examined with no finding

- **Grinding of the sortition draw** `[CONFIRMED clean at the crate boundary]`.
  `sample::sample` (`sample.rs:68-159`) takes `beacon_mix` as an opaque committed
  input; no proposer-controllable value enters the draw. Rejection sampling
  avoids modulo bias (`:118-136`), the eligible set is canonicalized by index
  before building the cumulative array (`:80-96`) so the result is independent of
  caller memory order, and role tags separate slot vs epoch draws
  (`:38-45`, `params.rs:76-77`). Given a correct preimage-bound beacon, the draw
  is not grindable. (The residual risks are in the beacon, not the draw — F6.)

- **u64 / u128 overflow in accounting** `[CONFIRMED clean]`. Every balance,
  stake, reward and penalty is `u128` (arithmetic contract, `interfaces.rs:31-40`;
  `tokenomics_v4.rs` throughout; cumulative stake `u128` in `sample.rs:98-106`;
  fork-choice sums `u64→u128` in `forkchoice.rs:66-74`). I checked the worst
  realistic products: `epoch_issuance · stake` (`rewards.rs:133`) ≈ 10¹⁶ · 10¹⁹ =
  10³⁵ ≪ u128::MAX (3.4·10³⁸); `balance · cap` (`tokenomics_v4.rs:140`) ≈ 10³³;
  even `TOTAL_SUPPLY_SAT²` = 10³⁸ fits (~29% of u128::MAX). The only narrowing to
  `u64` is `Validator::effective_stake`, and it is **saturated**, not wrapped
  (`delegation.rs:259-263`), with the ceiling (~10¹⁷ at 1% of 100 B) an order of
  magnitude below `u64::MAX`. The compile-time guard `TOTAL_SUPPLY_SAT >
  u64::MAX/2` (`tokenomics_v4.rs:168-171`) pins the reasoning. One boundary note:
  a triple product of supply-scale values *would* exceed u128 — no such
  expression exists today, but it is the next danger zone if accumulators grow.

- **Cap termination / determinism** `[CONFIRMED]`. See F8; monotone-convergent,
  fixed 32-round bound, identical on every node.

---

## Recommended gate additions for A4 sign-off (G7)

1. **F1 and F2 are Phase-1 blockers** — neither the finality quorum nor the
   attestation-role separation can be left to implementation.
2. Fix F3 before any devnet measures "time to activate a large position."
3. Rewrite the taint claims (F4/F5) and specify the propagation rule + KAT
   before the two-class-coin founder decision (§14.4) is taken on false premises.
4. Specify the beacon seed look-ahead (F6) and add a grinding KAT.
5. Resolve the genesis-bootstrap mechanism the fresh-genesis decision deleted.
