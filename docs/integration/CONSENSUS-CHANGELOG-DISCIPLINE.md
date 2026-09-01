# Consensus-parameter changelog discipline

```
Document:   CONSENSUS-CHANGELOG-DISCIPLINE
Audience:   anyone changing a constant in bloch-pos-committee/src/params.rs,
            fee_market.rs or tokenomics_v4.rs
Status:     in force
Scope:      INTERNAL AND PARTNER-DELIVERED. Never published to the website,
            never a shared artifact. Delivered to integrators as a file.
Created:    2026-08-31, after an exchange audit found three claims in the
            Integration Book that the code did not support
```

## Why this exists

On 2026-08-31 an exchange integrating against Genesis-4 read
`BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` against `main` at `e4083f9` and found
three things we had not told them:

1. `staking::validate_deposit` has no production call site.
2. `unlock_epoch` does not appear anywhere in `bloch-pos-committee`.
3. The block payload cap doubled to 524,288 at epoch 800 — they found this
   one themselves, from the code, because the document stated the post-flag-day
   figure flat with no era attached.

The first two happened because unreleased branch work was described as current.
The third happened because a consensus parameter moved and nothing obliged the
document that quotes it to move with it.

Their own summary of why the third one bites is the sharpest statement of the
problem anyone has made:

> *"Conservation is an equality, so a stale fee assumption is a hard rejection
> rather than a slow confirm."*

That is exactly right, and it generalises. `Transition::apply_transfer` and
`apply_transfer_v2` both check `sum(inputs) == sum(outputs) + fee` with `!=`.
There is no tolerance band and no overpayment path — an overpaying transfer is
`ValueNotConserved` for the same reason an underpaying one is. So on this chain
a stale published parameter does not degrade an integrator's service, it stops
it: every transaction they sign is rejected, and the rejection names a value
mismatch rather than the parameter that actually moved.

A chain whose failure mode for stale documentation is total rejection cannot
treat its integration documentation as commentary. It is part of the interface.

## The rule

**A change to any constant an integrator can observe must land in one commit
with the document that publishes it and the test that pins it.**

Three artifacts, one commit, no exceptions:

| | Artifact | What it is for |
|---|---|---|
| 1 | the constant | the change itself |
| 2 | `crates/bloch-pos-committee/tests/integration_book_claims.rs` | makes the stale document a red test |
| 3 | `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` | tells the people who will be rejected |

If the change cannot be made in one commit, it must not be made. Splitting it
is how a document goes stale: the constant lands on Tuesday, the doc update is
a follow-up nobody files, and the next integrator builds against Monday's
number.

## What counts as observable

A constant is observable if an integrator can be rejected for disagreeing with
it. That is a wider set than "consensus-critical", and it is the set that
matters here.

**Class A — arithmetic an integrator must reproduce exactly.** Getting these
wrong is `ValueNotConserved` on every transaction. This is the class the
exchange's remark is about.

- `fee_market::TX_FLAT_GAS`, `GAS_PER_BYTE`, `HYBRID_VERIFY_GAS` and the
  `HYBRID_VERIFY_INSTRUCTIONS` / `INSTRUCTIONS_PER_GAS` pair it derives from
- `fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS`, `BASE_FEE_CHANGE_DENOMINATOR`
- `fee_market::MILLISAT_PER_SAT` and the round-up rule in `fee_parts_sat`
- `tokenomics_v4::SAT_PER_BLOCH`

**Class B — capacity, which decides whether a built transaction can be
included at all.**

- `fee_market::MAX_BLOCK_TX_BYTES`, `MAX_BLOCK_TX_BYTES_V2` and both targets
- `fee_market::BLOCK_GAS_LIMIT` and `BLOCK_GAS_TARGET`

**Class C — activation gates, which decide which of A and B is in force.**
A gate change is the most dangerous edit in this table, because it moves
parameters without touching them.

- every `*_ACTIVATION_EPOCH` in `params.rs`

**Class D — cadence and settlement, which decide an integrator's timeouts and
credit policy.**

- `params::SLOT_DURATION_SECS`, `SLOTS_PER_EPOCH`
- `params::INACTIVITY_LEAK_THRESHOLD_EPOCHS`, the quorum floor
- `staking::ACTIVATION_DELAY_EPOCHS`, `MAX_ACTIVATIONS_PER_EPOCH`,
  the exit and withdrawal delays

**Class E — node-local policy that is nonetheless visible on the wire.** Not
consensus, and still capable of making an integrator's transaction disappear.

- `engine::MEMPOOL_MAX`
- `engine::REJECTION_TTL_SLOTS` *(unreleased — see below)*
- `rpc::UTXO_PAGE_DEFAULT`, `UTXO_PAGE_MAX`

## What a change must notify, and where

### 1. The test, first

Add or update the assertion in
`crates/bloch-pos-committee/tests/integration_book_claims.rs` **before**
changing the constant. Every test in that file names the Integration Book
section it pins. Writing the assertion first is what proves the document
actually says the thing you are about to invalidate — and occasionally proves
it does not, which is its own finding.

The file's job is not to re-test consensus. Consensus rules have owners
(`transition::tests::a_transfer_that_does_not_conserve_value_is_refused` owns
strict equality; `fee_market::tests` owns the cap era switch). Its job is to
make *the document* a build artifact, so that a stale claim fails in CI with
the section number in the assertion message.

### 2. The document, in the same commit

Update `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md`:

- the figure itself, wherever it appears — including the §9 checklist, which
  is what integrators actually paste into their planner;
- the **status marker** on the claim (see the book's §0), if the change moves
  it between *live*, *scheduled* and *unreleased*;
- the **measured-at line** at the foot of the document. A book that quotes a
  parameter must say which chain state it was measured against, because that
  is what lets a reader decide whether to trust it.

### 3. The machine-readable surface

Anything that changes the RPC surface — a method, a response field, an error
code, a limit — also belongs in the surface tables in
`crates/bloch-pos-node/src/rpc.rs`: `RPC_SURFACE`, `RPC_ABSENT`,
`RPC_ERROR_CODES`, the `limits` block, and `RPC_SURFACE_VERSION`.

**This is a different contract from this one and it has its own owner.** The
division of labour is deliberate and integrators should be told both halves:

| | `getcapabilities` | this discipline |
|---|---|---|
| answers | "what does *this node* serve?" | "what do the numbers mean?" |
| source | the running binary | the constants, pinned by tests |
| covers | methods, fields, error codes, limits, auth, transport | fees, capacity, gates, cadence |
| staleness | impossible — the node describes itself | prevented by CI |

A client should branch on `getcapabilities` at connect time and never on this
document's method tables. This document owns the arithmetic, which
`getcapabilities` deliberately does not carry: a node cannot tell you what its
fee constants *will be* after a flag day.

`selfcheck` is the offline half of the same idea — it asserts the frozen
parameters agree with each other at startup, so a binary built with an
inconsistent parameter set refuses to run rather than forking. When
`selfcheck --json` lands, its output becomes the third leg: `getcapabilities`
for the wire surface, `selfcheck --json` for the parameter set the binary was
built with, and this document plus its test file for what those parameters
mean to somebody building a transaction. **Do not duplicate the parameter dump
into the Integration Book.** Point at `selfcheck --json` and keep the book to
the parts a machine cannot emit: the derivations, the caveats and the reachable
/ unreachable distinction.

### 4. The integrators, by name

Consensus-parameter changes are delivered as a **file, to named contacts**.

- Never published to the website. Never a shared artifact. This is the standing
  rule for partner and exchange integration material and it has no exception
  for "it is only a constant".
- English.
- Sent when the change **merges**, not when it activates. An integrator needs
  to rebuild their planner before the flag day, not after their first
  rejection.

The notice states, in this order: the constant, its old and new values, the
epoch at which the change takes effect, and the concrete failure an integrator
who does nothing will see. That last item is the one that gets acted on. For
Class A and B it is always the same sentence and it should always be said:

> Transactions built against the old value will be rejected with
> `ValueNotConserved`, not delayed.

## Activation gates: the rule that has its own section

A gate is the only edit that changes an integrator's arithmetic without
changing an arithmetic constant, so it gets stricter handling.

**Arming a gate is a document change.** Lowering `*_ACTIVATION_EPOCH` from
`u64::MAX` to a real epoch moves a claim from *unreachable* to *scheduled*, and
crossing that epoch moves it from *scheduled* to *live*. Both transitions
change what the Integration Book may state as fact, and the second one happens
on its own, with no commit — which is why the book records the gate value
rather than only its effect, and why
`book_activation_gates_are_classified_not_assumed` asserts the classification
rather than the number.

**Three states, and the book must distinguish them:**

| State | Meaning | How the book may describe it |
|---|---|---|
| **open** | gate ≤ current epoch | as current fact |
| **armed** | gate is a real future epoch | as scheduled, **with the epoch** |
| **inert** | gate is `u64::MAX` | as not implemented on the wire — never as a capability |

The failure this prevents is the one that produced two of the three audit
findings: code that exists, compiles, is tested, and cannot be reached. A
document that lists such a capability without the distinction overstates the
binary. "It is in the code" is not a wire guarantee, and an integrator who
reads it as one will design against a path that returns an error.

The standing constraints on arming, from `params.rs` and not negotiable here:
a gate must be **strictly in the future** and **after the fleet rollout
completes**. Arming an epoch already in the past fails silently — that is how
1,600,000 BLOCH escaped a write-off that never fired.

## Unreleased work

**Never describe unreleased behaviour as current.** This is what produced the
`validate_deposit` and `unlock_epoch` findings, and it is the failure this
whole discipline exists to stop.

Branch work may be described in the Integration Book only in a section that
says so, names the branch, and states plainly that the released binary does not
do this. Two rules:

- The **released binary** is the subject of every unmarked sentence. If a
  statement is true only on a branch, it goes in the unreleased section or it
  does not go in.
- A parameter that exists only on a branch is pinned by a test **on that
  branch**, not on `main`. Adding the constant to `main` to make a test pass is
  shipping the change, not documenting it.

`REJECTION_TTL_SLOTS` is the current example. It is `128` slots (≈ 64 minutes)
on `canario/cache-recusa` and does not exist on `main`. Its behaviour is
already pinned there by
`a_refused_transaction_does_not_come_back_through_gossip` (which asserts the
bar lifts at exactly `slot + REJECTION_TTL_SLOTS`) and
`the_rejection_cache_is_bounded`. When it merges, its entry moves from the
book's unreleased section to §6 and its pin moves into
`integration_book_claims.rs` in the same commit.

The expiry is a **design property, not an implementation detail**, and the
book must say so when it lands: the bar lifts. Refused bytes are not
permanently invalid, because the reason a transaction was refused is usually
about the chain state at the time, not about the bytes — a transfer priced at a
base fee that has since moved becomes valid again when the price comes back. A
permanent ban would turn a transient pricing error into a dead transaction and
would make the node's mempool a place where an integrator's coins go to be
quietly unspendable. An integrator whose transaction was refused should be told
they may retry after the TTL, which is a different instruction from the one
`-32008 TX_REFUSED` carries at the RPC layer ("never resubmit these bytes") —
and the two must not be conflated in the document.

## Checklist

Before merging a change to any constant in the classes above:

- [ ] Assertion written or updated in `integration_book_claims.rs`, naming the
      book section it pins
- [ ] The test goes red against the old value and green against the new one
- [ ] Integration Book updated: the figure, every restatement of it including
      the §9 checklist, the status marker, the measured-at line
- [ ] If the RPC surface moved: `RPC_SURFACE` / `RPC_ABSENT` /
      `RPC_ERROR_CODES` / `limits` / `RPC_SURFACE_VERSION` updated by that
      contract's owner — coordinate, do not duplicate
- [ ] If a gate was armed: epoch is strictly in the future, rollout is
      complete, and the book's gate table records the value
- [ ] Notice drafted for named integrator contacts, in English, stating the
      concrete failure — as a file, not a published page
- [ ] All of the above in **one commit**
