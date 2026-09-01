<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Decision brief — arming `LEAK_RECOVERY_ACTIVATION_EPOCH`

```
Status:    DECISION BRIEF. Nothing in this document has been armed.
For:       the founder
Prepared:  2026-09-01, against main @ ad53573
Subject:   crates/bloch-pos-committee/src/params.rs:597
Scope:     what the flag day changes, what the floor should be, and what
           breaks if it is armed onto a fleet that is not uniform.
```

> **This brief does not arm anything and does not recommend a value for the
> floor.** `MIN_QUORUM_DENOMINATOR_NUM/DEN = 1/2` is a founder decision, taken
> knowing the residual, and it was already reversed once without being taken
> back to him — on 2026-08-24, to `3/4`, on another branch. The test
> `finality::tests::the_quorum_floor_is_the_one_the_owner_chose` exists to make
> that reversal loud rather than to argue the value is right. Nothing below
> changes it.

## 1. What actually activates

One constant gates **two** rules, and they are not separable today.

| Rule | Constant | Effect from the first epoch `>= E` |
|---|---|---|
| Leak recovery | `INACTIVITY_LEAK_RECOVERY_QUOTIENT = 16` | `leaked -= max(leaked/16, 1)` for every validator that participated this epoch (or for everyone once the chain is finalising again). Entries are removed at zero, so a fully recovered ledger is byte-identical to one that never leaked. |
| Quorum-denominator floor | `MIN_QUORUM_DENOMINATOR_NUM/DEN = 1/2` | The denominator the 2/3 test is measured against may not fall below half the **unleaked** active stake. |

Both live inside `FinalityState::process_epoch`
(`finality.rs:345-368` for the floor, `:494-556` for the recovery). Both are
gated on `votes.epoch >= LEAK_RECOVERY_ACTIVATION_EPOCH`.

Not in scope of this constant: the **duty roster** gate
(`LEAKED_ROSTER_ACTIVATION_EPOCH`), which decides whether a written-off
validator also stops winning proposer draws. That is a separate flag day at
epoch 1400 and is already rolled.

## 2. What the floor is worth, and what it is not

Write `p` for the fraction of the **original** active stake that is still
present. Once the absent stake has fully leaked, the 2/3 test with the floor in
place is `3p >= 2·max(p, 1/2)`, i.e. for `p < 1/2` it is `p >= 1/3`.

- A set holding **at least a third** of the original stake can still be rescued
  by the leak. That is the case the leak exists for, and the §5.1 recovery
  property is unchanged: `inactivity_leak_recovers_finality` still recovers its
  60/40 stall on the same epoch it always did.
- A set holding **less than a third** can never justify, however long it waits.
  The 2026-08-24 partitions were 4 of 64 — 6.25%.

**What it does not buy.** A floor of one half admits up to three pairwise
disjoint sets of exactly one third each. It bounds divergence from "any handful
of nodes" to "at most three ways". **It does not make the justified root
unique.** Uniqueness needs a floor above 3/4, at the price of never recovering
finality from an outage of more than half the stake. That is the safety /
liveness trade the founder already made, in the direction of liveness.

## 3. What breaks if it is armed onto a mixed fleet

This is the part that separates this flag day from the roster one, and it is
worse.

The leaked-roster runbook (`docs/LEAKED-ROSTER-FLAG-DAY.md`) can say *"the state
root is untouched — the leak values it commits are committed today already;
only who reads them changes."* **That sentence is false for this flag day.**

- The leak accumulator is committed into the state root:
  `ConsensusState.finality.leaked: Vec<LeakRecord>` (`state_root.rs:1187`).
  Recovery changes those values, so it changes the root.
- The floor changes **which checkpoints justify**, and the justified/finalized
  checkpoints are committed too.

So an armed node and an inert node, replaying the same block log, compute
different roots at the first epoch boundary that accrues or drains a bite.
`apply_block` re-validates the root at step 12 and returns
`StateRootMismatch`; `Engine::ingest` rejects and returns. The straggler does
not fork loudly — it **parks silently at an old height with a truncated chain
and cannot follow the live network either.** No panic, no alarm. The same
failure mode the `ANCESTRY_SEED_ACTIVATION_EPOCH` docs describe.

Two consequences for the procedure:

1. **The rollout must be complete, not merely mostly complete.** A single
   un-rebuilt validator is not a straggler that catches up; it is a node that
   stops. The roster flag day could tolerate one because the root did not move.
2. **The break point is the first epoch that touches the accumulator, not the
   flag day itself.** An empty accumulator serialises as a zero length, byte
   identical to a chain that never leaked, so on a healthy chain the divergence
   could lag the flag day. On today's chain the accumulator is **not** empty —
   the network has been leaking through a long stall — so divergence would be
   immediate, at the first boundary past `E`.

One thing is *easier* here than in the roster runbook. This gate reads
`votes.epoch`, which comes from `close_epoch` in the state transition
(`transition.rs:2795`) — a **chain-derived** epoch, not the wall clock the
roster gate reads (`slot = (now − genesis_time)/slot_ms`). Replay is therefore
deterministic: a rebuilt node replaying old blocks reproduces them under the
old rule and switches at exactly the same block on every machine. The
"activation arrives at `utc(E)` whatever the fleet is doing" hazard does not
apply. The "everyone must be armed" hazard applies more strongly.

## 4. Choosing E

The roster runbook's derivation still holds and should be reused:
`E = round_up_to_100(epoch_at_tag + 900)` — roughly 10 days, of which ~3 days
is a serialised rollout (a restart is a full replay of the block log) and the
rest is soak, decision margin and contingency. Two adjustments for this one:

- The "ready" predicate must be **100% of live validators on the armed binary**,
  not "the fleet is green". Add an explicit fleet census as a precondition to
  proceeding at the `E−180` decision point.
- There is no partial-rollback. Past `E`, an inert binary can no longer follow
  the chain, so a decision to abort must be taken **before** `E`, not after.

## 5. What the founder is being asked

1. **Arm, or hold?** Nothing below is urgent in the sense of a deadline; it is
   urgent in the sense that until it is armed, a partitioned handful of nodes
   can finalise its own branch and the Integration Book has to tell exchanges so.
2. **Split the constant, or keep it single?** Recovery and the floor are one
   gate today. They are independent rules and arming the recovery alone is the
   smaller change (it drains a ledger; it does not change who justifies).
   Splitting them costs one constant and one `if`, and it would let the
   recovery land first.
3. **Confirm 1/2 stands.** Restated here only so the answer is on the record,
   because it has been changed once without being asked.
