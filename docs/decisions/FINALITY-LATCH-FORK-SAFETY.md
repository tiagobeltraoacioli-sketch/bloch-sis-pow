<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The finality latch — what it is, and the fork-safety argument for arming it

```
Status:   SHIPPED INERT. `FINALITY_LATCH_ACTIVATION_EPOCH = u64::MAX`.
          Nothing here is armed and arming it is a founder decision.
Code:     crates/bloch-pos-committee/src/params.rs (the gate)
          crates/bloch-pos-node/src/engine.rs (the floor, the predicate, the guard)
Tests:    engine.rs, mod finality_latch_tests
Prepared: 2026-09-01, against main @ ad53573
```

## 1. The rule

**A node must never adopt a head that is not a descendant of its own finalized
checkpoint.**

## 2. What is broken without it

`FinalityState` is monotone: `process_epoch` replaces the finalized checkpoint
only with a strictly higher one (`finality.rs:458`). The node does not own one
`FinalityState` across a reorg. `Engine::do_reorg` takes an **ancestor's**
committed state, folds the winning branch onto it, and adopts the result — and
nowhere in `do_reorg`, `advance` or `ingest` is the incoming finalized
checkpoint compared with the outgoing one. The monotone rule is not violated;
its subject is swapped out from under it.

`TransitionError::FinalityRegression` (`transition.rs:3321`) does not cover
this. It checks that a header carries its own parent's committed roots — a
local consistency rule. Every block on the rewinding branch satisfies it,
because an older finalized root is exactly what that branch's parents commit.

**It is reachable, not merely callable.** Fork choice walks from the
**justified** root (`forkchoice.rs:184`, fed from `engine.rs:1229-1238`), so the
deepest cut LMD-GHOST may legitimately propose is down to the justified
checkpoint — and the state committed at that block already carries a finalized
epoch two below the head's. No invalid block, no misbehaving peer, no rule
broken.

**And it compounds.** After a rewind, `forkchoice_inputs` reads the justified
root out of the *rewound* state, so the next walk starts lower than the last one
did. Nothing pushes it back up. That descending ratchet is the mechanism behind
nodes observed far below their own finalized point — the same defect as the
single rewind, not a second one.

## 3. What the fix does

- `Engine::finalized_floor: Option<Checkpoint>` — a monotone high-water mark of
  the finalized checkpoint this node has committed. Raised in `apply_canonical`
  and in `do_reorg`; **never** lowered. It is a field on the engine and not a
  read of `self.state` precisely because `self.state` is what a reorg replaces.
  `None` until the node finalizes something of its own: genesis is "finalized by
  definition", not knowledge this node witnessed.
- `latch_violated(target)` — pure predicate: does `target` descend from
  `finalized_floor.root`, walking parents through the stored blocks, bounded
  against a cycle.
- `latch_refuses(target)` in `advance`, before `path_to_canonical` and before
  any adoption. `target` is the prospective head, so one check covers every way
  the chain can move: an extension always descends from the current head and so
  from the floor, and every rewind passes through this same value.
- A second check at the top of `do_reorg`, silent, because `do_reorg` is the
  only function in the engine that can make the canonical chain shorter and a
  rule about what may never be given back belongs where it is given back.

**Refusal is a stall, and that is the intended posture.** Reverting a finalized
checkpoint requires a third of the stake to have signed slashable votes. A node
that sees one must not quietly follow it. The armed node sets `needs_sync`,
asks the mesh, and keeps its chain.

## 4. Fork safety

### What the old binary does

Computes the LMD-GHOST head from the justified root over every stored block and
adopts it unconditionally — extending when it descends from the current head,
reorganising otherwise. If the head does not descend from the node's own
finalized checkpoint, it abandons that checkpoint silently.

### What the new binary does

Identical, plus: it maintains the floor, and before adopting any head it asks
whether that head descends from it. Below the flag day it logs
`FINALITY_LATCH_VIOLATION`, increments a counter, and **adopts anyway**. At or
above the flag day it refuses.

### Why no fork opens before activation

1. The gate is `epoch_of(state.slot()) >= FINALITY_LATCH_ACTIVATION_EPOCH` with
   the constant at `u64::MAX`. The largest epoch a `u64` slot can produce is
   `u64::MAX / 32`, so the comparison is **unsatisfiable** — the refusal is
   unreachable in a release build, not merely improbable. Pinned by
   `the_refusal_is_unreachable_while_the_gate_is_u64_max`.
2. Below the gate the only behavioural difference is a line on stderr and a
   counter. Neither is read by consensus. No state root, no block validity, no
   attestation and no proposal depends on either. Pinned by
   `below_the_flag_day_the_latch_changes_nothing_but_the_log`.
3. The floor field is written but read only by the predicate inside the (dead)
   refusal path.
4. Therefore, given the same blocks, an inert-latch node and a current node
   select the same head at every step, apply the same blocks in the same order,
   and compute the same roots. They are indistinguishable on the wire.

Note also that the gate reads the epoch derived from the **state**, never a wall
clock — reading node-local mutable time is what caused the 2026-08-08
`expected_bits` split.

### Why arming it is nevertheless a flag day

Head selection decides what a validator attests to and what a proposer builds
on. During a live rewind — the event the latch exists for — an armed node keeps
its head while an unarmed node follows the new one, and they attest to different
heads. That is a fork, even though no block's validity changed.

### Why this flag day is cheaper than the leak-recovery one

The latch changes no committed value. Boot replay drives `ingest` per block
(`engine.rs`, the replay loop), and the node's own log is a single linear chain,
so every target descends from the floor and the guard never fires during a
replay. There is therefore **no `StateRootMismatch` risk and no silent
parking** — the failure mode that makes `LEAK_RECOVERY_ACTIVATION_EPOCH`
dangerous. A straggler on the old binary stays a working node; it simply keeps
the ability to abandon its own finalized checkpoint.

### The operational cost, stated rather than glossed

An armed node that meets a genuine finality divergence **stops following the
network** and needs an operator. That is the correct trade — following would
mean serving a history the node itself contradicted — but it is a real cost and
it is why the detector ships hot and the refusal does not: nobody currently
knows how often this fires, and the counter is there to find out before anyone
decides.

## 5. Before arming

1. Run the inert binary on the fleet long enough to have a rate for
   `FINALITY_LATCH_VIOLATION`. If it is non-zero on honest nodes, arming it
   converts a silent safety violation into a visible stall — which is better,
   but it must be a decision, not a surprise.
2. Expose the counter through the RPC so the number is collectable without
   scraping logs. Not done in this change.
3. Choose `E` on the `docs/LEAKED-ROSTER-FLAG-DAY.md` procedure. Unlike that
   one, a partial rollout degrades safety rather than breaking liveness, so the
   rollout order should be reversed: arm the **highest**-stake boxes last, as
   there, but there is no need to hold the chain for stragglers.
