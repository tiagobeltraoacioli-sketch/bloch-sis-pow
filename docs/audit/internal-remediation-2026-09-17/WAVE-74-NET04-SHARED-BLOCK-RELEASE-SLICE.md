# Wave 74 — NET-04 / EN-08 shared deferred-block slice

Date: 2026-09-19

## Residual addressed

Future blocks and connected orphans each had a one-block-per-control-turn
release limit, but the slot loop invoked both limits in the same turn. Under
simultaneous pressure, one ready future block and one promoted orphan could
therefore each execute proposal checks, a state transition, fork-choice
rebuilds, pruning, and secondary release work before the loop regained its
duty/control point. The individual queues were bounded and FIFO, but their CPU
budgets composed additively.

## Hardening

The two deferred block classes now share one aggregate block release slice:

- at most one class is released per control turn;
- a volatile two-class cursor alternates future and orphan work whenever both
  remain ready;
- if only one class is ready it progresses immediately;
- after a release, readiness is recomputed because a future block can become
  an orphan and a promoted orphan can unlock descendants;
- the loop continues without sleeping or admitting a new external batch while
  either ready tail remains;
- duty and `stop_at_slot` gates still see both tail flags independently.

FIFO order, source attribution, the combined 256-orphan cap, cross-queue
duplicate suppression, per-source future limits, and all existing `Ignore`
semantics remain unchanged.

## Compatibility

The cursor is node-local, volatile scheduling state. It does not change block
validity, the order inside either retained queue, fork-choice rules, wire
messages, signatures, or persistent formats. It can delay one already-retained
block by one control turn when both classes are ready; it cannot accept, reject,
or reorder blocks within a class.

## Adversarial regressions

- `deferred_block_classes_share_one_fair_slice` holds both classes ready for
  128 turns and proves strict alternation, then proves a newly ready competing
  class receives the next shared turn and empty queues select no work.
- `future_and_orphan_releases_share_one_block_transition_turn` builds a real,
  sequential `b1 -> b2 -> b3` chain, retains `b2` as ready future work and
  `b3` as its blocked orphan, then proves the first call applies only `b2` and
  merely moves the exact `b3` entry into the deferred FIFO; only a second
  control turn applies `b3`. The fixture asserts distinct block ids.

Existing class-specific regressions also passed:

- `ready_future_block_release_is_sliced_and_gates_duties`;
- `reverse_orphan_chain_promotes_one_block_per_control_turn`.

Focused validation:

```text
cargo test -p bloch-pos-node --bin bloch-pos deferred_block_classes_share_one_fair_slice
cargo test -p bloch-pos-node --bin bloch-pos future_and_orphan_releases_share_one_block_transition_turn -- --nocapture
cargo test -p bloch-pos-node --bin bloch-pos ready_future_block_release_is_sliced_and_gates_duties -- --nocapture
cargo test -p bloch-pos-node --bin bloch-pos reverse_orphan_chain_promotes_one_block_per_control_turn -- --nocapture
cargo check -p bloch-pos-node --tests
```

All four focused tests and the check passed.

## Remaining bounds

- One selected block remains a non-preemptible transition.
- The same turn can still combine that one block with the separately bounded
  four-attestation held-release slice. Cost-weighted sharing between block and
  attestation release remains a possible refinement.
- Signature variants for one header id are intentionally not collapsed when
  signatures differ, because proposer identity may be branch-dependent.
  Existing global/per-source verification budgets bound that retry path.
- Readiness checks scan the separately bounded future pool; orphan readiness is
  constant-time. Total drain time increases when both classes are saturated,
  but neither can starve under the round-robin cursor.
