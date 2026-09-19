# Wave 72 — NET-04 / EN-08 orphan-promotion slicing

Date: 2026-09-19

## Residual addressed

The orphan pool was bounded at 256 blocks, but one newly landed parent could
synchronously promote a full connected chain. Every promoted block can run a
state transition, rebuild fork choice, prune branches, and release more work.
That bounded memory, but not the non-preemptible work performed by one admitted
block before the slot loop regained control.

## Hardening

- A landed parent now moves matching orphans, in arrival order, into an engine
  FIFO and returns to the control loop.
- The loop promotes at most one orphan per turn, then reevaluates slot and duty
  gates before continuing the bounded tail without sleeping or admitting a new
  external batch.
- A landed promoted block schedules its children at the FIFO tail. This keeps
  the former worklist's breadth-first ordering.
- Validator duties and `stop_at_slot` stay gated while the promotion tail is
  non-empty, so they cannot observe a deliberately partial release.
- Waiting and ready-to-promote orphans share the existing global
  `ORPHAN_MAX = 256` cap and block-id deduplication. Ready work is not displaced
  by a new unknown-parent block; when the ready tail alone fills the cap, the
  newcomer is dropped and counted as a local eviction.
- `blocks_parked` includes both halves of the bounded orphan population.

The verdict still belongs only to the envelope currently submitted by the
caller. A parked block already returned `Ignore`; its later promotion is never
charged to the peer that supplied the missing parent. The cap path likewise
remains `Ignore`, not peer blame.

## Compatibility

This is node-local scheduling and volatile bookkeeping. It does not change
block validity, fork-choice inputs or ordering, wire messages, persistent
formats, signatures, or consensus constants. Locally produced blocks use the
same transition path and are not subject to a new validity rule.

## Adversarial regression

- `reverse_orphan_chain_promotes_one_block_per_control_turn` parks a five-block
  chain in reverse order and proves that each explicit control turn advances
  exactly one block while preserving order and eventual convergence.
- `deferred_orphan_tail_shares_the_hard_cap_and_deduplication` fills the ready
  tail to 256, proves a duplicate consumes no second slot, proves fresh remote
  work cannot make the combined population 257, and proves one drained slot
  admits exactly one new orphan.
- `an_orphan_is_admitted_when_its_parent_lands` retains the two-block liveness
  regression under cooperative release.
- `deferred_orphan_tail_uses_the_same_final_gate` proves signing remains gated
  while the local view is partially released.

Focused validation:

```text
cargo test -p bloch-pos-node --bin bloch-pos reverse_orphan_chain_promotes_one_block_per_control_turn -- --nocapture
cargo test -p bloch-pos-node --bin bloch-pos deferred_orphan_tail_shares_the_hard_cap_and_deduplication -- --nocapture
cargo test -p bloch-pos-node --bin bloch-pos an_orphan_is_admitted_when_its_parent_lands -- --nocapture
cargo test -p bloch-pos-node --bin bloch-pos deferred_orphan_tail_uses_the_same_final_gate
cargo check -p bloch-pos-node --tests
```

All passed. Network fixtures require permission to bind an ephemeral loopback
port; a broad sandboxed `orphan` filter therefore fails at fixture setup, not
in the assertions above.

## Remaining bounds

- One promoted block remains a non-preemptible transition; this change bounds
  amplification per control turn, not the cost of one valid block.
- A maximum orphan population can require up to 256 turns to drain. The loop
  does not sleep or admit a second external batch during that tail.
- Discovering newly unblocked entries scans the bounded orphan deque. Registry
  growth may schedule the whole pool in one scan, but subsequent expensive
  block processing is still sliced one per turn.
- In one loop turn the engine may still process one ready future block, one
  promoted orphan, and the separately bounded held-attestation slice. These
  are fixed local constants; total work is finite, but cost-weighted scheduling
  across those three classes remains a possible future refinement.
