# Wave 66 — EN-08 cost-aware engine turns

Date: 2026-09-18
Requested base: `514ed42`

## Residual addressed

Wave 64 made the consensus-thread scheduler fair by event count, but a queue
containing only one class could still consume the full 32-event turn. Blocks
are the widest class: one admitted block can execute a transition, rebuild
fork choice, and release parked descendants. A 32-block batch could therefore
delay the next wall-slot and validator-duty check even though every individual
block was bounded.

## Change

The existing 32-event outer limit now also has node-local per-class slices:

- one block;
- eight attestations;
- eight transactions; and
- eight RPC calls.

The scheduler returns to the slot loop when every non-empty class has spent its
slice, even when the outer batch still has room. A block-only backlog therefore
causes one block to be processed between duty checks. Under a mixed backlog the
other classes retain the eight-event share they already received from strict
round-robin scheduling. FIFO ordering and the rotating class cursor remain
unchanged.

This is a processing slice, not admission or validity. Work remains queued with
its transport reservation until it is actually processed. Saturation continues
to shed or retry through the existing local overload paths and is never peer
fault. No wire encoding, consensus rule, fork-choice rule, persistent format,
or RPC schema changes.

## Adversarial coverage

- `block_flood_yields_to_the_slot_loop_after_one_event` queues 4,096 blocks
  followed by one event from every other class. It proves that the first turn
  serves one block and every other present class, then that a block-only tail
  yields after exactly one event.
- `sustained_mixed_backlog_is_cost_sliced_and_fifo_per_class` proves repeated
  mixed turns consume `[1, 8, 8, 8]` events while preserving each class's FIFO
  sequence.
- `lower_priority_backlog_cannot_hide_other_admitted_classes` retains the Wave
  64 proof that a 4,096-event lower-priority backlog cannot hide later classes.

## Residual risk

- Processing one event remains non-preemptible. In particular, one block can
  promote a bounded orphan chain before the slot loop regains control.
- Block transition and fork-choice cost varies with state and branch shape;
  one-event slicing bounds count between checks, not wall-clock milliseconds.
- Future-block release happens at the wall-slot boundary outside this fair
  queue and can release its separately bounded pool before validator duties.
- The attestation, transaction, and RPC slices are conservative count limits,
  not measured CPU budgets. Their existing byte, signature, timeout, and
  response limits remain the underlying cost bounds.
- The local queue still retains at most the already admitted transport/RPC
  capacity. This change reduces monopolization after admission; it does not
  increase admission capacity or guarantee service under sustained overload.
