# Wave 67 — EN-08 future-block release slicing

Date: 2026-09-18
Requested base: `0a8e268`

## Residual addressed

Wave 66 limited the admitted-work scheduler to one block between slot-loop
checks. Authenticated near-future blocks did not pass through that scheduler
when their slot arrived: the slot-boundary path removed and reprocessed every
eligible entry from the separately bounded 32-block future pool in one loop
turn. A full pool could therefore execute 32 block paths before the next duty,
heartbeat, or scheduling check.

## Change

Future-block release now reprocesses at most one eligible block per slot-loop
turn. If another eligible entry remains, the loop:

- keeps attestation and proposal duties gated, so the validator cannot sign
  against a partially released view;
- refreshes ordinary metrics and store-rewrite status on the next turn; and
- continues immediately, without sleeping or processing a second admitted
  block batch first.

The final eligible block is processed before duties become available in that
same turn. Thus the change inserts bounded control points without delaying a
ready tail to the next wall slot.

Entries are still removed from the future pool before normal ingestion and
retain their original `Source`. Their initial transport verdict remains
`Ignore`; release is local and emits no second verdict. The stop-at-slot path
waits for an eligible tail to drain, preserving the previous ordering.

This is node-local scheduling only. Block validity, fork choice, wire formats,
persistent formats, peer scoring, and consensus rules are unchanged.

## Adversarial coverage

`ready_future_block_release_is_sliced_and_gates_duties` parks two distinct
authenticated proposals that are both eligible at the release slot. It proves
that:

1. the first call releases exactly one and reports a ready tail;
2. the ready tail closes the final validator-duty gate;
3. the next call releases the remaining block without stranding it; and
4. duties reopen only after no eligible future block remains.

The existing `a_block_far_ahead_of_the_wall_clock_is_refused` regression still
proves future admission tolerance, release timing, orphan promotion, and source
attribution.

## Residual risk

- One released block remains non-preemptible and may promote a bounded orphan
  chain during normal ingestion.
- The future pool remains count- and byte-bounded rather than partitioned by
  source. Existing admission verification quotas limit one source's CPU share,
  but a source can still occupy retained entries until their slots arrive.
- Draining a full 32-entry eligible pool still performs 32 block ingestions;
  it now exposes a control point between each rather than reducing total work.
- Duties deliberately wait for the eligible tail. On a slow host that can
  still miss a duty, but signing earlier would use an incomplete admitted view.
- Orphan promotion and fork-choice execution inside one block remain the next
  larger unit for any future cooperative-work slicing design.
