# Wave 73 — NET-04 / EN-08 deferred duplicate gate

Date: 2026-09-19

## Residual addressed

Wave 72 moved connected orphans into a bounded FIFO and promoted one per
control turn. The cheap duplicate gate in `ingest_one`, however, still checked
only unknown-parent orphans and future blocks. Once an orphan entered the
ready-to-promote FIFO its parent was known, so reoffering that same signed
envelope could traverse body commitments and hybrid verification again. An
unchanged repeat could also enter immediately through ordinary ingestion,
bypassing the cooperative promotion slice and leaving the queued copy to be
discarded only later.

This did not make the retained queues unbounded, but it restored remotely
triggerable CPU work and weakened the one-block-per-turn scheduling guarantee.

## Hardening

The pre-body, pre-signature duplicate gate now checks all three retained block
queues:

- unknown-parent `orphans`;
- ready-to-promote `deferred_orphans`;
- authenticated `future_blocks`.

Identity remains the signed header/block id plus proposer signature. This is
the existing branch-safety rule: a different signature is not collapsed merely
because a branch-dependent proposer index produced the same header id. Exact
reoffers return `Ignore` before body hashing or signature verification, retain
the original FIFO envelope and source, and cannot advance the head ahead of
their assigned promotion turn.

The Wave 72 global bound and deduplication remain unchanged:
`orphans.len() + deferred_orphans.len() <= ORPHAN_MAX` (256). Capacity pressure
and duplicate suppression remain local `Ignore` outcomes, never peer guilt.

## Compatibility

This is an early node-local no-op for an envelope already retained and already
judged. It changes no consensus validity, fork-choice ordering, wire message,
persistent format, source attribution, or production behavior. The retained
copy still follows the same transition when its FIFO turn arrives.

## Adversarial regression

`repeated_deferred_orphan_cannot_bypass_its_promotion_slice`:

1. parks a child before its parent;
2. lands the parent and verifies that the child moves to the deferred FIFO;
3. reoffers the same signed header 64 times from distinct synthetic sources,
   with a deliberately mismatched body that would expose entry into body
   validation;
4. proves every attempt is `Ignore`, produces no landing, does not move the
   head, and cannot replace or duplicate the original FIFO copy;
5. releases one normal orphan turn and proves the retained child still lands.

Focused validation:

```text
cargo test -p bloch-pos-node --bin bloch-pos deferred_orphan -- --nocapture
# 3 passed, 0 failed

cargo check -p bloch-pos-node --tests
# passed
```

## Remaining bounds

- A different proposer signature for the same header id remains retryable by
  design because deposited proposer identity can be branch-dependent. Existing
  per-source/global verification budgets bound that path; collapsing it here
  could change which valid branch is accepted.
- One genuinely new promoted block remains a non-preemptible transition.
- A control turn can still combine one future-block release, one orphan
  promotion, and the four-attestation held slice. A shared cost scheduler
  across these local release classes remains a possible future hardening.
- The duplicate lookup is linear over bounded local queues: at most 256 combined
  orphans plus the separately bounded future pool.
