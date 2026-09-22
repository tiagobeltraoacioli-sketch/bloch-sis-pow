# Wave 64 — EN-08/NET-04 engine class fairness

Date: 2026-09-18
Requested base: `97ceeaf`

## Residual addressed

Transport admission bounded count, bytes, and expensive verification, but all
accepted work still entered one FIFO engine channel. The loop inspected only
the first 32 messages. A legal 4,096-event transaction or attestation backlog
could therefore hide a later block or RPC call for many turns even though the
lower-priority traffic had already passed its own admission limits.

## Change

The consensus thread now drains already-admitted work into four node-local
FIFO queues: blocks, attestations, transactions, and RPC. It processes at most
32 events per loop turn using strict round-robin across non-empty classes.
FIFO order remains unchanged inside each class.

The look-ahead is capped at 4,160 entries: the network admission maximum of
4,096 plus the RPC listener's 64-worker global ceiling. Consequently, any
class present anywhere in the largest externally reachable admitted backlog is
visible to the scheduler, while one turn still performs no more than the
pre-existing 32 events before returning to slot duties.

Reservations remain attached until actual processing. Moving an event from the
channel to the local scheduler does not free network or RPC capacity early.
Existing overload behavior is unchanged: network shedding and RPC retry errors
remain local load decisions and never become peer fault.

This is scheduling only. It changes no wire encoding, gossip verdict, consensus
transition, fork-choice rule, RPC schema, or persistent format.

## Adversarial coverage

- `lower_priority_backlog_cannot_hide_other_admitted_classes` places 4,096
  transaction events ahead of one event from each other class and proves all
  four receive space in the first four-item turn, with transaction FIFO intact.
- `sustained_mixed_backlog_is_strict_round_robin_and_fifo_per_class` fills all
  four classes and proves every 32-event turn serves exactly eight from each,
  in per-class arrival order, until empty.

## Residual risk

- Fairness is by event count, not measured CPU time. One block or RPC call can
  still cost more than one small attestation; the existing byte, verification,
  timeout, and response-size limits remain the cost bounds.
- Processing one event is not preemptible. A single bounded expensive operation
  must finish before another class runs.
- In-process callers that bypass the 64-worker HTTP listener could enqueue more
  than the scheduler look-ahead cap. No untrusted production transport has that
  path; such callers remain a trusted integration responsibility.
- Strict round-robin reserves progress rather than latency equality. A block
  flood cannot starve transactions, and a transaction flood cannot starve
  blocks, but both reduce each other's throughput while coexisting.
