# Wave 71 — NET-04 held-attestation release slicing

Date: 2026-09-19
Requested base: `7a85a56`

## Residual addressed

Wave 70 limited one landed block root to 32 parked attestations, but the block
path still extracted and re-judged all 32 synchronously. A block event could
also promote several orphan roots, each immediately releasing its own share.
Those authenticated revalidations happened inside the non-preemptible block
event and bypassed the engine scheduler's per-turn slices.

## Change

Landing a block now queues its root rather than replaying every waiter inline.
The slot loop re-judges at most four held attestations per control turn:

- roots are queued in block-landing FIFO order;
- waiters for each root retain their original pending FIFO order;
- the front root remains first until its tail is drained, preserving the old
  root-release ordering across blocks;
- every slice refreshes store status, wall-slot state, and metrics before the
  next slice; and
- the loop neither sleeps nor processes another admitted-work batch while an
  already-judgeable tail remains.

Validator duties remain gated until every queued ready tail is drained. This
preserves the prior safety ordering: the node does not sign from a view that
has processed only part of the attestations made judgeable by blocks it has
already admitted. The final slice completes before duties reopen in that same
turn.

The pending pool exposes a bounded `take_waiting_on_limit` operation. It
removes only the selected FIFO prefix through the existing single `evict`
path, leaving all dedup, per-duty, per-root, and sequence indexes attached to
the tail. `pending_for_root` prevents empty release work from entering the
engine queue. Queue cardinality is bounded by the pending pool itself.

Released accepts retain the existing relay, equivocation-reporting,
doppelgänger, and fork-choice-pool behavior. Initial held messages already
received `Ignore`; deferred replay emits no peer verdict, and local overload
never becomes peer guilt. No consensus, validity, wire, committee, fork-choice,
or persistent format changes.

## Adversarial coverage

`pending_root_release_is_sliced_fifo_without_stranding_tail` parks ten distinct
authenticated duties under one root plus an independent root. It drains the
first root as `4 + 4 + 2` and proves exact FIFO order, accurate tail reporting,
complete index removal, and survival of the independent root.

`deferred_attestation_tail_uses_the_same_final_gate` proves the deferred tail
closes the node's final duty gate. The existing boundary-attestation regression
was updated to traverse scheduling plus one release turn and remains green,
including its branch/epoch seed requirement.

## Residual risk

- Four revalidations remain one non-preemptible unit and can each perform
  hybrid verification and committee derivation.
- A full 32-entry root still takes eight immediate loop turns. Duties wait for
  those turns by design; signing earlier would expose a partial admitted view.
- Multiple roots can fill the global 256-entry pending pool. They now cost at
  most four revalidations per turn, but total work remains 256 revalidations.
- The orphan promotion worklist itself remains synchronous. This change
  prevents each promoted block from also replaying its attestations inline;
  it does not yet cooperatively slice block promotion or transition work.
- While a ready tail drains, newly admitted network and RPC work remains in
  its existing bounded queues with reservations intact. This matches the
  former priority of synchronous release while adding control points.
- Held attestations do not retain forwarding `Origin`; this was existing
  behavior. Their initial transport verdict is already final (`Ignore`), and
  release only broadcasts locally accepted messages.
