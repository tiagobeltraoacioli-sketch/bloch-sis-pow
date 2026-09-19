# Wave 70 — NET-04 pending-root release amplification

Date: 2026-09-19
Requested base: `e3fb033`

## Residual addressed

Engine scheduling now admits and releases at most one block per control turn,
but one landed block called `release_held` for every attestation waiting on its
root. The pending attestation pool was globally capped at 256 and per duty at
two, yet all 256 authenticated entries could name one missing root. One block
arrival could therefore replay the entire pool inside a single non-preemptible
block event, bypassing the event-count scheduler slice.

## Change

The node-local attestation pool now parks at most 32 authenticated attestations
under one missing block root. The existing limits of 256 globally and two per
duty remain in force. Other missing roots retain independent headroom, so one
root can occupy at most one eighth of the global pending pool.

The check uses the existing `pending_by_root` index immediately before hold.
No source or peer identity is invented, and no second quota cache or lifetime
state is added. `take_waiting_on` already removes every sequence from that
index, so a block release immediately reopens capacity for the root.

Overflow returns the new internal `PendingRootLimit` Ignore reason. It never
becomes Reject or peer score: a valid attestation racing a missing block is
ordinary timing, and retention saturation is this node's load state.

This pool is ephemeral relay state. The change does not alter attestation or
block validity, committee selection, fork choice, wire encoding, consensus,
or persistent formats. Local production is unaffected.

## Adversarial coverage

`one_landed_root_releases_only_its_bounded_pending_share` uses distinct valid
duties so the existing per-duty limit cannot mask the root limit. It proves:

1. one missing root parks exactly 32 authenticated waiters;
2. its next distinct duty receives `Ignore(PendingRootLimit)` and is not held;
3. an independent missing root still parks successfully;
4. releasing the saturated root extracts exactly 32 entries and leaves the
   independent root intact; and
5. the previously ignored attestation can park after release, proving the
   existing index provides correct quota lifetime.

The focused pending-pool suite also keeps the per-duty cap and deterministic
global FIFO eviction regressions green.

## Residual risk

- A single landed root can still replay 32 hybrid-signed attestations. The cap
  establishes a finite per-root slice; it does not make replay preemptible.
- One ingress can promote several bounded orphan roots, and each promoted root
  can release its own 32-entry share. The global 256-entry attestation cap and
  256-entry orphan cap remain the outer bounds on that combined amplification.
- An attacker controlling valid duty keys can spread waiters across eight or
  more missing roots and fill the global pool. No Sybil-resistant transport
  identity is assumed or fabricated here.
- Honest unattributed timing races for the same root share the 32-entry limit.
  Dropped attestations can be re-gossiped after the block arrives, but a burst
  larger than the slice can lose this node's first relay opportunity.
- Release re-judges retained attestations against current branch context. Its
  cryptographic and committee work remains bounded by the retained share, not
  by measured wall-clock time.
