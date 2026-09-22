# Wave 65 — EN-09 proposal-duty retention

Date: 2026-09-18
Requested base: `6e3328d`

## Residual addressed

An authenticated validator key could submit arbitrarily many distinct block
proposals for one proposer/slot duty. Losing variants remained in the orphan,
future-block, or fork-choice collections and made subsequent fork-choice work
grow with attacker-chosen equivocation count.

## Change

Live gossip admission now retains at most two distinct authenticated proposals
for one `(genesis proposer index, slot)` duty:

- the first is the protocol-intended proposal;
- the second preserves the complete equivocation pair; and
- later variants are `Ignore`, never `Reject`, because a valid signature proves
  key equivocation but does not prove misconduct by the forwarding peer.

The bound is applied after proposer authentication but before body hashing,
transaction decoding, orphan/future retention, or fork-choice insertion. Exact
proposal ids are remembered so release from the future queue and promotion
from the orphan queue do not charge the same proposal twice. Boot replay records
canonical proposals through the same index.

The admission index is pruned at the existing finalized floor. It records only
genesis validator identities, whose key assignment is immutable on every
branch. Deposit-added indices remain exempt because competing branches can
assign the same new index to different keys; applying a head-derived cap there
would recreate the branch-context identity bug.

Local production is never refused by the node-local gossip cap. No block
validity, wire encoding, fork-choice rule, persistent format, or peer score
changed.

## Adversarial coverage

`third_genesis_key_proposal_for_one_duty_is_ignored_without_peer_blame` starts
with a retained canonical proposal, parks a second signed variant as the
evidence pair, then submits a third signed variant through a different source.
It proves `Ignore`, unchanged orphan/fork-choice retention, and that the next
slot remains admissible rather than turning the cap into a durable key ban.

Existing out-of-order promotion coverage also exercises the exact-id lifetime:
a proposal observed before its parent can be promoted without consuming a
second duty slot.

## Residual risk

- EN-09 remains partial. One compromised genesis key can retain two proposals
  per slot while finality is stalled, so growth is rate-bounded rather than
  absolutely bounded over unlimited wall time.
- Multiple compromised validator keys multiply that bounded rate.
- Deposit-added validator identities remain outside this cap until admission
  can authenticate them against parent-derived branch state.
- Two retained variants can each carry the maximum bounded block payload and
  attestations. Existing byte limits and verification budgets bound arrival
  cost, but retained branch memory still scales with duties above finality.
- A selected operation remains non-preemptible; Wave 64 supplies class
  scheduling fairness but not CPU-time preemption inside block processing.
