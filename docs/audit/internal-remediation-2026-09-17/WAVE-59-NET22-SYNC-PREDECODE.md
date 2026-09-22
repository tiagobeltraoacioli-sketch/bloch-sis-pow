# Wave 59 NET-22: directed-sync admission before envelope decode

Date: 2026-09-18. Base: `9a0dd11`. Scope: production libp2p directed-sync
receive admission, one focused regression, the existing cold-sync regression
and this evidence note. No endpoint, protocol identifier, wire encoding,
consensus rule, persisted format or deployment changed.

## Correction

A directed sync response was bounded to 8 MiB and 128 envelopes, and each
decoded block needed the shared source/backlog allowance before it could enter
the engine channel. The allowance was acquired only after decoding the whole
envelope, however. A peer answering an expected request could therefore buy
canonical block parsing and decoder allocations even while its first-hop
allowance was already saturated.

The sync receive loop now reserves the envelope's already-bounded encoded byte
length against the authenticated `PeerId` before calling `decode_envelope`.
Successful decoding attaches that RAII reservation to the directed-sync
`Origin`, so the ordinary engine path releases the same charge and `Loop::emit`
does not charge it twice. Decode failure, noncanonical size disagreement,
channel failure and ordinary event drop all release the guard automatically.

When admission is saturated, the rest of the response page is not decoded.
Saturation is local overload, not peer misconduct, so no rejection verdict or
score penalty is manufactured. A page interrupted by saturation or malformed
input is also no longer chased from its highest decoded slot: the next periodic
sync request starts from the applied head, preserving the recoverable gap
instead of advancing a speculative cursor past it.

## Regression

`sync_envelopes_reserve_before_decode_and_release_every_exit` uses a one-block
allowance and proves that:

- a saturated peer returns the admission outcome before even malformed bytes
  reach the envelope decoder;
- malformed input releases its tentative reservation;
- a valid block reaches the engine with the predecode guard, without a second
  charge; and
- dropping that event restores the allowance.

The existing real two-node
`a_cold_node_is_served_the_whole_chain_from_genesis` regression also passed,
showing that healthy full pages still chase through more than two pages and
deliver the complete ordered chain.

Validation on this checkout:

- `cargo test -p bloch-pos-node sync_envelopes_reserve_before_decode_and_release_every_exit --offline -- --nocapture`:
  1 passed, 542 filtered out in the node unit target; all integration targets
  selected zero tests and passed;
- `cargo test -p bloch-pos-node a_cold_node_is_served_the_whole_chain_from_genesis --offline -- --nocapture`:
  1 passed, 542 filtered out in the node unit target; all integration targets
  selected zero tests and passed;
- `git diff --check`: passed.

No workspace-wide formatter or broad suite was run.

## Residual

NET-22 remains **PARTIAL**. Libp2p necessarily receives and allocates the
bounded 8 MiB response frame and its outer envelope vectors before the
application callback can apply this reservation. An admitted peer may still
consume bounded envelope-decode work within the existing 256-event/16 MiB
per-source and 4,096-event/64 MiB aggregate first-hop allowances. The 4,096
frame unindexed-tail fallback and its restart/rebuild requirement are
unchanged. Node-local resource controls are fairness limits, not client
authorization, and fleet firewall policy was not inspected or changed.
