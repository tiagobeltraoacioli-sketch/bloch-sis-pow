# Wave 202 — EN-08 recent-block expiry hint

Date: 2026-09-19
Comparison base: `c519e089`

## Reproduced residual

Libp2p keeps block IDs seen within `REGOSSIP_SUPPRESS_TTL` so an engine
re-broadcast does not repay gossipsub's body hash only to meet its duplicate
cache. `Loop::note_block` previously traversed the complete retained-ID map on
every received or published block, even when its oldest timestamp could not
yet have expired. A burst of distinct IDs in one TTL window therefore caused
each insertion to revisit the growing retained prefix.

The map has exactly two consumers: decoded inbound block gossip and outbound
block suppression through `outbound_block_is_fresh`. The engine-facing queue
budget bounds concurrent retained events, but released capacity can admit
further sequential IDs and does not make this repeated map traversal useful.

## Correction

`Loop::recent_blocks_expiry_hint` records a conservative lower bound on the
oldest retained timestamp. `note_block_at` skips the full-map expiry pass
until that lower bound reaches the 30-second TTL. A triggered pass retains
the same strict-before-boundary entries and recomputes the exact oldest
timestamp; insertion or refresh then takes the minimum of that value and the
new observation time. Production `note_block` supplies `Instant::now()`, while
the explicit clock seam remains private and exists to make boundary behavior
deterministic under test.

Refreshing an ID may leave the hint stale and early. Reaching that obsolete
boundary can cause one extra safe full-map scan, but the hint cannot become
later than the real oldest timestamp and therefore cannot postpone expiry.

## Preserved invariants

- a duplicate inside the TTL remains suppressed and refreshes its timestamp;
- equality at `REGOSSIP_SUPPRESS_TTL` remains expired and is admitted fresh;
- inbound decode, canonical queue-charge parity, reservation, emission and
  later engine verdict handling are unchanged;
- prepared IDs remain bound to their canonical payload, while the generic
  fallback still decodes best-effort and publishes malformed frames without
  inventing a suppression identity;
- payload ownership, topics, message IDs, wire bytes, queue caps, peer
  reporting and all public APIs are unchanged; and
- no protocol, persistence, activation or consensus behavior changed.

## Adversarial regression

`recent_block_expiry_hint_skips_early_scans_and_preserves_refresh` uses a
thread-local test-only scan counter and an explicit monotonic clock to prove:

- 100 same-time distinct IDs perform no expiry scan before their boundary;
- exact equality expires all old IDs and admits the boundary ID fresh;
- refreshing the sole retained ID still returns duplicate and leaves only a
  conservative early hint;
- reaching that stale hint performs one harmless scan and preserves the
  refreshed ID; and
- the refreshed ID expires exactly at its own equality boundary while newer
  IDs remain retained and the recomputed hint is exact.

Existing prepared-block regressions continue to pin decode-free typed-ID
suppression, generic malformed fallback, direct payload ownership and exact
ID binding.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos --offline recent_block_expiry_hint_skips_early_scans_and_preserves_refresh -- --nocapture`
  - outside the sandbox: 1 passed; 0 failed; 631 filtered out.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline prepared_block_ -- --nocapture`
  - outside the sandbox: 3 passed; 0 failed; 629 filtered out.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline two_nodes_form_a_mesh_and_keep_exchanging_blocks -- --nocapture`
  - outside the sandbox: 1 passed; 0 failed; 631 filtered out.
- `cargo check -p bloch-pos-node --bin bloch-pos --offline`
  - passed.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline`
  - outside the sandbox: 613 passed; 0 failed; 19 ignored; 61.37s.

## Residual boundary

When the conservative boundary arrives, expiry still scans the retained map.
An ID refresh can cause one earlier safe scan before the recomputed real
boundary. Retained ID/timestamp heap overhead, ID hashing, the 30-second
retention window, gossipsub's own duplicate cache and transport/kernel work
remain. This is not a hard heap/RSS cap or a new per-peer fairness mechanism.
`EN-08` remains `PARTIAL`.
