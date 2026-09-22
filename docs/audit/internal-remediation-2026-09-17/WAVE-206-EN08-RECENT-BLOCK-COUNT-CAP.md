# Wave 206 — EN-08 recent-block count cap

Date: 2026-09-19
Comparison base: `c8286491`

## Reproduced residual

Wave 202 removed premature full-map expiry scans from libp2p's recent-block
re-gossip suppression cache, but documented that the retained ID/timestamp map
still had no numeric count or byte ceiling. The 30-second TTL bounds retention
time, not the number of distinct decodable block IDs that sequentially
released engine-queue capacity can present inside that window.

The map retains fixed-size `[u8; 32]` identities and `Instant` values, not
block payloads, but unconstrained identity churn could still grow repository-
owned bookkeeping until the TTL boundary.

## Correction

`RECENT_BLOCKS_MAX` limits the private suppression map to 4,096 distinct IDs,
matching the engine-facing event-count ceiling. Expiry runs before capacity
admission, so an exact TTL boundary reopens space in the same call.

At capacity, an already retained ID still refreshes its timestamp and remains
suppressed. A new ID is drop-new: it is reported fresh to the existing publish
path but is not remembered and does not evict a third party's retained
suppression state. This fail-open direction is deliberate because the cache is
only a local duplicate-work optimization, not a block-admission or peer-verdict
authority.

## Preserved invariants

- duplicate IDs below or at capacity remain suppressed and refresh their TTL;
- equality at `REGOSSIP_SUPPRESS_TTL` remains expired and reopens capacity;
- expiry-hint scans, exact boundary behavior and stale-early safety from Wave
  202 are unchanged;
- inbound decode, canonical queue-charge parity, reservation, emission and
  engine verdict handling are unchanged;
- prepared-ID binding, generic malformed fallback, topics, message IDs,
  payload ownership and wire bytes are unchanged; and
- no public API, persistence, activation, protocol format or
  consensus-validity behavior changed.

## Adversarial regression

`recent_block_cache_count_cap_is_drop_new_and_reopens_at_expiry` proves:

- exactly 4,096 distinct IDs are retained;
- the next distinct ID returns fresh without entering the map or displacing
  any retained identity;
- an existing ID still refreshes and remains suppressed while the map is
  full; and
- at the exact oldest TTL boundary, expired entries leave and the refreshed
  survivor plus incoming ID are retained with the correct oldest hint.

The Wave 202 hint/refresh test and prepared-block ownership/fallback tests
continue to pin the surrounding behavior.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  recent_block_cache_count_cap_is_drop_new_and_reopens_at_expiry --offline
# 1 passed; 0 failed; 632 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  recent_block_expiry_hint_skips_early_scans_and_preserves_refresh --offline
# 1 passed; 0 failed; 632 filtered out

cargo test -p bloch-pos-node --bin bloch-pos prepared_block_ --offline
# 3 passed; 0 failed; 630 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  two_nodes_form_a_mesh_and_keep_exchanging_blocks --offline
# 1 passed; 0 failed; 632 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 614 passed; 0 failed; 19 ignored; 61.62s

git diff --check
# clean
```

The live-mesh focus and full suite ran outside the restricted sandbox because
their transport/HTTP fixtures bind localhost sockets. The restricted
live-mesh attempt failed only at `TcpListener::bind` with `EPERM`; the
unrestricted rerun above passed.

## Residual boundary

Drop-new saturation can allow a later local publication attempt for an
unremembered ID, leaving gossipsub to perform its ordinary duplicate handling.
This trades bounded repository-owned suppression state for possible bounded-
per-attempt duplicate work; it is not per-peer fairness or a peer penalty.
The map's allocator overhead, ID hashing, full-map scan at a reached expiry
boundary, the 30-second retention window, transport/kernel work and
gossipsub's separate duplicate cache remain. The count cap does not claim an
exact heap/RSS limit. `EN-08` remains `PARTIAL`.
