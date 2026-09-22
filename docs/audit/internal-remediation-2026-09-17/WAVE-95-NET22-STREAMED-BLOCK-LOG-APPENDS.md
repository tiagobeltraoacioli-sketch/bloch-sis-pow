# Wave 95 — NET-22 streamed block-log appends

Date: 2026-09-19
Comparison base: `5a09ba2`

## Finding

Every live applied block already had an owned canonical encoded-envelope
`Vec`, but `Store::append` allocated a second `4 + payload.len()` buffer and
copied the whole payload into it solely to prepend the log length. The store
accepts envelopes up to 8 MiB (current local production is bounded lower), so
this was a bounded but payload-sized allocation and copy on the consensus
thread before durability and broadcast.

Whole-log rewrite paths already stream the same prefix and payload separately.
The append handle is private to `Store`, the data-directory lock excludes a
second process, and `append` joins a pending rewrite before writing, so the
second concatenated buffer supplied no inter-writer atomicity.

## Correction

- A private generic writer helper validates the payload length as `u32` and
  checks `4 + payload.len()` before emitting any byte.
- It then uses `write_all` for the four-byte little-endian prefix followed by
  the borrowed encoded payload and returns the exact persisted frame length.
- `Store::append` uses that returned length for `log_len`; `sync_data`, index
  construction, index-after-log ordering and the fatal caller error path are
  unchanged.
- No reusable buffer or payload capacity is retained.

The log format and bytes are unchanged. A single `write_all` was not an atomic
filesystem transaction and could already leave a partial final frame. Failure
between the new phases leaves the same prefix-only truncated tail that startup
repair/replay already detects and removes. This change removes one avoidable
allocation and copy; it does not claim an exact heap/RSS reduction.

## Adversarial evidence

- `log_frame_writer_streams_prefix_then_payload_across_short_writes` forces
  both the prefix and payload through short writes, pins phase ordering, exact
  bytes and the returned frame size.
- `log_frame_writer_prefix_only_failure_remains_a_recoverable_torn_tail`
  injects failure immediately after the complete prefix, pins the propagated
  error and proves replay treats those bytes as a truncated empty tail.
- Existing exact-limit, torn-tail restart and failed-index continuity tests
  pin admission-before-mutation, recovery and log/index ordering.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline log_frame_writer_ -- --nocapture
# 2 passed; 0 failed; 597 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  persistence_refuses_oversized_frames_before_mutation_and_accepts_exact_limit -- --nocapture
# 1 passed; 0 failed; 598 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  restart_repairs_torn_tail_before_accepting_new_blocks -- --nocapture
# 1 passed; 0 failed; 598 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  failed_index_append_never_turns_a_later_entry_into_a_gap -- --nocapture
# 1 passed; 0 failed; 598 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 580 passed; 0 failed; 19 ignored; 58.14s
```

## Residual boundary

Canonical envelope encoding still needs its owned payload `Vec`, and durable
append still waits for `sync_data`; both dominate independently of the removed
concatenation. Two `write_all` phases may issue an additional write syscall.
Replay still decodes the whole retained chain at startup, returned sync frames
still need owned payloads, and this local persistence optimization changes no
network admission, fairness, consensus or wire policy.
