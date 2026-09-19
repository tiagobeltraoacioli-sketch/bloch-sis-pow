# Wave 117 — NET-22 streamed envelope persistence

Date: 2026-09-19
Comparison base: `42c5115`

## Finding

Every block-log append and both synchronous and asynchronous reorg rewrites
first materialized the complete canonical envelope in a temporary `Vec<u8>` of
up to 8 MiB. The store used that buffer only to obtain its length and write it
immediately, so persistence retained and copied one additional whole block per
write even though the borrowed `BlockEnvelope` already owned every field.

This was separate from payload vectors returned by read/sync APIs: those are
their existing result types and are not changed here.

## Correction

- `codec::write_envelope` is now the single canonical emitter shared by the
  public `encode_envelope` API and persistence. Header bytes, every u32 prefix,
  proposer signature, attestations, signatures and transactions are emitted
  in the same order from immutable borrows.
- `write_log_envelope` computes the exact canonical length before its first
  write. Saturating length arithmetic, the existing 8 MiB cap, u32 conversion
  and frame-length arithmetic all fail before the frame prefix or body reaches
  the writer.
- Append, synchronous rewrite and the asynchronous rewrite worker now write
  the four-byte log prefix followed by canonical fields directly. Append uses
  the same preflight length for its index entry and existing `log_len` update.
- Fsync, index ordering, staging publication, recovery and public codec/store
  APIs are unchanged. The block-log bytes and format are unchanged.

An I/O error can still leave a partial trailing log frame during append. That
was already possible inside `write_all` of the previous complete payload
slice, and restart still discards that incomplete tail. Rewrites remain
isolated in their private staging file until the existing sync and atomic
publication sequence succeeds.

## Adversarial evidence

- `canonical_envelope_emitter_matches_public_bytes_across_short_writes` pins
  exact equality with public encoding for empty, attestation/transaction and
  1 MiB-body envelopes while forcing repeated short writes.
- `log_frame_writer_streams_prefix_then_payload_across_short_writes` pins the
  exact `u32 length || encode_envelope` bytes, returned payload/frame lengths
  and completion of the prefix before canonical body emission.
- `log_frame_writer_partial_canonical_failure_remains_a_recoverable_torn_tail`
  injects failure after 37 canonical payload bytes and proves the exact prefix
  plus partial body remains the same recoverable torn tail.
- `persistence_refuses_oversized_frames_before_mutation_and_accepts_exact_limit`
  now also proves cap+1 offers zero bytes to a counting writer; existing disk
  and index immutability and exact-cap acceptance remain pinned.
- Existing synchronous staging publication, asynchronous publication/order
  and asynchronous over-cap failure regressions remain green.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  canonical_envelope_emitter_matches_public_bytes_across_short_writes -- --nocapture
# 1 passed; 0 failed; 603 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline log_frame_writer_ -- --nocapture
# 2 passed; 0 failed; 602 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  persistence_refuses_oversized_frames_before_mutation_and_accepts_exact_limit -- --nocapture
# 1 passed; 0 failed; 603 filtered out

# Each passed 1/1 with 603 filtered out:
# envelope_round_trips
# encoded_envelope_len_tracks_empty_collections_fields_and_limits
# private_staging_ignores_legacy_symlinks_and_cleans_only_its_own_file
# asynchronous_rewrite_publishes_then_orders_the_next_append
# asynchronous_rewrite_reports_failure_without_replacing_the_log
```

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside the sandbox; 585 passed; 0 failed; 19 ignored; 62.23s
```

## Residual boundary

Public callers of `encode_envelope` still receive and therefore allocate their
requested `Vec<u8>`. Log reads and sync responses still allocate the payloads
their APIs return. Persistence still performs the same canonical field writes,
fsyncs, index work and reorg staging I/O; it only avoids the store-owned
whole-envelope aggregate and its copy. This does not claim an exact heap/RSS
reduction. No wire, block-log, index, protocol, consensus or verdict changed,
and no activation rule changed.
