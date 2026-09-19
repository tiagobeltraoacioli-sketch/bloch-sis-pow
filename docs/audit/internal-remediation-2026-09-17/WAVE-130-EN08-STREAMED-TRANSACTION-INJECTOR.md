# Wave 130 — EN-08 streamed devnet transaction injector

Date: 2026-09-19
Comparison base: `dec64340`

## Finding

`send_transaction` receives canonical transaction bytes by borrow, but copied
the complete payload into a temporary owned `Vec` after `FRAME_TX` and then
immediately wrote that frame to a one-shot TCP connection. The function never
returned, queued or reused the owned frame, so this allocation and copy grew
with the submitted transaction while adding no ownership required by its API.

## Correction

The injector now calls the existing `write_typed_frame` helper directly with
`FRAME_TX` and the borrowed payload. It emits the unchanged wire in three
phases under the same socket ownership:

```text
u32_le(1 + tx_bytes.len()) || FRAME_TX || tx_bytes
```

The public function signature, connect-before-write order, no-ack behavior and
connection close on return are unchanged. For an impossible payload whose tag
plus length cannot fit u32, the shared typed writer now returns `InvalidInput`
before emitting bytes instead of truncating the old unchecked cast. All valid
protocol frames are byte-identical.

## Adversarial evidence

- `write_typed_frame_streams_length_tag_and_payload_across_short_writes` now
  exercises `FRAME_TX` with a 1 MiB payload, splits the prefix and payload over
  repeated writes, and pins prefix/tag/body phase order and exact bytes.
- `transaction_typed_frame_matches_legacy_oracle_and_preserves_partial_errors`
  compares empty, short and 1 MiB payloads with an explicitly assembled legacy
  wire oracle. It also injects a failure after seven payload bytes and pins the
  exact prefix, tag, partial body and propagated `BrokenPipe` error.
- `send_transaction_writes_exact_wire_then_closes_without_ack` accepts the real
  one-shot connection, reads until EOF, and compares the complete 1 MiB wire
  with the legacy oracle. Root ran this socket regression outside the sandbox.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  write_typed_frame_streams_length_tag_and_payload_across_short_writes -- --nocapture
# 1 passed; 0 failed; 607 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  transaction_typed_frame_matches_legacy_oracle_and_preserves_partial_errors -- --nocapture
# 1 passed; 0 failed; 607 filtered out
```

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside the sandbox; 589 passed; 0 failed; 19 ignored; 65.49s
# includes send_transaction_writes_exact_wire_then_closes_without_ack
```

## Residual boundary

The caller still owns the canonical transaction byte slice, and the receiving
node still allocates its bounded inbound frame as required by the decode API.
Socket writes, kernel buffering and canonical transaction construction are
unchanged. This patch removes only the injector-owned `FRAME_TX || payload`
aggregate and proportional copy; it does not claim an exact heap/RSS or
throughput change. No wire, API, protocol, consensus, verdict, cap, recovery or
activation rule changed.
