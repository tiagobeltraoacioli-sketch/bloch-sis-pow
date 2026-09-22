# Wave 113 — EN-08 streamed libp2p sync decode

Date: 2026-09-19
Comparison base: `a902859`

## Finding

The libp2p response codec first accumulated the entire directed-sync response
in a raw `Vec<u8>` of up to `MAX_SYNC_FRAME` (8 MiB). It then passed that
aggregate to `decode_sync_response`, whose length-prefixed `Reader::bytes`
copied every envelope into the `Vec<Vec<u8>>` carried by `SyncResponse`.

Those per-envelope vectors are the response API consumed by sync admission and
are not removed here. The extra whole-frame aggregate and the second copy of
all envelope bodies were transport-owned and avoidable.

## Correction

`SyncCodec::read_response` now decodes the existing wire format directly from
the async reader:

- the tag and block count are read into a fixed five-byte header;
- the existing `MAX_SYNC_BLOCKS` limit is checked before reserving the bounded
  outer vector;
- each four-byte envelope length is checked against both `MAX_FIELD_LEN` and
  the cumulative `MAX_SYNC_FRAME` budget before allocating its final vector;
- each body is read directly into that final vector, preserving wire order;
- one sentinel byte is read after the declared fields, so only real EOF
  accepts the response and `encode(x) || junk` remains invalid.

Structural EOF is still reported as `InvalidData`, as it was after the strict
buffer decoder, while non-EOF reader failures retain their original I/O error.
The public `encode_sync_response` and `decode_sync_response` functions remain
unchanged and serve as the byte/value compatibility oracle. `SyncResponse`,
the protocol id, wire bytes, ordering, caps and downstream peer/admission
behavior are unchanged.

## Adversarial evidence

- `sync_response_reader_streams_oracle_values_across_short_reads` splits fixed
  headers one byte at a time and a large body across repeated reads, then pins
  empty, multi-envelope and 1 MiB responses to
  `decode_sync_response(encode_sync_response(value))`.
- `audit_streaming_sync_cap_requires_actual_eof` accepts a response whose wire
  size is exactly 8 MiB, rejects the same response plus one trailing byte, and
  rejects a declared cap+1 response from framing bytes alone before its body
  can be allocated or read.
- `audit_streaming_sync_rejects_caps_truncation_and_preserves_io_errors`
  rejects an over-count response before payload work; rejects truncated tag,
  count, length and body as `InvalidData`; and proves a synthetic non-EOF I/O
  failure remains `ErrorKind::Other`.
- Existing public-codec round-trip, trailing-byte and block-count-cap tests
  remain green.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  sync_response_reader_streams_oracle_values_across_short_reads -- --nocapture
# 1 passed; 0 failed; 602 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  audit_streaming_sync_ -- --nocapture
# 2 passed; 0 failed; 601 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline sync_frames_ -- --nocapture
# 2 passed; 0 failed; 601 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  sync_response_block_cap_is_enforced_on_decode -- --nocapture
# 1 passed; 0 failed; 602 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  sync_response_writer_streams_oracle_bytes_across_short_writes -- --nocapture
# 1 passed; 0 failed; 602 filtered out
```

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside the sandbox; 584 passed; 0 failed; 19 ignored; 61.56s
```

## Residual boundary

An accepted response still owns one `Vec<u8>` per envelope and a bounded outer
vector because that is the existing `SyncResponse` API handed to downstream
admission. Each envelope is subsequently decoded into its block object, also
unchanged. This patch removes the simultaneous raw whole-response aggregate
and body recopy; it does not claim an exact heap/RSS reduction. Slow peers can
still hold a bounded response substream until the transport's existing stream
and connection controls end it. No consensus, wire, protocol, verdict or
activation rule changed.
