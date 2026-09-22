# Wave 126 — EN-08 fixed libp2p sync request framing

Date: 2026-09-19
Comparison base: `71a7d262`

## Finding

The directed-sync request wire value is exactly 13 bytes and decodes to a
small typed `SyncRequest`, but both codec directions still used temporary heap
vectors. Reads accumulated up to 14 bytes in a `Vec` before decoding, and
writes allocated the public encoder's 13-byte `Vec` only to pass it immediately
to `AsyncWrite`.

Neither vector is a payload required by the request API. This is a small,
fixed per-substream allocation rather than an unbounded retention issue.

## Correction

- `sync_request_bytes` is the shared canonical `[u8; 13]` authority for the
  existing tag, `after_slot` and `limit` byte order.
- Public `encode_sync_request` keeps its unchanged `Vec<u8>` API and exact bytes
  by converting that canonical array. The live writer sends the array directly
  and therefore does not allocate the public return value.
- The live reader fills a stack `[u8; 13]` with the existing exact-read helper,
  reads one sentinel byte to require real EOF, and then uses the unchanged
  public decoder as its semantic oracle.

Structural truncation remains `InvalidData`; a 14th byte remains invalid
trailing data; non-EOF transport errors retain their original `ErrorKind`.
Request/response protocol ids, wire bytes, public APIs, scheduler behavior and
peer handling are unchanged.

## Adversarial evidence

- `sync_request_streams_fixed_oracle_across_short_io_and_preserves_errors`
  forces every request byte through a separate async read and write, pins the
  stack array and live output to public `encode_sync_request`, and confirms the
  decoded typed request.
- The same regression refuses empty and 12-byte truncated inputs as
  `InvalidData`, refuses a 14th trailing byte, and preserves an injected
  non-EOF reader failure as `ErrorKind::Other`.
- Existing public request/response round-trip and trailing-byte tests remain
  green.
- All five `outbound_sync_` scheduler/swarm regressions remain green, including
  duplicate refusal, FIFO fairness, request-generation binding, failures and
  disconnect release.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  sync_request_streams_fixed_oracle_across_short_io_and_preserves_errors -- --nocapture
# 1 passed; 0 failed; 605 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline sync_frames_ -- --nocapture
# 2 passed; 0 failed; 604 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline outbound_sync_ -- --nocapture
# 5 passed; 0 failed; 601 filtered out
```

```text
cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside the sandbox; 587 passed; 0 failed; 19 ignored; 66.27s
```

## Residual boundary

Public callers that ask for `encode_sync_request` still receive its historical
13-byte `Vec`, as required for API compatibility. Sync responses still retain
their final envelope vectors, and the transport still opens and schedules the
same request-response substreams. This patch removes only two fixed temporary
allocations from the live request codec and does not claim an exact RSS or
throughput change. No wire, API, protocol, consensus, verdict, cap, recovery or
activation rule changed.
