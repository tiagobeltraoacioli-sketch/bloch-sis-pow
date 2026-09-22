# Wave 93 — EN-08 streamed libp2p sync responses

Date: 2026-09-19
Starting consolidation: `97f7a1f`

## Residual addressed

The directed libp2p sync server built one bounded page as
`Vec<Vec<u8>>`, then `SyncCodec::write_response` called
`encode_sync_response` to allocate a second aggregate buffer and copy every
envelope into it before writing any bytes. The original envelope allocations
and the aggregate encoding coexisted for the duration of the asynchronous
write.

Existing admission limits bound one answer to 128 blocks and an eight-MiB
wire frame. This was therefore one avoidable allocation and up to one page of
avoidable userspace copying per admitted response, not unbounded retention or
a protocol bypass.

## Hardening

`SyncCodec::write_response` now delegates to a private streaming writer. It
writes the existing response tag and block count from a five-byte stack
header, followed by each existing four-byte envelope length and the owned
envelope bytes. Every phase uses `AsyncWriteExt::write_all`, which retries
partial `poll_write` progress until that slice is complete.

The helper preflights the envelope count and every envelope length with
`u32::try_from` before emitting the header. Directly constructed impossible
values therefore fail with `InvalidInput` rather than wrap a wire field or
leave a predictable partial response. Production is much tighter: the serving
path already caps the count at 128 and the aggregate frame below eight MiB.

The request-response handler awaits `write_response` and closes its exclusive
substream only afterward. The codec contract does not require one
`poll_write`; sequential `write_all` calls append to the same stream and EOF
still follows the complete response. A write error retains the old consequence
of a partial failed substream.

`encode_sync_response` remains unchanged as the canonical byte oracle used by
tests. Decode, actual-EOF enforcement, count/byte caps, rate/concurrency
admission, envelope ordering, canonical envelope decode, verdicts, consensus,
storage and recovery behavior are unchanged.

## Adversarial coverage

- `sync_response_writer_streams_oracle_bytes_across_short_writes` uses an
  `AsyncWrite` that splits codec headers and large payloads across repeated
  polls. Empty, mixed multiple-envelope (including an empty envelope), and
  one-MiB response cases are byte-for-byte equal to
  `encode_sync_response`; all streamed bytes also decode back to the original
  response.
- `sync_wire_len_rejects_u32_overflow_without_payload_allocation` proves the
  fixed-width boundary accepts `u32::MAX` and, on wider hosts, rejects the
  next value without allocating a multi-gigabyte payload.
- Existing exact-EOF, strict trailing-byte, response count-cap and codec
  round-trip tests preserve receive-side behavior and the frozen format.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::sync_response_writer_streams_oracle_bytes_across_short_writes \
  --offline -- --exact
# 1 passed; 0 failed; 594 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::sync_wire_len_rejects_u32_overflow_without_payload_allocation \
  --offline -- --exact
# 1 passed; 0 failed; 594 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::audit_sync_cap_requires_actual_eof --offline -- --exact
# 1 passed; 0 failed; 594 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::audit_sync_short_frames_still_use_strict_decoding \
  --offline -- --exact
# 1 passed; 0 failed; 594 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::sync_frames_ --offline
# 2 passed; 0 failed; 593 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::sync_response_block_cap_is_enforced_on_decode \
  --offline -- --exact
# 1 passed; 0 failed; 594 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::a_cold_node_is_served_the_whole_chain_from_genesis \
  --offline -- --exact
# 1 passed; 0 failed; 594 filtered out; finished in 5.77s

cargo test -p bloch-pos-node --bin bloch-pos \
  p2p::tests::a_restarted_node_recovers_only_what_it_missed \
  --offline -- --exact
# 1 passed; 0 failed; 594 filtered out; finished in 5.30s

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 576 passed; 0 failed; 19 ignored; finished in 60.53s
```

Compiler output contained only existing unused-code/import warnings.

The socket-bearing live regressions and complete node suite were executed by
the root outside the restricted sandbox.

## Residual boundaries

- The response still owns one `Vec<u8>` per envelope returned by the store;
  inbound sync still reads its bounded response into one aggregate buffer
  before strict decode.
- Multiple small writes can add async write polls or syscalls. This change
  proves byte parity and removes aggregate construction; it does not claim a
  measured latency or throughput improvement.
- Kernel and libp2p internal buffering/copies remain. No exact allocator, heap
  or RSS reduction is claimed.
- Hosted CI, Linux reproducibility, release signing, rollback and fleet
  qualification remain outside this focused correction.
