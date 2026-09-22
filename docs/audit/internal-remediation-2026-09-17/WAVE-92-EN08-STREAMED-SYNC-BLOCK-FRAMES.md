# Wave 92 — EN-08 streamed devnet sync block frames

Date: 2026-09-19
Starting consolidation: `2987e02`

## Residual addressed

Wave 91 removed the final prefix-plus-frame concatenation from devnet socket
writes. The legacy sync response path still performed an earlier equivalent
copy for every served block: `Store::blocks_after` returned the canonical
encoded envelope in an owned `Vec<u8>`, then `serve_get_blocks` allocated
another vector, appended `FRAME_BLOCK`, and copied the entire envelope into it
before calling the streaming writer.

The existing page policy bounds a response to 512 blocks and eight MiB of
encoded envelopes. The residual was therefore up to one avoidable allocation
per returned block and one payload-sized userspace copy across an admitted
page, not an unbounded-retention or protocol bypass.

## Hardening

A private `write_typed_frame` helper writes one logical frame in three phases:
the four-byte little-endian length of `tag || payload`, the one-byte tag, and
the unchanged payload. Every phase uses `write_all`. `serve_get_blocks` now
passes `FRAME_BLOCK` and the store-owned canonical envelope directly to that
helper instead of constructing `FRAME_BLOCK || envelope` in a second vector.
The helper checks both `usize + 1` and conversion to the wire's `u32` length,
failing with `InvalidInput` rather than wrapping either boundary.

The new helper is used only by sync block serving. All other callers retain
Wave 91's `write_frame` behavior. The sync responder still acquires the same
socket mutex before the connection check and holds it across the complete
three-phase helper call, so concurrent broadcasts cannot interleave a prefix,
tag or payload. Failure in any phase retains the existing close-and-return
behavior for an unsynchronizable partial frame.

`Store::blocks_after` remains the owner and authority for returned envelope
bytes. Page count/byte caps, store reads, block order, socket timeouts,
connection accounting, sync authorization, wire bytes, consensus,
persistence and recovery behavior are unchanged.

## Adversarial coverage

`write_typed_frame_streams_length_tag_and_payload_across_short_writes` supplies
a private `Write` implementation that accepts the prefix in two pieces, then
the tag, then a one-MiB payload in many short writes. It proves:

- the encoded length is exactly `1 + payload.len()` in little-endian `u32`;
- the tag starts only after the complete prefix;
- the payload starts only after the complete tag; and
- all payload bytes remain exact and ordered across repeated partial accepts.

The only production caller receives payloads bounded to eight MiB by
`Store::blocks_after`, far below `u32::MAX`. A synthetic slice above four GiB
was not allocated solely to exercise the defensive conversion branch; the
branch is construction-visible and independent of payload contents.

Existing reverse-direction and bidirectional large-page sync regressions cover
the real store-to-locked-socket call path. The root ran both outside the
restricted sandbox.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  net::tests::write_typed_frame_streams_length_tag_and_payload_across_short_writes \
  --offline -- --exact
# 1 passed; 0 failed; 592 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  net::tests::shared_sync_outbound_reader_serves_reverse_direction_requests \
  --offline -- --exact
# 1 passed; 0 failed; 592 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  net::tests::shared_sync_bidirectional_large_pages_keep_both_readers_draining \
  --offline -- --exact
# 1 passed; 0 failed; 592 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 574 passed; 0 failed; 19 ignored; finished in 57.32s
```

Compiler output contained only existing unused-code/import warnings.

The socket-bearing focused tests and complete node suite were executed by the
root outside the restricted sandbox.

## Residual boundaries

- `Store::blocks_after` still allocates one owned encoded envelope for every
  block actually returned. Removing that ownership would require a different
  streaming store interface and generation-lock lifetime design.
- Three-phase output can add a write syscall for the separate tag. The
  whole-frame mutex preserves ordering, but this change does not claim fewer
  syscalls or measured throughput improvement.
- The operating system still necessarily copies userspace bytes into socket
  buffers. Libp2p owns separate framing and remains outside this change.
- The eight-MiB page cap bounds the removed copy; no exact allocator, heap or
  RSS reduction is claimed.
- Hosted CI, Linux reproducibility, release signing, rollback and fleet
  qualification remain outside this focused correction.
