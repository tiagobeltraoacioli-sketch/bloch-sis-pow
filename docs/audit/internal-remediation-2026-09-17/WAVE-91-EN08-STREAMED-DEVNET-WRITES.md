# Wave 91 — EN-08 streamed devnet frame writes

Date: 2026-09-19
Starting consolidation: `9e058f1`

## Residual addressed

After Wave 90 made devnet writer queues share immutable frame allocations,
each connected writer still allocated another `Vec<u8>` large enough for the
four-byte length prefix plus the complete frame. `write_frame` then copied the
whole queued payload into that temporary allocation before writing it to the
socket. A broadcast therefore avoided per-queue payload copies while queued,
but still paid one allocation and one payload-sized userspace copy for every
peer that drained its queue. Sync replies and the transaction injector used
the same helper.

Frame sizes and writer queues were already bounded. This was bounded allocator
and memory-copy work, not an unbounded-retention or protocol bypass.

## Hardening

The private `write_frame` helper is now generic over `Write` and streams the
existing slices in two phases: the same four-byte little-endian length prefix,
then the unchanged payload. Both phases use `write_all`, preserving complete
handling of short writes.

The production call sites are unchanged except for explicitly dereferencing
their `MutexGuard<TcpStream>` to the already-locked stream. The writer and sync
serving paths still hold the same whole-frame mutex across the complete helper
call, so two producers cannot interleave prefix or payload bytes. The
transaction injector still uniquely owns its socket.

The old single `write_all` was also permitted to fail after a partial socket
write. Failure in either new phase has the same partial-frame consequence:
the connection caller returns or closes the connection, and no later frame is
written onto an unsynchronizable stream. Socket timeouts, queue depth/order,
drops, reconnect, sync authorization, wire bytes, consensus, persistence and
recovery behavior are unchanged.

## Adversarial coverage

`write_frame_streams_prefix_then_large_payload_across_short_writes` supplies a
private `Write` implementation that accepts the prefix in two pieces and a
one-MiB payload in many short writes. It proves:

- payload writing begins only after all four prefix bytes were accepted;
- the prefix is exactly the payload length encoded as `u32` little endian;
- every payload byte remains exact and ordered; and
- the implementation handles repeated partial accepts without a concatenated
  output buffer.

Existing reverse-direction and bidirectional large-page sync regressions cover
the real locked TCP call sites. The root ran both outside the restricted
sandbox.

## Validation checkpoint

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  net::tests::write_frame_streams_prefix_then_large_payload_across_short_writes \
  --offline -- --exact
# 1 passed; 0 failed; 591 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  net::tests::shared_sync_outbound_reader_serves_reverse_direction_requests \
  --offline -- --exact
# 1 passed; 0 failed; 591 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  net::tests::shared_sync_bidirectional_large_pages_keep_both_readers_draining \
  --offline -- --exact
# 1 passed; 0 failed; 591 filtered out
```

Compiler output contained only existing unused-code/import warnings.

The two socket-bearing focused tests were executed by the root outside the
restricted sandbox. The integrated node suite remains pending.

## Residual boundaries

- The operating system still necessarily copies userspace bytes into its
  socket buffers.
- Separating prefix and payload can add a write syscall per frame. The existing
  whole-frame mutex preserves ordering, but this change does not claim fewer
  syscalls or measured throughput improvement.
- Sync serving still constructs `FRAME_BLOCK || encoded envelope` before the
  writer; transaction injection likewise constructs its typed frame. This
  change removes only the final prefix-plus-payload concatenation.
- Libp2p owns separate framing/buffers and remains outside this change.
- Queue retention and atomic `Arc` reference operations remain as documented
  in Wave 90. No exact allocator, heap or RSS reduction is claimed.
- Hosted CI, Linux reproducibility, release signing, rollback and fleet
  qualification remain outside this focused correction.
