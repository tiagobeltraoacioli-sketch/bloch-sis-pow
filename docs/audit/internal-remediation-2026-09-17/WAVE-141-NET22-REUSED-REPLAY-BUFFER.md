# Wave 141 — NET-22 reused replay frame buffer

Date: 2026-09-19
Comparison base: `3b408c57`

## Residual addressed

`Store::read_all` streams the block log during boot and recovery through
`read_log_frames`. Although it no longer aggregates the whole log, the loop
still allocated a new raw `Vec<u8>` for every historical block, read the frame,
decoded an owned `BlockEnvelope`, and immediately discarded that raw buffer.

The allocation was bounded per frame by the existing 8-MiB codec limit, but
its churn scaled with every block replayed. The decoded envelope is the
unavoidable result; the repeated raw-buffer allocation is repository-owned
temporary work.

## Correction and ownership proof

`read_log_frames` now creates one empty scratch `Vec<u8>` before the loop. Only
after the existing length cap, checked offset arithmetic, and stable-length
truncation check succeed does `read_frame_payload` resize that scratch and fill
it with `read_exact`. Frames no larger than the observed high-water reuse the
same allocation; larger legal frames grow it while logical length remains
under the same 8-MiB cap. Allocator-selected capacity may exceed the requested
length and is not claimed as an exact memory bound.

Reusing the bytes after decode is sound because `decode_envelope` returns owned
data. Its `Reader::bytes` copies each signature and transaction into a `Vec`,
attestations contain owned signatures, and the fixed header is deserialized by
value. No returned `BlockEnvelope` borrows the raw frame.

Format and failure behavior remain unchanged:

- the four-byte length prefix and canonical envelope bytes are unchanged;
- frame order and the returned public `Vec<BlockEnvelope>` are unchanged;
- over-cap lengths fail before scratch growth or payload I/O;
- checked frame-end overflow still fails closed;
- a torn trailing frame still returns the complete decoded prefix; and
- a complete corrupt frame still returns `InvalidData` rather than being
  skipped or repaired.

No wire, disk format, public API, consensus, activation, verdict, index,
append, rewrite or recovery-authority behavior changes.

## Adversarial coverage

- `replay_scratch_reuses_high_water_and_preserves_mixed_frames` replays empty,
  one-MiB and small canonical envelopes and compares all decoded fields and
  order. It then reads a one-MiB raw body followed by a smaller body and proves
  pointer and capacity identity across reuse. Finally it proves an 8-MiB+1
  prefix fails with `InvalidData` before a body is available.
- `replay_log_decode_streams_bounded_frames_and_preserves_tail_refusals`
  retains the existing bounded-reader, complete-prefix torn-tail and corrupt
  zero-frame behavior.

## Validation

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  replay_scratch_reuses_high_water_and_preserves_mixed_frames \
  --offline -- --nocapture
# 1 passed; 0 failed; 611 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  replay_log_decode_streams_bounded_frames_and_preserves_tail_refusals \
  --offline -- --nocapture
# 1 passed; 0 failed; 611 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 593 passed; 0 failed; 19 ignored; 62.37s
```

The full binary suite ran outside the sandbox so its localhost transport
coverage could execute.

## Residual boundary

- Reading and overwriting every raw byte, zero-initializing newly grown
  scratch, and decoding owned envelope fields remain necessary work.
- The scratch retains its allocation for the duration of one `read_all` call.
  Its requested logical high-water is capped at 8 MiB, while actual allocator
  capacity may be larger. This is a bounded-input lifetime tradeoff for
  removing per-frame allocation churn, not an exact resident-memory bound.
- The returned envelope vector and each envelope's owned signatures,
  attestations and transactions remain unavoidable replay output.
- No exact heap/RSS or allocator-call count is claimed; the proof is
  construction-level reuse for frames at or below the observed high-water.
- Hosted CI, Linux reproducibility, release signing, rollback and fleet
  qualification remain integration/release work.
