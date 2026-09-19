# Wave 89 — NET-22 fixed block-log header buffers

Date: 2026-09-19
Starting consolidation: `b3c0fb3`

## Residual addressed

Both network sync transports serve pages through `Store::blocks_after`. Its
bounded `scan_page` loop allocated and freed a `Vec` for the fixed-size block
header of every frame inspected, including frames whose bodies were skipped.
The open/restart index builder repeated the same allocation in `scan_index` for
every historical frame.

The work was bounded per request, but still avoidable. A normal indexed page
can inspect up to its page cap, and a lagging index permits a bounded tail scan
of up to 4,096 complete frames before failing closed. Libp2p and legacy sync
rate/concurrency limits bound how often this runs; they do not make thousands
of allocator round trips useful work. An index rebuild also paid one such
allocation per historical block.

## Hardening

`scan_page` and `scan_index` now each create one
`[u8; BlockHeaderV4::ENCODED_LEN]` buffer before their loop and reuse it for
every complete header read. Canonical header decoding still consumes exactly
those bytes at exactly the same point.

`scan_page` creates an owned `Vec` only after `header.slot > after_slot` proves
that the frame belongs in the response. It copies the already-read fixed header
once into that output buffer, resizes it to the original frame length, reads
the remaining body bytes and returns the same complete payload as before.
Skipped frames remain seek-only after their header.

This is a construction-level allocation removal, not allocator or heap/RSS
telemetry. Frame prefixes, seek/read ordering, canonical decode, index records,
error handling, tail bounds, response bytes and ordering are unchanged. No
wire, consensus, persistence format, API, activation or recovery policy
changed.

## Adversarial coverage

The new `fixed_header_scan_preserves_skipped_and_served_frames_exactly` test
drives the unindexed scan path over six differently sized frames: three are
skipped and three are served. It proves:

- all six headers are inspected exactly once;
- the returned suffix is byte-for-byte identical to the authoritative log;
- skipped bodies remain unread; and
- each returned body is read exactly once.

Existing focused regressions additionally preserve body skipping, zero-frame
past-tip lookup, fail-closed unindexed-tail limits and index creation for an
older data directory. The tail-bound unit test injects a limit of two to reach
the production 4,096-frame branch cheaply; it does not claim to allocate or
scan 4,096 fixtures during the test.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  fixed_header_scan_preserves_skipped_and_served_frames_exactly \
  --offline -- --nocapture
# 1 passed; 0 failed; 589 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  serving_a_page_does_not_read_the_bodies_it_skips \
  --offline -- --nocapture
# 1 passed; 0 failed; 589 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  serving_past_the_tip_touches_no_frames \
  --offline -- --nocapture
# 1 passed; 0 failed; 589 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  an_excessive_unindexed_tail_fails_at_the_scan_bound \
  --offline -- --nocapture
# 1 passed; 0 failed; 589 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  open_indexes_a_data_dir_that_has_none \
  --offline -- --nocapture
# 1 passed; 0 failed; 589 filtered out
```

Compiler output contained only existing unused-code/import warnings.

## Residual boundaries

- Every frame actually returned still needs one owned payload allocation for
  the network response; this change removes only the separate header-scan
  allocation.
- Header decode CPU, file opens, index binary search, body reads for returned
  frames and the bounded unindexed-tail scan remain.
- The existing sync admission/rate/fairness limits remain the availability
  boundary; this change neither strengthens nor weakens them.
- No exact allocator, heap or RSS reduction is claimed.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain outside this focused correction.
