# Wave 97 — NET-22 streamed block-index scan

Date: 2026-09-19
Comparison base: `9121563`

## Finding

Wave 96 bounded the encoded index-write buffer, but `scan_index` still retained
one Rust `IdxEntry` for every frame in the repaired log before writing any of
them. `Store::open` rebuilds the disposable index from offset zero, so this
allocation grew with the complete retained chain on ordinary restart, not only
with a rare corrupt tail.

## Correction

- The same header-only scanner now emits each fixed 20-byte index record
  directly into the existing 8 KiB `BufWriter` as soon as its complete log
  frame and canonical fixed header have been checked.
- The length cap, minimum-header check, frame-end arithmetic, canonical header
  decode, body seek, offsets, order and stop behavior for torn/corrupt tails are
  unchanged.
- `repair_index` still flushes explicitly before the existing `idx.sync_data`.
  Index magic, record format and serving behavior are unchanged.

This removes the remaining whole-tail `Vec<IdxEntry>` and its growth/reallocation
copies. It does not claim an exact heap/RSS value: filesystem and standard
library buffering remain, and the chain replay retains decoded state for its
own independent purpose.

## Error-state boundary

There is one deliberate local error-state difference. If reading the log fails
after the scanner has emitted some entries, that derived prefix may already be
present in `blocks.idx` when the same I/O error is returned. Previously the
whole-tail vector delayed the first index write until the scan returned.

This cannot make the index authoritative: the log remains the source of truth,
the node still fails that open/rewrite attempt, complete prefix records describe
frames already checked against the log, and a partial 20-byte record is
truncated and rederived by the next repair. The prior batch `write_all` could
also fail after a partial index write. Achieving byte-identical error state
would require a second full scan or another staged file and was intentionally
not traded for more boot I/O and complexity.

## Adversarial evidence

- `index_repair_writer_is_fixed_bounded_and_byte_exact` now drives a real
  1,000-frame log through the streaming scanner, pins exact record bytes/order
  and proves every inner write is at most 8 KiB.
- `partial_buffered_index_record_is_truncated_and_rebuilt` injects a writer
  failure 19 bytes into a record after the buffer boundary and proves the next
  repair reconstructs the exact complete 500-entry index.
- `streamed_index_scan_preserves_torn_and_corrupt_log_prefixes` proves a torn
  payload and a complete frame shorter than the fixed header both retain
  exactly the valid preceding index prefix.
- Existing missing/bad-magic, lagging-tail, reorg and same-length interrupted
  reorg regressions remain green.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  index_repair_writer_is_fixed_bounded_and_byte_exact -- --nocapture
# 1 passed; 0 failed; 601 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  partial_buffered_index_record_is_truncated_and_rebuilt -- --nocapture
# 1 passed; 0 failed; 601 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  streamed_index_scan_preserves_torn_and_corrupt_log_prefixes -- --nocapture
# 1 passed; 0 failed; 601 filtered out

# Each of the following passed 1/1 with 601 filtered out:
# a_missing_or_bad_magic_index_never_reopens_the_full_scan
# an_index_behind_the_log_still_serves_the_unindexed_tail
# a_reorg_rebuilds_the_index
# restart_rebuilds_same_length_index_left_by_interrupted_reorg

cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside the sandbox; 583 passed; 0 failed; 19 ignored; 59.32s
```

## Residual boundary

Index rebuild remains O(number of retained frames) in header reads, canonical
header decodes and seeks, then waits for index fsync. Startup separately replays
the complete block log and retains decoded chain/state structures. Local disk
read/write faults can leave a disposable index prefix before failing closed as
described above. No network, consensus, block-log or index format changed.
