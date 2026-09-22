# Wave 96 — NET-22 streamed block-index repair

Date: 2026-09-19
Comparison base: `848ccd3`

## Finding

Block-index repair first derived and retained every missing `IdxEntry`, then
allocated a second contiguous `20 * entry_count` byte vector and copied every
encoded entry into it before writing. At one million log frames that second
buffer alone requests about 20 MiB during boot/recovery or reorg publication.
Its size followed retained chain length rather than a fixed local bound.

## Correction

- `repair_index` still uses the existing `Vec<IdxEntry>` and unchanged
  header-only scan; this intentionally avoids changing index discovery.
- The second whole-tail encoded vector is replaced by a private 8 KiB
  `BufWriter`. Each fixed 20-byte entry is encoded on the stack, copied into
  that bounded buffer and flushed explicitly before the existing
  `idx.sync_data()`.
- Magic, entry encoding, order, offsets, tail truncation and rebuild behavior
  are unchanged. No writer capacity survives the repair call.

This bounds only the second encoding buffer and is not an exact heap/RSS
claim. A single `write_all` of the former large vector could already partially
write, so buffered partial output does not remove an atomicity guarantee that
previously existed. A final partial 20-byte record remains disposable index
tail and is truncated/rederived by the existing repair path.

## Adversarial evidence

- `index_repair_writer_is_fixed_bounded_and_byte_exact` writes 1,000 synthetic
  entries, compares the complete output with concatenated canonical encodings,
  and proves every inner write is at most 8 KiB.
- `partial_buffered_index_record_is_truncated_and_rebuilt` injects failure 19
  bytes into an index record after crossing the buffer boundary, persists that
  exact damaged index beside a valid 500-frame log, and proves `repair_index`
  reconstructs the exact complete index.
- Existing missing/bad-magic, lagging-tail, reorg and same-length interrupted
  reorg regressions keep index authority and recovery semantics pinned.

Validation:

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  index_repair_writer_is_fixed_bounded_and_byte_exact -- --nocapture
# 1 passed; 0 failed; 600 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  partial_buffered_index_record_is_truncated_and_rebuilt -- --nocapture
# 1 passed; 0 failed; 600 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  a_missing_or_bad_magic_index_never_reopens_the_full_scan -- --nocapture
# 1 passed; 0 failed; 600 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  an_index_behind_the_log_still_serves_the_unindexed_tail -- --nocapture
# 1 passed; 0 failed; 600 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  a_reorg_rebuilds_the_index -- --nocapture
# 1 passed; 0 failed; 600 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline \
  restart_rebuilds_same_length_index_left_by_interrupted_reorg -- --nocapture
# 1 passed; 0 failed; 600 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# outside sandbox for localhost sockets: 582 passed; 0 failed; 19 ignored; 58.02s
```

## Residual boundary

`scan_index` still retains the derived `Vec<IdxEntry>` for the whole repaired
tail, so repair memory remains O(number of retained frames). Eliminating that
vector would couple scanning and index mutation and would change failure
semantics; it is deliberately outside this small correction. Header reads,
file opens, canonical header decode, index fsync and full replay work also
remain. No network, consensus, log or index format changed.
