# Wave 144 — NET-22 reused inspection frame buffer

Date: 2026-09-19
Comparison base: `1f3509dd`

## Residual addressed

Wave 141 reused the raw frame buffer during boot replay, but the operator-facing
`inspect_log` full-history scan still allocated a fresh `Vec<u8>` for every
complete block-log frame. `repair_log_tail_offline` obtains its fresh evidence
by calling that same inspection path, so a confirmed repair repeated this
allocation churn before making any recovery decision.

Each raw allocation was logically bounded by the existing 8-MiB codec frame
limit, but the number of allocations scaled with historical block count. The
decoded envelope is deliberately discarded by inspection; repeatedly
allocating its raw input was repository-owned temporary work.

## Correction and invariants

`inspect_log` now owns one empty scratch `Vec<u8>` outside its scan loop. Only
after the existing remaining-prefix, frame-cap and complete-body checks pass
does it call the Wave 141 `read_frame_payload` helper to resize and overwrite
that scratch. Frames at or below the observed logical high-water reuse the
allocation.

This is ownership-safe because `decode_envelope` returns an owned header and
owned variable fields: signatures and transaction bytes do not borrow the raw
frame. The next inspection record can therefore overwrite the scratch after
the decode result is discarded.

All operator-visible semantics remain unchanged:

- `log_bytes`, `decoded_frames` and `valid_prefix_bytes` advance at the same
  boundaries;
- over-cap and incomplete-body checks occur before payload resize or read;
- the first undecodable complete frame preserves the exact historical issue
  string and prefix;
- inspection remains read-only and still rechecks file length after the scan;
  and
- offline repair still requires the same fresh matching prefix, exclusive
  lock, suffix classification, durable backup and post-backup truncation.

No disk format, public API, consensus, network protocol, verdict, index,
append/rewrite or recovery-authority behavior changes.

## Adversarial coverage

- `inspection_scratch_preserves_mixed_prefix_and_first_corruption` writes
  empty, one-MiB and small canonical frames, proves exact counts and complete
  prefix, then appends a complete undecodable frame and fixes the same three
  accepted frames, exact valid-prefix boundary, exact issue string and
  byte-identical untouched log.
- `audit_log_diagnostic_is_bounded_and_does_not_repair_or_hide_corruption`
  retains the existing incomplete-prefix, zero-length, over-cap and torn-body
  diagnostic behavior.
- `offline_tail_repair_backs_up_only_confirmed_incomplete_or_zero_suffixes`
  retains exclusive locking, exact-prefix matching, backup and refusal of a
  non-repairable corrupt suffix.
- Wave 141's `replay_scratch_reuses_high_water_and_preserves_mixed_frames`
  already pins pointer/capacity identity for the shared private helper across
  a large-to-small raw read.

## Validation

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  inspection_scratch_preserves_mixed_prefix_and_first_corruption \
  --offline -- --nocapture
# 1 passed; 0 failed; 612 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  audit_log_diagnostic_is_bounded_and_does_not_repair_or_hide_corruption \
  --offline -- --nocapture
# 1 passed; 0 failed; 612 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  offline_tail_repair_backs_up_only_confirmed_incomplete_or_zero_suffixes \
  --offline -- --nocapture
# 1 passed; 0 failed; 612 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 594 passed; 0 failed; 19 ignored; 67.71s
```

The full binary suite ran outside the sandbox so its localhost transport
coverage could execute.

## Residual boundary

- Inspection still reads and decodes every complete frame. The owned envelope
  fields allocated by `decode_envelope` are still created and discarded;
  removing them safely would require a shared borrowed validator/parser rather
  than a second drifting codec implementation.
- Scratch logical length remains under the 8-MiB frame cap. Actual allocator
  capacity may exceed the requested length and is retained until inspection
  returns; no exact heap/RSS bound is claimed.
- Disk I/O, zero-initialization when the scratch grows, decode work and the
  final file-length race check remain.
- Hosted CI, Linux reproducibility, release signing, rollback and fleet
  qualification remain integration/release work.
