# Wave 50 EN-23: streaming block-log decode

Date: 2026-09-18. Branch: `codex/audit-wave50-storage-stream`. Starting point:
`d914a77`. Scope: local boot/replay input decoding, tests and audit evidence.
No deployment, persisted-format change, consensus change or gate activation was
performed.

## Recovered residual

The original EN-23 finding was recovered from
`a79c88b:docs/audit/deep-audit-2026-09-16/A5-node-engine.md`. It records that
retained canonical history grows with chain age and that rebuilding fork choice
and pruning during cold replay are quadratic. Earlier remediation added a
validated restart cache, incremental state roots and copy-reduced cache restore,
but `Store::read_all` still used `read_to_end` before decoding. Boot therefore
held the complete raw `blocks.log` byte vector at the same time as the growing
vector of decoded envelopes.

## Local correction

`Store::read_all` now snapshots the opened log inode's length and decodes the
framed stream in order through a bounded buffered reader. At most one encoded
frame payload is retained transiently by this layer; decoded envelopes are
still returned in their original order for the unchanged cache validation and
replay path.

The persisted `u32 length || envelope` format is unchanged. The existing 8 MiB
frame ceiling remains authoritative. A complete malformed or zero-length frame
still fails closed, while an incomplete trailing length/body remains the one
tolerated crash residue. No block bytes, replay verdict, state root, fork-choice
input or cache format changed.

The regression feeds 128 valid frames through a reader that rejects a
whole-log-sized read request, checks exact slot order, retains the incomplete
tail behavior, and proves a complete zero-length frame is still corruption.
The existing store suite covers append, restart, reorg publication, index
repair and the exact-limit frame.

## Honest boundary

EN-23 remains `PARTIAL`. This removes one whole-log raw byte copy; it does not
remove the decoded `Vec<BlockEnvelope>`, the engine's canonical history,
quadratic cold-replay work, branch retention growth or state/cache memory.
There is no production-scale peak-RSS or restart-SLA measurement in this wave.

Ledger status and aggregate counts are unchanged: 200 findings total, 71
implemented, 98 partial, 15 unarmed candidates, five protocol decisions, seven
base-changed, one open, one refuted in the audit and two verified positives.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos
  replay_log_decode_streams_bounded_frames_and_preserves_tail_refusals --
  --nocapture`: 1 passed.
- `cargo test -p bloch-pos-node --bin bloch-pos store::tests:: --
  --nocapture`: all 27 store tests passed.
- `cargo clippy -p bloch-pos-node --bin bloch-pos`: passed with the inherited
  warning set; no warning was introduced in the streaming decoder.
- `git diff --check`: passed.
