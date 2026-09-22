# Wave 49 KS-07: explicit offline block-log tail recovery

Date: 2026-09-18. Branch: `codex/audit-storage-lifecycle-next`. Starting
point: `1acd578`. Scope: local block-log recovery and audit evidence only. No
deployment, persisted-format change or automatic repair was performed.

## Recovered finding and current behavior

The original KS-07 finding was recovered from
`a79c88b:docs/audit/deep-audit-2026-09-16/A7-node-storage-keys-boot.md`.
The current node already fails boot when a durable frame cannot replay through
consensus, and `block-log-inspect` reports a bounded framing/codec prefix
without modifying the data directory. An interrupted append with an incomplete
length/body is also handled by the existing startup path. The remaining local
operator gap was the original report's all-zero power-loss tail: it presents as
a complete zero-length frame, so decoding fails closed, but no supported tool
could preserve and remove that suffix.

## Narrow repair contract

`block-log-repair-tail` is a separate, explicitly mutating offline command. It
requires all three arguments:

```text
bloch-pos block-log-repair-tail --data-dir <stopped-node> \
    --truncate-to <inspected-offset> --backup <new-file>
```

The command acquires the normal exclusive data-directory lock and repeats the
inspection after locking. The operator-confirmed offset must equal that fresh
inspection's exact valid prefix. The suffix is eligible only when it is an
incomplete length/body or every remaining byte is zero. A codec-invalid,
non-zero complete frame is refused because the tool cannot prove that removing
it is safe.

Before truncation, the command copies every removed raw byte to an exclusively
created mode-0600 backup, fsyncs the backup and its parent directory, rechecks
the authoritative log length, and only then truncates and fsyncs the log and
data directory. An existing backup is never overwritten. A concurrent normal
node is refused by the same lock that prevents double signing. The derived slot
index is rebuilt on the next ordinary `Store::open` as before.

This ordering makes truncation explicit and recoverable; it does not claim to
distinguish an incomplete append from every possible corrupted length prefix.
The exact offset confirmation and retained backup are therefore load-bearing.

## Compatibility and residual risk

The `u32 length || envelope` frame format, index format and automatic startup
behavior are unchanged. No consensus rule, replay verdict, state root, network
message or activation constant changed. The read-only inspection command also
remains read-only.

KS-07 remains `PARTIAL`. There is still no checksum established at frame-write
time, so the tool cannot authenticate existing bytes or safely repair arbitrary
mid-log corruption. A complete frame that decodes but fails consensus replay
still causes a fail-closed boot refusal; selecting a replacement history is a
separate recovery-policy and provenance decision. External programs that ignore
the data-directory lock can still race any offline tool.

The ledger status and aggregate counts are unchanged. This wave advances only
the supported zero-tail recovery portion of KS-07.

## Validation

- Focused store regression covers preservation of a valid frame prefix,
  durable backup of an all-zero tail, explicit refusal of a non-zero corrupt
  complete frame, and repair of an incomplete body.
- CLI regression covers wrong-offset refusal and exact backup/truncation of an
  all-zero log.
- `git diff --check` is required before integration.
