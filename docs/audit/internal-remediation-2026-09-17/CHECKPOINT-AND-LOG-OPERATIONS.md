# Checkpoint and block-log operations — 2026-09-17

These changes preserve checkpoint encodings, signatures, historical zero validator-set roots, and checkpoint anti-rollback rules. No consensus activation is required.

## SR-05: local state evidence

At boot, both the stored checkpoint and an incoming verified envelope are checked against the state root of their named block when that block exists in the replay-validated canonical chain. The reserved release genesis anchor uses the manifest-derived genesis state. Published checkpoints whose boundary block is genesis retain the historical RPC/header convention (zero for legacy genesis, pre-state commitment for bound genesis), rather than being compared to the reserved anchor’s different state root. A mismatch is an operator-action refusal (exit 78 through the existing typed WS error). Incoming mismatches cannot replace `ws_latest`.

An absent local block is not evidence of agreement: the node prints that the checkpoint state root has not been locally validated. This does not implement state download or shorten replay. Revalidation during later synchronization remains separate work.

The existing published `validator_set_root = 0` encoding means that no independent validator registry commitment is available. It remains accepted. Existing nonzero signed roots remain accepted with an explicit warning that this field cannot be independently derived. New `ws-checkpoint` creation refuses a manually supplied nonzero `--validator-set-root`; signing an arbitrary operator value must not look like validating it. This is a deliberate CLI restriction, not a wire-format migration. Full SR-05 closure still requires a specified, independently derived validator-set commitment and post-sync validation.

## SR-13: repeatable publication

Repeat `ws-checkpoint` with the same `--out` prefix to recheck the RPC evidence and reuse the original binary checkpoint. If `--issued-at` is omitted, the original issuance time is retained, preserving its signed digest. Explicitly changing the timestamp, chain identity, epoch, signer arrangement, or either root is refused. The initial binary is created exclusively; a competing publisher cannot silently overwrite it. An incomplete or malformed existing binary is refused for investigation.

The JSON companion can be regenerated from the unchanged binary. Preserve and distribute the original binary throughout the signing ceremony. Do not select another output prefix to bypass a refusal: the tool has no global publication registry and cannot detect an artifact minted in another directory or machine. Same-epoch conflicting envelopes still cause the existing anti-equivocation boot refusal. SR-13 therefore remains partial.

## KS-07: offline log diagnosis

Stop the node or work from an immutable copy, preserving the original data directory and backup:

```sh
bloch-pos block-log-inspect --data-dir /path/to/offline-copy
```

The command reads `blocks.log` one bounded frame at a time without opening the store for mutation, creating a lock/index, or invoking startup tail repair. It reports total bytes, decoded frame count, the byte offset through the decoded prefix, and the first framing/codec issue. Exit 0 means the framing and codec scan completed; exit 1 reports a detected issue; exit 2 reports invocation or I/O failure. It does not inspect private key files or print block payloads.

A successfully decoded prefix is **not** a verified chain. This command does not execute consensus transitions, validate state roots or signatures, or provide missing per-frame checksums. In particular, an incomplete frame can indicate either a torn append or a corrupted earlier length: its offset is not authorization to truncate. Restore from a verified backup and investigate before modifying original bytes. Existing conservative startup handling of incomplete tails is unchanged; no new destructive repair command is introduced. KS-07 remains partial.
