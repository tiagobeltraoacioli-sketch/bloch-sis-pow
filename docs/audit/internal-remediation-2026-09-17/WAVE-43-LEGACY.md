# Internal audit remediation, forty-third wave — legacy accounting

Date: 2026-09-18. Base: `45ae11e`; branch `codex/audit-infra-legacy`.
This wave changes only the retired Genesis-3 reference pool. It does not move
funds, rewrite a journal, deploy a service or affect Genesis-4 consensus.

## LG-09 — historical accounting aliases

New Stratum sessions already used the parsed address's canonical display form,
but journal replay trusted the spelling stored by older builds. A valid address
whose hexadecimal payload appeared in upper case therefore rebuilt a second
miner row after restart. Shares, pending-block finders and snapshotted payouts
could remain divided even though they represented one address.

Replay now canonicalizes every syntactically valid Bloch address at all three
accounting boundaries. It leaves the append-only JSONL source untouched and
preserves non-address legacy identifiers for compatibility. Derived shares and
confirmed credits therefore converge deterministically before an operator
prepares a manual payout.

The regression creates a mixed-case historical journal containing two share
spellings plus an aliased finder and payout, confirms the block, replays from
disk and proves that one canonical miner owns both shares and the exact credit.

## Validation

- `cargo test historical_address_aliases_reconcile_during_replay --locked`
  passed: 1 targeted regression.
- `cargo test --locked` in `pool/` passed: 48 unit tests and all binary/doc
  targets, with no failures or ignored tests.
- `git diff --check` passed. `cargo fmt --package bloch-pool -- --check` remains
  red on extensive inherited package formatting drift; this wave does not mix a
  repository-wide formatter rewrite into the accounting correction.
- `cargo clippy --locked -- -D warnings` reached `bloch-pool` and then remained
  red on seven inherited findings in `state.rs`, `upstream.rs` and `stratum.rs`;
  none is in the changed replay path.

LG-09 is locally `IMPLEMENTED`. The pool remains a retired reference component;
this result is not evidence of a live deployment or a completed payout review.
