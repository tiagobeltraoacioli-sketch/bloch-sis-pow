# Wave 45: TX-10 transaction-resource candidate

Date: 2026-09-18. Branch: `codex/audit-tx10-staking-meter`. Starting point:
`4e15334`. Scope: local source, tests, and audit evidence only. No activation
epoch, node, validator, public endpoint, deployment, or live state changed.

## Recovered finding

The exact source was recovered from repository history at
`a79c88b:docs/audit/deep-audit-2026-09-16/A1-consensus-transition.md`. It
describes TX-10 as staking-class transactions consuming zero gas and zero bytes
while consensus has no transaction-count ceiling. The current tree requires a
more precise split:

- the reference producer already stops at 256 transactions per proposal;
- node admission holds at most 4,096 mempool entries, with a 64-entry
  per-source bound;
- the wire decoder permits up to 65,536 transactions, so that is a decode
  bound rather than a practical consensus execution policy;
- `staking_tx_charge` consumes gas and bytes whenever either the dedicated
  staking-meter gate or the withdrawal lifecycle gate is active. Consequently
  lifecycle-era blocks at and after epoch 2884 are metered, although
  `STAKING_TX_METERING_ACTIVATION_EPOCH` itself remains `u64::MAX`;
- consensus still had no independent transaction-count ceiling.

The admission and proposal bounds reduce exposure for the reference node, but
cannot establish a consensus rule for a hand-built block or another producer.

## Deliberately inactive candidate

`MAX_TRANSACTIONS_PER_BLOCK` is 4,096: the reference mempool ceiling and 16
times the reference proposal limit. When, and only when, the existing staking
metering gate is active, the transition refuses a longer body with
`TooManyTransactions`. The check is before canonical serialization and
body-root hashing, so an armed node bounds the first transition work that is
linear in an attacker-selected transaction count.

The candidate applies to every transaction class. A staking-only limit would
still let an adversarial mixed body buy unbounded dispatch/state-map work by
changing tags. Gas and byte ceilings remain separate checks.

The activation constant remains `u64::MAX`. Below the gate the new count is
not consulted, including after the independently scheduled withdrawal epoch.
The focused regression supplies an oversized body and proves that production
behavior reaches the old `BodyRootMismatch` verdict; with the test-only gate
open the same body returns `TooManyTransactions`, while exactly 4,096 clears
the count check. This preserves current consensus and historical replay.

TX-10 moves from `OPEN` to `UNARMED CANDIDATE`, not `IMPLEMENTED`. Before any
activation, maintainers still need full historical replay, analysis of blocks
from non-reference producers, measured CPU/memory qualification, mixed-version
fleet rehearsal, and an explicit protocol-owner decision. This wave proposes
no epoch and makes no deployment claim.

## Validation

- `cargo test -p bloch-pos-committee transaction_count_cap_is_inert_until_the_metering_gate_opens --offline`:
  one targeted unit test passed; all integration binaries completed with zero
  selected tests.
- `cargo test -p bloch-pos-committee staking_tx_metering --offline`: five
  existing gate and charge regressions passed; all integration binaries
  completed with zero selected tests.
- `cargo test -p bloch-pos-committee --lib --offline`: 435 passed, four
  ignored, zero failed.
- `git diff --check`: passed.
- `cargo fmt --all -- --check`: not counted as passing. It reports extensive
  pre-existing workspace formatting drift outside this change; no bulk
  formatting rewrite was made.

The targeted build emitted inherited unused-import, unused-doc-comment, and
dead-code warnings. No warning was treated as evidence of this candidate's
activation readiness.
