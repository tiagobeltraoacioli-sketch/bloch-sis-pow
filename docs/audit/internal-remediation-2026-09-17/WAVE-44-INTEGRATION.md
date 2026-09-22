# Wave 44: 2026-09-18 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`45ae11e`. Scope: local source, tests, and audit evidence only. No node,
validator, public endpoint, fleet configuration, release artifact, or live
funds were contacted or changed.

## Recovered continuation point

The previous local closeout left 200 finding rows: 66 implemented, 89 partial,
30 open, 7 base changed, 4 protocol decisions, 2 verified positives, one
unarmed candidate, and one finding refuted in the audit. The remaining open
set consisted primarily of protocol/economic decisions, external evidence,
the reorg-publication architecture item, and aggregate findings whose itemized
source was absent from the supplied bundle.

This continuation integrated four isolated work tracks:

- Legacy pool replay canonicalizes valid historical address aliases before
  accounting, so aliases cannot split miner credit. LG-09 moved from partial
  to implemented.
- Vault and API transaction construction now expose checked paths that reject
  invalid outpoints, monetary overflow or underflow, dust, disproportionate
  fees, unsafe CSV delays, and invalid or overlapping key roles. BV-05, BV-08,
  BV-19, and CR-07 remain partial because product policy, deployed key
  separation, and operational evidence are outside this local patch.
- Reorg persistence is published by a dedicated writer rather than performing
  encoding, durable writes, index invalidation, and index rebuild on the
  consensus thread. Validator duties remain blocked until the durable result
  is observed, and writer failure is fail-stop. EN-17 moved from open to
  implemented.
- Gossip and directed-sync height hints advance only after an engine `Accept`
  verdict from a still-connected peer. Rejection, ignore, disconnect, and late
  verdict behavior is regression-tested. NET-07 moved from partial to
  implemented. NET-21 and NET-22 were recovered from repository history and
  moved from aggregate open rows to itemized partial findings.

## Resulting ledger

The ledger remains 200 finding rows:

- 69 implemented
- 89 partial
- 27 open
- 7 base changed
- 4 protocol decisions
- 2 verified positives
- 1 unarmed candidate
- 1 refuted in audit

This is a three-finding reduction in the open set, not a release approval.
Twenty-seven findings still require protocol decisions, external operational
evidence, missing source-detail recovery, or further implementation.

## Combined validation

Validation was repeated after all four tracks were integrated into the same
branch:

- `cargo test -p bloch-pos-node --bin bloch-pos store::tests --no-fail-fast`:
  25 passed.
- `cargo test -p bloch-pos-node sync_height_hint_requires_engine_acceptance_and_is_monotonic --offline`:
  targeted regression passed.
- `cargo test -p bloch-pos-node directed_sync_origin_reports_every_engine_verdict --offline`:
  targeted regression passed.
- `cargo test -p bloch-pq-vault`: 33 passed.
- `cargo test --manifest-path services/pq-shield-api/Cargo.toml`: 18 passed.
- The isolated pool worktree ran 48 pool tests successfully before integration;
  subsequent tracks did not touch the pool package.
- The finding ledger was counted from its table rows and matches the totals
  above. `git diff --check 45ae11e..HEAD` passed before this checkpoint was
  added.

The workspace still has inherited formatting and lint warnings documented by
the individual Wave 43 reports. This checkpoint does not claim full-workspace
formatting, lint, release qualification, production deployment, or external
validator verification.

## Next safe work

Continue from the 27 open rows in `FINDINGS.md`. Prioritize findings with a
local implementation path and keep protocol/economic choices, production
credential claims, independent-validator evidence, and activation epochs out
of source-only remediation until the required owners and evidence are
available.
