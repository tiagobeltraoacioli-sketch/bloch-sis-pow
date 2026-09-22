# Wave 58 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`0c78e38`. Four agents implemented and reviewed strict canonical-envelope
verification, production-bound ordinary Argon2 allocation, bounded unindexed
block-log serving and pinned GitHub token permissions. Existing consensus
consumers, wire and persistent formats were not migrated; no release or
deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, KS-11, NET-22 and INF-11; each remains `PARTIAL`. SR-03 remains the
sole open finding.

## Integrated changes

CR-02 adds opt-in `verify_enveloped_canonical`, composing strict suite-envelope
parsing and dispatch with the canonical Falcon verifier introduced in Wave 57.
Suite `0x0001` rejects the legacy zero-padded Falcon half while suite `0x0002`
retains its fixed-length behavior. Historical raw and enveloped verifiers and
all consumers remain unchanged pending a coordinated migration.

KS-11 reduces the ordinary one-pass Argon2 allocation ceiling from 128 MiB to
64 MiB. Together with the existing 192 MiB-pass combined-work ceiling, the
ordinary path now admits no parameters more expensive than the shipped 64 MiB
times three production profile. The explicit verified-legacy recovery path
retains its finite larger caps.

NET-22 bounds a request scanning beyond the last valid block-index record to
4,096 complete frames. An excessive valid unindexed tail fails with an
`InvalidData` restart/index-rebuild instruction before parsing the next header.
Indexed hits and ordinary short crash tails retain their previous behavior.

INF-11 requires the GitHub security workflow to declare an explicit top-level
token-permission mapping with `contents: read`, permits only `read` or `none`
for every declared scope, and refuses job-level permission overrides on all
required jobs. Existing trigger and blocking-semantics checks remain active.

## Validation

- `bloch-pos-node` passed 522 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 119 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 188 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored.
- The scanner-posture guard passed 34 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 37 fixtures and both
  checked-in pipelines across eight live crates.
- Python compilation, ledger arithmetic, unambiguous conflict-marker scanning
  and `git diff --check` passed. The ledger remains exactly 200 rows with the
  published status counts.
- Workspace-wide `cargo fmt --check` retains the inherited formatting backlog
  and is not claimed green.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
