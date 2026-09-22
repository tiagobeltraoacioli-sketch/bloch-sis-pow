# Wave 59 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`9a0dd11`. Four agents implemented and reviewed canonical raw-hybrid
verification, an aggregate lifecycle-verification budget, directed-sync
predecode admission and scanner-job verdict binding. Existing consensus
consumers, validity rules, wire and persistent formats were not migrated; no
release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, ST-05, NET-22 and INF-11; each remains `PARTIAL`. SR-03 remains the
sole open finding.

## Integrated changes

CR-02 adds opt-in `verify_legacy_hybrid_raw_canonical` for callers whose
trusted metadata already requires the raw legacy hybrid layout. It performs no
magic sniffing or envelope fallback and rejects the zero-padded Falcon variant.
Historical raw verification and all consumers remain unchanged.

ST-05 adds a 256-call aggregate ceiling per 30-second wall slot around new
lifecycle hybrid verification, in addition to the existing two calls per
identity. Exact cached failures consume no allowance. The counter is
node-local admission policy, renews with the per-identity map, and never enters
block validation.

NET-22 reserves per-peer count and byte capacity before decoding each block
envelope in a directed libp2p sync page. The RAII reservation travels with the
engine event without double charging. Saturation or malformed input stops the
page and prevents chasing past a locally created gap; the next timer resumes
from the applied head.

INF-11 binds every required scanner job to its concrete local verdict in an
explicit GitLab `script` or GitHub `run`/`uses` field. Job/step names,
comments, variables, echoed command strings and compound commands that can
replace exit status no longer satisfy the posture guard.

## Validation

- `bloch-pos-node` passed 524 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 119 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 189 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored.
- The scanner-posture guard passed 38 two-direction fixtures and all 16
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
