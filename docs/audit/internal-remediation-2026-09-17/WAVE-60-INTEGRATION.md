# Wave 60 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`fc96e52`. Four agents implemented and reviewed canonical policies at modern
vault boundaries, aggregate gossip-verification admission, immutable scanner
entrypoints and build-tool binary fingerprints. Consensus validity, historical
compatibility APIs, wire and persistent formats were not changed; no release
or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, EN-07, NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-02 exposes opt-in canonical verification for versioned signed vault anchors,
Bitcoin anchors and recovery contexts. Canonical restore refuses a padded
Falcon representation before releasing the recovery secret. Existing
compatibility methods and historical artifacts retain their previous behavior.

EN-07/NET-04 give block, attestation and transaction network admission one
node-local allowance of 1,024 new hybrid verification calls per wall slot.
Exact cached failures consume no allowance. Exhaustion produces `Ignore` for
gossip or a retryable RPC refusal, never a peer rejection; local proposals and
consensus execution do not consult this relay budget.

INF-11 requires the GitHub OSV action to use an immutable lowercase 40-hex
revision. The scanner-posture job in each pipeline must directly run both its
adversarial self-test and the real-file guard; retaining only one no longer
satisfies the guard.

KS-09 incorporates domain-separated SHA3-256 fingerprints of the selected
`rustc` and Cargo executable bytes into the existing build-environment digest.
Paths and bytes are not published. The selected files are incremental build
dependencies, and buildinfo reports how many of the two tools were hashed.

## Validation

- `bloch-pos-node` passed 526 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 119 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 189 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored.
- `bloch-pq-vault` passed all 47 unit tests and both compile-fail doctests.
- The scanner-posture guard passed 41 two-direction fixtures and all 16
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
