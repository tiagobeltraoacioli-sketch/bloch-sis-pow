# Wave 64 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`97ceeaf`. Four agents continued the audit remediation across a genuine legacy
signature fixture, fair admitted-work scheduling, constrained GitLab execution
context and Rust-flags linker fingerprints. Consensus validity, historical
compatibility, wire and persistent formats were not changed; no release or
deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10, EN-08, NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-10 pins a genuine backend-generated valid raw hybrid signature whose first
bytes are the envelope magic `B1 0C`. Explicit raw verification accepts it
while generic format autodetection misclassifies and refuses it. The one-off
seed search is not part of CI; the fixed seed reconstructs the fixture directly.

EN-08/NET-04 move already-admitted blocks, attestations, transactions and RPC
into four local FIFO queues. Strict round-robin processes at most 32 events per
loop turn, with bounded look-ahead covering the maximum 4,096 network events
plus 64 RPC workers. Reservations remain charged through actual processing.

INF-11 constrains the accepted GitLab global and required-job execution
context to the reviewed variables, tag and setup. Inherited `set +e`, BASH_ENV
or PATH injection, hooks, unexpected before/after scripts and job variables
now fail closed while the checked-in pipelines retain their intended shape.

KS-09 parses effective Cargo/Rust flags for both `-Clinker=...` forms, follows
rustc's last-option precedence and fingerprints a resolvable selected linker.
Malformed, empty or unavailable selections remain represented by their hashed
environment field without inflating the executable count.

## Validation

- `bloch-pos-node` passed 534 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 122 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 191 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored.
- The scanner-posture guard passed 56 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 44 fixtures and both
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
