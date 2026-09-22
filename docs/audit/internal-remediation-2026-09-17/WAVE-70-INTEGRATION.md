# Wave 70 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`e3fb033`. Four agents continued audit remediation across offline deposit
inspection, pending-attestation amplification, the GitLab test contract and
mandatory workspace source identity. Consensus validity, historical
compatibility, wire and persistent formats were not changed; no release or
deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 make `validator-deposit inspect` authenticate every present
authorization signature before reporting success. It tries the explicit
suite-1 envelope, then raw verification after removing only the required
validated public-key header, before its retained historical fallback. The same
inspection runs before `sign` opens a keystore. A genuine raw `B1 0C` fixture
passes the explicit route, while a mutation is refused.

EN-08/NET-04 cap authenticated attestations waiting on one missing block root
at 32 inside the unchanged 256-global pending pool. One block arrival therefore
cannot release the entire pool into one engine event, other roots retain
headroom, overflow remains `Ignore`, and ordinary release reopens capacity.

INF-11 binds GitLab `build-and-test` to an exact whole-job contract: unique
global variables/default context, ordered header, timeout, YAML body and five
reviewed commands. Insertions, removals, reorder, block scalars, aliases,
quoted duplicate job keys, duplicated context and waiver changes fail closed.

KS-09 makes a complete source identity mandatory after a normal workspace is
detected. Partial traversal, symlinks or any missing declared root input now
stop the build instead of producing a runnable workspace binary stamped
`unavailable`. Genuinely vendored copies retain the explicit unavailable case.

## Validation

- Outside the restricted network sandbox, `bloch-pos-node` passed 545 unit
  tests with 19 ignored finite/performance rehearsals. All integration targets
  passed: 124 tests passed and 6 performance tests were explicitly ignored.
- The deposit CLI integration passed 1/1; its focused genuine magic-prefix
  regression and recorded binary check passed.
- The committee pending-pool focus passed 3/3, including per-root, per-duty and
  global FIFO regressions; the node test build check passed.
- The scanner-posture guard passed 74 two-direction fixtures and all required
  checked-in jobs. The test-posture guard passed 78 cases and both checked-in
  pipelines.
- Four applicable source-identity tests passed locally. Python compilation,
  ledger arithmetic, unambiguous conflict-marker scanning and
  `git diff --check` passed.
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
