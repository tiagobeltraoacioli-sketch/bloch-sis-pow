# Wave 69 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`8e0ebd6`. Four agents continued audit remediation across offline payout
inspection, future-block byte fairness, test-guard workflow integrity and
source-tree build identity. Consensus validity, historical compatibility,
wire and persistent formats were not changed; no release or deployment action
occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 make the read-only `validator-payout inspect` boundary try the
strict suite-1 envelope, then raw verification after removing only the already
validated header, before its retained historical fallback. A genuine payout
signature beginning `B1 0C` proves the explicit raw route succeeds where
generic autodetection refuses.

EN-08/NET-04 add a 4 MiB retained-byte ceiling per normalized source inside
the unchanged 16 MiB global future pool, alongside the existing 8-per-source
and 32-global envelope ceilings. A compile-time assertion guarantees one
maximum production proposal fits an empty source share. Overload remains
`Ignore`, and release immediately reopens capacity.

INF-11 binds the entire GitHub `tests-blocking-guard` job to an exact header
and ordered checkout, selftest, primary guard and auxiliary verification
contract. Missing, extra, reordered or ambiguous execution steps, mutable
checkout references and unreviewed execution metadata fail closed.

KS-09 makes the source inventory invalidate its identity on directory-entry,
metadata, path-encoding and file-read failures, as well as source symlinks,
instead of silently hashing a smaller set. The shared collector directly tests
hidden `.macros` inputs and symlink refusal.

## Validation

- Outside the restricted network sandbox, `bloch-pos-node` passed 542 unit
  tests with 19 ignored finite/performance rehearsals. All integration targets
  passed: 124 tests passed and 6 performance tests were explicitly ignored.
- The payout CLI target passed all 6 tests; its focused genuine magic-prefix
  regression passed, and the recorded binary check passed.
- The scanner-posture guard passed 74 two-direction fixtures and all required
  checked-in jobs. The test-posture guard passed 69 cases and both checked-in
  pipelines.
- Source-inventory focused tests and the live `getbuildinfo` digest regression
  passed. The non-UTF-8 filename fixture remains gated for Linux and no hosted
  result is claimed.
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
