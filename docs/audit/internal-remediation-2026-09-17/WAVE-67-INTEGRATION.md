# Wave 67 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`0a8e268`. Four agents continued the audit remediation across offline deposit
signatures, future-block scheduling, exact CI steps and configured-tool build
identity. Consensus validity, historical compatibility, wire and persistent
formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 make the offline `sign-deposit-funding` verifier try explicit
envelope then raw formats before the historical mixed-format fallback. A
genuine funded-deposit possession signature beginning `B1 0C` proves the raw
path succeeds where generic autodetection refuses. Consensus/admission paths
and canonical transaction bytes remain unchanged.

EN-08/NET-04 release at most one eligible future block per engine control turn.
If a ready tail remains, metrics and stop/control checks run and the loop
continues without sleeping or accepting a new batch; validator duties remain
gated until the ready tail is safely drained. Original source and initial
`Ignore` semantics are preserved.

INF-11 exact-allowlists every `run:` step, in order, for the eight required
GitHub security jobs. Extra, missing or reordered steps fail closed, and the
parser distinguishes literal from folded YAML so two reviewed commands cannot
be silently fused into one shell line.

KS-09 shares the fail-closed `env` parser with configured compiler, linker,
archiver and wrapper variables. The selected tool and any unambiguous known
delegate are now fingerprinted under the effective PATH that their wrapper
actually receives.

## Validation

- `bloch-pos-node` passed 537 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 124 tests passed and 6
  performance tests were explicitly ignored.
- The offline deposit-funding example passed 3 ordinary tests with its opt-in
  CLI roundtrip ignored; an explicit include-ignored run passed all 4 tests.
  Its example target also passed `cargo check`.
- The scanner-posture guard passed 74 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 57 cases and both
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
