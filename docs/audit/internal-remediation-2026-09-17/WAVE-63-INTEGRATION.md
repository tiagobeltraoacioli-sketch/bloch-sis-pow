# Wave 63 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`cef4b8e`. Four agents continued the audit remediation across explicit Ustav
verification policy, HTTP RPC source fairness, verdict-shell guards and
delegated compiler fingerprints. Consensus validity, historical compatibility,
wire and persistent formats were not changed; no release or deployment action
occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, CR-10, EN-07, NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-02/CR-10 remove generic format guessing from the Ustav compatibility
verifier after its existing envelope checks and add an opt-in canonical Ustav
verifier. Compact suite signatures pass both policies, padded Falcon passes
only compatibility, and raw signatures fail both at this boundary.

EN-07/NET-04 carry an HTTP RPC connection's normalized peer IP through JSON
dispatch and the bounded engine queue into transaction verification. RPC now
uses the same 128-call source share and 1,024-call aggregate wall-slot ceiling
as transported traffic. Exhaustion returns the existing retryable error and
deadline without partial admission or peer blame.

INF-11 closes a GitHub execution-context bypass in which an approved command
could run under `shell: bash {0} || true`. Required scanner/test jobs now refuse
custom `shell` and job/workflow `defaults` shapes rather than trying to classify
arbitrary shell templates.

KS-09 fingerprints an unambiguous compiler delegated directly by ccache,
distcc, icecc or sccache in addition to the configured wrapper. A shared,
restricted command parser handles quoted/Windows paths and refuses ambiguous
quotes, escapes and wrapper-option forms.

## Validation

- `bloch-pos-node` passed 532 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 121 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-ustav` passed all 5 crypto-kernel tests and its chameleon integration
  test; its library and doctest targets contain no tests.
- The scanner-posture guard passed 49 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 40 fixtures and both
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
