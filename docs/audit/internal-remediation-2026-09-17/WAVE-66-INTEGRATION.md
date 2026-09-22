# Wave 66 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`514ed42`. Four agents continued the audit remediation across wallet signature
policy, cost-aware engine scheduling, CI state channels and linker search-path
identity. Consensus validity, historical compatibility, wire and persistent
formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 move `postern-wallet verify-message` onto explicit compatible
envelope then raw verification before its final historical mixed-format
fallback. The new opt-in canonical mode requires canonical envelopes. A
genuine wallet-message raw signature beginning `B1 0C` pins the ambiguity and
the explicit escape path without a runtime search.

EN-08/NET-04 retain the 32-event outer engine turn but slice present classes
as one block, eight attestations, eight transactions and eight RPC calls. A
block-only 4,096-event flood therefore returns to wall-slot and validator-duty
checks after one processed block while FIFO, rotating round-robin and transport
reservations remain intact.

INF-11 refuses required GitHub steps that mutate later execution through
GITHUB_PATH, GITHUB_ENV, their workflow contexts or legacy add-path/set-env
commands. GITHUB_OUTPUT remains accepted. Six new two-direction fixtures cover
the permitted output channel and hostile cross-step replacement paths.

KS-09 carries the effective PATH from rustc's observed `env`-wrapped linker
command into executable resolution. Clearing PATH without restoring it makes a
bare linker unavailable rather than fingerprinting a same-named executable
from the build script's unrelated environment.

## Validation

- `bloch-pos-node` passed 536 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 123 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` with wallet CLI coverage passed 197 library tests with 2
  ignored. The default complete crate run passed 191 library tests and all 6
  integration tests; 2 library and 2 doctest cases were ignored.
- The scanner-posture guard passed 70 two-direction fixtures and all 16
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
