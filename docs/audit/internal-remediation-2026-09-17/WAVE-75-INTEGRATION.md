# Wave 75 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`708aa80`. Four agents continued audit remediation across legacy wallet-secret
handling, deferred consensus-work scheduling, GitLab execution context and WASI
sysroot identity. Consensus validity, historical compatibility, wire and
persistent formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-07, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-07 zeroizes the temporary enveloped secret created when a historical raw
wallet key signs. The modern borrowed-key path and legacy signatures remain
unchanged; the wrapper is erased on ordinary, error and unwind exits.

EN-08/NET-04 add an outer cooperative round robin between the aggregate
future/orphan block class and held-attestation replay. A control turn now runs
either one deferred block transition or one four-attestation slice, not both.
The inner future/orphan cursor, FIFO order, source identity, caps and all duty
gates remain intact.

INF-11 removes inherited GitLab tool-selection channels. The common setup
clears shell, Python, Rustup, Cargo and compiler-substitution variables, then
replaces the runner's inherited `PATH` with the reviewed conventional search
set. Both posture guards bind the exact contract.

KS-09 recursively inventories and hashes `WASI_SDK_DIR` for a WASI target,
mirroring the checked-in PQ compiler branch. Other targets bind only the
freestanding native include tree used by their branch. Unsafe or incomplete
trees stop the build.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 554
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 129 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` suite passed 195 tests with 2 ignored. Focused
  legacy signing regressions passed 3/3, including corrupt raw-secret handling.
- Deferred-work focused groups passed 7/7 and 21/21; the integrated valid-block
  plus held-attestation fixture passed.
- Native input-tree regressions passed 3/3 and the focused `getbuildinfo`
  environment-fingerprint regression passed.
- The test-posture guard passed 93 adversarial cases; the scanner-posture guard
  passed 76 two-direction fixtures. Both checked-in pipelines, the toolchain
  parser and real guards passed.
- The 12 partition-report tests, 4 activation-rewrite tests, 7 attested-SSH
  shapes and bootnode selftest passed. Python compilation passed.
- Ledger arithmetic, unambiguous conflict-marker scanning and
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
