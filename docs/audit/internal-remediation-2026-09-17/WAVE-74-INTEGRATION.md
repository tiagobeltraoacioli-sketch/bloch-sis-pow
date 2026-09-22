# Wave 74 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`76e6cfb`. Four agents continued audit remediation across imported-wallet key
authentication, deferred-block scheduling, CI Rust-toolchain selection and
native include identity. Consensus validity, historical compatibility, wire
and persistent formats were not changed; no release or deployment action
occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-07, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-07 authenticates every newly imported HD-wallet keypair before mutation.
The wallet recomputes the address and proves private/public correspondence with
a private domain-separated sign/verify challenge. Both modern enveloped and
raw legacy imports remain accepted; malformed combinations leave no state.

EN-08/NET-04 give ready future blocks and promoted orphans one aggregate
one-block release budget per control turn. A volatile round-robin cursor
prevents starvation when both classes are ready. FIFO order, source identity,
caps, duplicate handling, `Ignore` semantics and duty-tail gates remain intact.

INF-11 validates that the root and node Rust channel pins are simple and equal
before both GitHub and GitLab Cargo work. GitHub no longer extracts one pin
with `sed`; the adversarial parser selftest is now the fifteenth hash-protected
CI entrypoint.

KS-09 recursively inventories and hashes the selected freestanding native
include tree into the private aggregate build-environment fingerprint. Content
or inventory changes change identity, while symlinks, special files, unreadable
entries and incomplete traversal stop the build.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 552
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 128 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` suite passed 194 tests with 2 ignored. Focused
  imported-key regressions passed for malformed, enveloped and raw legacy
  inputs.
- Four focused shared-release regressions passed. The first integrated run
  exposed a nondeterministic test construction; the fixture was replaced with
  a real sequential three-block chain, passed three isolated repetitions and
  then passed the complete suite.
- Native include-tree regressions passed 2/2 and the focused `getbuildinfo`
  environment-fingerprint regression passed.
- The scanner-posture guard passed 74 two-direction fixtures. The test-posture
  guard passed 89 cases in isolated mode; both checked-in pipelines and the
  adversarial toolchain parser passed.
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
