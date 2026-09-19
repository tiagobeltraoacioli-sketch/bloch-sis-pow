# Wave 77 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`55d0d67`. Four agents continued audit remediation across exact expensive-KDF
recovery, bounded production HD-wallet callers, multi-root held-attestation
amplification and GitLab validator-lifecycle parity. Consensus validity,
historical compatibility, wire and persistent formats were not changed; no
release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-07, EN-08/NET-04, INF-03/INF-04 and KS-11; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

KS-11 binds the legacy expensive-KDF opt-in to one exact, operator-reviewed
`memory,passes,lanes` tuple. Missing, malformed, extra, out-of-range or
mismatching expectations fail closed before Argon2. The ordinary production
limits and finite historical ceilings remain unchanged.

CR-07 gives interactive consumers a conservative HD-wallet default of 64 MiB,
1,024 address records and 256 expensive mnemonic rederivations. Both repository
production restore callers use it; a conspicuous trusted-backup option retains
historical compatibility under the existing absolute byte ceiling.

EN-08/NET-04 cap pending attestations to 32 distinct missing roots, 32 entries
per attributed source and 8 per source/root. Source identity survives release
and a possible second hold, while per-root FIFO, duty gates and `Ignore`
capacity semantics remain intact.

INF-03/INF-04 make GitLab execute the same blocking eight-mutation validator
lifecycle checker as GitHub. The exact ordered posture contract and negative
selftests refuse deletion from either pipeline.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 556
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 131 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` suite passed 197 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests. The retained CLI
  consumer tests passed 2/2.
- Committee gossip passed 24/24 tests; focused held replay and every KS-11
  exact-tuple/boundary regression passed.
- The validator-lifecycle control passed and all eight source mutations were
  killed. The test-posture guard passed 98 adversarial cases; the scanner
  posture guard passed 79 two-direction fixtures. Both real guards and the
  pinned toolchain parser passed.
- The 12 partition-report tests, 4 activation-rewrite tests, 7 attested-SSH
  shapes and bootnode selftest passed. Relevant Python files compiled.
- Ledger arithmetic, unambiguous conflict-marker scanning and
  `git diff --check` passed.
- Workspace-wide `cargo fmt --check` retains the inherited formatting backlog
  and is not claimed green.

## Commits

- `2cb551d` — exact expensive-KDF expectation.
- `80ad80a` — bounded interactive HD-wallet restores.
- `562a6ee` — GitLab validator-lifecycle mutation gate.
- `b7fc057` — multi-root held-attestation bounds.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
