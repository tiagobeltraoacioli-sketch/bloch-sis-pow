# Wave 78 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`9eebe9d`. Four agents continued audit remediation across production KDF
pinning, bounded public HD-wallet listing, unattributed held-attestation
fairness and cross-pipeline proof parity. Consensus validity, historical
compatibility, wire and persistent formats were not changed; no release or
deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-07, EN-08/NET-04, INF-03/INF-04 and KS-11; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

KS-11 makes the ordinary keystore path accept only the exact production
Argon2 tuple. Any cheap or expensive alternative is refused before derivation;
historical non-production files remain recoverable only under one exact,
explicitly reviewed tuple.

CR-07 bounds public HD-wallet listing as well as encrypted restore. All three
repository production consumers now default to 64 MiB and 1,024 records;
decrypting consumers additionally cap mnemonic rederivations at 256. The
trusted-backup override remains explicit.

EN-08/NET-04 give source-free held attestations a collective 32-entry and
eight-per-root bucket. No identity is fabricated, capacity reopens through the
single eviction path, and attributed sources retain independent headroom.

INF-03/INF-04 make GitLab run the same partition-report and activation-parser
adversarial suites as GitHub. The complete GitLab guard job is bound to a
unique plain key, exact ordered commands, blocking semantics and a ten-minute
timeout. The known-red funded-admission rehearsal was tested and deliberately
not added as a false green gate.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 556
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 131 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` suite passed 198 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests. The retained CLI
  consumer passed 3/3 tests.
- Committee gossip passed 26/26 tests; focused held replay and all KS-11
  production-pin, exact-recovery and legacy-recovery regressions passed.
- The test-posture guard passed 102 adversarial cases; the scanner-posture
  guard passed 79 two-direction fixtures. Both real guards passed for eight
  crates/jobs on each pipeline.
- The 12 partition-report tests, 4 activation-rewrite tests, 7 attested-SSH
  shapes and bootnode selftest passed. Relevant Python files compiled.
- Ledger arithmetic, unambiguous conflict-marker scanning and
  `git diff --check` passed.
- Workspace-wide `cargo fmt --check` retains the inherited formatting backlog
  and is not claimed green.

## Commits

- `fd699d3` — pin ordinary keystore KDF to production.
- `dde05ea` — bound public HD-wallet listing.
- `6b700bf` — align cross-pipeline blocking proof regressions.
- `876a270` — bound unattributed held attestations.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
