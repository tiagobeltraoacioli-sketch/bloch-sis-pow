# Wave 76 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`5580070`. Four agents continued audit remediation across bounded HD-wallet
restore work, single-attestation replay, GitHub execution context and implicit
native build inputs. Consensus validity, historical compatibility, wire and
persistent formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-07, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-07 adds opt-in HD-wallet load limits for file bytes, total addresses and
expensive `derived:true` rederivations. Limits are enforced before mnemonic
handling, Argon2, decryption or PQ derivation, while historical load APIs and
the persistent schema remain compatible. A probabilistic legacy regression
was also replaced with two deterministic valid secrets.

EN-08/NET-04 reduce held-attestation replay from four hybrid verifications to
exactly one per control turn, the smallest practical verdict unit. The outer
block/attestation and inner future/orphan schedulers, per-root FIFO, source
semantics, caps and duty gates remain intact.

INF-11 closes inherited execution channels for every GitHub `run:` step. Both
workflows clear shell, Python, Rustup, Cargo and compiler-substitution variables,
replace inherited `PATH`, and invoke a fixed profile-free fail-fast Bash shell.
Both posture guards require the exact contract.

KS-09 binds twenty implicit native build variables covering compiler include
and subprogram search, native library search, Linux/macOS dynamic-loader
search/injection and archive timestamp control. Each exact variable is watched
even while absent and only its value hash enters the private aggregate build
identity.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 555
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 130 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` suite passed 196 tests with 2 ignored. The
  opt-in restore-bound regression passed at the exact limit and one over it;
  audit wallet boundaries passed 7/7.
- Deferred-work focused groups passed 7/7 and 21/21. The 33-turn maximum-root
  FIFO replay regression passed.
- The implicit native-environment inventory regression and the focused
  `getbuildinfo` scope regression passed.
- The test-posture guard passed 96 adversarial cases; the scanner-posture guard
  passed 79 two-direction fixtures. Both checked-in pipelines, the toolchain
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
