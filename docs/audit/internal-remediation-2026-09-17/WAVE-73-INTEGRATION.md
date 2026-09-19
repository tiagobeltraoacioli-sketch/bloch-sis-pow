# Wave 73 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`42eeab0`. Four agents continued audit remediation across HD-wallet structure,
deferred-orphan deduplication, isolated Python CI execution and native archiver
identity. Consensus validity, historical compatibility, wire and persistent
formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-07, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-07 refuses HD-wallet files with an empty address list and makes both
`new_address` and `try_import_keypair` fail closed if an impossible empty
in-memory state is constructed. The wallet no longer turns missing structural
state into an address at index 1. Existing valid derivation and file formats
are unchanged. The remaining CR-10/CR-02 generic callers were inventoried;
they are consensus/history/indexer boundaries, tests or deliberate final
compatibility fallbacks, so no unsafe migration was attempted.

EN-08/NET-04 include the ready-to-promote orphan queue in the cheap exact
signed-header duplicate gate. Reoffering an envelope already awaiting its
cooperative turn stops before body hashing and signature work, remains
`Ignore`, cannot enter immediately through its now-known parent, and cannot
replace the original FIFO source. The combined 256-entry cap and one-promotion
slice remain unchanged.

INF-11 requires isolated Python mode (`python3 -I`) for every Python command
in the exact GitHub cargo-test/test-guard and GitLab build-and-test contracts,
including propagated local subprocesses. The test guard and its selftest also
refuse to run unless `sys.flags.isolated` is true. This removes user-site,
`PYTHONPATH` and ambient Python environment influence, but does not attest the
interpreter bytes or installed system runtime.

KS-09 asks the locked cc-rs implementation which archiver it actually selects
for the effective host and target, resolves a bare command through the build
path, and hashes the selected executable bytes into the private aggregate
build-environment fingerprint. A missing or unreadable required archiver stops
the build. Its command and path remain absent from `getbuildinfo`.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 550
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 126 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` suite passed 193 tests with 2 ignored; the HD
  wallet audit module passed 5/5 and the focused empty-state regression 1/1.
- Three deferred-orphan regressions passed, including 64 adversarial
  retransmissions, and the full node test build check passed.
- The selected-native-tool tests passed 2/2, and the focused `getbuildinfo`
  environment-fingerprint regression passed.
- The scanner-posture guard passed 74 two-direction fixtures. The test-posture
  guard passed 86 cases in isolated mode, both checked-in pipelines passed,
  and 23 auxiliary isolation regressions passed.
- Python compilation, ledger arithmetic, unambiguous conflict-marker scanning
  and `git diff --check` passed.
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
