# Wave 68 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`99287b4`. Four agents continued audit remediation across legacy funding
verification, future-block retention fairness, exact test-workflow steps and
native-build identity. Consensus validity, historical compatibility, wire and
persistent formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 make the read-only `verify-funding-signature` tool verify the
native producer's raw-key/enveloped-signature representation explicitly, then
try enveloped/enveloped and raw/raw forms before its retained historical
fallback. A genuine TransferV2 raw signature beginning `B1 0C` proves the
explicit route succeeds where generic autodetection refuses.

EN-08/NET-04 cap the authenticated future-block pool at eight envelopes per
normalized source inside its unchanged 32-envelope and 16 MiB global bounds.
`Gossip(None)` is one bounded bucket, overload remains `Ignore`, and removing
or releasing an entry immediately reopens that source's capacity.

INF-11 exact-allowlists all 11 `run:` steps, in order, for the required GitHub
`cargo-test` job. Extra, missing, changed or reordered steps fail closed, and
literal-to-folded YAML changes cannot silently fuse reviewed commands.

KS-09 adds locked cc-rs output controls to the build-environment digest and
incremental rebuild watch set: archive and ranlib flags, default suppression,
shell-escaped parsing, custom wrapper declaration, forced disable and C++
standard-library selection, including their applicable target forms.

## Validation

- `bloch-pos-node` passed 538 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 124 tests passed and 6
  performance tests were explicitly ignored.
- The funding verifier's focused and complete example tests passed 1/1. The
  native funding plan passed 5 tests with its opt-in CLI roundtrip ignored;
  both relevant example targets passed their recorded offline checks.
- The scanner-posture guard passed 74 two-direction fixtures and all required
  checked-in jobs. The test-posture guard passed 61 cases and both checked-in
  pipelines; the GitHub cargo-test job matched all 11 reviewed run steps.
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
