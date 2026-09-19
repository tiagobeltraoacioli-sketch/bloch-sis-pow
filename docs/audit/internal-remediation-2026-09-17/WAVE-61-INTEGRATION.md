# Wave 61 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`8bf7bfc`. Four agents continued the audit remediation across canonical
disclosure verification, transport-source admission fairness, exact OSV action
scope and selected Rust sysroot fingerprints. Consensus validity, historical
compatibility APIs, wire and persistent formats were not changed; no release
or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, CR-10, EN-07, NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-02/CR-10 add opt-in canonical verification to off-chain selective-
disclosure bundles. The strict policy rejects raw/mixed and zero-padded Falcon
representations, while the historical verifier and watch summary preserve
compatibility with previously distributed files.

EN-07/NET-04 preserve part of the shared 1,024-call wall-slot allowance for
each transport source: attestations and transactions permit at most 128 new
hybrid verification calls per normalized devnet IP or authenticated libp2p
PeerId. Exact cached failures remain free, overload is never treated as peer
guilt, and block/RPC admission retains only the aggregate ceiling.

INF-11 requires the pinned GitHub OSV action step itself to carry exactly the
reviewed configuration and all 14 tracked lockfiles. Missing, extra, duplicated
or decoy arguments, including replacement with `--help`, now fail the posture
guard.

KS-09 extends the build-environment digest with the selected sysroot compiler,
available rustc-driver libraries and target `libstd` artifacts. The files are
incremental dependencies; buildinfo publishes only their count, not paths or
component digests.

## Validation

- `bloch-pos-node` passed 528 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 119 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 190 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored.
- The scanner-posture guard passed 44 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 37 fixtures and both
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
