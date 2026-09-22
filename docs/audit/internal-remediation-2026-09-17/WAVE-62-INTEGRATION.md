# Wave 62 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`d30afca`. Four agents continued the audit remediation across canonical wallet
policy, transported-block source fairness, Git-derived OSV scope and configured
native-tool fingerprints. Consensus validity, historical compatibility, wire
and persistent formats were not changed; no release or deployment action
occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, CR-10, EN-07, NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-02/CR-10 make the disclosure policy usable at the wallet boundary. Newly
created bundles receive a canonical self-check before publication, while
`verify-bundle` and `watch` expose `--canonical`. Their default remains the
historical compatibility policy so existing audit files are not silently
invalidated.

EN-07/NET-04 extend the existing 128-call per-source allowance to transported
blocks as well as attestations and transactions. The opaque IP/PeerId-derived
identity survives future-block holding, orphan holding and promotion; each
child retains its own source. The aggregate 1,024-call ceiling remains, and
exhaustion produces `Ignore`, never peer blame.

INF-11 derives the exact OSV lockfile universe from the current Git index
instead of a duplicated static register. The action scope must equal all 14
tracked `Cargo.lock` paths; missing, stale, duplicated, malformed or
command-injected fixture entries fail closed.

KS-09 fingerprints every resolvable explicitly configured linker, compiler,
archiver, ranlib or rustc-wrapper executable inside the build-environment
digest. Paths and individual component digests remain private; buildinfo
reports only the number of configured tool binaries incorporated.

## Validation

- `bloch-pos-node` passed 529 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 119 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 190 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored. Its three loopback tests required the
  permitted local-socket run outside the filesystem/network sandbox.
- The scanner-posture guard passed 47 two-direction fixtures and all 16
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
