# Wave 71 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`7a85a56`. Four agents continued audit remediation across native funding-plan
verification, held-attestation replay, local CI entrypoint integrity and WASI
native build inputs. Consensus validity, historical compatibility, wire and
persistent formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 make native funding-plan autocheck follow its known artifact
contract explicitly: raw public key with suite-1 enveloped signature first,
then explicit raw verification, then the retained historical mixed-format
fallback. A genuine funding-plan raw `B1 0C` fixture proves that explicit raw
verification avoids generic magic-prefix misclassification.

EN-08/NET-04 make block landing schedule only a pending root, then revalidate
at most four held attestations per control turn. Ready roots and their waiters
remain FIFO; the front root stays scheduled until drained, and validator duties
remain gated while the ready tail exists. The existing 32-per-root and
256-global pending bounds remain unchanged. Each individual verification is
still non-preemptible, and multiple roots can require multiple turns.

INF-11 derives all local Python and shell entrypoints from the three exact
test-job contracts and binds their reviewed bytes to 11 SHA-256 pins. Every
entrypoint must be a regular file with no symlink in the file or path
components. The checker is protected bidirectionally: its self-test exercises
the checker while the checker pins the self-test bytes. Interpreters, packages,
runtime behavior, hosted runners and repository rulesets remain external.

KS-09 adds the two checked-in WASI native-input selectors, `WASI_SDK_DIR` and
`DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE`, to the watched build
environment. Their normalized values now affect the build fingerprint without
being disclosed in version output. SDK, header and library contents,
undeclared inputs and independent provenance remain outside this proof.

## Validation

- Outside the restricted network sandbox, `bloch-pos-node` passed 546 unit
  tests with 19 ignored finite/performance rehearsals. All integration targets
  passed: 124 tests passed and 6 performance tests were explicitly ignored.
- Native funding-plan examples passed 6 tests with 1 ignored; the separate
  opt-in integration passed 1/1, including the genuine magic-prefix fixture.
- Focused network regressions passed for 4+4+2 sliced replay, an independent
  ready root, pending-pool boundaries and validator-duty gating; the node test
  build check passed.
- The scanner-posture guard passed 74 two-direction fixtures and all required
  checked-in jobs. The test-posture guard passed 81 cases and both checked-in
  pipelines.
- The focused build-fingerprint regression for the WASI selectors passed.
  Python compilation, ledger arithmetic, unambiguous conflict-marker scanning
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
