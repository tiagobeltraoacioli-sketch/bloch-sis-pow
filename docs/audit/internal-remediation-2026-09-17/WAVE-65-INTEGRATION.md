# Wave 65 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`6e3328d`. Four agents continued the audit remediation across pool signature
policy, proposal-duty retention, guarded CI execution context and default-linker
build identity. Consensus validity, historical compatibility, wire and
persistent formats were not changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-09, INF-11 and KS-09; each remains `PARTIAL`. SR-03 remains
the sole open finding.

## Integrated changes

CR-10/CR-02 make the pool ownership-proof boundary classify compatible
envelopes and raw legacy signatures explicitly before its final historical
mixed-format fallback. An opt-in canonical policy refuses raw proofs. A genuine
pool-domain fixture whose raw signature starts with `B1 0C` exercises the
ambiguity without a runtime search.

EN-09 retains at most two authenticated proposals for one immutable genesis
validator and slot: the intended proposal plus a complete equivocation pair.
Later variants are ignored before body/fork-choice retention without blaming
the forwarding peer. Exact proposal ids avoid double charging during future or
orphan promotion, and finalized-floor pruning bounds the index consistently.

INF-11 binds more of the executable context around required CI verdicts.
GitHub environment overrides, containers/services, mutable or unreviewed
actions and unexpected inputs fail closed. GitLab protected jobs refuse
unreviewed image, service, cache, artifact, dependency and needs context.

KS-09 asks rustc to link a tiny target probe only when no explicit linker is
selected, parses its reported command fail-closed and fingerprints the observed
platform-default linker. Buildinfo publishes only the resulting zero/one count
and incorporates the digest without disclosing a path.

## Validation

- `bloch-pos-node` passed 535 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 123 tests passed and 6
  performance tests were explicitly ignored.
- The pool passed all 49 library tests; its binary and doctest targets contain
  no tests.
- The scanner-posture guard passed 67 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 54 cases and both
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
