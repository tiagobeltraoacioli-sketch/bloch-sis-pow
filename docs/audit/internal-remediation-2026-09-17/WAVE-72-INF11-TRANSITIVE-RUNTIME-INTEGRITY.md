# Wave 72 — INF-11 transitive local runtime integrity

Date: 2026-09-19  
Starting point: `eef995e`  
Scope: locally resolvable runtime dependencies only; no hosted CI, runner,
ruleset, release, or deployment claim.

## Residual reproduced

Wave 71 pinned the bytes of all scripts named directly by the exact CI command
contracts. Three of those pinned entrypoints execute or load additional local
programs whose bytes were not covered:

- `verify-bootnodes.selftest.sh` copies and executes `verify-bootnodes.sh`;
- the activation rehearsal executes `devnet-particao.sh`, whose embedded
  report is also loaded by `devnet-particao-report.test.py`;
- the lifecycle mutation checker executes `pinned-rust-toolchain.py`.

Replacing any of these helpers with a successful stub did not change a direct
CI command or a Wave 71 digest, so the local posture guard passed.

## Remediation

The entrypoint digest map now includes all three transitive executables. A
separate parent/reference contract records every reviewed load edge and
requires its literal to remain present in the protected parent. The guard now
checks fourteen local executable files in total while continuing to derive the
eleven direct paths from the exact CI jobs.

This deliberately covers concrete local program loading, not arbitrary data
files read by rehearsals. Rust sources, toolchain declarations, and generated
test inputs remain ordinary version-controlled inputs rather than executable
entrypoints in this contract.

## Bidirectional adversarial evidence

The existing honest fixtures and real-file guard prove that the checked-in
fourteen-file graph is accepted. New negative fixtures prove that:

1. replacing `scripts/devnet-particao.sh` with `exit 0` fails its digest;
2. removing the reviewed parent reference to
   `scripts/pinned-rust-toolchain.py` fails the transitive graph contract.

The prior missing-file, direct replacement, and symlink fixtures continue to
exercise the shared fail-closed checks. The test-posture selftest now contains
83 cases including five filesystem-integrity cases.

## Local verification

Run from the repository root:

```text
python3 scripts/check-tests-blocking.selftest.py
python3 scripts/check-scanners-blocking.selftest.py
python3 scripts/check-tests-blocking.py
python3 scripts/check-scanners-blocking.py
python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-72-INF11-TRANSITIVE-RUNTIME-INTEGRITY.md
```

Observed locally:

- test-posture selftest: 83 cases passed;
- scanner-posture selftest: 74 cases passed;
- real test guard: passed, covering eight live crates on both pipelines;
- real scanner guard: passed, with eight required jobs on each pipeline;
- Python compilation and scoped diff check: passed.

## External residuals

The repository cannot locally attest the runner's actual `python3`, `bash`,
`cargo`, `rustup`, `git`, system packages, kernel, or hardware. It also cannot
prove that hosted CI ran, that repository rulesets consume a verdict, or that
release/deployment state matches this checkout. Those require external runner
and hosted-control-plane evidence and are not inferred here.
