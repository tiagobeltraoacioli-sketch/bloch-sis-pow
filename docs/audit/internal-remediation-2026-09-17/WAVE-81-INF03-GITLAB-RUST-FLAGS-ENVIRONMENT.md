# Wave 81 — INF-03 GitLab Rust-flags environment boundary

Date: 2026-09-19
Starting point: `7d49f78`
Scope: checked-in GitLab process-selection contract; no hosted-runner,
tool-byte, release, deployment, or artifact claim.

## Residual

The GitHub test and security workflows removed inherited `RUSTFLAGS`,
`CARGO_ENCODED_RUSTFLAGS`, and `CARGO_BUILD_RUSTFLAGS` before every reviewed
`run:` step. GitLab's protected `default.before_script` removed compiler and
wrapper substitutions, but retained those three compiler-flag channels.

An ambient runner value could consequently add target features, linker flags,
code-generation options, lint overrides, or other compiler arguments while the
reviewed Cargo commands and repository bytes remained unchanged. Both local
posture guards accepted that asymmetric environment as their exact contract.

## Remediation

The GitLab inherited setup now unsets, in addition to the already protected
Rust variables:

```text
RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
```

The test-posture and scanner-posture guards require this exact default context.
The change aligns these three selection channels with the existing GitHub
environment-clearing shell without claiming that either runner or compiler is
otherwise attested.

## Adversarial evidence

Both posture selftests contain an independent GitLab fixture which removes
only the three newly protected variables while preserving the runner tag,
closed `PATH`, compiler/wrapper unsets, and version probes. Each guard must
reject that near-match. Their honest GitLab and GitHub fixtures remain green,
so the positive and negative directions are exercised without hosted CI.

The existing test-posture fixture that deletes the complete inherited default
was also updated to the new exact spelling, preventing a stale no-op mutation
from being counted as evidence. The SHA-256 binding for that selftest was
updated only after its final bytes were fixed.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-81-INF03-GITLAB-RUST-FLAGS-ENVIRONMENT.md
```

Observed locally:

- test-posture selftest: all 118 cases passed;
- real test-posture guard: eight live crates remain covered by both pipelines;
- scanner-posture selftest: all 80 cases passed in both directions;
- real scanner-posture guard: eight blocking jobs passed per pipeline;
- Python compilation and scoped diff check: passed.

No Cargo build, long rehearsal, hosted pipeline, deployment, or release was
performed for this environment-contract change.

## Remaining boundary

INF-03 and INF-04 remain partial. The fixed search paths, `HOME`, executable
bytes, dynamic libraries, installed toolchains, host configuration, runner
identity, hosted execution, repository rulesets, artifact provenance,
signatures, rollback and canary evidence remain outside this local proof.
