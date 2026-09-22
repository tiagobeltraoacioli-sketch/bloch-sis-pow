# Wave 77 — INF-04 validator-lifecycle test parity

Date: 2026-09-19  
Starting point: `55d0d67`  
Scope: checked-in GitHub/GitLab blocking-test parity; no hosted-runner,
branch-protection, release, or deployment claim.

## Residual reproduced

GitHub's blocking `cargo-test` job ran
`scripts/check-validator-lifecycle-mutations.py`, but GitLab's blocking
`build-and-test` job did not. The ordinary live-crate suite therefore ran in
both pipelines while the dedicated mutation proof for the ADR-041 withdrawal
guards was only required by GitHub. This was a concrete remaining INF-04
pipeline divergence.

## Remediation

GitLab `build-and-test` now runs the same isolated Python mutation checker
after validating the Rust toolchain pins and before building/testing the
workspace. The checker first proves the unmodified lifecycle tests pass, then
requires each of eight mutations to be killed: activation, maturity,
one-shot withdrawal, indeterminate write-off, credential conversion,
arithmetic narrowing, output collision, and write-off overflow.

`scripts/check-tests-blocking.py` binds the added command into GitLab's exact
ordered script and complete YAML body. Its documented contract now explicitly
requires the lifecycle mutation checker in both pipelines. The entrypoint was
already byte-pinned because GitHub executes the same file.

## Bidirectional regression fixtures

The test-posture selftest now removes the shared lifecycle mutation command
from GitHub while leaving GitLab intact, and removes it from GitLab while
leaving GitHub intact. Both mutations must fail their pipeline's exact ordered
contract. The honest fixture includes the new GitLab command and remains
green.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-validator-lifecycle-mutations.py
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-validator-lifecycle-mutations.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-77-INF04-VALIDATOR-LIFECYCLE-PARITY.md
```

Observed locally:

- mutation checker: control passed and all eight withdrawal-guard mutations
  were killed; shipping source remained unchanged;
- test-posture selftest: all 98 cases passed;
- scanner-posture selftest: all 79 cases passed;
- real test guard: both pipelines cover all eight live crates;
- real scanner guard: eight blocking GitLab and eight blocking GitHub jobs;
- toolchain parser adversarial test, Python compilation, and scoped diff check:
  passed.

## Remaining boundary

INF-04 and INF-03 remain partial. This closes one locally demonstrable
blocking-test divergence, but does not prove complete pipeline equivalence,
that either hosted service scheduled and executed these jobs, that the
self-hosted GitLab runner is trustworthy, or that branch protection consumes
their verdicts. Other pipeline-specific jobs and external release evidence
remain outside this change.
