# Wave 78 — INF-04 cross-pipeline proof parity

Date: 2026-09-19
Starting point: `9eebe9d`
Scope: checked-in GitHub/GitLab blocking-test posture; no hosted-runner,
branch-protection, release, or deployment claim.

## Residual reproduced

GitHub's blocking `tests-blocking-guard` ran the partition-report and validator
activation parser regression suites. GitLab's job with the same name stopped
after the test-posture and Rust-pin checks. A GitLab merge could therefore
remove the fail-closed evidence requirements from either operational parser
without that pipeline executing their adversarial suites.

An initially considered parity change was deliberately rejected: adding
`scripts/rehearse-validator-admission.py` to GitLab reproduced the existing
functional failure even outside the sandbox. The isolated rehearsal ran two
funded-admission tests; the invalid-state refusal passed, but
`funded_validator_two_nodes_rehearsal` failed at the deposit assertion. That
known-red command was removed from the proposed change and is not a new
GitLab gate.

## Remediation

GitLab `tests-blocking-guard` now executes:

- `scripts/devnet-particao-report.test.py`, whose 12 tests require complete,
  internally consistent partition evidence and reject missing proof;
- `scripts/rehearse-validator-activation.test.py`, whose four tests require
  the expected activation-gate set and reject changed or missing gates.

The job now has a ten-minute timeout. `scripts/check-tests-blocking.py` binds
the complete GitLab guard job to a plain, unique key and an exact ordered
blocking contract, including `before_script: []` and `allow_failure: false`.
It continues to bind GitHub's corresponding exact job independently.

## Bidirectional regression fixtures

The posture selftest removes the partition-report suite from GitHub while
leaving GitLab intact, then removes it from GitLab while leaving GitHub intact.
It repeats both directions for the activation parser suite. All four mutations
must fail the affected pipeline's exact contract; the honest dual-pipeline
fixture remains green.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/devnet-particao-report.test.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/devnet-particao-report.test.py scripts/rehearse-validator-activation.test.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-78-INF04-CROSS-PIPELINE-PROOF-PARITY.md
```

Observed locally:

- test-posture selftest: all 102 cases passed;
- real test-posture guard: both pipelines cover all eight live crates and the
  two guard jobs match their reviewed contracts;
- partition-report suite: 12 passed;
- activation parser suite: four passed;
- Rust toolchain parser, scanner-posture selftest/guard, Python compilation,
  and scoped diff check: passed.

## Remaining boundary

INF-04 and INF-03 remain partial. This closes a source-level divergence in the
blocking proof jobs. It does not prove hosted execution, runner integrity,
branch protection, complete job equivalence, or any external release gate.
The funded-admission rehearsal remains known-red and was not represented as
passing evidence.
