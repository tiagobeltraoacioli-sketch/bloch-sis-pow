# Wave 80 — INF-04 independent joining-network parity

Date: 2026-09-19
Starting point: `f787b25`
Scope: checked-in GitHub/GitLab blocking-test posture; no hosted-runner,
branch-protection, release, or deployment claim.

## Residual

GitHub's blocking `cargo-test` job executed
`scripts/rehearse-validator-joining-network.py`, while GitLab's blocking
`build-and-test` job did not. The GitLab path therefore lacked GitHub's
independent-process proof of pre-activation refusal, post-activation funded
admission, finalized registration, joining-validator duties, terminal-state
agreement, committed duty logs, and default doppelganger observation.

This was an execution divergence, not a missing byte pin. The test-posture
guard already fixed the joining script's digest because GitHub invoked it and
bound the complete GitHub run-step order. That did not make the GitLab runner
execute the proof.

## Remediation

GitLab `build-and-test` now runs:

```text
python3 -I scripts/rehearse-validator-joining-network.py --output "$CI_PROJECT_DIR/.ci-validator-joining-network"
```

It follows the funded-admission, lifecycle-mutation and finite-activation
proofs and precedes the workspace build and eight-crate test command. The job
retains its 120-minute timeout and has no failure waiver. The rehearsal itself
bounds build and fixture subprocesses to 900 seconds and the two-process
network phase to 600 seconds.

`scripts/check-tests-blocking.py` binds the command into GitLab's exact ordered
script and exact whole-job YAML contract. It also records the joining
rehearsal's dynamic load of `scripts/rehearse-validator-activation.py` as a
reviewed parent/dependency relationship, in addition to both files' existing
content hashes.

## Bidirectional adversarial fixtures

The posture selftest removes the joining-network rehearsal from GitHub while
leaving GitLab intact, then removes it from GitLab while leaving GitHub intact.
Both mutations must fail the affected pipeline's exact ordered contract. The
honest dual-pipeline fixture remains green.

## Evidence and local validation

The independent-process proof was not rerun for this structural CI change.
The repository retains prior passed evidence in
`docs/audit/reproducers/validator-joining-network-protected-2026-09-13.json`,
and the checked-in GitHub job already treated the current rehearsal entrypoint
as blocking. This wave does not claim a new hosted execution result.

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/rehearse-validator-joining-network.py scripts/rehearse-validator-activation.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-80-INF04-JOINING-NETWORK-PARITY.md
```

Observed locally:

- test-posture selftest: all 108 cases passed;
- real test-posture guard: both pipelines cover all eight live crates and
  match their reviewed exact contracts;
- activation parser suite: four passed;
- Rust-pin parser/consumer suite: passed;
- scanner-posture selftest/guard: 79 cases and 16 blocking jobs passed;
- Python compilation and scoped diff check: passed.

## Remaining boundary

INF-03 and INF-04 remain partial. This closes one checked-in executable proof
divergence. It does not establish hosted execution, runner integrity, branch
protection, complete job equivalence, Linux release reproducibility, artifact
signatures, rollback rehearsal, weak-subjectivity freshness, or canary
evidence.
