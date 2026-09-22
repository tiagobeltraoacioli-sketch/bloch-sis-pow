# Wave 79 — INF-04 lifecycle-rehearsal parity

Date: 2026-09-19
Starting point: `6a30397`
Scope: checked-in GitHub/GitLab blocking-test posture; no hosted-runner,
branch-protection, release, or deployment claim.

## Residual reproduced

GitHub's blocking `cargo-test` job executed
`scripts/rehearse-validator-activation.py`, but GitLab's blocking
`build-and-test` job did not. GitLab ran only the parser's four-case adversarial
suite from `tests-blocking-guard`. A GitLab merge could therefore pass without
executing the finite activation boundary, committed-state replay, and unarmed
pre-activation compatibility proof required by GitHub.

The same divergence applied to `scripts/rehearse-validator-admission.py`:
GitHub required its complete funded-validator lifecycle proof while GitLab did
not execute it. The posture checker pinned the script bytes because GitHub
invoked it, but byte coverage did not imply a GitLab execution verdict.

The first attempted qualification exposed stale test expectations rather than
being represented as green. A forged funded deposit and two forged exits now
correctly exhaust their respective per-source verification budgets until the
next slot, and a funding transaction already committed to the chain is
classified as
`Admitted::Duplicate` without returning to the pending pool. Those fixture
corrections landed independently in `0f929c4` and are documented in
[WAVE-79-INF04-ADMISSION-REHEARSAL-RECOVERY.md](WAVE-79-INF04-ADMISSION-REHEARSAL-RECOVERY.md).
This CI change does not modify that source.

## Remediation

GitLab `build-and-test` now runs the same finite activation rehearsal before
its workspace build and eight-crate test command. Its output is isolated under
`$CI_PROJECT_DIR/.ci-validator-activation`. The exact whole-job and ordered
command contracts in `scripts/check-tests-blocking.py` bind the new command,
so deleting, moving, replacing, or wrapping it fails the earlier blocking
posture job.

The same job now runs `scripts/rehearse-validator-admission.py` immediately
after validating the Rust pin and before the mutation and activation proofs.
Its complete green run took approximately 16 minutes locally. The blocking
job retains its existing 120-minute timeout, shared build target and later
workspace build/test coverage; no timeout was weakened or failure waiver
added.

The rehearsal itself creates a disposable source copy, compresses the five
lifecycle gates to epoch four, and proves:

- the pre-boundary transaction remains refused by both admission and
  committed-state validation;
- the boundary transaction is included and replays to the same head and state
  root;
- the unarmed build retains pre-activation compatibility; and
- the shipping activation source remains unchanged.

## Bidirectional adversarial fixtures

The posture selftest independently removes the activation rehearsal from
GitHub while leaving GitLab intact, then removes it from GitLab while leaving
GitHub intact. Both mutations must fail the affected pipeline's exact ordered
contract. It repeats those two directions for the funded-admission rehearsal.
The honest dual-pipeline fixture remains green.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/rehearse-validator-activation.py scripts/rehearse-validator-activation.test.py scripts/pinned-rust-toolchain.py scripts/pinned-rust-toolchain.test.py
python3 -I scripts/rehearse-validator-activation.py --output <new-directory>
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-79-INF04-ACTIVATION-REHEARSAL-PARITY.md
```

Observed locally:

- test-posture selftest: all 106 cases passed;
- real test-posture guard: both pipelines cover all eight live crates and
  match their reviewed exact contracts;
- activation parser suite: four passed;
- finite activation rehearsal: both boundary/replay and unarmed compatibility
  completed, with shipping source unchanged;
- funded-admission rehearsal: the separately recorded complete run passed in
  approximately 16 minutes; it was not redundantly rerun for this CI-only
  change;
- Rust-pin parser/consumer suite: passed;
- scanner-posture selftest/guard: 79 cases and 16 blocking jobs passed;
- Python compilation and scoped diff check: passed.

The complete rehearsal required execution outside the local filesystem/network
sandbox because its isolated node test binds an ephemeral loopback port. No
external service, production host, or deployment target was contacted.

## Remaining boundary

INF-03 and INF-04 remain partial. This closes two executable proof divergences
in the checked-in blocking jobs. It does not establish hosted execution,
runner integrity, branch protection, complete job equivalence, Linux release
reproducibility, artifact signatures, rollback rehearsal, or canary evidence.
