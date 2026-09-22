# Wave 80 — INF-04 attested-SSH posture parity

Date: 2026-09-19
Starting point: `f3aaae0`
Scope: checked-in blocking-test posture; no hosted-runner, image-build,
branch-protection, release, or deployment claim.

## Residual

Both pipeline definitions executed the mutation-tested attested-image SSH
guard, but only GitHub bound both commands into the exact test-posture
contract. GitHub's `tests-blocking-guard` required the mutation selftest and
real verdict. GitLab ran them only from `iso-hardening-guard`, a job outside
both posture checkers' required job sets. Removing that GitLab job could
therefore remove the remote-access proof without either posture guard
detecting the loss.

This is narrower than a missing implementation or absent pipeline command:
the source guard remained green and the commands existed on both sides. The
residual was that deletion from the GitLab pipeline was not fail-closed under
the repository's meta-guards.

## Remediation

GitLab `tests-blocking-guard` now executes, in reviewed order:

```text
python3 -I scripts/check-attested-ssh.selftest.py
python3 -I scripts/check-attested-ssh.py
```

The job retains its empty `before_script`, ten-minute timeout and explicit
`allow_failure: false`. `scripts/check-tests-blocking.py` binds both commands
into the exact GitLab guard-job contract. The existing execution in
`iso-hardening-guard` remains defense in depth; deleting it no longer removes
the only GitLab verdict.

## Bidirectional adversarial fixtures

Four fixtures independently delete:

- the SSH mutation selftest from GitHub;
- the SSH mutation selftest from GitLab;
- the real SSH guard from GitHub; and
- the real SSH guard from GitLab.

Each mutation must fail the affected exact contract, while the honest
dual-pipeline fixture remains green.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-attested-ssh.selftest.py
python3 -I scripts/check-attested-ssh.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-attested-ssh.py scripts/check-attested-ssh.selftest.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-80-INF04-ATTESTED-SSH-POSTURE-PARITY.md
```

Observed locally:

- test-posture selftest: all 112 cases passed;
- real test-posture guard: both pipelines cover all eight live crates and
  match their reviewed exact contracts;
- attested-SSH mutation suite: six named red shapes and one green control;
- real attested-SSH guard: passed;
- activation parser suite: four passed;
- Rust-pin parser/consumer suite: passed;
- scanner-posture selftest/guard: 79 cases and 16 blocking jobs passed;
- Python compilation and scoped diff check: passed.

## Remaining boundary

INF-03, INF-04 and INF-17 remain partial. This closes a checked-in
meta-guard deletion path. It does not prove Nix composition, image boot,
persist-volume unlock, hosted execution, runner integrity, branch protection,
release reproducibility, signatures, rollback rehearsal or canary evidence.
