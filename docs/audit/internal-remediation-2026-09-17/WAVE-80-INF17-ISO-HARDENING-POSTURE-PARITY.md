# Wave 80 — INF-17 installer-ISO hardening posture parity

Date: 2026-09-19
Starting point: `df237f6`
Scope: checked-in structural CI proof; no Nix evaluation, image build, boot,
hosted-runner, branch-protection, release, or deployment claim.

## Residual

GitLab ran the mutation-tested structural installer-ISO hardening guard, but
GitHub did not. The GitLab execution also lived in `iso-hardening-guard`, a job
outside both CI posture checkers' required sets. A pipeline edit could therefore
remove the only structural proof without the repository's meta-guards detecting
that loss, while GitHub had no equivalent verdict.

The structural proof checks that every installer-profile ISO composition
imports `os/installer-hardening.nix`, that the OpenSSH, password and mining
overrides retain `lib.mkForce`, and that the separate Nix evaluation script
continues to name every composed value it must assert. It does not evaluate
Nix itself.

## Remediation

Both exact `tests-blocking-guard` contracts now execute:

```text
python3 -I scripts/check-iso-hardening.selftest.py
python3 -I scripts/check-iso-hardening.py
```

The jobs retain ten-minute timeouts and explicit blocking semantics. GitLab's
existing structural execution remains defense in depth, and its separate
Nix-runner `iso-hardening-eval` job remains the composed-value proof.

The test-posture guard now pins the bytes of the structural checker, its
mutation selftest and `scripts/check-iso-hardening.sh`. It also binds the
selftest's dynamic import of the checker and the checker's reviewed reference
to the Nix evaluation script. These are one-way dependency edges and introduce
no load cycle.

## Bidirectional adversarial fixtures

Four fixtures independently delete the ISO mutation selftest and real verdict
from GitHub and GitLab. Each deletion must fail the affected pipeline's exact
contract. The honest dual-pipeline fixture remains green.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-iso-hardening.selftest.py
python3 -I scripts/check-iso-hardening.py
python3 -I scripts/check-attested-ssh.selftest.py
python3 -I scripts/check-attested-ssh.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-iso-hardening.py scripts/check-iso-hardening.selftest.py
git diff --check -- .github/workflows/tests.yml .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-80-INF17-ISO-HARDENING-POSTURE-PARITY.md
```

Observed locally:

- test-posture selftest: all 116 cases passed;
- real test-posture guard: both pipelines cover all eight live crates and
  match their reviewed exact contracts;
- ISO hardening mutation suite: seven named red shapes and one green control;
- real structural ISO hardening guard: passed;
- attested-SSH mutation suite and verdict: passed;
- activation parser suite: four passed;
- Rust-pin parser/consumer suite: passed;
- scanner-posture selftest/guard: 79 cases and 16 blocking jobs passed;
- Python compilation and scoped diff check: passed.

## Remaining boundary

INF-03, INF-04 and INF-17 remain partial. This closes a checked-in structural
proof and deletion-path divergence. It does not establish the result of Nix
evaluation on this machine, image composition, boot behavior, persist-volume
unlock, hosted execution, runner integrity, branch protection, release
reproducibility, signatures, rollback rehearsal or canary evidence.
