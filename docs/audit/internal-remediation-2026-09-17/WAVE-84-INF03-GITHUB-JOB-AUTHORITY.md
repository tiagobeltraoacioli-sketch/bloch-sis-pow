# Wave 84 — INF-03/04/11 GitHub job execution authority

Date: 2026-09-19
Comparison base: `ff48c1d`

## Residual addressed

The local meta-guards bound required GitHub commands, actions, token authority,
global shell context and workflow triggers, but did not bind two job-level
fields that decide whether and where those commands execute.

A required job could add `needs: bypass-prerequisite`, where that prerequisite
is deliberately skipped, while retaining every reviewed command as unreachable
decoy text. It could also replace `runs-on: ubuntu-latest` with an arbitrary
self-hosted label, moving the exact commands outside the runner class reviewed
by the checked-in contract. Both mutated workflows passed the corresponding
local guard before this correction.

## Hardening

Every required GitHub test and security job must now:

- contain exactly one plain `runs-on: ubuntu-latest`; and
- contain no plain, quoted or duplicate semantic `needs:` key.

This covers `cargo-test` plus all eight required security jobs. The test guard
retains its exact header/step contract, and both guard jobs retain their exact
reviewed command sequences in addition to the runner/dependency rule.

The rule is intentionally local and narrow. It proves the checked-in workflow
selects the reviewed runner label and does not make required jobs conditional
on dependency status. It does not authenticate a hosted runner, prove GitHub
event delivery, inspect repository rules, or establish that hosted CI ran.
No pipeline command, action, trigger, permission, timeout or runner label was
changed.

## Adversarial coverage

Independent test-workflow fixtures retain the complete reviewed `cargo-test`
body while:

- adding a valid skipped prerequisite and a plain `needs:` dependency; and
- appending a quoted late `runs-on` duplicate selecting attacker-controlled
  self-hosted labels.

Independent security-workflow fixtures retain complete required scanner bodies
while:

- adding the same skipped prerequisite through quoted `needs`; and
- replacing one scanner's runner with self-hosted attacker-controlled labels.

The honest workflow fixtures retain `ubuntu-latest` without dependencies, so
both acceptance and rejection directions remain exercised.

## Validation

```text
python3 -I scripts/check-tests-blocking.selftest.py
# OK — 134 cases behave as documented

python3 -I scripts/check-tests-blocking.py
# OK — supported explicit test commands cover 8 live crates on both pipelines

python3 -I scripts/check-scanners-blocking.selftest.py
# OK — 95 cases, both directions

python3 -I scripts/check-scanners-blocking.py
# OK — 8 GitLab + 8 GitHub jobs are blocking

python3 -I -m py_compile scripts/check-tests-blocking.py \
  scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py \
  scripts/check-scanners-blocking.selftest.py
# passed

git diff --check -- <Wave 84 files>
# passed
```

The final `check-tests-blocking.selftest.py` SHA-256 is
`4af0c083683c8aee1ba218d2f5986104c77f52f0e5ca812cb45062d4a9a9972c` and
the test guard pins that exact digest.

## Residual risk

- `ubuntu-latest` is a provider-managed label, not an immutable image digest or
  runner attestation. Hosted runner/image provenance remains external.
- Branch protection, required-check selection, event delivery and repository
  policy remain outside the local structural proof.
- Workflow concurrency remains a scheduling/availability surface. The current
  per-ref groups do not turn a completed failing verdict green, so this wave
  does not claim a blocking-proof fix for that separate posture.
