# Wave 58 INF-11: pin read-only scanner token posture

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`0c78e38`. Scope: local scanner-posture parsing and adversarial fixtures only.
No hosted setting, release, deployment, protocol, format or consensus behavior
changed.

## Correction

The GitHub security workflow currently gives its token only `contents: read`,
but the posture guard did not protect that boundary. Removing the top-level
block or adding a write-capable job override left every required job locally
present and blocking while increasing the authority of code those jobs run.

The guard now requires an explicit mapping-form top-level `permissions:` block
with `contents: read`. Every parsed scope must be `read` or `none`; write and
unsupported values fail closed. Required scanner jobs may not carry their own
`permissions:` override and must inherit the checked top-level posture.

Two negative fixtures cover a write-capable top-level token and a job-level
override. The honest fixture and checked-in workflow retain read-only access.

## Residual and status

INF-11 remains `PARTIAL`. Repository and organization defaults, runner
credentials, action behavior, branch protection and actual hosted outcomes are
external to this local structural proof. The guard is not a complete YAML or
shell interpreter.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 34 fixtures pass.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
