# Wave 57 INF-11: pin security-workflow trigger posture

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`ab06afc`. Scope: local scanner-posture parsing and adversarial fixtures only.
No hosted setting, release, deployment, protocol, format or consensus behavior
changed.

## Correction

The guard proved that required GitHub jobs were locally blocking but did not
prove that the security workflow still ran for both pushes and pull requests.
A change could remove `pull_request:` while leaving every registered job body
unchanged. Substituting `pull_request_target:` would additionally run in the
base repository's privileged context rather than the ordinary PR context.

The supported subset now requires an explicit mapping-form top-level `on:`
block containing both `push:` and `pull_request:` and refuses
`pull_request_target:`. Two adversarial fixtures prove trigger removal and the
privileged substitution fail for their stated reasons. The checked-in workflow
continues to pass.

## Residual and status

INF-11 remains `PARTIAL`. Hosted branch-protection required-check selection,
repository Actions permissions, runner state and actual pipeline outcomes
remain external. The guard is deliberately not a full YAML or shell
interpreter.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 32 fixtures pass.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
