# Wave 56 INF-11: refuse hidden GitLab pipeline semantics

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`4747cd6`. Scope: local scanner-posture parsing and adversarial fixtures only.
No hosted setting, release, deployment, protocol, format or consensus behavior
changed.

## Correction

The scanner guard validated every registered required job but did not reject
top-level GitLab `include:` or `workflow:` configuration. An include could
move effective configuration outside the checked file, while workflow rules
could prevent the entire pipeline from being created even though every
required job body remained locally unchanged.

The explicit supported subset now refuses both top-level keys in the GitLab
security pipeline. Two negative fixtures prove an external include and
`workflow: rules: when: never` fail for the intended reason. The checked-in
pipeline uses neither feature and remains accepted.

## Residual and status

INF-11 remains `PARTIAL`. The guard still is not a full YAML or shell
interpreter. Dynamic or multiline construction of equivalent shell behavior,
hosted repository/branch-protection configuration and actual hosted pipeline
outcomes remain outside its local proof.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 30 fixtures pass.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
