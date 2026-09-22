# Wave 55 INF-11: refuse aliased scanner-job values

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`da2eb46`. Scope: scanner-posture parsing and adversarial fixtures only. No
release, deployment, hosted setting, protocol, format or consensus behavior
changed.

## Correction

Wave 54 refused GitLab `extends`/`inherit` and GitHub reusable-workflow jobs,
but a required job could still replace a locally visible `script` or `steps`
value with a YAML alias. GitLab additionally supports `!reference`, which can
copy configuration from another job. The required key remained present while
the guard no longer inspected the commands that supplied its verdict.

The guard now rejects property values beginning with a YAML alias or GitLab
`!reference`, as well as alias/reference list entries, inside every registered
required job. Ordinary action `uses:` entries and shell glob characters later
in a command remain accepted.

Two new negative fixtures cover GitLab `script: !reference [...]` and GitHub
`steps: *scanner-steps`. The honest fixture continues to cover locally visible
step actions.

## Residual and status

INF-11 remains `PARTIAL`. Full YAML parsing, top-level/external configuration,
dynamic or multiline construction of equivalent shell behavior, hosted branch
protection and actual hosted pipeline outcomes remain outside this local text
guard's proof.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 28 fixtures pass.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
