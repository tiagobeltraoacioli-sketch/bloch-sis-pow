# Wave 54 INF-11: inherited and delegated scanner jobs

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`db7b737`. Scope: the local scanner-posture guard and its adversarial fixtures.
No release was built, published or deployed, no hosted pipeline was changed,
and no consensus, protocol or activation behavior changed.

## Recovered residual

Wave 49 made the scanner guard fail closed on direct waiver, conditional,
merge-key and shell-success bypasses. Two supported-CI escape shapes remained:

- a required GitLab job could use `extends:` or `inherit:` and obtain its
  effective behavior from configuration the text guard did not inspect; and
- a required GitHub job could replace local `steps` with a job-level `uses:`
  reusable workflow, moving its effective verdict outside the inspected job.

In both cases, the required job key remained present while its actual blocking
semantics were no longer locally evident.

## Local hardening

`scripts/check-scanners-blocking.py` now rejects `extends:` and `inherit:` in
every registered GitLab job. It also rejects job-level `uses:` for registered
GitHub jobs. Step-level actions remain accepted: indentation distinguishes a
normal `steps: - uses: ...` action from reusable-workflow delegation.

Three negative fixtures cover the new refusals. The existing honest GitHub
fixture continues to contain step-level scanner actions, so the positive path
also proves they were not accidentally prohibited.

## Residual and status

INF-11 remains `PARTIAL`. The guard deliberately recognizes a small textual
subset; it is not a complete YAML or shell interpreter. Dynamic or multiline
construction of equivalent shell behavior, external includes, hosted branch
protection and actual hosted pipeline outcomes remain outside its proof.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 26 positive and
  negative fixtures passed.
- `python3 scripts/check-scanners-blocking.py`: eight required GitLab and eight
  required GitHub jobs passed the checked-in posture check.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passed.
- `git diff --check`: passed.
