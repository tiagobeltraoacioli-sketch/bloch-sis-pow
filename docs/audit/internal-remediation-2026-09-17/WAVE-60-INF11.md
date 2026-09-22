# Wave 60 INF-11: pin the OSV action and the guard's self-test

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`fc96e52`. Scope: local scanner-posture parsing and adversarial fixtures only.
No hosted setting, release, deployment, protocol, format or consensus behavior
changed.

## Correction

Wave 59 bound every required job to an explicit executable verdict, but two
integrity gaps remained in that binding:

1. GitHub's OSV action matcher accepted any suffix after `@`, so replacing the
   reviewed commit with a mutable branch such as `@main` still passed.
2. The `scanners-blocking-guard` job was required to invoke the guard, but not
   its adversarial self-test. Deleting the self-test removed the independent
   local proof that a weakened guard still rejects hostile fixtures.

The GitHub OSV verdict now accepts only the reviewed action path followed by a
full lowercase 40-hex commit identifier. The scanner-guard job in both GitLab
and GitHub must directly execute both
`scripts/check-scanners-blocking.selftest.py` and
`scripts/check-scanners-blocking.py`; names, comments, variables and compound
commands remain ineligible as execution evidence.

Three new negative fixtures replace the OSV commit with `@main` and remove the
self-test independently from each pipeline. Each fails for its stated reason.
The honest synthetic files and both checked-in pipeline definitions pass.

## Residual and status

INF-11 remains `PARTIAL`. The commit pin fixes the action revision locally but
does not independently authenticate its upstream source or prove its runtime
behavior. The self-test proves the checked guard rejects the registered local
fixtures, not arbitrary YAML/shell semantics. Runner credentials, hosted
branch protection and actual CI outcomes remain external; no hosted evidence
was generated or claimed.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 41 fixtures pass
  in both directions.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
