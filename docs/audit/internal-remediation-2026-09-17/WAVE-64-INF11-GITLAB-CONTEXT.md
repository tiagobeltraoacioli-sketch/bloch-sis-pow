# Wave 64 INF-11: constrain inherited GitLab execution context

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`97ceeaf`. Scope: local scanner/test posture parsing and adversarial fixtures
only. No network, hosted setting, release, deployment, protocol, format or
consensus behavior changed.

## Correction

Wave 63 closed verdict-masking custom shells in GitHub. The GitLab guards still
validated required job bodies without binding all inherited execution context.
A top-level or `default.before_script` change such as `set +e`, an injected
`BASH_ENV`/`PATH`, or job-local before/after scripts and hooks could preserve
the approved literal scanner or `cargo test` command while changing which
program ran or whether an earlier failure stopped the job.

Both guards now accept an explicit GitLab subset:

- the checked-in `default:` block must retain the reviewed runner tag and four
  bootstrap commands exactly;
- top-level variables, when present, are limited to the checked-in
  `CARGO_TERM_COLOR` and `RUST_BACKTRACE` values;
- global `before_script`, `after_script` and `hooks` are refused;
- a required job may only opt out with literal `before_script: []`;
- required-job `after_script` and `hooks` are refused;
- required-job variables are refused except for the exact
  `secret-history-scan` depth setting, `GIT_DEPTH: "0"`.

Comments and job names do not supply evidence. Inline comments are removed
before comparison, aliases and structured/inherited alternatives remain
outside the supported subset.

Eleven new fixtures cover the honest inherited context plus hostile default,
global-variable, hook, before-script, after-script and job-variable shapes in
the scanner and test guards. Existing no-default synthetic pipelines remain
valid, and the checked-in GitLab definition passes unchanged.

## Residual and status

INF-11 remains `PARTIAL`. This is a strict structural contract for the current
GitLab subset, not a general YAML or shell interpreter. It does not prove the
contents of invoked scripts, GitLab Runner implementation, host environment,
branch protection or actual hosted outcomes. Context on non-required/reporting
jobs is outside this finding. No hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-tests-blocking.selftest.py`: all 44 cases pass.
- `python3 scripts/check-scanners-blocking.selftest.py`: all 56 fixtures pass
  in both directions.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs cover
  all eight live crates.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in security pipeline pass.
- `python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
