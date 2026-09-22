# Wave 63 INF-11: refuse custom shells around blocking verdicts

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`cef4b8e`. Scope: local scanner/test posture parsing and adversarial fixtures
only. No network, hosted setting, release, deployment, protocol, format or
consensus behavior changed.

## Correction

Both posture guards validated the literal `run:` command and rejected
`continue-on-error`, compound commands and known shell escapes. They did not
validate how GitHub executed that `run:` scalar. A step-level `shell:`, a
job-level `defaults.run.shell`, or a workflow-level `defaults.run.shell` could
retain the exact approved `cargo test` or scanner command while wrapping the
temporary script as `bash {0} || true`. The command parser still saw the real
verdict, but GitHub received a successful status after it failed.

The test and scanner guards now refuse top-level `defaults:` in their checked
GitHub workflows and refuse `defaults:` or `shell:` anywhere inside a required
job. This intentionally keeps the accepted execution subset on the runner's
standard fail-fast shell instead of attempting to classify arbitrary custom
shell templates.

Five negative fixtures cover a custom shell on a scanner step, workflow-level
scanner defaults, a custom shell on the cargo-test step, job-level test
defaults and workflow-level test defaults. Existing honest fixtures prove the
unchanged standard-shell shapes remain accepted.

## Residual and status

INF-11 remains `PARTIAL`. This correction closes the checked GitHub custom
shell/default scopes. It does not interpret arbitrary shell behavior, runner
configuration or every GitLab inherited/default command context. Hosted
branch protection, runner state and actual pipeline outcomes remain external;
no hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-tests-blocking.selftest.py`: all 40 cases pass.
- `python3 scripts/check-scanners-blocking.selftest.py`: all 49 fixtures pass
  in both directions.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs cover
  all eight live crates.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in security pipeline pass.
- `python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
