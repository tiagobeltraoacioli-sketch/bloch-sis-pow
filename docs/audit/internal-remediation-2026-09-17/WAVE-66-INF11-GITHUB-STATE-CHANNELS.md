# Wave 66 INF-11: block cross-step executable replacement channels

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`514ed42`. Scope: local scanner/test posture parsing and adversarial fixtures
only. No hosted CI, network, release, deployment, protocol, format or
consensus behavior changed.

## Correction

Wave 65 constrained declared `env`, actions and action inputs, but an ordinary
approved `run:` step could still change later steps. Writing a directory of
fake binaries to `$GITHUB_PATH`, or `BASH_ENV`/other variables to
`$GITHUB_ENV`, preserves the exact literal `cargo test` or scanner command
that the guard checks while making the runner execute different code.

Both guards now inspect only explicit `run:` values in required GitHub jobs
and refuse cross-step execution-state channels:

- `GITHUB_PATH` and `GITHUB_ENV` environment files;
- their `github.path` / `github.env` context forms;
- legacy `add-path` and `set-env` workflow command forms.

`GITHUB_OUTPUT` remains accepted because it transports step outputs rather
than replacing PATH or process environment. Action lifecycle writes remain
bounded by Wave 65's exact action-commit and input allowlists.

Six fixtures prove both directions across both guards: honest
`GITHUB_OUTPUT` writes remain green, while PATH/environment mutations fail
before the unchanged scanner or cargo-test verdict can count as evidence.
The checked-in workflows use none of the rejected channels in protected jobs.

## Residual and status

INF-11 remains `PARTIAL`. This closes the documented GitHub command-file
dataflow, not arbitrary effects of every shell setup command. A reviewed
`run:` step could still mutate a known executable or tracked file directly;
fully proving arbitrary shell side effects would require exact whole-step
allowlisting or isolation rather than textual interpretation. Runner host
integrity, branch protection and actual hosted outcomes remain external. No
hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-tests-blocking.selftest.py`: all 57 cases pass.
- `python3 scripts/check-scanners-blocking.selftest.py`: all 70 fixtures pass
  in both directions.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs cover
  all eight live crates.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in security pipeline pass.
- `python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
