# Wave 65 INF-11: bind executable and action context

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`6e3328d`. Scope: local scanner/test posture parsing and adversarial fixtures
only. No network, hosted setting, release, deployment, protocol, format or
consensus behavior changed.

## Correction

The guards bound literal `run:` commands but still accepted surrounding
contexts able to replace what those commands executed. GitHub `env` could set
`BASH_ENV` or prepend a fake `cargo` through `PATH`; a job container could
supply different tools; an added action could write to `GITHUB_PATH` in its
pre/main/post lifecycle. Even an already reviewed cache action could receive a
new `with:` input that restored tracked entrypoint directories. On GitLab,
cache/dependency/needs artifacts could similarly overwrite scripts before the
unchanged verdict command.

Both guards now enforce the following fail-closed subset:

- optional top-level GitHub `env:` is limited to the checked-in
  `CARGO_TERM_COLOR` and `RUST_BACKTRACE` pair;
- required GitHub jobs and steps may not define `env`, `container` or
  `services` context;
- every action in a required job must match a reviewed path and full 40-hex
  commit;
- reviewed actions accept no inputs by default; the only scanner exceptions
  are exact history-checkout depth, clippy toolchain/components and the sole
  OSV `scan-args` key whose full contents are already verified;
- GitLab global/job image, service and cache context is refused, as are
  required-job artifacts, dependencies and needs.

Structured or aliased `env`/`with` forms do not bypass the restriction.
Comments and step names remain non-evidence.

Twenty-one new fixtures cover honest global GitHub environment plus hostile
global/step environment, container, services, unreviewed and mutable actions,
new inputs on approved actions, and GitLab cache/image/artifact inputs. The
checked-in workflows pass unchanged.

## Residual and status

INF-11 remains `PARTIAL`. Action commit allowlisting establishes local revision
identity, not an independent audit of upstream action code or its runtime.
These parsers do not prove runner host integrity, artifact service behavior,
branch protection or actual hosted outcomes. Non-required/reporting jobs stay
outside this structural contract. No hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-tests-blocking.selftest.py`: all 54 cases pass.
- `python3 scripts/check-scanners-blocking.selftest.py`: all 67 fixtures pass
  in both directions.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs cover
  all eight live crates.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in security pipeline pass.
- `python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
