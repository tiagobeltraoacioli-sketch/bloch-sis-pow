# Wave 59 INF-11: bind required jobs to executable verdicts

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Wave starting
point: `9a0dd11`. Scope: local scanner-posture parsing and adversarial fixtures
only. No hosted setting, release, deployment, protocol, format or consensus
behavior changed.

## Correction

The posture guard proved that each required job name existed and lacked known
failure waivers, but did not prove that the named job still executed the
scanner or guard it represented. Replacing `cargo deny check`, a gitleaks
entrypoint, or another required verdict with `echo ok` left a structurally
blocking job and a green posture guard while performing no check.

Each of the eight required jobs in both pipeline definitions is now bound to
its reviewed executable verdict. Evidence is taken only from explicit GitLab
`script:` items and GitHub step `run:`/`uses:` fields. Job names, step names,
comments, variables and unrelated YAML scalars do not count. Literal and
folded command scalars are supported for the checked-in shapes. A matched
verdict must also be a direct command/action rather than part of a compound
shell expression whose final command can replace the scanner's failing status.

Four new negative fixtures prove that a GitLab command replacement, a GitHub
step-name decoy, an `echo` of the expected command and a compound fail-masking
command are all refused for the intended reason. The honest synthetic files
and both checked-in pipeline definitions pass.

## Residual and status

INF-11 remains `PARTIAL`. This is an intentionally restricted local structural
parser, not a general YAML or shell interpreter. It proves presence and direct
invocation of the registered entrypoints, not the behavior of those scripts,
third-party actions, runner credentials, hosted branch protection or actual
CI outcomes. No hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 38 fixtures pass
  in both directions.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
