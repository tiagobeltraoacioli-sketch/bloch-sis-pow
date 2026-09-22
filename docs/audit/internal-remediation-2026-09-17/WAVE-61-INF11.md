# Wave 61 INF-11: bind OSV action inputs to the reviewed scan scope

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`8bf7bfc`. Scope: local scanner-posture parsing and adversarial fixtures only.
No hosted setting, release, deployment, protocol, format or consensus behavior
changed.

## Correction

Wave 60 pinned the GitHub OSV action to a full commit, but the posture guard
only proved that the action was invoked. Its `scan-args` remained unchecked.
Replacing the input with `--help`, deleting a standalone workspace lockfile,
or moving the expected text into a decoy step preserved the pinned action and
blocking job while no longer executing the reviewed advisory scan.

The guard now parses the explicit `with:` mapping from the same GitHub step as
the pinned OSV action. `scan-args` must contain exactly the reviewed
`osv-scanner.toml` configuration plus all 14 tracked lockfiles currently in
scope. Argument order may change, but missing, duplicated or additional
arguments fail closed. Values in job names, other steps, comments, environment
variables or unrelated mappings do not count.

Three new negative fixtures replace scanning with `--help`, remove
`pool/Cargo.lock`, and move the missing configuration string to another step.
Each fails for the intended scope reason. The honest synthetic pipelines and
both checked-in pipeline definitions pass.

## Residual and status

INF-11 remains `PARTIAL`. The lockfile registry is intentionally explicit and
must be changed together with the workflow when a tracked workspace is added;
the independent cargo-audit wrapper remains the local guard against an unknown
new tracked lockfile. This parser proves the checked action inputs, not OSV's
runtime behavior, database freshness, runner state, hosted branch protection
or actual CI outcomes. No hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 44 fixtures pass
  in both directions.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
