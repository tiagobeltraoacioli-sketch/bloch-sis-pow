# Wave 62 INF-11: derive the OSV scope from the tracked lockfiles

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`d30afca`. Scope: local scanner-posture parsing, Git-index inspection and
adversarial fixtures only. No network, hosted setting, release, deployment,
protocol, format or consensus behavior changed.

## Correction

Wave 61 required the GitHub OSV action to receive the reviewed configuration
and 14 lockfiles, but that universe was duplicated inside the guard. A newly
tracked standalone `Cargo.lock` could therefore be absent from both the
workflow inputs and the guard's static list while the posture check remained
green.

The guard now derives the canonical lockfile universe from `git ls-files -z`
with exact `Cargo.lock` pathspecs. The OSV action input must equal the derived
set in both directions: every tracked lockfile appears exactly once, and every
`--lockfile=` argument names a tracked file. Empty, duplicate, absolute,
traversing or malformed discovery results fail closed.

The manifest override used by the synthetic tests is hidden and is not an
accepted CI invocation. Both required scanner-guard jobs now match only the
argument-free `python3 scripts/check-scanners-blocking.py` command, so a CI
change cannot substitute fixture input for the real Git index.

Three new negative fixtures add a future tracked lockfile without extending
OSV, retain an OSV argument after its lockfile is no longer tracked, and try to
inject the fixture option into the GitLab guard command. Each fails for its
stated reason. The honest synthetic pipelines and checked-in files pass with
all 14 currently tracked lockfiles.

## Residual and status

INF-11 remains `PARTIAL`. This proves equality against the local checked-out
Git index, not the state of another ref, submodule contents, OSV database
freshness, action runtime behavior, runner state, hosted branch protection or
actual hosted outcomes. Untracked local files intentionally do not define CI
scope. No hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 47 fixtures pass
  in both directions.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in pipeline pass; the index reports 14 tracked lockfiles.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
