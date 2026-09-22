# Wave 67 INF-11: exact ordered security run steps

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Starting point:
`0a8e268`. Scope: local security-workflow posture parsing and adversarial
fixtures only. No hosted CI, network, release, deployment, protocol, format or
consensus behavior changed.

## Correction

Wave 66 blocked GitHub's explicit PATH/environment state channels, but an
arbitrary extra `run:` step could still overwrite a known script or binary
directly before the approved scanner command. The guard accepted the required
verdict somewhere in the job without binding all setup commands or their
ordering.

Each of the eight required GitHub security jobs now has an exact ordered
`run:` contract. The contract covers pinned tool installers, regression
self-tests, package provisioning and the final verdict; OSV intentionally has
no shell steps because its pinned action is the verdict. Adding an apparently
inert step, deleting setup, moving the verdict before setup, or changing any
command fails closed and requires an explicit guard review.

The extractor also preserves YAML block semantics. Literal `run: |` lines are
joined with newlines, while folded `run: >` lines are joined with spaces. A
change that merges the two clippy self-test commands into one shell command no
longer compares equal merely because the words are the same.

Four new adversarial fixtures add an entrypoint-overwrite step, reorder a
verdict and installer, delete scanner setup, and replace a literal command
block with folded YAML. An earlier permissive `GITHUB_OUTPUT` fixture is now
expected to fail because any extra security run step requires review. Honest
synthetic jobs and the checked-in workflow pass unchanged.

## Residual and status

INF-11 remains `PARTIAL`. Exact commands prove workflow structure, not the
contents of the repository-owned scripts those commands invoke or the runtime
behavior of apt, cargo and the runner host. The separate GitHub tests workflow
still permits its reviewed auxiliary run steps without a whole-job exact
allowlist. Branch protection and actual hosted outcomes remain external; no
hosted evidence was generated or claimed.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 74 fixtures pass
  in both directions.
- `python3 scripts/check-tests-blocking.selftest.py`: all 57 cases pass.
- `python3 scripts/check-scanners-blocking.py`: all eight required jobs in
  each checked-in security pipeline pass.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs cover
  all eight live crates.
- `python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passes.
- `git diff --check`: passes.
