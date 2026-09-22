# Wave 81 — INF-04 GitLab required-job environment inheritance

Date: 2026-09-19
Starting point: `c48df20`
Scope: checked-in execution context for required security jobs; no hosted CI,
runner-integrity, deployment, release, or scanner-result claim.

## Residual

GitHub's required security jobs all execute through the exact global
environment-clearing shell protected by the scanner-posture guard. Five
required GitLab jobs instead contained:

```text
before_script: []
```

That job-local override disabled the reviewed `default.before_script` for the
scanner posture guard itself, rollback-package integrity, OSV scanning, and
the tree and history secret scans. Those jobs therefore retained the runner's
ambient `PATH` and shell/Python/Rust selection variables even though other
required GitLab jobs inherited the protected context.

The scanner guard allowed an empty override and treated the entire GitLab
`default:` and `variables:` context as optional. Its synthetic honest fixture
therefore passed without either global block. The real test-posture guard
provided defense in depth for the checked-in file, but the scanner guard did
not independently prove the execution boundary of the jobs it claimed to
protect.

## Remediation

The five `before_script: []` overrides were removed. All eight required GitLab
security jobs now inherit the reviewed runner tag, variable clearing, closed
`PATH`, and fail-fast version-probe setup.

The scanner-posture guard now:

1. requires exactly one reviewed top-level `default:` block;
2. requires exactly one reviewed top-level `variables:` block; and
3. rejects every job-local `before_script`, including the empty form that
   disables inheritance.

GitHub's existing exact global shell and rejection of job-local shell/default
overrides remain unchanged.

## Adversarial evidence

The scanner selftest's honest GitLab fixture now includes the required global
context. Two new independent mutations prove that the guard rejects:

- `before_script: []` on `scanners-blocking-guard`; and
- complete removal of the reviewed GitLab global context.

The pre-existing nonempty `before_script` mutation continues to prove that a
required job cannot replace the inherited setup with attacker-controlled
commands. Existing flag-, path-, and global-variable mutations were rebased on
the honest complete fixture rather than relying on an optional context.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check -- .gitlab-ci.yml scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-81-INF04-GITLAB-REQUIRED-JOB-ENVIRONMENT.md
```

Observed locally:

- scanner-posture selftest: all 82 cases passed in both directions;
- real scanner-posture guard: eight blocking jobs passed per pipeline;
- test-posture selftest: all 118 cases passed;
- real test-posture guard: eight live crates remain covered by both pipelines;
- Python compilation and scoped diff check: passed.

No build, long rehearsal, hosted pipeline, deployment, or release was run.

## Remaining boundary

INF-03 and INF-04 remain partial. Inheritance constrains the checked-in command
environment after the GitLab shell starts; it does not attest pre-shell runner
startup, `$HOME`, executable bytes, installed scanners/toolchains, dynamic
libraries, runner identity, hosted execution, required-check settings,
artifact provenance, signatures, rollback execution, or canary behavior.
