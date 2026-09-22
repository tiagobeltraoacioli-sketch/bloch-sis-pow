# Wave 81 — INF-03 required test job-key integrity

Date: 2026-09-19
Starting point: `13a3bd2`
Scope: checked-in GitHub/GitLab required test-job selection; no hosted CI,
runner, branch-protection, deployment, release, or test-result claim.

## Residual

The test-posture checker already required GitLab's `build-and-test` and
`tests-blocking-guard` keys to occur once in a supported plain form. The two
required GitHub jobs, `cargo-test` and `tests-blocking-guard`, were instead
selected only from the checker's plain-key text parser.

A quoted mapping key has the same YAML scalar value as its unquoted spelling.
A second, later job such as:

```text
  "cargo-test":
    continue-on-error: true
```

was invisible to the local parser while the earlier honest plain block still
supplied all expected evidence. Depending on loader policy, the CI definition
could reject the duplicate or let the later value replace the reviewed job.
Neither is the single blocking mapping certified by the guard.

## Remediation

A common protected-job-key check now requires one unquoted semantic occurrence
for each reviewed GitHub test job before inspecting its body. It is applied to:

- `cargo-test`, which owns the live-crate tests and rehearsals; and
- `tests-blocking-guard`, which runs the guard and its auxiliary proofs.

Missing jobs retain their explicit missing-gate diagnostic in addition to the
key-integrity failure. GitLab's existing plain-and-unique enforcement remains
unchanged.

## Adversarial evidence

Three late-duplicate fixtures retain each complete honest job and append a
quoted replacement afterward:

- GitHub `cargo-test` becomes failure-waived and runs only an echo;
- GitHub `tests-blocking-guard` becomes failure-waived and runs only an echo;
- GitLab `tests-blocking-guard` becomes failure-waived and runs only an echo,
  exercising the previously implemented symmetric rule.

Each must fail specifically on protected job-key selection. Appending the
duplicates after the honest blocks deliberately models last-key-wins loaders,
not merely an ambiguous ordering. The exact honest dual-pipeline fixture stays
green.

The selftest content digest was updated after the final fixture bytes were
fixed, preserving the existing entrypoint-integrity chain.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-81-INF03-REQUIRED-TEST-JOB-KEY-INTEGRITY.md
```

Observed locally:

- test-posture selftest: all 121 cases passed;
- real test-posture guard: eight live crates remain covered by both pipelines;
- scanner-posture selftest: all 84 cases passed in both directions;
- real scanner-posture guard: eight required jobs passed per pipeline;
- Python compilation and scoped diff check: passed.

No build, long rehearsal, hosted pipeline, deployment, or release was run.

## Remaining boundary

INF-03 and INF-04 remain partial. This proves only the guarded plain-key YAML
subset. Arbitrary YAML evaluation, hosted workflow creation/execution, runner
identity, required-check settings, tool provenance, artifact signing,
rollback, and canary behavior remain outside the local evidence.
