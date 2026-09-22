# Wave 81 — INF-04 global execution-key integrity

Date: 2026-09-19
Starting point: `068068e`
Scope: checked-in global CI environment mappings; no hosted CI, runner,
branch-protection, deployment, release, or verdict claim.

## Residual

Both posture guards compared the parsed contents of GitHub's global
`defaults:` shell and optional `env:` mapping with reviewed values. The text
parser recognized only plain keys, however. A later quoted duplicate such as:

```text
"defaults":
  run:
    shell: bash {0} || true
```

or:

```text
'env':
  BASH_ENV: scripts/mask.sh
```

was invisible while the earlier honest block continued to supply the guard's
evidence. A last-key-wins loader could replace the fail-fast shell or inject
startup state into every required `run:` step.

The scanner guard had the corresponding GitLab weakness. It counted only
plain `default:` and `variables:` occurrences, so a quoted duplicate could
replace the reviewed inherited environment while the first block remained
green to the local checker. The test guard already used a quote-aware rule for
those two GitLab keys.

## Remediation

Both posture guards now apply a quote-aware semantic-key check before content
inspection:

- GitHub `defaults:` is required exactly once and in plain form;
- GitHub `env:` is allowed zero or one time, but only in plain form; and
- the scanner guard independently requires GitLab `default:` and `variables:`
  exactly once and in plain form.

The existing exact content comparisons remain authoritative after key
selection. This does not expand the supported YAML language; it makes the
already reviewed subset fail closed when an equivalent quoted key appears.

## Adversarial evidence

Late-duplicate fixtures retain the complete honest context and then append:

- a quoted GitHub test-workflow `defaults` with a failure-masking shell;
- a quoted GitHub test-workflow `env` with `BASH_ENV` injection;
- the same two replacements in the security-workflow fixture; and
- a quoted GitLab `default` with an attacker-selected `PATH` setup.

Each replacement must fail on the protected global key before its hidden
content can be accepted. Honest fixtures with no optional `env`, and with the
reviewed plain `env`, both remain green. The test selftest digest was updated
after its final fixture bytes were fixed.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-81-INF04-GLOBAL-EXECUTION-KEY-INTEGRITY.md
```

Observed locally:

- test-posture selftest: all 123 cases passed;
- real test-posture guard: eight live crates remain covered by both pipelines;
- scanner-posture selftest: all 87 cases passed in both directions;
- real scanner-posture guard: eight required jobs passed per pipeline;
- Python compilation and scoped diff check: passed.

No build, long rehearsal, hosted pipeline, deployment, or release was run.

## Remaining boundary

INF-03 and INF-04 remain partial. This proof covers only the named global
execution-context keys and the guards' supported textual subset. Arbitrary
YAML semantics, hosted workflow creation/execution, pre-shell runner state,
runner identity, required-check settings, tool provenance, artifact signing,
rollback, and canary behavior remain external.
