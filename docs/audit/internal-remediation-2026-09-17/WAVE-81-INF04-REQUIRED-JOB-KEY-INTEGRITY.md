# Wave 81 — INF-04 required CI job-key integrity

Date: 2026-09-19
Starting point: `28e8735`
Scope: checked-in GitHub/GitLab required security-job mappings; no hosted CI,
runner, branch-protection, deployment, release, or scanner-result claim.

## Residual

The scanner-posture guard located required jobs only through a text parser that
accepted plain YAML keys. It then reviewed the first plain block stored under
each expected name. YAML permits quoted mapping keys with the same scalar
value, so either pipeline could also contain, for example:

```text
"scanners-blocking-guard":
```

or:

```text
  "cargo-deny":
```

beside the honest plain-key job. The guard ignored the quoted duplicate and
continued to approve the honest block. A CI YAML loader could instead reject
the duplicate or select a different mapping value; neither outcome is the
single locally reviewed blocking job claimed by the guard.

The test-posture checker already applied this plain-and-unique rule to its
protected GitLab job keys. The security checker did not apply it to any of its
eight required jobs in either pipeline.

## Remediation

For every required GitLab and GitHub security job, the scanner guard now scans
the source at the correct job-key indentation and requires:

1. exactly one semantic occurrence of the expected key;
2. the occurrence to use the supported unquoted form; and
3. the corresponding locally parsed block to remain present.

This check runs before verdict-command inspection. A quoted-only key, quoted
duplicate, or repeated plain key cannot leave an older honest block as decoy
evidence.

## Bidirectional adversarial evidence

Two independent fixtures add an otherwise hidden duplicate while retaining the
complete honest pipeline:

- GitLab gains a quoted `scanners-blocking-guard` replacement with a waived,
  non-verdict body;
- GitHub gains a quoted `cargo-deny` replacement with `continue-on-error` and
  no deny verdict.

Both must fail specifically on protected job-key integrity. The unchanged
honest GitHub and GitLab fixtures remain green. The existing missing-job,
alias, reusable-workflow, and failure-waiver fixtures continue to exercise
their separate boundaries.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check -- scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-81-INF04-REQUIRED-JOB-KEY-INTEGRITY.md
```

Observed locally:

- scanner-posture selftest: all 84 cases passed in both directions;
- real scanner-posture guard: eight required jobs passed per pipeline;
- test-posture selftest: all 118 cases passed;
- real test-posture guard: eight live crates remain covered by both pipelines;
- Python compilation and scoped diff check: passed.

No build, long rehearsal, hosted pipeline, deployment, or release was run.

## Remaining boundary

INF-03 and INF-04 remain partial. This establishes a deliberately narrow
plain-key subset for required jobs. It does not prove arbitrary YAML semantics,
hosted workflow creation or execution, runner identity, required-check
settings, scanner/tool provenance, artifact signing, rollback, or canary
behavior.
