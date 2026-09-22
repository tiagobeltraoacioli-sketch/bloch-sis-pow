# Wave 82 — INF-03 workflow authority-key integrity

Date: 2026-09-19
Starting point: `49b9390`
Scope: checked-in GitHub workflow creation and token-authority mappings; no
hosted execution, ruleset, runner, deployment, release, or verdict claim.

## Reproduced bypass

The security-posture guard already required the security workflow to retain
`push` and `pull_request`, reject `pull_request_target`, and keep the token
read-only. The test-posture guard did not check those global properties at all.
Removing `pull_request:` from `tests.yml` or changing `contents: read` to
`contents: write` left every job-body contract green while changing when the
required tests run or what their token may do.

The security guard also selected `on:` and `permissions:` only through its
plain-key parser. A later quoted duplicate, semantically the same YAML key,
could remain invisible while an earlier honest block supplied evidence:

```text
"on":
  workflow_dispatch:

'permissions':
  contents: write
```

A last-key-wins loader could therefore disable automatic security checks or
replace the reviewed read-only token posture.

## Remediation

The test-posture guard now requires the GitHub tests workflow to:

- contain one plain top-level `on:` mapping;
- retain both `push:` and `pull_request:` triggers;
- reject `pull_request_target:`;
- contain one plain top-level `permissions:` mapping; and
- make that mapping exactly `contents: read`.

The scanner-posture guard keeps its existing trigger and permission content
checks and now additionally requires their top-level keys to occur exactly
once in plain form. The test guard applies the same key-integrity rule.

## Adversarial evidence

Five test-workflow fixtures independently remove the pull-request trigger,
add the privileged target trigger, grant write permission, append a quoted
late `on` replacement, and append a quoted late `permissions` replacement.

Two security-workflow fixtures append the same quoted late replacements while
retaining the complete honest workflow as decoy evidence. All mutations fail
by their intended trigger, authority, or protected-key diagnostic. The honest
fixtures remain green. The SHA-256 binding for the test-posture selftest was
updated after its final bytes were fixed.

## Local validation

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-82-INF03-WORKFLOW-AUTHORITY-KEY-INTEGRITY.md
```

Observed locally:

- test-posture selftest: all 128 cases passed;
- real test-posture guard: eight live crates remain covered by both pipelines;
- scanner-posture selftest: all 89 cases passed in both directions;
- real scanner-posture guard: eight required jobs passed per pipeline;
- Python compilation and scoped diff check: passed.

No build, long rehearsal, hosted pipeline, deployment, or release was run.

## Remaining boundary

INF-03 and INF-04 remain partial. These checks bind only the checked-in
workflow mapping subset. Hosted workflow creation/execution, repository and
organization policy, required-check configuration, runner identity, token
issuance, action/tool provenance, artifact signing, rollback, and canary
behavior remain external.
