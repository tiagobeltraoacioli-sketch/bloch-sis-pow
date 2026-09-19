# Wave 69 — INF-11 GitHub test-guard execution contract

Date: 2026-09-18  
Starting point: `8e0ebd6`  
Scope: local structural CI evidence only; no hosted-run, branch-protection,
release, or deployment claim.

## Residual reproduced

`check-tests-blocking.py` previously inspected the GitHub `cargo-test` job but
did not inspect the `tests-blocking-guard` job that is supposed to execute the
checker. A workflow could therefore retain the approved checker literal while
removing its selftest, moving checkout after the command, using a mutable
checkout ref, changing the timeout, adding a masking command, or injecting a
step-local `PATH`. The local guard still returned success.

## Remediation

The checker now requires the `tests-blocking-guard` job and binds it to:

- the reviewed name, `ubuntu-latest` runner, ten-minute timeout, and `steps:`
  header;
- one immutable `actions/checkout` invocation with no inputs;
- the exact unified execution order: checkout, checker selftest, checker,
  partition-report test, activation-rehearsal test, attested-SSH selftest, and
  attested-SSH guard;
- one execution field per step and no additional step metadata beyond `name`,
  `uses`, or `run`.

The contract compares parsed execution fields, not comments or step names.
Thus descriptive edits remain possible, while execution-order or context
changes fail closed and require explicit review of the contract.

## Adversarial coverage

The selftest fixture now mirrors the checked-in job. New negative cases prove
that the checker rejects:

1. deletion of `tests-blocking-guard`;
2. removal of its selftest while the guard literal remains;
3. reordering the selftest and guard;
4. moving checkout after a command;
5. replacing the checkout digest with `@v4`;
6. changing the exact timeout;
7. appending an extra command; and
8. adding a step-local environment that replaces `PATH`.

The honest fixture and the checked-in workflow remain accepted.

## Local verification

Run from the repository root:

```text
python3 scripts/check-tests-blocking.selftest.py
python3 scripts/check-scanners-blocking.selftest.py
python3 scripts/check-tests-blocking.py
python3 scripts/check-scanners-blocking.py
python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-69-INF11-TEST-GUARD-CONTRACT.md
```

Observed locally:

- test-blocking selftest: 69 cases passed;
- scanner-blocking selftest: 74 cases passed;
- real test guard: passed, covering eight live crates on both pipelines;
- real scanner guard: passed, with eight required jobs on each pipeline;
- Python compilation and scoped diff check: passed.

## Remaining boundary

This is a parser-enforced contract over the checked-in YAML. It does not prove
GitHub-hosted execution, runner integrity, action implementation, repository
rulesets, or arbitrary shell effects. The GitLab `build-and-test` job remains
structurally checked for blocking live-crate tests and reviewed context, but is
not yet bound to an exact whole-job command list.
