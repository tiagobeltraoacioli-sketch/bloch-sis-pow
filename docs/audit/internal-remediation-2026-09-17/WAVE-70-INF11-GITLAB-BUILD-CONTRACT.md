# Wave 70 — INF-11 GitLab build-and-test whole-job contract

Date: 2026-09-19  
Starting point: `e3fb033`  
Scope: checked-in local CI structure only; no hosted CI, runner, release, or
deployment claim.

## Residual reproduced

The test-posture guard previously proved semantic live-crate coverage and
rejected several known GitLab escape hatches, but it did not bind the complete
`build-and-test` job. The required test literal could remain while another
script item was inserted, setup checks were removed or reordered, the timeout
changed, or an ambiguous second `script:` key replaced the reviewed command
list. The global `default:` and `variables:` blocks were checked only when
present, so deletion or duplicate-key replacement was not fail-closed.

## Remediation

`scripts/check-tests-blocking.py` now requires:

- exactly one reviewed top-level `variables:` block;
- exactly one reviewed top-level `default:` block, including runner tag and
  fail-fast setup;
- the exact `build-and-test` header: `stage: test`, `script:`, and
  `timeout: 120m`, in reviewed order with no extra job context;
- the exact YAML shape and ordered five-command script: bootnode selftest,
  retired/live isolation selftest, isolation guard, workspace build, and the
  locked eight-crate test command.

Comments remain outside the execution contract. Any executable or structural
change now requires an explicit update to the guard and its bidirectional
fixtures. A semantically broader `cargo test --workspace` command is
deliberately not accepted as a silent substitute for the reviewed job.

## Adversarial fixtures

The honest fixture now mirrors the checked-in GitLab job and inherited global
context. New or tightened negative cases cover:

1. insertion of an extra script command;
2. removal of the setup selftest;
3. reordering the isolation selftest and guard;
4. duplicate `script:` keys and a quoted duplicate `build-and-test` key;
5. a block scalar that preserves command text but changes YAML execution
   shape;
6. an aliased job value outside the locally inspectable subset;
7. duplicate inherited `variables:` and missing inherited `default:`;
8. explicit `allow_failure: false` as an unreviewed header insertion;
9. timeout removal and `--workspace` substitution.

Existing waiver fixtures continue to reject truthy `allow_failure`, manual or
conditional execution, disabled failure propagation, and masked commands.

## Local verification

Run from the repository root:

```text
python3 scripts/check-tests-blocking.selftest.py
python3 scripts/check-scanners-blocking.selftest.py
python3 scripts/check-tests-blocking.py
python3 scripts/check-scanners-blocking.py
python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-70-INF11-GITLAB-BUILD-CONTRACT.md
```

Observed locally:

- test-posture selftest: 78 cases passed;
- scanner-posture selftest: 74 cases passed;
- real test guard: passed, covering eight live crates on both pipelines;
- real scanner guard: passed, with eight required jobs on each pipeline;
- Python compilation and scoped diff check: passed.

## Remaining boundary

The guard establishes an exact textual/structural contract for the supported
checked-in YAML subset. It does not establish that GitLab scheduled or ran a
pipeline, that the self-hosted runner or tools are trustworthy, or that branch
protection consumes the verdict. Shell behavior inside the explicitly
reviewed commands remains runtime evidence, not something this parser claims
to prove.
