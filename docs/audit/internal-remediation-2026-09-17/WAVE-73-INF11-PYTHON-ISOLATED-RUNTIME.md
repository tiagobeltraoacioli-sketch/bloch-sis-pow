# Wave 73 — INF-11 isolated Python invocation semantics

Date: 2026-09-19  
Starting point: `42eeab0`  
Scope: in-repository invocation semantics; no hosted CI, runner identity,
ruleset, release, or deployment claim.

## Residual reproduced

The fourteen direct/transitive local entrypoints had reviewed content, but CI
invoked Python as plain `python3`. Before a protected script runs, normal
Python startup can consume `PYTHONHOME`, `PYTHONPATH`, and user-site packages.
That leaves module resolution partially controlled by runner environment even
when the entrypoint bytes and YAML command text are pinned.

## Remediation

All Python commands in the exact GitHub `cargo-test`, GitHub
`tests-blocking-guard`, and GitLab `build-and-test` contracts now use
`python3 -I`. The GitLab job that executes the test guard uses the same form.
Python isolated mode ignores Python-specific environment configuration and
user-site injection before importing the protected program.

The isolation boundary is propagated through locally controlled nested Python
execution:

- the test selftest invokes the checker with `sys.executable -I`;
- lifecycle mutation invokes `pinned-rust-toolchain.py` with `-I`;
- `devnet-particao.sh` uses `python3 -I -` for its embedded report;
- its report test uses isolated `-c` execution;
- `verify-bootnodes.sh` uses isolated `-c` execution for JSON validation.

The checker and its selftest both inspect `sys.flags.isolated` and fail before
normal work if their own invocation omitted `-I`. Exact command contracts
reject removing the flag from any reviewed CI step. Digests were updated for
the protected transitive files whose invocation semantics changed.

## Bidirectional adversarial evidence

The checked-in GitHub and GitLab fixtures using `-I`, plus the real workflow
files, are the positive direction. New negative cases prove that:

1. dropping `-I` from a GitHub rehearsal command fails the exact ordered job
   contract;
2. dropping `-I` from a GitLab isolation command fails the exact whole-job
   contract;
3. directly invoking the checker without isolated mode returns a named
   failure even when both CI fixtures are otherwise honest.

The test-posture selftest now reports 86 cases, including six filesystem and
invocation-integrity cases beyond the YAML table.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 scripts/check-scanners-blocking.py
python3 -I scripts/devnet-particao-report.test.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/check-attested-ssh.selftest.py
bash deploy/bootnodes/verify-bootnodes.selftest.sh
python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- .gitlab-ci.yml .github/workflows/tests.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-validator-lifecycle-mutations.py scripts/devnet-particao.sh scripts/devnet-particao-report.test.py deploy/bootnodes/verify-bootnodes.sh docs/audit/internal-remediation-2026-09-17/WAVE-73-INF11-PYTHON-ISOLATED-RUNTIME.md
```

Observed locally:

- test-posture selftest: 86 cases passed;
- scanner-posture selftest: 74 cases passed;
- real test and scanner guards: passed;
- partition-report tests: 12 passed;
- activation-rewrite tests: 4 passed;
- attested-SSH selftest: 6 negative and 1 positive shape passed;
- bootnode verifier selftest: passed;
- Python compilation and scoped diff check: passed.

## External residuals

`-I` constrains Python startup semantics; it does not identify or attest the
`python3` executable itself. The actual Python, Bash, Cargo, Rustup, Git,
package-manager and system binaries remain runner-controlled. Kernel,
hardware, hosted-run evidence, repository rulesets, release state and deploy
state likewise require external evidence and are not inferred here.
