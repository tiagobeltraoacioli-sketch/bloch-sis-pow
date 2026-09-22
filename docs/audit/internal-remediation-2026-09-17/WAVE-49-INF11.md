# Wave 49 INF-11: blocking-job posture guard

Date: 2026-09-18. Branch: `codex/audit-network-infra-next`. Starting point:
`1acd578`. Scope: local CI structure, adversarial self-tests and audit evidence.
No release was built, published or deployed, no consensus code or activation
changed, and no hosted pipeline was run or reconfigured outside this tree.

## Recovered finding

The exact source is
`a79c88b:docs/audit/deep-audit-2026-09-16/A10-infra-supply-chain.md`.
INF-11 found that the blocking-posture guards matched only literal lowercase
waivers, missed conditional job execution and direct shell-success masking,
and registered too few of the jobs described as mandatory.

Earlier remediation had already made `check-tests-blocking.py` strict about
its explicit command subset and expanded the scanner guard from the original
five jobs to seven per pipeline. The scanner guard still accepted several
named bypass shapes, however, and did not register the consensus
panic/arithmetic ratchet `clippy-hardened`.

## Local hardening

`scripts/check-scanners-blocking.py` now fails closed for each registered job
when it sees:

- any `allow_failure` or `continue-on-error` value other than the literal
  false forms `false`, `no` or `0`, including expressions, structured values
  and missing values;
- `if`, `rules`, `only`, `except` or YAML merge inheritance;
- a `when` value other than `on_success` or `always`;
- `exit 0`, `set +e`, or direct `|| true`, `| true` and `; true` masking; or
- a missing required job.

Both the GitLab and GitHub required sets now include `clippy-hardened`, bringing
each registered set to eight jobs. The GitLab job's standalone
`rustup component add clippy || true` setup was removed: the called
`hardened-clippy.sh` already resolves the pinned toolchain, attempts its
installation, verifies `cargo clippy`, and exits nonzero if it is unavailable.
The informational `clippy` job and its explicitly nonblocking posture are
unchanged.

The self-test now exercises 23 cases in both directions. New adversarial cases
cover `True`, `${{ true }}`, an `exit_codes` mapping, `rules: when: never`,
GitHub `if: false`, YAML merge inheritance, all three direct success-mask forms,
`set +e`, and deletion of the newly registered clippy job. The honest
pipelines and their intentionally report-only job remain accepted.

## Residual and status

INF-11 remains `PARTIAL`. This is a deliberately small structural parser, not
a general YAML or shell interpreter. It does not prove external includes,
multiline construction of equivalent shell escapes, workflow call semantics,
hosted branch protection, or actual pipeline outcomes. Expanding the accepted
language without an AST parser would turn explicit refusal into false
assurance. The implemented subset now rejects the concrete bypasses from the
finding and accurately states its boundary.

## Validation

- `python3 scripts/check-scanners-blocking.selftest.py`: all 23 positive and
  negative fixtures passed.
- `python3 scripts/check-scanners-blocking.py`: the checked-in CI files passed;
  eight GitLab and eight GitHub jobs are registered as blocking.
- `python3 scripts/check-tests-blocking.selftest.py`: the adjacent test-posture
  guard's fixtures passed.
- `python3 scripts/check-tests-blocking.py`: both checked-in test jobs passed.
- `python3 -m py_compile scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py`:
  passed.
- `git diff --check`: passed.
