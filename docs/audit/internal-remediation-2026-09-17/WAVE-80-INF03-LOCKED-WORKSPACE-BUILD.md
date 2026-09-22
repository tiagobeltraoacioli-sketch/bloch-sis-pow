# Wave 80 — INF-03 locked GitLab workspace build

Date: 2026-09-19
Starting point: `428864d`
Scope: checked-in GitLab dependency-resolution contract; no hosted-runner,
release, deployment, or artifact claim.

## Residual

GitHub's blocking Cargo commands all used `--locked`, explicitly binding their
verdicts to the committed dependency graph. GitLab's `build-and-test` ended
with a locked eight-crate test command, but first ran:

```text
cargo build --workspace --all-targets
```

If a change modified a workspace manifest without updating `Cargo.lock`, that
first command could resolve dependencies and rewrite the working-tree lockfile.
The later `cargo test --locked` would then accept the already-generated
lockfile rather than proving that the committed lockfile was sufficient. The
pipeline could therefore test a dependency graph absent from the proposed
commit.

## Remediation

The GitLab build command is now:

```text
cargo build --locked --workspace --all-targets
```

This fails before compilation when the committed root lockfile cannot satisfy
the workspace manifests. The existing exact whole-job and ordered-command
contracts were updated to require the locked spelling.

An adversarial fixture removes only `--locked` while retaining the workspace
and all-target coverage. The posture guard must reject that near-match as a
changed execution contract. Existing fixtures continue to reject block-scalar
wrapping and an `exit 0` skip around the now-locked command.

## Local validation

Run from the repository root:

```text
cargo metadata --locked --offline --no-deps --format-version 1
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-iso-hardening.selftest.py
python3 -I scripts/check-iso-hardening.py
python3 -I scripts/check-attested-ssh.selftest.py
python3 -I scripts/check-attested-ssh.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-80-INF03-LOCKED-WORKSPACE-BUILD.md
```

Observed locally:

- locked offline Cargo metadata resolution: passed without changing
  `Cargo.lock`;
- test-posture selftest: all 117 cases passed;
- real test-posture guard: both pipelines cover all eight live crates and
  match their reviewed exact contracts;
- ISO hardening and attested-SSH mutation suites and verdicts: passed;
- activation parser suite: four passed;
- Rust-pin parser/consumer suite: passed;
- scanner-posture selftest/guard: 79 cases and 16 blocking jobs passed;
- Python compilation and scoped diff check: passed.

The full workspace build was not repeated for this single-option contract
change.

## Remaining boundary

INF-03 and INF-04 remain partial. This closes a local dependency-input drift
path but does not establish hosted execution, runner integrity, branch
protection, complete pipeline equivalence, release reproducibility, artifact
signatures, rollback rehearsal or canary evidence.
