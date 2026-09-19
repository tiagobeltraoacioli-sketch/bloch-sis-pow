# Wave 74 — INF-11 Rust toolchain invocation contract

Date: 2026-09-19  
Starting point: `76e6cfb`  
Scope: checked-in Rust channel selection semantics; no runner binary, hosted
CI, ruleset, release, or deployment attestation.

## Residual reproduced

The GitHub test job extracted a channel with `sed` from only
`crates/bloch-pos-node/rust-toolchain.toml`. It did not validate the matching
root-workspace pin that controls root Cargo commands. The GitLab
`build-and-test` job invoked Cargo from the repository root, so Rustup would
normally discover the root pin, but the blocking contract did not execute the
existing validator for the two files before build/test.

A drift between the two toolchain files could therefore select different
compilers across commands while the test-posture guard remained green.

## Remediation

The GitHub setup now obtains its channel from:

```text
python3 -I scripts/pinned-rust-toolchain.py
```

The protected helper accepts only one simple channel assignment per file and
requires the root and node pins to agree. GitHub passes that validated value to
the existing exact `rustup toolchain install` command and then to every Cargo
test as `+${{ steps.pin.outputs.toolchain }}`.

GitLab now executes the same helper immediately before root-workspace Cargo
build/test. Root Cargo is controlled by the validated root
`rust-toolchain.toml`; a missing, malformed, or divergent pin makes the helper
fail before compilation.

The GitHub and GitLab test-guard jobs now execute
`pinned-rust-toolchain.test.py`. That test invokes the helper in Python
isolated mode and covers agreeing pins, disagreement, missing channel,
duplicate channel and shell-like invalid channel input. The test itself is a
new SHA-256-protected CI entrypoint, bringing the protected set to fifteen.

## Bidirectional adversarial evidence

The checked-in dual pins, helper selftest and real CI files are the positive
direction. New test-posture cases prove that the guard rejects:

1. regression of the GitHub setup to single-file `sed` parsing;
2. removal of the toolchain parser selftest while the guard remains;
3. removal of GitLab's pin validation while Cargo commands remain unchanged.

The test-posture selftest now reports 89 cases. The dedicated toolchain test
also runs independently as part of local verification.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 scripts/check-scanners-blocking.py
python3 -I scripts/pinned-rust-toolchain.test.py
python3 -I scripts/devnet-particao-report.test.py
python3 -I scripts/rehearse-validator-activation.test.py
python3 -I scripts/check-attested-ssh.selftest.py
bash deploy/bootnodes/verify-bootnodes.selftest.sh
python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/pinned-rust-toolchain.py scripts/pinned-rust-toolchain.test.py
git diff --check -- .gitlab-ci.yml .github/workflows/tests.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/pinned-rust-toolchain.test.py docs/audit/internal-remediation-2026-09-17/WAVE-74-INF11-RUST-TOOLCHAIN-CONTRACT.md
```

Observed locally:

- test-posture selftest: 89 cases passed;
- scanner-posture selftest: 74 cases passed;
- real test and scanner guards: passed;
- toolchain parser/consumer selftest: all adversarial cases passed;
- partition-report tests: 12 passed;
- activation-rewrite tests: 4 passed;
- attested-SSH selftest: 6 negative and 1 positive shape passed;
- bootnode verifier selftest: passed;
- Python compilation and scoped diff check: passed.

## External residuals

The contract proves which Rust channel is requested; it does not attest the
bytes or provenance of `rustup`, `cargo`, `rustc`, Bash, Python, Git, system
packages, kernel, hardware, or runner image. Hosted-run evidence, repository
rulesets, release state and deployment state remain external.
