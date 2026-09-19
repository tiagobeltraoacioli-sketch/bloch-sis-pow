#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove `check-tests-blocking.py` fires on every regression shape and stays quiet otherwise.

The defect this guard was written for (finding TEST1-ci-runs-tests) was a
pipeline that looked complete and tested nothing: GitHub ran zero tests,
GitLab's test job was permanently red so its verdict meant nothing. An
unexercised guard would repeat that one level up, so this builds synthetic CI
files in a temporary directory — never the real tree — and asserts BOTH
directions:

  * every regression shape is caught, BY NAME: the tests workflow deleted, the
    job deleted, `cargo test` removed while the job stays, one live crate
    silently dropped, the timeout removed, and each escape hatch
    (allow_failure, continue-on-error, exit 0, when: manual);
  * the honest exact GitLab/GitHub contracts stay green, including a comment
    that merely mentions `allow_failure` next to a gated job.
  * missing, replaced, or symlinked local script entrypoints fail their byte
    integrity contract, including a transitively executed helper, while the
    checked-in entrypoints stay green.
  * dropping Python isolated mode from either pipeline, or invoking the guard
    itself without `-I`, fails closed.

Run: python3 -I scripts/check-tests-blocking.selftest.py
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-tests-blocking.py")

CRATE_ARGS = (
    "    - cargo test --locked -p bloch-pos-committee -p bloch-pos-node"
    " -p bloch-crypto -p coherence-core -p bloch-sis-pow -p bloch-pq-vault"
    " -p pqcrypto-internals -p genesis4-ceremony\n"
)
SAFE_GITLAB_GLOBALS = """\
variables:
  CARGO_TERM_COLOR: "always"
  RUST_BACKTRACE: "1"

default:
  tags:
    - bloch-linux-aarch64
  before_script:
    - unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
    - export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
    - rustc --version && cargo --version
    - clang --version | head -1 || true
    - cmake --version | head -1 || true

"""

GOOD_GITLAB = """\
stages:
  - test

""" + SAFE_GITLAB_GLOBALS + """\

# a comment mentioning allow_failure: true must not fail the guard
build-and-test:
  stage: test
  script:
    - bash deploy/bootnodes/verify-bootnodes.selftest.sh
    - python3 -I scripts/check-live-node-retired-isolation.py --selftest
    - python3 -I scripts/check-live-node-retired-isolation.py
    - python3 -I scripts/pinned-rust-toolchain.py
    - python3 -I scripts/rehearse-validator-admission.py
    - python3 -I scripts/check-validator-lifecycle-mutations.py
    - python3 -I scripts/rehearse-validator-activation.py --output "$CI_PROJECT_DIR/.ci-validator-activation"
    - python3 -I scripts/rehearse-validator-joining-network.py --output "$CI_PROJECT_DIR/.ci-validator-joining-network"
    - cargo build --locked --workspace --all-targets
""" + CRATE_ARGS + """\
  timeout: 120m

workspace-tests:
  stage: test
  script:
    - cargo test --workspace
  allow_failure: true
  timeout: 90m

tests-blocking-guard:
  stage: check
  before_script: []
  script:
    - python3 -I scripts/check-tests-blocking.selftest.py
    - python3 -I scripts/check-tests-blocking.py
    - python3 -I scripts/pinned-rust-toolchain.test.py
    - python3 -I scripts/devnet-particao-report.test.py
    - python3 -I scripts/rehearse-validator-activation.test.py
    - python3 -I scripts/check-attested-ssh.selftest.py
    - python3 -I scripts/check-attested-ssh.py
    - python3 -I scripts/check-iso-hardening.selftest.py
    - python3 -I scripts/check-iso-hardening.py
  timeout: 10m
  allow_failure: false
"""

GOOD_GITHUB = """\
name: tests
defaults:
  run:
    shell: /usr/bin/env -u BASH_ENV -u ENV -u PYTHONHOME -u PYTHONPATH -u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u CARGO_BUILD_RUSTFLAGS -u CARGO_BUILD_RUSTC -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER PATH=/home/runner/.cargo/bin:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin /bin/bash --noprofile --norc -euo pipefail {0}
jobs:
  cargo-test:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - run: |
          ch="$(python3 -I scripts/pinned-rust-toolchain.py)"
          rustup toolchain install "$ch" --profile minimal --no-self-update
          echo "toolchain=$ch" >> "$GITHUB_OUTPUT"
      - run: sudo apt-get update && sudo apt-get install -y clang cmake
      - run: python3 -I scripts/rehearse-validator-admission.py
      - run: python3 -I scripts/check-validator-lifecycle-mutations.py
      - run: bash deploy/bootnodes/verify-bootnodes.selftest.sh
      - run: |
          python3 -I scripts/check-live-node-retired-isolation.py --selftest
          python3 -I scripts/check-live-node-retired-isolation.py
      - run: python3 -I scripts/rehearse-validator-activation.py --output "$RUNNER_TEMP/validator-activation"
      - run: python3 -I scripts/rehearse-validator-joining-network.py --output "$RUNNER_TEMP/validator-joining-network"
      - run: cargo +${{ steps.pin.outputs.toolchain }} test --locked -p bloch-pos-node --bin bloch-pos audit_
      - run: cargo +${{ steps.pin.outputs.toolchain }} test --locked -p pqcrypto-internals
      - run: |
          cargo +${{ steps.pin.outputs.toolchain }} test --locked \\
            -p bloch-pos-committee \\
            -p bloch-pos-node \\
            -p bloch-crypto \\
            -p coherence-core \\
            -p bloch-sis-pow \\
            -p bloch-pq-vault \\
            -p pqcrypto-internals \\
            -p genesis4-ceremony

  tests-blocking-guard:
    name: tests-blocking guard (blocking)
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - run: python3 -I scripts/check-tests-blocking.selftest.py
      - run: python3 -I scripts/check-tests-blocking.py
      - run: python3 -I scripts/pinned-rust-toolchain.test.py
      - run: python3 -I scripts/devnet-particao-report.test.py
      - run: python3 -I scripts/rehearse-validator-activation.test.py
      - run: python3 -I scripts/check-attested-ssh.selftest.py
      - run: python3 -I scripts/check-attested-ssh.py
      - run: python3 -I scripts/check-iso-hardening.selftest.py
      - run: python3 -I scripts/check-iso-hardening.py
"""
GOOD_GITHUB_WITH_ENV = GOOD_GITHUB.replace(
    "name: tests\n",
    "name: tests\nenv:\n  CARGO_TERM_COLOR: always\n  RUST_BACKTRACE: \"1\"\n")

# Semantic coverage alone no longer substitutes for the reviewed exact job.
WORKSPACE_GITLAB = GOOD_GITLAB.replace(CRATE_ARGS, "    - cargo test --workspace\n")


class Case:
    def __init__(self, name, gitlab, github, *, must_fail, expect=""):
        self.name = name
        self.gitlab = gitlab
        self.github = github
        self.must_fail = must_fail
        self.expect = expect


def sub(text: str, old: str, new: str) -> str:
    assert old in text, "selftest fixture drift: %r not in fixture" % old
    return text.replace(old, new, 1)


CASES = [
    Case("GitLab reviewed execution environment stays green",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=False),
    Case("GitLab cannot inherit the runner PATH suffix",
         GOOD_GITLAB.replace(
             'export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"',
             'export PATH="$HOME/.cargo/bin:$PATH"'),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),
    Case("GitLab cannot retain Rust tool substitution variables",
         GOOD_GITLAB.replace(
             "unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME "
             "RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC ",
             "unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME RUSTC "),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),
    Case("GitLab cannot retain inherited Rust compiler flags",
         GOOD_GITLAB.replace(
             "RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC",
             "RUSTUP_TOOLCHAIN RUSTC").replace(
             "RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC",
             "RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC"),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),
    Case("GitLab cannot retain Python startup substitution variables",
         GOOD_GITLAB.replace(
             "unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME",
             "unset BASH_ENV ENV CARGO_HOME"),
         GOOD_GITHUB, must_fail=True, expect="reviewed runner tags and fail-fast before_script"),
    Case("reviewed GitHub global test environment stays green",
         GOOD_GITLAB, GOOD_GITHUB_WITH_ENV, must_fail=False),
    Case("reviewed GitHub run shell stays green",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=False),
    Case("GitHub run shell cannot retain inherited RUSTC",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(" -u RUSTC -u RUSTC_WRAPPER", " -u RUSTC_WRAPPER"),
         must_fail=True, expect="environment-clearing run shell"),
    Case("GitHub run shell cannot inherit a PATH suffix",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "PATH=/home/runner/.cargo/bin:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin",
             "PATH=/home/runner/.cargo/bin:$PATH"),
         must_fail=True, expect="environment-clearing run shell"),
    Case("GitHub global test BASH_ENV is refused",
         GOOD_GITLAB,
         GOOD_GITHUB_WITH_ENV.replace(
             '  RUST_BACKTRACE: "1"',
             '  RUST_BACKTRACE: "1"\n  BASH_ENV: scripts/mask-tests.sh'),
         must_fail=True, expect="top-level `env:` differs"),
    Case("GitHub cargo step PATH is refused",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "            -p genesis4-ceremony\n",
             "            -p genesis4-ceremony\n"
             "        env:\n          PATH: scripts/fake-cargo"),
         must_fail=True, expect="environment/container/service context"),
    Case("GitHub cargo job container is refused",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-test:\n    runs-on: ubuntu-latest",
             "  cargo-test:\n    runs-on: ubuntu-latest\n"
             "    container: attacker.invalid/fake-rust:latest"),
         must_fail=True, expect="environment/container/service context"),
    Case("GitHub cargo services are refused",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  cargo-test:\n    runs-on: ubuntu-latest",
             "  cargo-test:\n    runs-on: ubuntu-latest\n"
             "    services:\n      helper:\n        image: attacker.invalid/helper:latest"),
         must_fail=True, expect="environment/container/service context"),
    Case("unreviewed action cannot precede cargo test",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "      - uses: attacker/example@0123456789abcdef0123456789abcdef01234567\n"
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"),
         must_fail=True, expect="unreviewed or mutable action"),
    Case("checkout action cannot regress to a mutable tag",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "actions/checkout@v4"),
         must_fail=True, expect="unreviewed or mutable action"),
    Case("reviewed checkout cannot gain unreviewed inputs",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
             "        with:\n          path: scripts"),
         must_fail=True, expect="unreviewed `with:` inputs"),
    Case("even inert extra cargo run steps need explicit review",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "      - run: echo status=ready >> \"$GITHUB_OUTPUT\"\n"
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"),
         must_fail=True, expect="reviewed ordered command list"),
    Case("extra cargo setup cannot overwrite a rehearsal entrypoint",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/rehearse-validator-admission.py",
             "      - run: cp scripts/fake-rehearsal.py scripts/rehearse-validator-admission.py\n"
             "      - run: python3 -I scripts/rehearse-validator-admission.py"),
         must_fail=True, expect="reviewed ordered command list"),
    Case("cargo setup commands cannot be reordered",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/rehearse-validator-admission.py\n"
             "      - run: python3 -I scripts/check-validator-lifecycle-mutations.py",
             "      - run: python3 -I scripts/check-validator-lifecycle-mutations.py\n"
             "      - run: python3 -I scripts/rehearse-validator-admission.py"),
         must_fail=True, expect="reviewed ordered command list"),
    Case("cargo guard setup cannot be deleted",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: bash deploy/bootnodes/verify-bootnodes.selftest.sh\n", ""),
         must_fail=True, expect="reviewed ordered command list"),
    Case("folded YAML cannot merge toolchain setup commands",
         GOOD_GITLAB,
         GOOD_GITHUB.replace("      - run: |\n", "      - run: >\n", 1),
         must_fail=True, expect="reviewed ordered command list"),
    Case("GitHub PATH command file cannot replace cargo",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "      - run: |\n"
             "          mkdir -p scripts/fake-bin\n"
             "          echo scripts/fake-bin >> \"$GITHUB_PATH\"\n"
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"),
         must_fail=True, expect="cross-step environment/PATH channel"),
    Case("legacy set-env workflow command cannot replace cargo variables",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
             "      - run: echo '::set-env name=BASH_ENV::scripts/mask.sh'\n"
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"),
         must_fail=True, expect="cross-step environment/PATH channel"),
    Case("reviewed GitLab inherited test context stays green",
         GOOD_GITLAB, GOOD_GITHUB, must_fail=False),
    Case("GitLab default cannot disable test fail-fast",
         GOOD_GITLAB.replace(
             "    - cmake --version | head -1 || true",
             "    - cmake --version | head -1 || true\n    - set +e"),
         GOOD_GITHUB, must_fail=True, expect="`default:` must occur exactly once"),
    Case("GitLab global test variables cannot inject BASH_ENV",
         GOOD_GITLAB.replace(
             '  RUST_BACKTRACE: "1"',
             '  RUST_BACKTRACE: "1"\n  BASH_ENV: scripts/mask-tests.sh'),
         GOOD_GITHUB, must_fail=True, expect="top-level `variables:` must occur exactly once"),
    Case("GitLab test job cannot inject execution variables",
         GOOD_GITLAB.replace(
             "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  variables:\n    PATH: scripts/fake-cargo"),
         GOOD_GITHUB, must_fail=True, expect="unreviewed execution variables"),
    Case("GitLab test job cannot replace the runner image",
         GOOD_GITLAB.replace(
             "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  image: attacker.invalid/fake-cargo:latest"),
         GOOD_GITHUB, must_fail=True, expect="unsupported `image:`"),
    Case("GitLab test job cannot fetch entrypoint artifacts with needs",
         GOOD_GITLAB.replace(
             "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  needs:\n    - job: poison-entrypoints\n      artifacts: true"),
         GOOD_GITHUB, must_fail=True, expect="unsupported `needs:`"),
    Case("conditional test execution is not guaranteed", GOOD_GITLAB.replace(CRATE_ARGS, "    - if false; then\n" + CRATE_ARGS + "    - fi\n"), GOOD_GITHUB, must_fail=True),
    Case("disabled shell failures are refused", GOOD_GITLAB.replace(CRATE_ARGS, "    - set +e\n" + CRATE_ARGS), GOOD_GITHUB, must_fail=True),
    Case("background test cannot gate", GOOD_GITLAB.replace(CRATE_ARGS, CRATE_ARGS.rstrip() + " &\n"), GOOD_GITHUB, must_fail=True),
    Case("equals workspace exclusion is refused", WORKSPACE_GITLAB.replace("cargo test --workspace", "cargo test --workspace --exclude=bloch-pos-node"), GOOD_GITHUB, must_fail=True),
    Case("even literal false is outside the exact GitLab header", GOOD_GITLAB.replace("  timeout: 120m", "  allow_failure: false\n  timeout: 120m", 1), GOOD_GITHUB, must_fail=True, expect="header differs"),
    Case("alternate YAML true still waives failures", GOOD_GITLAB.replace("  timeout: 120m", "  allow_failure: YES\n  timeout: 120m", 1), GOOD_GITHUB, must_fail=True),
    Case("workspace exclusion is not full coverage", WORKSPACE_GITLAB.replace("cargo test --workspace", "cargo test --workspace --exclude bloch-pos-node"), GOOD_GITHUB, must_fail=True),
    Case("build mentions cannot supply missing test crates",
         GOOD_GITLAB.replace(CRATE_ARGS, "    - cargo build " + " ".join("-p " + c for c in ("bloch-pos-committee", "bloch-pos-node", "bloch-crypto", "coherence-core", "bloch-sis-pow", "bloch-pq-vault", "pqcrypto-internals", "genesis4-ceremony")) + "\n    - cargo test -p bloch-pos-node\n"),
         GOOD_GITHUB, must_fail=True),
    Case("test failure cannot be swallowed",
         GOOD_GITLAB.replace("cargo test --locked", "cargo test --locked", 1).replace(CRATE_ARGS, CRATE_ARGS.rstrip() + " || true\n"),
         GOOD_GITHUB, must_fail=True),
    Case("no-run is not a test execution", GOOD_GITLAB.replace("cargo test", "cargo test --no-run"), GOOD_GITHUB, must_fail=True),
    Case("echo is not a test execution", GOOD_GITLAB.replace("- cargo test", "- echo cargo test"), GOOD_GITHUB, must_fail=True),
    Case("pipe cannot mask test failure", GOOD_GITLAB.replace(CRATE_ARGS, CRATE_ARGS.rstrip() + " | cat\n"), GOOD_GITHUB, must_fail=True),

    Case("honest pipelines stay green", GOOD_GITLAB, GOOD_GITHUB, must_fail=False),

    Case("github Python entrypoint cannot drop isolated mode",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "python3 -I scripts/rehearse-validator-admission.py",
             "python3 scripts/rehearse-validator-admission.py", 1),
         must_fail=True, expect="reviewed ordered command list"),

    Case("github cannot remove the funded validator admission rehearsal",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/rehearse-validator-admission.py\n", ""),
         must_fail=True, expect="reviewed ordered command list"),

    Case("github cannot remove the shared validator lifecycle mutation check",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/check-validator-lifecycle-mutations.py\n", ""),
         must_fail=True, expect="reviewed ordered command list"),

    Case("github cannot remove the finite validator activation rehearsal",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             '      - run: python3 -I scripts/rehearse-validator-activation.py --output "$RUNNER_TEMP/validator-activation"\n', ""),
         must_fail=True, expect="reviewed ordered command list"),

    Case("github cannot remove the independent validator joining rehearsal",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             '      - run: python3 -I scripts/rehearse-validator-joining-network.py --output "$RUNNER_TEMP/validator-joining-network"\n', ""),
         must_fail=True, expect="reviewed ordered command list"),

    Case("github toolchain setup cannot regress to one-file sed parsing",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             'ch="$(python3 -I scripts/pinned-rust-toolchain.py)"',
             'ch="$(sed -n \'s/^channel *= *"\\(.*\\)".*/\\1/p\' '
             'crates/bloch-pos-node/rust-toolchain.toml)"'),
         must_fail=True, expect="reviewed ordered command list"),

    Case("gitlab Python entrypoint cannot drop isolated mode",
         GOOD_GITLAB.replace(
             "python3 -I scripts/check-live-node-retired-isolation.py --selftest",
             "python3 scripts/check-live-node-retired-isolation.py --selftest", 1),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("workspace superset cannot replace the reviewed GitLab script",
         WORKSPACE_GITLAB, GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("github tests workflow deleted outright",
         GOOD_GITLAB, None, must_fail=True, expect="MISSING"),

    Case("github cargo-test job deleted",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  cargo-test:", "  cargo-test-disabled:"),
         must_fail=True, expect="`cargo-test` is MISSING"),

    Case("github quoted duplicate cargo-test cannot override reviewed job",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n  \"cargo-test\":\n"
         "    runs-on: ubuntu-latest\n"
         "    continue-on-error: true\n"
         "    steps:\n"
         "      - run: echo skipped\n",
         must_fail=True,
         expect="protected `cargo-test:` job key must occur exactly once"),

    Case("github tests-blocking-guard job deleted",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  tests-blocking-guard:", "  tests-blocking-guard-disabled:"),
         must_fail=True, expect="`tests-blocking-guard` is MISSING"),

    Case("github quoted duplicate test guard cannot override reviewed job",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n  'tests-blocking-guard':\n"
         "    runs-on: ubuntu-latest\n"
         "    continue-on-error: true\n"
         "    steps:\n"
         "      - run: echo skipped\n",
         must_fail=True,
         expect="protected `tests-blocking-guard:` job key must occur exactly once"),

    Case("gitlab quoted duplicate test guard cannot override reviewed job",
         GOOD_GITLAB +
         "\n'tests-blocking-guard':\n"
         "  stage: check\n"
         "  script:\n"
         "    - echo skipped\n"
         "  allow_failure: true\n",
         GOOD_GITHUB, must_fail=True,
         expect="protected `tests-blocking-guard:` key must occur exactly once"),

    Case("github guard selftest cannot be removed while guard literal remains",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/check-tests-blocking.selftest.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("github partition-report adversarial test cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/devnet-particao-report.test.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("gitlab partition-report adversarial test cannot be removed",
         sub(GOOD_GITLAB, "    - python3 -I scripts/devnet-particao-report.test.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact blocking contract"),

    Case("github activation parser adversarial test cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/rehearse-validator-activation.test.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("gitlab activation parser adversarial test cannot be removed",
         sub(GOOD_GITLAB, "    - python3 -I scripts/rehearse-validator-activation.test.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact blocking contract"),

    Case("github attested SSH selftest cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/check-attested-ssh.selftest.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("gitlab attested SSH selftest cannot be removed",
         sub(GOOD_GITLAB, "    - python3 -I scripts/check-attested-ssh.selftest.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact blocking contract"),

    Case("github attested SSH verdict cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/check-attested-ssh.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("gitlab attested SSH verdict cannot be removed",
         sub(GOOD_GITLAB, "    - python3 -I scripts/check-attested-ssh.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact blocking contract"),

    Case("github ISO hardening selftest cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/check-iso-hardening.selftest.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("gitlab ISO hardening selftest cannot be removed",
         sub(GOOD_GITLAB, "    - python3 -I scripts/check-iso-hardening.selftest.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact blocking contract"),

    Case("github ISO hardening verdict cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/check-iso-hardening.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("gitlab ISO hardening verdict cannot be removed",
         sub(GOOD_GITLAB, "    - python3 -I scripts/check-iso-hardening.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact blocking contract"),

    Case("github toolchain parser selftest cannot be removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 -I scripts/pinned-rust-toolchain.test.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard and selftest cannot be reordered",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/check-tests-blocking.selftest.py\n"
             "      - run: python3 -I scripts/check-tests-blocking.py\n",
             "      - run: python3 -I scripts/check-tests-blocking.py\n"
             "      - run: python3 -I scripts/check-tests-blocking.selftest.py\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard checkout cannot move after commands",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
             "      - run: python3 -I scripts/check-tests-blocking.selftest.py\n",
             "      - run: python3 -I scripts/check-tests-blocking.selftest.py\n"
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard checkout cannot float",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  tests-blocking-guard:\n    name: tests-blocking guard (blocking)\n"
             "    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n"
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
             "  tests-blocking-guard:\n    name: tests-blocking guard (blocking)\n"
             "    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n"
             "      - uses: actions/checkout@v4\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard timeout is exact",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  tests-blocking-guard:\n    name: tests-blocking guard (blocking)\n"
             "    runs-on: ubuntu-latest\n    timeout-minutes: 10\n",
             "  tests-blocking-guard:\n    name: tests-blocking guard (blocking)\n"
             "    runs-on: ubuntu-latest\n    timeout-minutes: 60\n"),
         must_fail=True, expect="header differs"),

    Case("github guard cannot append a masking command",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/check-attested-ssh.py\n",
             "      - run: python3 -I scripts/check-attested-ssh.py\n"
             "      - run: echo verdict replaced\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard command cannot gain step environment",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 -I scripts/check-tests-blocking.py\n",
             "      - run: python3 -I scripts/check-tests-blocking.py\n"
             "        env:\n          PATH: /attacker/bin\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github job kept but cargo test removed",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(" test --locked", " build --locked"),
         must_fail=True, expect="no longer runs `cargo test`"),

    Case("github drops one live crate from the list",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "            -p bloch-pos-committee \\\n", ""),
         must_fail=True, expect="bloch-pos-committee"),

    Case("github timeout removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  cargo-test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 60\n",
             "  cargo-test:\n    runs-on: ubuntu-latest\n"),
         must_fail=True, expect="no timeout"),

    Case("github continue-on-error on cargo-test",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  cargo-test:\n    runs-on: ubuntu-latest",
             "  cargo-test:\n    runs-on: ubuntu-latest\n    continue-on-error: true"),
         must_fail=True, expect="continue-on-error"),

    Case("github step shell cannot mask cargo test status",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "            -p genesis4-ceremony\n",
             "            -p genesis4-ceremony\n"
             "        shell: bash {0} || true\n"),
         must_fail=True, expect="custom shell/defaults"),

    Case("github job defaults cannot mask cargo test status",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  cargo-test:\n    runs-on: ubuntu-latest",
             "  cargo-test:\n    runs-on: ubuntu-latest\n"
             "    defaults:\n      run:\n        shell: bash {0} || true"),
         must_fail=True, expect="custom shell/defaults"),

    Case("github workflow defaults cannot mask cargo test status",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "name: tests\n",
             "name: tests\ndefaults:\n  run:\n    shell: bash {0} || true\n"),
         must_fail=True, expect="top-level `defaults:`"),

    Case("github quoted duplicate defaults cannot replace reviewed shell",
         GOOD_GITLAB,
         GOOD_GITHUB +
         "\n\"defaults\":\n"
         "  run:\n"
         "    shell: bash {0} || true\n",
         must_fail=True,
         expect="protected top-level `defaults:` key must occur exactly once"),

    Case("github quoted duplicate env cannot inject startup variables",
         GOOD_GITLAB,
         GOOD_GITHUB_WITH_ENV +
         "\n'env':\n"
         "  BASH_ENV: scripts/mask-tests.sh\n",
         must_fail=True,
         expect="protected top-level `env:` key must occur at most once"),

    Case("gitlab build-and-test deleted",
         sub(GOOD_GITLAB, "build-and-test:", "build-and-test-disabled:"),
         GOOD_GITHUB, must_fail=True, expect="`build-and-test` is MISSING"),

    Case("gitlab build-and-test cannot insert a command",
         GOOD_GITLAB.replace(
             "    - cargo build --locked --workspace --all-targets\n",
             "    - echo replacing toolchain\n"
             "    - cargo build --locked --workspace --all-targets\n"),
         GOOD_GITHUB, must_fail=True, expect="exact whole-job contract"),

    Case("gitlab workspace build cannot update the committed lockfile",
         GOOD_GITLAB.replace(
             "cargo build --locked --workspace --all-targets",
             "cargo build --workspace --all-targets"),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab build-and-test cannot remove setup selftest",
         GOOD_GITLAB.replace(
             "    - bash deploy/bootnodes/verify-bootnodes.selftest.sh\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab build-and-test cannot remove toolchain pin validation",
         GOOD_GITLAB.replace(
             "    - python3 -I scripts/pinned-rust-toolchain.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab cannot remove the funded validator admission rehearsal",
         GOOD_GITLAB.replace(
             "    - python3 -I scripts/rehearse-validator-admission.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab cannot remove the shared validator lifecycle mutation check",
         GOOD_GITLAB.replace(
             "    - python3 -I scripts/check-validator-lifecycle-mutations.py\n", ""),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab cannot remove the finite validator activation rehearsal",
         GOOD_GITLAB.replace(
             '    - python3 -I scripts/rehearse-validator-activation.py --output "$CI_PROJECT_DIR/.ci-validator-activation"\n', ""),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab cannot remove the independent validator joining rehearsal",
         GOOD_GITLAB.replace(
             '    - python3 -I scripts/rehearse-validator-joining-network.py --output "$CI_PROJECT_DIR/.ci-validator-joining-network"\n', ""),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab build-and-test commands cannot be reordered",
         GOOD_GITLAB.replace(
             "    - python3 -I scripts/check-live-node-retired-isolation.py --selftest\n"
             "    - python3 -I scripts/check-live-node-retired-isolation.py\n",
             "    - python3 -I scripts/check-live-node-retired-isolation.py\n"
             "    - python3 -I scripts/check-live-node-retired-isolation.py --selftest\n"),
         GOOD_GITHUB, must_fail=True, expect="exact ordered command contract"),

    Case("gitlab duplicate script key is ambiguous",
         GOOD_GITLAB.replace(
             "  timeout: 120m\n",
             "  script:\n    - cargo test --workspace\n  timeout: 120m\n", 1),
         GOOD_GITHUB, must_fail=True, expect="exact whole-job contract"),

    Case("gitlab quoted duplicate job key cannot override reviewed job",
         GOOD_GITLAB + "\n'build-and-test':\n  stage: test\n  script:\n    - true\n",
         GOOD_GITHUB, must_fail=True,
         expect="protected `build-and-test:` key must occur exactly once"),

    Case("gitlab block scalar cannot disguise a reviewed command",
         GOOD_GITLAB.replace(
             "    - cargo build --locked --workspace --all-targets\n",
             "    - |\n      cargo build --locked --workspace --all-targets\n"),
         GOOD_GITHUB, must_fail=True, expect="exact whole-job contract"),

    Case("gitlab aliased build-and-test job is outside local proof",
         GOOD_GITLAB.replace(
             "build-and-test:\n  stage: test\n",
             "build-and-test: *reviewed-test-job\n"),
         GOOD_GITHUB, must_fail=True, expect="`build-and-test` is MISSING"),

    Case("gitlab inherited variables cannot be duplicated",
         "variables:\n  CARGO_TERM_COLOR: always\n" + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True,
         expect="top-level `variables:` must occur exactly once"),

    Case("gitlab inherited default cannot be removed",
         GOOD_GITLAB.replace(
             "default:\n"
             "  tags:\n    - bloch-linux-aarch64\n"
             "  before_script:\n"
             "    - unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME "
             "RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC "
             "RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC "
             "CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER\n"
             "    - export PATH=\"$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin\"\n"
             "    - rustc --version && cargo --version\n"
             "    - clang --version | head -1 || true\n"
             "    - cmake --version | head -1 || true\n\n", ""),
         GOOD_GITHUB, must_fail=True,
         expect="`default:` must occur exactly once"),

    Case("gitlab allow_failure on build-and-test",
         sub(GOOD_GITLAB, "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  allow_failure: true"),
         GOOD_GITHUB, must_fail=True, expect="allow_failure"),

    Case("gitlab exit-0 skip inside build-and-test",
         sub(GOOD_GITLAB, "    - cargo build --locked --workspace --all-targets",
             "    - |\n      if ! command -v cargo >/dev/null; then\n        echo skipping\n        exit 0\n      fi\n    - cargo build --locked --workspace --all-targets"),
         GOOD_GITHUB, must_fail=True, expect="exit 0"),

    Case("gitlab when: manual on build-and-test",
         sub(GOOD_GITLAB, "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  when: manual"),
         GOOD_GITHUB, must_fail=True, expect="when: manual"),

    Case("gitlab drops one live crate from the list",
         sub(GOOD_GITLAB, " -p bloch-pq-vault", ""),
         GOOD_GITHUB, must_fail=True, expect="bloch-pq-vault"),

    Case("gitlab timeout removed",
         sub(GOOD_GITLAB, CRATE_ARGS + "  timeout: 120m\n", CRATE_ARGS),
         GOOD_GITHUB, must_fail=True, expect="header differs"),

    Case("both files missing entirely fails closed", None, None,
         must_fail=True, expect="MISSING"),
]


# Audit wave 2: data fields, filtered harnesses and skipped jobs do not prove
# execution of the live crates' full test suites.
for name, command in {
    "positional filter runs zero matching tests": "cargo test --workspace DOES_NOT_EXIST",
    "library-only selection omits the node binary": "cargo test --workspace --lib",
    "one integration target omits other suites": "cargo test --workspace --test recovery_fence",
    "empty skip filter suppresses every test": 'cargo test --workspace -- --skip ""',
    "another workspace cannot vouch for live crates": "cargo test --workspace --manifest-path services/pq-shield-api/Cargo.toml",
}.items():
    CASES.append(Case(name, GOOD_GITLAB.replace(CRATE_ARGS, "    - " + command + "\n"), GOOD_GITHUB, must_fail=True))
for when in ("never", "manual"):
    CASES.append(Case("GitLab rules skip " + when, GOOD_GITLAB.replace("  stage: test", "  stage: test\n  rules:\n    - when: " + when, 1), GOOD_GITHUB, must_fail=True))
CASES.append(Case("GitLab variables are not commands", "build-and-test:\n  timeout: 1h\n  variables:\n    NOTE: |\n      cargo test --workspace\n  script:\n    - true\n", GOOD_GITHUB, must_fail=True))
CASES.append(Case("GitHub environment strings are not commands", GOOD_GITLAB, "jobs:\n  cargo-test:\n    timeout-minutes: 1\n    env:\n      NOTE: |\n        cargo test --workspace\n    steps:\n      - run: true\n", must_fail=True))
CASES.append(Case("here-doc contents are not executed", "build-and-test:\n  timeout: 1h\n  script:\n    - |\n      cat <<'EOF'\n      cargo test --workspace\n      EOF\n", GOOD_GITHUB, must_fail=True))


def run(case: Case, tmp: str) -> tuple[int, str]:
    gl = os.path.join(tmp, "gitlab-ci.yml")
    gh = os.path.join(tmp, "tests.yml")
    for path, body in ((gl, case.gitlab), (gh, case.github)):
        if body is None:
            if os.path.exists(path):
                os.remove(path)
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    proc = subprocess.run(
        [sys.executable, "-I", CHECKER, "--gitlab", gl, "--github", gh],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def run_with_entrypoint_root(tmp: str, root: str) -> tuple[int, str]:
    gl = os.path.join(tmp, "entrypoint-gitlab-ci.yml")
    gh = os.path.join(tmp, "entrypoint-tests.yml")
    for path, body in ((gl, GOOD_GITLAB), (gh, GOOD_GITHUB)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    proc = subprocess.run(
        [sys.executable, "-I", CHECKER, "--gitlab", gl, "--github", gh,
         "--entrypoint-root", root],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    if not sys.flags.isolated:
        print("check-tests-blocking selftest: FAIL — invoke with `python3 -I` isolated mode")
        return 1
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in CASES:
            code, out = run(case, tmp)
            if case.must_fail and code == 0:
                failures.append("%s: expected the guard to FAIL, it passed" % case.name)
            elif not case.must_fail and code != 0:
                failures.append("%s: expected the guard to PASS, it failed:\n%s" % (case.name, out))
            elif case.must_fail and case.expect and case.expect not in out:
                failures.append(
                    "%s: guard failed, but not for the stated reason (%r absent):\n%s"
                    % (case.name, case.expect, out))

        gl = os.path.join(tmp, "nonisolated-gitlab-ci.yml")
        gh = os.path.join(tmp, "nonisolated-tests.yml")
        for path, body in ((gl, GOOD_GITLAB), (gh, GOOD_GITHUB)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        proc = subprocess.run(
            [sys.executable, CHECKER, "--gitlab", gl, "--github", gh],
            capture_output=True, text=True)
        out = proc.stdout + proc.stderr
        if proc.returncode == 0 or "invoke with `python3 -I` isolated mode" not in out:
            failures.append("non-isolated checker invocation did not fail closed:\n%s" % out)

        missing_root = os.path.join(tmp, "missing-entrypoints")
        os.makedirs(missing_root)
        code, out = run_with_entrypoint_root(tmp, missing_root)
        if code == 0 or "is MISSING or not a regular file" not in out:
            failures.append("missing entrypoint: expected named fail-closed error:\n%s" % out)

        replaced_root = os.path.join(tmp, "replaced-entrypoints")
        replaced = os.path.join(replaced_root, "scripts", "check-attested-ssh.py")
        os.makedirs(os.path.dirname(replaced))
        with open(replaced, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env python3\nraise SystemExit(0)\n")
        code, out = run_with_entrypoint_root(tmp, replaced_root)
        if code == 0 or "`scripts/check-attested-ssh.py` digest differs" not in out:
            failures.append("replaced entrypoint: expected digest failure:\n%s" % out)

        transitive_root = os.path.join(tmp, "replaced-transitive-entrypoints")
        transitive = os.path.join(transitive_root, "scripts", "devnet-particao.sh")
        os.makedirs(os.path.dirname(transitive))
        with open(transitive, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env bash\nexit 0\n")
        code, out = run_with_entrypoint_root(tmp, transitive_root)
        if code == 0 or "`scripts/devnet-particao.sh` digest differs" not in out:
            failures.append("replaced transitive entrypoint: expected digest failure:\n%s" % out)

        reference_root = os.path.join(tmp, "missing-transitive-reference")
        parent = os.path.join(reference_root, "scripts", "check-validator-lifecycle-mutations.py")
        os.makedirs(os.path.dirname(parent))
        with open(parent, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env python3\n# helper invocation removed\n")
        code, out = run_with_entrypoint_root(tmp, reference_root)
        if code == 0 or "lost reviewed reference" not in out:
            failures.append("missing transitive reference: expected scope failure:\n%s" % out)

        symlink_root = os.path.join(tmp, "symlink-entrypoints")
        symlink = os.path.join(symlink_root, "scripts", "check-attested-ssh.py")
        os.makedirs(os.path.dirname(symlink))
        os.symlink(CHECKER, symlink)
        code, out = run_with_entrypoint_root(tmp, symlink_root)
        if code == 0 or "`scripts/check-attested-ssh.py` is or traverses a symlink" not in out:
            failures.append("symlink entrypoint: expected symlink failure:\n%s" % out)

    if failures:
        print("check-tests-blocking selftest: FAIL — %d case(s)\n" % len(failures))
        for f in failures:
            print("  * %s" % f)
        return 1

    print("check-tests-blocking selftest: OK — %d cases behave as documented"
          % (len(CASES) + 6))
    return 0


if __name__ == "__main__":
    sys.exit(main())
