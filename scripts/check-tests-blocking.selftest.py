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
  * the honest shapes stay green — the per-crate `-p` list, a `--workspace`
    run (a superset of the list), and a comment that merely mentions
    `allow_failure` next to a gated job.

Run: python3 scripts/check-tests-blocking.selftest.py
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
    - export PATH="$HOME/.cargo/bin:$PATH"
    - rustc --version && cargo --version
    - clang --version | head -1 || true
    - cmake --version | head -1 || true

"""

GOOD_GITLAB = """\
stages:
  - test

# a comment mentioning allow_failure: true must not fail the guard
build-and-test:
  stage: test
  script:
    - cargo build --workspace --all-targets
""" + CRATE_ARGS + """\
  timeout: 60m

workspace-tests:
  stage: test
  script:
    - cargo test --workspace
  allow_failure: true
  timeout: 90m
"""

GOOD_GITHUB = """\
name: tests
jobs:
  cargo-test:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - run: |
          ch="$(sed -n 's/^channel *= *"\(.*\)".*/\\1/p' crates/bloch-pos-node/rust-toolchain.toml)"
          if [ -z "$ch" ]; then
            echo "cannot read the toolchain pin — refusing to test on a floating toolchain" >&2
            exit 1
          fi
          rustup toolchain install "$ch" --profile minimal --no-self-update
          echo "toolchain=$ch" >> "$GITHUB_OUTPUT"
      - run: sudo apt-get update && sudo apt-get install -y clang cmake
      - run: python3 scripts/rehearse-validator-admission.py
      - run: python3 scripts/check-validator-lifecycle-mutations.py
      - run: bash deploy/bootnodes/verify-bootnodes.selftest.sh
      - run: |
          python3 scripts/check-live-node-retired-isolation.py --selftest
          python3 scripts/check-live-node-retired-isolation.py
      - run: python3 scripts/rehearse-validator-activation.py --output "$RUNNER_TEMP/validator-activation"
      - run: python3 scripts/rehearse-validator-joining-network.py --output "$RUNNER_TEMP/validator-joining-network"
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
      - run: python3 scripts/check-tests-blocking.selftest.py
      - run: python3 scripts/check-tests-blocking.py
      - run: python3 scripts/devnet-particao-report.test.py
      - run: python3 scripts/rehearse-validator-activation.test.py
      - run: python3 scripts/check-attested-ssh.selftest.py
      - run: python3 scripts/check-attested-ssh.py
"""
GOOD_GITHUB_WITH_ENV = GOOD_GITHUB.replace(
    "name: tests\n",
    "name: tests\nenv:\n  CARGO_TERM_COLOR: always\n  RUST_BACKTRACE: \"1\"\n")

# --workspace covers every member crate; the guard must accept it.
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
    Case("reviewed GitHub global test environment stays green",
         GOOD_GITLAB, GOOD_GITHUB_WITH_ENV, must_fail=False),
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
             "      - run: python3 scripts/rehearse-validator-admission.py",
             "      - run: cp scripts/fake-rehearsal.py scripts/rehearse-validator-admission.py\n"
             "      - run: python3 scripts/rehearse-validator-admission.py"),
         must_fail=True, expect="reviewed ordered command list"),
    Case("cargo setup commands cannot be reordered",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 scripts/rehearse-validator-admission.py\n"
             "      - run: python3 scripts/check-validator-lifecycle-mutations.py",
             "      - run: python3 scripts/check-validator-lifecycle-mutations.py\n"
             "      - run: python3 scripts/rehearse-validator-admission.py"),
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
         SAFE_GITLAB_GLOBALS + GOOD_GITLAB, GOOD_GITHUB, must_fail=False),
    Case("GitLab default cannot disable test fail-fast",
         SAFE_GITLAB_GLOBALS.replace(
             "    - cmake --version | head -1 || true",
             "    - cmake --version | head -1 || true\n    - set +e") + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True, expect="`default:` differs"),
    Case("GitLab global test variables cannot inject BASH_ENV",
         SAFE_GITLAB_GLOBALS.replace(
             '  RUST_BACKTRACE: "1"',
             '  RUST_BACKTRACE: "1"\n  BASH_ENV: scripts/mask-tests.sh') + GOOD_GITLAB,
         GOOD_GITHUB, must_fail=True, expect="top-level `variables:` differs"),
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
    Case("literal false does not waive failures", GOOD_GITLAB.replace("  timeout: 60m", "  allow_failure: false\n  timeout: 60m", 1), GOOD_GITHUB, must_fail=False),
    Case("alternate YAML true still waives failures", GOOD_GITLAB.replace("  timeout: 60m", "  allow_failure: YES\n  timeout: 60m", 1), GOOD_GITHUB, must_fail=True),
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

    Case("--workspace is accepted as a superset of the crate list",
         WORKSPACE_GITLAB, GOOD_GITHUB, must_fail=False),

    Case("github tests workflow deleted outright",
         GOOD_GITLAB, None, must_fail=True, expect="MISSING"),

    Case("github cargo-test job deleted",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  cargo-test:", "  cargo-test-disabled:"),
         must_fail=True, expect="`cargo-test` is MISSING"),

    Case("github tests-blocking-guard job deleted",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  tests-blocking-guard:", "  tests-blocking-guard-disabled:"),
         must_fail=True, expect="`tests-blocking-guard` is MISSING"),

    Case("github guard selftest cannot be removed while guard literal remains",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "      - run: python3 scripts/check-tests-blocking.selftest.py\n", ""),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard and selftest cannot be reordered",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 scripts/check-tests-blocking.selftest.py\n"
             "      - run: python3 scripts/check-tests-blocking.py\n",
             "      - run: python3 scripts/check-tests-blocking.py\n"
             "      - run: python3 scripts/check-tests-blocking.selftest.py\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard checkout cannot move after commands",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
             "      - run: python3 scripts/check-tests-blocking.selftest.py\n",
             "      - run: python3 scripts/check-tests-blocking.selftest.py\n"
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
             "      - run: python3 scripts/check-attested-ssh.py\n",
             "      - run: python3 scripts/check-attested-ssh.py\n"
             "      - run: echo verdict replaced\n"),
         must_fail=True, expect="exact ordered contract"),

    Case("github guard command cannot gain step environment",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "      - run: python3 scripts/check-tests-blocking.py\n",
             "      - run: python3 scripts/check-tests-blocking.py\n"
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

    Case("gitlab build-and-test deleted",
         sub(GOOD_GITLAB, "build-and-test:", "build-and-test-disabled:"),
         GOOD_GITHUB, must_fail=True, expect="`build-and-test` is MISSING"),

    Case("gitlab allow_failure on build-and-test",
         sub(GOOD_GITLAB, "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  allow_failure: true"),
         GOOD_GITHUB, must_fail=True, expect="allow_failure"),

    Case("gitlab exit-0 skip inside build-and-test",
         sub(GOOD_GITLAB, "    - cargo build --workspace --all-targets",
             "    - |\n      if ! command -v cargo >/dev/null; then\n        echo skipping\n        exit 0\n      fi\n    - cargo build --workspace --all-targets"),
         GOOD_GITHUB, must_fail=True, expect="exit 0"),

    Case("gitlab when: manual on build-and-test",
         sub(GOOD_GITLAB, "build-and-test:\n  stage: test",
             "build-and-test:\n  stage: test\n  when: manual"),
         GOOD_GITHUB, must_fail=True, expect="when: manual"),

    Case("gitlab drops one live crate from the list",
         sub(GOOD_GITLAB, " -p bloch-pq-vault", ""),
         GOOD_GITHUB, must_fail=True, expect="bloch-pq-vault"),

    Case("gitlab timeout removed",
         sub(GOOD_GITLAB, CRATE_ARGS + "  timeout: 60m\n", CRATE_ARGS),
         GOOD_GITHUB, must_fail=True, expect="no timeout"),

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
        [sys.executable, CHECKER, "--gitlab", gl, "--github", gh],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
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

    if failures:
        print("check-tests-blocking selftest: FAIL — %d case(s)\n" % len(failures))
        for f in failures:
            print("  * %s" % f)
        return 1

    print("check-tests-blocking selftest: OK — %d cases behave as documented" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
