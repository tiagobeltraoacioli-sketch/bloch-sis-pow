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
    " -p pqcrypto-internals\n"
)

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
      - uses: actions/checkout@v4
      - run: |
          cargo test --locked \\
            -p bloch-pos-committee \\
            -p bloch-pos-node \\
            -p bloch-crypto \\
            -p coherence-core \\
            -p bloch-sis-pow \\
            -p bloch-pq-vault \\
            -p pqcrypto-internals

  tests-blocking-guard:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: python3 scripts/check-tests-blocking.py
"""

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
    Case("honest pipelines stay green", GOOD_GITLAB, GOOD_GITHUB, must_fail=False),

    Case("--workspace is accepted as a superset of the crate list",
         WORKSPACE_GITLAB, GOOD_GITHUB, must_fail=False),

    Case("github tests workflow deleted outright",
         GOOD_GITLAB, None, must_fail=True, expect="MISSING"),

    Case("github cargo-test job deleted",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "  cargo-test:", "  cargo-test-disabled:"),
         must_fail=True, expect="`cargo-test` is MISSING"),

    Case("github job kept but cargo test removed",
         GOOD_GITLAB,
         sub(GOOD_GITHUB, "cargo test --locked", "cargo build --locked"),
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
