#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove `check-scanners-blocking.py` fires on every escape and stays quiet otherwise.

Why this file exists
--------------------
The defect this guard was written for (finding I-H4) was itself a green check
that checked nothing: a scanner job that exited 0 when the tool was absent, on
a job that was allowed to fail anyway. Replacing it with an unexercised guard
would repeat the mistake one level up. Three guards previously audited in this
repository were green while what they guarded was broken.

So this builds synthetic CI files in a temporary directory — never the real
tree, so a failed selftest cannot leave the working copy dirty — and asserts
BOTH directions:

  * every escape shape must be caught, and caught BY NAME (a checker failing
    for some other reason would otherwise look like a pass): allow_failure,
    continue-on-error, an `exit 0` skip, `when: manual`, and a job deleted
    outright;
  * the honest shape must stay green, INCLUDING the shapes one word away from a
    violation — a deliberately report-only job (cargo-geiger) that is allowed
    to fail, and a comment that merely mentions `allow_failure` next to a
    blocking job.

Run: python3 scripts/check-scanners-blocking.selftest.py
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-scanners-blocking.py")

GOOD_GITLAB = """\
stages:
  - check

# cargo-geiger is deliberately report-only (see the written rationale); the
# guard must NOT flag it, and must not flag this comment's allow_failure: true
# either.
cargo-geiger:
  stage: check
  script:
    - cargo geiger || true
  allow_failure: true

osv-scanner:
  stage: check
  script:
    - bash scripts/ci-install-scanner.sh osv-scanner
    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock
  allow_failure: false

secret-scan:
  stage: check
  script:
    - bash scripts/ci-install-scanner.sh gitleaks
    - gitleaks detect --source . --no-banner --redact
  allow_failure: false

cargo-audit:
  stage: check
  script:
    - cargo audit --deny warnings
  allow_failure: false

supply-chain:
  stage: check
  script:
    - cargo deny check advisories bans licenses sources
  allow_failure: false

scanners-blocking-guard:
  stage: check
  script:
    - python3 scripts/check-scanners-blocking.py
  allow_failure: false
"""

GOOD_GITHUB = """\
name: security
jobs:
  cargo-audit:
    runs-on: ubuntu-latest
    steps:
      - run: cargo audit --deny warnings

  cargo-deny:
    runs-on: ubuntu-latest
    steps:
      - run: cargo deny check advisories bans licenses sources

  osv-scanner:
    runs-on: ubuntu-latest
    steps:
      - uses: google/osv-scanner-action/osv-scanner-action@v1.9.2

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: gitleaks/gitleaks-action@v2

  scanners-blocking-guard:
    runs-on: ubuntu-latest
    steps:
      - run: python3 scripts/check-scanners-blocking.py

  cargo-geiger:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: cargo geiger
"""


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

    Case("gitlab allow_failure on osv-scanner",
         sub(GOOD_GITLAB,
             "    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock\n  allow_failure: false",
             "    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock\n  allow_failure: true"),
         GOOD_GITHUB, must_fail=True, expect="`osv-scanner`"),

    Case("gitlab exit-0 skip on secret-scan (the silent one)",
         sub(GOOD_GITLAB,
             "    - bash scripts/ci-install-scanner.sh gitleaks",
             "    - |\n      if ! command -v gitleaks >/dev/null; then\n        echo skipping\n        exit 0\n      fi"),
         GOOD_GITHUB, must_fail=True, expect="exit 0"),

    Case("gitlab when: manual on cargo-audit",
         sub(GOOD_GITLAB,
             "cargo-audit:\n  stage: check",
             "cargo-audit:\n  stage: check\n  when: manual"),
         GOOD_GITHUB, must_fail=True, expect="when: manual"),

    Case("gitlab scanner job deleted outright",
         GOOD_GITLAB.replace(
             "osv-scanner:\n  stage: check\n"
             "  script:\n"
             "    - bash scripts/ci-install-scanner.sh osv-scanner\n"
             "    - osv-scanner --config=osv-scanner.toml --lockfile=Cargo.lock\n"
             "  allow_failure: false\n\n", ""),
         GOOD_GITHUB, must_fail=True, expect="MISSING"),

    Case("github continue-on-error on osv-scanner",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  osv-scanner:\n    runs-on: ubuntu-latest",
             "  osv-scanner:\n    runs-on: ubuntu-latest\n    continue-on-error: true"),
         must_fail=True, expect="continue-on-error"),

    Case("github continue-on-error on secret-scan",
         GOOD_GITLAB,
         sub(GOOD_GITHUB,
             "  secret-scan:\n    runs-on: ubuntu-latest",
             "  secret-scan:\n    runs-on: ubuntu-latest\n    continue-on-error: true"),
         must_fail=True, expect="`secret-scan`"),

    Case("github guard job deleted outright",
         GOOD_GITLAB,
         GOOD_GITHUB.replace(
             "  scanners-blocking-guard:\n    runs-on: ubuntu-latest\n"
             "    steps:\n      - run: python3 scripts/check-scanners-blocking.py\n\n", ""),
         must_fail=True, expect="MISSING"),

    Case("both files missing entirely fails closed", None, None,
         must_fail=True, expect="MISSING"),
]


def run(case: Case, tmp: str) -> tuple[int, str]:
    gl = os.path.join(tmp, "gitlab-ci.yml")
    gh = os.path.join(tmp, "security.yml")
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
            else:
                print("  ok  %s" % case.name)

    if failures:
        print("\nselftest: FAIL — %d case(s)\n" % len(failures))
        for f in failures:
            print("  * %s" % f)
        return 1
    print("\nselftest: OK — %d cases, both directions" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
