#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Refuse a security-scanner job that cannot fail the build.

WHY THIS EXISTS
---------------
Audit finding I-H4. Both scanner jobs carried two independent escapes at once:

    secret-scan:                      osv-scanner:
      script:                           script:
        - |                               - |
          if ! command -v gitleaks ...      if ! command -v osv-scanner ...
            echo "skipping"                   echo "skipping (informational)."
            exit 0                            exit 0
        - gitleaks detect ...             - osv-scanner --lockfile=Cargo.lock
      allow_failure: true               allow_failure: true

`allow_failure` is at least visible in the UI. The `exit 0` is not: on a runner
that never had the tool, the job SUCCEEDED, printed one line of prose, and
scanned nothing. "The scanner found no secrets" and "there is no scanner" were
the same green tick.

That mattered most for osv-scanner, which is the only tool in this repository
reading the OSV.dev DB (RustSec + GHSA). GHSA-vxx9-2994-q338 — yamux 0.12.1,
CVSS 8.7, a stream-multiplexer DoS reachable from any connected peer — is not
in cargo-audit's RustSec feed and is not in cargo-deny's. One job saw it, and
that job could not fail.

WHAT THIS GUARD DOES
--------------------
Reads both CI files as text (no PyYAML on the runners) and, for each REQUIRED
scanner job, fails if the job:

  * is ABSENT               — a deleted gate must not read as a passing gate;
  * `allow_failure: true`   — GitLab escape;
  * `continue-on-error: true` — the GitHub spelling of the same thing;
  * contains `exit 0`       — the silent skip that started this;
  * is `when: manual`       — a gate nobody triggers is not a gate.

It does NOT require every job to be blocking. cargo-geiger, miri and the fuzz
smoke are deliberately report-only, with written reasons, and stay green here.
The set below is the list of jobs whose failure must stop a merge; adding an
escape to one of them is the regression this file exists to catch.

Deliberately blunt about `exit 0`: any occurrence inside a required scanner job
is refused, even a plausible-looking one. There is no legitimate reason for a
blocking scanner to hand-roll a success exit, and a guard that tries to tell a
good early-exit from a bad one is a guard that can be talked around.

Pure Python 3. No toolchain, no build, no network.

Run: python3 scripts/check-scanners-blocking.py
Exit 0 = both pipelines can still fail on a scanner finding.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Jobs whose failure must stop a merge, per file. Keys are the YAML job keys.
GITLAB_REQUIRED = {
    "osv-scanner":             "the only OSV/GHSA advisory scan (yamux GHSA-vxx9-2994-q338)",
    "secret-scan":             "committed-credential scan",
    "cargo-audit":             "RustSec advisory backstop",
    "supply-chain":            "cargo-deny advisories + licenses + sources",
    "scanners-blocking-guard": "this guard (it must gate its own pipeline)",
}
GITHUB_REQUIRED = {
    "osv-scanner":             "the only OSV/GHSA advisory scan (yamux GHSA-vxx9-2994-q338)",
    "secret-scan":             "committed-credential scan",
    "cargo-audit":             "RustSec advisory backstop",
    "cargo-deny":              "advisories + licenses + sources",
    "scanners-blocking-guard": "this guard (it must gate its own pipeline)",
}

ESCAPES = (
    (re.compile(r"^\s*allow_failure:\s*true\b"),      "allow_failure: true"),
    (re.compile(r"^\s*continue-on-error:\s*true\b"),  "continue-on-error: true"),
    (re.compile(r"(^|[;&|\s])exit\s+0\b"),            "an `exit 0` escape (the silent skip)"),
    (re.compile(r"^\s*when:\s*manual\b"),             "when: manual"),
)


def job_blocks(text: str, indent: int) -> dict[str, list[str]]:
    """Split a CI file into {job key: body lines} at the given key indentation.

    GitLab jobs are top-level (indent 0); GitHub jobs sit under `jobs:` at
    indent 2. Comment and blank lines between jobs belong to no block, which is
    what we want: a comment saying "allow_failure" must not fail the guard.
    """
    key = re.compile(r"^ {%d}([A-Za-z0-9_.\-]+):\s*(#.*)?$" % indent)
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.split("\n"):
        m = key.match(line)
        if m:
            current = m.group(1)
            blocks[current] = []
            continue
        if current is None:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        # A line at or left of the key indentation ends the block.
        if len(line) - len(line.lstrip(" ")) <= indent:
            current = None
            continue
        if stripped.startswith("#"):
            continue
        blocks[current].append(line)
    return blocks


def check_file(path: str, required: dict[str, str], indent: int, label: str) -> list[str]:
    if not os.path.exists(path):
        return ["%s: MISSING — the pipeline definition itself is gone" % label]
    text = open(path, encoding="utf-8").read()
    blocks = job_blocks(text, indent)
    problems: list[str] = []
    for job, why in sorted(required.items()):
        if job not in blocks:
            problems.append(
                "%s: job `%s` is MISSING (%s). A gate that was deleted is not a "
                "gate that passed." % (label, job, why))
            continue
        for line in blocks[job]:
            for pattern, name in ESCAPES:
                if pattern.search(line):
                    problems.append(
                        "%s: job `%s` (%s) carries %s — it cannot fail the "
                        "build.\n      %s" % (label, job, why, name, line.strip()))
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gitlab", default=os.path.join(REPO, ".gitlab-ci.yml"))
    ap.add_argument("--github", default=os.path.join(REPO, ".github/workflows/security.yml"))
    args = ap.parse_args()

    problems = []
    problems += check_file(args.gitlab, GITLAB_REQUIRED, 0, ".gitlab-ci.yml")
    problems += check_file(args.github, GITHUB_REQUIRED, 2, ".github/workflows/security.yml")

    if problems:
        print("scanner-posture guard: FAIL — %d problem(s)\n" % len(problems))
        for p in problems:
            print("  * %s" % p)
        print("\nA security scanner that cannot fail the build is a claim, not a check.")
        print("See SECURITY_TOOLING.md §Advisory posture and osv-scanner.toml: an")
        print("advisory is accepted by NAMING it with a rationale and a review date,")
        print("never by letting the job go green.")
        return 1

    print("scanner-posture guard: OK — %d GitLab + %d GitHub scanner jobs are blocking"
          % (len(GITLAB_REQUIRED), len(GITHUB_REQUIRED)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
