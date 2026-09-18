#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Refuse a required security job that cannot fail the build.

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
security job, fails if the job:

  * is ABSENT               — a deleted gate must not read as a passing gate;
  * any non-false `allow_failure` / `continue-on-error` value;
  * contains `exit 0`       — the silent skip that started this;
  * masks a command with `|| true`, `| true`, or `; true`;
  * conditionally skips execution through `if`, `rules`, `only`, `except`,
    GitLab inheritance, a YAML alias/reference, a GitHub reusable-workflow
    delegation, or a `when` other than `on_success`/`always`.
  * moves GitLab pipeline selection or configuration behind top-level
    `workflow:` / `include:` content this local guard does not inspect.

It does NOT require every job to be blocking. cargo-geiger, miri and the fuzz
smoke are deliberately report-only, with written reasons, and stay green here.
The set below is the list of jobs whose failure must stop a merge; adding an
escape to one of them is the regression this file exists to catch.

Deliberately blunt about `exit 0`: any occurrence inside a required security
job is refused, even a plausible-looking one. There is no legitimate reason
for a blocking gate to hand-roll a success exit, and a guard that tries to tell
a good early-exit from a bad one is a guard that can be talked around.

Pure Python 3. No toolchain, no build, no network.

Run: python3 scripts/check-scanners-blocking.py
Exit 0 = the supported explicit job subset can still fail on every registered
security verdict. This is not a proof for full YAML parsing, dynamic shell
execution semantics, or hosted branch protection.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Jobs whose failure must stop a merge, per file. Keys are the YAML job keys.
GITLAB_REQUIRED = {
    "clippy-hardened":          "consensus panic/arithmetic ratchet",
    "osv-scanner":             "the only OSV/GHSA advisory scan (yamux GHSA-vxx9-2994-q338)",
    "secret-scan":             "committed-credential scan",
    "secret-history-scan":     "reachable-history credential scan",
    "cargo-audit":             "RustSec advisory backstop",
    "supply-chain":            "cargo-deny advisories + licenses + sources",
    "scanners-blocking-guard": "this guard (it must gate its own pipeline)",
    "rollback-package-integrity": "signed rollback-package rejection paths",
}
GITHUB_REQUIRED = {
    "clippy-hardened":          "consensus panic/arithmetic ratchet",
    "osv-scanner":             "the only OSV/GHSA advisory scan (yamux GHSA-vxx9-2994-q338)",
    "secret-scan":             "committed-credential scan",
    "secret-history-scan":     "reachable-history credential scan",
    "cargo-audit":             "RustSec advisory backstop",
    "cargo-deny":              "advisories + licenses + sources",
    "scanners-blocking-guard": "this guard (it must gate its own pipeline)",
    "rollback-package-integrity": "signed rollback-package rejection paths",
}

SHELL_ESCAPES = (
    (re.compile(r"(^|[;&|\s])exit\s+0\b"), "an `exit 0` escape (the silent skip)"),
    (re.compile(r"(?:\|\||\||;)\s*true\b"), "a shell-success masking escape"),
    (re.compile(r"^\s*(?:-\s+)?set\s+\+e\b"), "disabled shell failure propagation"),
)

FALSE_LITERALS = {"false", "no", "0"}
SAFE_WHEN = {"on_success", "always"}


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
    if label == ".gitlab-ci.yml":
        for line in text.splitlines():
            if re.match(r"^(?:include|workflow):(?:\s|$)", line):
                key = line.split(":", 1)[0]
                problems.append(
                    "%s: top-level `%s:` moves pipeline semantics outside the "
                    "locally inspectable blocking subset" % (label, key))
    for job, why in sorted(required.items()):
        if job not in blocks:
            problems.append(
                "%s: job `%s` is MISSING (%s). A gate that was deleted is not a "
                "gate that passed." % (label, job, why))
            continue
        for line in blocks[job]:
            waiver = re.match(
                r"^\s*(?:-\s+)?(allow_failure|continue-on-error):\s*(.*?)\s*(?:#.*)?$",
                line,
            )
            if waiver and waiver.group(2).strip("\"'").lower() not in FALSE_LITERALS:
                problems.append(
                    "%s: job `%s` (%s) carries %s with a true, structured, "
                    "expression, or missing value — it cannot certify a blocking verdict"
                    % (label, job, why, waiver.group(1)))

            value = re.sub(r"^\s*-\s+", "", line.strip())
            if re.match(r"^(?:if|rules|only|except|extends|inherit):", value) or value.startswith("<<:"):
                problems.append(
                    "%s: job `%s` (%s) has conditional or inherited execution; "
                    "the supported blocking subset requires an unconditional job"
                    % (label, job, why))
            if (re.match(r"^[A-Za-z0-9_.-]+:\s*(?:\*|!reference\b)", value)
                    or value.startswith("*")
                    or value.startswith("!reference")):
                problems.append(
                    "%s: job `%s` (%s) uses a YAML alias or GitLab reference; "
                    "the supported blocking subset requires locally inspectable values"
                    % (label, job, why))
            line_indent = len(line) - len(line.lstrip(" "))
            if (label == ".github/workflows/security.yml"
                    and line_indent == indent + 2
                    and re.match(r"^uses:", value)):
                problems.append(
                    "%s: job `%s` (%s) delegates to a reusable workflow; "
                    "the supported blocking subset requires locally inspectable steps"
                    % (label, job, why))
            when = re.match(r"^when:\s*([^\s#]+)", value)
            if when and when.group(1).strip("\"'").lower() not in SAFE_WHEN:
                problems.append(
                    "%s: job `%s` (%s) carries conditional `when: %s`"
                    % (label, job, why, when.group(1)))

            for pattern, name in SHELL_ESCAPES:
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

    print("security-posture guard: OK — %d GitLab + %d GitHub jobs are blocking"
          % (len(GITLAB_REQUIRED), len(GITHUB_REQUIRED)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
