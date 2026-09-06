#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Refuse a pipeline in which the live crates' tests cannot fail a merge.

WHY THIS EXISTS
---------------
Round-2 audit finding TEST1-ci-runs-tests. The GitHub pipeline ran security
scanners and NO `cargo test` at all; the GitLab `build-and-test` job did run
tests but was permanently red, so the stage behind it never ran and its
verdict carried no information. Both states are the same defect: the test
suite of the chain that is producing blocks had no green-able gate anywhere.

WHAT THIS GUARD DOES
--------------------
Reads both CI files as text (no PyYAML on the runners) and holds two jobs —
GitHub `.github/workflows/tests.yml` job `cargo-test`, GitLab `.gitlab-ci.yml`
job `build-and-test` — to the posture the finding required:

  * the job EXISTS — a deleted gate must not read as a passing gate;
  * it runs `cargo test`;
  * every LIVE crate below is named with `-p` (or the job tests the whole
    workspace with `--workspace`, which is a superset);
  * it has a timeout (`timeout-minutes:` / `timeout:`) — a job that can hang
    forever gates by luck, not by verdict;
  * it carries no escape hatch: `allow_failure: true`, `continue-on-error:
    true`, an `exit 0` skip, or `when: manual`.

The live-crate list is duplicated in `.github/workflows/tests.yml` on
purpose: the workflow states what it gates, this file makes dropping a crate
a red pipeline instead of a silent narrowing. Change both together, with a
written reason.

Deliberately blunt, like scripts/check-scanners-blocking.py: any `exit 0`
inside a gated job is refused, even a plausible-looking one.

Pure Python 3. No toolchain, no build, no network.

Run: python3 scripts/check-tests-blocking.py
Exit 0 = both pipelines can still fail on a broken test in a live crate.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The crates whose tests must be able to fail a merge. Genesis-4 consensus and
# everything on its signing/hashing path, plus the shared protocol crates.
LIVE_CRATES = (
    "bloch-pos-committee",
    "bloch-pos-node",
    "bloch-crypto",
    "coherence-core",
    "bloch-sis-pow",
    "bloch-pq-vault",
    "pqcrypto-internals",
)

ESCAPES = (
    (re.compile(r"^\s*allow_failure:\s*true\b"),      "allow_failure: true"),
    (re.compile(r"^\s*continue-on-error:\s*true\b"),  "continue-on-error: true"),
    (re.compile(r"(^|[;&|\s])exit\s+0\b"),            "an `exit 0` escape (the silent skip)"),
    (re.compile(r"^\s*when:\s*manual\b"),             "when: manual"),
)

TIMEOUTS = (
    re.compile(r"^\s*timeout:\s*\S"),          # GitLab
    re.compile(r"^\s*timeout-minutes:\s*\d"),  # GitHub
)


def job_blocks(text: str, indent: int) -> dict[str, list[str]]:
    """Split a CI file into {job key: body lines} at the given key indentation.

    GitLab jobs are top-level (indent 0); GitHub jobs sit under `jobs:` at
    indent 2. Comment and blank lines between jobs belong to no block, so a
    comment that merely mentions an escape cannot fail the guard.
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
        if len(line) - len(line.lstrip(" ")) <= indent:
            current = None
            continue
        if stripped.startswith("#"):
            continue
        blocks[current].append(line)
    return blocks


def check_job(path: str, job: str, indent: int, label: str) -> list[str]:
    if not os.path.exists(path):
        return ["%s: MISSING — the pipeline definition itself is gone" % label]
    text = open(path, encoding="utf-8").read()
    blocks = job_blocks(text, indent)
    if job not in blocks:
        return ["%s: job `%s` is MISSING. A gate that was deleted is not a "
                "gate that passed." % (label, job)]

    body = blocks[job]
    joined = "\n".join(body)
    problems: list[str] = []

    for line in body:
        for pattern, name in ESCAPES:
            if pattern.search(line):
                problems.append(
                    "%s: job `%s` carries %s — it cannot fail the build.\n"
                    "      %s" % (label, job, name, line.strip()))

    test_re = re.compile(r"\bcargo\s+(\+\S+\s+)?test\b")
    test_lines = [line for line in body if test_re.search(line)]
    if not test_lines:
        problems.append(
            "%s: job `%s` no longer runs `cargo test` — a test gate that runs "
            "no tests is a claim, not a check." % (label, job))
    # --workspace counts only on the `cargo test` invocation itself: a
    # `cargo build --workspace` line must not vouch for the test line.
    elif not any("--workspace" in line for line in test_lines):
        for crate in LIVE_CRATES:
            if not re.search(r"-p\s+%s\b" % re.escape(crate), joined):
                problems.append(
                    "%s: job `%s` does not test live crate `%s` (and does not "
                    "run --workspace, which would cover it)."
                    % (label, job, crate))

    if not any(t.search(line) for line in body for t in TIMEOUTS):
        problems.append(
            "%s: job `%s` has no timeout — a job that can hang forever gates "
            "by luck, not by verdict." % (label, job))

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gitlab", default=os.path.join(REPO, ".gitlab-ci.yml"))
    ap.add_argument("--github", default=os.path.join(REPO, ".github/workflows/tests.yml"))
    args = ap.parse_args()

    problems = []
    problems += check_job(args.gitlab, "build-and-test", 0, ".gitlab-ci.yml")
    problems += check_job(args.github, "cargo-test", 2, ".github/workflows/tests.yml")

    if problems:
        print("test-posture guard: FAIL — %d problem(s)\n" % len(problems))
        for p in problems:
            print("  * %s" % p)
        print("\nThe live crates' tests must be able to fail a merge on BOTH")
        print("pipelines. See .github/workflows/tests.yml for the gated list and")
        print("the written reasons; narrow it only there and here together.")
        return 1

    print("test-posture guard: OK — cargo test gates %d live crates on both pipelines"
          % len(LIVE_CRATES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
