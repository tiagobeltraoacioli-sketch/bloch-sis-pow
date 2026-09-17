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
Exit 0 = the supported explicit job/command subset passes these checks.
This is a structural regression guard, not a proof for arbitrary YAML,
workflow inheritance, branch protection, or shell execution semantics.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
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
    "genesis4-ceremony",
)

ESCAPES = (
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


def command_blocks(body: list[str], job_indent: int) -> list[list[str]]:
    """Extract only explicit script/run fields in the supported CI shapes.

    Indentation is part of the contract: text in env/variables/name scalars
    cannot become execution evidence. YAML aliases/merges are not supported.
    """
    blocks = []
    context = None
    index = 0
    while index < len(body):
        line = body[index]
        spaces = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if spaces == job_indent + 2:
            context = stripped if stripped in ("script:", "steps:") else None
        value = None
        if job_indent == 0 and context == "script:" and spaces == 4 and stripped.startswith("- "):
            value = stripped[2:]
        elif job_indent == 2 and context == "steps:":
            if spaces == 6 and stripped.startswith("- run:"):
                value = stripped[len("- run:"):].strip()
            elif spaces == 8 and stripped.startswith("run:"):
                value = stripped[len("run:"):].strip()
        index += 1
        if value is None:
            continue
        if value in ("|", "|-", "|+"):
            content = []
            required_indent = 6 if job_indent == 0 else 10
            while index < len(body):
                candidate = body[index]
                if len(candidate) - len(candidate.lstrip(" ")) < required_indent:
                    break
                content.append(candidate[required_indent:])
                index += 1
            blocks.append(content)
        elif not value.startswith((">", "*", "&", "[", "{", "'", '"')):
            blocks.append([value])
    return blocks


def complete_test_tokens(command: str) -> list[str] | None:
    """Only unfiltered cargo tests in the current workspace prove coverage."""
    tokens = shlex.split(command, comments=True)
    at = 2 if len(tokens) > 1 and tokens[1].startswith("+") else 1
    if len(tokens) <= at or tokens[0] != "cargo" or tokens[at] != "test":
        return None
    index = at + 1
    while index < len(tokens):
        token = tokens[index]
        if token in ("--locked", "--offline", "--frozen", "--workspace", "--all-targets", "--all-features", "--no-default-features", "--release", "--quiet", "-q", "--verbose", "-v"):
            index += 1
        elif token in ("-p", "--package", "--features", "-j", "--jobs"):
            if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                return None
            index += 2
        elif token.startswith(("--package=", "--features=", "--jobs=")):
            index += 1
        else:
            # Includes positional test names, --lib/--bin/--test selection,
            # --manifest-path, --exclude, --no-run and test-harness filters.
            return None
    return tokens


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
        waiver = re.match(r"^\s*(?:-\s+)?(allow_failure|continue-on-error):\s*(.*?)\s*(?:#.*)?$", line)
        if waiver and waiver.group(2).strip("\"'").lower() not in ("false", "no", "0"):
            problems.append(f"{label}: job `{job}` carries {waiver.group(1)}: true or a nonliteral failure waiver")
        for pattern, name in ESCAPES:
            if pattern.search(line):
                problems.append(
                    "%s: job `%s` carries %s — it cannot fail the build.\n"
                    "      %s" % (label, job, name, line.strip()))

    # Keep the accepted execution language small. The guard does not pretend
    # that arbitrary shell/YAML syntax can be proved safe using line matches.
    for line in body:
        value = re.sub(r"^\s*-\s+", "", line.strip())
        if re.match(r"^(?:if|rules|only|except):", value) or value.startswith("<<:"):
            problems.append(f"{label}: conditional/inherited job execution needs explicit review")
        if re.match(r"^when:\s*(?!on_success\b|always\b)", value):
            problems.append(f"{label}: conditional or manual job execution cannot certify coverage")
    blocks = command_blocks(body, indent)
    if indent == 0:
        # GitLab script list items share one shell; a condition/set +e in
        # an earlier item can change whether a later test gates the job.
        for block in blocks:
            for line in block:
                value = line.strip()
                if re.match(r"^(?:if|for|while|until|case|function)\b", value) or re.match(r"^set\s+\+e\b", value):
                    problems.append(f"{label}: conditional execution or disabled failure propagation in test job")
    test_commands = []
    for block in blocks:
        logical = []
        pending = ""
        for line in block:
            value = (pending + " " + line.strip()).strip()
            if value.endswith("\\"):
                pending = value[:-1]
                continue
            logical.append(re.sub(r"\$\{\{[^}]*\}\}", "PINNED", value))
            pending = ""
        candidates = [command for command in logical if re.match(r"^cargo\s+(?:\+\S+\s+)?test\b", command)]
        if not candidates:
            continue
        if pending or any(command not in candidates and command != "set -euo pipefail" for command in logical):
            problems.append(f"{label}: unsupported shell context around cargo test")
            continue
        for command in candidates:
            if any(operator in command for operator in ("|", ";", "&", "$(", "`", "<", ">")):
                problems.append(f"{label}: compound/masked cargo test command is not a blocking gate")
                continue
            try:
                tokens = complete_test_tokens(command)
            except ValueError:
                problems.append(f"{label}: malformed cargo test command")
                continue
            if tokens is not None:
                test_commands.append(tokens)
    if not test_commands:
        problems.append(f"{label}: job `{job}` no longer runs `cargo test` commands that execute tests")
    elif not any("--workspace" in tokens for tokens in test_commands):
        tested = set()
        for tokens in test_commands:
            tested.update(tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token in ("-p", "--package"))
            tested.update(token.split("=", 1)[1] for token in tokens if token.startswith("--package="))
        for crate in LIVE_CRATES:
            if crate not in tested:
                problems.append(f"{label}: job `{job}` does not test live crate `{crate}`")

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

    print("test-posture guard: OK — supported explicit test commands cover %d live crates on both pipelines"
          % len(LIVE_CRATES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
