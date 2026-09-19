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
    true`, an `exit 0` skip, `when: manual`, or a GitHub custom/default shell
    that can replace the test script's exit status.
  * its GitLab inherited `default:`/`variables:` context remains the reviewed
    explicit subset, with no job-local script hooks or execution variables.
  * its GitHub environment is the reviewed inert pair, required jobs use no
    containers/services/env overrides, and every action plus input is a
    reviewed immutable form.
  * no required GitHub run step writes the cross-step PATH/environment command
    files that can replace `cargo` before the approved test command.

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
SAFE_GITLAB_DEFAULT = (
    "tags:",
    "- bloch-linux-aarch64",
    "before_script:",
    '- export PATH="$HOME/.cargo/bin:$PATH"',
    "- rustc --version && cargo --version",
    "- clang --version | head -1 || true",
    "- cmake --version | head -1 || true",
)
SAFE_GITLAB_VARIABLES = (
    'CARGO_TERM_COLOR: "always"',
    'RUST_BACKTRACE: "1"',
)
SAFE_GITHUB_ENV = (
    "CARGO_TERM_COLOR: always",
    'RUST_BACKTRACE: "1"',
)
REVIEWED_GITHUB_ACTIONS = {
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
}
GITHUB_STATE_CHANNEL = re.compile(
    r"GITHUB_(?:PATH|ENV)\b|github\.(?:path|env)\b|::(?:add-path|set-env)\b",
    re.IGNORECASE,
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


def github_action_steps(
    body: list[str], job_indent: int
) -> list[tuple[str, dict[str, str]]]:
    step_indent = job_indent + 4
    steps: list[list[str]] = []
    current: list[str] | None = None
    for line in body:
        spaces = len(line) - len(line.lstrip(" "))
        if spaces == step_indent and line.strip().startswith("- "):
            current = []
            steps.append(current)
        if current is not None:
            current.append(line)
    result = []
    for step in steps:
        action = None
        inputs: dict[str, str] = {}
        in_with = False
        for line in step:
            spaces = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            if spaces == step_indent and stripped.startswith("- uses:"):
                action = stripped.split(":", 1)[1].strip()
            elif spaces == step_indent + 2 and stripped.startswith("uses:"):
                action = stripped.split(":", 1)[1].strip()
            if spaces == step_indent + 2:
                if stripped.startswith("with:") and stripped != "with:":
                    inputs["<unsupported-with-shape>"] = stripped[len("with:"):].strip()
                    in_with = False
                else:
                    in_with = stripped == "with:"
            elif in_with and spaces == step_indent + 4:
                match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", stripped)
                if match:
                    inputs[match.group(1)] = re.sub(
                        r"\s+#.*$", "", match.group(2)).strip(" \"'")
        if action is not None:
            action = re.sub(r"\s+#.*$", "", action).strip(" \"'")
            result.append((action, inputs))
    return result


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


def normalized_yaml_lines(lines: list[str]) -> tuple[str, ...]:
    return tuple(
        re.sub(r"\s+#.*$", "", line.strip())
        for line in lines
        if re.sub(r"\s+#.*$", "", line.strip()))


def check_gitlab_global_context(text: str, blocks: dict[str, list[str]]) -> list[str]:
    problems = []
    present = {
        match.group(1)
        for line in text.splitlines()
        if (match := re.match(
            r"^(default|variables|before_script|after_script|hooks|image|services|cache):", line))
    }
    for key in ("before_script", "after_script", "hooks", "image", "services", "cache"):
        if key in present:
            problems.append(
                ".gitlab-ci.yml: top-level `%s:` is outside the supported "
                "inherited execution context" % key)
    if "default" in present and (
            "default" not in blocks
            or normalized_yaml_lines(blocks["default"]) != SAFE_GITLAB_DEFAULT):
        problems.append(
            ".gitlab-ci.yml: `default:` differs from the reviewed runner tags "
            "and fail-fast before_script")
    if "variables" in present and (
            "variables" not in blocks
            or normalized_yaml_lines(blocks["variables"]) != SAFE_GITLAB_VARIABLES):
        problems.append(
            ".gitlab-ci.yml: top-level `variables:` differs from the reviewed "
            "non-execution-affecting subset")
    return problems


def check_gitlab_job_context(body: list[str], job: str, indent: int) -> list[str]:
    problems = []
    for line in body:
        spaces = len(line) - len(line.lstrip(" "))
        if spaces != indent + 2:
            continue
        value = re.sub(r"\s+#.*$", "", line.strip())
        key = value.split(":", 1)[0]
        if key == "before_script" and value != "before_script: []":
            problems.append(f".gitlab-ci.yml: job `{job}` has an unreviewed `before_script:`")
        elif key in ("after_script", "hooks", "image", "services", "cache",
                     "artifacts", "dependencies", "needs"):
            problems.append(f".gitlab-ci.yml: job `{job}` uses unsupported `{key}:` context")
        elif key == "variables":
            problems.append(f".gitlab-ci.yml: job `{job}` has unreviewed execution variables")
    return problems


def check_job(path: str, job: str, indent: int, label: str) -> list[str]:
    if not os.path.exists(path):
        return ["%s: MISSING — the pipeline definition itself is gone" % label]
    text = open(path, encoding="utf-8").read()
    blocks = job_blocks(text, indent)
    if job not in blocks:
        return ["%s: job `%s` is MISSING. A gate that was deleted is not a "
                "gate that passed." % (label, job)]

    body = blocks[job]
    problems: list[str] = []

    if label == ".gitlab-ci.yml":
        problems += check_gitlab_global_context(text, job_blocks(text, 0))
        problems += check_gitlab_job_context(body, job, indent)

    if label == ".github/workflows/tests.yml":
        top_level = job_blocks(text, 0)
        if "defaults" in top_level:
            problems.append(
                f"{label}: top-level `defaults:` can replace the required test shell")
        env_lines = top_level.get("env")
        env_present = any(re.match(r"^env:", line) for line in text.splitlines())
        if env_present and (env_lines is None
                or normalized_yaml_lines(env_lines) != SAFE_GITHUB_ENV):
            problems.append(
                f"{label}: top-level `env:` differs from the reviewed inert subset")
        for action, inputs in github_action_steps(body, indent):
            if action not in REVIEWED_GITHUB_ACTIONS:
                problems.append(
                    f"{label}: job `{job}` invokes unreviewed or mutable action `{action}`")
            elif inputs:
                problems.append(
                    f"{label}: job `{job}` action `{action}` has unreviewed `with:` inputs")

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
        if (label == ".github/workflows/tests.yml"
                and re.match(r"^(?:defaults|shell):", value)):
            problems.append(
                f"{label}: custom shell/defaults can replace the cargo test exit status")
        if (label == ".github/workflows/tests.yml"
                and re.match(r"^(?:env|container|services):", value)):
            problems.append(
                f"{label}: environment/container/service context can replace cargo")
    blocks = command_blocks(body, indent)
    if (label == ".github/workflows/tests.yml"
            and any(GITHUB_STATE_CHANNEL.search(line) for block in blocks for line in block)):
        problems.append(
            f"{label}: cross-step environment/PATH channel can replace cargo test")
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
