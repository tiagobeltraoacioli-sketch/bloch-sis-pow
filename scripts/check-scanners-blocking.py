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
  * removes or filters the reviewed GitHub `push`/`pull_request` triggers, or
    substitutes the privileged `pull_request_target` event.
  * removes the explicit read-only GitHub token posture or adds a job-level
    permission override to a required scanner.
  * keeps the job name but removes/replaces its actual scanner or guard
    command. Evidence is accepted only from explicit GitLab `script:` items
    and GitHub step `run:`/`uses:` fields, never names, comments or variables.
  * duplicates or quotes a required job key, so the CI parser cannot select a
    different mapping value than the plain-key block reviewed here.
  * makes the GitHub OSV verdict mutable by replacing its full commit pin with
    a tag/branch, or removes this guard's own adversarial self-test.
  * lets the GitHub OSV lockfile scope drift from the complete set of tracked
    `Cargo.lock` files in either direction.
  * changes the exact GitHub global run shell that clears inherited
    shell/Python/Rust substitution variables, fixes PATH, and preserves
    fail-fast semantics, or adds a required-job custom shell.
  * removes or changes the reviewed GitLab inherited default/variable context,
    or lets a required job override it with before/after scripts, hooks or
    unreviewed variables.
  * adds GitHub environment/container/service replacement context or an
    unreviewed/mutable action (including new inputs to a reviewed action).
  * writes GitHub's cross-step PATH/environment command files before an
    otherwise unchanged scanner or guard command.
  * adds, removes or reorders a required GitHub security job's reviewed run
    steps, including folding distinct literal-block commands together.

It does NOT require every job to be blocking. cargo-geiger, miri and the fuzz
smoke are deliberately report-only, with written reasons, and stay green here.
The set below is the list of jobs whose failure must stop a merge; adding an
escape to one of them is the regression this file exists to catch.

Deliberately blunt about `exit 0`: any occurrence inside a required security
job is refused, even a plausible-looking one. There is no legitimate reason
for a blocking gate to hand-roll a success exit, and a guard that tries to tell
a good early-exit from a bad one is a guard that can be talked around.

Python 3 plus the local Git index. No toolchain, build or network.

Run: python3 scripts/check-scanners-blocking.py
Exit 0 = the supported explicit job subset can still fail on every registered
security verdict. This is not a proof for full YAML parsing, dynamic shell
execution semantics, or hosted branch protection.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
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

# A job name is not evidence that its verdict still runs. Keep these patterns
# deliberately tied to the repository-owned entrypoints (or, for OSV on
# GitHub, the reviewed action). Matching happens only against executable YAML
# fields extracted by explicit_execution_values(), not against the whole job.
GITLAB_VERDICTS = {
    "clippy-hardened": re.compile(r"^bash\s+scripts/hardened-clippy\.sh(?:\s|$)"),
    "osv-scanner": re.compile(r"^(?:osv-scanner|[\"']?[^\s\"']*/osv-scanner[\"']?)\s+.*--config=osv-scanner\.toml.*--lockfile=Cargo\.lock"),
    "secret-scan": re.compile(r"^bash\s+scripts/scan-secrets\.sh\s+tree(?:\s|$)"),
    "secret-history-scan": re.compile(r"^bash\s+scripts/scan-secrets\.sh\s+history(?:\s|$)"),
    "cargo-audit": re.compile(r"^bash\s+scripts/audit-all-lockfiles\.sh(?:\s|$)"),
    "supply-chain": re.compile(r"^cargo\s+deny\s+check\s+advisories\s+bans\s+licenses\s+sources(?:\s|$)"),
    "scanners-blocking-guard": re.compile(r"^python3\s+scripts/check-scanners-blocking\.py$"),
    "rollback-package-integrity": re.compile(r"^bash\s+deploy/rollback/make-rollback-package\.selftest\.sh(?:\s|$)"),
}
GITHUB_VERDICTS = {
    "clippy-hardened": GITLAB_VERDICTS["clippy-hardened"],
    "osv-scanner": re.compile(r"^google/osv-scanner-action/osv-scanner-action@[0-9a-f]{40}$"),
    "secret-scan": GITLAB_VERDICTS["secret-scan"],
    "secret-history-scan": GITLAB_VERDICTS["secret-history-scan"],
    "cargo-audit": GITLAB_VERDICTS["cargo-audit"],
    "cargo-deny": GITLAB_VERDICTS["supply-chain"],
    "scanners-blocking-guard": GITLAB_VERDICTS["scanners-blocking-guard"],
    "rollback-package-integrity": GITLAB_VERDICTS["rollback-package-integrity"],
}
SELFTEST_VERDICTS = {
    "scanners-blocking-guard": re.compile(
        r"^python3\s+scripts/check-scanners-blocking\.selftest\.py$"),
}

SHELL_ESCAPES = (
    (re.compile(r"(^|[;&|\s])exit\s+0\b"), "an `exit 0` escape (the silent skip)"),
    (re.compile(r"(?:\|\||\||;)\s*true\b"), "a shell-success masking escape"),
    (re.compile(r"^\s*(?:-\s+)?set\s+\+e\b"), "disabled shell failure propagation"),
)

FALSE_LITERALS = {"false", "no", "0"}
SAFE_WHEN = {"on_success", "always"}
SAFE_GITLAB_DEFAULT = (
    "tags:",
    "- bloch-linux-aarch64",
    "before_script:",
    "- unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME "
    "RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC "
    "RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTC "
    "CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    '- export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"',
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
SAFE_GITHUB_DEFAULTS = (
    "run:",
    "shell: /usr/bin/env -u BASH_ENV -u ENV -u PYTHONHOME -u PYTHONPATH "
    "-u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN -u RUSTFLAGS "
    "-u CARGO_ENCODED_RUSTFLAGS -u RUSTC -u RUSTC_WRAPPER "
    "-u RUSTC_WORKSPACE_WRAPPER -u CARGO_BUILD_RUSTFLAGS "
    "-u CARGO_BUILD_RUSTC -u CARGO_BUILD_RUSTC_WRAPPER "
    "-u CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER "
    "PATH=/home/runner/.cargo/bin:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin "
    "/bin/bash --noprofile --norc -euo pipefail {0}",
)
REVIEWED_GITHUB_ACTIONS = {
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87",
    "dtolnay/rust-toolchain@d1031067263f94b142dd6c0ce24c5eb9d02d52a0",
    "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
    "google/osv-scanner-action/osv-scanner-action@764c91816374ff2d8fc2095dab36eecd42d61638",
}
GITHUB_REVIEWED_RUNS = {
    "clippy-hardened": (
        "bash scripts/hardened-clippy.selftest.sh\npython3 scripts/hardened-clippy-score.test.py",
        "sudo apt-get update && sudo apt-get install -y clang cmake",
        "bash scripts/hardened-clippy.sh",
    ),
    "osv-scanner": (),
    "secret-scan": (
        'CI_TOOLS_BIN="$HOME/.local/bin" bash scripts/ci-install-scanner.sh gitleaks',
        "bash scripts/scan-secrets.sh tree",
    ),
    "secret-history-scan": (
        'CI_TOOLS_BIN="$HOME/.local/bin" bash scripts/ci-install-scanner.sh gitleaks',
        "bash scripts/scan-secrets.sh history",
        "python3 scripts/scan-secrets.test.py",
    ),
    "cargo-audit": (
        "cargo install cargo-audit --version 0.22.2 --locked",
        "bash scripts/audit-all-lockfiles.sh",
    ),
    "cargo-deny": (
        "cargo install cargo-deny --version 0.20.2 --locked",
        "cargo deny check advisories bans licenses sources",
    ),
    "scanners-blocking-guard": (
        "python3 scripts/ci-install-scanner.test.py",
        "python3 scripts/check-scanners-blocking.selftest.py",
        "python3 scripts/check-scanners-blocking.py",
    ),
    "rollback-package-integrity": (
        "sudo apt-get update && sudo apt-get install -y minisign",
        "bash deploy/rollback/make-rollback-package.selftest.sh",
    ),
}
GITHUB_STATE_CHANNEL = re.compile(
    r"GITHUB_(?:PATH|ENV)\b|github\.(?:path|env)\b|::(?:add-path|set-env)\b",
    re.IGNORECASE,
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


def explicit_execution_values(body: list[str], job_indent: int, label: str) -> list[str]:
    """Return only locally visible commands/actions in the supported subset.

    This intentionally is not a general YAML parser. Indentation binds
    evidence to GitLab `script:` list items or GitHub step `run:`/`uses:`
    fields. Block/folded scalars are joined so a multi-line scanner invocation
    is one value. Everything else (name/env/variables/comments) is ignored.
    """
    values: list[str] = []
    index = 0
    in_gitlab_script = False
    while index < len(body):
        line = body[index]
        spaces = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        value: str | None = None
        field_indent = spaces

        if label == ".gitlab-ci.yml":
            if spaces == job_indent + 2:
                in_gitlab_script = stripped == "script:"
            elif in_gitlab_script and spaces == job_indent + 4 and stripped.startswith("- "):
                value = stripped[2:].strip()
        else:
            if spaces == job_indent + 4 and stripped.startswith(("- run:", "- uses:")):
                value = stripped.split(":", 1)[1].strip()
            elif spaces == job_indent + 6 and stripped.startswith(("run:", "uses:")):
                value = stripped.split(":", 1)[1].strip()

        index += 1
        if value is None:
            continue
        if value in ("|", "|-", "|+", ">", ">-", ">+"):
            continuation: list[str] = []
            while index < len(body):
                candidate = body[index]
                candidate_indent = len(candidate) - len(candidate.lstrip(" "))
                if candidate_indent <= field_indent:
                    break
                continuation.append(candidate.strip())
                index += 1
            value = " ".join(continuation)
        # Inline YAML comments annotate pinned actions in the real workflow;
        # they are metadata, not part of the executable value.
        value = re.sub(r"\s+#.*$", "", value).strip()
        values.append(value.strip("\"'"))
    return values


def github_run_values(body: list[str], job_indent: int) -> list[str]:
    """Extract ordered explicit run values, excluding names/actions/inputs."""
    values = []
    index = 0
    while index < len(body):
        line = body[index]
        spaces = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        value = None
        field_indent = spaces
        if spaces == job_indent + 4 and stripped.startswith("- run:"):
            value = stripped[len("- run:"):].strip()
        elif spaces == job_indent + 6 and stripped.startswith("run:"):
            value = stripped[len("run:"):].strip()
        index += 1
        if value is None:
            continue
        if value in ("|", "|-", "|+", ">", ">-", ">+"):
            separator = "\n" if value.startswith("|") else " "
            continuation = []
            while index < len(body):
                candidate = body[index]
                candidate_indent = len(candidate) - len(candidate.lstrip(" "))
                if candidate_indent <= field_indent:
                    break
                continuation.append(candidate.strip())
                index += 1
            value = separator.join(continuation)
        value = re.sub(r"\s+#.*$", "", value).strip()
        values.append(value.strip("\"'"))
    return values


def github_action_input(
    body: list[str], job_indent: int, action: re.Pattern[str], input_name: str
) -> str | None:
    """Read one scalar input from the same explicit step as a pinned action."""
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

    for step in steps:
        action_value = None
        for line in step:
            spaces = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            if spaces == step_indent and stripped.startswith("- uses:"):
                action_value = stripped.split(":", 1)[1].strip()
            elif spaces == step_indent + 2 and stripped.startswith("uses:"):
                action_value = stripped.split(":", 1)[1].strip()
        if action_value is None:
            continue
        action_value = re.sub(r"\s+#.*$", "", action_value).strip(" \"'")
        if not action.fullmatch(action_value):
            continue

        in_with = False
        index = 0
        while index < len(step):
            line = step[index]
            spaces = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            if spaces == step_indent + 2:
                in_with = stripped == "with:"
            if in_with and spaces == step_indent + 4:
                match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", stripped)
                if match and match.group(1) == input_name:
                    value = match.group(2).strip()
                    index += 1
                    if value in ("|", "|-", "|+", ">", ">-", ">+"):
                        continuation = []
                        while index < len(step):
                            candidate = step[index]
                            candidate_indent = len(candidate) - len(candidate.lstrip(" "))
                            if candidate_indent <= spaces:
                                break
                            continuation.append(candidate.strip())
                            index += 1
                        return " ".join(continuation)
                    return re.sub(r"\s+#.*$", "", value).strip(" \"'")
            index += 1
    return None


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
                    value = re.sub(r"\s+#.*$", "", match.group(2)).strip(" \"'")
                    inputs[match.group(1)] = value
        if action is not None:
            action = re.sub(r"\s+#.*$", "", action).strip(" \"'")
            result.append((action, inputs))
    return result


def reviewed_action_inputs(job: str, action: str) -> dict[str, str]:
    if job == "osv-scanner" and action.startswith(
            "google/osv-scanner-action/osv-scanner-action@"):
        return {"scan-args": "*"}
    if job == "secret-history-scan" and action.startswith("actions/checkout@"):
        return {"fetch-depth": "0"}
    if job == "clippy-hardened" and action.startswith("dtolnay/rust-toolchain@"):
        return {"toolchain": "1.94.1", "components": "clippy"}
    return {}


def tracked_lockfiles(manifest: str | None) -> tuple[list[str], str | None]:
    """Return the canonical tracked Cargo.lock set, or a fail-closed error.

    The manifest seam exists only for adversarial self-tests. Checked-in CI is
    constrained to the argument-free guard invocation and therefore always
    reads the repository index directly.
    """
    if manifest is not None:
        try:
            with open(manifest, encoding="utf-8") as fh:
                values = fh.read().splitlines()
        except OSError as exc:
            return [], "cannot read tracked-lockfile fixture: %s" % exc
    else:
        try:
            proc = subprocess.run(
                ["git", "-C", REPO, "ls-files", "-z", "--", "Cargo.lock",
                 ":(glob)**/Cargo.lock"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except OSError as exc:
            return [], "cannot execute git for tracked lockfile discovery: %s" % exc
        if proc.returncode != 0:
            return [], "git tracked-lockfile discovery failed"
        try:
            values = [item for item in proc.stdout.decode("utf-8").split("\0") if item]
        except UnicodeDecodeError:
            return [], "git returned a non-UTF-8 tracked lockfile path"

    if not values:
        return [], "tracked Cargo.lock set is empty"
    if len(values) != len(set(values)):
        return [], "tracked Cargo.lock set contains duplicates"
    for value in values:
        parts = value.split("/")
        if (not value or value.startswith("/") or ".." in parts
                or parts[-1] != "Cargo.lock"):
            return [], "invalid tracked Cargo.lock path: %r" % value
    return sorted(values), None


def normalized_yaml_lines(lines: list[str]) -> tuple[str, ...]:
    return tuple(
        re.sub(r"\s+#.*$", "", line.strip())
        for line in lines
        if re.sub(r"\s+#.*$", "", line.strip()))


REVIEWED_GITHUB_TRIGGERS = (
    "push:",
    'branches: [main, "euvm/**"]',
    "pull_request:",
    "workflow_dispatch:",
)


def protected_global_key_problems(
    text: str, key: str, label: str, *, required: bool
) -> list[str]:
    """Reject quoted/duplicate global execution-context keys."""
    protected = [
        match.group("quote")
        for line in text.splitlines()
        if (match := re.match(
            r"^(?P<quote>['\"]?)%s(?P=quote)\s*:" % re.escape(key), line))
    ]
    valid_count = len(protected) == 1 if required else len(protected) <= 1
    if not valid_count or any(protected):
        cardinality = "exactly once" if required else "at most once"
        return [
            f"{label}: protected top-level `{key}:` key must occur {cardinality} "
            "in the supported plain-key form"
        ]
    return []


def check_gitlab_global_context(text: str, blocks: dict[str, list[str]]) -> list[str]:
    """Restrict inherited GitLab execution context to the reviewed subset."""
    problems = []
    problems += protected_global_key_problems(
        text, "default", ".gitlab-ci.yml", required=True)
    problems += protected_global_key_problems(
        text, "variables", ".gitlab-ci.yml", required=True)
    occurrences = [
        match.group(1)
        for line in text.splitlines()
        if (match := re.match(
            r"^(default|variables|before_script|after_script|hooks|image|services|cache):", line))
    ]
    present = set(occurrences)
    for key in ("before_script", "after_script", "hooks", "image", "services", "cache"):
        if key in present:
            problems.append(
                ".gitlab-ci.yml: top-level `%s:` is outside the supported "
                "inherited execution context" % key)
    if (occurrences.count("default") != 1 or "default" not in blocks
            or normalized_yaml_lines(blocks["default"]) != SAFE_GITLAB_DEFAULT):
        problems.append(
            ".gitlab-ci.yml: `default:` must occur exactly once and match the "
            "reviewed runner tags and fail-fast before_script")
    if (occurrences.count("variables") != 1 or "variables" not in blocks
            or normalized_yaml_lines(blocks["variables"]) != SAFE_GITLAB_VARIABLES):
        problems.append(
            ".gitlab-ci.yml: top-level `variables:` must occur exactly once and "
            "match the reviewed non-execution-affecting subset")
    return problems


def check_gitlab_job_context(body: list[str], job: str, indent: int) -> list[str]:
    problems = []
    index = 0
    while index < len(body):
        line = body[index]
        spaces = len(line) - len(line.lstrip(" "))
        value = re.sub(r"\s+#.*$", "", line.strip())
        if spaces != indent + 2:
            index += 1
            continue
        key = value.split(":", 1)[0]
        if key == "before_script":
            problems.append(
                ".gitlab-ci.yml: job `%s` overrides the reviewed inherited `before_script:`" % job)
        elif key in ("after_script", "hooks", "image", "services", "cache",
                     "artifacts", "dependencies", "needs"):
            problems.append(
                ".gitlab-ci.yml: job `%s` uses unsupported `%s:` context" % (job, key))
        elif key == "variables":
            nested = []
            scan = index + 1
            while scan < len(body):
                candidate = body[scan]
                if len(candidate) - len(candidate.lstrip(" ")) <= indent + 2:
                    break
                nested.append(candidate)
                scan += 1
            expected = ('GIT_DEPTH: "0"',) if job == "secret-history-scan" else ()
            if value != "variables:" or normalized_yaml_lines(nested) != expected:
                problems.append(
                    ".gitlab-ci.yml: job `%s` has unreviewed execution variables" % job)
        index += 1
    return problems


def check_file(
    path: str,
    required: dict[str, str],
    indent: int,
    label: str,
    tracked: list[str],
) -> list[str]:
    if not os.path.exists(path):
        return ["%s: MISSING — the pipeline definition itself is gone" % label]
    text = open(path, encoding="utf-8").read()
    blocks = job_blocks(text, indent)
    problems: list[str] = []
    if label == ".gitlab-ci.yml":
        top_level = job_blocks(text, 0)
        problems += check_gitlab_global_context(text, top_level)
        for line in text.splitlines():
            if re.match(r"^(?:include|workflow):(?:\s|$)", line):
                key = line.split(":", 1)[0]
                problems.append(
                    "%s: top-level `%s:` moves pipeline semantics outside the "
                    "locally inspectable blocking subset" % (label, key))
    if label == ".github/workflows/security.yml":
        problems += protected_global_key_problems(
            text, "defaults", label, required=True)
        problems += protected_global_key_problems(
            text, "env", label, required=False)
        problems += protected_global_key_problems(
            text, "on", label, required=True)
        problems += protected_global_key_problems(
            text, "permissions", label, required=True)
        top_level = job_blocks(text, 0)
        default_count = sum(
            bool(re.match(r"^defaults:\s*(?:#.*)?$", line))
            for line in text.splitlines())
        if (default_count != 1 or "defaults" not in top_level
                or normalized_yaml_lines(top_level["defaults"]) != SAFE_GITHUB_DEFAULTS):
            problems.append(
                "%s: top-level `defaults:` must occur exactly once and match "
                "the reviewed environment-clearing run shell"
                % label)
        trigger_lines = top_level.get("on")
        if trigger_lines is None:
            problems.append(
                "%s: top-level `on:` trigger block is missing or not in the "
                "supported explicit mapping form" % label)
        else:
            triggers = set()
            for line in trigger_lines:
                match = re.match(r"^  ([A-Za-z0-9_-]+):(?:\s|$)", line)
                if match:
                    triggers.add(match.group(1))
            for trigger in ("push", "pull_request"):
                if trigger not in triggers:
                    problems.append(
                        "%s: required top-level `%s:` trigger is missing"
                        % (label, trigger))
            if "pull_request_target" in triggers:
                problems.append(
                    "%s: privileged `pull_request_target:` is outside the "
                    "supported security-workflow trigger subset" % label)
            if normalized_yaml_lines(trigger_lines) != REVIEWED_GITHUB_TRIGGERS:
                problems.append(
                    "%s: top-level `on:` must match the reviewed exact trigger mapping"
                    % label)
        permission_lines = top_level.get("permissions")
        if permission_lines is None:
            problems.append(
                "%s: explicit top-level read-only `permissions:` block is missing"
                % label)
        else:
            permissions = {}
            for line in permission_lines:
                match = re.match(
                    r"^  ([A-Za-z0-9_-]+):\s*([^\s#]+)", line)
                if match:
                    permissions[match.group(1)] = match.group(2).strip("\"'").lower()
            if permissions.get("contents") != "read":
                problems.append(
                    "%s: top-level `permissions:` must explicitly set `contents: read`"
                    % label)
            for scope, access in sorted(permissions.items()):
                if access not in {"read", "none"}:
                    problems.append(
                        "%s: top-level permission `%s: %s` is write-capable or unsupported"
                        % (label, scope, access))
            if normalized_yaml_lines(permission_lines) != ("contents: read",):
                problems.append(
                    "%s: top-level `permissions:` must be exactly `contents: read`"
                    % label)
        env_lines = top_level.get("env")
        env_present = any(re.match(r"^env:", line) for line in text.splitlines())
        if env_present and (env_lines is None
                or normalized_yaml_lines(env_lines) != SAFE_GITHUB_ENV):
            problems.append(
                "%s: top-level `env:` differs from the reviewed inert subset"
                % label)
    for job, why in sorted(required.items()):
        protected = [
            match.group("quote")
            for line in text.splitlines()
            if (match := re.match(
                r"^ {%d}(?P<quote>['\"]?)%s(?P=quote)\s*:"
                % (indent, re.escape(job)), line))
        ]
        if len(protected) != 1 or protected[0]:
            problems.append(
                "%s: protected `%s:` job key must occur exactly once in the "
                "supported plain-key form" % (label, job))
        if job not in blocks:
            problems.append(
                "%s: job `%s` is MISSING (%s). A gate that was deleted is not a "
                "gate that passed." % (label, job, why))
            continue
        verdicts = GITLAB_VERDICTS if label == ".gitlab-ci.yml" else GITHUB_VERDICTS
        if label == ".gitlab-ci.yml":
            problems += check_gitlab_job_context(blocks[job], job, indent)
        executable = explicit_execution_values(blocks[job], indent, label)
        if label == ".github/workflows/security.yml":
            runs = tuple(github_run_values(blocks[job], indent))
            if runs != GITHUB_REVIEWED_RUNS[job]:
                problems.append(
                    "%s: job `%s` (%s) run steps differ from the reviewed "
                    "ordered command list"
                    % (label, job, why))
            if any(GITHUB_STATE_CHANNEL.search(value) for value in executable):
                problems.append(
                    "%s: job `%s` (%s) writes a cross-step environment/PATH "
                    "channel that can replace a required executable"
                    % (label, job, why))
            for action, inputs in github_action_steps(blocks[job], indent):
                if action not in REVIEWED_GITHUB_ACTIONS:
                    problems.append(
                        "%s: job `%s` (%s) invokes unreviewed or mutable action `%s`"
                        % (label, job, why, action))
                    continue
                expected_inputs = reviewed_action_inputs(job, action)
                if (expected_inputs == {"scan-args": "*"}
                        and set(inputs) != {"scan-args"}) or (
                        expected_inputs != {"scan-args": "*"}
                        and inputs != expected_inputs):
                    problems.append(
                        "%s: job `%s` action `%s` has unreviewed `with:` inputs"
                        % (label, job, action))
        # A required verdict must be a direct command/action, not one operand
        # of a compound shell expression that can replace its exit status.
        def has_direct_entrypoint(pattern: re.Pattern[str]) -> bool:
            return any(
                pattern.search(value)
                and not re.search(r"(?:\|\||&&|[;|&]|\$\(|`)", value)
                for value in executable)

        has_verdict = has_direct_entrypoint(verdicts[job])
        if not has_verdict:
            problems.append(
                "%s: job `%s` (%s) no longer executes its required verdict "
                "in an explicit local script/run/uses field"
                % (label, job, why))
        companion = SELFTEST_VERDICTS.get(job)
        if companion is not None and not has_direct_entrypoint(companion):
            problems.append(
                "%s: job `%s` (%s) no longer executes the adversarial "
                "self-test that proves its guard can fail"
                % (label, job, why))
        if label == ".github/workflows/security.yml" and job == "osv-scanner":
            scan_args = github_action_input(
                blocks[job], indent, GITHUB_VERDICTS[job], "scan-args")
            try:
                tokens = shlex.split(scan_args, comments=True) if scan_args is not None else []
            except ValueError:
                tokens = []
            required_args = ["--config=osv-scanner.toml"] + [
                "--lockfile=" + path for path in tracked]
            if (len(tokens) != len(required_args)
                    or set(tokens) != set(required_args)):
                problems.append(
                    "%s: job `%s` must give the pinned action the exact reviewed "
                    "config and complete lockfile scan scope"
                    % (label, job))
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
            if (label == ".github/workflows/security.yml"
                    and re.match(r"^(?:defaults|shell):", value)):
                problems.append(
                    "%s: job `%s` (%s) uses custom shell/defaults; the "
                    "supported subset requires the runner's fail-fast shell"
                    % (label, job, why))
            if (label == ".github/workflows/security.yml"
                    and re.match(r"^(?:env|container|services):", value)):
                problems.append(
                    "%s: job `%s` (%s) uses environment/container/service "
                    "context that can replace a required executable"
                    % (label, job, why))
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
                    and re.match(r"^(?:['\"]?)permissions(?:['\"]?)\s*:", value)):
                problems.append(
                    "%s: job `%s` (%s) has a job-level permissions override; "
                    "required scanners must inherit the checked read-only posture"
                    % (label, job, why))
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
    ap.add_argument("--tracked-lockfiles", help=argparse.SUPPRESS)
    args = ap.parse_args()

    problems = []
    tracked, discovery_error = tracked_lockfiles(args.tracked_lockfiles)
    if discovery_error is not None:
        problems.append("repository index: " + discovery_error)
    problems += check_file(args.gitlab, GITLAB_REQUIRED, 0, ".gitlab-ci.yml", tracked)
    problems += check_file(args.github, GITHUB_REQUIRED, 2, ".github/workflows/security.yml", tracked)

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
