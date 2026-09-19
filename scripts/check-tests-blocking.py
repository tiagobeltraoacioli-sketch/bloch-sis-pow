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
Reads both CI files as text (no PyYAML on the runners) and holds the GitHub
`.github/workflows/tests.yml` jobs `cargo-test` and `tests-blocking-guard`, plus
GitLab `.gitlab-ci.yml` job `build-and-test`, to the reviewed posture:

  * the job EXISTS — a deleted gate must not read as a passing gate;
  * it runs `cargo test`;
  * every LIVE crate below is named in the reviewed exact test command;
  * it has a timeout (`timeout-minutes:` / `timeout:`) — a job that can hang
    forever gates by luck, not by verdict;
  * it carries no escape hatch: `allow_failure: true`, `continue-on-error:
    true`, an `exit 0` skip, `when: manual`, or a GitHub custom/default shell
    that can replace the test script's exit status.
  * its GitLab inherited `default:`/`variables:` context remains the reviewed
    explicit subset, exactly once, with no job-local script hooks or execution
    variables. The `build-and-test` header and complete ordered script match
    the reviewed whole-job contract.
  * its GitHub environment is the reviewed inert pair and its exact global
    run shell clears inherited shell/Python/Rust substitution variables while
    replacing PATH; required jobs use no containers/services/env overrides,
    and every action plus input is a reviewed immutable form.
  * no required GitHub run step writes the cross-step PATH/environment command
    files that can replace `cargo` before the approved test command.
  * the `cargo-test` job's setup, rehearsals and test commands exactly match
    the reviewed ordered run-step list and YAML block semantics.
  * the validator-lifecycle mutation check is blocking in both pipelines;
    removing it from either reviewed job fails the corresponding contract.
  * the funded validator-admission rehearsal is blocking in both pipelines;
    removing it from either reviewed job fails independently.
  * the finite validator-activation boundary/replay rehearsal is blocking in
    both pipelines; removing it from either reviewed job fails independently.
  * the independent-process funded-joining rehearsal is blocking in both
    pipelines; removing it from either reviewed job fails independently.
  * the `tests-blocking-guard` job has the reviewed runner/timeout and exact
    ordered checkout, selftest and guard/rehearsal command sequence on GitHub;
    GitLab runs the same posture, toolchain, partition-report, activation
    parser and attested-image remote-access tests under an exact blocking
    contract. This prevents the guard's own CI entrypoint from becoming a
    decorative literal.
  * local script entrypoints named directly by those commands, plus the
    reviewed transitively loaded executables, are regular non-symlink files
    whose SHA-256 content and parent/load relationships match the contract.
  * every reviewed Python CI command uses isolated mode (`python3 -I`), and
    this guard refuses to run unless its own interpreter reports that mode.
  * both repository Rust toolchain pins are parsed by the protected helper;
    GitHub installs that validated channel and GitLab validates it before its
    root-workspace Cargo invocations. The parser's adversarial test is gated.

The live-crate list is duplicated in `.github/workflows/tests.yml` on
purpose: the workflow states what it gates, this file makes dropping a crate
a red pipeline instead of a silent narrowing. Change both together, with a
written reason.

Deliberately blunt, like scripts/check-scanners-blocking.py: any `exit 0`
inside a gated job is refused, even a plausible-looking one.

Pure Python 3. No toolchain, no build, no network.

Run: python3 -I scripts/check-tests-blocking.py
Exit 0 = the supported explicit job/command subset passes these checks.
This is a structural regression guard, not a proof for arbitrary YAML,
workflow inheritance, branch protection, or shell execution semantics.
"""

from __future__ import annotations

import argparse
import hashlib
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
GITHUB_CARGO_TEST_RUNS = (
    'ch="$(python3 -I scripts/pinned-rust-toolchain.py)"\n'
    'rustup toolchain install "$ch" --profile minimal --no-self-update\n'
    'echo "toolchain=$ch" >> "$GITHUB_OUTPUT"',
    "sudo apt-get update && sudo apt-get install -y clang cmake",
    "python3 -I scripts/rehearse-validator-admission.py",
    "python3 -I scripts/check-validator-lifecycle-mutations.py",
    "bash deploy/bootnodes/verify-bootnodes.selftest.sh",
    "python3 -I scripts/check-live-node-retired-isolation.py --selftest\n"
    "python3 -I scripts/check-live-node-retired-isolation.py",
    'python3 -I scripts/rehearse-validator-activation.py --output "$RUNNER_TEMP/validator-activation"',
    'python3 -I scripts/rehearse-validator-joining-network.py --output "$RUNNER_TEMP/validator-joining-network"',
    "cargo +${{ steps.pin.outputs.toolchain }} test --locked -p bloch-pos-node --bin bloch-pos audit_",
    "cargo +${{ steps.pin.outputs.toolchain }} test --locked -p pqcrypto-internals",
    "cargo +${{ steps.pin.outputs.toolchain }} test --locked \\\n"
    "-p bloch-pos-committee \\\n"
    "-p bloch-pos-node \\\n"
    "-p bloch-crypto \\\n"
    "-p coherence-core \\\n"
    "-p bloch-sis-pow \\\n"
    "-p bloch-pq-vault \\\n"
    "-p pqcrypto-internals \\\n"
    "-p genesis4-ceremony",
)
GITHUB_TEST_GUARD_STEPS = (
    ("uses", "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", ()),
    ("run", "python3 -I scripts/check-tests-blocking.selftest.py", ()),
    ("run", "python3 -I scripts/check-tests-blocking.py", ()),
    ("run", "python3 -I scripts/pinned-rust-toolchain.test.py", ()),
    ("run", "python3 -I scripts/devnet-particao-report.test.py", ()),
    ("run", "python3 -I scripts/rehearse-validator-activation.test.py", ()),
    ("run", "python3 -I scripts/check-attested-ssh.selftest.py", ()),
    ("run", "python3 -I scripts/check-attested-ssh.py", ()),
)
GITHUB_TEST_GUARD_HEADER = (
    "name: tests-blocking guard (blocking)",
    "runs-on: ubuntu-latest",
    "timeout-minutes: 10",
    "steps:",
)
GITLAB_TEST_GUARD_BODY = (
    "stage: check",
    "before_script: []",
    "script:",
    "- python3 -I scripts/check-tests-blocking.selftest.py",
    "- python3 -I scripts/check-tests-blocking.py",
    "- python3 -I scripts/pinned-rust-toolchain.test.py",
    "- python3 -I scripts/devnet-particao-report.test.py",
    "- python3 -I scripts/rehearse-validator-activation.test.py",
    "- python3 -I scripts/check-attested-ssh.selftest.py",
    "- python3 -I scripts/check-attested-ssh.py",
    "timeout: 10m",
    "allow_failure: false",
)
GITLAB_BUILD_TEST_HEADER = (
    "stage: test",
    "script:",
    "timeout: 120m",
)
GITLAB_BUILD_TEST_SCRIPT = (
    "bash deploy/bootnodes/verify-bootnodes.selftest.sh",
    "python3 -I scripts/check-live-node-retired-isolation.py --selftest",
    "python3 -I scripts/check-live-node-retired-isolation.py",
    "python3 -I scripts/pinned-rust-toolchain.py",
    "python3 -I scripts/rehearse-validator-admission.py",
    "python3 -I scripts/check-validator-lifecycle-mutations.py",
    'python3 -I scripts/rehearse-validator-activation.py --output "$CI_PROJECT_DIR/.ci-validator-activation"',
    'python3 -I scripts/rehearse-validator-joining-network.py --output "$CI_PROJECT_DIR/.ci-validator-joining-network"',
    "cargo build --workspace --all-targets",
    "cargo test --locked -p bloch-pos-committee -p bloch-pos-node "
    "-p bloch-crypto -p coherence-core -p bloch-sis-pow -p bloch-pq-vault "
    "-p pqcrypto-internals -p genesis4-ceremony",
)
GITLAB_BUILD_TEST_BODY = (
    "stage: test",
    "script:",
    "- bash deploy/bootnodes/verify-bootnodes.selftest.sh",
    "- python3 -I scripts/check-live-node-retired-isolation.py --selftest",
    "- python3 -I scripts/check-live-node-retired-isolation.py",
    "- python3 -I scripts/pinned-rust-toolchain.py",
    "- python3 -I scripts/rehearse-validator-admission.py",
    "- python3 -I scripts/check-validator-lifecycle-mutations.py",
    '- python3 -I scripts/rehearse-validator-activation.py --output "$CI_PROJECT_DIR/.ci-validator-activation"',
    '- python3 -I scripts/rehearse-validator-joining-network.py --output "$CI_PROJECT_DIR/.ci-validator-joining-network"',
    "- cargo build --workspace --all-targets",
    "- cargo test --locked -p bloch-pos-committee -p bloch-pos-node "
    "-p bloch-crypto -p coherence-core -p bloch-sis-pow -p bloch-pq-vault "
    "-p pqcrypto-internals -p genesis4-ceremony",
    "timeout: 120m",
)
CI_SCRIPT_ENTRYPOINT_SHA256 = {
    "deploy/bootnodes/verify-bootnodes.sh":
        "151e6f8e621d2be1cadeacc31eac7d385fe660ea73b1a028435ef1d0c56952c0",
    "deploy/bootnodes/verify-bootnodes.selftest.sh":
        "95bb6c90d395f9a706f8349eede35330afd4b62e5979497fcaecc5410f0b3612",
    "scripts/check-attested-ssh.py":
        "c684c6adc23b1286a68c8205b0540a0b3673942d3e798e71a37e7be531fba602",
    "scripts/check-attested-ssh.selftest.py":
        "16245f0a98bf1ad1ea49ea930cbc1e3edd175f476617d7aee105c15ac4a6e9ac",
    "scripts/check-live-node-retired-isolation.py":
        "45ece7368931469c2c64c161708009b41aebcbf3c1033fa75006e16d5e16518d",
    "scripts/check-tests-blocking.selftest.py":
        "65d74422b1a7562128875326d7131ed6104003717910e364c60063902dc3974a",
    "scripts/check-validator-lifecycle-mutations.py":
        "12b477e5043bc3ea98387be33ca586976494b30083522b214cea7d88c0e9f429",
    "scripts/devnet-particao-report.test.py":
        "a2416dba17ddb42a97ab83d2a71d55d746a0c5ac8989d1ba07f494ec969f71b6",
    "scripts/devnet-particao.sh":
        "de0b39b7bfd7baf0da6ddab10d55b62c3a5371a262ac2f5cc38f8a5759ed5e2d",
    "scripts/pinned-rust-toolchain.py":
        "8e0bf93355825f811b619da27a0667d7349105ca8e7a9bf5d5e31ee60bf5d205",
    "scripts/pinned-rust-toolchain.test.py":
        "83c030e986546e42269e0331fb3485484d3001e97e47baffc9666d401176ab39",
    "scripts/rehearse-validator-activation.py":
        "e2e527bb71046fb20b88003403b8cca633581839974a7ddb7f8e314e36d33762",
    "scripts/rehearse-validator-activation.test.py":
        "3a1188041f8541d47a8132639d4675822dfbb23d7b40f4d016da86be798121c9",
    "scripts/rehearse-validator-admission.py":
        "2992e7e32d51406665b57f74debb74cba2c073c1f11f6e8db3c56faf6faf6b65",
    "scripts/rehearse-validator-joining-network.py":
        "fb3b69d21805a6361d0737d64c50a225cf7a9d0389e954b8f0c0b049d99449e4",
}
CI_TRANSITIVE_ENTRYPOINT_REFERENCES = {
    "scripts/rehearse-validator-activation.py": (
        ("scripts/rehearse-validator-joining-network.py", "scripts/rehearse-validator-activation.py"),
    ),
    "deploy/bootnodes/verify-bootnodes.sh": (
        ("deploy/bootnodes/verify-bootnodes.selftest.sh", "verify-bootnodes.sh"),
    ),
    "scripts/devnet-particao.sh": (
        ("scripts/rehearse-validator-activation.py", "scripts/devnet-particao.sh"),
        ("scripts/devnet-particao-report.test.py", "devnet-particao.sh"),
    ),
    "scripts/pinned-rust-toolchain.py": (
        ("scripts/check-validator-lifecycle-mutations.py", "scripts/pinned-rust-toolchain.py"),
    ),
}

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
    "- unset BASH_ENV ENV PYTHONHOME PYTHONPATH CARGO_HOME RUSTUP_HOME "
    "RUSTUP_TOOLCHAIN RUSTC "
    "RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC "
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


def github_run_values(body: list[str], job_indent: int) -> list[str]:
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
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values.append(value)
    return values


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


def github_execution_steps(
    body: list[str], job_indent: int
) -> list[tuple[str, str, tuple[tuple[str, str], ...]]]:
    """Return one ordered signature for every GitHub step.

    A step with zero or multiple execution fields gets an explicit unsupported
    signature so it cannot disappear while an approved literal remains later.
    """
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
        actions = github_action_steps(step, job_indent)
        runs = github_run_values(step, job_indent)
        metadata = []
        for line in step:
            spaces = len(line) - len(line.lstrip(" "))
            value = line.strip()
            if spaces == step_indent and value.startswith("- "):
                value = value[2:]
            elif spaces != step_indent + 2:
                continue
            match = re.match(r"^([A-Za-z0-9_-]+):", value)
            if match:
                metadata.append(match.group(1))
        unsupported_metadata = set(metadata) - {"name", "run", "uses"}
        if len(actions) + len(runs) != 1 or unsupported_metadata:
            result.append(("unsupported", normalized_yaml_lines(step).__repr__(), ()))
        elif actions:
            action, inputs = actions[0]
            result.append(("uses", action, tuple(sorted(inputs.items()))))
        else:
            result.append(("run", runs[0], ()))
    return result


def check_github_test_guard(path: str) -> list[str]:
    """Bind the job that runs this guard to its complete execution contract."""
    label = ".github/workflows/tests.yml"
    job = "tests-blocking-guard"
    if not os.path.exists(path):
        return [f"{label}: MISSING — the pipeline definition itself is gone"]
    text = open(path, encoding="utf-8").read()
    blocks = job_blocks(text, 2)
    if job not in blocks:
        return [f"{label}: job `{job}` is MISSING. A guard that was deleted is not a guard that passed."]

    body = blocks[job]
    direct = tuple(
        re.sub(r"\s+#.*$", "", line.strip())
        for line in body
        if len(line) - len(line.lstrip(" ")) == 4
    )
    problems = []
    if direct != GITHUB_TEST_GUARD_HEADER:
        problems.append(
            f"{label}: job `{job}` header differs from the reviewed runner/timeout/steps contract")
    if tuple(github_execution_steps(body, 2)) != GITHUB_TEST_GUARD_STEPS:
        problems.append(
            f"{label}: job `{job}` execution steps differ from the reviewed exact ordered contract")
    return problems


def check_gitlab_test_guard(path: str) -> list[str]:
    """Bind GitLab's guard job to the reviewed cross-pipeline proof contract."""
    label = ".gitlab-ci.yml"
    job = "tests-blocking-guard"
    if not os.path.exists(path):
        return [f"{label}: MISSING — the pipeline definition itself is gone"]
    text = open(path, encoding="utf-8").read()
    blocks = job_blocks(text, 0)
    protected = [
        match.group("quote")
        for line in text.splitlines()
        if (match := re.match(
            r"^(?P<quote>['\"]?)tests-blocking-guard(?P=quote)\s*:", line))
    ]
    if (len(protected) != 1 or protected[0] or job not in blocks):
        return [
            f"{label}: protected `{job}:` key must occur exactly once in the "
            "supported plain-key form"
        ]
    body = blocks[job]
    problems = check_gitlab_job_context(body, job, 0)
    if normalized_yaml_lines(body) != GITLAB_TEST_GUARD_BODY:
        problems.append(
            f"{label}: job `{job}` differs from the reviewed exact blocking contract")
    return problems


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
    protected = [
        (match.group("key"), match.group("quote"))
        for line in text.splitlines()
        if (match := re.match(
            r"^(?P<quote>['\"]?)(?P<key>default|variables|build-and-test)"
            r"(?P=quote)\s*:", line))
    ]
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
    if sum(key == "default" for key, _ in protected) != 1 or any(
            key == "default" and quote for key, quote in protected) or (
            "default" not in blocks
            or normalized_yaml_lines(blocks["default"]) != SAFE_GITLAB_DEFAULT):
        problems.append(
            ".gitlab-ci.yml: `default:` must occur exactly once and match the "
            "reviewed runner tags and fail-fast before_script")
    if sum(key == "variables" for key, _ in protected) != 1 or any(
            key == "variables" and quote for key, quote in protected) or (
            "variables" not in blocks
            or normalized_yaml_lines(blocks["variables"]) != SAFE_GITLAB_VARIABLES):
        problems.append(
            ".gitlab-ci.yml: top-level `variables:` must occur exactly once and "
            "match the reviewed non-execution-affecting subset")
    if sum(key == "build-and-test" for key, _ in protected) != 1 or any(
            key == "build-and-test" and quote for key, quote in protected):
        problems.append(
            ".gitlab-ci.yml: protected `build-and-test:` key must occur exactly "
            "once in the supported plain-key form")
    return problems


def check_gitlab_build_contract(body: list[str]) -> list[str]:
    """Bind build-and-test to its entire reviewed header and ordered script."""
    direct = tuple(
        re.sub(r"\s+#.*$", "", line.strip())
        for line in body
        if len(line) - len(line.lstrip(" ")) == 2
    )
    problems = []
    if direct != GITLAB_BUILD_TEST_HEADER:
        problems.append(
            ".gitlab-ci.yml: job `build-and-test` header differs from the "
            "reviewed stage/script/timeout contract")
    if normalized_yaml_lines(body) != GITLAB_BUILD_TEST_BODY:
        problems.append(
            ".gitlab-ci.yml: job `build-and-test` YAML structure differs from "
            "the reviewed exact whole-job contract")
    commands = command_blocks(body, 0)
    if tuple(command for block in commands for command in block) != GITLAB_BUILD_TEST_SCRIPT:
        problems.append(
            ".gitlab-ci.yml: job `build-and-test` script differs from the "
            "reviewed exact ordered command contract")
    return problems


def check_ci_script_entrypoints(root: str) -> list[str]:
    """Require every non-self CI script entrypoint to match reviewed bytes."""
    commands = list(GITHUB_CARGO_TEST_RUNS) + list(GITLAB_BUILD_TEST_SCRIPT)
    commands += [value for kind, value, _ in GITHUB_TEST_GUARD_STEPS if kind == "run"]
    invoked = set()
    for command in commands:
        for line in command.splitlines():
            match = re.match(
                r"^(?:python3\s+-I|bash)\s+([A-Za-z0-9_./-]+)(?:\s|$)",
                line.strip())
            if match:
                invoked.add(match.group(1))

    # This checker cannot contain its own digest without an impossible
    # self-referential hash. Its behavior is instead proved by the selftest,
    # whose bytes are pinned here; the exact CI job runs selftest before guard.
    invoked.discard("scripts/check-tests-blocking.py")
    transitive = set(CI_TRANSITIVE_ENTRYPOINT_REFERENCES)
    declared = set(CI_SCRIPT_ENTRYPOINT_SHA256)
    problems = []
    covered = invoked | transitive
    if covered != declared:
        missing = sorted(covered - declared)
        stale = sorted(declared - covered)
        problems.append(
            "CI script digest scope differs from exact job contracts "
            f"(missing={missing}, stale={stale})")

    if transitive - set(CI_SCRIPT_ENTRYPOINT_SHA256):
        problems.append("transitive CI entrypoint references lack reviewed digests")

    for relative, expected in sorted(CI_SCRIPT_ENTRYPOINT_SHA256.items()):
        path = os.path.join(root, relative)
        component = root
        traverses_symlink = os.path.islink(component)
        for part in relative.split("/"):
            component = os.path.join(component, part)
            traverses_symlink = traverses_symlink or os.path.islink(component)
        if traverses_symlink:
            problems.append(
                f"CI script entrypoint `{relative}` is or traverses a symlink")
            continue
        if not os.path.isfile(path):
            problems.append(f"CI script entrypoint `{relative}` is MISSING or not a regular file")
            continue
        with open(path, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        if actual != expected:
            problems.append(
                f"CI script entrypoint `{relative}` digest differs from reviewed content")
    for dependency, references in sorted(CI_TRANSITIVE_ENTRYPOINT_REFERENCES.items()):
        for parent, literal in references:
            parent_path = os.path.join(root, parent)
            if os.path.isfile(parent_path) and not os.path.islink(parent_path):
                with open(parent_path, "r", encoding="utf-8") as fh:
                    source = fh.read()
                if literal not in source:
                    problems.append(
                        f"CI transitive entrypoint `{dependency}` lost reviewed reference in `{parent}`")
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
        problems += check_gitlab_build_contract(body)

    if label == ".github/workflows/tests.yml":
        top_level = job_blocks(text, 0)
        default_count = sum(
            bool(re.match(r"^defaults:\s*(?:#.*)?$", line))
            for line in text.splitlines())
        if (default_count != 1 or "defaults" not in top_level
                or normalized_yaml_lines(top_level["defaults"]) != SAFE_GITHUB_DEFAULTS):
            problems.append(
                f"{label}: top-level `defaults:` must occur exactly once and match "
                "the reviewed environment-clearing run shell")
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
        if tuple(github_run_values(body, indent)) != GITHUB_CARGO_TEST_RUNS:
            problems.append(
                f"{label}: job `{job}` run steps differ from the reviewed ordered command list")

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
    if not sys.flags.isolated:
        print("test-posture guard: FAIL — invoke with `python3 -I` isolated mode")
        return 1
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gitlab", default=os.path.join(REPO, ".gitlab-ci.yml"))
    ap.add_argument("--github", default=os.path.join(REPO, ".github/workflows/tests.yml"))
    ap.add_argument("--entrypoint-root", default=REPO,
                    help="repository root used for local entrypoint integrity checks")
    args = ap.parse_args()

    problems = []
    problems += check_job(args.gitlab, "build-and-test", 0, ".gitlab-ci.yml")
    problems += check_job(args.github, "cargo-test", 2, ".github/workflows/tests.yml")
    problems += check_github_test_guard(args.github)
    problems += check_gitlab_test_guard(args.gitlab)
    problems += check_ci_script_entrypoints(args.entrypoint_root)

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
