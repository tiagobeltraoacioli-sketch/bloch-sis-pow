#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check explicit deploy YAML image references without resolving registries.

Supported image scalars must end in an exact SHA-256 digest. Comments never
supply pins or exemptions. The only template exemption is the deliberately
non-pullable REPLACE_WITH_DIGEST_PINNED_IMAGE sentinel. The retired local
compose fixture may use bloch:latest only with an adjacent build declaration
and pull_policy: never in the same service.

This structural guard supports explicit mapping/list image fields and refuses
YAML anchors, aliases and merge keys rather than pretending to resolve
inheritance. Generated configurations, registry provenance and signatures
require separate release verification. It scans existing .yaml/.yml files
under deploy/, including nested files; it does not claim to scan only tracked
files.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO / "deploy"

IMAGE_RE = re.compile(r"^\s*(?:-\s+)?(?:image|\"image\"|'image'):\s*(.*?)\s*$")
DIGEST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:\-]*@sha256:[0-9a-fA-F]{64}")
PLACEHOLDER = "REPLACE_WITH_DIGEST_PINNED_IMAGE"
MERGE_KEY_RE = re.compile(r"(?:^|[\s\[\{,])<<\s*:")
# YAML anchor/alias tokens begin at a structural separator. Quoted and block
# scalar content is removed by yaml_line_views before this expression runs.
ANCHOR_ALIAS_RE = re.compile(r"(?:^|[\s:\[\{,])([&*])[^\s\[\]\{\},]+(?=$|[\s,\]\}])")
BLOCK_SCALAR_RE = re.compile(r"(?:^|:)\s*[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*$")


def find_yaml_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in (".yaml", ".yml"))


def yaml_line_views(line: str) -> tuple[str, str]:
    """Return uncommented text and an inheritance-token view.

    A `#` starts a comment only outside quotes. The structural view replaces
    quoted bytes with spaces, so text such as `"use *base"` is not treated as
    an alias while a real token after `"x#y"` remains visible. This is a small
    fail-closed lexer, not a YAML value resolver.
    """
    visible: list[str] = []
    structural: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote == '"':
            visible.append(char)
            structural.append(" ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if quote == "'":
            visible.append(char)
            structural.append(" ")
            if char == "'" and index + 1 < len(line) and line[index + 1] == "'":
                visible.append("'")
                structural.append(" ")
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char == "#":
            break
        visible.append(char)
        if char in ("'", '"'):
            quote = char
            structural.append(" ")
        else:
            structural.append(char)
        index += 1
    return "".join(visible).rstrip(), "".join(structural).rstrip()


def local_build_only(path: Path, lines: list[str], index: int, value: str) -> bool:
    if path.relative_to(REPO).as_posix() != "deploy/docker-compose.yml" or value != "bloch:latest":
        return False
    # Accepted local fixture shape: services are indented two spaces, their
    # properties four. Never borrow a build/pull policy from another service.
    if not lines[index].startswith("    image:"):
        return False
    start = index
    while start > 0:
        start -= 1
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[start]):
            break
        if lines[start].strip() and not lines[start].startswith(" "):
            return False
    end = index + 1
    while end < len(lines):
        if lines[end].strip() and not lines[end].startswith("    ") and not lines[end].lstrip().startswith("#"):
            break
        end += 1
    block = lines[start + 1:end]
    return (any(re.match(r"^    build:\s*(?:$|\{)", line) for line in block)
            and any(re.match(r"^    pull_policy:\s*never\s*$", line) for line in block))


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    # Keep comment-aware visible lines for the same-service local-build check.
    lines = [yaml_line_views(line)[0] for line in raw_lines]
    block_indent: int | None = None
    for index, raw_line in enumerate(raw_lines):
        if block_indent is not None:
            if not raw_line.strip():
                continue
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            if indent > block_indent:
                continue
            block_indent = None

        line, structural = yaml_line_views(raw_line)
        begins_block = BLOCK_SCALAR_RE.search(structural) is not None
        if MERGE_KEY_RE.search(structural) or ANCHOR_ALIAS_RE.search(structural):
            problems.append(
                f"{path.relative_to(REPO)}:{index + 1}: unsupported YAML inheritance; "
                "expand anchors/aliases before image-pin review"
            )
            if begins_block:
                block_indent = len(raw_line) - len(raw_line.lstrip(" "))
            continue
        m = IMAGE_RE.match(line)
        if not m:
            if re.search(r"\bimage[\"']?\s*:", line):
                problems.append(f"{path.relative_to(REPO)}:{index + 1}: unsupported image mapping syntax")
            if begins_block:
                block_indent = len(raw_line) - len(raw_line.lstrip(" "))
            continue
        value = m.group(1)
        if len(value) >= 2 and value[0] in ("'", '\"') and value[-1] == value[0]:
            value = value[1:-1]
        if DIGEST_RE.fullmatch(value) or value == PLACEHOLDER or local_build_only(path, lines, index, value):
            if begins_block:
                block_indent = len(raw_line) - len(raw_line.lstrip(" "))
            continue
        problems.append(f"{path.relative_to(REPO)}:{index + 1}: image `{value}` has no @sha256 digest pin")
        if begins_block:
            block_indent = len(raw_line) - len(raw_line.lstrip(" "))
    return problems


def main() -> int:
    if not DEPLOY_DIR.is_dir():
        print("check-deploy-image-pins: FAIL — deploy/ does not exist", file=sys.stderr)
        return 1

    files = find_yaml_files(DEPLOY_DIR)
    problems: list[str] = []
    for f in files:
        problems += check_file(f)

    if problems:
        print("check-deploy-image-pins: FAIL — %d unpinned image(s)\n" % len(problems))
        for p in problems:
            print("  * %s" % p)
        print("\nUse an exact digest, the non-pullable template sentinel, or the reviewed local build fixture with pull_policy: never.")
        return 1

    print(
        "check-deploy-image-pins: OK — every deploy/ image: reference is "
        "pinned or explicitly non-pullable (%d file(s) scanned)" % len(files)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
