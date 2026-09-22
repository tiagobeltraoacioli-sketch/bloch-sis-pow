#!/usr/bin/env python3
"""Fail if the live PoS node reaches a retired Genesis-3 consensus crate.

Normal dependencies are linked into the live package, while build dependencies
execute as part of producing it; both are therefore inside this guard's trust
boundary. Development-only dependencies do not contribute to a production
build and are deliberately excluded from the inspected Cargo tree.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


LIVE_PACKAGE = "bloch-pos-node"
FORBIDDEN = {"bloch", "bloch-euvm", "bloch-ffg"}


TREE_LINE = re.compile(r"^(?P<depth>[0-9]+)@@(?P<name>[^ ]+) (?:v[^ ]+)(?: |$)")


def cargo_tree_command() -> list[str]:
    """Return the reviewed feature-scoped production/build dependency query."""
    return [
        "cargo",
        "tree",
        "--quiet",
        "--locked",
        "--offline",
        "--package",
        LIVE_PACKAGE,
        "--edges",
        "normal,build",
        "--target",
        "all",
        "--prefix",
        "depth",
        "--format",
        "@@{p}",
    ]


def dependency_path(tree: str, live: str, forbidden: set[str]) -> list[str] | None:
    """Return the first live→forbidden path from a depth-prefixed Cargo tree."""
    stack: list[str] = []
    saw_root = False
    for raw_line in tree.splitlines():
        if not raw_line:
            continue
        match = TREE_LINE.match(raw_line)
        if match is None:
            raise ValueError(f"unrecognised cargo tree line: {raw_line!r}")
        depth = int(match.group("depth"))
        name = match.group("name")
        if depth == 0:
            if saw_root or name != live:
                raise ValueError(f"expected exactly one root named {live!r}")
            saw_root = True
            stack = [name]
            continue
        if not saw_root or depth > len(stack):
            raise ValueError(f"invalid cargo tree depth {depth} for package {name!r}")
        stack = [*stack[:depth], name]
        if name in forbidden:
            return stack
    if not saw_root:
        raise ValueError(f"expected exactly one root named {live!r}")
    return None


def selftest() -> None:
    clean = "0@@bloch-pos-node v1\n1@@sha3 v1\n"
    direct = "0@@bloch-pos-node v1\n1@@bloch-euvm v1\n"
    transitive = "0@@bloch-pos-node v1\n1@@adapter v1\n2@@bloch-ffg v1\n"
    assert dependency_path(clean, LIVE_PACKAGE, FORBIDDEN) is None
    assert dependency_path(direct, LIVE_PACKAGE, FORBIDDEN) == [
        LIVE_PACKAGE,
        "bloch-euvm",
    ]
    assert dependency_path(transitive, LIVE_PACKAGE, FORBIDDEN) == [
        LIVE_PACKAGE,
        "adapter",
        "bloch-ffg",
    ]
    try:
        dependency_path("0@@other v1\n", LIVE_PACKAGE, FORBIDDEN)
    except ValueError:
        pass
    else:
        raise AssertionError("missing live package must fail closed")
    try:
        dependency_path("0@@bloch-pos-node v1\n2@@sha3 v1\n", LIVE_PACKAGE, FORBIDDEN)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed scoped tree must fail closed")
    # Regression: an unrelated workspace member may enable an optional feature
    # on bloch-pos-committee.  `cargo metadata` then reports bloch-euvm in its
    # workspace-unified resolve graph even though the node's own feature-scoped
    # tree (the shape below) does not contain it.
    workspace_unified_but_node_clean = (
        "0@@bloch-pos-node v1\n1@@bloch-pos-committee v1\n1@@sha3 v1\n"
    )
    assert dependency_path(workspace_unified_but_node_clean, LIVE_PACKAGE, FORBIDDEN) is None
    command = cargo_tree_command()
    edge_index = command.index("--edges")
    assert command[edge_index + 1] == "normal,build"
    assert "dev" not in command[edge_index + 1].split(",")
    print(
        "retired-isolation selftest: OK — clean, direct, transitive, malformed, "
        "missing-root, workspace-feature-unification and normal+build edge cases"
    )


def load_tree(path: Path | None) -> str:
    if path is not None:
        return path.read_text(encoding="utf-8")
    result = subprocess.run(
        cargo_tree_command(),
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, help="read depth-prefixed cargo tree output")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0

    try:
        path = dependency_path(load_tree(args.tree), LIVE_PACKAGE, FORBIDDEN)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"retired-isolation guard could not establish the graph: {error}", file=sys.stderr)
        return 2
    if path is not None:
        print(
            "retired-isolation guard: FAIL — live binary reaches retired consensus: "
            + " -> ".join(path),
            file=sys.stderr,
        )
        return 1
    print(
        "retired-isolation guard: OK — bloch-pos-node reaches none of "
        + ", ".join(sorted(FORBIDDEN))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
