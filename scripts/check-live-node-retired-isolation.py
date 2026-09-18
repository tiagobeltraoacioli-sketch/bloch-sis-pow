#!/usr/bin/env python3
"""Fail if the live PoS node reaches a retired Genesis-3 consensus crate."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import deque
from pathlib import Path


LIVE_PACKAGE = "bloch-pos-node"
FORBIDDEN = {"bloch", "bloch-euvm", "bloch-ffg"}


def dependency_path(metadata: dict, live: str, forbidden: set[str]) -> list[str] | None:
    """Return the first live→forbidden package-name path, if one exists."""
    names = {package["id"]: package["name"] for package in metadata.get("packages", [])}
    nodes = {node["id"]: node for node in metadata.get("resolve", {}).get("nodes", [])}
    roots = [package_id for package_id, name in names.items() if name == live]
    if len(roots) != 1:
        raise ValueError(f"expected exactly one package named {live!r}, found {len(roots)}")

    root = roots[0]
    queue = deque([(root, [root])])
    seen = {root}
    while queue:
        package_id, path = queue.popleft()
        if package_id != root and names.get(package_id) in forbidden:
            return [names.get(item, item) for item in path]
        node = nodes.get(package_id)
        if node is None:
            raise ValueError(f"resolve graph has no node for {package_id!r}")
        dependencies = [dep["pkg"] for dep in node.get("deps", [])]
        # Cargo metadata v1 also carries the package IDs in `dependencies`.
        # Accept it in synthetic fixtures and older Cargo output.
        if not dependencies:
            dependencies = node.get("dependencies", [])
        for dependency in dependencies:
            if dependency not in seen:
                seen.add(dependency)
                queue.append((dependency, [*path, dependency]))
    return None


def fixture(edges: dict[str, list[str]]) -> dict:
    packages = [{"id": name, "name": name} for name in edges]
    nodes = [
        {"id": name, "deps": [{"pkg": dependency} for dependency in dependencies]}
        for name, dependencies in edges.items()
    ]
    return {"packages": packages, "resolve": {"nodes": nodes}}


def selftest() -> None:
    clean = fixture({LIVE_PACKAGE: ["sha3"], "sha3": []})
    direct = fixture({LIVE_PACKAGE: ["bloch-euvm"], "bloch-euvm": []})
    transitive = fixture(
        {LIVE_PACKAGE: ["adapter"], "adapter": ["bloch-ffg"], "bloch-ffg": []}
    )
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
        dependency_path(fixture({"other": []}), LIVE_PACKAGE, FORBIDDEN)
    except ValueError:
        pass
    else:
        raise AssertionError("missing live package must fail closed")
    print("retired-isolation selftest: OK — clean, direct, transitive and missing-root cases")


def load_metadata(path: Path | None) -> dict:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, help="read Cargo metadata JSON from this file")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0

    try:
        path = dependency_path(load_metadata(args.metadata), LIVE_PACKAGE, FORBIDDEN)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
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
