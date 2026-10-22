#!/usr/bin/env python3
"""Rewrite activation-epoch constants in a SCRATCH copy of the tree.

DEV TOOLING ONLY, used by scripts/hf-verify/run-all.sh. It edits the files of
the directory it is given in place, so only ever point it at a throwaway
overlay, never at a worktree whose changes could be committed.

    override_consts.py ROOT NAME=EPOCH [NAME=EPOCH ...]   rewrite, print old -> new
    override_consts.py ROOT --get NAME                     print value (or "absent")

EPOCH is a decimal number (underscores allowed) or `MAX` (= u64::MAX, inert).
Every `pub const NAME: u64 = ...;` / `pub(crate) const ...` definition under
ROOT/crates/*/src is rewritten, including cfg-selected duplicates. A name that
is not defined anywhere is an error (a typo must not silently test nothing).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def definition(name: str) -> re.Pattern[str]:
    return re.compile(r"(\bpub(?:\([a-z]+\))?\s+const\s+" + re.escape(name) + r"\s*:\s*u64\s*=)(\s*)([^;]+);",
                      re.S)


def sources(root: Path):
    yield from sorted((root / "crates").glob("*/src/**/*.rs"))


def literal(value: str) -> str:
    if value.upper() in ("MAX", "U64::MAX", "INERT"):
        return "u64::MAX"
    n = int(value.replace("_", ""))
    if not 0 <= n < 1 << 64:
        raise ValueError(value)
    return f"{n:_}"


def get(root: Path, name: str) -> str:
    pat = definition(name)
    for f in sources(root):
        m = pat.search(f.read_text())
        if m:
            expr = " ".join(m.group(3).split())
            if expr == "u64::MAX":
                return "MAX"
            if re.fullmatch(r"[0-9_]+", expr):
                return str(int(expr.replace("_", "")))
            return "expr:" + expr
    return "absent"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[0])
    if argv[1] == "--get":
        print(get(root, argv[2]))
        return 0
    status = 0
    for arg in argv[1:]:
        name, _, value = arg.partition("=")
        new = literal(value)
        pat = definition(name)
        hits = 0
        for f in sources(root):
            text = f.read_text()
            olds = [" ".join(m.group(3).split()) for m in pat.finditer(text)]
            if not olds:
                continue
            f.write_text(pat.sub(lambda m: f"{m.group(1)} {new};", text))
            hits += len(olds)
            print(f"override {name}: {' | '.join(olds)} -> {new}  ({f.relative_to(root)})")
        if hits == 0:
            print(f"override {name}: NOT DEFINED under {root}/crates/*/src", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
