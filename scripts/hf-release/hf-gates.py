#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Consensus activation gates of a candidate commit, and forced-epoch patching.

  hf-gates.py discover --repo <git dir> --base <fleet commit> --candidate <commit> [--gate NAME ...]
      Prints TSV: name, base value, candidate value, status. A gate is every
      single-line `pub const <NAME>_EPOCH: u64 = <value>;` under crates/ whose
      name contains ACTIVATION or REFUSAL or starts with HF<n>_ and whose definition is new or changed
      between the fleet release and the candidate, plus any --gate given.
      status: scheduled:<epoch> | inert (u64::MAX) | alias:<expr> | missing

  hf-gates.py force --tree <exported source dir> --gate NAME --epoch N
      Rewrites every single-line definition of NAME under <tree>/crates to N.
      QUALIFICATION ONLY: the result must never be released. Fails if the
      gate has no single-line definition.
"""
import argparse
import os
import re
import subprocess
import sys

DEF = re.compile(r"^(\s*pub(?:\([a-z]+\))?\s+const\s+)([A-Z0-9_]+)(\s*:\s*u64\s*=\s*)([^;]+)(;.*)$")
U64_MAX = (1 << 64) - 1


def is_gate_name(name):
    return name.endswith("_EPOCH") and (
        "ACTIVATION" in name or "REFUSAL" in name or re.match(r"HF[0-9]+_", name) is not None)


def definitions(repo, commit):
    out = subprocess.run(
        ["git", "-C", repo, "grep", "-hE", r"^\s*pub(\([a-z]+\))? +const +[A-Z0-9_]+ *: *u64 *=", commit, "--", "crates/*.rs"],
        check=False, capture_output=True, text=True,
    )
    if out.returncode not in (0, 1):
        sys.exit(f"hf-gates: git grep failed at {commit}: {out.stderr.strip()}")
    defs = {}
    for line in out.stdout.splitlines():
        m = DEF.match(line)
        if m:
            defs.setdefault(m.group(2), []).append(m.group(4).strip())
    return defs


def evaluate(value, defs, depth=0):
    v = value.replace("_", "") if re.fullmatch(r"[0-9_]+", value) else value
    if re.fullmatch(r"[0-9]+", v):
        return int(v)
    if value == "u64::MAX":
        return U64_MAX
    if depth < 4 and re.fullmatch(r"[A-Z0-9_]+", value) and len(defs.get(value, [])) == 1:
        return evaluate(defs[value][0], defs, depth + 1)
    return None


def status(values, defs):
    if not values:
        return "missing"
    if len(set(values)) != 1:
        return "multiple:" + "|".join(sorted(set(values)))
    n = evaluate(values[0], defs)
    if n is None:
        return "alias:" + values[0]
    if n == U64_MAX:
        return "inert"
    return f"scheduled:{n}"


def discover(args):
    base = definitions(args.repo, args.base)
    cand = definitions(args.repo, args.candidate)
    names = {n for n in cand if is_gate_name(n) and cand[n] != base.get(n)}
    names.update(args.gate or [])
    for name in sorted(names):
        b = ",".join(base.get(name, [])) or "-"
        c = ",".join(cand.get(name, [])) or "-"
        print(f"{name}\t{b}\t{c}\t{status(cand.get(name, []), cand)}")


def force(args):
    if not re.fullmatch(r"[A-Z0-9_]+", args.gate):
        sys.exit("hf-gates: bad gate name")
    hits = []
    root = os.path.join(args.tree, "crates")
    for dirpath, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".rs"):
                continue
            path = os.path.join(dirpath, f)
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().split("\n")
            changed = False
            for i, line in enumerate(lines):
                m = DEF.match(line)
                if m and m.group(2) == args.gate:
                    lines[i] = f"{m.group(1)}{m.group(2)}{m.group(3)}{args.epoch}{m.group(5)}"
                    hits.append(f"{os.path.relpath(path, args.tree)}:{i + 1}: {m.group(4).strip()} -> {args.epoch}")
                    changed = True
            if changed:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines))
    if not hits:
        sys.exit(f"hf-gates: no single-line definition of {args.gate} under {root}")
    for h in hits:
        print(h)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover")
    d.add_argument("--repo", required=True)
    d.add_argument("--base", required=True)
    d.add_argument("--candidate", required=True)
    d.add_argument("--gate", action="append")
    f = sub.add_parser("force")
    f.add_argument("--tree", required=True)
    f.add_argument("--gate", required=True)
    f.add_argument("--epoch", required=True, type=int)
    args = p.parse_args()
    discover(args) if args.cmd == "discover" else force(args)


if __name__ == "__main__":
    main()
