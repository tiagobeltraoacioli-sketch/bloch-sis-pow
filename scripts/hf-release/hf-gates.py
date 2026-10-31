#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Consensus activation gates of a candidate commit, and forced-epoch patching.

  hf-gates.py discover --repo <git dir> --base <fleet commit> --candidate <commit> [--gate NAME ...]
      Prints TSV: name, base value, candidate value, status. A gate is every
      single-line `pub const <NAME>_EPOCH: u64 = <value>;` under crates/ whose
      name contains ACTIVATION or REFUSAL or starts with HF<n>_ and whose definition is new or changed
      between the fleet release and the candidate, plus any --gate given.
      status: scheduled:<epoch> | inert (u64::MAX) | alias:<expr> | missing

  hf-gates.py tripwires --repo <git dir> --commit <commit> --gate NAME [--gate NAME ...]
      Prints the test functions that pin one of the given gates to u64::MAX
      (`assert_eq!(<..>NAME, u64::MAX)` or `NAME == u64::MAX` in their body).
      Such a test must fail once the gate is armed; qualify.sh accepts exactly
      these failures for the gates it finds armed.

  hf-gates.py force --tree <exported source dir> --gate NAME --epoch N
      Rewrites every single-line definition of NAME under <tree>/crates to N.
      QUALIFICATION ONLY: the result must never be released. Fails if the
      gate has no single-line definition.

  hf-gates.py relax-order --tree <exported source dir>
      Makes the compile-time gate ordering rules always true, so one gate can
      be forced alone even when the release rules tie it to another gate.
      QUALIFICATION ONLY: the result must never be released. Fails if any rule
      is not found exactly once.
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


ORDER_RULES = {
    "crates/bloch-pos-committee/src/params.rs": (
        "hf1_gates_coherent",
        "gate_is_inert_or_not_before",
        "kes_registration_precedes_enforcement",
        "kes_registration_window_is_long_enough",
    ),
    "crates/bloch-pos-committee/src/hard_forks.rs": ("hard_fork_schedule_coherent",),
}


def relax_order(args):
    for rel, names in ORDER_RULES.items():
        path = os.path.join(args.tree, rel)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for name in names:
            heads = list(re.finditer(r"const fn " + name + r"\s*\([^)]*\)\s*->\s*bool\s*\{", src))
            if len(heads) != 1:
                sys.exit(f"hf-gates: expected one definition of {name} in {rel}, found {len(heads)}")
            start = heads[0].end()
            depth, i = 1, start
            while depth:
                depth += {"{": 1, "}": -1}.get(src[i], 0)
                i += 1
            body = src[start:i - 1]
            src = f"{src[:start]} true || {{{body}}} {src[i - 1:]}"
            print(f"{rel}: {name} relaxed")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)


def tripwires(args):
    names = set()
    for gate in args.gate:
        pat = r"(^|[^A-Z0-9_])" + gate + r"[[:space:]]*(,|==)[[:space:]]*u64::MAX"
        out = subprocess.run(["git", "-C", args.repo, "grep", "-nE", pat, args.commit, "--", "crates/*.rs"],
                             check=False, capture_output=True, text=True)
        for line in out.stdout.splitlines():
            _, path, lineno, _ = line.split(":", 3)
            src = subprocess.run(["git", "-C", args.repo, "show", f"{args.commit}:{path}"],
                                 check=True, capture_output=True, text=True).stdout.split("\n")
            for i in range(int(lineno) - 1, -1, -1):
                m = re.match(r"\s*(?:pub\s+)?fn\s+([a-z0-9_]+)\s*\(", src[i])
                if m:
                    # Only a #[test] function counts as a tripwire.
                    if any("#[test]" in src[j] for j in range(max(0, i - 4), i)):
                        names.add(m.group(1))
                    break
    for n in sorted(names):
        print(n)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover")
    d.add_argument("--repo", required=True)
    d.add_argument("--base", required=True)
    d.add_argument("--candidate", required=True)
    d.add_argument("--gate", action="append")
    t = sub.add_parser("tripwires")
    t.add_argument("--repo", required=True)
    t.add_argument("--commit", required=True)
    t.add_argument("--gate", action="append", required=True)
    f = sub.add_parser("force")
    f.add_argument("--tree", required=True)
    f.add_argument("--gate", required=True)
    f.add_argument("--epoch", required=True, type=int)
    r = sub.add_parser("relax-order")
    r.add_argument("--tree", required=True)
    args = p.parse_args()
    {"discover": discover, "tripwires": tripwires, "force": force, "relax-order": relax_order}[args.cmd](args)


if __name__ == "__main__":
    main()
