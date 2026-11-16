#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Consensus activation gates of a candidate commit, and forced-epoch patching.

  hf-gates.py discover --repo <git dir> --base <fleet commit> --candidate <commit> [--gate NAME ...]
      Prints TSV: name, base value, candidate value, status. A gate is every
      single-line `pub const <NAME>_EPOCH: u64 = <value>;` under crates/ whose
      name contains ACTIVATION or REFUSAL or starts with HF<n>_ or L2_ and whose definition is new or changed
      between the fleet release and the candidate, plus any --gate given.
      status: scheduled:<epoch> | inert (u64::MAX) | alias:<expr> | missing

  hf-gates.py status --repo <git dir> --commit <commit> --gate NAME [--gate NAME ...]
      Prints TSV: name, status (as above) of the named constants at one commit.
      The value is evaluated: literals, `u64::MAX`, other constants, + - * /,
      parentheses. `alias:<expr>` means it could not be evaluated; treat that
      as possibly armed (review R308-10).

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
    # L2_*_EPOCH: the L2 program swap and its rollback (L2_NEXT_PROGRAM_EPOCH, L2_PROGRAM_ROLLBACK_EPOCH),
    # which qualify would otherwise only see with an explicit --gate.
    return name.endswith("_EPOCH") and (
        "ACTIVATION" in name or "REFUSAL" in name or re.match(r"HF[0-9]+_", name) is not None
        or re.match(r"L2_[A-Z0-9_]+_EPOCH$", name) is not None)


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
    """The u64 a constant's right-hand side evaluates to, or None when this tool cannot tell.

    Understood (review R308-10: an armed gate written as anything but a plain decimal was not seen as armed):
    decimal and 0x literals with `_` and an optional integer suffix, `u64::MAX`, the name of another constant
    with exactly one definition (optionally `params::`/`crate::params::` qualified), parentheses, `as u64`,
    and + - * / between those. Anything else (function calls, shifts, other paths) is None: callers must treat
    an unknown value as possibly armed, never as inert."""
    if depth > 8:
        return None
    tokens = re.findall(r"\s*(0x[0-9a-fA-F_]+|[0-9][0-9_]*|[A-Za-z_][A-Za-z0-9_:]*|[-+*/()]|\S)", value)
    pos = 0

    def atom():
        nonlocal pos
        if pos >= len(tokens):
            return None
        tok = tokens[pos]
        pos += 1
        if tok == "(":
            n = expr()
            if n is None or pos >= len(tokens) or tokens[pos] != ")":
                return None
            pos += 1
        elif re.fullmatch(r"0x[0-9a-fA-F_]+", tok):
            n = int(tok.replace("_", ""), 16)
        elif re.fullmatch(r"[0-9][0-9_]*", tok):
            n = int(tok.replace("_", ""))
            if pos < len(tokens) and re.fullmatch(r"u(8|16|32|64|128|size)", tokens[pos]):
                pos += 1
        elif tok in ("u64::MAX", "core::u64::MAX", "std::u64::MAX"):
            n = U64_MAX
        elif re.fullmatch(r"(?:(?:crate::)?params::)?[A-Z][A-Z0-9_]*", tok):
            name = tok.rsplit("::", 1)[-1]
            if len(defs.get(name, [])) != 1:
                return None
            n = evaluate(defs[name][0], defs, depth + 1)
        else:
            return None
        while n is not None and pos + 1 < len(tokens) and tokens[pos] == "as":
            if tokens[pos + 1] != "u64":
                return None
            pos += 2
        return n

    def term():
        nonlocal pos
        n = atom()
        while n is not None and pos < len(tokens) and tokens[pos] in "*/":
            op = tokens[pos]
            pos += 1
            m = atom()
            if m is None or (op == "/" and m == 0):
                return None
            n = n * m if op == "*" else n // m
        return n

    def expr():
        nonlocal pos
        n = term()
        while n is not None and pos < len(tokens) and tokens[pos] in "+-":
            op = tokens[pos]
            pos += 1
            m = term()
            if m is None:
                return None
            n = n + m if op == "+" else n - m
        return n

    n = expr()
    if n is None or pos != len(tokens) or not 0 <= n <= U64_MAX:
        return None
    return n


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


def gate_status(args):
    """`status`: one line per --gate, `NAME<TAB>status`, at one commit. `inert` is printed only for a value this
    tool evaluated to u64::MAX; a value it cannot evaluate is `alias:<expr>` and is NOT inert."""
    defs = definitions(args.repo, args.commit)
    for name in args.gate:
        print(f"{name}\t{status(defs.get(name, []), defs)}")


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
    g = sub.add_parser("status")
    g.add_argument("--repo", required=True)
    g.add_argument("--commit", required=True)
    g.add_argument("--gate", action="append", required=True)
    f = sub.add_parser("force")
    f.add_argument("--tree", required=True)
    f.add_argument("--gate", required=True)
    f.add_argument("--epoch", required=True, type=int)
    r = sub.add_parser("relax-order")
    r.add_argument("--tree", required=True)
    args = p.parse_args()
    {"discover": discover, "status": gate_status, "tripwires": tripwires, "force": force, "relax-order": relax_order}[args.cmd](args)


if __name__ == "__main__":
    main()
