#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Arm a DISPOSABLE source copy for the local HF1/HF2/HF3 activation rehearsal.

    arm.py <copy-root> --hf1 10 --hf2 14 --hf3 18 --past-gate 6 --report arming.json
    arm.py <copy-root> --past-gate 6 --no-hf --report arming.json   # the non-upgraded build

Never run it on a checkout: it rewrites consensus constants in place and
refuses a directory that is a git work tree.

Two groups of `pub const NAME: u64 = VALUE;` declarations are rewritten:

  PAST  every `*ACTIVATION_EPOCH` in bloch-pos-committee/src/params.rs whose
        value is a finite epoch at or below --mainnet-epoch (default 7000):
        flag days mainnet has ALREADY crossed. Values below 2884 become 0
        (active from genesis); values >= 2884 become --past-gate, so the
        rehearsal network has a short pre-slashing era in which an offence
        can be committed before SLASHING_EVIDENCE_ACTIVATION_EPOCH and
        submitted after it (the 2026-10-19 exposure class). Relative order
        (>=) between the 2884+ gates is preserved; the compile-time asserts
        that tie them together still hold. L2_SETTLEMENT_ACTIVATION_EPOCH is
        left untouched: its activation policy names the mainnet admission
        domain and is inert on a fresh devnet either way.
  HF    every `HF1_*`, `HF2_*`, `HF3_*` constant (u64::MAX or a number) in
        bloch-pos-committee/src and bloch-pos-node/src becomes --hf1/--hf2/
        --hf3. That is the naming convention of the codex/hf*-20261020
        branches (e.g. HF1_CLAIM_FINALITY_EPOCH, HF2_SLASHING_V2_EPOCH).
        Aliases (`= HF2_SLASHING_V2_EPOCH`) follow automatically.

If the tree declares a cargo feature `hf-rehearsal` (the mechanism the
codex/hf-verify-harness-20261020 branch may add) run.sh builds with it
instead and calls this script with --no-hf, so the two mechanisms never
stack.

Output: a JSON report of every rewrite (file, name, from, to), which run.sh
stores next to the binaries and the rehearsal reads to know which HF gates
actually exist in the build under test.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PARAMS = Path("crates/bloch-pos-committee/src/params.rs")
HF_ROOTS = [Path("crates/bloch-pos-committee/src"), Path("crates/bloch-pos-node/src")]
SLASHING_ERA = 2_884
UNTOUCHED = {"L2_SETTLEMENT_ACTIVATION_EPOCH"}

DECL = re.compile(r"^(?P<indent>\s*)pub(?:\([a-z]+\))? const (?P<name>[A-Z0-9_]+): u64 = (?P<value>u64::MAX|\d[\d_]*);$",
                  re.M)


def as_int(value: str) -> int | None:
    return None if value == "u64::MAX" else int(value.replace("_", ""))


def rewrite(text: str, decide) -> tuple[str, list[dict]]:
    changes: list[dict] = []

    def sub(m: re.Match) -> str:
        new = decide(m.group("name"), m.group("value"))
        if new is None or str(new) == m.group("value"):
            return m.group(0)
        changes.append({"name": m.group("name"), "from": m.group("value"), "to": str(new)})
        return m.group(0).replace(f"= {m.group('value')};", f"= {new};")

    return DECL.sub(sub, text), changes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("--hf1", type=int, default=10)
    ap.add_argument("--hf2", type=int, default=14)
    ap.add_argument("--hf3", type=int, default=18)
    ap.add_argument("--no-hf", action="store_true", help="arm only the PAST group (non-upgraded build)")
    ap.add_argument("--past-gate", type=int, default=6)
    ap.add_argument("--mainnet-epoch", type=int, default=7_000)
    ap.add_argument("--report", type=Path, required=True)
    args = ap.parse_args()

    root = args.root.resolve()
    if (root / ".git").exists():
        sys.exit(f"REFUSED: {root} is a git work tree; arm.py only rewrites a disposable copy")
    if not (root / PARAMS).is_file():
        sys.exit(f"{root / PARAMS} not found")
    if not args.no_hf and not (args.past_gate < args.hf1 < args.hf2 < args.hf3):
        sys.exit("need past-gate < hf1 < hf2 < hf3")

    report: dict = {"past_gate": args.past_gate, "hf": {} if args.no_hf else
                    {"HF1": args.hf1, "HF2": args.hf2, "HF3": args.hf3},
                    "past": [], "hf_constants": []}

    def past(name: str, value: str):
        n = as_int(value)
        if "ACTIVATION_EPOCH" not in name or name in UNTOUCHED or n is None or n == 0 or n > args.mainnet_epoch:
            return None
        return 0 if n < SLASHING_ERA else args.past_gate

    path = root / PARAMS
    text, changes = rewrite(path.read_text(), past)
    path.write_text(text)
    report["past"] = [dict(c, file=str(PARAMS)) for c in changes]

    if not args.no_hf:
        epochs = {"1": args.hf1, "2": args.hf2, "3": args.hf3}

        def hf(name: str, value: str):
            m = re.match(r"HF([123])_", name)
            return epochs[m.group(1)] if m else None

        for base in HF_ROOTS:
            for file in sorted((root / base).rglob("*.rs")):
                rel = file.relative_to(root)
                if "tests" in rel.parts or file.name.endswith("_tests.rs"):
                    continue
                text, changes = rewrite(file.read_text(), hf)
                if changes:
                    file.write_text(text)
                    report["hf_constants"] += [dict(c, file=str(rel)) for c in changes]

    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"armed {len(report['past'])} past gates -> {{0, {args.past_gate}}}; "
          f"{len(report['hf_constants'])} HF constants -> {report['hf'] or 'none (--no-hf)'}")
    for c in report["past"] + report["hf_constants"]:
        print(f"  {c['file']}: {c['name']} {c['from']} -> {c['to']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
