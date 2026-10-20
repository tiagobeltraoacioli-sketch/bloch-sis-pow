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
  HF    every INERT (u64::MAX) gate named in gates.conf, plus any other
        inert `HF1_*`/`HF2_*`/`HF3_*` constant, in bloch-pos-committee,
        bloch-pos-node and bloch-crypto sources, becomes --hf1/--hf2/--hf3
        (plus the offset gates.conf gives, e.g. own-target votes at HF1+2).
        Numeric HF constants (HF1_MAX_GATE_SPACING_EPOCHS = 16) are never
        touched. Aliases (`= HF2_SLASHING_V2_EPOCH`) follow automatically.

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
HF_ROOTS = [Path("crates/bloch-pos-committee/src"), Path("crates/bloch-pos-node/src"), Path("crates/bloch-crypto/src")]
GATES_CONF = Path(__file__).resolve().parent / "gates.conf"
SLASHING_ERA = 2_884
UNTOUCHED = {"L2_SETTLEMENT_ACTIVATION_EPOCH"}

DECL = re.compile(r"^(?P<indent>\s*)pub(?:\([a-z]+\))? const (?P<name>[A-Z0-9_]+): (?:u64|u8) = (?P<value>u64::MAX|\d[\d_]*);$",
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
    ap.add_argument("--conf", type=Path, action="append",
                    help="gate conf file(s); default gates.conf. Repeatable (e.g. gates.conf + kes.conf)")
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
        epochs = {"HF1": args.hf1, "HF2": args.hf2, "HF3": args.hf3}
        conf: dict[str, int] = {}
        literal: dict[str, int] = {}
        drops: list[str] = []
        for conf_file in (args.conf or [GATES_CONF]):
          for raw in conf_file.read_text().splitlines():
            if raw.startswith("!drop-line "):
                drops.append(raw[len("!drop-line "):].strip())
                continue
            line = raw.split("#", 1)[0].split()
            if len(line) == 2 and line[1].startswith("="):
                literal[line[0]] = int(line[1][1:])
                continue
            if len(line) == 2:
                m = re.fullmatch(r"(HF[123])(?:\+(\d+))?", line[1])
                if not m:
                    sys.exit(f"gates.conf: bad entry {line}")
                conf[line[0]] = epochs[m.group(1)] + int(m.group(2) or 0)
        report["gates_conf"] = conf

        report["literal_overrides"] = literal

        def hf(name: str, value: str):
            if name in literal:
                return literal[name]
            if value != "u64::MAX":
                if name in conf:
                    report.setdefault("already_armed", []).append({"name": name, "value": value})
                return None
            if name in conf:
                return conf[name]
            m = re.match(r"(HF[123])_", name)
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

    if not args.no_hf:
        # Literal overrides whose initializer is an expression (e.g. `14 * 90`)
        # are not matched by DECL: rewrite them by exact name, exactly once.
        done = {c["name"] for c in report["hf_constants"]}
        for name, value in literal.items():
            if name in done:
                continue
            pat = re.compile(rf"^(\s*pub(?:\([a-z]+\))? const {name}: (?:u64|u8) = )([^;]+);$", re.M)
            hits = []
            for base in HF_ROOTS:
                for file in sorted((root / base).rglob("*.rs")):
                    text = file.read_text()
                    found = pat.findall(text)
                    if found:
                        hits.append((file, found[0][1]))
            if not hits:
                report.setdefault("missing_literals", []).append(name)
                print(f"  note: literal {name} is not declared in this tree (skipped)")
                continue
            if len(hits) != 1:
                sys.exit(f"literal {name}: expected exactly one declaration, found {len(hits)}")
            file, old_value = hits[0]
            file.write_text(pat.sub(rf"\g<1>{value};", file.read_text(), count=1))
            report["hf_constants"].append({"name": name, "from": old_value, "to": str(value),
                                           "file": str(file.relative_to(root))})

    if not args.no_hf and drops:
        path = root / PARAMS
        lines = path.read_text().splitlines(keepends=True)
        for needle in drops:
            hits = [i for i, l in enumerate(lines) if needle in l]
            if len(hits) != 1:
                sys.exit(f"!drop-line {needle!r}: expected exactly one line in {PARAMS}, found {len(hits)}")
            report.setdefault("dropped_lines", []).append(lines[hits[0]].strip())
            del lines[hits[0]]
        path.write_text("".join(lines))

    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"armed {len(report['past'])} past gates -> {{0, {args.past_gate}}}; "
          f"{len(report['hf_constants'])} HF constants -> {report['hf'] or 'none (--no-hf)'}")
    for c in report["past"] + report["hf_constants"]:
        print(f"  {c['file']}: {c['name']} {c['from']} -> {c['to']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
