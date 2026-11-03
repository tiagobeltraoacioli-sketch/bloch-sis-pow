#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Make the compile-time gate ordering rules always true in a DISPOSABLE copy,
so a single gate can be moved (same rule as hf-gates.py relax-order)."""
import re
import sys
from pathlib import Path

RULES = {"crates/bloch-pos-committee/src/params.rs": ("hf1_gates_coherent", "gate_is_inert_or_not_before",
                                                      "kes_registration_precedes_enforcement",
                                                      "kes_registration_window_is_long_enough"),
         "crates/bloch-pos-committee/src/hard_forks.rs": ("hard_fork_schedule_coherent",)}
root = Path(sys.argv[1])
for rel, names in RULES.items():
    p = root / rel
    s = p.read_text()
    for n in names:
        heads = list(re.finditer(r"const fn " + n + r"\s*\([^)]*\)\s*->\s*bool\s*\{", s))
        if len(heads) != 1:
            sys.exit(f"relax: {n} in {rel}: {len(heads)}")
        start = heads[0].end()
        depth, i = 1, start
        while depth:
            depth += {"{": 1, "}": -1}.get(s[i], 0)
            i += 1
        s = f"{s[:start]} true || {{{s[start:i - 1]}}} {s[i - 1:]}"
    p.write_text(s)
