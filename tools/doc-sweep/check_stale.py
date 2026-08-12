#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
Sweeps the docs for numbers that consensus code has moved past.

Why this exists: the tokenomics was revised five times on 2026-08-11 — supply
100 B → 21 B, the carryover unified, the founder grant 17% → 10% — and each
revision updated the Rust constants and the headline table while leaving the
same figures written out in prose elsewhere. Three of those survived a PDF
regeneration and were caught by the founder reading the output, not by any
check. A document that contradicts the code is worse than an incomplete one,
because it still reads as authoritative.

The authority is `crates/bloch-pos-committee/src/tokenomics_v4.rs`. This script
parses the live constants out of it and greps the docs for figures that are
recognisably an *older* value of the same quantity. It is a lint, not a proof:
it finds stale numbers it has been taught about, and says nothing about ones it
has not.

    python3 tools/doc-sweep/check_stale.py          # report
    python3 tools/doc-sweep/check_stale.py --ci     # exit 1 on any hit
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOK = os.path.join(ROOT, "crates/bloch-pos-committee/src/tokenomics_v4.rs")

# Superseded values, with what replaced them. Add a row whenever a constant
# changes — that is the whole maintenance burden.
RETIRED = [
    ("100,000,000,000",  "supply antigo",            "21,000,000,000"),
    ("10^19 satoshis",   "supply antigo em sat",     "2.1 x 10^18"),
    ("54.21%",           "fracao antiga de u64::MAX","11.38%"),
    ("53,700,000,000",   "alocacao de validador v1", "9,036,115,200"),
    ("7,566,115,200",    "alocacao de validador v2", "9,036,115,200"),
    ("3,570,000,000",    "concessao do fundador 17%","2,100,000,000"),
    ("33.89%",           "total do fundador antigo", "26.89%"),
    ("36.03%",           "share de validador antigo","43.03%"),
    ("5,181.54",         "decay ano 1 (100 bi)",     "871.90"),
    ("730.06",           "decay ano 1 (21 bi, 17%)", "871.90"),
    ("6,387",            "halving R0 (100 bi)",      "1,075"),
    ("1,276 BLCH",       "flat (100 bi)",            "215 BLCH"),
    ("300,000,000",      "teto de holders aposentado", "sem teto"),
    ("2-year cliff",     "cliff do fundador antigo", "10-year cliff"),
]

# Trechos que citam valores antigos DE PROPOSITO, como historico.
EXEMPT = ("earlier draft", "an earlier version", "was wrong", "superseded",
          "retired", "V2 nominal", "rascunho", "no longer", "went with")

# Documentos que descrevem a cadeia Genesis-3 VIVA, onde os numeros antigos
# sao os corretos.
SKIP = ("TOKENOMICS_V2.md", "TOKENOMICS_V3.md", "CARRYOVER.md", "API.md",
        "PROJECT-STATUS.md", "/adr/", "/historical/", "/post-mortems/")


def live_constants():
    """Read the constants the docs must agree with."""
    src = open(TOK, encoding="utf-8").read()
    out = {}
    for name in ("TOTAL_SUPPLY_BLOCH", "FOUNDER_BLOCH", "CARRYOVER_TOTAL_BLOCH",
                 "VALIDATOR_EMISSION_BLOCH", "VC_BLOCH", "TEAM_BLOCH"):
        m = re.search(rf"pub const {name}: u128 = ([0-9_]+)", src)
        if m:
            out[name] = int(m.group(1).replace("_", ""))
    return out


def sweep():
    hits = []
    files = sorted(
        glob.glob(os.path.join(ROOT, "docs/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "spikes/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "tools/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "deploy/*.md"))
    )
    for path in files:
        rel = os.path.relpath(path, ROOT)
        if any(s in rel for s in SKIP):
            continue
        for i, line in enumerate(open(path, encoding="utf-8"), 1):
            low = line.lower()
            if any(e in low for e in EXEMPT):
                continue
            for old, what, new in RETIRED:
                if old.lower() in low:
                    hits.append((rel, i, what, old, new, line.strip()[:88]))
    return hits


def main():
    consts = live_constants()
    print("constantes vivas em tokenomics_v4.rs:")
    for k, v in consts.items():
        print(f"  {k:<26} {v:>16,}")
    print()

    hits = sweep()
    if not hits:
        print("nenhum numero velho encontrado nos documentos normativos.")
        return 0

    last = None
    for rel, ln, what, old, new, text in hits:
        if rel != last:
            print(f"\n{rel}")
            last = rel
        print(f"  :{ln:<5} {what}  ({old} -> {new})")
        print(f"         {text}")
    print(f"\n{len(hits)} ocorrencia(s). Nao sao todas erro: um trecho que cite o")
    print("valor antigo como historico deve conter uma das marcas de isencao")
    print(f"({', '.join(EXEMPT[:4])}...), senao le como afirmacao corrente.")
    return 1 if "--ci" in sys.argv else 0


if __name__ == "__main__":
    sys.exit(main())
