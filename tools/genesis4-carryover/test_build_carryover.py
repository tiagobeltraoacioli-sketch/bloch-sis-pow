#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Hermetic regression tests for the retired carryover generator.

These tests cover only the historical transformation rules. They do not read a
founder-specific home-directory snapshot and do not qualify the live carryover.
"""
import os, sys, tempfile, subprocess
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_carryover import build, write, SAT_PER_BLOCH

FOUNDER = "e986db5149cff7499b282a048272a09aff0af4ff"
fails = []
temporary = tempfile.TemporaryDirectory(prefix="bloch-retired-carryover-test-")
tmpdir = Path(temporary.name)

def check(name, cond, detail=""):
    print(f"  {'ok  ' if cond else 'FALHA'} {name}{'  ' + detail if detail and not cond else ''}")
    if not cond: fails.append(name)

def tmp_tsv(rows):
    fh = tempfile.NamedTemporaryFile("w", suffix=".tsv", dir=tmpdir, delete=False)
    for i, (addr, val) in enumerate(rows):
        fh.write(f"{'aa'*32}\t{i}\t{val}\t{addr}\n")
    fh.close(); return fh.name

print("fixture hermetica do gerador retirado:")
source = tmp_tsv([("bb"*20, 20*SAT_PER_BLOCH), ("aa"*20, 10*SAT_PER_BLOCH)])
r = build(source, {FOUNDER}, 300_000_000)
a, b = tmpdir / "deterministic-a.tsv", tmpdir / "deterministic-b.tsv"
d1, d2 = write(r, a), write(build(source, {FOUNDER}, 300_000_000), b)
check("digest deterministico", d1 == d2)
check("saida ordenada por endereco",
      [x[0] for x in r["rows"]] == sorted(x[0] for x in r["rows"]))

print("\nrateio pro-rata:")
p = tmp_tsv([("aa"*20, 600_000_000*SAT_PER_BLOCH), ("bb"*20, 200_000_000*SAT_PER_BLOCH)])
r = build(p, {FOUNDER}, 300_000_000)
d = dict(r["rows"])
check("aplicou rateio", r["scaled"])
check("proporcao 3:1 preservada", d["aa"*20] == 3 * d["bb"*20])
check("total nao passa do teto", r["out_total_sat"] <= 300_000_000*SAT_PER_BLOCH,
      str(r["out_total_sat"]))
check("total encosta no teto (truncamento < 1 BLCH)",
      300_000_000*SAT_PER_BLOCH - r["out_total_sat"] < SAT_PER_BLOCH)

print("\ntaint:")
p = tmp_tsv([(FOUNDER, 999*SAT_PER_BLOCH), ("cc"*20, 10*SAT_PER_BLOCH)])
r = build(p, {FOUNDER}, 300_000_000)
check("moeda do fundador nao entra", len(r["rows"]) == 1 and r["rows"][0][0] == "cc"*20)
check("fundador contabilizado a parte", r["founder_sat"] == 999*SAT_PER_BLOCH)

p2 = tmp_tsv([(FOUNDER, 999*SAT_PER_BLOCH), ("cc"*20, 10*SAT_PER_BLOCH)])
r2 = build(p2, {FOUNDER, "cc"*20}, 300_000_000)
check("multiplos enderecos de taint", len(r2["rows"]) == 0)

print("\nbordas:")
p = tmp_tsv([])
r = build(p, {FOUNDER}, 300_000_000)
check("entrada vazia nao quebra", r["rows"] == [] and r["out_total_sat"] == 0)
p = tmp_tsv([("dd"*20, 300_000_000*SAT_PER_BLOCH)])
r = build(p, {FOUNDER}, 300_000_000)
check("exatamente no teto: sem rateio", not r["scaled"])
check("lista de taint vazia e recusada",
      subprocess.run([sys.executable, "build_carryover.py", "--utxo", p,
                      "--founder", "", "--out", str(tmpdir / "empty-founder.tsv")],
                     capture_output=True).returncode != 0)

print(f"\n{'TODOS OS TESTES PASSARAM' if not fails else 'FALHARAM: ' + ', '.join(fails)}")
temporary.cleanup()
sys.exit(1 if fails else 0)
