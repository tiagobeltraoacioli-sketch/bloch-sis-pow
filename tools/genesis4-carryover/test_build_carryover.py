#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Testes do gerador de carryover — RETIRADO.

O arquivo real em ~/dev/BlochPOS/carryover.tsv.gz nao e mais o de 413.743
linhas contra o qual estes numeros foram fixados; foi substituido em
2026-08-14 pelo terminal de Genesis-3 (452.726 linhas). As checagens
"contra os dados reais" abaixo descrevem um arquivo que nao existe mais e
uma regra (taint + teto) que foi abandonada antes do lancamento.

Rodar: python3 test_build_carryover.py"""
import os, sys, tempfile, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_carryover import build, write, SAT_PER_BLOCH

FOUNDER = "e986db5149cff7499b282a048272a09aff0af4ff"
REAL = os.path.expanduser("~/dev/BlochPOS/carryover.tsv.gz")
fails = []

def check(name, cond, detail=""):
    print(f"  {'ok  ' if cond else 'FALHA'} {name}{'  ' + detail if detail and not cond else ''}")
    if not cond: fails.append(name)

def tmp_tsv(rows):
    fh = tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False)
    for i, (addr, val) in enumerate(rows):
        fh.write(f"{'aa'*32}\t{i}\t{val}\t{addr}\n")
    fh.close(); return fh.name

print("contra os dados reais (carryover.tsv.gz, 413.743 utxos) -- RETIRADO:")
print("  este arquivo agora tem 452.726 linhas; as checagens abaixo vao falhar")
print("  por projeto. Ver README.md.")
if os.path.exists(REAL):
    r = build(REAL, {FOUNDER}, 300_000_000)
    check("fundador excluido = 3.294.337.200 BLCH",
          r["founder_sat"] == 3_294_337_200 * SAT_PER_BLOCH, str(r["founder_sat"]))
    check("nao-fundador = 181.104.000 BLCH",
          r["raw_total_sat"] == 181_104_000 * SAT_PER_BLOCH, str(r["raw_total_sat"]))
    check("4 enderecos nao-fundador", len(r["rows"]) == 4, str(len(r["rows"])))
    check("abaixo do teto: sem rateio", not r["scaled"])
    check("total preservado integralmente", r["out_total_sat"] == r["raw_total_sat"])
    # determinismo: mesma entrada, mesmo digest
    a, b = tempfile.mktemp(), tempfile.mktemp()
    d1, d2 = write(r, a), write(build(REAL, {FOUNDER}, 300_000_000), b)
    check("digest deterministico", d1 == d2)
    check("saida ordenada por endereco",
          [x[0] for x in r["rows"]] == sorted(x[0] for x in r["rows"]))
else:
    check("arquivo real presente", False, REAL)

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
                      "--founder", "", "--out", tempfile.mktemp()],
                     capture_output=True).returncode != 0)

print(f"\n{'TODOS OS TESTES PASSARAM' if not fails else 'FALHARAM: ' + ', '.join(fails)}")
sys.exit(1 if fails else 0)
