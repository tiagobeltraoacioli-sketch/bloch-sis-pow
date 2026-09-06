#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
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
#
# 2026-08-12: o supply voltou a 100 bi como SPLIT PURO x100/21 do cronograma
# de 21 bi. As linhas que tratavam "100,000,000,000", "10^19 satoshis" e
# "54.21%" como valores velhos foram REMOVIDAS — esses agora sao os valores
# vivos — e a era de 21 bi (2026-08-11 a 2026-08-12) entrou como aposentada.
RETIRED = [
    ("21,000,000,000",   "supply da era 21 bi",      "100,000,000,000 (split x100/21)"),
    ("2.1 x 10^18",      "supply em sat da era 21 bi", "10^19 satoshis"),
    ("11.38%",           "fracao de u64::MAX da era 21 bi", "54.21%"),
    ("3,773,884,800",    "carryover pre-split",      "17,970,880,000"),
    ("3,546,175,400",    "maior endereco pre-split", "16,886,549,523"),
    ("53,700,000,000",   "alocacao de validador v1", "42,853,600,000"),
    ("7,566,115,200",    "alocacao de validador v2", "42,853,600,000"),
    ("9,036,115,200",    "alocacao de validador da era 21 bi", "42,853,600,000"),
    # 2026-09-06: CARRYOVER_TOTAL_BLOCH e LARGEST_CARRYOVER_ADDRESS_BLOCH foram
    # remedidos apos a re-medicao da G3 (altura CARRYOVER_MEASURED_HEIGHT =
    # 39,918). As linhas abaixo tinham a coluna "new" apontando para os valores
    # PRE-remedicao (17,970,880,000 / 16,886,549,523) como se fossem os atuais
    # -- self-check_retired_table_fresh() abaixo trava o CI se isso recorrer.
    ("17,970,880,000",   "carryover pre-remedicao (2026-08 antes da 2a medicao)", "18,146,400,000"),
    ("16,886,549,523",   "maior endereco pre-remedicao (2026-08 antes da 2a medicao)", "17,046,829,380"),
    ("2,100,000,000",    "concessao do fundador da era 21 bi", "10,000,000,000"),
    ("3,570,000,000",    "concessao do fundador 17%","10,000,000,000"),
    ("33.89%",           "total do fundador antigo", "27.04%"),
    ("26.89%",           "total do fundador antes da remedicao do carryover (tokenomics_v4.rs linha ~101 registra isso como a mesma armadilha)", "27.04%"),
    ("36.03%",           "share de validador antigo","43.03%"),
    ("5,181.54",         "decay ano 1 (100 bi, rascunho de 08-10)", "4,151.90"),
    ("5,450,564,151",    "emissao ano 1 (100 bi, rascunho de 08-10)", "4,367,467,018"),
    ("871.90",           "decay ano 1 da era 21 bi", "4,151.90"),
    ("917,168,073",      "emissao ano 1 da era 21 bi", "4,367,467,018"),
    ("730.06",           "decay ano 1 (21 bi, 17%)", "4,151.90"),
    ("6,387",            "halving R0 (100 bi, rascunho de 08-10)", "5,118"),
    ("1,074.81",         "halving R0 da era 21 bi",  "5,118.16"),
    ("1,276 BLCH",       "flat (100 bi, rascunho de 08-10)", "1,022 BLCH"),
    ("214.75 BLCH",      "flat da era 21 bi",        "1,022.63 BLCH"),
    ("215 BLCH",         "flat da era 21 bi",        "1,022 BLCH"),
    ("residual zero",    "afirmacao impossivel sobre a curva de decay", "EMISSION_DUST_SAT = 176,880 sat"),
    ("zero residual",    "afirmacao impossivel sobre a curva de decay", "EMISSION_DUST_SAT = 176,880 sat"),
    ("300,000,000",      "teto de holders aposentado", "sem teto"),
    # INVERTIDA ate 2026-09-06: esta linha tratava o valor VIVO ("2-year
    # cliff" == FOUNDER_CLIFF_SLOTS = 2 * SLOTS_PER_YEAR) como se fosse o
    # antigo, e sugeria "10-year cliff" como substituicao -- exatamente ao
    # contrario. O efeito pratico: a varredura nunca acusava o site publico e
    # o spec continuarem com "10-year cliff / 40-year vest" (o rascunho
    # pre-2026-08-21), porque o texto ANTIGO era o que a tabela chamava de
    # "new". Corrigida para apontar o rascunho de 10 anos como o valor
    # aposentado e o par 2yr/8yr (FOUNDER_CLIFF_SLOTS / FOUNDER_VESTING_SLOTS)
    # como o vivo.
    ("10-year cliff",    "cliff do fundador (rascunho anterior a 2026-08-21; decisao viva e 2yr/8yr)", "2-year cliff / 8-year vest"),
    ("10 yr cliff",      "cliff do fundador (rascunho anterior a 2026-08-21; decisao viva e 2yr/8yr)", "2 yr cliff / 8 yr vest"),
    ("40-year vest",     "vesting do fundador (rascunho anterior a 2026-08-21; decisao viva e 2yr/8yr)", "8-year vest"),
    ("40 yr vest",       "vesting do fundador (rascunho anterior a 2026-08-21; decisao viva e 2yr/8yr)", "8 yr vest"),
    # Bond e churn (2026-08-12): MIN_DEPOSIT 100.000 -> 25.000 BLCH (fracao de
    # supply do bond da Ethereum, arredondado para baixo); MIN_CHURN deixou de
    # ser alias e vale 500.000 BLCH (piso em tempo de parede). Autoridade:
    # staking.rs / delegation.rs.
    ("100,000 BLCH",     "deposito minimo da era 21 bi", "25,000 BLCH"),
    ("bond of 100,000",  "deposito minimo da era 21 bi", "25,000 BLCH"),
    ("MIN_CHURN_SAT (= MIN_DEPOSIT_SAT)", "piso de churn era alias", "MIN_CHURN_SAT = 500,000 BLCH"),
    # Concessao do fundador 17% -> 10% (2026-08-11). Frases estreitas de
    # proposito: "17% founder premine" segue CORRETO nos docs da V2/G3.
    ("new grant is 17%", "concessao do fundador antiga em prosa", "new grant is 10%"),
    ("new 17% grant",    "concessao do fundador antiga em prosa", "new 10% grant"),
    ("grant is 17%",     "concessao do fundador antiga",          "10% (FOUNDER_BLOCH)"),
    ("Founder 17%",      "concessao do fundador antiga",          "Founder grant 10%"),
    ("53.7%",            "share de validador v1",                 "43.03%"),
    # Stakeabilidade do carryover: decidida, nao mais em aberto.
    ("still open, and",  "decisao de stakeabilidade ja tomada",   "decidida 2026-08-11 (§4A.1)"),
    ("still undecided: **liquid", "decisao de stakeabilidade ja tomada", "decidida 2026-08-11 (§4A.1)"),
    # Churn (2026-08-11): WARMUP_RATE_BPS 900 -> 25; piso MIN_DELEGATION_SAT
    # -> MIN_CHURN_SAT (= MIN_DEPOSIT_SAT). Autoridade: delegation.rs.
    ("WARMUP_RATE_BPS = 900", "taxa de churn antiga",  "WARMUP_RATE_BPS = 25"),
    ("900 bps",          "taxa de churn antiga",       "25 bps"),
    ("9% of active stake","taxa de churn antiga",      "0.25% (25 bps)"),
    ("9% per epoch",     "taxa de churn antiga",       "0.25% (25 bps)"),
    ("9%/epoch",         "taxa de churn antiga",       "0.25% (25 bps)"),
    # Licenca (2026-08-11): crates PoS relicenciados. Autoridade:
    # Cargo.toml de bloch-pos-committee + migracao spec §16.
    ("MIT OR Apache-2.0","licenca antiga dos crates PoS", "AGPL-3.0-or-later"),
]

# Componentes que LEGITIMAMENTE permanecem MIT/Apache-2.0 hoje (nunca foram
# AGPL, nao sao os "crates PoS" que a linha "licenca antiga dos crates PoS"
# em RETIRED guarda). Sem isso, qualquer tabela de licencas honesta —
# README.md's "Not everything in this repository is AGPL" — dispara um falso
# positivo por citar corretamente o proprio texto da licenca. A regra em
# RETIRED continua util para pegar um doc que ainda alegue que os crates PoS
# (bloch-pos-committee etc.) sao MIT/Apache; ela so nao deve disparar numa
# linha que tambem nomeia um destes componentes conhecidos.
LICENSE_EXCEPTION_COMPONENTS = (
    "bloch-sis-pow", "pqcrypto-internals", "libp2p-yamux", "anchoring/",
    "tools/faucet", "tools/indexer",
)

# Trechos que citam valores antigos DE PROPOSITO, como historico.
EXEMPT = ("earlier draft", "an earlier version", "was wrong", "superseded",
          "at the old", "used to be", "until 2026-08-11", "until 2026-08-12",
          "retired", "V2 nominal", "rascunho", "no longer", "went with",
          # A era 21 bi citada como historico (o split de 2026-08-12 e uma
          # redenominacao — o valor antigo aparece legitimamente ao explicar
          # a razao x100/21).
          "21 b era", "era 21 bi", "pre-split", "was 100,000", "was 21 b",
          "g3 measurement", "medido na g3", "da g3", "x100/21", "x 100/21")

# Documentos que descrevem a cadeia Genesis-3 VIVA, onde os numeros antigos
# sao os corretos, mais registros datados (releases, portal publico da G3) e
# analises seladas que citam o valor antigo DE PROPOSITO como objeto de estudo
# (o selo no topo do documento cobre o que a isencao por linha nao alcanca).
# `tools/faucet` e `tools/indexer` sao ferramentas da era G3 que declaram a
# PROPRIA licenca, e ela realmente e MIT/Apache — a regra acima e sobre os crates
# de PoS. Se essas duas devem seguir para AGPL e decisao de fundador/PMO em
# aberto (2026-08-11); ate la a declaracao delas e verdadeira, nao stale.
SKIP = ("tools/faucet/README.md", "tools/indexer/README.md",
        "TOKENOMICS_V2.md", "TOKENOMICS_V3.md", "CARRYOVER.md", "API.md",
        "PROJECT-STATUS.md", "/adr/", "/historical/", "/post-mortems/",
        "/releases/", "/portal/",
        "FLEET-BRIEF-",                  # briefs sao registros DATADOS do dia

        "BLOCH-POS-STAKE-CHURN.md",      # registro da decisao 900->25
        "BLOCH-POS-THREAT-MODEL.md",     # selado; texto mantido de proposito
        "BLOCH-POS-THREAT-MODEL-2.md")   # idem


def live_constants():
    """Read the constants the docs must agree with.

    Never hand-copy one of these into a doc or into RETIRED below — cite the
    constant name and let this function be the only place a number is typed
    twice (here, and in tokenomics_v4.rs itself).
    """
    src = open(TOK, encoding="utf-8").read()
    out = {}
    for name in ("TOTAL_SUPPLY_BLOCH", "FOUNDER_BLOCH", "CARRYOVER_TOTAL_BLOCH",
                 "VALIDATOR_EMISSION_BLOCH", "VC_BLOCH", "TEAM_BLOCH",
                 "MARKETING_BLOCH", "LIQUIDITY_BLOCH",
                 "LARGEST_CARRYOVER_ADDRESS_BLOCH", "CARRYOVER_MEASURED_HEIGHT",
                 "CARRYOVER_MEASURED_UTXOS", "SLOTS_PER_YEAR",
                 "FOUNDER_CLIFF_SLOTS", "FOUNDER_VESTING_SLOTS"):
        m = re.search(rf"pub const {name}: u(?:128|64) = ([0-9_]+)", src)
        if m:
            out[name] = int(m.group(1).replace("_", ""))
        else:
            # FOUNDER_CLIFF_SLOTS / FOUNDER_VESTING_SLOTS are `N * SLOTS_PER_YEAR`
            # expressions, not literals — pull the multiplier instead.
            m = re.search(rf"pub const {name}: u64 = (\d+) \* SLOTS_PER_YEAR", src)
            if m:
                out[name] = int(m.group(1))
    return out


def check_retired_table_fresh(consts):
    """Derive the handful of RETIRED "current" values that come straight from
    a live constant, and fail loudly if a hardcoded row has drifted out from
    under a later re-measurement (this is exactly how the four stale rows
    fixed on 2026-09-06 went unnoticed: CARRYOVER_TOTAL_BLOCH and
    LARGEST_CARRYOVER_ADDRESS_BLOCH were re-measured on 2026-08-11 but the
    "new" column in three RETIRED rows and the founder-total percentage kept
    citing the pre-re-measurement figures as current).
    """
    problems = []

    def fmt(n):
        return f"{n:,}"

    expected_validator_emission = (
        consts["TOTAL_SUPPLY_BLOCH"] - consts["CARRYOVER_TOTAL_BLOCH"]
        - consts["FOUNDER_BLOCH"] - consts["VC_BLOCH"] - consts["TEAM_BLOCH"]
        - consts["MARKETING_BLOCH"] - consts["LIQUIDITY_BLOCH"]
    )
    checks = [
        ("CARRYOVER_TOTAL_BLOCH", fmt(consts["CARRYOVER_TOTAL_BLOCH"])),
        ("LARGEST_CARRYOVER_ADDRESS_BLOCH",
         fmt(consts["LARGEST_CARRYOVER_ADDRESS_BLOCH"])),
        ("VALIDATOR_EMISSION_BLOCH", fmt(expected_validator_emission)),
    ]
    for name, expected in checks:
        if not any(expected in new for _old, _what, new in RETIRED):
            problems.append(
                f"{name} is now {expected} but no RETIRED row's 'new' column "
                f"says so — a stale figure may be citing an old value as current."
            )

    if "LARGEST_CARRYOVER_ADDRESS_BLOCH" in consts and "FOUNDER_BLOCH" in consts:
        founder_total = (
            consts["LARGEST_CARRYOVER_ADDRESS_BLOCH"] + consts["FOUNDER_BLOCH"]
        )
        founder_bps = founder_total * 10_000 // consts["TOTAL_SUPPLY_BLOCH"]
        expected_pct = f"{founder_bps / 100:.2f}%"
        if not any(expected_pct in new for _old, _what, new in RETIRED):
            problems.append(
                f"founder total share is now {expected_pct} "
                f"(FOUNDER_TOTAL_BLOCH={founder_total:,}, {founder_bps} bps) "
                f"but no RETIRED row's 'new' column says so."
            )

    if "FOUNDER_CLIFF_SLOTS" in consts and "FOUNDER_VESTING_SLOTS" in consts:
        expected_cliff = f"{consts['FOUNDER_CLIFF_SLOTS']}-year cliff"
        expected_vest = f"{consts['FOUNDER_VESTING_SLOTS']}-year vest"
        if not any(expected_cliff in new or "2-year cliff" in new
                   for _old, _what, new in RETIRED):
            problems.append(
                f"founder cliff is now {expected_cliff} but no RETIRED row's "
                f"'new' column says so, and none has been flipped by mistake."
            )
    return problems


def sweep():
    hits = []
    files = sorted(
        glob.glob(os.path.join(ROOT, "docs/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "spikes/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "tools/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "deploy/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "gips/**/*.md"), recursive=True)
        + glob.glob(os.path.join(ROOT, "apps/**/*.html"), recursive=True)
        + glob.glob(os.path.join(ROOT, "*.md"))
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
                if old.lower() not in low:
                    continue
                if what == "licenca antiga dos crates PoS" and any(
                    c in low for c in LICENSE_EXCEPTION_COMPONENTS
                ):
                    # This line names a component that is legitimately
                    # MIT/Apache-2.0 today, not a stale claim about the PoS
                    # crates — not a hit.
                    continue
                hits.append((rel, i, what, old, new, line.strip()[:88]))
    return hits


def main():
    consts = live_constants()
    print("constantes vivas em tokenomics_v4.rs:")
    for k, v in consts.items():
        print(f"  {k:<32} {v:>16,}")
    print()

    problems = check_retired_table_fresh(consts)
    if problems:
        print("RETIRED table is stale against live_constants():")
        for p in problems:
            print(f"  - {p}")
        print()
        if "--ci" in sys.argv:
            return 1

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
