#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
Genesis-4 carryover builder.

Takes the raw UTXO snapshot produced by `bloch-snapshot-utxo` at the terminal
height and turns it into the Genesis-4 opening balances:

    1. drop every output belonging to a founder-controlled address (taint)
    2. aggregate the rest by address
    3. if the total exceeds the cap, scale every balance pro-rata
    4. emit a deterministic TSV plus a SHAKE-256 commitment

Why pro-rata and not first-come or per-address: it treats a holder identically
regardless of when the coins were acquired, and it needs no discretion. Any
rule with a knob is a rule someone has to be trusted not to turn.

The commitment is a TRUST ANCHOR, not a proof — the same caveat
`bloch-snapshot-utxo` states about its own output. Several operators should run
this independently on the same input and compare digests; agreement is the
evidence, not the digest itself.

Usage:
    build_carryover.py --utxo utxo-snapshot.tsv --founder <hash20>[,<hash20>...]
                       [--cap-bloch 300000000] --out genesis4-carryover.tsv
"""

import argparse
import gzip
import hashlib
import sys
from collections import defaultdict

SAT_PER_BLOCH = 100_000_000


def read_utxos(path):
    """Yield (txid, vout, value_sat, addr_hash) from a snapshot TSV."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 4:
                raise SystemExit(f"{path}:{lineno}: esperava 4 colunas, veio {len(parts)}")
            txid, vout, value, addr = parts
            yield txid, int(vout), int(value), addr


def build(utxo_path, founder_addrs, cap_bloch):
    cap_sat = cap_bloch * SAT_PER_BLOCH
    by_addr = defaultdict(int)
    counts = defaultdict(int)
    founder_sat = 0
    founder_utxos = 0

    for _txid, _vout, value, addr in read_utxos(utxo_path):
        if addr in founder_addrs:
            founder_sat += value
            founder_utxos += 1
            continue
        by_addr[addr] += value
        counts[addr] += 1

    total_sat = sum(by_addr.values())

    # Pro-rata scale-down. Integer division truncates, so the result is at or
    # just under the cap, never over: an allocation that overshoots the cap by
    # rounding would break the supply invariant it exists to enforce.
    if cap_sat and total_sat > cap_sat:
        scale_num, scale_den = cap_sat, total_sat
        scaled = {a: v * scale_num // scale_den for a, v in by_addr.items()}
    else:
        scale_num, scale_den = 1, 1
        scaled = dict(by_addr)

    # Deterministic order: by address hash. Never by iteration order of a dict.
    rows = sorted(scaled.items())
    return {
        "rows": rows,
        "counts": counts,
        "raw_total_sat": total_sat,
        "out_total_sat": sum(v for _, v in rows),
        "founder_sat": founder_sat,
        "founder_utxos": founder_utxos,
        "scaled": (scale_num, scale_den) != (1, 1),
        "cap_sat": cap_sat,
    }


def write(result, out_path):
    """Write `addr<TAB>value_sat` and return the SHAKE-256 commitment."""
    h = hashlib.shake_256()
    with open(out_path, "w") as fh:
        for addr, value in result["rows"]:
            line = f"{addr}\t{value}\n"
            fh.write(line)
            h.update(line.encode())
    return h.hexdigest(32)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--utxo", required=True, help="snapshot do bloch-snapshot-utxo (.tsv ou .tsv.gz)")
    ap.add_argument("--founder", default="",
                    help="enderecos a EXCLUIR, separados por virgula. Vazio por padrao: "
                         "o carryover atravessa inteiro. Uma lista de exclusao e poder "
                         "sem auditoria — quem a escreve decide quem fica de fora — e "
                         "a decisao de 2026-08-11 foi nao ter nenhuma.")
    ap.add_argument("--cap-bloch", type=int, default=0,
                    help="0 = sem teto (padrao). O teto de 300M foi aposentado "
                         "junto com a exclusao do fundador: ele existia para limitar "
                         "o que legados recebiam enquanto o fundador era excluido.")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    founder = {a.strip() for a in args.founder.split(",") if a.strip()}
    if not founder:
        print("nenhuma exclusao: o carryover inteiro atravessa, o saldo do")
        print("fundador junto — ele minerou na mesma cadeia sob as mesmas regras.")

    r = build(args.utxo, founder, args.cap_bloch)
    digest = write(r, args.out)

    b = lambda sat: f"{sat / SAT_PER_BLOCH:,.2f}"
    print(f"fundador (excluido) : {b(r['founder_sat']):>20} BLCH em {r['founder_utxos']:,} utxos")
    print(f"nao-fundador bruto  : {b(r['raw_total_sat']):>20} BLCH em {len(r['rows'])} enderecos")
    print(f"teto                : {b(r['cap_sat']):>20} BLCH")
    if r["scaled"]:
        keep = r["out_total_sat"] / r["raw_total_sat"] * 100
        print(f"RATEIO APLICADO     : cada holder preserva {keep:.4f}%")
    else:
        print("rateio              : nao foi preciso (abaixo do teto)")
    print(f"carryover final     : {b(r['out_total_sat']):>20} BLCH")
    print(f"arquivo             : {args.out}")
    print(f"SHAKE-256           : {digest}")

    if r["out_total_sat"] > r["cap_sat"] > 0:
        print("ERRO: saida acima do teto", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
