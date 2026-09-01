#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# O digesto dos portoes de consenso de um binario que NAO sabe se declarar.
#
# `bloch-pos selfcheck --json`, com `gates_digest`, entrou em 758ac1a8 e NAO
# esta no bed1b9ce que a frota vai receber, nem no `quatro`/`cinco` que rodam
# hoje. Ate ele chegar em producao, a unica pergunta que importa — "este
# binario conhece o mesmo conjunto de portoes que a rede?" — se responde pelo
# FONTE, ancorado no commit que o proprio `--version` imprime.
#
# Os dois caminhos produzem a MESMA string: SHA3-256 sobre uma linha
# `NOME=<epoca|inert>\n` por portao, ORDENADAS por nome. Ordenadas de proposito,
# para o digesto ser propriedade do CONJUNTO e nao da ordem de declaracao.
#
# USO
#   bash digesto-portoes.sh                      # digesto do HEAD deste worktree
#   bash digesto-portoes.sh 0a3a436a             # de um commit (ex.: o `quatro`)
#   bash digesto-portoes.sh 0a3a436a 46133196    # compara dois
#
# VERIFICACAO (nao muda nada):
#   bash digesto-portoes.sh 0a3a436a 46133196
#   # os dois TEM que sair iguais: e a prova de que `quatro` e `cinco` declaram
#   # o mesmo consenso, e portanto de que os arquivais nao correm risco de
#   # bifurcar por portao — so por defeito de catch-up.
#
# ROLLBACK: nao ha. Este script so le git e imprime.

set -u -o pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PARAMS=crates/bloch-pos-committee/src/params.rs

# A LISTA. Tem que ser a mesma de CONSENSUS_GATES em bloch-pos-node/src/main.rs;
# o tripwire `gate_table_mirrors_params_exactly` (758ac1a8) e quem garante isso
# do lado do binario. Aqui ela e derivada do fonte por varredura, para nao
# depender de eu manter uma copia certa: pega TODA constante *_ACTIVATION_EPOCH
# publica de params.rs.
digesto_de() { # digesto_de <commit-ish|WORKTREE>
  local ref="$1" fonte
  if [ "$ref" = WORKTREE ]; then fonte=$(cat "$PARAMS"); else fonte=$(git show "$ref:$PARAMS" 2>/dev/null); fi
  [ -n "$fonte" ] || { echo "sem $PARAMS em $ref" >&2; return 1; }
  printf '%s\n' "$fonte" | python3 -c '
import sys, re, hashlib
src = sys.stdin.read()
pat = re.compile(r"^pub const ([A-Z0-9_]*_ACTIVATION_EPOCH)\s*:\s*u64\s*=\s*([0-9_]+|u64::MAX)\s*;", re.M)
linhas = []
for nome, val in pat.findall(src):
    val = "inert" if val == "u64::MAX" else str(int(val.replace("_", "")))
    linhas.append(f"{nome}={val}\n")
if not linhas:
    sys.exit("nenhuma constante *_ACTIVATION_EPOCH encontrada")
linhas.sort()
sys.stderr.write("".join("  " + l for l in linhas))
print(hashlib.sha3_256("".join(linhas).encode()).hexdigest())'
}

if [ "$#" -eq 0 ]; then set -- WORKTREE; fi

primeiro=""
for ref in "$@"; do
  echo "== $ref"
  d=$(digesto_de "$ref") || exit 1
  echo "  gates_digest = $d"
  if [ -z "$primeiro" ]; then primeiro=$d
  elif [ "$d" != "$primeiro" ]; then
    echo ""
    echo "DIFEREM. Conjuntos de portoes distintos: um destes binarios fica"
    echo "consenso-morto na epoca do primeiro portao que o outro conhece."
    exit 1
  fi
done

if [ "$#" -gt 1 ]; then echo ""; echo "IGUAIS — mesmo conjunto de portoes, mesma declaracao de compatibilidade."; fi
