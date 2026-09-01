#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Roll dos DOIS arquivais da Genesis-4 — os nos que sustentam o RPC publico.
#
# NAO E UM ROLLOUT DE VALIDADOR. Os arquivais nao tem chave ("no validator
# key", na propria Description da unit), nao propoem, nao atestam e nao tem
# memoria de voto. Por isso duas coisas que o rollout-release.sh PROIBE sao
# seguras aqui: nao existe guarda de duas epocas (nada pode assinar em
# duplicata) e o snapshot pre-roll PODE ser restaurado por script (meta.bin e
# ws_latest.bin nao carregam voto). Em troca, uma coisa que la e barata aqui e
# cara: enquanto um arquival esta fora, o quorum publico perde uma das duas
# testemunhas que nao dependem de socat de rollout.
#
# A REGRA QUE ORGANIZA TUDO: um arquival de cada vez, e ele SAI DO QUORUM
# PUBLICO ANTES DE SER PARADO. Parar o encaminhador 8080 primeiro tira o no da
# lista do proxy sem deploy nenhum (o fetch falha, o proxy o esfria e o joga
# para o fim da ordem). Ele so volta ao 8080 DEPOIS de uma prova de raiz. Assim
# um no que bifurcar no roll e detectado enquanto esta invisivel para o publico,
# em vez de ser servido.
#
# PROVA. A prova de um passo e `block_id` E `state_root` IDENTICOS aos da frota
# num slot COMUM e JA ASSENTADO — nunca "respondeu", nunca "a altura bateu".
# `behind_by_slots` nao serve de prova: um no que virou cabeca de si mesmo anda
# na propria bifurcacao e marca behind=0 (limite medido no ensaio de 31/08).
#
# SEGURANCA DE EXECUCAO. Por padrao este script NAO MUDA NADA: toda fase que
# escreve exige EXECUTAR=1 no ambiente e, sem isso, imprime o comando exato que
# rodaria. As fases de leitura (inventario/checar/provar/verificar) rodam
# sempre. Nao existe `pkill` aqui: so `systemctl` por NOME de unit.
#
# USO
#   export ROLLOUT_CONF=$HOME/bloch-rollout/rollout-release/rollout.conf.mainnet
#   bash rolar-arquivais.sh inventario            # leitura
#   bash rolar-arquivais.sh checar                # leitura: pre-condicoes
#   bash rolar-arquivais.sh provar <arquival>     # leitura: raiz vs frota
#   EXECUTAR=1 bash rolar-arquivais.sh rolar <arquival>   # o roll de UM
#   EXECUTAR=1 bash rolar-arquivais.sh reverter <arquival>
#   bash rolar-arquivais.sh verificar             # leitura
#
# ORDEM RECOMENDADA (o `checar` recusa outra):
#   1. 139.180.173.231  — ja tem `bloch-pos-cinco` em disco, entao tem DOIS
#      degraus de reversao (cinco e depois quatro) em vez de um.
#   2. 139.180.166.5    — so depois do primeiro estar provado e de volta no
#      8080 por uma epoca inteira.

set -u -o pipefail

: "${ROLLOUT_CONF:=$HOME/bloch-rollout/rollout-release/rollout.conf.mainnet}"
[ -r "$ROLLOUT_CONF" ] || { echo "conf ilegivel: $ROLLOUT_CONF" >&2; exit 2; }
# shellcheck disable=SC1090
. "$ROLLOUT_CONF"

: "${CHAVE:?}" "${BOXES:?}" "${ARQUIVAIS:?}" "${BIN_NOVO:?}" "${ESPERADO:?}" "${BIN_REMOTO:?}"
: "${BEHIND_OK:=2}" "${SLOT_MS:=30000}"
: "${EXECUTAR:=0}"
: "${PROXY_URL:=https://posternlabs.com/g4rpc}"

# Ordem obrigatoria do roll. Trocar isto e uma decisao, nao um detalhe.
ORDEM="139.180.173.231 139.180.166.5"

WORKA="$HOME/bloch-rollout/rollout-release/work-arquivais"
mkdir -p "$WORKA"

RUIM=0
diga() { printf '%s\n' "$*"; }
bem()  { printf '  ok   %s\n' "$*"; }
mal()  { printf '  RUIM %s\n' "$*"; RUIM=1; }

# ── transporte ─────────────────────────────────────────────────────────────
# `-n` NAO E DECORACAO. Sem ele o ssh le do stdin herdado e ENGOLE o resto de
# qualquer laco `while read ... < <(...)`. Foi assim que a prova de raiz
# conferia UMA referencia e concluia "so 1 referencia respondeu": o primeiro
# ssh comia as outras linhas. Uma prova que le menos testemunhas do que pensa
# e pior do que nenhuma prova.
G() { # G <host> <comando>  — ssh de leitura
  ssh -n -i "$CHAVE" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
      -o BatchMode=yes "ubuntu@$1" "$2" 2>/dev/null
}

# Toda escrita passa por aqui. Sem EXECUTAR=1 ela IMPRIME e nao roda.
E() { # E <host> <comando>
  if [ "$EXECUTAR" = 1 ]; then
    ssh -n -i "$CHAVE" -o StrictHostKeyChecking=no -o ConnectTimeout=20 \
        -o BatchMode=yes "ubuntu@$1" "$2"
  else
    printf '  [ENSAIO] ssh ubuntu@%s -- %s\n' "$1" "$2"
  fi
}

RPC() { # RPC <host> <porta> <metodo> [params-json]
  local m="$3" p="${4:-[]}"
  G "$1" "curl -s --max-time 20 -X POST 127.0.0.1:$2 -H 'content-type: application/json' \
      -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":$p}'"
}

# NOTA: tudo aqui usa PIPE, nunca here-string (`<<<`). Um here-string materializa
# um arquivo temporario, e quando o TMPDIR local encheu, em 31/08, TODA leitura
# falhou e o `checar` reportou os dois arquivais como "JA diverge". Uma
# ferramenta de prova nao pode confundir "nao consegui ler" com "bifurcou": o
# primeiro e um problema da minha maquina, o segundo para um rollout.
campo() { # campo <json> <caminho.pontilhado>
  printf '%s' "$1" | python3 -c '
import sys,json
try: d=json.loads(sys.stdin.read())
except Exception: sys.exit(1)
r=d.get("result")
if r is None: sys.exit(1)
for k in sys.argv[1].split("."):
    if not isinstance(r,dict) or k not in r: sys.exit(1)
    r=r[k]
print(r)' "$2"
}

# Porta de RPC canonica de uma caixa: a que o proprio encaminhador 8080 serve.
# Descoberta, nunca tabelada — foi tabela velha que quebrou a lista do proxy.
porta_de() { G "$1" "grep -o 'TCP:127.0.0.1:[0-9]*' /etc/systemd/system/bloch-rpc-8080.service | cut -d: -f3"; }

# ── referencias: caixas de VALIDADOR, nunca um arquival ────────────────────
# A frota e a cadeia. Um arquival nao corrobora outro arquival: sao os dois nos
# que este procedimento move, e correlacionar a testemunha com o objeto do
# teste e como o lote 12 de 31/08 parou a corrente.
referencias() {
  local n=0
  for b in $BOXES; do
    local p; p=$(porta_de "$b"); [ -n "$p" ] || continue
    local ci; ci=$(RPC "$b" "$p" getchaininfo); [ -n "$ci" ] || continue
    campo "$ci" block_id >/dev/null || continue
    printf '%s %s\n' "$b" "$p"; n=$((n+1))
    [ "$n" -ge 4 ] && return 0
  done
  [ "$n" -ge 2 ] || return 1
}

# ── a prova ────────────────────────────────────────────────────────────────
# Raiz identica num slot comum e ASSENTADO. Devolve 0 so se o alvo e >=2
# referencias, em caixas distintas, derem o MESMO block_id e o MESMO state_root.
prova_de_raiz() { # prova_de_raiz <host> <porta>
  local alvo="$1" pa="$2"
  local refs; refs=$(referencias) || { mal "sem 2 referencias de validador vivas — nao da para provar nada"; return 2; }

  # slot alvo: o menor finalizado entre as referencias, recuado 2 slots. Abaixo
  # do finalizado nenhum no honesto pode reescrever, entao uma divergencia ali
  # e divergencia de verdade e nao corrida de cabeca.
  local menor=999999999
  while read -r b p; do
    local ci fh sl; ci=$(RPC "$b" "$p" getchaininfo) || continue
    fh=$(campo "$ci" finalized_height) || continue
    sl=$(campo "$ci" slot) || continue
    # converte altura finalizada em slot seguro: usa o slot atual menos a folga
    local cand=$(( sl - (  $(campo "$ci" height) - fh ) - 2 ))
    [ "$cand" -lt "$menor" ] && menor=$cand
  done < <(printf '%s\n' "$refs")
  [ "$menor" -gt 0 ] 2>/dev/null || { mal "nao consegui derivar um slot assentado"; return 2; }

  # slots podem ser VAZIOS (nem todo slot vira bloco). Varre para tras ate achar
  # um que a primeira referencia sirva de verdade — 12 tentativas.
  local b1 p1; read -r b1 p1 < <(printf '%s\n' "$refs" | head -1)
  local S="" i=0
  while [ "$i" -lt 12 ]; do
    local cand=$(( menor - i )) j
    j=$(RPC "$b1" "$p1" getblockbyslot "[$cand]")
    if campo "$j" block_id >/dev/null 2>&1; then S=$cand; break; fi
    i=$((i+1))
  done
  [ -n "$S" ] || { mal "nenhum slot com bloco real nos 12 candidatos — nao provo nada sem raiz"; return 2; }

  local esperado_id="" esperado_sr="" concordam=0 caixas=""
  while read -r b p; do
    local j id sr
    j=$(RPC "$b" "$p" getblockbyslot "[$S]") || continue
    id=$(campo "$j" block_id)   || continue
    sr=$(campo "$j" state_root) || continue
    if [ -z "$esperado_id" ]; then esperado_id=$id; esperado_sr=$sr; concordam=1; caixas=$b; continue; fi
    if [ "$id" = "$esperado_id" ] && [ "$sr" = "$esperado_sr" ]; then
      concordam=$((concordam+1)); caixas="$caixas $b"
    else
      mal "referencia $b DISCORDA das outras no slot $S — a FROTA esta partida; nao role nada agora"
      return 1
    fi
  done < <(printf '%s\n' "$refs")
  [ "$concordam" -ge 2 ] || { mal "so $concordam referencia respondeu com raiz real no slot $S"; return 2; }

  local ja aid asr
  ja=$(RPC "$alvo" "$pa" getblockbyslot "[$S]")
  aid=$(campo "$ja" block_id)   || { mal "$alvo: sem block_id no slot $S (RPC mudo, em replay, ou leitura local falhou) — NAO e o mesmo que bifurcar"; return 2; }
  asr=$(campo "$ja" state_root) || { mal "$alvo: sem state_root no slot $S — NAO e o mesmo que bifurcar"; return 2; }

  if [ "$aid" = "$esperado_id" ] && [ "$asr" = "$esperado_sr" ]; then
    bem "$alvo PROVADO no slot $S: block_id=${aid:0:16}… state_root=${asr:0:16}… (contra $concordam validadores:$caixas)"
    printf '%s slot=%s id=%s sr=%s refs=%s\n' "$(date -u +%FT%TZ)" "$S" "$aid" "$asr" "$concordam" >> "$WORKA/provas-$alvo.txt"
    return 0
  fi
  mal "$alvo BIFURCOU no slot $S"
  mal "   alvo:  id=$aid sr=$asr"
  mal "   frota: id=$esperado_id sr=$esperado_sr"
  return 1
}

# ── digesto dos portoes ────────────────────────────────────────────────────
# `selfcheck --json` (com gates_digest) so existe a partir de 758ac1a8 e NAO
# esta no bed1b9ce que a frota vai receber. Enquanto o binario nao souber se
# declarar, o digesto do que esta EM PRODUCAO sai do fonte, pelo commit que o
# proprio `--version` imprime. Os dois caminhos produzem a MESMA string.
DIGESTO_CANONICO=a03bccc3e460ae15e7b233637334ab09610a684b66f77540ac88b1b7cc34876f

digesto_do_alvo() { # digesto_do_alvo <host> <caminho-do-binario>
  local j; j=$(G "$1" "$2 selfcheck --json 2>/dev/null")
  if printf '%s' "$j" | grep -q gates_digest; then
    printf '%s' "$j" | python3 -c 'import sys,json;print(json.load(sys.stdin)["gates_digest"])' 2>/dev/null && return 0
  fi
  return 1   # binario antigo: use digesto-portoes.sh contra o commit do --version
}

# ── fases ──────────────────────────────────────────────────────────────────
f_inventario() {
  diga "== inventario dos arquivais (so leitura) =="
  for a in $ARQUIVAIS; do
    diga "-- $a"
    local exec ver ativa p
    exec=$(G "$a" "grep -o '/home/ubuntu/g4/bloch-pos-[a-z0-9.-]*' /etc/systemd/system/bloch-archival.service | head -1")
    ver=$(G "$a" "$exec --version 2>&1 | head -1")
    ativa=$(G "$a" "systemctl is-active bloch-archival")
    p=$(porta_de "$a")
    diga "   ExecStart : $exec"
    diga "   --version : $ver"
    diga "   unit      : $ativa   8080 -> 127.0.0.1:$p"
    diga "   em disco  : $(G "$a" "ls /home/ubuntu/g4/ | grep '^bloch-pos-' | tr '\n' ' '")"
    diga "   8080 socat: $(G "$a" 'systemctl is-active bloch-rpc-8080')"
  done
}

f_checar() {
  diga "== pre-condicoes (so leitura) =="

  # 1. binario novo existe aqui e bate com ESPERADO
  if [ -r "$BIN_NOVO" ]; then
    bem "BIN_NOVO presente: $BIN_NOVO ($(shasum -a 256 "$BIN_NOVO" | cut -c1-16)…)"
  else
    mal "BIN_NOVO ilegivel: $BIN_NOVO"
  fi

  # 2. a frota esta INTEIRA antes de mexer em qualquer arquival
  local refs; refs=$(referencias) && bem "referencias de validador vivas: $(wc -l <<<"$refs" | tr -d ' ')" \
    || mal "menos de 2 caixas de validador respondendo — nao role arquival com a frota assim"

  # 3. os dois arquivais estao HOJE na cadeia (linha de base)
  for a in $ARQUIVAIS; do
    local p; p=$(porta_de "$a")
    [ -n "$p" ] || { mal "$a: sem encaminhador 8080 — o proxy publico depende dele"; continue; }
    prova_de_raiz "$a" "$p" >/dev/null
    case $? in
      0) bem "$a concorda com a frota agora" ;;
      1) mal "$a JA BIFUROU — resolva isso antes de qualquer roll" ;;
      *) mal "$a: NAO CONSEGUI PROVAR (leitura falhou; nao e uma acusacao de bifurcacao) — rode 'provar $a' e olhe o motivo" ;;
    esac
  done

  # 4. o publico responde e vem corroborado
  local pj; pj=$(curl -s --max-time 25 -X POST "$PROXY_URL" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}')
  if campo "$pj" height >/dev/null 2>&1; then
    local w; w=$(campo "$pj" corroboration.witnesses 2>/dev/null || echo '?')
    bem "$PROXY_URL responde (altura $(campo "$pj" height), testemunhas=$w)"
  else
    mal "$PROXY_URL nao respondeu — nao comece um roll com o publico ja quebrado"
  fi

  # 5. espaco para o snapshot
  for a in $ARQUIVAIS; do
    local livre; livre=$(G "$a" "df -BG --output=avail /home/ubuntu | tail -1 | tr -dc 0-9")
    [ "${livre:-0}" -ge 5 ] && bem "$a: ${livre}G livres (store ~1G)" || mal "$a: so ${livre:-?}G livres"
  done

  diga ""
  [ "$RUIM" = 0 ] && diga "PRE-CONDICOES OK — ordem obrigatoria: $ORDEM" || diga "PRE-CONDICOES REPROVADAS — nao role nada."
  return "$RUIM"
}

f_provar() {
  local a="${1:?uso: provar <arquival>}"
  local p; p=$(porta_de "$a"); : "${p:=16400}"
  prova_de_raiz "$a" "$p"
}

f_rolar() {
  local a="${1:?uso: rolar <arquival>}"
  case " $ARQUIVAIS " in *" $a "*) ;; *) echo "nao e um arquival: $a" >&2; return 2;; esac

  # A ordem e obrigatoria: o segundo so entra depois de o primeiro estar
  # provado e de volta no 8080.
  local primeiro; primeiro=$(awk '{print $1}' <<<"$ORDEM")
  if [ "$a" != "$primeiro" ] && [ ! -s "$WORKA/rolado-$primeiro" ]; then
    echo "RECUSO: $primeiro ainda nao foi rolado e provado. Um arquival por vez." >&2
    return 3
  fi

  local p; p=$(porta_de "$a"); : "${p:=16400}"
  local unit=/etc/systemd/system/bloch-archival.service
  local velho; velho=$(G "$a" "grep -o '/home/ubuntu/g4/bloch-pos-[a-z0-9.-]*' $unit | head -1")
  diga "== rolar $a : $velho -> $BIN_REMOTO =="
  [ "$EXECUTAR" = 1 ] || diga "   (ENSAIO — nada sera alterado; exporte EXECUTAR=1 para valer)"

  # -- 0. prova ANTES. Nao se rola um no que ja esta bifurcado.
  prova_de_raiz "$a" "$p" || { echo "ABORTA: $a nao esta provado ANTES do roll" >&2; return 1; }

  # -- 1. copiar o binario e conferir NO ALVO (ida e volta de sha256)
  local sl; sl=$(shasum -a 256 "$BIN_NOVO" | awk '{print $1}')
  if [ "$EXECUTAR" = 1 ]; then
    scp -q -i "$CHAVE" -o StrictHostKeyChecking=no "$BIN_NOVO" "ubuntu@$a:$BIN_REMOTO.entrando" || return 1
    local sr; sr=$(G "$a" "sha256sum $BIN_REMOTO.entrando | cut -d' ' -f1")
    [ "$sl" = "$sr" ] || { echo "ABORTA: sha256 nao bate ($sl != $sr)" >&2; return 1; }
    local v; v=$(G "$a" "chmod +x $BIN_REMOTO.entrando && $BIN_REMOTO.entrando --version 2>&1 | head -1")
    case "$v" in *"$ESPERADO"*) bem "binario no alvo: $v";; *) echo "ABORTA: --version no alvo nao contem '$ESPERADO': $v" >&2; return 1;; esac
    # portoes: se o binario sabe se declarar, o digesto TEM que bater
    local d; if d=$(digesto_do_alvo "$a" "$BIN_REMOTO.entrando"); then
      [ "$d" = "$DIGESTO_CANONICO" ] && bem "gates_digest = $d (bate com o canonico)" \
        || { echo "ABORTA: gates_digest $d != $DIGESTO_CANONICO — conjunto de portoes DIFERENTE" >&2; return 1; }
    else
      diga "   aviso: este binario nao tem 'selfcheck --json'; confira com digesto-portoes.sh"
    fi
    E "$a" "mv $BIN_REMOTO.entrando $BIN_REMOTO"
  else
    diga "  [ENSAIO] scp $BIN_NOVO -> ubuntu@$a:$BIN_REMOTO (sha $sl), --version deve conter '$ESPERADO'"
  fi

  # -- 2. SAIR DO QUORUM PUBLICO ANTES DE PARAR O NO.
  # E o passo que torna uma bifurcacao detectavel em vez de servida: o proxy
  # falha o fetch, esfria este destino e passa a ler do outro arquival + das 7
  # caixas. Nenhum deploy, nenhuma mudanca de env.
  diga "-- 2. tirando $a do quorum publico (para o socat 8080, o no segue rodando)"
  E "$a" "sudo systemctl stop bloch-rpc-8080"
  publico_ainda_serve || { echo "ABORTA: o RPC publico degradou ao tirar $a; religue o 8080" >&2; return 1; }

  # -- 3. parar o no e fotografar a store.
  # Seguro por script porque este no NAO TEM CHAVE: meta.bin/ws_latest.bin aqui
  # nao carregam memoria de voto (num validador isso seria assinatura dupla).
  diga "-- 3. parando o no e fotografando a store"
  E "$a" "sudo systemctl stop bloch-archival"
  E "$a" "rm -rf /home/ubuntu/g4/archival.preroll && mkdir -p /home/ubuntu/g4/archival.preroll && \
          cp -a /home/ubuntu/g4/archival/blocks.log /home/ubuntu/g4/archival/meta.bin \
                /home/ubuntu/g4/archival/ws_latest.bin /home/ubuntu/g4/archival.preroll/"

  # -- 4. trocar SO o token do binario na unit. Um dos dois arquivais tem
  # ExecStart de uma linha e o outro de varias com barra invertida; mexer so no
  # caminho do binario funciona nos dois sem reescrever a unit.
  diga "-- 4. trocando o binario na unit (guardando $unit.preroll)"
  E "$a" "sudo cp -a $unit $unit.preroll && \
          sudo sed -i 's#$velho#$BIN_REMOTO#' $unit && \
          grep -c '$BIN_REMOTO' $unit && ! grep -q '$velho' $unit && sudo systemctl daemon-reload"

  # -- 5. subir e esperar chegar na ponta.
  diga "-- 5. subindo"
  E "$a" "sudo systemctl start bloch-archival"
  esperar_ponta "$a" "$p" || { echo "NAO CHEGOU NA PONTA: reverta com  EXECUTAR=1 bash $0 reverter $a" >&2; return 1; }

  # -- 6. A PROVA. So aqui se decide se o roll valeu.
  diga "-- 6. prova de raiz depois do roll"
  prova_de_raiz "$a" "$p"; pr=$?
  if [ "$pr" = 2 ]; then
    echo "NAO CONSEGUI PROVAR (leitura falhou). NAO religue o 8080 e NAO conclua nada:" >&2
    echo "  resolva a leitura e rode:  bash $0 provar $a" >&2
    return 2
  fi
  if [ "$pr" != 0 ]; then
    echo "BIFURCOU. NAO religue o 8080. Dois caminhos, nesta ordem:" >&2
    echo "  a) transplante do snapshot (seguro: no sem chave):" >&2
    echo "     sudo systemctl stop bloch-archival && cp -a /home/ubuntu/g4/archival.preroll/. /home/ubuntu/g4/archival/ && sudo systemctl start bloch-archival" >&2
    echo "  b) se bifurcar de novo:  EXECUTAR=1 bash $0 reverter $a" >&2
    return 1
  fi

  # -- 7. so agora volta ao quorum publico
  diga "-- 7. devolvendo $a ao quorum publico"
  E "$a" "sudo systemctl start bloch-rpc-8080"
  [ "$EXECUTAR" = 1 ] && date -u +%FT%TZ > "$WORKA/rolado-$a"
  bem "$a rolado e provado. Espere UMA EPOCA INTEIRA (~16 min) antes do outro."
}

f_reverter() {
  local a="${1:?uso: reverter <arquival>}"
  local unit=/etc/systemd/system/bloch-archival.service
  diga "== reverter $a para o binario anterior =="
  # A unit pre-roll e a origem da verdade: ela aponta para o `bloch-pos-quatro`
  # que NUNCA foi sobrescrito (por isso BIN_REMOTO tem nome proprio).
  E "$a" "sudo systemctl stop bloch-rpc-8080"
  E "$a" "sudo systemctl stop bloch-archival"
  E "$a" "test -f $unit.preroll && sudo cp -a $unit.preroll $unit && sudo systemctl daemon-reload"
  E "$a" "sudo systemctl start bloch-archival"
  local p; p=$(porta_de "$a"); : "${p:=16400}"
  esperar_ponta "$a" "$p"
  if prova_de_raiz "$a" "$p"; then
    E "$a" "sudo systemctl start bloch-rpc-8080"
    [ "$EXECUTAR" = 1 ] && rm -f "$WORKA/rolado-$a"
    bem "$a revertido, provado e de volta no quorum"
  else
    echo "revertido e AINDA divergente: restaure a store" >&2
    echo "  sudo systemctl stop bloch-archival && cp -a /home/ubuntu/g4/archival.preroll/. /home/ubuntu/g4/archival/ && sudo systemctl start bloch-archival" >&2
    return 1
  fi
}

esperar_ponta() { # esperar_ponta <host> <porta>
  local a="$1" p="$2" i=0 anterior=-1 parado=0
  [ "$EXECUTAR" = 1 ] || { diga "  [ENSAIO] esperaria $a chegar na ponta"; return 0; }
  diga "   esperando $a chegar na ponta (ate ~40 min; um no que religa muito atras pode travar — e o defeito que o release novo corrige)"
  while [ "$i" -lt 80 ]; do
    sleep 30
    i=$((i+1))
    local ci h b; ci=$(RPC "$a" "$p" getchaininfo)
    h=$(campo "$ci" height 2>/dev/null) || { printf '   %02d sem RPC ainda\n' "$i"; continue; }
    b=$(campo "$ci" behind_by_slots 2>/dev/null || echo '')
    printf '   %02d altura=%s behind=%s\n' "$i" "$h" "${b:-n/d}"
    if [ -n "$b" ] && [ "$b" -le "$BEHIND_OK" ] 2>/dev/null; then bem "$a na ponta (behind=$b)"; return 0; fi
    # binario velho nao expoe behind_by_slots: cai para "a altura anda e alcanca"
    if [ -z "$b" ]; then
      local refs rh; refs=$(referencias); read -r rb rp < <(printf '%s\n' "$refs" | head -1)
      rh=$(campo "$(RPC "$rb" "$rp" getchaininfo)" height 2>/dev/null || echo 0)
      [ $(( rh - h )) -le 4 ] 2>/dev/null && { bem "$a alcancou a frota (altura $h vs $rh)"; return 0; }
    fi
    [ "$h" = "$anterior" ] && parado=$((parado+1)) || parado=0
    anterior=$h
    [ "$parado" -ge 6 ] && { echo "   cabeca imovel em $h por 6 leituras" >&2; return 1; }
  done
  return 1
}

publico_ainda_serve() {
  [ "$EXECUTAR" = 1 ] || { diga "  [ENSAIO] conferiria $PROXY_URL"; return 0; }
  local i=0
  while [ "$i" -lt 5 ]; do
    local j; j=$(curl -s --max-time 25 -X POST "$PROXY_URL" -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}')
    if campo "$j" height >/dev/null 2>&1; then
      bem "publico segue servindo (altura $(campo "$j" height))"; return 0
    fi
    i=$((i+1)); sleep 10
  done
  return 1
}

f_verificar() {
  diga "== verificar (so leitura) =="
  for a in $ARQUIVAIS; do
    local p exec ver
    p=$(porta_de "$a"); exec=$(G "$a" "grep -o '/home/ubuntu/g4/bloch-pos-[a-z0-9.-]*' /etc/systemd/system/bloch-archival.service | head -1")
    ver=$(G "$a" "$exec --version 2>&1 | head -1")
    diga "-- $a  $ver"
    [ "$(G "$a" 'systemctl is-active bloch-archival')" = active ] && bem "bloch-archival ativa" || mal "bloch-archival NAO ativa"
    [ "$(G "$a" 'systemctl is-active bloch-rpc-8080')" = active ] && bem "bloch-rpc-8080 ativa" || mal "bloch-rpc-8080 NAO ativa (fora do quorum publico)"
    prova_de_raiz "$a" "${p:-16400}" || mal "$a nao passou na prova de raiz"
  done
  publico_ainda_serve || mal "o RPC publico nao respondeu"
  diga ""
  [ "$RUIM" = 0 ] && diga "VERIFICADO" || diga "VERIFICACAO REPROVADA"
  return "$RUIM"
}

main() {
  case "${1:-}" in
    inventario) f_inventario ;;
    checar)     f_checar ;;
    provar)     shift; f_provar "$@" ;;
    rolar)      shift; f_rolar "$@" ;;
    reverter)   shift; f_reverter "$@" ;;
    verificar)  f_verificar ;;
    *) sed -n '2,50p' "$0"; exit 2 ;;
  esac
}

main "$@"; exit $?
