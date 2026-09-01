#!/usr/bin/env bash
# cleanup-references.sh — remove the dead dials, WITHOUT inventing a new way
# to restart validators.
#
# THIS SCRIPT DOES NOT RESTART ANYTHING. It cannot: it has no stop, no start,
# no systemctl. Every restart in this fleet goes through ONE tool that already
# has the batch discipline, the epoch guard and the revert — ~/bloch-rollout/
# rollout-release/rollout-release.sh — which already supports exactly this
# cleanup via PEERS_LIMPAR=1 (it rewrites "--peers" to the live inventory while
# staging the unit, and preserves the pre-roll unit for REVERTER).
#
# Restarting validators outside that discipline risks double-signing: the node
# holds a 32-minute double-vote guard for a reason, and the rollout refuses to
# SUBIR before e+2 because of it. So this script's whole job is to PLAN:
#   - prove the cleanup is needed and safe (read-only preflight),
#   - show what the peer list becomes, character for character,
#   - print the exact commands, in order, with the rollback for each,
#   - and refuse to run any of them without an explicit, typed confirmation.
#
# Usage:
#   cleanup-references.sh plan          # default: prints the plan, runs nothing
#   cleanup-references.sh preflight     # read-only gates only
#   cleanup-references.sh diff          # current vs derived --peers, per unit
#   cleanup-references.sh run --i-have-read-the-plan
#                                       # hands control to rollout-release.sh,
#                                       # batch by batch, pausing between each
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${REFINT_CONF:-$HERE/reference-integrity.conf}"
ROLLOUT="${ROLLOUT_DIR:-$HOME/bloch-rollout/rollout-release}"
ROLLOUT_CONF_FILE="${ROLLOUT_CONF:-$ROLLOUT/rollout.conf.mainnet}"
MODE="${1:-plan}"; shift || true
CONFIRM=""
while [ $# -gt 0 ]; do case "$1" in --i-have-read-the-plan) CONFIRM=1; shift;; -c) CONF="$2"; shift 2;; --reuse) REUSE="$2"; shift 2;; *) shift;; esac; done
[ -f "$CONF" ] || { echo "REFUSED: missing conf $CONF" >&2; exit 2; }
# shellcheck disable=SC1090
. "$CONF"
: "${STATE_DIR:=$HOME/.bloch-reference-integrity}" "${REUSE:=}"

say() { echo "$*"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────────────────"; }

INV="${REUSE:-$(REFINT_WORK="$STATE_DIR" "$HERE/inventory.sh" -c "$CONF")}" || { echo "REFUSED: inventory failed"; exit 2; }
[ -f "$INV/PARTIAL" ] && { echo "REFUSED: partial inventory. A cleanup derived from a partial view would delete live peers."; exit 2; }

# The rollout's PEERS_LIMPAR builds --peers from ITS OWN inventory, which is
# validators only. This plan must show the same string the rollout will write,
# character for character, or the plan is fiction. Hence live-validators.txt.
: "${PEER_SCOPE:=validators}"
case "$PEER_SCOPE" in
  validators) LIVE_SRC="$INV/live-validators.txt";;
  all)        LIVE_SRC="$INV/live-endpoints.txt";;
  *) echo "REFUSED: PEER_SCOPE must be 'validators' or 'all'"; exit 2;;
esac
LIVE=$(grep -v '^$' "$LIVE_SRC" | sort -u)
ALL_LIVE=$(grep -v '^$' "$INV/live-endpoints.txt" | sort -u)
NLIVE=$(printf '%s\n' "$LIVE" | wc -l | tr -d ' ')
NVAL=$(awk -F'\t' '$3=="validator" && $5=="active"' "$INV/nodes.tsv" | wc -l | tr -d ' ')
NOBS=$(awk -F'\t' '$3=="observer" && $5=="active"' "$INV/nodes.tsv" | wc -l | tr -d ' ')
DEAD_TOTAL=$(python3 - "$INV" <<'PY'
import sys,os
inv=sys.argv[1]
live=set(l.strip() for l in open(os.path.join(inv,"live-endpoints.txt")) if l.strip())
n=0
for l in open(os.path.join(inv,"peers.tsv")):
    if l.startswith("#") or not l.strip(): continue
    if l.rstrip("\n").split("\t")[2] not in live: n+=1
print(n)
PY
)
UNITS_ROTTEN=$(python3 - "$INV" <<'PY'
import sys,os,collections
inv=sys.argv[1]
live=set(l.strip() for l in open(os.path.join(inv,"live-endpoints.txt")) if l.strip())
d=collections.defaultdict(int)
for l in open(os.path.join(inv,"peers.tsv")):
    if l.startswith("#") or not l.strip(): continue
    h,u,p=l.rstrip("\n").split("\t")
    if p not in live: d[(h,u)]+=1
print(len(d))
PY
)

preflight() {
  local bad=0
  rule; say "PREFLIGHT (read-only) — evidence: $INV"; rule
  say "  inventory:        $NVAL validators + $NOBS observers, $NLIVE live endpoints"
  say "  dead dials:       $DEAD_TOTAL entries across $UNITS_ROTTEN units"
  # 1. the chain must be healthy BEFORE we touch it
  # Heads are compared ONLY within the same slot. The RPC sweep takes minutes
  # and a slot is 30 s, so counting distinct heads across the whole sweep
  # reports a fork on a converged fleet. Finalized height is the slot-insensitive
  # signal and is the one that must be unanimous.
  local splitslots fin
  splitslots=$(awk -F'\t' 'NF>5 && $3 ~ /^[0-9]+$/ && $6!=""{print $3"\t"$6}' "$INV/rpc.tsv" \
      | sort -u | cut -f1 | uniq -d | wc -l | tr -d ' ')
  fin=$(awk -F'\t' 'NF>4 && $5!=""{print $5}' "$INV/rpc.tsv" | sort -u | wc -l | tr -d ' ')
  if [ "$splitslots" = 0 ] && [ "$fin" = 1 ]; then
    say "  chain:            converged (one head per slot, one finalized height $(awk -F'\t' 'NF>4 && $5!=""{print $5}' "$INV/rpc.tsv" | sort -u)) — safe to roll"
  else
    say "  chain:            REFUSE — $splitslots slot(s) with disagreeing heads, $fin distinct finalized heights. Converge first: a peer rewrite during a fork changes who each side can hear."; bad=1
  fi
  # 2. the rollout tool must exist and already know how to do this
  if [ -x "$ROLLOUT/rollout-release.sh" ]; then say "  rollout tool:     $ROLLOUT/rollout-release.sh present"
  else say "  rollout tool:     REFUSE — $ROLLOUT/rollout-release.sh not found. Do not improvise a restart loop."; bad=1; fi
  if grep -q 'PEERS_LIMPAR' "$ROLLOUT/rollout-release.sh" 2>/dev/null; then say "  PEERS_LIMPAR:     supported by the rollout (rewrites --peers from \$INV while staging)"
  else say "  PEERS_LIMPAR:     REFUSE — this rollout build does not support it; do not patch units by hand."; bad=1; fi
  if [ -f "$ROLLOUT_CONF_FILE" ] && grep -qE '^PEERS_LIMPAR=1' "$ROLLOUT_CONF_FILE"; then say "  rollout conf:     PEERS_LIMPAR=1 already set in $(basename "$ROLLOUT_CONF_FILE")"
  else say "  rollout conf:     set PEERS_LIMPAR=1 in $ROLLOUT_CONF_FILE before PREPARAR"; fi
  # 3. structural hazards
  if [ -s "$INV/anomalies.txt" ]; then say "  anomalies:        REFUSE — resolve these first:"; sed 's/^/                      /' "$INV/anomalies.txt"; bad=1
  else say "  anomalies:        none (no double-sign risk, no orphan RPC, no unit whose name lies)"; fi
  # 4. TWO INDEPENDENT DERIVATIONS MUST AGREE. This tool discovers nodes by unit
  #    CONTENT; the rollout discovers them by unit NAME (ls bloch-n*.service) and
  #    builds its own peer string from that. If those two disagree, one of them is
  #    blind — which is precisely the failure that let a stale twin unit sign for
  #    29 hours — and no cleanup runs until the disagreement is explained.
  local rinv="${ROLLOUT_INV:-$ROLLOUT/work-mainnet/inventario.tsv}"
  if [ -f "$rinv" ]; then
    local a b
    a=$(printf '%s\n' "$LIVE" | sort -u)
    b=$(awk -F'\t' 'NF>=5{print $3":"$5}' "$rinv" | sort -u)
    if [ "$a" = "$b" ]; then say "  cross-check:      content-derived list == rollout's name-derived list ($(printf '%s\n' "$a" | wc -l | tr -d ' ') endpoints)"
    else
      say "  cross-check:      REFUSE — the two derivations disagree:"
      say "                      only content-derived: $(comm -23 <(printf '%s\n' "$a") <(printf '%s\n' "$b") | tr '\n' ' ')"
      say "                      only rollout-derived: $(comm -13 <(printf '%s\n' "$a") <(printf '%s\n' "$b") | tr '\n' ' ')"
      say "                      (rollout inventory may be stale: re-run 'rollout-release.sh inventario')"
      bad=1
    fi
  else
    say "  cross-check:      rollout inventory absent ($rinv) — run 'rollout-release.sh inventario' first so the two derivations can be compared"
  fi
  # 5. the derived list must be sane before anyone writes it into 63 units
  if [ "$NLIVE" -lt 1 ]; then say "  derived list:     REFUSE — empty"; bad=1
  elif [ "$NLIVE" -lt $(( (NVAL + NOBS) * 9 / 10 )) ]; then say "  derived list:     REFUSE — only $NLIVE endpoints for $((NVAL+NOBS)) active nodes"; bad=1
  else say "  derived list:     $NLIVE endpoints, $(printf '%s\n' "$LIVE" | cut -d: -f1 | sort -u | wc -l | tr -d ' ') hosts — plausible"; fi
  rule
  return $bad
}

case "$MODE" in
  preflight) preflight; exit $?;;

  diff)
    "$HERE/derive-peers.sh" check --reuse "$INV"; exit $?;;

  plan|run)
    rule
    say "CLEANUP PLAN — dead peer references, Genesis-4 fleet"
    say "generated $(date -u +%FT%TZ) from $INV"
    rule
    say
    say "WHAT IS WRONG"
    say "  $DEAD_TOTAL dead dial entries survive in $UNITS_ROTTEN units. Each unit's"
    say "  --peers still names the decommissioned 'classic' hosts. The devnet"
    say "  transport retries them forever and logs nothing, so the cost is paid as"
    say "  connection churn and latency, never as an error anyone sees."
    say
    say "WHAT CHANGES"
    say "  Exactly one string per unit: --peers, rewritten to the $NLIVE validator endpoints (scope=$PEER_SCOPE)"
    say "  DERIVED from active units at staging time. Nothing else in the unit is"
    say "  touched — same binary, same --data-dir, same ports, same key."
    say
    say "  new --peers (identical for every unit except its own entry; the rollout"
    say "  emits the same SET ordered by validator index rather than lexically):"
    printf '%s\n' "$LIVE" | paste -sd, - | fold -w 68 | sed 's/^/    /'
    say
    say "WHY IT GOES THROUGH THE ROLLOUT AND NOT THROUGH THIS SCRIPT"
    say "  A --peers change needs a restart. Restarting validators outside the"
    say "  rollout's batch discipline risks double-signing — the node's 32-minute"
    say "  double-vote guard exists because that has nearly happened. The rollout"
    say "  stops at most BATCH_MAX nodes, one per box, refuses to bring them back"
    say "  before e+2, keeps the pre-roll unit for REVERTER, and checks the floor"
    say "  of live validators (PISO) before every batch."
    say
    say "PRE-CONDITIONS"
    preflight || { say; say "REFUSED: preflight failed. Nothing below may be run."; exit 1; }
    say
    say "COMMANDS, IN ORDER (nothing here has been executed)"
    say "  export ROLLOUT_CONF=$ROLLOUT_CONF_FILE"
    say "  # 0. confirm the conf carries PEERS_LIMPAR=1 and the CURRENT binary"
    say "  #    (this is a peer cleanup, not a version change: BIN_NOVO must be"
    say "  #     the binary already running, so the only delta is --peers)"
    say "  grep -E '^(PEERS_LIMPAR|BIN_NOVO|BIN_REMOTO|ESPERADO|PISO|BATCH_MAX)=' \$ROLLOUT_CONF"
    say "  # 1. rebuild the rollout's own inventory + batches (read-only)"
    say "  $ROLLOUT/rollout-release.sh inventario"
    say "  $ROLLOUT/rollout-release.sh checar"
    nb=$(( (NVAL + 5) / 6 ))
    say "  # 2. batch by batch — $NVAL validators at BATCH_MAX=6 is ~$nb batches,"
    say "  #    ~2 epochs (32 min) apart. Between batches, re-run the detector."
    say "  for L in \$(seq 0 $((nb-1))); do"
    say "     $ROLLOUT/rollout-release.sh PREPARAR \$L    # stages, stops nothing"
    say "     $ROLLOUT/rollout-release.sh PARAR    \$L"
    say "     $ROLLOUT/rollout-release.sh SUBIR    \$L    # refuses before e+2"
    say "     $HERE/rot-detector.sh                      # must not regress"
    say "  done"
    say "  # 3. observers/archival are NOT in the rollout's batches and hold no"
    say "  #    key, so they are done last, one at a time, by hand:"
    awk -F'\t' '$3=="observer" && $5=="active"{print "     #   "$2" "$4}' "$INV/nodes.tsv"
    say "     $HERE/derive-peers.sh private --for <host>:19100"
    say "  # 4. final proof"
    say "  $ROLLOUT/rollout-release.sh verificar"
    say "  $HERE/rot-detector.sh          # must print OK: ... 0 dead references"
    say
    say "ROLLBACK"
    say "  Per node, immediately:  $ROLLOUT/rollout-release.sh REVERTER <idx> --imediato"
    say "     restores the exact pre-roll unit file the rollout saved before"
    say "     touching it (WORK/units/<unit>.preroll) and restarts on the SAME"
    say "     --data-dir, so no state is rebuilt and no key moves."
    say "  Per batch: REVERTER each index in the batch; the batch is at most 6"
    say "     nodes and never more than one per box, so a full revert leaves"
    say "     >= PISO validators live throughout."
    say "  Whole change: the pre-roll units are the complete rollback. The old"
    say "     --peers is a strict SUPERSET of the new one (it holds the same $NLIVE"
    say "     live validator endpoints plus the dead ones), so reverting cannot disconnect"
    say "     a node from anything it can currently reach. Worst case a reverted"
    say "     node resumes wasting dials on dead hosts — the status quo."
    say "  Nothing in this plan changes consensus, arms an activation constant,"
    say "     or touches key material. --peers is a transport hint only."
    rule
    if [ "$MODE" = plan ]; then
      say "This was a PLAN. Nothing was executed. To proceed, read it, then run:"
      say "  $0 run --i-have-read-the-plan"
      exit 0
    fi
    [ "$CONFIRM" = 1 ] || { say "REFUSED: 'run' requires --i-have-read-the-plan"; exit 2; }
    say "CONFIRMED. Handing control to the rollout, batch by batch."
    say "This script still runs no systemctl of its own; it only calls the rollout,"
    say "and it stops at the first refusal."
    export ROLLOUT_CONF="$ROLLOUT_CONF_FILE"
    "$ROLLOUT/rollout-release.sh" inventario || exit 1
    "$ROLLOUT/rollout-release.sh" checar || exit 1
    for L in $(seq 0 $((nb-1))); do
      say; rule; say "BATCH $L — press Enter to PREPARAR, Ctrl-C to stop here"; rule
      read -r _
      "$ROLLOUT/rollout-release.sh" PREPARAR "$L" || exit 1
      say "PREPARAR done, nothing stopped. Press Enter to PARAR batch $L."
      read -r _
      "$ROLLOUT/rollout-release.sh" PARAR "$L" || exit 1
      "$ROLLOUT/rollout-release.sh" SUBIR "$L" || { say "SUBIR refused/failed — REVERTER the batch before continuing"; exit 1; }
      "$HERE/rot-detector.sh" || say "(detector still reports rot — expected until the last batch)"
    done
    "$ROLLOUT/rollout-release.sh" verificar
    "$HERE/rot-detector.sh"
    ;;
  *) sed -n '2,32p' "$0"; exit 2;;
esac
