#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-health.sh — the health check a Bloch Genesis-4 validator alarms on.
# Nagios-style exit codes: 0 OK, 1 WARN, 2 CRIT — wire it to a systemd timer,
# cron+alert, or any monitoring agent that understands exit codes.
#
# What it checks, and why each one is THE thing to alarm on here:
#
#   liveness    RPC answers at all. A dead node leaks stake (inactivity leak)
#               from the first missed epoch.
#   sync        `behind_by_slots` — under PoS this IS the "am I synced"
#               number; there is no difficulty to infer it from.
#   finality    the finalized epoch ADVANCES between runs. Height moving while
#               finality is stuck is precisely how the 2026-08 stalls looked
#               from one node: blocks arrive, settlement doesn't. Height is
#               the number that is NOT the guarantee.
#   divergence  same finalized epoch on a reference node => same finalized
#               root. A forked node still answers, still attests, still looks
#               healthy in every local metric — divergence NEVER shows up
#               without comparing against a second node (2026-08-30 lesson:
#               15 nodes on one head, 33 alone, all "fine").
#   duty        with --index: this validator's registry state is `active` and
#               not slashed/exiting-unexpectedly.
#   exposure    the RPC port is not listening on a routable address. The RPC
#               has no authentication; a routable bind is an incident, not a
#               config choice (all 64 fleet nodes were exposed on 2026-08-30).
#
# Usage:
#   blochv-health.sh [--rpc URL]            (default http://127.0.0.1:16400)
#                    [--index N]            alarm on this validator's state
#                    [--reference URL]      second node for divergence check
#                    [--max-behind N]       slots (default 3)
#                    [--stall-secs N]       max age of finality progress
#                                           (default 3600 = ~3.75 epochs)
#                    [--state-dir DIR]      progress marker (default
#                                           ~/.cache/blochv-health)
#
# Dependencies: curl, python3 (JSON parsing; every fleet box has both).

set -u

RPC="http://127.0.0.1:16400"
REFERENCE=""
INDEX=""
MAX_BEHIND=3
STALL_SECS=3600
STATE_DIR="${HOME}/.cache/blochv-health"

while [ $# -gt 0 ]; do
  case "$1" in
    --rpc)        RPC="$2"; shift 2 ;;
    --reference)  REFERENCE="$2"; shift 2 ;;
    --index)      INDEX="$2"; shift 2 ;;
    --max-behind) MAX_BEHIND="$2"; shift 2 ;;
    --stall-secs) STALL_SECS="$2"; shift 2 ;;
    --state-dir)  STATE_DIR="$2"; shift 2 ;;
    -h|--help)    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-health: unknown argument $1" >&2; exit 2 ;;
  esac
done

command -v curl    >/dev/null 2>&1 || { echo "CRIT curl not found"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "CRIT python3 not found"; exit 2; }

STATUS=0
raise() { [ "$1" -gt "$STATUS" ] && STATUS=$1; }
ok()   { printf 'OK    %s\n' "$*"; }
w()    { printf 'WARN  %s\n' "$*"; raise 1; }
crit() { printf 'CRIT  %s\n' "$*"; raise 2; }

rpc_call() { # rpc_call <url> <method> [params-json]
  curl -sS --max-time 10 -X POST "$1" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" 2>/dev/null
}
jget() { # jget <json> <python-expr over r (the result object)>
  python3 -c '
import json,sys
try:
    r = json.loads(sys.argv[1]).get("result")
    v = eval(sys.argv[2], {"r": r})
    print("" if v is None else v)
except Exception:
    print("")' "$1" "$2" 2>/dev/null
}

# ── liveness + sync ─────────────────────────────────────────────────────────
INFO="$(rpc_call "$RPC" getchaininfo)"
if [ -z "$INFO" ] || [ -z "$(jget "$INFO" 'r["slot"]')" ]; then
  crit "node RPC at $RPC not answering getchaininfo — a dead validator leaks stake every epoch it misses"
  echo "health: CRIT"; exit 2
fi
BEHIND="$(jget "$INFO" 'r["behind_by_slots"]')"
HEIGHT="$(jget "$INFO" 'r["height"]')"
FIN_EPOCH="$(jget "$INFO" 'r["finalized"]["epoch"]')"
FIN_ROOT="$(jget "$INFO" 'r["finalized"]["root"]')"
EPOCH="$(jget "$INFO" 'r["epoch"]')"

if [ "${BEHIND:-999999}" -le "$MAX_BEHIND" ]; then ok "sync: behind_by_slots=$BEHIND (<=$MAX_BEHIND), height=$HEIGHT, epoch=$EPOCH"
else crit "sync: behind_by_slots=$BEHIND (> $MAX_BEHIND) — this node is not current; its duties are landing dead or not at all"; fi

# ── finality progress (stall detector across runs) ──────────────────────────
mkdir -p "$STATE_DIR" 2>/dev/null
MARK="$STATE_DIR/finalized_epoch"
NOW="$(date +%s)"
if [ -f "$MARK" ]; then
  read -r LAST_EPOCH LAST_TS < "$MARK" || { LAST_EPOCH=0; LAST_TS=$NOW; }
else LAST_EPOCH=""; LAST_TS=$NOW; fi
if [ -z "$LAST_EPOCH" ] || [ "${FIN_EPOCH:-0}" -gt "$LAST_EPOCH" ] 2>/dev/null; then
  echo "$FIN_EPOCH $NOW" > "$MARK"
  ok "finality: finalized epoch $FIN_EPOCH (advancing)"
else
  AGE=$(( NOW - LAST_TS ))
  if [ "$AGE" -gt "$STALL_SECS" ]; then
    crit "finality: finalized epoch stuck at $FIN_EPOCH for ${AGE}s (> ${STALL_SECS}s) — height moving without finality is a stall or a partition; height is not the guarantee"
  else
    ok "finality: finalized epoch $FIN_EPOCH (unchanged ${AGE}s, within ${STALL_SECS}s)"
  fi
fi

# ── divergence against a reference node ─────────────────────────────────────
if [ -n "$REFERENCE" ]; then
  RINFO="$(rpc_call "$REFERENCE" getchaininfo)"
  RFIN_EPOCH="$(jget "$RINFO" 'r["finalized"]["epoch"]')"
  RFIN_ROOT="$(jget "$RINFO" 'r["finalized"]["root"]')"
  if [ -z "$RFIN_EPOCH" ]; then
    w "reference: $REFERENCE not answering — divergence unchecked this run (a forked node looks healthy alone)"
  elif [ "$RFIN_EPOCH" = "$FIN_EPOCH" ]; then
    if [ "$RFIN_ROOT" = "$FIN_ROOT" ]; then ok "divergence: finalized root agrees with reference at epoch $FIN_EPOCH"
    else crit "DIVERGENCE: same finalized epoch $FIN_EPOCH, DIFFERENT roots (local $FIN_ROOT vs reference $RFIN_ROOT) — this node is on a fork; stop trusting its reads and investigate before it signs anything else"; fi
  else
    ok "divergence: epochs differ (local $FIN_EPOCH vs reference $RFIN_EPOCH) — roots not comparable this run"
  fi
else
  w "no --reference node configured — divergence is the failure mode that local metrics can NEVER show; configure one"
fi

# ── this validator's registry state ─────────────────────────────────────────
if [ -n "$INDEX" ]; then
  VAL="$(rpc_call "$RPC" getvalidator "[$INDEX]")"
  VSTATE="$(jget "$VAL" 'r["status"]')"
  case "$VSTATE" in
    active)  ok "validator $INDEX: active" ;;
    queued)  w  "validator $INDEX: queued — not yet doing duties (activation queue admits 4/epoch)" ;;
    exiting) w  "validator $INDEX: exiting — duties stop at exit_epoch; expected only if YOU submitted the exit" ;;
    exited)  w  "validator $INDEX: exited — withdrawal after the 2048-epoch delay" ;;
    slashed) crit "validator $INDEX: SLASHED — stop the node NOW (it cannot un-slash, and correlation pricing means more offences in the 4096-epoch window cost everyone more)" ;;
    "")      crit "validator $INDEX: getvalidator returned nothing — wrong index, or node unhealthy" ;;
    *)       w  "validator $INDEX: unrecognised state '$VSTATE'" ;;
  esac
fi

# ── RPC exposure ────────────────────────────────────────────────────────────
RPC_PORT="$(printf '%s' "$RPC" | sed -n 's/.*:\([0-9][0-9]*\).*/\1/p')"
if [ -n "$RPC_PORT" ] && command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -E "^(0\.0\.0\.0|\*|\[::\]):${RPC_PORT}\$" >/dev/null; then
    crit "exposure: RPC port $RPC_PORT is listening on a routable address. The RPC has NO authentication, NO rate limit, NO authorisation — this is a live incident, not a configuration style. Rebind to 127.0.0.1."
  else
    ok "exposure: RPC port $RPC_PORT not on a wildcard bind"
  fi
fi

case "$STATUS" in
  0) echo "health: OK" ;;
  1) echo "health: WARN" ;;
  2) echo "health: CRIT" ;;
esac
exit "$STATUS"
