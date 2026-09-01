#!/usr/bin/env bash
# heartbeat.sh — checks the CHECKER.
#
# The detector makes reference rot loud. This makes a SILENT DETECTOR loud,
# which is a different failure and the more dangerous one: rot that is not
# being looked for is indistinguishable from no rot. Both are quiet.
#
# Every unattended run leaves a receipt (see detector-run.sh). This reads it
# and answers two questions the detector cannot answer about itself:
#
#   1. Did it run recently enough?  A timer that was disabled, a script that
#      was deleted, a unit that is wedged in `activating` because an ssh hung,
#      a Mac that slept through the night — all of these stop the receipt
#      advancing while `systemctl --failed` stays empty and the mailbox stays
#      quiet. Staleness is the only symptom they share.
#   2. What did the last run actually say?  An exit 2 repeated every hour
#      (an expired key, a revoked host) mails the same line so often it
#      becomes wallpaper. Here it is a standing failure until it is fixed.
#
# Exit codes, deliberately the same alphabet as the detector:
#   0  the detector ran recently and its last verdict was clean
#   1  the detector ran recently and its last verdict was ROT (or exit 1)
#   2  COULD NOT DETERMINE — no receipt, unreadable receipt, receipt stale,
#      or the last run itself ended undetermined. Treat as failure.
#
# Exit 2 is the whole point of this file. "I do not know whether the fleet is
# rotting" must never be quieter than "the fleet is rotting".
#
# Usage: heartbeat.sh [-c CONF] [--max-age SECONDS] [--quiet]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${REFINT_CONF:-$HERE/reference-integrity.conf}"
MAX_AGE=""; QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    -c) CONF="$2"; shift 2;;
    --max-age) MAX_AGE="$2"; shift 2;;
    --quiet) QUIET=1; shift;;
    *) echo "usage: $0 [-c CONF] [--max-age SECONDS] [--quiet]" >&2; exit 2;;
  esac
done
if [ -f "$CONF" ]; then . "$CONF" || true; fi
: "${STATE_DIR:=$HOME/.bloch-reference-integrity}"
# Default: three times the hourly cadence. One missed run is a laptop lid or a
# RandomizedDelaySec; three in a row is a mechanism that stopped.
: "${HEARTBEAT_MAX_AGE:=10800}"
MAX_AGE="${MAX_AGE:-$HEARTBEAT_MAX_AGE}"

RECEIPT="$STATE_DIR/last-run.tsv"

if [ ! -s "$RECEIPT" ]; then
  echo "HEARTBEAT: UNDETERMINED — no receipt at $RECEIPT. The detector has never completed a run through detector-run.sh, or STATE_DIR moved. Nothing is watching the fleet's references."
  exit 2
fi

IFS=$'\t' read -r ts epoch rc verdict < "$RECEIPT"
case "${epoch:-}" in
  ''|*[!0-9]*) echo "HEARTBEAT: UNDETERMINED — receipt $RECEIPT is unreadable (timestamp field: '${epoch:-}')."; exit 2;;
esac
now=$(date +%s)
age=$(( now - epoch ))
# A receipt from the future means the clock moved under us; we cannot reason
# about freshness from it, so we refuse rather than report a comfortable age.
if [ "$age" -lt -300 ]; then
  echo "HEARTBEAT: UNDETERMINED — receipt is dated $(( -age ))s in the FUTURE ($ts); the clock on this machine cannot be trusted to judge staleness."
  exit 2
fi
[ "$age" -lt 0 ] && age=0
human=$(( age / 60 ))

if [ "$age" -gt "$MAX_AGE" ]; then
  echo "HEARTBEAT: UNDETERMINED — the detector has not completed a run in ${human} min (limit $(( MAX_AGE / 60 )) min; last was $ts, exit ${rc:-?}). The fleet is UNWATCHED: check the timer/agent is loaded and not wedged."
  exit 2
fi

case "${rc:-}" in
  0) [ "$QUIET" = 1 ] || echo "HEARTBEAT: OK — detector ran ${human} min ago (exit 0). ${verdict}"
     exit 0;;
  1) echo "HEARTBEAT: ROT STANDING — detector ran ${human} min ago and found rot. ${verdict}"
     exit 1;;
  2) echo "HEARTBEAT: UNDETERMINED — the detector ran ${human} min ago but could not determine anything (exit 2). ${verdict}"
     exit 2;;
  *) echo "HEARTBEAT: UNDETERMINED — receipt records an unexpected exit code '${rc:-}' at $ts. ${verdict}"
     exit 2;;
esac
