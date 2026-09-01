#!/usr/bin/env bash
# selftest.sh — pins the EXIT-CODE CONTRACT of the detector wrapper and the
# heartbeat. Touches no fleet host; runs in a temp dir in seconds.
#
# Why this file exists. The contract is the whole product: 0 clean, 1 rot,
# 2 could-not-determine — and 2 must be as loud as 1, because losing the
# ability to check is how the last outage stayed invisible. A contract nobody
# exercises is a comment. Two real defects were found by running this matrix
# by hand the first time:
#
#   - the wrapper appended a diagnostic note AFTER capturing the verdict, so
#     every receipt recorded the note instead of the verdict;
#   - the wrapper did not parse `-c`, so a run against another conf wrote its
#     receipt into the DEFAULT state dir, silently overwriting the real
#     fleet's receipt with a test run's result.
#
# Both are fixed. This keeps them fixed.
#
# Usage: bash selftest.sh    (exit 0 = contract holds)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok(){ printf '  ok    %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  FAIL  %s (got %s, wanted %s)\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); }
chk(){ [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }

mkconf(){ mkdir -p "$1"; cat > "$1/conf" <<C
KEY=\$HOME/.ssh/edgevana_fleet_g4
SSH_USER=ubuntu
SSH_TIMEOUT=5
FLEET="${2:-192.0.2.1}"
ARCHIVAL=""
STATE_DIR=$1
C
}

echo "heartbeat.sh — receipt states"
D="$TMP/hb"; mkconf "$D"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "no receipt at all      -> 2" $? 2
printf 'x\ty\tz\tw\n' > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "unparseable receipt    -> 2" $? 2
now=$(date +%s)
printf 'now\t%s\t0\tOK: clean\n' "$now" > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "fresh + clean          -> 0" $? 0
printf 'now\t%s\t1\tROT: findings\n' "$now" > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "fresh + rot            -> 1" $? 1
printf 'now\t%s\t2\tUNDETERMINED\n' "$now" > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "fresh + undetermined   -> 2" $? 2
printf 'now\t%s\t7\tweird\n' "$now" > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "unknown exit code      -> 2" $? 2
printf 'old\t%s\t0\tOK: clean but ancient\n' "$(( now - 14400 ))" > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "STALE though clean     -> 2" $? 2
printf 'fut\t%s\t0\tOK\n' "$(( now + 99999 ))" > "$D/last-run.tsv"
bash "$HERE/heartbeat.sh" -c "$D/conf" >/dev/null 2>&1; chk "receipt from future    -> 2" $? 2

echo "detector-run.sh — receipt is written on EVERY exit path"
D2="$TMP/w1"; mkconf "$D2"
bash "$HERE/detector-run.sh" -c "$D2/conf" --quiet >/dev/null 2>&1
chk "unreachable host       -> 2" $? 2
[ -s "$D2/last-run.tsv" ] && ok "…and still left a receipt" || no "…and still left a receipt" "none" "a receipt"
grep -q '	2	' "$D2/last-run.tsv" && ok "…recording exit 2" || no "…recording exit 2" "$(cut -f3 "$D2/last-run.tsv")" 2

D3="$TMP/w2"; mkconf "$D3"
STATE_DIR="$D3" REFINT_CONF=/nonexistent/x.conf bash "$HERE/detector-run.sh" --quiet >/dev/null 2>&1
chk "missing conf           -> 2" $? 2
[ -s "$D3/last-run.tsv" ] && ok "…receipt even with no conf" || no "…receipt even with no conf" "none" "a receipt"

echo "detector-run.sh — a killed sweep is 2, never 0"
STUB="$TMP/stub"; mkdir -p "$STUB"; printf '#!/bin/sh\nexit 124\n' > "$STUB/timeout"; chmod +x "$STUB/timeout"
D4="$TMP/w3"; mkconf "$D4"
PATH="$STUB:$PATH" bash "$HERE/detector-run.sh" -c "$D4/conf" --quiet >/dev/null 2>&1
chk "timeout(124)           -> 2" $? 2
grep -q 'exceeded' "$D4/last-run.tsv" && ok "…verdict says it was killed" || no "…verdict says it was killed" "$(cut -f4 "$D4/last-run.tsv")" "an 'exceeded' line"

echo "detector-run.sh — -c must NOT clobber the default receipt"
D5="$TMP/w4"; mkconf "$D5"
DEF="$TMP/default"; mkdir -p "$DEF"; printf 'keep\t%s\t0\tORIGINAL\n' "$(date +%s)" > "$DEF/last-run.tsv"
STATE_DIR="$DEF" bash "$HERE/detector-run.sh" -c "$D5/conf" --quiet >/dev/null 2>&1
grep -q ORIGINAL "$DEF/last-run.tsv" && ok "default receipt untouched" || no "default receipt untouched" "clobbered" "ORIGINAL"
[ -s "$D5/last-run.tsv" ] && ok "…receipt landed in -c's STATE_DIR" || no "…receipt landed in -c's STATE_DIR" "none" "a receipt"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || exit 1
