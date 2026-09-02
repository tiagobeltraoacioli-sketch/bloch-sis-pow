#!/usr/bin/env bash
# verify-bootnodes.sh — prove the published entry list is still true.
#
# WHY THIS EXISTS. The devnet transport reconnects dead peers forever and
# never raises an error, so a rotted entry list does not fail — it just stops
# working, silently, for every stranger who follows our instructions. On
# 2026-08-31 four systems broke this exact way on the same day. This script is
# the check that turns silent rot into a loud failure.
#
# It is READ-ONLY. It changes nothing, on any host.
#
# Run it: after any fleet move, weekly, and before publishing the list.
#
#   ./verify-bootnodes.sh              # public reachability + liveness (no ssh)
#   ./verify-bootnodes.sh --deep       # also ssh each bootnode to re-prove
#                                      # keylessness, transport and one chain
#
# The plain run is the one a third party can do; --deep needs our fleet key.
#
# Exit 0 = every published entry passed. Non-zero = do not publish.
set -uo pipefail
cd "$(dirname "$0")"

LIST=bootnodes.txt
KEY=${BLOCH_FLEET_KEY:-$HOME/.ssh/edgevana_fleet_g4}
DEEP=0
[ "${1:-}" = "--deep" ] && DEEP=1

# bash 3.2 (the macOS default) has no `mapfile`, and this script has to run on
# whatever an operator has. Plain word-splitting over a newline list is enough.
ENTRIES=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$LIST")
COUNT=$(printf '%s\n' "$ENTRIES" | grep -c . || true)
[ "$COUNT" -eq 0 ] && { echo "FAIL: $LIST lists no entries"; exit 2; }

# Pick a connect probe that works on THIS machine before using it 3 times per
# host. `nc -G` (connect timeout) is macOS-only: Ubuntu's OpenBSD netcat exits
# "invalid option -- 'G'" for every host, which would report a perfectly
# healthy list as entirely unreachable — on Linux, which is exactly what the
# quick start tells an operator to run. Detect once, against a closed local
# port, so the choice is never made from a network result.
if nc -z -G 5 -w 5 127.0.0.1 1 >/dev/null 2>&1 || \
   [ "$(nc -z -G 5 -w 5 127.0.0.1 1 2>&1 | grep -c 'invalid option')" -eq 0 ]; then
  probe() { nc -z -G 5 -w 5 "$1" "$2" >/dev/null 2>&1; }
else
  probe() { nc -z -w 5 "$1" "$2" >/dev/null 2>&1; }
fi

echo "Checking $COUNT published entries from $LIST"
echo

FAIL=0
ROOTS=$(mktemp) ; trap 'rm -f "$ROOTS"' EXIT

for e in $ENTRIES; do
  HOST=${e%%:*}; PORT=${e##*:}
  echo "── $e"

  # 1. Reachable from OUTSIDE. This is the stranger's actual experience; a
  #    check that only works from inside our network proves nothing.
  #    Three attempts: a single probe blips often enough that one failure is
  #    not evidence, and a false "unpublish this" alarm is its own outage.
  OK=0
  for _ in 1 2 3; do
    probe "$HOST" "$PORT" && { OK=1; break; }
    sleep 2
  done
  if [ $OK -eq 1 ]; then
    echo "   reachable      : yes"
  else
    echo "   reachable      : NO (3 attempts)  <-- a stranger cannot peer here"
    FAIL=1; continue
  fi

  [ $DEEP -eq 0 ] && continue

  # 2. Still keyless, still devnet, still following. A bootnode that has
  #    acquired a validator.key must come off the public list immediately: we
  #    would be publishing an unauthenticated push surface into consensus.
  OUT=$(ssh -o ConnectTimeout=10 -o BatchMode=yes -i "$KEY" ubuntu@"$HOST" '
      if find /home/ubuntu/g4 -name validator.key 2>/dev/null | grep -q .; then
        echo "KEY=present"; else echo "KEY=absent"; fi
      systemctl cat bloch-archival.service 2>/dev/null | grep -oE -- "--transport [a-z0-9]+" | head -1
      curl -s --max-time 8 -X POST http://127.0.0.1:16400 \
        -H "content-type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getchaininfo\",\"params\":[]}"
    ' 2>/dev/null)

  case "$OUT" in
    *KEY=absent*)  echo "   keyless        : yes" ;;
    *KEY=present*) echo "   keyless        : NO  <-- REMOVE FROM PUBLIC LIST NOW"; FAIL=1 ;;
    *)             echo "   keyless        : unknown (ssh failed)"; FAIL=1; continue ;;
  esac

  case "$OUT" in
    *"--transport devnet"*) echo "   transport      : devnet" ;;
    *"--transport libp2p"*) echo "   transport      : libp2p <-- MISMATCH: the published list is devnet"; FAIL=1 ;;
    *)                      echo "   transport      : not stated (defaults to devnet)" ;;
  esac

  # 3. Following the chain, not merely answering. A forked node responds.
  #    The finalized height and root are appended for the cross-check below;
  #    a check that only prints them proves nothing on its own.
  echo "$OUT" | grep -o '{"jsonrpc".*' | HOST="$HOST" ROOTS="$ROOTS" python3 -c '
import sys, json, os
try:
    d = json.load(sys.stdin)["result"]
except Exception:
    print("   chain          : no RPC answer")
    sys.exit(1)
b = d["behind_by_slots"]
flag = "" if b <= 2 else "   <-- LAGGING: upstreams may have rotted"
h, fin, ep = d["height"], d["finalized_height"], d["epoch"]
root = d["finalized"]["root"]
print("   chain          : h=%s finalized=%s epoch=%s behind=%s%s" % (h, fin, ep, b, flag))
print("   finalized root : %s" % root)
with open(os.environ["ROOTS"], "a") as f:
    f.write("%s %s %s\n" % (os.environ["HOST"], fin, root))
' || FAIL=1
done

# 4. THE FORK CHECK. Publishing two addresses that are on two chains is worse
#    than publishing one, so this must be a comparison and not a suggestion
#    that the reader make one. Roots are only comparable at the SAME finalized
#    height, so unequal heights are inconclusive, not a pass.
# `grep -c .` EXITS 1 when the count is zero, so `grep -c . f || echo 0` emits
# BOTH the "0" it printed and the fallback "0" — the test then receives the
# two-line string "0\n0" and bash aborts the comparison with "integer
# expression expected". That is exactly what happened when the cross-check
# collected no roots, which is the normal case for a third party: the published
# bootnodes bind their RPC to loopback (correctly — see the quickstart §0), so
# nobody outside the host can read a finalized root from them. `wc -l < file`
# always succeeds and always prints one number.
ROOTC_LINES=$(wc -l < "$ROOTS" 2>/dev/null || echo 0)
if [ $DEEP -eq 1 ] && [ "$ROOTC_LINES" -ge 2 ]; then
  echo
  echo "Cross-check: published entries must agree on ONE chain."
  HEIGHTS=$(awk '{print $2}' "$ROOTS" | sort -u | grep -c .)
  ROOTC=$(awk '{print $3}' "$ROOTS" | sort -u | grep -c .)
  if [ "$HEIGHTS" -eq 1 ] && [ "$ROOTC" -eq 1 ]; then
    echo "   PASS: identical finalized root at the same finalized height."
    awk '{printf "         %-18s finalized=%s %s\n", $1, $2, $3}' "$ROOTS"
  elif [ "$HEIGHTS" -eq 1 ] && [ "$ROOTC" -gt 1 ]; then
    echo "   FORK: same finalized height, DIFFERENT roots. DO NOT PUBLISH."
    awk '{printf "         %-18s finalized=%s %s\n", $1, $2, $3}' "$ROOTS"
    FAIL=1
  else
    echo "   INCONCLUSIVE: entries are at different finalized heights, so the"
    echo "   roots are not comparable. Re-run; if it persists, one is stuck."
    awk '{printf "         %-18s finalized=%s %s\n", $1, $2, $3}' "$ROOTS"
    FAIL=1
  fi
elif [ $DEEP -eq 1 ]; then
  # Say why the fork check did not run, rather than printing nothing and
  # letting the reader assume it passed. A check that silently does not
  # execute is worse than one that fails.
  echo
  echo "Cross-check: NOT PERFORMED — fewer than two entries returned a"
  echo "   finalized root over RPC. The published bootnodes bind RPC to"
  echo "   loopback, so this cross-check can only be run ON one of them."
  echo "   From outside, compare YOUR node against a second node you control"
  echo "   at the same finalized height instead; see quickstart section 7."
fi

echo
if [ $FAIL -eq 0 ]; then echo "PASS — every published entry is reachable and sound."
else echo "FAIL — fix or unpublish the entries flagged above before shipping."; fi
exit $FAIL
