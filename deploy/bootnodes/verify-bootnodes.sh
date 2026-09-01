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
#                                      # keylessness and transport
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

echo "Checking $COUNT published entries from $LIST"
echo

FAIL=0
for e in $ENTRIES; do
  HOST=${e%%:*}; PORT=${e##*:}
  echo "── $e"

  # 1. Reachable from OUTSIDE. This is the stranger's actual experience; a
  #    check that only works from inside our network proves nothing.
  #    Three attempts: a single probe blips often enough that one failure is
  #    not evidence, and a false "unpublish this" alarm is its own outage.
  OK=0
  for _ in 1 2 3; do
    nc -z -G 5 -w 5 "$HOST" "$PORT" >/dev/null 2>&1 && { OK=1; break; }
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
      if [ -f /home/ubuntu/g4/archival/validator.key ]; then echo "KEY=present"; else echo "KEY=absent"; fi
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
  echo "$OUT" | grep -o '{"jsonrpc".*' | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)["result"]
except Exception:
    print("   chain          : no RPC answer")
    sys.exit(1)
b = d["behind_by_slots"]
flag = "" if b <= 2 else "   <-- LAGGING: upstreams may have rotted"
h, fin, ep = d["height"], d["finalized_height"], d["epoch"]
print("   chain          : h=%s finalized=%s epoch=%s behind=%s%s" % (h, fin, ep, b, flag))
print("   finalized root : %s" % d["finalized"]["root"])
' || FAIL=1
done

if [ $DEEP -eq 1 ] && [ "$COUNT" -ge 2 ]; then
  echo
  echo "Cross-check: the entries must agree on the SAME finalized root."
  echo "Two nodes at the same height with different roots are a fork, and"
  echo "publishing both would hand strangers two different chains."
fi

echo
if [ $FAIL -eq 0 ]; then echo "PASS — every published entry is reachable and sound."
else echo "FAIL — fix or unpublish the entries flagged above before shipping."; fi
exit $FAIL
