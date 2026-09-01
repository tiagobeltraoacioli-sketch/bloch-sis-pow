#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Restart an existing local testnet (made by local-testnet-up.sh) from its
# data dirs — the WHOLE set together, which is the one restart mode the
# genesis/README cold-sync caveat allows. Verifies the chain resumes:
# blocks replay, production continues, and finality advances past its
# pre-restart mark.
#
#   deploy/testnet/local-testnet-restart.sh <workdir> [n]
set -uo pipefail

WORKDIR="${1:?usage: local-testnet-restart.sh <workdir> [n]}"
N="${2:-4}"
BASE_PORT="${BASE_PORT:-19500}"
RPC_BASE="${RPC_BASE:-18500}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BLOCH_POS_BIN:-$REPO/target/release/bloch-pos}"
[ -x "$BIN" ] || { echo "FATAL: no binary at $BIN" >&2; exit 1; }
[ -f "$WORKDIR/genesis.blg" ] || { echo "FATAL: no $WORKDIR/genesis.blg — run local-testnet-up.sh first" >&2; exit 1; }

if [ -f "$WORKDIR/pids" ]; then
  while read -r p; do kill "$p" 2>/dev/null; done < "$WORKDIR/pids"; sleep 1
  while read -r p; do kill -9 "$p" 2>/dev/null; done < "$WORKDIR/pids"
fi

: > "$WORKDIR/pids"
for i in $(seq 0 $(( N - 1 ))); do
  peers=""
  for j in $(seq 0 $(( N - 1 ))); do
    [ "$j" = "$i" ] && continue
    peers="${peers}${peers:+,}127.0.0.1:$(( BASE_PORT + j ))"
  done
  "$BIN" run --data-dir "$WORKDIR/node$i" --genesis "$WORKDIR/genesis.blg" \
    --transport devnet --listen "$(( BASE_PORT + i ))" --peers "$peers" \
    --rpc-bind 127.0.0.1 --rpc-port "$(( RPC_BASE + i ))" \
    >> "$WORKDIR/node$i/run.log" 2>&1 &
  echo "$!" >> "$WORKDIR/pids"
done
echo "restarted $N nodes: $(tr '\n' ' ' < "$WORKDIR/pids")"

rpc() {
  curl -s --max-time 5 -X POST "http://127.0.0.1:$1" \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' 2>/dev/null
}

MARK=""
DEADLINE=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  info=$(rpc "$RPC_BASE")
  fin=$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["finalized"]["epoch"])' 2>/dev/null)
  h=$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null)
  if [ -n "${fin:-}" ]; then
    [ -z "$MARK" ] && { MARK="$fin"; echo "resumed: height=$h finalized_epoch=$fin (pre-restart mark)"; }
    printf '\r  height=%-6s finalized_epoch=%-4s' "${h:-?}" "${fin:-?}"
    if [ "$fin" -gt "$MARK" ] 2>/dev/null; then
      echo
      echo "RESTART OK — finality advanced past the pre-restart mark (e$MARK -> e$fin)"
      exit 0
    fi
  fi
  sleep 3
done
echo
echo "RESTART FAIL: finality did not advance within 300s — see $WORKDIR/node*/run.log" >&2
exit 1
