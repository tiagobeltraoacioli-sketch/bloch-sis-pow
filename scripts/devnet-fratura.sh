#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── DEVNET SELF-FRACTURE HARNESS ────────────────────────────────────────────
#
# Runs N throwaway validators as a FULL MESH on one host — no partition, no
# joining node, no injected fault — and measures whether they stay on one
# chain. It exists because three founder validators on one idle box were twice
# observed drifting to different heights with no external cause, which if true
# invalidates every devnet measurement in this repository past a few hundred
# slots.
#
# Deliberately DIFFERENT from scripts/devnet-particao.sh: that harness measures
# convergence ACROSS a partition and heal, and polls RPC while the phase is
# live. This one measures the no-fault case and, by default, POLLS NOTHING —
# observation is read off the nodes' own logs and their blocks.log after they
# exit. RPC polling is a separate, opt-in arm (POLL_SECS), because "the
# measurement caused the fracture" is one of the hypotheses under test.
#
#   usage: devnet-fratura.sh <workdir> [n] [slot_ms] [stop_at] [label]
#   env:   BLOCH_POS_BIN   required
#          POLL_SECS       if set, poll getchaininfo every N s (observation arm)
#          POLL_METHOD     method to poll (default getchaininfo)
#          DROP_EVERY      if set, node 0 drops 1 in N outbound broadcast
#                          frames (BLOCH_DEVNET_DROP_EVERY, the induce arm)
#          TRANSPORT       devnet (default) or libp2p — the production stack
#          BASE_PORT/RPC_BASE
#
# DEVNET ONLY: 127.0.0.1, throwaway keys from `keygen`, never a production
# manifest.
set -uo pipefail

WORKDIR="${1:?usage: devnet-fratura.sh <workdir> [n] [slot_ms] [stop_at] [label]}"
N="${2:-3}"; SLOT_MS="${3:-1000}"; STOP_AT="${4:-600}"; LABEL="${5:-run}"
# How many validators the GENESIS MANIFEST declares. Defaults to the number
# actually launched. Setting it higher is the "declared > running" arm: the
# absent validators never attest, the quorum is never met, and the inactivity
# leak arms — which is the ordinary state of a devnet where somebody stood up
# fewer nodes than the manifest names.
DECLARED="${DECLARED:-$N}"
BASE_PORT="${BASE_PORT:-19510}"; RPC_BASE="${RPC_BASE:-17510}"
POLL_SECS="${POLL_SECS:-}"; POLL_METHOD="${POLL_METHOD:-getchaininfo}"
TRANSPORT="${TRANSPORT:-devnet}"
BIN="${BLOCH_POS_BIN:?set BLOCH_POS_BIN}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
for i in $(seq 0 $(( DECLARED - 1 ))); do
  "$BIN" keygen --dir "$WORKDIR/node$i" --index "$i" >/dev/null || exit 1
done
KEYS=""; for i in $(seq 0 $(( DECLARED - 1 ))); do KEYS="${KEYS:+$KEYS,}$WORKDIR/node$i"; done
"$BIN" genesis --keys "$KEYS" --out "$WORKDIR/genesis.blg" \
  --slot-ms "$SLOT_MS" --start-in 10 >/dev/null || exit 1

peers_for() {
  local i="$1" out="" j addr
  for j in $(seq 0 $(( N - 1 ))); do
    [ "$j" = "$i" ] && continue
    if [ "$TRANSPORT" = "libp2p" ]; then addr="/ip4/127.0.0.1/tcp/$(( BASE_PORT + j ))"
    else addr="127.0.0.1:$(( BASE_PORT + j ))"; fi
    out="${out:+$out,}$addr"
  done
  printf '%s' "$out"
}

# The two transports take different flags for the same two facts. `--listen`
# and `--peers` are host:port; `--p2p-listen`/`--p2p-peer` are multiaddrs.
listen_flags() {
  local i="$1"
  if [ "$TRANSPORT" = "libp2p" ]; then
    printf -- "--p2p-listen /ip4/127.0.0.1/tcp/%s --p2p-peer %s" \
      "$(( BASE_PORT + i ))" "$(peers_for "$i")"
  else
    printf -- "--listen %s --peers %s" "$(( BASE_PORT + i ))" "$(peers_for "$i")"
  fi
}

PIDS=()
for i in $(seq 0 $(( N - 1 ))); do
  env ${DROP_EVERY:+BLOCH_DEVNET_DROP_EVERY=$( [ "$i" = 0 ] && echo "$DROP_EVERY" || echo 0 )} \
   "$BIN" run --data-dir "$WORKDIR/node$i" --genesis "$WORKDIR/genesis.blg" \
    --transport "$TRANSPORT" $(listen_flags "$i") \
    --rpc-bind 127.0.0.1 --rpc-port "$(( RPC_BASE + i ))" \
    --stop-at-slot "$STOP_AT" > "$WORKDIR/node$i/$LABEL.log" 2>&1 &
  PIDS+=("$!")
done
echo "launched $N nodes, pids ${PIDS[*]}, stop at slot $STOP_AT"

if [ -n "$POLL_SECS" ]; then
  ( while :; do
      for i in $(seq 0 $(( N - 1 ))); do
        curl -s --max-time 3 -X POST "http://127.0.0.1:$(( RPC_BASE + i ))" \
          -H 'content-type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$POLL_METHOD\",\"params\":[]}" \
          >> "$WORKDIR/poll.node$i.jsonl" 2>/dev/null
        echo >> "$WORKDIR/poll.node$i.jsonl"
      done
      sleep "$POLL_SECS"
    done ) &
  POLLER=$!
  echo "polling $POLL_METHOD every ${POLL_SECS}s (pid $POLLER)"
fi

wait "${PIDS[@]}" 2>/dev/null
[ -n "${POLLER:-}" ] && kill "$POLLER" 2>/dev/null
for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
echo "done: $WORKDIR"
