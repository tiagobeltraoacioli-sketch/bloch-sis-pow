#!/usr/bin/env bash
# WP7 — build the fixture chain ONCE and reuse it for every condition.
#
# Two validators produce into their own data dirs until wall slot SLOTS. The
# resulting blocks.log is the chain a syncing node will pull. Regenerating this
# per run would add the producers' variance to every measurement and burn the
# machine, so it is built once and copied.
set -uo pipefail
BENCH=/private/tmp/pmo-copilot/wp7-syncmeasure/bench
BIN=/private/tmp/pmo-copilot/wp7-syncmeasure/bench/bloch-pos-wp7
FIX=$BENCH/fixture
SLOT_MS=${SLOT_MS:-150}
SLOTS=${SLOTS:-900}

rm -rf "$FIX"; mkdir -p "$FIX"
"$BIN" keygen --dir "$FIX/n0" --index 0 >"$FIX/keygen0.log" 2>&1 || { echo "keygen0 FAILED"; cat "$FIX/keygen0.log"; exit 1; }
"$BIN" keygen --dir "$FIX/n1" --index 1 >"$FIX/keygen1.log" 2>&1 || { echo "keygen1 FAILED"; cat "$FIX/keygen1.log"; exit 1; }
"$BIN" genesis --keys "$FIX/n0,$FIX/n1" --out "$FIX/genesis.json" --slot-ms "$SLOT_MS" --start-in 5 \
  >"$FIX/genesis.log" 2>&1 || { echo "genesis FAILED"; cat "$FIX/genesis.log"; exit 1; }
cp "$FIX/genesis.json" "$BENCH/genesis.json"

"$BIN" run --data-dir "$FIX/n0" --genesis "$FIX/genesis.json" --listen 17001 \
  --peers 127.0.0.1:17002 --rpc-port off --stop-at-slot "$SLOTS" >"$FIX/n0.log" 2>&1 &
P0=$!
"$BIN" run --data-dir "$FIX/n1" --genesis "$FIX/genesis.json" --listen 17002 \
  --peers 127.0.0.1:17001 --rpc-port off --stop-at-slot "$SLOTS" >"$FIX/n1.log" 2>&1 &
P1=$!
echo "fixture producers: $P0 $P1 (slot_ms=$SLOT_MS, stop at slot $SLOTS)"
echo "$P0 $P1" > "$FIX/pids"
wait $P0; R0=$?
wait $P1; R1=$?
echo "producer exit codes: n0=$R0 n1=$R1"
grep -c . "$FIX/n0.log" >/dev/null
echo "--- n0 STOP line ---"; grep '^STOP' "$FIX/n0.log" || echo "NO STOP LINE (n0)"
echo "--- n1 STOP line ---"; grep '^STOP' "$FIX/n1.log" || echo "NO STOP LINE (n1)"
# The tip the syncing node must reach. Taken from the producer's own STOP
# line (chain.len()-1), not from the log's byte count: the log may hold
# non-canonical blocks and the client counts canonical ones.
TIP=$(sed -n 's/^STOP.*head slot [0-9]*, \([0-9]*\) blocks.*/\1/p' "$FIX/n0.log" | tail -1)
if [ -z "${TIP:-}" ] || [ "$TIP" -lt 100 ]; then
  echo "FIXTURE TOO SMALL OR UNPARSEABLE (tip='${TIP:-}') — refusing to write it"
  tail -5 "$FIX/n0.log"; exit 1
fi
echo "$TIP" > "$FIX/tip"
echo "fixture tip = $TIP blocks"
ls -la "$FIX/n0" "$FIX/n1"
