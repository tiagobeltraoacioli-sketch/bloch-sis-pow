#!/usr/bin/env bash
# WP7 — one measurement run.
#   run1.sh <label> <cap|inf> <runid>
# Starts an OBSERVER server on a copy of the fixture chain, waits for it to
# finish replaying, then starts an EMPTY observer that syncs from it. The empty
# node prints a `syncbench` line every BENCH_MS; the throughput is read off the
# curve, not off a stopwatch that would include boot and the first round trip.
set -uo pipefail
BENCH=/private/tmp/pmo-copilot/wp7-syncmeasure/bench
BIN=/private/tmp/pmo-copilot/wp7-syncmeasure/bench/bloch-pos-wp7
FIX=$BENCH/fixture3
LABEL=$1; CAP=$2; RUN=$3
OUT=$BENCH/out/$LABEL.$RUN
BENCH_MS=${BENCH_MS:-250}
SPORT=$((17100 + RANDOM % 300))
CPORT=$((17500 + RANDOM % 300))
TIP=$(awk '{print $1}' "$FIX/tip")
# The machine is shared. A node timed at load 9 is not comparable to one timed
# at load 4, so the load is recorded WITH the number rather than averaged away.
LOAD_BEFORE=$(uptime | sed 's/.*averages*: *//')
# Provenance of the thing being timed, recorded per run: the shared
# CARGO_TARGET_DIR lets another agent's build land on the same path, so the
# binary is a private copy and its digest is pinned into every run's output.
BIN_SHA=$(shasum -a 256 "$BIN" | awk '{print $1}')

rm -rf "$OUT"; mkdir -p "$OUT/srv" "$OUT/cli"
cp "$FIX/n2/validator.key" "$OUT/cli/validator.key"
# Server: the fixture chain WITHOUT a keystore -> observer. It serves
# FRAME_GET_BLOCKS straight from the log and produces nothing, so it adds no
# blocks mid-run and no proposer work to the machine.
cp "$FIX/n0/blocks.log" "$OUT/srv/blocks.log"

# The server is held at ONE setting across every condition (unbounded), so the
# only thing that varies between conditions is the client's drain bound.
env BLOCH_MAX_EVENTS_PER_TICK=0 \
  "$BIN" run --data-dir "$OUT/srv" --genesis "$FIX/genesis.json" --listen "$SPORT" \
  --rpc-port off >"$OUT/srv.log" 2>&1 &
SPID=$!
echo "$SPID" > "$OUT/srv.pid"

# Wait for the server to finish replay before loading the machine with a second
# node: overlapping the two would put the client's first seconds in competition
# with the server's replay and show up as variance, not as throughput.
for _ in $(seq 1 600); do
  grep -q '^replayed ' "$OUT/srv.log" && break
  kill -0 "$SPID" 2>/dev/null || { echo "SERVER DIED"; cat "$OUT/srv.log"; exit 1; }
  perl -e 'select undef,undef,undef,0.2'
done
grep -q '^replayed ' "$OUT/srv.log" || { echo "SERVER NEVER FINISHED REPLAY"; tail -20 "$OUT/srv.log"; kill "$SPID"; exit 1; }

# WP3's knob: 0 == the old unbounded drain, so every condition including the
# control arm is the SAME binary with one variable changed.
env BLOCH_MAX_EVENTS_PER_TICK="$CAP" BLOCH_SYNC_BENCH_MS="$BENCH_MS" \
  "$BIN" run --data-dir "$OUT/cli" --genesis "$FIX/genesis.json" --listen "$CPORT" \
  --peers "127.0.0.1:$SPORT" --rpc-port off >"$OUT/cli.log" 2>&1 &
CPID=$!
echo "$CPID" > "$OUT/cli.pid"

# Poll until the client's head reaches the fixture tip, or 120s.
DONE=no
for _ in $(seq 1 600); do
  h=$(grep '^syncbench t_ms=' "$OUT/cli.log" | tail -1 | sed -n 's/.*blocks=\([0-9]*\).*/\1/p')
  if [ -n "${h:-}" ] && [ "$h" -ge "$TIP" ]; then DONE=yes; break; fi
  kill -0 "$CPID" 2>/dev/null || break
  perl -e 'select undef,undef,undef,0.2'
done
kill "$CPID" 2>/dev/null; kill "$SPID" 2>/dev/null
wait "$CPID" 2>/dev/null; wait "$SPID" 2>/dev/null
LOAD_AFTER=$(uptime | sed 's/.*averages*: *//')
echo "$LABEL run=$RUN cap=$CAP tip=$TIP reached_tip=$DONE sport=$SPORT"
echo "load_before=[$LOAD_BEFORE] load_after=[$LOAD_AFTER] bin=$BIN_SHA"
{ echo "load_before=$LOAD_BEFORE"; echo "load_after=$LOAD_AFTER"; echo "bin_sha=$BIN_SHA"; } > "$OUT/meta"
# PROOF the knob took effect. A run whose environment silently did not apply is
# the likeliest way this measurement comes out wrong, so the mode line is
# asserted, not assumed.
MODE=$(grep -m1 '^engine: .*drain\|^engine: draining' "$OUT/cli.log")
if [ -z "$MODE" ]; then echo "!! NO DRAIN-MODE LINE — knob did not apply, run is VOID"; exit 3; fi
echo "knob: $MODE"
grep -c '^syncbench' "$OUT/cli.log" | sed 's/^/syncbench lines: /'
