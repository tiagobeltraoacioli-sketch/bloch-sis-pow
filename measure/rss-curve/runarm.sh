#!/bin/bash
# runarm.sh <name> <arm> <frames|full> <period_s>
# Replays a copy of the base log in OBSERVER mode (no validator.key), sampling
# VmRSS/VmHWM against the height the node itself reports. Writes nothing to the
# fleet, dials no peer, serves no RPC, exits before going live.
set -u
NAME="$1"; ARM="$2"; FRAMES="${3:-full}"; PER="${4:-0.1}"
cd /home/ubuntu/rsscurve || exit 1
mkdir -p out
RUN="run-$NAME"
rm -rf "$RUN"; mkdir -p "$RUN"
if [ "$FRAMES" = "full" ]; then
  cp base/blocks.log "$RUN/blocks.log"
else
  head -c "$FRAMES" base/blocks.log > "$RUN/blocks.log"
fi
cp base/meta.bin "$RUN/meta.bin"
[ -e "$RUN/validator.key" ] && { echo "ABORT: validator.key in data dir"; exit 9; }

{ echo "phase=PRE  epoch=$(date +%s.%N)  loadavg=$(cat /proc/loadavg)  memavail_kB=$(awk '/MemAvailable/{print $2}' /proc/meminfo)  blochprocs=$(pgrep -c bloch || echo 0)"; } > "out/$NAME.env"

/usr/bin/time -v ./bloch-pos run --data-dir "$RUN" \
    --genesis /home/ubuntu/g4/mainnet.manifest \
    --carryover /home/ubuntu/g4/carryover.tsv \
    --transport devnet --listen-addr 127.0.0.1 --listen 0 \
    --rpc-port off \
    --sig-retention "$ARM" --stop-at-slot 1 \
    2> "out/$NAME.time" | python3 /home/ubuntu/rsscurve/stamp.py > "out/$NAME.stdout" &
WRAP=$!

PID=""
for i in $(seq 1 200); do
  for p in $(pgrep -f "run-$NAME" 2>/dev/null); do
    if [ "$(cat /proc/$p/comm 2>/dev/null)" = "bloch-pos" ]; then PID=$p; break; fi
  done
  [ -n "$PID" ] && break
  sleep 0.05
done
if [ -z "$PID" ]; then echo "ABORT: could not find node pid"; wait $WRAP; exit 8; fi
echo "node pid $PID  sampling every ${PER}s" >> "out/$NAME.env"
python3 /home/ubuntu/rsscurve/sample.py "$PID" "out/$NAME.rss" "$PER" &
SAMP=$!
wait $WRAP; RC=$?
wait $SAMP 2>/dev/null

{ echo "phase=POST epoch=$(date +%s.%N)  loadavg=$(cat /proc/loadavg)  memavail_kB=$(awk '/MemAvailable/{print $2}' /proc/meminfo)  blochprocs=$(pgrep -c bloch || echo 0)  rc=$RC"; } >> "out/$NAME.env"
rm -rf "$RUN"
echo "=== DONE $NAME (arm=$ARM rc=$RC) ==="
tail -4 "out/$NAME.stdout"
grep -E "Maximum resident|Elapsed|Minor|Major" "out/$NAME.time"
echo "samples: $(wc -l < out/$NAME.rss)"
