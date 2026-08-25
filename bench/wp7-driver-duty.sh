#!/usr/bin/env bash
# WP7 — all conditions, ROUND-ROBIN rather than blocked.
#
# The machine is shared with other agents whose load drifts over the hour. Three
# runs of (a) followed by three of (b) would put that drift inside the
# comparison; interleaving puts it inside each condition's spread instead, where
# it is visible.
set -uo pipefail
BENCH=/private/tmp/pmo-copilot/wp7-syncmeasure/bench
ROUNDS=${ROUNDS:-3}
CONDS=${CONDS:-"unbounded:0 cap4:4 cap16:16 cap64:64 cap256:256"}
mkdir -p "$BENCH/out3"
for r in $(seq 1 "$ROUNDS"); do
  for c in $CONDS; do
    label=${c%%:*}; cap=${c##*:}
    l=$(uptime | sed 's/.*averages*: *//' | tr ',' '.' | awk '{print int($1)}')
    while [ "${l:-0}" -ge 8 ]; do
      echo "[driver] load $l >= 8, waiting"
      sleep 15
      l=$(uptime | sed 's/.*averages*: *//' | tr ',' '.' | awk '{print int($1)}')
    done
    echo "=== round $r  $label (cap=$cap)  load=$l ==="
    "$BENCH/wp7-run-duty.sh" "$label" "$cap" "$r"
  done
done
echo "=== all runs done ==="
