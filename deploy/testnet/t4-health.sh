#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── t4 HEALTH PROBE (systemd timer, every 5 min) ────────────────────────────
# The antidote to the mainnet proxy's silent-upstream failure: every node is
# probed BY PORT on every run, and the result is a public fact (served at
# /health by nginx) rather than a quiet 502. Checks, per node:
#   * RPC answers getchaininfo,
#   * finalized epoch ADVANCED since the previous probe (staleness file),
#   * all nodes report the SAME finalized root at the same finalized epoch
#     (divergence on a single host = a real consensus bug worth waking up for).
# Exit nonzero on any failure so `systemctl status bloch-t4-health` shows red.
set -uo pipefail

T4DIR="${T4DIR:-/home/ubuntu/t4}"
RPC_BASE="${RPC_BASE:-18500}"
N="${N:-4}"
STATE="$T4DIR/health.last"     # previous finalized epoch
OUT="$T4DIR/health.json"

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fail=""
declare -a heights fins roots
for i in $(seq 0 $(( N - 1 ))); do
  r=$(curl -s --max-time 5 -X POST "http://127.0.0.1:$(( RPC_BASE + i ))" \
      -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' 2>/dev/null)
  heights[$i]=$(printf '%s' "$r" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["height"])' 2>/dev/null)
  fins[$i]=$(printf '%s' "$r"    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["finalized"]["epoch"])' 2>/dev/null)
  roots[$i]=$(printf '%s' "$r"   | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["finalized"]["root"])' 2>/dev/null)
  [ -n "${fins[$i]}" ] || fail="node$i: RPC dead on port $(( RPC_BASE + i )); $fail"
done

# Same finalized root wherever the finalized epoch is the same.
for i in $(seq 1 $(( N - 1 ))); do
  if [ -n "${fins[0]:-}" ] && [ "${fins[$i]:-}" = "${fins[0]}" ] \
     && [ -n "${roots[0]:-}" ] && [ "${roots[$i]:-x}" != "${roots[0]}" ]; then
    fail="node$i: DIVERGED finalized root at epoch ${fins[0]}; $fail"
  fi
done

# Finality must advance between probes eventually: allow 3 stale probes
# (15 min > 1 epoch increment at 16 min/epoch is borderline, so 3 gives
# ~45 min before alarm — real stall, not jitter).
prev_epoch=0; prev_count=0
[ -f "$STATE" ] && read -r prev_epoch prev_count < "$STATE"
cur="${fins[0]:-0}"
if [ -n "${fins[0]:-}" ]; then
  if [ "$cur" -gt "$prev_epoch" ] 2>/dev/null; then
    echo "$cur 0" > "$STATE"
  else
    prev_count=$(( prev_count + 1 ))
    echo "$prev_epoch $prev_count" > "$STATE"
    [ "$prev_count" -ge 3 ] && fail="finality STALLED at epoch $cur for $prev_count probes; $fail"
  fi
fi

status=ok; [ -n "$fail" ] && status=fail
{
  printf '{"status":"%s","checked_at":"%s","finalized_epoch":%s,"height":%s' \
    "$status" "$now" "${fins[0]:-null}" "${heights[0]:-null}"
  printf ',"nodes_up":%s' "$(for i in $(seq 0 $((N-1))); do [ -n "${fins[$i]:-}" ] && echo x; done | wc -l | tr -d ' ')"
  [ -n "$fail" ] && printf ',"detail":"%s"' "$fail"
  printf '}\n'
} > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"

if [ -n "$fail" ]; then
  echo "t4-health FAIL: $fail" >&2
  echo "recovery: sudo systemctl restart bloch-t4.target   (always the whole set)" >&2
  exit 1
fi
echo "t4-health ok: epoch ${fins[0]} height ${heights[0]} all $N nodes agree"
