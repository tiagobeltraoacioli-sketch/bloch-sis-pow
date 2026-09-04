#!/usr/bin/env bash
# Replay determinism: does the dual-stack binary compute the same state as the
# binary it replaces, on the same chain?
#
# Wall-clock-driven nodes do not produce identical chains across two live runs,
# so "byte-identical" cannot be measured by running the two binaries side by
# side. Replay can: it is a pure function of the block log. Take ONE chain,
# built once, and hand it to:
#
#   1. the baseline binary                      (the code being replaced)
#   2. the patched binary, no --transport flag   (the default path)
#   3. the patched binary, --transport devnet    (named explicitly)
#   4. the patched binary, --transport dual      (both transports live)
#
# All four must print the same head slot, the same block count and the same
# state root. (4) is the one that matters most: if the transport could reach
# block validity, this is where it would show.
#
# usage: replay-determinismo.sh <blocks.log> <genesis.blg> <baseline-bin> \
#                               <patched-bin> <outdir>
#
# Ports 287xx are hard-coded; every run binds a listener before it replays, so
# pick a range nothing else on the box holds.
set -uo pipefail
LOG="${1:?blocks.log}"; GEN="${2:?genesis manifest}"; BASE="${3:?baseline binary}"; NEW="${4:?patched binary}"; R="${5:?outdir}"
[ -f "$LOG" ] || { echo "no chain at $LOG" >&2; exit 1; }
rm -rf "$R"; mkdir -p "$R"
run_one() { # $1=label  $2=binary  $3...=extra args
  local label="$1" bin="$2"; shift 2
  local d="$R/$label"; mkdir -p "$d"
  # Observer mode: copy the chain and nothing else. No validator.key (a second
  # signer for one index is equivocation) and no p2p_identity.bin.
  cp "$LOG" "$d/blocks.log"
  "$bin" run --data-dir "$d" --genesis "$GEN" \
     --rpc-port off --stop-at-slot 1 "$@" > "$R/$label.log" 2>&1
  local rc=$?
  printf '%-28s rc=%d  %s\n' "$label" "$rc" \
    "$(grep -E '^(replayed|STOP at slot)' "$R/$label.log" | tr '\n' ' | ')"
}

echo "blocks.log: $(wc -c < "$LOG") bytes"
run_one baseline-default      "$BASE" --transport devnet --listen 28701
run_one patched-noflag        "$NEW"  --listen 28702
run_one patched-devnet        "$NEW"  --transport devnet --listen 28703
run_one patched-dual          "$NEW"  --transport dual   --listen 28704 \
                                      --p2p-listen /ip4/127.0.0.1/tcp/28714
run_one patched-libp2p        "$NEW"  --transport libp2p \
                                      --p2p-listen /ip4/127.0.0.1/tcp/28715

echo
echo "── state roots ─────────────────────────────────────────────"
ok=1
ref=""
for f in "$R"/*.log; do
  lbl=$(basename "$f" .log)
  root=$(grep -oE 'state root [0-9a-f]{64}' "$f" | tail -1 | awk '{print $3}')
  head=$(grep -oE 'STOP at slot [0-9]+: head slot [0-9]+, [0-9]+ blocks' "$f" | tail -1)
  printf '  %-22s %s   [%s]\n' "$lbl" "${root:-MISSING}" "${head:-no STOP line}"
  [ -z "$ref" ] && ref="$root"
  [ "$root" != "$ref" ] && ok=0
  [ -z "$root" ] && ok=0
done
echo
[ "$ok" = 1 ] && echo "VERDICT: IDENTICAL — the transport does not reach the state transition" \
              || echo "VERDICT: DIVERGENT — the transport reaches the state transition. STOP."
