#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── DEVNET PARTITION-AND-RECONNECT HARNESS ──────────────────────────────────
#
# Runs a throwaway N-node devnet through three phases — full mesh, a network
# SPLIT into two halves, then a heal back to full mesh — and prints a
# CONVERGED/DIVERGED verdict computed from the nodes' head block ids.
#
# PROVENANCE. Written by PMO10/devA as `devnet-partition2.sh`, derived from
# dev8's `scripts/devnet-partition.sh` skeleton, which had never been executed
# (it passed no --rpc-port, so every node used the default 127.0.0.1:16310 and
# all but one failed to bind). Brought in-tree unmodified except for this
# header and the credit, because the founder's requirement is that a proof be
# runnable by a third party from the repo, not from somebody's scratch
# directory. Measured with it: n=8 control WITHOUT a split CONVERGES; n=8 WITH
# the split DIVERGES, repeatably.
#
# ── WHAT THIS DOES AND DOES NOT MEASURE ─────────────────────────────────────
#
# This harness measures NODE-LEVEL fork-choice divergence across a partition
# and heal. That is NOT the same defect as the leaked-roster split that
# `crates/bloch-pos-committee/src/prova.rs` and `scripts/prova-relanca.sh`
# prove. The two are distinct and must not be reported as one:
#
#   * THIS harness         — a partition splits fork choice and the halves do
#                            not reconverge on heal. Live today at any epoch.
#   * prova.rs scenarios   — a leak ledger makes `epoch_committees` shuffle a
#                            different-length list, so attestations admitted
#                            into a block are dropped at the boundary tally.
#                            Inert until LEAKED_ROSTER_ACTIVATION_EPOCH = 1400.
#
# A run of this harness against a binary that carries the roster fix answers
# whether the roster fix ALSO closes the partition divergence. It does not
# assume it, and neither should any report quoting it.
#
# USAGE
#
#   BLOCH_POS_BIN=/path/to/bloch-pos scripts/devnet-particao.sh <workdir> \
#       [n] [slot_ms] [split_at] [heal_at] [stop_at] [split|control]
#
#   scripts/devnet-veredito.py <workdir>:<n>:<label> ...   # verdict from logs
#
# `mode=control` runs phase 2 as a full mesh instead of a split, which is what
# proves the harness can say CONVERGED at all. Always run the control arm: a
# harness that can only print DIVERGED is not measuring anything.
#
# DEVNET ONLY: binds 127.0.0.1, throwaway keys, never a production manifest.
#
# Original header follows.
#
# PMO10 / devA — partition-and-reconnect harness, RPC-instrumented.
# Derived from dev8's skeleton (scripts/devnet-partition.sh), which was never
# executed. Fixes vs that version:
#   1. --rpc-port per node. The skeleton passed none, so every node used the
#      default 127.0.0.1:16310 and all but one failed to bind.
#   2. A real report: getchaininfo sampled over RPC while the phase is LIVE
#      (the nodes exit at --stop-at-slot, so a post-hoc query is impossible).
#   3. A CONVERGED/DIVERGED verdict computed from head block ids.
#   4. mode=control runs phase 2 as a full mesh, to prove the harness can say
#      CONVERGED.
set -uo pipefail

WORKDIR="${1:?usage: devnet-particao.sh <workdir> [n] [slot_ms] [split] [heal] [stop] [split|control]}"
N="${2:-4}"; SLOT_MS="${3:-1000}"; SPLIT_AT="${4:-20}"; HEAL_AT="${5:-60}"; STOP_AT="${6:-110}"
MODE="${7:-split}"
BASE_PORT="${BASE_PORT:-19410}"; RPC_BASE="${RPC_BASE:-17410}"
BIN="${BLOCH_POS_BIN:?set BLOCH_POS_BIN}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

rm -rf "$WORKDIR"; mkdir -p "$WORKDIR/rpc"
HALF=$(( N / 2 )); PIDS=()

peers_for() {
  local i="$1" mode="$2" lo hi out=""
  if [ "$mode" = "mesh" ]; then lo=0; hi=$(( N - 1 ))
  elif [ "$i" -lt "$HALF" ]; then lo=0; hi=$(( HALF - 1 ))
  else lo="$HALF"; hi=$(( N - 1 )); fi
  for j in $(seq "$lo" "$hi"); do
    [ "$j" = "$i" ] && continue
    out="${out:+$out,}127.0.0.1:$(( BASE_PORT + j ))"
  done
  printf '%s' "$out"
}

rpc() { # $1=port $2=method  -> json or empty
  curl -s --max-time 3 -X POST "http://127.0.0.1:$1" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}" 2>/dev/null
}

launch() { # $1=mode $2=stop $3=tag ; runs nodes, samples RPC, waits
  local mode="$1" stop="$2" tag="$3" i
  PIDS=()
  for i in $(seq 0 $(( N - 1 ))); do
    local d="$WORKDIR/node$i"
    "$BIN" run --data-dir "$d" --genesis "$WORKDIR/genesis.blg" --transport devnet \
      --listen "$(( BASE_PORT + i ))" --peers "$(peers_for "$i" "$mode")" \
      --rpc-bind 127.0.0.1 --rpc-port "$(( RPC_BASE + i ))" \
      --stop-at-slot "$stop" >> "$d/$tag.log" 2>&1 &
    PIDS+=("$!")
  done
  # Sample while live; keep the last good sample per node.
  while :; do
    local alive=0
    for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
    for i in $(seq 0 $(( N - 1 ))); do
      local j; j=$(rpc "$(( RPC_BASE + i ))" getchaininfo)
      [ -n "$j" ] && printf '%s' "$j" > "$WORKDIR/rpc/$tag.node$i.json"
    done
    [ "$alive" = "0" ] && break
    sleep 2
  done
  wait "${PIDS[@]}" 2>/dev/null || true
  # A node that never reaches --stop-at-slot would otherwise outlive the phase
  # and steal CPU from every later measurement (observed: 11 strays).
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  sleep 1
}

report() { # $1=tag
  local tag="$1"
  echo "── phase $tag ──────────────────────────────────────────────"
  python3 - "$WORKDIR" "$tag" "$N" <<'PY'
import json,os,sys,re
wd,tag,n=sys.argv[1],sys.argv[2],int(sys.argv[3])
heads={}; proposed={}; refused={}; landed=set()
for i in range(n):
    f=f"{wd}/rpc/{tag}.node{i}.json"
    log=f"{wd}/node{i}/{tag}.log"
    nic=applied=0
    if os.path.exists(log):
        t=open(log,errors="replace").read()
        nic=t.count("NotInCommittee"); applied=len(re.findall(r"\] applied ",t))
        proposed[i]=set(re.findall(r"\] proposing block ([0-9a-f]+)",t))
        refused[i]=len(re.findall(r"REFUSED OWN BLOCK",t))
        landed.update(re.findall(r"\] applied ([0-9a-f]+)",t))
    if os.path.exists(f):
        try: d=json.load(open(f))["result"]
        except Exception: d=None
    else: d=None
    if d:
        heads[i]=d["block_id"]
        print(f"node{i:<2} slot={d['slot']:<5} height={d['height']:<5} head={d['block_id'][:8]} "
              f"fin=e{d['finalized']['epoch']}/{d['finalized']['root'][:8]} "
              f"just=e{d['justified']['epoch']} blocks_known={d['blocks_known']:<5} "
              f"behind={d['behind_by_slots']:<4} NotInCommittee={nic:<5} applied={applied}")
    else:
        print(f"node{i:<2} NO RPC SAMPLE   NotInCommittee={nic:<5} applied={applied}")
tp=tl=tr=0
for i in range(n):
    pr=proposed.get(i,set()); ld=pr & landed; tp+=len(pr); tl+=len(ld); tr+=refused.get(i,0)
    if pr:
        print(f"  node{i} proposed={len(pr):<4} landed={len(ld):<4} never_landed={len(pr)-len(ld):<4} refused_own={refused.get(i,0)}")
if tp: print(f"  TOTAL proposed={tp} landed={tl} never_landed={tp-tl} ({100.0*(tp-tl)/tp:.1f}%) refused_own={tr}")
distinct=sorted(set(heads.values()))
if not heads: print("VERDICT: NO DATA")
elif len(distinct)==1: print(f"VERDICT[{tag}]: CONVERGED on {distinct[0][:8]} ({len(heads)}/{n} nodes reporting)")
else:
    print(f"VERDICT[{tag}]: DIVERGED — {len(distinct)} distinct heads")
    for h in distinct: print("   ",h[:8],"=",sorted(k for k,v in heads.items() if v==h))
PY
}

for i in $(seq 0 $(( N - 1 ))); do
  d="$WORKDIR/node$i"; mkdir -p "$d"
  "$BIN" keygen --dir "$d" --index "$i" >/dev/null || { echo "keygen failed" >&2; exit 1; }
  KEYDIRS="${KEYDIRS:-}${KEYDIRS:+,}$d"
done
"$BIN" genesis --keys "$KEYDIRS" --out "$WORKDIR/genesis.blg" --slot-ms "$SLOT_MS" --start-in 5 \
  || { echo "genesis failed" >&2; exit 1; }

echo "devnet-partition2: n=$N slot_ms=$SLOT_MS split@$SPLIT_AT heal@$HEAL_AT stop@$STOP_AT mode=$MODE"
P2MODE=mesh; [ "$MODE" = "split" ] && P2MODE=split
echo "  phase2 mode=$P2MODE  halves A=[0,$HALF) B=[$HALF,$N)"
T0=$(date +%s)
launch mesh    "$SPLIT_AT" phase1-mesh
launch $P2MODE "$HEAL_AT"  phase2
launch mesh    "$STOP_AT"  phase3-heal
T1=$(date +%s)
report phase1-mesh; report phase2; report phase3-heal
echo; echo "wall-clock: $(( T1 - T0 ))s for n=$N slot_ms=$SLOT_MS stop@$STOP_AT mode=$MODE"
