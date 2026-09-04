#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── MIXED-TRANSPORT CONVERGENCE HARNESS ─────────────────────────────────────
#
# Answers with real nodes, not with reasoning: when a Genesis-4 fleet is PART
# devnet-mesh and PART libp2p, do the halves converge on one chain, and what
# does a dual-stack node (`--transport dual`) actually buy?
#
# Five arms. Three validators each, one set of keys, one cadence, one stop
# slot. The arms differ ONLY in each node's --transport (and, in `observer`,
# in whether node2 holds a validator key at all).
#
#   control    n0 devnet   n1 devnet   n2 devnet
#              A plain full mesh. Proves the harness can say SAME CHAIN.
#
#   island     n0 devnet   n1 devnet   n2 libp2p
#              The fleet as it is TODAY with a libp2p newcomer: node2 speaks a
#              protocol nobody else speaks. Expect FORKED. An arm that cannot
#              reproduce the failure proves nothing about the fix.
#
#   bridged    n0 devnet   n1 DUAL     n2 libp2p (validator)
#              One dual node, and a libp2p node that PRODUCES BLOCKS. This is
#              the case dual-stack does NOT fully solve, and the arm exists to
#              show exactly where the limit is: node1 and node2 agree, node0
#              falls off, because a dual node does not relay mesh-to-mesh and
#              devnet's `blocks_after(head)` sync cannot backfill below its own
#              head once it has forked.
#
#   rolling    n0 devnet   n1 DUAL     n2 DUAL
#              The migration's middle state: everyone who has crossed is dual,
#              nobody is libp2p-only yet, so NO BLOCK IS BORN ON A TRANSPORT
#              SOME VALIDATOR CANNOT HEAR. Expect SAME CHAIN. This is the arm
#              that says the rolling crossing order is safe.
#
#   observer   n0 devnet   n1 DUAL     n2 libp2p, NO VALIDATOR KEY
#              The exchange's case. node2 signs nothing, so again no block is
#              born on libp2p. Expect SAME CHAIN, with node2 having built its
#              state by validating every block itself over an authenticated
#              transport — not from a donated data directory.
#
# DEVNET ONLY: binds 127.0.0.1, throwaway keys, never a production manifest.
#
# USAGE
#   BLOCH_POS_BIN=/path/to/bloch-pos devnet-transporte-misto.sh <workdir> \
#       [slot_ms] [stop_at_slot] [arm ...]
set -uo pipefail

WORKDIR="${1:?usage: devnet-transporte-misto.sh <workdir> [slot_ms] [stop_at] [arm...]}"
SLOT_MS="${2:-1000}"; STOP_AT="${3:-90}"
shift 3 2>/dev/null || shift $# 
ARMS=("$@"); [ ${#ARMS[@]} -eq 0 ] && ARMS=(control island island-obs observer bridged rolling)
BIN="${BLOCH_POS_BIN:?set BLOCH_POS_BIN}"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }

DEV_BASE="${DEV_BASE:-19510}"     # devnet mesh TCP ports
P2P_BASE="${P2P_BASE:-19520}"     # libp2p TCP ports
RPC_BASE="${RPC_BASE:-17510}"

rm -rf "$WORKDIR"
# Logs and RPC samples live OUTSIDE the node data directories: the data dirs
# are wiped between arms, and an earlier version of this script kept the logs
# inside them and so deleted the evidence of every arm but the last.
mkdir -p "$WORKDIR/rpc" "$WORKDIR/logs" "$WORKDIR/keys"

for i in 0 1 2; do
  d="$WORKDIR/keys/node$i"; mkdir -p "$d"
  "$BIN" keygen --dir "$d" --index "$i" >/dev/null || { echo "keygen failed" >&2; exit 1; }
  KEYDIRS="${KEYDIRS:-}${KEYDIRS:+,}$d"
done

rpc() {
  curl -s --max-time 3 -X POST "http://127.0.0.1:$1" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}" 2>/dev/null
}

launch() { # $1 = arm
  local arm="$1" i
  # One genesis PER ARM. `genesis_time_ms` is stamped when the manifest is
  # written and `--stop-at-slot` is an absolute slot, so one manifest shared
  # across sequential arms puts every arm after the first past its stop slot
  # before it has produced anything. Same keys, same stakes, same cadence —
  # only the start time moves.
  "$BIN" genesis --keys "$KEYDIRS" --out "$WORKDIR/g-$arm.blg" \
    --slot-ms "$SLOT_MS" --start-in 5 >/dev/null \
    || { echo "genesis failed for $arm" >&2; exit 1; }

  # Fresh, empty data dirs, seeded only with the validator key — except node2
  # in `observer`, which gets no key and so starts in observer mode.
  for i in 0 1 2; do
    local d="$WORKDIR/$arm/node$i"; rm -rf "$d"; mkdir -p "$d"
    if [ "$i" = 2 ] && { [ "$arm" = observer ] || [ "$arm" = island-obs ]; }; then :; else
      cp "$WORKDIR/keys/node$i/validator.key" "$d/validator.key"
    fi
  done

  PIDS=()
  local G="$WORKDIR/g-$arm.blg"

  # node0 — always the devnet mesh, always peered at node1.
  "$BIN" run --data-dir "$WORKDIR/$arm/node0" --genesis "$G" \
    --transport devnet --listen "$DEV_BASE" --peers "127.0.0.1:$((DEV_BASE+1))" \
    --rpc-bind 127.0.0.1 --rpc-port "$RPC_BASE" --stop-at-slot "$STOP_AT" \
    > "$WORKDIR/logs/$arm.node0.log" 2>&1 &
  PIDS+=("$!")

  # node1 — devnet in control/island, dual everywhere else.
  case "$arm" in
    control|island|island-obs)
      "$BIN" run --data-dir "$WORKDIR/$arm/node1" --genesis "$G" \
        --transport devnet --listen "$((DEV_BASE+1))" --peers "127.0.0.1:$DEV_BASE" \
        --rpc-bind 127.0.0.1 --rpc-port "$((RPC_BASE+1))" --stop-at-slot "$STOP_AT" \
        > "$WORKDIR/logs/$arm.node1.log" 2>&1 & ;;
    *)
      "$BIN" run --data-dir "$WORKDIR/$arm/node1" --genesis "$G" \
        --transport dual --listen "$((DEV_BASE+1))" --peers "127.0.0.1:$DEV_BASE" \
        --p2p-listen "/ip4/127.0.0.1/tcp/$((P2P_BASE+1))" \
        --rpc-bind 127.0.0.1 --rpc-port "$((RPC_BASE+1))" --stop-at-slot "$STOP_AT" \
        > "$WORKDIR/logs/$arm.node1.log" 2>&1 & ;;
  esac
  PIDS+=("$!")

  # node2 — devnet in control; dual in rolling; libp2p otherwise.
  case "$arm" in
    control)
      "$BIN" run --data-dir "$WORKDIR/$arm/node2" --genesis "$G" \
        --transport devnet --listen "$((DEV_BASE+2))" \
        --peers "127.0.0.1:$DEV_BASE,127.0.0.1:$((DEV_BASE+1))" \
        --rpc-bind 127.0.0.1 --rpc-port "$((RPC_BASE+2))" --stop-at-slot "$STOP_AT" \
        > "$WORKDIR/logs/$arm.node2.log" 2>&1 & ;;
    rolling)
      # Dual, and peered on BOTH: devnet at node0 and node1, libp2p at node1.
      "$BIN" run --data-dir "$WORKDIR/$arm/node2" --genesis "$G" \
        --transport dual --listen "$((DEV_BASE+2))" \
        --peers "127.0.0.1:$DEV_BASE,127.0.0.1:$((DEV_BASE+1))" \
        --p2p-listen "/ip4/127.0.0.1/tcp/$((P2P_BASE+2))" \
        --p2p-peer "/ip4/127.0.0.1/tcp/$((P2P_BASE+1))" \
        --rpc-bind 127.0.0.1 --rpc-port "$((RPC_BASE+2))" --stop-at-slot "$STOP_AT" \
        > "$WORKDIR/logs/$arm.node2.log" 2>&1 & ;;
    *)
      # Dials node1's libp2p listener by address. In `island` nobody is
      # listening there, which is the whole point of that arm.
      "$BIN" run --data-dir "$WORKDIR/$arm/node2" --genesis "$G" \
        --transport libp2p \
        --p2p-listen "/ip4/127.0.0.1/tcp/$((P2P_BASE+2))" \
        --p2p-peer "/ip4/127.0.0.1/tcp/$((P2P_BASE+1))" \
        --rpc-bind 127.0.0.1 --rpc-port "$((RPC_BASE+2))" --stop-at-slot "$STOP_AT" \
        > "$WORKDIR/logs/$arm.node2.log" 2>&1 & ;;
  esac
  PIDS+=("$!")

  # Sample getchaininfo while the nodes are LIVE: they exit at --stop-at-slot,
  # so there is nothing left to query afterwards.
  while :; do
    local alive=0
    for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
    for i in 0 1 2; do
      local j; j=$(rpc "$((RPC_BASE+i))" getchaininfo)
      [ -n "$j" ] && printf '%s' "$j" > "$WORKDIR/rpc/$arm.node$i.json"
    done
    [ "$alive" = "0" ] && break
    sleep 1
  done
  wait "${PIDS[@]}" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  sleep 1
}

report() {
  python3 - "$WORKDIR" "$@" <<'@PY@'
import json,os,sys,re
wd=sys.argv[1]; arms=sys.argv[2:]

# Per node: slot -> (block_id8, state_root8), read from the node's own log.
# Comparing the CHAINS slot by slot, rather than the heads at one sampling
# instant, is what makes this robust to a node simply being behind: a lagging
# node on the same chain agrees everywhere the two overlap, and a node on its
# own chain disagrees from the fork point onward.
APPLIED = re.compile(r"\[slot (\d+)\] applied ([0-9a-f]+) by v\d+ . head root ([0-9a-f]+)")
for arm in arms:
    chains={}; info={}
    for i in range(3):
        log=f"{wd}/logs/{arm}.node{i}.log"; c={}
        if os.path.exists(log):
            for slot,bid,root in APPLIED.findall(open(log,errors="replace").read()):
                c[int(slot)]=(bid,root)
        chains[i]=c
        f=f"{wd}/rpc/{arm}.node{i}.json"
        if os.path.exists(f):
            try: info[i]=json.load(open(f))["result"]
            except Exception: pass
    print("-- arm %-9s %s" % (arm, "-"*48))
    for i in range(3):
        d=info.get(i)
        if d:
            print(f"  node{i} slot={d['slot']:<4} height={d['height']:<4} "
                  f"head={d['block_id'][:12]} root={d.get('state_root','?')[:12]} "
                  f"fin=e{d['finalized']['epoch']} applied={len(chains[i])}")
        else:
            print(f"  node{i} NO RPC SAMPLE  applied={len(chains[i])}")
    verdict="SAME CHAIN"
    for a in range(3):
        for b in range(a+1,3):
            common=sorted(set(chains[a]) & set(chains[b]))
            if not common:
                print(f"    node{a} vs node{b}: NO COMMON SLOT "
                      f"({len(chains[a])} vs {len(chains[b])} applied)")
                verdict="FORKED"; continue
            bad=[s for s in common if chains[a][s]!=chains[b][s]]
            if bad:
                s=bad[0]
                print(f"    node{a} vs node{b}: {len(common)} common slots, {len(bad)} DISAGREE, "
                      f"first slot {s} ({chains[a][s][0]} vs {chains[b][s][0]})")
                verdict="FORKED"
            else:
                print(f"    node{a} vs node{b}: {len(common)} common slots, ALL AGREE")
    heads={i:info[i]["block_id"] for i in info}
    roots={i:info[i].get("state_root") for i in info}
    print(f"  VERDICT[{arm}]: {verdict}"
          f" | identical head at sample: {'YES' if len(set(heads.values()))==1 and len(heads)==3 else 'no'}"
          f" | identical state root: {'YES' if len(set(roots.values()))==1 and len(roots)==3 else 'no'}")
@PY@
}

echo "mixed-transport: slot_ms=$SLOT_MS stop@$STOP_AT arms=${ARMS[*]}"
for arm in "${ARMS[@]}"; do echo "-- running arm: $arm"; launch "$arm"; done
echo
report "${ARMS[@]}"
