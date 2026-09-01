#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The OBSERVATION arm of scripts/devnet-fratura.sh: a poller that sweeps
# `getblockbyslot` for EVERY slot on EVERY pass, against every node.
#
# This is not a strawman. It is the shape of a test written in this repository
# that reported a fracture it had itself manufactured: every RPC call is
# enqueued onto the single consensus thread (`EngineBackend::call`,
# rpc.rs:987-1012 → engine.rs:2663-2668), so a sweep of N slots is N pieces of
# work serialised against block application, in a loop whose cost grows with
# the chain.
#
#   usage: devnet-fratura-varredura.sh <rpc_base> <n_nodes> <outdir>
set -uo pipefail
RPC_BASE="${1:?rpc base}"; N="${2:?n}"; OUT="${3:?outdir}"
mkdir -p "$OUT"
count=0
while :; do
  head=$(curl -s --max-time 3 -X POST "http://127.0.0.1:$RPC_BASE" \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' \
    | sed -n 's/.*"wall_slot":\([0-9]*\).*/\1/p')
  [ -z "$head" ] && head=0
  for i in $(seq 0 $(( N - 1 ))); do
    for s in $(seq 0 "$head"); do
      curl -s --max-time 3 -X POST "http://127.0.0.1:$(( RPC_BASE + i ))" \
        -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockbyslot\",\"params\":[$s]}" \
        > /dev/null 2>&1
      count=$(( count + 1 ))
    done
  done
  echo "$(date +%s) sweep to slot $head, cumulative requests $count" >> "$OUT/varredura.log"
done
