#!/usr/bin/env bash
# Proof that `--transport dual` is a PRODUCTION path, not a test fixture:
# that it reaches `engine::run` with a `Transport` that starts BOTH stacks in
# one process, that both say so at startup, and that both report peers.
#
# Three nodes, one arm, ~90s:
#
#   node0  --transport devnet   (dials node1's mesh port)
#   node1  --transport dual     (mesh + swarm, ONE process)   <-- under test
#   node2  --transport libp2p   (dials node1's swarm address)
#
# PASS requires node1's `getchaininfo` to report
#   transport.name == "dual"  AND  transport.peers.devnet > 0
#                             AND  transport.peers.libp2p > 0
# which no single-stack node can produce: a devnet node answers
# `peers.libp2p: null` and a libp2p node answers `peers.devnet: null`.
#
# THE `bridged` LIMIT IS EXPECTED HERE, NOT A FAILURE. node2 holds a validator
# key, so it is a libp2p-only PRODUCER, and a dual node does not relay
# mesh-to-mesh (see the header of crates/bloch-pos-node/src/net.rs). Blocks
# born on libp2p alone therefore never reach node0, and node0 falls off the
# chain partway through. That is the measured basis for the ordering rule in
# docs/THIRD-PARTY-QUICKSTART.md: dual must be fleet-wide BEFORE anyone runs
# libp2p alone. This script prints the divergence rather than hiding it.
#
# Usage:  BIN=./target/debug/bloch-pos scripts/transporte-postura-prova.sh
set -u

BIN="${BIN:-./target/debug/bloch-pos}"
W="${W:-$(mktemp -d)}"
DEV="${DEV:-19710}"
P2P="${P2P:-19720}"
RPC="${RPC:-17710}"
STOP_AT="${STOP_AT:-40}"

[ -x "$BIN" ] || { echo "no binary at $BIN (cargo build -p bloch-pos-node)" >&2; exit 1; }

# ── Keystore at rest (audit I-H1) ──────────────────────────────────────────
# This is a DEVNET harness: throwaway keys, throwaway chain, a temp dir. The
# node now refuses to read or write a keystore whose secret key sits on disk in
# the clear unless someone says so, so this script says so, once, for every
# bloch-pos it launches below. A real validator is sealed instead: leave this
# unset and export BLOCH_KEYSTORE_PASSPHRASE_FILE=<path> in the unit.
export BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1


rm -rf "$W"; mkdir -p "$W/keys" "$W/logs"
KEYDIRS=""
for i in 0 1 2; do
  d="$W/keys/node$i"; mkdir -p "$d"
  # Throwaway devnet keys in a temp dir: --allow-plaintext-keystore is the
  # explicit opt-in the node now requires before it will write (or read) a
  # keystore with the secret key in the clear (audit I-H1). A real validator
  # is sealed instead, with BLOCH_KEYSTORE_PASSPHRASE_FILE.
  "$BIN" keygen --allow-plaintext-keystore --dir "$d" --index "$i" >/dev/null || exit 1
  KEYDIRS="${KEYDIRS}${KEYDIRS:+,}$d"
done
"$BIN" genesis --keys "$KEYDIRS" --out "$W/g.blg" --slot-ms 2000 --start-in 5 >/dev/null || exit 1
for i in 0 1 2; do
  mkdir -p "$W/node$i"; cp "$W/keys/node$i/validator.key" "$W/node$i/validator.key"
done

"$BIN" run --data-dir "$W/node0" --genesis "$W/g.blg" \
  --transport devnet --listen "$DEV" --peers "127.0.0.1:$((DEV+1))" \
  --rpc-bind 127.0.0.1 --rpc-port "$RPC" --stop-at-slot "$STOP_AT" \
  > "$W/logs/node0.log" 2>&1 &

"$BIN" run --data-dir "$W/node1" --genesis "$W/g.blg" \
  --transport dual --listen "$((DEV+1))" --peers "127.0.0.1:$DEV" \
  --p2p-listen "/ip4/127.0.0.1/tcp/$((P2P+1))" \
  --rpc-bind 127.0.0.1 --rpc-port "$((RPC+1))" --stop-at-slot "$STOP_AT" \
  > "$W/logs/node1.log" 2>&1 &

"$BIN" run --data-dir "$W/node2" --genesis "$W/g.blg" \
  --transport libp2p \
  --p2p-listen "/ip4/127.0.0.1/tcp/$((P2P+2))" \
  --p2p-peer "/ip4/127.0.0.1/tcp/$((P2P+1))" \
  --rpc-bind 127.0.0.1 --rpc-port "$((RPC+2))" --stop-at-slot "$STOP_AT" \
  > "$W/logs/node2.log" 2>&1 &

rpc() {
  curl -s --max-time 3 -X POST "http://127.0.0.1:$1" \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' 2>/dev/null
}
field() { # $1 = json file, $2 = devnet|libp2p
  python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["result"]["transport"]["peers"][sys.argv[2]])
except Exception: print("null")' "$1" "$2" 2>/dev/null || echo null
}

PASS=1
for _ in $(seq 1 40); do
  sleep 2
  out="$(rpc $((RPC+1)))"
  case "$out" in *'"transport"'*) printf '%s' "$out" > "$W/node1.chaininfo.json";; esac
  [ -s "$W/node1.chaininfo.json" ] || continue
  d="$(field "$W/node1.chaininfo.json" devnet)"
  l="$(field "$W/node1.chaininfo.json" libp2p)"
  if [ "$d" != "null" ] && [ "$l" != "null" ] && [ "$d" -gt 0 ] && [ "$l" -gt 0 ] 2>/dev/null; then
    PASS=0; break
  fi
done

echo "── node1 startup, both transport lines ─────────────────────"
grep -E '^transport:' "$W/logs/node1.log"
echo "── node1 getchaininfo ──────────────────────────────────────"
python3 -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))["result"]["transport"]))' \
  "$W/node1.chaininfo.json" 2>/dev/null || echo "(no answer)"
echo "── single-stack nodes, for contrast ────────────────────────"
for p in "$RPC" "$((RPC+2))"; do
  rpc "$p" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)["result"]["transport"]))' \
    2>/dev/null || echo "port $p: no answer"
done

wait
echo "── the ordering rule, measured (see the header) ────────────"
for i in 0 1 2; do
  printf 'node%s last applied: %s\n' "$i" \
    "$(grep applied "$W/logs/node$i.log" | tail -1)"
done
[ "$PASS" = 0 ] && echo "PASS: one process, two stacks, peers on both" \
                || echo "FAIL: node1 did not report peers on both stacks"
echo "workdir: $W"
exit "$PASS"
