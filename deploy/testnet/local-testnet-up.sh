#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── LOCAL GENESIS-4 TESTNET, FROM NOTHING ───────────────────────────────────
#
# Brings up an N-validator Bloch PoS testnet on localhost, from zero state,
# and PROVES three things before it calls itself up:
#
#   1. blocks are produced (height advances),
#   2. finality advances (finalized epoch moves past genesis),
#   3. the SPEND PATH works end to end: a genesis faucet output is spent
#      through submit-tx (external-signer seam) with a real hybrid
#      ML-DSA-65 ‖ Falcon-1024 signature, lands in a block, and the
#      recipient's balance is visible over RPC on every node.
#
# This exercises the same consensus code path as mainnet: same binary, same
# `run` command, same `--transport devnet` the live fleet runs, same
# transition, fee market and signature suite. What differs from mainnet is
# genesis material only: throwaway keys, no carryover, a faucet allocation,
# and (by default) a faster slot so finality is observable in seconds.
# Pass slot_ms=30000 for mainnet cadence.
#
# ── ISOLATION FROM MAINNET (read before running anything public) ────────────
#
# The spend signing root (transition.rs `spend_signing_root`) carries NO
# network identifier: a signature authorises moving specific OUTPOINTS
# (txid:vout), wherever they exist. Cross-network replay is impossible if and
# only if the two networks' outpoint sets are disjoint — which they are as
# long as the testnet genesis:
#   * ingests NO mainnet carryover (this script never touches carryover), and
#   * has NO allocation with the same (purpose, script_hash, amount,
#     unlock_epoch) tuple as a mainnet allocation (this script allocates to a
#     freshly generated throwaway key, so the tuple cannot collide).
# Every later txid commits to its input outpoints, so disjointness at genesis
# is disjointness forever. Consensus signatures are likewise safe: testnet
# validator keys are freshly generated here and never mainnet keys.
#
# NEVER load a mainnet key into this testnet, and never re-run mainnet's
# genesis-mainnet manifest here.
#
# ── RESTART HAZARD (why everything is co-located) ───────────────────────────
#
# A node restarted far behind the live head does not reliably complete a cold
# sync on this transport (genesis/README.md, measured 2026-08-14). Keep
# testnet validators few and on one host so a stall is fixed by restarting
# the WHOLE network from its data dirs (or from scratch) in seconds, not by
# babysitting a straggler.
#
# USAGE
#   deploy/testnet/local-testnet-up.sh <workdir> [n] [slot_ms]
#   deploy/testnet/local-testnet-up.sh <workdir> down     # stop the nodes
#
#   BLOCH_POS_BIN=/path/to/bloch-pos   overrides the binary
#   BASE_PORT (default 19500)          devnet transport ports, +i per node
#   RPC_BASE  (default 18500)          JSON-RPC ports, +i per node
#
# The network keeps running when the script exits; PIDs are in
# <workdir>/pids. RPC: http://127.0.0.1:$((RPC_BASE+i)).
set -uo pipefail

WORKDIR="${1:?usage: local-testnet-up.sh <workdir> [n] [slot_ms] | <workdir> down}"

if [ "${2:-}" = "down" ]; then
  if [ -f "$WORKDIR/pids" ]; then
    while read -r p; do kill "$p" 2>/dev/null; done < "$WORKDIR/pids"
    sleep 1
    while read -r p; do kill -9 "$p" 2>/dev/null; done < "$WORKDIR/pids"
    rm -f "$WORKDIR/pids"
    echo "testnet stopped"
  else
    echo "no $WORKDIR/pids — nothing to stop"
  fi
  exit 0
fi

N="${2:-4}"
SLOT_MS="${3:-1000}"
BASE_PORT="${BASE_PORT:-19500}"
RPC_BASE="${RPC_BASE:-18500}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BLOCH_POS_BIN:-$REPO/target/release/bloch-pos}"
[ -x "$BIN" ] || { echo "FATAL: no binary at $BIN (build with: cargo build --release -p bloch-pos-node, or set BLOCH_POS_BIN)" >&2; exit 1; }

# Faucet economics (satoshis; 1 BLOCH = 100_000_000 sat).
FAUCET_ALLOC_SAT=100000000000000       # 1,000,000 test BLCH at genesis
PAY_SAT=50000000000                    # 500 test BLCH to the recipient
TX_BYTES=9000                          # declared size, >= encoding, signed
TIP=0                                  # priority fee off: fee is exact
# Exact fee at the genesis base-fee floor (10 msat/gas), tip 0:
#   gas = TX_FLAT_GAS(5000) + TX_BYTES*GAS_PER_BYTE(16) + HYBRID_VERIFY_GAS(72748)
#   fee_sat = ceil(gas * 10 / 1000)
GAS=$(( 5000 + TX_BYTES * 16 + 72748 ))
FEE_SAT=$(( (GAS * 10 + 999) / 1000 ))
CHANGE_SAT=$(( FAUCET_ALLOC_SAT - PAY_SAT - FEE_SAT ))

rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"

say() { printf '\n── %s ──────────────────────────────────────────────\n' "$*"; }

rpc() { # $1=rpc-port $2=method [$3=params-json-array]
  curl -s --max-time 5 -X POST "http://127.0.0.1:$1" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" 2>/dev/null
}

jget() { # stdin=json  $1=python expression over d["result"]
  python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null
}

# ── 1. Keys: N validators + faucet + recipient, all throwaway ───────────────
say "generating $N validator keys + faucet + recipient (throwaway)"
KEYDIRS=""
for i in $(seq 0 $(( N - 1 ))); do
  d="$WORKDIR/node$i"; mkdir -p "$d"
  "$BIN" keygen --dir "$d" --index "$i" >/dev/null || { echo "keygen failed" >&2; exit 1; }
  KEYDIRS="${KEYDIRS}${KEYDIRS:+,}$d"
done
"$BIN" keygen --dir "$WORKDIR/faucet"    --index 0 >/dev/null || exit 1
"$BIN" keygen --dir "$WORKDIR/recipient" --index 0 >/dev/null || exit 1

FAUCET_SH=$("$BIN" spendkey --dir "$WORKDIR/faucet"    | awk '$1=="script_hash"{print $2}')
FAUCET_PK=$("$BIN" spendkey --dir "$WORKDIR/faucet"    | awk '$1=="pubkey"{print $2}')
RECIP_SH=$("$BIN"  spendkey --dir "$WORKDIR/recipient" | awk '$1=="script_hash"{print $2}')
[ -n "$FAUCET_SH" ] && [ -n "$RECIP_SH" ] || { echo "spendkey failed" >&2; exit 1; }
echo "faucet    script_hash $FAUCET_SH"
echo "recipient script_hash $RECIP_SH"

# ── 2. Genesis: own manifest, own digest, own network ───────────────────────
say "building testnet genesis (slot ${SLOT_MS}ms, faucet $((FAUCET_ALLOC_SAT / 100000000)) BLCH)"
"$BIN" genesis --keys "$KEYDIRS" --out "$WORKDIR/genesis.blg" \
  --slot-ms "$SLOT_MS" --start-in 10 \
  --alloc "$FAUCET_SH:$FAUCET_ALLOC_SAT" \
  || { echo "genesis failed" >&2; exit 1; }

# ── 3. Launch the validators, full mesh on localhost ────────────────────────
say "launching $N validators"
: > "$WORKDIR/pids"
for i in $(seq 0 $(( N - 1 ))); do
  peers=""
  for j in $(seq 0 $(( N - 1 ))); do
    [ "$j" = "$i" ] && continue
    peers="${peers}${peers:+,}127.0.0.1:$(( BASE_PORT + j ))"
  done
  "$BIN" run --data-dir "$WORKDIR/node$i" --genesis "$WORKDIR/genesis.blg" \
    --transport devnet --listen "$(( BASE_PORT + i ))" --peers "$peers" \
    --rpc-bind 127.0.0.1 --rpc-port "$(( RPC_BASE + i ))" \
    >> "$WORKDIR/node$i/run.log" 2>&1 &
  echo "$!" >> "$WORKDIR/pids"
done
echo "pids: $(tr '\n' ' ' < "$WORKDIR/pids")"

trap 'echo; echo "NOTE: nodes left running — stop with: $0 $WORKDIR down"' EXIT

# ── 4. Prove production and finality ────────────────────────────────────────
say "waiting for finality (finalized epoch >= 1)"
DEADLINE=$(( $(date +%s) + 300 ))
FIN_OK=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  info=$(rpc "$RPC_BASE" getchaininfo)
  if [ -n "$info" ]; then
    fin=$(printf '%s' "$info" | jget 'd["result"]["finalized"]["epoch"]')
    h=$(printf '%s' "$info"   | jget 'd["result"]["height"]')
    printf '\r  height=%-6s finalized_epoch=%-4s' "${h:-?}" "${fin:-?}"
    if [ -n "${fin:-}" ] && [ "$fin" -ge 1 ] 2>/dev/null; then FIN_OK=1; break; fi
  fi
  sleep 2
done
echo
[ -n "$FIN_OK" ] || { echo "FAIL: no finality within 300s — see $WORKDIR/node*/run.log" >&2; exit 1; }
echo "finality advancing: epoch $fin at height $h"

# ── 5. Prove the spend path ─────────────────────────────────────────────────
say "spending the faucet allocation (external-signer seam)"

# The faucet's genesis outpoint, read from the chain rather than recomputed.
utxo=$(rpc "$RPC_BASE" getutxos "[\"$FAUCET_SH\"]")
FTXID=$(printf '%s' "$utxo" | jget 'd["result"]["utxos"][0]["txid"]')
FVOUT=$(printf '%s' "$utxo" | jget 'd["result"]["utxos"][0]["vout"]')
[ -n "$FTXID" ] || { echo "FAIL: faucet has no UTXO on chain" >&2; exit 1; }
echo "faucet outpoint: $FTXID:$FVOUT"

basefee=$(rpc "$RPC_BASE" getchaininfo | jget 'd["result"]["next_base_fee_millisat_per_gas"]')
if [ "$basefee" != "10" ]; then
  echo "FAIL: base fee is $basefee msat/gas, not the floor 10 — the exact-fee arithmetic below would not conserve" >&2
  exit 1
fi
echo "fee: gas=$GAS fee_sat=$FEE_SAT  pay=$PAY_SAT  change=$CHANGE_SAT"

TXFLAGS=(--pubkey "$FAUCET_PK"
         --spend "$FTXID:$FVOUT"
         --pay "$RECIP_SH:$PAY_SAT"
         --pay "$FAUCET_SH:$CHANGE_SAT"
         --tx-bytes "$TX_BYTES" --tip "$TIP")

ROOT=$("$BIN" submit-tx --to "127.0.0.1:$BASE_PORT" "${TXFLAGS[@]}" 2>/dev/null)
[ -n "$ROOT" ] || { echo "FAIL: submit-tx printed no signing root" >&2; exit 1; }
echo "signing root: $ROOT"

SIG=$("$BIN" spendkey --dir "$WORKDIR/faucet" --sign "$ROOT" | awk '$1=="signature"{print $2}')
[ -n "$SIG" ] || { echo "FAIL: spendkey produced no signature" >&2; exit 1; }
echo "signed (hybrid ML-DSA-65 ‖ Falcon-1024, ${#SIG} hex chars)"

"$BIN" submit-tx --to "127.0.0.1:$BASE_PORT" "${TXFLAGS[@]}" --signature "$SIG" \
  || { echo "FAIL: signed submit failed" >&2; exit 1; }

say "waiting for the transfer to land"
DEADLINE=$(( $(date +%s) + 180 ))
LANDED=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  bal=$(rpc "$RPC_BASE" getbalance "[\"$RECIP_SH\"]" | jget 'd["result"]["balance_sat"]')
  printf '\r  recipient balance_sat=%-16s' "${bal:-?}"
  if [ "${bal:-0}" = "$PAY_SAT" ]; then LANDED=1; break; fi
  sleep 2
done
echo
[ -n "$LANDED" ] || { echo "FAIL: transfer did not land within 180s" >&2; exit 1; }

# Every node must agree — same balance out of each node's own committed state.
AGREE=1
for i in $(seq 0 $(( N - 1 ))); do
  b=$(rpc "$(( RPC_BASE + i ))" getbalance "[\"$RECIP_SH\"]" | jget 'd["result"]["balance_sat"]')
  f=$(rpc "$(( RPC_BASE + i ))" getbalance "[\"$FAUCET_SH\"]" | jget 'd["result"]["balance_sat"]')
  echo "node$i: recipient=$b faucet=$f"
  [ "$b" = "$PAY_SAT" ] && [ "$f" = "$CHANGE_SAT" ] || AGREE=0
done
[ "$AGREE" = 1 ] || { echo "FAIL: nodes disagree on post-spend balances" >&2; exit 1; }

# ── 6. Prove the spend is FINALIZED, not merely included ────────────────────
say "waiting for finality to pass the spend"
incl_epoch=$(rpc "$RPC_BASE" getchaininfo | jget 'd["result"]["finalized"]["epoch"]')
DEADLINE=$(( $(date +%s) + 240 ))
FINAL2=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  fin=$(rpc "$RPC_BASE" getchaininfo | jget 'd["result"]["finalized"]["epoch"]')
  printf '\r  finalized_epoch=%-4s (need > %s)' "${fin:-?}" "$(( incl_epoch + 1 ))"
  if [ -n "${fin:-}" ] && [ "$fin" -gt "$(( incl_epoch + 1 ))" ] 2>/dev/null; then FINAL2=1; break; fi
  sleep 2
done
echo
[ -n "$FINAL2" ] || { echo "FAIL: finality stopped advancing after the spend" >&2; exit 1; }
bal=$(rpc "$RPC_BASE" getbalance "[\"$RECIP_SH\"]" | jget 'd["result"]["balance_sat"]')
[ "$bal" = "$PAY_SAT" ] || { echo "FAIL: balance changed after finality ($bal)" >&2; exit 1; }

say "TESTNET UP — all proofs passed"
echo "  validators : $N (localhost, slot ${SLOT_MS}ms)"
echo "  finality   : advancing (epoch $fin)"
echo "  spend path : genesis faucet -> recipient, 500 test BLCH, finalized"
echo "  RPC        : http://127.0.0.1:$RPC_BASE .. $(( RPC_BASE + N - 1 ))"
echo "  faucet     : $WORKDIR/faucet (script_hash $FAUCET_SH)"
echo "  stop       : $0 $WORKDIR down"
trap - EXIT
echo
echo "NOTE: nodes are RUNNING. Restart hazard: if you stop them for long,"
echo "bring the whole set back together (or wipe and re-run) — a single node"
echo "restarted far behind the head does not reliably cold-sync."
