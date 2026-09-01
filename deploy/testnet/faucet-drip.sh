#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── MANUAL FAUCET DRIP (run ON the testnet host) ────────────────────────────
#
# Pays test BLCH from the testnet faucet keystore to a partner's script hash,
# using the exact spend path the local testnet proved end to end:
# getutxos -> submit-tx (signing root) -> spendkey --sign -> submit-tx.
#
# This IS the faucet for the first partners — a deliberate decision, see
# HOSTED-TESTNET.md §5: the tools/faucet scaffold is Genesis-3 vintage
# (bloch1t… bech32 addresses, a G3 RPC surface, a G3 tx format), unaudited
# and never run against a live network; adapting it is a rewrite. This
# script is ~100 lines over a proven path, and a manual drip is enough while
# partners number in the single digits.
#
#   deploy/testnet/faucet-drip.sh <t4dir> <recipient-script-hash-hex> [amount_blch]
#
#   RPC_PORT  (default 18500)   any local node's JSON-RPC
#   MESH_PORT (default 19500)   any local node's devnet transport port
#   BLOCH_POS_BIN (default /home/ubuntu/bloch-pos-t4)
set -uo pipefail

T4DIR="${1:?usage: faucet-drip.sh <t4dir> <recipient-script-hash-hex> [amount_blch]}"
RECIP_SH="${2:?usage: faucet-drip.sh <t4dir> <recipient-script-hash-hex> [amount_blch]}"
AMOUNT_BLCH="${3:-1000}"
RPC_PORT="${RPC_PORT:-18500}"
MESH_PORT="${MESH_PORT:-19500}"
BIN="${BLOCH_POS_BIN:-/home/ubuntu/bloch-pos-t4}"
[ -x "$BIN" ] || { echo "FATAL: no binary at $BIN" >&2; exit 1; }
[ -d "$T4DIR/faucet" ] || { echo "FATAL: no faucet keystore at $T4DIR/faucet" >&2; exit 1; }
case "$RECIP_SH" in
  *[!0-9a-fA-F]*|"") echo "FATAL: recipient script hash must be hex" >&2; exit 1;;
esac
[ "${#RECIP_SH}" = 64 ] || { echo "FATAL: recipient script hash must be 64 hex chars (32 bytes)" >&2; exit 1; }

PAY_SAT=$(( AMOUNT_BLCH * 100000000 ))

rpc() { curl -s --max-time 5 -X POST "http://127.0.0.1:$RPC_PORT" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" 2>/dev/null; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

FAUCET_SH=$("$BIN" spendkey --dir "$T4DIR/faucet" | awk '$1=="script_hash"{print $2}')
FAUCET_PK=$("$BIN" spendkey --dir "$T4DIR/faucet" | awk '$1=="pubkey"{print $2}')
if [ "$RECIP_SH" = "$FAUCET_SH" ]; then
  echo "FATAL: recipient is the faucet itself" >&2; exit 1
fi

# Refuse to double-spend a drip already in flight: the faucet keeps exactly
# one UTXO (each drip returns all change to it), so a second UTXO means the
# previous drip has not committed yet. Wait for it.
utxos=$(rpc getutxos "[\"$FAUCET_SH\"]")
COUNT=$(printf '%s' "$utxos" | jget 'len(d["result"]["utxos"])')
FTXID=$(printf '%s' "$utxos" | jget 'd["result"]["utxos"][0]["txid"]')
FVOUT=$(printf '%s' "$utxos" | jget 'd["result"]["utxos"][0]["vout"]')
FVAL=$(printf '%s'  "$utxos" | jget 'd["result"]["utxos"][0]["value_sat"]')
[ -n "$FTXID" ] || { echo "FATAL: faucet has no committed UTXO" >&2; exit 1; }
[ "$COUNT" = 1 ] || { echo "FATAL: faucet has $COUNT UTXOs — a previous drip may be mid-flight; retry after it commits" >&2; exit 1; }

# Fee, exactly, at the base-fee floor. The local-testnet proof established
# the arithmetic: gas = TX_FLAT_GAS(5000) + tx_bytes*GAS_PER_BYTE(16)
# + HYBRID_VERIFY_GAS(72748) for one input; fee_sat = ceil(gas*price/1000),
# tip 0. On an idle testnet the base fee sits at its floor of 10 msat/gas;
# if it does not, DO NOT guess — wait for it to decay back.
basefee=$(rpc getchaininfo | jget 'd["result"]["next_base_fee_millisat_per_gas"]')
[ "$basefee" = "10" ] || { echo "FATAL: base fee is ${basefee:-?} msat/gas, not the floor 10 — wait for it to decay, then retry" >&2; exit 1; }
TX_BYTES=9000
GAS=$(( 5000 + TX_BYTES * 16 + 72748 ))
FEE_SAT=$(( (GAS * 10 + 999) / 1000 ))
CHANGE_SAT=$(( FVAL - PAY_SAT - FEE_SAT ))
[ "$CHANGE_SAT" -gt 0 ] || { echo "FATAL: faucet UTXO ($FVAL sat) cannot cover $PAY_SAT + fee $FEE_SAT" >&2; exit 1; }
echo "drip: $AMOUNT_BLCH tBLCH -> $RECIP_SH  (fee $FEE_SAT sat, change $CHANGE_SAT sat)"

TXFLAGS=(--pubkey "$FAUCET_PK"
         --spend "$FTXID:$FVOUT"
         --pay "$RECIP_SH:$PAY_SAT"
         --pay "$FAUCET_SH:$CHANGE_SAT"
         --tx-bytes "$TX_BYTES" --tip 0)

BAL0=$(rpc getbalance "[\"$RECIP_SH\"]" | jget 'd["result"]["balance_sat"]'); BAL0=${BAL0:-0}

ROOT=$("$BIN" submit-tx --raw "${TXFLAGS[@]}" 2>/dev/null)
[ -n "$ROOT" ] || { echo "FATAL: submit-tx printed no signing root" >&2; exit 1; }
SIG=$("$BIN" spendkey --dir "$T4DIR/faucet" --sign "$ROOT" | awk '$1=="signature"{print $2}')
[ -n "$SIG" ] || { echo "FATAL: spendkey produced no signature" >&2; exit 1; }
"$BIN" submit-tx --to "127.0.0.1:$MESH_PORT" "${TXFLAGS[@]}" --signature "$SIG" \
  || { echo "FATAL: signed submit failed" >&2; exit 1; }

echo "waiting for inclusion (30 s slots — typically 1–4 slots)"
DEADLINE=$(( $(date +%s) + 600 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  bal=$(rpc getbalance "[\"$RECIP_SH\"]" | jget 'd["result"]["balance_sat"]')
  printf '\r  recipient balance_sat=%-16s' "${bal:-?}"
  if [ -n "${bal:-}" ] && [ "$bal" -ge $(( BAL0 + PAY_SAT )) ] 2>/dev/null; then
    echo; echo "DRIP LANDED: +$AMOUNT_BLCH tBLCH (balance $bal sat). Finality follows ≈2 epochs (~32 min)."
    exit 0
  fi
  sleep 10
done
echo; echo "FATAL: drip did not land within 10 min — check journalctl -u bloch-t4-n0" >&2
exit 1
