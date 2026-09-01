#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── HOSTED GENESIS-4 PUBLIC TESTNET — bring-up (run ON the testnet host) ────
#
# The hosted sibling of local-testnet-up.sh: same binary, same `run` command,
# same devnet transport, same genesis path, but
#
#   * slot is 30_000 ms — MAINNET CADENCE, non-negotiable for this network.
#     An integrator rehearsing a withdrawal loop needs real inclusion and
#     finality timing (epoch = 32 × 30 s = 16 min; finality ≈ 2 epochs), not
#     a fast devnet's.
#   * validators run under systemd (bloch-t4-n0..n{N-1} + bloch-t4.target),
#     not shell background jobs, so they survive reboots and are restarted
#     AS A SET (`systemctl restart bloch-t4.target`) — the one restart mode
#     the cold-sync caveat in genesis/README.md allows.
#   * the devnet mesh stays on LOOPBACK (net.rs binds 127.0.0.1 by default).
#     That transport is unauthenticated by design; on mainnet one stale
#     external peer dumping old blocks halted production for the whole
#     network (2026-08-09). The public sees JSON-RPC through the nginx +
#     cloudflared front ONLY. Never pass --listen-addr on a public interface.
#
# ── ISOLATION FROM MAINNET (binding, same as the local script) ──────────────
# `spend_signing_root` carries NO network id; replay isolation is outpoint
# disjointness at genesis, forever. Therefore:
#   * NO carryover, ever (this script has no flag for it);
#   * every key is generated fresh ON THIS HOST by this script — never load
#     a mainnet key, never reproduce a mainnet allocation tuple.
#
# USAGE (as the `ubuntu` user on the testnet host):
#   deploy/testnet/hosted-testnet-up.sh <t4dir> [n]
#   deploy/testnet/hosted-testnet-up.sh <t4dir> destroy   # stop + wipe state
#
#   BLOCH_POS_BIN (default /home/ubuntu/bloch-pos-t4)  the release binary
#   BASE_PORT (default 19500)  loopback devnet mesh ports, +i per node
#   RPC_BASE  (default 18500)  loopback JSON-RPC ports, +i per node
#
# Bring-up validation runs the same three proofs as the local script
# (production, finality, a real hybrid-signed spend, finalized). At 30 s
# slots that takes ≈ 1.5–2 h wall clock. It is a one-time cost per genesis;
# let it run to the end before announcing the endpoint.
set -uo pipefail

T4DIR="${1:?usage: hosted-testnet-up.sh <t4dir> [n] | <t4dir> destroy}"
SLOT_MS=30000   # fixed: this network exists to show mainnet cadence

if [ "${2:-}" = "destroy" ]; then
  sudo systemctl stop bloch-t4.target 2>/dev/null
  sudo systemctl disable 'bloch-t4-n*' bloch-t4.target 2>/dev/null
  sudo rm -f /etc/systemd/system/bloch-t4-n*.service /etc/systemd/system/bloch-t4.target
  sudo systemctl daemon-reload
  rm -rf "$T4DIR"
  echo "testnet destroyed (units removed, $T4DIR wiped)"
  exit 0
fi

N="${2:-4}"
BASE_PORT="${BASE_PORT:-19500}"
RPC_BASE="${RPC_BASE:-18500}"
BIN="${BLOCH_POS_BIN:-/home/ubuntu/bloch-pos-t4}"
[ -x "$BIN" ] || { echo "FATAL: no binary at $BIN (set BLOCH_POS_BIN)" >&2; exit 1; }

[ -e "$T4DIR/genesis.blg" ] && { echo "FATAL: $T4DIR already holds a genesis — 'destroy' first (a re-run would strand the systemd units on old state)" >&2; exit 1; }
mkdir -p "$T4DIR"

say() { printf '\n── %s ──────────────────────────────────────────────\n' "$*"; }
rpc() { curl -s --max-time 5 -X POST "http://127.0.0.1:$1" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" 2>/dev/null; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

# ── 1. Fresh throwaway keys: N validators + faucet ──────────────────────────
say "generating $N validator keys + faucet (throwaway, on this host)"
KEYDIRS=""
for i in $(seq 0 $(( N - 1 ))); do
  d="$T4DIR/node$i"; mkdir -p "$d"
  "$BIN" keygen --dir "$d" --index "$i" >/dev/null || { echo "keygen failed" >&2; exit 1; }
  KEYDIRS="${KEYDIRS}${KEYDIRS:+,}$d"
done
"$BIN" keygen --dir "$T4DIR/faucet" --index 0 >/dev/null || exit 1
chmod 700 "$T4DIR/faucet"
FAUCET_SH=$("$BIN" spendkey --dir "$T4DIR/faucet" | awk '$1=="script_hash"{print $2}')
[ -n "$FAUCET_SH" ] || { echo "spendkey failed" >&2; exit 1; }
echo "faucet script_hash $FAUCET_SH"

# ── 2. Genesis: 100,000,000 test BLCH to the faucet, slot 0 in 120 s ────────
# Big on purpose: MIN_DEPOSIT_SAT is 25,000 BLCH, and when funded bonding
# lands, deposit rehearsals draw from this same faucet.
FAUCET_ALLOC_SAT=10000000000000000
say "building testnet genesis (slot ${SLOT_MS}ms, mainnet cadence)"
"$BIN" genesis --keys "$KEYDIRS" --out "$T4DIR/genesis.blg" \
  --slot-ms "$SLOT_MS" --start-in 120 \
  --alloc "$FAUCET_SH:$FAUCET_ALLOC_SAT" || { echo "genesis failed" >&2; exit 1; }
sha256sum "$T4DIR/genesis.blg" | tee "$T4DIR/genesis.blg.sha256"

# ── 3. systemd: one unit per validator, grouped under one target ────────────
# PartOf= means `systemctl restart bloch-t4.target` restarts the WHOLE SET —
# the only restart discipline the transport tolerates. Individual crashed
# units still self-restart (Restart=always) and rejoin within seconds, which
# the local restart test proved works from data dirs.
say "installing systemd units bloch-t4-n0..n$(( N - 1 )) + bloch-t4.target"
sudo tee /etc/systemd/system/bloch-t4.target >/dev/null <<EOF
[Unit]
Description=Bloch Genesis-4 public testnet (t4) — all validators
[Install]
WantedBy=multi-user.target
EOF
for i in $(seq 0 $(( N - 1 ))); do
  peers=""
  for j in $(seq 0 $(( N - 1 ))); do
    [ "$j" = "$i" ] && continue
    peers="${peers}${peers:+,}127.0.0.1:$(( BASE_PORT + j ))"
  done
  sudo tee "/etc/systemd/system/bloch-t4-n$i.service" >/dev/null <<EOF
[Unit]
Description=Bloch G4 public testnet validator n$i (t4, NOT mainnet)
PartOf=bloch-t4.target
After=network.target

[Service]
User=ubuntu
ExecStart=$BIN run --data-dir $T4DIR/node$i --genesis $T4DIR/genesis.blg \\
  --transport devnet --listen $(( BASE_PORT + i )) --peers $peers \\
  --rpc-bind 127.0.0.1 --rpc-port $(( RPC_BASE + i ))
Restart=always
RestartSec=5

[Install]
WantedBy=bloch-t4.target
EOF
done
sudo systemctl daemon-reload
sudo systemctl enable bloch-t4.target $(for i in $(seq 0 $(( N - 1 ))); do printf 'bloch-t4-n%s.service ' "$i"; done) >/dev/null 2>&1
sudo systemctl start bloch-t4.target
echo "started; logs: journalctl -u bloch-t4-n0 -f"

# ── 4. Proofs, at mainnet cadence (be patient: ≈1.5–2 h total) ──────────────
say "waiting for finality (finalized epoch >= 1; ≈2–3 epochs = 30–50 min)"
DEADLINE=$(( $(date +%s) + 5400 )); FIN_OK=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  info=$(rpc "$RPC_BASE" getchaininfo)
  fin=$(printf '%s' "$info" | jget 'd["result"]["finalized"]["epoch"]')
  h=$(printf '%s' "$info"   | jget 'd["result"]["height"]')
  printf '\r  height=%-6s finalized_epoch=%-4s' "${h:-?}" "${fin:-?}"
  [ -n "${fin:-}" ] && [ "$fin" -ge 1 ] 2>/dev/null && { FIN_OK=1; break; }
  sleep 20
done
echo
[ -n "$FIN_OK" ] || { echo "FAIL: no finality within 90 min — journalctl -u bloch-t4-n0" >&2; exit 1; }
echo "finality advancing: epoch $fin at height $h"

say "proving the spend path (faucet -> scratch recipient, finalized)"
# Reuses the drip tool so bring-up proves the exact tool partners' coins
# will come from.
"$BIN" keygen --dir "$T4DIR/smoke-recipient" --index 0 >/dev/null
SMOKE_SH=$("$BIN" spendkey --dir "$T4DIR/smoke-recipient" | awk '$1=="script_hash"{print $2}')
BLOCH_POS_BIN="$BIN" RPC_PORT="$RPC_BASE" MESH_PORT="$BASE_PORT" \
  "$(cd "$(dirname "$0")" && pwd)/faucet-drip.sh" "$T4DIR" "$SMOKE_SH" 500 \
  || { echo "FAIL: bring-up drip failed" >&2; exit 1; }

incl=$(rpc "$RPC_BASE" getchaininfo | jget 'd["result"]["finalized"]["epoch"]')
say "waiting for finality to pass the spend (≈2 epochs = 32 min)"
DEADLINE=$(( $(date +%s) + 3600 )); FINAL2=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  fin=$(rpc "$RPC_BASE" getchaininfo | jget 'd["result"]["finalized"]["epoch"]')
  printf '\r  finalized_epoch=%-4s (need > %s)' "${fin:-?}" "$(( incl + 1 ))"
  [ -n "${fin:-}" ] && [ "$fin" -gt "$(( incl + 1 ))" ] 2>/dev/null && { FINAL2=1; break; }
  sleep 30
done
echo
[ -n "$FINAL2" ] || { echo "FAIL: finality stalled after the spend" >&2; exit 1; }

say "HOSTED TESTNET UP — all proofs passed at mainnet cadence"
echo "  validators : $N under systemd (bloch-t4.target)"
echo "  genesis    : $T4DIR/genesis.blg ($(cut -d' ' -f1 "$T4DIR/genesis.blg.sha256"))"
echo "  faucet     : $T4DIR/faucet  (script_hash $FAUCET_SH)"
echo "  local RPC  : http://127.0.0.1:$RPC_BASE .. $(( RPC_BASE + N - 1 ))"
echo "  next       : install nginx front + cloudflared (see HOSTED-TESTNET.md §4)"
echo "  restart    : sudo systemctl restart bloch-t4.target   (ALWAYS the whole set)"
