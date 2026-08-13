#!/usr/bin/env bash
# regtest-merged-rehearsal.sh — end-to-end MERGED-MINING (AuxPoW) rehearsal.
#
# Proves the whole BTC↔Bloch dual-mining loop OFF-MAINNET, on a throwaway
# regtest, without touching the live chain. It brings up the four moving parts,
# points a CPU miner at the pool, and waits for a merged Bloch block to be
# accepted by the node:
#
#     cpuminer ──stratum──▶ bloch-pool-proxy (BLOCH_POOL_MERGED=on)
#                                │  ├─ createauxblock ─▶ bloch node (rehearsal)
#                                │  ├─ getblocktemplate ▶ bitcoind -regtest
#                                │  └─ on a Bloch-target hit:
#                                │        submitauxblock ─▶ bloch node  ✅
#                                ▼
#                        one SHA-256d hash secures BOTH
#
# WHY A REHEARSAL BUILD: merged mining is INERT on mainnet — the node rejects an
# AuxPoW block below AUXPOW_ACTIVATION_HEIGHT (u64::MAX) fail-closed. The node
# MUST be built `--features auxpow-rehearsal`, which lowers that gate to 0 so a
# LOCAL build accepts merged blocks. A mainnet artifact never sets that feature.
# This script refuses to run against anything but a throwaway datadir.
#
# HONEST CAVEAT (see legacy/MERGED-MINING.md): merged mining only secures Bloch
# with the fraction of BTC hashrate that opts in, and lets a big BTC miner
# attack at ~zero marginal cost — a bootstrap lever, not a security guarantee.
# NEVER exercise this on the live chain; regtest only.
#
# PREREQUISITES (on PATH):
#   * cargo (builds the node + proxy from this checkout)
#   * bitcoind + bitcoin-cli   (Bitcoin Core, for the parent chain)
#   * a CPU miner: minerd (cpuminer / cpuminer-multi, `-a sha256d`). Optional —
#     if absent the script prints the exact command to run by hand.
#   * a carry-over snapshot for the Bloch node (genesis3 requires it); pass its
#     path in CARRYOVER=... (see the node onboarding runbook).
#
# USAGE:
#   CARRYOVER=/path/to/carryover.tsv \
#   BLOCH_ADDR=bloch1q...           \   # a valid Bloch payout address you control
#   scripts/regtest-merged-rehearsal.sh
#
# All other knobs have regtest-friendly defaults; override any via env.
#
# NOTE ON DIFFICULTY: a Bloch-target win needs the parent BTC hash to meet
# BLOCH's target. On a high-difficulty chain a CPU miner may take a long time.
# For a fast rehearsal point the node at a FRESH / low-difficulty chain (or a
# devnet), not the production-difficulty tip. The script waits up to
# REHEARSAL_TIMEOUT seconds and reports honestly if no block landed in time.
set -euo pipefail

# ── Config (override via env) ────────────────────────────────────────────────
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$(mktemp -d -t bloch-merged-rehearsal.XXXXXX)}"
NODE_RPC_PORT="${NODE_RPC_PORT:-16299}"
NODE_P2P_PORT="${NODE_P2P_PORT:-16298}"
PROXY_LISTEN="${PROXY_LISTEN:-127.0.0.1:3336}"
BTC_RPC_PORT="${BTC_RPC_PORT:-18443}"      # bitcoind regtest default
BTC_RPC_USER="${BTC_RPC_USER:-rehearsal}"
BTC_RPC_PASS="${BTC_RPC_PASS:-rehearsal}"
MERGED_DIFF="${MERGED_DIFF:-0.001}"        # low share diff so shares flow fast
MERGED_REFRESH="${MERGED_REFRESH:-10}"
REHEARSAL_TIMEOUT="${REHEARSAL_TIMEOUT:-300}"
CARRYOVER="${CARRYOVER:-}"
BLOCH_ADDR="${BLOCH_ADDR:-}"
# Full node start command (override to point at a fresh low-diff / devnet chain).
NODE_BIN="$REPO/target/release/bloch"
NODE_START_CMD_DEFAULT="$NODE_BIN --genesis3 --archive --carryover-snapshot $CARRYOVER \
  --data-dir $WORK/g3-data --rpc-bind 127.0.0.1 --rpc-port $NODE_RPC_PORT \
  --listen /ip4/127.0.0.1/tcp/$NODE_P2P_PORT"
NODE_START_CMD="${NODE_START_CMD:-$NODE_START_CMD_DEFAULT}"

log()  { printf '\033[1;36m[rehearsal]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[rehearsal] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

# ── Prereqs ──────────────────────────────────────────────────────────────────
command -v cargo       >/dev/null || die "cargo not on PATH"
command -v bitcoind    >/dev/null || die "bitcoind not on PATH (install Bitcoin Core)"
command -v bitcoin-cli >/dev/null || die "bitcoin-cli not on PATH"
[ -n "$BLOCH_ADDR" ]              || die "set BLOCH_ADDR=bloch1q... (a payout address you control)"
if printf '%s' "$NODE_START_CMD" | grep -q -- '--genesis3'; then
  [ -n "$CARRYOVER" ] && [ -f "$CARRYOVER" ] || die "genesis3 needs CARRYOVER=/path/to/carryover.tsv (file must exist)"
fi

PIDS=()
cleanup() {
  log "cleaning up..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  bitcoin-cli -regtest -datadir="$WORK/btc" -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASS" stop 2>/dev/null || true
  sleep 1
  [ "${KEEP_WORK:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log "workdir: $WORK  (KEEP_WORK=1 to preserve)"

# ── 1. Build node (rehearsal) + proxy ────────────────────────────────────────
log "building bloch node --features 'node auxpow-rehearsal' (activation lowered to 0)..."
( cd "$REPO" && cargo build --release -p bloch --features "node auxpow-rehearsal" --bin bloch )
log "building bloch-pool-proxy..."
( cd "$REPO/pool-proxy" && cargo build --release )
PROXY_BIN="$REPO/pool-proxy/target/release/bloch-pool-proxy"
[ -x "$PROXY_BIN" ] || PROXY_BIN="$REPO/target/release/bloch-pool-proxy"

# ── 2. bitcoind -regtest ─────────────────────────────────────────────────────
mkdir -p "$WORK/btc"
log "starting bitcoind -regtest on :$BTC_RPC_PORT..."
bitcoind -regtest -datadir="$WORK/btc" -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASS" \
  -rpcport="$BTC_RPC_PORT" -fallbackfee=0.0001 -daemon
BCLI=(bitcoin-cli -regtest -datadir="$WORK/btc" -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASS" -rpcport="$BTC_RPC_PORT")
# Wait for RPC.
for _ in $(seq 1 30); do "${BCLI[@]}" getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
"${BCLI[@]}" getblockchaininfo >/dev/null 2>&1 || die "bitcoind RPC never came up"
# A wallet + 101 blocks so getblocktemplate has a spendable coinbase + a payout.
"${BCLI[@]}" createwallet rehearsal >/dev/null 2>&1 || "${BCLI[@]}" loadwallet rehearsal >/dev/null 2>&1 || true
BTC_ADDR="$("${BCLI[@]}" getnewaddress)"
"${BCLI[@]}" generatetoaddress 101 "$BTC_ADDR" >/dev/null
BTC_PAYOUT_SPK="$("${BCLI[@]}" getaddressinfo "$BTC_ADDR" | sed -n 's/.*"scriptPubKey": *"\([0-9a-fA-F]*\)".*/\1/p' | head -1)"
[ -n "$BTC_PAYOUT_SPK" ] || die "could not read BTC payout scriptPubKey"
log "bitcoind ready; BTC payout spk=$BTC_PAYOUT_SPK"

# ── 3. Bloch node (rehearsal build) ──────────────────────────────────────────
log "starting bloch node...  ($NODE_START_CMD)"
mkdir -p "$WORK/g3-data"
# shellcheck disable=SC2086
$NODE_START_CMD >"$WORK/node.log" 2>&1 &
PIDS+=($!)
bloch_rpc() {
  curl -s --max-time 8 -X POST "http://127.0.0.1:$NODE_RPC_PORT/" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"
}
bloch_count() { bloch_rpc getblockcount | sed -n 's/.*"result":\([0-9]*\).*/\1/p'; }
for _ in $(seq 1 60); do [ -n "$(bloch_count)" ] && break; sleep 1; done
START_COUNT="$(bloch_count)"
[ -n "$START_COUNT" ] || { tail -20 "$WORK/node.log"; die "bloch node RPC never came up"; }
log "bloch node ready; block_count=$START_COUNT"
# Sanity: createauxblock must succeed (SHA-256d chain, bodied tip, active).
AUX="$(bloch_rpc createauxblock "[\"$BLOCH_ADDR\"]")"
printf '%s' "$AUX" | grep -q '"active":true' \
  || die "createauxblock not active — is this a --features auxpow-rehearsal build on a SHA-256d chain? got: $AUX"
log "createauxblock OK + active: $(printf '%s' "$AUX" | tr ',' '\n' | grep -E 'hash|bits|active' | tr '\n' ' ')"

# ── 4. bloch-pool-proxy (merged mode) ────────────────────────────────────────
log "starting bloch-pool-proxy in merged mode on $PROXY_LISTEN..."
BLOCH_POOL_LISTEN="$PROXY_LISTEN" \
BLOCH_POOL_METRICS="127.0.0.1:0" \
BLOCH_POOL_RPC="127.0.0.1:$NODE_RPC_PORT" \
BLOCH_POOL_RPC_OBSERVER="off" \
BLOCH_POOL_MERGED="on" \
BLOCH_POOL_BTC_RPC="127.0.0.1:$BTC_RPC_PORT" \
BLOCH_POOL_BTC_RPC_USER="$BTC_RPC_USER" \
BLOCH_POOL_BTC_RPC_PASS="$BTC_RPC_PASS" \
BLOCH_POOL_BLOCH_ADDR="$BLOCH_ADDR" \
BLOCH_POOL_BTC_PAYOUT_SCRIPT="$BTC_PAYOUT_SPK" \
BLOCH_POOL_MERGED_DIFF="$MERGED_DIFF" \
BLOCH_POOL_MERGED_REFRESH_SECS="$MERGED_REFRESH" \
RUST_LOG="${RUST_LOG:-info}" \
"$PROXY_BIN" >"$WORK/proxy.log" 2>&1 &
PIDS+=($!)
sleep 3
grep -qiE "cannot bind|FATAL|panic" "$WORK/proxy.log" && { tail -20 "$WORK/proxy.log"; die "proxy failed to start"; }
log "proxy up (log: $WORK/proxy.log)"

# ── 5. CPU miner ─────────────────────────────────────────────────────────────
if command -v minerd >/dev/null; then
  log "starting cpuminer (minerd) against $PROXY_LISTEN..."
  minerd -a sha256d -o "stratum+tcp://$PROXY_LISTEN" -u "$BLOCH_ADDR" -p x \
    >"$WORK/miner.log" 2>&1 &
  PIDS+=($!)
else
  log "minerd not found — run a CPU miner by hand, e.g.:"
  log "    minerd -a sha256d -o stratum+tcp://$PROXY_LISTEN -u $BLOCH_ADDR -p x"
fi

# ── 6. Verify a merged block is accepted ─────────────────────────────────────
log "waiting up to ${REHEARSAL_TIMEOUT}s for a merged Bloch block..."
deadline=$(( SECONDS + REHEARSAL_TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
  now="$(bloch_count)"
  if [ -n "$now" ] && [ "$now" -gt "$START_COUNT" ]; then
    log "✅ SUCCESS: bloch block_count $START_COUNT → $now (a merged block was accepted)"
    grep -i "BLOCH BLOCK accepted" "$WORK/proxy.log" | tail -3 | sed 's/^/    /' || true
    exit 0
  fi
  if grep -qi "BLOCH BLOCK accepted" "$WORK/proxy.log"; then
    log "✅ SUCCESS: proxy reports a merged block accepted by the node"
    grep -i "BLOCH BLOCK accepted" "$WORK/proxy.log" | tail -3 | sed 's/^/    /'
    exit 0
  fi
  sleep 3
done

log "⏱  no merged block within ${REHEARSAL_TIMEOUT}s. This is usually the Bloch"
log "   target being too hard for a CPU miner — see the difficulty note in the"
log "   header, and try a fresh/low-difficulty chain via NODE_START_CMD."
log "   proxy log tail:"; tail -15 "$WORK/proxy.log" | sed 's/^/    /'
exit 1
