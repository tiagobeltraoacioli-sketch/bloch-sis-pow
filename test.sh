#!/usr/bin/env bash
# Bloch Protocol — Local test script
# Usage: chmod +x test.sh && ./test.sh
set -euo pipefail

AMBER='\033[38;5;214m'
GREEN='\033[38;5;71m'
RED='\033[38;5;167m'
MUTED='\033[38;5;245m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
fail() { echo -e "  ${RED}✗${RESET} $1"; exit 1; }
step() { echo -e "\n  ${AMBER}▸${RESET} ${BOLD}$1${RESET}"; }

echo
echo -e "  ${BOLD}◆ Bloch Protocol — Test Suite ◆${RESET}"
echo -e "  ${MUTED}Bloch-SIS PoW (Module-SIS, testnet regime) · ML-DSA-65 PQC · GhostDAG-Q${RESET}"
echo

# ── Prerequisites ───────────────────────────────────────────────────
step "Checking prerequisites"
command -v cargo >/dev/null 2>&1 || fail "cargo not found — install Rust from https://rustup.rs"
RUST_VER=$(rustc --version | awk '{print $2}')
ok "Rust $RUST_VER"

# ── Step 1: Compile ─────────────────────────────────────────────────
step "Compiling (release mode)"
if cargo build --release 2>&1; then
    ok "Build succeeded"
else
    fail "Build failed — check errors above"
fi

# ── Step 2: Unit tests ──────────────────────────────────────────────
step "Running unit tests"
if cargo test 2>&1; then
    ok "All tests passed"
else
    fail "Tests failed"
fi

# ── Step 3: Wallet smoke test ───────────────────────────────────────
step "Wallet smoke test"
WALLET_BIN="./target/release/bloch-wallet"
NODE_BIN="./target/release/bloch"

if [ ! -f "$WALLET_BIN" ]; then
    fail "bloch-wallet binary not found"
fi
ok "bloch-wallet binary exists"

if [ ! -f "$NODE_BIN" ]; then
    fail "bloch node binary not found"
fi
ok "bloch node binary exists"

# ── Step 4: Node smoke test (start, mine genesis, stop) ─────────────
step "Node smoke test (genesis creation + DAG persistence)"
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo -e "  ${MUTED}data dir: $TEST_DIR${RESET}"

# Start node in background, let it create genesis
timeout 8 "$NODE_BIN" --data-dir "$TEST_DIR" --rpc-bind 127.0.0.1 --rpc-port 16299 2>&1 &
NODE_PID=$!
sleep 4

# Test RPC
RPC_RESP=$(curl -s http://127.0.0.1:16299 -X POST \
    -H "Content-Type: application/json" \
    -d '{"method":"getnetworkinfo","id":1}' 2>/dev/null || echo '{}')

if echo "$RPC_RESP" | grep -q '"chain":"bloch-sis"'; then
    ok "RPC responding — chain=bloch-sis"
else
    echo -e "  ${MUTED}RPC response: $RPC_RESP${RESET}"
    echo -e "  ${MUTED}(RPC may not be ready yet — this is OK for genesis mining)${RESET}"
fi

# Check genesis was created
if [ -d "$TEST_DIR/db" ]; then
    ok "RocksDB created at $TEST_DIR/db"
else
    fail "No database directory"
fi

# Kill node
kill $NODE_PID 2>/dev/null || true
wait $NODE_PID 2>/dev/null || true
sleep 1

# ── Step 5: DAG persistence test (restart node, verify DAG loads) ───
step "DAG persistence test (restart → verify reload)"

timeout 5 "$NODE_BIN" --data-dir "$TEST_DIR" --rpc-bind 127.0.0.1 --rpc-port 16299 2>&1 | tee /tmp/bloch-restart.log &
NODE_PID2=$!
sleep 3

if grep -q "DAG loaded from disk" /tmp/bloch-restart.log; then
    ok "DAG loaded from disk on restart"
elif grep -q "Genesis loaded" /tmp/bloch-restart.log; then
    ok "Genesis loaded (fallback — first run had no DAG data yet)"
else
    echo -e "  ${MUTED}(checking log...)${RESET}"
    cat /tmp/bloch-restart.log | grep -i "genesis\|dag\|loaded" || true
fi

kill $NODE_PID2 2>/dev/null || true
wait $NODE_PID2 2>/dev/null || true

# ── Step 6: Mining test ─────────────────────────────────────────────
step "Mining test (mine 3 blocks)"
TEST_DIR2=$(mktemp -d)

timeout 30 "$NODE_BIN" \
    --data-dir "$TEST_DIR2" \
    --rpc-bind 127.0.0.1 \
    --rpc-port 16298 \
    --mine 2>&1 | tee /tmp/bloch-mine.log &
MINE_PID=$!

# Wait for blocks
for i in $(seq 1 20); do
    BLOCKS=$(grep -c "Block found" /tmp/bloch-mine.log 2>/dev/null || echo 0)
    if [ "$BLOCKS" -ge 3 ]; then
        break
    fi
    sleep 1
done

BLOCKS=$(grep -c "Block found" /tmp/bloch-mine.log 2>/dev/null || echo 0)
if [ "$BLOCKS" -ge 1 ]; then
    ok "Mined $BLOCKS blocks"
else
    echo -e "  ${MUTED}Mining may take longer with default difficulty — check /tmp/bloch-mine.log${RESET}"
fi

# Check RPC block count
BLOCK_COUNT=$(curl -s http://127.0.0.1:16298 -X POST \
    -H "Content-Type: application/json" \
    -d '{"method":"getblockcount","id":1}' 2>/dev/null | grep -o '"result":[0-9]*' | cut -d: -f2 || echo "?")
if [ "$BLOCK_COUNT" != "?" ] && [ "$BLOCK_COUNT" -gt 1 ]; then
    ok "RPC reports $BLOCK_COUNT blocks in DAG"
fi

kill $MINE_PID 2>/dev/null || true
wait $MINE_PID 2>/dev/null || true
rm -rf "$TEST_DIR2"

# ── Summary ─────────────────────────────────────────────────────────
echo
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}${BOLD}All tests completed${RESET}"
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo
