#!/usr/bin/env bash
# Bloch Protocol — local test script
#
# Default: the LIVE chain. Genesis-4, proof of stake — the consensus crate and
# the node the fleet runs.
#
#     ./test.sh                # Genesis-4 (default)
#     ./test.sh --genesis3     # the retired proof-of-work node, additionally
#     ./test.sh --all          # both
#
# This script used to build the Genesis-3 proof-of-work node, start it, and
# mine three blocks — and it was the repository's front-door "does it work?"
# command. Genesis-3 stopped at height 39,918 on 2026-08-13. Mining blocks on
# it still works locally and proves nothing about the network, so it is no
# longer what this script does unless you ask for it.
set -euo pipefail

AMBER='\033[38;5;214m'
GREEN='\033[38;5;71m'
RED='\033[38;5;167m'
MUTED='\033[38;5;245m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
fail() { echo -e "  ${RED}✗${RESET} $1"; exit 1; }
note() { echo -e "  ${MUTED}$1${RESET}"; }
step() { echo -e "\n  ${AMBER}▸${RESET} ${BOLD}$1${RESET}"; }

RUN_G4=1
RUN_G3=0
case "${1:-}" in
    --genesis3) RUN_G3=1 ;;
    --all)      RUN_G3=1 ;;
    --g4|"")    ;;
    -h|--help)  awk 'NR>1 { if (/^#/) { sub(/^# ?/, ""); print } else { exit } }' "$0"; exit 0 ;;
    *)          fail "unknown argument: $1  (try --help)" ;;
esac

echo
echo -e "  ${BOLD}◆ Bloch Protocol — Test Suite ◆${RESET}"
echo -e "  ${MUTED}Genesis-4 · proof of stake · ML-DSA-65 ‖ Falcon-1024 · SHA-3/SHAKE-256${RESET}"
echo

# ── Prerequisites ───────────────────────────────────────────────────
step "Checking prerequisites"
command -v cargo >/dev/null 2>&1 || fail "cargo not found — install Rust from https://rustup.rs"
RUST_VER=$(rustc --version | awk '{print $2}')
ok "Rust $RUST_VER"

if [ "$RUN_G4" = 1 ]; then
    # ── Genesis-4: the live chain ───────────────────────────────────
    step "Genesis-4 — building the live node (release)"
    cargo build --release -p bloch-pos-node || fail "build failed — check errors above"
    ok "bloch-pos built"

    POS_BIN="./target/release/bloch-pos"
    [ -x "$POS_BIN" ] || fail "expected $POS_BIN — the release build did not produce it"
    ok "$POS_BIN exists"

    step "Genesis-4 — version stamp"
    # build.rs stamps the source commit into the binary; the fleet is verified
    # against it (deploy/RELEASE-INTEGRITY.md). If this does not run, the
    # binary is not one you can identify later.
    VERSION_OUT="$("$POS_BIN" --version 2>&1)" || fail "bloch-pos --version failed"
    note "$VERSION_OUT"
    ok "version stamp present"

    step "Genesis-4 — consensus core (bloch-pos-committee)"
    cargo test -p bloch-pos-committee || fail "consensus tests failed — do not ship this"
    ok "consensus tests passed"

    step "Genesis-4 — node (bloch-pos-node)"
    cargo test -p bloch-pos-node || fail "node tests failed"
    ok "node tests passed"
fi

if [ "$RUN_G3" = 1 ]; then
    # ── Genesis-3: the retired chain ────────────────────────────────
    echo
    echo -e "  ${MUTED}────────────────────────────────────────────────${RESET}"
    note "Genesis-3 (proof of work) stopped at height 39,918 on 2026-08-13."
    note "What follows mines a private local chain. It joins nothing."
    echo -e "  ${MUTED}────────────────────────────────────────────────${RESET}"

    step "Genesis-3 — building the retired node (release)"
    cargo build --release -p bloch || fail "build failed — check errors above"
    ok "bloch built"

    NODE_BIN="./target/release/bloch"
    WALLET_BIN="./target/release/bloch-wallet"
    [ -f "$NODE_BIN" ]   || fail "bloch node binary not found"
    [ -f "$WALLET_BIN" ] || fail "bloch-wallet binary not found"
    ok "bloch + bloch-wallet binaries exist"

    step "Genesis-3 — node smoke test (genesis creation + DAG persistence)"
    TEST_DIR=$(mktemp -d)
    trap 'rm -rf "$TEST_DIR"' EXIT

    note "data dir: $TEST_DIR"
    timeout 8 "$NODE_BIN" --data-dir "$TEST_DIR" --rpc-bind 127.0.0.1 --rpc-port 16299 2>&1 &
    NODE_PID=$!
    sleep 4

    RPC_RESP=$(curl -s http://127.0.0.1:16299 -X POST \
        -H "Content-Type: application/json" \
        -d '{"method":"getnetworkinfo","id":1}' 2>/dev/null || echo '{}')

    if echo "$RPC_RESP" | grep -q '"chain":"bloch-sis"'; then
        ok "RPC responding — chain=bloch-sis"
    else
        note "RPC response: $RPC_RESP"
        note "(RPC may not be ready yet — this is OK for genesis mining)"
    fi

    if [ -d "$TEST_DIR/db" ]; then
        ok "RocksDB created at $TEST_DIR/db"
    else
        fail "No database directory"
    fi

    kill $NODE_PID 2>/dev/null || true
    wait $NODE_PID 2>/dev/null || true
    sleep 1

    step "Genesis-3 — DAG persistence test (restart → verify reload)"
    timeout 5 "$NODE_BIN" --data-dir "$TEST_DIR" --rpc-bind 127.0.0.1 --rpc-port 16299 2>&1 | tee /tmp/bloch-restart.log &
    NODE_PID2=$!
    sleep 3

    if grep -q "DAG loaded from disk" /tmp/bloch-restart.log; then
        ok "DAG loaded from disk on restart"
    elif grep -q "Genesis loaded" /tmp/bloch-restart.log; then
        ok "Genesis loaded (fallback — first run had no DAG data yet)"
    else
        note "(checking log...)"
        grep -i "genesis\|dag\|loaded" /tmp/bloch-restart.log || true
    fi

    kill $NODE_PID2 2>/dev/null || true
    wait $NODE_PID2 2>/dev/null || true

    step "Genesis-3 — mining test (mine 3 blocks on a private local chain)"
    TEST_DIR2=$(mktemp -d)

    timeout 30 "$NODE_BIN" \
        --data-dir "$TEST_DIR2" \
        --rpc-bind 127.0.0.1 \
        --rpc-port 16298 \
        --mine 2>&1 | tee /tmp/bloch-mine.log &
    MINE_PID=$!

    for _ in $(seq 1 20); do
        BLOCKS=$(grep -c "Block found" /tmp/bloch-mine.log 2>/dev/null || echo 0)
        if [ "$BLOCKS" -ge 3 ]; then
            break
        fi
        sleep 1
    done

    BLOCKS=$(grep -c "Block found" /tmp/bloch-mine.log 2>/dev/null || echo 0)
    if [ "$BLOCKS" -ge 1 ]; then
        ok "Mined $BLOCKS blocks (locally — this chain has no network)"
    else
        note "Mining may take longer with default difficulty — check /tmp/bloch-mine.log"
    fi

    BLOCK_COUNT=$(curl -s http://127.0.0.1:16298 -X POST \
        -H "Content-Type: application/json" \
        -d '{"method":"getblockcount","id":1}' 2>/dev/null | grep -o '"result":[0-9]*' | cut -d: -f2 || echo "?")
    if [ "$BLOCK_COUNT" != "?" ] && [ "$BLOCK_COUNT" -gt 1 ]; then
        ok "RPC reports $BLOCK_COUNT blocks in DAG"
    fi

    kill $MINE_PID 2>/dev/null || true
    wait $MINE_PID 2>/dev/null || true
    rm -rf "$TEST_DIR2"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}${BOLD}All tests completed${RESET}"
echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo
