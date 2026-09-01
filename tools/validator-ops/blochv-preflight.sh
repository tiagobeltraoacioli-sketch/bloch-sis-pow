#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-preflight.sh — "will this machine keep up as a Bloch Genesis-4
# validator" — run BEFORE the deposit, because the deposit is slow to undo
# (EXIT_DELAY_EPOCHS = 32 ≈ 8.5 h to stop duties, WITHDRAWAL_DELAY_EPOCHS =
# 2048 ≈ 22.8 days to get the stake back).
#
# What "keeping up" means on this chain, in numbers:
#   - one slot every 30 s; your duties (attest every epoch, propose when
#     drawn) must land inside the slot;
#   - cold-start replay costs ~81 ms per applied block on reference hardware
#     (post the 2026-08-31 per-epoch-clone fix) and replay is SINGLE-THREADED
#     — one core is pinned for its whole duration;
#   - the fleet reference: 8 GB RAM, 2 cores, 20 GB disk per node. Nodes
#     have OOM-died sharing RAM (the 2026-08 "5-6 validators per box, one
#     alive" incident) — do not undersize RAM, and run ONE validator per
#     failure domain anyway (two validators on one box that both die still
#     leak; one key on two boxes gets slashed).
#
# Checks (each prints PASS / WARN / FAIL; exit 0 = all pass, 1 = warns only,
# 2 = at least one fail):
#   1. binary present, --version stamp is a clean release triple, selfcheck
#   2. cores >= 2, RAM >= 8 GB, free disk on --data-dir fs >= 20 GB
#   3. single-core hash throughput proxy for the 81 ms/block replay budget
#   4. clock discipline (NTP sync active; the node ALSO gates on peer-time
#      at boot and will refuse to start on gross skew — this check is so you
#      find out now, not then)
#   5. open-files limit
#   6. RPC/P2P port hygiene: ports free; loud warning if you plan a routable
#      RPC bind (the RPC has NO authentication — see the runbook §6.4)
#
# Usage:
#   blochv-preflight.sh [--bloch-pos PATH] [--data-dir DIR]
#                       [--rpc-port N] [--p2p-port N] [--skip-bench]

set -u

BLOCH_POS="${BLOCH_POS:-bloch-pos}"
DATA_DIR="${HOME}/bloch-validator/data"
RPC_PORT=16400
P2P_PORT=19100
SKIP_BENCH=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bloch-pos) BLOCH_POS="$2"; shift 2 ;;
    --data-dir)  DATA_DIR="$2"; shift 2 ;;
    --rpc-port)  RPC_PORT="$2"; shift 2 ;;
    --p2p-port)  P2P_PORT="$2"; shift 2 ;;
    --skip-bench) SKIP_BENCH=1; shift ;;
    -h|--help) sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-preflight: unknown argument $1" >&2; exit 2 ;;
  esac
done

FAILS=0; WARNS=0
pass() { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; WARNS=$((WARNS+1)); }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS+1)); }

OS="$(uname -s)"

# ── 1. Binary ───────────────────────────────────────────────────────────────
if command -v "$BLOCH_POS" >/dev/null 2>&1; then
  VER="$("$BLOCH_POS" --version 2>/dev/null | head -1)"
  case "$VER" in
    *+dirty*)         fail "binary is a +dirty build: '$VER' — a validator runs a release triple, never an unidentifiable binary (deploy/RELEASE-INTEGRITY.md §1)" ;;
    *unknown+nogit*)  fail "binary has no commit stamp: '$VER' — release gates treat this as a hard failure" ;;
    "")               fail "binary found but --version printed nothing" ;;
    *)                pass "binary: $VER" ;;
  esac
  if "$BLOCH_POS" selfcheck >/dev/null 2>&1; then
    pass "selfcheck: frozen consensus parameters verified"
  else
    fail "selfcheck failed — this binary does not link the consensus parameters it claims"
  fi
else
  fail "bloch-pos binary not found ('$BLOCH_POS') — build per runbook §3, then re-run"
fi

# ── 2. Cores / RAM / disk ───────────────────────────────────────────────────
if [ "$OS" = "Darwin" ]; then
  CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo 0)"
  RAM_GB="$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 ))"
else
  CORES="$(nproc 2>/dev/null || echo 0)"
  RAM_KB="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  RAM_GB="$(( RAM_KB / 1048576 ))"
fi
[ "$CORES" -ge 2 ] && pass "cores: $CORES (>=2; replay pins one whole core)" \
  || fail "cores: $CORES — replay is single-threaded and pins a core; with <2 cores duties starve during any replay"
if [ "$RAM_GB" -ge 8 ]; then pass "RAM: ${RAM_GB} GB (>=8)"
elif [ "$RAM_GB" -ge 6 ]; then warn "RAM: ${RAM_GB} GB — reference is 8 GB; the fleet's OOM deaths were RAM-sharing, do not run anything else heavy here"
else fail "RAM: ${RAM_GB} GB — below 8 GB the node is the next OOM casualty"; fi

mkdir -p "$DATA_DIR" 2>/dev/null
if [ -d "$DATA_DIR" ]; then
  FREE_GB="$(df -Pk "$DATA_DIR" | awk 'NR==2{print int($4/1048576)}')"
  if [ "${FREE_GB:-0}" -ge 20 ]; then pass "disk: ${FREE_GB} GB free at $DATA_DIR (>=20)"
  else fail "disk: ${FREE_GB:-?} GB free at $DATA_DIR — reference blocks.log alone is hundreds of MB and grows; 20 GB is the floor"; fi
else
  warn "data dir $DATA_DIR does not exist and could not be created — re-run with --data-dir pointing at the real location"
fi

# ── 3. Single-core throughput proxy ─────────────────────────────────────────
# Not a consensus benchmark — a floor detector for the class of machine.
# Reference hardware replays ~12 blocks/s (81 ms/block). A machine that
# cannot hash 256 MiB with sha256 in ~3 s single-core is well below that
# class (burstable/oversold VPS cores fail exactly here).
if [ "$SKIP_BENCH" -eq 1 ]; then
  warn "benchmark skipped (--skip-bench)"
else
  SHA_BIN="$(command -v sha256sum || command -v shasum)"
  now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000' 2>/dev/null \
             || echo $(( $(date +%s) * 1000 )); }
  if [ -n "$SHA_BIN" ]; then
    START_MS=$(now_ms)
    dd if=/dev/zero bs=1048576 count=256 2>/dev/null | "$SHA_BIN" >/dev/null
    END_MS=$(now_ms)
    ELAPSED=$(( END_MS - START_MS ))
    if [ "$ELAPSED" -le 3000 ]; then pass "cpu proxy: 256 MiB sha256 in ${ELAPSED} ms (<=3000)"
    elif [ "$ELAPSED" -le 6000 ]; then warn "cpu proxy: ${ELAPSED} ms — marginal; expect replay well below the 12 blocks/s reference"
    else fail "cpu proxy: ${ELAPSED} ms — this machine is not in the class that keeps up"; fi
  else
    warn "no sha256sum/shasum found; cpu proxy skipped"
  fi
fi

# ── 4. Clock ────────────────────────────────────────────────────────────────
# The node refuses to boot on gross clock-vs-peer skew (time_check.rs, margin
# = half an epoch). NTP discipline here means that gate never fires on you.
if [ "$OS" = "Darwin" ]; then
  warn "clock: macOS — verify 'Set date and time automatically' is on; the node's peer-time boot gate is the enforcement"
elif command -v timedatectl >/dev/null 2>&1; then
  if timedatectl show 2>/dev/null | grep -q '^NTPSynchronized=yes'; then
    pass "clock: NTP synchronized (timedatectl)"
  else
    fail "clock: NOT NTP-synchronized — the node's boot gate refuses gross skew, and a drifting clock makes your attestations refusable network-wide (admission window is {wall_epoch, wall_epoch+1}). Enable chrony/systemd-timesyncd."
  fi
elif command -v chronyc >/dev/null 2>&1 && chronyc tracking >/dev/null 2>&1; then
  pass "clock: chrony answering"
else
  warn "clock: cannot verify NTP state (no timedatectl/chronyc) — verify by hand"
fi

# ── 5. Open files ───────────────────────────────────────────────────────────
NOFILE="$(ulimit -n 2>/dev/null || echo 0)"
case "$NOFILE" in unlimited) pass "open files: unlimited" ;;
  *) if [ "$NOFILE" -ge 65535 ] 2>/dev/null; then pass "open files: $NOFILE (>=65535)"
     else warn "open files: $NOFILE — set LimitNOFILE=65535 in the systemd unit (runbook §6.5)"; fi ;;
esac

# ── 6. Ports ────────────────────────────────────────────────────────────────
port_in_use() {
  if command -v ss >/dev/null 2>&1; then ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1\$"
  else netstat -an 2>/dev/null | grep LISTEN | grep -q "[.:]$1 "; fi
}
port_in_use "$RPC_PORT" && fail "rpc port $RPC_PORT already in use" || pass "rpc port $RPC_PORT free"
port_in_use "$P2P_PORT" && fail "p2p port $P2P_PORT already in use" || pass "p2p port $P2P_PORT free"
echo
echo "REMINDER: the RPC has NO authentication, NO rate limit, NO authorisation."
echo "Bind it to 127.0.0.1 (the default) and never port-forward it. Expose ONLY"
echo "the P2P port, and firewall even that to known peer addresses while the"
echo "fleet transport is the unauthenticated devnet mesh (runbook §6)."
echo

if [ "$FAILS" -gt 0 ]; then echo "preflight: $FAILS FAIL, $WARNS WARN — do not deposit from this machine yet"; exit 2
elif [ "$WARNS" -gt 0 ]; then echo "preflight: 0 FAIL, $WARNS WARN — read each warning before proceeding"; exit 1
else echo "preflight: all checks passed"; exit 0; fi
