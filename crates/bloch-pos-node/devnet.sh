#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Local Genesis-4 PoS devnet: N validator PROCESSES on a localhost TCP mesh.
# Throwaway keys, fast slots. Usage:
#
#   ./devnet.sh <workdir> [n_validators] [slot_ms] [stop_at_slot]
#
# Each node runs as its own `bloch-pos run` process with its own data dir and
# block log; logs land in <workdir>/node<i>/node.log. To exercise
# restart-persistence, kill one node's PID (printed below) and re-run the
# exact `bloch-pos run ...` line from its node.log header.
#
# Weak subjectivity (BLOCH-WEAK-SUBJECTIVITY.md §4.2) is enforced at boot, and
# a devnet passes it via the GENESIS ANCHOR: an empty data dir on a young
# genesis is the "trust-once" window, so no checkpoint flag is needed. Two
# consequences worth knowing before they look like bugs:
#   * A node starting with an EMPTY data dir against a genesis older than
#     WS_PERIOD_EPOCHS (2,016 epochs — at 500 ms slots, ~9 h of wall time)
#     refuses to sync and asks for --ws-checkpoint. Reusing a day-old
#     <workdir>/genesis.blg is the way to hit this; delete the workdir and let
#     this script mint a fresh genesis instead.
#   * A node that was DOWN for more than that window refuses too, for the same
#     reason and with the same recovery. Both refusals are the mechanism, not
#     a fault.

set -euo pipefail

WORKDIR="${1:?usage: devnet.sh <workdir> [n] [slot_ms] [stop_at_slot]}"
N="${2:-4}"
SLOT_MS="${3:-500}"
STOP_AT="${4:-}"
BASE_PORT=19310
# Release strongly preferred: the debug-build hybrid/SHAKE crypto is slow
# enough to push block propagation past the slot time on fast devnets.
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/target/release/bloch-pos"
[ -x "$BIN" ] || BIN="$HERE/target/debug/bloch-pos"
[ -x "$BIN" ] || { echo "build first: cargo build --release (in crates/bloch-pos-node)"; exit 1; }
mkdir -p "$WORKDIR"

# 1. Throwaway devnet keys (rule zero: devnet only, never production).
KEYDIRS=""
for i in $(seq 0 $((N - 1))); do
  d="$WORKDIR/node$i"
  mkdir -p "$d"
  [ -f "$d/validator.key" ] || "$BIN" keygen --dir "$d" --index "$i"
  KEYDIRS="${KEYDIRS:+$KEYDIRS,}$d"
done

# 2. Genesis manifest (slot 0 a few seconds out so every node is up first).
GENESIS="$WORKDIR/genesis.blg"
[ -f "$GENESIS" ] || "$BIN" genesis --keys "$KEYDIRS" --out "$GENESIS" --slot-ms "$SLOT_MS" --start-in 5

# 3. Launch N real node processes, full mesh.
PIDS=()
for i in $(seq 0 $((N - 1))); do
  PEERS=""
  for j in $(seq 0 $((N - 1))); do
    [ "$i" = "$j" ] && continue
    PEERS="${PEERS:+$PEERS,}127.0.0.1:$((BASE_PORT + j))"
  done
  d="$WORKDIR/node$i"
  # --transport devnet is the default, but it is written out here so this
  # script keeps producing the run it has always produced even if the default
  # is ever flipped to libp2p.
  CMD=("$BIN" run --data-dir "$d" --genesis "$GENESIS" --transport devnet \
       --listen "$((BASE_PORT + i))" --peers "$PEERS")
  [ -n "$STOP_AT" ] && CMD+=(--stop-at-slot "$STOP_AT")
  { echo "# ${CMD[*]}"; } > "$d/node.log"
  "${CMD[@]}" >> "$d/node.log" 2>&1 &
  pid=$!
  PIDS+=("$pid")
  echo "node$i pid=$pid port=$((BASE_PORT + i)) log=$d/node.log"
done

echo "devnet up: $N validators, ${SLOT_MS}ms slots (epoch = $((32 * SLOT_MS / 1000))s)."
if [ -n "$STOP_AT" ]; then
  wait "${PIDS[@]}" || true
  echo "--- final lines ---"
  for i in $(seq 0 $((N - 1))); do echo "[node$i] $(tail -1 "$WORKDIR/node$i/node.log")"; done
else
  echo "kill with: kill ${PIDS[*]}"
fi
