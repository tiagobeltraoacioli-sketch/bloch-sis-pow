#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# HF verification run (DEV TOOLING ONLY; no consensus code is changed).
#
# 1. Rust partition harness (crates/bloch-pos-committee/tests/support/partition.rs)
#    over the REAL transition of the tree under test: 2-way (60/40), 3-way,
#    50/50 splits (+ heal-both, votes-cross by default).
# 2. Python partition model sweep (tools/partition-model) over the mainnet
#    fleet snapshot, every variant (TODAY, CLAIM, P2A, P1A, BOTH).
# 3. Report: conflicting finalizations and double-pays, per scenario/variant.
#
# Usage:
#   scripts/hf-verify/run-all.sh [options]
#
#   --repo DIR            tree under test (default: this script's tree). If it
#                         lacks the harness, the harness files of this script's
#                         tree are copied into the overlay.
#   --override NAME=EPOCH rewrite `pub const NAME: u64` (EPOCH decimal or MAX)
#                         in a scratch overlay of --repo; repeatable.
#   --arm NAME            same as --override NAME=<start epoch>; repeatable.
#   --start-epoch N       harness warm-up end / scenario start (default 5860).
#   --max-epochs N        cap on each open-ended split phase (default 4000).
#   --scenarios "a b"     harness scenarios (default "split2 split3 split50
#                         heal-both votes-cross"; "none" skips the harness).
#   --model quick|full|none   model sweep size (default quick).
#   --model-hf-from N     absolute epoch from which model variants bind
#                         (default: from the partition start).
#   --jobs N              parallel harness scenarios / model processes (default 4).
#   --out DIR             output dir (default target/hf-verify/<timestamp>).
#   --claim-gate-const NAME  constant holding the claim-finality gate (default:
#                         first defined of HF1_CLAIM_FINALITY_EPOCH,
#                         NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH); absent = inert.
#   --strict              exit 3 if any harness scenario reports conflicting
#                         finality or a double-pay under the build's own rule.
#
# Overrides never touch --repo: the tree is rsynced to
# <repo>/target/hf-verify-overlay/src, patched there by override_consts.py, and
# built with its own CARGO_TARGET_DIR. The claim predicate's gate is taken from
# the (patched) claim-finality constant (--claim-gate-const) and passed to the
# harness as HF_CLAIM_GATE_EPOCH.
#
# HF1 example (both halves live from the split onward; the integrated branch
# enforces that its two gates are armed together):
#   scripts/hf-verify/run-all.sh --repo ~/worktrees/<hf1-merge> \
#       --arm HF1_CLAIM_FINALITY_EPOCH --arm HF1_FROZEN_FINALITY_SET_EPOCH --arm <own-target gate>
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF_ROOT="$(cd "$HERE/../.." && pwd)"
REPO="$SELF_ROOT"
START=5860
MAX=4000
SCENARIOS="split2 split3 split50 heal-both votes-cross"
MODEL=quick
MODEL_HF_FROM=""
JOBS=4
OUT=""
STRICT=0
CLAIM_GATE_CONSTS="${HF_CLAIM_GATE_CONSTS:-HF1_CLAIM_FINALITY_EPOCH NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH}"
OVERRIDES=()
ARMS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$(cd "$2" && pwd)"; shift 2 ;;
    --override) OVERRIDES+=("$2"); shift 2 ;;
    --arm) ARMS+=("$2"); shift 2 ;;
    --start-epoch) START="$2"; shift 2 ;;
    --max-epochs) MAX="$2"; shift 2 ;;
    --scenarios) SCENARIOS="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --model-hf-from) MODEL_HF_FROM="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --claim-gate-const) CLAIM_GATE_CONSTS="$2"; shift 2 ;;
    -h|--help) sed -n '3,46p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
for a in ${ARMS[@]+"${ARMS[@]}"}; do OVERRIDES+=("$a=$START"); done

OUT="${OUT:-$REPO/target/hf-verify/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
REPORT="$OUT/report.txt"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"

log() { echo "$*" | tee -a "$REPORT"; }
: > "$REPORT"
log "# HF verification run $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "repo:        $REPO"
log "commit:      $(git -C "$REPO" rev-parse --short=12 HEAD 2>/dev/null || echo n/a)$(git -C "$REPO" diff --quiet HEAD 2>/dev/null || echo ' (+uncommitted changes)')"
log "harness from: $SELF_ROOT ($(git -C "$SELF_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo n/a))"
log "start epoch: $START, max split epochs: $MAX"
log "overrides:   ${OVERRIDES[*]:-none}"

HARNESS_FILES=(
  crates/bloch-pos-committee/tests/support/partition.rs
  crates/bloch-pos-committee/tests/partition.rs
  crates/bloch-pos-committee/examples/partition_sim.rs
)
need_overlay=0
[ ${#OVERRIDES[@]} -gt 0 ] && need_overlay=1
for f in "${HARNESS_FILES[@]}"; do [ -f "$REPO/$f" ] || need_overlay=1; done

BUILD_ROOT="$REPO"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
if [ "$need_overlay" = 1 ]; then
  BUILD_ROOT="$REPO/target/hf-verify-overlay/src"
  TARGET_DIR="$REPO/target/hf-verify-overlay/target"
  mkdir -p "$BUILD_ROOT"
  rsync -a --delete --exclude /target --exclude /.git "$REPO/" "$BUILD_ROOT/"
  for f in "${HARNESS_FILES[@]}"; do
    if [ ! -f "$REPO/$f" ]; then
      mkdir -p "$BUILD_ROOT/$(dirname "$f")"
      cp "$SELF_ROOT/$f" "$BUILD_ROOT/$f"
      log "harness file copied into overlay: $f"
    fi
  done
  if [ ${#OVERRIDES[@]} -gt 0 ]; then
    python3 "$HERE/override_consts.py" "$BUILD_ROOT" "${OVERRIDES[@]}" | tee -a "$REPORT"
  fi
  log "overlay:     $BUILD_ROOT"
fi

GATE=absent
GATE_NAME=none
for name in $CLAIM_GATE_CONSTS; do
  GATE="$(python3 "$HERE/override_consts.py" "$BUILD_ROOT" --get "$name")"
  if [ "$GATE" != absent ]; then GATE_NAME="$name"; break; fi
done
case "$GATE" in
  absent|MAX) export HF_CLAIM_GATE_EPOCH=MAX ;;
  expr:*) log "WARNING: $GATE_NAME is an expression ($GATE); treating the claim gate as inert"; export HF_CLAIM_GATE_EPOCH=MAX ;;
  *) export HF_CLAIM_GATE_EPOCH="$GATE" ;;
esac
log "claim gate:  $GATE_NAME = $GATE (looked up: $CLAIM_GATE_CONSTS)"
log "gates in tree under test (after overrides):"
grep -rhoE "pub const [A-Z0-9_]*_EPOCH: u64 = [^;]+" "$BUILD_ROOT"/crates/bloch-pos-committee/src/params.rs \
  | sed 's/pub const /  /' | sort -u | tee -a "$REPORT" >/dev/null

# ── 2a. Python model sweep, in the background while the harness runs ──────────
MODEL_DIR="$SELF_ROOT/tools/partition-model"
model_pid=""
if [ "$MODEL" != "none" ]; then
  margs=(sweep --jobs "$JOBS" --out "$OUT/model.json")
  [ "$MODEL" = quick ] && margs+=(--quick)
  [ -n "$MODEL_HF_FROM" ] && margs+=(--hf-from "$MODEL_HF_FROM")
  ( python3 "$MODEL_DIR/test_bloch_partition_model.py" > "$OUT/model-tests.log" 2>&1 \
      && echo OK > "$OUT/model-tests.status" || echo FAILED > "$OUT/model-tests.status"
    /usr/bin/time -p python3 "$MODEL_DIR/bloch_partition_model.py" "${margs[@]}" > "$OUT/model-sweep.log" 2>&1 ) &
  model_pid=$!
fi

# ── 1. Rust harness ──────────────────────────────────────────────────────────
harness_conflicts=0
harness_double=0
if [ "$SCENARIOS" != "none" ]; then
  log ""
  log "## Harness (real transition)"
  ( cd "$BUILD_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release -q -p bloch-pos-committee --example partition_sim ) \
    > "$OUT/build.log" 2>&1 || { log "BUILD FAILED, see $OUT/build.log"; tail -30 "$OUT/build.log"; exit 1; }
  BIN="$TARGET_DIR/release/examples/partition_sim"
  pids=()
  slots=$JOBS
  [ -n "$model_pid" ] && slots=$((JOBS + 1))
  for s in $SCENARIOS; do
    ( /usr/bin/time -p "$BIN" "$s" --start-epoch "$START" --max-epochs "$MAX" > "$OUT/harness-$s.log" 2> "$OUT/harness-$s.time" ) &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge "$slots" ]; do sleep 2; done
  done
  fail=0
  for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || fail=1; done
  for s in $SCENARIOS; do
    line="$(grep '^HFV ' "$OUT/harness-$s.log" || true)"
    if [ -z "$line" ]; then
      log "harness $s: NO RESULT (see $OUT/harness-$s.log)"; fail=1; continue
    fi
    log "$line wall_s=$(awk '/^real/{print $2}' "$OUT/harness-$s.time")"
    c="$(sed -E 's/.* conflicting_finality=([0-9]+).*/\1/' <<<"$line")"
    d="$(sed -E 's/.* double_pay=([0-9]+).*/\1/' <<<"$line")"
    harness_conflicts=$((harness_conflicts + c))
    harness_double=$((harness_double + d))
    grep -q "could not build" "$OUT/harness-$s.log" && log "  WARNING $s: a producer built a block the real transition refused"
  done
  log "HARNESS TOTAL conflicting_finality=$harness_conflicts double_pay=$harness_double"
  [ "$fail" = 0 ] || log "WARNING: at least one harness scenario failed"
fi

# ── 2. Python model ──────────────────────────────────────────────────────────
if [ -n "$model_pid" ]; then
  log ""
  log "## Model sweep ($MODEL${MODEL_HF_FROM:+, variants from epoch $MODEL_HF_FROM})"
  wait "$model_pid" || { log "MODEL SWEEP FAILED, see $OUT/model-sweep.log"; tail -20 "$OUT/model-sweep.log"; exit 1; }
  log "model self-tests: $(cat "$OUT/model-tests.status") (log $OUT/model-tests.log)"
  log "model sweep wall_s=$(awk '/^real/{print $2}' "$OUT/model-sweep.log")"
  python3 "$MODEL_DIR/bloch_partition_model.py" counts "$OUT/model.json" | tee -a "$REPORT"
  python3 "$MODEL_DIR/bloch_partition_model.py" summary "$OUT/model.json" > "$OUT/model-summary.md"
  log "(per heal time: $OUT/model-summary.md)"
fi

log ""
log "report: $REPORT"
if [ "$STRICT" = 1 ] && [ $((harness_conflicts + harness_double)) -gt 0 ]; then exit 3; fi
