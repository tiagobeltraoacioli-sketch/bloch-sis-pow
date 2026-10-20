#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# LOCAL HF1/HF2/HF3 ACTIVATION REHEARSAL — build two armed binaries from
# disposable source copies and run rehearse.py on a throwaway loopback devnet.
#
#   scripts/hf-rehearsal/run.sh [options] [-- rehearse.py options]
#
#   --candidate REF       upgraded source (git ref in this repo). Default: --baseline
#                         (the gates-off arm: proves the harness on the release).
#   --candidate-tree DIR  upgraded source from a work tree (tracked + untracked,
#                         not ignored), e.g. an uncommitted local merge.
#   --baseline REF        the NON-upgraded release. Default b4a21fb6 (mainnet release).
#   --work DIR            scratch directory (must not exist). Default:
#                         ${TMPDIR:-/tmp}/hf-rehearsal-<utc-stamp>
#   --target DIR          shared CARGO_TARGET_DIR (deps are reused across the two
#                         builds and across runs). Default <repo>/target/hf-rehearsal
#   --hf1 E --hf2 E --hf3 E   default 10 / 14 / 18
#   --past-gate E         where the already-crossed 2884-era flag days land (default 6)
#   --jobs N              CARGO_BUILD_JOBS (default 4); builds run under nice -n 10
#   --candidate-bin F --baseline-bin F --arming F   skip the builds
#   --baseline-bin F alone   reuse a baseline binary, build only the candidate
#   --build-only          stop after the builds (prints the binaries)
#   --conf FILE           arm.py gate conf (repeatable; default gates.conf), e.g.
#                         --conf scripts/hf-rehearsal/gates.conf --conf scripts/hf-rehearsal/kes.conf
#
# Gate override: if the candidate's crates/bloch-pos-node/Cargo.toml declares a
# feature `hf-rehearsal`, it is built with that feature and
# BLOCH_HF{1,2,3}_REHEARSAL_EPOCH; otherwise arm.py rewrites every HF<n>_*
# constant in the disposable copy. Either way the 2884-era gates are moved
# to --past-gate in BOTH builds (they are already active on mainnet).
#
# SAFETY: everything binds 127.0.0.1, keys are generated fresh in --work, the
# manifest is new (unique genesis digest), peers are harness relays only.
# The armed binaries are written under --work only and must never be copied
# to a host: they would follow a different consensus than mainnet.
set -euo pipefail

REPO="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
HERE="$REPO/scripts/hf-rehearsal"
BASELINE=b4a21fb657d0beb17f64c62889b605c9a7a2d031
CANDIDATE=""; CANDIDATE_TREE=""; WORK=""; TARGET="$REPO/target/hf-rehearsal"
HF1=10; HF2=14; HF3=18; PAST=6; JOBS=4
CBIN=""; BBIN=""; ARMING=""; BUILD_ONLY=0; CONFS=()
PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --candidate) CANDIDATE="$2"; shift 2;;
    --candidate-tree) CANDIDATE_TREE="$2"; shift 2;;
    --baseline) BASELINE="$2"; shift 2;;
    --work) WORK="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --hf1) HF1="$2"; shift 2;;
    --hf2) HF2="$2"; shift 2;;
    --hf3) HF3="$2"; shift 2;;
    --past-gate) PAST="$2"; shift 2;;
    --jobs) JOBS="$2"; shift 2;;
    --candidate-bin) CBIN="$2"; shift 2;;
    --baseline-bin) BBIN="$2"; shift 2;;
    --arming) ARMING="$2"; shift 2;;
    --build-only) BUILD_ONLY=1; shift;;
    --conf) CONFS+=(--conf "$2"); shift 2;;
    --) shift; PASS=("$@"); break;;
    -h|--help) sed -n '3,33p' "$0"; exit 0;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ -n "$CANDIDATE" ] || [ -n "$CANDIDATE_TREE" ] || CANDIDATE="$BASELINE"
WORK="${WORK:-${TMPDIR:-/tmp}/hf-rehearsal-$(date -u +%Y%m%dT%H%M%SZ)}"
WORK="${WORK%/}"
[ -e "$WORK" ] && { echo "REFUSED: $WORK exists" >&2; exit 2; }
mkdir -p "$WORK.build"; chmod 700 "$WORK.build"
BUILD="$WORK.build"
echo "hf-rehearsal: work=$WORK build=$BUILD target=$TARGET"

export_ref() { # $1 ref $2 dest
  mkdir -p "$2"; git -C "$REPO" archive "$1" | tar -x -C "$2"
}
export_tree() { # $1 work tree $2 dest
  mkdir -p "$2"
  (cd "$1" && git ls-files -co --exclude-standard -z | tar --null -T - -cf -) | tar -x -C "$2"
}
build() { # $1 src $2 out-binary $3 features
  local feat=()
  [ -n "$3" ] && feat=(--features "$3")
  ( cd "$1" && CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" \
      BLOCH_HF1_REHEARSAL_EPOCH="$HF1" BLOCH_HF2_REHEARSAL_EPOCH="$HF2" BLOCH_HF3_REHEARSAL_EPOCH="$HF3" \
      nice -n 10 cargo build --locked --release -p bloch-pos-node --bin bloch-pos ${feat[@]+"${feat[@]}"} ) \
      > "$BUILD/$(basename "$2").build.log" 2>&1 \
    || { echo "build failed: $BUILD/$(basename "$2").build.log" >&2; tail -30 "$BUILD/$(basename "$2").build.log" >&2; exit 1; }
  cp "$TARGET/release/bloch-pos" "$2"
}

if [ -z "$CBIN" ]; then
  if [ -z "$BBIN" ]; then
    echo "== baseline $BASELINE"
    export_ref "$BASELINE" "$BUILD/src-baseline"
    python3 -I "$HERE/arm.py" "$BUILD/src-baseline" --no-hf --past-gate "$PAST" --report "$BUILD/arming-baseline.json"
  fi
  echo "== candidate ${CANDIDATE_TREE:-$CANDIDATE}"
  if [ -n "$CANDIDATE_TREE" ]; then export_tree "$CANDIDATE_TREE" "$BUILD/src-candidate"
  else export_ref "$CANDIDATE" "$BUILD/src-candidate"; fi
  # The rehearsal needs devnet-equivocate --evidence-out; if the candidate
  # predates it, carry this branch's devnet_tools.rs (devnet tooling only).
  if ! grep -q -- '--evidence-out' "$BUILD/src-candidate/crates/bloch-pos-node/src/devnet_tools.rs"; then
    echo "   candidate lacks devnet-equivocate --evidence-out: overlaying devnet_tools.rs from $REPO"
    cp "$REPO/crates/bloch-pos-node/src/devnet_tools.rs" "$BUILD/src-candidate/crates/bloch-pos-node/src/devnet_tools.rs"
  fi
  FEATURES=""
  if grep -qE '^hf-rehearsal *=' "$BUILD/src-candidate/crates/bloch-pos-node/Cargo.toml"; then
    FEATURES="hf-rehearsal"
    python3 -I "$HERE/arm.py" "$BUILD/src-candidate" --no-hf --past-gate "$PAST" --report "$BUILD/arming-candidate.json"
    python3 -I - "$BUILD/arming-candidate.json" "$HF1" "$HF2" "$HF3" <<'PY'
import json,sys
p=sys.argv[1]; r=json.load(open(p)); r["feature_mode"]="hf-rehearsal"
r["hf"]={"HF1":int(sys.argv[2]),"HF2":int(sys.argv[3]),"HF3":int(sys.argv[4])}
json.dump(r,open(p,"w"),indent=2)
PY
  else
    python3 -I "$HERE/arm.py" "$BUILD/src-candidate" --hf1 "$HF1" --hf2 "$HF2" --hf3 "$HF3" --past-gate "$PAST" \
      --report "$BUILD/arming-candidate.json" ${CONFS[@]+"${CONFS[@]}"}
  fi
  CBIN="$BUILD/bloch-pos-candidate"; ARMING="$BUILD/arming-candidate.json"
  if [ ! -d "$BUILD/src-baseline" ]; then
    echo "== reusing baseline binary $BBIN (must be built with the same --past-gate)"
  else
    BBIN="$BUILD/bloch-pos-baseline"
    echo "== building baseline (nice, jobs=$JOBS)"; build "$BUILD/src-baseline" "$BBIN" ""
  fi
  echo "== building candidate (nice, jobs=$JOBS${FEATURES:+, features=$FEATURES})"; build "$BUILD/src-candidate" "$CBIN" "$FEATURES"
fi

if [ "$BUILD_ONLY" = 1 ]; then echo "built: --baseline-bin $BBIN --candidate-bin $CBIN --arming $ARMING"; exit 0; fi
exec python3 -I "$HERE/rehearse.py" --candidate-bin "$CBIN" --baseline-bin "$BBIN" ${ARMING:+--arming "$ARMING"} \
  --work "$WORK" --hf1 "$HF1" --hf2 "$HF2" --hf3 "$HF3" "${PASS[@]+"${PASS[@]}"}"
