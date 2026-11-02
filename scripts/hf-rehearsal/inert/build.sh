#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# REHEARSAL BUILD ONLY - NEVER RELEASE. Builds, from a fresh 78d4921c export per
# variant, the candidate (every gate on the compressed schedule), the tooling
# copy, and one binary per gate-side variant that moves a single gate.
#   build.sh WORK NATIVE_78_TAR HERE [variant ...]
# One cargo target is shared; rsync -c touches only changed files, so a changed
# constant always rebuilds. Every binary's source-digest is asserted distinct.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd); TAR=$2; HERE=$3; shift 3
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
PAST=5; HF1=10; OWN=16; HF2=26; HF3=36; KESE=44; KESW=8; HF2MIN=10; LATE=100000; EARLY=33
log() { echo "== $* ($(date -u +%FT%TZ))"; }
capped() { systemd-run --user --scope -q -p MemoryMax=40G nice -n 10 "$@"; }
mkdir -p "$W/src" "$W/out" "$W/conf" "$W/tree"
echo "REHEARSAL ONLY - NEVER RELEASE" > "$W/NEVER-RELEASE"
base_conf() { cat <<C
HF1_CLAIM_FINALITY_EPOCH            =$HF1
HF1_FROZEN_FINALITY_SET_EPOCH       =$HF1
HF1_OWN_TARGET_VOTES_EPOCH          =$OWN
HF2_SLASHING_V2_EPOCH               =${SLASH:-$HF2}
HF2_GROWTH_CAP_EPOCH                =${GROWTH:-$HF2}
SIG_CANONICAL_ACTIVATION_EPOCH      =${SIG:-$HF2}
MLDSA_PIN_ACTIVATION_EPOCH          =${PIN:-$HF2}
HF3_SLH_SUITE_EPOCH                 =${SLHG:-$HF3}
HF3_PQ_MIGRATION_EPOCH              =${PQ:-$HF3}
HF3_KES_EPOCH                       =${KES:-$HF3}
HF3_KES_ENFORCE_EPOCH               =${ENF:-$KESE}
HF2_MIN_EPOCHS_AFTER_HF1            =$HF2MIN
KES_MIN_REGISTRATION_WINDOW_EPOCHS  =$KESW
!inert LATTICE_EMERGENCY_ACTIVATION_EPOCH
C
}
build_variant() { # name relax(0/1) fault(0/1) tooling(0/1)  env carries the moved gates
  local v=$1 relax=$2 fault=$3 tooling=$4; local s="$W/src/$v"
  log "variant $v"
  rm -rf "$s"; mkdir -p "$s"; tar -x -C "$s" -f "$TAR"
  base_conf > "$W/conf/$v.conf"
  [ "$tooling" = 1 ] && echo '!devnet-equivocate-tooling' >> "$W/conf/$v.conf"
  python3 -I "$s/scripts/hf-rehearsal/arm.py" "$s" --hf1 $HF1 --hf2 $HF2 --hf3 $HF3 --past-gate $PAST --only-listed \
    --conf "$W/conf/$v.conf" --report "$W/out/arming-$v.json" > "$W/out/arming-$v.log"
  [ "$relax" = 1 ] && python3 -I "$HERE/relax_order.py" "$s"
  [ "$fault" = 1 ] && python3 -I "$HERE/patch.py" pin-fault "$s"
  [ "$tooling" = 1 ] && { cp "$HERE/gate_probe.rs" "$s/crates/bloch-pos-node/src/gate_probe.rs"; python3 -I "$HERE/patch.py" tooling "$s"; }
  rsync -a -c --delete --exclude target "$s/" "$W/tree/"
  (cd "$W/tree" && BLOCH_BUILD_COMMIT="$v" CARGO_TARGET_DIR="$W/target" CARGO_BUILD_JOBS=6 \
    capped cargo +1.94.1 build --locked --release -p bloch-pos-node --bin bloch-pos) > "$W/build-$v.log" 2>&1 \
    || { tail -40 "$W/build-$v.log"; exit 2; }
  cp "$W/target/release/bloch-pos" "$W/out/bloch-pos-$v"
  local d; d=$("$W/out/bloch-pos-$v" --version | sed -n 's/.*source-digest sha3-256:\([0-9a-f]*\).*/\1/p' | head -1)
  [ -n "$d" ] || { echo "no digest $v"; exit 2; }
  case "$d" in 35c2b943*|a4c4af85*) echo "stale digest $v"; exit 2;; esac
  if grep -q " $d\$" "$W/out/DIGESTS" 2>/dev/null; then echo "digest of $v repeats"; exit 2; fi
  echo "$v $d" >> "$W/out/DIGESTS"
  rm -rf "$s"
}
all() {
build_variant cand 0 0 0
build_variant tool 0 0 1
GROWTH=$LATE build_variant growth-late 1 0 0
SLASH=$LATE build_variant slash-late 1 0 0
SIG=$LATE build_variant sig-late 1 0 0
ENF=$LATE build_variant kese-late 1 0 0
KES=$EARLY build_variant kes-early 1 0 0
KES=$LATE ENF=$((LATE+1)) build_variant kes-late 1 0 0
SLHG=$EARLY build_variant slh-early 1 0 0
SLHG=$LATE PQ=$LATE build_variant slh-late 1 0 0
SLHG=$EARLY PQ=$EARLY build_variant pq-early 1 0 0
PQ=$LATE build_variant pq-late 1 0 0
build_variant pinfi-both 0 1 0
PIN=$LATE build_variant pinfi-pinlate 1 1 0
SIG=$LATE build_variant pinfi-pinonly 1 1 0
PIN=$LATE SIG=$LATE build_variant pinfi-nopin 1 1 0
}
if [ $# -gt 0 ]; then "$@"; else all; fi
(cd "$W/out" && sha256sum bloch-pos-* > SHA256SUMS)
log "BUILD OK"
echo OK > "$W/BUILD-DONE"
