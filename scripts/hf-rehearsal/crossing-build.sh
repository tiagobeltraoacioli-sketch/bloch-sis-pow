#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# REHEARSAL BUILD ONLY - NEVER RELEASE. Builds the binaries crossing.py needs
# from FRESH source exports (no container, no build cache reused across
# trees, so a same-size edit can never be silently skipped):
#
#   candidate  native fa980367 (+ this branch's rehearsal tooling), every
#              already-crossed flag day moved to --past-gate, every HF1/HF2/HF3
#              and KES gate rescheduled by literal, L2 rehearsal activation
#   baseline   the same export with ONLY the past flag days moved (the HF
#              gates keep their mainnet epochs, unreachable on the private
#              net): the node that did not upgrade
#   tool       crates/bloch-pos-node/examples/hf3_rehearsal_tool.rs
#   L2         bloch-l2-native-follower + bloch-l2-produce-dev (+ gate probe)
#              from bloch-l2-evm 1aad0a2 against native 78d4921c armed with the
#              IDENTICAL rescheduling (the L2 links no file that differs
#              between 78d4921c and fa980367), NATIVE_LOCK 26bf4453, --locked
#
#   crossing-build.sh WORK NATIVE_FA_TAR NATIVE_78_TAR L2_SRC RETH_SRC NATIVE_LOCK [L2_TARGET_SEED]
#
# Env (epochs): PAST L2E HF1 OWN HF2 HF3 KESE KESW HF2MIN; JOBS (<= 6); MEM (GiB cap per cargo);
# NATIVE_ONLY=1 builds candidate, baseline and tool only (NATIVE_78_TAR and the L2 arguments ignored).
# Asserts: the candidate's source-digest differs from release 78d4921c
# (35c2b943...) and from release fa980367 (a4c4af85...); the armed consensus
# crates are byte-identical between the fa980367 and 78d4921c exports.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd); FA_TAR=$2; N78_TAR=$3; L2_SRC=$4; RETH_SRC=$5; LOCK=$6; SEED=${7:-}
PAST=${PAST:-5}; L2E=${L2E:-7}; HF1=${HF1:-10}; OWN=${OWN:-16}; HF2=${HF2:-20}; HF3=${HF3:-28}
KESE=${KESE:-44}; KESW=${KESW:-16}; HF2MIN=${HF2MIN:-10}; JOBS=${JOBS:-6}; MEM=${MEM:-24}
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
log() { echo "== $* ($(date -u +%FT%TZ))"; }
die() { echo "crossing-build: $*" >&2; exit 2; }
RELEASE_78=35c2b943d42ec370
RELEASE_FA=a4c4af850fec3efd
capped() { systemd-run --user --scope -q -p MemoryMax=${MEM}G nice -n 10 "$@"; }
[ "$JOBS" -le 6 ] || die "JOBS must be <= 6 on the shared hosts"

mkdir -p "$W/src" "$W/out"
echo "QUALIFICATION / REHEARSAL ONLY - NEVER RELEASE. Gates rescheduled for a private loopback network." > "$W/NEVER-RELEASE"
cat > "$W/crossing.conf" <<EOF
# Literal rescheduling of the armed release's gates (crossing-build.sh)
HF1_CLAIM_FINALITY_EPOCH            =$HF1
HF1_FROZEN_FINALITY_SET_EPOCH       =$HF1
HF1_OWN_TARGET_VOTES_EPOCH          =$OWN
HF2_SLASHING_V2_EPOCH               =$HF2
HF2_GROWTH_CAP_EPOCH                =$HF2
SIG_CANONICAL_ACTIVATION_EPOCH      =$HF2
MLDSA_PIN_ACTIVATION_EPOCH          =$HF2
HF3_SLH_SUITE_EPOCH                 =$HF3
HF3_PQ_MIGRATION_EPOCH              =$HF3
HF3_KES_EPOCH                       =$HF3
HF3_KES_ENFORCE_EPOCH               =$KESE
# Spacing asserts compressed for the private net (mainnet: 90 and 14*90)
HF2_MIN_EPOCHS_AFTER_HF1            =$HF2MIN
KES_MIN_REGISTRATION_WINDOW_EPOCHS  =$KESW
!inert LATTICE_EMERGENCY_ACTIVATION_EPOCH
EOF

export_tar() { rm -rf "$2"; mkdir -p "$2"; tar -x -C "$2" -f "$1"; }
log "fresh exports"
export_tar "$FA_TAR" "$W/src/cand"
export_tar "$FA_TAR" "$W/src/base"
export_tar "$FA_TAR" "$W/src/tooling"
NATIVE_ONLY=${NATIVE_ONLY:-0}
[ "$NATIVE_ONLY" = 1 ] || export_tar "$N78_TAR" "$W/src/bloch-validator-payout"
ARM="$W/src/cand/scripts/hf-rehearsal/arm.py"
log "arm candidate (fa980367)"
python3 -I "$ARM" "$W/src/cand" --hf1 "$HF1" --hf2 "$HF2" --hf3 "$HF3" --past-gate "$PAST" --only-listed \
  --conf "$W/crossing.conf" --report "$W/out/arming-candidate.json"
log "arm tooling copy (candidate gates + devnet-equivocate epoch-policy patch; devnet_tools.rs only)"
{ cat "$W/crossing.conf"; echo '!devnet-equivocate-tooling'; } > "$W/crossing-tooling.conf"
python3 -I "$ARM" "$W/src/tooling" --hf1 "$HF1" --hf2 "$HF2" --hf3 "$HF3" --past-gate "$PAST" --only-listed \
  --conf "$W/crossing-tooling.conf" --report "$W/out/arming-tooling.json"
diff -r "$W/src/cand/crates/bloch-pos-committee" "$W/src/tooling/crates/bloch-pos-committee" > /dev/null \
  || die "tooling copy changed consensus"
log "arm baseline (past flag days only)"
python3 -I "$ARM" "$W/src/base" --no-hf --past-gate "$PAST" --report "$W/out/arming-baseline.json"
if [ "$NATIVE_ONLY" != 1 ]; then
log "arm L2 native (78d4921c), identical rescheduling"
python3 -I "$ARM" "$W/src/bloch-validator-payout" --hf1 "$HF1" --hf2 "$HF2" --hf3 "$HF3" --past-gate "$PAST" --only-listed \
  --conf "$W/crossing.conf" --report "$W/out/arming-l2-native.json"
for c in bloch-pos-committee bloch-crypto; do
  diff -r "$W/src/cand/crates/$c" "$W/src/bloch-validator-payout/crates/$c" > /dev/null \
    || die "armed $c differs between the fa980367 and 78d4921c exports"
done
for f in codec.rs genesis.rs genesis_l2.rs lib.rs; do
  cmp -s "$W/src/cand/crates/bloch-pos-node/src/$f" "$W/src/bloch-validator-payout/crates/bloch-pos-node/src/$f" \
    || die "bloch-pos-node/src/$f differs between the exports"
done
echo "armed consensus crates identical across fa980367 / 78d4921c exports" | tee "$W/out/armed-identical.txt"
fi

native_build() { # $1 src $2 label $3 target
  log "native $2"
  (cd "$1" && BLOCH_BUILD_COMMIT="$2" BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$L2E CARGO_TARGET_DIR="$3" CARGO_BUILD_JOBS=$JOBS \
    capped cargo +1.94.1 build --locked --release -p bloch-pos-node --bin bloch-pos \
      --features l2-activation-rehearsal-mainnet-policy) > "$W/build-$2.log" 2>&1 || { tail -40 "$W/build-$2.log"; die "build $2"; }
}
native_build "$W/src/cand" candidate "$W/target-cand"
cp "$W/target-cand/release/bloch-pos" "$W/out/bloch-pos-candidate-REHEARSAL-ONLY"
log "tool example"
(cd "$W/src/cand" && BLOCH_BUILD_COMMIT=candidate BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$L2E CARGO_TARGET_DIR="$W/target-cand" \
  CARGO_BUILD_JOBS=$JOBS capped cargo +1.94.1 build --locked --release -p bloch-pos-node --example hf3_rehearsal_tool \
  --features l2-activation-rehearsal-mainnet-policy) > "$W/build-tool.log" 2>&1 || { tail -40 "$W/build-tool.log"; die "build tool"; }
cp "$W/target-cand/release/examples/hf3_rehearsal_tool" "$W/out/hf3_rehearsal_tool"
native_build "$W/src/tooling" tooling "$W/target-cand"
cp "$W/target-cand/release/bloch-pos" "$W/out/bloch-pos-tooling-REHEARSAL-ONLY"
native_build "$W/src/base" baseline "$W/target-base"
cp "$W/target-base/release/bloch-pos" "$W/out/bloch-pos-baseline-REHEARSAL-ONLY"

log "source digests"
for b in candidate baseline; do "$W/out/bloch-pos-$b-REHEARSAL-ONLY" --version; done | tee "$W/out/versions.txt"
CD=$(sed -n 's/.*source-digest sha3-256:\([0-9a-f]*\).*/\1/p' "$W/out/versions.txt" | head -1)
[ -n "$CD" ] || die "no source-digest printed"
case "$CD" in "$RELEASE_78"*|"$RELEASE_FA"*) die "candidate source-digest $CD equals a release digest: stale source";; esac
grep -q "= $HF1;" <(grep 'pub const HF1_CLAIM_FINALITY_EPOCH' "$W/src/cand/crates/bloch-pos-committee/src/params.rs") \
  || die "candidate params.rs is not armed at HF1=$HF1"
echo "candidate source-digest $CD differs from releases 78d4921c ($RELEASE_78...) and fa980367 ($RELEASE_FA...)" | tee -a "$W/out/versions.txt"

if [ "$NATIVE_ONLY" = 1 ]; then (cd "$W/out" && sha256sum * > SHA256SUMS); log "BUILD OK (native only): $W/out"; exit 0; fi
log "L2 follower + produce-dev against the armed 78d4921c export"
cp -a "$L2_SRC" "$W/src/bloch-l2-evm"
cp -a "$RETH_SRC" "$W/src/reth-bloch-rpc-snapshot"
SR=$W/src/bloch-l2-evm/integrations/settlement-recovery
python3 "$W/src/bloch-l2-evm/deployment/mainnet/follower-rpc/native-feature-shim.py" "$W/src/bloch-validator-payout"
cp "$LOCK" "$SR/Cargo.lock"
mkdir -p "$SR/examples"
cp "$W/src/cand/scripts/hf-rehearsal/l2_gate_probe.rs" "$SR/examples/l2_gate_probe.rs"
[ -z "$SEED" ] || [ -d "$W/l2-target" ] || { log "seed l2-target"; cp -a "$SEED" "$W/l2-target"; }
export VERGEN_GIT_SHA=8eb210175687c9f0c889a3b6795c16781d830e3a VERGEN_GIT_DESCRIBE=v2.4.1 VERGEN_GIT_DIRTY=true VERGEN_IDEMPOTENT=1
(BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH=$L2E CARGO_TARGET_DIR=$W/l2-target CARGO_BUILD_JOBS=$JOBS capped cargo +1.98.1 build --release --locked \
  --manifest-path "$SR/Cargo.toml" \
  --features bloch-pos-committee/l2-activation-rehearsal-mainnet-policy,bloch-pos-node/l2-activation-rehearsal-mainnet-policy \
  --bin bloch-l2-native-follower --bin bloch-l2-produce-dev --example l2_gate_probe) > "$W/build-l2.log" 2>&1 \
  || { tail -40 "$W/build-l2.log"; die "build L2"; }
for b in bloch-l2-native-follower bloch-l2-produce-dev; do cp "$W/l2-target/release/$b" "$W/out/$b-REHEARSAL-ONLY"; done
cp "$W/l2-target/release/examples/l2_gate_probe" "$W/out/l2_gate_probe"
python3 "$W/src/bloch-l2-evm/deployment/mainnet/l1_gates.py" "$W/src/bloch-validator-payout/crates/bloch-pos-committee/src/params.rs" \
  > "$W/out/l2-l1-activation-epochs.json" || true
(cd "$W/out" && sha256sum * > SHA256SUMS 2>/dev/null || true)
log "BUILD OK: $W/out"
