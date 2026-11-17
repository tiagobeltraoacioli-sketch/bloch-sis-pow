#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# REHEARSAL ONLY - NEVER RELEASE. Candidate and baseline for kes.py from a fresh export of an armed
# native tree: kes-armed-build.sh WORK NATIVE_TAR. Asserts the digest differs from the releases.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd); TAR=$2; JOBS=${JOBS:-6}; MEM=${MEM:-24}
export PATH=$HOME/.cargo/bin:/usr/bin:/bin
capped() { systemd-run --user --scope -q -p MemoryMax=${MEM}G nice -n 10 "$@"; }
rm -rf "$W/src"; mkdir -p "$W/src/cand" "$W/src/base" "$W/out"
tar -x -C "$W/src/cand" -f "$TAR"; tar -x -C "$W/src/base" -f "$TAR"
H=$W/src/cand/scripts/hf-rehearsal
python3 -I "$H/arm.py" "$W/src/cand" --hf1 2 --hf2 3 --hf3 4 --past-gate 1 --only-listed --conf "$H/kes-armed.conf" --report "$W/out/arming-candidate.json"
python3 -I "$H/arm.py" "$W/src/base" --no-hf --past-gate 1 --report "$W/out/arming-baseline.json"
for t in cand base; do
  (cd "$W/src/$t" && BLOCH_BUILD_COMMIT=kes-$t CARGO_TARGET_DIR="$W/target-$t" CARGO_BUILD_JOBS=$JOBS \
    capped cargo +1.94.1 build --locked --release -p bloch-pos-node --bin bloch-pos) > "$W/build-$t.log" 2>&1 || { tail -40 "$W/build-$t.log"; exit 2; }
  cp "$W/target-$t/release/bloch-pos" "$W/out/bloch-pos-$t-REHEARSAL-ONLY"
  "$W/out/bloch-pos-$t-REHEARSAL-ONLY" --version | tee -a "$W/out/versions.txt"
done
if grep -q 'sha3-256:\(35c2b943\|a4c4af85\)' "$W/out/versions.txt"; then echo "digest equals a release: stale source" >&2; exit 2; fi
echo BUILD-OK > "$W/out/DONE"
