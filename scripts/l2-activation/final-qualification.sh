#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Final qualification of the native-L2 mainnet activation build (M9).
#
# Given the FINAL commit, on a clean export of exactly that commit
# (`git archive`, never the working tree), it runs:
#
#   policy     the set-once parts of l2_settlement::mainnet are filled
#              (ATTESTOR_SET, PROGRAM) and the armed epoch, if any, is reported
#   tests      bloch-pos-committee: default, local-state-cache,
#              devnet-l2-user-txs,local-state-cache; bloch-pos-node: default
#   release    cargo build --release -p bloch-pos-node (no features); the
#              build identity must carry no devnet / rehearsal marker; SHA-256
#   fleet      mixed-fleet qualification (qualify-mixed-fleet.py), loopback
#              only and network-sandboxed, with a rehearsal build of this
#              commit that installs the MAINNET policy values
#              (--features l2-activation-rehearsal-mainnet-policy); the
#              installed L2 must report chain id 700770, async, the approved
#              limits and an attestor set
#   stake      stake-readiness stub: share of stake whose reported version
#              carries the final commit, from a file (see below), >= threshold
#
# and prints one summary with a single verdict line: "FINAL QUALIFICATION: PASS"
# only if EVERY stage passed (a skipped stage is not a pass). Exit 0 on PASS,
# 1 on FAIL, 2 on usage errors.
#
# It never contacts a live network: no RPC to any host, no peers; the mixed
# fleet is a throwaway local devnet on 127.0.0.1 inside sandbox-exec (macOS) or
# `unshare --net` (Linux).
#
# usage:
#   scripts/l2-activation/final-qualification.sh \
#     --commit <final commit>                    (default: HEAD) \
#     --work <new dir> \
#     [--baseline <bloch-pos the fleet runs>]    (required for the fleet stage) \
#     [--versions <file>]                        (required for the stake stage) \
#     [--stake-threshold <percent>]              (default 90) \
#     [--activation-epoch <E>]                   (rehearsal epoch, default 6) \
#     [--epochs-after <n>]                       (default 6) \
#     [--target-dir <dir>]                       (cargo cache; default <work>/target) \
#     [--retries <n>]                            (re-runs of a failed suite, default 1) \
#     [--skip-tests] [--allow-unsandboxed]
#
# Versions file (stake stage), one validator per line, '#' comments:
#   <validator id> <stake in BLCH> <reported build version or commit>
# e.g. the `build_version` / `commit` of `getbuildinfo` collected by the
# operators. A validator counts as upgraded when its version contains the
# first 12 hex digits of the final commit. Unlisted stake counts as NOT
# upgraded only if you list it: the file must cover the whole active stake.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT=HEAD WORK="" BASELINE="" VERSIONS="" THRESHOLD=90 EPOCH=6 AFTER=6 TARGET="" RETRIES=1
SKIP_TESTS=0 UNSANDBOXED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --commit) COMMIT="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    --versions) VERSIONS="$2"; shift 2 ;;
    --stake-threshold) THRESHOLD="$2"; shift 2 ;;
    --activation-epoch) EPOCH="$2"; shift 2 ;;
    --epochs-after) AFTER="$2"; shift 2 ;;
    --target-dir) TARGET="$2"; shift 2 ;;
    --retries) RETRIES="$2"; shift 2 ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --allow-unsandboxed) UNSANDBOXED=1; shift ;;
    -h|--help) sed -n '2,52p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$WORK" ] || { echo "--work <new dir> is required" >&2; exit 2; }
[ -e "$WORK" ] && { echo "$WORK exists; pass a new directory" >&2; exit 2; }
FULL="$(git -C "$REPO" rev-parse --verify "$COMMIT^{commit}" 2>/dev/null)" \
  || { echo "unknown commit: $COMMIT" >&2; exit 2; }
SHORT="${FULL:0:12}"
mkdir -p "$WORK" && chmod 700 "$WORK"
WORK="$(cd "$WORK" && pwd)"
SRC="$WORK/src" LOGS="$WORK/logs"
TARGET="${TARGET:-$WORK/target}"
mkdir -p "$SRC" "$LOGS" "$TARGET"
SUMMARY="$WORK/summary.txt"
: > "$SUMMARY"

# Stage results: "name|STATUS|detail" lines.
RESULTS=()
record() { RESULTS+=("$1|$2|$3"); printf '[%s] %-8s %s\n' "$2" "$1" "$3"; }
log() { printf '\n== %s\n' "$*"; }

# Network isolation for the local devnet: loopback only.
isolate() {
  if [ "$(uname)" = Linux ] && unshare --net --map-root-user true 2>/dev/null; then
    unshare --net --map-root-user "$@"
  elif [ "$(uname)" = Darwin ] && command -v sandbox-exec >/dev/null; then
    sandbox-exec -p '(version 1)(allow default)(deny network*)(allow network* (local ip "localhost:*"))(allow network* (remote ip "localhost:*"))' "$@"
  elif [ "$UNSANDBOXED" = 1 ]; then
    echo "WARNING: no network sandbox; relying on the loopback-only flags" >&2
    "$@"
  else
    echo "no network isolation available (unshare/sandbox-exec); pass --allow-unsandboxed" >&2
    return 97
  fi
}

# The exact commit, without the working tree (no uncommitted file can leak in).
log "export $FULL"
git -C "$REPO" archive --format=tar "$FULL" | tar -x -C "$SRC" || { echo "git archive failed" >&2; exit 2; }
export BLOCH_BUILD_COMMIT="$FULL" BLOCH_BUILD_TREE_ASSERTION=clean CARGO_TARGET_DIR="$TARGET"
unset BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH
cd "$SRC"

# ── policy: set-once parts and the gate ─────────────────────────────────────
log "policy (l2_settlement::mainnet, params)"
L2RS=crates/bloch-pos-committee/src/l2_settlement.rs
PARAMS=crates/bloch-pos-committee/src/params.rs
missing=()
grep -Eq 'pub const ATTESTOR_SET: Option<&str> = None;' "$L2RS" && missing+=("ATTESTOR_SET")
grep -Eq 'pub const PROGRAM: Option<Program> = None;' "$L2RS" && missing+=("PROGRAM")
GATE="$(grep -A1 '#\[cfg(not(feature = "l2-activation-rehearsal"))\]' "$PARAMS" \
  | sed -n 's/^pub const L2_SETTLEMENT_ACTIVATION_EPOCH: u64 = \(.*\);$/\1/p' | head -1)"
if [ ${#missing[@]} -eq 0 ]; then
  record policy PASS "ATTESTOR_SET and PROGRAM set; gate L2_SETTLEMENT_ACTIVATION_EPOCH = ${GATE:-?}"
else
  record policy FAIL "unset: ${missing[*]} (mainnet::activation() refuses); gate = ${GATE:-?}"
fi

# ── tests ───────────────────────────────────────────────────────────────────
suite() { # name, cargo args...
  local name="$1"; shift
  local attempt=0 out="$LOGS/test-$name.log" counts
  while :; do
    cargo test "$@" > "$out" 2>&1; local rc=$?
    counts="$(awk '/^test result:/ {p+=$4; f+=$6; i+=$8} END {printf "%d passed, %d failed, %d ignored", p, f, i}' "$out")"
    if [ $rc -eq 0 ]; then
      record "test" PASS "$name: $counts$([ $attempt -gt 0 ] && echo " (after $attempt retry; see $out.try*)")"
      return
    fi
    if [ $attempt -ge "$RETRIES" ]; then
      record "test" FAIL "$name: $counts, rc $rc; $(grep -E '^test .* FAILED$|^error' "$out" | head -3 | tr '\n' ' ')"
      return
    fi
    attempt=$((attempt + 1)); cp "$out" "$out.try$attempt"
  done
}
if [ "$SKIP_TESTS" = 1 ]; then
  record test SKIP "--skip-tests"
else
  log "test suites (logs in $LOGS)"
  suite committee-default -p bloch-pos-committee
  suite committee-local-state-cache -p bloch-pos-committee --features local-state-cache
  suite committee-devnet-l2-user-txs -p bloch-pos-committee --features devnet-l2-user-txs,local-state-cache
  suite node-default -p bloch-pos-node
fi

# ── release build ───────────────────────────────────────────────────────────
log "release build"
RELEASE="$TARGET/release/bloch-pos"
if cargo build --release -p bloch-pos-node > "$LOGS/build-release.log" 2>&1 && [ -x "$RELEASE" ]; then
  cp "$RELEASE" "$WORK/bloch-pos" && RELEASE="$WORK/bloch-pos"
  VERSION="$("$RELEASE" buildinfo | python3 -c 'import json,sys; print(json.load(sys.stdin)["build_version"])')"
  SUM="$(shasum -a 256 "$RELEASE" | cut -d' ' -f1)"
  echo "$SUM  bloch-pos" > "$WORK/SHA256SUMS"
  if echo "$VERSION" | grep -Eq 'devnet|rehearsal|dirty|unknown' || ! echo "$VERSION" | grep -q "$SHORT"; then
    record release FAIL "build identity '$VERSION' (expected $SHORT, no devnet/rehearsal marker)"
  else
    record release PASS "$VERSION sha256 $SUM"
  fi
else
  RELEASE=""
  record release FAIL "cargo build failed; see $LOGS/build-release.log"
fi

# ── mixed fleet with the mainnet policy values ──────────────────────────────
if [ -z "$BASELINE" ]; then
  record fleet SKIP "no --baseline (the release the fleet runs)"
elif [ -z "$RELEASE" ]; then
  record fleet FAIL "no release build"
else
  log "rehearsal build (mainnet policy, epoch $EPOCH)"
  RTARGET="$TARGET/rehearsal-mainnet-e$EPOCH"
  if BLOCH_L2_REHEARSAL_ACTIVATION_EPOCH="$EPOCH" cargo build --release -p bloch-pos-node \
       --features l2-activation-rehearsal-mainnet-policy --target-dir "$RTARGET" \
       > "$LOGS/build-rehearsal.log" 2>&1; then
    cp "$RTARGET/release/bloch-pos" "$WORK/bloch-pos-rehearsal-mainnet"
    log "mixed fleet (loopback, sandboxed): baseline $BASELINE"
    isolate python3 "$SRC/scripts/l2-activation/qualify-mixed-fleet.py" \
      --baseline "$BASELINE" --rehearsal "$WORK/bloch-pos-rehearsal-mainnet" --inert "$RELEASE" \
      --activation-epoch "$EPOCH" --epochs-after "$AFTER" --work "$WORK/fleet" \
      > "$LOGS/fleet.log" 2>&1
    rc=$?
    detail="$(python3 - "$WORK/fleet/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
if r.get("status") != "PASS":
    print("FAIL", "qualify-mixed-fleet status", r.get("status"), r.get("error", "")[:300]); sys.exit()
assert "+mainnet-policy" in r["buildinfo"]["rehearsal"]["build_version"], "rehearsal build lacks +mainnet-policy"
sat = lambda v: int(round(float(v) * 1e8)) if isinstance(v, str) and "." in v else int(v)
problems = []
for i, l2 in enumerate(r["l2_on_rehearsal_nodes"]):
    w = l2["withdrawals"]
    got = {
        "chain_id": l2["chain_id"], "asynchronous": l2["asynchronous"], "activated": l2["profile"]["activated"],
        "delay_blocks": w["delay_blocks"], "large_delay_blocks": w["large_delay_blocks"],
        "retention_blocks": w["retention_blocks"], "window_blocks": w["release_window"]["blocks"],
        "window_bps": w["release_window"]["bps"], "attestor_set": w["attestor_set"] is not None,
        "large_claim_sat": sat(w["large_claim_sat"]), "floor_sat": sat(w["release_window"]["floor_sat"]),
    }
    want = {"chain_id": 700770, "asynchronous": True, "activated": True, "delay_blocks": 64,
            "large_delay_blocks": 2880, "retention_blocks": 2880, "window_blocks": 2880, "window_bps": 1000,
            "attestor_set": True, "large_claim_sat": 100 * 10**8, "floor_sat": 10 * 10**8}
    problems += [f"node{i+1} {k}={got[k]!r} want {v!r}" for k, v in want.items() if got[k] != v]
if problems:
    print("FAIL", "; ".join(problems))
else:
    print("PASS", f"finalized {r['finalized_epochs']}, {r['shared_blocks_before_gate']} shared blocks before the gate,",
          f"StateRootMismatch lines {r['root_mismatch_log_lines']}; L2 chain 700770 async, delay 64/2880,",
          "window 2880 blocks 10% floor 10 BLCH, attestor set present")
PY
)"
    [ -n "$detail" ] || detail="FAIL no report (rc $rc); see $LOGS/fleet.log"
    record fleet "${detail%% *}" "${detail#* } (log $LOGS/fleet.log)"
  else
    record fleet FAIL "rehearsal build failed; see $LOGS/build-rehearsal.log"
  fi
fi

# ── stake readiness (stub: operator-reported versions from a file) ──────────
if [ -z "$VERSIONS" ]; then
  record stake SKIP "no --versions file"
else
  detail="$(python3 - "$VERSIONS" "$SHORT" "$THRESHOLD" <<'PY'
import sys
path, short, threshold = sys.argv[1], sys.argv[2], float(sys.argv[3])
total = ready = 0.0
behind = []
for n, line in enumerate(open(path), 1):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    parts = line.split(None, 2)
    if len(parts) != 3:
        print(f"FAIL line {n}: expected '<validator> <stake> <version>'"); sys.exit()
    who, stake, version = parts[0], float(parts[1]), parts[2]
    total += stake
    if short in version:
        ready += stake
    else:
        behind.append(who)
if total <= 0:
    print("FAIL no stake listed"); sys.exit()
share = 100 * ready / total
verdict = "PASS" if share >= threshold else "FAIL"
print(verdict, f"{share:.2f}% of {total:g} BLCH on {short} (threshold {threshold:g}%);",
      f"not upgraded: {', '.join(behind) or 'none'}")
PY
)"
  record stake "${detail%% *}" "${detail#* }"
fi

# ── summary ─────────────────────────────────────────────────────────────────
{
  echo "L2 mainnet activation, final qualification"
  echo "commit  $FULL"
  echo "date    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "work    $WORK"
  verdict=PASS
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r name status detail <<< "$r"
    printf '  %-5s %-8s %s\n' "$status" "$name" "$detail"
    [ "$status" = PASS ] || verdict=FAIL
  done
  echo "FINAL QUALIFICATION: $verdict"
} | tee "$SUMMARY"
grep -q 'FINAL QUALIFICATION: PASS' "$SUMMARY"
