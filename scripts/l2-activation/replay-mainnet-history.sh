#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Historical replay qualification for the native-L2 activation build (M9).
#
# Replays a COPY of the real Genesis-4 mainnet block log with the candidate
# build (and, optionally, the release the fleet runs), from genesis, isolated
# from the network, and requires that every block re-applies with its own
# header's state root. The node checks that per block: `apply_block` refuses a
# post-state whose root differs from `header.state_root`, and the replay loop
# then aborts with "durable block log failed consensus replay". So a run that
# prints `replayed N blocks: …` has asserted every block's state root.
#
# What it does NOT read: any production host. The caller supplies a LOCAL
# directory that already holds a copy of an ARCHIVAL node's `blocks.log`,
# `meta.bin` and `ws_latest.bin` (see docs/L2-MAINNET-ACTIVATION.md, "Historical
# replay"). The copy is never modified: each run gets its own fresh data dir.
#
# usage:
#   scripts/l2-activation/replay-mainnet-history.sh \
#     --candidate <bloch-pos built from this branch, release, no devnet features> \
#     --source <dir with blocks.log meta.bin ws_latest.bin> \
#     --work <new dir> \
#     [--baseline <bloch-pos the fleet runs>] \
#     [--carryover <carryover.tsv.gz | carryover.tsv>]   (default: repo copy) \
#     [--manifest <genesis/mainnet.manifest>]             (default: repo copy) \
#     [--expect-root <hex64> --expect-slot <n>]          (head reported by two archivals) \
#     [--allow-unsandboxed]                               (no unshare / sandbox-exec available)
#
# Verdict: exit 0 and "VERDICT: PASS" only if every run replayed the whole log,
# the candidate is a mainnet build, the gate is inert in it, and all runs (and
# the expected head, when given) agree on head slot, block count and state root.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="$REPO/genesis/mainnet.manifest"
MANIFEST_SHA256="7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd"
CARRYOVER="$REPO/carryover.tsv.gz"
CARRYOVER_TSV_SHA256="84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6"
CANDIDATE="" BASELINE="" SOURCE="" WORK="" EXPECT_ROOT="" EXPECT_SLOT="" UNSANDBOXED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --candidate) CANDIDATE="$2"; shift 2 ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --carryover) CARRYOVER="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --expect-root) EXPECT_ROOT="$2"; shift 2 ;;
    --expect-slot) EXPECT_SLOT="$2"; shift 2 ;;
    --allow-unsandboxed) UNSANDBOXED=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$CANDIDATE" ] && [ -n "$SOURCE" ] && [ -n "$WORK" ] || { sed -n '18,31p' "$0" >&2; exit 2; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
die() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$CANDIDATE" ] || die "candidate binary $CANDIDATE is not executable"
[ -z "$BASELINE" ] || [ -x "$BASELINE" ] || die "baseline binary $BASELINE is not executable"
for f in blocks.log meta.bin; do [ -f "$SOURCE/$f" ] || die "$SOURCE/$f missing"; done
[ ! -e "$SOURCE/validator.key" ] || echo "WARNING: $SOURCE holds a validator.key; it is NOT copied. Prefer an archival copy." >&2
[ "$(sha256 "$MANIFEST")" = "$MANIFEST_SHA256" ] || die "manifest is not the published Genesis-4 mainnet manifest"
[ ! -e "$WORK" ] || die "$WORK exists; give a new directory"
mkdir -m 700 -p "$WORK"

# The carryover the manifest commits to (the node re-checks its SHA3-256).
case "$CARRYOVER" in
  *.gz) gunzip -c "$CARRYOVER" > "$WORK/carryover.tsv" ;;
  *) cp "$CARRYOVER" "$WORK/carryover.tsv" ;;
esac
[ "$(sha256 "$WORK/carryover.tsv")" = "$CARRYOVER_TSV_SHA256" ] || die "carryover.tsv is not the Genesis-4 carryover"

# The candidate must be a mainnet build: no devnet consensus features, and its
# build identity is recorded next to the verdict.
"$CANDIDATE" buildinfo > "$WORK/candidate.buildinfo.json"
grep -q '"build_version":"[^"]*devnet' "$WORK/candidate.buildinfo.json" \
  && die "candidate was built with devnet features; build it without features"
[ -z "$BASELINE" ] || "$BASELINE" buildinfo > "$WORK/baseline.buildinfo.json"

# Isolation: no route off the host. Linux: a fresh network namespace (only an
# unconfigured loopback). macOS: a sandbox profile that denies every network
# operation except loopback. Either way no --peers / --p2p-peer is passed and
# RPC is off, so the node has nobody to talk to even on loopback.
isolate() {
  if [ "$(uname)" = Linux ] && unshare --net --map-root-user true 2>/dev/null; then
    unshare --net --map-root-user "$@"
  elif [ "$(uname)" = Darwin ] && command -v sandbox-exec >/dev/null; then
    sandbox-exec -p '(version 1)(allow default)(deny network*)(allow network* (local ip "localhost:*"))(allow network* (remote ip "localhost:*"))' "$@"
  elif [ "$UNSANDBOXED" = 1 ]; then
    echo "WARNING: running without network isolation (loopback-only flags, no peers)" >&2
    "$@"
  else
    die "no network isolation available (unshare/sandbox-exec); pass --allow-unsandboxed to rely on the flags alone"
  fi
}

PORT=28790
run_one() { # label binary
  local label="$1" bin="$2" d="$WORK/$1"
  mkdir -m 700 "$d"
  # By name only (never a glob): no validator.key, no p2p identity, no
  # .TRAVADO-* operator snapshots, no state cache (full replay is the point).
  cp "$SOURCE/blocks.log" "$SOURCE/meta.bin" "$d/"
  [ ! -f "$SOURCE/ws_latest.bin" ] || cp "$SOURCE/ws_latest.bin" "$d/"
  [ ! -f "$SOURCE/blocks.idx" ] || cp "$SOURCE/blocks.idx" "$d/"
  PORT=$((PORT + 1))
  local started rc
  started=$(date +%s)
  set +e
  # No inherited BLOCH_* switch may change the boot path (state cache,
  # replay budget, finality rewind): the flags below are the whole config.
  isolate env $(env | awk -F= '/^BLOCH_/{printf "-u %s ", $1}') "$bin" run --data-dir "$d" --genesis "$MANIFEST" --carryover "$WORK/carryover.tsv" \
    --transport devnet --listen "$PORT" --listen-addr 127.0.0.1 \
    --rpc-port off --replay-from-genesis --stop-at-slot 1 > "$WORK/$label.log" 2>&1
  rc=$?
  set -e
  echo "$label: rc=$rc, $(( $(date +%s) - started )) s"
  grep -q 'durable block log failed consensus replay' "$WORK/$label.log" \
    && { grep -E 'replay [0-9]+/' "$WORK/$label.log" | tail -1; die "$label: a block did not re-apply to its header state root"; }
  grep -qE '^replayed [0-9]+ blocks' "$WORK/$label.log" || die "$label: no 'replayed N blocks' line (see $WORK/$label.log)"
  grep -qE '^recovery: mode=full-replay' "$WORK/$label.log" || die "$label: not a full replay from genesis"
}
summary() { # label -> "slot blocks root"
  local stop
  stop=$(grep -oE 'STOP at slot [0-9]+: head slot [0-9]+, [0-9]+ blocks, state root [0-9a-f]+' "$WORK/$1.log" | tail -1)
  [ -n "$stop" ] || die "$1: no STOP line (see $WORK/$1.log)"
  echo "$stop" | awk '{print $7, $8, $12}' | tr -d ','
}

run_one candidate "$CANDIDATE"
[ -z "$BASELINE" ] || run_one baseline "$BASELINE"

echo
echo "── head after replay (slot, blocks, state root) ──"
ref="$(summary candidate)"
echo "  candidate  $ref"
if [ -n "$BASELINE" ]; then
  base="$(summary baseline)"
  echo "  baseline   $base"
  [ "$base" = "$ref" ] || die "candidate and baseline disagree after the same log"
fi
if [ -n "$EXPECT_ROOT" ]; then
  read -r slot _ root <<<"$ref"
  [ "$slot" = "$EXPECT_SLOT" ] || die "head slot $slot, expected $EXPECT_SLOT"
  case "$EXPECT_ROOT" in "$root"*) ;; *) die "state root $root does not match expected $EXPECT_ROOT" ;; esac
fi
grep -E '^replayed [0-9]+ blocks' "$WORK/candidate.log"
echo "VERDICT: PASS — every block of the copied mainnet log re-applied to its header state root with the candidate build"
