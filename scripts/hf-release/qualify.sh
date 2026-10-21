#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Qualify a hard-fork release candidate before anyone signs it.
#
#   1. build   the candidate in the canonical release container
#              (the candidate's own scripts/build-pos-release-container.sh);
#   2. tests   every workspace package in the pinned toolchain, with complete
#              tracked fixtures and Python; legacy/proof suites use --release;
#   3. replay  a COPY of mainnet history from genesis with the gates at their
#              configured epochs, candidate and fleet baseline side by side:
#              both must re-apply every block and end on the same head. Every
#              changed gate must be scheduled after the replayed head (or be
#              inert), so this run is the "nothing changes before activation"
#              proof;
#   4. forced  for each gate the candidate arms (plus any --gate), a QUALIFICATION-ONLY build with only that
#              gate moved to an early epoch E inside the copied history:
#                pre   slots < E*32: must end on exactly the head the candidate
#                      reaches on the same prefix (moving the constant changes
#                      nothing before activation);
#                post  slots < (E+W)*32: must cross activation without a panic
#                      or crash. Either every historical block still applies
#                      ("inert-on-history") or replay stops cleanly with a
#                      consensus rejection ("diverged-after-activation"), which
#                      is the expected shape of a consensus change.
#              Forced binaries carry a synthetic commit and are never staged.
#
# Steps 2-4 run concurrently (tests in the container, replays on the host,
# forced builds serially in the container); wall time is about one canonical
# build + max(tests, forced builds + ~45 min of replays).
#
# Runs on a Linux x86-64 build host with a container engine (docker buildx).
# Never contacts a fleet host; every replay is network-isolated and works on
# its own copy of --source.
#
# usage:
#   scripts/hf-release/qualify.sh <commit> --source <dir> --baseline-bin <fleet bloch-pos> [options]
#     --source DIR          copy of an archival's blocks.log, blocks.idx, meta.bin, ws_latest.bin
#     --baseline-bin FILE   the binary the fleet runs today (b4a21fb6 release)
#     --out DIR             new output directory (default ~/hf-qualify-<commit12>-<utc>)
#     --base-commit C       fleet release commit for gate discovery (default b4a21fb6...)
#     --gate NAME[=EPOCH]   extra gate to force (repeatable; default: every gate armed in <commit>)
#     --gates-only          force only the --gate list (the schedule check still
#                           covers every discovered gate)
#     --force-epoch N       early test epoch (default: head epoch of --source - window - 8)
#     --window W            epochs replayed after the forced activation (default 16)
#     --jobs N              concurrent replays (default 8)
#     --expect-slot N --expect-root HEX   head reported by the archivals for --source
#     --tests-allow-fail PKG  package whose test failures are reported, not fatal
#                           (repeatable; default: no allowed failing packages)
#     --tests-allow-test NAME test (full path or final segment) whose failure is
#                           expected (tests that pin an ARMED gate to u64::MAX are
#                           found and accepted automatically; see hf-gates.py tripwires)
#     --skip-tests | --skip-forced | --allow-unsandboxed
#   env: CONTAINER_ENGINE (default docker; e.g. a `sudo -n docker` wrapper)
#
# Exit 0 and "VERDICT: PASS" only if no step FAILed (WARN is reported, not fatal).
set -euo pipefail

KIT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$KIT/../.." && pwd)"
REPLAY="$REPO/scripts/l2-activation/replay-mainnet-history.sh"
GATES_PY="$KIT/hf-gates.py"
PREFIX_PY="$KIT/log-prefix.py"
ENGINE="${CONTAINER_ENGINE:-docker}"
SLOTS_PER_EPOCH=32

case "${1:-}" in -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;; esac
COMMIT_ARG="${1:-}"; [ $# -gt 0 ] && shift
SOURCE="" BASELINE_BIN="" OUT="" BASE_COMMIT=b4a21fb657d0beb17f64c62889b605c9a7a2d031
FORCE_EPOCH="" WINDOW=16 JOBS=8 EXPECT_SLOT="" EXPECT_ROOT=""
SKIP_TESTS=0 SKIP_FORCED=0 UNSANDBOXED=0 GATES_ONLY=0
GATE_ARGS=() ALLOW_FAIL=() ALLOW_FAIL_SET=0 ALLOW_TEST=()
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --baseline-bin) BASELINE_BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --base-commit) BASE_COMMIT="$2"; shift 2 ;;
    --gate) GATE_ARGS+=("$2"); shift 2 ;;
    --gates-only) GATES_ONLY=1; shift ;;
    --force-epoch) FORCE_EPOCH="$2"; shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --expect-slot) EXPECT_SLOT="$2"; shift 2 ;;
    --expect-root) EXPECT_ROOT="$2"; shift 2 ;;
    --tests-allow-fail) ALLOW_FAIL+=("$2"); ALLOW_FAIL_SET=1; shift 2 ;;
    --tests-allow-test) ALLOW_TEST+=("$2"); shift 2 ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --skip-forced) SKIP_FORCED=1; shift ;;
    --allow-unsandboxed) UNSANDBOXED=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
usage() { sed -n '/^# usage:/,/^#   env:/p' "$0" >&2; exit 2; }
[ -n "$COMMIT_ARG" ] && [ -n "$SOURCE" ] && [ -n "$BASELINE_BIN" ] || usage
for n in "$WINDOW" "$JOBS" ${FORCE_EPOCH:+"$FORCE_EPOCH"}; do
  case "$n" in ''|*[!0-9]*) echo "numeric option expected, got '$n'" >&2; exit 2 ;; esac
done
[ "$JOBS" -ge 1 ] || JOBS=1
[ "$GATES_ONLY" = 0 ] || [ ${#GATE_ARGS[@]} -gt 0 ] || { echo "--gates-only needs --gate" >&2; exit 2; }

die() { echo "qualify: FAIL - $*" >&2; exit 1; }
COMMIT="$(git -C "$REPO" rev-parse --verify --quiet "$COMMIT_ARG^{commit}")" || die "unknown commit $COMMIT_ARG"
BASE_COMMIT="$(git -C "$REPO" rev-parse --verify --quiet "$BASE_COMMIT^{commit}")" || die "unknown base commit"
# Release integrity (HF1 review H-3): the candidate must descend from the
# fleet release, or it silently drops what that release fixed (for example
# the pre-activation offence refusal). Never qualify a source branch that
# forks before it.
git -C "$REPO" merge-base --is-ancestor "$BASE_COMMIT" "$COMMIT" \
  || die "$COMMIT does not descend from the fleet release $BASE_COMMIT"
C12="${COMMIT:0:12}"
OUT="${OUT:-$HOME/hf-qualify-$C12-$(date -u +%Y%m%dT%H%M%SZ)}"
[ ! -e "$OUT" ] || die "$OUT exists; give a new directory"
[ -x "$BASELINE_BIN" ] || die "baseline binary $BASELINE_BIN is not executable"
for f in blocks.log blocks.idx meta.bin; do [ -f "$SOURCE/$f" ] || die "$SOURCE/$f missing"; done
command -v "$ENGINE" >/dev/null 2>&1 || die "container engine not found: $ENGINE"
command -v python3 >/dev/null || die "python3 is required"
[ -x "$REPLAY" ] || die "$REPLAY missing"
SDE="$(git -C "$REPO" show -s --format=%ct "$COMMIT")"

mkdir -m 700 -p "$OUT"/{replay,data,forced}
exec > >(tee -a "$OUT/qualify.log") 2>&1
RESULTS="$OUT/RESULTS.tsv"; : > "$RESULTS"
say() { echo "[$(date -u +%H:%M:%S)] $*"; }
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"; say "$1: $2 ${3:+- $3}"; }

WT=""
cleanup() { [ -z "$WT" ] || git -C "$REPO" worktree remove --force "$WT" >/dev/null 2>&1 || true; }
trap cleanup EXIT

say "qualify $COMMIT (fleet base $BASE_COMMIT) on $(hostname), out=$OUT"
say "kit: $(git -C "$REPO" rev-parse HEAD)  engine: $ENGINE  source: $SOURCE"
{
  echo "commit=$COMMIT"; echo "base_commit=$BASE_COMMIT"; echo "host=$(hostname)"
  echo "kit_commit=$(git -C "$REPO" rev-parse HEAD)"; echo "started=$(date -u +%FT%TZ)"
  echo "source_blocks_log_bytes=$(wc -c < "$SOURCE/blocks.log" | tr -d ' ')"
  echo "baseline_bin_sha256=$(sha256sum "$BASELINE_BIN" | awk '{print $1}')"
} > "$OUT/qualify.env"

# ── 1. canonical build ────────────────────────────────────────────────────
WT="$OUT/src"
git -C "$REPO" worktree add --detach "$WT" "$COMMIT" >/dev/null
# The ML-DSA pin's QUALIFICATION-ONLY feature arms MLDSA_PIN_ACTIVATION_EPOCH
# at 0 (all of history under the pinned rule). It must never reach a release
# build: not in a default feature set, not in the release build script.
if grep -nE '^[[:space:]]*default[[:space:]]*=.*mldsa-pin-replay-qualification' \
    "$WT/crates/bloch-pos-node/Cargo.toml" "$WT/crates/bloch-pos-committee/Cargo.toml"; then
  die "a default feature set enables mldsa-pin-replay-qualification"
fi
if grep -n 'mldsa-pin-replay-qualification' "$WT/scripts/build-pos-release-container.sh"; then
  die "the release build script enables mldsa-pin-replay-qualification"
fi
record qualification-features-off PASS "mldsa-pin-replay-qualification not enabled by the release build"
say "building in the canonical container (log: $OUT/build.log)"
if (cd "$WT" && CONTAINER_ENGINE="$ENGINE" scripts/build-pos-release-container.sh "$OUT/release") > "$OUT/build.log" 2>&1; then
  BIN="$OUT/release/bloch-pos"
  BIN_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
  "$BIN" --version > "$OUT/release/VERSION.txt"
  grep -qF "($COMMIT)" "$OUT/release/VERSION.txt" || die "built binary does not report $COMMIT"
  "$BIN" buildinfo > "$OUT/release/buildinfo.json"
  record build PASS "bloch-pos sha256 $BIN_SHA"
else
  tail -30 "$OUT/build.log"; record build FAIL "see build.log"; die "canonical build failed"
fi
cleanup; WT=""

# ── gates (git only), before the tests so armed-gate tripwires are known ──
IDX_LAST_SLOT="$(python3 -I -c '
import struct, sys
b = open(sys.argv[1], "rb").read()
assert b[:8] == b"BPOSIDX1" and len(b) >= 28, "bad blocks.idx"
n = (len(b) - 8) // 20
print(struct.unpack_from("<Q", b, 8 + (n - 1) * 20)[0])' "$SOURCE/blocks.idx")"
IDX_HEAD_EPOCH=$((IDX_LAST_SLOT / SLOTS_PER_EPOCH))
gate_names=(); for g in ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}; do gate_names+=(--gate "${g%%=*}"); done
python3 -I "$GATES_PY" discover --repo "$REPO" --base "$BASE_COMMIT" --candidate "$COMMIT" \
  ${gate_names[@]+"${gate_names[@]}"} > "$OUT/gates.tsv"
say "gates (name, fleet value, candidate value, status); source head e$IDX_HEAD_EPOCH (index):"
sed 's/^/    /' "$OUT/gates.tsv"

armed=(); while IFS=$'\t' read -r name _ _ st; do case "$st" in scheduled:*) armed+=(--gate "$name") ;; esac; done < "$OUT/gates.tsv"
if [ ${#armed[@]} -gt 0 ]; then
  python3 -I "$GATES_PY" tripwires --repo "$REPO" --commit "$COMMIT" "${armed[@]}" > "$OUT/tripwires.txt"
  if [ -s "$OUT/tripwires.txt" ]; then
    say "tests pinning an armed gate to u64::MAX (expected to fail, accepted): $(tr '\n' ' ' < "$OUT/tripwires.txt")"
    while read -r t; do ALLOW_TEST+=("$t"); done < "$OUT/tripwires.txt"
  fi
fi

# ── 2. workspace tests (in the background) ────────────────────────────────
run_tests() {
  local ctx="$OUT/test-ctx" build_tag="bloch-hf-qualify:$C12" tag="bloch-hf-tests:$C12" trc verdict
  local allow_args=() a
  mkdir -p "$ctx" "$OUT/tests"
  git -C "$REPO" archive --format=tar "$COMMIT" | tar -xf - -C "$ctx"
  say "tests: canonical build image $build_tag"
  if ! "$ENGINE" buildx build --progress=plain --target build --load -t "$build_tag" \
    --build-arg "BLOCH_BUILD_COMMIT=$COMMIT" --build-arg "SOURCE_DATE_EPOCH=$SDE" \
    --file "$ctx/deploy/pos-release/Dockerfile" "$ctx" > "$OUT/tests-image.log" 2>&1; then
    record tests FAIL "base image build failed (tests-image.log)"; return 0
  fi
  if ! "$ENGINE" buildx build --progress=plain --load -t "$tag" \
    --build-arg "BUILD_IMAGE=$build_tag" \
    --file "$ctx/scripts/hf-release/Tests.Dockerfile" "$ctx" >> "$OUT/tests-image.log" 2>&1; then
    record tests FAIL "test image build failed (tests-image.log)"; return 0
  fi
  rm -rf "$ctx"
  for a in ${ALLOW_FAIL[@]+"${ALLOW_FAIL[@]}"}; do allow_args+=(--allow-package "$a"); done
  for a in ${ALLOW_TEST[@]+"${ALLOW_TEST[@]}"}; do allow_args+=(--allow-test "$a"); done
  say "tests: live debug, legacy release, proof release, explicit indexer lib (logs: $OUT/tests)"
  set +e
  "$ENGINE" run --rm --name "bloch-hf-qualify-tests-$C12-$$" \
    -e "BLOCH_BUILD_COMMIT=$COMMIT" -e BLOCH_BUILD_TREE_ASSERTION=clean -e CARGO_TERM_COLOR=never \
    --mount "type=bind,src=$OUT/tests,dst=/results" \
    "$tag" python3 -I scripts/hf-release/test-matrix.py /results \
    ${allow_args[@]+"${allow_args[@]}"} > "$OUT/tests.log" 2>&1
  trc=$?
  set -e
  if [ "$trc" != 0 ] || [ ! -f "$OUT/tests/summary.json" ]; then
    record tests FAIL "rc=$trc; all four stages must complete (tests.log, tests/*.log)"
    return 0
  fi
  verdict=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/tests/summary.json")
  case "$verdict" in
    PASS|WARN) record tests "$verdict" "all four stages completed (tests/summary.json)" ;;
    *) record tests FAIL "unexpected matrix verdict $verdict" ;;
  esac
}
TESTS_PID=""
if [ "$SKIP_TESTS" = 1 ]; then
  record tests SKIPPED "--skip-tests"
else
  run_tests & TESTS_PID=$!
fi

# ── replay helpers ────────────────────────────────────────────────────────
PORT_NEXT=28800
REPLAY_FLAGS=(); [ "$UNSANDBOXED" = 0 ] || REPLAY_FLAGS+=(--allow-unsandboxed)
REPLAY_PIDS=()
# replay <label> <binary> <source dir> [replay args...]: runs in the background,
# at most JOBS at once; output in replay/<label>.out, exit code in replay/<label>.rc.
replay() {
  local label="$1" bin="$2" src="$3" alive p; shift 3
  while :; do
    alive=0
    for p in ${REPLAY_PIDS[@]+"${REPLAY_PIDS[@]}"}; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
    [ "$alive" -ge "$JOBS" ] || break
    sleep 15
  done
  PORT_NEXT=$((PORT_NEXT + 10))
  (
    set +e
    "$REPLAY" --candidate "$bin" --source "$src" --work "$OUT/replay/$label" --port-base "$PORT_NEXT" \
      ${REPLAY_FLAGS[@]+"${REPLAY_FLAGS[@]}"} "$@" > "$OUT/replay/$label.out" 2>&1
    echo "$?" > "$OUT/replay/$label.rc"
  ) &
  REPLAY_PIDS+=($!)
  say "  replay $label started"
}
head_of() { awk '$1=="candidate" && NF==4 {print $2, $3, $4}' "$OUT/replay/$1.out" 2>/dev/null | tail -1; }
rc_of() { cat "$OUT/replay/$1.rc" 2>/dev/null || echo none; }

# ── forced sets (from the index, before any replay) ───────────────────────
# A forced set is "label spec" with spec "NAME=E[,NAME=E...]", built as ONE
# qualification binary. Default: one set "armed" holding every gate this build
# arms, all shifted by the same delta so the latest lands at head - window - 8
# (keeps every ordering/spacing rule the release itself satisfies, e.g. CF <=
# frozen set, KES enforcement >= registration + 14 days). Each --gate NAME[=E]
# adds its own single-gate set; --gates-only keeps only those.
forced=()
if [ "$SKIP_FORCED" = 0 ]; then
  target_e="${FORCE_EPOCH:-$((IDX_HEAD_EPOCH - WINDOW - 8))}"
  if [ "$GATES_ONLY" = 0 ]; then
    spec="" max_armed=0
    while IFS=$'\t' read -r name _ _ st; do
      case "$st" in scheduled:*) v="${st#scheduled:}"; [ "$v" -gt "$max_armed" ] && max_armed="$v"
        spec="$spec,$name=$v" ;; esac
    done < "$OUT/gates.tsv"
    if [ -n "$spec" ]; then
      shifted=""
      for kv in ${spec//,/ }; do
        v="${kv#*=}"; nv=$((v - max_armed + target_e))
        [ "$nv" -ge 1 ] || die "cannot shift ${kv%%=*} (e$v) into the copied history; give a longer --source or --force-epoch"
        shifted="$shifted,${kv%%=*}=$nv"
      done
      forced+=("armed ${shifted#,}")
    fi
  fi
  for g in ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}; do
    case "$g" in *=*) e="${g#*=}" ;; *) e="$target_e" ;; esac
    case "$e" in ''|*[!0-9]*) die "bad forced epoch in --gate $g" ;; esac
    forced+=("${g%%=*} ${g%%=*}=$e")
  done
fi
cuts=""
for item in ${forced[@]+"${forced[@]}"}; do
  read -r label spec <<<"$item"
  lo=$(echo "$spec" | tr ',' '\n' | awk -F= 'NR==1||$2<m{m=$2} END{print m}')
  hi=$(echo "$spec" | tr ',' '\n' | awk -F= 'NR==1||$2>m{m=$2} END{print m}')
  [ $(( (hi + WINDOW) * SLOTS_PER_EPOCH )) -le "$IDX_LAST_SLOT" ] || die "$label: forced e$hi + window $WINDOW is beyond the source head e$IDX_HEAD_EPOCH"
  say "forced set $label: $spec (pre: slots < e$lo, post: slots < e$((hi + WINDOW)))"
  cuts="$cuts $lo $((hi + WINDOW))"
done
cuts=$(printf '%s\n' $cuts | sort -un)
for c in $cuts; do
  python3 -I "$PREFIX_PY" --source "$SOURCE" --dest "$OUT/data/cut-e$c" --before-slot $((c * SLOTS_PER_EPOCH)) | sed 's/^/  cut-e'"$c"': /'
done

# ── 3. configured replays + candidate references on each prefix ───────────
expect=(); [ -z "$EXPECT_ROOT" ] || expect=(--expect-root "$EXPECT_ROOT" --expect-slot "$EXPECT_SLOT")
replay full-candidate "$BIN" "$SOURCE" ${expect[@]+"${expect[@]}"}
replay full-baseline "$BASELINE_BIN" "$SOURCE" ${expect[@]+"${expect[@]}"}
for c in $cuts; do replay "ref-cut-e$c" "$BIN" "$OUT/data/cut-e$c"; done

# ── 4. forced builds (serially, in the container) and their replays ───────
for item in ${forced[@]+"${forced[@]}"}; do
  read -r label spec <<<"$item"
  lo=$(echo "$spec" | tr ',' '\n' | awk -F= 'NR==1||$2<m{m=$2} END{print m}')
  hi=$(echo "$spec" | tr ',' '\n' | awk -F= 'NR==1||$2>m{m=$2} END{print m}')
  d="$OUT/forced/$label"; mkdir -p "$d/tree"
  echo "$lo $((hi + WINDOW)) $spec" > "$d/set"
  git -C "$REPO" archive --format=tar "$COMMIT" | tar -xf - -C "$d/tree"
  ok=1
  for kv in ${spec//,/ }; do
    python3 -I "$GATES_PY" force --tree "$d/tree" --gate "${kv%%=*}" --epoch "${kv#*=}" >> "$d/patch.txt" || ok=0
  done
  if [ "$ok" = 0 ]; then echo "FAIL	could not patch $spec" > "$d/verdict"; continue; fi
  (cd "$d/tree" && git init -q && git add -A \
    && GIT_AUTHOR_DATE="@$SDE" GIT_COMMITTER_DATE="@$SDE" git -c user.name=hf-qualify -c user.email=hf-qualify@invalid \
       commit -q -m "QUALIFICATION ONLY - NEVER RELEASE: $spec on top of $COMMIT")
  say "forced build $label ($(tr '\n' ' ' < "$d/patch.txt"))"
  if (cd "$d/tree" && CONTAINER_ENGINE="$ENGINE" scripts/build-pos-release-container.sh "$d/build") > "$d/build.log" 2>&1; then
    fb="$d/bloch-pos-FORCED-$label"
    mv "$d/build/bloch-pos" "$fb"
    rm -f "$d/build/SHA256SUMS"
    echo "QUALIFICATION ONLY: $spec. Never sign, stage or run on a network." > "$d/build/NEVER-RELEASE"
    rm -rf "$d/tree"
    replay "forced-$label-pre" "$fb" "$OUT/data/cut-e$lo"
    replay "forced-$label-post" "$fb" "$OUT/data/cut-e$((hi + WINDOW))"
  else
    grep -E '^#[0-9]+ .*error' "$d/build.log" | head -5 || true
    echo "FAIL	forced build failed (forced/$label/build.log)" > "$d/verdict"
  fi
done

say "waiting for $(( ${#REPLAY_PIDS[@]} )) replay(s)"
[ ${#REPLAY_PIDS[@]} -eq 0 ] || wait "${REPLAY_PIDS[@]}" || true

# ── verdicts ──────────────────────────────────────────────────────────────
ref_full="$(head_of full-candidate)"; base_full="$(head_of full-baseline)"
if [ "$(rc_of full-candidate)" = 0 ] && [ "$(rc_of full-baseline)" = 0 ] && [ -n "$ref_full" ] && [ "$ref_full" = "$base_full" ]; then
  record replay-configured PASS "head (slot blocks root) $ref_full, identical to baseline"
  read -r HEAD_SLOT _ _ <<<"$ref_full"
else
  tail -5 "$OUT/replay/full-candidate.out" "$OUT/replay/full-baseline.out" || true
  record replay-configured FAIL "candidate [$ref_full] rc=$(rc_of full-candidate) / baseline [$base_full] rc=$(rc_of full-baseline)"
  HEAD_SLOT="$IDX_LAST_SLOT"
fi
HEAD_EPOCH=$((HEAD_SLOT / SLOTS_PER_EPOCH))

sched_bad=""
while IFS=$'\t' read -r name _ _ st; do
  case "$st" in
    scheduled:*) e="${st#scheduled:}"
      if [ "$e" -le "$HEAD_EPOCH" ]; then
        explicit=0; for g in ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}; do [ "${g%%=*}" = "$name" ] && explicit=1; done
        [ "$explicit" = 1 ] || sched_bad="$sched_bad $name(e$e<=head e$HEAD_EPOCH)"
      else
        say "  $name armed at e$e: $(( e - HEAD_EPOCH )) epochs (~$(( (e - HEAD_EPOCH) * 16 / 60 )) h) after the replayed head"
      fi ;;
    inert) : ;;
    missing) sched_bad="$sched_bad $name(missing)" ;;
    *) say "  NOTE $name: $st (check by hand)" ;;
  esac
done < "$OUT/gates.tsv"
# KES: enforcement needs a registration window of at least 14 days (1,260
# epochs) after registration opens, so every validator can register its root.
kes_reg="$(awk -F'\t' '$1=="HF3_KES_EPOCH"{print $4}' "$OUT/gates.tsv")"
kes_enf="$(awk -F'\t' '$1=="HF3_KES_ENFORCE_EPOCH"{print $4}' "$OUT/gates.tsv")"
case "$kes_enf" in scheduled:*)
  case "$kes_reg" in
    scheduled:*) w=$(( ${kes_enf#scheduled:} - ${kes_reg#scheduled:} ))
      if [ "$w" -lt 1260 ]; then sched_bad="$sched_bad KES-window($w<1260 epochs)"
      else say "  KES registration window: $w epochs (~$((w / 90)) days)"; fi ;;
    *) sched_bad="$sched_bad HF3_KES_ENFORCE_EPOCH-armed-without-HF3_KES_EPOCH" ;;
  esac ;;
esac
if [ -n "$sched_bad" ]; then
  record gate-schedule FAIL "changed gate at or before the replayed head:$sched_bad"
else
  record gate-schedule PASS "$(grep -c scheduled: "$OUT/gates.tsv" || true) armed, $(grep -c inert "$OUT/gates.tsv" || true) inert; replayed head e$HEAD_EPOCH"
fi

if [ "$SKIP_FORCED" = 1 ]; then
  record forced SKIPPED "--skip-forced"
elif [ ${#forced[@]} -eq 0 ]; then
  record forced SKIPPED "no gate to force"
else
  for item in "${forced[@]}"; do
    read -r label spec <<<"$item"
    d="$OUT/forced/$label"
    if [ ! -f "$d/verdict" ]; then
      read -r lo post_cut _ < "$d/set"
      ref_pre="$(head_of "ref-cut-e$lo")"; ref_post="$(head_of "ref-cut-e$post_cut")"
      pre_head="$(head_of "forced-$label-pre")"; post_head="$(head_of "forced-$label-post")"
      if [ "$(rc_of "ref-cut-e$lo")" != 0 ] || [ "$(rc_of "ref-cut-e$post_cut")" != 0 ]; then
        echo "FAIL	the configured candidate itself failed on a prefix (replay/ref-cut-*.out)" > "$d/verdict"
      elif [ "$(rc_of "forced-$label-pre")" != 0 ] || [ "$pre_head" != "$ref_pre" ]; then
        echo "FAIL	before e$lo the forced build differs: [$pre_head] vs configured [$ref_pre] (replay/forced-$label-pre.out)" > "$d/verdict"
      elif [ "$(rc_of "forced-$label-post")" = 0 ]; then
        if [ "$post_head" = "$ref_post" ]; then
          echo "PASS	identical before e$lo; crossed $spec and replayed to e$post_cut with history still valid (inert-on-history)" > "$d/verdict"
        else
          echo "FAIL	replayed but head [$post_head] != configured [$ref_post]" > "$d/verdict"
        fi
      elif grep -q 'did not re-apply to its header state root' "$OUT/replay/forced-$label-post.out"; then
        h="$(grep -h 'apply refused' "$OUT/replay/forced-$label-post/candidate.log" 2>/dev/null | head -1 | cut -c1-160 || true)"
        last="$(grep -h '^replay ' "$OUT/replay/forced-$label-post/candidate.log" 2>/dev/null | tail -1 | grep -oE 'head slot [0-9]+' || true)"
        echo "PASS	identical before e$lo; after activation a clean consensus rejection (diverged-after-activation; last progress ${last:-n/a}): ${h:-no reason logged}" > "$d/verdict"
      else
        echo "FAIL	post-activation replay crashed or stopped without a consensus verdict (replay/forced-$label-post.out)" > "$d/verdict"
      fi
    fi
    IFS=$'\t' read -r st detail < "$d/verdict"
    record "forced:$label" "$st" "$spec: $detail"
  done
fi

if [ -n "$TESTS_PID" ]; then say "waiting for the workspace tests"; wait "$TESTS_PID" || true; fi
echo "finished=$(date -u +%FT%TZ)" >> "$OUT/qualify.env"
echo
echo "── results ($RESULTS) ──"
column -t -s $'\t' "$RESULTS" 2>/dev/null || cat "$RESULTS"
if awk -F'\t' '$2=="FAIL"{bad=1} END{exit bad?0:1}' "$RESULTS"; then
  echo "VERDICT: FAIL - do not sign $COMMIT"
  exit 1
fi
cat <<EOF

VERDICT: PASS - $COMMIT
  binary   $OUT/release/bloch-pos
  sha256   $BIN_SHA
  version  $(head -1 "$OUT/release/VERSION.txt")
  release  $OUT/release/{bloch-pos,SHA256SUMS,BUILD-INFO} (unsigned; deployment_authorized=false)
EOF
