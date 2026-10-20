#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Qualify a hard-fork release candidate before anyone signs it.
#
#   1. build   the candidate in the canonical release container
#              (the candidate's own scripts/build-pos-release-container.sh);
#   2. tests   `cargo test --workspace --locked --no-fail-fast` in the same
#              pinned toolchain image (Dockerfile target `build`);
#   3. replay  a COPY of mainnet history from genesis with the gates at their
#              configured epochs, candidate and fleet baseline side by side:
#              both must re-apply every block and end on the same head. Every
#              changed gate must be scheduled after the replayed head (or be
#              inert), so this run is the "nothing changes before activation"
#              proof;
#   4. forced  for each gate, a QUALIFICATION-ONLY build with only that gate
#              moved to an early epoch E inside the copied history:
#                pre   slots < E*32: must end on exactly the configured head
#                      (moving the constant changes nothing before activation);
#                post  slots < (E+W)*32: must cross activation without a panic
#                      or crash. Either every historical block still applies
#                      ("inert-on-history") or replay stops cleanly with a
#                      consensus rejection ("diverged-after-activation"), which
#                      is the expected shape of a consensus change.
#              Forced binaries carry a synthetic commit and are never staged.
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
#     --gate NAME[=EPOCH]   gate to force (repeatable; default: every changed gate)
#     --force-epoch N       early test epoch (default: replayed head epoch - window - 8)
#     --window W            epochs replayed after the forced activation (default 16)
#     --jobs N              concurrent replays (default 3)
#     --expect-slot N --expect-root HEX   head reported by the archivals for --source
#     --tests-allow-fail PKG  package whose test failures are reported, not fatal
#                           (repeatable; default: bloch = legacy/genesis3-node, the
#                           closed Genesis-3 PoW node outside the CI blocking set)
#     --skip-tests | --skip-forced | --allow-unsandboxed
#   env: CONTAINER_ENGINE (default docker; e.g. a `sudo -n docker` wrapper)
#
# Exit 0 and "VERDICT: PASS" only if every step passed.
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
FORCE_EPOCH="" WINDOW=16 JOBS=3 EXPECT_SLOT="" EXPECT_ROOT=""
SKIP_TESTS=0 SKIP_FORCED=0 UNSANDBOXED=0
GATE_ARGS=() ALLOW_FAIL=() ALLOW_FAIL_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --baseline-bin) BASELINE_BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --base-commit) BASE_COMMIT="$2"; shift 2 ;;
    --gate) GATE_ARGS+=("$2"); shift 2 ;;
    --force-epoch) FORCE_EPOCH="$2"; shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --expect-slot) EXPECT_SLOT="$2"; shift 2 ;;
    --expect-root) EXPECT_ROOT="$2"; shift 2 ;;
    --tests-allow-fail) ALLOW_FAIL+=("$2"); ALLOW_FAIL_SET=1; shift 2 ;;
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
[ "$ALLOW_FAIL_SET" = 1 ] || ALLOW_FAIL=(bloch)

die() { echo "qualify: FAIL - $*" >&2; exit 1; }
COMMIT="$(git -C "$REPO" rev-parse --verify --quiet "$COMMIT_ARG^{commit}")" || die "unknown commit $COMMIT_ARG"
BASE_COMMIT="$(git -C "$REPO" rev-parse --verify --quiet "$BASE_COMMIT^{commit}")" || die "unknown base commit"
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

# ── 2. workspace tests (in the background, alongside the replays) ─────────
run_tests() {
  local ctx="$OUT/test-ctx" tag="bloch-hf-qualify:$C12" trc passed failed
  mkdir -p "$ctx"
  git -C "$REPO" archive --format=tar "$COMMIT" | tar -xf - -C "$ctx"
  say "tests: image $tag (pinned toolchain, Dockerfile target build)"
  if ! "$ENGINE" buildx build --progress=plain --target build --load -t "$tag" \
    --build-arg "BLOCH_BUILD_COMMIT=$COMMIT" --build-arg "SOURCE_DATE_EPOCH=$SDE" \
    --file "$ctx/deploy/pos-release/Dockerfile" "$ctx" > "$OUT/tests-image.log" 2>&1; then
    record tests FAIL "test image build failed (tests-image.log)"; return 0
  fi
  rm -rf "$ctx"
  say "tests: cargo test --workspace --locked --no-fail-fast (log: $OUT/tests.log)"
  set +e
  "$ENGINE" run --rm --name "bloch-hf-qualify-tests-$C12-$$" \
    -e "BLOCH_BUILD_COMMIT=$COMMIT" -e BLOCH_BUILD_TREE_ASSERTION=clean -e CARGO_TERM_COLOR=never \
    "$tag" cargo test --workspace --locked --no-fail-fast > "$OUT/tests.log" 2>&1
  trc=$?
  set -e
  passed=$(grep -E '^test result:' "$OUT/tests.log" | awk '{s+=$4} END{print s+0}')
  failed=$(grep -E '^test result:' "$OUT/tests.log" | awk '{s+=$6} END{print s+0}')
  # Packages with a failing test target, from cargo's "-p <pkg> --<target>" hints.
  local failing blocking="" p a ok
  failing="$(grep -oE '`-p [A-Za-z0-9_-]+' "$OUT/tests.log" | awk '{print $2}' | sort -u | tr '\n' ' ')"
  for p in $failing; do
    ok=0; for a in "${ALLOW_FAIL[@]}"; do [ "$p" = "$a" ] && ok=1; done
    [ "$ok" = 1 ] || blocking="$blocking $p"
  done
  if [ "$trc" = 0 ]; then
    record tests PASS "$passed passed, $failed failed"
  elif [ -n "$failing" ] && [ -z "$blocking" ]; then
    grep -E '^test .* FAILED$' "$OUT/tests.log" | sort -u | head -20 || true
    record tests WARN "$passed passed, $failed failed, only in allowed package(s): $failing(tests.log)"
  else
    grep -E '^test .* FAILED$|^error(\[|:)' "$OUT/tests.log" | sort -u | head -40 || true
    record tests FAIL "rc=$trc, $passed passed, $failed failed; blocking package(s):${blocking:- none identified (build error?)} (tests.log)"
  fi
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
# replay <label> <binary> <source dir> <port> [replay args...]; output in replay/<label>.out
replay() {
  local label="$1" bin="$2" src="$3" port="$4"; shift 4
  set +e
  "$REPLAY" --candidate "$bin" --source "$src" --work "$OUT/replay/$label" --port-base "$port" \
    ${REPLAY_FLAGS[@]+"${REPLAY_FLAGS[@]}"} "$@" > "$OUT/replay/$label.out" 2>&1
  local rc=$?
  set -e
  echo "$rc" > "$OUT/replay/$label.rc"
  return 0
}
head_of() { awk '$1=="candidate" && NF==4 {print $2, $3, $4}' "$OUT/replay/$1.out" | tail -1; }
rc_of() { cat "$OUT/replay/$1.rc"; }
# Each replay gets its own loopback port range (relevant when not in a netns).
alloc() { PORT_NEXT=$((PORT_NEXT + 10)); P=$PORT_NEXT; }

# ── 3. configured-epoch replay of the whole copy ──────────────────────────
say "full replay: candidate and fleet baseline, from genesis, in parallel (~30 min each)"
expect=(); [ -z "$EXPECT_ROOT" ] || expect=(--expect-root "$EXPECT_ROOT" --expect-slot "$EXPECT_SLOT")
alloc; replay full-candidate "$BIN" "$SOURCE" "$P" ${expect[@]+"${expect[@]}"} & pids=($!)
alloc; replay full-baseline "$BASELINE_BIN" "$SOURCE" "$P" ${expect[@]+"${expect[@]}"} & pids+=($!)
wait "${pids[@]}"
ref_full="$(head_of full-candidate)"; base_full="$(head_of full-baseline)"
if [ "$(rc_of full-candidate)" = 0 ] && [ "$(rc_of full-baseline)" = 0 ] && [ -n "$ref_full" ] && [ "$ref_full" = "$base_full" ]; then
  record replay-configured PASS "head (slot blocks root) $ref_full, identical to baseline"
else
  tail -5 "$OUT/replay/full-candidate.out" "$OUT/replay/full-baseline.out"
  record replay-configured FAIL "candidate [$ref_full] rc=$(rc_of full-candidate) / baseline [$base_full] rc=$(rc_of full-baseline)"
  [ -z "$TESTS_PID" ] || wait "$TESTS_PID" || true
  die "configured-epoch replay did not pass; forced smoke tests are meaningless without it"
fi
read -r HEAD_SLOT _ _ <<<"$ref_full"
HEAD_EPOCH=$((HEAD_SLOT / SLOTS_PER_EPOCH))

# ── gates ─────────────────────────────────────────────────────────────────
gate_names=(); for g in ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}; do gate_names+=(--gate "${g%%=*}"); done
python3 -I "$GATES_PY" discover --repo "$REPO" --base "$BASE_COMMIT" --candidate "$COMMIT" \
  ${gate_names[@]+"${gate_names[@]}"} > "$OUT/gates.tsv"
say "gates (name, fleet value, candidate value, status):"; sed 's/^/    /' "$OUT/gates.tsv"
sched_bad=""
while IFS=$'\t' read -r name _ _ st; do
  case "$st" in
    scheduled:*) e="${st#scheduled:}"
      if [ "$e" -le "$HEAD_EPOCH" ]; then
        explicit=0; for g in ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}; do [ "${g%%=*}" = "$name" ] && explicit=1; done
        [ "$explicit" = 1 ] || sched_bad="$sched_bad $name(e$e<=head e$HEAD_EPOCH)"
      fi ;;
    inert) say "  NOTE $name is inert (u64::MAX): not scheduled in this build" ;;
    missing) sched_bad="$sched_bad $name(missing)" ;;
    *) say "  NOTE $name: $st (check by hand)" ;;
  esac
done < "$OUT/gates.tsv"
if [ -n "$sched_bad" ]; then
  record gate-schedule FAIL "changed gate at or before the replayed head:$sched_bad"
else
  record gate-schedule PASS "$(wc -l < "$OUT/gates.tsv" | tr -d ' ') gate(s); replayed head e$HEAD_EPOCH"
fi

# ── 4. forced early activation, one gate at a time ────────────────────────
if [ "$SKIP_FORCED" = 1 ]; then
  record forced SKIPPED "--skip-forced"
elif [ ! -s "$OUT/gates.tsv" ]; then
  record forced SKIPPED "no changed gate and no --gate given"
else
  default_e="${FORCE_EPOCH:-$((HEAD_EPOCH - WINDOW - 8))}"
  forced=()   # "name epoch"
  while IFS=$'\t' read -r name _ _ _; do
    e="$default_e"
    for g in ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}; do
      case "$g" in "$name="*) e="${g#*=}" ;; esac
    done
    case "$e" in ''|*[!0-9]*) die "bad forced epoch for $name: $e" ;; esac
    [ $(( (e + WINDOW) * SLOTS_PER_EPOCH )) -le "$HEAD_SLOT" ] || die "$name: forced epoch $e + window $WINDOW is beyond the replayed head e$HEAD_EPOCH"
    forced+=("$name $e")
  done < "$OUT/gates.tsv"

  # Slot-bounded prefixes and the configured candidate's head on each.
  epochs=$(printf '%s\n' "${forced[@]}" | awk '{print $2}' | sort -un)
  for e in $epochs; do
    python3 -I "$PREFIX_PY" --source "$SOURCE" --dest "$OUT/data/pre-e$e" --before-slot $((e * SLOTS_PER_EPOCH)) | sed 's/^/  pre-e'"$e"': /'
    python3 -I "$PREFIX_PY" --source "$SOURCE" --dest "$OUT/data/post-e$e" --before-slot $(((e + WINDOW) * SLOTS_PER_EPOCH)) | sed 's/^/  post-e'"$e"': /'
  done
  say "reference replays of the configured candidate on each prefix"
  pids=()
  for e in $epochs; do
    alloc; replay "ref-pre-e$e" "$BIN" "$OUT/data/pre-e$e" "$P" & pids+=($!)
    alloc; replay "ref-post-e$e" "$BIN" "$OUT/data/post-e$e" "$P" & pids+=($!)
  done
  wait "${pids[@]}"
  for e in $epochs; do
    for k in pre post; do
      [ "$(rc_of "ref-$k-e$e")" = 0 ] || { tail -5 "$OUT/replay/ref-$k-e$e.out"; die "configured candidate failed on the $k-e$e prefix"; }
    done
  done

  # Forced builds, serially (each is a full container build).
  for item in "${forced[@]}"; do
    read -r g e <<<"$item"
    d="$OUT/forced/$g-e$e"; mkdir -p "$d/tree"
    git -C "$REPO" archive --format=tar "$COMMIT" | tar -xf - -C "$d/tree"
    python3 -I "$GATES_PY" force --tree "$d/tree" --gate "$g" --epoch "$e" > "$d/patch.txt" \
      || { record "forced:$g" FAIL "could not patch"; continue; }
    (cd "$d/tree" && git init -q && git add -A \
      && GIT_AUTHOR_DATE="@$SDE" GIT_COMMITTER_DATE="@$SDE" git -c user.name=hf-qualify -c user.email=hf-qualify@invalid \
         commit -q -m "QUALIFICATION ONLY - NEVER RELEASE: $g forced to epoch $e on top of $COMMIT")
    say "forced build $g=e$e"
    if (cd "$d/tree" && CONTAINER_ENGINE="$ENGINE" scripts/build-pos-release-container.sh "$d/build") > "$d/build.log" 2>&1; then
      mv "$d/build/bloch-pos" "$d/bloch-pos-FORCED-$g-e$e"
      rm -f "$d/build/SHA256SUMS"
      echo "QUALIFICATION ONLY: $g forced to epoch $e. Never sign, stage or run on a network." > "$d/build/NEVER-RELEASE"
      rm -rf "$d/tree"
    else
      tail -20 "$d/build.log"; record "forced:$g" FAIL "forced build failed (forced/$g-e$e/build.log)"
    fi
  done

  # Forced replays: pre (must equal the configured head) then post (must cross cleanly).
  run_forced() {
    local g="$1" e="$2" d="$OUT/forced/$1-e$2" fb ref_pre ref_post h post_head
    fb="$d/bloch-pos-FORCED-$g-e$e"
    ref_pre="$(head_of "ref-pre-e$e")"; ref_post="$(head_of "ref-post-e$e")"
    read -r hs _ hr <<<"$ref_pre"
    replay "forced-$g-pre" "$fb" "$OUT/data/pre-e$e" "$3" --expect-slot "$hs" --expect-root "$hr"
    if [ "$(rc_of "forced-$g-pre")" != 0 ]; then
      echo "FAIL	pre-activation replay differs from the configured build (replay/forced-$g-pre.out)" > "$d/verdict"; return 0
    fi
    replay "forced-$g-post" "$fb" "$OUT/data/post-e$e" "$4"
    post_head="$(head_of "forced-$g-post")"
    if [ "$(rc_of "forced-$g-post")" = 0 ]; then
      if [ "$post_head" = "$ref_post" ]; then
        echo "PASS	inert-on-history: crossed e$e and replayed to e$((e + WINDOW)) unchanged" > "$d/verdict"
      else
        echo "FAIL	replayed but head [$post_head] != configured [$ref_post]" > "$d/verdict"
      fi
    elif grep -q 'did not re-apply to its header state root' "$OUT/replay/forced-$g-post.out"; then
      h="$(grep -h 'apply refused' "$OUT/replay/forced-$g-post/candidate.log" 2>/dev/null | head -1 | cut -c1-160)"
      echo "PASS	diverged-after-activation (clean consensus rejection at or after slot $((e * SLOTS_PER_EPOCH))): ${h:-no reason logged}" > "$d/verdict"
    else
      echo "FAIL	post-activation replay crashed or stopped without a consensus verdict (replay/forced-$g-post.out)" > "$d/verdict"
    fi
  }
  pids=()
  for item in "${forced[@]}"; do
    read -r g e <<<"$item"
    [ -x "$OUT/forced/$g-e$e/bloch-pos-FORCED-$g-e$e" ] || continue
    alloc; p_pre=$P; alloc
    run_forced "$g" "$e" "$p_pre" "$P" & pids+=($!)
    # Throttle: keep at most JOBS forced pipelines alive.
    while [ "$(jobs -rp | grep -vx "${TESTS_PID:-none}" | wc -l)" -ge "$JOBS" ]; do sleep 20; done
  done
  [ ${#pids[@]} -eq 0 ] || wait "${pids[@]}"
  for item in "${forced[@]}"; do
    read -r g e <<<"$item"
    v="$OUT/forced/$g-e$e/verdict"
    [ -f "$v" ] || continue
    IFS=$'\t' read -r st detail < "$v"
    record "forced:$g@e$e" "$st" "$detail"
  done
fi

# ── verdict ───────────────────────────────────────────────────────────────
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
