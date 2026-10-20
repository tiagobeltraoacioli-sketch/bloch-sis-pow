#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# "Gates off is byte-identical" guard for hard-fork ports.
#
#   scripts/hf-replay-guard/check.sh <branch-or-commit> [...]
#
# For each target, proves that with its new rules not yet active the code
# computes exactly what the reference release computes:
#
#   (a) fixture chains — deterministic-shape chains built ONCE by the
#       reference release's own block generator (real hybrid signatures,
#       committee attestations, transfers; early epochs, a non-justifying
#       regime, skipped slots, a leak-and-recovery gap; epochs 0..10, i.e.
#       the pre-800 rule set) are replayed through Engine::ingest_replay. Per
#       block: verdict, post-state root, justified and finalized checkpoints.
#   (a') golden tests — the reference release's bloch-pos-committee
#       integration tests (pinned roots, wire tags, e2e chains, L2 fixtures)
#       compiled against the target's library.
#   (b) mainnet headers — >=2000 finalized mainnet headers including slot
#       187200 (first slot of epoch 5850), fetched read-only over public RPC,
#       re-encoded by the target: id, proposal signing root, round trip.
#
# Every dump is diffed line by line against the reference dump; the first
# differing line names the first divergent slot.
#
# Nothing here touches a network other than the read-only RPC fetch, and
# nothing touches any host. Every build happens in a detached worktree under
# the cache directory, never in the caller's tree.
#
# Environment:
#   HF_GUARD_REF     reference commit (default b4a21fb657d0beb17f64c62889b605c9a7a2d031)
#   HF_GUARD_CACHE   cache dir (default ~/.cache/hf-replay-guard)
#   HF_GUARD_RPC     RPC for the sample (default https://blochl1.com/g4rpc)
#   HF_GUARD_SKIP_GOLDEN=1   skip (a')
#
# Exit: 0 all targets PASS, 1 any FAIL, 2 usage/infra error.
set -uo pipefail

REF="${HF_GUARD_REF:-b4a21fb657d0beb17f64c62889b605c9a7a2d031}"
CACHE="${HF_GUARD_CACHE:-$HOME/.cache/hf-replay-guard}"
RPC="${HF_GUARD_RPC:-https://blochl1.com/g4rpc}"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
GUARD_TREE="$(cd "$HERE/../.." && pwd -P)"
REPO="$(git -C "$GUARD_TREE" rev-parse --git-common-dir)"
[ $# -ge 1 ] || { sed -n 2,40p "$0"; exit 2; }
# --all: every codex/hf*-20261020 branch with commits beyond the reference,
# except this guard's own branch.
if [ "$1" = --all ]; then
  set -- $(git --git-dir="$REPO" for-each-ref --format='%(refname:short)' 'refs/heads/codex/hf*-20261020' \
    | while read -r b; do
        [ "$b" = codex/hf-replay-guard-20261020 ] && continue
        [ "$(git --git-dir="$REPO" rev-list --count "$REF..$b")" -gt 0 ] && echo "$b"
      done)
  [ $# -ge 1 ] || { echo "no codex/hf*-20261020 branch has commits beyond ${REF:0:10}"; exit 0; }
fi
# Results are cached per (target sha, guard version): an unchanged branch is
# not rebuilt on the next pass.
GUARD_VER="$(cat "$HERE/check.sh" "$HERE/overlay.sh" "$GUARD_TREE/crates/bloch-pos-node/src/engine/hf_replay_guard.rs" | shasum -a 256 | cut -c1-10)"

# One target dir PER TREE. Cargo leaves the source path out of a path
# package's artifact hash, so two worktrees sharing a target dir silently
# reuse each other's compiled bloch-pos-committee / bloch-crypto — observed
# here: a branch "replayed" with a sibling's library. Never share it.
# Same opt-level and overflow-checks as the release profile (overflow
# behaviour is consensus-relevant and stays identical); only fat LTO and the
# single codegen unit are relaxed, which change build time, not semantics.
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
mkdir -p "$CACHE/src" "$CACHE/dumps" "$CACHE/logs" "$CACHE/mainnet"
FIX="$CACHE/fixtures-${REF:0:12}"
SAMPLE="$CACHE/mainnet/sample.jsonl"
NICE="nice -n 10"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }

# Detached worktree at <sha>, overlaid with the guard harness.
prepare_tree() { # $1=label $2=sha
  local d="$CACHE/src/$1"
  if [ ! -e "$d/.git" ]; then
    git --git-dir="$REPO" worktree add --detach -f "$d" "$2" >/dev/null 2>&1 || return 1
  fi
  git -C "$d" checkout --detach -f "$2" >/dev/null 2>&1 || return 1
  git -C "$d" clean -fdq -e /target >/dev/null 2>&1
  "$HERE/overlay.sh" "$GUARD_TREE" "$d" || return 1
  echo "$d"
}

# Run one ignored guard test in tree $1; extra env in "$@".
run_guard() { # $1=tree $2=test-name $3=logfile, rest env
  local t="$1" name="$2" lf="$3"; shift 3
  ( cd "$t" && env CARGO_TARGET_DIR="$t/target" "$@" $NICE cargo test --release -p bloch-pos-node --bin bloch-pos \
      "engine::hf_replay_guard::$name" -- --ignored --exact --nocapture --test-threads=1 ) >"$lf" 2>&1
}

build_guard() { # $1=tree $2=logfile
  ( cd "$1" && CARGO_TARGET_DIR="$1/target" $NICE cargo test --release -p bloch-pos-node --bin bloch-pos --no-run ) >"$2" 2>&1
}

# First differing line of two dumps -> "slot <n> (<context>)".
first_divergence() { # $1=ref $2=got $3=kind
  python3 -I - "$1" "$2" "$3" <<'PY'
import sys
ref = open(sys.argv[1]).read().splitlines()
got = open(sys.argv[2]).read().splitlines()
kind = sys.argv[3]
for i in range(max(len(ref), len(got))):
    r = ref[i] if i < len(ref) else "<missing>"
    g = got[i] if i < len(got) else "<missing>"
    if r != g:
        f = (r if r != "<missing>" else g).split()
        if kind == "fixtures":
            where = f"{f[0]} slot {f[2]} (block #{f[1]})" if len(f) > 2 else r
        else:
            where = f"slot {f[0]}"
        print(f"{where}\n    ref: {r}\n    got: {g}")
        sys.exit(1)
print("identical")
PY
}

# ── reference ──────────────────────────────────────────────────────────────
ensure_reference() {
  REFTREE="$(prepare_tree ref "$REF")" || { log "cannot prepare reference tree"; exit 2; }
  if [ ! -s "$CACHE/dumps/ref-${REF:0:12}.fixtures" ] || [ ! -f "$FIX/.complete" ] \
     || [ ! -s "$CACHE/dumps/ref-${REF:0:12}.mainnet" ] || [ "$SAMPLE" -nt "$CACHE/dumps/ref-${REF:0:12}.mainnet" ]; then
    log "building reference ${REF:0:12}"
    build_guard "$REFTREE" "$CACHE/logs/ref-build.log" || { log "reference build failed: $CACHE/logs/ref-build.log"; exit 2; }
  fi
  if [ ! -f "$FIX/.complete" ]; then
    log "generating fixtures with the reference generator -> $FIX"
    rm -rf "$FIX"; mkdir -p "$FIX"
    run_guard "$REFTREE" hf_guard_generate_fixtures "$CACHE/logs/ref-generate.log" HF_GUARD_FIXTURE_DIR="$FIX" \
      || { log "fixture generation failed: $CACHE/logs/ref-generate.log"; exit 2; }
    ( cd "$FIX" && find . -type f -name '*.bin' | sort | xargs shasum -a 256 > SHA256SUMS ) && touch "$FIX/.complete"
  fi
  if [ ! -s "$SAMPLE" ]; then
    log "fetching mainnet header sample from $RPC"
    python3 -I "$HERE/fetch_mainnet_sample.py" "$SAMPLE" --rpc "$RPC" || { log "sample fetch failed"; exit 2; }
  fi
  for kind in fixtures mainnet; do
    local out="$CACHE/dumps/ref-${REF:0:12}.$kind"
    if [ ! -s "$out" ] || { [ "$kind" = mainnet ] && [ "$SAMPLE" -nt "$out" ]; }; then
      log "reference dump: $kind"
      if [ "$kind" = fixtures ]; then
        run_guard "$REFTREE" hf_guard_replay_fixtures "$CACHE/logs/ref-$kind.log" HF_GUARD_FIXTURE_DIR="$FIX" HF_GUARD_OUT="$out"
      else
        run_guard "$REFTREE" hf_guard_mainnet_headers "$CACHE/logs/ref-$kind.log" HF_GUARD_MAINNET_SAMPLE="$SAMPLE" HF_GUARD_OUT="$out"
      fi || { log "reference $kind dump failed"; rm -f "$out"; exit 2; }
    fi
  done
  local rg="$CACHE/dumps/ref-${REF:0:12}.golden"
  if [ "${HF_GUARD_SKIP_GOLDEN:-0}" != 1 ] && [ ! -f "$rg" ]; then
    log "reference golden tests"
    ( cd "$REFTREE" && CARGO_TARGET_DIR="$REFTREE/target" $NICE cargo test --release -p bloch-pos-committee --test '*' --no-fail-fast ) >"$CACHE/logs/ref-golden.log" 2>&1
    grep -qE '^error\[|^error: could not compile' "$CACHE/logs/ref-golden.log" && { log "reference golden tests do not build"; exit 2; }
    grep -E '^test .* \.\.\. FAILED$' "$CACHE/logs/ref-golden.log" | awk '{print $2}' | sort > "$rg"
  fi
  # Sanity on the reference itself: every fixture block accepted, every
  # mainnet id reproduced. Otherwise the guard proves nothing.
  if grep -qE ' (REJECT|PANIC) ' "$CACHE/dumps/ref-${REF:0:12}.fixtures"; then
    log "reference rejects its own fixture — harness broken"; exit 2; fi
  if grep -q 'ID-MISMATCH\|roundtrip=false' "$CACHE/dumps/ref-${REF:0:12}.mainnet"; then
    log "reference does not reproduce mainnet ids — harness broken"; exit 2; fi
}

# ── one target ─────────────────────────────────────────────────────────────
check_target() { # $1=branch-or-commit
  local tgt="$1" sha label tree verdict=PASS notes=()
  sha="$(git --git-dir="$REPO" rev-parse --verify -q "$tgt^{commit}")" || { echo "$tgt  ERROR  unknown ref"; return 2; }
  label="t-$(printf '%s' "$tgt" | tr -c 'A-Za-z0-9._-' '_')"
  local base="$CACHE/dumps/$label-${sha:0:12}-g$GUARD_VER"
  if [ -s "$base.verdict" ]; then cat "$base.verdict"; head -1 "$base.verdict" | grep -q '  PASS  '; return; fi
  # A port must sit on the reference. A target that does not contain it is a
  # different chain line; comparing it would only report the missing commits.
  if ! git --git-dir="$REPO" merge-base --is-ancestor "$REF" "$sha"; then
    local mb; mb="$(git --git-dir="$REPO" merge-base "$REF" "$sha")"
    echo "$tgt ${sha:0:10}  FAIL  NOT-BASED-ON-REFERENCE (merge-base ${mb:0:10}; $(git --git-dir="$REPO" rev-list --count "$mb..$REF") reference commits missing)" | tee "$base.verdict"
    return 1
  fi
  # Short-cut by identity: the guard compiles only these paths. A target that
  # changes none of them compiles to the reference's code by construction.
  if git --git-dir="$REPO" diff --quiet "$REF" "$sha" -- crates Cargo.toml Cargo.lock rust-toolchain.toml; then
    echo "$tgt ${sha:0:10}  PASS  identical consensus sources (no change under crates/, Cargo.*, rust-toolchain.toml)" | tee "$base.verdict"
    return 0
  fi
  tree="$(prepare_tree "$label" "$sha")" || { echo "$tgt ${sha:0:10}  FAIL  overlay could not be applied (engine.rs / replay_bench.rs anchors moved)"; return 1; }
  log "$tgt ${sha:0:10}: build"
  if ! build_guard "$tree" "$base.build.log"; then
    echo "$tgt ${sha:0:10}  FAIL  BUILD (see $base.build.log)"; return 1
  fi
  log "$tgt: fixtures replay"
  run_guard "$tree" hf_guard_replay_fixtures "$base.fixtures.log" HF_GUARD_FIXTURE_DIR="$FIX" HF_GUARD_OUT="$base.fixtures"
  local fx; fx="$(first_divergence "$CACHE/dumps/ref-${REF:0:12}.fixtures" "$base.fixtures" fixtures)" \
    || { verdict=FAIL; notes+=("fixtures: first divergent $fx"); }
  log "$tgt: mainnet headers"
  run_guard "$tree" hf_guard_mainnet_headers "$base.mainnet.log" HF_GUARD_MAINNET_SAMPLE="$SAMPLE" HF_GUARD_OUT="$base.mainnet"
  local mn; mn="$(first_divergence "$CACHE/dumps/ref-${REF:0:12}.mainnet" "$base.mainnet" mainnet)" \
    || { verdict=FAIL; notes+=("mainnet: first divergent $mn"); }
  local gold="skipped"
  if [ "${HF_GUARD_SKIP_GOLDEN:-0}" != 1 ]; then
    log "$tgt: reference golden tests against target library"
    # Reference integration tests (and their fixtures) over the target's
    # bloch-pos-committee; the target's own src/ is left untouched.
    rm -rf "$tree/crates/bloch-pos-committee/tests"
    cp -R "$REFTREE/crates/bloch-pos-committee/tests" "$tree/crates/bloch-pos-committee/tests"
    # A reference test target that no longer COMPILES against the target
    # (typically an exhaustive match over an enum the port extended) proves
    # nothing either way; it is dropped and named, and the rest still run.
    local dropped="" try
    for try in 1 2 3 4; do
      ( cd "$tree" && CARGO_TARGET_DIR="$tree/target" $NICE cargo test --release -p bloch-pos-committee --test '*' --no-fail-fast ) >"$base.golden.log" 2>&1
      local bad; bad="$(grep -oE '^error: could not compile `bloch-pos-committee` \(test "[A-Za-z0-9_]+"\)' "$base.golden.log" \
        | sed -E 's/.*\(test "([^"]+)"\)/\1/' | sort -u)"
      [ -n "$bad" ] || break
      for b in $bad; do rm -f "$tree/crates/bloch-pos-committee/tests/$b.rs"; dropped="$dropped$b "; done
    done
    local failed; failed="$(grep -E '^test .* \.\.\. FAILED$' "$base.golden.log" | awk '{print $2}' | sort \
      | comm -23 - "$CACHE/dumps/ref-${REF:0:12}.golden" | tr '\n' ' ')"
    if grep -qE '^error\[|^error: could not compile' "$base.golden.log"; then
      gold="BUILD-FAIL"; verdict=FAIL; notes+=("golden: reference tests do not compile against target ($base.golden.log)")
    elif [ -n "$failed" ]; then
      gold="FAIL"; verdict=FAIL; notes+=("golden: $failed")
    else
      gold="OK($(grep -cE '^test .* \.\.\. ok$' "$base.golden.log"))"
    fi
    [ -n "$dropped" ] && notes+=("golden: not comparable (reference test no longer compiles against the target's extended types): $dropped")
    git -C "$tree" checkout -q -- crates/bloch-pos-committee/tests 2>/dev/null; git -C "$tree" clean -fdq crates/bloch-pos-committee/tests
  fi
  local nfx nmn; nfx="$(grep -c ' ACCEPT ' "$base.fixtures" 2>/dev/null)"; nmn="$(grep -c ID-MATCH "$base.mainnet" 2>/dev/null)"
  { echo "$tgt ${sha:0:10}  $verdict  fixtures=${nfx:-0} blocks, mainnet=${nmn:-0} headers, golden=$gold"
    for n in "${notes[@]+"${notes[@]}"}"; do echo "    $n"; done; } | tee "$base.verdict"
  [ "$verdict" = PASS ]
}

ensure_reference
log "reference: $(grep -c ' ACCEPT ' "$CACHE/dumps/ref-${REF:0:12}.fixtures") fixture blocks, $(grep -c ID-MATCH "$CACHE/dumps/ref-${REF:0:12}.mainnet") mainnet headers ($(awk '{print $1}' "$SAMPLE" >/dev/null; wc -l < "$SAMPLE" | tr -d ' ') in sample; slot 187200 $(grep -q '"slot": 187200' "$SAMPLE" && echo present || echo ABSENT))"
rc=0
for t in "$@"; do check_target "$t" || rc=1; done
exit $rc
