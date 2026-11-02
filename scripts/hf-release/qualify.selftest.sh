#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-test of the qualification kit that needs no container engine, network
# or compile: bash, git and python3 only (runs on a Mac with bash 3.2).
#
#   1. syntax of every kit script; shellcheck when installed
#      (SHELLCHECK=<path> picks the binary; REQUIRE_SHELLCHECK=1 makes a
#      missing shellcheck a failure);
#   2. fresh-build.py check on real buildkit logs from the 2026-10 qualifications
#      (testdata/): a fresh canonical and a fresh forced build pass; the stale
#      79.74 kB context of the broken 78d4921c forced build and a canonical
#      build with every RUN step CACHED are refused;
#   3. the generated fresh engine: --no-cache and a context prune before every
#      `buildx build`, everything else passed through;
#   4. qualify.sh argument refusals;
#   5. qualify.sh --dry-run on a throwaway two-commit repo that carries this
#      tree's real params.rs, hard_forks.rs, Cargo files and release build
#      script: plan, forced patches (incl. --relax-order) and predicted
#      digests; a patch that leaves the source unchanged and a patched tree
#      that hashes to --fleet-digest are refused; a gate before the index
#      head fails the schedule;
#   6. qualify.sh with a FAKE container engine that replays the testdata logs:
#      the canonical build is refused on a cached or stale context, a forced
#      build is refused on a stale context, and a forced binary that reports
#      the release digest is refused as a stale build.
#
# usage: scripts/hf-release/qualify.selftest.sh
set -euo pipefail

KIT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$KIT/../.." && pwd)"
TESTDATA="$KIT/testdata"
SCOPE_78D=9749759 # source-digest scope of 78d4921c in bytes (357 files)
tmp="$(mktemp -d "${TMPDIR:-/tmp}/qualify-selftest.XXXXXX")"
trap '[ "${KEEP_SELFTEST_TMP:-0}" = 1 ] && echo "kept $tmp" || rm -rf "$tmp"' EXIT

passes=0 failures=0
ok() { passes=$((passes + 1)); echo "ok   $*"; }
bad() { failures=$((failures + 1)); echo "FAIL $*"; }
# check <description> <command...>: the command must succeed.
check() { local d="$1"; shift; if "$@" > "$tmp/last.out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/     /' "$tmp/last.out" | tail -15; fi; }
# refuse <description> <expected exit> <command...>: the command must exit with that code.
refuse() {
  local d="$1" want="$2" rc=0; shift 2
  "$@" > "$tmp/last.out" 2>&1 || rc=$?
  if [ "$rc" = "$want" ]; then ok "$d"; else bad "$d (exit $rc, expected $want)"; sed 's/^/     /' "$tmp/last.out" | tail -15; fi
}
# says <file> <text> <description>: the file must contain the text.
says() { if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3"; sed 's/^/     /' "$1" | tail -15; fi; }

# ── 1. syntax and shellcheck ──────────────────────────────────────────────
for f in "$KIT"/*.sh; do check "bash -n ${f##*/}" bash -n "$f"; done
for f in "$KIT"/*.py; do
  check "python parses ${f##*/}" python3 -I -c 'import ast, sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$f"
done
SHELLCHECK="${SHELLCHECK:-shellcheck}"
if command -v "$SHELLCHECK" >/dev/null 2>&1; then
  check "shellcheck qualify.sh qualify.selftest.sh" "$SHELLCHECK" "$KIT/qualify.sh" "$KIT/qualify.selftest.sh"
  python3 -I "$KIT/fresh-build.py" engine --engine docker --out "$tmp/engine-fresh.sc"
  check "shellcheck the generated fresh engine" "$SHELLCHECK" "$tmp/engine-fresh.sc"
elif [ "${REQUIRE_SHELLCHECK:-0}" = 1 ]; then
  bad "shellcheck is not installed (REQUIRE_SHELLCHECK=1)"
else
  echo "skip shellcheck (not installed; REQUIRE_SHELLCHECK=1 makes this a failure)"
fi

# ── 2. fresh-build.py check on real logs ──────────────────────────────────
FB="$KIT/fresh-build.py"
fb_check() { python3 -I "$FB" check --log "$@"; }
check "fresh canonical build (fa980367, 53.87 MB context) passes" \
  fb_check "$TESTDATA/buildkit-fresh-canonical-fa980367.txt" --min-context-bytes "$SCOPE_78D"
check "fresh forced build (fa980367 armed) passes" \
  fb_check "$TESTDATA/buildkit-fresh-forced-fa980367.txt" --min-context-bytes "$SCOPE_78D"
refuse "stale 79.74 kB context of the broken 78d4921c forced build is refused" 1 \
  fb_check "$TESTDATA/buildkit-stale-context-forced-78d4921c.txt" --min-context-bytes "$SCOPE_78D"
says "$tmp/last.out" "79740 bytes, below the $SCOPE_78D-byte" "  ... with the transferred size"
refuse "canonical build with every RUN step CACHED is refused" 1 \
  fb_check "$TESTDATA/buildkit-cached-compile-canonical-fa980367.txt" --min-context-bytes "$SCOPE_78D"
says "$tmp/last.out" "[build 6/7] RUN BLOCH_BUILD_COMMIT" "  ... naming the cached compile step"
refuse "the stale log passes the CACHED rule alone (why the size rule exists)" 0 \
  fb_check "$TESTDATA/buildkit-stale-context-forced-78d4921c.txt" --no-context-floor
printf '#0 building with "default" instance using docker driver\n#1 [internal] load build definition from Dockerfile\n#1 DONE 0.0s\n#2 [build 1/2] RUN true\n#2 DONE 1.0s\n' > "$tmp/noctx.log"
refuse "a build without a context step is refused" 1 fb_check "$tmp/noctx.log" --min-context-bytes 1
: > "$tmp/empty.log"
refuse "an empty log is refused" 1 fb_check "$tmp/empty.log" --min-context-bytes 1
refuse "a floor of 0 is a usage error" 2 fb_check "$tmp/empty.log" --min-context-bytes 0
{
  cat "$TESTDATA/buildkit-fresh-canonical-fa980367.txt"
  printf '#0 building with "default" instance using docker driver\n#1 [internal] load build definition from Tests.Dockerfile\n#1 DONE 0.0s\n'
  printf '#5 [internal] load build context\n#5 transferring context: 1.20kB done\n#5 DONE 0.0s\n#6 [2/3] COPY . .\n#6 CACHED\n'
} > "$tmp/two.log"
refuse "a second build in the same log with a CACHED COPY is refused" 1 fb_check "$tmp/two.log" --no-context-floor
says "$tmp/last.out" "build 2:" "  ... attributed to build 2"
printf '#1 [internal] load build definition from Dockerfile\n#2 [internal] load build context\n#2 transferring context: 1.5GB 9.0s done\n#3 [b 1/1] COPY . .\n#3 DONE 1s\n' > "$tmp/gb.log"
check "GB units parse (1.5GB >= 1,500,000,000 bytes)" fb_check "$tmp/gb.log" --min-context-bytes 1500000000

# ── 3. the generated fresh engine ─────────────────────────────────────────
cat > "$tmp/stub-engine" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "${STUB_LOG:?}"
if [ "${1:-}" = buildx ] && [ "${2:-}" = prune ] && [ -n "${STUB_PRUNE_FAILS:-}" ]; then exit 3; fi
exit 0
EOF
chmod 700 "$tmp/stub-engine"
python3 -I "$FB" engine --engine "$tmp/stub-engine" --out "$tmp/engine-fresh"
export STUB_LOG="$tmp/stub.log"
: > "$STUB_LOG"; "$tmp/engine-fresh" buildx build --progress=plain -t x "$tmp"
printf 'buildx prune -f --filter type=source.local\nbuildx build --no-cache --progress=plain -t x %s\n' "$tmp" > "$tmp/want.log"
check "engine: prune synced contexts, then buildx build --no-cache" cmp -s "$tmp/want.log" "$STUB_LOG"
: > "$STUB_LOG"; STUB_PRUNE_FAILS=1 "$tmp/engine-fresh" buildx build -t y .
check "engine: a failed prune does not stop the build (the log check still guards)" grep -qx -- 'buildx build --no-cache -t y .' "$STUB_LOG"
: > "$STUB_LOG"; "$tmp/engine-fresh" run --rm img true; "$tmp/engine-fresh" buildx du
printf 'run --rm img true\nbuildx du\n' > "$tmp/want.log"
check "engine: other commands pass through unchanged" cmp -s "$tmp/want.log" "$STUB_LOG"

# ── 4. qualify.sh argument refusals ───────────────────────────────────────
Q="$KIT/qualify.sh"
refuse "qualify: no arguments" 2 "$Q"
refuse "qualify: unknown argument" 2 "$Q" HEAD --source "$tmp" --bogus
refuse "qualify: --forced-only with --skip-forced" 2 "$Q" HEAD --source "$tmp" --forced-only --skip-forced
refuse "qualify: malformed --fleet-digest" 2 "$Q" HEAD --source "$tmp" --forced-only --fleet-digest 35c2b943
refuse "qualify: malformed --forced-set" 2 "$Q" HEAD --source "$tmp" --forced-only --forced-set nolabel
refuse "qualify: malformed --expect-halt" 2 "$Q" HEAD --source "$tmp" --forced-only --expect-halt armed=abc
check "qualify: --help documents --dry-run and the fresh context rule" sh -c "'$Q' --help | grep -q -- '--dry-run' && '$Q' --help | grep -q 'Fresh build context'"

# ── 5. dry run on a throwaway repo ────────────────────────────────────────
R="$tmp/repo"
mkdir -p "$R/scripts/hf-release" "$R/scripts/l2-activation" "$R/crates/bloch-pos-committee/src" \
  "$R/crates/bloch-pos-node" "$R/deploy/pos-release"
git -C "$R" init -q
for f in "$KIT"/*.py "$KIT"/*.sh "$KIT"/Tests.Dockerfile "$KIT"/Tests.Dockerfile.dockerignore; do cp "$f" "$R/scripts/hf-release/"; done
for f in crates/bloch-pos-committee/src/params.rs crates/bloch-pos-committee/src/hard_forks.rs \
         crates/bloch-pos-committee/Cargo.toml crates/bloch-pos-node/Cargo.toml \
         crates/bloch-pos-node/rust-toolchain.toml Cargo.toml Cargo.lock rust-toolchain.toml \
         scripts/build-pos-release-container.sh deploy/pos-release/Dockerfile; do
  cp "$REPO/$f" "$R/$f"
done
cat > "$R/scripts/l2-activation/replay-mainnet-history.sh" <<'EOF'
#!/usr/bin/env bash
# selftest stub: records that a replay was started; prints no head.
echo "$*" >> "$(dirname "$0")/../../../replays-started"
exit 0
EOF
chmod 755 "$R/scripts/l2-activation/replay-mainnet-history.sh"
gitc() { git -C "$R" -c user.name=selftest -c user.email=selftest@invalid "$@"; }
gitc add -A; gitc commit -qm fleet
BASE="$(git -C "$R" rev-parse HEAD)"
# The candidate moves one gate (HF2_GROWTH_CAP_EPOCH 7270 -> 7271).
python3 -I - "$R/crates/bloch-pos-committee/src/params.rs" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
old = "pub const HF2_GROWTH_CAP_EPOCH: u64 = 7270;"
assert s.count(old) == 1, "params.rs: HF2_GROWTH_CAP_EPOCH definition moved; update the selftest"
open(p, "w").write(s.replace(old, "pub const HF2_GROWTH_CAP_EPOCH: u64 = 7271;"))
EOF
gitc commit -qam candidate
CAND="$(git -C "$R" rev-parse HEAD)"
# Synthetic history: one 4-byte frame per epoch up to the given head epoch.
make_source() {
  mkdir -p "$1"; : > "$1/meta.bin"
  python3 -I - "$1" "$2" <<'EOF'
import struct, sys
d, head = sys.argv[1], int(sys.argv[2])
with open(f"{d}/blocks.idx", "wb") as idx, open(f"{d}/blocks.log", "wb") as log:
    idx.write(b"BPOSIDX1")
    for e in range(head + 1):
        # frame = u32 LE length + payload (log-prefix.py checks both)
        idx.write(struct.pack("<QQI", e * 32, e * 8, 4)); log.write(struct.pack("<I", 4) + b"\0" * 4)
EOF
}
make_source "$tmp/src6600" 6600
make_source "$tmp/src7300" 7300
printf '#!/bin/sh\nexit 0\n' > "$tmp/baseline"; chmod 755 "$tmp/baseline"
RQ="$R/scripts/hf-release/qualify.sh"
rq() { CONTAINER_ENGINE=/nonexistent/engine "$RQ" "$@"; }

refuse "dry run: plan with the armed set and a relaxed single-gate set" 0 \
  rq "$CAND" --source "$tmp/src6600" --baseline-bin "$tmp/baseline" --base-commit "$BASE" \
     --out "$tmp/dry1" --dry-run --relax-order --forced-set claim=HF1_CLAIM_FINALITY_EPOCH=5860
O="$tmp/dry1"
says "$tmp/last.out" "VERDICT: DRY-RUN" "  ... verdict DRY-RUN"
# shellcheck disable=SC2016 # awk program, not shell
check "  ... gates.tsv lists HF2_GROWTH_CAP_EPOCH scheduled:7271" awk -F'\t' '$1=="HF2_GROWTH_CAP_EPOCH" && $4=="scheduled:7271" {f=1} END {exit !f}' "$O/gates.tsv"
check "  ... armed set shifted to head - window - 8 (e6576)" grep -q 'HF2_GROWTH_CAP_EPOCH=6576' "$O/forced/armed/set"
check "  ... five ordering rules relaxed in the claim tree" sh -c "[ \"\$(grep -c relaxed '$O/forced/claim/patch.txt')\" = 5 ]"
check "  ... gate-schedule PASS against the index head" grep -qE '^gate-schedule	PASS' "$O/RESULTS.tsv"
check "  ... build, tests and replay rows are SKIPPED" sh -c "grep -qE '^build	SKIPPED' '$O/RESULTS.tsv' && grep -qE '^tests	SKIPPED' '$O/RESULTS.tsv' && grep -qE '^replay-configured	SKIPPED' '$O/RESULTS.tsv'"
rel="$(sed -n 's/^release_source_digest=//p' "$O/qualify.env")"
d_armed="$(cat "$O/forced/armed/expected-source-digest")"; d_claim="$(cat "$O/forced/claim/expected-source-digest")"
check "  ... predicted forced digests differ from the release and from each other" \
  sh -c "[ -n '$rel' ] && [ '$d_armed' != '$rel' ] && [ '$d_claim' != '$rel' ] && [ '$d_armed' != '$d_claim' ]"
check "  ... fresh engine written with --no-cache" grep -q -- '--no-cache' "$O/engine-fresh"
check "  ... both fleet release digests (78d4921c, fa980367) are refused by default" \
  sh -c "grep -q '^fleet_source_digests=.*35c2b943d42ec370d087ac69c417492df4063e51547482cfc8346aeb19b1f177' '$O/qualify.env' && grep -q 'a4c4af850fec3efd66485558282e1ca9381a70874750ab2373be3e23fd866308' '$O/qualify.env'"
check "  ... no replay was started" test ! -e "$tmp/replays-started"
check "  ... no worktree left behind" sh -c "[ \"\$(git -C '$R' worktree list | wc -l | tr -d ' ')\" = 1 ]"

refuse "dry run: a forced set that leaves the source unchanged is refused" 1 \
  rq "$CAND" --source "$tmp/src7300" --base-commit "$BASE" \
     --out "$tmp/dry2" --dry-run --forced-only --gates-only --forced-set same=HF2_GROWTH_CAP_EPOCH=7271
check "  ... verdict names the identical source" grep -q 'identical to the release' "$tmp/dry2/forced/same/verdict"

refuse "dry run: a patched tree that hashes to --fleet-digest is refused" 1 \
  rq "$CAND" --source "$tmp/src6600" --baseline-bin "$tmp/baseline" --base-commit "$BASE" \
     --out "$tmp/dry3" --dry-run --gates-only --relax-order --forced-set claim=HF1_CLAIM_FINALITY_EPOCH=5860 \
     --fleet-digest "$d_claim"
check "  ... verdict names the fleet digest" grep -q "a fleet release source-digest ($d_claim)" "$tmp/dry3/forced/claim/verdict"

refuse "dry run: a gate at or before the source head fails the schedule" 1 \
  rq "$CAND" --source "$tmp/src7300" --baseline-bin "$tmp/baseline" --base-commit "$BASE" --out "$tmp/dry4" --dry-run
check "  ... gate-schedule FAIL names HF2_GROWTH_CAP_EPOCH" grep -qE '^gate-schedule	FAIL.*HF2_GROWTH_CAP_EPOCH' "$tmp/dry4/RESULTS.tsv"

refuse "an existing --out is refused" 1 \
  rq "$CAND" --source "$tmp/src6600" --baseline-bin "$tmp/baseline" --base-commit "$BASE" --out "$tmp/dry1" --dry-run
refuse "a candidate that does not descend from the fleet base is refused" 1 \
  rq "$BASE" --source "$tmp/src6600" --baseline-bin "$tmp/baseline" --base-commit "$CAND" --out "$tmp/dry5" --dry-run

# ── 6. fake container engine replaying the testdata logs ──────────────────
# Build n (1, 2, ...) prints FAKE_LOG_<n> (default FAKE_LOG) as its buildkit
# log and exports a fake bloch-pos whose --version reports the source-digest
# of the context it was given, or the digest in FAKE_DIGEST_<n> if set.
cat > "$tmp/fake-engine" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "${FAKE_STATE:?}/calls"
[ "${1:-}" = buildx ] || exit 0
[ "${2:-}" = build ] || exit 0
shift 2
n=$(( $(cat "$FAKE_STATE/n" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE_STATE/n"
dest="" commit="" sde="" ctx=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) dest="${2#type=local,dest=}"; shift 2 ;;
    --build-arg) case "$2" in BLOCH_BUILD_COMMIT=*) commit="${2#*=}" ;; SOURCE_DATE_EPOCH=*) sde="${2#*=}" ;; esac; shift 2 ;;
    --file|-t|--target|--progress) shift 2 ;;
    --*) shift ;;
    *) ctx="$1"; shift ;;
  esac
done
log_var="FAKE_LOG_$n"; digest_var="FAKE_DIGEST_$n"
cat "${!log_var:-${FAKE_LOG:?}}"
read -r digest files bytes <<<"$(python3 -I "$FAKE_KIT/source-digest.py" --tree "$ctx")"
digest="${!digest_var:-$digest}"
umask 022; mkdir -p "$dest"
cat > "$dest/bloch-pos" <<BIN
#!/bin/sh
case "\$1" in
  --version) printf 'bloch-pos 0.0.0-selftest (%s)\nsource-digest sha3-256:%s (%s files, %s bytes) commit-source:asserted tree:asserted-clean\n' "$commit" "$digest" "$files" "$bytes" ;;
  buildinfo) echo '{}' ;;
esac
BIN
chmod 755 "$dest/bloch-pos"
sha="$(shasum -a 256 "$dest/bloch-pos" | awk '{print $1}')"
printf '%s  bloch-pos\n' "$sha" > "$dest/SHA256SUMS"
printf '%s\n' artifact_kind=canonical-container-candidate "source_commit=$commit" "source_date_epoch=$sde" \
  debian_snapshot=20260917T000000Z target=x86_64-unknown-linux-gnu "binary_sha256=$sha" signed=false \
  deployment_authorized=false > "$dest/BUILD-INFO"
EOF
chmod 700 "$tmp/fake-engine"
fresh_log="$TESTDATA/buildkit-fresh-canonical-fa980367.txt"
# fake <state dir> <log of build 1> <log of later builds> <digest build 2 reports, or -> [qualify args...]
fake() {
  local state="$1" log1="$2" log2="$3" dig2="$4"; shift 4
  mkdir -p "$state"
  if [ "$dig2" = - ]; then dig2=""; fi
  FAKE_STATE="$state" FAKE_KIT="$KIT" FAKE_LOG="$log2" FAKE_LOG_1="$log1" FAKE_DIGEST_2="$dig2" \
    CONTAINER_ENGINE="$tmp/fake-engine" "$RQ" "$CAND" \
    --source "$tmp/src6600" --base-commit "$BASE" --out "$state/out" "$@"
}
cached_log="$TESTDATA/buildkit-cached-compile-canonical-fa980367.txt"
stale_log="$TESTDATA/buildkit-stale-context-forced-78d4921c.txt"
claim=(--forced-only --gates-only --relax-order --forced-set claim=HF1_CLAIM_FINALITY_EPOCH=5860)

refuse "fake engine: canonical build with every RUN step CACHED is refused" 1 \
  fake "$tmp/f1" "$cached_log" "$fresh_log" - "${claim[@]}"
says "$tmp/last.out" "refusing a cached build context for the canonical build" "  ... qualify dies naming the cached context"
check "  ... RESULTS has build-context FAIL" grep -qE '^build-context	FAIL' "$tmp/f1/out/RESULTS.tsv"
check "  ... every buildx build went through --no-cache after a prune" \
  sh -c "! grep '^buildx build' '$tmp/f1/calls' | grep -v -- '--no-cache' && grep -q '^buildx prune -f --filter type=source.local' '$tmp/f1/calls'"

refuse "fake engine: canonical build with the stale 79.74 kB context is refused" 1 \
  fake "$tmp/f2" "$stale_log" "$fresh_log" - "${claim[@]}"
check "  ... RESULTS has build-context FAIL with the size" grep -qE '^build-context	FAIL.*79740 bytes' "$tmp/f2/out/RESULTS.tsv"

refuse "fake engine: forced build with the stale context is refused" 1 \
  fake "$tmp/f3" "$fresh_log" "$stale_log" - "${claim[@]}"
check "  ... canonical build-context PASS" grep -qE '^build-context	PASS' "$tmp/f3/out/RESULTS.tsv"
check "  ... forced:claim FAIL cached build context refused" grep -qE '^forced:claim	FAIL.*cached build context refused' "$tmp/f3/out/RESULTS.tsv"

rel_fake="$(python3 -I "$KIT/source-digest.py" --tree "$R" | awk '{print $1}')"
refuse "fake engine: forced binary that reports the release digest is refused (stale build)" 1 \
  fake "$tmp/f5" "$fresh_log" "$fresh_log" "$rel_fake" "${claim[@]}"
check "  ... forced:claim FAIL stale build" grep -qE '^forced:claim	FAIL.*stale build' "$tmp/f5/out/RESULTS.tsv"
refuse "fake engine: forced binary that reports the 78d4921c fleet digest 35c2b943... is refused" 1 \
  fake "$tmp/f6" "$fresh_log" "$fresh_log" 35c2b943d42ec370d087ac69c417492df4063e51547482cfc8346aeb19b1f177 "${claim[@]}"
check "  ... forced:claim FAIL stale build naming 35c2b943" grep -qE '^forced:claim	FAIL.*stale build.*35c2b943d42ec370' "$tmp/f6/out/RESULTS.tsv"

echo
echo "qualify selftest: $passes passed, $failures failed"
[ "$failures" = 0 ]
