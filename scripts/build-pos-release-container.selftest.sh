#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-build-wrapper-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fake_engine="$work/fake-engine"

cat > "$fake_engine" <<'ENGINE'
#!/usr/bin/env bash
set -euo pipefail
stage=
commit=
epoch=
context="${@: -1}"
for arg in "$@"; do
  case "$arg" in
    type=local,dest=*) stage="${arg#type=local,dest=}" ;;
    BLOCH_BUILD_COMMIT=*) commit="${arg#BLOCH_BUILD_COMMIT=}" ;;
    SOURCE_DATE_EPOCH=*) epoch="${arg#SOURCE_DATE_EPOCH=}" ;;
  esac
done
[ -n "$stage" ] && [ -n "$commit" ] && [ -n "$epoch" ]
mkdir -p "$stage"
if [ "${FAKE_BINARY_FROM_CONTEXT:-0}" = 1 ]; then
  marker="$(cat "$context/SOURCE-MARKER")"
  printf '#!/bin/sh\necho %s\n' "$marker" > "$stage/bloch-pos"
else
  printf '#!/bin/sh\necho fake canonical candidate\n' > "$stage/bloch-pos"
fi
chmod 0755 "$stage/bloch-pos"
if command -v sha256sum >/dev/null 2>&1; then
  binary_sha="$(sha256sum "$stage/bloch-pos" | awk '{print $1}')"
else
  binary_sha="$(shasum -a 256 "$stage/bloch-pos" | awk '{print $1}')"
fi
cat > "$stage/BUILD-INFO" <<EOF
artifact_kind=canonical-container-candidate
source_commit=$commit
source_date_epoch=$epoch
debian_snapshot=20260917T000000Z
target=x86_64-unknown-linux-gnu
binary_sha256=$binary_sha
signed=false
deployment_authorized=${FAKE_DEPLOYMENT_AUTHORIZED:-false}
EOF
if [ "${FAKE_DUPLICATE_DEPLOYMENT_AUTHORIZED:-0}" = 1 ]; then
  printf 'deployment_authorized=true\n' >> "$stage/BUILD-INFO"
fi
if command -v sha256sum >/dev/null 2>&1; then
  build_info_sha="$(sha256sum "$stage/BUILD-INFO" | awk '{print $1}')"
else
  build_info_sha="$(shasum -a 256 "$stage/BUILD-INFO" | awk '{print $1}')"
fi
case "${FAKE_MANIFEST_MODE:-canonical}" in
  canonical) printf '%s  bloch-pos\n' "$binary_sha" > "$stage/SHA256SUMS" ;;
  extra) printf '%s  bloch-pos\n%s  BUILD-INFO\n' \
    "$binary_sha" "$build_info_sha" > "$stage/SHA256SUMS" ;;
  omit-binary) printf '%s  BUILD-INFO\n' "$build_info_sha" > "$stage/SHA256SUMS" ;;
  *) exit 64 ;;
esac
ENGINE
chmod 0755 "$fake_engine"

run_wrapper() {
  local mode="$1" output="$2" authorized="${3:-false}" duplicate="${4:-0}"
  FAKE_MANIFEST_MODE="$mode" FAKE_DEPLOYMENT_AUTHORIZED="$authorized" \
    FAKE_DUPLICATE_DEPLOYMENT_AUTHORIZED="$duplicate" \
    CONTAINER_ENGINE="$fake_engine" \
    bash scripts/build-pos-release-container.sh "$output"
}

run_wrapper canonical "$work/canonical" > "$work/canonical.log" 2>&1
grep -Fq 'build-pos-release-container: PASS' "$work/canonical.log"
cmp -s <(printf '%s  bloch-pos\n' "$(
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$work/canonical/bloch-pos" | awk '{print $1}'
  else
    shasum -a 256 "$work/canonical/bloch-pos" | awk '{print $1}'
  fi
)") "$work/canonical/SHA256SUMS"

manifest_error='exported SHA256SUMS is not the exact canonical one-line manifest'
for mode in extra omit-binary; do
  if run_wrapper "$mode" "$work/$mode" > "$work/$mode.log" 2>&1; then
    echo "selftest: noncanonical $mode manifest was accepted" >&2
    exit 1
  fi
  grep -Fq "$manifest_error" "$work/$mode.log" || {
    echo "selftest: noncanonical $mode manifest failed without expected diagnostic" >&2
    cat "$work/$mode.log" >&2
    exit 1
  }
done

authorization_error='BUILD-INFO does not explicitly refuse deployment authorization'
if run_wrapper canonical "$work/authorized-true" true \
    > "$work/authorized-true.log" 2>&1; then
  echo "selftest: deployment_authorized=true was accepted" >&2
  exit 1
fi
grep -Fq "$authorization_error" "$work/authorized-true.log" || {
  echo "selftest: deployment_authorized=true failed without expected diagnostic" >&2
  cat "$work/authorized-true.log" >&2
  exit 1
}
if run_wrapper canonical "$work/authorized-duplicate" false 1 \
    > "$work/authorized-duplicate.log" 2>&1; then
  echo "selftest: duplicate deployment_authorized fields were accepted" >&2
  exit 1
fi
grep -Fq "$authorization_error" "$work/authorized-duplicate.log" || {
  echo "selftest: duplicate deployment_authorized failed without expected diagnostic" >&2
  cat "$work/authorized-duplicate.log" >&2
  exit 1
}

# HEAD may move after the wrapper captures its commit. The timestamp and
# archive must still come from that immutable OID, never from the late ref.
race_repo="$work/race-repo"
mkdir -p "$race_repo/scripts" "$race_repo/deploy/pos-release"
cp scripts/build-pos-release-container.sh "$race_repo/scripts/"
printf 'FROM scratch\n' > "$race_repo/deploy/pos-release/Dockerfile"
printf 'context-A\n' > "$race_repo/SOURCE-MARKER"
git -C "$race_repo" init -q
git -C "$race_repo" config user.email selftest@invalid
git -C "$race_repo" config user.name selftest
git -C "$race_repo" add -A
GIT_AUTHOR_DATE='2001-09-09T01:46:40Z' \
GIT_COMMITTER_DATE='2001-09-09T01:46:40Z' \
  git -C "$race_repo" commit -qm A
commit_a="$(git -C "$race_repo" rev-parse HEAD)"
epoch_a="$(git -C "$race_repo" show -s --format=%ct "$commit_a")"
printf 'context-B\n' > "$race_repo/SOURCE-MARKER"
git -C "$race_repo" add SOURCE-MARKER
GIT_AUTHOR_DATE='2033-05-18T03:33:20Z' \
GIT_COMMITTER_DATE='2033-05-18T03:33:20Z' \
  git -C "$race_repo" commit -qm B
commit_b="$(git -C "$race_repo" rev-parse HEAD)"
git -C "$race_repo" reset -q --hard "$commit_a"

real_git="$(command -v git)"
shim_dir="$work/git-shim"
mkdir "$shim_dir"
cat > "$shim_dir/git" <<'GIT_SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = show ]; then
  "$REAL_GIT" update-ref HEAD "$RACE_COMMIT_B"
fi
exec "$REAL_GIT" "$@"
GIT_SHIM
chmod 0755 "$shim_dir/git"

(
  cd "$race_repo"
  PATH="$shim_dir:$PATH" REAL_GIT="$real_git" RACE_COMMIT_B="$commit_b" \
    FAKE_BINARY_FROM_CONTEXT=1 CONTAINER_ENGINE="$fake_engine" \
    bash scripts/build-pos-release-container.sh "$work/race-output"
) > "$work/race.log" 2>&1
grep -Fq 'build-pos-release-container: PASS' "$work/race.log"
grep -Fq 'echo context-A' "$work/race-output/bloch-pos"
grep -Fxq "source_commit=$commit_a" "$work/race-output/BUILD-INFO"
grep -Fxq "source_date_epoch=$epoch_a" "$work/race-output/BUILD-INFO"
[ "$("$real_git" -C "$race_repo" rev-parse HEAD)" = "$commit_b" ]

echo "build-pos-release-container selftest: PASS"
