#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-build-wrapper-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fake_engine="$work/fake-engine"

# Put a controllable SHA-256 shim first on PATH. Canonical mode delegates to
# the host implementation, while malformed modes exercise only the wrapper:
# the fake engine below always hashes with the captured real implementation.
mkdir -p "$work/bin"
REAL_SHA256SUM="$(command -v sha256sum || true)"
REAL_SHASUM="$(command -v shasum || true)"
[ -n "$REAL_SHA256SUM" ] || [ -n "$REAL_SHASUM" ] || {
  echo "selftest: no host SHA-256 implementation is available" >&2
  exit 1
}
export REAL_SHA256SUM REAL_SHASUM
cat > "$work/bin/sha256sum" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
delegate() {
  if [ -n "${REAL_SHA256SUM:-}" ]; then
    exec "$REAL_SHA256SUM" "$@"
  elif [ "${1:-}" = -c ]; then
    exec "$REAL_SHASUM" -a 256 -c "$2"
  else
    exec "$REAL_SHASUM" -a 256 "$@"
  fi
}
case "${BUILD_WRAPPER_SHA_MODE:-canonical}" in
  canonical) delegate "$@" ;;
  exit) exit 71 ;;
  short) printf '%063d  %s\n' 0 "${1:-input}" ;;
  nonhex) printf '%064d  %s\n' 0 "${1:-input}" | tr 0 g ;;
  uppercase) printf '%064d  %s\n' 0 "${1:-input}" | tr 0 A ;;
  multirow)
    printf '%064d  %s\n' 0 "${1:-input}"
    printf '%064d  second-row\n' 0
    ;;
  *) exit 72 ;;
esac
SHIM
chmod 0755 "$work/bin/sha256sum"
export PATH="$work/bin:$PATH"

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
if [ -n "${REAL_SHA256SUM:-}" ]; then
  binary_sha="$("$REAL_SHA256SUM" "$stage/bloch-pos" | awk '{print $1}')"
else
  binary_sha="$("$REAL_SHASUM" -a 256 "$stage/bloch-pos" | awk '{print $1}')"
fi
cat > "$stage/BUILD-INFO" <<EOF
artifact_kind=${FAKE_ARTIFACT_KIND:-canonical-container-candidate}
source_commit=$commit
source_date_epoch=$epoch
debian_snapshot=${FAKE_DEBIAN_SNAPSHOT:-20260917T000000Z}
target=${FAKE_TARGET:-x86_64-unknown-linux-gnu}
binary_sha256=${FAKE_METADATA_BINARY_SHA:-$binary_sha}
signed=${FAKE_SIGNED:-false}
deployment_authorized=${FAKE_DEPLOYMENT_AUTHORIZED:-false}
EOF
if [ "${FAKE_DUPLICATE_ARTIFACT_KIND:-0}" = 1 ]; then
  printf 'artifact_kind=unsigned-release-candidate\n' >> "$stage/BUILD-INFO"
fi
if [ "${FAKE_DUPLICATE_BINARY_SHA:-0}" = 1 ]; then
  printf 'binary_sha256=%064d\n' 0 >> "$stage/BUILD-INFO"
fi
if [ "${FAKE_DUPLICATE_SIGNED:-0}" = 1 ]; then
  printf 'signed=true\n' >> "$stage/BUILD-INFO"
fi
if [ "${FAKE_DUPLICATE_DEPLOYMENT_AUTHORIZED:-0}" = 1 ]; then
  printf 'deployment_authorized=true\n' >> "$stage/BUILD-INFO"
fi
case "${FAKE_BUILD_INFO_MODE:-canonical}" in
  canonical) ;;
  duplicate-source-commit)
    printf 'source_commit=ffffffffffffffffffffffffffffffffffffffff\n' \
      >> "$stage/BUILD-INFO" ;;
  duplicate-source-date)
    printf 'source_date_epoch=1\n' >> "$stage/BUILD-INFO" ;;
  extra-field)
    printf 'unexpected=engine-controlled\n' >> "$stage/BUILD-INFO" ;;
  reordered)
    awk 'NR == 1 { first = $0; next }
         NR == 2 { print; print first; next }
         { print }' "$stage/BUILD-INFO" > "$stage/BUILD-INFO.new"
    mv "$stage/BUILD-INFO.new" "$stage/BUILD-INFO" ;;
  missing-newline)
    build_info_without_newline="$(cat "$stage/BUILD-INFO")"
    printf '%s' "$build_info_without_newline" > "$stage/BUILD-INFO" ;;
  *) exit 65 ;;
esac
if [ -n "${REAL_SHA256SUM:-}" ]; then
  build_info_sha="$("$REAL_SHA256SUM" "$stage/BUILD-INFO" | awk '{print $1}')"
else
  build_info_sha="$("$REAL_SHASUM" -a 256 "$stage/BUILD-INFO" | awk '{print $1}')"
fi
case "${FAKE_MANIFEST_MODE:-canonical}" in
  canonical) printf '%s  bloch-pos\n' "$binary_sha" > "$stage/SHA256SUMS" ;;
  extra) printf '%s  bloch-pos\n%s  BUILD-INFO\n' \
    "$binary_sha" "$build_info_sha" > "$stage/SHA256SUMS" ;;
  omit-binary) printf '%s  BUILD-INFO\n' "$build_info_sha" > "$stage/SHA256SUMS" ;;
  *) exit 64 ;;
esac
chmod 0644 "$stage/SHA256SUMS" "$stage/BUILD-INFO"
if [ -n "${FAKE_SYMLINK_ARTIFACT:-}" ]; then
  artifact="$FAKE_SYMLINK_ARTIFACT"
  target="$context/engine-export-$artifact"
  mv "$stage/$artifact" "$target"
  ln -s "$target" "$stage/$artifact"
fi
if [ -n "${FAKE_HARDLINK_ARTIFACT:-}" ]; then
  artifact="$FAKE_HARDLINK_ARTIFACT"
  target="$context/engine-hardlink-$artifact"
  mv "$stage/$artifact" "$target"
  ln "$target" "$stage/$artifact"
fi
case "${FAKE_EXTRA_ENTRY:-none}" in
  none) ;;
  regular) printf 'unexpected\n' > "$stage/unexpected-file" ;;
  dotfile) printf 'unexpected\n' > "$stage/.unexpected-file" ;;
  subdir) mkdir "$stage/unexpected-directory" ;;
  fifo) mkfifo "$stage/unexpected-fifo" ;;
  *) exit 66 ;;
esac
case "${FAKE_UNSAFE_MODE_ARTIFACT:-}" in
  '') ;;
  bloch-pos) chmod 0777 "$stage/bloch-pos" ;;
  SHA256SUMS|BUILD-INFO) chmod 0666 "$stage/$FAKE_UNSAFE_MODE_ARTIFACT" ;;
  *) exit 67 ;;
esac
if [ "${FAKE_OUTPUT_COLLISION:-0}" = 1 ]; then
  mkdir "$FAKE_COLLISION_OUT"
fi
if [ "${FAKE_STAGE_ROOT_SYMLINK:-0}" = 1 ]; then
  target="$context/engine-export-root"
  mv "$stage" "$target"
  ln -s "$target" "$stage"
  : > "$FAKE_STAGE_ROOT_OBSERVATION"
fi
ENGINE
chmod 0755 "$fake_engine"

run_wrapper() {
  local mode="$1" output="$2" authorized="${3:-false}" duplicate="${4:-0}"
  local signed="${5:-false}" signed_duplicate="${6:-0}"
  local metadata_sha="${7:-}" sha_duplicate="${8:-0}"
  local artifact_kind="${9:-canonical-container-candidate}"
  local artifact_duplicate="${10:-0}"
  local symlink_artifact="${11:-}"
  local extra_entry="${12:-none}"
  local unsafe_mode_artifact="${13:-}"
  local hardlink_artifact="${14:-}"
  local output_collision="${15:-0}"
  local stage_root_symlink="${16:-0}"
  FAKE_MANIFEST_MODE="$mode" FAKE_DEPLOYMENT_AUTHORIZED="$authorized" \
    FAKE_DUPLICATE_DEPLOYMENT_AUTHORIZED="$duplicate" \
    FAKE_SIGNED="$signed" FAKE_DUPLICATE_SIGNED="$signed_duplicate" \
    FAKE_METADATA_BINARY_SHA="$metadata_sha" \
    FAKE_DUPLICATE_BINARY_SHA="$sha_duplicate" \
    FAKE_ARTIFACT_KIND="$artifact_kind" \
    FAKE_DUPLICATE_ARTIFACT_KIND="$artifact_duplicate" \
    FAKE_SYMLINK_ARTIFACT="$symlink_artifact" \
    FAKE_EXTRA_ENTRY="$extra_entry" \
    FAKE_UNSAFE_MODE_ARTIFACT="$unsafe_mode_artifact" \
    FAKE_HARDLINK_ARTIFACT="$hardlink_artifact" \
    FAKE_OUTPUT_COLLISION="$output_collision" \
    FAKE_COLLISION_OUT="$output" \
    FAKE_STAGE_ROOT_SYMLINK="$stage_root_symlink" \
    FAKE_STAGE_ROOT_OBSERVATION="$output.stage-root-observed" \
    CONTAINER_ENGINE="$fake_engine" \
    bash scripts/build-pos-release-container.sh "$output"
}

expect_stage_root_symlink_failure() {
  local output="$work/stage-root-symlink"
  local log="$work/stage-root-symlink.log"
  if run_wrapper canonical "$output" false 0 false 0 "" 0 \
      canonical-container-candidate 0 "" none "" "" 0 1 > "$log" 2>&1; then
    echo "selftest: wrapper accepted a symlinked export root" >&2
    exit 1
  fi
  [ -f "$output.stage-root-observed" ] || {
    echo "selftest: fixture did not install the export-root symlink" >&2
    exit 1
  }
  grep -Fq 'container export root must be a real non-symlink directory' "$log" || {
    echo "selftest: symlinked export root failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  ! grep -Fq 'build-pos-release-container: PASS' "$log" || {
    echo "selftest: wrapper reported PASS for a symlinked export root" >&2
    exit 1
  }
  [ ! -e "$output" ] || {
    echo "selftest: wrapper published a symlinked export root" >&2
    exit 1
  }
}

expect_publication_collision_failure() {
  local output="$work/publication-collision"
  local log="$work/publication-collision.log"
  if run_wrapper canonical "$output" false 0 false 0 "" 0 \
      canonical-container-candidate 0 "" none "" "" 1 > "$log" 2>&1; then
    echo "selftest: wrapper reported PASS after a raced output collision" >&2
    exit 1
  fi
  grep -Fq 'output path changed during publication; refusing a nested or replaced destination' \
      "$log" || {
    echo "selftest: raced output collision failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  [ ! -f "$output/bloch-pos" ] || {
    echo "selftest: raced destination unexpectedly exposes the staged binary directly" >&2
    exit 1
  }
  [ -f "$output/output/bloch-pos" ] || {
    echo "selftest: fixture did not reproduce the nested-stage mv collision" >&2
    exit 1
  }
}

expect_hardlink_failure() {
  local artifact="$1" output="$work/hardlink-$1" log="$work/hardlink-$1.log"
  if run_wrapper canonical "$output" false 0 false 0 "" 0 \
      canonical-container-candidate 0 "" none "" "$artifact" \
      > "$log" 2>&1; then
    echo "selftest: wrapper accepted hardlinked $artifact export" >&2
    exit 1
  fi
  grep -Fq "container export $artifact must have exactly one hard link" \
      "$log" || {
    echo "selftest: hardlinked $artifact failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  [ ! -e "$output" ] || {
    echo "selftest: wrapper published output after rejecting hardlinked $artifact" >&2
    exit 1
  }
}

run_build_info_wrapper() {
  local output="$1" layout="${2:-canonical}"
  local snapshot="${3:-20260917T000000Z}"
  local target="${4:-x86_64-unknown-linux-gnu}"
  FAKE_BUILD_INFO_MODE="$layout" FAKE_DEBIAN_SNAPSHOT="$snapshot" \
    FAKE_TARGET="$target" CONTAINER_ENGINE="$fake_engine" \
    bash scripts/build-pos-release-container.sh "$output"
}

expect_build_info_failure() {
  local label="$1" layout="$2" snapshot="$3" target="$4" expected="$5"
  local output="$work/build-info-$label" log="$work/build-info-$label.log"
  if run_build_info_wrapper "$output" "$layout" "$snapshot" "$target" \
      > "$log" 2>&1; then
    echo "selftest: noncanonical BUILD-INFO $label was accepted" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log" || {
    echo "selftest: BUILD-INFO $label failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
}

expect_sha_failure() {
  local mode="$1" expected="$2"
  local output="$work/sha-$mode" log="$work/sha-$mode.log"
  if BUILD_WRAPPER_SHA_MODE="$mode" run_wrapper canonical "$output" \
      > "$log" 2>&1; then
    echo "selftest: wrapper accepted $mode SHA-256 output" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log" || {
    echo "selftest: $mode SHA-256 output failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  [ ! -e "$output" ] || {
    echo "selftest: wrapper published output after rejecting $mode SHA-256 output" >&2
    exit 1
  }
}

expect_symlink_failure() {
  local artifact="$1" output="$work/symlink-$1" log="$work/symlink-$1.log"
  if run_wrapper canonical "$output" false 0 false 0 "" 0 \
      canonical-container-candidate 0 "$artifact" > "$log" 2>&1; then
    echo "selftest: wrapper accepted symlinked $artifact export" >&2
    exit 1
  fi
  grep -Fq "container export $artifact must be a regular non-symlink file" \
      "$log" || {
    echo "selftest: symlinked $artifact failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  [ ! -e "$output" ] || {
    echo "selftest: wrapper published output after rejecting symlinked $artifact" >&2
    exit 1
  }
}

expect_extra_entry_failure() {
  local mode="$1" output="$work/extra-$1" log="$work/extra-$1.log"
  if run_wrapper canonical "$output" false 0 false 0 "" 0 \
      canonical-container-candidate 0 "" "$mode" > "$log" 2>&1; then
    echo "selftest: wrapper accepted $mode extra export entry" >&2
    exit 1
  fi
  grep -Fq 'container export must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found 4 entries)' \
      "$log" || {
    echo "selftest: $mode extra entry failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  [ ! -e "$output" ] || {
    echo "selftest: wrapper published output after rejecting $mode extra entry" >&2
    exit 1
  }
}

expect_unsafe_mode_failure() {
  local artifact="$1" output="$work/unsafe-mode-$1" log="$work/unsafe-mode-$1.log"
  if run_wrapper canonical "$output" false 0 false 0 "" 0 \
      canonical-container-candidate 0 "" none "$artifact" > "$log" 2>&1; then
    echo "selftest: wrapper accepted unsafe write mode on $artifact" >&2
    exit 1
  fi
  grep -Fq "container export $artifact must not be writable by group or others" \
      "$log" || {
    echo "selftest: unsafe $artifact mode failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
  [ ! -e "$output" ] || {
    echo "selftest: wrapper published output after rejecting unsafe $artifact mode" >&2
    exit 1
  }
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
[ "$(find "$work/canonical" -mindepth 1 -maxdepth 1 -exec printf x \; \
  | wc -c | tr -d '[:space:]')" = 3 ]
[ -z "$(find "$work/canonical" -name '.bloch-pos-publication.*' -print -quit)" ]

( umask 000
  run_wrapper canonical "$work/canonical-umask-000"
) > "$work/canonical-umask-000.log" 2>&1
grep -Fq 'build-pos-release-container: PASS' "$work/canonical-umask-000.log"
[ "$(find "$work/canonical-umask-000/bloch-pos" -prune -perm 0755 -exec printf x \;)" = x ]
for artifact in SHA256SUMS BUILD-INFO; do
  [ "$(find "$work/canonical-umask-000/$artifact" -prune -perm 0644 -exec printf x \;)" = x ]
done

expect_publication_collision_failure
expect_stage_root_symlink_failure

expect_sha_failure exit 'SHA-256 tool failed for exported bloch-pos'
expect_sha_failure short \
  'SHA-256 tool returned a digest that is not exactly 64 characters for exported bloch-pos'
expect_sha_failure nonhex \
  'SHA-256 tool returned a non-lowercase hexadecimal digest for exported bloch-pos'
expect_sha_failure uppercase \
  'SHA-256 tool returned a non-lowercase hexadecimal digest for exported bloch-pos'
expect_sha_failure multirow \
  'SHA-256 tool returned a non-lowercase hexadecimal digest for exported bloch-pos'

for artifact in bloch-pos SHA256SUMS BUILD-INFO; do
  expect_symlink_failure "$artifact"
done
for artifact in bloch-pos SHA256SUMS BUILD-INFO; do
  expect_hardlink_failure "$artifact"
done
for mode in regular dotfile subdir fifo; do
  expect_extra_entry_failure "$mode"
done
for artifact in bloch-pos SHA256SUMS BUILD-INFO; do
  expect_unsafe_mode_failure "$artifact"
done

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

signed_error='BUILD-INFO does not explicitly declare its unsigned state'
if run_wrapper canonical "$work/signed-true" false 0 true \
    > "$work/signed-true.log" 2>&1; then
  echo "selftest: signed=true was accepted" >&2
  exit 1
fi
grep -Fq "$signed_error" "$work/signed-true.log" || {
  echo "selftest: signed=true failed without expected diagnostic" >&2
  cat "$work/signed-true.log" >&2
  exit 1
}
if run_wrapper canonical "$work/signed-duplicate" false 0 false 1 \
    > "$work/signed-duplicate.log" 2>&1; then
  echo "selftest: duplicate signed fields were accepted" >&2
  exit 1
fi
grep -Fq "$signed_error" "$work/signed-duplicate.log" || {
  echo "selftest: duplicate signed fields failed without expected diagnostic" >&2
  cat "$work/signed-duplicate.log" >&2
  exit 1
}

binary_sha_error='BUILD-INFO binary_sha256 does not match the exported binary'
wrong_binary_sha=0000000000000000000000000000000000000000000000000000000000000000
if run_wrapper canonical "$work/binary-sha-mismatch" false 0 false 0 \
    "$wrong_binary_sha" > "$work/binary-sha-mismatch.log" 2>&1; then
  echo "selftest: mismatched BUILD-INFO binary_sha256 was accepted" >&2
  exit 1
fi
grep -Fq "$binary_sha_error" "$work/binary-sha-mismatch.log" || {
  echo "selftest: mismatched binary_sha256 failed without expected diagnostic" >&2
  cat "$work/binary-sha-mismatch.log" >&2
  exit 1
}
if run_wrapper canonical "$work/binary-sha-duplicate" false 0 false 0 "" 1 \
    > "$work/binary-sha-duplicate.log" 2>&1; then
  echo "selftest: duplicate BUILD-INFO binary_sha256 fields were accepted" >&2
  exit 1
fi
grep -Fq "$binary_sha_error" "$work/binary-sha-duplicate.log" || {
  echo "selftest: duplicate binary_sha256 failed without expected diagnostic" >&2
  cat "$work/binary-sha-duplicate.log" >&2
  exit 1
}

artifact_error='BUILD-INFO does not declare a canonical-container candidate'
if run_wrapper canonical "$work/artifact-kind-wrong" false 0 false 0 "" 0 \
    unsigned-release-candidate > "$work/artifact-kind-wrong.log" 2>&1; then
  echo "selftest: wrong artifact_kind was accepted" >&2
  exit 1
fi
grep -Fq "$artifact_error" "$work/artifact-kind-wrong.log" || {
  echo "selftest: wrong artifact_kind failed without expected diagnostic" >&2
  cat "$work/artifact-kind-wrong.log" >&2
  exit 1
}
if run_wrapper canonical "$work/artifact-kind-duplicate" false 0 false 0 "" 0 \
    canonical-container-candidate 1 > "$work/artifact-kind-duplicate.log" 2>&1; then
  echo "selftest: duplicate artifact_kind fields were accepted" >&2
  exit 1
fi
grep -Fq "$artifact_error" "$work/artifact-kind-duplicate.log" || {
  echo "selftest: duplicate artifact_kind failed without expected diagnostic" >&2
  cat "$work/artifact-kind-duplicate.log" >&2
  exit 1
}

expect_build_info_failure duplicate-source-commit duplicate-source-commit \
  20260917T000000Z x86_64-unknown-linux-gnu 'BUILD-INFO does not bind HEAD'
expect_build_info_failure duplicate-source-date duplicate-source-date \
  20260917T000000Z x86_64-unknown-linux-gnu \
  'BUILD-INFO does not bind the commit timestamp'
expect_build_info_failure alternate-snapshot canonical \
  20260918T000000Z x86_64-unknown-linux-gnu \
  'debian_snapshot does not match the canonical Dockerfile snapshot'
expect_build_info_failure malformed-target canonical \
  20260917T000000Z 'NOT A TARGET' \
  'target must be a lowercase ASCII Rust host triple'
canonical_build_info_error='BUILD-INFO is not in the exact canonical field order and encoding'
expect_build_info_failure reordered reordered 20260917T000000Z \
  x86_64-unknown-linux-gnu "$canonical_build_info_error"
expect_build_info_failure extra-field extra-field 20260917T000000Z \
  x86_64-unknown-linux-gnu "$canonical_build_info_error"
expect_build_info_failure missing-newline missing-newline 20260917T000000Z \
  x86_64-unknown-linux-gnu "$canonical_build_info_error"

run_build_info_wrapper "$work/alternate-valid-target" canonical \
  20260917T000000Z aarch64-unknown-linux-gnu \
  > "$work/alternate-valid-target.log" 2>&1
grep -Fq 'build-pos-release-container: PASS' "$work/alternate-valid-target.log"

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
