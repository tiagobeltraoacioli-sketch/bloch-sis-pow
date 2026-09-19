#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Produce one canonical-container candidate from the committed HEAD.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
out_dir="${1:?usage: build-pos-release-container.sh <new-output-directory>}"
engine="${CONTAINER_ENGINE:-docker}"
canonical_debian_snapshot=20260917T000000Z

fail() { echo "build-pos-release-container: FAIL — $*" >&2; exit 1; }
field() {
  local key="$1" file="$2"
  awk -F= -v key="$key" '
    $1 == key { count++; value = substr($0, length(key) + 2) }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "$file"
}
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}
validated_sha256_file() {
  local digest
  digest="$(sha256_file "$1")" \
    || fail "SHA-256 tool failed for exported bloch-pos"
  case "$digest" in
    ''|*[!0123456789abcdef]*)
      fail "SHA-256 tool returned a non-lowercase hexadecimal digest for exported bloch-pos" ;;
  esac
  [ "${#digest}" -eq 64 ] \
    || fail "SHA-256 tool returned a digest that is not exactly 64 characters for exported bloch-pos"
  printf '%s\n' "$digest"
}
check_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$1" && sha256sum -c SHA256SUMS)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$1" && shasum -a 256 -c SHA256SUMS)
  else
    fail "sha256sum or shasum is required"
  fi
}
command -v "$engine" >/dev/null 2>&1 || fail "container engine not found: $engine"
[ ! -e "$out_dir" ] || fail "output path already exists: $out_dir"

commit="$(git rev-parse HEAD)"
case "$commit" in ''|*[!0-9a-f]*) fail "HEAD is not a lowercase hexadecimal commit" ;; esac
[ "${#commit}" -eq 40 ] || fail "HEAD is not a 40-character commit"
source_date_epoch="$(git show -s --format=%ct "$commit")"
case "$source_date_epoch" in ''|*[!0-9]*) fail "commit timestamp is not numeric" ;; esac

# Archive the captured commit instead of copying the worktree or rereading a
# movable ref. Untracked files, local Cargo configuration, credentials and
# concurrent edits cannot enter the context.
work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-container.XXXXXX")"
trap 'rm -rf "$work"' EXIT
context="$work/context"
stage="$work/output"
mkdir -p "$context" "$stage"
git archive --format=tar "$commit" | tar -xf - -C "$context"
[ -f "$context/deploy/pos-release/Dockerfile" ] \
  || fail "release Dockerfile is not committed at the captured commit"

"$engine" buildx build \
  --progress=plain \
  --target export \
  --output "type=local,dest=$stage" \
  --build-arg "BLOCH_BUILD_COMMIT=$commit" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  --file "$context/deploy/pos-release/Dockerfile" \
  "$context"

# Emit one fixed byte per entry rather than counting printed path lines: an
# engine-controlled filename containing a newline must not alter cardinality.
entry_count="$(
  find "$stage" -mindepth 1 -maxdepth 1 -exec printf x \; \
    | wc -c | tr -d '[:space:]'
)"
[ "$entry_count" = 3 ] \
  || fail "container export must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found $entry_count entries)"
for artifact in bloch-pos SHA256SUMS BUILD-INFO; do
  [ -f "$stage/$artifact" ] && [ ! -L "$stage/$artifact" ] \
    || fail "container export $artifact must be a regular non-symlink file"
done
[ -x "$stage/bloch-pos" ] || fail "container did not export bloch-pos"
binary_sha="$(validated_sha256_file "$stage/bloch-pos")"
cmp -s <(printf '%s  bloch-pos\n' "$binary_sha") "$stage/SHA256SUMS" \
  || fail "exported SHA256SUMS is not the exact canonical one-line manifest"
check_sha256 "$stage" || fail "exported checksum does not verify"
build_info="$stage/BUILD-INFO"
artifact_kind="$(field artifact_kind "$build_info")" \
  || fail "BUILD-INFO does not declare a canonical-container candidate"
[ "$artifact_kind" = canonical-container-candidate ] \
  || fail "BUILD-INFO does not declare a canonical-container candidate"
metadata_commit="$(field source_commit "$build_info")" \
  || fail "BUILD-INFO does not bind HEAD"
[ "$metadata_commit" = "$commit" ] || fail "BUILD-INFO does not bind HEAD"
metadata_epoch="$(field source_date_epoch "$build_info")" \
  || fail "BUILD-INFO does not bind the commit timestamp"
[ "$metadata_epoch" = "$source_date_epoch" ] \
  || fail "BUILD-INFO does not bind the commit timestamp"
debian_snapshot="$(field debian_snapshot "$build_info")" \
  || fail "BUILD-INFO debian_snapshot does not match the canonical Dockerfile snapshot"
[ "$debian_snapshot" = "$canonical_debian_snapshot" ] \
  || fail "BUILD-INFO debian_snapshot does not match the canonical Dockerfile snapshot"
target="$(field target "$build_info")" \
  || fail "BUILD-INFO target must be a lowercase ASCII Rust host triple"
case "$target" in
  ''|*[!abcdefghijklmnopqrstuvwxyz0123456789_-]*|-*|*-|*--*)
    fail "BUILD-INFO target must be a lowercase ASCII Rust host triple" ;;
  *-*-*) : ;;
  *) fail "BUILD-INFO target must be a lowercase ASCII Rust host triple" ;;
esac
metadata_sha="$(field binary_sha256 "$build_info")" \
  || fail "BUILD-INFO binary_sha256 does not match the exported binary"
[ "$metadata_sha" = "$binary_sha" ] \
  || fail "BUILD-INFO binary_sha256 does not match the exported binary"
signed="$(field signed "$build_info")" \
  || fail "BUILD-INFO does not explicitly declare its unsigned state"
[ "$signed" = false ] \
  || fail "BUILD-INFO does not explicitly declare its unsigned state"
deployment_authorized="$(field deployment_authorized "$build_info")" \
  || fail "BUILD-INFO does not explicitly refuse deployment authorization"
[ "$deployment_authorized" = false ] \
  || fail "BUILD-INFO does not explicitly refuse deployment authorization"
cmp -s <(printf '%s\n' \
    'artifact_kind=canonical-container-candidate' \
    "source_commit=$metadata_commit" \
    "source_date_epoch=$metadata_epoch" \
    "debian_snapshot=$debian_snapshot" \
    "target=$target" \
    "binary_sha256=$metadata_sha" \
    'signed=false' \
    'deployment_authorized=false') "$build_info" \
  || fail "BUILD-INFO is not in the exact canonical field order and encoding"

mkdir -p "$(dirname "$out_dir")"
mv "$stage" "$out_dir"
trap - EXIT
rm -rf "$work"
echo "build-pos-release-container: PASS — $out_dir"
