#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Produce one canonical-container candidate from the committed HEAD.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
out_dir="${1:?usage: build-pos-release-container.sh <new-output-directory>}"
engine="${CONTAINER_ENGINE:-docker}"

fail() { echo "build-pos-release-container: FAIL — $*" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
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

[ -x "$stage/bloch-pos" ] || fail "container did not export bloch-pos"
binary_sha="$(sha256_file "$stage/bloch-pos")"
cmp -s <(printf '%s  bloch-pos\n' "$binary_sha") "$stage/SHA256SUMS" \
  || fail "exported SHA256SUMS is not the exact canonical one-line manifest"
check_sha256 "$stage" || fail "exported checksum does not verify"
grep -Fx "source_commit=$commit" "$stage/BUILD-INFO" >/dev/null \
  || fail "BUILD-INFO does not bind HEAD"
grep -Fx "source_date_epoch=$source_date_epoch" "$stage/BUILD-INFO" >/dev/null \
  || fail "BUILD-INFO does not bind the commit timestamp"
awk -F= '
  $1 == "signed" { count++; value = substr($0, length($1) + 2) }
  END { exit !(count == 1 && value == "false") }
' "$stage/BUILD-INFO" \
  || fail "BUILD-INFO does not explicitly declare its unsigned state"
awk -F= '
  $1 == "deployment_authorized" { count++; value = substr($0, length($1) + 2) }
  END { exit !(count == 1 && value == "false") }
' "$stage/BUILD-INFO" \
  || fail "BUILD-INFO does not explicitly refuse deployment authorization"

mkdir -p "$(dirname "$out_dir")"
mv "$stage" "$out_dir"
trap - EXIT
rm -rf "$work"
echo "build-pos-release-container: PASS — $out_dir"
