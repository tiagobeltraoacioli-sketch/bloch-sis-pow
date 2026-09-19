#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Compare outputs produced on two independent builders. Success is evidence of
# equality, not signing, publication or deployment authorization.
set -euo pipefail

a="${1:?usage: compare-pos-release-builds.sh <builder-a-dir> <builder-b-dir>}"
b="${2:?usage: compare-pos-release-builds.sh <builder-a-dir> <builder-b-dir>}"
canonical_debian_snapshot=20260917T000000Z
fail() { echo "compare-pos-release-builds: FAIL — $*" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}
field() {
  local key="$1" file="$2"
  awk -F= -v key="$key" '
    $1 == key { count++; value = substr($0, length(key) + 2) }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "$file" || fail "$file must contain exactly one nonempty $key field"
}

for dir in "$a" "$b"; do
  [ -d "$dir" ] || fail "not a directory: $dir"
  for file in bloch-pos SHA256SUMS BUILD-INFO; do
    [ -f "$dir/$file" ] || fail "missing $dir/$file"
    [ ! -L "$dir/$file" ] || fail "$dir/$file must not be a symlink"
  done
  # Emit one fixed byte per top-level entry instead of counting printed path
  # lines: a filename containing a newline must not confuse the cardinality.
  entry_count="$(
    find "$dir" -mindepth 1 -maxdepth 1 -exec printf x \; \
      | wc -c | tr -d '[:space:]'
  )"
  [ "$entry_count" = 3 ] \
    || fail "$dir must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found $entry_count entries)"
  [ -x "$dir/bloch-pos" ] || fail "$dir/bloch-pos is not executable"
  [ "$(wc -l < "$dir/BUILD-INFO" | tr -d ' ')" = 8 ] \
    || fail "$dir/BUILD-INFO must contain exactly the eight canonical fields"
  actual_sha="$(sha256_file "$dir/bloch-pos")"
  case "$actual_sha" in
    ''|*[!0-9a-f]*) fail "checksum tool returned a non-lowercase SHA-256 for $dir/bloch-pos" ;;
  esac
  [ "${#actual_sha}" = 64 ] \
    || fail "checksum tool returned a non-64-byte SHA-256 for $dir/bloch-pos"
  cmp -s <(printf '%s  bloch-pos\n' "$actual_sha") "$dir/SHA256SUMS" \
    || fail "$dir/SHA256SUMS is not the exact canonical one-line manifest"
  metadata_sha="$(field binary_sha256 "$dir/BUILD-INFO")"
  [ "$actual_sha" = "$metadata_sha" ] || fail "BUILD-INFO checksum mismatch in $dir"
  [ "$(field artifact_kind "$dir/BUILD-INFO")" = canonical-container-candidate ] \
    || fail "$dir is not a canonical-container candidate"
  [ "$(field signed "$dir/BUILD-INFO")" = false ] \
    || fail "$dir does not declare its unsigned state"
  [ "$(field deployment_authorized "$dir/BUILD-INFO")" = false ] \
    || fail "$dir does not refuse deployment authorization"
  source_commit="$(field source_commit "$dir/BUILD-INFO")"
  case "$source_commit" in
    ''|*[!0-9a-f]*)
      fail "$dir/BUILD-INFO source_commit must be a 40-character lowercase hexadecimal commit" ;;
  esac
  [ "${#source_commit}" = 40 ] \
    || fail "$dir/BUILD-INFO source_commit must be a 40-character lowercase hexadecimal commit"
  source_date_epoch="$(field source_date_epoch "$dir/BUILD-INFO")"
  case "$source_date_epoch" in
    ''|*[!0-9]*)
      fail "$dir/BUILD-INFO source_date_epoch must be a nonempty decimal integer" ;;
  esac
  debian_snapshot="$(field debian_snapshot "$dir/BUILD-INFO")"
  snapshot_digits="${debian_snapshot:0:8}${debian_snapshot:9:6}"
  if [ "${#debian_snapshot}" != 16 ] \
      || [ "${debian_snapshot:8:1}" != T ] \
      || [ "${debian_snapshot:15:1}" != Z ]; then
    fail "$dir/BUILD-INFO debian_snapshot must have exact YYYYMMDDTHHMMSSZ syntax"
  fi
  case "$snapshot_digits" in
    ''|*[!0123456789]*)
      fail "$dir/BUILD-INFO debian_snapshot must have exact YYYYMMDDTHHMMSSZ syntax" ;;
  esac
  [ "$debian_snapshot" = "$canonical_debian_snapshot" ] \
    || fail "$dir/BUILD-INFO debian_snapshot does not match the canonical Dockerfile snapshot"
  target="$(field target "$dir/BUILD-INFO")"
  case "$target" in
    ''|*[!abcdefghijklmnopqrstuvwxyz0123456789_-]*|-*|*-|*--*)
      fail "$dir/BUILD-INFO target must be a lowercase ASCII Rust host triple" ;;
    *-*-*) : ;;
    *) fail "$dir/BUILD-INFO target must be a lowercase ASCII Rust host triple" ;;
  esac
  cmp -s <(printf '%s\n' \
      'artifact_kind=canonical-container-candidate' \
      "source_commit=$source_commit" \
      "source_date_epoch=$source_date_epoch" \
      "debian_snapshot=$debian_snapshot" \
      "target=$target" \
      "binary_sha256=$metadata_sha" \
      'signed=false' \
      'deployment_authorized=false') "$dir/BUILD-INFO" \
    || fail "$dir/BUILD-INFO is not in the exact canonical field order and encoding"
  if [ "$dir" = "$a" ]; then
    a_source_commit="$source_commit"
    a_source_date_epoch="$source_date_epoch"
    a_debian_snapshot="$debian_snapshot"
    a_target="$target"
    a_binary_sha256="$metadata_sha"
  else
    b_source_commit="$source_commit"
    b_source_date_epoch="$source_date_epoch"
    b_debian_snapshot="$debian_snapshot"
    b_target="$target"
    b_binary_sha256="$metadata_sha"
  fi
done

a_real="$(cd "$a" && pwd -P)"
b_real="$(cd "$b" && pwd -P)"
[ "$a_real" != "$b_real" ] \
  || fail "the two inputs resolve to the same directory; obtain a second builder output"
for file in bloch-pos SHA256SUMS BUILD-INFO; do
  [ ! "$a/$file" -ef "$b/$file" ] \
    || fail "the two inputs alias the same filesystem object for $file"
done

cmp -s "$a/bloch-pos" "$b/bloch-pos" || fail "binary bytes differ"
cmp -s "$a/BUILD-INFO" "$b/BUILD-INFO" || fail "complete BUILD-INFO differs"
[ "$a_source_commit" = "$b_source_commit" ] \
  || fail "source_commit differs between builders"
[ "$a_source_date_epoch" = "$b_source_date_epoch" ] \
  || fail "source_date_epoch differs between builders"
[ "$a_debian_snapshot" = "$b_debian_snapshot" ] \
  || fail "debian_snapshot differs between builders"
[ "$a_target" = "$b_target" ] || fail "target differs between builders"
[ "$a_binary_sha256" = "$b_binary_sha256" ] \
  || fail "binary_sha256 differs between builders"

echo "compare-pos-release-builds: PASS — distinct supplied outputs are byte-identical"
echo "builder independence still requires separately authenticated build records"
