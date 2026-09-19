#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build a traceable Genesis-4 release candidate for CI artifact retention.
# This does not sign, publish or authorize fleet deployment.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
out_dir="${1:-$repo_root/dist/pos-release-candidate}"

fail() { echo "package-pos-release-candidate: FAIL — $*" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

commit="$(git rev-parse HEAD)"
case "$commit" in
  *[!0-9a-f]*|'') fail "HEAD is not a lowercase hexadecimal commit" ;;
esac
[ "${#commit}" -eq 40 ] || fail "HEAD must be a 40-character SHA-1 commit"
if [ -n "${CI_COMMIT_SHA:-}" ] && [ "$CI_COMMIT_SHA" != "$commit" ]; then
  fail "CI_COMMIT_SHA does not match the checked-out HEAD"
fi

# Release candidates must describe committed source. Untracked CI output is
# harmless, but any tracked edit would make the embedded commit untruthful.
git diff --quiet -- || fail "tracked working tree differs from HEAD"
git diff --cached --quiet -- || fail "index differs from HEAD"

# Keep this list aligned with the release-integrity gate. A candidate built
# with a target-specific linker, a profile override or a compiler wrapper is
# not the default locked release recipe, even if its source commit is clean.
# Values are deliberately never printed because wrappers can contain secrets.
while IFS= read -r variable; do
  case "$variable" in
    RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|\
    CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_RUSTC|CARGO_BUILD_RUSTC_WRAPPER|\
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_TARGET|\
    CARGO_PROFILE_*|CARGO_TARGET_*_RUSTFLAGS|CARGO_TARGET_*_LINKER)
      [ -z "${!variable}" ] \
        || fail "unset build override $variable before packaging a release candidate"
      ;;
  esac
done < <(compgen -e)

work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-package.XXXXXX")"
trap 'rm -rf "$work"' EXIT
source="$work/src"
mkdir -p "$source"
git archive "$commit" | tar -x -C "$source" \
  || fail "could not materialize the captured commit archive"

# Resolve both the reviewed pin and the active toolchain from the captured
# source tree. Running Rust and Cargo there also loads only the archived Cargo
# configuration, never a config or source file changed after the clean checks.
pin="$(python3 -I "$source/scripts/pinned-rust-toolchain.py" \
  "$source/rust-toolchain.toml" \
  "$source/crates/bloch-pos-node/rust-toolchain.toml")" \
  || fail "archived Rust toolchain pins are invalid or disagree"
active="$(cd "$source/crates/bloch-pos-node" && rustc --version)"
case "$active" in
  "rustc $pin "*) : ;;
  *) fail "active Rust compiler does not match the node pin $pin" ;;
esac

( cd "$source" && BLOCH_BUILD_COMMIT="${commit:0:12}" \
    cargo build --release --locked -p bloch-pos-node --bin bloch-pos \
      --target-dir "$work/target" )
binary="$work/target/release/bloch-pos"
[ -x "$binary" ] || fail "release binary was not produced"
version_file="$work/binary-version"
"$binary" --version > "$version_file" \
  || fail "release binary --version failed"
[ "$(wc -l < "$version_file" | tr -d '[:space:]')" = 2 ] \
  || fail "binary version output must contain exactly two newline-terminated lines"
binary_version="$(sed -n '1p' "$version_file")"
source_identity="$(sed -n '2p' "$version_file")"
cmp -s <(printf '%s\n%s\n' "$binary_version" "$source_identity") "$version_file" \
  || fail "binary version output must contain exactly two canonical text lines"
case "$binary_version" in
  *"(${commit:0:12})"*) : ;;
  *) fail "binary version line does not contain (${commit:0:12})" ;;
esac
LC_ALL=C grep -Eq \
  '^source-digest sha3-256:[0-9a-f]{64} \([0-9]+ files, [0-9]+ bytes\) commit-source:asserted tree:asserted-clean$' \
  <<< "$source_identity" \
  || fail "binary source identity line is not the exact asserted clean-source format"

rustc_verbose="$(cd "$source" && rustc -vV)" \
  || fail "rustc -vV failed while resolving the release target"
target_count="$(printf '%s\n' "$rustc_verbose" \
  | awk '/^host: / { count++ } END { print count + 0 }')"
[ "$target_count" = 1 ] \
  || fail "rustc -vV must report exactly one host target"
target="$(printf '%s\n' "$rustc_verbose" | sed -n 's/^host: //p')"
case "$target" in
  ''|*[!abcdefghijklmnopqrstuvwxyz0123456789_-]*|-*|*-|*--*)
    fail "rustc host target must be a lowercase ASCII Rust triple" ;;
  *-*-*) : ;;
  *) fail "rustc host target must be a lowercase ASCII Rust triple" ;;
esac

stage="$work/stage"
mkdir -p "$stage"
cp "$binary" "$stage/bloch-pos"
chmod 0755 "$stage/bloch-pos"
binary_sha="$(sha256_file "$stage/bloch-pos")" \
  || fail "SHA-256 tool failed for the packaged binary"
case "$binary_sha" in
  ''|*[!0123456789abcdef]*)
    fail "SHA-256 tool returned a non-lowercase hexadecimal digest" ;;
esac
[ "${#binary_sha}" = 64 ] \
  || fail "SHA-256 tool returned a digest that is not exactly 64 characters"
printf '%s  bloch-pos\n' "$binary_sha" > "$stage/SHA256SUMS"
{
  printf 'artifact_kind=unsigned-release-candidate\n'
  printf 'source_commit=%s\n' "$commit"
  printf 'source_commit_short=%s\n' "${commit:0:12}"
  printf 'rust_toolchain=%s\n' "$pin"
  printf 'target=%s\n' "$target"
  printf 'binary_sha256=%s\n' "$binary_sha"
  printf 'binary_version=%s\n' "$binary_version"
  printf 'binary_source_identity=%s\n' "$source_identity"
  printf 'tracked_tree_clean=true\n'
  printf 'canonical_container=false\n'
  printf 'signed=false\n'
  printf 'deployment_authorized=false\n'
} > "$stage/BUILD-INFO"

mkdir -p "$(dirname "$out_dir")"
[ ! -e "$out_dir" ] || fail "output path already exists: $out_dir"
mv "$stage" "$out_dir"
trap - EXIT
rm -rf "$work"
echo "package-pos-release-candidate: PASS — $out_dir ($binary_sha)"
