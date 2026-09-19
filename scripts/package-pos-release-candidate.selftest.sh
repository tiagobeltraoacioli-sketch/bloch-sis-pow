#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Prove the unsigned candidate is built from one captured Git object, even if
# the checked-out branch advances after the clean-worktree preflight.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-package-selftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT
test_repo="$work/repo"
fake_bin="$work/bin"
mkdir -p "$test_repo/scripts" "$test_repo/crates/bloch-pos-node" \
  "$test_repo/.cargo" "$fake_bin"
cp "$repo_root/scripts/package-pos-release-candidate.sh" "$test_repo/scripts/"
cp "$repo_root/scripts/pinned-rust-toolchain.py" "$test_repo/scripts/"

printf 'baseline-source\n' > "$test_repo/source-marker"
printf '# baseline-config\n[net]\noffline = true\n' \
  > "$test_repo/.cargo/config.toml"
cat > "$test_repo/crates/bloch-pos-node/rust-toolchain.toml" <<'EOF'
[toolchain]
channel = "1.80.0"
EOF
cat > "$test_repo/rust-toolchain.toml" <<'EOF'
[toolchain]
channel = "1.80.0"
EOF
cat > "$test_repo/Cargo.toml" <<'EOF'
[workspace]
members = []
EOF

git -C "$test_repo" init -q
git -C "$test_repo" config user.name selftest
git -C "$test_repo" config user.email selftest@example.invalid
git -C "$test_repo" add .
git -C "$test_repo" commit -qm baseline
baseline_commit="$(git -C "$test_repo" rev-parse HEAD)"
real_git="$(command -v git)"
if command -v sha256sum >/dev/null 2>&1; then
  real_sha_tool="$(command -v sha256sum)"
  real_sha_kind=sha256sum
else
  real_sha_tool="$(command -v shasum)"
  real_sha_kind=shasum
fi

cat > "$fake_bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = archive ] && [ "${FAKE_ADVANCE_HEAD:-0}" = 1 ] \
    && [ ! -e "$TEST_REPO/.advanced-once" ]; then
  : > "$TEST_REPO/.advanced-once"
  printf 'late-source\n' > "$TEST_REPO/source-marker"
  printf '# late-config\n[net]\noffline = true\n' \
    > "$TEST_REPO/.cargo/config.toml"
  sed 's/1\.80\.0/1.81.0/' \
    "$TEST_REPO/crates/bloch-pos-node/rust-toolchain.toml" \
    > "$TEST_REPO/crates/bloch-pos-node/rust-toolchain.toml.new"
  mv "$TEST_REPO/crates/bloch-pos-node/rust-toolchain.toml.new" \
    "$TEST_REPO/crates/bloch-pos-node/rust-toolchain.toml"
  sed 's/1\.80\.0/1.81.0/' "$TEST_REPO/rust-toolchain.toml" \
    > "$TEST_REPO/rust-toolchain.toml.new"
  mv "$TEST_REPO/rust-toolchain.toml.new" "$TEST_REPO/rust-toolchain.toml"
  "$REAL_GIT" -C "$TEST_REPO" add source-marker .cargo/config.toml \
    rust-toolchain.toml crates/bloch-pos-node/rust-toolchain.toml
  "$REAL_GIT" -C "$TEST_REPO" commit -qm late-head
fi
exec "$REAL_GIT" "$@"
EOF
chmod 0755 "$fake_bin/git"

cat > "$fake_bin/rustc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ -f rust-toolchain.toml ]; then
  toolchain_file=rust-toolchain.toml
else
  toolchain_file=crates/bloch-pos-node/rust-toolchain.toml
fi
pin="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$toolchain_file")"
case "${1:-}" in
  --version) printf 'rustc %s (selftest)\n' "$pin" ;;
  -vV)
    case "${FAKE_RUSTC_MODE:-canonical}" in
      canonical)
        printf 'rustc %s (selftest)\n' "$pin"
        printf 'host: x86_64-unknown-linux-gnu\n'
        ;;
      exit) exit 70 ;;
      missing)
        printf 'rustc %s (selftest)\n' "$pin"
        ;;
      duplicate)
        printf 'rustc %s (selftest)\n' "$pin"
        printf 'host: x86_64-unknown-linux-gnu\n'
        printf 'host: aarch64-unknown-linux-gnu\n'
        ;;
      malformed)
        printf 'rustc %s (selftest)\n' "$pin"
        printf 'host: NOT A TARGET\n'
        ;;
    esac
    ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "$fake_bin/rustc"

cat > "$fake_bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${FAKE_SHA_MODE:-canonical}" in
  canonical)
    if [ "$REAL_SHA_KIND" = sha256sum ]; then
      exec "$REAL_SHA_TOOL" "$@"
    else
      exec "$REAL_SHA_TOOL" -a 256 "$@"
    fi
    ;;
  exit) exit 71 ;;
  short) printf 'abc  %s\n' "${1:-binary}" ;;
  nonhex)
    printf 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg  %s\n' \
      "${1:-binary}"
    ;;
  uppercase)
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  %s\n' \
      "${1:-binary}"
    ;;
  duplicate)
    printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' \
      "${1:-binary}"
    printf '1111111111111111111111111111111111111111111111111111111111111111  %s\n' \
      "${1:-binary}"
    ;;
esac
EOF
chmod 0755 "$fake_bin/sha256sum"

cat > "$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target_dir=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --target-dir ]; then
    shift
    target_dir="${1:-}"
  fi
  shift
done
[ -n "$target_dir" ]
source_marker="$(cat source-marker)"
config_marker="$(sed -n 's/^# //p' .cargo/config.toml)"
pin="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' \
  crates/bloch-pos-node/rust-toolchain.toml)"
version_mode="${FAKE_VERSION_MODE:-canonical}"
mkdir -p "$target_dir/release"
cat > "$target_dir/release/bloch-pos" <<BIN
#!/usr/bin/env bash
# source=$source_marker config=$config_marker pin=$pin
case '$version_mode' in
  canonical)
    printf '%s\n' 'bloch-pos-node 0.0.0 (${BLOCH_BUILD_COMMIT}) (Genesis-4, block version 0x00000004)'
    printf '%s\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    ;;
  missing-commit)
    printf '%s\n' 'bloch-pos-node 0.0.0 (unbound) (Genesis-4, block version 0x00000004)'
    printf '%s\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    ;;
  decoy-third)
    printf '%s\n' 'bloch-pos-node 0.0.0 (unbound) (Genesis-4, block version 0x00000004)'
    printf '%s\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    printf '%s\n' 'decoy (${BLOCH_BUILD_COMMIT})'
    ;;
  extra-line)
    printf '%s\n' 'bloch-pos-node 0.0.0 (${BLOCH_BUILD_COMMIT}) (Genesis-4, block version 0x00000004)'
    printf '%s\n' 'source-digest sha3-256:0000000000000000000000000000000000000000000000000000000000000000 (1 files, 1 bytes) commit-source:asserted tree:asserted-clean'
    printf '%s\n' 'unexpected third line'
    ;;
  malformed-source)
    printf '%s\n' 'bloch-pos-node 0.0.0 (${BLOCH_BUILD_COMMIT}) (Genesis-4, block version 0x00000004)'
    printf '%s\n' 'source-digest sha3-256:NOT-LOWERCASE-HEX (1 files, 1 bytes) commit-source:asserted tree:dirty'
    ;;
esac
BIN
chmod 0755 "$target_dir/release/bloch-pos"
EOF
chmod 0755 "$fake_bin/cargo"

run_package() {
  local version_mode="${2:-canonical}"
  local rustc_mode="${3:-canonical}"
  local sha_mode="${4:-canonical}"
  local package_umask="${5:-022}"
  ( umask "$package_umask"
    cd "$test_repo" && PATH="$fake_bin:$PATH" REAL_GIT="$real_git" \
      REAL_SHA_TOOL="$real_sha_tool" REAL_SHA_KIND="$real_sha_kind" \
      FAKE_VERSION_MODE="$version_mode" \
      FAKE_RUSTC_MODE="$rustc_mode" \
      FAKE_SHA_MODE="$sha_mode" \
      TEST_REPO="$test_repo" "$test_repo/scripts/package-pos-release-candidate.sh" \
      "$1" )
}

expect_sha_failure() {
  local mode="$1" expected="$2"
  local output="$work/sha-$mode" log="$work/sha-$mode.log"
  if run_package "$output" canonical canonical "$mode" > "$log" 2>&1; then
    echo "selftest: noncanonical SHA-256 mode $mode was accepted" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log" || {
    echo "selftest: SHA-256 mode $mode failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
}

expect_pin_failure() {
  local label="$1" root_pin="$2" node_pin="$3"
  local output="$work/pin-$label" log="$work/pin-$label.log"
  printf '%s' "$root_pin" > "$test_repo/rust-toolchain.toml"
  printf '%s' "$node_pin" \
    > "$test_repo/crates/bloch-pos-node/rust-toolchain.toml"
  git -C "$test_repo" add rust-toolchain.toml \
    crates/bloch-pos-node/rust-toolchain.toml
  git -C "$test_repo" commit -qm "pin-$label"
  if run_package "$output" > "$log" 2>&1; then
    echo "selftest: invalid toolchain pin case $label was accepted" >&2
    exit 1
  fi
  grep -Fq 'archived Rust toolchain pins are invalid or disagree' "$log" || {
    echo "selftest: toolchain pin case $label failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
}

expect_version_failure() {
  local mode="$1" expected="$2"
  local output="$work/version-$mode" log="$work/version-$mode.log"
  if run_package "$output" "$mode" > "$log" 2>&1; then
    echo "selftest: noncanonical --version mode $mode was accepted" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log" || {
    echo "selftest: --version mode $mode failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
}

expect_target_failure() {
  local mode="$1" expected="$2"
  local output="$work/target-$mode" log="$work/target-$mode.log"
  if run_package "$output" canonical "$mode" > "$log" 2>&1; then
    echo "selftest: noncanonical rustc target mode $mode was accepted" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log" || {
    echo "selftest: rustc target mode $mode failed without expected diagnostic" >&2
    cat "$log" >&2
    exit 1
  }
}

# Dirty input must still be refused before any archive or build is attempted.
printf 'dirty-before-start\n' > "$test_repo/source-marker"
if run_package "$work/dirty-output" > "$work/dirty.log" 2>&1; then
  echo "selftest: dirty tracked source was accepted" >&2
  exit 1
fi
grep -Fq 'tracked working tree differs from HEAD' "$work/dirty.log"
git -C "$test_repo" restore source-marker

# Advance HEAD exactly when archive is requested. The candidate must retain
# baseline source, config and toolchain bytes from the earlier captured OID.
FAKE_ADVANCE_HEAD=1 run_package "$work/race-output" > "$work/race.log" 2>&1
grep -Fxq "source_commit=$baseline_commit" "$work/race-output/BUILD-INFO"
grep -Fxq 'rust_toolchain=1.80.0' "$work/race-output/BUILD-INFO"
race_version="$($work/race-output/bloch-pos --version)"
printf '%s\n' "$race_version" | grep -Fq "(${baseline_commit:0:12})"
grep -Fq '# source=baseline-source config=baseline-config pin=1.80.0' \
  "$work/race-output/bloch-pos"
late_commit="$(git -C "$test_repo" rev-parse HEAD)"
[ "$late_commit" != "$baseline_commit" ]

# A subsequent clean invocation captures and builds the new OID normally.
run_package "$work/late-output" > "$work/late.log" 2>&1
grep -Fxq "source_commit=$late_commit" "$work/late-output/BUILD-INFO"
grep -Fxq 'rust_toolchain=1.81.0' "$work/late-output/BUILD-INFO"
late_version="$($work/late-output/bloch-pos --version)"
printf '%s\n' "$late_version" | grep -Fq "(${late_commit:0:12})"
grep -Fq '# source=late-source config=late-config pin=1.81.0' \
  "$work/late-output/bloch-pos"

# Published modes are deterministic even under a maximally permissive umask.
mode_output="$work/permissive-umask-output"
run_package "$mode_output" canonical canonical canonical 000 \
  > "$work/permissive-umask.log" 2>&1
for mode_path in "$mode_output" "$mode_output/bloch-pos"; do
  [ "$(find "$mode_path" -prune -perm 0755 -exec printf x \;)" = x ] || {
    echo "selftest: $mode_path is not mode 0755" >&2
    exit 1
  }
done
for mode_path in "$mode_output/SHA256SUMS" "$mode_output/BUILD-INFO"; do
  [ "$(find "$mode_path" -prune -perm 0644 -exec printf x \;)" = x ] || {
    echo "selftest: $mode_path is not mode 0644" >&2
    exit 1
  }
  [ -r "$mode_path" ] || {
    echo "selftest: $mode_path is not readable" >&2
    exit 1
  }
done
[ -x "$mode_output/bloch-pos" ] || {
  echo "selftest: packaged binary is not executable" >&2
  exit 1
}

expect_version_failure missing-commit \
  'binary version line does not contain ('
expect_version_failure decoy-third \
  'binary version output must contain exactly two newline-terminated lines'
expect_version_failure extra-line \
  'binary version output must contain exactly two newline-terminated lines'
expect_version_failure malformed-source \
  'binary source identity line is not the exact asserted clean-source format'

expect_target_failure exit \
  'rustc -vV failed while resolving the release target'
expect_target_failure missing \
  'rustc -vV must report exactly one host target'
expect_target_failure duplicate \
  'rustc -vV must report exactly one host target'
expect_target_failure malformed \
  'rustc host target must be a lowercase ASCII Rust triple'

expect_sha_failure exit \
  'SHA-256 tool failed for the packaged binary'
expect_sha_failure short \
  'SHA-256 tool returned a digest that is not exactly 64 characters'
expect_sha_failure nonhex \
  'SHA-256 tool returned a non-lowercase hexadecimal digest'
expect_sha_failure uppercase \
  'SHA-256 tool returned a non-lowercase hexadecimal digest'
expect_sha_failure duplicate \
  'SHA-256 tool returned a non-lowercase hexadecimal digest'

expect_pin_failure mismatch \
  $'[toolchain]\nchannel = "1.82.0"\n' \
  $'[toolchain]\nchannel = "1.81.0"\n'
expect_pin_failure duplicate \
  $'[toolchain]\nchannel = "1.82.0"\n' \
  $'[toolchain]\nchannel = "1.82.0"\nchannel = "stable"\n'
expect_pin_failure injection \
  $'[toolchain]\nchannel = "1.82.0"\n' \
  $'[toolchain]\nchannel = "$(touch /tmp/never-executed)"\n'

echo "package-pos-release-candidate selftest: PASS"
