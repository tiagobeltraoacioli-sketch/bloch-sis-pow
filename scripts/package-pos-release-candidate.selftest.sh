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

printf 'baseline-source\n' > "$test_repo/source-marker"
printf '# baseline-config\n[net]\noffline = true\n' \
  > "$test_repo/.cargo/config.toml"
cat > "$test_repo/crates/bloch-pos-node/rust-toolchain.toml" <<'EOF'
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
  "$REAL_GIT" -C "$TEST_REPO" add source-marker .cargo/config.toml \
    crates/bloch-pos-node/rust-toolchain.toml
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
    printf 'rustc %s (selftest)\n' "$pin"
    printf 'host: x86_64-unknown-linux-gnu\n'
    ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "$fake_bin/rustc"

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
  ( cd "$test_repo" && PATH="$fake_bin:$PATH" REAL_GIT="$real_git" \
      FAKE_VERSION_MODE="$version_mode" \
      TEST_REPO="$test_repo" "$test_repo/scripts/package-pos-release-candidate.sh" \
      "$1" )
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

expect_version_failure missing-commit \
  'binary version line does not contain ('
expect_version_failure decoy-third \
  'binary version output must contain exactly two newline-terminated lines'
expect_version_failure extra-line \
  'binary version output must contain exactly two newline-terminated lines'
expect_version_failure malformed-source \
  'binary source identity line is not the exact asserted clean-source format'

echo "package-pos-release-candidate selftest: PASS"
