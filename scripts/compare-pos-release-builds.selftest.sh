#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-compare-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
make_fixture() {
  local dir="$1"
  mkdir "$dir"
  printf 'candidate binary\n' > "$dir/bloch-pos"
  chmod 0755 "$dir/bloch-pos"
  local sha
  if command -v sha256sum >/dev/null 2>&1; then
    sha="$(sha256sum "$dir/bloch-pos" | awk '{print $1}')"
  else
    sha="$(shasum -a 256 "$dir/bloch-pos" | awk '{print $1}')"
  fi
  printf '%s  bloch-pos\n' "$sha" > "$dir/SHA256SUMS"
  cat > "$dir/BUILD-INFO" <<EOF
artifact_kind=canonical-container-candidate
source_commit=0123456789abcdef0123456789abcdef01234567
source_date_epoch=1789689600
debian_snapshot=20260917T000000Z
target=x86_64-unknown-linux-gnu
binary_sha256=$sha
signed=false
deployment_authorized=false
EOF
}
expect_failure() {
  local label="$1" expected="$2"
  shift 2
  local output="$work/failure-output"
  if "$@" >"$output" 2>&1; then
    echo "selftest: $label was accepted" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$output"; then
    echo "selftest: $label failed without expected message: $expected" >&2
    cat "$output" >&2
    exit 1
  fi
}
make_fixture "$work/a"
cp -R "$work/a" "$work/b"
bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null
expect_failure "one directory as two builders" \
  "the two inputs resolve to the same directory" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$work/a"

expect_unsafe_write_mode() {
  local file="$1" mode="$2"
  local left="$work/write-mode-$file-a" right="$work/write-mode-$file-b"
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  chmod "$mode" "$left/$file" "$right/$file"
  expect_failure "matching unsafe write mode $mode on $file" \
    "$file must not be writable by group or others" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_unsafe_write_mode bloch-pos 0777
expect_unsafe_write_mode SHA256SUMS 0666
expect_unsafe_write_mode BUILD-INFO 0666

for file in bloch-pos SHA256SUMS BUILD-INFO; do
  hardlink_dir="$work/hardlink-$file"
  cp -R "$work/a" "$hardlink_dir"
  rm "$hardlink_dir/$file"
  ln "$work/a/$file" "$hardlink_dir/$file"
  expect_failure "hardlinked $file" \
    "the two inputs alias the same filesystem object for $file" \
    bash scripts/compare-pos-release-builds.sh "$work/a" "$hardlink_dir"

  symlink_dir="$work/symlink-$file"
  cp -R "$work/a" "$symlink_dir"
  rm "$symlink_dir/$file"
  ln -s "$work/a/$file" "$symlink_dir/$file"
  expect_failure "symlinked $file" \
    "$symlink_dir/$file must not be a symlink" \
    bash scripts/compare-pos-release-builds.sh "$work/a" "$symlink_dir"
done

extra_file_dir="$work/extra-file"
cp -R "$work/a" "$extra_file_dir"
printf '#!/bin/sh\necho unreviewed installer\n' > "$extra_file_dir/install.sh"
chmod 0755 "$extra_file_dir/install.sh"
expect_failure "extra executable file" \
  "must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found 4 entries)" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$extra_file_dir"

extra_dotfile_dir="$work/extra-dotfile"
cp -R "$work/a" "$extra_dotfile_dir"
printf 'unreviewed\n' > "$extra_dotfile_dir/.release-context"
expect_failure "extra dotfile" \
  "must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found 4 entries)" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$extra_dotfile_dir"

extra_subdir_dir="$work/extra-subdir"
cp -R "$work/a" "$extra_subdir_dir"
mkdir "$extra_subdir_dir/unreviewed"
expect_failure "extra subdirectory" \
  "must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found 4 entries)" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$extra_subdir_dir"

extra_newline_dir="$work/extra-newline"
cp -R "$work/a" "$extra_newline_dir"
printf 'unreviewed\n' > "$extra_newline_dir/line
break"
expect_failure "extra newline-bearing filename" \
  "must contain exactly bloch-pos, SHA256SUMS and BUILD-INFO (found 4 entries)" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$extra_newline_dir"

canonical_sha="$(
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$work/a/bloch-pos" | awk '{print $1}'
  else
    shasum -a 256 "$work/a/bloch-pos" | awk '{print $1}'
  fi
)"
manifest_error="SHA256SUMS is not the exact canonical one-line manifest"

manifest_comment_dir="$work/manifest-comment"
cp -R "$work/a" "$manifest_comment_dir"
printf '# ignored extra payload\n' >> "$manifest_comment_dir/SHA256SUMS"
expect_failure "checksum manifest comment" "$manifest_error" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$manifest_comment_dir"

manifest_blank_dir="$work/manifest-blank"
cp -R "$work/a" "$manifest_blank_dir"
printf '\n' >> "$manifest_blank_dir/SHA256SUMS"
expect_failure "checksum manifest blank line" "$manifest_error" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$manifest_blank_dir"

manifest_trailing_dir="$work/manifest-trailing"
cp -R "$work/a" "$manifest_trailing_dir"
printf 'trailing-without-newline' >> "$manifest_trailing_dir/SHA256SUMS"
expect_failure "checksum manifest trailing bytes" "$manifest_error" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$manifest_trailing_dir"

manifest_no_newline_dir="$work/manifest-no-newline"
cp -R "$work/a" "$manifest_no_newline_dir"
printf '%s  bloch-pos' "$canonical_sha" > "$manifest_no_newline_dir/SHA256SUMS"
expect_failure "checksum manifest missing final newline" "$manifest_error" \
  bash scripts/compare-pos-release-builds.sh "$work/a" "$manifest_no_newline_dir"

canonical_commit="$(sed -n 's/^source_commit=//p' "$work/a/BUILD-INFO")"
commit_error="source_commit must be a 40-character lowercase hexadecimal commit"
expect_bad_commit() {
  local label="$1" value="$2"
  local left="$work/commit-$label-a" right="$work/commit-$label-b"
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  sed -i.bak "s/^source_commit=.*/source_commit=$value/" \
    "$left/BUILD-INFO" "$right/BUILD-INFO"
  rm "$left/BUILD-INFO.bak" "$right/BUILD-INFO.bak"
  expect_failure "matching malformed source_commit ($label)" "$commit_error" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_bad_commit nonhex "g${canonical_commit#?}"
expect_bad_commit uppercase "$(printf '%s' "$canonical_commit" | tr 'a-f' 'A-F')"
expect_bad_commit short "${canonical_commit%?}"
expect_bad_commit long "${canonical_commit}0"

epoch_error="source_date_epoch must be a nonempty decimal integer"
expect_bad_epoch() {
  local label="$1" value="$2"
  local left="$work/epoch-$label-a" right="$work/epoch-$label-b"
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  sed -i.bak "s/^source_date_epoch=.*/source_date_epoch=$value/" \
    "$left/BUILD-INFO" "$right/BUILD-INFO"
  rm "$left/BUILD-INFO.bak" "$right/BUILD-INFO.bak"
  expect_failure "matching malformed source_date_epoch ($label)" "$epoch_error" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_bad_epoch letters not-a-timestamp
expect_bad_epoch negative -1789689600
expect_bad_epoch decimal 1789689600.5
expect_bad_epoch whitespace "1789689600 "

snapshot_error="debian_snapshot must have exact YYYYMMDDTHHMMSSZ syntax"
expect_bad_snapshot() {
  local label="$1" value="$2"
  local left="$work/snapshot-$label-a" right="$work/snapshot-$label-b"
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  sed -i.bak "s/^debian_snapshot=.*/debian_snapshot=$value/" \
    "$left/BUILD-INFO" "$right/BUILD-INFO"
  rm "$left/BUILD-INFO.bak" "$right/BUILD-INFO.bak"
  expect_failure "matching malformed debian_snapshot ($label)" "$snapshot_error" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_bad_snapshot text whatever-is-live
expect_bad_snapshot lowercase 20260917t000000z
expect_bad_snapshot separator 20260917-000000Z
expect_bad_snapshot short 20260917T00000Z
expect_bad_snapshot whitespace "20260917T000000Z "

snapshot_pin_error="debian_snapshot does not match the canonical Dockerfile snapshot"
expect_noncanonical_snapshot() {
  local label="$1" value="$2"
  local left="$work/snapshot-pin-$label-a" right="$work/snapshot-pin-$label-b"
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  sed -i.bak "s/^debian_snapshot=.*/debian_snapshot=$value/" \
    "$left/BUILD-INFO" "$right/BUILD-INFO"
  rm "$left/BUILD-INFO.bak" "$right/BUILD-INFO.bak"
  expect_failure "matching noncanonical debian_snapshot ($label)" \
    "$snapshot_pin_error" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_noncanonical_snapshot alternate-valid 20260918T000000Z
expect_noncanonical_snapshot structural-month-13 20261317T000000Z
expect_noncanonical_snapshot old-valid 20200101T000000Z

target_error="target must be a lowercase ASCII Rust host triple"
expect_bad_target() {
  local label="$1" value="$2"
  local left="$work/target-$label-a" right="$work/target-$label-b"
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  local dir
  for dir in "$left" "$right"; do
    awk -v value="$value" \
      '{ if ($0 ~ /^target=/) print "target=" value; else print }' \
      "$dir/BUILD-INFO" > "$dir/BUILD-INFO.new"
    mv "$dir/BUILD-INFO.new" "$dir/BUILD-INFO"
  done
  expect_failure "matching malformed target ($label)" "$target_error" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_bad_target whitespace "x86_64 unknown linux gnu"
expect_bad_target uppercase X86_64-unknown-linux-gnu
expect_bad_target path /tmp/custom-target.json
expect_bad_target two-components linux-gnu
expect_bad_target empty-component x86_64--linux-gnu

build_info_order_error="BUILD-INFO is not in the exact canonical field order and encoding"
expect_bad_build_info_order() {
  local label="$1" mode="$2"
  local left="$work/order-$label-a" right="$work/order-$label-b" dir
  cp -R "$work/a" "$left"
  cp -R "$work/a" "$right"
  for dir in "$left" "$right"; do
    case "$mode" in
      first-two)
        awk 'NR == 1 { first = $0; next }
             NR == 2 { print; print first; next }
             { print }' "$dir/BUILD-INFO" > "$dir/BUILD-INFO.new" ;;
      reverse)
        awk '{ lines[NR] = $0 }
             END { for (n = NR; n >= 1; n--) print lines[n] }' \
          "$dir/BUILD-INFO" > "$dir/BUILD-INFO.new" ;;
      middle)
        awk 'NR == 4 { fourth = $0; next }
             NR == 5 { print; print fourth; next }
             { print }' "$dir/BUILD-INFO" > "$dir/BUILD-INFO.new" ;;
    esac
    mv "$dir/BUILD-INFO.new" "$dir/BUILD-INFO"
  done
  expect_failure "matching noncanonical BUILD-INFO order ($label)" \
    "$build_info_order_error" \
    bash scripts/compare-pos-release-builds.sh "$left" "$right"
}
expect_bad_build_info_order first-two first-two
expect_bad_build_info_order reverse reverse
expect_bad_build_info_order middle middle

no_build_info_newline_left="$work/no-build-info-newline-a"
no_build_info_newline_right="$work/no-build-info-newline-b"
cp -R "$work/a" "$no_build_info_newline_left"
cp -R "$work/a" "$no_build_info_newline_right"
for dir in "$no_build_info_newline_left" "$no_build_info_newline_right"; do
  build_info_without_newline="$(cat "$dir/BUILD-INFO")"
  printf '%s' "$build_info_without_newline" > "$dir/BUILD-INFO"
done
expect_failure "BUILD-INFO missing final newline" \
  "BUILD-INFO must contain exactly the eight canonical fields" \
  bash scripts/compare-pos-release-builds.sh \
    "$no_build_info_newline_left" "$no_build_info_newline_right"

chmod 0644 "$work/b/bloch-pos"
if bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null 2>&1; then
  echo "selftest: non-executable binary was accepted" >&2; exit 1
fi
chmod 0755 "$work/b/bloch-pos"

printf 'tampered\n' >> "$work/b/bloch-pos"
if bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null 2>&1; then
  echo "selftest: tampered binary was accepted" >&2; exit 1
fi
cp "$work/a/bloch-pos" "$work/b/bloch-pos"
cp "$work/a/SHA256SUMS" "$work/b/SHA256SUMS"
sed -i.bak 's/source_commit=.*/source_commit=ffffffffffffffffffffffffffffffffffffffff/' "$work/b/BUILD-INFO"
rm -f "$work/b/BUILD-INFO.bak"
if bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null 2>&1; then
  echo "selftest: mismatched provenance was accepted" >&2; exit 1
fi
cp "$work/a/BUILD-INFO" "$work/b/BUILD-INFO"
printf 'signed=true\n' >> "$work/b/BUILD-INFO"
if bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null 2>&1; then
  echo "selftest: duplicate authorization field was accepted" >&2; exit 1
fi
cp "$work/a/BUILD-INFO" "$work/b/BUILD-INFO"
printf 'unexpected=same-looking-but-unsupported\n' >> "$work/b/BUILD-INFO"
if bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null 2>&1; then
  echo "selftest: noncanonical metadata field was accepted" >&2; exit 1
fi

echo "compare-pos-release-builds selftest: PASS"
