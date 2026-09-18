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
make_fixture "$work/a"
cp -R "$work/a" "$work/b"
bash scripts/compare-pos-release-builds.sh "$work/a" "$work/b" >/dev/null
if bash scripts/compare-pos-release-builds.sh "$work/a" "$work/a" >/dev/null 2>&1; then
  echo "selftest: one directory was accepted as two builders" >&2; exit 1
fi

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
