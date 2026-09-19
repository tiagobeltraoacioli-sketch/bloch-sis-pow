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
for arg in "$@"; do
  case "$arg" in
    type=local,dest=*) stage="${arg#type=local,dest=}" ;;
    BLOCH_BUILD_COMMIT=*) commit="${arg#BLOCH_BUILD_COMMIT=}" ;;
    SOURCE_DATE_EPOCH=*) epoch="${arg#SOURCE_DATE_EPOCH=}" ;;
  esac
done
[ -n "$stage" ] && [ -n "$commit" ] && [ -n "$epoch" ]
mkdir -p "$stage"
printf '#!/bin/sh\necho fake canonical candidate\n' > "$stage/bloch-pos"
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
deployment_authorized=false
EOF
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
  local mode="$1" output="$2"
  FAKE_MANIFEST_MODE="$mode" CONTAINER_ENGINE="$fake_engine" \
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

echo "build-pos-release-container selftest: PASS"
