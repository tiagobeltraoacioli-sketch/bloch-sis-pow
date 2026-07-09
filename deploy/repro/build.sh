#!/usr/bin/env bash
# Reproducible build of the Bloch-SIS node image (Bloch-SIS-Linux L1).
#
# Produces a content-addressed OCI image whose digest depends ONLY on the source
# tree — the same commit yields the same digest on any machine. Two things make
# it reproducible: base images pinned by digest (Dockerfile), a committed
# Cargo.lock + vendored deps built with --locked, and SOURCE_DATE_EPOCH +
# buildkit's rewrite-timestamp to clamp all layer/file timestamps.
#
# Usage:  deploy/repro/build.sh            # build + print binary hash & image digest
#         deploy/repro/build.sh verify     # build twice, assert the digests match
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Deterministic timestamp = the HEAD commit time (never "now").
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
GIT_SHA="$(git rev-parse --short HEAD)"

build() {
  local out="$1"
  docker buildx build \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --provenance=false --sbom=false \
    --output "type=oci,dest=${out},rewrite-timestamp=true" \
    . >/dev/null 2>&1 || {
      # Fallback for older buildkit without rewrite-timestamp.
      docker buildx build --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        --provenance=false --sbom=false --output "type=oci,dest=${out}" .
    }
}

echo "commit=${GIT_SHA}  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
echo "building reproducible OCI image…"
build /tmp/bloch-repro-a.oci
DIGEST_A="$(shasum -a 256 /tmp/bloch-repro-a.oci | awk '{print $1}')"
echo "image OCI sha256: ${DIGEST_A}"

if [[ "${1:-}" == "verify" ]]; then
  echo "second independent build for verification…"
  build /tmp/bloch-repro-b.oci
  DIGEST_B="$(shasum -a 256 /tmp/bloch-repro-b.oci | awk '{print $1}')"
  echo "image OCI sha256: ${DIGEST_B}"
  if [[ "$DIGEST_A" == "$DIGEST_B" ]]; then
    echo "✅ REPRODUCIBLE — both builds produced ${DIGEST_A}"
  else
    echo "❌ NON-REPRODUCIBLE — digests differ:"
    echo "   A=${DIGEST_A}"
    echo "   B=${DIGEST_B}"
    exit 1
  fi
fi
