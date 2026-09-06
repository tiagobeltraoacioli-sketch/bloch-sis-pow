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

# Portable sha256: prefer sha256sum (most Linux), fall back to shasum (macOS
# default, no sha256sum), fall back to openssl. A script that only tries
# `shasum` fails outright on a base Linux image with no BSD-perl toolchain —
# exactly the kind of "worked on my machine" gap a REPRODUCIBILITY tool must
# not have.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    echo "build.sh: no sha256sum, shasum, or openssl found — cannot verify a digest" >&2
    exit 1
  fi
}

# Deterministic timestamp = the HEAD commit time (never "now").
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
GIT_SHA="$(git rev-parse --short HEAD)"

# Probe buildkit's rewrite-timestamp capability EXPLICITLY, rather than
# attempting the real build and catching whatever comes back. Catching all
# failures meant a genuine build error (a compile failure, a missing
# dependency, a disk-full mid-build) silently retried under a DIFFERENT
# code path — the non-timestamp-clamped fallback — which can both mask the
# real error behind a confusing second failure, and silently produce a
# "reproducible" build that used wall-clock timestamps because the retry
# path was taken for the wrong reason. Probe once, decide once, and say
# which path was taken.
probe_rewrite_timestamp() {
  # `docker buildx build --help` lists supported --output suboptions in its
  # text; this is the same signal a real build's -o parser would use, without
  # spending a full build cycle to find out. If buildx itself is missing or
  # too old to even print help sanely, treat that as "not supported" rather
  # than erroring here — the actual build invocation below will fail loudly
  # and specifically if buildx is unusable.
  docker buildx build --help 2>&1 | grep -q -- 'rewrite-timestamp'
}

if probe_rewrite_timestamp; then
  REWRITE_TS=1
  echo "buildkit capability: rewrite-timestamp supported"
else
  REWRITE_TS=0
  echo "buildkit capability: rewrite-timestamp NOT detected (older buildkit) — falling back to unclamped output timestamps for the OCI layout itself; SOURCE_DATE_EPOCH still governs in-image file mtimes via the Dockerfile"
fi

build() {
  local out="$1"
  if [ "$REWRITE_TS" = "1" ]; then
    docker buildx build \
      --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      --provenance=false --sbom=false \
      --output "type=oci,dest=${out},rewrite-timestamp=true" \
      .
  else
    docker buildx build --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      --provenance=false --sbom=false --output "type=oci,dest=${out}" .
  fi
}

echo "commit=${GIT_SHA}  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
echo "building reproducible OCI image…"
build /tmp/bloch-repro-a.oci
DIGEST_A="$(sha256_file /tmp/bloch-repro-a.oci)"
echo "image OCI sha256: ${DIGEST_A}"

if [[ "${1:-}" == "verify" ]]; then
  echo "second independent build for verification…"
  build /tmp/bloch-repro-b.oci
  DIGEST_B="$(sha256_file /tmp/bloch-repro-b.oci)"
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
