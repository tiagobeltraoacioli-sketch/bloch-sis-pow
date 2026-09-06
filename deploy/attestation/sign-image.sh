#!/usr/bin/env bash
# Sign the reproducible Bloch image (L1) with cosign so CoCo's image-rs admits
# ONLY it (image-security-policy.json). This is the image-side half of binding
# attestation to the reproducible digest.
#
#   COSIGN_KEY=/secure/out-of-tree/path/cosign.key \
#     deploy/attestation/sign-image.sh docker.io/blochv/bloch:0.1
#
# Prereqs: cosign installed; the image pushed to the registry.
#
# KEY HANDLING (MED-10 fix): this script NEVER auto-generates a signing key,
# and never writes or reads one from the current working directory. A key
# silently generated into whatever directory the script happened to be run
# from is one accidental `git add -A` away from a private signing key
# committed to this repository — the repo is public, and a leaked cosign key
# lets anyone sign an image CoCo's image-rs would then admit as genuine.
# `COSIGN_KEY` is REQUIRED, must be an absolute path, and must already exist;
# this script only ever reads it, never writes it. Generate the keypair
# yourself, once, with `cosign generate-key-pair`, into a path this script's
# operator controls and that is outside every git working tree on the host
# (a secrets manager, an HSM-backed path, or at minimum a directory excluded
# from every repo's .gitignore AND never `git add`ed).
set -euo pipefail

IMAGE="${1:?usage: sign-image.sh <registry>/<repo>:<tag>}"

COSIGN_KEY="${COSIGN_KEY:?COSIGN_KEY must be set to an absolute path to an existing cosign private key. This script will not generate one and will not look in the current directory. Generate with: cosign generate-key-pair (into a path OUTSIDE any git working tree), then re-run with COSIGN_KEY=<that path>/cosign.key}"

case "$COSIGN_KEY" in
  /*) ;;
  *) echo "sign-image.sh: COSIGN_KEY must be an absolute path (got: $COSIGN_KEY)" >&2; exit 2 ;;
esac

if [[ ! -f "$COSIGN_KEY" ]]; then
  echo "sign-image.sh: COSIGN_KEY does not exist: $COSIGN_KEY" >&2
  echo "This script never generates a key. Create one with 'cosign generate-key-pair'" >&2
  echo "in a directory that is NOT inside this or any other git working tree." >&2
  exit 2
fi

COSIGN_PUB="${COSIGN_PUB:-${COSIGN_KEY%.key}.pub}"
if [[ ! -f "$COSIGN_PUB" ]]; then
  echo "sign-image.sh: expected public key at $COSIGN_PUB (override with COSIGN_PUB=)" >&2
  exit 2
fi

echo "signing ${IMAGE}…"
cosign sign --key "$COSIGN_KEY" --yes "${IMAGE}"

echo "verifying signature…"
cosign verify --key "$COSIGN_PUB" "${IMAGE}" >/dev/null && echo "✅ signed & verified"

echo
echo "digest that CoCo will pin:"
cosign triangulate "${IMAGE}" 2>/dev/null || true
echo
echo "Next: publish ${COSIGN_PUB} + image-security-policy.json to Trustee/KBS, then"
echo "deploy with CoCo (runtimeClassName: kata-qemu-*snp). The policy hash lands"
echo "in the SEV-SNP HOSTDATA of the attestation report — verified by"
echo "src/attestation::verify against your reproducible L1 digest."
