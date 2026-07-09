#!/usr/bin/env bash
# Sign the reproducible Bloch image (L1) with cosign so CoCo's image-rs admits
# ONLY it (image-security-policy.json). This is the image-side half of binding
# attestation to the reproducible digest.
#
#   deploy/attestation/sign-image.sh docker.io/blochv/bloch:0.1
#
# Prereqs: cosign installed; the image pushed to the registry.
set -euo pipefail

IMAGE="${1:?usage: sign-image.sh <registry>/<repo>:<tag>}"

# One-time: generate a signing keypair. Keep cosign.key SECRET; publish cosign.pub
# to Trustee/KBS (the kbs:// keyPath in image-security-policy.json).
if [[ ! -f cosign.key ]]; then
  echo "no cosign.key found — generating a keypair (guard cosign.key!)"
  cosign generate-key-pair
fi

echo "signing ${IMAGE}…"
cosign sign --key cosign.key --yes "${IMAGE}"

echo "verifying signature…"
cosign verify --key cosign.pub "${IMAGE}" >/dev/null && echo "✅ signed & verified"

echo
echo "digest that CoCo will pin:"
cosign triangulate "${IMAGE}" 2>/dev/null || true
echo
echo "Next: publish cosign.pub + image-security-policy.json to Trustee/KBS, then"
echo "deploy with CoCo (runtimeClassName: kata-qemu-*snp). The policy hash lands"
echo "in the SEV-SNP HOSTDATA of the attestation report — verified by"
echo "src/attestation::verify against your reproducible L1 digest."
