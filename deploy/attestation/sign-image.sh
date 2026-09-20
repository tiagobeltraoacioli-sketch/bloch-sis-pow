#!/usr/bin/env bash
# Sign the reproducible Bloch image (L1) with cosign so CoCo's image-rs admits
# ONLY it (image-security-policy.json). This is the image-side half of binding
# attestation to the reproducible digest.
#
#   COSIGN_KEY=/secure/out-of-tree/path/cosign.key \
#     deploy/attestation/sign-image.sh \
#       docker.io/blochv/bloch:0.1@sha256:<64-lowercase-hex-digest>
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

IMAGE="${1:?usage: sign-image.sh <registry>/<repo>[:<tag>]@sha256:<64-lowercase-hex>}"

# Sign one immutable image identity, not whichever manifest a mutable tag
# happens to resolve to at each separate registry operation. This pins the
# exact same digest-bearing reference across sign, verify and triangulate.
IMAGE_REPOSITORY="${IMAGE%@sha256:*}"
IMAGE_DIGEST="${IMAGE##*@sha256:}"
if [[ -z "$IMAGE_REPOSITORY" \
   || "$IMAGE" != "$IMAGE_REPOSITORY@sha256:$IMAGE_DIGEST" \
   || "$IMAGE_REPOSITORY" == *"@"* \
   || "$IMAGE_REPOSITORY" == *[[:space:]]* \
   || ${#IMAGE_DIGEST} -ne 64 \
   || "$IMAGE_DIGEST" == *[!0-9a-f]* ]]; then
  echo "sign-image.sh: IMAGE must be an immutable reference ending in @sha256:<64 lowercase hex> (got: $IMAGE)" >&2
  exit 2
fi

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

if [[ -L "$COSIGN_KEY" ]]; then
  echo "sign-image.sh: COSIGN_KEY must not be a symbolic link: $COSIGN_KEY" >&2
  exit 2
fi

if ! COSIGN_KEY_DIR="$(cd -P -- "$(dirname -- "$COSIGN_KEY")" && pwd)"; then
  echo "sign-image.sh: cannot resolve COSIGN_KEY parent directory: $COSIGN_KEY" >&2
  exit 2
fi
COSIGN_KEY_REAL="$COSIGN_KEY_DIR/$(basename -- "$COSIGN_KEY")"

if [[ ! -f "$COSIGN_KEY_REAL" || -L "$COSIGN_KEY_REAL" ]]; then
  echo "sign-image.sh: resolved COSIGN_KEY is not a regular non-symlink file: $COSIGN_KEY_REAL" >&2
  exit 2
fi

# Refuse private-key aliases that could make an apparently external path name
# repository-owned bytes. This is intentionally a conservative local
# filesystem boundary; it does not claim to discover every possible Git
# metadata layout or filesystem-level alias.
key_ancestor="$COSIGN_KEY_DIR"
while :; do
  if [[ -e "$key_ancestor/.git" || -L "$key_ancestor/.git" ]]; then
    echo "sign-image.sh: COSIGN_KEY must be outside a Git worktree: $COSIGN_KEY_REAL" >&2
    exit 2
  fi
  [[ "$key_ancestor" == "/" ]] && break
  key_ancestor="$(dirname -- "$key_ancestor")"
done

if ! key_link_violation="$(find "$COSIGN_KEY_REAL" ! -links 1 -exec printf x \;)"; then
  echo "sign-image.sh: cannot inspect COSIGN_KEY link count: $COSIGN_KEY_REAL" >&2
  exit 2
fi
if [[ -n "$key_link_violation" ]]; then
  echo "sign-image.sh: COSIGN_KEY must have exactly one hard link: $COSIGN_KEY_REAL" >&2
  exit 2
fi

# `cosign generate-key-pair` creates an owner-private key. Preserve that
# confidentiality boundary instead of allowing a permissive umask or later
# chmod to make the secret group/world accessible. GNU and BSD/macOS expose
# the same octal mode through different `stat` forms; failure is a refusal.
if key_mode="$(stat -c '%a' "$COSIGN_KEY_REAL" 2>/dev/null)"; then
  :
elif key_mode="$(stat -f '%Lp' "$COSIGN_KEY_REAL" 2>/dev/null)"; then
  :
else
  echo "sign-image.sh: cannot inspect COSIGN_KEY permissions: $COSIGN_KEY_REAL" >&2
  exit 2
fi
case "$key_mode" in
  400|600) ;;
  *)
    echo "sign-image.sh: COSIGN_KEY permissions must be 0400 or 0600 (got: $key_mode): $COSIGN_KEY_REAL" >&2
    exit 2
    ;;
esac

# Pass the physical path whose ancestry and link count were validated.
COSIGN_KEY="$COSIGN_KEY_REAL"

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
echo "image digest to pin in CoCo policy: sha256:${IMAGE_DIGEST}"
echo "cosign signature object reference (informational):"
cosign triangulate "${IMAGE}" 2>/dev/null || true
echo
echo "Next: publish ${COSIGN_PUB} + image-security-policy.json to Trustee/KBS, then"
echo "deploy with CoCo (runtimeClassName: kata-qemu-*snp). The policy hash lands"
echo "in the SEV-SNP HOSTDATA of the attestation report — verified by"
echo "src/attestation::verify against your reproducible L1 digest."
