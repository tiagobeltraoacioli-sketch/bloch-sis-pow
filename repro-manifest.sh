#!/usr/bin/env bash
# repro-manifest.sh <flake-attr>
#
# Build one flake attr and emit a reproducibility manifest: the arch-agnostic
# narHash (content hash of the whole build output) plus, when the output is a
# disk image, the raw-image sha256 and the dm-verity roothash.
#
# Run this IDENTICALLY on host A and host B (same committed flake.lock), then
# feed the two manifests to repro-compare.sh. See REPRO.md §"#9".
#
# Examples (native on an aarch64 host — cheapest, highest-signal first):
#   ./repro-manifest.sh .#packages.aarch64-linux.bloch
#   ./repro-manifest.sh .#packages.aarch64-linux.attested-image
#   ./repro-manifest.sh .#mobile-image
#
# HONESTY: a matching manifest across two independent builders is what earns the
# word "reproducible". A single host proves nothing on its own; on one host use
# `nix build … --rebuild --check` (see REPRO.md) for the self-check.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <flake-attr>   e.g. .#packages.aarch64-linux.bloch" >&2
  exit 2
fi
ATTR="$1"

OUT=$(nix build "$ATTR" --print-out-paths --no-link -L)

MANIFEST="manifest-$(hostname)-$(echo "$ATTR" | tr -c 'A-Za-z0-9' _).txt"

{
  echo "attr:        $ATTR"
  echo "host:        $(uname -mno)"
  echo "nix:         $(nix --version)"
  echo "flake.lock:  $(sha256sum flake.lock | cut -d' ' -f1)"
  echo "outpath:     $OUT"
  # narHash = canonical content hash of the whole build output (arch-agnostic
  # form). Two hosts with the same flake.lock compute the same store-path *name*
  # regardless; only identical CONTENT yields an identical narHash. That is the
  # bit-for-bit test.
  echo "narHash:     $(nix path-info --json "$OUT" | jq -r 'to_entries[0].value.narHash')"

  # For a disk image (attested-image / mobile-image): also hash the raw image and
  # dump the dm-verity roothash. If the raw sha256 matches, the roothash matches
  # BY CONSTRUCTION (roothash is a pure function of the rootfs bytes).
  IMG=$(find "$OUT" -maxdepth 2 \( -name '*.raw' -o -name '*.img' \) 2>/dev/null | head -1 || true)
  if [ -n "${IMG:-}" ]; then
    echo "image:       $IMG"
    echo "image_sha256:$(sha256sum "$IMG" | cut -d' ' -f1)"
    # roothash from the verity partition (needs systemd-dissect; read-only, no boot):
    ROOT=$(sudo systemd-dissect --json=short "$IMG" 2>/dev/null | jq -r \
        '.mounts[]? | select(.type|test("verity")) | .roothash' 2>/dev/null || true)
    [ -n "${ROOT:-}" ] && echo "roothash:    $ROOT"
  fi
} | tee "$MANIFEST"

echo "wrote $MANIFEST" >&2
