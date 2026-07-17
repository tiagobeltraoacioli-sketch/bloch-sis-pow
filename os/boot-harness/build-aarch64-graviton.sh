#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# build-aarch64-graviton.sh — Rung 0 of the mobile boot ladder: BUILD the
# Postern OS Mobile image natively on an aarch64 host (an AWS Graviton, an
# Ampere box, an Apple-silicon Linux VM — anything `uname -m` = aarch64 with
# Nix + flakes). Native aarch64 = NO binfmt/qemu-user emulation, so this is the
# cheapest honest determinism probe (bundled RocksDB 8.10 C++ is the #1
# nondeterminism risk — see REPRO.md §"#9").
#
#   built ≠ booted   — a green build here is NOT a boot. Rung 1 is
#                      ./boot-qemu-aarch64.sh, and even that is QEMU ≠ hardware.
#   reproducible-by-design ≠ reproduced — nobody has rebuilt this to a matching
#                      hash on a second builder yet.
#   UNAUDITED reference prototype; the coin is worthless by design.
#
# This script has NEVER been run on the dev workstation (macOS: no Nix). It is
# written to run on an aarch64 Linux host with Nix + flakes.
#
# ── WHICH ATTRIBUTE (branch-specific — read this) ─────────────────────────────
# In THIS branch's flake.nix the flashable image is exposed as
#
#       packages.x86_64-linux.mobile-image           (flake.nix ~line 86)
#
# whose DERIVATION is pinned to `system = "aarch64-linux"` internally (the image,
# its closure, and blochPkg are all aarch64). So:
#   * The attribute lives in the x86_64-linux attr SET, but Nix evaluation is
#     platform-independent and lazy — forcing just `.mobile-image` never builds
#     any x86_64 derivation; the whole closure it pulls is aarch64-native.
#   * Therefore the portable, host-agnostic selector is the FULLY-QUALIFIED
#     `.#packages.x86_64-linux.mobile-image`. On a Graviton it builds natively.
#   * The BARE alias `.#mobile-image` resolves via `packages.<current-system>`,
#     i.e. `packages.aarch64-linux.mobile-image` on a Graviton — which this
#     branch's flake does NOT define (the aarch64-linux set has bloch / default /
#     attested-image only). So bare `.#mobile-image` works ONLY on an x86_64
#     host and 404s on aarch64. Do not use it here; that is the exact rung-0
#     death recorded for the sibling harness (see evidence/README.md).
# If a later flake change also exposes `packages.aarch64-linux.mobile-image`,
# override with `ATTR=.#packages.aarch64-linux.mobile-image` — env below.
#
# Usage:
#   build-aarch64-graviton.sh [--attr <flake-attr>] [--out <symlink>]
#                             [--extra-nix-arg <arg>]... [--no-provenance]
# Env overrides: ATTR, OUT, EXTRA_NIX_ARGS (space-separated), FLAKE (default '.').
#
# Output: prints the built store path on the LAST stdout line (so a caller can
# `IMAGE=$(build-aarch64-graviton.sh | tail -n1)`), and writes a provenance
# sidecar `<out>.provenance` with the store path + `nix hash path` + sha256.
#
# Exit: 0 build succeeded (store path on last line); 3 not an aarch64 host and
#       emulation not explicitly allowed; 4 nix build failed; 5 missing tool.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` is the intended scoped-empty idiom
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)   # os/boot-harness
OSDIR=$(dirname -- "$HERE")                          # os
REPO=$(dirname -- "$OSDIR")                          # repo root

FLAKE=${FLAKE:-.}
ATTR=${ATTR:-.#packages.x86_64-linux.mobile-image}
OUT=${OUT:-}
NO_PROVENANCE=0
EXTRA_NIX_ARGS=${EXTRA_NIX_ARGS:-}

while [ $# -gt 0 ]; do
  case "$1" in
    --attr) ATTR=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --extra-nix-arg) EXTRA_NIX_ARGS="$EXTRA_NIX_ARGS $2"; shift 2 ;;
    --no-provenance) NO_PROVENANCE=1; shift ;;
    -h|--help) sed -n '3,55p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 5 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 5; }; }
need nix

# ── Native-aarch64 gate ───────────────────────────────────────────────────────
# The whole point of this script is a NATIVE build. If we are not on aarch64,
# refuse unless the operator has explicitly wired up binfmt qemu-user emulation
# AND opted in with ALLOW_EMULATED_BUILD=1 (SLOW; not the honest determinism
# probe — see the flake's BUILD NOTE and os/MOBILE.md).
ARCH=$(uname -m 2>/dev/null || echo unknown)
case "$ARCH" in
  aarch64|arm64) : ;;  # native — the intended path
  *)
    if [ "${ALLOW_EMULATED_BUILD:-0}" != "1" ]; then
      echo "refusing: host arch is '$ARCH', not aarch64." >&2
      echo "This builder is for NATIVE aarch64 (a Graviton). To cross-build on" >&2
      echo "x86_64 you must have binfmt qemu-user + 'extra-platforms =" >&2
      echo "aarch64-linux' in nix.conf, then re-run with ALLOW_EMULATED_BUILD=1" >&2
      echo "(SLOW; emulated ≠ the native determinism probe)." >&2
      exit 3
    fi
    echo "==> WARNING: emulated cross-build on '$ARCH' (ALLOW_EMULATED_BUILD=1)."
    echo "    This is SLOW and is NOT the native-aarch64 determinism probe."
    ;;
esac

echo "==> repo   : $REPO"
echo "==> flake  : $FLAKE"
echo "==> attr   : $ATTR"
echo "==> host   : $(uname -srm 2>/dev/null || echo unknown)"
echo "==> nix    : $(nix --version 2>/dev/null || echo unknown)"
echo "==> building the Postern OS Mobile image (first build cross-compiles the"
echo "    node + bundled RocksDB — expect a long, CPU-bound run; cached after)."

cd "$REPO" || { echo "cannot cd to repo root: $REPO" >&2; exit 4; }

# Build. --print-out-paths decouples us from ./result symlink layout; keep a
# named symlink too if the operator asked for one (--out / OUT), else --no-link.
set -- build "$ATTR" --print-out-paths
if [ -n "$OUT" ]; then
  set -- "$@" --out-link "$OUT"
else
  set -- "$@" --no-link
fi
# shellcheck disable=SC2086  # EXTRA_NIX_ARGS is an intentional word-split list
STORE_PATH=$(nix "$@" $EXTRA_NIX_ARGS 2>&1 | tee /dev/stderr | tail -n1) || {
  echo "nix build $ATTR FAILED — rung 0 not satisfied; nothing to boot." >&2
  echo "If the error is an attribute-resolution 404, re-check --attr against" >&2
  echo "this branch's flake.nix (see the WHICH ATTRIBUTE header above)." >&2
  exit 4
}

if [ ! -e "$STORE_PATH" ]; then
  echo "build reported success but store path is not present: '$STORE_PATH'" >&2
  exit 4
fi
echo "==> BUILD OK"
echo "==> store path: $STORE_PATH"

# ── Provenance sidecar (record what was built, before anyone boots it) ────────
if [ "$NO_PROVENANCE" -eq 0 ]; then
  PROV="${OUT:-$HERE/evidence/last-build}.provenance"
  mkdir -p "$(dirname -- "$PROV")" 2>/dev/null || true
  {
    echo "# Postern OS Mobile — aarch64 build provenance (Rung 0)"
    echo "# UNAUDITED. built≠booted; reproducible-by-design≠reproduced."
    echo "timestamp   : $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
    echo "host        : $(uname -srm 2>/dev/null || echo unknown)"
    echo "arch        : $ARCH"
    echo "nix         : $(nix --version 2>/dev/null | head -n1)"
    echo "flake_attr  : $ATTR"
    echo "store_path  : $STORE_PATH"
    echo "store_nixhash: $(nix hash path "$STORE_PATH" 2>/dev/null || echo 'n/a')"
    if command -v sha256sum >/dev/null 2>&1 && [ -f "$STORE_PATH" ]; then
      echo "store_sha256: $(sha256sum "$STORE_PATH" | awk '{print $1}')"
    fi
    echo "note        : native build if arch=aarch64; boot is a SEPARATE rung."
  } > "$PROV" 2>/dev/null && echo "==> provenance sidecar: $PROV"
fi

echo "==> NEXT (Rung 1, still not hardware): boot it under QEMU with"
echo "        $HERE/boot-qemu-aarch64.sh --image $STORE_PATH"
# The store path MUST be the last stdout line (caller contract).
echo "$STORE_PATH"
