#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# boot-qemu-aarch64.sh — Rung 1 of the mobile boot ladder: boot the Postern OS
# Mobile image under qemu-system-aarch64 (TCG, no KVM) and capture the serial
# console as boot evidence. Proves the SOFTWARE boot chain only.
#
#   built ≠ booted     — a green `nix build` is not this.
#   QEMU ≠ hardware    — `-M virt` models NO phone DTB, DSI panel, touch, modem
#                        or power. This says NOTHING about a PinePhone.
#   reproducible-by-design ≠ reproduced.
#   UNAUDITED reference prototype; the coin is worthless by design.
#
# This harness has NEVER been booted green on any host. It is written to run on
# an aarch64 Linux host with Nix + flakes + qemu-system-aarch64 — the same
# Graviton that ./build-aarch64-graviton.sh builds on. Rung 0 (the build) is
# delegated to that builder so the flake ATTRIBUTE lives in exactly one place.
#
# Usage:
#   boot-qemu-aarch64.sh [--image <store-path|dir>] [--log <file>]
#                        [--timeout <secs>] [--mem <MiB>] [--smp <n>]
# Env overrides: IMAGE, LOG, BOOT_TIMEOUT, MEM, SMP, QEMU_CPU, QEMU_MACHINE.
# With no --image, it calls ./build-aarch64-graviton.sh to produce one (Rung 0).
#
# Definition of done (Rung 1), per the boot-bring-up plan §2:
#   1. The captured log shows kernel → Mobile-NixOS stage-1 → systemd → getty
#      with NO `Kernel panic` and NO `Entering emergency mode`
#      (graded by ./check-boot-log.sh against ./success-markers.txt).
#   2. bloch-wallet --help succeeds on the emulated console — an INTERACTIVE /
#      CI-expect follow-up (this headless harness proves boot-to-login; it does
#      not type into the console).
#   3. The log is kept as evidence with the image store path + sha256 recorded
#      alongside (this script writes a `<log>.evidence` sidecar).
#   4. It runs unattended in CI (exit codes below). Wiring the CI job itself is
#      a separate deliverable — this script is what that job calls.
#
# Exit: 0 boot passed the marker ladder; 1 markers failed; 2 boot/QEMU failure
#       marker; 4 could not produce/locate a bootable artifact; 5 missing tools.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` is the intended scoped-empty idiom
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

IMAGE=${IMAGE:-}
LOG=${LOG:-/tmp/qemu-aarch64-boot.log}
BOOT_TIMEOUT=${BOOT_TIMEOUT:-600}
MEM=${MEM:-2048}
SMP=${SMP:-2}
QEMU_CPU=${QEMU_CPU:-cortex-a53}
QEMU_MACHINE=${QEMU_MACHINE:-virt}

while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE=$2; shift 2 ;;
    --log) LOG=$2; shift 2 ;;
    --timeout) BOOT_TIMEOUT=$2; shift 2 ;;
    --mem) MEM=$2; shift 2 ;;
    --smp) SMP=$2; shift 2 ;;
    -h|--help) sed -n '3,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 5 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 5; }; }
need qemu-system-aarch64
need grep
need awk

# ── 1. Produce or locate the artifact (delegate Rung 0 to the builder) ────────
# Single source of truth for the flake attribute is build-aarch64-graviton.sh;
# this harness never hard-codes the mobile-image attr itself.
if [ -z "$IMAGE" ]; then
  echo "==> no --image given; building via ./build-aarch64-graviton.sh (Rung 0)"
  IMAGE=$(sh "$HERE/build-aarch64-graviton.sh" --no-provenance 2>&1 | tee /dev/stderr | tail -n1) || {
    echo "Rung 0 build failed — nothing to boot (see the builder output above)." >&2
    exit 4
  }
fi
if [ ! -e "$IMAGE" ]; then
  echo "artifact not found: $IMAGE" >&2
  exit 4
fi
echo "==> artifact: $IMAGE"

# ── 2. Record boot evidence provenance BEFORE booting ─────────────────────────
EVIDENCE="${LOG%.log}.evidence"
{
  echo "# Postern OS Mobile — QEMU-aarch64 boot evidence (Rung 1)"
  echo "# UNAUDITED. built≠booted; QEMU≠hardware; reproducible-by-design≠reproduced."
  echo "timestamp   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host        : $(uname -srm 2>/dev/null || echo unknown)"
  echo "qemu        : $(qemu-system-aarch64 --version 2>/dev/null | head -n1)"
  echo "machine     : -M $QEMU_MACHINE -cpu $QEMU_CPU -m $MEM -smp $SMP (TCG, no KVM)"
  echo "image_path  : $IMAGE"
  if command -v nix >/dev/null 2>&1; then
    echo "image_nixhash: $(nix hash path "$IMAGE" 2>/dev/null || echo 'n/a')"
  fi
  if command -v sha256sum >/dev/null 2>&1 && [ -f "$IMAGE" ]; then
    echo "image_sha256: $(sha256sum "$IMAGE" | awk '{print $1}')"
  fi
  echo "log         : $LOG"
} > "$EVIDENCE"
echo "==> evidence sidecar: $EVIDENCE"

# ── 3. Boot. Prefer a Mobile-NixOS device runner; fall back to -M virt ────────
# The device output usually ships a runner (name varies by mobile-nixos rev).
RUNNER=""
if [ -d "$IMAGE" ]; then
  for cand in boot-qemu run-postern-phone-vm boot-vm runvm; do
    if [ -x "$IMAGE/$cand" ]; then RUNNER="$IMAGE/$cand"; break; fi
  done
  if [ -z "$RUNNER" ]; then
    RUNNER=$(find "$IMAGE" -maxdepth 2 -type f \( -name 'run-*-vm' -o -name '*boot-qemu*' \) 2>/dev/null | head -n1 || true)
  fi
fi

# Bound a hung boot: prefix the emulator with `timeout` when available so an
# unattended CI run cannot wedge forever (124 = timed out).
TIMEOUT_PREFIX=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_PREFIX="timeout --foreground $BOOT_TIMEOUT"
fi

boot() {
  if [ -n "$RUNNER" ]; then
    echo "==> booting via Mobile-NixOS device runner: $RUNNER"
    # shellcheck disable=SC2086
    $TIMEOUT_PREFIX "$RUNNER"
    return
  fi

  # Fallback: drive kernel + initrd on the generic virt board. virt uses a
  # QEMU-GENERATED DTB — do NOT pass a phone DTB here (that is the #1 QEMU↔
  # hardware divergence). Locate kernel/initrd inside the artifact.
  KERNEL=""; INITRD=""
  if [ -d "$IMAGE" ]; then
    for k in kernel Image zImage; do [ -f "$IMAGE/$k" ] && KERNEL="$IMAGE/$k" && break; done
    for i in initrd initrd.img initramfs; do [ -f "$IMAGE/$i" ] && INITRD="$IMAGE/$i" && break; done
  fi
  if [ -z "$KERNEL" ] || [ -z "$INITRD" ]; then
    echo "could not find a device runner OR a kernel+initrd inside the artifact." >&2
    echo "The bootable output attribute varies by the pinned mobile-nixos rev —" >&2
    echo "expose kernel+initrd (or a runner) and/or adjust this harness for your pin." >&2
    return 4
  fi
  echo "==> booting via fallback: qemu-system-aarch64 -M $QEMU_MACHINE (kernel+initrd)"
  # shellcheck disable=SC2086
  $TIMEOUT_PREFIX qemu-system-aarch64 \
    -M "$QEMU_MACHINE" -cpu "$QEMU_CPU" -m "$MEM" -smp "$SMP" \
    -kernel "$KERNEL" -initrd "$INITRD" \
    -append 'console=ttyAMA0 loglevel=7' \
    -nographic -serial mon:stdio -no-reboot
}

echo "==> capturing serial console to $LOG (timeout ${BOOT_TIMEOUT}s)"
set +e
# BOOT_RC is tee's status (POSIX sh has no PIPESTATUS); the marker grading in
# check-boot-log.sh is the real gate. A `timeout` kill still lands in the log.
boot 2>&1 | tee "$LOG"
BOOT_RC=$?
set -e

# ── 4. Grade the captured log against the shared marker contract ──────────────
echo "==> grading $LOG against $HERE/success-markers.txt"
set +e
sh "$HERE/check-boot-log.sh" "$LOG" "$HERE/success-markers.txt"
CHECK_RC=$?
set -e

{
  echo "boot_rc     : ${BOOT_RC:-n/a}"
  echo "check_rc    : $CHECK_RC"
} >> "$EVIDENCE"

echo "==> evidence: $EVIDENCE"
echo "==> NEXT (DoD #2, interactive/CI-expect): on the console run"
echo "        bloch-wallet --help        # wallet engine loaded"
echo "        systemctl is-system-running"
exit "$CHECK_RC"
