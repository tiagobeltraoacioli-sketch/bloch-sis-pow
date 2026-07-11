# ─────────────────────────────────────────────────────────────────────────────
#  Postern OS Mobile — OPTIONAL "Android compatibility" layer (Waydroid)
# ─────────────────────────────────────────────────────────────────────────────
#
#  ⚠  HONESTY HEADER — READ BEFORE ENABLING  ⚠
#
#  This layer runs a full ANDROID userland (LineageOS) inside an LXC container
#  via Waydroid. It exists ONLY so users who genuinely need an Android app can
#  opt in. It is the LESS-PRIVATE, NON-ATTESTABLE tier of Postern OS Mobile:
#
#    • It runs Google's Android stack (Bionic/ART/AOSP surface) next to your
#      post-quantum wallet — a much larger, less auditable trust surface than
#      the wallet-only base image.
#    • It is NOT covered by the Postern Seal attestation chain (os/attested.nix).
#      The Android container is mutable state pulled at `waydroid init`, not part
#      of the dm-verity-sealed rootfs — so `os_roothash` says NOTHING about what
#      runs inside Waydroid. Do not treat an Android app here as attested.
#    • Play Integrity / SafetyNet: the STRONG (hardware) verdict WILL fail, and
#      even BASIC/DEVICE verdicts are unreliable (no bootloader/keystore chain,
#      no CTS profile). Banking, DRM/Widevine-L1, and some wallet/2FA apps may
#      REFUSE to run. That is expected and is NOT a bug we can fix here.
#    • This is a SCAFFOLD. It has NEVER been built or booted on aarch64 hardware
#      in this repo. Every `# TODO: validate on-device` below is a real unknown.
#
#  Default posture: OFF. Nothing in this file activates unless you both
#  (a) import it in the mobile profile AND (b) set `postern.android.enable`.
#  Even when enabled it defaults to a Google-FREE image (microG/vanilla).
# ─────────────────────────────────────────────────────────────────────────────
#
#  Real integration references (researched, not invented):
#    • nixpkgs module: nixos/modules/virtualisation/waydroid.nix
#        option:  virtualisation.waydroid.enable
#        it sets: virtualisation.lxc.enable, boot.kernelParams = [ "psi=1" ],
#                 system.requiredKernelConfig = ANDROID_BINDER_IPC,
#                 ANDROID_BINDERFS, ASHMEM; gbinder /etc/gbinder.d/waydroid.conf;
#                 firewall trusts the `waydroid0` bridge; a `waydroid-container`
#                 systemd service (LXC).
#    • NixOS Wiki: Waydroid — needs a WAYLAND session; `waydroid init` pulls the
#                 system image; `-s GAPPS -f` adds Google apps (opt-in).
#    • Kernel: binder is mandatory. `ASHMEM` was dropped by Waydroid ≥1.2.1
#                 (memfd replaces it on Linux ≥5.18); newer kernels use the
#                 rust/upstream binder. PinePhone/Mobile-NixOS kernels do NOT
#                 ship these configs by default — see the on-device TODOs.

{ config, lib, pkgs, ... }:

let
  cfg = config.postern.android;
in
{
  # ── Feature gate ───────────────────────────────────────────────────────────
  options.postern.android = {
    enable = lib.mkEnableOption ''
      the OPTIONAL, NON-ATTESTABLE Android compatibility layer (Waydroid).
      Runs a full Android userland in LXC. Less private than the wallet-only
      base; Play Integrity STRONG will fail. Off by default'';

    googleApps = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Explicit opt-in to Google Play Services (GApps) instead of the private
        default (microG / a Google-free LineageOS "vanilla" image).

        This option only DOCUMENTS the choice for the operator — Waydroid pulls
        its system image at runtime via `waydroid init` (see the MOTD/README
        emitted below), NOT at Nix build time. Setting true here means "I intend
        to run `waydroid init -s GAPPS -f`"; leaving it false means the private
        microG/vanilla path. Either way this is your explicit, informed choice.

        Privacy note: GApps ships proprietary Google Play Services with broad
        device/telemetry access. Default (false) keeps the layer Google-free.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # ── The real nixpkgs Waydroid module ─────────────────────────────────────
    # Enables Waydroid + LXC, pulls in the binder/ashmem kernel-config
    # requirement, the gbinder config, the waydroid0 firewall trust, and the
    # `waydroid-container` service. Single source of truth for the integration.
    virtualisation.waydroid.enable = true;

    # On newer kernels the nft-based build is the working one. Harmless to pin;
    # flip if your nixpkgs lacks the attribute.
    # TODO: validate on-device — confirm `pkgs.waydroid-nftables` exists in the
    # pinned nixpkgs and is the right package for the device kernel's netfilter.
    # virtualisation.waydroid.package = pkgs.waydroid-nftables;

    # ── Kernel modules / config ───────────────────────────────────────────────
    # Waydroid needs Android binder. The nixpkgs module already REQUIRES the
    # kernel *config* (ANDROID_BINDER_IPC / ANDROID_BINDERFS / ASHMEM) via
    # system.requiredKernelConfig, so a kernel missing them fails to BUILD (good
    # — honest failure, not a silent no-op). Request the runtime modules too, in
    # case the device kernel builds them as loadable modules rather than builtin:
    boot.kernelModules = [
      "binder_linux"   # Android inter-process comms — mandatory for Waydroid.
      # "ashmem_linux" # Only for Waydroid <1.2.1 / kernels <5.18. Modern
                       # kernels drop ashmem (memfd replaces it); leaving it out
                       # avoids a load failure on new kernels.
    ];
    # Some kernels want binderfs devices named explicitly:
    boot.extraModprobeConfig = ''
      options binder_linux devices=binder,hwbinder,vndbinder
    '';

    # ── PinePhone / Mobile-NixOS reality ──────────────────────────────────────
    # The stock PinePhone / Mobile-NixOS kernels are typically built WITHOUT
    # CONFIG_ANDROID_BINDER_IPC / _BINDERFS. Without a kernel that has them,
    # `virtualisation.waydroid.enable` will fail system.requiredKernelConfig at
    # build time. You must supply a kernel with binder enabled, e.g. a
    # boot.kernelPatches entry (device-specific — cannot be written blind here):
    #
    #   boot.kernelPatches = [{
    #     name = "waydroid-binder";
    #     patch = null;
    #     extraStructuredConfig = with lib.kernel; {
    #       ANDROID_BINDER_IPC = yes;
    #       ANDROID_BINDERFS   = yes;
    #       # ASHMEM = yes;  # only if targeting kernel <5.18
    #     };
    #   }];
    #
    # TODO: validate on-device — pin the actual Mobile-NixOS device kernel,
    # confirm which binder configs it ships, and add the kernelPatches above ONLY
    # if they are missing. Left commented so the base eval never breaks.

    # ── Graphics ──────────────────────────────────────────────────────────────
    # Waydroid renders through the host GPU (gbm). On the PinePhone (Lima/Mali)
    # HW GL usually works; if it doesn't, Waydroid falls back to SwiftShader by
    # editing /var/lib/waydroid/waydroid_base.prop (ro.hardware.gralloc=default,
    # ro.hardware.egl=swiftshader) — runtime state, not settable from Nix.
    # TODO: validate on-device — check Lima GBM path vs SwiftShader on the panel.
    hardware.graphics.enable = lib.mkDefault true;

    # Waydroid REQUIRES a Wayland session to display. The wallet-first base image
    # is largely headless; a compositor (e.g. Phosh, or `cage` as a kiosk) must
    # be present for the Waydroid UI. Do not force a DE here — surface the
    # requirement honestly and let the device profile own the compositor.
    # TODO: validate on-device — confirm a Wayland compositor is active before
    # `waydroid show-full-ui`, else the container starts but nothing displays.

    # Clipboard bridge between host Wayland and the Android container.
    environment.systemPackages = [ pkgs.wl-clipboard ];

    # ── Operator-facing honesty at runtime ────────────────────────────────────
    # Anyone who logs into a device with this layer enabled sees exactly what
    # they opted into and how to finish setup on the private (default) path.
    users.motd = lib.mkForce ''
      ◆ Postern OS Mobile — wallet-first · post-quantum
        ⚠ ANDROID COMPATIBILITY LAYER ENABLED (Waydroid)

      This device runs a full Android userland in a container. It is the
      LESS-PRIVATE, NON-ATTESTABLE tier: it is NOT covered by the Postern Seal
      (os_roothash), and Play Integrity STRONG will fail — banking / DRM apps
      may refuse to run. Your wallet keys still live in the sealed base; keep
      secrets OUT of Android apps.

      Finish Android setup (PRIVATE default — no Google):
          sudo waydroid init            # pulls a Google-free LineageOS image
                                        # add microG separately for push/APIs
          waydroid show-full-ui         # needs an active Wayland session

      Google Play (EXPLICIT opt-in, less private):
          sudo waydroid init -s GAPPS -f
    '';
  };
}
