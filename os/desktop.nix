# Postern OS — Desktop (privacy daily-driver profile). A Postern Labs product.
#
# The first real step from "an OS that runs the node" toward "a Linux people
# daily-drive for privacy" (the personalized-Linux vision): a hardened graphical
# desktop, full-disk encryption, private-by-default networking (Tor), the Postern
# Wallet, and the Postern Seal attestation — declaratively, on NixOS.
#
# Built on the Bloch-SIS-PoW protocol's tooling, but the OS is a Postern Labs
# product; anyone may build their own privacy OS on the same open protocol.
# ("Ownerless" was retracted — docs/adr/ADR-036-retract-ownerless-adopt-foundation.md.)
#
# The node it bundles is `bloch` (os/package.nix), the Genesis-3 proof-of-work
# node whose chain stopped permanently at height 39,918 on 2026-08-13. The live
# chain is Genesis-4, proof of stake; `bloch-pos` is not packaged for Nix.
#
# NOTE: a profile to ITERATE on a Nix host (`nix build .#desktop-iso`), not a
# frozen distro. A true daily-driver needs curation (apps, updates, device
# support) beyond this; this establishes the security/privacy spine.
{ config, lib, pkgs, blochPkg, ... }:
{
  imports = [ ./browser.nix ];   # the hardened Postern Browser

  networking.hostName = lib.mkForce "postern";

  # ── Graphical desktop (Wayland GNOME — familiar daily-driver) ──────────────
  services.xserver.enable = true;
  services.xserver.displayManager.gdm = { enable = true; wayland = true; };
  services.xserver.desktopManager.gnome.enable = true;
  # Strip GNOME's online/telemetry bits; keep the desktop, drop the phone-home.
  services.gnome.gnome-online-accounts.enable = lib.mkForce false;
  services.gnome.gnome-initial-setup.enable = lib.mkForce false;
  environment.gnome.excludePackages = with pkgs; [ gnome-tour epiphany geary ];

  # ── Full-disk encryption (LUKS) ────────────────────────────────────────────
  # systemd-in-initrd + TPM2 unlock support. The actual LUKS device is set at
  # install time; this enables the machinery + recommends an encrypted install.
  boot.initrd.systemd.enable = true;
  boot.initrd.systemd.tpm2.enable = lib.mkDefault true;
  # (install: cryptsetup luksFormat + boot.initrd.luks.devices.<name>.device)

  # ── Private-by-default networking ──────────────────────────────────────────
  networking.firewall.enable = true;           # deny inbound by default
  networking.firewall.allowedTCPPorts = [ ];
  services.tor = {
    enable = true;
    client.enable = true;                        # SOCKS at 127.0.0.1:9050
  };
  services.resolved = {                          # DNS-over-TLS
    enable = true;
    dnssec = "true";
    dnsovertls = "true";
  };
  networking.networkmanager.enable = true;
  # The minimal install-CD profile enables wpa_supplicant (networking.wireless);
  # NetworkManager manages Wi-Fi here, and the two are mutually exclusive.
  networking.wireless.enable = lib.mkForce false;

  # ── Hardening ──────────────────────────────────────────────────────────────
  security.apparmor.enable = true;
  security.sudo.execWheelOnly = true;
  boot.kernel.sysctl = {
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
  };
  # No coredumps of secret-holding processes; no telemetry.
  systemd.coredump.enable = false;
  services.speechd.enable = lib.mkDefault false;

  # ── Postern products on the desktop ────────────────────────────────────────
  environment.systemPackages = with pkgs; [
    blochPkg          # the node + `bloch-wallet` (Postern Wallet CLI) + `bloch-cli`
    tor torsocks
    gnome-terminal
    # the hardened Postern Browser (Firefox) is provided by ./browser.nix
  ];
  # The node is available but NOT mining by default on a laptop (battery/privacy);
  # opt in with `services.bloch.enable = true`.
  services.bloch.enable = lib.mkDefault false;

  # Encrypted keystores (Argon2 + AEAD) are the wallet default; the attestation
  # layer (Postern Seal) can prove this desktop is the genuine build — pair with
  # os/attested.nix for the immutable + measured variant.

  # ── Branding ───────────────────────────────────────────────────────────────
  users.motd = ''
    ◆ Postern OS — Desktop · privacy daily-driver
    Encrypted disk · Tor · hardened · post-quantum wallet.
    Wallet:  bloch-wallet --help
    A Postern Labs product built on the Bloch-SIS-PoW protocol.
  '';

  time.timeZone = lib.mkDefault "UTC";
  system.stateVersion = lib.mkDefault "25.05";
}
