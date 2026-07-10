# Postern OS — Desktop (privacy daily-driver)

A Postern Labs product: the first real step from *"an OS that runs the node"*
toward *"a Linux people daily-drive for privacy"* — the personalized-Linux vision
(an Android/RedHat-style curated distro), built declaratively on NixOS.

Built on the **ownerless Bloch-SIS-PoW protocol**'s tooling, but the OS is a
Postern Labs product — and anyone may build their own privacy OS on the same open
protocol.

## What's in it (`os/desktop.nix`)

| Spine | Choice |
|---|---|
| **Desktop** | hardened Wayland GNOME (telemetry/online-accounts/initial-setup stripped) |
| **Disk** | full-disk encryption (LUKS) — systemd-initrd + TPM2 unlock support |
| **Network** | private by default: firewall (deny inbound), **Tor** client (SOCKS 9050), DNS-over-TLS + DNSSEC |
| **Browser** | **Postern Browser** — hardened Firefox (`os/browser.nix`): resistFingerprinting, strict tracking protection, HTTPS-only, no telemetry, no IP leaks, uBlock Origin |
| **Hardening** | AppArmor, `execWheelOnly` sudo, kptr/dmesg restrict, no coredumps, no telemetry |
| **Wallet** | **Postern Wallet** (`bloch-wallet` CLI) + the post-quantum crypto stack |
| **Node** | available, **off by default** on a laptop (battery/privacy); opt in with `services.bloch.enable = true` |
| **Attestation** | pair with `os/attested.nix` for the immutable + measured **Postern Seal** variant |

## Build (on a Nix host)

```bash
nix build .#desktop-iso     # → result/iso/*.iso  (a live/installer ISO)
```
Install with full-disk encryption: `cryptsetup luksFormat` the root partition,
then set `boot.initrd.luks.devices.<name>.device` before `nixos-install`.

## Honesty

- **Not built in this sandbox** (no Nix here). It's an idiomatic, valid NixOS
  profile that builds on a Nix host — like the rest of `os/`.
- It's a **profile to iterate**, not a frozen distro. It establishes the
  security/privacy **spine** (encryption, Tor, hardening, hardware-attestable
  integrity). A true daily-driver competing with Windows/macOS still needs
  curation this doesn't yet have: a curated private app set, an update channel,
  and device support. (The hardened **Postern Browser** is now included —
  `os/browser.nix`.)
- The **Postern Container (Android)** and the app layer are the next products on
  the roadmap (`docs/POSTERN-LABS.md`).
