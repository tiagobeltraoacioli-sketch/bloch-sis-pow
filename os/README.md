# Postern OS — a reproducible NixOS appliance with the node built in

A Postern Labs product. A minimal, declarative NixOS image that boots straight
into a running (mining) Bloch-SIS node. (The Bloch-SIS-PoW protocol is
ownerless — anyone may build their own OS/products on it.) Because it's NixOS, the **same inputs produce the same image** —
the reproducibility that L1 (the reproducible container build) and Coherence are
built on, now at the OS level.

> **Postern OS vs Postern Desktop** — different tools, both kept:
> - **Postern OS** (this) — a *whole operating system* you boot; the node is a
>   system service. For running a node / a dedicated Bloch machine.
> - **Postern Desktop** (`../desktop`) — a *desktop app* you install on your
>   existing Linux/Mac/Windows; a node companion + wallet for anyone who just
>   wants to hold keys / protect sensitive data without replacing their OS.

## What's in it

- The `bloch` node (+ `bloch-wallet`/`bloch-cli`) as a reproducible Nix package
  (`os/package.nix`) — built from the self-contained workspace (vendored
  pqcrypto, committed `Cargo.lock`), no network/git fetches.
- A **hardened systemd service** (`os/bloch-node.nix`) for the RETIRED
  Genesis-3 binary (`bloch`) — dedicated user, `ProtectSystem=strict`,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, syscall filtering,
  `MemoryMax`/`TasksMax` containment, an `IPAddressDeny=any` perimeter with
  an operator-filled allowlist, no core dumps (mirrors the L2 container
  hardening).
- A **hardened systemd service** (`os/bloch-pos-node.nix`) for the LIVE
  Genesis-4 proof-of-stake binary (`bloch-pos`) — the same hardening spine,
  plus loopback-only RPC and metrics, and the sealed keystore passphrase
  delivered via systemd `LoadCredential=` rather than an environment
  variable. **Its package default does not yet resolve to a real
  `bloch-pos` build** — see the TODO in that file; wiring the actual
  derivation is a follow-up, not done in this pass.
- An **interim health watchdog** (`os/health-watchdog.nix`) — polls
  `/health` and restarts the target unit on sustained (not single-blip)
  failure. `deploy/monitoring/`'s Prometheus alerts are the primary fix;
  this is the backstop for a host without that stack running.
- A minimal live/installer config (`os/configuration.nix`) that mines on boot.

## Build & run (on a Linux host with Nix + flakes)

```bash
# Bootable ISO  ->  ./result/iso/*.iso
nix build .#iso

# Just the node package
nix build .#bloch && ./result/bin/bloch --help

# Try it in a VM without flashing
nixos-rebuild build-vm --flake .#bloch-os && ./result/bin/run-*-vm

# Flash the ISO to USB (careful with the device!)
sudo dd if=result/iso/*.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

On boot the node auto-starts: `systemctl status bloch`, `journalctl -u bloch -f`.

## Add the node to an existing NixOS host (no full image)

```nix
{
  inputs.bloch.url = "git+https://gitlab.com/bloch-sis-group/bloch-sis-project";
  # ...
  imports = [ bloch.nixosModules.bloch ];
  services.bloch = { enable = true; mine = true; };
}
```

## Toward an attested OS (Bloch-SIS-Linux)

NixOS gives reproducibility (same input → same image). The next rungs, reusing
the existing attestation layer (`docs/specs/BLOCH-SIS-ATTESTATION.md`):

- **Immutable + measured boot** — a read-only, dm-verity-sealed image with a UKI
  so the boot measurement is stable and attestable.
- **TEE binding** — run the image in a SEV-SNP/TDX confidential VM; the launch
  measurement binds to this reproducible image, verified by L3 (`getattestation`
  RPC + the `AttestationProvider`).

That turns "reproducible OS" into "reproducible *and* remotely-attestable OS".

## Honesty

- **Not built in this sandbox** (no Nix on the dev host) — this is validated,
  idiomatic Nix that builds on a Linux host with `nix`. Pin `nixpkgs` and run
  `nix flake check` there.
- First `nix build` compiles the whole node (rocksdb linked from the system
  package) — minutes, cached afterwards.
- Testnet is zero-security by design; no privacy/attestation claim until each is
  audited.
