# Postern OS — a reproducible NixOS appliance with the node built in

> **The node built in is Genesis-3 — the retired proof-of-work node.** Every
> output of this directory (`iso`, `attested-image`, `mobile-image`,
> `postern-desktop`) is built from `os/package.nix`, which builds `bloch`. The
> proof-of-work chain stopped permanently at height 39,918 on 2026-08-13, so an
> image built from here boots into a miner with no network to join. The live
> chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality
> by epoch) and its binary, `bloch-pos`, is **not packaged for Nix at all** —
> see the banner in `flake.nix`. That is a stated gap, not an oversight to read
> around: packaging `bloch-pos` and repointing these outputs is real work nobody
> has done.
>
> "Ownerless" was also retracted — see
> `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`.

A Postern Labs product. A minimal, declarative NixOS image that boots straight
into a running (mining) Bloch-SIS Genesis-3 node. Because it's NixOS, the
**same inputs produce the same image** — the reproducibility that L1 (the
reproducible container build) and Coherence are built on, now at the OS level.

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
- A **hardened systemd service** (`os/bloch-node.nix`) — dedicated user,
  `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, syscall
  filtering, no core dumps (mirrors the L2 container hardening).
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
- **This appliance does not run the live chain.** It packages the retired
  Genesis-3 node only. Under Genesis-4 the security question is not hashrate,
  it is concentration: all 64 validators are run by one entity, 93.94% of the
  carryover sits at a single address, and 56.05 B of the 57.15 B BLOCH issued at
  genesis is held by the founder and the Foundation. One operator can halt the
  chain and one holder can outvote every other. A third party cannot yet join:
  the transport has a fixed peer list and no discovery, and `Deposit`/`Delegate`
  are refused at every node's mempool.
