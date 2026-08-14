# Postern OS Mobile — a phone OS, wallet-first

A Postern Labs product, the mobile sibling of Postern OS: a **reproducible Linux
phone OS** (via [Mobile NixOS](https://github.com/nix-community/mobile-nixos))
that ships the Postern Wallet as a first-class key vault. Same NixOS flake, same reproducibility,
same post-quantum crypto — on a phone.

> **Historical framing — Genesis-3.** The reasoning below is from the
> proof-of-work era. That chain stopped permanently at height 39,918 on
> 2026-08-13; the live chain is **Genesis-4, proof of stake** (30 s slots,
> 32-slot epochs, finality by epoch), where nothing mines at all and blocks come
> from a proposer schedule over staked validators. The wallet-only scope still
> holds, for a different reason: a phone is a key vault, and validator duty is
> not a phone workload. The image also packages `bloch` (Genesis-3), not
> `bloch-pos` — see the banner in `flake.nix`.

> **Scope: wallet only.** Phones can't mine the Bloch-SIS PoW competitively, so
> Postern OS Mobile does **not** mine — PoW secured the Genesis-3 chain from
> desktops/nodes. The phone holds keys and signs (hybrid Falcon‖ML-DSA,
> addresses byte-identical to the node). This matched the project's decision at
> the time: *mobile = wallet, focus is PoW*.

## The Postern clients, clarified

| | Runs on | What it is | Mines? |
|---|---|---|---|
| **Postern OS** | a computer you boot | full node OS | yes |
| **Postern OS Mobile** | a phone you boot | wallet OS / key vault | no |
| **Postern Desktop** | your existing OS | node-companion app | via the node |
| **bloch-mobile** | inside another mobile app | the wallet *engine* (Rust) | no |

## Devices

Mobile NixOS targets Linux phones (PinePhone, Librem 5, …) and has device ports
for many **Android** phones (mainline/downstream kernels). The flake defaults to
`pine64-pinephone`; change `device` in `flake.nix` (`mobile-image`) to your
handset — see the Mobile NixOS device list.

## Build (on a Nix host)

```bash
# Phone image for the configured device
nix build .#mobile-image

# The output is device-specific (e.g. a flashable disk image / Android boot img);
# follow Mobile NixOS's flashing guide for your device.
```

The image includes `bloch-wallet` (CLI) + the crypto stack. A touch wallet UI is
the app layer on top — reuse the Postern Desktop web UI in a mobile shell, or a
UniFFI-backed native app over `bloch-mobile`'s `WalletCore`.

## Pinned revisions (fill after `nix flake lock` — see REPRO.md §"#2")

Once the Nix host runs `nix flake lock`, record the resolved revs here so the
aarch64 wallet build is documented and the pin is human-visible:

```
date:                      <YYYY-MM-DD>
nixpkgs rev:               <from `nix flake metadata`>
mobile-nixos rev:          <from `nix flake metadata`>
mobile-nixos-nixpkgs rev:  <mobile-nixos's own npins nixpkgs pin>
```

(These are placeholders — an agent cannot run Nix. REPRO.md §"#2" has the exact
commands that emit each value.)

## Honesty

- **Not built in this sandbox** (no Nix; Mobile NixOS also needs device configs).
  Validated, idiomatic config that builds on a Nix host with the device port —
  `nix build .#mobile-image`. Mobile NixOS APIs evolve; pin its revision.
- Wallet-only by design — no mining, no misleading "phone mining" claims.
- Testnet is zero-security; a phone wallet on testnet holds worthless coins.
