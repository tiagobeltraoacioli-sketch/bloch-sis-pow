# Postern OS — a minimal NixOS image that boots straight into a running node.
#
# GENESIS-3. `blochPkg` is `bloch`, the proof-of-work node whose chain stopped
# permanently at height 39,918 on 2026-08-13. This image therefore boots a miner
# with no network to join. The live chain is Genesis-4, proof of stake, and its
# binary `bloch-pos` is not packaged for Nix — see the banner in flake.nix.
# Kept as part of the Genesis-3 record. ("ownerless" was retracted — see
# docs/adr/ADR-036-retract-ownerless-adopt-foundation.md.)
{ config, pkgs, lib, blochPkg, ... }:
{
  networking.hostName = lib.mkForce "postern-os";

  # Mine out of the box. Genesis-3 only — proof of work secured that chain until
  # it stopped; the live chain is proof of stake and this flag reaches nothing.
  # Turn off with mine = false.
  services.bloch = {
    enable = true;
    mine = true;
    package = blochPkg;
  };

  # Node + wallet CLI on the console.
  environment.systemPackages = [ blochPkg ];

  users.motd = ''
    ◆ Postern OS — Module-SIS PoW · Falcon‖ML-DSA · pure PoW

    The node runs as a hardened service:
        systemctl status bloch
        journalctl -u bloch -f
    Wallet CLI:  bloch-wallet --help

    Testnet is ZERO-security by design — do not attach value.
  '';

  # Reasonable defaults for an appliance.
  networking.firewall.enable = true;
  time.timeZone = lib.mkDefault "UTC";
  services.openssh.enable = lib.mkDefault true;

  # Live-image state version; on an installed system pin to your install.
  system.stateVersion = lib.mkDefault "25.05";
}
