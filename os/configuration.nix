# Postern OS — a minimal NixOS image that boots straight into a running node.
# A Postern Labs product built on the ownerless Bloch-SIS-PoW protocol (anyone
# may build their own products on the protocol).
{ config, pkgs, lib, blochPkg, ... }:
{
  networking.hostName = lib.mkForce "postern-os";

  # Mine out of the box (PoW secures the chain). Turn off with mine = false.
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
