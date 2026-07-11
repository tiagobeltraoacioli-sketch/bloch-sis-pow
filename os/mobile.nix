# Postern OS Mobile — the phone profile (wallet-first). A Postern Labs product.
#
# Phones can't meaningfully do Module-SIS PoW, so this is a wallet / key vault,
# not a miner (matches the project scope: "mobile = wallet only, focus is PoW").
# Layered on top of a Mobile NixOS device config (kernel/modem/display come from
# the device module).
{ config, lib, pkgs, blochPkg, ... }:
{
  # OPTIONAL Android compatibility (Waydroid) — OFF by default and intentionally
  # NOT imported. It is the less-private, NON-attestable tier: it runs a full
  # Android userland, is not covered by the Postern Seal, and Play Integrity
  # STRONG will fail. Opt in by uncommenting the import AND setting the gate:
  #
  #   imports = [ ./android-compat.nix ];
  #   postern.android.enable = true;      # runs Android in LXC (see the header)
  #   # postern.android.googleApps = true; # EXPLICIT opt-in to Google Play/GApps
  #
  # See os/android-compat.nix for the full honesty header + on-device TODOs.

  networking.hostName = lib.mkForce "postern-phone";

  # No mining node on a phone — ship the wallet + tooling instead.
  services.bloch.enable = lib.mkForce false;

  # The wallet CLI + the post-quantum crypto stack (byte-identical to the node).
  environment.systemPackages = [ blochPkg ];

  users.motd = ''
    ◆ Postern OS Mobile — wallet-first · post-quantum

    Your key vault:  bloch-wallet --help
    Phones don't mine (PoW runs on desktops/nodes) — this holds keys + signs.
    Hybrid Falcon‖ML-DSA · addresses identical to the node.
  '';

  # Phone hygiene: keep it lean, favour battery + privacy.
  documentation.enable = lib.mkDefault false;
  services.openssh.enable = lib.mkDefault false;

  # A touch wallet UI is the app layer on top: reuse the desktop web UI in a
  # mobile shell, or a UniFFI-backed native app over `bloch-mobile`'s WalletCore.
  # (Tracked separately — this profile ships the OS + the wallet engine.)
}
