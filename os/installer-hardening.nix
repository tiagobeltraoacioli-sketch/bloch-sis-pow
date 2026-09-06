# Live-media hardening for the ISO images (.#iso and .#desktop-iso).
#
# FINDING C-R6-1 (second pass, composed-image level). Both ISO configs import
# nixos-25.05's installation-cd-minimal.nix, which (via installation-cd-base.nix)
# imports nixos/modules/profiles/installation-device.nix. That profile ships an
# installer that is remotely reachable with EMPTY passwords:
#
#   services.openssh.enable            = mkDefault true;     (priority 1000)
#   services.openssh.settings.PermitRootLogin = mkDefault "yes";  (priority 1000)
#   users.users.nixos.initialHashedPassword   = "";          (plain, priority 100)
#   users.users.root.initialHashedPassword    = "";          (plain, priority 100)
#
# os/configuration.nix's own `services.openssh.enable = lib.mkDefault true`
# (priority 1000) never contradicted it, so the COMPOSED image booted with sshd
# up, port 22 opened by the openssh module (openFirewall defaults true), and two
# empty-password accounts — regardless of any text-level edits to configuration.nix.
#
# THE MERGE, TRACED (NixOS module option priorities: lower number wins;
# lib.mkForce = mkOverride 50, plain assignment = 100, lib.mkDefault = 1000,
# lib.mkImageMediaOverride = mkOverride 60):
#
#   services.openssh.enable:
#     profile mkDefault true (1000)  vs  configuration.nix mkDefault true (1000)
#     vs  THIS FILE mkForce false (50)              -> composed value: false
#   users.users.root.initialHashedPassword:
#     profile "" (100)  vs  THIS FILE mkForce "!" (50)   -> composed value: "!"
#   users.users.nixos.initialHashedPassword:
#     profile "" (100)  vs  THIS FILE mkForce "!" (50)   -> composed value: "!"
#   services.bloch.mine:
#     configuration.nix true (100)  vs  THIS FILE mkForce false (50) -> false
#
# "!" is the classic locked-password hash: no password authenticates, ever.
# The installer stays usable exactly the way upstream intends for a keyless,
# passwordless live image: the profile's getty autologin (nixos) on the console
# plus passwordless wheel sudo. Nothing can log in over the network.
#
# Scope: imported ONLY by the two ISO nixosConfigurations in flake.nix
# (bloch-os, postern-desktop). The attested/appliance images do not import the
# installer profile and are not touched here.
#
# Guarded by scripts/check-iso-hardening.py (static, CI, no Nix) and proven on
# the composed config by scripts/check-iso-hardening.sh (nix eval, Nix host).
{ config, lib, ... }:
{
  # sshd does not run on live media. mkForce (50) beats both the installer
  # profile's and configuration.nix's mkDefault true (1000).
  services.openssh.enable = lib.mkForce false;

  # Belt and braces: if a later module ever re-enables sshd at priority < 50,
  # it still refuses passwords and root. (KbdInteractiveAuthentication guards
  # the PAM keyboard-interactive path that bypasses PasswordAuthentication.)
  services.openssh.settings = {
    PermitRootLogin = lib.mkForce "no";
    PasswordAuthentication = lib.mkForce false;
    KbdInteractiveAuthentication = lib.mkForce false;
  };

  # Lock both accounts instead of leaving them empty. initialHashedPassword is
  # the operative option on live media (users are created fresh every boot);
  # overriding the same option the profile sets also avoids NixOS's
  # multiple-password-options precedence warning.
  users.users.root.initialHashedPassword = lib.mkForce "!";
  users.users.nixos.initialHashedPassword = lib.mkForce "!";

  # A live image must not silently spend the machine owner's electricity:
  # the node may run, but mining is strictly opt-in after boot
  # (`sudo systemctl edit bloch` / installed-system configuration).
  services.bloch.mine = lib.mkForce false;

  # The profile's help text promises empty passwords and ssh; both are now
  # false. Replace it (plain 100 beats nothing, mkForce for determinism).
  services.getty.helpLine = lib.mkForce ''

    Console access: the "nixos" account is logged in automatically and has
    passwordless sudo. Network logins are disabled on this live image: sshd
    is off and the "nixos"/"root" passwords are locked. To administer over
    ssh, set a password AND enable sshd explicitly:
        sudo passwd nixos && sudo systemctl start sshd
    Mining is OFF on live media; opt in from an installed system.
  '';

  # Deny-inbound stance stated here too, so the ISO does not depend on another
  # module for its firewall (mkDefault: configuration.nix/desktop.nix already
  # assert it at plain priority).
  networking.firewall.enable = lib.mkDefault true;
}
