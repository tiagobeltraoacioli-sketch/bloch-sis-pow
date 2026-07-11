{
  description = "Bloch-SIS — the node packaged for Nix + Postern OS, a reproducible NixOS appliance with the node built in";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  # Mobile NixOS powers Postern OS Mobile (phones). Not a flake — used via its
  # top-level default.nix ({ device, configuration, pkgs/system }); pin a
  # revision on your build host. (Canonical org is mobile-nixos, not
  # nix-community — the latter 404s.)
  inputs.mobile-nixos = { url = "github:mobile-nixos/mobile-nixos"; flake = false; };

  outputs = { self, nixpkgs, mobile-nixos }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # The phone is aarch64; its node/wallet package must be too. Built
      # natively-for-aarch64 (via binfmt emulation on an x86_64 host).
      pkgsAarch64 = nixpkgs.legacyPackages.aarch64-linux;
    in
    {
      # The node itself, as a Nix package (reproducible build of the workspace).
      packages.${system} = {
        bloch = pkgs.callPackage ./os/package.nix { };
        default = self.packages.${system}.bloch;

        # Bootable ISO: `nix build .#iso` -> result/iso/*.iso
        iso = self.nixosConfigurations.bloch-os.config.system.build.isoImage;

        # Immutable, dm-verity-sealed disk image (measured/attestable):
        # `nix build .#attested-image`
        attested-image = self.nixosConfigurations.bloch-os-attested.config.system.build.image;

        # Postern OS Mobile — a phone image (wallet-first) via Mobile NixOS.
        # `nix build .#mobile-image`. DEVICE is per-phone; pinephone here.
        # Android devices go through Mobile NixOS device ports.
        #
        # Entrypoint: mobile-nixos's top-level default.nix takes
        # { device, configuration, pkgs } (configuration = ONE NixOS module);
        # `.outputs.default` is the flashable image — for u-boot devices like
        # the PinePhone it aliases mobile.outputs.u-boot.disk-image.
        # BUILD NOTE: aarch64 image on an x86_64 host (Fly/OVH) needs
        # binfmt qemu + `extra-platforms = aarch64-linux` in nix.conf, and it
        # is SLOW. Expected, not a bug.
        # NOTE: we hand Mobile NixOS this flake's nixos-25.05 nixpkgs (it uses
        # pkgs.path as the module source); upstream develops against its own
        # npins pin, so if eval breaks on a bump, drop `pkgs = ...` for
        # `system = "aarch64-linux"` to use upstream's pinned nixpkgs.
        mobile-image = (import mobile-nixos {
          device = "pine64-pinephone";
          # Use Mobile NixOS's own pinned nixpkgs — its master overlay (gui-assets
          # needs `svgo`, etc.) drifts from our nixos-25.05, which breaks eval.
          system = "aarch64-linux";
          configuration = {
            imports = [
              self.nixosModules.bloch
              ./os/mobile.nix
            ];
            _module.args.blochPkg = self.packages.aarch64-linux.bloch;
          };
        }).outputs.default;

        # Postern OS Desktop — the privacy daily-driver live ISO.
        desktop-iso = self.nixosConfigurations.postern-desktop.config.system.build.isoImage;
      };

      # The same node package, built for aarch64 (consumed by mobile-image).
      packages.aarch64-linux = {
        bloch = pkgsAarch64.callPackage ./os/package.nix { };
        default = self.packages.aarch64-linux.bloch;
      };

      # Reusable NixOS module — add `services.bloch.enable = true` to any host.
      nixosModules.bloch = import ./os/bloch-node.nix;

      # Postern OS: a minimal NixOS live/installer image that boots straight into a
      # running (mining) node.
      nixosConfigurations.bloch-os = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { blochPkg = self.packages.${system}.bloch; };
        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
          self.nixosModules.bloch
          ./os/configuration.nix
        ];
      };

      # Immutable + attestable Postern OS: same node, sealed with dm-verity + a UKI
      # + measured boot, so its roothash/measurement is attestable (L3).
      nixosConfigurations.bloch-os-attested = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { blochPkg = self.packages.${system}.bloch; };
        modules = [
          "${nixpkgs}/nixos/modules/image/repart.nix"
          self.nixosModules.bloch
          ./os/configuration.nix
          ./os/attested.nix
        ];
      };

      # Postern OS Desktop — the privacy daily-driver profile (hardened GNOME +
      # LUKS + Tor + Postern Wallet). `nix build .#desktop-iso` → live ISO.
      nixosConfigurations.postern-desktop = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { blochPkg = self.packages.${system}.bloch; };
        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
          self.nixosModules.bloch
          ./os/desktop.nix
          # The live installer ISO must use the SCRIPTED initrd: its ISO9660 +
          # squashfs store mount (/sysroot/iso, /nix/.ro-store) has no equivalent
          # in the systemd initrd that desktop.nix turns on for encrypted installs.
          # Leaving systemd-initrd on drops the live media to emergency mode.
          { boot.initrd.systemd.enable = nixpkgs.lib.mkForce false; }
        ];
      };

      # Convenience: `nix run` a VM of the OS to try it without flashing.
      # (built by nixos-rebuild build-vm on the config above)
    };
}
