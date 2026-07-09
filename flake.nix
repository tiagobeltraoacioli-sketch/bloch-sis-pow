{
  description = "Bloch-SIS — the node packaged for Nix + Postern OS, a reproducible NixOS appliance with the node built in";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  # Mobile NixOS powers Postern OS Mobile (phones). Not a flake — used via its
  # eval-config; pin a revision on your build host.
  inputs.mobile-nixos = { url = "github:nix-community/mobile-nixos"; flake = false; };

  outputs = { self, nixpkgs, mobile-nixos }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
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
        mobile-image = (import "${mobile-nixos}/lib/eval-config.nix" {
          device = "pine64-pinephone";
          modules = [
            self.nixosModules.bloch
            ./os/mobile.nix
            ({ ... }: { _module.args.blochPkg = self.packages.${system}.bloch; })
          ];
        }).outputs.default;

        # Postern OS Desktop — the privacy daily-driver live ISO.
        desktop-iso = self.nixosConfigurations.postern-desktop.config.system.build.isoImage;
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
        ];
      };

      # Convenience: `nix run` a VM of the OS to try it without flashing.
      # (built by nixos-rebuild build-vm on the config above)
    };
}
