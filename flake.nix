{
  description = "Bloch-SIS — the node packaged for Nix + Postern OS, a reproducible NixOS appliance with the node built in";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  # Mobile NixOS powers Postern OS Mobile (phones). Not a flake — used via its
  # top-level default.nix ({ device, configuration, pkgs/system }); pin a
  # revision on your build host. (Canonical org is mobile-nixos, not
  # nix-community — the latter 404s.)
  #
  # PIN THE REV (roadmap #2 — do this on the Nix host, see REPRO.md §"#2"):
  #   `nix flake lock` already pins mobile-nixos to a fixed rev inside flake.lock,
  #   but the URL below still floats on the branch, so `nix flake update` can move
  #   it silently and the pin is invisible in review. To make the rev a single
  #   diffable line, resolve it and REPLACE the line below with the pinned form:
  #
  #     nix flake lock            # resolves the branch -> a fixed rev in flake.lock
  #     nix flake metadata --json | jq -r \
  #       '"mobile-nixos rev: " + .locks.nodes["mobile-nixos"].locked.rev'
  #
  #   then swap the active line for (keeping flake = false):
  #     url = "github:mobile-nixos/mobile-nixos/<MOBILE_NIXOS_REV>";
  #   and re-run `nix flake lock` so the lock matches the pinned input.
  #
  # Until pinned, the line below floats on the branch so `nix flake lock` Just
  # Works out of the box (it still records a concrete rev in flake.lock).
  inputs.mobile-nixos = { url = "github:mobile-nixos/mobile-nixos"; flake = false; };

  outputs = { self, nixpkgs, mobile-nixos }:
    let
      # ── PLATFORM CAVEAT (read before building on aarch64 hardware) ────────────
      # The image/OS outputs `.#iso`, `.#desktop-iso`, `.#attested-image` and the
      # NixOS configs `bloch-os`, `bloch-os-attested`, `postern-desktop` are wired
      # to `system = "x86_64-linux"` below. On an aarch64 host they build ONLY via
      # binfmt qemu-user emulation (SLOW) or a real x86_64 builder.
      #
      # What builds NATIVELY on aarch64 (no emulation), and is the honest, cheap
      # first determinism probe (see REPRO.md §"#9"):
      #   .#packages.aarch64-linux.bloch          — the node/wallet crate
      #   .#packages.aarch64-linux.attested-image — the sealed image, aarch64 variant
      #   .#mobile-image                          — the PinePhone image (aarch64)
      # The aarch64 attested variant (bloch-os-attested-aarch64) exists precisely so
      # the sealed image can be repro-checked on aarch64 hardware WITHOUT emulation.
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # The phone is aarch64; its node/wallet package must be too. On an aarch64
      # host this builds natively; on an x86_64 host it goes via binfmt emulation.
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
      # NATIVE on aarch64 hardware — this is the cheapest determinism probe
      # (bundled RocksDB 8.10 C++ is the #1 nondeterminism risk). See REPRO.md.
      packages.aarch64-linux = {
        bloch = pkgsAarch64.callPackage ./os/package.nix { };
        default = self.packages.aarch64-linux.bloch;

        # aarch64-native sealed image — the same immutable + dm-verity-sealed
        # profile as x86_64 `.#attested-image`, but built on the aarch64 host
        # you actually have, so the sealed image can be `--rebuild --check`ed and
        # two-builder compared WITHOUT binfmt emulation (report §3.4, recommendation b).
        # The `image.repart` verity/roothash machinery in os/attested.nix is
        # arch-agnostic; only the toplevel closure differs by platform.
        attested-image =
          self.nixosConfigurations.bloch-os-attested-aarch64.config.system.build.image;
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

      # aarch64-native twin of bloch-os-attested. Same modules, same seal profile
      # (os/attested.nix), but `system = "aarch64-linux"` and the aarch64 node
      # package — so the sealed image builds + repro-checks natively on aarch64
      # hardware (no x86_64 emulation). Consumed by
      # `.#packages.aarch64-linux.attested-image`. See REPRO.md §"#9".
      nixosConfigurations.bloch-os-attested-aarch64 = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = { blochPkg = self.packages.aarch64-linux.bloch; };
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
