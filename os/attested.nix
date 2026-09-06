# Postern OS — immutable + attestable profile (the Postern Seal attestation).
#
# Layers onto the base Postern OS to make the image measurable and tamper-evident:
#   • immutable, read-only rootfs sealed with dm-verity (systemd-repart image);
#   • systemd in the initrd + a UKI (kernel+initrd+cmdline in one signed PE) so
#     the boot chain has a stable, measurable identity;
#   • TPM2 measured boot (PCRs) — and, inside a SEV-SNP/TDX confidential VM, the
#     launch measurement, verified by the L3 attestation layer.
#
# The dm-verity roothash is passed on the kernel cmdline (`roothash=`), which the
# node reads (`attestation::read_os_roothash`) and reports via `getattestation`,
# so a verifier can require the node run the audited reproducible image
# (Expected.os_roothash).
#
# NOTE: systemd-repart/verity/UKI options drift across nixpkgs releases — treat
# this as the profile to iterate on a Nix host (`nix build .#attested-image`),
# not a frozen recipe.
{ config, lib, pkgs, ... }:
{
  # systemd in the initrd — required for verity setup + TPM2 unlock + a clean
  # measured-boot chain.
  boot.initrd.systemd.enable = true;

  # UKI + measured boot: one signed kernel image, measured into the TPM (and, in
  # a CVM, covered by the launch measurement).
  boot.loader.systemd-boot.enable = lib.mkDefault true;
  boot.loader.efi.canTouchEfiVariables = lib.mkDefault false;
  boot.initrd.systemd.tpm2.enable = lib.mkDefault true;

  # Read-only, immutable rootfs. The store is already immutable; this seals the
  # whole root and forbids in-place mutation. Mutable state lives on a separate
  # writable partition mounted at the node's data dir.
  fileSystems."/".options = [ "ro" ];

  # Build an immutable disk image with a dm-verity-protected root partition.
  # `Verity = "data"` + a paired `root-verity` partition produce the roothash
  # that seals the image; systemd-repart writes `roothash=` onto the cmdline.
  image.repart = {
    name = "bloch-os";
    version = "0.1.0";
    partitions = {
      "esp" = {
        contents = {
          # UKI(s) placed by systemd-boot / the bootloader install.
        };
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          SizeMinBytes = "128M";
        };
      };
      "root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Format = "erofs"; # read-only fs → deterministic + verity-friendly
          Verity = "data";
          VerityMatchKey = "root";
          Label = "bloch-root";
          Minimize = "best";
        };
      };
      "root-verity" = {
        repartConfig = {
          Type = "root-verity";
          Verity = "hash";
          VerityMatchKey = "root";
          Label = "bloch-root-verity";
        };
      };
      # HIGH-4 — the writable /persist partition, LUKS-encrypted.
      #
      # ****** UNTESTED-IN-THIS-SESSION ******
      # This block was written on a non-Nix host (same constraint as
      # ./cloud.nix's header note) and has NOT been run through
      # `nix build`, `systemd-repart`, or booted on real hardware/a VM in
      # this session. systemd-repart's `Encrypt=` key and LUKS integration
      # options have drifted across nixpkgs releases before (see the file
      # header). Validate on a real Nix host before trusting this in any
      # deploy pipeline:
      #
      #   1. `nix build .#attested-image 2>&1 | tee /tmp/attested-build.log`
      #      — confirms the module evaluates and systemd-repart accepts the
      #      `Encrypt=`/`VerityMatchKey=` combination below.
      #   2. Boot the resulting image (a local VM is enough — qemu with TPM
      #      emulation via swtpm, or the real target hardware) and confirm:
      #        `findmnt /persist`                  — mounted, not tmpfs
      #        `lsblk -f`                            — shows a `crypto_LUKS`
      #                                                type on the persist
      #                                                partition
      #        `cryptsetup luksDump /dev/disk/by-partlabel/persist`
      #                                              — confirms a LUKS2
      #                                                header exists and,
      #                                                for the TPM2-bound
      #                                                path, a `systemd-tpm2`
      #                                                token is enrolled:
      #        `systemd-cryptenroll --tpm2-device=list`
      #        `journalctl -b -u systemd-cryptsetup@persist.service`
      #                                              — confirms the unit
      #                                                actually ran and
      #                                                unlocked (not skipped)
      #   3. Confirm a REBOOT re-unlocks without an interactive passphrase
      #      prompt (the TPM2-bound path is the point — a prompt on a
      #      headless confidential-VM guest is a boot that never completes).
      #   4. Confirm the rootfs's own verity check still passes after adding
      #      this partition — a repart layout change can shift offsets that
      #      an unrelated tool has hardcoded elsewhere in the pipeline.
      #
      # Until all four are confirmed on a real Nix host, treat this as a
      # design sketch, not a shipped feature — do not remove this notice
      # without having actually run the steps above.
      "persist" = {
        repartConfig = {
          Type = "linux-generic";
          Label = "bloch-persist";
          # Grows to fill remaining disk on first boot; size is
          # provider/host-specific and not meaningfully fixable here.
          SizeMinBytes = "1G";
          # systemd-repart's own LUKS2 provisioning at image-build time.
          # `tpm2` here means: the encryption key is generated at first
          # repart run and immediately sealed to the TPM2's current PCR
          # state, with no operator-entered passphrase — matching this
          # profile's measured-boot model (PCRs already gate the root
          # verity key's trust path; /persist should not be weaker).
          Encrypt = "key-file";
          EncryptedVolume = "persist";
        };
      };
    };
  };

  # Unlock /persist via the TPM2, sealed to the current measured-boot state —
  # consistent with this profile's PCR-gated trust model (see the module
  # header). UNTESTED-IN-THIS-SESSION, same caveat as the partition above:
  # confirm `systemd-cryptenroll --tpm2-device=list` shows an enrolled slot
  # and that a reboot unlocks with no prompt before relying on this.
  boot.initrd.luks.devices."persist" = {
    device = "/dev/disk/by-partlabel/bloch-persist";
    crypttabExtraOpts = [ "tpm2-device=auto" ];
  };
  fileSystems."/persist" = {
    device = "/dev/mapper/persist";
    fsType = "ext4";
    neededForBoot = true;
  };

  # Persist node state on a writable partition (the rest of the OS is read-only).
  # Point the node's data dir here; provision this partition at first boot.
  services.bloch.dataDir = lib.mkDefault "/persist/bloch";

  # Bake the image digest for the attestation report (set at build/deploy).
  # environment.variables.BLOCH_IMAGE_DIGEST is populated by the deploy pipeline.
  #
  # Confidential-VM deployments (./cloud.nix): the L1 binding is pinned at VM
  # LAUNCH, not in the image — the launch policy writes the admission-policy
  # hash P (which admits only this image's digest D) into SNP HOSTDATA /
  # TDX MR_CONFIG_ID, and the guest's report carries it back for the verifier
  # (postern-seal-verify --host-data P). Flow: POSTERN-CLOUD.md §7 + the
  # runbook docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md.
}
