{ lib
, rustPlatform
}:

# Reproducible build of the Postern Seal gate + verifier CLI from the
# products workspace (crates/postern-seal-companion, feature `sev-snp`):
#   postern-seal-gate   — the guest-side attestation endpoint (POSTERN-CLOUD.md §4.1)
#   postern-seal-verify — the client-side verifier (chains the report to the AMD root)
#
# HONEST STATUS: written on a non-Nix host — expression is idiomatic but NOT
# built here; validate with `nix build .#seal-gate` on a Nix host. The gate's
# /dev/sev-guest path additionally needs a real SEV-SNP VM (see
# docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md).
rustPlatform.buildRustPackage {
  pname = "postern-seal-gate";
  version = "0.1.0";

  src = lib.cleanSource ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    # The workspace consumes the ownerless Bloch-SIS-PoW protocol as a git
    # dependency; pin its lockfile hash here on first `nix build` (the build
    # error prints the correct value):
    # outputHashes."bloch-crypto-0.1.0-genesis" = lib.fakeHash;
  };

  buildAndTestSubdir = "crates/postern-seal-companion";
  buildFeatures = [ "sev-snp" ];
  cargoBuildFlags = [ "--bins" ];

  # The SNP vector tests are pure-compute and could run here; the image build
  # skips them like os/package.nix does (they run in CI on the dev host).
  doCheck = false;

  meta = with lib; {
    description = "Postern Seal gate — SEV-SNP attestation endpoint + verifier (attestation-before-connect)";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "postern-seal-gate";
  };
}
