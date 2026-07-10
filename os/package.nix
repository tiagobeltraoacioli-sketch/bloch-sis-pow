{ lib
, rustPlatform
, pkg-config
, openssl
, rocksdb
, clang
, llvmPackages
, stdenv
}:

# Reproducible build of the Bloch-SIS node (+ its CLI/wallet bins) from the
# workspace. The workspace is fully self-contained (pqcrypto-internals is
# vendored, Cargo.lock is committed), so no network / git fetches are needed.
rustPlatform.buildRustPackage {
  pname = "bloch";
  version = "0.1.0";

  # Repo root (this file lives in ./os). cleanSource drops .git; the sandbox
  # builds fresh so a stray ./target is only copy bloat.
  src = lib.cleanSource ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    # All deps are crates.io or vendored path deps — no git deps to hash.
  };

  nativeBuildInputs = [ pkg-config clang ];
  buildInputs = [ openssl rocksdb ];

  # librocksdb-sys: build its BUNDLED RocksDB (8.10, matching the crate's FFI
  # bindings) rather than the system rocksdb — nixpkgs ships RocksDB 10.x, which
  # removed `access_hint_on_compaction_start` and breaks the 0.22 crate. Only
  # point bindgen at libclang.
  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

  # Build the node + its companion bins (wallet/cli); skip the heavy test suite
  # in the image build (it runs in CI).
  doCheck = false;

  meta = with lib; {
    description = "Bloch-SIS post-quantum, pure-PoW BlockDAG node";
    longDescription = ''
      The Bloch-SIS node: SHAKE-256 hashcash Proof-of-Work with a Module-SIS
      structural gate, hybrid Falcon+ML-DSA signatures, GhostDAG-Q consensus.
      Testnet is zero-security by design — do not attach value.
    '';
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "bloch";
  };
}
