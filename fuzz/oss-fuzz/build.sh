#!/bin/bash -eu
# OSS-Fuzz build script for the Bloch node fuzzers.
#
# Builds every cargo-fuzz target in fuzz/ under the OSS-Fuzz sanitizer profile
# and copies the resulting libFuzzer binaries (plus seed corpora) into $OUT.
# Invoked by OSS-Fuzz inside the base-builder-rust image; $SRC, $OUT and the
# sanitizer flags are provided by the harness.

cd "$SRC/bloch"

# cargo-fuzz auto-detects the fuzz/ crate; -O enables optimizations, and
# --debug-assertions keeps the overflow / bounds checks that turn a silent
# consensus miscompute into a fuzzer-visible panic.
cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR="$SRC/bloch/fuzz/target/x86_64-unknown-linux-gnu/release"

# Keep this list in sync with the [[bin]] entries in fuzz/Cargo.toml.
TARGETS=(
  block_parse
  tx_parse
  netmsg_decode
  handshake_decode
  merkle_path
  mempool_ops
  sha256d_pow
  pow_verify
  pow_decode
  ghostdag_order
  sig_verify
  g4_codec
  g4_rpc
  g4_p2p_sync
)

for target in "${TARGETS[@]}"; do
  cp "$FUZZ_TARGET_OUTPUT_DIR/$target" "$OUT/"
  # Ship the committed seed corpus for targets that have one.
  if [ -d "$SRC/bloch/fuzz/corpus/$target" ]; then
    zip -j "$OUT/${target}_seed_corpus.zip" "$SRC/bloch/fuzz/corpus/$target/"* 2>/dev/null || true
  fi
done
