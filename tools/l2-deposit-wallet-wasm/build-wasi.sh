#!/bin/sh
# Build the L2 deposit signer for wasm32-wasip1 (reactor, cdylib).
# Toolchain: the repository-pinned Rust (rust-toolchain.toml, 1.94.1) and an
# official WASI SDK 33.0, the same pair the delegation signer was built with.
set -eu
: "${WASI_SDK_ROOT:?Set WASI_SDK_ROOT to the verified WASI SDK 33.0 directory}"
export CC_wasm32_wasip1="$WASI_SDK_ROOT/bin/clang"
export AR_wasm32_wasip1="$WASI_SDK_ROOT/bin/llvm-ar"
export WASI_SDK_DIR="$WASI_SDK_ROOT/share/wasi-sysroot"
cd "$(dirname "$0")/../.."
"${CARGO:-cargo}" build --offline --locked -p bloch-l2-deposit-wallet-wasm --target wasm32-wasip1 --release
shasum -a 256 "${CARGO_TARGET_DIR:-target}/wasm32-wasip1/release/bloch_l2_deposit_wallet_wasm.wasm"
