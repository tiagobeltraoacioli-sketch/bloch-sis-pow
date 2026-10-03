#!/bin/sh
set -eu
: "${WASI_SDK_ROOT:?Set WASI_SDK_ROOT to the verified WASI SDK directory}"
export CC_wasm32_wasip1="$WASI_SDK_ROOT/bin/clang"
export AR_wasm32_wasip1="$WASI_SDK_ROOT/bin/llvm-ar"
export WASI_SDK_DIR="$WASI_SDK_ROOT/share/wasi-sysroot"
cd "$(dirname "$0")/../.."
"${CARGO:-cargo}" build --offline --locked -p bloch-delegation-wallet-wasm --target wasm32-wasip1 --release
shasum -a 256 target/wasm32-wasip1/release/bloch_delegation_wallet_wasm.wasm
