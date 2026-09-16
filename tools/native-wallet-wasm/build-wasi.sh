#!/bin/sh
set -eu
# Supply an independently verified official WASI SDK installation.
: "${WASI_SDK_ROOT:?Set WASI_SDK_ROOT to the extracted WASI SDK 33 directory}"
export CC_wasm32_wasip1="$WASI_SDK_ROOT/bin/clang"
export AR_wasm32_wasip1="$WASI_SDK_ROOT/bin/llvm-ar"
export WASI_SDK_DIR="$WASI_SDK_ROOT/share/wasi-sysroot"
test -x "$CC_wasm32_wasip1"
test -d "$WASI_SDK_DIR"
cd "$(dirname "$0")/../.."
"${CARGO:-cargo}" build --offline --locked -p bloch-native-wallet-wasm --target wasm32-wasip1 --release
shasum -a 256 target/wasm32-wasip1/release/bloch_native_wallet_wasm.wasm
