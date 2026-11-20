#!/bin/sh
# Build the L2 deposit signer for wasm32-wasip1 (reactor, cdylib).
# Toolchain: the repository-pinned Rust (rust-toolchain.toml, 1.94.1) and an
# official WASI SDK 33.0, the same pair the delegation signer was built with.
#
# The build machine's paths are mapped to fixed names, so the artifact carries
# no home directory or account name and does not depend on where CARGO_HOME or
# the source tree are:
#   $CARGO_HOME   -> /cargo
#   workspace root -> /bloch-sis-pow
set -eu
: "${WASI_SDK_ROOT:?Set WASI_SDK_ROOT to the verified WASI SDK 33.0 directory}"
export CC_wasm32_wasip1="$WASI_SDK_ROOT/bin/clang"
export AR_wasm32_wasip1="$WASI_SDK_ROOT/bin/llvm-ar"
export WASI_SDK_DIR="$WASI_SDK_ROOT/share/wasi-sysroot"
cd "$(dirname "$0")/../.."
ROOT="$(pwd -P)"
CARGO_HOME_DIR="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
# Ambient flags would change the bytes; the build defines its own.
export RUSTFLAGS="--remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$ROOT=/bloch-sis-pow"
unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
export CFLAGS_wasm32_wasip1="-ffile-prefix-map=$CARGO_HOME_DIR=/cargo -ffile-prefix-map=$ROOT=/bloch-sis-pow"
"${CARGO:-cargo}" build --offline --locked -p bloch-l2-deposit-wallet-wasm --target wasm32-wasip1 --release
OUT="${CARGO_TARGET_DIR:-target}/wasm32-wasip1/release/bloch_l2_deposit_wallet_wasm.wasm"
# Fail closed if a home directory still leaks into the artifact.
if LC_ALL=C grep -a -q -e "/Users/" -e "/home/" -e "$CARGO_HOME_DIR" -e "$ROOT" "$OUT"; then
  echo "build-wasi.sh: the artifact still embeds a build-machine path" >&2
  exit 1
fi
shasum -a 256 "$OUT"
