#!/usr/bin/env bash
# Hardened Clippy profile for CONSENSUS-CRITICAL code (security scanner lane).
#
# Panics (unwrap/expect) and unchecked arithmetic in consensus, emission, and
# tokenomics code are a denial-of-service / inflation vector: a single crafted
# input that reaches a panic aborts the node. This profile denies them.
#
# Scope (the consensus-critical set):
#   - bloch      : src/consensus/*, src/pow/*, src/reorg.rs   (root crate lib)
#   - bloch-crypto: src/core/tokenomics_v2.rs, src/core/mod.rs (emission + sighash)
#   - bloch-euvm : native eUTXO validator VM (off-by-default `euvm` feature)
#
# `--no-deps` is MANDATORY here: without it, `cargo clippy -p X` also lints
# workspace path-dependencies (bloch-sis-pow, coherence-core), and a single
# `-D unwrap_used` hit in one of those aborts the run before the target crate
# is ever linted.
#
# Usage:  ./scripts/hardened-clippy.sh
# Exit non-zero if any denied lint fires in a scoped crate.
set -euo pipefail
cd "$(dirname "$0")/.."

HARDENED=(
  -W clippy::pedantic
  -W clippy::arithmetic_side_effects
  -D clippy::unwrap_used
  -D clippy::expect_used
)

echo "== bloch (consensus/pow/reorg) =="
cargo clippy -p bloch --lib --no-deps --no-default-features --features node -- "${HARDENED[@]}"

echo "== bloch-crypto (tokenomics/emission/sighash) =="
cargo clippy -p bloch-crypto --lib --no-deps --all-features -- "${HARDENED[@]}"

echo "== bloch-euvm (eUTXO VM) =="
cargo clippy -p bloch-euvm --lib --no-deps -- "${HARDENED[@]}"

echo "hardened-clippy: OK"
