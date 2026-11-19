#!/usr/bin/env bash
# cross-arch-determinism-check.sh — run on a host of ANOTHER architecture
# (in practice: aarch64 Linux or Apple Silicon) to check that it reproduces
# the consensus results recorded on x86-64.
#
# WHAT IT RUNS (tests only; nothing is installed, signed, sent or deployed):
#
#   1. bloch-crypto  tests/r19_cross_arch_determinism.rs
#        ML-DSA-65: every backend this CPU can run (clean, AVX2, AArch64/NEON),
#        the historical CPU-dispatching verifier and the pinned verifier, on a
#        fixed corpus of genuine, malformed and boundary signatures; Falcon-1024
#        and SLH-DSA-SHAKE-128s keys, signatures and verdicts; SHA-2 / SHA-3
#        against a portable reference. Each part ends in a digest that must
#        equal the constant recorded on x86-64.
#   2. bloch-crypto  the existing per-backend suites: NIST ACVP (FIPS 204 and
#        FIPS 205), the Falcon round-3 submission vectors, HF2 backend tests,
#        the seeded Falcon known-answer test and the "no native floating-point
#        Falcon linked" tripwire.
#   3. bloch-mldsa-clean  the pinned wrapper's own tests.
#   4. bloch-pos-committee  the whole crate: it carries state roots, signing
#        roots and beacon outputs recorded as constants (for example
#        `fc_horizon_pre_activation_committed_root_is_the_golden_root`), so a
#        pass means the state transition gives the x86-64 roots on this host.
#
# A pass on aarch64 covers the code. It does not replace a full-history
# replay on that architecture (below MLDSA_PIN_ACTIVATION_EPOCH an aarch64
# node verifies ML-DSA with the NEON backend).
#
# Usage: bash scripts/cross-arch-determinism-check.sh
#   CARGO_BUILD_JOBS and CARGO_TARGET_DIR are honoured as usual.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "host: $(uname -sm); rustc: $(rustc -V)"
case "$(uname -m)" in
  x86_64|amd64) echo "note: this is x86-64, the architecture the constants were recorded on." ;;
esac

run() { echo; echo "== $*"; "$@"; }

run cargo test --locked -p bloch-crypto --test r19_cross_arch_determinism -- --nocapture
run cargo test --locked -p bloch-crypto \
  --test acvp_fips204_full --test acvp_mldsa --test acvp_slhdsa \
  --test falcon_submission --test hf2_sigdet_backends --test p9e_hybrid_boundaries
run cargo test --locked -p bloch-crypto --lib falcon
run cargo test --locked -p bloch-mldsa-clean
run cargo test --locked -p bloch-pos-committee

echo
echo "cross-arch determinism check: all suites passed on $(uname -m)"
