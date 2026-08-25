#!/bin/sh
# Demonstrates the defect the preservation manifest exists to refuse:
# `cargo test` reports `ok` for two of the five proof suites having run ZERO
# tests, because every test in them is `#[ignore]`d.
set -e
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
echo "── replay_hotpath_perf, the way a reviewer runs it ────────────────────"
cargo test -p bloch-pos-node --test replay_hotpath_perf 2>&1 | tail -3
echo
echo "── the same suite, with --include-ignored ─────────────────────────────"
cargo test -p bloch-pos-node --test replay_hotpath_perf -- --include-ignored --test-threads 1 2>&1 | tail -3
