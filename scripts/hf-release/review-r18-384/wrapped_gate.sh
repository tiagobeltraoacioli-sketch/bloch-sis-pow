#!/bin/bash
# Review R384-1 (agent 384, round 18): hf-gates.py reads single-line gate definitions only, so an armed gate whose
# definition rustfmt wraps, or a non-pub one, is reported `missing`, and qualify.sh's l2_gate_armed counts `missing`
# as NOT armed. Usage: wrapped_gate.sh <bloch-sis-pow checkout at the commit under review>
# Expected output on a fixed tool: neither gate prints `missing`. On 189f3178 / f596fb78 both print `missing`.
set -euo pipefail
TOOL=$(cd "$1" && pwd)/scripts/hf-release/hf-gates.py
T=$(mktemp -d)
trap 'rm -rf -- "${T:?}"' EXIT
mkdir -p "$T/crates/c/src"
printf 'pub const L2_NEXT_PROGRAM_EPOCH: u64 =\n    crate::params::SOME_LONG_NAMED_CONSTANT_THAT_MAKES_RUSTFMT_WRAP_THIS_LINE_EPOCH_VALUE + 7_000;\nconst L2_DA_RESERVED_SLOT_EPOCH: u64 = 9_000;\npub const L2_PROGRAM_ROLLBACK_EPOCH: u64 = u64::MAX;\n' > "$T/crates/c/src/params.rs"
git -C "$T" init -q
git -C "$T" add .
git -C "$T" -c user.email=review@invalid -c user.name=review commit -qm fixture
python3 -I "$TOOL" status --repo "$T" --commit HEAD --gate L2_NEXT_PROGRAM_EPOCH --gate L2_DA_RESERVED_SLOT_EPOCH --gate L2_PROGRAM_ROLLBACK_EPOCH
