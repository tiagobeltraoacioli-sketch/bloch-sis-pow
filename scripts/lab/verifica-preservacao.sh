#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verifica-preservacao.sh — prove a candidate branch still carries the four
# things the founder requires the relaunch binary to preserve.
#
#   ./verifica-preservacao.sh [worktree-path]     (default: this worktree)
#
# Exits non-zero if ANY check fails. Every check is written so that breaking
# the thing it guards makes it FAIL — see MUTATION at the bottom for how to
# prove that to yourself rather than taking this header's word for it.
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT" || { echo "no such worktree: $ROOT" >&2; exit 2; }
FAIL=0
ok()   { printf 'PASS  %-22s %s\n' "$1" "$2"; }
bad()  { printf 'FAIL  %-22s %s\n' "$1" "$2"; FAIL=1; }

# 1. The flag day already deployed to 64 production nodes. The VALUE matters,
#    not merely the symbol: a branch that renamed it or moved it to 1399 has
#    silently rescheduled a consensus change on a live fleet.
P=crates/bloch-pos-committee/src/params.rs
if grep -qE '^pub const LEAKED_ROSTER_ACTIVATION_EPOCH: u64 = 1400;' "$P" 2>/dev/null; then
  ok flagday-1400 "$P"
else
  bad flagday-1400 "LEAKED_ROSTER_ACTIVATION_EPOCH is not exactly 1400 in $P"
fi

# 2. perf/smt — the incremental state root (2h10m replay -> ~7 min). Pinned by
#    provenance AND by the real-scale test, because a grep for a function name
#    would survive gutting the function.
if git merge-base --is-ancestor a248241d HEAD 2>/dev/null \
   && git merge-base --is-ancestor 39def019 HEAD 2>/dev/null; then
  ok perf-smt-provenance "a248241d + 39def019 are ancestors"
else
  bad perf-smt-provenance "an smt commit is missing from this history"
fi
if [ -f crates/bloch-pos-committee/tests/state_root_carryover_scale.rs ]; then
  ok perf-smt-scaletest "state_root_carryover_scale.rs present"
else
  bad perf-smt-scaletest "the 452,726-leaf scale test is gone"
fi

# 3. perf/fork — all subtree weights in ONE pass instead of a walk per query.
F=crates/bloch-pos-committee/src/forkchoice.rs
if grep -q 'fn subtree_weights' "$F" 2>/dev/null && grep -q 'subtree_weights(tree)' "$F" 2>/dev/null; then
  ok perf-fork-onepass "subtree_weights defined AND called in $F"
else
  bad perf-fork-onepass "subtree_weights missing or never called - the per-query walk is back"
fi

# 4. perf/rpc-stateroot — getchaininfo must not re-hash a root the head header
#    already carries.
if git merge-base --is-ancestor ae4cffbb HEAD 2>/dev/null; then
  ok perf-rpc-stateroot "ae4cffbb is an ancestor"
else
  bad perf-rpc-stateroot "ae4cffbb missing - getchaininfo may be re-hashing"
fi

# 5. The two RPC fields an operator needs to tell "never received" apart from
#    "received but never adopted". Losing these makes the fleet unobservable in
#    exactly the dimension that mattered during the partition.
R=crates/bloch-pos-node/src/rpc.rs
if grep -q '"blocks_known"' "$R" 2>/dev/null && grep -q '"behind_by_slots"' "$R" 2>/dev/null; then
  ok rpc-diagnostics "blocks_known + behind_by_slots in $R"
else
  bad rpc-diagnostics "getchaininfo lost blocks_known and/or behind_by_slots"
fi

# 6. THE SEED RULE ITSELF. Added after 2026-08-25, when branch
#    pmo/seed-ancestralidade-v2 was found carrying commit 8075fe24 - message
#    "wire the F6 seed look-ahead into both production readers", diff doing
#    the OPPOSITE: `let Some(src) = epoch.checked_sub(1)` with a trailing
#    `// MUTATION A: reader back at E-1`, in `pub fn seed_for_epoch`, a
#    PRODUCTION function with no cfg(test) gate. A binary built from that
#    branch ships the exact partition bug under a commit claiming it fixed.
#    The commit message is not the artifact. The code is.
T=crates/bloch-pos-committee/src/transition.rs
#    The reader may express the rule either way, but it must express the
#    LOOK-AHEAD and it must be pinned to committees::seed_epoch by a test.
#    A bare `checked_sub(1)` is the defect; `1 + MIN_SEED_LOOKAHEAD_EPOCHS`
#    or `seed_epoch(epoch)` are both the rule.
if grep -qE 'crate::committees::seed_epoch\(epoch\)|1 \+ crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS' "$T" 2>/dev/null; then
  ok seed-rule-lookahead "seed_for_epoch expresses the look-ahead in $T"
else
  bad seed-rule-lookahead "seed_for_epoch does NOT express the look-ahead - it is back at E-1"
fi
if grep -q 'fn the_lookahead_matches_the_committee_crates_seed_epoch' "$T" 2>/dev/null; then
  ok seed-rule-pinned "the reader is pinned to committees::seed_epoch by a test"
else
  bad seed-rule-pinned "nothing pins the reader's arithmetic to committees::seed_epoch"
fi
if grep -nE 'MUTATION [A-Z]' crates/*/src/*.rs 2>/dev/null | grep -vq 'MUTATION DID NOT BITE'; then
  bad no-stray-mutation "a 'MUTATION x' marker is left in a source file - see grep above"
else
  ok no-stray-mutation "no stray mutation markers in production sources"
fi

echo
[ "$FAIL" -eq 0 ] && echo "PRESERVATION: OK" || echo "PRESERVATION: FAILED"
exit "$FAIL"
