#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ── THE RELAUNCH PROOF ───────────────────────────────────────────────────────
#
# One command. Every scenario of the Genesis-4 relaunch proof, every mutation
# that must make it go red, and a PASS/FAIL table. Exits non-zero if anything
# a relaunch depends on is not proven.
#
#   scripts/prova-relanca.sh                # scenarios + static preservation
#   scripts/prova-relanca.sh --deep         # ... and the preservation cargo phase
#   scripts/prova-relanca.sh --list         # print what it would run, run nothing
#   scripts/prova-relanca.sh --commands     # print the exact per-gate cargo
#                                           # command, so any single scenario or
#                                           # mutation can be run and watched
#
# THE DEFAULT MODE CANNOT REPORT PASS. It runs every scenario and every
# mutation, but the preservation manifest's static gates cannot type-check, so
# they cannot see a target that does not compile — the exact way that verifier
# reported "42/42 PASS" on a tree whose --bin target was broken (69f20e07).
# The default therefore exits 3, INCOMPLETE, however green the table is. Only
# --deep can reach exit 0, and it is slow (a full workspace build plus two
# workspace test runs). A mode that can lie by omission either fails loud or
# does not exist.
#
# WHY IT EXISTS
#
# Nine commits on this project say "proven by mutation" and left behind no
# script, no CI target and no recorded output. If the founder cannot run the
# command and watch the test go red, it does not count. Everything below is
# runnable by a third party from a clean checkout.
#
# WHAT A MUTATION IS HERE
#
# Each scenario has a partner test that flips the code back to the BROKEN
# behaviour and asserts the scenario's conclusion fails. The switches are
# `AtomicBool`s under `#[cfg(test)]` (the `params::rehearsal::MUTATE_SEED`
# idiom), so they cannot exist in a shipped binary:
#
#   crates/bloch-pos-committee/src/prova.rs      mutation::PRE_FIX_FILTER
#     -> which now sets params::rehearsal::RESTORE_ZERO_STAKE_FILTER, the
#        switch `committees::epoch_committees` actually reads. Between
#        2026-08-24 and 2026-09-01 it did not, so BOTH arms called the same
#        post-fix code, no mutation could bite, and five gates were red while
#        their messages announced the analysis "refuted". A mutation switch
#        that does not reach production is not a switch. If you add one, the
#        test that it BITES is the only thing that tells you it is wired.
#   crates/bloch-pos-committee/src/finality.rs   tests_hook::IGNORE_LEAK_IN_DENOMINATOR
#   crates/bloch-pos-committee/src/finality.rs   tests_hook::DISABLE_DENOMINATOR_FLOOR
#   crates/bloch-pos-committee/src/params.rs     rehearsal::MUTATE_SEED
#   crates/bloch-pos-committee/src/params.rs     rehearsal::gates_open_guard()
#
# SECTION 0 IS NOT A MUTATION SCENARIO. `s0_three_partitions_…` touches no
# switch at all: it runs the arithmetic a shipped binary runs, because
# LEAK_RECOVERY_ACTIVATION_EPOCH is u64::MAX. Its partner opens the gates to
# show the cure works. See docs/post-mortems/2026-08-24-finality-divergence.md.
#
# MACHINE RULE
#
# Exactly one cargo may run on this box at a time (8 cores, jobs=2, several
# agents). Every cargo call here goes through the lock wrapper and BLOCKS
# until the lock frees. Waiting is expected and correct.
#
# COST
#
# One cargo build + one test-binary run for the whole suite (the scenarios are
# selected out of a single JSON-formatted run, not one cargo invocation each),
# plus the preservation manifest's own runs unless --fast.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_LOCK="${BLOCH_CARGO_LOCK:-/private/tmp/bloch-cargo-lock.sh}"
DEEP=0
LIST=0
COMMANDS=0
for a in "$@"; do
  case "$a" in
    --deep) DEEP=1 ;;
    --list) LIST=1 ;;
    --commands) COMMANDS=1 ;;
    -h|--help) sed -n '3,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 64 ;;
  esac
done

if [ -x "$CARGO_LOCK" ]; then
  CARGO=("$CARGO_LOCK" cargo)
else
  echo "WARNING: no cargo lock wrapper at $CARGO_LOCK; running cargo directly." >&2
  echo "         On the shared build box this is a rule violation. Set BLOCH_CARGO_LOCK." >&2
  CARGO=(cargo)
fi

# ── the manifest of what must be proven ──────────────────────────────────────
#
# Format: <section>|<test path>|<kind>|<what it proves>
# kind: proof   — must PASS, or the relaunch is not proven
#       mutation— must PASS (the test itself asserts the mutation BITES)
#       pending — expected RED until another dev lands their half; reported,
#                 never fatal, and loudly flagged if it starts passing
MANIFEST=$(cat <<'EOF'
1. leak accumulator|finality::tests::the_relaunch_opens_its_books_with_an_empty_leak_ledger|proof|a relaunch inherits no leak balance from the broken chain
1. leak accumulator|finality::tests::the_leak_ledger_shrinks_only_under_a_governed_rule|proof|one accrual site; any recovery rule is named and switchable
1. leak accumulator|finality::tests::the_leak_ledger_is_committed_but_never_restored|proof|LATENT FINDING: committed as LeakRecord, never read back
1. leak accumulator|finality::tests::the_leak_only_ever_grows|proof|behavioural: leak is monotonic. EXPECT THIS TO GO RED at pmo/leak-zero integration (2f477fa2 adds a recovery rule); it is that branch's test to update, not this one's
0. model fidelity|prova::tests::the_model_of_the_fix_is_the_production_shuffle|proof|the modelled fix IS the production shuffle, bit for bit
0. model fidelity|prova::tests::the_leak_mirror_is_the_production_arithmetic|proof|the mirrored leak arithmetic still matches transition.rs
0. INCIDENT 24/08|prova::tests::s0_three_partitions_finalize_three_different_roots_at_the_same_epoch|proof|three 4-of-64 partitions finalize ONE epoch under THREE roots, on the shipped arithmetic
0. INCIDENT 24/08|prova::tests::s0_cure_the_denominator_floor_stops_all_three_partitions|mutation|with the denominator floor in force none of the three finalizes
0. INCIDENT 24/08|prova::tests::the_quorum_floor_is_shipped_but_not_in_force|proof|LEAK_RECOVERY_ACTIVATION_EPOCH is u64::MAX, so the floor is unreachable in production
2. S1 disease|prova::tests::s1_disease_two_nodes_diverge_and_the_chain_never_finalizes_again|proof|two nodes with different zero-sets diverge; the fleet is consumed
2. S2 cure|prova::tests::s2_cure_the_same_divergent_nodes_converge_from_the_same_state|proof|the SAME divergent ledgers converge under the contract
2. S2 cure|prova::tests::s2_mutation_restoring_the_pre_fix_filter_breaks_the_cure|mutation|restoring the pre-shuffle filter breaks the cure
3. S3 healthy no-op|prova::tests::s3_healthy_network_is_identical_under_the_fix|proof|on a healthy network the fix changes nothing
3. S3 healthy no-op|prova::tests::s3_mutation_the_comparator_bites_one_zero_stake_validator|mutation|the comparator sees a planted zero-stake validator
3. S3 healthy no-op|transition::tests::two_identical_runs_produce_an_identical_chain|proof|chain-level: the real block driver is deterministic
3. S3 healthy no-op|transition::tests::the_comparator_bites_a_planted_difference|mutation|chain-level: MUTATE_SEED makes the chain comparator go red
4. S4 accrued leak|prova::tests::s4_accrued_leak_plus_the_reset_restore_the_quorum_denominator|proof|a real accrued ledger + fix + reset give the correct denominator
4. S4 accrued leak|prova::tests::s4_mutation_the_pre_fix_filter_destroys_the_quorum_again|mutation|the pre-fix filter destroys the quorum again
5. false quorum|finality::tests::a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator|proof|the leak-adjusted denominator lets a minority self-finalize
5. false quorum|finality::tests::without_the_leak_in_the_denominator_the_minority_never_finalizes|mutation|removing the leak from the denominator stops it
6. roster split (Dev A)|finality::tests::a_single_fully_leaked_validator_makes_the_two_rosters_partition_differently|proof|one zero-stake validator splits the two rosters
6. roster split (Dev A)|finality::tests::the_only_guard_on_the_roster_split_is_absent_from_a_release_build|proof|the debug_assert guard is compiled out of the shipped profile
7. flag day|transition::tests::leaked_roster_armed_epoch_matches_the_runbook|proof|LEAKED_ROSTER_ACTIVATION_EPOCH is still 1400
7. flag day|transition::tests::consensus_roster_matches_duty_roster_before_the_flag_day|proof|the gate is closed, so the rosters are the same today
6. roster split (Dev A)|prova::tests::production_membership_is_leak_invariant|proof|LANDED: production epoch_committees is leak-invariant; the pre-shuffle filter is gone
EOF
)

if [ "$COMMANDS" = "1" ]; then
  echo "Run any single gate like this. Add --nocapture to see the measured numbers."
  echo "Every one goes through the machine cargo lock; waiting is expected."
  echo
  printf '%s\n' "$MANIFEST" | while IFS='|' read -r section test kind claim; do
    [ -z "$test" ] && continue
    ign=""
    [ "$kind" = "pending" ] && ign=" --ignored"
    echo "# [$kind] $claim"
    echo "$CARGO_LOCK cargo test -p bloch-pos-committee --lib \\"
    echo "    $test --$ign --exact --nocapture"
    echo
  done
  exit 0
fi

if [ "$LIST" = "1" ]; then
  printf '%s\n' "$MANIFEST" | awk -F'|' '{printf "  [%-8s] %-6s %s\n", $3, "", $2}'
  exit 0
fi

echo "═══════════════════════════════════════════════════════════════════════════"
echo " THE RELAUNCH PROOF — Genesis-4"
echo " $(date -u '+%Y-%m-%dT%H:%M:%SZ')   $(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo '?')"
echo "═══════════════════════════════════════════════════════════════════════════"
echo
echo "-> one cargo run, through $CARGO_LOCK (it blocks until the lock frees)"
echo

RAW="$(mktemp -t prova-relanca)"
RAW2="$(mktemp -t prova-relanca-pending)"
RUNNER="$(mktemp -t prova-relanca-run)"
KEEP_DIR="${PROVA_KEEP_DIR:-$ROOT/.prova-runs}"
mkdir -p "$KEEP_DIR"
keep_evidence() {
  cp "$RAW"  "$KEEP_DIR/last-events.json"  2>/dev/null
  cp "$RAW2" "$KEEP_DIR/last-pending.json" 2>/dev/null
  cp "$RAW.err" "$KEEP_DIR/last-stderr.log" 2>/dev/null
  rm -f "$RAW" "$RAW2" "$RAW.err" "$RUNNER"
}
trap keep_evidence EXIT

# No `#[ignore]`d gate remains. `pending_dev_a_production_membership_is_leak_invariant`
# was un-ignored and renamed on 2026-09-01: the fix it waited for had landed on
# 2026-08-24 and the ignore outlived its reason by a week. The second pass is kept,
# empty, because the next gate that is red-by-construction will want it back.
PENDING_TEST=""

# TWO test-binary runs, ONE build, ONE lock acquisition.
#
# The first version of this ran everything with `--include-ignored` so the
# pending gate would be picked up in a single pass. That was wrong and cost a
# 15-minute hold on the shared cargo lock: `--include-ignored` on this crate
# also drags in every ignored perf and scale benchmark (the preservation
# manifest budgets THREE HOURS for the equivalent workspace run). The pending
# gate is one test and is selected by exact name instead.
#
# --show-output, because libtest only puts stdout in the JSON for FAILING
# tests without it — and the measured numbers each scenario prints are the
# substance of this report, not decoration.
#
# JSON, so a test that never RAN is distinguishable from one that passed —
# which is the failure mode this whole file exists to prevent.
# --test-threads 1, because the mutation switches are process globals.
cat > "$RUNNER" <<RUNNER_EOF
#!/bin/sh
cd "$ROOT" || exit 1
export RUSTC_BOOTSTRAP=1
cargo test -p bloch-pos-committee --lib -- \
    --test-threads 1 --show-output -Z unstable-options --format json > "$RAW" 2> "$RAW.err"
if [ -n "$PENDING_TEST" ]; then
  cargo test -p bloch-pos-committee --lib -- --ignored --exact "$PENDING_TEST" \
      --test-threads 1 --show-output -Z unstable-options --format json > "$RAW2" 2>> "$RAW.err"
else
  : > "$RAW2"
fi
RUNNER_EOF
chmod +x "$RUNNER"

set +e
if [ -x "$CARGO_LOCK" ]; then
  "$CARGO_LOCK" "$RUNNER"
else
  "$RUNNER"
fi
CARGO_RC=$?
set -e

if ! grep -q '"type": *"test"' "$RAW" 2>/dev/null; then
  echo "!! THE TEST BINARY PRODUCED NO TEST EVENTS. This report means NOTHING."
  echo "!! cargo exit=$CARGO_RC. Raw stream kept in $KEEP_DIR/"
  echo "!! Last lines of stderr:"
  tail -25 "$RAW.err" 2>/dev/null | sed 's/^/   /'
  exit 2
fi

PROVA_RAW="$RAW" PROVA_RAW2="$RAW2" PROVA_MANIFEST="$MANIFEST" python3 - <<'PYEOF'
import json, os, sys

raw = open(os.environ["PROVA_RAW"], encoding="utf-8", errors="replace").read()
# The pending gate runs in its own pass (see the script above); its events are
# appended so the manifest is resolved against BOTH passes.
p2 = os.environ.get("PROVA_RAW2", "")
if p2 and os.path.exists(p2):
    raw += "\n" + open(p2, encoding="utf-8", errors="replace").read()
results, outputs = {}, {}
for line in raw.splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    if ev.get("type") != "test":
        continue
    name = ev.get("name", "")
    if ev.get("event") in ("ok", "failed", "ignored", "timeout"):
        results[name] = ev["event"]
        if ev.get("stdout"):
            outputs[name] = ev["stdout"]

rows = []
for line in os.environ["PROVA_MANIFEST"].splitlines():
    line = line.strip()
    if not line:
        continue
    section, test, kind, claim = line.split("|", 3)
    rows.append((section, test, kind, claim))

# A test named in the manifest that the binary never ran is a FAIL, never a
# skip. That is the defect this project has already shipped once: a suite that
# reports `ok` having run nothing.
verdicts, fatal, pending_red, pending_green = [], 0, 0, 0
for section, test, kind, claim in rows:
    got = results.get(test)
    if got is None:
        verdict, bad = "MISSING", True
    elif got == "ok":
        verdict, bad = "PASS", False
    elif got == "ignored":
        verdict, bad = "NOT RUN", True
    else:
        verdict, bad = "FAIL", True

    if kind == "pending":
        if verdict == "PASS":
            verdict, bad = "PASS (!)", False
            pending_green += 1
        elif verdict in ("FAIL",):
            verdict, bad = "PENDING", False
            pending_red += 1
    if bad:
        fatal += 1
    verdicts.append((section, test, kind, claim, verdict))

W = 74
last = None
print("┌" + "─" * (W + 22) + "┐")
for section, test, kind, claim, verdict in verdicts:
    if section != last:
        print("│ " + f"── {section} ".ljust(W + 20, "─") + " │")
        last = section
    mark = {"PASS": "PASS   ", "FAIL": "FAIL   ", "MISSING": "MISSING", "NOT RUN": "NOT RUN",
            "PENDING": "PENDING", "PASS (!)": "PASS(!)"}[verdict]
    short = test.split("::")[-1]
    print("│ " + f"{mark}  {short}"[:W + 20].ljust(W + 20) + " │")
    print("│ " + f"           {claim}"[:W + 20].ljust(W + 20) + " │")
print("└" + "─" * (W + 22) + "┘")

print()
print("── measured output ─────────────────────────────────────────────────────")
for _, test, _, _, _ in verdicts:
    out = outputs.get(test, "")
    for l in out.splitlines():
        if l.strip():
            print("  " + l.strip())

print()
ran = sum(1 for v in verdicts if v[4] not in ("MISSING",))
print(f"gates in the manifest: {len(verdicts)}   resolved: {ran}   failing: {fatal}")
print(f"test events parsed: {len(results)}")
if not raw.rstrip().endswith("}") or '"type": "suite"' not in raw:
    print("!! THE EVENT STREAM DOES NOT END IN A SUITE SUMMARY — the test binary")
    print("!! terminated early. Any MISSING gate above is a TRUNCATED RUN, not a")
    print("!! deleted test. Raw stream is in .prova-runs/.")
if len(verdicts) < 20:
    print("!! THE MANIFEST SHRANK. A proof you can delete is a proof you do not have.")
    sys.exit(2)
if pending_green:
    print()
    print("** A PENDING gate is now GREEN. Dev A's fix appears to have landed:")
    print("** remove the #[ignore] from prova.rs and move it out of the pending section.")
if pending_red:
    print(f"** {pending_red} gate(s) PENDING — red by construction until another dev lands their half.")
    print("** Not fatal here. It IS fatal before the relaunch tag.")
sys.exit(1 if fatal else 0)
PYEOF
RC=$?

echo
echo "── preservation manifest (Task 3) ──────────────────────────────────────"
if [ ! -x "$ROOT/scripts/preservation-manifest.py" ]; then
  echo "!! scripts/preservation-manifest.py is missing — Task 3 is UNPROVEN"
  RC=1
  PRC=2
elif [ "$DEEP" = "1" ]; then
  PROVA_CARGO="$CARGO_LOCK cargo" "$ROOT/scripts/preservation-manifest.py" \
    --worktree "$ROOT" --label "prova-relanca (deep)"
  PRC=$?
else
  echo "-- static gates only (no --deep). This run CANNOT report PASS."
  PROVA_CARGO="$CARGO_LOCK cargo" "$ROOT/scripts/preservation-manifest.py" \
    --worktree "$ROOT" --label "prova-relanca (static)" --no-cargo
  PRC=$?
fi

echo
if [ "$RC" -ne 0 ]; then
  echo "RESULT: FAIL — a gate the relaunch depends on is not proven."
  echo "        See the table. Do not relaunch on this tree."
  exit 1
fi
if [ "$PRC" -eq 3 ] || [ "$DEEP" = "0" ]; then
  echo "RESULT: INCOMPLETE — every scenario passed and every mutation bit, but the"
  echo "        preservation manifest ran static gates only. Re-run with --deep"
  echo "        before calling anything preserved."
  exit 3
fi
if [ "$PRC" -ne 0 ]; then
  echo "RESULT: FAIL — the preservation manifest rejected this tree."
  exit 1
fi
echo "RESULT: PASS — every gate the relaunch depends on is proven, every mutation"
echo "        bites, and the preservation manifest accepts this tree."
echo "        See the PENDING note above before tagging."
exit 0
