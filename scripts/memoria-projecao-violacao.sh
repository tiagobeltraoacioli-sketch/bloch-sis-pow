#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# memoria-projecao-violacao.sh — prove the memory-projection tests actually bite.
#
# A test that never fails is indistinguishable from a test that cannot fail,
# and this programme has already shipped several numbers that nobody could
# have caught going wrong. So the tests in tools/memoria-projecao are not
# trusted because they are green: they are trusted because each one has been
# made to go RED on demand, by falsifying the live-fleet snapshot in the
# specific way that test exists to notice.
#
# For each falsification below this script asserts THE NAMED TEST FAILS. If a
# falsification slips through green, THIS SCRIPT FAILS — a check that no
# longer bites is worse than no check, because it is still being counted.
#
# READ-ONLY with respect to the fleet: it never connects to a box. It copies
# the checked-in snapshot into a temp dir, edits the copy, and points the
# tests at it via BLOCH_FLEET_OBSERVATIONS. The real snapshot is not touched.
#
# USAGE   scripts/memoria-projecao-violacao.sh
# EXIT    0 every falsification was caught; 1 one was not; 2 setup failure
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAP="$ROOT/scripts/fleet-memory-observations.tsv"
[ -r "$SNAP" ] || { echo "violacao: no snapshot at $SNAP; run scripts/fleet-memory-observe.sh" >&2; exit 2; }

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

# Build somewhere of our own unless told otherwise. The repo is worked on by
# several agents at once and cargo takes a directory lock on its target dir;
# sharing it turns this script into an unexplained wait.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$TMP/target}"

pass=0; fail=0

# run_case NAME EXPECTED_TEST MUTATED_FILE
run_case() {
  local name=$1 want=$2 file=$3 out rc
  out=$(cd "$ROOT" && BLOCH_FLEET_OBSERVATIONS="$file" \
        cargo test -q -p bloch-memoria-projecao 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "NOT CAUGHT  $name"
    echo "            the suite stayed GREEN against a snapshot falsified to trip"
    echo "            tests::$want. That test is decorative — fix it or delete it."
    fail=$((fail+1)); return
  fi
  if printf '%s' "$out" | grep -q "tests::$want"; then
    echo "caught      $name  ->  tests::$want"
    # Show the operator-facing message, which is the actual deliverable: a
    # failing test that does not say what to do is a puzzle, not an alarm.
    printf '%s' "$out" | sed -n "/panicked at/,/^\$/p" | head -6 | sed 's/^/              /'
    pass=$((pass+1))
  else
    echo "WRONG TEST  $name"
    echo "            the suite went red, but not on tests::$want. Something else is"
    echo "            broken, and this falsification is therefore unproven."
    printf '%s' "$out" | grep -E '^\s+tests::' | head -5 | sed 's/^/              /'
    fail=$((fail+1))
  fi
}

# ---- the falsifications --------------------------------------------------
# Each edits ONE thing, so a red suite is attributable to it.

# 1. A box is re-provisioned smaller. The per-validator ceiling is
#    (MemTotal - reserve) / N, so this silently changes the date for that box.
awk -F'\t' -v OFS='\t' 'NF>=13 && $1 !~ /^#/ && $1=="139.84.201.52" {$3="16384"} {print}' \
  "$SNAP" > "$TMP/box-shrunk.tsv"
run_case "a box re-provisioned to 16 GiB" \
         "every_box_still_has_the_ram_the_projection_assumes" "$TMP/box-shrunk.tsv"

# 2. A tenth validator lands on a box. Both dates scale with N.
{ cat "$SNAP"; grep -m1 '^139\.84\.201\.52	' "$SNAP" | awk -F'\t' -v OFS='\t' '{$8=$8+1; print}'; } \
  > "$TMP/tenth.tsv"
run_case "a tenth validator on one box" \
         "every_box_still_carries_the_validators_the_projection_assumes" "$TMP/tenth.tsv"

# 3. THE HIDDEN VARIABLE. The block cadence falls back to the h10k-15k regime
#    (5,000 blocks in 21,187 slots). Nothing about the boxes changes. If growth
#    really follows slots the dates should not move -- and this is the live
#    experiment that would confirm it. It must not pass unnoticed.
sed 's/^# blocks_per_slot_measured	.*/# blocks_per_slot_measured	0.2360/' \
  "$SNAP" > "$TMP/cadence-collapse.tsv"
run_case "block cadence back to 24% of slots" \
         "the_slot_to_block_relation_is_still_what_the_projection_was_derived_under" \
         "$TMP/cadence-collapse.tsv"

# 4. The fleet is fatter than the projection was derived against -- the
#    dangerous direction, and the one nobody notices, because nothing breaks
#    until a box dies. 250 MiB per validator is about nine days of drift.
awk -F'\t' -v OFS='\t' 'NF>=13 && $1 !~ /^#/ {$9=$9+250; $10=$10+250} {print}' \
  "$SNAP" > "$TMP/fatter.tsv"
run_case "every validator 250 MiB fatter than projected" \
         "the_published_roll_date_still_follows_from_the_live_fleet" "$TMP/fatter.tsv"

# 5. Nobody has restarted a validator in ten days, so every VmHWM was set
#    against a much shorter chain. The marks still LOOK fine -- they are just
#    no longer evidence about a boot today. This is the floor-not-headroom
#    failure, and it is invisible unless something checks the age.
awk -F'\t' -v OFS='\t' 'NF>=13 && $1 !~ /^#/ {$11=$11-864000; $12=$12+864000} {print}' \
  "$SNAP" > "$TMP/stale-marks.tsv"
run_case "no boot fresher than 10 days" \
         "roll_arm_rests_on_marks_that_are_still_informative" "$TMP/stale-marks.tsv"

# 6. The snapshot itself is old. Every other number in it can be internally
#    consistent and still describe a fleet that no longer exists.
OLD=$(( $(date +%s) - 40*86400 ))
sed "s/^# captured_unix	.*/# captured_unix	$OLD/" "$SNAP" > "$TMP/old-snapshot.tsv"
run_case "snapshot 40 days old" \
         "snapshot_has_not_gone_stale" "$TMP/old-snapshot.tsv"

# 7. The boot premium collapses. That would retire the PEAK curve as a
#    distinct risk -- which is good news, and good news is what this programme
#    has historically believed without checking.
awk -F'\t' -v OFS='\t' 'NF>=13 && $1 !~ /^#/ {$9=$10} {print}' \
  "$SNAP" > "$TMP/no-premium.tsv"
run_case "boot peak equal to steady state" \
         "the_boot_premium_is_still_a_premium_and_still_not_a_multiple" "$TMP/no-premium.tsv"

# 8. A column shift -- the exact bug this collector shipped once already, where
#    the hostname landed in mem_total_mib and every downstream number moved one
#    place right. It reads as a plausible file, not as an error.
awk -F'\t' -v OFS='\t' 'NF>=13 && $1 !~ /^#/ {$9=$10-1} {print}' \
  "$SNAP" > "$TMP/peak-below-resident.tsv"
run_case "a peak below its own resident set (corrupt columns)" \
         "snapshot_is_structurally_whole" "$TMP/peak-below-resident.tsv"

# ---- and the control: the real snapshot must be GREEN ---------------------
echo
if (cd "$ROOT" && cargo test -q -p bloch-memoria-projecao >/dev/null 2>&1); then
  echo "control     the unmodified snapshot is GREEN"
else
  echo "CONTROL RED the unmodified snapshot FAILS its own tests. Either the fleet has"
  echo "            moved past the published projection -- which is the alarm working"
  echo "            -- or the suite is broken. Read the failure before assuming which."
  fail=$((fail+1))
fi

echo
echo "falsifications caught: $pass   missed: $fail"
[ "$fail" -eq 0 ] || exit 1
