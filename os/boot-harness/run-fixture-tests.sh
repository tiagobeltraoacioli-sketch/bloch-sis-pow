#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# run-fixture-tests.sh — HOST-provable self-test for the SHARED boot grader.
#
# This is the ONE thing in the aarch64 boot rung that runs on the dev host
# (macOS: no Nix, no KVM, no qemu-system). It does NOT boot anything. It feeds
# check-boot-log.sh a set of HAND-WRITTEN synthetic serial logs (./fixtures/*.log)
# whose correct verdicts are known in advance, and asserts the grader returns the
# expected exit code for each. It proves the grader LOGIC — the ordered-marker
# ladder + failure-marker veto — is correct. It proves NOTHING about a real boot.
#
#   grader-logic-correct ≠ image-boots.  QEMU ≠ hardware.  UNAUDITED.
#
# Grader exit contract under test (see check-boot-log.sh):
#   0  all REQUIRED markers present, in order, and NO failure marker seen
#   1  a required marker is missing / out of order
#   2  a failure marker (panic / emergency / rootfs / stage-1 shell) was found
#   3  usage / unreadable input
#
# Usage:  ./run-fixture-tests.sh
# Exit:   0 every fixture graded as expected; 1 one or more mismatches.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` is the intended scoped-empty idiom
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GRADER="$HERE/check-boot-log.sh"
MARKERS="$HERE/success-markers.txt"
FIX="$HERE/fixtures"

# Each case: "<fixture-file> <expected-rc> <what-it-proves>".
# Keep pass first, then the failure taxonomy.
CASES='
pass.log|0|happy path: full ladder in order, no failure marker
fail-panic.log|2|failure marker (Kernel panic) vetoes an otherwise-complete ladder
fail-emergency.log|2|failure marker (Entering emergency mode) is caught
fail-rootfs.log|2|failure marker (Unable to mount root fs) is caught
fail-stage1-shell.log|2|failure marker (stage-1 emergency shell) is caught
fail-missing-login.log|1|required rung (login:/MOTD) missing -> not passed
fail-out-of-order.log|1|markers present but out of order -> not passed
'

if [ ! -x "$GRADER" ] && [ ! -r "$GRADER" ]; then
  echo "self-test: cannot find grader at $GRADER" >&2
  exit 1
fi
if [ ! -r "$MARKERS" ]; then
  echo "self-test: cannot find markers at $MARKERS" >&2
  exit 1
fi

pass=0
fail=0
printf '== boot-grader self-test (HOST; no boot happens) ==\n'
printf 'grader : %s\n' "$GRADER"
printf 'markers: %s\n\n' "$MARKERS"

echo "$CASES" | while IFS='|' read -r file want why; do
  [ -z "$file" ] && continue
  log="$FIX/$file"
  if [ ! -r "$log" ]; then
    printf 'MISS  %-24s (fixture not found)\n' "$file"
    echo fail >> "$HERE/.selftest.tally"
    continue
  fi
  # Run the grader; capture only its exit code (its own stdout/stderr is noise here).
  got=0
  sh "$GRADER" "$log" "$MARKERS" >/dev/null 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then
    printf 'PASS  %-24s rc=%s  (%s)\n' "$file" "$got" "$why"
    echo pass >> "$HERE/.selftest.tally"
  else
    printf 'FAIL  %-24s rc=%s want=%s  (%s)\n' "$file" "$got" "$want" "$why"
    echo fail >> "$HERE/.selftest.tally"
  fi
done

# Extra case: an unreadable/missing log must be a usage error (rc=3), not a
# false PASS. This guards the "no input silently grades green" failure mode.
got=0
sh "$GRADER" "$FIX/does-not-exist.log" "$MARKERS" >/dev/null 2>&1 || got=$?
if [ "$got" -eq 3 ]; then
  printf 'PASS  %-24s rc=%s  (%s)\n' "(missing input)" "$got" "unreadable log -> usage error, never a green pass"
  echo pass >> "$HERE/.selftest.tally"
else
  printf 'FAIL  %-24s rc=%s want=3  (%s)\n' "(missing input)" "$got" "unreadable log -> usage error, never a green pass"
  echo fail >> "$HERE/.selftest.tally"
fi

# The while-loop ran in a subshell (pipe), so tally via a temp file, then reduce.
if [ -f "$HERE/.selftest.tally" ]; then
  pass=$(grep -c '^pass$' "$HERE/.selftest.tally" || true)
  fail=$(grep -c '^fail$' "$HERE/.selftest.tally" || true)
  rm -f "$HERE/.selftest.tally"
fi

printf '\n== %s passed, %s failed ==\n' "$pass" "$fail"
if [ "${fail:-0}" -ne 0 ]; then
  echo "self-test FAILED — the grader logic regressed against the fixtures." >&2
  exit 1
fi
echo "self-test OK — grader LOGIC is correct against the fixtures."
echo "Reminder: this is HOST proof of the grader only; no image booted anywhere."
