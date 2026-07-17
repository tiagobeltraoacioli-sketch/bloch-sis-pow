#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# check-boot-log.sh — grade a captured serial log against success-markers.txt.
#
# Shared by the QEMU rung (this dir's harness / a CI job) and the hardware rung
# (the PinePhone serial capture), so both agree on what "booted" means.
#
# Usage:  check-boot-log.sh <boot.log> [markers.txt]
# Exit:   0 all REQUIRED markers present (in order) and NO failure marker seen
#         1 a required marker is missing / out of order
#         2 a failure marker was found (panic / emergency / rootfs / stage-1 shell)
#         3 usage / missing input
set -eu

LOG="${1:-}"
# shellcheck disable=SC1007  # `CDPATH= cd` is the intended scoped-empty idiom
MARKERS="${2:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/success-markers.txt}"

if [ -z "$LOG" ] || [ ! -r "$LOG" ]; then
  echo "check-boot-log: cannot read boot log: '${LOG:-<none>}'" >&2
  echo "usage: check-boot-log.sh <boot.log> [markers.txt]" >&2
  exit 3
fi
if [ ! -r "$MARKERS" ]; then
  echo "check-boot-log: cannot read markers file: '$MARKERS'" >&2
  exit 3
fi

rc=0

# 1) Failure markers must not appear anywhere.
while IFS= read -r line; do
  case "$line" in
    '- '*)
      pat=${line#- }
      if grep -Eq -- "$pat" "$LOG"; then
        echo "FAIL  found failure marker: /$pat/" >&2
        rc=2
      fi
      ;;
  esac
done < "$MARKERS"

# 2) Required markers must appear, and in the listed order. We walk the log once
#    per marker but require each next marker at/after the previous one's line.
last_line=0
while IFS= read -r line; do
  case "$line" in
    '+ '*)
      pat=${line#+ }
      # First matching line number for this marker.
      hit=$(grep -En -- "$pat" "$LOG" | awk -F: -v min="$last_line" '$1 >= min {print $1; exit}')
      if [ -z "$hit" ]; then
        echo "FAIL  required marker missing (or out of order): /$pat/" >&2
        [ "$rc" -lt 1 ] && rc=1
      else
        echo "ok    /$pat/  (line $hit)"
        last_line=$hit
      fi
      ;;
  esac
done < "$MARKERS"

# 3) Report optional/informational markers (never gate).
while IFS= read -r line; do
  case "$line" in
    '~ '*)
      pat=${line#~ }
      if grep -Eq -- "$pat" "$LOG"; then
        echo "info  present: /$pat/"
      else
        echo "info  absent : /$pat/"
      fi
      ;;
  esac
done < "$MARKERS"

if [ "$rc" -eq 0 ]; then
  echo "PASS  boot log satisfies the shared success ladder (software chain)."
  echo "      Reminder: QEMU ≠ hardware — this proves nothing about the phone."
else
  echo "boot log did NOT pass (rc=$rc)." >&2
fi
exit "$rc"
