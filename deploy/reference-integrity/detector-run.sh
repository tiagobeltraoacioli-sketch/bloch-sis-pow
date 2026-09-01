#!/usr/bin/env bash
# detector-run.sh — the entry point the TIMER calls. Never call rot-detector.sh
# from a timer directly; call this.
#
# Why a wrapper exists at all. The detector answers "has anything rotted?".
# It cannot answer "did anyone ask?" — and that second question is the one
# that cost nine hours on 2026-08-31. A check that silently stopped running
# looks exactly like a check that keeps passing: both are silence.
#
# So every unattended run leaves a receipt, on EVERY exit path including the
# undetermined one. Exit 2 means we lost the ability to check; a run that ends
# in 2 must still prove it happened, or "the detector is broken" and "the
# detector was never started" become indistinguishable — which is precisely
# the confusion this whole directory exists to abolish.
#
# The receipt is $STATE_DIR/last-run.tsv, one line, overwritten:
#     <iso8601-utc>\t<unix-epoch>\t<exit-code>\t<verdict line>
# heartbeat.sh reads it. Nothing else does; nothing else may depend on it.
#
# STRICTLY READ-ONLY with respect to the fleet: it adds no ssh of its own and
# runs no command on a node. It only writes inside STATE_DIR, on this machine.
#
# Usage: detector-run.sh [args passed through to rot-detector.sh]
# Exit:  whatever rot-detector.sh exited with (0 clean, 1 rot, 2 undetermined).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${REFINT_CONF:-$HERE/reference-integrity.conf}"

# The wrapper must PEEK at -c without consuming it: it needs the conf to learn
# where STATE_DIR is (that is where the receipt goes), and rot-detector.sh
# needs the same flag forwarded. An earlier draft only forwarded it, so a run
# with `-c other.conf` wrote its receipt into the DEFAULT state dir — silently
# overwriting the real fleet's receipt with a test run's verdict. A receipt
# that can be clobbered by an unrelated invocation is worse than no receipt.
_prev=""
for _a in "$@"; do
  [ "$_prev" = "-c" ] && { CONF="$_a"; break; }
  _prev="$_a"
done
unset _prev _a

# STATE_DIR is read from the conf when there is one, but the receipt must be
# writable even when the conf is the thing that is missing — a missing conf is
# an exit 2, and an exit 2 that leaves no receipt is the failure above.
STATE_DIR="${STATE_DIR:-$HOME/.bloch-reference-integrity}"
if [ -f "$CONF" ]; then
  # shellcheck disable=SC1090
  . "$CONF" || true
  : "${STATE_DIR:=$HOME/.bloch-reference-integrity}"
fi
mkdir -p "$STATE_DIR" 2>/dev/null

RECEIPT="$STATE_DIR/last-run.tsv"
OUTFILE="$STATE_DIR/last-verdict.txt"

# Bound the whole run. A detector that HANGS is worse than one that fails:
# systemd reports the oneshot as "activating" forever, `systemctl --failed`
# stays empty, and the receipt stops advancing while everything looks fine.
# A sweep of 9 hosts and 65 RPCs measures ~4 min; 20 is generous and finite.
TIMEOUT_S="${DETECTOR_TIMEOUT_S:-1200}"
runner() {
  if command -v timeout >/dev/null 2>&1; then timeout -k 30 "$TIMEOUT_S" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout -k 30 "$TIMEOUT_S" "$@"
  else "$@"; fi   # no timeout binary: still run, and say so in the receipt
}
HAVE_TIMEOUT=1
command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1 || HAVE_TIMEOUT=0

set +e
runner "$HERE/rot-detector.sh" "$@" > "$OUTFILE.tmp" 2>&1
rc=$?
set -e
mv -f "$OUTFILE.tmp" "$OUTFILE" 2>/dev/null || true

# The verdict is the LAST non-empty line: rot-detector prints its detail block
# first and the one-line verdict last, by design.
#
# CAPTURE IT BEFORE APPENDING ANYTHING. An earlier draft appended the
# "no timeout(1)" note first and then took the last line, so every receipt
# recorded the note instead of the verdict — a heartbeat that faithfully
# reported a number and a sentence that had nothing to do with each other.
# Notes go after this line; they never become the verdict.
verdict=$(awk 'NF{l=$0} END{print l}' "$OUTFILE" 2>/dev/null)
[ -n "$verdict" ] || verdict="(no output — rot-detector.sh produced nothing, exit $rc)"

# `timeout` reports 124 (or 137 after -k). Map it to 2: we did not determine
# anything. It is NOT a 0, and it is not a 1 either — there is no finding,
# there is an absence of an answer. This DOES replace the verdict, because a
# killed sweep's last line is wherever it happened to be when it died.
if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
  verdict="ROT-DETECTOR: UNDETERMINED — the sweep exceeded ${TIMEOUT_S}s and was killed"
  echo "$verdict" >> "$OUTFILE"
  rc=2
fi
[ "$HAVE_TIMEOUT" = 0 ] && echo "(note: no timeout(1) on this host — the sweep was unbounded; install coreutils for gtimeout)" >> "$OUTFILE"

printf '%s\t%s\t%s\t%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date +%s)" "$rc" "$verdict" > "$RECEIPT"

# Pass the output through so cron mails it and the journal keeps it.
cat "$OUTFILE"
exit "$rc"
