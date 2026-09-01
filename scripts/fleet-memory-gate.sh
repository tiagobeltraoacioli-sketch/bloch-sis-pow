#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# fleet-memory-gate.sh — "will this roll still fit in the box's RAM?"
#
# Run it BEFORE restarting validators fleet-wide. It answers one question per
# box: if every validator on this box is restarted at the same time, does the
# sum of their BOOT PEAKS fit in RAM?
#
# WHY THIS EXISTS
#   The Genesis-4 memory program tracks a per-validator ceiling that a drift
#   projection says is ~5 weeks away. That projection is not what kills a box.
#   A box carries 9 validators. Steady state is what the projection measures,
#   but a roll restarts all 9 at once, and a booting node's peak is ABOVE its
#   steady state. Nine simultaneous boot peaks is the number that has to fit,
#   and it is reached in minutes, not in weeks.
#
#   So the drift date and the roll date are different risks. This gate is for
#   the roll. `scripts/fleet-gate-sweep.sh` answers "will the fleet agree on
#   consensus after this roll?"; this one answers "will the fleet survive it?"
#
# WHERE THE PEAK NUMBER COMES FROM — AND WHY IT IS NOT A GUESS
#   Linux keeps VmHWM (peak resident set) per process for the process's whole
#   lifetime. For a validator that is running right now, VmHWM IS the boot peak
#   it actually paid, measured by the kernel, retained for free. So for the
#   binary the fleet is ALREADY running, this gate needs no experiment: it
#   reads the truth off the live processes.
#
#   For the binary you are ABOUT TO roll, that number does not exist yet and
#   cannot be read off the fleet. Measure it on an idle box — boot one node of
#   the candidate binary against a tip-height blocks.log and read its VmHWM —
#   and pass it as --peak-mib. WITHOUT --peak-mib this gate reports on the
#   binary now running and REFUSES to certify a roll, because a new binary's
#   peak is exactly the thing that changed.
#
# READ-ONLY. One ssh per box running `cat /proc/meminfo` and reading
# /proc/<pid>/status for the node processes. It starts nothing, stops nothing,
# writes nothing, and cannot arm anything.
#
# USAGE
#   scripts/fleet-memory-gate.sh [--hosts FILE] [--peak-mib N]
#                                [--reserve-mib N] [--jobs N] [--timeout S]
#                                [--json]
#
#   --peak-mib N     measured boot peak, per validator, MiB, for the binary
#                    about to be rolled. Required to certify a roll.
#   --reserve-mib N  RAM held back for page cache and the OS (default 3072).
#                    The block log is read through the page cache on every
#                    boot; starving it trades RAM for a slower replay.
#   --hosts FILE     host table (default: scripts/fleet-gates.tsv), same
#                    format and same file as fleet-gate-sweep.sh.
#
# VERDICTS, per box
#   SUM_DATA is the sum of VmData (heap actually allocated) across the box.
#   It runs AHEAD of SUM_RSS — measured 2026-09-01, ~2,000 MiB of heap against
#   ~1,250 MiB resident per validator, a lag of ~650 MiB each. That gap is why
#   an RSS-derived growth slope reads LOW over a short window: new map entries
#   land in heap the allocator already holds, and RSS only steps up later. Use
#   RSS for "does it fit in RAM right now" (this gate) and VmData for "where is
#   this going" (the projection). A projection built on an RSS slope measured
#   over minutes will be optimistic; this program had one.
#
#   PASS     N x peak + reserve <= MemTotal. Roll all at once.
#   STAGGER  the simultaneous roll does not fit, but one boot peak alongside
#            N-1 nodes at their CURRENT resident size does. Restart them one
#            at a time, waiting for each to finish replaying before the next.
#            This is a real remedy, not a warning: it converts N peaks into
#            1 peak + (N-1) steady.
#   FAIL     even a staggered roll does not fit. Do not roll. The box needs
#            fewer validators on it, or the memory work has to land first.
#
# EXIT STATUS
#   0  every box PASS
#   1  any box STAGGER or FAIL, or a box that could not be read
#   2  usage error, or asked to certify a roll with no --peak-mib
set -uo pipefail

HOSTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fleet-gates.tsv"
PEAK=""; RESERVE=3072; JOBS=8; TIMEOUT=20; JSON=0
# Process-name pattern for a validator node. Deliberately matches the binary
# family (bloch-pos*) rather than a unit name: the fleet has carried units
# called g4-vNN and bloch-nNN pointing at the same directories, and a name
# match has already missed a duplicate signer once.
PAT='bloch-pos'

die() { echo "fleet-memory-gate: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --hosts) HOSTS="${2:?}"; shift 2;;
    --peak-mib) PEAK="${2:?}"; shift 2;;
    --reserve-mib) RESERVE="${2:?}"; shift 2;;
    --jobs) JOBS="${2:?}"; shift 2;;
    --timeout) TIMEOUT="${2:?}"; shift 2;;
    --json) JSON=1; shift;;
    -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done
[ -r "$HOSTS" ] || die "host table not readable: $HOSTS"
case "${PEAK:-0}" in ''|*[!0-9]*) [ -n "$PEAK" ] && die "--peak-mib must be an integer";; esac
case "$RESERVE" in ''|*[!0-9]*) die "--reserve-mib must be an integer";; esac

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# ---- probe one box, read-only -------------------------------------------
# Emits: label host memtotal_mib memavail_mib nproc sum_rss_mib max_hwm_mib
probe() {
  local label=$1 host=$2 key=$3
  local out
  out=$(ssh -n -i "$HOME/.ssh/$key" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout="$TIMEOUT" "ubuntu@$host" '
    mt=$(awk "/^MemTotal:/{print int(\$2/1024)}" /proc/meminfo)
    ma=$(awk "/^MemAvailable:/{print int(\$2/1024)}" /proc/meminfo)
    n=0; rss=0; hwm=0; age=0; dat=0
    for p in $(pgrep -f "'"$PAT"'" 2>/dev/null); do
      [ "$p" = "$$" ] && continue
      s=/proc/$p/status; [ -r "$s" ] || continue
      # A node is a process whose argv carries BOTH the run subcommand and
      # --data-dir, as separate NUL-delimited arguments. Matching the raw
      # cmdline with grep is not enough: the string "run" appears inside
      # directory names, and pgrep -f also matches the probe shell itself.
      # --data-dir is the discriminator: selfcheck, keygen, scp and the
      # probe never carry it. NOTE for future editors: this whole remote
      # script is single-quoted, so it must contain no apostrophe anywhere,
      # comments included.
      args=$(tr "\\000" "\\012" < /proc/$p/cmdline 2>/dev/null)
      printf "%s\\n" "$args" | grep -qx -- "run" || continue
      printf "%s\\n" "$args" | grep -qx -- "--data-dir" || continue
      printf "%s\\n" "$args" | grep -qx -- "--data-dir" || continue
      r=$(awk "/^VmRSS:/{print int(\$2/1024)}" "$s" 2>/dev/null)
      dv=$(awk "/^VmData:/{print int(\$2/1024)}" "$s" 2>/dev/null)
      [ -n "${dv:-}" ] && dat=$((dat+dv))
      h=$(awk "/^VmHWM:/{print int(\$2/1024)}" "$s" 2>/dev/null)
      [ -n "$r" ] || continue
      n=$((n+1)); rss=$((rss+r)); [ "${h:-0}" -gt "$hwm" ] && hwm=$h
      # VmHWM is a lifetime high-water mark. A node that booted weeks ago set
      # it against a SHORTER chain, so an old process reports a peak that is
      # too small for a boot today. Carry the age so the caller can see it.
      e=$(ps -o etimes= -p $p 2>/dev/null | tr -d " ")
      [ -n "${e:-}" ] && [ "$e" -gt "$age" ] && age=$e
    done
    echo "$mt $ma $n $rss $hwm $((age/86400)) $dat"' 2>/dev/null)
  if [ -z "$out" ]; then
    echo "$label $host UNREACHABLE 0 0 0 0 0 0" > "$TMP/$label.out"
  else
    echo "$label $host $out" > "$TMP/$label.out"
  fi
}

n=0
while IFS=$'\t' read -r label host key bin role; do
  case "$label" in ''|\#*) continue;; esac
  probe "$label" "$host" "$key" &
  n=$((n+1)); [ $((n % JOBS)) -eq 0 ] && wait
done < "$HOSTS"
wait

# ---- verdicts ------------------------------------------------------------
rc=0; rows=""; stale=""
printf '%-12s %-16s %6s %6s %3s %8s %8s %8s %5s %8s  %s\n' \
  BOX HOST TOTAL AVAIL N SUM_RSS SUM_DATA MAX_HWM AGE_D NEED VERDICT
for f in "$TMP"/*.out; do
  read -r label host mt ma np rss hwm aged dat < "$f"
  if [ "$mt" = "UNREACHABLE" ]; then
    printf '%-12s %-16s %6s %6s %3s %8s %8s %8s %5s %8s  %s\n' \
      "$label" "$host" - - - - - - - - "UNREACHABLE"
    rc=1; rows="$rows{\"box\":\"$label\",\"verdict\":\"UNREACHABLE\"},"; continue
  fi
  # peak per validator: measured candidate if given, else this box's own
  # observed high-water mark for the binary it is running now.
  if [ -n "$PEAK" ]; then p=$PEAK; src=candidate; else p=$hwm; src=observed; fi
  cap=$((mt - RESERVE))
  need=$((np * p))
  # staggered: one boot peak, plus the others at their current resident size
  steady_others=0
  [ "$np" -gt 0 ] && steady_others=$(( rss - (rss / np) ))
  stag=$((p + steady_others))
  if [ "$np" -eq 0 ]; then v="NO-NODES"
  elif [ "$need" -le "$cap" ]; then v="PASS"
  elif [ "$stag" -le "$cap" ]; then v="STAGGER"; rc=1
  else v="FAIL"; rc=1; fi
  [ -z "$PEAK" ] && [ "$v" = "PASS" ] && v="PASS(observed-only)"
  printf '%-12s %-16s %6s %6s %3s %8s %8s %8s %5s %8s  %s\n' \
    "$label" "$host" "$mt" "$ma" "$np" "$rss" "$dat" "$hwm" "$aged" "$need" "$v"
  [ -z "$PEAK" ] && [ "${aged:-0}" -gt 2 ] && stale="$stale $label(${aged}d)"
  rows="$rows{\"box\":\"$label\",\"host\":\"$host\",\"mem_total_mib\":$mt,\"mem_avail_mib\":$ma,\"validators\":$np,\"sum_rss_mib\":$rss,\"max_hwm_mib\":$hwm,\"peak_mib\":$p,\"peak_source\":\"$src\",\"capacity_mib\":$cap,\"simultaneous_need_mib\":$need,\"staggered_need_mib\":$stag,\"verdict\":\"$v\"},"
done

echo
if [ -z "$PEAK" ]; then
  echo "NOT A ROLL CERTIFICATE: --peak-mib was not given, so MAX_HWM above is"
  echo "the peak of the binary each box is ALREADY running. A new binary's peak"
  echo "is the thing that changed; measure it on an idle box and pass it in."
  if [ -n "$stale" ]; then
    echo
    echo "AND THOSE MARKS ARE STALE:$stale"
    echo "VmHWM is a lifetime high-water mark. Those nodes booted that many days"
    echo "ago, against a chain shorter by roughly age x 2873 blocks, so the peak"
    echo "they report is LOWER than a boot today would pay. Treat MAX_HWM as a"
    echo "floor, never as the headroom you have."
  fi
  rc=1
fi
[ $JSON -eq 1 ] && printf '{"reserve_mib":%s,"peak_mib":"%s","boxes":[%s]}\n' \
  "$RESERVE" "${PEAK:-observed}" "${rows%,}"
exit $rc
