#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# fleet-memory-observe.sh — capture the live fleet's own memory numbers into a
# snapshot the memory projection is CHECKED AGAINST.
#
# WHY THIS EXISTS
#   `docs/MEMORY-PROJECTION.md` names a date on which 9 validators per box
#   exhaust a 31,866 MiB box. Every input to that date is either a measurement
#   or is marked as modelled. The measured half has to keep being true, and the
#   programme's repeated failure mode is a headline number that nobody
#   re-checked. So the projection does not restate its inputs — it recomputes
#   them from THIS file, and `tools/memoria-projecao` fails its tests when the
#   file and the projection disagree, or when the file has gone stale.
#
#   Nothing here is an estimate. Linux keeps VmHWM (peak resident set) per
#   process for the process's whole lifetime, so a running fleet's boot peaks
#   are already recorded, kernel-measured, at no cost. Boot heights come from
#   the chain's own archive, not from arithmetic on wall-clock.
#
# READ-ONLY, AND STRUCTURALLY SO. One ssh per box that reads /proc and curls
# the node's own loopback RPC. It starts nothing, stops nothing, restarts no
# validator, writes nothing on any box except under /tmp, and arms nothing.
#
# USAGE
#   scripts/fleet-memory-observe.sh [--out FILE] [--hosts FILE] [--key NAME]
#                                   [--rpc-base N] [--fast]
#
#   --out FILE    snapshot to write (default scripts/fleet-memory-observations.tsv)
#   --hosts FILE  one box IP per line, '#' comments allowed
#                 (default: the 7 Genesis-4 "grandes")
#   --key NAME    ssh key under ~/.ssh (default edgevana_fleet_g4)
#   --rpc-base N  first validator RPC port (default 16400); the collector uses
#                 the FIRST live port it finds on the first reachable box.
#   --fast        skip the archival boot-height lookup. Leaves boot_height as
#                 NA; the projection then cannot report how many blocks stale
#                 each VmHWM mark is, only how many seconds.
#
# EXIT STATUS
#   0  snapshot written, every box read
#   1  a box could not be read, or the chain could not be reached
#   2  usage error
set -uo pipefail
# The snapshot is parsed by tools/memoria-projecao with f64::from_str, which
# accepts only '.' as a decimal point. Under a pt_BR locale awk and printf emit
# '2826,8' and the parse fails at the far end, days later, with a message about
# a malformed field rather than about a locale. Pin it here.
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/fleet-memory-observations.tsv"
HOSTS=""
KEY="edgevana_fleet_g4"
RPC_BASE=16400
FAST=0
CONNECT_TIMEOUT=15

die() { echo "fleet-memory-observe: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?}"; shift 2;;
    --hosts) HOSTS="${2:?}"; shift 2;;
    --key) KEY="${2:?}"; shift 2;;
    --rpc-base) RPC_BASE="${2:?}"; shift 2;;
    --fast) FAST=1; shift;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

# The seven Genesis-4 "grandes", 9 validators each, after the 31/08 migration.
DEFAULT_HOSTS='139.84.205.54
139.84.204.46
139.84.202.139
139.84.201.52
149.28.180.128
67.219.108.230
67.219.108.96'

if [ -n "$HOSTS" ]; then
  [ -r "$HOSTS" ] || die "host file not readable: $HOSTS"
  BOXES=$(grep -v '^[[:space:]]*#' "$HOSTS" | grep -v '^[[:space:]]*$')
else
  BOXES="$DEFAULT_HOSTS"
fi

IDENT="$HOME/.ssh/$KEY"
[ -r "$IDENT" ] || die "ssh key not readable: $IDENT"

TMP=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$TMP"' EXIT

sshq() {  # sshq HOST COMMAND...   -- always -n: never let a loop eat stdin
  ssh -n -i "$IDENT" -o BatchMode=yes -o StrictHostKeyChecking=no \
      -o ConnectTimeout="$CONNECT_TIMEOUT" "ubuntu@$1" "$2" 2>/dev/null
}

# ---------------------------------------------------------------- per box ---
# The remote probe. Sent base64-encoded so it survives quoting intact and so
# `ssh -n` stays available (a piped heredoc would need stdin, and stdin inside
# a loop is exactly how these sweeps have silently eaten their host list).
read -r -d '' PROBE <<'PROBE_EOF'
#!/bin/sh
BOX=$(hostname)
MT=$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo)
MA=$(awk '/^MemAvailable:/{printf "%d", $2/1024}' /proc/meminfo)
CA=$(awk '/^Cached:/{printf "%d", $2/1024; exit}' /proc/meminfo)
NC=$(nproc)
NOW=$(date +%s)
BOOT=$(awk '/^btime/{print $2}' /proc/stat)
HZ=$(getconf CLK_TCK)
echo "BOXMETA	$BOX	$MT	$MA	$CA	$NC	$NOW"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  [ -r "$p/cmdline" ] || continue
  # A validator is a process whose argv carries BOTH `run` and `--data-dir` as
  # separate NUL-delimited arguments. Matching the flat cmdline is not enough:
  # "run" occurs inside directory names, and selfcheck/keygen/scp never carry
  # --data-dir. Match on argv, never on a unit name -- this fleet has carried
  # g4-vNN and bloch-nNN units pointing at the same directory.
  args=$(tr '\000' '\012' < "$p/cmdline" 2>/dev/null)
  printf '%s\n' "$args" | grep -qx -- 'run' || continue
  printf '%s\n' "$args" | grep -qx -- '--data-dir' || continue
  hwm=$(awk '/^VmHWM:/{print $2}' "$p/status" 2>/dev/null)
  rss=$(awk '/^VmRSS:/{print $2}' "$p/status" 2>/dev/null)
  [ -n "$hwm" ] && [ -n "$rss" ] || continue
  st=$(awk '{print $22}' "$p/stat" 2>/dev/null)
  started=$(( BOOT + st / HZ ))
  # The RPC port is the argument AFTER --rpc-port, and it must be read that
  # way. Taking "the first 5-digit argument" instead picks up --listen, which
  # comes earlier in this argv, and every later probe then talks to the p2p
  # port and silently finds nothing.
  port=$(printf '%s\n' "$args" | awk '/^--rpc-port$/{getline; print; exit}')
  unit=$(grep -o 'bloch-[A-Za-z0-9]*' "/proc/$pid/cgroup" 2>/dev/null | head -1)
  echo "PROC	$BOX	$pid	${unit:-?}	${port:-?}	$hwm	$rss	$started"
done
PROBE_EOF
PROBE_B64=$(printf '%s' "$PROBE" | base64 | tr -d '\n')

rc=0
: > "$TMP/raw"
for h in $BOXES; do
  out=$(sshq "$h" "echo $PROBE_B64 | base64 -d | sh")
  if [ -z "$out" ]; then
    echo "fleet-memory-observe: UNREACHABLE $h" >&2
    rc=1
    continue
  fi
  printf '%s\n' "$out" | sed "s|^|$h\t|" >> "$TMP/raw"
done
[ -s "$TMP/raw" ] || die "no box could be read"

# ------------------------------------------------------------- the chain ---
# One reachable box, one live RPC port, read through the node's own loopback.
RPC_HOST=""; RPC_PORT=""
for h in $BOXES; do
  ports=$(awk -F'\t' -v H="$h" '$1==H && $2=="PROC" && $6 ~ /^[0-9]+$/ {print $6}' "$TMP/raw" | sort -n)
  # Bounded: three ports per box is enough to tell a reachable node from an
  # unreachable box, and an unbounded sweep over a 63-node fleet is how a
  # "quick" read-only check turns into a twenty-minute hang.
  for p in $(printf '%s\n' "$ports" | head -3); do
    r=$(sshq "$h" "curl -s --max-time 8 -X POST http://127.0.0.1:$p -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getchaininfo\",\"params\":[]}'")
    case "$r" in *'"height"'*) RPC_HOST=$h; RPC_PORT=$p; CHAIN="$r"; break;; esac
  done
  [ -n "$RPC_HOST" ] && break
done
[ -n "$RPC_HOST" ] || die "no validator RPC answered getchaininfo on any box"

# Capture the (time, slot) pair as tightly as the link allows, then bracket it:
# CAP_LO and CAP_HI are the wall clock immediately before and after the query,
# so the genesis anchor derived below carries its own error bar.
PAIR=$(sshq "$RPC_HOST" "date +%s; curl -s --max-time 8 -X POST http://127.0.0.1:$RPC_PORT -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getchaininfo\",\"params\":[]}'; echo; date +%s")
CAP_LO=$(printf '%s\n' "$PAIR" | sed -n '1p')
CHAIN=$(printf '%s\n' "$PAIR"  | sed -n '2p')
CAP_HI=$(printf '%s\n' "$PAIR" | sed -n '3p')
jget() { printf '%s' "$CHAIN" | sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" | head -1; }
HEIGHT=$(jget height); SLOT=$(jget slot); FINAL=$(jget finalized_height); EPOCH=$(jget epoch)
[ -n "$HEIGHT" ] && [ -n "$SLOT" ] || die "could not parse getchaininfo"
SLOT_SECS=30   # SLOT_DURATION_SECS, asserted at crates/bloch-pos-node/src/main.rs:914
GENESIS=$(( CAP_LO - SLOT * SLOT_SECS ))

# ------------------------------------------- boot height per validator ------
# start wall-clock -> slot (exact: slots are a fixed 30 s off genesis) -> the
# height the chain actually stood at, read out of the archive. Walking BACK
# from the slot is required: not every slot carries a block.
#
# The slot->height map lives in a FILE, not a bash associative array: this
# script has to run on the operator laptop, and macOS ships bash 3.2, where
# `declare -A` fails -- and fails NON-FATALLY, leaving every boot height as NA
# and the roll arm silently unbounded. A file works on both.
: > "$TMP/bh.tsv"
if [ "$FAST" -eq 0 ]; then
  awk -F'\t' -v g="$GENESIS" -v ss="$SLOT_SECS" '$2=="PROC"{print int(($9-g)/ss)}' "$TMP/raw" \
    | sort -un > "$TMP/slots.txt"
  cat > "$TMP/bh.sh" <<'BH_EOF'
#!/bin/sh
for s in $(cat /tmp/bloch-memobs-slots.txt); do
  i=0; h=""
  while [ $i -lt 40 ]; do
    t=$((s - i))
    [ $t -lt 0 ] && break
    r=$(curl -s --max-time 6 -X POST http://127.0.0.1:__PORT__ -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockbyslot\",\"params\":[$t]}")
    h=$(printf '%s' "$r" | sed -n 's/.*"height":\([0-9]*\).*/\1/p' | head -1)
    [ -n "$h" ] && break
    i=$((i+1))
  done
  echo "$s	${h:-NA}"
done
BH_EOF
  sed "s/__PORT__/$RPC_PORT/" "$TMP/bh.sh" > "$TMP/bh.run.sh"
  if scp -q -i "$IDENT" -o BatchMode=yes -o StrictHostKeyChecking=no \
        "$TMP/slots.txt" "ubuntu@$RPC_HOST:/tmp/bloch-memobs-slots.txt" \
     && scp -q -i "$IDENT" -o BatchMode=yes -o StrictHostKeyChecking=no \
        "$TMP/bh.run.sh" "ubuntu@$RPC_HOST:/tmp/bloch-memobs-bh.sh"; then
    sshq "$RPC_HOST" 'sh /tmp/bloch-memobs-bh.sh; rm -f /tmp/bloch-memobs-slots.txt /tmp/bloch-memobs-bh.sh' \
      > "$TMP/bh.tsv"
  else
    echo "fleet-memory-observe: boot-height lookup could not be staged; boot_height=NA" >&2
    rc=1
  fi
  if [ ! -s "$TMP/bh.tsv" ]; then
    echo "fleet-memory-observe: boot-height lookup returned nothing; boot_height=NA" >&2
    rc=1
  fi
fi

# --------------------------------------------------- measured block rate ----
# blocks/day is MEASURED here, not assumed: the oldest validator's boot height
# and the head give a real interval on the real chain, spanning the whole
# window the snapshot describes.
BPD="NA"; BPS="NA"; BPD_WINDOW="none"
OLDEST=$(awk -F'\t' '$2!="NA"{print $1"\t"$2}' "$TMP/bh.tsv" 2>/dev/null | sort -n | head -1)
if [ -n "$OLDEST" ]; then
  s0=$(printf '%s' "$OLDEST" | cut -f1)
  h0=$(printf '%s' "$OLDEST" | cut -f2)
  BPD=$(awk -v h0="$h0" -v h1="$HEIGHT" -v s0="$s0" -v s1="$SLOT" -v ss="$SLOT_SECS" \
        'BEGIN{ if(s1>s0) printf "%.1f", (h1-h0)/((s1-s0)*ss/86400.0); else print "NA" }')
  BPD_WINDOW="slot ${s0}..${SLOT} height ${h0}..${HEIGHT}"
  BPS=$(awk -v h0="$h0" -v h1="$HEIGHT" -v s0="$s0" -v s1="$SLOT" \
        'BEGIN{ if(s1>s0) printf "%.4f", (h1-h0)/(s1-s0); else print "NA" }')
fi

# ------------------------------------------------------------- emit ---------
NOW=$(date -u +%s)
awk -F'\t' -v OFS='\t' -v g="$GENESIS" -v ss="$SLOT_SECS" -v now="$NOW" '
  $2=="BOXMETA"{ mt[$1]=$4; ma[$1]=$5; ca[$1]=$6; nc[$1]=$7; next }
  $2=="PROC"{ print $1, $3, mt[$1], ma[$1], ca[$1], nc[$1], $5, $4, $7, $8, $9, now-$9, int(($9-g)/ss) }
' "$TMP/raw" > "$TMP/rows"

# join the slot->height map onto the last column, and convert KiB -> MiB
awk -F'\t' -v OFS='\t' '
  NR==FNR { H[$1]=$2; next }
  { bh = ($13 in H) ? H[$13] : "NA"
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.1f\t%.1f\t%s\t%s\t%s\n", \
           $1,$2,$3,$4,$5,$6,$7,$8, $9/1024, $10/1024, $11,$12, bh }
' "$TMP/bh.tsv" "$TMP/rows" | sort -t"$(printf '\t')" -k1,1 -k11,11n > "$TMP/final"

NROWS=$(wc -l < "$TMP/final" | tr -d ' ')
{
  echo "# fleet-memory-observations v1 -- kernel-measured, read-only, regenerate with scripts/fleet-memory-observe.sh"
  echo "# captured_unix	$NOW"
  echo "# captured_utc	$(date -u -r "$NOW" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)"
  echo "# chain_height	$HEIGHT"
  echo "# chain_slot	$SLOT"
  echo "# chain_finalized_height	${FINAL:-NA}"
  echo "# chain_epoch	${EPOCH:-NA}"
  echo "# slot_secs	$SLOT_SECS"
  echo "# genesis_unix	$GENESIS"
  echo "# anchor_error_secs	$(( CAP_HI - CAP_LO ))"
  echo "# blocks_per_day_measured	$BPD"
  echo "# blocks_per_slot_measured	$BPS"
  echo "# slots_per_day	$(( 86400 / SLOT_SECS ))"
  echo "# blocks_per_day_window	$BPD_WINDOW"
  echo "# rpc_source	$RPC_HOST:$RPC_PORT"
  echo "# validator_rows	$NROWS"
  printf '#\n'
  printf 'box_ip\tbox_host\tmem_total_mib\tmem_avail_mib\tcached_mib\tnproc\tunit\tpid\tvmhwm_mib\tvmrss_mib\tstarted_unix\tmark_age_s\tboot_height\n'
  cat "$TMP/final"
} > "$OUT"

NA=$(awk -F'\t' 'NF>=13 && $13=="NA"' "$OUT" | wc -l | tr -d ' ')
echo "fleet-memory-observe: wrote $OUT"
echo "  chain height $HEIGHT slot $SLOT, blocks/day measured $BPD ($BPD_WINDOW)"
echo "  $NROWS validator processes across $(printf '%s\n' "$BOXES" | wc -l | tr -d ' ') boxes, $NA without a boot height"
[ "$NA" -gt 0 ] && [ "$FAST" -eq 0 ] && rc=1
if [ "$rc" -ne 0 ]; then
  echo "fleet-memory-observe: SNAPSHOT IS INCOMPLETE -- do not publish a date from it" >&2
fi
exit $rc
