#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# fleet-gate-sweep.sh — "is the fleet ready for this flag day?"
#
# Asks every node's binary which consensus flag days it was built knowing
# (`bloch-pos selfcheck --json`), groups the fleet by `gates_digest`, and
# reports disagreement. Run it BEFORE arming an activation epoch.
#
# WHY THIS EXISTS
#   The two archival nodes behind the public RPC quorum and the 60-odd
#   validators do not run the same binary — archivals were on
#   `bloch-pos-quatro` while the fleet moved to `bloch-pos-cinco`. Before this
#   tool there was no way to ask a binary which gates it knows: `selfcheck`
#   answered `self-check passed` and nothing else, and silently ignored
#   `--json`. So "will the archivals follow this flag day or fork?" was
#   unanswerable, and the honest answer to "is the fleet ready?" was a guess.
#
#   That guess is what killed `genesis4-node-20260814`: it predated every
#   armed flag day, diverged on schedule, and its release page said nothing.
#
# WHAT COUNTS AS COMPATIBLE
#   Two binaries are consensus-compatible AT EPOCH E if and only if their gate
#   lists agree on every gate with activation epoch <= E. Gates armed beyond E
#   (or inert) cannot make them disagree yet — but they WILL, on their own
#   flag day, which is why the full-set digest is reported too.
#
#   Equal `gates_digest`  => compatible at every epoch, now and later.
#   Different digest      => compatible only up to the first gate they differ
#                            on. `--epoch E` computes exactly that.
#
# READ-ONLY. This tool runs one command per host — the binary's own
# `selfcheck`, which opens no data directory, binds no port, and touches no
# state. It never restarts a service, never copies a file, never writes.
# It cannot arm anything.
#
# USAGE
#   scripts/fleet-gate-sweep.sh [--hosts FILE] [--epoch E]
#                               [--reference HOST|--reference-json FILE]
#                               [--jobs N] [--timeout SECS] [--json]
#
#   --hosts FILE       host table (default: scripts/fleet-gates.tsv)
#   --epoch E          the flag day you are about to arm. Verdict is computed
#                      against gates with epoch <= E only.
#   --reference HOST   the host whose gate list is canonical (default: the
#                      first row of the table marked `ref` in the role column,
#                      else the first row).
#   --reference-json F a local `bloch-pos selfcheck --json` dump to compare the
#                      fleet against — use the binary you are ABOUT TO ship.
#   --jobs N           parallel ssh probes (default 8).
#   --timeout SECS     per-host ssh timeout (default 20).
#   --json             machine-readable report on stdout.
#
# HOST TABLE FORMAT (tab-separated; `#` comments and blank lines ignored)
#   label <TAB> host <TAB> ssh_key_basename <TAB> binary_path <TAB> role
#   role is free text; `ref` marks the default reference node.
#
# EXIT STATUS
#   0  every probed host agrees with the reference (through --epoch if given)
#   1  disagreement, or a host whose binary cannot state its gates
#   2  usage / setup error
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOSTS_FILE="$REPO_ROOT/scripts/fleet-gates.tsv"
SSH_DIR="$HOME/.ssh"
SSH_USER="ubuntu"
EPOCH=""
REF_HOST=""
REF_JSON=""
JOBS=8
TIMEOUT=20
OUT_JSON=0

die() { echo "fleet-gate-sweep: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --hosts)          HOSTS_FILE="${2:-}"; shift 2 ;;
    --epoch)          EPOCH="${2:-}"; shift 2 ;;
    --reference)      REF_HOST="${2:-}"; shift 2 ;;
    --reference-json) REF_JSON="${2:-}"; shift 2 ;;
    --jobs)           JOBS="${2:-}"; shift 2 ;;
    --timeout)        TIMEOUT="${2:-}"; shift 2 ;;
    --json)           OUT_JSON=1; shift ;;
    -h|--help)        sed -n '2,60p' "$0"; exit 0 ;;
    *)                die "unknown argument \`$1\` (see --help)" ;;
  esac
done

[ -f "$HOSTS_FILE" ] || die "host table not found: $HOSTS_FILE"
case "$EPOCH" in ''|*[!0-9]*) [ -z "$EPOCH" ] || die "--epoch must be a number" ;; esac
[ -z "$REF_JSON" ] || [ -f "$REF_JSON" ] || die "--reference-json not found: $REF_JSON"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gate-sweep.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ── Probe one host ───────────────────────────────────────────────────────────
# Writes $WORK/<label>.out (raw stdout) and $WORK/<label>.meta (label,host,bin).
# Deliberately captures stdout VERBATIM: a binary that predates `--json` prints
# `self-check passed` and exits 0, and that non-answer is a finding, not an
# error. Reporting it as "cannot state its gates" is the entire point.
probe() {
  local label="$1" host="$2" key="$3" bin="$4"
  local keypath="$SSH_DIR/$key"
  if [ ! -f "$keypath" ]; then
    printf 'SWEEP-ERROR: ssh key %s not found\n' "$keypath" > "$WORK/$label.out"
    return
  fi
  timeout "$((TIMEOUT + 5))" ssh \
      -i "$keypath" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout="$TIMEOUT" \
      "$SSH_USER@$host" \
      "'$bin' selfcheck --json 2>&1" \
      > "$WORK/$label.out" 2>"$WORK/$label.err"
  local rc=$?
  if [ $rc -ne 0 ] && [ ! -s "$WORK/$label.out" ]; then
    { printf 'SWEEP-ERROR: ssh/selfcheck failed (rc=%d)\n' "$rc"
      head -3 "$WORK/$label.err" 2>/dev/null; } > "$WORK/$label.out"
  fi
}

# ── Fan out ──────────────────────────────────────────────────────────────────
# Runs of tabs are squeezed first: the table is tab-ALIGNED by hand for the
# person who has to read it at 3am, and `IFS=$'\t' read` would otherwise take
# the padding as empty columns and shift every field left — silently probing
# the wrong binary path, which is the one mistake this tool must never make.
NORM="$WORK/hosts.norm"
grep -v $'^[[:space:]]*#' "$HOSTS_FILE" | grep -v '^[[:space:]]*$' \
  | tr -s '\t' '\t' > "$NORM"

n=0
while IFS=$'\t' read -r label host key bin role; do
  [ -n "${label:-}" ] || continue
  [ -n "${bin:-}" ] || die "malformed row for \`${label}\` in $HOSTS_FILE \
(need: label<TAB>host<TAB>ssh_key<TAB>binary_path[<TAB>role])"
  probe "$label" "$host" "$key" "$bin" &
  n=$((n + 1))
  if [ $((n % JOBS)) -eq 0 ]; then wait; fi
done < "$NORM"
wait

[ "$n" -gt 0 ] || die "host table $HOSTS_FILE has no usable rows"

# ── Report ───────────────────────────────────────────────────────────────────
WORK="$WORK" HOSTS_FILE="$HOSTS_FILE" EPOCH="$EPOCH" REF_HOST="$REF_HOST" \
REF_JSON="$REF_JSON" OUT_JSON="$OUT_JSON" python3 "$REPO_ROOT/scripts/fleet-gate-sweep.py"
