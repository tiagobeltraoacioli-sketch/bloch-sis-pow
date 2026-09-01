#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Run `devnet-fratura.sh` R times CONCURRENTLY on distinct port bases and print
# one line per run: converged, or the first slot at which two nodes applied
# different blocks.
#
# Concurrent rather than sequential because the thing being measured is a RATE
# — a single devnet run that stays on one chain proves nothing about a
# transport that fractures one run in two — and a rate needs repeats within a
# session, not across days. Each run costs about 3% of one core, so ten of them
# still leave an idle box idle; the verdict prints the load it ran under so a
# reader can tell whether that stayed true.
#
#   usage: devnet-fratura-repete.sh <root> <repeats> <n> <slot_ms> <stop_at> <tag>
#   env:   everything devnet-fratura.sh reads (TRANSPORT, DECLARED, ...) plus
#          whatever the node itself reads from the environment.
set -uo pipefail
PORT_OFFSET="${PORT_OFFSET:-0}"
ROOT="${1:?root}"; R="${2:-4}"; N="${3:-3}"; SLOT_MS="${4:-1000}"; STOP="${5:-600}"; TAG="${6:-rep}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT"
pids=()
for r in $(seq 1 "$R"); do
  BASE_PORT=$(( 20000 + PORT_OFFSET + r * 20 )) RPC_BASE=$(( 40000 + PORT_OFFSET + r * 20 )) \
    bash "$HERE/devnet-fratura.sh" "$ROOT/r$r" "$N" "$SLOT_MS" "$STOP" "$TAG" \
    > "$ROOT/r$r.out" 2>&1 &
  pids+=("$!")
done
echo "$TAG: $R concurrent runs, load at start: $(uptime | sed 's/.*load/load/')"
wait "${pids[@]}" 2>/dev/null
echo "$TAG: done, load at end: $(uptime | sed 's/.*load/load/')"
for r in $(seq 1 "$R"); do
  printf '%s run %s: ' "$TAG" "$r"
  # "0 conflicting slots" is also what an empty run prints, and a run whose
  # nodes never bound their ports is not a converged run — that false pass cost
  # an arm of this very investigation. Report the height first, and let a zero
  # there say NO DATA out loud.
  v=$(python3 "$HERE/devnet-fratura-veredito.py" "$ROOT/r$r" 2>/dev/null)
  h=$(printf '%s' "$v" | sed -n 's/^node0 *\([0-9]*\).*/\1/p')
  if [ -z "$h" ] || [ "$h" = "0" ]; then
    printf 'NO DATA (node0 built no chain — check %s/r%s/node0/*.log)\n' "$ROOT" "$r"
  else
    printf 'height %s, conflicts: %s\n' "$h" \
      "$(printf '%s' "$v" | sed -n 's/^slots where two nodes hold DIFFERENT blocks: \(.*\)$/\1/p')"
  fi
done
