#!/usr/bin/env bash
# derive-peers.sh — peer lists are DERIVED, never pinned.
#
# The design principle this implements (from bootnodes-20260831/derive-upstreams.sh,
# generalised from the observer tier to the whole fleet):
#
#   PUBLIC list  = only addresses WE CONTROL AND EXPECT TO KEEP.
#                  Today that is the observer/archival tier on :19100 — hosts
#                  whose whole job is to have a stable address. No validator
#                  address is ever published: validators move, and a published
#                  address that moves is a support burden and a fingerprint.
#
#   PRIVATE list = DERIVED by enumerating ACTIVE units across the fleet.
#                  Never copied from a previous list, never read from a file,
#                  never typed. If a validator was decommissioned this morning,
#                  it is out of the list this afternoon without anyone
#                  remembering to remove it. That is the whole fix: a list
#                  nobody maintains cannot rot.
#
# Everything here is read-only. It PRINTS lists and drop-ins; it installs
# nothing. Installation is the rollout's job, under batch discipline.
#
# Usage:
#   derive-peers.sh private [--for HOST:PORT]   fleet dial list (minus self)
#   derive-peers.sh public                      publishable bootstrap list
#   derive-peers.sh check                       running vs derived, per unit
#   derive-peers.sh dropin <unit> <host>        a systemd drop-in for one unit
#   [--reuse DIR] to analyse an inventory already collected
#
# Exit: 0 agreement / list printed; 1 drift found (check); 2 undetermined.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${REFINT_CONF:-$HERE/reference-integrity.conf}"
MODE="${1:-}"; shift || true
FOR=""; REUSE=""; UNIT=""; UHOST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --for) FOR="$2"; shift 2;;
    --reuse) REUSE="$2"; shift 2;;
    -c) CONF="$2"; shift 2;;
    *) if [ -z "$UNIT" ]; then UNIT="$1"; else UHOST="$1"; fi; shift;;
  esac
done
[ -f "$CONF" ] || { echo "REFUSED: missing conf $CONF" >&2; exit 2; }
# shellcheck disable=SC1090
. "$CONF"
: "${STATE_DIR:=$HOME/.bloch-reference-integrity}" "${OBSERVER_LISTEN:=19100}"

if [ -n "$REUSE" ]; then INV="$REUSE"
else INV=$(REFINT_WORK="$STATE_DIR" "$HERE/inventory.sh" -c "$CONF") || { echo "REFUSED: inventory failed" >&2; exit 2; }
fi
# A derived list is only as good as the view it was derived from. A partial
# inventory would quietly DROP every validator on an unreachable box — exactly
# the silent amputation this tool exists to prevent.
[ -f "$INV/PARTIAL" ] && { echo "REFUSED: partial inventory ($(tr '\n' ' ' < "$INV/unreachable.txt") unreachable). A derived list built from a partial view amputates whole hosts; nothing derived here may be installed." >&2; exit 2; }

# SCOPE. Default 'validators': the set a unit should dial is the active
# validators, which is what every unit already carries today. That makes the
# cleanup a pure DELETION — the derived list is a subset of the configured one —
# and a pure deletion is trivially reversible. PEER_SCOPE=all additionally dials
# the observers; that ADDS endpoints, so it is a topology change and must be
# decided deliberately, not inherited from a default.
: "${PEER_SCOPE:=validators}"
case "$PEER_SCOPE" in
  validators) LIVE_FILE="$INV/live-validators.txt";;
  all)        LIVE_FILE="$INV/live-endpoints.txt";;
  *) echo "REFUSED: PEER_SCOPE must be 'validators' or 'all'" >&2; exit 2;;
esac
live()      { grep -v '^$' "$LIVE_FILE" | sort -u; }
all_live()  { grep -v '^$' "$INV/live-endpoints.txt" | sort -u; }
observers() { awk -F'\t' '$3=="observer" && $5=="active" {print $2":"$9}' "$INV/nodes.tsv" | sort -u; }
validators(){ awk -F'\t' '$3=="validator" && $5=="active" {print $2":"$9}' "$INV/nodes.tsv" | sort -u; }

case "$MODE" in
  private)
    # Ordered host-major so the string is stable across runs: an unstable
    # ordering makes every diff look like drift and trains people to ignore it.
    if [ -n "$FOR" ]; then live | grep -vxF "$FOR" | paste -sd, -
    else live | paste -sd, -; fi
    ;;

  public)
    echo "# Genesis-4 public bootstrap endpoints — derived $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# ONLY addresses we control and expect to keep. No validator is listed:"
    echo "# validators move; observers exist precisely so that they do not."
    n=0
    for e in $(observers); do echo "$e"; n=$((n+1)); done
    echo "# $n observer endpoint(s). Validators discovered but deliberately withheld: $(validators | wc -l | tr -d ' ')"
    [ "$n" -ge 1 ] || { echo "# REFUSED: no observer is live — publishing an empty bootstrap list would strand every new node" >&2; exit 2; }
    ;;

  check)
    # Per unit: what it dials vs what it should, computed fresh both times.
    L=$(live); TOTAL=$(printf '%s\n' "$L" | wc -l | tr -d ' ')
    echo "# scope=$PEER_SCOPE — a unit should dial $TOTAL endpoint(s) (minus itself)"
    drift=0
    while IFS=$'\t' read -r idx host role unit active enabled bin dd listen rpcp bind; do
      [ "$active" = active ] || continue
      self="$host:$listen"
      want=$(printf '%s\n' "$L" | grep -vxF "$self")
      have=$(awk -F'\t' -v h="$host" -v u="$unit" '$1==h && $2==u {print $3}' "$INV/peers.tsv" | sort -u)
      dead=$(comm -23 <(printf '%s\n' "$have") <(all_live))
      miss=$(comm -13 <(printf '%s\n' "$have") <(printf '%s\n' "$want"))
      nd=$(printf '%s' "$dead" | grep -c . ); nm=$(printf '%s' "$miss" | grep -c . )
      if [ "$nd" -gt 0 ] || [ "$nm" -gt 0 ]; then
        drift=$((drift+1))
        echo "DRIFT $host/$unit  dead=$nd missing=$nm  (dials $(printf '%s' "$have" | grep -c .), should dial $((TOTAL-1)))"
        [ "$nd" -gt 0 ] && echo "   dead:    $(printf '%s' "$dead" | tr '\n' ' ' | cut -c1-160)..."
        [ "$nm" -gt 0 ] && echo "   missing: $(printf '%s' "$miss" | tr '\n' ' ' | cut -c1-160)"
      fi
    done < <(grep -v '^#' "$INV/nodes.tsv")
    echo
    if [ "$drift" = 0 ]; then echo "OK: every active unit's --peers equals the derived live set ($TOTAL endpoints, scope=$PEER_SCOPE)."; exit 0
    else echo "DRIFT: $drift unit(s) disagree with the derived live set ($TOTAL endpoints). Fix with cleanup-references.sh — never by hand."; exit 1; fi
    ;;

  dropin)
    [ -n "$UNIT" ] && [ -n "$UHOST" ] || { echo "usage: $0 dropin <unit> <host>" >&2; exit 2; }
    row=$(awk -F'\t' -v h="$UHOST" -v u="$UNIT" '$2==h && $4==u' "$INV/nodes.tsv")
    [ -n "$row" ] || { echo "REFUSED: $UHOST/$UNIT is not in the inventory" >&2; exit 2; }
    listen=$(printf '%s' "$row" | cut -f9)
    P=$(live | grep -vxF "$UHOST:$listen" | paste -sd, -)
    echo "# /etc/systemd/system/$UNIT.service.d/peers.conf   (derived $(date -u +%FT%TZ) from $INV)"
    echo "# A drop-in, not an edit: reverting is 'rm this file + daemon-reload',"
    echo "# and the original ExecStart is never touched."
    echo "[Service]"
    echo "Environment=BLOCH_PEERS=$P"
    echo "# NOTE: the fleet's units hard-code --peers in ExecStart, so a drop-in"
    echo "# cannot override it without also restating ExecStart. Prefer the"
    echo "# rollout's PEERS_LIMPAR=1 rewrite, which stages a full unit and keeps"
    echo "# the pre-roll copy for REVERTER. This output is for observers/archival"
    echo "# hosts, which are rolled one at a time and hold no key."
    ;;

  *) sed -n '2,40p' "$0"; exit 2;;
esac
