#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-health.sh — the health check a Bloch Genesis-4 validator alarms on.
# Nagios-style exit codes: 0 OK, 1 WARN, 2 CRIT — wire it to a systemd timer,
# cron+alert, or any monitoring agent that understands exit codes.
#
# ── THE DEFECT THIS TOOL EXISTS TO CLOSE ────────────────────────────────────
#
# `getchaininfo.behind_by_slots` is `wall_slot - slot`: the distance from the
# node's OWN head to wall-clock time. It says nothing about whether that head
# is the network's head. A validator that forks keeps proposing on its own
# branch, so its own head keeps pace with the wall clock and
# `behind_by_slots` reads 0 — forever, while it agrees with nobody. Every
# local metric on a forked node looks perfect: RPC answers, height climbs,
# attestations are produced, finality may even advance on the fork.
#
# On 2026-08-30, 15 fleet nodes sat on one head and 33 sat alone, and every
# one of them was "fine" by its own numbers. Divergence is not observable
# from inside a node. It is only ever observable by comparing this node's
# `block_id` AND `state_root` at the SAME SLOT against independent
# references.
#
# So: this script REFUSES to print OK without at least two independent
# references. `behind_by_slots` is reported as advisory context and is never
# allowed to produce an OK verdict on its own.
#
# ── What it checks ──────────────────────────────────────────────────────────
#
#   liveness    RPC answers. A dead validator leaks stake from the first
#               missed epoch.
#   agreement   THE check. At a common anchor slot, this node's block_id and
#               state_root must equal the reference majority's. Anchored a
#               few slots back from the tip so ordinary propagation lag is
#               not read as a fork.
#   lag         head slot vs the reference majority's head slot. A node that
#               is genuinely behind and a node that is forked are different
#               incidents with different responses; this separates them.
#   finality    the finalized epoch ADVANCES between runs, and the finalized
#               root agrees with the references. Height moving while finality
#               is stuck is exactly what the 2026-08 stalls looked like from
#               one node. Height is the number that is NOT the guarantee.
#   duty        with --index: registry state is `active` and `slashed` is
#               false.
#   exposure    the RPC port is not on a wildcard bind. The RPC has no
#               authentication; a routable bind is an incident, not a config
#               choice (all 64 fleet nodes were exposed on 2026-08-30).
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   blochv-health.sh --reference URL --reference URL [options]
#
#     --rpc URL              this node        (default http://127.0.0.1:16400)
#     --reference URL        independent reference; REPEAT IT. Two minimum.
#                            "Independent" means a different operator, host
#                            and network path. Three nodes you run in one
#                            rack are one reference wearing three hats.
#     --index N              alarm on this validator's registry state
#     --max-behind N         head-slot lag vs references, slots (default 4)
#     --stall-secs N         max age of finality progress (default 3600)
#     --lookback-slots N     anchor N slots behind the shallowest head
#                            (default 4) so tip churn is not read as a fork
#     --state-dir DIR        progress marker (default ~/.cache/blochv-health)
#     --no-reference-i-accept-blindness
#                            run with fewer than two references. Caps the
#                            best possible verdict at WARN and says so, every
#                            run. It does not make the node healthy; it makes
#                            the check honest about not knowing.
#
# Dependencies: curl, python3.

set -u

RPC="http://127.0.0.1:16400"
REFERENCES=()
INDEX=""
MAX_BEHIND=4
STALL_SECS=3600
LOOKBACK=4
STATE_DIR="${HOME}/.cache/blochv-health"
ACCEPT_BLIND=0
MAX_ANCHOR_STEPS=32

while [ $# -gt 0 ]; do
  case "$1" in
    --rpc)             RPC="$2"; shift 2 ;;
    --reference)       REFERENCES+=("$2"); shift 2 ;;
    --index)           INDEX="$2"; shift 2 ;;
    --max-behind)      MAX_BEHIND="$2"; shift 2 ;;
    --stall-secs)      STALL_SECS="$2"; shift 2 ;;
    --lookback-slots)  LOOKBACK="$2"; shift 2 ;;
    --state-dir)       STATE_DIR="$2"; shift 2 ;;
    --no-reference-i-accept-blindness) ACCEPT_BLIND=1; shift ;;
    -h|--help)         sed -n '2,66p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-health: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done

command -v curl    >/dev/null 2>&1 || { echo "CRIT curl not found"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "CRIT python3 not found"; exit 2; }

STATUS=0
raise() { [ "$1" -gt "$STATUS" ] && STATUS="$1"; return 0; }
ok()   { printf 'OK    %s\n' "$*"; }
w()    { printf 'WARN  %s\n' "$*"; raise 1; }
crit() { printf 'CRIT  %s\n' "$*"; raise 2; }

rpc_call() { # rpc_call <url> <method> [params-json]
  curl -sS --max-time 10 -X POST "$1" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" 2>/dev/null
}
jget() { # jget <json> <python-expr over r (the result object)>
  python3 -c '
import json,sys
try:
    r = json.loads(sys.argv[1]).get("result")
    v = eval(sys.argv[2], {"r": r})
    print("" if v is None else v)
except Exception:
    print("")' "$1" "$2" 2>/dev/null
}
jerr() { # jerr <json>  -> JSON-RPC error code, or ""
  python3 -c '
import json,sys
try:
    print(json.loads(sys.argv[1])["error"]["code"])
except Exception:
    print("")' "$1" 2>/dev/null
}

# ── 0. Reference discipline ─────────────────────────────────────────────────
# Enforced BEFORE anything else, because every check below that could return
# OK is meaningless without it.
NREF="${#REFERENCES[@]}"
if [ "$NREF" -lt 2 ]; then
  if [ "$ACCEPT_BLIND" -eq 1 ]; then
    w "references: $NREF (< 2) and --no-reference-i-accept-blindness was passed. \
This run CANNOT certify that the node is on the network's chain; the best \
verdict it can reach is WARN. A forked node reads perfect from inside itself."
    BLIND_CAP=1
  else
    crit "references: $NREF configured, two required. Divergence is invisible \
from inside a node: a forked validator answers RPC, climbs in height, and \
reports behind_by_slots=0 because it is measuring distance to its OWN head. \
Pass --reference twice with independently operated nodes, or acknowledge the \
blindness with --no-reference-i-accept-blindness."
    echo "health: CRIT"
    exit 2
  fi
else
  BLIND_CAP=0
fi

# ── 1. Liveness ─────────────────────────────────────────────────────────────
INFO="$(rpc_call "$RPC" getchaininfo)"
SLOT="$(jget "$INFO" 'r["slot"]')"
if [ -z "$INFO" ] || [ -z "$SLOT" ]; then
  crit "liveness: RPC at $RPC did not answer getchaininfo — a validator that \
is down leaks stake every epoch it misses (inactivity leak), and the leak is \
not refunded"
  echo "health: CRIT"; exit 2
fi
HEIGHT="$(jget "$INFO" 'r["height"]')"
EPOCH="$(jget "$INFO" 'r["epoch"]')"
BEHIND="$(jget "$INFO" 'r["behind_by_slots"]')"
FIN_EPOCH="$(jget "$INFO" 'r["finalized"]["epoch"]')"
FIN_ROOT="$(jget "$INFO" 'r["finalized"]["root"]')"
ok "liveness: RPC answering; head slot $SLOT, height $HEIGHT, epoch $EPOCH"

# behind_by_slots is printed, never trusted. Reported here so an operator who
# has read the header can see the trap with their own eyes.
echo "INFO  advisory: behind_by_slots=$BEHIND (wall_slot - own head slot). \
This is NOT a network-agreement signal: a forked node holds this at 0 while \
agreeing with nobody. The agreement check below is the one that matters."

# ── 2. Agreement at a common anchor slot — THE check ─────────────────────────
# Anchored at a slot a few behind the shallowest head so that ordinary
# propagation lag reads as lag (it is) and not as a fork (it is not). Slots
# with no block answer -32007 ("a missed proposal, not an error") and the
# anchor steps back until every endpoint can answer the same slot.
if [ "$NREF" -eq 0 ]; then
  # Blindness was acknowledged above; do not double-report it as CRIT.
  AGREE_OUT="WARN|agreement: not checked - no references were configured. Whether this node is on the network's chain is UNKNOWN, which is not the same as agreed."
else
# bash 3.2 mis-parses a heredoc nested inside $( ), so the comparison
# program is materialised as a file first. Removed on exit.
AGREE_PY="$(mktemp "${TMPDIR:-/tmp}/blochv-agree.XXXXXX")"
trap 'rm -f "$AGREE_PY"' EXIT INT TERM
cat > "$AGREE_PY" <<'PY'
# Compares this node against independent references at a common anchor slot.
# Emits "LEVEL|message" lines for the shell wrapper to score.
import json, sys, urllib.request

local, lookback, max_steps, max_behind = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])

# Deduplicate while preserving order, and drop the local node if it was also
# listed as a reference. A reference listed twice is one reference, and
# silently treating it as two would inflate the apparent agreement.
refs, seen = [], {local}
for u in sys.argv[5:]:
    if u not in seen:
        seen.add(u)
        refs.append(u)

def emit(level, msg):
    print("%s|%s" % (level, msg))

if len(refs) < len(sys.argv[5:]):
    emit("WARN", "reference list contained duplicates (or the local node); "
                 "%d distinct reference(s) actually used. Two copies of one "
                 "reference is one reference." % len(refs))

def call(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # A plain urllib User-Agent is 403'd by CDN front-ends that sit in front of
    # some public RPC endpoints; identify ourselves so a reference that is up is
    # not misreported as unreachable.
    req = urllib.request.Request(url, data=body, headers={
        "content-type": "application/json",
        "user-agent": "blochv-health/1",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())

heads = {}
for url in [local] + refs:
    try:
        heads[url] = call(url, "getchaininfo", [])["result"]
    except Exception as e:
        if url == local:
            emit("CRIT", "agreement: local node stopped answering mid-check (%s)" % e)
            sys.exit(0)
        emit("WARN", "reference %s unreachable (%s) - it contributes nothing to "
                     "this run's verdict" % (url, e))

live = [u for u in refs if u in heads]
if not live:
    emit("CRIT", "agreement: NO reference answered. This node cannot be "
                 "distinguished from a forked node right now. Treat it as "
                 "unverified, not as healthy.")
    sys.exit(0)

# --- lag, measured against the references rather than the node's own head
ref_head = max(heads[u]["slot"] for u in live)
local_head = heads[local]["slot"]
lag = ref_head - local_head
if lag > max_behind:
    emit("CRIT", "lag: local head slot %d is %d slots behind the furthest reference "
                 "(%d, > %d). Duties computed from a stale head land late or not "
                 "at all." % (local_head, lag, ref_head, max_behind))
elif lag < -max_behind:
    emit("WARN", "lag: local head slot %d is %d slots AHEAD of every reference. "
                 "Either the references are stalled, or this node is building "
                 "blocks nobody else has - read the agreement verdict below "
                 "before assuming the former." % (local_head, -lag))
else:
    emit("OK", "lag: local head slot %d, reference head %d (delta %d, within %d)"
               % (local_head, ref_head, lag, max_behind))

# --- pick the anchor from the LOCAL node only (cheap: one endpoint, and most
#     slots on this chain are empty, so stepping back is normal, not a fault).
anchor = min(heads[u]["slot"] for u in heads) - lookback
if anchor < 0:
    emit("WARN", "agreement: chain too young for a %d-slot lookback" % lookback)
    sys.exit(0)

mine, slot = None, None
for step in range(max_steps):
    s = anchor - step
    if s < 0:
        break
    try:
        r = call(local, "getblockbyslot", {"slot": s})
    except Exception as e:
        emit("CRIT", "agreement: local node failed getblockbyslot(%d): %s" % (s, e))
        sys.exit(0)
    if "error" in r:
        if r["error"].get("code") == -32007:
            continue          # empty slot: a missed proposal, not a fault
        emit("CRIT", "agreement: local node rejected getblockbyslot(%d): %s"
                     % (s, r["error"].get("message", "?")))
        sys.exit(0)
    mine, slot = r["result"], s
    break

if mine is None:
    emit("WARN", "agreement: this node has no block in the %d slots below the "
                 "anchor. Agreement is UNVERIFIED this run - which is not the "
                 "same as agreed." % max_steps)
    sys.exit(0)

def fp(b):
    return (b.get("block_id"), b.get("state_root"), b.get("height"))

# --- ask every reference about that ONE slot
views, absent, failed = {}, [], []
for u in live:
    try:
        r = call(u, "getblockbyslot", {"slot": slot})
    except Exception as e:
        failed.append((u, str(e))); continue
    if "error" in r:
        if r["error"].get("code") == -32007:
            absent.append(u)          # it has no canonical block where we do
        else:
            failed.append((u, r["error"].get("message", "?")))
        continue
    views.setdefault(fp(r["result"]), []).append(u)

for u, msg in failed:
    emit("WARN", "agreement: %s could not answer getblockbyslot(%d): %s" % (u, slot, msg))

if absent:
    emit("CRIT", "DIVERGENCE at slot %d: this node holds canonical block %s.. "
                 "there, but %s report NO canonical block at that slot even "
                 "though their heads are past it. Two chains disagreeing about "
                 "which block is canonical is a fork, not lag."
                 % (slot, mine["block_id"][:16], ", ".join(absent)))

if not views:
    emit("WARN", "agreement: no reference produced a comparable block at slot %d. "
                 "UNVERIFIED this run." % slot)
    sys.exit(0)

best = max(views.values(), key=len)
best_fp = next(k for k, v in views.items() if v is best)
n_answering = sum(len(v) for v in views.values())

if len(views) > 1:
    emit("WARN", "agreement: the references DISAGREE among themselves at slot %d "
                 "(%d distinct views). The network is partitioned; a verdict "
                 "about this node alone is not available. Views: %s"
                 % (slot, len(views),
                    "; ".join("%s..=[%s]" % (k[0][:12], ",".join(v)) for k, v in views.items())))

if fp(mine) == best_fp:
    emit("OK", "agreement: at slot %d (height %s) block_id %s.. and state_root "
               "%s.. match the reference majority (%d/%d)"
               % (slot, mine.get("height"), mine["block_id"][:16],
                  mine["state_root"][:16], len(best), n_answering))
else:
    detail = []
    if mine.get("block_id") != best_fp[0]:
        detail.append("block_id local %s.. vs majority %s.." % (str(mine.get("block_id"))[:16], str(best_fp[0])[:16]))
    if mine.get("state_root") != best_fp[1]:
        detail.append("state_root local %s.. vs majority %s.." % (str(mine.get("state_root"))[:16], str(best_fp[1])[:16]))
    if mine.get("height") != best_fp[2]:
        detail.append("height local %s vs majority %s" % (mine.get("height"), best_fp[2]))
    emit("CRIT", "DIVERGENCE at slot %d: this node does NOT agree with the "
                 "reference majority (%d/%d). %s. This node is on a fork. Its "
                 "reads are wrong, its attestations are worthless, and every "
                 "local metric will keep reporting it healthy. Do not restart "
                 "blindly and do NOT move the key to a second machine while "
                 "investigating - find the slot where the chains split first."
                 % (slot, len(best), n_answering, "; ".join(detail)))

# --- finalized root cross-check, independent of the anchor
lf = heads[local].get("finalized") or {}
for u in live:
    rf = heads[u].get("finalized") or {}
    if rf.get("epoch") == lf.get("epoch") and rf.get("root") != lf.get("root"):
        emit("CRIT", "FINALITY DIVERGENCE: at finalized epoch %s this node's root "
                     "%s.. differs from %s's %s... Two conflicting finalized roots "
                     "at one epoch is a safety failure, not a lag problem."
                     % (lf.get("epoch"), str(lf.get("root"))[:16], u,
                        str(rf.get("root"))[:16]))
PY
AGREE_OUT="$(python3 "$AGREE_PY" "$RPC" "$LOOKBACK" "$MAX_ANCHOR_STEPS" "$MAX_BEHIND" "${REFERENCES[@]}")"

fi

if [ -n "$AGREE_OUT" ]; then
  while IFS='|' read -r LVL MSG; do
    [ -z "$LVL" ] && continue
    case "$LVL" in
      OK)   ok   "$MSG" ;;
      WARN) w    "$MSG" ;;
      CRIT) crit "$MSG" ;;
      *)    echo "$LVL|$MSG" ;;
    esac
  done <<< "$AGREE_OUT"
else
  crit "agreement: the comparison could not run at all (python3 error) — treat this node as unverified"
fi

# ── 3. Finality progress (stall detector across runs) ───────────────────────
mkdir -p "$STATE_DIR" 2>/dev/null
MARK="$STATE_DIR/finalized_epoch"
NOW="$(date +%s)"
LAST_EPOCH=""; LAST_TS="$NOW"
[ -f "$MARK" ] && read -r LAST_EPOCH LAST_TS < "$MARK"
: "${LAST_TS:=$NOW}"
if [ -z "$LAST_EPOCH" ] || [ "${FIN_EPOCH:-0}" -gt "$LAST_EPOCH" ] 2>/dev/null; then
  echo "$FIN_EPOCH $NOW" > "$MARK"
  ok "finality: finalized epoch $FIN_EPOCH (advancing)"
else
  AGE=$(( NOW - LAST_TS ))
  if [ "$AGE" -gt "$STALL_SECS" ]; then
    crit "finality: finalized epoch stuck at $FIN_EPOCH for ${AGE}s (> ${STALL_SECS}s). \
Height climbing while finality does not is what the 2026-08 stalls looked like \
from a single node: blocks arrive, settlement does not. Height is not the guarantee."
  else
    ok "finality: finalized epoch $FIN_EPOCH (unchanged ${AGE}s, within ${STALL_SECS}s)"
  fi
fi

# ── 4. This validator's registry state ──────────────────────────────────────
# Field names verified against a live Genesis-4 node on 2026-08-31:
# getvalidator returns `state` (NOT `status`) and a separate `slashed` bool.
if [ -n "$INDEX" ]; then
  VAL="$(rpc_call "$RPC" getvalidator "{\"index\":$INDEX}")"
  VSTATE="$(jget "$VAL" 'r["state"]')"
  VSLASHED="$(jget "$VAL" 'r["slashed"]')"
  if [ "$VSLASHED" = "True" ] || [ "$VSLASHED" = "true" ]; then
    crit "validator $INDEX: SLASHED. Stop the node NOW. It cannot un-slash, and \
correlation pricing (3x over the surrounding 4,096-epoch window) means every \
further offence in the window costs you and everyone else caught in it more. \
NOTE: no slashing has ever been applied on this chain and none can be today \
(see VALIDATOR-RUNBOOK 14.1) - so this flag reading true means the state or \
the binary changed, and that is itself worth investigating."
  fi
  case "$VSTATE" in
    active)  ok "validator $INDEX: active" ;;
    queued|pending)
             w  "validator $INDEX: $VSTATE — not doing duties yet (activation \
queue admits 4 per epoch after an 8-epoch delay)" ;;
    exiting) w  "validator $INDEX: exiting — duties stop at exit_epoch. Expected \
ONLY if you submitted the exit yourself; if you did not, your key signed \
something you did not authorise." ;;
    exited)  w  "validator $INDEX: exited — withdrawable after the 2,048-epoch \
(~22.8 day) delay" ;;
    slashed) crit "validator $INDEX: SLASHED — stop the node now" ;;
    "")      crit "validator $INDEX: getvalidator returned no state. Wrong index, \
or the node is not answering properly. A validator that cannot identify itself \
does no duties." ;;
    *)       w  "validator $INDEX: unrecognised state '$VSTATE'" ;;
  esac
fi

# ── 5. RPC exposure ─────────────────────────────────────────────────────────
case "$RPC" in
  *127.0.0.1*|*localhost*|*"[::1]"*)
    RPC_PORT="$(printf '%s' "$RPC" | sed -n 's/.*:\([0-9][0-9]*\).*/\1/p')"
    if [ -n "$RPC_PORT" ] && command -v ss >/dev/null 2>&1; then
      if ss -ltn 2>/dev/null | awk '{print $4}' \
           | grep -E "^(0\.0\.0\.0|\*|\[::\]):${RPC_PORT}\$" >/dev/null; then
        crit "exposure: RPC port $RPC_PORT is listening on a WILDCARD address. \
The RPC has no authentication, no rate limit and no per-method authorisation, \
and sendrawtransaction is a write. This is a live incident, not a configuration \
style. Rebind to 127.0.0.1 (--rpc-bind 127.0.0.1)."
      else
        ok "exposure: RPC port $RPC_PORT is not on a wildcard bind"
      fi
    fi
    ;;
esac

# ── Verdict ─────────────────────────────────────────────────────────────────
if [ "${BLIND_CAP:-0}" -eq 1 ] && [ "$STATUS" -lt 1 ]; then
  STATUS=1
  echo "WARN  verdict capped at WARN: fewer than two references were configured, \
so 'agreed with the network' was never established this run."
fi
case "$STATUS" in
  0) echo "health: OK" ;;
  1) echo "health: WARN" ;;
  2) echo "health: CRIT" ;;
esac
exit "$STATUS"
