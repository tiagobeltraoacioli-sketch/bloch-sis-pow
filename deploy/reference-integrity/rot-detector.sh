#!/usr/bin/env bash
# rot-detector.sh — makes reference rot LOUD.
#
# Reference rot is the failure mode of 2026-08-31: a port or a peer address
# written down once, pointing at a node that has since moved or died, with
# nobody owning the reference and nothing checking it. The devnet transport
# retries dead peers forever without logging an error, so rot presents as
# latency and finality drag, never as a failure — which is why it survived
# long enough to break four systems in one day.
#
# This runs unattended (systemd timer or cron). It is read-only. It prints ONE
# human-readable verdict line and exits non-zero when anything has rotted, so
# cron mails it, the timer marks the unit failed, and nobody has to read a log.
#
# Classes checked, all against the DISCOVERED inventory, never a stored list:
#   PEER-ROT       peers configured in a unit that match no live endpoint
#   PEER-GAP       live endpoints missing from a unit's peer list
#   FORWARD-ROT    socat forwarders whose 127.0.0.1:P has no owner on that box,
#                  or that no longer carry a getchaininfo through
#   PROXY-ROT      public proxy upstreams that disagree with the fleet
#   CONSENSUS      head/finality divergence and stragglers (rot's usual symptom)
#   STRUCTURE      anomalies from the inventory: double-sign risk, orphan RPCs
#                  and processes, invisible nodes, units whose name lies
#
# Exit codes:  0 clean   1 rot found   2 could not determine (ssh/partial)
#
# Usage: rot-detector.sh [-c CONF] [--quiet] [--reuse DIR] [--json]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${REFINT_CONF:-$HERE/reference-integrity.conf}"
QUIET=0; REUSE=""; JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -c) CONF="$2"; shift 2;;
    --quiet) QUIET=1; shift;;
    --reuse) REUSE="$2"; shift 2;;
    --json) JSON=1; shift;;
    *) echo "usage: $0 [-c CONF] [--quiet] [--reuse DIR] [--json]" >&2; exit 2;;
  esac
done
[ -f "$CONF" ] || { echo "ROT-DETECTOR: UNDETERMINED — missing conf $CONF"; exit 2; }
# shellcheck disable=SC1090
. "$CONF"
: "${BEHIND_OK:=4}" "${DEAD_PEER_FAIL:=1}" "${MIN_LIVE_FRACTION:=95}"
: "${PROXY_JS:=}" "${PROXY_URL:=}" "${STATE_DIR:=$HOME/.bloch-reference-integrity}"

note() { [ "$QUIET" = 1 ] || echo "$*"; }

mkdir -p "$STATE_DIR" 2>/dev/null
if [ -n "$REUSE" ]; then INV="$REUSE"
else
  INV=$(REFINT_WORK="$STATE_DIR" "$HERE/inventory.sh" -c "$CONF" 2>"$STATE_DIR/.last-inventory.err") || {
    echo "ROT-DETECTOR: UNDETERMINED — inventory failed ($(tail -1 "$STATE_DIR/.last-inventory.err" 2>/dev/null))"; exit 2; }
fi
[ -s "$INV/nodes.tsv" ] || { echo "ROT-DETECTOR: UNDETERMINED — empty inventory at $INV"; exit 2; }

# A partial view cannot prove absence: an endpoint looks "dead" only because we
# could not reach the box that hosts it. Refuse rather than report false rot.
if [ -f "$INV/PARTIAL" ]; then
  echo "ROT-DETECTOR: UNDETERMINED — unreachable hosts ($(tr '\n' ' ' < "$INV/unreachable.txt")); a partial inventory cannot distinguish a dead peer from an unreachable one"
  exit 2
fi

# The public proxy's upstream list is source code on the Mac, not state on a
# box, so it is read here and handed to the analyser.
PROXY_LIST=""
[ -n "$PROXY_JS" ] && [ -f "$PROXY_JS" ] && \
  PROXY_LIST=$(grep -oE "'https?://[^']+'" "$PROXY_JS" | tr -d "'" | sort -u)

# End-to-end: does the public URL still answer at all? (three tries; one lost
# read is not a defect — 2026-08-31 produced a false alarm exactly that way)
PROXY_E2E="skipped"
if [ -n "$PROXY_URL" ]; then
  for _ in 1 2 3; do
    b=$(curl -s --max-time 10 -X POST "$PROXY_URL" -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' 2>/dev/null)
    [ -n "$b" ] && { PROXY_E2E="$b"; break; }
    sleep 3
  done
  [ "$PROXY_E2E" = "skipped" ] && PROXY_E2E=""
fi
printf '%s' "${PROXY_E2E:-}" > "$INV/proxy-e2e.raw"
# Each configured upstream, independently.
UP_RESULT=""
for u in $PROXY_LIST; do
  s=""
  for _ in 1 2; do
    s=$(curl -s --max-time 10 -X POST "$u" -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}' 2>/dev/null)
    [ -n "$s" ] && break; sleep 2
  done
  UP_RESULT="$UP_RESULT$u	${s:-NORESP}"$'\n'
done

printf '%s' "$UP_RESULT" > "$INV/proxy-upstreams.raw"

python3 - "$INV" "$BEHIND_OK" "$DEAD_PEER_FAIL" "$MIN_LIVE_FRACTION" "$QUIET" "$JSON" "${PROXY_URL:-}" "${PEER_SCOPE:-validators}" <<'PY'
import sys, os, json, collections
inv, behind_ok, dead_fail, min_frac, quiet, as_json, proxy_url, scope = sys.argv[1:9]
behind_ok, dead_fail, min_frac, quiet, as_json = int(behind_ok), int(dead_fail), int(min_frac), int(quiet), int(as_json)

def tsv(name):
    p = os.path.join(inv, name)
    if not os.path.exists(p): return []
    rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip() and not l.startswith("#")]
    return rows

nodes = tsv("nodes.tsv"); peers = tsv("peers.tsv"); fwd = tsv("forwarders.tsv"); rpc = tsv("rpc.tsv")
# `live` answers "does this endpoint exist?" — always the full set, because an
# observer's endpoint is not dead just because validators are not asked to dial it.
live = set(l.strip() for l in open(os.path.join(inv, "live-endpoints.txt")) if l.strip())
# `should` answers "what ought this unit dial?" — the scoped set. See PEER_SCOPE.
_sf = os.path.join(inv, "live-validators.txt" if scope == "validators" else "live-endpoints.txt")
should = set(l.strip() for l in open(_sf) if l.strip()) if os.path.exists(_sf) else set(live)
findings = collections.defaultdict(list)   # class -> [line]
def rot(cls, line): findings[cls].append(line)

# ── PEER-ROT / PEER-GAP ───────────────────────────────────────────────────
# Derived truth, not a stored list: `live` is exactly the set of endpoints that
# an ACTIVE unit is currently listening on. Anything a unit dials that is not
# in that set is a dial into the past.
by_unit = collections.defaultdict(list)
for h, u, p in peers: by_unit[(h, u)].append(p)
dead_total = 0; dead_ep = collections.Counter(); units_rotten = 0; gap_units = 0
for (h, u), ps in sorted(by_unit.items()):
    dead = [p for p in ps if p not in live]
    self_ep = None
    for n in nodes:
        if n[1] == h and n[3] == u: self_ep = f"{n[1]}:{n[8]}"
    want = should - ({self_ep} if self_ep else set())
    missing = want - set(ps)
    if dead:
        dead_total += len(dead); units_rotten += 1
        for p in dead: dead_ep[p] += 1
    if missing:
        gap_units += 1
        have = len(want & set(ps))
        if want and have * 100 // len(want) < min_frac:
            rot("PEER-GAP", f"{h}/{u} carries only {have}/{len(want)} live endpoints "
                            f"(missing {len(missing)}, e.g. {sorted(missing)[:3]})")
if dead_total >= dead_fail:
    ips = sorted({e.rsplit(':', 1)[0] for e in dead_ep})
    rot("PEER-ROT", f"{dead_total} dead dial entries across {units_rotten} units — "
                    f"{len(dead_ep)} distinct dead endpoints on {len(ips)} hosts: {', '.join(ips)}")
    for e, c in dead_ep.most_common(8):
        rot("PEER-ROT", f"  {e} dialled by {c} units, listening on nothing")
    if len(dead_ep) > 8: rot("PEER-ROT", f"  ... and {len(dead_ep)-8} more dead endpoints")

# ── FORWARD-ROT ───────────────────────────────────────────────────────────
# A forwarder is a static reference by construction: socat holds a port number.
# It is correct only while a node that LIVES ON THAT BOX answers on it.
for h, u, lp, tp, owner, state in fwd:
    if state != "active":
        rot("FORWARD-ROT", f"{h}/{u} is '{state}' — socat does not survive on its own, the unit must be active")
    if owner == "NONE":
        rot("FORWARD-ROT", f"{h}/{u} forwards :{lp} -> 127.0.0.1:{tp} and NO active node on {h} serves that port")
answering = {(r[0], r[1]): r for r in rpc if len(r) > 2 and r[2] not in ("NORESP", "")}
for h, u, lp, tp, owner, state in fwd:
    if owner != "NONE" and (h, tp) not in answering:
        rot("FORWARD-ROT", f"{h}/{u} target 127.0.0.1:{tp} ({owner}) did not answer getchaininfo")

# ── CONSENSUS (rot's symptom, not its cause) ──────────────────────────────
slots = sorted(int(r[2]) for r in rpc if len(r) > 2 and r[2].isdigit())
fins = collections.Counter(r[4] for r in rpc if len(r) > 4 and r[4])
median = slots[len(slots)//2] if slots else None
# Head divergence is only meaningful AT THE SAME SLOT. This sweep takes minutes
# and slots are 30 s, so a naive "how many distinct heads" count reports a fork
# on a perfectly converged fleet — it did, on the first run: 3 heads that turned
# out to be 3 consecutive slots, one head each. Compare within a slot only.
per_slot = collections.defaultdict(collections.Counter)
for r in rpc:
    if len(r) > 5 and r[2].isdigit() and r[5]: per_slot[int(r[2])][r[5]] += 1
for sl, hc in sorted(per_slot.items()):
    if len(hc) > 1:
        rot("CONSENSUS", f"slot {sl}: {len(hc)} distinct heads among nodes reading the SAME slot — "
            + ", ".join(f"{k}×{v}" for k, v in hc.most_common(4)) + " (a real fork, not sweep skew)")
# Finalized height is monotone and slot-insensitive: disagreement here is the
# reliable fork signal, and a node below the others is the reliable straggler.
if len(fins) > 1:
    rot("CONSENSUS", f"{len(fins)} distinct finalized heights: " + ", ".join(f"{k}×{v}" for k, v in fins.most_common(4)))
late = [(r[0], r[1], median - int(r[2])) for r in rpc if len(r) > 2 and r[2].isdigit() and median - int(r[2]) > behind_ok]
for h, p, d in late:
    rot("CONSENSUS", f"{h}:{p} is {d} slots behind the fleet median ({median}) — the usual first sign of a rotted peer set")
for r in rpc:
    if len(r) > 2 and r[2] == "NORESP":
        rot("CONSENSUS", f"{r[0]}:{r[1]} listens but does not answer getchaininfo")

# ── PROXY-ROT ─────────────────────────────────────────────────────────────
# The upstream list is the one static list we keep on purpose (it must name
# only hosts we own). Rot here = it names a host the fleet no longer uses, or
# omits one it does.
owned = {n[1] for n in nodes}
up_raw = os.path.join(inv, "proxy-upstreams.raw")
ups = []
if os.path.exists(up_raw):
    for l in open(up_raw):
        if not l.strip(): continue
        u, body = l.rstrip("\n").split("\t", 1)
        ups.append((u, body))
seen_hosts = set()
for u, body in ups:
    hostpart = u.split("//", 1)[-1].split("/")[0].split(":")[0].replace(".nip.io", "")
    seen_hosts.add(hostpart)
    if hostpart not in owned:
        rot("PROXY-ROT", f"upstream {u} names {hostpart}, which hosts NO node in the inventory")
    if body == "NORESP":
        rot("PROXY-ROT", f"upstream {u} did not answer getchaininfo")
    else:
        try:
            s = json.loads(body)["result"].get("slot")
            if median and isinstance(s, int) and median - s > behind_ok:
                rot("PROXY-ROT", f"upstream {u} is {median - s} slots behind the fleet")
        except Exception:
            rot("PROXY-ROT", f"upstream {u} returned unparseable body: {body[:80]}")
for h in sorted(owned - seen_hosts):
    rot("PROXY-ROT", f"host {h} carries nodes but appears in NO proxy upstream — capacity silently unused")
e2e_p = os.path.join(inv, "proxy-e2e.raw")
if proxy_url and os.path.exists(e2e_p):
    e2e = open(e2e_p).read().strip()
    if not e2e:
        rot("PROXY-ROT", f"{proxy_url} did not answer end-to-end after 3 tries")
    else:
        try:
            s = json.loads(e2e)["result"].get("slot")
            if median and isinstance(s, int) and median - s > behind_ok:
                rot("PROXY-ROT", f"{proxy_url} serves a head {median - s} slots behind the fleet")
        except Exception:
            rot("PROXY-ROT", f"{proxy_url} returned unparseable body end-to-end: {e2e[:80]}")

# ── STRUCTURE ─────────────────────────────────────────────────────────────
ap = os.path.join(inv, "anomalies.txt")
if os.path.exists(ap):
    for l in open(ap):
        l = l.strip()
        if not l: continue
        cls = l.split("\t")[0]
        rot("STRUCTURE", l.replace("\t", " "))

# ── report ────────────────────────────────────────────────────────────────
hard = {"PEER-ROT", "FORWARD-ROT", "PROXY-ROT", "CONSENSUS", "PEER-GAP", "STRUCTURE"}
n_find = sum(len(v) for v in findings.values())
if as_json:
    print(json.dumps(dict(inventory=inv, findings={k: v for k, v in findings.items()},
                          validators=len([n for n in nodes if n[2] == "validator" and n[4] == "active"]),
                          observers=len([n for n in nodes if n[2] == "observer" and n[4] == "active"]),
                          dead_dials=dead_total, median_slot=median), indent=1))
elif not quiet or n_find:
    print(f"═══ REFERENCE ROT — {inv} ═══")
    for cls in sorted(findings):
        for l in findings[cls]: print(f"  {cls:<12} {l}")
    if not findings: print("  (nothing rotted)")
    print()

v = len([n for n in nodes if n[2] == "validator" and n[4] == "active"])
o = len([n for n in nodes if n[2] == "observer" and n[4] == "active"])
# THE ONE LINE. cron mails it; `systemctl status` shows it; a human reads it in
# two seconds and knows whether to care.
if n_find == 0:
    print(f"OK: {v} validators + {o} observers, slot {median}, 1 head, "
          f"{len(fwd)} forwarders and {len(ups)} upstreams all resolve to live nodes; 0 dead references.")
    sys.exit(0)
else:
    cls_summary = ", ".join(f"{c}×{len(findings[c])}" for c in sorted(findings))
    print(f"ROT: {n_find} finding(s) [{cls_summary}] — {dead_total} dead dial entries in "
          f"{units_rotten}/{len(by_unit)} units, {v} validators + {o} observers live at slot {median}. "
          f"Detail above; evidence in {inv}.")
    sys.exit(1)
PY
rc=$?
[ "$QUIET" = 1 ] || note "evidence: $INV"
exit $rc
