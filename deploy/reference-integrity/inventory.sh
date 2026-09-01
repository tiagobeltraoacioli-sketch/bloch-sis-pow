#!/usr/bin/env bash
# inventory.sh — the TRUTH about what is running, discovered by CONTENT.
#
# WHY: on 2026-08-31 four systems broke from one cause — a static reference to
# a node (a port, a peer address) with no owner and no verification. The devnet
# transport reconnects dead peers forever and silently, so this rot never
# raises an error; it shows up as latency, and nine hours later as an outage.
#
# The first defence is refusing to guess what the fleet is. Two rules:
#
#   1. ENUMERATE BY UNIT CONTENT, NOT BY UNIT NAME. `ls bloch-n*.service` is a
#      guess. Stale `g4-vNN` twins have pointed at the SAME --data-dir with a
#      different port before, and one of them double-signed for 29 hours
#      unnoticed because nobody was listing it. Here a node is any unit whose
#      ExecStart runs a bloch-pos binary with `run`, whatever it is called.
#   2. CORROBORATE BY RPC. A unit file is an intention; an answering RPC on
#      16400+i is a fact. A unit with no RPC is an invisible node; an RPC with
#      no unit is an orphan. Both are reported.
#
# STRICTLY READ-ONLY: ssh + systemctl cat/is-active/is-enabled, ss, ps, curl to
# 127.0.0.1 inside each box. It starts nothing, stops nothing, edits nothing.
#
# Usage:
#   inventory.sh [-c CONF] [-o OUTDIR]
# Outputs (TSV, machine-readable, consumed by rot-detector.sh and derive-peers.sh):
#   nodes.tsv       idx host role unit active enabled bin datadir listen rpc rpc_bind
#   peers.tsv       host unit peer                (one row per configured dial)
#   forwarders.tsv  host unit listen_port target_port owner_unit state
#   rpc.tsv         host port slot height finalized head
#   anomalies.txt   every discrepancy, one per line (empty file == clean)
set -uo pipefail

CONF="${REFINT_CONF:-$(dirname "$0")/reference-integrity.conf}"
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) CONF="$2"; shift 2;;
    -o) OUT="$2"; shift 2;;
    *) echo "usage: $0 [-c CONF] [-o OUTDIR]" >&2; exit 2;;
  esac
done
[ -f "$CONF" ] || { echo "REFUSED: missing conf: $CONF" >&2; exit 2; }
# shellcheck disable=SC1090
. "$CONF"
: "${KEY:?conf must set KEY}" "${FLEET:?conf must set FLEET}"
: "${ARCHIVAL:=}" "${SSH_USER:=ubuntu}" "${RPC_BASE:=16400}" "${P2P_BASE:=19000}"
OUT="${OUT:-${REFINT_WORK:-$HOME/.bloch-reference-integrity}/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT" || exit 2

say() { echo "[$(date -u +%H:%M:%SZ)] $*" >&2; }
G() { ssh -n -o BatchMode=yes -o ConnectTimeout="${SSH_TIMEOUT:-15}" \
        -o StrictHostKeyChecking=accept-new -i "$KEY" "$SSH_USER@$1" "$2" 2>/dev/null; }

# ── the remote probe. One ssh per host; everything it prints is a fact it read.
read -r -d '' PROBE <<'REMOTE'
# REFINT-PROBE (this marker lets the ps sweep below exclude this very shell)
set -uo pipefail
echo "##IP $(hostname -I 2>/dev/null | awk '{print $1}')"
# Every unit FILE, then its state. Names are recorded but never trusted.
echo "##STATE"
for f in /etc/systemd/system/*.service; do
  [ -e "$f" ] || continue
  u=$(basename "$f" .service)
  printf '%s\t%s\t%s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)" "$(systemctl is-enabled "$u" 2>/dev/null)"
done
# ExecStart of every unit. `systemctl show -p ExecStart --value` is used
# deliberately instead of `systemctl cat`: it returns the RESOLVED argv on a
# SINGLE line, so a unit written with backslash continuations (both archival
# units are) parses identically to one written on one line. Parsing the file
# text instead is how a node stays invisible to an audit.
echo "##EXEC"
for f in /etc/systemd/system/*.service; do
  [ -e "$f" ] || continue
  u=$(basename "$f" .service)
  e=$(systemctl show -p ExecStart --value "$u" 2>/dev/null | tr '\n' ' ')
  case "$e" in *bloch*|*socat*) printf '@@%s\t%s\n' "$u" "$e";; esac
done
echo "##LISTEN"
ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | sed 's/.*://' | sort -un
# Processes are the last word: a bloch-pos running under no unit is an orphan
# that no rollout will ever stop, and no reboot will ever bring back.
# This probe's OWN command line contains the section markers below, so it is
# excluded and any stray "##" is defanged — otherwise the audit corrupts its
# own output, which it did on the first run.
echo "##PROC"
ps -eo pid,etimes,unit,args 2>/dev/null \
  | grep -E '[b]loch-pos|[s]ocat' \
  | grep -v 'REFINT-PROBE' \
  | sed 's/[[:space:]]\+/ /g; s/##/@@/g'
echo "##RPCPORTS"
ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | sed 's/.*://' | sort -un | awk '$1>=16400 && $1<16600'
REMOTE

# Per-host dumps land in their own directory. They are NEVER globbed into a
# file that lives beside them: `cat raw.* > raw.txt` reads raw.txt while
# writing it and grows without bound (it ate 67 GB of the author's disk once).
mkdir -p "$OUT/hosts"
: > "$OUT/unreachable.txt"
for h in $FLEET $ARCHIVAL; do
  ( r=$(G "$h" "$PROBE")
    if [ -z "$r" ]; then echo "$h" >> "$OUT/unreachable.txt"
    else { echo "##HOST $h"; echo "$r"; } > "$OUT/hosts/$h.raw"; fi ) &
done
wait
: > "$OUT/raw.txt"
for f in "$OUT"/hosts/*.raw; do [ -e "$f" ] && cat "$f" >> "$OUT/raw.txt"; done

if [ -s "$OUT/unreachable.txt" ]; then
  say "UNREACHABLE: $(tr '\n' ' ' < "$OUT/unreachable.txt")"
  # An incomplete inventory must never be mistaken for a complete one: every
  # consumer of these files (the derivation especially) reads this marker and
  # refuses to install anything derived from a partial view.
  echo "PARTIAL" > "$OUT/PARTIAL"
fi

# ── RPC corroboration: ask every 164xx that is actually listening, on the box.
: > "$OUT/rpc.tsv"
for h in $FLEET $ARCHIVAL; do
  grep -q "^$h\$" "$OUT/unreachable.txt" 2>/dev/null && continue
  ( PORTS=$(awk -v h="$h" '$0=="##HOST "h{f=1} f&&/^##RPCPORTS/{g=1;next} g&&/^##/{exit} g&&NF{print}' "$OUT/raw.txt")
    # ONE LOST READ IS NOT A DEFECT. A box running nine nodes drops the odd
    # request under load, and a single miss here is indistinguishable from a
    # dead node — it produced six false INVISIBLE-NODE findings on the first
    # unattended run. Three tries; only persistent silence counts.
    for p in $PORTS; do
      b=""
      for _try in 1 2 3; do
        b=$(G "$h" "curl -s --max-time 8 -X POST http://127.0.0.1:$p -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getchaininfo\",\"params\":[]}'")
        [ -n "$b" ] && break
        sleep 3
      done
      python3 - "$h" "$p" <<PY
import sys,json
h,p=sys.argv[1],sys.argv[2]
try:
    r=json.loads('''$b''')["result"]
    print("\t".join([h,p,str(r.get("slot","")),str(r.get("height","")),
        str(r.get("finalized_height", r.get("finalized",""))),
        str(r.get("head", r.get("block_id","")))[:16]]))
except Exception:
    print("\t".join([h,p,"NORESP","","",""]))
PY
    done ) >> "$OUT/rpc.tsv" &
done
wait
sort -k1,1 -k2,2n -o "$OUT/rpc.tsv" "$OUT/rpc.tsv"

# ── classification, collisions, anomalies
python3 - "$OUT" "$RPC_BASE" "$P2P_BASE" <<'PY'
import re, sys, os, collections
out, RPC_BASE, P2P_BASE = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
raw = open(os.path.join(out, "raw.txt")).read()
blocks = re.split(r'(?m)^##HOST ', raw)[1:]
nodes, fwd, peers, anom, listen, procs = [], [], [], [], {}, {}

def arg(ex, flag):
    m = re.search(r'"%s"\s+"([^"]*)"' % flag, ex) or re.search(r'%s[= ]([^\s\']+)' % flag, ex)
    return m.group(1) if m else None

for blk in blocks:
    host = blk.split("\n", 1)[0].strip()
    def sec(n):
        m = re.search(r'(?m)^##%s\n(.*?)(?=\n##|\Z)' % n, blk, re.S)
        return m.group(1) if m else ""
    state = {}
    for l in sec("STATE").strip().splitlines():
        f = l.split("\t")
        if f and f[0]: state[f[0]] = (f[1] if len(f) > 1 else "?", f[2] if len(f) > 2 else "?")
    listen[host] = set(x.strip() for x in sec("LISTEN").split() if x.strip())
    procs[host] = [l for l in sec("PROC").strip().splitlines() if l.strip()]
    for l in sec("EXEC").strip().splitlines():
        if not l.startswith("@@"): continue
        unit, ex = l[2:].split("\t", 1)
        a, e = state.get(unit, ("?", "?"))
        # CLASSIFY BY CONTENT. Not by name. This is the whole point.
        if re.search(r'/\S*bloch-pos\S*["\s]+.*\brun\b', ex) or (re.search(r'bloch-pos', ex) and ' run' in ex.replace('"', ' ')):
            binm = re.search(r'[=\s"](/\S*bloch-pos[^"\s;]*)', ex)
            dd, li, rp = arg(ex, "--data-dir"), arg(ex, "--listen"), arg(ex, "--rpc-port")
            if not dd: continue
            role = "validator" if (li and rp and int(li) - P2P_BASE == int(rp) - RPC_BASE and 0 <= int(rp) - RPC_BASE < 100) else "observer"
            idx = str(int(rp) - RPC_BASE) if (rp and rp.isdigit() and role == "validator") else "-"
            nodes.append(dict(idx=idx, host=host, role=role, unit=unit, active=a, enabled=e,
                              bin=binm.group(1) if binm else "?", datadir=dd, listen=li or "?",
                              rpc=rp or "off", rpc_bind=arg(ex, "--rpc-bind") or "?"))
            for p in (arg(ex, "--peers") or "").split(","):
                if p.strip(): peers.append((host, unit, p.strip()))
        elif "socat" in ex and "TCP-LISTEN:" in ex:
            lp = re.search(r'TCP-LISTEN:(\d+)', ex); tp = re.search(r'TCP:127\.0\.0\.1:(\d+)', ex)
            fwd.append(dict(host=host, unit=unit, listen=lp.group(1) if lp else "?",
                            target=tp.group(1) if tp else "?", active=a, enabled=e))

live_units = {(n["host"], n["unit"]) for n in nodes if n["active"] == "active"}

# --- collisions and invisibles ------------------------------------------------
dd = collections.defaultdict(list)
for n in nodes:
    if n["active"] == "active": dd[(n["host"], n["datadir"])].append(n["unit"])
for (h, d), us in dd.items():
    if len(us) > 1:
        anom.append(f"DOUBLE-SIGN-RISK\t{h}\ttwo active units share --data-dir {d}: {', '.join(us)}")
for key, label in ((("host", "listen"), "P2P"), (("host", "rpc"), "RPC")):
    c = collections.defaultdict(list)
    for n in nodes:
        if n["active"] == "active" and n[key[1]] not in ("?", "off"): c[(n["host"], n[key[1]])].append(n["unit"])
    for (h, p), us in c.items():
        if len(us) > 1: anom.append(f"PORT-COLLISION\t{h}\t{label} port {p} claimed by {', '.join(us)}")

rpcrows = [l.rstrip("\n").split("\t") for l in open(os.path.join(out, "rpc.tsv")) if l.strip()]
answering = {(r[0], r[1]) for r in rpcrows if r[2] not in ("NORESP", "")}
for n in nodes:
    if n["active"] == "active" and n["rpc"] != "off" and (n["host"], n["rpc"]) not in answering:
        anom.append(f"INVISIBLE-NODE\t{n['host']}\t{n['unit']} is active but RPC {n['rpc']} does not answer")
claimed = {(n["host"], n["rpc"]) for n in nodes}
for hp in sorted(answering - claimed):
    anom.append(f"ORPHAN-RPC\t{hp[0]}\tport {hp[1]} answers getchaininfo but no unit file claims it")
for h, ps in procs.items():
    for p in ps:
        if "bloch-pos" in p and re.search(r'\s-\s', " " + p):  # unit column '-' == no unit
            f = p.strip().split(None, 3)
            if len(f) > 2 and f[2] == "-":
                anom.append(f"ORPHAN-PROCESS\t{h}\tpid {f[0]} runs bloch-pos under NO systemd unit")
# name-vs-content: recorded as INFO, because the name is never the authority
for n in nodes:
    m = re.match(r'.*?(\d+)$', n["unit"])
    if n["role"] == "validator" and m and int(m.group(1)) != int(n["idx"]):
        anom.append(f"NAME-LIES\t{n['host']}\tunit {n['unit']} actually serves index {n['idx']} (ports {n['listen']}/{n['rpc']})")
    if n["role"] == "validator" and not m:
        anom.append(f"NAME-LIES\t{n['host']}\tunit {n['unit']} carries no index but serves validator {n['idx']}")

def w(name, rows, header):
    with open(os.path.join(out, name), "w") as fh:
        fh.write("#" + "\t".join(header) + "\n")
        for r in rows: fh.write("\t".join(str(x) for x in r) + "\n")

nodes.sort(key=lambda n: (n["role"], int(n["idx"]) if n["idx"].isdigit() else 999, n["host"]))
w("nodes.tsv", [[n["idx"], n["host"], n["role"], n["unit"], n["active"], n["enabled"], n["bin"],
                n["datadir"], n["listen"], n["rpc"], n["rpc_bind"]] for n in nodes],
  ["idx", "host", "role", "unit", "active", "enabled", "bin", "datadir", "listen", "rpc", "rpc_bind"])
w("peers.tsv", sorted(peers), ["host", "unit", "peer"])
byrpc = {(n["host"], n["rpc"]): n["unit"] for n in nodes if n["active"] == "active"}
w("forwarders.tsv", [[f["host"], f["unit"], f["listen"], f["target"],
                      byrpc.get((f["host"], f["target"]), "NONE"), f["active"]] for f in sorted(fwd, key=lambda x: (x["host"], x["listen"]))],
  ["host", "unit", "listen_port", "target_port", "owner_unit", "state"])
open(os.path.join(out, "anomalies.txt"), "w").write("\n".join(sorted(set(anom))) + ("\n" if anom else ""))

# The derived truth other tools consume, in two flavours:
#   live-endpoints.txt   every active node — used to judge whether a configured
#                        peer is DEAD (an endpoint that exists is never dead)
#   live-validators.txt  active validators only — the default scope for what a
#                        unit SHOULD dial. Keeping these separate is what lets
#                        the cleanup be a strict deletion: the derived list is a
#                        subset of what every unit already carries, so reverting
#                        can never disconnect a node from something it can reach.
with open(os.path.join(out, "live-endpoints.txt"), "w") as fh:
    for n in nodes:
        if n["active"] == "active" and n["listen"] != "?": fh.write(f"{n['host']}:{n['listen']}\n")
with open(os.path.join(out, "live-validators.txt"), "w") as fh:
    for n in nodes:
        if n["active"] == "active" and n["role"] == "validator" and n["listen"] != "?":
            fh.write(f"{n['host']}:{n['listen']}\n")

v = [n for n in nodes if n["role"] == "validator" and n["active"] == "active"]
o = [n for n in nodes if n["role"] == "observer" and n["active"] == "active"]
print(f"nodes: {len(v)} validators + {len(o)} observers on "
      f"{len(set(n['host'] for n in nodes))} hosts; forwarders: {len(fwd)}; "
      f"RPCs answering: {len(answering)}; anomalies: {len(set(anom))}", file=sys.stderr)
PY
rc=$?
say "inventory written to $OUT"
echo "$OUT"
exit $rc
