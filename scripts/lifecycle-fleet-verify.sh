#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# lifecycle-fleet-verify.sh — the read-only sweep behind the ADR-041 flag day
# (deploy/FLAG-DAY-LIFECYCLE.md). Asks every node what it is RUNNING and
# prints one verdict for the fleet.
#
# Three RPCs per node, all unauthenticated reads:
#   getbuildinfo           — `commit` and `source_digest` of the running binary
#   getvalidatoradmission  — `activation_epoch`: null on an unarmed binary,
#                            the lifecycle epoch L on an armed one. The
#                            compile-time assert in params.rs makes the five
#                            ADR-041 constants equal, so this ONE field speaks
#                            for all five — on a binary built from this tree.
#                            A binary whose params.rs deleted the assert can
#                            report L with the other four unarmed, which is
#                            why the commit and digest columns are not
#                            optional: the fleet must match the release, not
#                            merely say the right number.
#   getchaininfo           — head epoch, finalized epoch and root
#
# READY means: every node answered, every node reports activation_epoch == L,
# every node runs the same commit AND source_digest, and every pair of nodes
# that agree on a finalized epoch also agree on its root. Anything else is
# NOT READY, with the offending rows named. The script never writes to a node.
#
# Nodes bind RPC to 127.0.0.1:16310 by default and MUST stay that way
# (main.rs --help, "YOU MUST firewall"), so the sweep reaches them either
# through a host you already have SSH into or through an endpoint you have
# tunnelled yourself. The inventory file has one node per line:
#
#   <label>  http://127.0.0.1:16310          # direct (tunnelled, or run on the host)
#   <label>  ssh://ubuntu@HOST-001           # curl runs ON the host against
#                                            # 127.0.0.1:${RPC_PORT:-16310}
#
# Labels are the opaque host IDs of deploy/FLEET-INVENTORY.md; this file is
# expected to be readable in a public repo and the inventory is not.
# `#` starts a comment; blank lines are ignored.
#
# Usage:
#   scripts/lifecycle-fleet-verify.sh <inventory-file> [--epoch L] [--out sweep.tsv]
#
# --epoch defaults to the `LIFECYCLE_EPOCH = ...` line of the runbook;
# `unarmed` there means the sweep expects every node to report null. Exit 0
# only on READY. Needs bash, curl, python3; ssh for ssh:// rows.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNBOOK="$REPO/deploy/FLAG-DAY-LIFECYCLE.md"
RPC_PORT="${RPC_PORT:-16310}"
SSH_KEY="${SSH_KEY:-}"

usage() { sed -n '4,44p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

[ $# -ge 1 ] || usage
INVENTORY="$1"; shift
[ -r "$INVENTORY" ] || { echo "cannot read inventory $INVENTORY" >&2; exit 2; }

EXPECT=""
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --epoch) EXPECT="${2:?--epoch needs a value}"; shift 2 ;;
    --out)   OUT="${2:?--out needs a path}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown option $1" >&2; usage ;;
  esac
done

if [ -z "$EXPECT" ]; then
  EXPECT="$(sed -n 's/^LIFECYCLE_EPOCH = \(unarmed\|[0-9]\+\)$/\1/p' "$RUNBOOK" | head -1)"
  [ -n "$EXPECT" ] || { echo "no LIFECYCLE_EPOCH line in $RUNBOOK and no --epoch given" >&2; exit 2; }
fi
case "$EXPECT" in unarmed|[0-9]*) ;; *) echo "--epoch must be a number or 'unarmed'" >&2; exit 2 ;; esac

rpc_body() { printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":[]}' "$1"; }

# One call, one JSON line on stdout, empty on failure. Never fails the script:
# an unreachable node is a row in the verdict, not an abort.
call() { # call <target> <method>
  local target="$1" method="$2"
  case "$target" in
    http://*|https://*)
      curl -s --max-time 8 -X POST "$target" -H 'content-type: application/json' \
        -d "$(rpc_body "$method")" 2>/dev/null || true ;;
    ssh://*)
      local hostspec="${target#ssh://}"
      local keyopt=()
      [ -n "$SSH_KEY" ] && keyopt=(-i "$SSH_KEY")
      ssh -o ConnectTimeout=10 -o BatchMode=yes "${keyopt[@]}" "$hostspec" \
        "curl -s --max-time 8 -X POST http://127.0.0.1:$RPC_PORT -H 'content-type: application/json' -d '$(rpc_body "$method")'" \
        2>/dev/null || true ;;
    *) echo "" ;;
  esac
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/lifecycle-sweep.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
ROWS="$TMP/rows.tsv"
: > "$ROWS"

echo "lifecycle fleet sweep — expecting activation_epoch = $EXPECT"
echo "inventory: $INVENTORY"
echo

while read -r label target _; do
  case "$label" in ''|'#'*) continue ;; esac
  [ -n "${target:-}" ] || { echo "$label: no target" >&2; continue; }
  build="$(call "$target" getbuildinfo)"
  adm="$(call "$target" getvalidatoradmission)"
  chain="$(call "$target" getchaininfo)"
  LABEL="$label" BUILD="$build" ADM="$adm" CHAIN="$chain" python3 - >> "$ROWS" <<'PY'
import json, os
def result(raw):
    try:
        return json.loads(raw)["result"]
    except Exception:
        return None
b, a, c = (result(os.environ[k]) for k in ("BUILD", "ADM", "CHAIN"))
label = os.environ["LABEL"]
if b is None or a is None or c is None:
    print("\t".join([label, "NO-ANSWER", "-", "-", "-", "-", "-"]))
else:
    act = a.get("activation_epoch")
    print("\t".join([
        label,
        str(b.get("commit", "?")),
        str(b.get("source_digest", "?")),
        "unarmed" if act is None else str(act),
        str(c.get("epoch", "?")),
        str(c.get("finalized", {}).get("epoch", "?")),
        str(c.get("finalized", {}).get("root", "?")),
    ]))
PY
done < "$INVENTORY"

[ -n "$OUT" ] && cp "$ROWS" "$OUT"

EXPECT="$EXPECT" python3 - "$ROWS" <<'PY'
import os, sys
from collections import Counter, defaultdict
expect = os.environ["EXPECT"]
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[1]) if line.strip()]
if not rows:
    print("no nodes in inventory"); sys.exit(1)
w = [max(len(r[i]) for r in rows + [["label","commit","source_digest","activation","head","finalized","finalized_root"]]) for i in range(7)]
hdr = ["label","commit","source_digest","activation","head","finalized","finalized_root"]
def show(r):
    return "  ".join(v[:16].ljust(min(w[i],16)) if i in (1,2,6) else v.ljust(w[i]) for i, v in enumerate(r))
print(show(hdr)); print(show(["-"*min(x,16) if i in (1,2,6) else "-"*x for i, x in enumerate(w)]))
for r in rows: print(show(r))
problems = []
answered = [r for r in rows if r[1] != "NO-ANSWER"]
for r in rows:
    if r[1] == "NO-ANSWER":
        problems.append(f"{r[0]}: no RPC answer")
for r in answered:
    if r[3] != expect:
        problems.append(f"{r[0]}: activation_epoch is {r[3]}, expected {expect}")
commits = Counter(r[1] for r in answered)
digests = Counter(r[2] for r in answered)
if len(commits) > 1:
    problems.append("more than one commit on the fleet: " + ", ".join(f"{c[:12]} x{n}" for c, n in commits.items()))
if len(digests) > 1:
    problems.append("more than one source_digest on the fleet: " + ", ".join(f"{d[:12]} x{n}" for d, n in digests.items()))
by_fin = defaultdict(set)
for r in answered:
    by_fin[r[5]].add(r[6])
for epoch, roots in by_fin.items():
    if len(roots) > 1:
        problems.append(f"finalized epoch {epoch} has {len(roots)} different roots — a fork, not a readiness question")
print()
if problems:
    print("FLEET: NOT READY")
    for p in problems: print(f"  - {p}")
    sys.exit(1)
print(f"FLEET: READY — {len(answered)} nodes, one commit, one digest, activation_epoch = {expect}, finalized roots agree")
PY
