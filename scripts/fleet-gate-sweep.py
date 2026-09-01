#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Report half of scripts/fleet-gate-sweep.sh. Reads the probe output the shell
# half collected and answers one question: if we arm a flag day, does the whole
# fleet follow, or does part of it fork?
#
# The comparison rule, stated once:
#   Two binaries are consensus-compatible AT EPOCH E iff their gate lists agree
#   on every gate whose activation epoch is <= E. Absent-from-one is a
#   disagreement — a binary that never heard of a gate follows the OLD rule at
#   that gate's epoch, which is precisely a fork.
#
# `gates_digest` covers the whole set (every epoch, plus inert gates). It is
# the strong check and the one to quote on a release page. `--epoch E` is the
# narrow, operational check: it can pass while the digest differs, and that is
# a legitimate "safe to arm E today, but these hosts are already doomed at the
# next flag day" verdict — which the report says in words.

import json
import os
import sys
from collections import defaultdict

WORK = os.environ["WORK"]
HOSTS_FILE = os.environ["HOSTS_FILE"]
EPOCH = os.environ.get("EPOCH") or ""
REF_HOST = os.environ.get("REF_HOST") or ""
REF_JSON = os.environ.get("REF_JSON") or ""
OUT_JSON = os.environ.get("OUT_JSON") == "1"

EPOCH = int(EPOCH) if EPOCH else None
INERT = "inert"


def parse_statement(text):
    """Return (gates, digest, binary, error). gates maps NAME -> epoch|'inert'.

    A binary built before `selfcheck --json` existed prints `self-check passed`
    and exits 0 — it accepts the flag and ignores it. That is not a crash and
    must not be reported as one: it is a binary that CANNOT STATE ITS GATES,
    which for flag-day purposes is the most dangerous answer there is.
    """
    text = (text or "").strip()
    if not text:
        return None, None, None, "no output"
    if text.startswith("SWEEP-ERROR:"):
        return None, None, None, text.split("\n")[0][len("SWEEP-ERROR:"):].strip()
    start = text.find("{")
    if start < 0:
        if "self-check passed" in text:
            return None, None, None, (
                "binary predates `selfcheck --json` — it accepted the flag, "
                "ignored it, and printed only `self-check passed`. It cannot "
                "state which gates it knows"
            )
        return None, None, None, "no JSON in output: " + text.split("\n")[0][:120]
    try:
        doc = json.loads(text[start:])
    except json.JSONDecodeError as e:
        return None, None, None, f"malformed JSON: {e}"
    gates = {}
    for g in doc.get("consensus_gates", []):
        ep = g.get("epoch")
        gates[g["name"]] = INERT if ep is None else int(ep)
    if not gates:
        return None, None, None, "statement carries no consensus_gates"
    return gates, doc.get("gates_digest"), doc.get("binary"), None


def load_rows():
    rows = []
    with open(HOSTS_FILE) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            # Drop padding: the table is tab-ALIGNED for human eyes, so a
            # run of tabs is one separator, not three empty columns.
            parts = [p for p in line.split("\t") if p != ""]
            if len(parts) < 4:
                continue
            label, host, key, binary = parts[0], parts[1], parts[2], parts[3]
            role = parts[4] if len(parts) > 4 else ""
            rows.append(dict(label=label, host=host, binary_path=binary, role=role))
    return rows


nodes = []
for row in load_rows():
    try:
        with open(os.path.join(WORK, row["label"] + ".out")) as fh:
            raw = fh.read()
    except OSError:
        # No probe file at all means the shell half never ran this host --
        # a bug in the SWEEP, not a fact about the fleet. Say so, loudly and
        # separately, so it is never read as "this node is fine" or as a
        # property of the binary.
        raw = ("SWEEP-ERROR: this host was never probed — the sweep itself "
               "failed to run it. Re-run; if it repeats, fix the sweep. Do NOT "
               "read this as information about the node.")
    # Which image actually answered — the running one, or the table's path.
    # Never silently equate them: RELEASE-INTEGRITY.md §4 exists because a
    # path and a running process routinely disagree.
    source = next((l[len("GATE-SWEEP-SOURCE:"):].strip()
                   for l in raw.splitlines()
                   if l.startswith("GATE-SWEEP-SOURCE:")), None)
    row["source"] = source
    gates, digest, binary, err = parse_statement(raw)
    # Whose fault is a non-answer? A SWEEP-ERROR is this tool failing to ASK
    # the question; anything else is the node failing to ANSWER it. Never
    # collapse the two: "we could not reach it" is not evidence about the
    # binary, and reporting it as though it were is how a sweep launders its
    # own bugs into a green flag day.
    row.update(gates=gates, digest=digest, binary=binary, error=err,
               sweep_side=raw.strip().startswith("SWEEP-ERROR:"))
    nodes.append(row)


def print_probe_failure_table(nodes):
    """Per-host reasons, for the case where NOTHING could state its gates.

    Bailing out with a single line hides the fact an operator most needs here:
    why nothing answered. "10 hosts reachable, all on a binary that predates
    --json" and "8 hosts unreachable" reduce to the same one-liner and are
    completely different situations — the first is a release problem, the
    second is an outage. Each reason is printed in the sweep's own words, and
    the SWEEP/NODE column says who failed.
    """
    w = max([len(n["label"]) for n in nodes] + [5])
    n_sweep = sum(1 for n in nodes if n["gates"] is None and n["sweep_side"])
    n_node = sum(1 for n in nodes if n["gates"] is None and not n["sweep_side"])
    print(f"probed {len(nodes)} host(s): 0 could state their gates "
          f"({n_node} answered but could not state them, "
          f"{n_sweep} were not successfully asked by this sweep)",
          file=sys.stderr)
    for n in nodes:
        origin = "SWEEP" if n["sweep_side"] else "NODE "
        print(f"  {origin} {n['label']:<{w}}  {n['host']:<16}  {n['error']}",
              file=sys.stderr)

# ── Reference ────────────────────────────────────────────────────────────────
ref_gates = ref_digest = ref_name = None
if REF_JSON:
    with open(REF_JSON) as fh:
        ref_gates, ref_digest, ref_bin, err = parse_statement(fh.read())
    if err:
        print(f"fleet-gate-sweep: --reference-json unusable: {err}", file=sys.stderr)
        sys.exit(2)
    ref_name = f"{REF_JSON} ({ref_bin})"
else:
    cand = None
    if REF_HOST:
        cand = next((n for n in nodes if REF_HOST in (n["host"], n["label"])), None)
        if cand is None:
            print(f"fleet-gate-sweep: --reference {REF_HOST} not in host table", file=sys.stderr)
            sys.exit(2)
    else:
        cand = next((n for n in nodes if n["role"] == "ref" and n["gates"]), None)
        cand = cand or next((n for n in nodes if n["gates"]), None)
    if cand is None or not cand["gates"]:
        print_probe_failure_table(nodes)
        print("\nfleet-gate-sweep: no usable reference — no probed host could state "
              "its gates. Point --reference-json at a local `bloch-pos selfcheck "
              "--json` dump of the binary you intend to ship.", file=sys.stderr)
        sys.exit(2)
    ref_gates, ref_digest, ref_name = cand["gates"], cand["digest"], f"{cand['label']} ({cand['host']})"


def compare(gates, cutoff):
    """Gates <= cutoff on which `gates` disagrees with the reference.

    Returns list of (name, ref_value, node_value|None). `cutoff=None` compares
    the entire set including inert gates.
    """
    out = []
    names = set(ref_gates) | set(gates)
    for name in sorted(names):
        rv, nv = ref_gates.get(name), gates.get(name)
        relevant = rv if rv is not None else nv
        if cutoff is not None:
            # An inert gate cannot bind at any epoch, so it is out of scope for
            # a specific flag day — but it stays in the digest, and the report
            # says so.
            if relevant == INERT or (isinstance(relevant, int) and relevant > cutoff):
                continue
        if rv != nv:
            out.append((name, rv, nv))
    return out


for n in nodes:
    if n["gates"] is None:
        n["verdict"] = "UNKNOWN"
        n["diffs_full"] = n["diffs_epoch"] = []
        continue
    n["diffs_full"] = compare(n["gates"], None)
    n["diffs_epoch"] = compare(n["gates"], EPOCH) if EPOCH is not None else n["diffs_full"]
    n["verdict"] = "OK" if not n["diffs_epoch"] else "FORK"

unknown = [n for n in nodes if n["verdict"] == "UNKNOWN"]
forks = [n for n in nodes if n["verdict"] == "FORK"]
later = [n for n in nodes if n["verdict"] == "OK" and n["diffs_full"]]
ready = not forks and not unknown

if OUT_JSON:
    print(json.dumps({
        "reference": ref_name,
        "reference_digest": ref_digest,
        "epoch": EPOCH,
        "ready": ready,
        "nodes": [{
            "label": n["label"], "host": n["host"], "binary_path": n["binary_path"],
            "role": n["role"], "binary": n["binary"], "gates_digest": n["digest"],
            "verdict": n["verdict"], "error": n["error"], "asked": n.get("source"),
            "disagreements_at_epoch": [
                {"gate": g, "reference": r, "node": v} for g, r, v in n["diffs_epoch"]],
            "disagreements_full_set": [
                {"gate": g, "reference": r, "node": v} for g, r, v in n["diffs_full"]],
        } for n in nodes],
    }, indent=2))
    sys.exit(0 if ready else 1)

# ── Human report ─────────────────────────────────────────────────────────────
W = max([len(n["label"]) for n in nodes] + [5])


def show(v):
    return "inert" if v == INERT else ("ABSENT" if v is None else str(v))


print(f"reference: {ref_name}")
print(f"reference gates_digest: {ref_digest}")
if EPOCH is not None:
    print(f"flag day under test: epoch {EPOCH} "
          f"(verdict counts only gates with epoch <= {EPOCH})")
else:
    print("no --epoch given: verdict counts the ENTIRE gate set, "
          "which is the strict check")
print()

by_digest = defaultdict(list)
for n in nodes:
    by_digest[n["digest"] or "-none-"].append(n)

print(f"{'NODE'.ljust(W)}  {'VERDICT':<8}  {'GATES DIGEST':<16}  BINARY")
print("-" * (W + 60))
for n in nodes:
    d = (n["digest"] or "").__str__()[:16] or "--"
    print(f"{n['label'].ljust(W)}  {n['verdict']:<8}  {d:<16}  {n['binary'] or n['binary_path']}")
print()

print(f"digest groups: {len([k for k in by_digest if k != '-none-'])} distinct "
      f"among {len(nodes) - len(unknown)} node(s) that answered")
for d, group in sorted(by_digest.items()):
    if d == "-none-":
        continue
    print(f"  {d[:16]}  x{len(group):<3} {', '.join(x['label'] for x in group)}")
print()

if unknown:
    print("CANNOT STATE THEIR GATES — treat as NOT READY:")
    for n in unknown:
        print(f"  {n['label']} ({n['host']}) [{n['binary_path']}]")
        if n.get("source"):
            print(f"      asked: {n['source']}")
        print(f"      {n['error']}")
    print("  A binary that cannot answer this question is not evidence that it")
    print("  agrees. It is the same blind spot that let genesis4-node-20260814")
    print("  ship. Upgrade it, or read its gate table from the source commit its")
    print("  --version stamp names, before arming anything.")
    print()

if forks:
    scope = f"at epoch {EPOCH}" if EPOCH is not None else "on the full gate set"
    print(f"DISAGREE WITH THE REFERENCE {scope} — THESE WILL FORK:")
    for n in forks:
        print(f"  {n['label']} ({n['host']})")
        for g, r, v in n["diffs_epoch"]:
            print(f"      {g}: reference={show(r)}  this node={show(v)}")
    print()

if later:
    print("Compatible at the epoch under test, but ALREADY divergent on a gate")
    print("that binds later — these fork on a future flag day, not this one:")
    for n in later:
        print(f"  {n['label']} ({n['host']})")
        for g, r, v in n["diffs_full"]:
            print(f"      {g}: reference={show(r)}  this node={show(v)}")
    print()

if ready:
    where = f"epoch {EPOCH}" if EPOCH is not None else "every gate in the set"
    print(f"READY: all {len(nodes)} probed node(s) agree with the reference on {where}.")
    if later:
        print("       (see the future-flag-day divergence listed above)")
    sys.exit(0)

print("NOT READY: do not arm. "
      f"{len(forks)} node(s) would fork, {len(unknown)} cannot be asked.")
sys.exit(1)
