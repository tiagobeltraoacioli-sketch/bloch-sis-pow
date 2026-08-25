#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
CONVERGED/DIVERGED verdict for a `scripts/devnet-particao.sh` run.

PROVENANCE. PMO10/devA's `verdict.py`, brought in-tree. One change: the run
directories are ARGUMENTS instead of a hard-coded list of `/private/tmp/pmoA-*`
paths. A verdict script that only reads one machine's scratch directory cannot
be re-run by a third party, which is the whole requirement.

WHY IT READS THE LOGS AND NOT THE RPC SAMPLE

`devnet-particao.sh` samples `getchaininfo` while a phase is live and compares
head block ids. That answers "where did each node end up". This answers a
stricter question: at the highest slot EVERY node actually applied a block
for, did they apply the SAME block? Reading `[slot N] applied <id>` with
last-write-wins per slot gives the post-reorg truth, so a node that forked and
later reorged onto the majority branch counts as agreeing — which is what
"converged" has to mean.

A run where the halves share no applied slot at all reports NO COMMON SLOT
rather than a verdict. That is not a pass: it means the partition was total
and the comparison has no basis.

USAGE

    scripts/devnet-veredito.py <workdir>:<n>[:<label>] [...]
    scripts/devnet-veredito.py /tmp/ctl8:8:"CONTROL n=8" /tmp/arm8:8:"SPLIT n=8"

    # optional: --tag phase2   (default: phase3-heal, the post-heal phase)
"""

import os
import re
import sys


def score(wd, tag, n):
    per = {}
    for i in range(n):
        f = os.path.join(wd, f"node{i}", f"{tag}.log")
        if not os.path.exists(f):
            continue
        m = {}
        with open(f, errors="replace") as fh:
            text = fh.read()
        # Last write wins per slot => post-reorg truth.
        for s, b in re.findall(r"\[slot (\d+)\] applied ([0-9a-f]+)", text):
            m[int(s)] = b
        if m:
            per[i] = m
    if len(per) < 2:
        return f"{tag}: NO DATA ({len(per)} node log(s) with an applied block)"

    common = set.intersection(*(set(m) for m in per.values()))
    if not common:
        return f"{tag}: NO COMMON SLOT (the halves share no applied slot at all)"

    out = []
    for s in sorted(common)[-3:]:
        ids = {i: per[i][s] for i in per}
        d = sorted(set(ids.values()))
        if len(d) == 1:
            out.append(f"slot {s}: AGREE {d[0][:8]}")
        else:
            grp = {h: sorted(k for k, v in ids.items() if v == h) for h in d}
            out.append(f"slot {s}: DISAGREE " + " | ".join(f"{h[:8]}={g}" for h, g in grp.items()))

    top = sorted(common)[-1]
    ids = {i: per[i][top] for i in per}
    verdict = "CONVERGED" if len(set(ids.values())) == 1 else "DIVERGED"
    head = f"{tag}: {verdict} (highest common applied slot {top}, {len(per)}/{n} nodes)"
    return head + "\n      " + "\n      ".join(out)


def main(argv):
    tag = "phase3-heal"
    args = []
    it = iter(argv)
    for a in it:
        if a == "--tag":
            tag = next(it)
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            args.append(a)
    if not args:
        print(__doc__, file=sys.stderr)
        return 64

    seen = 0
    diverged = 0
    for spec in args:
        parts = spec.split(":")
        wd = parts[0]
        n = int(parts[1]) if len(parts) > 1 else 8
        label = parts[2] if len(parts) > 2 else wd
        if not os.path.isdir(wd):
            print(f"── {label} ──\n    MISSING: {wd} is not a directory")
            continue
        seen += 1
        result = score(wd, tag, n)
        print(f"── {label} ──")
        print("   ", result)
        if "DIVERGED" in result:
            diverged += 1

    if seen == 0:
        print("!! NO RUN DIRECTORY EXISTED. This report means NOTHING.", file=sys.stderr)
        return 2
    # Deliberately not an error: a DIVERGED arm is the expected result of the
    # split arm. The caller decides what a given arm was supposed to show.
    print(f"\n{seen} run(s) read, {diverged} DIVERGED at tag '{tag}'")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
