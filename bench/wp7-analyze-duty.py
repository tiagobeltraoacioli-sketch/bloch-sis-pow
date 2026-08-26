#!/usr/bin/env python3
"""WP7 — slot-duty starvation, per condition.

The throughput table asks what the drain bound COSTS. This one asks what it
BUYS. The slot loop attests and proposes only between ticks, so a tick that
outlasts a slot does not delay a duty — it skips it, and the node is
indistinguishable from one that is down for those slots.
"""
import glob, os, re, statistics

LINE = re.compile(
    r"syncbench t_ms=(\d+) head=(\d+) blocks=(\d+) ticks=(\d+) events=(\d+) "
    r"shedblk=(\d+) shedatt=(\d+) shedtx=(\d+) qblk=(\d+) qatt=(\d+) qtx=(\d+) "
    r"skipped=(\d+) maxjump=(\d+) proposed=(\d+) attested=(\d+) latemax=(\d+)")
ORDER = ["unbounded", "cap256", "cap64", "cap32", "cap16", "cap4"]
BENCH = os.path.dirname(os.path.abspath(__file__))


def main(outdir):
    labels = {}
    for d in sorted(glob.glob(os.path.join(BENCH, outdir, "*"))):
        base = os.path.basename(d)
        label, _ = base.rsplit(".", 1)
        cli = os.path.join(d, "cli.log")
        if not os.path.exists(cli):
            continue
        mode = next((l.strip() for l in open(cli) if l.startswith("engine: ")), "")
        want = label.replace("cap", "")
        ok = ("UNBOUNDED" in mode) if label == "unbounded" else \
             (f"at most {want} event" in mode)
        if not ok:
            print(f"!! {base}: knob did NOT apply — VOID")
            continue
        s = [tuple(int(x) for x in m.groups())
             for m in (LINE.search(l) for l in open(cli)) if m]
        if not s:
            print(f"!! {base}: no samples")
            continue
        last = s[-1]
        # slots the wall clock crossed over the sampled window
        span = (last[0] - s[0][0]) / 1000.0
        labels.setdefault(label, []).append(
            (last[11], last[12], last[13], last[14], last[15], span, last[2]))
    print("| %-10s | %4s | %8s | %8s | %8s | %8s | %9s |" % (
        "condition", "runs", "skipped", "maxjump", "proposed", "attested", "latemax"))
    print("|" + "-" * 12 + "|" + "-" * 6 + "|" + "-" * 10 + "|" + "-" * 10 +
          "|" + "-" * 10 + "|" + "-" * 10 + "|" + "-" * 11 + "|")
    for label in ORDER:
        if label not in labels:
            continue
        rs = labels[label]
        med = lambda i: statistics.median([r[i] for r in rs])
        print("| %-10s | %4d | %8.0f | %8.0f | %8.0f | %8.0f | %7.0fms |" % (
            label, len(rs), med(0), med(1), med(2), med(3), med(4)))
    print("\nraw (skipped slots / max slot jump / proposed / attested):")
    for label in ORDER:
        if label not in labels:
            continue
        print(f"  {label:<10s} " + "  ".join(
            f"{r[0]}/{r[1]}/{r[2]}/{r[3]}" for r in labels[label]))


import sys
main(sys.argv[1] if len(sys.argv) > 1 else "out3")
