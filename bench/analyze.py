#!/usr/bin/env python3
"""WP7 — read blocks/s off the syncbench curve of each run.

Deliberately NOT a stopwatch over the whole process: the first samples include
dial, the first sync request and the server's first page, none of which are the
drain loop's throughput. The slope is taken across the interior of the catch-up
(5%..95% of the fixture tip), which is the part where the queue is full and the
drain bound — if it binds at all — is what limits progress.
"""
import glob, os, re, statistics, sys

LINE = re.compile(
    r"syncbench t_ms=(\d+) head=(\d+) blocks=(\d+) ticks=(\d+) events=(\d+) "
    r"shedblk=(\d+) shedgos=(\d+) blkbytes=(\d+) gosbytes=(\d+)")

def samples(path):
    out = []
    with open(path) as f:
        for ln in f:
            m = LINE.search(ln)
            if m:
                out.append(tuple(int(x) for x in m.groups()))
    return out

def time_to_tip(s, tip):
    """Blocks per second end-to-end: the whole catch-up, tip over elapsed.

    This, not the interior slope, is the headline metric. The interior slope
    needs several samples inside the catch-up, and the sample DENSITY is itself
    a function of the condition being tested: one unbounded tick swallows a
    whole 512-block page, so an unbounded run emits two or three samples where
    a `cap4` run emits seventy. A statistic whose precision depends on the arm
    is not a fair comparison. Elapsed-to-tip is measured the same way in every
    arm, and `t_ms` starts at the slot loop, so boot and replay are already out
    of it.
    """
    at_tip = [x for x in s if x[2] >= tip]
    if not at_tip:
        return None
    ms = at_tip[0][0]
    return (tip / (ms / 1000.0), ms) if ms > 0 else None


def slope(s, tip):
    lo, hi = 0.05 * tip, 0.95 * tip
    seg = [x for x in s if lo <= x[2] <= hi]
    if len(seg) < 3:
        seg = [x for x in s if x[2] > 0]
    if len(seg) < 2:
        return None
    dt = (seg[-1][0] - seg[0][0]) / 1000.0
    db = seg[-1][2] - seg[0][2]
    if dt <= 0 or db <= 0:
        return None
    return db / dt

ORDER = ["unbounded", "cap256", "cap64", "cap32", "cap16", "cap4"]


def main():
    bench = os.path.dirname(os.path.abspath(__file__))
    tip = int(open(os.path.join(bench, "fixture", "tip")).read().split()[0])
    labels = {}
    for d in sorted(glob.glob(os.path.join(bench, "out", "*"))):
        base = os.path.basename(d)
        label, run = base.rsplit(".", 1)
        cli = os.path.join(d, "cli.log")
        if not os.path.exists(cli):
            continue
        # PROOF the knob applied, checked per run rather than assumed. A run
        # whose environment silently did not take is indistinguishable from a
        # real measurement in the numbers alone, and would quietly turn the
        # whole comparison into noise.
        mode = ""
        for ln in open(cli):
            if ln.startswith("engine: "):
                mode = ln.strip()
                break
        want = label.replace("cap", "")
        ok = ("UNBOUNDED" in mode) if label == "unbounded" else \
             (f"at most {want} events" in mode)
        if not ok:
            print(f"!! {base}: knob did NOT apply (mode line: {mode!r}) — run VOID")
            continue
        s = samples(cli)
        if not s:
            print(f"!! {base}: NO syncbench samples — the run produced no number")
            continue
        tt = time_to_tip(s, tip)
        r = tt[0] if tt else None
        last = s[-1]
        labels.setdefault(label, []).append(
            (run, r, last[2], last[0], last[5], last[6],
             max(x[7] for x in s), last[4] / max(last[3], 1),
             slope(s, tip), tt[1] if tt else None, last[3]))
    print(f"fixture tip = {tip} blocks\n")
    hdr = ("condition", "runs", "median blk/s", "spread (min..max)",
           "reached", "shedBLK", "shedGOS", "peakBLKb", "ev/tick")
    print("| %-14s | %4s | %12s | %-21s | %7s | %7s | %7s | %9s | %7s |" % hdr)
    print("|" + "-" * 16 + "|" + "-" * 6 + "|" + "-" * 14 + "|" + "-" * 23 +
          "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 11 +
          "|" + "-" * 9 + "|")
    for label in ORDER:
        if label not in labels:
            continue
        rs = labels[label]
        vals = [x[1] for x in rs if x[1] is not None]
        if not vals:
            print(f"| {label:<14s} | {len(rs):4d} |   NO SLOPE   |")
            continue
        med = statistics.median(vals)
        spread = f"{min(vals):.0f}..{max(vals):.0f}"
        rel = 100.0 * (max(vals) - min(vals)) / med if med else 0
        reached = sum(1 for x in rs if x[2] >= tip)
        shedb = max(x[4] for x in rs)
        shedg = max(x[5] for x in rs)
        peakq = max(x[6] for x in rs)
        evt = statistics.median([x[7] for x in rs])
        print("| %-14s | %4d | %12.1f | %-21s | %3d/%-3d | %7d | %7d | %9d | %7.2f |"
              % (label, len(rs), med, f"{spread} (±{rel:.0f}%)", reached,
                 len(rs), shedb, shedg, peakq, evt))
    print("\nblk/s above is tip/elapsed-to-tip. Raw per run:\n")
    for label in ORDER:
        if label not in labels:
            continue
        rs = sorted(labels[label])
        vals = ", ".join(f"{x[1]:.1f}" if x[1] else "n/a" for x in rs)
        secs = ", ".join(f"{x[9]/1000:.1f}" if x[9] else "n/a" for x in rs)
        tks = ", ".join(str(x[10]) for x in rs)
        print(f"  {label:<10s} blk/s: {vals}")
        print(f"  {'':<10s} secs : {secs}")
        print(f"  {'':<10s} ticks: {tks}")

main()
