#!/usr/bin/env python3
"""Join the RSS samples to the heights the node reported, and answer the
monotonicity question from the data.

Usage: analyse.py <name.rss> <name.stdout> [<name.time>]
"""
import sys, re, bisect

rssf, outf = sys.argv[1], sys.argv[2]
timef = sys.argv[3] if len(sys.argv) > 3 else None

samples = []           # (t, rss_kb, hwm_kb, memavail_kb, load1)
with open(rssf) as f:
    next(f)
    for l in f:
        p = l.split("\t")
        samples.append((float(p[0]), int(p[1]), int(p[2]), int(p[3]), float(p[4])))

# Events from the node's own stdout, each already stamped with epoch seconds.
events = []            # (t, kind, done, slot, text)
prog = re.compile(r"replay (\d+)/(\d+) \(([\d.]+)%\) — head slot (\d+), ([\d.]+) blocks/s")
with open(outf) as f:
    for l in f:
        t, _, text = l.partition("\t")
        try: t = float(t)
        except ValueError: continue
        text = text.rstrip("\n")
        m = prog.search(text)
        if m:
            events.append((t, "progress", int(m.group(1)), int(m.group(4)), text))
        elif text.startswith("carryover:"):
            events.append((t, "carryover", None, None, text))
        elif text.startswith("observer mode:"):
            events.append((t, "observer", None, None, text))
        elif text.startswith("bloch-pos node —"):
            events.append((t, "boot", None, None, text))
        elif text.startswith("replaying "):
            events.append((t, "replay_start", 0, None, text))
        elif text.startswith("replayed "):
            m2 = re.search(r"replayed (\d+) blocks: head slot (\d+), state root (\w+)", text)
            events.append((t, "replay_end", int(m2.group(1)) if m2 else None,
                           int(m2.group(2)) if m2 else None, text))
        elif text.startswith("signatures:") or text.startswith("STOP"):
            events.append((t, "post", None, None, text))

if not samples:
    sys.exit("no samples")
t0 = samples[0][0]
mib = lambda kb: kb / 1024.0

ts = [s[0] for s in samples]
def at(t):
    i = bisect.bisect_left(ts, t)
    i = min(range(max(0, i-1), min(len(ts), i+2)), key=lambda j: abs(ts[j]-t))
    return samples[i]

print("=== EVENTS (t = seconds since first sample) ===")
for t, kind, done, slot, text in events:
    s = at(t)
    print("  %8.2fs  %-12s  rss=%8.1f MiB  hwm=%8.1f MiB  | %s"
          % (t-t0, kind, mib(s[1]), mib(s[2]), text[:96]))

peak = max(samples, key=lambda s: s[1])
last = samples[-1]
final_hwm = max(s[2] for s in samples)
print()
print("=== PEAK / END ===")
print("  samples                    : %d over %.1f s (period ~%.3f s)"
      % (len(samples), ts[-1]-t0, (ts[-1]-t0)/max(1, len(samples)-1)))
print("  peak VmRSS                 : %.1f MiB at t=%.2fs" % (mib(peak[1]), peak[0]-t0))
print("  max VmHWM seen             : %.1f MiB" % mib(final_hwm))
print("  last sampled VmRSS         : %.1f MiB at t=%.2fs" % (mib(last[1]), last[0]-t0))

# RSS at end of replay
end = [e for e in events if e[1] == "replay_end"]
if end:
    et = end[0][0]
    s = at(et)
    print("  VmRSS at end-of-replay     : %.1f MiB (t=%.2fs, height %s, slot %s)"
          % (mib(s[1]), et-t0, end[0][2], end[0][3]))
    print("  end-of-replay vs VmHWM     : %+.1f MiB (%+.2f%%)"
          % (mib(s[1]) - mib(final_hwm), 100.0*(s[1]-final_hwm)/final_hwm))
    print("  peak is at %.1f%% of the replay wall clock"
          % (100.0*(peak[0]-t0)/max(1e-9, et-t0)))

# Monotonicity: how far does RSS ever fall below a running max?
run = 0; worst = 0; worst_t = None
for t, rss, hwm, ma, la in samples:
    if rss > run: run = rss
    d = run - rss
    if d > worst: worst, worst_t = d, t
print()
print("=== MONOTONICITY ===")
print("  largest drawdown below running max : %.1f MiB at t=%.2fs"
      % (mib(worst), (worst_t-t0) if worst_t else 0))
print("  peak occurs at sample %d of %d (%.1f%% through the run)"
      % (samples.index(peak)+1, len(samples), 100.0*(samples.index(peak)+1)/len(samples)))
print("  VERDICT: %s" % ("MONOTONE (peak is at/near the end; no transient exceeds the tail)"
      if peak[0] >= ts[-1] - 5 or mib(worst) < 5 else
      "NOT MONOTONE — an earlier transient exceeds the tail by %.1f MiB" % mib(worst)))

# Phase decomposition: RSS delta attributable to each boot phase.
print()
print("=== BOOT PHASES (RSS at each marker; delta = cost of the phase that ENDED there) ===")
order = ["carryover", "observer", "boot", "replay_start", "replay_end"]
label = {"carryover":"ingest_carryover (452,726-output snapshot)",
         "observer":"keystore probe",
         "boot":"Store::open + manifest.genesis_state() + genesis_state.state_root()",
         "replay_start":"Store::count (seek-only frame walk)",
         "replay_end":"the 29,377-block replay itself"}
prev_rss = samples[0][1]; prev_t = t0
print("  %10s  %10s  %10s   %s" % ("t_s", "VmRSS_MiB", "d_MiB", "phase that ended here"))
print("  %10.2f  %10.1f  %10s   %s" % (0.0, mib(samples[0][1]), "-", "first sample after exec"))
for k in order:
    e = [x for x in events if x[1] == k]
    if not e: continue
    t = e[0][0]; s_ = at(t)
    print("  %10.2f  %10.1f  %+10.1f   %s" % (t-t0, mib(s_[1]), mib(s_[1]-prev_rss), label[k]))
    prev_rss = s_[1]; prev_t = t

# VmHWM is monotone non-decreasing and is the kernel's own high-water mark.
# Every STEP in it says "a new peak happened in this sample interval" — which
# localises the peak far better than VmRSS sampling, that can stride over a
# short spike entirely.
print()
print("=== VmHWM STEPS — where the peak actually happened ===")
def height_at(t):
    """Height the node last reported at or before t."""
    h = None; sl = None
    for et, kind, done, slot, _ in events:
        if et <= t and kind in ("replay_start", "progress", "replay_end"):
            h, sl = done, slot
    return h, sl
prev = samples[0][2]; steps = []
for i, (t, rss, hwm, ma, la) in enumerate(samples):
    if hwm > prev:
        steps.append((t, hwm - prev, hwm, rss, samples[i-1][0] if i else t))
        prev = hwm
print("  %8s  %9s  %10s  %10s  %10s  %s" % ("t_s", "step_MiB", "VmHWM_MiB", "VmRSS_MiB", "gap_MiB", "height/slot at that moment"))
for t, d, hwm, rss, pt in steps:
    h, sl = height_at(t)
    print("  %8.2f  %+9.2f  %10.1f  %10.1f  %10.1f  %s / %s"
          % (t-t0, mib(d), mib(hwm), mib(rss), mib(hwm-rss),
             h if h is not None else "pre-replay", sl if sl is not None else "-"))
print("  (%d steps; the last step is the run's true peak)" % len(steps))
tot = sum(d for _, d, _, _, _ in steps)
print("  total VmHWM climb after first sample: %.1f MiB" % mib(tot))

# Contamination
print()
print("=== BOX HYGIENE DURING THE RUN ===")
print("  loadavg1  min/max : %.2f / %.2f" % (min(s[4] for s in samples), max(s[4] for s in samples)))
print("  MemAvailable min  : %.0f MiB (start %.0f MiB)"
      % (mib(min(s[3] for s in samples)), mib(samples[0][3])))

# The curve, decimated to one row per progress report
print()
print("=== CURVE (wall, height, slot, VmRSS, VmHWM) ===")
print("  %8s  %8s  %8s  %10s  %10s" % ("t_s", "height", "slot", "VmRSS_MiB", "VmHWM_MiB"))
rows = [e for e in events if e[1] in ("carryover", "observer", "boot", "replay_start", "progress", "replay_end")]
for t, kind, done, slot, text in rows:
    s = at(t)
    print("  %8.2f  %8s  %8s  %10.1f  %10.1f"
          % (t-t0, done if done is not None else "-", slot if slot is not None else "-",
             mib(s[1]), mib(s[2])))
if timef:
    print()
    print("=== /usr/bin/time -v ===")
    for l in open(timef):
        if re.search(r"Maximum resident|Elapsed \(wall|Minor|Major|Exit status", l):
            print("  " + l.strip())
