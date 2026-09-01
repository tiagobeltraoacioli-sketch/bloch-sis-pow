# Sample VmRSS/VmHWM of a pid on a fixed cadence until it exits.
# Also samples MemAvailable so contamination by another process is visible.
import sys, time, os
pid = sys.argv[1]; out = sys.argv[2]; period = float(sys.argv[3])
st = "/proc/%s/status" % pid
def rd():
    rss = hwm = None
    with open(st) as f:
        for l in f:
            if l.startswith("VmRSS:"):  rss = int(l.split()[1])
            elif l.startswith("VmHWM:"): hwm = int(l.split()[1])
            if rss is not None and hwm is not None: break
    return rss, hwm
def memavail():
    with open("/proc/meminfo") as f:
        for l in f:
            if l.startswith("MemAvailable:"): return int(l.split()[1])
    return -1
with open(out, "w") as o:
    o.write("epoch\tvmrss_kb\tvmhwm_kb\tmemavail_kb\tloadavg1\n")
    nxt = time.time()
    while True:
        try:
            rss, hwm = rd()
        except (IOError, OSError):
            break
        if rss is None: break
        la = open("/proc/loadavg").read().split()[0]
        o.write("%.3f\t%d\t%d\t%d\t%s\n" % (time.time(), rss, hwm, memavail(), la))
        o.flush()
        nxt += period
        d = nxt - time.time()
        if d > 0: time.sleep(d)
        else: nxt = time.time()
