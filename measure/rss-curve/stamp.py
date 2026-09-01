import sys, time
for line in sys.stdin:
    sys.stdout.write("%.3f\t%s" % (time.time(), line))
    sys.stdout.flush()
