#!/usr/bin/env sage-python
"""Extended Bloch-SIS PoW frontier sweep.

Maps the hardness (core-SVP log2 rop, infinity-norm SIS proxy) AND the
mineability (feasibility: does a small-s solution exist) across (n, m, beta),
to locate 100/128-bit crossings and demonstrate the secure<->mineable tension.

Run inside the estimator container (mount over /opt/lattice-estimator/sweep.py).
"""
from math import log2, sqrt

try:
    from sage.all import oo
except Exception:
    oo = float("inf")

from estimator import SIS

Q = 8380417  # ML-DSA modulus, q = 2^23 - 2^13 + 1
B = 2        # infinity-norm bound on s


def rop_of(v):
    try:
        return float(v["rop"])
    except Exception:
        r = getattr(v, "rop", None)
        try:
            return float(r) if r is not None else None
        except Exception:
            return None


def core_svp(n, m, beta):
    try:
        params = SIS.Parameters(n=n, q=Q, length_bound=beta, m=m, norm=oo)
        est = SIS.estimate(params)
        rops = [r for r in (rop_of(v) for v in est.values()) if r is not None]
        return log2(min(rops)) if rops else float("nan")
    except Exception as exc:
        return float("nan")


def feas_bits(n, m, beta):
    # log2 E[#s]  with s in {-B..B}^n, residual coords independent uniform:
    #   = n*log2(2B+1) + m*log2(2*beta/q)
    return n * log2(2 * B + 1) + m * log2(2 * beta / Q)


def row(label, n, m, beta):
    trivial = sqrt(m) * beta / Q
    bits = core_svp(n, m, beta)
    feas = feas_bits(n, m, beta)
    mine = "mineable" if feas >= 0 else "UNMINEABLE"
    note = "TRIVIAL" if trivial >= 1 else ""
    print(f"{label:22} {n:>5} {m:>6} {beta:>9} {trivial:>7.2f} {bits:>9.1f} {feas:>9.0f}  {mine} {note}")


def main():
    print(f"q = {Q}   B = {B}   (full-M lattice-hardness-as-work model)\n")
    print(f"{'label':22} {'n':>5} {'m':>6} {'beta':>9} {'sqm.b/q':>7} {'core-SVP':>9} {'feas_b':>9}  mineability")
    print("-" * 96)

    # Baselines
    row("current q/16",       256,  512, Q // 16)
    row("q/32",               256,  512, Q // 32)
    row("q/64",               256,  512, Q // 64)

    # n=256 frontier: shrink beta
    for d in (24, 32, 48, 64, 96, 128):
        row(f"n256 q/{d}",     256,  512, Q // d)

    # n=512 frontier
    for d in (32, 48, 64, 96, 128, 192, 256):
        row(f"n512 q/{d}",     512, 1024, Q // d)

    # n=768 frontier
    for d in (64, 96, 128, 192, 256, 384):
        row(f"n768 q/{d}",     768, 1536, Q // d)

    # n=1024 frontier
    for d in (96, 128, 192, 256, 384, 512):
        row(f"n1024 q/{d}",   1024, 2048, Q // d)

    print("\nRead: core-SVP is BOTH the attack cost and (no trapdoor) the honest")
    print("mining cost. 'feas_b>=0' means a small-s solution exists at all. A row")
    print("that is secure (core-SVP high) AND mineable requires a trapdoor we do")
    print("not have; expect them to be mutually exclusive.")


if __name__ == "__main__":
    main()
