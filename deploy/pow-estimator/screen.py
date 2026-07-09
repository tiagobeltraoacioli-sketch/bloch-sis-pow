#!/usr/bin/env python3
"""First-order PoW parameter SCREEN (pure Python, no Sage).

Two analytic constraints from the S1 analysis, computable without the lattice-
estimator — used to NARROW candidates before the (Sage) core-SVP run:

  1. trivial q-ary regime:  sqrt(m)*beta/q  — want << 1, else BKZ's q-vectors
     already satisfy the infinity-norm bound (a valid vector with no PoW work).

  2. feasibility (small-s solutions exist): expected count of s in {-B..B}^n with
     ||A*s - t||_inf < beta, heuristic (A,t uniform, coords independent):
        log2 E[#s] = n*log2(2B+1) + m*log2(2*beta/q)
     A canonical full-m check needs this comfortably > 0 (solutions exist) but
     bounded (difficulty tunable). The relaxed testnet checks only k coords, so
     its feasibility uses k, not m — which is exactly why testnet mines while the
     full-m check at beta=q/16 does NOT (see below).

This screen does NOT give the attack bit-security (that needs the Sage estimator /
BKZ core-SVP). It only rejects params that are trivial or infeasible.
"""
import math

Q = 8380417  # Dilithium/ML-DSA modulus


def screen(n, m, B, beta):
    trivial = math.sqrt(m) * beta / Q
    # Brute-force PoW work = expected tries to hit all m coords in (-beta,beta):
    #   work_bits = m * log2(q / (2*beta))
    work_bits = m * math.log2(Q / (2 * beta))
    # Feasibility: the s-space must be big enough to contain a solution:
    #   n*log2(2B+1) >= work_bits.  (log2 E[#s] = space - work_bits.)
    log2_sols = n * math.log2(2 * B + 1) - work_bits
    return trivial, work_bits, log2_sols


def verdict(trivial, work_bits, log2_sols):
    if trivial >= 1:
        return "TRIVIAL (BKZ q-vectors satisfy bound)"
    if log2_sols < 0:
        return "INFEASIBLE (space too small for a solution)"
    if not (4 <= work_bits <= 64):
        return f"work {work_bits:.0f}b out of a tunable range"
    return "WINDOW (non-trivial + feasible + tunable) -> estimator"


CANDIDATES = [
    # (label, n, m, B, beta)  — m = number of residual coords actually checked
    ("current (full m)",  256,  512, 2, Q // 16),
    ("testnet k=8",       256,    8, 2, Q // 16),
    # Small-k designs: few checked coords + a separate leading-zeros difficulty
    # knob. Escape trivial (sqrt(k)*beta<q) with tunable work.
    ("k=2 b=q/8",         256,    2, 2, Q // 8),
    ("k=4 b=q/8",         256,    4, 2, Q // 8),
    ("k=6 b=q/16",        256,    6, 2, Q // 16),
    ("k=8 b=q/16",        256,    8, 2, Q // 16),
    ("k=12 b=q/32",       256,   12, 2, Q // 32),
]


def main():
    print(f"q = {Q}\n")
    print(f"{'label':18} {'n':>5} {'k(m)':>5} {'B':>3} {'beta':>9} {'sqrt(k)b/q':>10} {'work_b':>7} {'feas_b':>7}  verdict")
    print("-" * 108)
    for label, n, m, B, beta in CANDIDATES:
        t, w, s = screen(n, m, B, beta)
        print(f"{label:18} {n:>5} {m:>5} {B:>3} {beta:>9} {t:>10.2f} {w:>7.1f} {s:>7.0f}  {verdict(t, w, s)}")
    print("\nKey tension: PoW work = k*log2(q/2beta) grows fast in k, while escaping"
          "\nthe trivial regime needs sqrt(k)*beta < q. Large m has NO usable window"
          "\n(trivial OR astronomically hard). The viable shape is SMALL k + a separate"
          "\nleading-zeros difficulty threshold. Feed WINDOW rows to the Sage estimator"
          "\nfor the per-instance BKZ core-SVP bit-security before freezing.")


if __name__ == "__main__":
    main()
