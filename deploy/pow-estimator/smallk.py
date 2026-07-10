#!/usr/bin/env sage-python
"""Small-k substrate probe + feasibility-crossing check.

(1) What does the estimator say about the SMALL-k checked instance itself
    (k rows of A, n=256 cols)? Expected: trivially weak as a lattice problem
    (underdetermined) -> its security is NOT lattice hardness but the hash.
(2) The feasibility crossing for full-M: solve for the beta at which a small-s
    solution first exists, and show it lands deep in the trivial regime.
"""
from math import log2, sqrt

try:
    from sage.all import oo
except Exception:
    oo = float("inf")

from estimator import SIS

Q = 8380417
B = 2


def rop_of(v):
    try:
        return float(v["rop"])
    except Exception:
        r = getattr(v, "rop", None)
        return float(r) if r is not None else None


def core_svp(n, m, beta):
    try:
        params = SIS.Parameters(n=n, q=Q, length_bound=beta, m=m, norm=oo)
        est = SIS.estimate(params)
        rops = [r for r in (rop_of(v) for v in est.values()) if r is not None]
        return log2(min(rops)) if rops else float("nan")
    except Exception as exc:
        return f"ERR {exc}"


print("== (1) small-k checked instance as a lattice problem ==")
print("   (estimator convention: n_est = #constraints = k rows, m_est = solution dim = 256)")
print(f"{'label':16} {'k':>4} {'sdim':>5} {'beta':>9} {'sqk.b/q':>7}  core-SVP")
for (k, sdim, beta) in [(4, 256, Q // 8), (8, 256, Q // 16), (12, 256, Q // 32),
                        (16, 256, Q // 16), (32, 256, Q // 16), (64, 256, Q // 16)]:
    triv = sqrt(k) * beta / Q
    print(f"k{k:<3}b{beta:<9} {k:>4} {sdim:>5} {beta:>9} {triv:>7.2f}  {core_svp(k, sdim, beta)}")

print("\n== (2) full-M feasibility crossing (m = 2n) ==")
# log2 E[#s] = n*log2(5) + m*log2(2beta/q) >= 0  with m=2n
#  => log2(5)/2 >= log2(q/2beta) => q/2beta <= sqrt(5) => beta >= q/(2*sqrt(5))
crossing = Q / (2 * sqrt(5))
print(f"beta where a small-s full-M solution first exists: beta >= q/(2*sqrt5) = {crossing:.0f}")
print(f"  = q/{Q/crossing:.2f}   ->  sqrt(m)*beta/q at m=1024: {sqrt(1024)*crossing/Q:.1f}  (>>1 = deep TRIVIAL)")
print("  => full-M is mineable ONLY when it is trivially insecure. No window.")
