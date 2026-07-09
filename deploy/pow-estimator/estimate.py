#!/usr/bin/env sage-python
"""Estimate the hardness of Bloch-SIS PoW parameter candidates.

Runs the lattice-estimator (malb/lattice-estimator) core-SVP model over the
Module-SIS / ISIS instance behind the PoW, and prints a table of the trivial-
regime flag (sqrt(m)*beta/q) and log2(attack cost). See docs/specs/POW-HARDNESS.md
for the analysis this operationalizes.

Run:  sage -python estimate.py            (from a lattice-estimator checkout)
  or:  docker run --rm bloch-pow-estimator (see README.md)

NOTE: the estimator's SIS module is homogeneous (find short x with A·x=0); the PoW
is *inhomogeneous* (A·s ≈ t within β), which is BDD/approx-CVP. Modeling it as
infinity-norm SIS with length_bound=β is the first-order proxy the analysis calls
for; treat the numbers as a screen, not a final proof, and cross-check the
inhomogeneous/BDD framing (estimator LWE module) before freezing parameters.
The estimator API drifts across versions — adjust the SIS.Parameters/estimate
calls to the version you install.
"""
from math import log2, sqrt

try:
    from sage.all import oo
except Exception:
    oo = float("inf")

from estimator import SIS

Q = 8380417  # Dilithium/ML-DSA modulus, q = 2^23 - 2^13 + 1

# (label, n, m, beta) — beta is the infinity-norm residual bound.
CANDIDATES = [
    ("current",        256,  512, Q // 16),                    # expect TRIVIAL
    ("beta=q/32",      256,  512, Q // 32),
    ("beta<q/sqrt(m)", 256,  512, int(Q / sqrt(512)) - 1),     # just below trivial
    ("bigger 512",     512, 1024, Q // 64),
    ("bigger 1024",   1024, 2048, Q // 128),
]


def _rop_of(v):
    """Extract the `rop` (attack cost) from an estimator Cost — dict-like in the
    current lattice-estimator (`v["rop"]`), attribute in older ones (`v.rop`)."""
    try:
        return float(v["rop"])
    except Exception:
        r = getattr(v, "rop", None)
        try:
            return float(r) if r is not None else None
        except Exception:
            return None


def cost_bits(n, m, beta):
    """log2 of the cheapest estimated attack, or nan if the estimator errors."""
    try:
        params = SIS.Parameters(n=n, q=Q, length_bound=beta, m=m, norm=oo)
        est = SIS.estimate(params)
        rops = [r for r in (_rop_of(v) for v in est.values()) if r is not None]
        return log2(min(rops)) if rops else float("nan")
    except Exception as exc:  # noqa: BLE001 — surface, don't crash the sweep
        print(f"    ! estimate failed for (n={n},m={m},beta={beta}): {exc}")
        return float("nan")


def main():
    print(f"q = {Q}  (2^23 - 2^13 + 1)\n")
    print(f"{'label':16} {'n':>5} {'m':>6} {'beta':>10} {'√m·β/q':>8} {'log2(rop)':>10}  note")
    print("-" * 68)
    for label, n, m, beta in CANDIDATES:
        trivial = sqrt(m) * beta / Q
        bits = cost_bits(n, m, beta)
        note = "TRIVIAL q-ary regime" if trivial >= 1 else ("< 128-bit" if bits < 128 else "ok")
        print(f"{label:16} {n:>5} {m:>6} {beta:>10} {trivial:>8.2f} {bits:>10.1f}  {note}")
    print("\nTarget: √m·β/q < 1 (out of trivial regime) AND log2(rop) >= 128.")


if __name__ == "__main__":
    main()
