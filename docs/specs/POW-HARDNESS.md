# Module-SIS PoW — hardness analysis (S1)

> **Status update (2026-07) — goal superseded.** The follow-up frontier
> research (`docs/research/POW-CANONICAL-frontier.md`, dense estimator sweep)
> established that the target this file works toward — a *mineable* instance
> with a ≥2^100/2^128 lattice no-shortcut margin — **does not exist and cannot
> exist for a trapdoorless PoW**: with no trapdoor, the core-SVP cost is both
> the attack cost and the honest mining cost, and the sweep shows the secure
> and mineable regimes are disjoint (every ≥100-bit point has no short `s` at
> all; every mineable point is trivial). The viable design is the one §"First-
> order screen" already points at — **small-`k` residual gate + a separate
> leading-zeros hashcash knob** — whose honest security claim is **cumulative
> SHAKE-256 hash work** (post-quantum via Grover's quadratic bound), with the
> Module-SIS residual as a non-trivial *structural* gate, **not** a lattice
> bit-security wall. This file remains as the S1 analysis that motivated the
> screen and the sweep; read its "target ~2^128 margin" language as the
> historical goal, not the current claim.

Findings from a fact-checked survey (IACR ePrint, the lattice-estimator, FIPS
204) on whether the Bloch-SIS PoW parameters are hard, and how to fix them. This
is the **mainnet security gate**: the testnet regime is forgeable by design; the
question here is whether the *canonical* instance is actually hard.

## The problem, classified

The PoW — hash the header into `A ∈ Z_q^{m×n}` and `t ∈ Z_q^m`, find `s` with
`||s||_∞ ≤ B` such that `||A·s − t||_∞ < β` — is **Inhomogeneous-SIS (ISIS)**,
solved as **Bounded-Distance-Decoding / approximate-CVP**. The complete attack
toolkit:

- **primal BKZ embedding** (Kannan: BDD → unique-SVP, then reduce),
- **dual / SIS distinguishing** in the scaled dual lattice,
- **post-reduction decoding** (Babai nearest-plane → Lindner–Peikert → pruned
  enumeration / sieving).

Cost is estimated with the **lattice-estimator core-SVP** model:
`2^(0.292·β)` classical, `2^(0.265·β)` quantum, for BKZ blocksize β — using the
**two-step** model (reduce, then search), which beats BKZ alone.

## 🔴 The current parameters are very likely broken

Current: `n=256, m=512, q=8380417 (≈2^23), B=2, β=q/16 ≈ 523776`.

**Estimator hardness is a direct function of how loose the norm bound is** — a
looser bound needs a smaller, easier BKZ blocksize. For infinity-norm bounds the
estimator has a **trivial q-ary regime**: once `√m · β ≥ q`, the q-vectors BKZ
already produces satisfy the bound, so a valid `s` is found by lattice reduction
**with no PoW work at all**.

```
√m · β  =  √512 · (q/16)  ≈  22.6 · q/16  ≈  1.41·q  ≥  q      ← in the trivial regime
```

So **β = q/16 is too large**. To even leave the trivial regime you need

```
β  <  q / √m          (for m=512:  β < q/22.6 ≈ 0.044·q)
```

and even below that threshold the concrete blocksize must be estimated — being
out of the trivial regime is necessary, not sufficient.

**Dimension is also too small.** B=2 is fine on its own (it is exactly η in
ML-DSA-44/87 at the same q), but ML-DSA's security comes from a **large effective
dimension (~1024–2048)**, not from the ±2 bound. A plain `256×512` matrix is
small; the PoW must be **independently sized** for its target hardness, not
assumed secure because it reuses B=2 and q from Dilithium.

> No published source ran the estimator on this exact instance — so the number
> above is a red flag, not a proof. The next step produces the real numbers.

## Design fixes

1. **Separate the difficulty knob from the security bound.** β sets the *hardness
   floor* (the no-shortcut margin); it must **not** double as the difficulty
   knob. Tune difficulty with an independent **target-prefix / leading-zeros
   threshold** on `H(s)` (hashcash-style), so difficulty adjusts smoothly without
   ever pushing β into the trivial regime.
2. **Pick β below the trivial threshold** (`β < q/√m`) and then size `(n, m, q)`
   so the estimated blocksize gives the target ~2^128 classical no-shortcut
   margin. Expect `n` and/or `m` to grow beyond `256/512`. *(Superseded: the
   frontier sweep proved every such point is unmineable — no short `s` exists.
   See the status banner above.)*
3. **Keep A unstructured** (already the case): per-nonce `(A,t)` from SHAKE makes
   the PoW progress-free (hashcash-like) and blocks cross-nonce precomputation for
   random lattices — a heuristic "no known advice" argument, adequate for a PoW.
   Power-of-two-cyclotomic module speedups do **not** apply here.

## First-order screen (no Sage) — the design tension, quantified

`deploy/pow-estimator/screen.py` computes three quantities analytically (pure
Python), enough to reject broken params before the Sage run:

- **trivial regime:** `√k·β / q` (want ≪ 1), where `k` = residual coords checked;
- **PoW work:** `k · log2(q / 2β)` bits (brute-force tries to hit all k coords);
- **feasibility:** `n·log2(2B+1) ≥ work` (the s-space must contain a solution).

Running it exposes a structural tension:

```
label               n  k(m)  B     beta  √k·β/q  work_b  feas_b  verdict
current (full m)  256   512  2   q/16     1.41    1536    -942   TRIVIAL
testnet k=8       256     8  2   q/16     0.18      24     570   WINDOW
k=4 b=q/8         256     4  2   q/8      0.25       8     586   WINDOW
k=12 b=q/32       256    12  2   q/32     0.11      48     546   WINDOW
```

**PoW work `= k·log2(q/2β)` grows fast in `k`, while escaping the trivial regime
needs `√k·β < q`.** At the full `m = 512` there is NO usable window — the design
is either trivial (large β) or astronomically hard / infeasible (small β). The
current `(m=512, β=q/16)` is both trivial for lattice reduction AND has no small-s
solution: broken in both directions.

**The viable shape is a SMALL number of checked coordinates `k` plus a separate
leading-zeros difficulty threshold** (β sets the security floor, leading-zeros
tunes difficulty smoothly). The small-`k` candidates above sit in the window
(non-trivial, feasible, tunable base work). This is *screening only* — the
per-instance BKZ core-SVP bit-security of the small-`k` lattice still must be
confirmed with the Sage estimator before freezing (a small-`k` instance could
still be lattice-shortcut below its brute-force work).

## The concrete next step — run the estimator

The lattice-estimator ships an **infinity-norm Module-SIS example at the identical
q = 8380417**, so it applies directly. Model the ISIS instance and sweep:

```python
# lattice-estimator (github: malb/lattice-estimator), run in Sage
from estimator import SIS
from estimator.nd import NoiseDistribution

# Model: find s (||s||_inf ≤ B) with ||A·s − t||_inf < β.
# As an ∞-norm SIS/BDD, length_bound = β, norm = ∞ (oo). Sweep β and dims.
for (n, m, beta) in [(256, 512, 8380417//16),      # current — expect "trivial"
                     (256, 512, 8380417//32),
                     (512, 1024, 8380417//64),
                     (1024, 2048, 8380417//128)]:
    p = SIS.Parameters(n=n, q=8380417, length_bound=beta, m=m, norm=oo)
    print(n, m, beta, SIS.estimate(p))   # look at rop (log2 attack cost)
```

Deliverables of the run:
- confirm `(256,512,q/16)` is trivial / sub-target;
- the `(n, m, β)` set whose `log2(rop) ≥ 128` (classical), with a feasibility
  check (a valid `s` exists with non-negligible probability);
- verification cost of that set (must stay cheap — one `A·s` + norm check).

Then: flip the node default to the canonical regime with the chosen params, and
write the ePrint-style parameter rationale.

## Prior art

The main academic lattice PoW — **LPoW (ePrint 2020/1362, INDOCRYPT-DPM 2021)** —
is a *different* problem: α-Hermite-**SVP** in the **Euclidean** norm on
Goldstein–Mayer random lattices (find any nonzero `v` with `||v|| ≤ α·det^{1/n}`,
no target, no ∞-bound), difficulty tuned by dimension `n` (suggests `n ≥ 150` to
match Bitcoin), core-SVP cost `2^0.292n`. No deployed chain uses the ISIS
"`A·s ≈ t` within β" framing; there is no external security verdict for it — so
Bloch-SIS must produce its own estimate and, ultimately, an audit.

## Sources (primary)

- Albrecht–Player–Scott, *Concrete hardness of LWE*, ePrint 2015/046 (attack
  taxonomy: BDD-decoding, Kannan embedding, dual).
- lattice-estimator (malb/lattice-estimator) — SIS ∞-norm regime split
  `√m·bound ≶ q`; ships a Module-SIS ∞-norm example at q=8380417.
- FIPS 204 (ML-DSA) — frames short-vector finding as (M)SIS; B=2 = η rationale.
- ePrint 2020/1540 — two-step (reduce + search) is more efficient than BKZ alone.
- LPoW, ePrint 2020/1362 — the Euclidean-Hermite-SVP lattice PoW (prior art).
