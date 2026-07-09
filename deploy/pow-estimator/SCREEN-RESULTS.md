# PoW parameter screen — results + gate status

A durable, reproducible record of the first-order parameter screen
(`screen.py`, pure Python, no Sage). It **narrows** candidates; it does **not**
set bit-security. See `docs/specs/POW-HARDNESS.md` for the full analysis.

Reproduce: `python3 deploy/pow-estimator/screen.py`

## Screen output (`q = 8380417`, the ML-DSA modulus)

```
label                  n  k(m)   B      beta sqrt(k)b/q  work_b  feas_b  verdict
------------------------------------------------------------------------------------------------------------
current (full m)     256   512   2    523776       1.41  1536.0    -942  TRIVIAL (BKZ q-vectors satisfy bound)
testnet k=8          256     8   2    523776       0.18    24.0     570  WINDOW (non-trivial + feasible + tunable) -> estimator
k=2 b=q/8            256     2   2   1047552       0.18     4.0     590  WINDOW (non-trivial + feasible + tunable) -> estimator
k=4 b=q/8            256     4   2   1047552       0.25     8.0     586  WINDOW (non-trivial + feasible + tunable) -> estimator
k=6 b=q/16           256     6   2    523776       0.15    18.0     576  WINDOW (non-trivial + feasible + tunable) -> estimator
k=8 b=q/16           256     8   2    523776       0.18    24.0     570  WINDOW (non-trivial + feasible + tunable) -> estimator
k=12 b=q/32          256    12   2    261888       0.11    48.0     546  WINDOW (non-trivial + feasible + tunable) -> estimator
```

## What the screen establishes (and what it does NOT)

- **The full-m regime is TRIVIAL** — `√m·β/q = 1.41 ≥ 1`, so BKZ's q-ary vectors
  already satisfy the ∞-norm bound: a valid PoW solution exists **with no work**.
  This is exactly why the current testnet regime is **zero-security by design**.
- **The small-k rows escape the trivial regime** (`√k·β < q`) and are feasible +
  tunable — the viable design shape.
- The screen does **not** output attack bit-security. It only rejects params that
  are trivial or infeasible.

## Two security models — do not conflate them

There are **two distinct designs**, with **different** security arguments (per
`docs/specs/POW-HARDNESS.md`):

1. **Small-k + leading-zeros (the viable shape).** The PoW *difficulty* comes from
   a separate **leading-zeros hash threshold** (Bitcoin-style, freely tunable),
   **not** from lattice hardness. The Module-SIS part supplies post-quantum,
   ASIC-unfriendly *structure*; its only security requirement is the
   **non-trivial** condition above (`√k·β < q`), which the screen checks. It would
   be **wrong to attach a "core-SVP bit-security" number to these rows** — their
   work is hash-based, not lattice-based. Remaining gate: calibrate the
   leading-zeros threshold + a proof that the SIS substrate adds no shortcut.
2. **Canonical full-m (lattice-hardness = mining work).** Here the SIS hardness
   *is* the work — and it needs the **Sage lattice-estimator** (BKZ core-SVP, plus
   the two-step reduce-then-search model, and the **inhomogeneous/BDD** cross-check
   since the PoW is `A·s ≈ t`, not `A·s = 0`). The screen shows the full-m regime
   is trivial at these β; a canonical design would need different (n, m, β), and
   its bit-security is **not** decided here.

## Gate status (honest)

- ✅ Screened: trivial-regime + feasibility (this file, reproducible).
- ⏳ **Not done here** (needs SageMath + the lattice-estimator, which don't run in
  this environment): per-instance BKZ core-SVP on any canonical candidate; the
  inhomogeneous/BDD framing cross-check; the two-step-attack cost.
- ⏳ Leading-zeros difficulty calibration for the small-k design.
- ⏳ Third-party audit + an ePrint write-up.
- 🔴 Until all of the above: **zero-security testnet, no mainnet claim, no value.**

No bit-security number is asserted in this file — by design. A hand-computed
core-SVP figure (especially for the small-k rows, whose security is *not* lattice
hardness) would misrepresent the model; the Sage estimator + audit are the gate.

---

## Sage lattice-estimator run (2026-07-09) — real core-SVP numbers

The estimator (`estimate.py` via SageMath + `malb/lattice-estimator`, `docker run`)
now actually runs. Real BKZ core-SVP `log2(rop)` for the ∞-norm SIS proxy:

```
label                n      m       beta   √m·β/q  log2(rop)  note
--------------------------------------------------------------------
current            256    512     523776     1.41       42.5  TRIVIAL q-ary regime
beta=q/32          256    512     261888     0.71       43.0  < 128-bit
beta<q/sqrt(m)     256    512     370364     1.00       43.0  < 128-bit
bigger 512         512   1024     130944     0.50       88.2  < 128-bit
bigger 1024       1024   2048      65472     0.35      201.8  >=128 but UNMINEABLE
```

**What it establishes (honestly):**
- **Current testnet params (n=256, m=512, β=q/16) = 42.5 bits** → trivially
  forgeable, confirming "zero-security testnet" with a hard number.
- **Full-M has NO usable window.** As β shrinks to escape the trivial regime the
  cost jumps straight past mineable into the unusable: n=1024/β=q/128 reaches
  ~202 bits — but a PoW has **no trapdoor**, so 2^202 to *attack* is also 2^202 to
  *mine*. Secure ⇒ unmineable; mineable ⇒ trivial. This is exactly the tension the
  screen predicted.
- **⇒ The canonical design is confirmed to be small-k + leading-zeros**, not
  full-M: the Module-SIS supplies a *non-trivial* (√k·β<q), ASIC-unfriendly,
  post-quantum substrate — cheap to solve (underdetermined) — while a **leading-
  zeros hash threshold** supplies the tunable, mineable difficulty (Bitcoin-style).
  The SIS security requirement collapses to non-triviality + a no-shortcut argument,
  NOT a 128-bit lattice wall.

**Still open (the honest remainder of G1→mainnet):** a formal security argument for
the small-k + leading-zeros construction (non-triviality bound + proof the SIS adds
no shortcut to the hash grind); the **inhomogeneous/BDD** cross-check (this is the
homogeneous ∞-SIS proxy); the two-step (reduce-then-search) refinement; an ePrint
write-up; and third-party audit. But the estimator gate is now *run*, reproducible,
and its verdict is unambiguous — full-M is a dead-end; small-k + leading-zeros is
the path.
