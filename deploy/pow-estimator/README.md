# PoW hardness estimator

> **Historical — Genesis-3.** This screens the parameters of the Module-SIS
> lattice proof of work used by the chain that stopped permanently at height
> 39,918 on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s
> slots, 32-slot epochs, finality by epoch) — it does no proof of work at all,
> so no number produced here bears on the security of what runs today. Kept as
> part of the Genesis-3 record.

Turns the S1 analysis (`docs/specs/POW-HARDNESS.md`) into runnable numbers: a
SageMath + lattice-estimator container that prints, for each PoW parameter
candidate, the trivial-regime flag (`√m·β/q`) and `log2(attack cost)`.

## Run

```bash
# from the repo root (Dockerfile COPYs deploy/pow-estimator/estimate.py)
docker build -t bloch-pow-estimator -f deploy/pow-estimator/Dockerfile .
docker run --rm bloch-pow-estimator
```

Expected shape of the output:

```
label              n      m       beta   √m·β/q  log2(rop)  note
current          256    512     523776     1.41       ...   TRIVIAL q-ary regime
beta=q/32        256    512     261888     0.71       ...   ...
...
Target: √m·β/q < 1 (out of trivial regime) AND log2(rop) >= 128.
```

The `current` row is expected to flag **TRIVIAL** — confirming the analysis that
`β = q/16` is too loose. Read the first candidate whose `√m·β/q < 1` **and**
`log2(rop) ≥ 128` as a starting canonical set, then refine.

## Iterating

Edit the `CANDIDATES` list in `estimate.py` and re-run. Two knobs matter:

- **β** must satisfy `√m·β < q` (out of the trivial regime) — necessary, not
  sufficient; the estimated `log2(rop)` must then reach the target.
- **(n, m)** likely need to grow beyond 256/512 (ML-DSA-grade security uses a much
  larger effective dimension). Bigger dims raise `log2(rop)` at the cost of proof
  size + verify time — keep verification to one `A·s` + a norm check.

## Caveats (honest)

- The estimator's **SIS** module is *homogeneous* (`A·x=0`); the PoW is
  *inhomogeneous* (`A·s ≈ t` within β) = BDD/approx-CVP. Modeling it as ∞-norm SIS
  with `length_bound=β` is the first-order screen the analysis calls for — treat
  the number as a screen and cross-check the BDD framing (estimator LWE module)
  before freezing parameters.
- **Estimator API drifts** across versions; pin `ESTIMATOR_REF` and adjust the
  `SIS.Parameters` / `SIS.estimate` calls if the interface changed.
- Not run in this repo's sandbox (no Sage here). This is a validated recipe;
  the numbers come from running the container.

## Next

Feed the chosen `(n, m, q, B, β)` back into `bloch-sis-pow::params`, flip the node
default from the testnet regime to canonical, and write the ePrint-style
parameter rationale. That closes S1.
