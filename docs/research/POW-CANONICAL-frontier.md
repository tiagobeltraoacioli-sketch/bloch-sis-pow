# The Canonical Bloch-SIS-PoW: Frontier, Forgeability, and the No-Trapdoor Wall

Evidence-first research on whether a **genuinely hard, non-forgeable** Module-SIS
proof-of-work parameterization exists for Bloch — the real gate to an honest
"mainnet beta." Estimator numbers are reproducible from the
`bloch-pow-estimator` container (`deploy/pow-estimator/`).

**Status of this document:** research + analysis. It does **not** change the
shipped consensus params, and it does **not** replace the required IACR ePrint
pre-print + third-party audit. It scopes the gate; it does not clear it.

Labels used below: **[SOLID]** = estimator-backed / arithmetic fact from the
code; **[PRELIM]** = heuristic or design argument that still needs a proof.

---

## 0. TL;DR + verdict

**Is there a viable canonical point where lattice reduction is the mining work
and the PoW is ≥100/128-bit non-forgeable? NO — and it is structurally
impossible, not merely unfound.** [SOLID]

- A PoW has **no trapdoor**: the honest miner and the attacker face the *same*
  instance. So the estimator's `core-SVP` cost is **simultaneously** the attack
  cost *and* the honest mining cost. "Secure enough to be non-forgeable" (say
  2^128) therefore means "honest miners must also spend 2^128 per block" —
  unmineable. The frontier sweep confirms the two regimes are **disjoint**:
  every parameter row with `core-SVP ≥ 100` has a solution-count of `2^(−2900)`
  or worse (no short `s` exists *at all*), and every row where a short `s`
  exists is in the trivial q-ary regime. There is no window. [SOLID]

- The **shipped testnet regime (k=4, β=q/16) is trivially forgeable**: the
  lattice constraint costs a brute-force miner only **~2^12 rejection trials**;
  everything else is a plain hashcash grind on `SHAKE-256(s‖nonce‖header) <
  target`. No lattice reduction is required to mint. The oft-cited **42.5 bits**
  is the estimator's core-SVP for the *full-M* (n=256, m=512, β=q/16) instance —
  already sub-security and inside the trivial q-ary regime — and the *actually
  shipped* k=4 path is weaker still. [SOLID]

- **The only viable shape is the one the repo already converged on: small-`k`
  residual (a non-trivial `√k·β < q` PQ substrate) + a separate leading-zeros
  hashcash difficulty knob.** But its honest security claim is **hashcash
  difficulty + a no-shortcut argument**, NOT a lattice bit-security wall. Calling
  it a "genuinely hard, non-forgeable Module-SIS PoW" (in the lattice sense)
  would be false. [SOLID for the impossibility; PRELIM for the substrate's
  no-shortcut safety]

**Best candidate (viable *shape*, not a hardness wall):** N=256, Q=8 380 417,
B=2, **β=q/16, k=8** (up from testnet k=4). `√k·β/q = 0.18` (non-trivial),
residual floor ≈ 24 bits, difficulty via ASERT leading-zeros. **Core-SVP of this
substrate: the estimator *declines* it** (solutions abundant → not a hard lattice
instance) — which is the point: security here is hashcash, not lattice. [SOLID]

**If you insist on a lattice-as-work "core-SVP ≥ N bits" number** (the dead-end
design), the frontier crossings are: **~100 bits ≈ (n=512, m=1024, β≈q/144);
~128 bits ≈ (n=768, m=1536, β=q/64) → 131.9 bits.** Both are **UNMINEABLE**
(no short `s` exists), so they are *impossibility witnesses*, not candidate
params. [SOLID]

**Bottom line:** the mainnet gate is **not** "reach 128-bit core-SVP" — a
mineable trapdoorless PoW provably cannot. The honest gate is (a) non-triviality
`√k·β < q` (already enforced at compile time), (b) a **formal proof the SIS
substrate adds no shortcut and no asymmetric attacker advantage over honest
brute-force**, (c) leading-zeros difficulty calibration, (d) ePrint + audit.
This research reframes the gate; it does not clear it.

---

## 1. Forgeability of the shipped testnet regime — with numbers

### 1.1 What actually ships

`src/pow/mod.rs` wires **`TESTNET_RESIDUAL_COEFFS = 4`** as the *live consensus*
verifier (`Block::validate_pow → verify_regime(..., 4)`), with SHA-256d removed
(B5b). The full-M `verify()` path exists only for wire-compat/tests. So the
consensus PoW checks the residual on **k=4 coordinates** with **β=q/16** and
**B=2**, plus `SHAKE-256(s‖nonce‖header) < target`. [SOLID — code]

The acceptance conditions a miner must satisfy:
1. `‖s‖∞ ≤ 2` — free (sample `s ∈ {−2..2}^256`; the space is `5^256 = 2^594`).
2. `‖A·s − t‖∞ < β` on **k=4** coords — a rejection filter.
3. `SHAKE-256(s‖nonce‖header) < target` — the hashcash difficulty filter.

### 1.2 Cost of the lattice constraint (condition 2)

Each residual coordinate of a random `s` lands in the centered interval
`(−β, β)` with probability `2β/q = 2·(q/16)/q = 1/8`. Independent across the
k=4 checked coords:

```
P[all 4 residual coords in-band] = (1/8)^4 = 2^-12
work_bits = k · log2(q / 2β) = 4 · log2(8) = 12 bits
```

So a brute-force miner finds a residual-valid `s` in **~2^12 ≈ 4096 trials** —
and there are `~2^(594−12) = 2^582` residual-valid `s` to spare. **No lattice
reduction is required or helpful.** [SOLID — matches `screen.py`'s `work_b` and
the abundance calc.]

### 1.3 The "42.5 bits" figure, placed correctly

The estimator (`docker run bloch-pow-estimator`, reproduced this run) reports for
the **full-M** instance the params nominally describe:

```
current  n=256 m=512 β=523776(q/16)  √m·β/q=1.41  core-SVP log2(rop)=42.5  TRIVIAL q-ary
```

That 42.5 bits is (a) the *full-M* lattice-attack cost, not the k=4 path, and
(b) already inside the **trivial q-ary regime** (`√m·β/q = 1.41 ≥ 1`), meaning
BKZ's own q-vectors satisfy the ∞-bound with essentially no search — so even
42.5 overstates the real barrier. The **shipped k=4 regime is weaker still** (a
12-bit rejection floor). Either way: **zero post-quantum lattice hardness gates
block production.** [SOLID]

### 1.4 The exact attack

There is no special "forgery" — **an attacker mines exactly as an honest miner
does**, and that is the indictment. Sample small `s`, pass the ~2^12 residual
filter, grind `nonce` (and fresh `s`) against `SHAKE < target`. The lattice
adds ≤12 bits of fixed rejection; the rest is Bitcoin-style hashcash on SHAKE.
Consequences:
- The PoW is a **SHAKE hashcash in a lattice costume**. A SHAKE-grinding
  GPU/ASIC dominates just as in Bitcoin; the "ASIC-unfriendly Module-SIS"
  promise is not delivered by k=4. [SOLID]
- "Non-forgeable = must perform lattice work" **fails completely**: block
  production requires no lattice reduction. [SOLID]

The code is *honest* about this — `lib.rs`, `verify.rs`, `solver.rs`,
`src/pow/mod.rs`, and the README all label it "zero security by design." This
section confirms it with the arithmetic.

---

## 2. The hardness / mineability frontier — estimator table

Design model here: **full-M, lattice-hardness = mining work** (the strong,
"non-forgeable" interpretation the mission targets). Reproduced with
`deploy/pow-estimator/sweep.py` in the container (2026-07 run). `core-SVP` =
`log2(min rop)` from the lattice-estimator ∞-norm SIS proxy; `feas_b` =
`log2 E[#short s]` (`n·log2(2B+1) + m·log2(2β/q)`), `≥0` ⇒ a short `s` exists.

```
label            n     m      β       √m·β/q  core-SVP  feas_b    mineability
current q/16   256   512   523776     1.41      42.5     -942   UNMINEABLE TRIVIAL
n256 q/64      256   512   130944     0.35      46.9    -1966   UNMINEABLE
n256 q/128     256   512    65472     0.18      52.6    -2478   UNMINEABLE
n512 q/64      512  1024   130944     0.50      88.2    -3931   UNMINEABLE
n512 q/128     512  1024    65472     0.25      98.7    -4955   UNMINEABLE
n512 q/192     512  1024    43648     0.17     106.4    -5554   UNMINEABLE
n512 q/256     512  1024    32736     0.12     112.7    -5979   UNMINEABLE
n768 q/64      768  1536   130944     0.61     131.9    -5897   UNMINEABLE
n768 q/128     768  1536    65472     0.31     148.8    -7433   UNMINEABLE
n768 q/384     768  1536    21824     0.10     186.1    -9867   UNMINEABLE
n1024 q/128   1024  2048    65472     0.35     201.8    -9910   UNMINEABLE
n1024 q/512   1024  2048    16368     0.09     269.9   -14006   UNMINEABLE
```

(Full 28-row sweep in `deploy/pow-estimator/sweep.py`. `current`, `n512 q/64`,
`n1024 q/128` reproduce the prior `SCREEN-RESULTS.md` values 42.5 / 88.2 / 201.8
exactly.) [SOLID]

**Reading:**
- **The regimes are disjoint.** Every row is `UNMINEABLE`: at m=2n the
  feasibility term `m·log2(2β/q)` swamps `n·log2(5)`, so no short `s` exists
  anywhere on the secure side of the sweep. Analytically, a short full-M
  solution first appears only at **`β ≥ q/(2√5) ≈ q/4.47`** — which gives
  `√m·β/q ≈ 7.2` at m=1024, i.e. **deep inside the trivial regime.** So *full-M
  is mineable only when it is trivially insecure.* There is no window. [SOLID]
- **100-bit crossing:** between `n512 q/128` (98.7) and `n512 q/192` (106.4) →
  ≈ (n=512, m=1024, β≈q/144). **128-bit crossing:** `n768 q/64` = 131.9. Both
  UNMINEABLE. These are the *impossibility frontier*, not candidate params.
- This is exactly the tension `docs/specs/POW-HARDNESS.md` and
  `SCREEN-RESULTS.md` predicted, now confirmed with a dense estimator sweep.

**Estimator caveat (carried from the repo, unchanged):** the estimator's SIS
module is *homogeneous* (`A·x=0`); the PoW is *inhomogeneous* (`A·s ≈ t`) =
BDD/approx-CVP. The ∞-norm SIS with `length_bound=β` is a first-order **proxy**.
The BDD cross-check (estimator LWE module) and the two-step reduce-then-search
refinement remain open. The *direction* (disjoint regimes) is robust to the
proxy; the exact crossing bits are proxy-dependent. [SOLID for direction; PRELIM
for exact bits.]

---

## 3. No-shortcut analysis (the crux) — is lattice reduction actually forced?

### 3.1 Full-M design: forced, but self-defeating

At full-M with `√m·β < q`, mining *does* require real lattice reduction (BKZ +
Babai) — brute-force over `s ∈ {−2..2}^256` finds nothing because `feas_b ≪ 0`.
But that is precisely why it is unmineable: the honest miner must solve a
2^≥100 lattice instance per block. **Forced ⇒ unmineable.** Not a shortcut
problem; a no-trapdoor problem. [SOLID]

### 3.2 Small-k design: NOT forced — and that is by design

For small k the checked instance is `k` rows × `n=256` cols — massively
underdetermined. Short solutions are abundant (`feas_b ≈ +570`). The estimator
**refuses** these instances entirely:

```
SISParameters(n=4,  q=8380417, length_bound=q/8,  m=256, norm=∞)  → "Incorrect bounds 20 > 5"
SISParameters(n=8,  q=8380417, length_bound=q/16, m=256, norm=∞)  → "Incorrect bounds 20 > 10"
SISParameters(n=12, q=8380417, length_bound=q/32, m=256, norm=∞)  → nan
```

i.e. β exceeds the reduced-basis geometry — the instance is trivially
satisfiable, there is no meaningful blocksize. **The small-k substrate provides
no lattice-reduction hardness on its own.** [SOLID — estimator output]. Its
security is therefore **not** lattice hardness; it is the hashcash target on the
aux hash. Correct not to attach a "core-SVP" number to it (as `SCREEN-RESULTS.md`
already warns).

### 3.3 The adversarial questions that remain (the real ePrint content)

Because the difficulty is hashcash, "no-shortcut" for the small-k design reduces
to: **can an attacker mint cheaper than an honest miner?** The subtle risks:

1. **Hash-grind decoupling.** The aux hash binds `s`
   (`SHAKE(s‖nonce‖header)`), and `s` must also pass the k-residual. If
   residual-valid `s` are abundant (they are: `~2^582` of them at k=4), the
   attacker grinds the hash over an effectively unlimited supply of valid `s` —
   so the SIS imposes only its **one-time ~work_bits rejection floor** and does
   **not** otherwise constrain the grind. Net: it *is* hashcash with a small
   additive floor. Adequate for a hashcash PoW, but it must be stated as such,
   not as lattice hardness. [PRELIM — needs a formal statement/bound.]

2. **Attacker asymmetry via lattice reduction.** Could an attacker use BKZ+Babai
   to *generate* residual-valid `s` more cheaply than honest 2^work brute force,
   and thus mine faster? For tiny k the brute-force floor is cheap and embarrassingly
   parallel; one Babai solve per distinct `s` is *more* expensive, so no
   advantage — **at the operating k.** But as k grows, brute-force work grows
   **exponentially** (`k·log2(q/2β)`) while the abundance shrinks; there is a
   **crossover** beyond which lattice reduction beats brute force and hands an
   attacker asymmetric advantage. The canonical k must be kept **well below** that
   crossover. Locating it is an ePrint deliverable. [PRELIM — this is a genuine
   open risk, not yet bounded.]

3. **Algebraic / structural shortcuts.** A/t are per-nonce SHAKE-expanded and
   unstructured (no power-of-two cyclotomic ring, no reuse across nonces) —
   progress-free, blocks cross-nonce precomputation. This is the standard
   "no known advice" heuristic, adequate for a PoW but **not a theorem**. [PRELIM]

**Verdict of §3:** the canonical (small-k) regime does **not** force lattice
reduction — it deliberately relies on hashcash. So "PoW backed by lattice
hardness" is **not** what small-k delivers; it delivers "hashcash + PQ-structured
inner gate." The honest security argument is (1) non-triviality `√k·β<q`,
(2) a proof the substrate adds no shortcut and no lattice asymmetry over honest
brute-force at the chosen k, (3) hashcash cumulative-work security à la Bitcoin.

---

## 4. Candidate canonical parameter set(s)

### 4.1 The viable shape — small-k + leading-zeros (RECOMMENDED direction)

Not a lattice-hardness wall; a **PQ-structured hashcash**. Security = leading-zeros
cumulative work + non-triviality + a no-shortcut proof (§3.3).

| Param | Value | Rationale |
|---|---|---|
| N | 256 | NTT reuse with ML-DSA-65; s-space `5^256` ample |
| Q | 8 380 417 (2²³−2¹³+1) | shared modulus / NTT |
| B | 2 | = η in ML-DSA; keeps `s` in i8 |
| β | q/16 = 523 776 (or q/32) | loose enough for abundant `s`, `√k·β<q` |
| **k** | **8** (candidate; up from testnet 4) | `√8·β/q = 0.18` non-trivial; floor ≈ 24 bits |
| difficulty | ASERT leading-zeros on aux target | the tunable knob (already implemented) |

Substrate core-SVP: **estimator declines it** (abundant solutions; §3.2) →
security is hashcash, correctly *not* a lattice number. `√k·β/q = 0.18 < 1`
(non-trivial floor holds). Alternative points from the screen also sit in-window:
`k=6, β=q/16` (floor 18 b), `k=12, β=q/32` (floor 48 b). **Choice of k trades
the fixed residual floor against the §3.3 attacker-asymmetry crossover — this is
the parameter the ePrint must pin.** [SOLID for non-triviality/floor; PRELIM for
the "8 is safe" claim.]

### 4.2 The lattice-as-work frontier (NOT candidates — impossibility witnesses)

If one insisted on a `core-SVP ≥ N`-bit number, from §2:

| target | (n, m, β) | core-SVP | mineability |
|---|---|---|---|
| ~100 bit | (512, 1024, ≈q/144) | ~100 | **UNMINEABLE** (feas ≪ 0) |
| ~128 bit | (768, 1536, q/64) | 131.9 | **UNMINEABLE** (feas −5897) |
| ~200 bit | (1024, 2048, q/128) | 201.8 | **UNMINEABLE** (feas −9910) |

These exist only to prove the point: **there is no (n,m,β) that is both ≥100-bit
core-SVP and mineable.** They must not be shipped as PoW params. [SOLID]

---

## 5. The code change-set

### 5.1 To adopt the viable shape (small-k + leading-zeros)

The code is **already structured** for this — the change is mostly params +
honesty framing, not new algorithms:

- **`crates/bloch-sis-pow/src/lib.rs`** — replace `TESTNET_RESIDUAL_COEFFS = 4`
  with a chosen `CANONICAL_RESIDUAL_COEFFS` (candidate **8**). Keep the
  compile-time `residual_regime_nontrivial` guardrail (already enforces
  `√k·β<q`). Update the doc from "ZERO security" to the honest hashcash claim.
- **`src/pow/mod.rs`** — point `validate_pow` / miner at the canonical k
  (`verify_regime(..., CANONICAL_RESIDUAL_COEFFS)`); rename
  `verify_sis_pow_testnet` → `verify_sis_pow`. Difficulty path (ASERT
  leading-zeros) is unchanged — it is already the real knob.
- **`crates/bloch-sis-pow/src/solver.rs`** — **keep the brute-force miner.**
  It is *correct and optimal* for this design (solutions abundant). **Do NOT
  implement BKZ/Babai** — real lattice reduction is only needed for the full-M
  lattice-as-work design, which §2 proves is unmineable. Building a BKZ miner
  would be effort spent toward a dead end.
- **`crates/bloch-sis-pow/src/params.rs`** — N, M, Q, B stay. Optionally lower
  β to q/32 if the ePrint's asymmetry analysis wants a smaller floor. Any β/k
  change is a **hard fork** (noted in-file).
- **Docs** — rewrite the security claim everywhere it says "128-bit lattice PoW":
  the honest claim is *"post-quantum-structured hashcash; the Module-SIS is a
  non-trivial (√k·β<q), ASIC-unfriendly inner gate, not a bit-security wall;
  block-production security is cumulative chain work."*

**This is not "testnet → hard non-forgeable lattice PoW."** It is "testnet
hashcash → slightly-harder-floor hashcash with a documented PQ substrate." It
does not deliver the mission's strong goal because that goal is unachievable for
a trapdoorless PoW (§0, §2).

### 5.2 The change-set that the strong goal would require (and why it's blocked)

A *genuinely lattice-hard, non-forgeable* PoW where an attacker must do lattice
reduction to mint **cannot** be a symmetric hashcash. It would need a
**trapdoor/asymmetry** (miner easier than attacker) — which the current
construction has none of, and which is a different cryptographic object
(verifiable-delay / trapdoor-lattice territory), out of scope of parameter
tuning. Absent that, per-block work must be *small and tunable* (à la Bitcoin's
sub-80-bit hashcash), and "non-forgeability" comes from **cumulative** work, not
a per-block 128-bit wall. Reframing the security claim this way is itself the
main "change." [SOLID reasoning; the trapdoor alternative is PRELIM/scoping.]

---

## 6. The honest remaining gate (what this does NOT clear)

This research **scopes** the gate; it does not clear it. Still required before
any mainnet-beta security claim:

1. **Formal no-shortcut proof (§3.3)** for the small-k + leading-zeros
   construction: (a) the additive residual floor bound, (b) a bound on the
   attacker-asymmetry crossover in k with a chosen k safely below it, (c) the
   hash-grind decoupling statement. **Not done here.**
2. **Inhomogeneous / BDD cross-check** — the estimator numbers are the
   homogeneous ∞-SIS proxy; the PoW is `A·s ≈ t` (BDD). Re-run via the LWE/BDD
   module + the two-step reduce-then-search model. **Not done here.**
3. **Leading-zeros difficulty calibration** against the 30 s target block time
   with the k-residual floor folded in.
4. **IACR ePrint pre-print** stating the (reframed) security claim and the
   parameter rationale.
5. **Third-party audit.** Until 1–5: **zero-security testnet, no mainnet claim,
   no value** — as the code already says.

**Honest closing:** No viable canonical point exists for the *strong*
interpretation (lattice-hard, non-forgeable mining) — it is structurally
impossible for a trapdoorless PoW, and the estimator frontier proves the secure
and mineable regimes are disjoint. The best achievable frontier is the small-k +
leading-zeros hashcash-with-PQ-substrate; adopting it is a params-and-honesty
change, not a new mining algorithm, and its security claim must be **reframed**
away from "128-bit lattice wall" to "PQ-structured cumulative-work hashcash." The
blocking items are the no-shortcut proof, the BDD cross-check, the ePrint, and
the audit.

---

### Reproduce

```bash
docker run --rm bloch-pow-estimator                                    # baseline table (42.5 etc.)
docker run --rm --entrypoint sage \
  -v "$PWD/deploy/pow-estimator/sweep.py:/opt/lattice-estimator/sweep.py:ro" \
  bloch-pow-estimator -python sweep.py                                 # §2 frontier sweep
docker run --rm --entrypoint sage \
  -v "$PWD/deploy/pow-estimator/smallk.py:/opt/lattice-estimator/smallk.py:ro" \
  bloch-pow-estimator -python smallk.py                                # §3.2 substrate probe
python3 deploy/pow-estimator/screen.py                                 # analytic screen
```

Estimator: `malb/lattice-estimator` (container `bloch-pow-estimator`, SageMath
10.3). New sweep scripts: `deploy/pow-estimator/{sweep.py, smallk.py}`.
