<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Falcon-1024 Online Signing Under PoS

> **PARCIALMENTE SUPERADO — 2026-08-11.** Esta analise foi escrita contra o
> estado do projeto naquele dia e depende de premissas que mudaram DEPOIS:
>
> - **o comite amostrado (128 por epoca + 8 por slot)** — substituido por particao do conjunto ativo: o quorum amostrado nao tinha denominador coerente (achado F1).
>
> O texto NAO foi reescrito, de proposito: o raciocinio que produziu cada
> achado tem valor mesmo quando a premissa mudou, e reescrever apagaria a
> trilha. Leia os achados; confira as premissas contra
> `BLOCH-TOKENOMICS-V4.md` e `BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, que sao
> os normativos.


**Answers:** `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §14.3 (open question) and the
DEV-2 caveat in §6.2.
**Author:** A6 (applied cryptography) · **Date:** 2026-08-11 · **Status:** finding, for A4/DEV-2 review

---

## 0. The question, and the answer in three sentences

> *Is a constant-time, integer-only Falcon-1024 signer available and reviewable
> for a machine that signs on a publicly predictable schedule — or must the
> design fall back to `SUITE_MLDSA65_ONLY` (0x0002)?*

**Yes, it exists, and it is already in the tree**: the PQClean `clean`
implementation of Falcon-1024 — written by Thomas Pornin, the same author as
the reference code — is integer-only end to end, emulating IEEE-754 binary64
with `uint32_t`/`uint64_t` arithmetic, and was designed and reviewed as
constant-time. **But the node as currently built does not run it**: the
`pqcrypto-falcon` crate's *default features* compile and runtime-dispatch to
native floating-point paths on both server architectures (AVX2 doubles on
x86_64, `typedef double fpr` on aarch64), so every release build today signs
with hardware FP — exactly what §6.2 forbids for DEV-2. The fix is a one-line
`Cargo.toml` change plus a CI guard; the escape hatch to 0x0002 does **not**
need to be pulled on current evidence.

The rest of this document substantiates that, surveys the alternatives
(including the pure-Rust ecosystem and FIPS 206's status), reviews the attack
literature against the PoS threat model, and prices the escape hatch anyway.

---

## 1. Why online signing is a different problem (threat-model delta)

Falcon is already consensus code in Bloch — this question is not about adding
it. What PoS changes (§6.2):

| | PoW today | PoS |
|---|---|---|
| Signing frequency | occasional (wallet spends) | every assigned slot/epoch, indefinitely |
| Machine | often offline / cold | internet-facing validator, always on |
| Value at risk | one UTXO per signature | the bonded stake behind the key |
| Attacker's knowledge of *when* | none | **full** — the proposer schedule is public one epoch ahead (§6.4) |

The public schedule is the sharp edge. A remote attacker knows in advance the
exact wall-clock window in which a given validator will run the Falcon signing
algorithm, can trigger nothing yet observe everything — in particular the
**time at which the signed message appears on the network**, which includes the
signing latency. Over years of slots that is a high-quality repeated
measurement of the same secret-dependent computation. That is the channel this
document is about. (Power/EM channels require physical access to the box and
are a hosting decision, not a protocol one; they are surveyed in §5 for
completeness.)

Volume estimate, current constants (30 s slots, 32-slot epochs, committee 128
at the boundary + subcommittee 8 per slot, §6.5.2): a validator attests
roughly once per epoch → **~33,000 signatures/year**, plus proposals
proportional to its share of the validator set. Attacks quoted in the
literature at 10⁴–10⁶ *traces* are therefore not fantasy volumes for a
validator key that lives a few years — the question is whether the remote
observable carries any signal at all.

## 2. Where the floating point lives in Falcon

Falcon signing walks the FFT/LDL "Falcon tree" and calls a discrete Gaussian
sampler (`SamplerZ`, with a Bernoulli-exponential rejection step `BerExp`) once
per coefficient. In the reference formulation this is IEEE-754 binary64
arithmetic — the reason NIST itself lists "special challenges relating to
floating point" and why FIPS 206 has lagged FIPS 204/205 by two years
([NIST status update, Sept 2025][perlner]). Two distinct failure modes matter:

1. **Timing/side channels.** Hardware FP instructions are *mostly*
   constant-time on modern cores, but the claim is per-microarchitecture folklore
   (subnormal penalties, older dividers), not a contract. The original 2019
   rework of the reference code exists precisely because the pre-CT sampler
   leaked ([Pornin 2019][pornin2019]; [Howe–Prest–Ricosset–Rossi,
   PQCrypto 2020][isochronous] gives the formal isochrony analysis of the
   sampler now in use).
2. **Numerical divergence.** "Do Not Disturb a Sleeping Falcon"
   (Eurocrypt 2025) shows that if the *same* (key, message) pair can ever
   produce two signatures that differ because of floating-point discrepancies —
   different hardware, different rounding, FMA contraction — full key recovery
   follows with probability ~1/thousands per pair
   ([Lin–Tibouchi–Yu–Zhang, eprint 2024/1709][sleeping]). This kills
   *deterministic* Falcon; randomized signing (fresh salt per signature, which
   PQClean does and FIPS 206 will mandate) prevents the attack.

Both failure modes are eliminated at the root by an **integer-only emulation**
of the binary64 arithmetic: identical bit-exact behaviour on every platform
(one set of KATs), and constant-time by construction provided the CPU's
32×32→64 multiply is constant-time — true on every x86_64 and ARMv8-A core a
validator would run, and the *only* arithmetic assumption left in the argument.

## 3. Implementation survey (as of 2026-08-11)

### 3.1 PQClean `clean` — the answer, already vendored

[`PQClean/PQClean` PR #210][pr210], "Falcon implementations (integer-only
code, constant-time)", by Pornin, is the origin of the `clean` variant that
`pqcrypto-falcon 0.4.1` vendors at
`~/.cargo/registry/src/…/pqcrypto-falcon-0.4.1/pqclean/crypto_sign/falcon-1024/clean/`.
Its `fpr.h` opens with: *"Custom floating-point implementation with integer
arithmetics"* — the FPEMU path of the reference implementation
([falcon-sign.info][falconimpl]), corresponding to `FALCON_FPEMU` in the
reference `config.h`. Properties:

- **Integer-only**: no FP types, no FP instructions, no libm; IEEE-754
  binary64 semantics reproduced with `uint64_t` ops. Bit-exact across
  platforms → one KAT set covers every validator.
- **Constant-time claim**: documented in [Pornin 2019 (eprint 2019/893)][pornin2019]
  §3–4, conditional only on constant-time 32×32→64 multiplication. The
  Gaussian sampler is the isochronous design of [eprint 2019/1411][isochronous].
- **Reviewable**: C, self-contained (~15 files), inside PQClean's CI
  (Valgrind-based constant-time checks run on PQClean schemes), same author as
  the reference implementation, unchanged since 2019–2021 — a stable review
  target for A4. NIST's own FIPS 206 deck cites exactly these two papers as
  *the* references for constant-time implementation ([bonus slide][perlner]).
- **Randomized signing**: fresh 40-byte salt per signature via the system RNG —
  the property that neutralizes the Sleeping-Falcon class (§2.2).

**This satisfies §6.2's requirement as written** ("constant-time /
integer-emulated signing path only, no FP fallback in release builds") — except
that we are not running it, which is the next finding.

### 3.2 Finding F1 — the current build signs with native FP

`pqcrypto-falcon 0.4.1` default features are `["avx2", "neon", "std"]`
(vendored `Cargo.toml:45-51`). Its `build.rs` additionally compiles, and
`src/falcon1024.rs` runtime-dispatches to:

- **x86_64 + AVX2 detected** → `crypto_sign/falcon-1024/avx2/`, whose `fpr.h`
  wraps a native `double v;` and uses `__m256d` intrinsics — hardware FP;
- **aarch64 (NEON assumed on)** → `crypto_sign/falcon-1024/aarch64/`, whose
  `fpr.h` is `typedef double fpr;` — hardware FP.

The workspace declares `pqcrypto-falcon = "0.4"` with default features
(`/Users/tiagoacioli/dev/BlochPOS/Cargo.toml:119`,
`crates/bloch-crypto/Cargo.toml:53`). **Every release binary on both server
architectures therefore signs Falcon with native floating point today.** For
the wallet-grade PoW threat model that was acceptable (and is Pornin's own
recommendation for x86_64, where SSE2/AVX2 double ops are constant-time for
non-exceptional inputs); for §6.2's PoS requirement it is exactly the
forbidden configuration, silently selected by a transitive default.

**Required change (DEV-2, one line):**

```toml
pqcrypto-falcon = { version = "0.4", default-features = false, features = ["std"] }
```

plus (a) a KAT test asserting sign/verify vectors match the `clean` outputs so
a future dependency bump cannot silently re-enable dispatch, and (b) a CI deny
on `CARGO_FEATURE_AVX2` / `CARGO_FEATURE_NEON` for this crate in release
builds. Verification is unaffected (same code paths validate signatures
regardless of which path produced them), so this is not a consensus change.

### 3.3 Measured cost of the integer-only path

Measured on this repo's exact dependency (Apple M-series, `pqcrypto-falcon
0.4.1`, release profile, 100 signatures after warmup; bench in scratchpad):

| Path | avg per Falcon-1024 signature |
|---|---|
| Native FP (aarch64 dispatch, default features) | **0.46 ms** |
| Integer-only (`clean`, `default-features = false`) | **11.6 ms** |

**~25× slower — and ~2,600× inside the 30 s slot budget.** Even a validator
signing a proposal *and* attesting in the same slot spends < 25 ms of a
30,000 ms slot on Falcon. ML-DSA-65 signing (integer-only by design) adds
single-digit ms. The performance cost of doing this correctly is a rounding
error; there is no engineering pressure to keep the FP path.

### 3.4 The pure-Rust ecosystem — not usable for signing, and why

- **[`rust-fn-dsa`][rustfndsa]** (Pornin): pure Rust, high quality, but it
  implements a *"best guess at the FN-DSA draft"* — a **different wire format**
  from Falcon-as-submitted (different salt length, NTT-form public keys, …),
  incompatible with every signature and key already on Bloch. It also
  **auto-selects native FP** on x86_64/aarch64 with no feature to force the
  emulated path, is pre-1.0 with explicit breaking-change policy until FIPS 206
  finalizes, and is unaudited. Three independent disqualifiers.
- **[`c-fn-dsa`][cfndsa]** (Pornin): same format problem, C.
- **`tide-fn-dsa-vrfy`** (used by the prover-cost spike, `FalconProfile::PqClean`):
  **verification only** — valuable for the in-circuit path, irrelevant here.
- No pure-Rust *signer* for the original Falcon format with a constant-time
  claim was found. The pure-Rust ecosystem has collectively parked itself on
  the FN-DSA draft and is waiting for FIPS 206.
- Active research continues on integer-only CT sampler components — e.g.
  [eprint 2026/1610][sampler2026] (Aug 2026) optimizes `fpr_expm_p63` in
  fixed-point with zero FPU instructions and DUDECT-verified timing — evidence
  that integer-only is the community's direction, not a Bloch eccentricity.

Conclusion: **the signer is the C `clean` code via FFI, and that is fine.**
"Pure Rust" was never a §6.2 requirement; constant-time, integer-only,
reviewable was — and the C code is the only artifact that meets it today.

## 4. FIPS 206 / FN-DSA status — and a format warning

- Falcon was selected for standardization in July 2022. As of the
  [Sept 2025 NIST status update][perlner] the Initial Public Draft was
  *"basically written, awaiting approval"*; press coverage dates the submission
  for approval to 2025-08-28 ([DigiCert][digicert]). **As of this writing
  (2026-08-11) no published IPD could be located**; community discussion
  continues on the [pqc-forum thread][forum] (Oct 2025). Final standard
  realistically **2027**.
- Provisional content relevant to us (from the NIST deck, marked provisional):
  signing must use **native or emulated IEEE-754 binary64 — fixed-point is
  explicitly *not* allowed for signing** (only for keygen); implementations are
  **expected to exactly match KATs** (order of operations specified, no FMA);
  **only randomized signing** is allowed, citing Sleeping Falcon; seeds must
  not be exported as private keys. NIST's validation philosophy thus
  *endorses* exactly the emulated-FP-as-integers approach of §3.1.
- **Format warning for the GIP**: FN-DSA final will not be bit-compatible with
  Falcon-as-submitted (NTT-form public keys, sampler tweaks — 79-bit base
  randomness, infinity-norm check, uniform 40-byte seeds). Bloch's Falcon is
  and remains **Falcon-as-submitted (PQClean profile)**. If the project ever
  wants FIPS-validated FN-DSA, that is a *new suite ID* (e.g.
  `SUITE_MLDSA65_FNDSA1024 = 0x0003`) — a planned migration through the
  existing envelope mechanism, not an upgrade in place. Do not adopt
  `fn-dsa`-family crates until FIPS 206 is final.

## 5. Attack literature vs. the PoS threat model

| Work | Channel | Applies to online PoS signing? |
|---|---|---|
| [Sleeping Falcon (2024/1709)][sleeping], Eurocrypt 2025 | FP divergence, chosen-message, *deterministic* Falcon | **Neutralized**: PQClean signs randomized; integer path is bit-exact anyway; FIPS 206 will forbid deterministic mode |
| [SHIFT SNARE (2025/146)][shiftsnare] | single power trace of **keygen** | Physical access; keygen happens once, offline, at validator setup — keep keygen off the validator box |
| [Thorough Power Analysis on Falcon Gaussian Samplers (2025/351)][power2025] | power traces of signing (≥85% fewer traces than prior art) | Physical access. Not remotely mountable; relevant only to hosting guidance (dedicated hardware, no co-located tenants with power telemetry) |
| [Improved Power Analysis (2023/224)][power2023], [GPV side-channels (2024/2043)][gpv2024] | power/EM | Same class as above |
| **Remote timing on the CT integer path** | network-observable latency | **No published attack.** The isochrony argument ([2019/1411][isochronous]) plus integer-only arithmetic is the state of the art; A4's review should target exactly this configuration |

Two protocol-level mitigations that cost nothing and should go into the spec:

1. **Fixed-deadline publication.** A validator releases its proposal or
   attestation at a fixed offset within the slot (it has 30,000 ms; signing
   takes 12), not "as soon as signing finishes". This pads the one observable a
   remote attacker actually has — publication time — to a constant, converting
   "constant-time signing" from a code property the whole argument leans on
   into defense-in-depth. Recommend A1 adopt this as a spec-level rule in §6.5.
2. **Keygen off-box.** Validator keys are generated on an offline machine
   (SHIFT SNARE targets keygen); the validator box only ever holds the
   expanded signing key.

## 6. The escape hatch, priced (`SUITE_MLDSA65_ONLY = 0x0002`)

Already fully wired: `crypto/mod.rs` signs (line 152) and verifies (line ~192)
suite 0x0002; no format break, exactly as §6.2 promises.

| Dimension | Hybrid 0x0001 | ML-DSA-only 0x0002 | Delta |
|---|---|---|---|
| Signature | 4,589 B | 3,309 B | **−28%** bandwidth/storage (§5.1 sizing relaxes; scenario D drops 57.9 → ~41.7 GB/yr) |
| Public key | 3,745 B | 1,952 B | −48% |
| In-circuit verify (spike, RESULTS.md) | 7.22 M instr | 5.91 M instr | **only −18%** — ML-DSA is the expensive half; dropping Falcon barely helps the prover |
| Signer quality | Falcon: this document | ML-DSA signing is integer-only *by design*, FIPS-final since Aug 2024, with formally verified implementations available | escape removes the entire FP question |
| Security architecture | break of one lattice family ≠ chain break | **single point of failure on ML-DSA / Module-LWE** | this is the real price |

Honest assessment: the escape is cheap operationally and would *simplify* this
whole problem away — but it sells the one genuinely strong property of the
hybrid (NTRU + Module-LWE diversity held into a consensus role) to avoid an
engineering task that §3 shows is a one-line dependency change plus a review
of code that already exists, is already vendored, and was written by the
Falcon reference author for exactly this purpose. **Recommendation: do not
pull it.** Keep 0x0002 as the documented response to a *failed* A4 review, per
§6.2 — the trigger is a P0 finding against the `clean` path, not this survey.

## 7. Verdict and actions

**§14.3 answer: YES** — a constant-time, integer-only, reviewable Falcon-1024
signer exists (PQClean `clean`, in-tree), is sanctioned by NIST's provisional
FIPS 206 validation philosophy, costs 11.6 ms per signature (0.04% of a slot),
and has no published remote-timing attack against it. The design does **not**
fall back to `SUITE_MLDSA65_ONLY`.

The finding that must not get lost: **the requirement is currently violated by
a build default, not by an availability gap.**

| # | Action | Owner |
|---|---|---|
| 1 | `default-features = false` on `pqcrypto-falcon` (workspace + crate), forcing `clean` on all targets | DEV-2 |
| 2 | Cross-platform KATs pinning `clean` outputs; CI deny on avx2/neon features for this crate in release | DEV-2 |
| 3 | Remote-timing review scoped to the `clean` path on x86_64 + aarch64 (dudect-style, validator signing on a public schedule), per §6.2 | A4 |
| 4 | Fixed-deadline publication rule into §6.5; keygen-off-box into validator ops guidance | A1 / A5 |
| 5 | Track FIPS 206 IPD; on final publication, evaluate `SUITE_MLDSA65_FNDSA1024 = 0x0003` as a planned migration — never an in-place swap | A6 |

## Sources

- [NIST, *FIPS 206 Status Update* (R. Perlner, 6th PQC Standardization Conf., Sept 2025)][perlner] — IPD status, FP/validation philosophy (Table 1: fixed point not allowed for signing), randomized-only, planned changes, CT references
- [pqc-forum, *FIPS 206 Status Update* thread (Oct 2025)][forum]
- [DigiCert, *Quantum-Ready FN-DSA (FIPS 206) Nears Draft Approval*][digicert]
- [T. Pornin, *New Efficient, Constant-Time Implementations of Falcon*, eprint 2019/893][pornin2019]
- [J. Howe, T. Prest, T. Ricosset, M. Rossi, *Isochronous Gaussian Sampling*, PQCrypto 2020, eprint 2019/1411][isochronous]
- [PQClean PR #210 — *Falcon implementations (integer-only code, constant-time)*][pr210]
- [Falcon reference implementation notes (falcon-sign.info): `config.h` / FPEMU][falconimpl]
- [X. Lin, M. Tibouchi, Y. Yu, S. Zhang, *Do Not Disturb a Sleeping Falcon*, Eurocrypt 2025, eprint 2024/1709][sleeping]
- [*SHIFT SNARE: Uncovering Secret Keys in FALCON via Single-Trace Analysis*, eprint 2025/146][shiftsnare]
- [*Thorough Power Analysis on Falcon Gaussian Samplers and Practical Countermeasure*, eprint 2025/351][power2025]
- [*Improved Power Analysis Attacks on Falcon*, eprint 2023/224][power2023]
- [*Efficient Error-tolerant Side-channel Attacks on GPV Signatures*, eprint 2024/2043][gpv2024]
- [T. Pornin, `rust-fn-dsa`][rustfndsa] · [T. Pornin, `c-fn-dsa`][cfndsa]
- [N. Houlès, T. Heckmann, *Algorithmic Optimization of the Gaussian Sampler in FN-DSA*, eprint 2026/1610][sampler2026]
- Local: `crates/bloch-crypto/src/crypto/mod.rs` (suites, Falcon wiring); vendored `pqcrypto-falcon 0.4.1` (`Cargo.toml`, `build.rs`, `pqclean/crypto_sign/falcon-1024/{clean,avx2,aarch64}/fpr.h`); `spikes/prover-cost/RESULTS.md` (in-circuit costs, Rust-verifier gates); benchmark in session scratchpad (`falcon-bench`)

[perlner]: https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf
[forum]: https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y
[digicert]: https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist
[pornin2019]: https://eprint.iacr.org/2019/893
[isochronous]: https://eprint.iacr.org/2019/1411
[pr210]: https://github.com/PQClean/PQClean/pull/210
[falconimpl]: https://falcon-sign.info/impl/README.txt.html
[sleeping]: https://eprint.iacr.org/2024/1709
[shiftsnare]: https://eprint.iacr.org/2025/146
[power2025]: https://eprint.iacr.org/2025/351
[power2023]: https://eprint.iacr.org/2023/224
[gpv2024]: https://eprint.iacr.org/2024/2043
[rustfndsa]: https://github.com/pornin/rust-fn-dsa
[cfndsa]: https://github.com/pornin/c-fn-dsa
[sampler2026]: https://eprint.iacr.org/2026/1610
