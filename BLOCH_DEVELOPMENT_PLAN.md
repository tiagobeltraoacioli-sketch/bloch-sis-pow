# Bloch-SIS Protocol — Development Plan

**Bloch-SIS Protocol** is a **post-quantum, pure-Proof-of-Work Layer 1** whose
identity is the Module-**SIS** (Short Integer Solution) lattice proof-of-work.
Forked from the
Bloch-SIS Protocol (BLOCH) codebase. This document is the source of truth for
how Bloch diverges from BLOCH. BLOCH is preserved untouched (local + GitLab);
Bloch is developed only in this repository, with fresh pseudonymous history.

Status: **research/pre-testnet.** Nothing here is mainnet-ready.

---

## 1. Founder decisions (override the published specs where noted)

| # | Decision | Effect | Note |
|---|----------|--------|------|
| D1 | **PoW only in Bloch** | BLOCH keeps SHA-256d; the Module-SIS lattice PoW is **Bloch-exclusive**. | Correct call: PoW does not need to be post-quantum (Grover is only a quadratic speedup, absorbed by difficulty). SIS-PoW is a research bet, so it belongs in the experimental chain, not BLOCH mainnet. |
| D2 | **No BFT** | **Remove Casper-FFG finality, the validator committee, and BLS12-381.** Bloch = pure PoW (GhostDAG-Q + Module-SIS), Bitcoin/Kaspa-style. | **Deviates from Bloch Protocol Spec v0.3** (which includes FFG). This is deliberate and *fixes a real hole*: the spec's FFG uses **BLS12-381, which is NOT post-quantum** — a quantum adversary could forge finality votes. Removing BFT makes the "post-quantum L1" claim honest. |
| D3 | **Keep premine** | Retain the founder premine (Spec §9.1, 17%). No reduction. | Honest note (flagged, not blocking): a 17% premine + the §14.2 6-hour stealth-mine window is an instamine pattern in tension with fair-launch/anonymization. Recommend at least dropping the stealth-mine window and engineering anti-instamine genesis difficulty. Founder's decision stands. |
| D4 | **Remove PoBRS** | Delete the PoBRS oracle subsystem (`src/pobrs/`, `src/oracle/`, `bloch-oracle` bin). | Consequence of D2 (no validators/oracles → pure PoW). The 5% oracle-pool coinbase split becomes vestigial and is resolved in B3 (tokenomics). |

**Sequencing (founder):** B1 (rebrand) **before** B2 (remove FFG); PoBRS removal (D4) folds into the teardown after B1.

### Cascade of D2 (must be decided before implementation)
Removing the validator/BFT layer removes the *reason* for several BLOCH
subsystems. Proposed consequences (confirm before coding):
- **Tokenomics:** the 70/25/5 miner/validator/oracle split loses its validator
  and oracle rationale → move toward **~100% to miner** (Bitcoin/Kaspa model).
  Drop the 25% validator pool and 5% oracle pool.
- **Remove `src/ffg/`** entirely (committee, DKG, election, BLS signatures).
- **Bonding/slashing (`src/bonding/`)** existed to bond FFG validators → remove
  or repurpose.
- **PoBRS oracle (`src/pobrs/`, `src/oracle/`)** was a compliance/attestation
  quorum tied to the oracle pool → decide: remove, or keep as an optional
  application-layer service (not consensus).
- **Finality** becomes PoW depth-based (à la Bitcoin/Kaspa confirmations), not
  epoch-based hard finality.

---

## 2. Deltas from BLOCH per the Bloch Protocol Spec v0.3 (§3.2)

| Dimension | BLOCH | Bloch (spec) | Bloch (after D1/D2) |
|-----------|------|--------------|---------------------|
| PoW | SHA-256d | Module-SIS lattice PoW | **Module-SIS lattice PoW** |
| Finality | FFG-BFT (BLS) | FFG-BFT (BLS) | **none — pure PoW depth** (D2) |
| Signatures | ML-DSA-65 only | hybrid Falcon-1024 ∥ ML-DSA-65 | hybrid Falcon-1024 ∥ ML-DSA-65 |
| Hashing | mixed (SHA-2/3) | unified SHAKE-256 | unified SHAKE-256 |
| Block time | 150 s | 30 s | 30 s |
| Consensus | GhostDAG (k=10) | GhostDAG-Q (k=18) | GhostDAG-Q (k=18) |
| Supply | 1 B nominal | 21 B | 21 B (premine TBD — see §4) |

---

## 3. Module-SIS PoW status (from the validation report + reference crate)

The reference crate is vendored at `crates/bloch-sis-pow/` (v0.1.0, 43 tests,
0 unsafe, SHAKE-256 domain separation, q = 8 380 417 = ML-DSA-65 modulus).

**Honest state:**
- Hardness is **conjectured, not proven**; no lattice-estimator run yet;
  parameters provisional.
- At canonical parameters the brute-force solver **cannot mine**
  (P ≈ (1/8)^512). Production mining **requires lattice reduction (BKZ + Babai)**
  — not yet implemented, and its progress-freeness / ASIC dynamics are open
  problems the report itself flags.
- Verify is ~5–6 ms (target ≤ 1 ms via NTT). Heavier than SHA-256 → mild DoS
  surface until optimized.
- No audit; own timeline: cryptographer paper Q1 2027, ePrint 2027, audit 2028.

**Consequence:** Bloch stays **testnet** until (a) lattice-estimator concrete
security, (b) a working BKZ solver, (c) ePrint review, (d) audit. For dev we
use the crate's relaxed regime (residual bound on first few coefficients) which
provides **zero security** and is for wiring/e2e only.

---

## 4. Honest red flags to resolve (from spec review)

1. **Premine / stealth-mine (Spec §9.1, §14.2):** 29% premine, **17% (3.57 B) to
   the founder**, plus a **~6-hour unannounced "hashrate ramp-up" window**. That
   is a textbook **instamine/stealth-premine** pattern and, combined with the
   BLOCH anonymization/renunciation direction, is *inconsistent with fair-launch
   credibility*. **Recommendation:** reconsider premine size, drop the stealth
   window, and engineer anti-instamine genesis difficulty (the Litecoin lesson).
   Founder's call — flagged, not decided here.
2. **PoW soundness under-specified in the spec** (target `t` / matrix `A`
   derivation) — but the **crate** defines it concretely via SHAKE expansion, so
   the crate, not the paper, is the implementation reference.
3. **"Post-quantum" honesty:** with D2 (no BLS/FFG), the PQ claim becomes true
   (PoW + Falcon/ML-DSA sigs + SHAKE-256 only). Keep it that way — do not
   reintroduce any classical primitive on the consensus path.

---

## 5. Phased work plan

- **B0 — Fork & scaffold** ✅ (this repo): duplicate BLOCH, vendor SIS-PoW crate,
  this plan.
- **B1 — Rebrand:** rename crate `bloch-layer` → `bloch`, binaries,
  address prefix (`bloch1q` → `bloch1q`?), network magic, ports, docs. Mechanical,
  fully testable. Low risk.
- **B2 — Remove BFT (D2):** delete `src/ffg/`; strip finality from
  `src/consensus/` and `src/main.rs`; switch to PoW depth-based confirmation.
  Consensus-critical.
- **B3 — Tokenomics under pure PoW:** 100%-miner emission; drop validator/oracle
  pools; decide premine per §4; 21B supply; 30 s blocks. Consensus/economic.
- **B4 — Decide oracle/bonding fate** (remove or demote to app-layer).
- **B5 — Swap PoW SHA-256d → Module-SIS** (largest phase; consensus-critical).
  Done in verifiable sub-steps on a single adapter seam:
  - **B5a** ✅ — `bloch-sis-pow` wired as a dependency + `src/pow` adapter
    (`verify_sis_pow`, `bits`↔`Target`, `SOLUTION_LEN`). SHA-256d still live.
    (Also fixed a missing `AtomicU64` import in the vendored crate.)
  - **B5b** — block carries the solution vector `s`; block identity → SIS aux
    hash; `Block::validate_pow` → `pow::verify_sis_pow`; serialization
    (network + storage) updated.
  - **B5c** — mining loop (main + stratum) → SIS solver; **relaxed testnet
    regime** (canonical params can't brute-force mine — needs BKZ).
  - **B5c** ✅ — per-block ASERT-Lattice difficulty (miner + validator);
    testnet anchor difficulty `GENESIS_BITS=0x2100ffff`; windowed retarget
    removed.
  - **B5d** ✅ — GhostDAG `work` from the SIS target (`pow::work_from_bits`).
  - **B5e** ✅ — genesis mined under the SIS PoW (`GENESIS_POW_SOLUTION`);
    genesis validates and the node boots.
  - **B5f** (pending) — wire the **stratum V1/V2** mining paths to Module-SIS
    (they still emit SHA-256d work; the core node miner is already on SIS).
  Research track (lattice-estimator, BKZ solver, ePrint, audit) gates mainnet.

**Status:** the core chain mines, validates, and boots on Module-SIS lattice
PoW end-to-end (testnet regime, ZERO security). Remaining: B5f (stratum),
B6 (unify SHAKE-256 + hybrid Falcon∥ML-DSA signatures), B7 (testnet), and the
research track before any mainnet claim.
- **B6 — Unify crypto:** SHAKE-256 everywhere; hybrid Falcon-1024 ∥ ML-DSA-65
  signatures.
- **B7 — Genesis + testnet.**
- **Research track (parallel, gates mainnet):** lattice-estimator, BKZ solver,
  IACR ePrint, third-party audit.

Each phase lands as its own commit(s) with tests kept green.

---

## 6. Privacy / Coherence layer

The "confidential computing / privacy" story is **not** in the Protocol or Linux
specs (which are transparent-L1 + TEE-attested audit respectively). Per review:
those documents make **no "100% privacy" claim**, and their confidentiality is
**TEE-based, not cryptographic** — so any "100% private" framing would be
**overstated** (TEEs have a long side-channel break history; a commitment hides
preimages, not computation). The dedicated privacy analysis is now drafted:

- **Coherence v0.2** (privacy layer, cryptographic): `docs/specs/COHERENCE-v0.2.md`
  — post-quantum-coherent shielded pool (hash-STARK + lattice commitments; no
  curve primitives), with a hard rule against any "100% privacy" claim until
  audited (phase C4).
- **Bloch-SIS-Linux** (operational layer, TEE-attested — NOT cryptographic):
  `docs/specs/BLOCH-SIS-LINUX.md` — reproducible, hardened, attestable node OS.

No privacy claim is adopted until the Coherence gates (COHERENCE-v0.2 §7) pass.

## Founder wallet (testnet)

Created by unifying the two previously-divergent founder-address constants
(`main.rs::FOUNDER_ADDRESS_HEX` and `core::tokenomics_v2::FOUNDER_ADDRESS_HASH`)
onto a single wallet, then re-mining the Module-SIS genesis witness (the coinbase
→ merkle → PoW preimage changed).

- **Address:** `bloch1q565fb89ed8419042494c75a81922a028c3a8ff7c195efc8d`
- **Hash (20B):** `565fb89ed8419042494c75a81922a028c3a8ff7c`
- **Scheme:** hybrid Falcon-1024 ‖ ML-DSA-65 (pk 3745 B, sk 6337 B)
- **Reproducible from a documented dev seed** (recreate the keypair with
  `crypto::generate_keypair_from_seed(SEED)`):
  `SEED = b"bloch-sis-protocol/testnet/founder/v1 :: DOCUMENTED DEV SEED :: zero-security"`

> ⚠️ **ZERO SECURITY.** The seed is public, so anyone can derive the founder key
> and spend the premine/vesting. This is intentional for the zero-security
> testnet regime. For any real deployment the founder MUST generate a fresh
> wallet (holding the seed/password privately) and re-mine genesis to its
> address — do NOT reuse this dev seed.
