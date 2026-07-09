# ADR-020 — PQ Hybridization Roadmap

- **Status:** Proposed
- **Date:** 2026-04-30
- **Author:** BLOCH Founder
- **Sprint:** 2.1.C-rev1 (post Phase β Day 0)
- **Supersedes:** —
- **Related:** ADR-001 (ML-DSA-65 over Falcon), ADR-002-rev2 (BLS fork strategy), ADR-010-A (per-block split), ADR-018 (Oracle Network), ADR-019 (Fork governance), ADR-021 (Transport Continuity), ADR-022 (Hash-to-Curve)

---

## 1. Context

BLOCH positions itself publicly as a *quantum-resistant L1*. As of Sprint
2.1.C-rev1 Phase β Day 1, the in-tree cryptographic stack is:

| Layer | Primitive | PQ posture | Status |
|---|---|---|---|
| Block / tx signatures | ML-DSA-65 (FIPS 204) | **Lattice — Shor-resistant** | Deployed (ADR-001) |
| FFG votes | ML-DSA-65 | **Lattice — Shor-resistant** | Deployed |
| PoW | SHA-256d | Grover-bounded (~128-bit effective) | Deployed |
| Merkle / commitments | SHA-256 | Grover-bounded | Deployed |
| zk commitments (PoBRS) | Poseidon | Hash-based, plausibly PQ | Deployed |
| Backup envelope | AES-256 + Argon2 | Grover-bounded | Operational |
| Transport KEM | ML-KEM-768 (FIPS 203) | **Lattice — Shor-resistant** | Deployed (ADR-021) |
| **Oracle aggregation** | **BLS12-381 (zkcrypto)** | **Pairing-based — Shor-vulnerable** | Deployed (ADR-018) |
| **Validator DKG** | **Gennaro-DKG over BLS12-381** | **Pairing-based — Shor-vulnerable** | Sprint 2.1.C-rev1 Phase β |
| **BLS hash-to-curve** | RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_ | **Pairing-based — Shor-vulnerable** | Sprint 2.1.C-rev1 Phase β Day 2 (ADR-022) |

The BLS12-381 subsystem is the **sole component family** of the protocol
that would be broken by a cryptographically relevant quantum computer
(CRQC). Every public-facing claim of "quantum-resistant BLOCH" must
therefore be qualified by a documented migration plan for this
subsystem — otherwise the marketing claim is technically inaccurate, and
the regulatory exposure (MiCA technical-standards review, US securities
counsel diligence) is non-trivial.

This ADR establishes that plan.

## 2. Threat Model

A CRQC capable of running Shor's algorithm against 256-bit-security
pairing groups would enable an attacker to:

1. **Forge BLS aggregate attestations** — fabricate PoBRS scores
   indistinguishable from genuine 7-of-12 attestations.
2. **Recover validator BLS shares from DKG transcripts** — break
   threshold security retroactively, since DKG transcripts are public.
3. **Forge historical FinalityCertificates** if the FFG is later
   migrated to BLS aggregation (currently it is not — FFG uses ML-DSA-65,
   so this risk is bounded to the oracle path).

A CRQC would *not* affect:

- PoW security (SHA-256d, Grover-bounded).
- Block proposer / tx signatures (ML-DSA-65, lattice).
- ZK commitments (Poseidon, hash-based).
- Backup envelopes (AES-256, Grover-bounded).
- Transport KEM handshakes (ML-KEM-768, lattice — see ADR-021).

### Timeline anchors

- **NIST IR 8547 (Aug 2024)** signals deprecation of pairing-based
  aggregates by 2030 and disallowance by 2035.
- **Independent CRQC arrival estimates:** aggressive 2030, central 2035,
  conservative 2040+.
- **BLOCH mainnet target:** Q3 2027.

The protocol must therefore have a migration path **activated** before
CRQC arrival, not designed after.

## 3. Considered Options

### Option 1 — Direct migration to a lattice aggregate

Replace BLS12-381 entirely with a lattice aggregate scheme
(Falcon-aggregate, Squirrel, Chipmunk, or successor) at mainnet launch.

- ✅ Clean cryptographic story; single primitive family.
- ❌ No production-grade audited implementation as of 2026-Q2.
- ❌ Aggregate sizes are 4–10× larger than BLS; would require
  re-architecting AttestationRegistry layout and FinalityCertificate
  budget.
- ❌ Discards Kudelski 2023 audit transferability secured by ADR-002-rev2.

**Verdict:** not viable today. Revisit annually.

### Option 2 — Hybrid attestations (BLS + ML-DSA-65)

Each oracle signs every attestation **twice**: once with its registered
BLS key and once with its registered ML-DSA-65 key. Verifiers require
**both** signatures valid for an attestation to be accepted.

| Item | Size | Notes |
|---|---|---|
| BLS aggregate signature (12 oracles) | ~96 B | unchanged |
| ML-DSA-65 signature, per oracle | 3,309 B | not aggregable today |
| ML-DSA-65 PK, per oracle | 1,952 B | registered once on-chain |
| Per-attestation overhead | ~39.7 KB worst case | 12 × 3,309 |
| FinalityCertificate envelope today | ~69 KB | ADR-001 + ADR-018 |
| FinalityCertificate envelope under H1 | ~108 KB | manageable, non-trivial |

- ✅ PQ-secure under standard "either-scheme-survives" composition: an
  attacker must break **both** BLS and ML-DSA-65 to forge.
- ✅ Preserves Kudelski 2023 audit on the BLS path.
- ✅ Smooth on/off ramp; no committee re-bonding required.
- ❌ ~57% larger FinalityCertificates during H1.
- ❌ Operational overhead: oracles maintain two keysets.

### Option 3 — Planned BLS sunset, single hard-fork

Keep BLS until external trigger T, then hard-fork directly to
ML-DSA-65-only attestations.

- ✅ Simpler steady states.
- ❌ Discontinuity at T; coordinated hard-fork required.
- ❌ Oracle network must re-bond and re-run DKG under new scheme.
- ❌ No graceful failure if T arrives sooner than expected.

## 4. Decision

BLOCH adopts a **phased hybrid approach**, combining Option 2 and Option 3
in sequence:

```
H0 ──► H1 ──► H2 ──► H3 (optional)
BLS    BLS+    ML-DSA  Lattice
only   ML-DSA  only    aggregate
```

### Phase H0 — Current state (mainnet → ratification of H1)

- BLS12-381 only for oracle attestations and Gennaro-DKG.
- ML-DSA-65 already deployed for FFG votes and tx signatures.
- Endowment funds an external research line tracking CRQC progress and
  PQ-aggregate audit status.
- AttestationRegistry schema is published with a `pq_pubkey` reserved
  field (nullable in H0) so H1 activation does not require a schema
  migration.
- DkgTranscript schema (Sprint 2.1.C-rev1 Phase γ) reserves a nullable
  `pq_commitment: Option<MlDsaCommitment>` field for the same reason.

### Phase H1 — Hybrid attestations

- Each oracle registers an ML-DSA-65 PK in AttestationRegistry.
- Each attestation carries a BLS aggregate signature **and** a vector of
  ML-DSA-65 signatures (one per attesting oracle).
- Verifiers require **both** signature paths valid for acceptance.
- DKG ceremony adds an ML-DSA-65 commitment alongside BLS shares.
- Activation by hard-fork at a height to be set by governance, when **at
  least one** of the following triggers fires:

| Trigger | Definition |
|---|---|
| **A — Regulatory** | NIST publishes a deprecation timeline for pairing-based aggregates, OR EU MiCA technical-standards body issues equivalent guidance. |
| **B — Capability** | A credible CRQC milestone is reached (factoring of RSA-1024 or equivalent ECDLP demonstration over a 256-bit curve). |
| **C — Toolchain** | A production-grade audited PQ aggregate implementation becomes available, signaling H3 preparation should begin. |

**H1 minimum duration before H2** is defined as: 12 months of
continuous H1 operation during which (i) zero successful forgery
attempts are observed against either signature path, (ii) zero
confirmed signature-scheme CVEs against the deployed ML-DSA-65 or BLS12-381
implementations are disclosed by upstream maintainers and unpatched
for more than 30 days, and (iii) no consensus-relevant chain reorganization
exceeding 100 blocks occurs that is attributable to either signature
path. Counters reset on any of these conditions.

### Phase H2 — BLS sunset

- Remove BLS verification path from consensus.
- AttestationRegistry deprecates the `bls_pubkey` field (kept read-only
  for historical block validation).
- Activation by hard-fork at a height set by governance, contingent on:
  - Phase H1 has been live for **≥ 12 months** under the conditions
    enumerated above.
  - At least **one full oracle mandate cycle (2 years per ADR-018)** has
    rotated under H1 conditions.

### Phase H3 — Lattice aggregate (contingent, optional)

Triggered only if **all three** of the following hold:

1. An audited lattice aggregate implementation (Squirrel, Chipmunk, or
   successor) is available with formal verification of the
   constant-time and zeroize properties.
2. FinalityCertificate budget pressure (≥ 200 KB per cert) makes the
   non-aggregated ML-DSA-65 path operationally costly.
3. Governance vote: ≥ 2/3 of FFG validator weight + ≥ 7/12 oracle
   approval.

H3 migrates oracle aggregation from "12 ML-DSA-65 sigs side-by-side" to
a true lattice aggregate. The FFG itself may also be migrated at this
phase by separate ADR.

## 5. Consequences

### Positive

- Cryptographic agility documented and **pre-committed** before mainnet,
  not retrofitted under pressure.
- No surprise hard-forks — protocol participants and partners have a
  public, dated roadmap.
- Audit story remains intact:
  - Kudelski 2023 BLS audit valid through H1.
  - H2 onwards audited per phase against the chosen audit firm
    (NCC / ToB / Kudelski — selection deadline 2026-05-15).
- **Compliance signal**: pre-empts EU MiCA technical-standards updates
  and aligns BLOCH with US NIST IR 8547 trajectory. Useful artifact for
  US securities counsel and EU MiCA counsel engagement.
- Resolves the public-claim consistency gap: "quantum-resistant BLOCH"
  becomes accurate **with** a documented migration plan for the one
  classical primitive in the stack.

### Negative

- Phase H1 increases FinalityCertificate size from ~69 KB to ~108 KB
  worst case (+57%).
- Operational complexity during H1: oracles maintain two keysets and
  perform two signing operations per attestation.
- DKG ceremony must be re-run for any committee that did not register an
  ML-DSA-65 commitment at genesis or during H1 ratification.
- Verifier code must support versioned attestation format (H0 and H1
  variants) without breaking syncing nodes during the transition window.

### Public-claim discipline (mandatory)

For the duration of phases H0 and H1, every external public communication
of the form "BLOCH is quantum-resistant" or equivalent — including, without
limitation, the project website, whitepaper, pitch decks, regulatory
filings, social-media announcements, and partnership materials — MUST
either (a) be qualified with the footnote "with the BLS12-381 oracle
aggregation path classified as classical and migration governed by
ADR-020", or (b) avoid the unqualified claim entirely. This requirement
is binding on the project until phase H2 activation height. Drafts of
external materials that omit this qualification SHOULD be flagged in
review.

### Implementation requirements (pre-H1)

- [ ] `AttestationRegistry` schema extension: add nullable `pq_pubkey:
      Option<MlDsaPubkey>` field at mainnet, before H1 ratification.
- [ ] `DkgTranscript` schema (Sprint 2.1.C-rev1 Phase γ): add nullable
      `pq_commitment: Option<MlDsaCommitment>` field at first emission,
      not at H1 trigger time.
- [ ] Genesis oracles (12 under ADR-018) register ML-DSA-65 PKs during
      onboarding, not at H1 trigger time, to avoid race conditions.
- [ ] Versioned `Attestation` enum: `V1Bls`, `V2Hybrid`. Verifier
      dispatch by version field.
- [ ] Gennaro-DKG transcript extension: add ML-DSA-65 commitments
      alongside BLS shares. Backwards-compatible with existing transcripts.
- [ ] FinalityCertificate envelope size budget revised to 128 KB
      (current 69 KB + headroom for H1 + 20% margin).
- [ ] Test vectors: H1 hybrid attestation, H1→H2 transition,
      H0-attestation replayed under H1 verifier (must reject cleanly).

## 6. Open Questions

- **Trigger ratification window.** Exact thresholds for Trigger A/B/C
  must be ratified by the governance committee within 6 months of
  mainnet. This ADR commits to *the structure of triggers*, not their
  numerical thresholds.
- **Bonding adjustment.** Whether oracle bonding (1M BLOCH minimum,
  ADR-018) should be increased during H1 to compensate for operational
  overhead. Proposed: +20% during H1, restored at H2.
- **FFG hardening.** Whether the FFG itself should also shift to a true
  lattice aggregate at H3. Currently FFG uses individual ML-DSA-65 sigs;
  this works but is suboptimal at committee size 21. Out of scope for
  ADR-020; tracked for a future ADR.
- **Backwards-compat horizon.** How long must the H0 verifier remain in
  the codebase post-H1 activation? Proposal: 2 epochs after H1 height
  (i.e., 12 blocks), then dead-code-eliminated at next minor release.

## 7. Decision Status

This ADR is **Proposed** as of 2026-04-30 and gated on:

1. Audit firm selection (NCC / Trail of Bits / Kudelski) — deadline
   2026-05-15.
2. US securities counsel review of public-claim consistency.
3. EU MiCA counsel review of regulatory alignment.

Promotion to **Accepted** requires sign-off from the chosen audit firm
on the H1 schema design and from both legal counsels on the public-claim
language.

## 8. References

### Standards and guidance

- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (Aug 2024)
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA, Aug 2024)
- NIST IR 8547 — Transition to Post-Quantum Cryptographic Standards (Aug 2024)
- BSI TR-02102-1 — Cryptographic Mechanisms (current edition)
- ENISA Post-Quantum Cryptography Integration Study
- IRTF RFC 9380 — Hashing to Elliptic Curves (Aug 2023)

### Academic

- Boneh, Drijvers, Neven — *Compact Multi-Signatures for Smaller Blockchains* (Asiacrypt 2018) — BLS aggregate baseline.
- Fleischhacker, Simkin, Zhang — *Squirrel: Efficient Synchronized Multi-Signatures from Lattices* (USENIX Security 2022).
- Fleischhacker, Herold, Simkin, Zhang — *Chipmunk: Better Synchronized Multi-Signatures from Lattices* (ACM CCS 2023).
- Gennaro, Jarecki, Krawczyk, Rabin — *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems* (J. Cryptology, 2007).

### Internal

- BLOCH ADR-001 — ML-DSA-65 over Falcon
- BLOCH ADR-002-rev2 — BLS fork strategy (`gennaro-dkg-fork`, `uint-zigzag-fork`, `pqcrypto-internals`)
- BLOCH ADR-005 — Inactivity threshold (NUM=40 / DEN=100, post-fix)
- BLOCH ADR-018 — Oracle Network (12 genesis oracles, 4 tiers)
- BLOCH ADR-019 — Fork governance and quarterly upstream review
- BLOCH ADR-021 — Transport Layer Continuity Under BLOCH Rebrand
- BLOCH ADR-022 — Hash-to-Curve and BLS Group Layout

---

*End of ADR-020.*
