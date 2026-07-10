# Coherence v0.2 — the Bloch-SIS privacy layer

> Status: **design draft**. No privacy claim is adopted for mainnet until this
> document is completed, externally reviewed, and its primitives are audited.
> The current chain is a **zero-security testnet** and offers **no privacy**.

## 0. What "Coherence" means

Two senses, deliberately fused:

1. **Post-quantum coherence** (the load-bearing one). Every consensus-critical
   primitive in Bloch-SIS lives in **one post-quantum algebraic family** — no
   quantum-vulnerable elliptic curve anywhere on the critical path:

   | Layer | Primitive | Family |
   |---|---|---|
   | Proof-of-work | SHAKE-256 hashcash + Module-SIS structural gate | Hash (SHAKE-256, Grover-bounded) |
   | Signatures | Falcon-1024 ‖ ML-DSA-65 (hybrid) | Lattice (NTRU + Module-LWE/SIS) |
   | Hashing / domain sep | SHAKE-256 / SHA3 | Hash (Keccak) |
   | **Privacy proofs (this doc)** | **hash-STARKs, lattice commitments** | **Hash + lattice** |

   Coherence is the rule that the privacy layer must **not** break this: it may
   only use hash-based (STARK) or lattice-based zero-knowledge, never
   Groth16/PLONK/Bulletproofs over BN254/secp256k1 (all Shor-broken). This
   inherits ADR-018 **D5** (post-quantum coherence) even though the oracle
   network that ADR lived in was removed in Bloch phase B2.

2. **Quantum coherence** (the thematic one, à la the Bloch sphere). A metaphor,
   not a security claim — the state stays "coherent" (private) until an
   authorized measurement (spend) collapses it.

## 1. Honest scope — what this is and is NOT

The Protocol is a **transparent L1**: today every address, amount, and edge of
the transaction graph is public. The Linux track's confidentiality is
**TEE-attested, not cryptographic** (see `BLOCH-SIS-LINUX.md`). Therefore:

- ❌ **No "100% privacy" claim.** TEEs have a long side-channel break history;
  a commitment hides a preimage, not a computation. Any "fully private" framing
  is overstated and is prohibited in Bloch marketing/docs.
- ✅ Coherence provides **cryptographic confidentiality of specific fields**
  (amounts, and — in the shielded pool — sender/receiver linkage), with
  **post-quantum** proof systems, on an otherwise transparent base layer.
- ❌ It does **not** provide network/metadata privacy (IP, timing). That needs
  a transport mixnet / Tor and is out of scope here (tracked separately).

Stating the limits precisely is the point of the "coherence" discipline: claims
must match what the math actually delivers.

## 2. Threat model

Adversary observes the full public chain and the P2P network, and holds a
(future) cryptographically-relevant quantum computer. Goals we defend against:

| # | Adversary goal | Coherence defense |
|---|---|---|
| T1 | Read the **amount** of a shielded transfer | Homomorphic commitment + PQ range proof |
| T2 | **Link** shielded sender ↔ receiver | Nullifier + note-commitment Merkle tree (hash-based) |
| T3 | **Forge** value (inflate supply) inside the shielded pool | Balance proof: Σ inputs = Σ outputs, enforced in-circuit |
| T4 | **Double-spend** a shielded note | One-time nullifier, checked against a global set |
| T5 | Break any of the above **with a quantum computer** | Hash-STARK + lattice only; no curve-based primitive |

Explicitly **out of scope** (documented, not solved here): T6 network-level
deanonymization, T7 TEE side-channels (Linux track), T8 statistical
amount/timing correlation across the transparent↔shielded boundary.

## 3. Design

### 3.1 Two-tier ledger

- **Transparent tier** — the current UTXO model, unchanged. Fast, auditable,
  the default.
- **Shielded tier ("coherent pool")** — a separate commitment set. Value moves
  in via a `shield` tx (transparent → note commitment) and out via `deshield`
  (note → transparent), with fully-shielded transfers in between. This mirrors
  Zcash Sapling's architecture but with **every curve primitive replaced by a
  post-quantum one**.

### 3.2 Notes, commitments, nullifiers

- A **note** = (value `v`, recipient shielding key, randomness `r`).
- **Note commitment** `cm = H(v ‖ pk_d ‖ r)` using **SHAKE-256** (hash-based →
  PQ). Commitments are appended to an incremental **Merkle tree** (SHAKE-256
  nodes) whose root is consensus state.
- **Nullifier** `nf = PRF_{nk}(position)` (SHAKE-256 keyed) — revealed on spend,
  recorded in a global set; a repeat is a double-spend (T4).
- **Amount confidentiality (T1/T3):** value is carried in a **hiding, binding
  commitment**. v0.2 candidates, in preference order:
  1. **Hash-commitment + STARK range proof** — `cm` already hides `v`; a STARK
     proves `0 ≤ v < 2^64` and the balance equation. Simplest, fully hash-based,
     no new hardness assumption. Cost: larger proofs.
  2. **Lattice (Module-SIS) commitment** — additively homomorphic, so balance
     (T3) is a cheap linear check and only the range needs a proof. Smaller, but
     depends on the same lattice hardness as the PoW (acceptable — it's the
     coherence thesis) and is **research-grade** (needs a concrete-security
     analysis, like the canonical PoW).

### 3.3 Zero-knowledge proof system

Per §0/ADR-018 D5, the spend circuit (Merkle membership of `cm`, nullifier
derivation, balance, range) is proved with a **hash-based STARK**:

- **Candidate:** Plonky3 (Poseidon2/Keccak) or RISC Zero (zkVM). Both are
  PQ-secure via hash-based FRI commitments — no trusted setup, no curves.
- **Rejected (quantum-broken):** Groth16, PLONK/BN254, Bulletproofs/secp256k1.
- **Lattice ZK** (e.g., LaBRADOR/Lantern-style) is tracked as a **v0.3+**
  research option for smaller proofs once primitives mature.

### 3.4 Consensus integration

The shielded pool adds to consensus state: the note-commitment Merkle root, the
nullifier set, and a `shield`/`deshield` balance that must reconcile with the
transparent supply (no net issuance). A shielded tx is valid iff its STARK
verifies, its nullifiers are unseen, and its anchor is a recent Merkle root.
Verification is cheap (STARK verify ≈ ms); proving is the client's cost.

## 4. Why not just TEEs?

Bloch-SIS-Linux offers **attested** execution (a relay/indexer can prove it ran
approved code). That is useful for **operational** confidentiality but is
**hardware trust**, not cryptography: SGX/SEV have repeated side-channel breaks,
and attestation proves *what ran*, not *that data stayed secret*. Coherence's
cryptographic tier does not depend on any TEE. The two are complementary and
must never be conflated in a privacy claim.

## 5. Roadmap

| Phase | Deliverable |
|---|---|
| C0 (this doc) | Design + honest scope + threat model |
| C1 | ✅ **done** — `COHERENCE-C1.md`: SHAKE-256 note/commitment/nullifier/Merkle, spend statement, SP1 (raw-FRI) proof system, shielded-tx wire format (lattice RingCT tracked as post-audit alternative) |
| C2 | Reference prover/verifier (hash-STARK, option 3.2.1) behind a feature flag, transparent↔shielded on testnet |
| C3 | External review + concrete-security analysis (esp. if lattice commitments, 3.2.2) |
| C4 | Audit; only then may a scoped, precise privacy claim be published |

## 6. Open problems (do not hand-wave)

- STARK **prover performance** for a Sapling-class circuit on commodity
  hardware (client-side proving latency).
- **Lattice commitment** concrete security + parameters (shares the canonical
  Module-SIS research track).
- **Boundary leakage** (T8): correlating `shield`/`deshield` amounts/timing with
  the transparent graph; needs pool-size and denomination analysis.
- **Metadata** (T6): out of scope here; requires a separate transport privacy
  effort.

## 7. Non-negotiables

1. No quantum-vulnerable primitive on any privacy-critical path.
2. No "100% / fully private" language anywhere until C4.
3. Every claim in shipped docs must name exactly which field is hidden, by which
   primitive, under which assumption.
