# RFC-001: FFG Signature Scheme — Hybrid BLS12-381 + ML-DSA-65

| Field | Value |
|---|---|
| **Status** | DRAFT — pending implementation |
| **Date** | 2026-04-28 |
| **Author** | BLOCH Founder + research synthesis |
| **Replaces** | n/a |
| **Depends on** | ADR-001 (accepted), patent drawings FIG. 1–10 |
| **Sprint context** | Sprint 2.0 → Sprint 2.4 (start 2026-05-15) |
| **Last revision** | 2026-04-28 |

---

## 1. Summary

The Friendly Finality Gadget (FFG) overlay for BLOCH uses a **hybrid signature
scheme** combining BLS12-381 (classical, aggregated) and ML-DSA-65 (post-quantum,
concatenated). Each validator holds two keypairs and signs each attestation
with both schemes in a **sequential protocol** that produces four block states
(`PENDING` → `BLS_JUSTIFIED` → `BLS_FINALIZED` → `FULLY_FINALIZED`) culminating
in post-quantum-attested finality at approximately 3 hours after block
production.

This RFC specifies the trait, types, slashing semantics, state transitions,
storage layout, and migration path. Implementation skeletons live in
`src/ffg/{mod,types,errors,signature}.rs` (Sprint 2.0 deliverable).

## 2. Motivation

BLOCH is a post-quantum BlockDAG L1. The transaction layer uses ML-DSA-65 for
signatures. Until Sprint 2, the consensus layer used SHA-256 PoW with no
finality gadget — finality was probabilistic in the Bitcoin / Nakamoto sense.

Sprint 2 introduces FFG. The signature primitive choice for FFG is
consensus-critical: a finality certificate signed only with BLS12-381 (a
curve vulnerable to Shor's algorithm) would undermine BLOCH's post-quantum
thesis at the most security-sensitive layer.

ADR-001 considered five alternatives (BLS-only, Falcon, ML-DSA-65, hybrid
BLS+Falcon, BLS-now-MLDSA-later) and accepted **hybrid BLS+ML-DSA-65** because:

1. The patent drawings (FIG. 3, FIG. 10) already disclose this exact hybrid.
2. ML-DSA-65 (FIPS 204) is a final NIST standard; Falcon (FIPS 206) is still
   in IPD draft.
3. BLOCH already uses ML-DSA-65 elsewhere — consolidates audit surface.
4. Hybrid retains BLS aggregation for fast-path verification while ensuring
   PQ resistance through the ML-DSA path.

## 3. Non-goals

- **Aggregated post-quantum signatures.** No production-ready primitive for
  ML-DSA-aggregate or Falcon-aggregate exists today. The trait
  `FFGSignatureScheme` is designed to allow future hot-swap to a V2 scheme
  with PQ aggregation when such primitives mature (research targets:
  zkLayer SNARK-aggregated lattice signatures; ETA 2028–2030).
- **Slashing of consensus violations outside FFG scope** (e.g., PoW
  selfish mining, eclipse attacks). FFG slashing covers only attestation
  misbehavior.
- **Validator key rotation.** Out of scope for this RFC; will be handled
  in S3.x as a separate sprint.
- **Light client protocol.** Out of scope; mentioned only where finality
  certificate format affects light clients.

## 4. Glossary

| Term | Meaning |
|---|---|
| Validator | Member of the 21-node FFG committee. Has BLS pubkey, ML-DSA pubkey, bond. |
| Committee | The 21 active validators in a given epoch. Renewed every epoch by hashrate election. |
| Epoch | 6 BLOCH blocks (~1 hour). Indexed by `u64`. |
| Vote / Attestation | Signed message from a validator with `(source_epoch, source_root, target_epoch, target_root, bls_sig, mldsa_sig)`. |
| Justify | Epoch reaches BLS supermajority (14-of-21) on a target_root. |
| BLS-finalize | Casper rule: epoch N is BLS_FINALIZED if J(N) and J(N+1) both hold and N+1 votes target N. |
| ML-DSA-confirm | Epoch N reaches ML-DSA supermajority (14-of-21) confirming the BLS-finalized target. |
| Fully-finalize | Both BLS-finalized AND ML-DSA-confirmed — post-quantum-attested finality. |
| Surround-vote | Slashable: vote B with `B.source < A.source ∧ B.target > A.target` for some prior vote A by the same validator. |
| Cross-sig inconsistency | New slashing condition (this RFC): validator BLS-votes target X but ML-DSA-votes target Y, X ≠ Y. |

## 5. Cryptographic primitives

### 5.1 BLS12-381

- **Curve:** BLS12-381, IETF spec `draft-irtf-cfrg-bls-signature` (ciphersuite
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`).
- **Implementation:** `blst` (NCC Group audited 2021; Galois formal
  verification ongoing). Already in BLOCH dependency tree via PoBRS.
- **Public key:** 48 bytes (G1 compressed).
- **Signature:** 96 bytes (G2 compressed).
- **Aggregation:** group operation, O(1) size, O(n) verification.
- **Why:** mature, audited, aggregating, used by Ethereum / Filecoin / Tezos
  consensus.

### 5.2 ML-DSA-65

- **Standard:** FIPS 204 (finalized August 2024).
- **Parameter set:** ML-DSA-65 (NIST security level 3, ~192-bit classical /
  Cat 3 PQ).
- **Implementation:** BLOCH's existing ML-DSA-65 stack (currently used for
  transaction signatures). To be reused, not re-implemented.
- **Public key:** 1952 bytes.
- **Signature:** 3293 bytes.
- **Aggregation:** none (concatenation only).
- **Why:** PQ-resistant, FIPS-final, no floating-point side-channel
  (unlike Falcon), reuses existing BLOCH crypto.

### 5.3 Why both?

- **BLS alone** is fast and aggregating but classical — Shor's algorithm
  breaks it on a CRQC. Unacceptable as sole primitive given BLOCH's
  PQ thesis.
- **ML-DSA alone** is PQ-resistant but does not aggregate — every committee
  signature must be stored individually (~69KB cert vs 96B BLS aggregate).
- **Hybrid** uses BLS for fast-path light-client verification and ML-DSA
  for post-quantum security. If either primitive is broken, the other
  still secures finality.

## 6. Validator structure

Per FIG. 3 of the patent drawings:

```rust
struct ValidatorEntry {
    validator_id:        u32,
    bls_pubkey:          [u8; 48],
    mldsa_pubkey:        [u8; 1952],
    bond_amount:         u128,
    activation_epoch:    u64,
    exit_epoch:          u64,
    status:              ValidatorStatus,
    attestation_count:   u64,
    missed_mldsa_epochs: u32,  // sliding window for slashing-on-miss
}
```

### 6.1 Distributed Key Generation (DKG)

At committee election (every epoch boundary), the elected 21 validators
participate in **dual DKG**:

1. **BLS DKG** — already implemented in PoBRS (oracle 7-of-12). Reused
   verbatim, parametrized for 21-of-21 keygen with 14-of-21 threshold.
2. **ML-DSA DKG** — ML-DSA-65 does NOT support threshold keygen natively
   (it's a Fiat-Shamir lattice signature, not threshold-friendly). Each
   validator generates an independent ML-DSA-65 keypair. The committee's
   "ML-DSA public key" is the *set* of 21 individual pubkeys.

Implication: `mldsa_pubkey` in `ValidatorEntry` is the validator's
individual key. There is no aggregate ML-DSA public key. The `bls_pubkey`
participates in BLS aggregation; `mldsa_pubkey` is verified individually.

## 7. Vote / attestation message

Per FIG. 4 of the patent drawings (extended for hybrid):

```rust
struct Vote {
    validator_id:  u32,
    source_epoch:  u64,
    source_root:   [u8; 32],
    target_epoch:  u64,
    target_root:   [u8; 32],
    bls_sig:       [u8; 96],
    mldsa_sig:     [u8; 3293],
}
```

Total size: ~3.5KB per vote.

**Signing payload (canonical encoding):**
```
domain_separator || validator_id || source_epoch || source_root || target_epoch || target_root
```
Both BLS and ML-DSA sign the **same payload** — this is critical for the
cross-sig inconsistency slashing condition (§9.3).

`domain_separator` = `b"BLOCH_FFG_VOTE_V1"` (ASCII, 16 bytes, fixed). When V2
ships, the separator increments to `V2`, preventing cross-version vote replay.

## 8. State machine

Per FIG. 5 (extended from 3 to 4 states):

```
                                 ┌────────────────────────┐
                                 │ Cross-sig inconsistency│
                                 │ → SLASH (any state)    │
                                 └────────────────────────┘

  ┌───────┐  14+ BLS  ┌─────────────┐  Casper rule  ┌──────────────┐
  │PENDING│──────────>│BLS_JUSTIFIED│──────────────>│BLS_FINALIZED │
  └───────┘ in epoch  └─────────────┘   J(N) +      └──────────────┘
                                        J(N+1)             │
                                        + N+1 votes N      │ 14+ ML-DSA
                                                           │ in epoch N+2
                                                           ▼
                                                  ┌──────────────────┐
                                                  │ FULLY_FINALIZED  │
                                                  └──────────────────┘
                                                  (canonical for
                                                   light clients,
                                                   exchanges, RWA)
```

### 8.1 State invariants

- A block in `BLS_FINALIZED` MUST NOT be reorganized. Attempting to do so
  is a slashable consensus failure (§9 — handled by bloch-consensus
  fork-choice rule honoring `last_bls_finalized_height`).
- A block in `FULLY_FINALIZED` is canonical for all PQ-aware clients.
  Classical-only clients may treat `BLS_FINALIZED` as canonical (with the
  caveat that BLS is breakable on a CRQC).

### 8.2 Transitions and timing

| Epoch | Validator action | New state for block in epoch N |
|---|---|---|
| N | Mine + propagate block | PENDING |
| N | Validators submit BLS+ML-DSA Vote with target_epoch=N | (still PENDING until thresh) |
| N (end) | If 14+ BLS votes for target_root → BLS_JUSTIFIED | BLS_JUSTIFIED |
| N+1 | Validators vote target_epoch=N+1 (with source=N's root) | (J(N+1) accumulates) |
| N+1 (end) | If J(N+1) AND votes refer to N's target_root → Casper finalizes N | BLS_FINALIZED |
| N+2 | Validators submit ML-DSA-only attestation for epoch N's target | (mldsa_threshold accumulates) |
| N+2 (end) | If 14+ ML-DSA confirms for N → FULLY_FINALIZED | FULLY_FINALIZED |

Total wall-clock: ~3 hours from block production to FULLY_FINALIZED
(3 epochs × 1 hour).

### 8.3 Why ML-DSA-confirm in epoch N+2 specifically?

- Epoch N: validators are busy attesting to epoch N as target. Adding
  ML-DSA confirm of N here would compete for bandwidth.
- Epoch N+1: validators are busy attesting to N+1 as target (which
  produces the BLS-finalize Casper trigger for N).
- Epoch N+2: BLS work for N is done (BLS_FINALIZED). Validators have
  bandwidth to do ML-DSA-confirm of N as a "second pass."

This is the **sequential** model of §6.1 in `STATUS-REPORT-fips206-rust-pq.md`.

## 9. Slashing conditions

### 9.1 BLS double-attestation (FIG. 6)

**Detection:** validator V emits two votes with same `target_epoch` but
different `target_root`. Both `bls_sig` verify under V's `bls_pubkey`.

**Punishment:** validator forfeits full bond; status → SLASHED;
exit_epoch set to current epoch + 1.

**Index in storage:** `(validator_id, target_epoch) → vote_hash`. On
submit, lookup; if existing entry with different target_root, slash.

### 9.2 BLS surround-vote (FIG. 7)

**Detection:** validator V emits vote B such that for some prior vote A
by V: `B.source < A.source AND B.target > A.target`. Bidirectional check
(also slash if A surrounds B).

**Punishment:** identical to 9.1.

**Index in storage:** `(validator_id, source_epoch, target_epoch) → vote`.
Surround-vote search: O(votes by V in last K epochs); K = lookback window
(suggested: 30 epochs / ~30 hours).

### 9.3 Cross-sig inconsistency (NEW — not in original drawings)

**Detection:** validator V submits vote V_a with `(target_epoch, target_root_X, bls_sig, mldsa_sig)` and vote V_b with same `target_epoch` such
that:

- `V_a.bls_sig` verifies under V's bls_pubkey for `target_root_X`
- `V_b.mldsa_sig` verifies under V's mldsa_pubkey for `target_root_Y`
- `target_root_X ≠ target_root_Y`

In other words: validator BLS-signed one chain but ML-DSA-signed a
different chain.

**Punishment:** identical to 9.1 + 9.2. This catches an attacker who
controls the BLS key but not ML-DSA (or vice versa), or one who tries
to game the dual-sig protocol.

**Index in storage:** maintain `(validator_id, target_epoch) →
{bls_target_root, mldsa_target_root}` map. On submit of new sig,
cross-check.

### 9.4 ML-DSA miss policy (slash-on-N-misses)

Validators who BLS-sign but fail to ML-DSA-confirm within 3 consecutive
epochs are slashed. Implemented via `missed_mldsa_epochs` counter in
`ValidatorEntry`:

```
for each epoch boundary:
    if validator V signed BLS for epoch N but did not submit
       ML-DSA-confirm by end of epoch N+2:
        V.missed_mldsa_epochs += 1
    else if V did submit:
        V.missed_mldsa_epochs = 0  # reset on success

    if V.missed_mldsa_epochs >= 3:
        slash(V, reason: ML_DSA_MISS_POLICY)
```

**Rationale:** 1-2 missed epochs = lost rewards (no slash) — humane for
hardware glitches. 3+ consecutive misses = consistent failure → slash.

**Symmetric:** ML-DSA-confirms but no BLS = same policy. (Edge case;
unusual but possible if attacker has only ML-DSA key.)

## 10. FinalityCertificate

Issued when a block transitions to FULLY_FINALIZED.

```rust
struct FinalityCertificate {
    epoch:                       u64,        // 8 bytes
    source_root:                 [u8; 32],   // 32 bytes
    target_root:                 [u8; 32],   // 32 bytes
    bls_agg_sig:                 [u8; 96],   // 96 bytes — aggregate of 14+ BLS votes
    bls_committee_bitmap:        u32,        // 4 bytes — 21 bits set; one per signing validator
    mldsa_sigs:                  Vec<MLDSAEntry>,  // 14..21 × ~3300 bytes ≈ 46-69 KB
    mldsa_committee_bitmap:      u32,        // 4 bytes
    fully_finalized_at_block:    u64,        // 8 bytes
    bls_finalized_at_block:      u64,        // 8 bytes
}

struct MLDSAEntry {
    validator_id:  u32,         // 4 bytes
    sig:           [u8; 3293],  // 3293 bytes
}
// total per entry: 3297 bytes
```

**Total certificate size (worst case, 21 ML-DSA sigs):**
- Fixed header: 220 bytes
- 21 × 3297 = 69,237 bytes
- **Grand total: ~69.5 KB**

**Total certificate size (minimum, 14 ML-DSA sigs):**
- Fixed header: 220 bytes
- 14 × 3297 = 46,158 bytes
- **Grand total: ~46.4 KB**

### 10.1 Verification cost (light client perspective)

To verify a `FinalityCertificate`:

1. **BLS path (fast):** verify `bls_agg_sig` against the aggregated public key
   derived from `bls_committee_bitmap` + the committee BLS pubkeys. Single
   pairing operation. ~3ms on commodity hardware.

2. **ML-DSA path (slow but PQ-secure):** for each set bit in
   `mldsa_committee_bitmap`, verify the corresponding ML-DSA sig
   individually. ~50ms total for 14 sigs on commodity hardware
   (~3.5ms/verify).

3. **Final acceptance:** both verifications pass AND
   `popcount(bls_committee_bitmap) >= 14` AND
   `popcount(mldsa_committee_bitmap) >= 14`.

Light clients in resource-constrained environments may verify only the
BLS path and trust the ML-DSA path was verified by full nodes. This is
explicitly acceptable for non-PQ-critical use cases.

### 10.2 Storage and gossip

- **Storage:** ~604 MB / year per node (1 cert/hour × 8760 hours × 69KB
  upper bound). Tolerable. Archival nodes keep all; pruned nodes keep
  last K (suggested K = 720 = 30 days).
- **Gossip:** new gossip topic `ffg/v1/cert`. Backpressure: if a node has
  pending certs older than 24h unsynced, throttle peer message rate.
- **RPC:** `getFinalityCertificate(height)` returns full cert.
  `getFinalityCertificateMeta(height)` returns just header (220 bytes)
  for light clients.

## 11. The `FFGSignatureScheme` trait

Designed for V1 (this RFC) with hot-swap to V2 (future) when PQ aggregation
matures.

```rust
pub trait FFGSignatureScheme: Send + Sync + 'static {
    /// Version identifier embedded in domain separator.
    const VERSION: u8;

    /// Marker types — bound by the impl, not the trait, to allow size variance.
    type BlsPubkey;
    type BlsSecretKey;
    type BlsSignature;
    type BlsAggregate;

    type PqPubkey;
    type PqSecretKey;
    type PqSignature;
    /// V1: PqAggregate is just Vec<PqSignature>.
    /// V2: may be a true aggregate (e.g., SNARK-aggregated lattice).
    type PqAggregate;

    /// Produce a vote sig pair from the canonical message.
    fn sign(
        bls_sk: &Self::BlsSecretKey,
        pq_sk: &Self::PqSecretKey,
        message: &[u8],
    ) -> (Self::BlsSignature, Self::PqSignature);

    /// Verify a single Vote.
    fn verify_vote(
        bls_pk: &Self::BlsPubkey,
        pq_pk: &Self::PqPubkey,
        message: &[u8],
        bls_sig: &Self::BlsSignature,
        pq_sig: &Self::PqSignature,
    ) -> Result<(), VerificationError>;

    /// Aggregate BLS sigs and concatenate / aggregate PQ sigs.
    fn aggregate(
        bls_sigs: &[Self::BlsSignature],
        pq_sigs: &[Self::PqSignature],
    ) -> Result<(Self::BlsAggregate, Self::PqAggregate), AggregationError>;

    /// Verify a FinalityCertificate's signatures.
    fn verify_certificate(
        bls_pks: &[Self::BlsPubkey],
        pq_pks: &[Self::PqPubkey],
        bls_bitmap: u32,
        pq_bitmap: u32,
        message: &[u8],
        bls_agg: &Self::BlsAggregate,
        pq_agg: &Self::PqAggregate,
    ) -> Result<(), VerificationError>;
}
```

### 11.1 V1 implementation

```rust
pub struct V1HybridScheme;

impl FFGSignatureScheme for V1HybridScheme {
    const VERSION: u8 = 1;

    type BlsPubkey      = blst::min_pk::PublicKey;
    type BlsSecretKey   = blst::min_pk::SecretKey;
    type BlsSignature   = blst::min_pk::Signature;
    type BlsAggregate   = blst::min_pk::Signature;  // BLS aggregate is a single point

    type PqPubkey       = MLDSA65PublicKey;     // BLOCH existing type
    type PqSecretKey    = MLDSA65SecretKey;
    type PqSignature    = MLDSA65Signature;
    type PqAggregate    = Vec<MLDSA65Signature>; // V1 has no PQ aggregation

    // ... (impls — see signature.rs stub)
}
```

### 11.2 V2 hot-swap path

When SNARK-aggregated lattice signatures mature (research targets:
`zkLayer`, `Plonky3-aggregated-Dilithium`, etc., ETA 2028–2030), we
introduce `V2HybridScheme` with `type PqAggregate = SNARKProof`.

The trait stays unchanged. Daemon code paths key off `VERSION` constant
and a hard-fork height (`H_FFG_V2_ACTIVATION`).

This is what gives us **hot-swap without refactor**: trait is the
boundary, not concrete types. Generic over `<S: FFGSignatureScheme>`.

## 12. Storage layout (RocksDB)

| CF | Purpose | Key | Value |
|---|---|---|---|
| `CF_FFG_VOTES` | Vote registry (with hybrid sigs) | `(validator_id: u32, target_epoch: u64) || target_root: [u8;32]` | serialized `Vote` |
| `CF_FFG_CERTS` | Finality certificates | `epoch: u64` | serialized `FinalityCertificate` |
| `CF_FFG_COMMITTEE` | Per-epoch committee snapshots | `epoch: u64` | serialized `Vec<CommitteeMember>` |
| `CF_FFG_META` | Misc state (last_bls_finalized_height, last_fully_finalized_height, schema_version) | string | bincode |

**Migration:** schema v13 → v14 adds these 4 CFs. Forward-compat: old
nodes (< v14) refuse to start without migration; migration script seeds
empty CFs.

## 13. Hard-fork activation

`H_FFG_ACTIVATION`: block height at which FFG is enforced. Before this
height, FFG votes are ignored. After this height, fork-choice rule honors
`last_bls_finalized_height` (see bloch-consensus changes in S2.4).

Concrete value TBD — depends on mainnet launch date.

## 14. Open issues / non-decisions

These are intentionally left for Sprint 2.x sub-RFCs or for runtime tuning:

1. **Surround-vote lookback window K:** suggested 30 epochs. May tune up
   for higher tolerance or down for storage savings.
2. **Pruning policy for old certs:** archive vs prune at K=720. Light
   client UX vs disk cost.
3. **Hashrate snapshot window for committee election:** patent drawings
   suggest "last N blocks." Concrete N suggested = 2016 (~14d). Open.
4. **ML-DSA-confirm gossip topic name:** `ffg/v1/mldsa-confirm` vs split
   into per-validator. Bandwidth optimization, deferrable.
5. **FFG params as on-chain governance vs hard-coded:** for MiCA, prefer
   hard-coded (auditor-friendly); for product agility, prefer governance.
   Default to hard-coded; revisit.

## 15. Test vectors

Test vectors will be generated as part of Sprint 2.0 (schema migration)
and live in `tests/ffg/vectors/`. Categories:

- Single Vote sign/verify (positive, BLS only, ML-DSA only, both)
- Single Vote sign/verify (negative — wrong validator key, wrong epoch,
  wrong root, replay, version mismatch)
- Aggregate of 14, 17, 21 BLS sigs
- FinalityCertificate construction + verification
- All 4 slashing conditions, all 4 detection paths
- State transitions (PENDING → BLS_JUSTIFIED → BLS_FINALIZED → FULLY_FINALIZED),
  including failure paths (REORG)

## 16. Audit considerations

This RFC will be reviewed by external audit firm during Sprint 2.5 audit
pass. Key audit prompts:

- Is the cross-sig inconsistency slashing condition (§9.3) sound? Does it
  introduce false positives?
- Is the 3-missed-epochs policy (§9.4) tight enough? Could attacker
  oscillate at 2 misses indefinitely?
- Is the V1→V2 hot-swap path actually clean, or does it require Vote
  format changes that constitute a hard-fork beyond just the signature
  scheme?
- Are domain separators sufficient to prevent cross-version replay?
- Is ML-DSA-65 verification cost (~50ms/cert) acceptable for full-node
  workload at 1 cert/hour?

## 17. Patent fidelity

| Drawing | RFC section | Status |
|---|---|---|
| FIG. 1 (Prior Art) | §1 motivation | ✅ BLOCH-FFG positioning |
| FIG. 2 (System architecture) | §1, §10 | ✅ |
| FIG. 3 (ValidatorEntry) | §6 | ✅ exact match |
| FIG. 4 (Attestation) | §7 | ✅ extended for hybrid |
| FIG. 5 (State transitions) | §8 | ⚠️ extended 3 → 4 states. FULLY_FINALIZED is a refinement of FINALIZED, not a divergence. May warrant a continuation patent if defensive coverage is desired. |
| FIG. 6 (Double-attestation) | §9.1 | ✅ |
| FIG. 7 (Surround-vote) | §9.2 | ✅ |
| FIG. 8 (Hybrid PoW+FFG) | §1, §13 | ✅ |
| FIG. 9 (BLS aggregation) | §10.1 | ✅ |
| FIG. 10 (Comparison) | §1 | ✅ |
| New (not in drawings) | §9.3 cross-sig inconsistency | ⚠️ novel slashing condition. Candidate for continuation patent. |
| New (not in drawings) | §9.4 slash-on-N-misses | ⚠️ novel availability slashing. Candidate for continuation patent. |

**Recommendation:** after Sprint 2 ships, file a continuation-in-part
covering (a) the 4-state machine with FULLY_FINALIZED, (b) cross-sig
inconsistency slashing, (c) slash-on-N-misses ML-DSA availability
condition. These are non-obvious novel improvements over the issued
drawings.

---

## Appendix A: Comparison table (revised)

| Property | Casper FFG | Tendermint | HotStuff | BLOCH-FFG (this RFC) |
|---|---|---|---|---|
| Signature scheme | BLS12-381 | Ed25519 | ECDSA | **BLS + ML-DSA-65 hybrid** |
| Post-quantum secure | No | No | No | **Yes (ML-DSA path)** |
| PoW integration | No | No | No | Yes |
| Two-vote rule | Yes | No | No | Yes |
| Surround-vote slashing | Yes | No | No | Yes |
| Cross-sig slashing | n/a | n/a | n/a | **Yes (this RFC §9.3)** |
| Availability slashing | Inactivity leak | No | No | **Yes (3-miss policy)** |
| Aggregation | Yes | No | Threshold | Yes (BLS); No (ML-DSA — V1) |
| State count | 3 (Pending/Justified/Finalized) | 2 | 2 | **4 (adds FULLY_FINALIZED)** |
| Time to finality | ~12 min | ~1s | ~1s | ~3 hours |
| Time to PQ-finality | n/a | n/a | n/a | **~3 hours** |
| Cert size | ~250B | implicit | implicit | **~46-69 KB** |

The cert size increase is the price of post-quantum finality. The 3-hour
time to finality is comparable to Bitcoin's "12 confirmations" practice
and is acceptable for L1 use cases, exchange policies, and RWA settlement.
