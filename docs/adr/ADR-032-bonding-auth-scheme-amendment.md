# ADR-032 — Bonding Authorization Scheme: BLS-G2 → ML-DSA-65 Amendment

**Status:** Accepted
**Date:** 2026-05-02
**Sprint:** 2.1.E (Day β)
**Author:** BLOCH Founder
**Related:** ADR-001 (FFG signature scheme — hybrid BLS + ML-DSA), ADR-007 §4.3 (bonding tx types — original BLS-96 placeholder), ADR-031 §3.1 (Sprint 2.1.D auth deferral)
**Amends:** ADR-007 §4.3 (UnbondValidatorTx, WithdrawBondTx authorization field type)

---

## 1. Context

Sprint 2.1.D (ADR-031 §3.1) deferred authorization signature verification
to Sprint 2.1.E. The original ADR-007 §4.3 modeled the `authorization`
field on `UnbondValidatorTx` and `WithdrawBondTx` as `[u8; 96]`, sized
for BLS12-381 G2-compressed signatures.

When implementing the verification logic in Sprint 2.1.E, we observed
three facts about the codebase:

1. **No production BLS sign/verify primitives exist.** The `bls12_381`
   crate is a dependency, used exclusively in the DKG adapter for G1/G2
   point arithmetic and hash-to-curve. `ffg::signature::PlaceholderBlsSignature`
   exists only as a type-level placeholder.
2. **ML-DSA-65 sign/verify is fully implemented and tested.**
   `crate::crypto::{sign, verify, generate_keypair_from_seed}` provides
   a complete production interface for the FIPS 204 Level 3 PQ scheme.
3. **`BondRecord` already carries `mldsa_pubkey: MlDsaPubkey([u8; 1952])`.**
   No additional key storage is needed if we authorize bonding-control
   transactions with ML-DSA-65.

Implementing BLS-G2 sign/verify dedicated to bonding authorization would
add ~600–800 LoC of crypto code that is otherwise unneeded. Hybrid
BLS+ML-DSA (matching the FFG `verify_vote` pattern) doubles the
authorization payload and verification cost without proportional
security gain — bonding control-plane operations are low-frequency and
21-day-delayed.

## 2. Decision Drivers

- **D1.** BLOCH is positioned as a post-quantum L1; ML-DSA for
  operator-control authorization is more coherent with this identity.
- **D2.** Adding BLS sign/verify only for bonding is throw-away work.
- **D3.** Hybrid auth doubles tx size and verification cost. For a
  21-day-delayed operation, defense-in-depth via dual schemes is luxury.
- **D4.** No real submissions exist (chain not running). Schema change
  has zero migration cost.
- **D5.** ADR-007 §4.3 stays authoritative as historical doc; this
  amendment via a new ADR is more reviewable than in-place editing.

## 3. Considered Options

### 3.1 Implement BLS-G2 sign/verify dedicated to bonding (rejected)
Pros: ADR-007 §4.3 unchanged. Cons: ~600–800 LoC of throw-away crypto.

### 3.2 ML-DSA-65 only — **selected**
Pros: Reuses existing `crate::crypto`. Coherent with PQ identity. Single
audit surface. Cons: Heterogeneous with FFG hybrid pattern. Tx grows
96 B → 3309 B authorization (still small absolute).

### 3.3 Hybrid BLS+ML-DSA (rejected)
Pros: Maximum defense-in-depth. Cons: Double crypto code volume. 2×
verification cost.

### 3.4 Defer further (rejected)
Pros: No work. Cons: Persistent deferral; bonding registry remains
structurally unauthorized.

## 4. Decision Outcome

**Selected: Option 3.2 (ML-DSA-65 only).**

### 4.1 Schema change

```rust
// Before (ADR-007 §4.3)
pub struct UnbondValidatorTx {
    pub bond_id:       BondId,
    pub authorization: [u8; 96],   // BLS-G2 compressed (placeholder)
}
pub struct WithdrawBondTx {
    pub bond_id:       BondId,
    pub destination:   Address,
    pub authorization: [u8; 96],   // BLS-G2 compressed (placeholder)
}

// After (this ADR)
pub struct UnbondValidatorTx {
    pub bond_id:       BondId,
    pub authorization: Vec<u8>,    // ML-DSA-65, len = ML_DSA_SIG_BYTES = 3309
}
pub struct WithdrawBondTx {
    pub bond_id:       BondId,
    pub destination:   Address,
    pub authorization: Vec<u8>,    // ML-DSA-65, len = ML_DSA_SIG_BYTES = 3309
}
```

### 4.2 Canonical signing message format

```text
unbond_signing_message(bond_id) =
    b"bloch/bonding/v1/unbond" || bond_id.to_be_bytes()      // 22 + 8 = 30 bytes

withdraw_signing_message(bond_id, destination) =
    b"bloch/bonding/v1/withdraw"        // 24 bytes
    || bond_id.to_be_bytes()           //  8 bytes
    || destination.hash_bytes()        // 20 bytes
    || destination.network_byte()      //  1 byte (0=Mainnet, 1=Testnet)
                                       // = 53 bytes total
```

### 4.3 Verification rule

In `BondingRegistry::initiate_unbond` and `withdraw`:

```rust
tx.validate_shape()?;             // shape (cheap)
let record = self.storage.get_bond(tx.bond_id)?
    .ok_or(BondingError::BondNotFound(tx.bond_id))?;
self.verify_*_authorization(&record, tx)?;   // ADR-032 — crypto
// state machine validation (existing)
```

`verify_*_authorization` calls `crate::crypto::verify(&record.mldsa_pubkey.0,
&signing_message(...), &tx.authorization)`. Mismatch returns
`BondingError::InvalidAuthorization`.

### 4.4 Replay prevention

- **Cross-domain** (using unbond sig as withdraw sig): prevented by
  domain tag bytes.
- **Cross-network** (Testnet sig replayed on Mainnet): prevented by
  network byte in `withdraw_signing_message`.
- **Same-domain self-replay** (re-using a valid unbond sig later):
  prevented by `BondStatus` state machine; second `initiate_unbond`
  fails with `InvalidStatusTransition` before reaching verification.

## 5. Consequences

### 5.1 Positive
- Authorization is real and tested (6 new auth tests).
- Single crypto scheme = single audit surface.
- ML-DSA-65 is FIPS 204 standardized.

### 5.2 Negative
- ADR-007 §4.3 is amended. Future readers must follow cross-reference.
- Tx size grows 96 B → 3309 B authorization (modest absolute).
- Heterogeneous with FFG hybrid pattern. Documented here.

### 5.3 Open risks
- **R1.** Compromise of operator's ML-DSA secret key allows
  unauthorized unbond/withdraw. Mitigation: 21-day unbonding period
  gives detection window.
- **R2.** Future hybrid-auth desire. Migration path: add optional
  `bls_authorization: Option<[u8; 96]>` field with backward-compatible
  default.
- **R3.** ADR-007 dual-source-of-truth. Mitigation: this ADR's
  existence cross-referenced from ADR-007's §4.3 footer (follow-up
  doc-only commit).

## 6. Implementation Plan

### 6.1 Sprint 2.1.E Day β (this commit)

- [x] Add `ML_DSA_SIG_BYTES = 3309` constant.
- [x] Migrate `UnbondValidatorTx.authorization` and
      `WithdrawBondTx.authorization` to `Vec<u8>`.
- [x] Implement `unbond_signing_message` / `withdraw_signing_message`.
- [x] Implement `verify_unbond_authorization` /
      `verify_withdraw_authorization` in `BondingRegistry`.
- [x] Wire verification into `initiate_unbond` and `withdraw`.
- [x] Add 6 new Day β auth tests.
- [x] Migrate 23 existing test callsites to use real ML-DSA signatures.

### 6.2 Future

- [ ] Optional: amend ADR-007 §4.3 with `[Sup. by ADR-032]` footer.
- [ ] If telemetry reveals concentrated authorization failures,
      consider hybrid path per R2.

## 7. References

- ADR-001 — FFG signature scheme (BLS + ML-DSA hybrid)
- ADR-007 §4.3 — Bonding contract original transaction types
- ADR-031 §3.1 — Sprint 2.1.D authorization deferral
- FIPS 204 — Module-Lattice-Based Digital Signature Algorithm
