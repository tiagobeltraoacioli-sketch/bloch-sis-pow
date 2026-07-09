# ADR-022 — Hash-to-Curve and BLS Group Layout

- **Status:** Proposed (gated on confirmation that `bls12_381 = "0.8"` with the `experimental` feature flag passes RFC 9380 Appendix J test vectors when wired into our adapter — see §10)
- **Date:** 2026-04-30
- **Author:** BLOCH Founder
- **Sprint:** 2.1.C-rev1 Phase β Day 2
- **Supersedes:** —
- **Related:** ADR-001 (ML-DSA-65), ADR-002-rev2 (BLS fork strategy), ADR-018 (Oracle Network), ADR-019 (Fork governance), ADR-020 (PQ Hybridization Roadmap), ADR-021 (Transport Continuity)

---

## 1. Context

BLOCH Sprint 2.1.C-rev1 Phase β Day 1 (commit `b1405b5`, tag
`v0.2.1.c-beta-day1`) shipped the BLS12-381 adapter with
`EntlG1`/`EntlG2`/`EntlScalar` newtypes wrapping `bls12_381` 0.8
(zkcrypto), serde encoding (compressed: 48/96/32 bytes), constant-time
equality, and `ZeroizeOnDrop` for the scalar.

Day 1 deliberately deferred two foundational decisions:

1. **Hash-to-curve.** The protocol needs a deterministic mapping from
   arbitrary message bytes to a group element, used for: (a) BLS
   signature verification at FFG and at oracle aggregation; (b) future
   proof-of-possession (PoP) registration of validator keys; (c) any
   protocol-defined hash-to-point primitive needed by gennaro-dkg
   adversarial-security tests.
2. **Group layout for keys vs signatures.** BLS over BLS12-381 admits
   two symmetric layouts: pubkey in G1 + signature in G2 ("min-pk")
   and the swap ("min-sig"). Each has implications for storage cost
   and verification cost.

Both decisions affect signature, attestation, and committee storage
schemas across the protocol surface. They must be settled before
hash-to-curve code is added to the adapter, because changing them later
forces a hard fork.

This ADR settles both.

## 2. Standards baseline

### 2.1 RFC 9380

The relevant standard is **IRTF RFC 9380 — Hashing to Elliptic Curves**
(Faz-Hernández, Scott, Sullivan, Wahby, Wood; August 2023). RFC 9380
was published from Internet-Draft `draft-irtf-cfrg-hash-to-curve-16`
without algorithmic changes. Implementations conformant with draft-16
are bit-compatible with the final RFC.

RFC 9380 §8.8 defines two BLS12-381 ciphersuites:

| Suite ID | Target group | Hash | Map | Encoding type |
|---|---|---|---|---|
| `BLS12381G1_XMD:SHA-256_SSWU_RO_` | G1 | SHA-256 (XMD) | Simplified SWU (E' isogenous to G1, 11-isogeny map) | random oracle |
| `BLS12381G2_XMD:SHA-256_SSWU_RO_` | G2 | SHA-256 (XMD) | Simplified SWU (E' isogenous to G2, 3-isogeny map) | random oracle |

`_NU_` (encode-to-curve, non-uniform) variants exist but are NOT used
by BLOCH; we use `_RO_` (hash-to-curve, random oracle indifferentiable)
exclusively. Test vectors live in RFC 9380 Appendix J.9 (G1) and J.10
(G2).

### 2.2 Domain separation tag (DST)

RFC 9380 §3.1 requires every application that uses hash-to-curve to
specify a unique non-zero-length DST string of at least 16 bytes.
Cross-protocol DST collision allows signature replay between protocols.

The IETF BLS Signatures draft (`draft-irtf-cfrg-bls-signature-05`,
expected to advance to RFC) standardizes DSTs of the form
`BLS_SIG_<suite>_<scheme>_`, where `<scheme>` is one of `NUL`
(basic), `AUG` (message-augmented), or `POP` (proof-of-possession).
Ethereum 2.0 uses
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

## 3. Considered Options

### 3.1 Group layout: G1 pubkey + G2 signature ("min-pk") vs swap

| Property | Min-pk (pk in G1, sig in G2) | Min-sig (pk in G2, sig in G1) |
|---|---|---|
| Pubkey size (compressed) | 48 B | 96 B |
| Signature size (compressed) | 96 B | 48 B |
| Pubkey ops cost (verification side) | cheaper | costlier |
| Signature ops cost (signing side) | costlier | cheaper |
| Used by | Ethereum 2.0, Filecoin, Chia, most BLS-on-blockchain | Drand, some pairing-based credentials |

BLOCH keeps validator and oracle pubkeys in long-lived on-chain
registries (CommitteeRegistry, AttestationRegistry) for the lifetime of
the bonding period. Signatures appear once per epoch (FFG) or once per
attestation window (oracle). The persistent storage cost of pubkeys
dominates.

### 3.2 DST format: copy ETH 2.0 vs BLOCH-specific

| Property | Copy ETH 2.0 (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`) | BLOCH-specific |
|---|---|---|
| Test vector reuse | Direct: ETH 2.0 fixtures apply unmodified | Vectors must be regenerated locally |
| Cross-protocol replay isolation | None: signatures are valid against any verifier expecting the ETH DST | Strong: signatures are domain-separated by construction |
| External library compat | Direct: any RFC 9380 BLS impl works out of the box | Trivial: every impl takes DST as a parameter |

### 3.3 Crate choice for hash-to-curve

| Option | Crate | Pros | Cons |
|---|---|---|---|
| **A** | `bls12_381` 0.8 + feature `experimental` | Already a direct dep. Bit-compatible with `draft-irtf-cfrg-hash-to-curve-16` = RFC 9380. Zero churn. | Upstream "may change at any time" warning on the experimental flag. Risk that a future minor release relocates or renames the API. |
| **B** | `bls12_381_plus` 0.8.x (mikelodder7) | Hash-to-curve under stable `hashing` feature (default). Same author as `gennaro-dkg` (already trusted under ADR-019). Multi-scalar mul as a free bonus. | Adds another crate and another cross-fork sync surface (ADR-019 burden +1). Slightly different API surface from `bls12_381`. |
| **C** | `blst` 0.3.x (supranational, C/asm) | Industry default for ETH 2.0, Lighthouse, Prysm, Lodestar. NCC Group audit (Jan 2021). Galois formal verification ongoing. Highest performance. | Different impl from the rest of our BLS stack — the audit transferability argument from ADR-002-rev2 (Kudelski 2023 covers gennaro-dkg over zkcrypto) does NOT extend to blst-based code. We would be running two BLS implementations side by side, which is exactly the dual-implementation footgun ADR-002-rev2 was designed to avoid. |

## 4. Decision

BLOCH adopts the following four bindings simultaneously, ratified
together because changing any one of them later forces a hard fork:

### 4.1 Group layout

BLOCH adopts **min-pk**: validator and oracle public keys live in **G1
(48 bytes compressed)**, signatures live in **G2 (96 bytes
compressed)**.

Rationale: pubkeys are long-lived registry entries scaled by committee
size and oracle population (21 validators × 1 G1 pk + 12 oracles × 1
G1 pk = 33 × 48 B = 1,584 B, plus DKG verification keys). Signatures
are ephemeral certificate components scaled by attestation cadence.
Optimizing the persistent footprint dominates.

### 4.2 Domain separation tag

BLOCH uses **its own DST**, not a copy of the Ethereum 2.0 string. The
canonical DST is:

```
BLOCH_FFG_V1_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
```

ASCII length: 49 bytes (RFC 9380 §3.1 minimum is 16 bytes, satisfied).

For oracle aggregation (PoBRS attestations), a sibling DST is reserved:

```
BLOCH_ORACLE_V1_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_
```

The `V1` token is a protocol-version compartment: a future incompatible
change to the BLS scheme increments to `V2`, ensuring V1 signatures
cannot be replayed under V2 verifier semantics.

Rationale: DST collision is a cheap-to-prevent and expensive-to-fix
class of bug. Copying ETH 2.0's DST would mean any signature minted
for an ETH 2.0 BLS verifier could in principle be replayed against an
BLOCH verifier that processes raw bytes from the wrong code path, and
vice versa. The cost of an BLOCH-specific DST is one local
test-vector-generation step and zero runtime overhead.

### 4.3 Suite ID

BLOCH uses **`BLS12381G2_XMD:SHA-256_SSWU_RO_`** for hash-to-curve
mappings into G2, per RFC 9380 §8.8.2. The G1 suite
(`BLS12381G1_XMD:SHA-256_SSWU_RO_`) is reserved for future use (e.g.,
hashing public-key-derived material into G1) and not exercised by Day
2 code. SHA-256 is the hash function. Simplified SWU is the map.
Random-oracle indifferentiability is the encoding type.

### 4.4 Crate choice — Day 2 implementation

BLOCH adopts **Option A** (`bls12_381` 0.8 with the `experimental`
feature flag) for Sprint 2.1.C-rev1 Phase β Day 2.

Rationale:

1. The `experimental` API in zkcrypto's `bls12_381` 0.8 is bit-compatible
   with `draft-irtf-cfrg-hash-to-curve-16`, which is the RFC 9380 final
   specification. Test vectors from RFC 9380 Appendix J pass against
   the experimental API.
2. We are already pinned to `bls12_381 = "=0.8.0"` exact version under
   ADR-002-rev2 §3.3 (BLS fork strategy locks this version for
   audit-transferability with Kudelski 2023). The `experimental` flag
   is a feature gate, not a separate crate, and pinning blocks the
   "may change at any time" risk for the duration of the pin.
3. The audit-transferability argument from ADR-002-rev2 — Kudelski 2023
   covers `gennaro-dkg` over `bls12_381` zkcrypto APIs — extends to
   the experimental-gated hash-to-curve module within the same crate,
   which uses the same field/group arithmetic primitives that audit
   reviewed.
4. Adding `bls12_381_plus` doubles ADR-019 quarterly review burden
   without delivering capability we cannot get from the existing crate
   today.
5. Adding `blst` doubles the BLS implementation surface, breaking the
   single-implementation property that ADR-002-rev2 was designed to
   preserve.

### 4.5 Migration path (escape hatch)

If, in any quarterly ADR-019 upstream review, the upstream
`bls12_381` crate either:

(a) Removes the experimental hash-to-curve module, OR
(b) Changes its API in a way that breaks our adapter wrapper, OR
(c) Disables the `experimental` feature, OR
(d) Issues a security advisory against the experimental code path,

then BLOCH migrates the hash-to-curve implementation site to
**Option B (`bls12_381_plus`)** under a separate fork at
`gitlab.com/Entanglementlayer/bls12_381_plus-fork`, mirroring the
fork governance pattern established by ADR-019 for `pqcrypto-internals`,
`uint-zigzag-fork`, and `gennaro-dkg-fork`.

The migration is internally local to the new module
`src/ffg/dkg/hash_to_curve.rs` (Day 2). The existing `EntlG1`/`EntlG2`/
`EntlScalar` newtypes remain untouched because they wrap `bls12_381`
types directly; if we migrate to `bls12_381_plus`, we re-target only
the wrapping crate and the test-vector-source crate. Source-level
ergonomic cost: one Cargo.toml line change plus a small impl shim.

## 5. Implementation contract

### 5.1 New module

```text
src/ffg/dkg/hash_to_curve.rs
```

Public API:

```rust
/// Hash arbitrary bytes to a G2 point per RFC 9380 §8.8.2.
/// Suite: BLS12381G2_XMD:SHA-256_SSWU_RO_
pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> EntlG2;

/// Hash arbitrary bytes to a G1 point per RFC 9380 §8.8.1.
/// Suite: BLS12381G1_XMD:SHA-256_SSWU_RO_
/// (Reserved for future use; no consensus path calls this in Day 2.)
pub fn hash_to_g1(message: &[u8], dst: &[u8]) -> EntlG1;

/// The canonical DST for BLOCH FFG V1 signatures.
pub const FFG_V1_DST: &[u8] =
    b"BLOCH_FFG_V1_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The canonical DST for BLOCH oracle V1 attestations.
pub const ORACLE_V1_DST: &[u8] =
    b"BLOCH_ORACLE_V1_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
```

Implementation calls into `bls12_381::hash_to_curve::HashToCurve`
(experimental feature). Output is wrapped in `EntlG1`/`EntlG2` via the
existing `from_inner` constructor from Day 1.

### 5.2 Cargo.toml changes

```toml
# Day 1 line — keep
bls12_381 = { version = "=0.8.0", features = ["zeroize", "experimental"] }
```

The exact-version pin (`=0.8.0`) is preserved. The added feature is
`experimental`. No new dependencies introduced in Day 2.

### 5.3 Test vector strategy

Day 2 ships **at least eight tests** in
`src/ffg/dkg/hash_to_curve.rs::tests`:

1. **Three RFC 9380 J.10 vectors** (G2, suite
   `BLS12381G2_XMD:SHA-256_SSWU_RO_`) for empty message, one short
   message (`abc`), and one long message (`abcdef0123456789`) under
   the RFC's literal DST `QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_`.
   Pass criterion: bit-exact match of the expected G2 point compressed
   bytes.
2. **Three RFC 9380 J.9 vectors** (G1) under the same literal DST,
   same shape. Pass criterion: bit-exact match.
3. **One BLOCH-DST determinism test:** `hash_to_g2(b"any-message",
   FFG_V1_DST)` produces the same point on every call, and a different
   point from `hash_to_g2(b"any-message", ORACLE_V1_DST)`.
4. **One DST-collision-rejection test:** asserts that
   `hash_to_g2(msg, FFG_V1_DST) != hash_to_g2(msg, b"")`, confirming
   DST is actually fed into the XMD expansion.

If any of vectors (1)–(2) fails, the build fails and the ADR is
demoted to **Rejected** pending a switch to Option B; see §10.

## 6. Out-of-scope for Day 2

The following are deliberately deferred:

- **Signature scheme implementation** (signing, verifying, aggregating).
  Sprint 2.2 — FFG signature path. Day 2 only ships the hash primitive.
- **Proof-of-possession registration flow.** ADR-018 §X (oracle
  onboarding) and a future sprint on validator bonding.
- **Multi-signature aggregation testing.** Requires ceremony output
  from Phase γ.
- **Hash-to-G1 production callers.** Reserved API; not exercised by
  consensus until a future ADR opens a use case.
- **Constant-time and timing-leak testing.** Days 7–10 (adversarial
  test suite).
- **Hash-to-scalar.** Used by some BLS schemes; not adopted here. BLOCH
  hashes-to-curve only at the points where the signature scheme
  requires a curve point.

## 7. Consequences

### Positive

- The DST-version-compartment design (`V1` token) gives BLOCH a
  graceful upgrade path for any future BLS-scheme change without a
  hard fork: a `V2` DST can be activated by adding `FFG_V2_DST` and
  routing new signatures through it, while `V1` verifies legacy.
- Sticking with `bls12_381` 0.8 keeps the audit story coherent under
  ADR-002-rev2. One BLS impl, one audit thread.
- Min-pk layout aligns BLOCH with the ETH 2.0 / Filecoin / Chia
  ecosystem convention, easing tooling reuse (block explorers, key
  managers, hardware wallets if ever supported) without inheriting
  ETH 2.0's DST namespace.
- RFC 9380 conformance is a positive item for audit deliverables and
  for MiCA technical-standards review; the suite ID is named in the
  RFC explicitly.

### Negative

- The `experimental` feature flag in `bls12_381` is a pinned-version
  bet on upstream stability. ADR-019 quarterly upstream review must
  explicitly inspect the experimental module on every cycle, not just
  the stable surface. This is now §6 of the ADR-019 review checklist.
- An BLOCH-specific DST means external libraries that hard-code ETH
  2.0's DST cannot verify BLOCH signatures without a small shim. This
  is the correct trade and we document it explicitly.
- Min-pk means signing is more expensive than verification, which is
  the wrong direction for full-node throughput. The asymmetry is small
  in practice (~2× signing cost vs swap, on a 100 µs operation) and
  will not bottleneck a 21-validator FFG epoch.
- Hash-to-G1 is implemented but not exercised by consensus paths in
  Day 2. Dead-code lint must be silenced explicitly with `#[allow(
  dead_code)]` until the future ADR opens a caller. This is preferable
  to deleting the function and re-adding it later under a different
  test discipline.

## 8. Acceptance test (must pass before promotion to Accepted)

Promotion of this ADR from Proposed to Accepted is gated on:

1. The eight tests in §5.3 pass against `bls12_381 = "=0.8.0"` with
   feature `experimental`, on a clean clone, with `cargo test --lib
   ffg::dkg::hash_to_curve`.
2. The full lib test suite remains green (target: 481 + 8 = 489
   tests passing post Day 2).
3. The RFC 9380 J.9 and J.10 reference vectors used in the tests
   match the official RFC source verbatim (bytes copied from the RFC
   9380 published text, not from a third-party mirror, with the source
   citation in a comment).

## 9. Decision Status

This ADR is **Proposed** as of 2026-04-30, gated on §8.

Once Day 2 code lands and the eight tests pass on CI, the ADR is
promoted to **Accepted** in a follow-up commit that updates only this
section and §1's Status line.

If §8 fails — specifically, if the experimental hash-to-curve module
in `bls12_381` 0.8 does not produce RFC 9380-conformant output — the
ADR is demoted to **Rejected** and superseded by a follow-up ADR
selecting Option B (`bls12_381_plus`).

## 10. References

### External

- IRTF RFC 9380 — *Hashing to Elliptic Curves* (Faz-Hernández, Scott,
  Sullivan, Wahby, Wood; August 2023).
- IETF draft-irtf-cfrg-bls-signature — *BLS Signatures* (Boneh, Gorbunov,
  Wahby, Wee, Zhang; ongoing draft toward RFC).
- Wahby, Boneh — *Fast and simple constant-time hashing to the BLS12-381
  elliptic curve* (IACR TCHES 2019/3, paper 188) — basis for the SSWU
  optimized implementation.
- Budroni, Pintore — *Efficient hash maps to G2 on BLS curves* (Applicable
  Algebra in Engineering, Communication and Computing, 2022) — basis
  for the G2 cofactor clearing used by RFC 9380 §8.8.2 `h_eff`.

### Implementation references

- zkcrypto `bls12_381` 0.8 — `hash_to_curve` module (gated on
  `experimental` feature). Documentation comments cite
  `draft-irtf-cfrg-hash-to-curve-16`, which is the RFC 9380 final
  draft. Source:
  `https://github.com/zkcrypto/bls12_381/blob/main/src/hash_to_curve/mod.rs`.
- mikelodder7 `bls12_381_plus` — fallback option B with stable
  `hashing` feature.
- supranational `blst` — reference industrial implementation, NCC Group
  audit January 2021, Galois formal verification ongoing. Used for
  cross-checking test vectors only, not as a runtime dependency.

### Internal

- BLOCH ADR-001 — ML-DSA-65 over Falcon
- BLOCH ADR-002-rev2 — BLS fork strategy
- BLOCH ADR-005 — Inactivity threshold
- BLOCH ADR-018 — Oracle Network
- BLOCH ADR-019 — Fork governance and quarterly upstream review
- BLOCH ADR-020 — PQ Hybridization Roadmap
- BLOCH ADR-021 — Transport Layer Continuity Under BLOCH Rebrand

---

*End of ADR-022.*
