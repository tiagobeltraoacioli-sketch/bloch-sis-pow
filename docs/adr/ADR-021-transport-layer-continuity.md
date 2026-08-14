# ADR-021 — Transport Layer Continuity Under BLOCH Rebrand

**Status:** **SUPERSEDED** — This records a **Genesis-3** libp2p transport with a Kyber768 / ML-KEM-768 hybrid handshake. **It does not describe the live Genesis-4 network and must not be cited as evidence that one exists.** What the Genesis-4 fleet actually runs is `--transport devnet`: a point-to-point TCP full mesh with a **fixed peer list, no discovery and no authentication**, which is why a third party cannot yet join the network. A libp2p layer exists in `crates/bloch-pos-node/src/p2p.rs` behind `--transport libp2p`, it is not in service, and its handshake is **Noise, not post-quantum** (`crates/bloch-pos-node/src/main.rs:25`). Consensus signatures are hybrid PQ regardless of transport. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* - **Status:** Proposed
- **Date:** 2026-04-30
- **Author:** BLOCH Founder
- **Sprint:** 2.1.C-rev1 (post Phase β Day 0)
- **Supersedes:** —
- **Related:** ADR-001 (ML-DSA-65), ADR-002-rev2 (BLS fork strategy), ADR-019 (Fork governance), ADR-020 (PQ Hybridization Roadmap), ADR-022 (Hash-to-Curve)

---

## 1. Context

The Bloch-SIS Protocol (BLOCH) project is the rebrand of an earlier
codebase released under the GroundState identity. The rebrand was a
clean break of public identity (chain magic, crate name, binaries,
volume paths, domain) executed for regulatory purposes — to remove from
the public surface a brand that had been associated with experimental
testnet software, before engaging US securities counsel and EU MiCA
counsel for the mainnet phase.

The rebrand was **not** a re-implementation. The codebase is
substantially the same, with renames applied across the five naming
contexts identified in the GroundState clean-break decision: crate,
main binary, auxiliary binaries, chain magic, and temporary volumes
plus environment variables.

This ADR documents that the **post-quantum transport layer** is part of
the substantially-preserved code, not part of the rebrand surface, and
records the operational facts about its history and continuity. The ADR
exists primarily as an **audit-trail artifact** for the firm to be
selected (NCC Group, Trail of Bits, or Kudelski; deadline 2026-05-15)
and for regulatory counsel.

## 2. Historical Record

On **2026-04-20 at 21:58:42 UTC**, two libp2p nodes running the
GroundState binary `v0.5.14-sprintr` (commit `6a672b4`, branch
`sprint-r-network-stability`) completed a successful post-quantum
key-encapsulation handshake using the Kyber768 / ML-KEM-768 hybrid
transport upgrade. The event was documented in the milestone record
PDF dated 2026-04-20.

The network on which the event occurred was an **experimental testnet**
publicly described as such on the GroundState project website
(`groundstate.network`), under the experimental-software notice. The
PDF used the word "mainnet" in the colloquial network-engineering sense
of a publicly reachable peer-to-peer network with consensus, mining,
and gossip propagation — distinct from a local developer network — and
not in the regulated-financial-product sense of a token-launched
production network. No tokens of economic value were minted, distributed,
or traded on that network. No production-financial claim was made.

The endpoints involved:

| Role | Provider | libp2p Peer ID | Multiaddr |
|---|---|---|---|
| Seed (non-mining) | Njalla VPS, Debian 13 | `<TODO: full 52-char base58 peer ID, prefix 12D3KooWQfXJ…vjvDbQp>` | `/ip4/80.78.28.142/tcp/16110/p2p/<full-peer-id>` |
| Worker (miner) | Akash decentralized cloud, node5 | `<TODO: full 52-char base58 peer ID, prefix 12D3KooWBi3N…8cYwda>` | provider-assigned at session time |

> **Pre-commit task (mandatory before Proposed → Accepted):** replace
> the `<TODO: …>` placeholders above with the complete 52-character
> base58 libp2p peer IDs as recorded by the actual nodes that completed
> the 2026-04-20 handshake. Source of truth: the libp2p PeerStore
> snapshot from the same nodes, or the original handshake transcript
> log if preserved. Truncated peer IDs are not acceptable in an
> audit-trail document.

Both endpoints, peer IDs, and ports remain canonical in the present
BLOCH workspace, as enumerated in §3 below.

## 3. Inventory of Preserved Components

The following components were inventoried in the BLOCH workspace on
**2026-04-30** (post Sprint 2.1.C-rev1 Phase β Day 0) and are
confirmed live and exercised by tests:

### 3.1 Source modules

| Path | Role |
|---|---|
| `src/transport/mod.rs` | Transport entry, primitive selection |
| `src/transport/upgrade.rs` | Kyber768 KEM handshake; defines `KyberConfig`, `KyberUpgradeError`, protocol version `1.0.0` |
| `src/transport/stream.rs` | Encrypted stream wrapper; defines `KyberStream` |
| `src/network/mod.rs` | libp2p network glue; default listen `/ip4/0.0.0.0/tcp/16110`, WebSocket on `/tcp/16111/ws` |
| `src/wallet/encryption.rs` | AES-GCM + KDF for keystore envelope |
| `src/metrics/mod.rs` | Runtime instrumentation, references Kyber/HKDF labels |

### 3.2 Test coverage

| Path | Sprint origin |
|---|---|
| `tests/sprint_a2_upgrade_tests.rs` | Sprint A2 — handshake regression suite |
| `tests/sprint_a2_stream_tests.rs` | Sprint A2 — encrypted-stream regression suite |

The "A2" lineage indicates the transport upgrade was migrated and
re-validated under the BLOCH workspace, not merely renamed.

### 3.3 Canonical network constants

- **TCP listen port:** `16110` (production default in `src/main.rs` and
  `src/network/mod.rs`).
- **WebSocket listen port:** `16111` (`src/network/mod.rs`).
- **Bootstrap seed:** `/ip4/80.78.28.142/tcp/16110/p2p/<full-peer-id>`
  (`src/core/mod.rs`, constant `BOOTSTRAP_SEED`). Same physical seed
  and peer identity as the 2026-04-20 handshake. The full peer ID MUST
  be filled in §2 above and matched by the regression test in §7.4
  below.
- **Public DNS alias:** `seed.blochlayer.com`.

> **DNS provisioning status (2026-04-30):** `seed.blochlayer.com`
> is currently used as a fixture in `tests/sprint_p_pex_tests.rs` and
> referenced by the libp2p multiaddr resolution code path. The A
> record pointing to `80.78.28.142` SHOULD be provisioned at the
> blochlayer.com authoritative DNS before this ADR is promoted
> from Proposed to Accepted. If the alias is not provisioned at
> mainnet, this section is inaccurate and must be updated. Provisioning
> is tracked as the first item under §7.

### 3.4 Cryptographic primitives in active use

| Layer | Primitive | Standard |
|---|---|---|
| Key encapsulation | Kyber768 / ML-KEM-768 | NIST FIPS 203 |
| Block / tx signature | ML-DSA-65 (CRYSTALS-Dilithium) | NIST FIPS 204 |
| Session encryption | AES-256-GCM (random 96-bit nonce) | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 over KEM shared secret | RFC 5869 |
| MITM transcript binding | SHA3-256 | NIST FIPS 202 |
| Multiplexing | yamux | libp2p spec |

The Rust implementation crate for the KEM is currently `pqcrypto-kyber`
(KyberSlash patches applied). The exact `Cargo.toml` pinning is
documented separately and tracked under ADR-019 (Fork governance) for
upstream review.

## 4. Naming Note

The Rust types and module documentation use the name **Kyber** (e.g.,
`KyberConfig`, `KyberStream`, `KyberUpgradeError`) because the
implementing crate predates the NIST-finalized name change.

NIST FIPS 203 (August 2024) finalized the standard under the name
**ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism). The
algorithm and parameters at security level 3 (Kyber768 / ML-KEM-768)
are functionally identical, but the public-facing name is ML-KEM-768.

**ML-KEM-768 and Kyber768 refer to the same algorithmic specification
at NIST security level 3. The name change from "Kyber" (Round-3 CRYSTALS
submission) to "ML-KEM" (FIPS 203 final standard) was nominal: it did
not introduce protocol changes, keystream changes, or test-vector
incompatibility relative to the Round-3 IPD specification at security
level 3.** Implementations that conform to either name at level 3
interoperate.

Public documentation, the BLOCH website, milestone records, and audit
deliverables shall use **ML-KEM-768 (Kyber768)** on first reference and
**ML-KEM-768** thereafter. Internal source identifiers may continue to
use `Kyber*` until a future rename ADR is opened.

## 5. Decision

BLOCH formally records the following:

1. The post-quantum transport layer described in the GroundState
   milestone PDF of 2026-04-20 has been **preserved in the BLOCH
   workspace**, with all five rebrand contexts applied (crate, main
   binary, auxiliary binaries, chain magic, volumes/env vars).
2. The transport-layer source code, test suite, network constants, and
   bootstrap-seed identity have **operational continuity**. The BLOCH
   testnet is the same operational network as the GroundState testnet,
   under a renamed identity, not a different network with similar code.
3. The code remains classified as **experimental software running on a
   testnet**, consistent with the disclaimer carried on the legacy
   GroundState project page. BLOCH mainnet activation is targeted for
   **Q3 2027** and is contingent on the pre-mainnet milestones tracked
   under the Sprint 2.1.C-rev1 plan, including audit-firm engagement
   and US/EU regulatory counsel sign-off.
4. No claim of cryptographic-historical primacy ("first PQ blockchain
   handshake") is to be re-asserted under the BLOCH brand. The 2026-04-20
   event stands on its own historical record as a testnet engineering
   milestone. Any forthcoming BLOCH milestone records shall use
   operational-activation language, not firstness language.
5. The PoBRS oracle aggregation path retains a classical primitive
   (BLS12-381) outside the scope of the present transport ADR.
   Migration of that path is governed by **ADR-020 (PQ Hybridization
   Roadmap)**.

## 6. Consequences

### Positive

- The audit firm receives an explicit, dated, source-pinned record of
  what was preserved across the rebrand, eliminating ambiguity about
  whether BLOCH is a fresh implementation or a continuation. The
  Sprint A2 test artifacts provide independent regression evidence.
- Public claims about the BLOCH technology stack can be substantiated
  by cross-referencing this ADR to the source paths listed in §3,
  rather than to the legacy GroundState milestone PDF (which now
  carries inherited brand context the rebrand was designed to retire).
- The honest framing of the historical event as a **testnet** milestone
  on experimental software brings the public record into precise
  alignment with the project's regulatory posture, reducing exposure
  during US securities and EU MiCA counsel diligence.
- Removes ambiguity about the word "mainnet" in the 2026-04-20 PDF,
  by stating explicitly that the term was used in the
  network-engineering sense and that no token of economic value was
  involved.

### Negative

- The Sprint A2 tests assume the legacy port and seed identity. Any
  future change to either constant requires a coordinated update of
  source, tests, fixtures, and this ADR.
- Source-level type names continue to use `Kyber*` while public
  documentation uses `ML-KEM-768`. The naming gap creates a small
  cognitive cost for new contributors and must be flagged in
  CONTRIBUTING.md until a rename ADR is opened.
- A future audit deliverable must continue to acknowledge the
  testnet-mainnet language distinction for any documents authored
  before this ADR. The 2026-04-20 PDF is preserved unmodified as a
  historical artifact; a one-page errata note clarifying the
  testnet status and the colloquial-vs-regulated meaning of "mainnet"
  shall be appended to the public record without altering the original.

## 7. Implementation Tasks

### 7.1 Errata

- [ ] Create `docs/history/2026-04-20-pq-handshake-errata.md` clarifying
      testnet status and the colloquial use of "mainnet" in the
      original milestone PDF.
- [ ] Add a `CONTRIBUTING.md` note about the `Kyber*` ↔ `ML-KEM-768`
      naming gap, pointing to §4 of this ADR.

### 7.2 Crate pinning

- [ ] Pin the exact `pqcrypto-kyber` (or successor) version in
      `Cargo.toml` and reference it from §3.4.

### 7.3 Peer ID and DNS

- [ ] Replace `<TODO: …>` peer ID placeholders in §2 with the full
      52-character base58 IDs from the libp2p PeerStore snapshot of
      the 2026-04-20 handshake nodes.
- [ ] Provision the DNS A record `seed.blochlayer.com → 80.78.28.142`
      at the authoritative DNS for `blochlayer.com`, before
      promoting this ADR from Proposed to Accepted.

### 7.4 Bootstrap-seed regression test

Add a regression test asserting that the bootstrap seed multiaddr
remains operationally continuous with the GroundState lineage. The
test sits in `tests/adr_021_continuity.rs` and is canonical text:

```rust
//! ADR-021 — Operational continuity regression.
//!
//! Asserts that the canonical bootstrap-seed multiaddr is the exact
//! one preserved from the GroundState testnet on 2026-04-20. Any
//! refactor that silently changes seed identity, IP, port, or peer ID
//! will fail this test. To intentionally change the seed, update the
//! constant AND ADR-021 §2/§3.3 in the same commit.

use bloch_layer::core::BOOTSTRAP_SEED;

#[test]
fn bootstrap_seed_matches_groundstate_lineage() {
    let expected = "/ip4/80.78.28.142/tcp/16110/p2p/<full-peer-id-from-adr-021-section-2>";
    assert_eq!(
        BOOTSTRAP_SEED, expected,
        "ADR-021 §3.3 — operational continuity from GroundState testnet was broken. \
         If this change is intentional, update src/core/mod.rs::BOOTSTRAP_SEED, \
         tests/adr_021_continuity.rs, and ADR-021 §2/§3.3 in the same commit."
    );
}
```

The test is added in the same commit as this ADR. Once §7.3 fills in
the full peer ID, both the constant and the assertion are updated
together.

### 7.5 Cross-link

- [ ] Cross-link this ADR from ADR-020 §1 (Context), since the BLS
      classical-primitive carve-out depends on the transport-layer
      story being settled. (Already present in ADR-020 rev1.)

## 8. Open Questions

- **Crate rename trigger.** When should the source-level rename
  `Kyber*` → `MlKem*` be performed? Options: (a) opportunistically
  alongside an unrelated network refactor; (b) as a dedicated minor-
  version pre-mainnet hardening pass; (c) deferred to mainnet
  activation. No decision required by this ADR.
- **Errata distribution.** The 2026-04-20 PDF is preserved unmodified.
  The errata is hosted as a separate document at
  `docs/history/2026-04-20-pq-handshake-errata.md` and linked from the
  public website page that references the milestone PDF, to preserve
  the integrity of the original dated artifact while making the
  clarification discoverable to anyone reaching the PDF through public
  channels.

## 9. References

### External

- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (Aug 2024)
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (Aug 2024)
- NIST FIPS 202 — SHA-3 Standard
- NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- libp2p specifications — yamux multiplexer

### Internal

- BLOCH ADR-001 — ML-DSA-65 over Falcon
- BLOCH ADR-002-rev2 — BLS fork strategy
- BLOCH ADR-019 — Fork governance and quarterly upstream review
- BLOCH ADR-020 — PQ Hybridization Roadmap
- BLOCH ADR-022 — Hash-to-Curve and BLS Group Layout
- GroundState milestone PDF, 2026-04-20 — first post-quantum P2P handshake on experimental testnet (preserved historical artifact)

---

*End of ADR-021.*
