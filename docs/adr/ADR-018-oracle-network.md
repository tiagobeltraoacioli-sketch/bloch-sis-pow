# ADR-018: Oracle Network — Eligibility, Compensation, and Bidirectional ZK API

**Sprint:** 2.4 (specification) / 3.0 (initial outreach) / 3.1+ (implementation)
**Status:** **SUPERSEDED** — The oracle network is specified against PoBRS, the FFG committee and the 70/25/5 miner/validator/oracle emission split — none of which exist under Genesis-4. Tokenomics V4 has no oracle bucket: the seven destinations are carryover, founder, VC, team, marketing, liquidity and validator emission (`crates/bloch-pos-committee/src/tokenomics_v4.rs`). **No oracle network is built, wired or running.** The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Proposed (draft for review)
**Date:** 2026-04-29
**Author:** BLOCH Core
**Related:** ADR-002 (PoBRS), ADR-005 (Committee), ADR-010 (Tokenomics — requires update), ADR-017 (Compliance Framework — pending)

---

## 1. Context

ADR-002 specified the PoBRS oracle attestation network: 12 oracles with 7-of-12 BLS threshold, 10% slashing, multi-vendor TEE attestation. However, several critical aspects remained unspecified:

1. **Eligibility criteria** — who can become an oracle?
2. **Selection process** — how are the genesis 12 chosen and rotated?
3. **Compensation structure** — how are oracles paid sustainably?
4. **Anti-concentration rules** — how to prevent capture by a single jurisdiction or entity?

In addition, the strategic decision in subsequent design sessions to adopt **follow-the-money compliance model** (using PoBRS for transaction flow attestation, not actor filtering) and the **bidirectional ZK API** concept (where oracles consume enriched chain data via ZK proofs in exchange for attestations) require formal specification.

This ADR consolidates all three decisions:

1. **Oracle eligibility and selection** — curated genesis with stake-weighted rotation
2. **Compensation structure** — four revenue streams plus rebate mechanism
3. **Bidirectional ZK API** — inbound attestations + outbound chain queries

## 2. Decision Drivers

- **D1.** Regulatory credibility: integrating tier-1 AML players (Chainalysis, TRM, Elliptic, Mastercard Crypto Secure) provides immediate institutional credibility and SEC/FinCEN-compatible compliance attestations.
- **D2.** Anti-competition strategy: rather than competing with established blockchain analytics providers, integrate them as oracles with revenue share — converts competitors into advocates.
- **D3.** Sustainability of oracle operations: oracle work has real costs (TEE infrastructure, monitoring, maintenance). Compensation must be sufficient that institutional players accept participation.
- **D4.** Privacy preservation: bidirectional API must not compromise user privacy or violate GDPR. ZK proofs enable enrichment without raw data exposure.
- **D5.** Post-quantum coherence: ZK proof systems must use STARKs or lattice-based primitives, not classical SNARKs (Groth16, PLONK over BN254 are quantum-vulnerable).
- **D6.** Anti-capture: 12 oracles must be distributed across jurisdictions, entity types, and TEE vendors to prevent coordinated capture.
- **D7.** Compatibility with ADR-010: oracle compensation requires reallocation of block reward and fee distribution.
- **D8.** Compatibility with ADR-005: oracle bonding model parallels validator bonding model — uniformity simplifies tooling.

## 3. Considered Options for Eligibility Model

### 3.1 Option A — Curated Federation (Chainlink-style)

Foundation selects all oracles. Public criteria but discretionary selection.

**Pros:** maximum quality control, predictable composition.
**Cons:** centralization, perceived unfair, difficult to defend as "decentralized" oracle network.

### 3.2 Option B — Permissionless Bonded (UMA-style)

Anyone with sufficient bond can apply. No KYC, no curation. Reputation emerges over time.

**Pros:** maximally decentralized, censorship resistant.
**Cons:** quality control is purely economic; institutional integration is harder; no guarantee of jurisdictional/vendor diversity.

### 3.3 Option C — Hybrid: Curated Genesis + Stake-Weighted Rotation ✅ SELECTED

Foundation selects 12 oracles for genesis with public criteria. Post-mainnet, rotation occurs via stake-weighted voting with anti-concentration rules.

**Pros:**
- Genesis has institutional credibility immediately.
- Post-mainnet rotation provides legitimacy and avoids permanent capture.
- Anti-concentration rules baked into protocol.
- Compatible with curated AML players who would not participate in pure permissionless model.

**Cons:** more complex than pure A or B. Requires governance specification.

### 3.4 Option D — Permissionless + KYC

Anyone can apply with valid KYC and bonding.

**Pros:** decentralized but with compliance floor.
**Cons:** KYC requirement reduces quality benefit (small operators with KYC are not necessarily competent oracles); doesn't guarantee tier-1 credibility.

## 4. Decision Outcome

**Adopt Option C: Hybrid model with curated genesis and stake-weighted rotation.**

### 4.1 Genesis Oracle Composition (12 Slots)

Foundation selects genesis oracles per the following allocation, with all selections publicly justified in a "Genesis Oracle Charter" document published at mainnet launch.

| Tier | Slots | Target Composition |
|------|-------|-------------------|
| **Tier 1 — Established AML/Analytics** | 4 | Chainalysis, TRM Labs, Elliptic, Mastercard Crypto Secure |
| **Tier 2 — Regional/Specialized** | 4 | Merkle Science (APAC), Coinfirm-Lukka (EU/US), Crystal Blockchain (EU), Scorechain (EU) |
| **Tier 3 — Crypto-Native Partners** | 2 | Notabene (Travel Rule specialty), CertiK or similar (security audit + AML) |
| **Tier 4 — Foundation/Academic** | 2 | BLOCH Foundation Research entity (Switzerland), University-affiliated research center (MIT DCI / Cornell IC3 / Imperial College CCC) |

### 4.2 Eligibility Criteria

To be selected (genesis or rotation), a candidate must satisfy ALL of:

**Technical requirements:**
1. Operate multi-vendor TEE attestation infrastructure (Intel SGX-2, AMD SEV-SNP, Intel TDX, or AWS Nitro).
2. Maintain 99.5%+ uptime SLA on testnet for 90 days prior to selection.
3. Bonding minimum: **1,000,000 BLOCH** ($1M+ at $1 BLOCH).
4. ML-DSA-65 signing infrastructure with hardware-backed key storage.

**Institutional requirements:**
5. Legal entity (corporation, foundation, or academic institution) — no anonymous candidates.
6. Minimum 5 years operating in blockchain analytics, AML/compliance, or cryptographic research (genesis tier-1 only).
7. Demonstrable client base or research output (genesis only).
8. Domiciled in Tier 4 (crypto-friendly: Switzerland, Singapore, UAE, etc.) OR Tier 3 (regulated: US, UK, Japan, etc.).
9. No domicile in Tier 1 sanctioned jurisdiction (Cuba, Iran, North Korea, Syria, Crimea, Donetsk, Luhansk).

**Operational requirements:**
10. Public commitment to operating oracle for minimum 2 years (mandate length).
11. Acceptance of slashing terms (10% bonded for equivocation; reputation-based slashing for sustained underperformance).
12. Public dashboard exposing oracle uptime and attestation accuracy.
13. Compliance with GDPR Article 17 for any user data accessed (raw data off-chain only; on-chain commitments only).

### 4.3 Anti-Concentration Rules (Hardcoded in Bonding Contract)

To prevent capture and ensure diversity, the protocol enforces:

```rust
pub const MAX_ORACLES_PER_LEGAL_ENTITY: usize = 1;
pub const MAX_ORACLES_PER_JURISDICTION: usize = 3;
pub const MAX_ORACLES_PER_TEE_VENDOR: usize = 4;
```

Verified at oracle registration time:

```rust
pub fn validate_oracle_eligibility(
    candidate: &OracleIdentity,
    current_oracles: &[OracleIdentity],
) -> Result<(), OracleError> {
    // Anti-Sybil: one oracle per entity
    let same_entity = current_oracles.iter()
        .filter(|o| o.legal_entity_hash == candidate.legal_entity_hash)
        .count();
    if same_entity >= MAX_ORACLES_PER_LEGAL_ENTITY {
        return Err(OracleError::EntityCapExceeded);
    }

    // Anti-jurisdictional concentration
    let same_jurisdiction = current_oracles.iter()
        .filter(|o| o.jurisdiction == candidate.jurisdiction)
        .count();
    if same_jurisdiction >= MAX_ORACLES_PER_JURISDICTION {
        return Err(OracleError::JurisdictionCapExceeded);
    }

    // Anti-supply-chain risk via TEE diversity
    let same_tee = current_oracles.iter()
        .filter(|o| o.tee_vendor == candidate.tee_vendor)
        .count();
    if same_tee >= MAX_ORACLES_PER_TEE_VENDOR {
        return Err(OracleError::TeeVendorCapExceeded);
    }

    Ok(())
}
```

### 4.4 Selection and Rotation Process

**Genesis (Pre-mainnet):** Foundation selects 12 oracles per section 4.1 composition. Selection criteria and rationale are publicly documented in the Genesis Oracle Charter. Selected oracles bond BLOCH via vesting contract pre-mainnet.

**Post-genesis Rotation:**

- Each oracle has a **2-year mandate** (≈ 730 days = 420,480 blocks at 150s block time).
- 30 days before mandate expiry, slot opens for application via on-chain registry.
- New candidates submit bonding + identity proof on-chain.
- Verification of technical + institutional + operational criteria via PoBRS-attested verification (oracles attest each other's eligibility).
- 30-day voting period: BLOCH stakers vote with stake-weighted votes.
- Threshold: 60% approval (of total BLOCH stake voting) to enter.
- Incumbent can renew if: zero slashing events in mandate, SLA met, anti-concentration rules still satisfied.

**Emergency removal:** if oracle fails (slashing event, hardware failure, voluntary exit), slot opens immediately for short-cycle replacement (7-day voting period).

## 5. Compensation Structure

Oracle compensation is calibrated to make participation genuinely attractive to tier-1 institutions while maintaining sustainable economics. Four revenue streams:

### 5.1 Stream 1: Block Reward Share (Baseline)

5% of all block emission flows to the oracle pool, distributed pro-rata by attestation participation count per epoch.

```
Block emission allocation (revised from ADR-010):
  70% → miners (PoW)
  25% → validator pool (FFG)
  5%  → oracle pool (PoBRS)
```

Per-oracle baseline (assuming 12 active oracles with equal participation):

```
Total emission/year (steady state with halvings averaged): ~25M BLOCH
Oracle pool 5%: ~1.25M BLOCH/year total
Per-oracle: ~104k BLOCH/year baseline
At $1 BLOCH: $104k/year baseline
```

### 5.2 Stream 2: Inbound Attestation Fees

VASPs and services pay per-query fees in BLOCH when consulting attestations.

```
Attestation query fee: 0.1 BLOCH per query
Distribution: 60% to oracle that signed attestation
              30% to oracle pool (rebated to active oracles)
              10% burned (deflationary pressure)

Estimated query volume year 3+: 10M queries/year (conservative)
Per-oracle (20% market share, top contributors): ~166k BLOCH/year
At $1 BLOCH: $166k/year
```

### 5.3 Stream 3: Subscription Tiers

Enterprise VASPs and services purchase subscription tiers for guaranteed access:

```
Tier 1 — Foundation API access:    $5,000/month → unlimited basic queries
Tier 2 — Direct oracle access:     $25,000/month → priority + SLA
Tier 3 — Custom integration:       $100,000/month → bespoke + private oracle channel

Estimated subscriptions year 3+: 20 enterprise clients
Annual subscription revenue: ~$6M total
Distribution: 70% to oracle pool, 30% to BLOCH Labs
Per-oracle: ~$350k/year
```

### 5.4 Stream 4: Outbound Query Revenue (Bidirectional API)

Oracles pay BLOCH when querying enriched chain data. This is an inversion: chain charges oracles for data, but with rebate mechanism:

```
Outbound query base fees:
  Layer 1 queries (simple):       1-3 BLOCH per query
  Layer 2 queries (intermediate): 10-20 BLOCH per query
  Layer 3 queries (complex):      50-100 BLOCH per query

Distribution of outbound fees:
  50% burned (deflationary)
  30% to endowment buffer
  20% pro-rata to oracles by contribution score (rebate)
```

### 5.5 Rebate Mechanism (Critical for Tier-1 Acceptance)

Without rebate, oracles consuming many queries (e.g., Chainalysis using outbound API for analytics) would have negative net economics. Rebate solves this:

```rust
pub fn calculate_oracle_query_cost(
    base_cost_sats: u64,
    oracle_id: OracleId,
    contribution_score: f64,  // [0, 1] based on attestations provided
) -> u64 {
    let rebate_pct = match contribution_score {
        s if s > 0.9 => 0.80,  // Top 10% contributors: 80% rebate
        s if s > 0.7 => 0.60,
        s if s > 0.5 => 0.40,
        s if s > 0.3 => 0.20,
        _ => 0.0,
    };

    (base_cost_sats as f64 * (1.0 - rebate_pct)) as u64
}
```

Contribution score is computed monthly based on:
- Attestation volume provided
- Attestation accuracy (verified retrospectively via dispute outcomes)
- Uptime / SLA compliance
- Diversity of attestation sources (encourages broad coverage)

### 5.6 Slashing Rewards (Stream 5, Occasional)

When an oracle is slashed (10% bonded confiscated), distribution:
- 50% burned
- 30% to oracles that detected and reported the violation
- 20% to dispute resolver (Kleros-style mechanism)

Estimated frequency: 1-3 slashing events per year (in established network).

### 5.7 Total Estimated Revenue per Oracle (Year 3+)

For a typical tier-1 oracle (Chainalysis-scale) with high contribution score:

```
Stream 1 (block reward share):           $104k
Stream 2 (inbound attestation fees):     $166k
Stream 3 (subscription tier share):      $350k
Stream 4 (outbound query rebates):     ~$400k effective (vs $4M paid without rebate)
Stream 5 (slashing rewards):              $50k
─────────────────────────────────────────────
TOTAL effective annual revenue:        ~$1.07M

Less operations cost:
  TEE infrastructure:                    $80k
  Engineering staff (1 FTE):            $200k
  Monitoring + integration:              $50k
  Audit/compliance:                      $30k
─────────────────────────────────────────────
TOTAL operations cost:                 $360k

NET PROFIT per tier-1 oracle:          ~$700k/year
Margin: ~65%
```

For a tier-3 (academic/research) oracle with lower volume, baseline ($104k) covers operations costs (~$80k for university lab) — not profitable but covers cost of contribution.

## 6. Bidirectional ZK API

The bidirectional ZK API is the core innovation that makes BLOCH's oracle model competitive. It enables oracles to enrich their analytics with BLOCH chain data without compromising user privacy or violating GDPR.

### 6.1 Two-Way Information Flow

**Direction 1: Oracle → Chain (Inbound — already in ADR-002)**

```
Oracle observes external data (OFAC list, sanctions, mixer addresses)
    ↓
Oracle generates BLS attestation + ZK commitment
    ↓
Submitted on-chain via PoBRS contract
    ↓
VASPs consume attestation when needed (paying inbound query fee)
```

**Direction 2: Chain → Oracle (Outbound — NEW)**

```
Oracle submits ZK query to chain endpoint
    ↓
Chain prover infrastructure generates ZK proof responding to query
    ↓
Oracle receives proof + answer (without raw data exposure)
    ↓
Oracle pays outbound query fee in BLOCH
```

### 6.2 Query Catalog (Phased Rollout)

#### Layer 1 — Basic Queries (v1.0 mainnet)

| Query Code | Description | Proof Type | Base Cost |
|-----------|-------------|------------|-----------|
| Q-S1 | Did address X transact between blocks N and M? | Existence proof | 1 BLOCH |
| Q-S2 | Is total volume of X in last 30 days within range [A, B]? | Bulletproof range | 2 BLOCH |
| Q-S3 | How many distinct counterparties did X have (bucketed)? | Cardinality bucket | 3 BLOCH |
| Q-S4 | Is X a contract or EOA? | Type proof | 1 BLOCH |
| Q-S5 | First and last activity blocks for X (bucketed)? | Range proof | 2 BLOCH |

#### Layer 2 — Intermediate Queries (v1.5+)

| Query Code | Description | Proof Type | Base Cost |
|-----------|-------------|------------|-----------|
| Q-M1 | Does X receive funds traceable to flagged source within N hops? | Taint proof | 10 BLOCH |
| Q-M2 | Is X member of behavioral cluster Y? | Cluster membership | 15 BLOCH |
| Q-M3 | Has X exhibited mixing pattern in last 90 days? | Pattern matching | 20 BLOCH |
| Q-M4 | Does transaction graph of X match suspicious template? | Graph match | 25 BLOCH |
| Q-M5 | Is X likely controlled by sanctioned entity (probabilistic)? | Inference proof | 30 BLOCH |

#### Layer 3 — Complex Queries (v2+, research-grade)

| Query Code | Description | Proof Type | Base Cost |
|-----------|-------------|------------|-----------|
| Q-C1 | Compute centrality score of X in subgraph | zkVM computation | 50 BLOCH |
| Q-C2 | Match X transaction patterns against known fingerprints | zk ML inference | 100 BLOCH |
| Q-C3 | Cross-chain correlation of X with external chain addresses | Cross-chain ZK | 75 BLOCH |

### 6.3 ZK Proof System Selection

To preserve post-quantum coherence, queries must use one of:

- **zk-STARKs** — Plonky3 or RISC Zero. PQ-secure via hash-based commitments.
- **Lattice-based ZK** (research) — for v2+ when primitives mature.

**Explicitly rejected:**
- ❌ Groth16, PLONK over BN254 (quantum-vulnerable elliptic curves)
- ❌ Bulletproofs over secp256k1 (quantum-vulnerable curve, despite being a STARK-like construction)

For v1.0, **Plonky3 with Poseidon hash** is the candidate (already part of BLOCH's planned PoBRS architecture).

### 6.4 Prover Infrastructure

Generating ZK proofs is computationally expensive. Three options:

**Option A — Decentralized prover marketplace** (RiscZero-style)
- Provers monitor pending queries, generate proofs, get paid
- Most decentralized, but high latency

**Option B — BLOCH Labs centralized prover service**
- Fast UX, single point of failure
- Suitable for v1.0 bootstrap

**Option C — Hybrid (recommended)**
- Default: BLOCH Labs prover service for low-latency queries
- Advanced: Open marketplace for cost-sensitive queries
- Migrates to A as marketplace matures

**Decision: Option C, starting with B-heavy, transitioning to A-heavy over 24 months.**

### 6.5 Privacy Guarantees

To prevent leakage via query patterns:

1. **Query mixnet:** queries are routed via Tor-like privacy network before reaching chain prover.
2. **Cryptographic blinding:** oracle identity decoupled from query content via blinding tokens.
3. **Differential privacy:** noise added to range and count responses to prevent triangulation attacks.
4. **Rate limiting per address:** maximum N queries about any single address per 24 hours, aggregated across all oracles.
5. **GDPR compliance:** all raw data off-chain; on-chain only ZK commitments; right-to-erasure satisfied via off-chain deletion.

### 6.6 Fee Distribution for Outbound Queries

Per query fee paid by oracle:
- 50% burned (deflationary pressure on BLOCH)
- 30% deposited into endowment buffer (per ADR-010)
- 20% distributed pro-rata to other oracles (rebate pool — funds the rebate mechanism in 5.5)

This creates a positive feedback loop: more outbound queries → more rebate pool → more attractive for oracles to contribute attestations → more inbound revenue → more attractive for VASPs to integrate.

## 7. Implementation Plan

### Sprint 2.4 — Oracle Specification Finalization (2026-07-15 to 2026-08-15)

- [ ] Finalize Genesis Oracle Charter document with selection rationale.
- [ ] Implement `src/oracle/eligibility.rs` with anti-concentration rules.
- [ ] Implement `src/oracle/registry.rs` with rotation mechanism.
- [ ] Property tests for anti-concentration invariants.

### Sprint 3.0 — Outreach to Tier-1 Oracles (2026-09-01 to 2026-12-01)

- [ ] Formal outreach to Chainalysis (Crypto Investigations Lead)
- [ ] Formal outreach to TRM Labs (CEO Esteban Castaño)
- [ ] Formal outreach to Elliptic (UK + EU positioning)
- [ ] Formal outreach to Mastercard Crypto Secure
- [ ] Tier 2/3/4 outreach (Merkle Science, Coinfirm, Notabene, academic partners)
- [ ] LOIs signed with minimum 8 of 12 target oracles before mainnet launch

**Foundation budget allocation: $50-100k for outreach (events, travel, demo infrastructure).**

### Sprint 3.1 — Compensation Implementation (2026-12-01 to 2027-02-01)

- [ ] Implement `src/oracle/compensation.rs` with 4 streams + rebate.
- [ ] Update `src/tokenomics/distribution.rs` with revised 70/25/5 split.
- [ ] Subscription billing infrastructure (off-chain, BLOCH Labs operates).
- [ ] Slashing reward distribution mechanism.

### Sprint 3.2 — Bidirectional API v1.0 (2027-02-01 to 2027-05-01)

- [ ] Implement Layer 1 queries (Q-S1 through Q-S5) with Plonky3 proofs.
- [ ] BLOCH Labs prover service infrastructure deployed.
- [ ] API documentation and client SDKs (Rust, TypeScript, Python).
- [ ] Mixnet integration for query privacy.
- [ ] Differential privacy framework calibrated.

### Sprint 3.3 — Mainnet Launch (Target: ~Q3 2027)

- [ ] Genesis with 12 oracles registered and bonded.
- [ ] Oracle compensation streams activate from block 1.
- [ ] Public dashboard for oracle network state.
- [ ] First inbound attestations and outbound queries processed.

### Sprint 4.0+ — Layer 2/3 Queries (Post-mainnet, 6-24 months)

- [ ] Layer 2 queries (Q-M1 through Q-M5) implementation.
- [ ] Decentralized prover marketplace bootstrap.
- [ ] Layer 3 queries research and prototyping.
- [ ] Cross-chain ZK correlation (Q-C3) — depends on bridge maturity.

## 8. Consequences

### 8.1 Positive

- **Immediate institutional credibility.** Genesis with 4 tier-1 AML players gives BLOCH regulatory standing equivalent to chains years older.
- **Anti-competitive moat via incorporation.** Chainalysis, TRM, etc. become advocates rather than ignorers.
- **Defensible compliance posture.** BLOCH Labs services consume PoBRS attestations from regulated entities; SEC/FinCEN compliance argument is robust.
- **Bidirectional API as unique differentiator.** No other chain offers this — creates new product category.
- **Sustainable oracle economics.** $700k+ annual net profit per tier-1 oracle is sufficient to attract serious participation.
- **Privacy-preserving by construction.** ZK proofs + off-chain raw data ensure GDPR compliance.
- **Post-quantum coherent.** All cryptography uses STARKs or PQ-secure primitives.
- **Compatible with existing BLOCH design.** Reuses PoBRS infrastructure (already in ADR-002 / Sprint 1.5).

### 8.2 Negative

- **Centralization risk in genesis.** Curated selection means Foundation has control at genesis. Mitigation: 2-year mandate forces rotation; anti-concentration rules; public charter.
- **Tier-1 incumbents may have conflicts of interest.** Chainalysis sells competing product (off-chain analytics). Could deliberately under-perform on PoBRS. Mitigation: SLA monitoring + slashing + reputation tracking.
- **Reduced miner/validator revenue.** Oracle pool's 5% comes from somewhere. ADR-010 update reduces validator pool from 30% to 25%. Acceptable but requires explicit communication.
- **Implementation complexity.** Bidirectional ZK API is substantial engineering effort. Layer 1 alone is ~6 months work.
- **Foundation outreach cost.** $50-100k pre-mainnet outreach is meaningful budget allocation.
- **Prover infrastructure cost.** Plonky3 proof generation requires specialized hardware. BLOCH Labs absorbs this initially.
- **Dependency on tier-1 cooperation.** If Chainalysis et al. decline participation, alternative composition needed (likely lower credibility).

### 8.3 Open Risks

- **R1.** Genesis oracle decline. If 2+ tier-1 candidates decline, replace with tier-2 alternates. Mitigation: 6-month outreach buffer pre-mainnet.
- **R2.** Regulatory pressure to "freeze on-chain" rather than tag. US Treasury could pressure tier-1 oracles to refuse attesting unless BLOCH implements freezing. Mitigation: legal opinion letter pre-mainnet defending tag-only model under Tornado Cash precedent.
- **R3.** ZK proof generation costs higher than estimated. If proofs cost $1+ each in compute, query economics break. Mitigation: research phase in Sprint 3.2 calibrates costs before mainnet.
- **R4.** Differential privacy parameters insufficient. Adversaries could triangulate via repeated queries. Mitigation: rate limits + DP audit by external researcher pre-mainnet.
- **R5.** Subscription billing complexity. Off-chain billing for $5-100k/month subscriptions requires legal contracts, accounting infrastructure. BLOCH Labs (Delaware C-Corp) handles this; not protocol concern.
- **R6.** Mainnet timeline pressure. Sprint 3.3 mainnet target Q3 2027 requires Sprint 2.4-3.2 to execute on schedule. Slippage cascades.

## 9. Validation Metrics Post-Mainnet

| Metric | Target (Year 1) | Target (Year 3) | Threshold |
|--------|-----------------|-----------------|-----------|
| Active oracles | 12 of 12 | 12 of 12 | < 10 = critical |
| Inbound query volume | 100k/month | 1M/month | < 10k/month = adoption failure |
| Outbound query volume | 10k/month | 200k/month | Used by oracles for enrichment |
| VASP integrations | 5 | 30 | Listings bottleneck |
| Slashing events | 0-1 | 0-3 | > 5 = governance issue |
| Average oracle profit margin | Positive | > 50% | Negative = attrition risk |
| Anti-concentration violations | 0 | 0 | Any = bug |

## 10. References

- ADR-002 — PoBRS specification (this ADR extends)
- ADR-005 — Committee structure (parallel bonding model)
- ADR-010 — Tokenomics (requires update for 5% oracle pool)
- ADR-017 — Compliance framework (pending, complementary)
- Chainalysis Reactor product documentation (compliance attestation reference)
- TRM Labs Risk Score methodology (taint analysis reference)
- Plonky3 specification (zk-STARK proof system)
- RISC Zero zkVM (alternative prover system)
- Tornado Cash legal precedent (protocol neutrality defense)
- FATF Travel Rule guidelines (compliance baseline)
- GDPR Article 17 (right to erasure compatibility)

---

**Revision history:**

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-04-29 | Initial draft consolidating oracle eligibility, compensation, and bidirectional ZK API. |
