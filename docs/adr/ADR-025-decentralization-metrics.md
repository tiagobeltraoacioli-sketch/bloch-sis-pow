# ADR-025 — Decentralization Metrics Computation

| Field             | Value                                                              |
| ----------------- | ------------------------------------------------------------------ |
| **Status**        | Proposed                                                           |
| **Date**          | 2026-05-01                                                         |
| **Authors**       | Founder (custodial)                                                |
| **Reviewers**     | (TBD — engineering, US securities counsel)                         |
| **Supersedes**    | None                                                               |
| **Superseded by** | None                                                               |
| **Related ADRs**  | ADR-011 (FFG BFT), ADR-023 (Foundation Genesis Model), ADR-024 (Steward Council bootstrap) |
| **Reference doc** | `BLOCH-FGM-001 v1.0` §4 Phase 2                                     |

---

## 1. Context

ADR-023 D-4 establishes five decentralization metrics (M-1 through M-5) that gate the exit of Phase 2 (the seasoning period) and therefore gate the start of Phase 3 (community foundation genesis). The metrics are the objective component of the gate; the community petition under ADR-024 is the subjective component. Both are required.

ADR-023 specifies the metrics as principles. This ADR specifies the computation: data sources, methodologies, frequency, publication format, and dispute resolution between methodologies.

The metrics are consumed by the petition contract from ADR-024: a petition cannot advance to P-2 unless `chain_state.metrics_satisfied_for_contiguous_days() >= 90`. The petition module reads this from chain state; the chain state is updated by the metrics module specified in this ADR.

The integrity of the metrics is critical because the entire regulatory defense rests on them. If the metrics are gameable, the seasoning period is theatre. The design prioritises:

* **Reproducibility from chain state alone for the canonical methodology.**
* **Independent cross-check from network-level data for the secondary methodology.**
* **Public, dated, signed reports.**
* **Detection of methodology disagreement, with conservative interpretation (the more restrictive value binds).**

---

## 2. Decision

### 2.1 D-1 — Five metrics, restated

For unambiguous reference and to fix the parameter values:

| Metric | Description                                          | Threshold | Window         |
| ------ | ---------------------------------------------------- | --------- | -------------- |
| M-1    | Nakamoto coefficient (block production)              | ≥ 20      | 90 days rolling|
| M-2    | Distinct validator operators                         | ≥ 100     | At snapshot    |
| M-2.j  | Operator jurisdictions                               | ≥ 3       | At snapshot    |
| M-3    | Maximum client-implementation share                  | ≤ 65%     | At snapshot    |
| M-4    | ADRs ratified, none authored by founder              | ≥ 3       | Cumulative since seasoning start |
| M-5    | Validator-signaled upgrades activated without founder coordination | ≥ 1       | Cumulative since seasoning start |

All metrics must be simultaneously satisfied for ≥ 90 contiguous days for Phase 2 to exit. The 90-day window is computed from the most recent block in which all metrics were satisfied; if any metric falls below threshold, the contiguous-day counter resets to zero.

### 2.2 D-2 — Two methodologies per metric

Each metric is computed by **two methodologies**:

* **Methodology A (canonical).** On-chain only. Reproducible by any validator from chain state. This is the binding methodology for the chain's `metrics_satisfied` flag.
* **Methodology B (peer).** Off-chain, includes peer-reported data, network-level observation, and external sources (WHOIS, ASN registries). Computed by a public dashboard infrastructure. Used as cross-check.

If A and B agree, the metric is reported as satisfied/unsatisfied per their agreement. If A and B disagree, the **more restrictive value binds**: a metric is reported as satisfied only if both methodologies agree it is satisfied. Disagreements are logged and trigger a public investigation.

### 2.3 D-3 — Metric M-1: Nakamoto coefficient

**Definition.** The Nakamoto coefficient for block production over a window `W` is the minimum number of distinct entities `n` such that the top-`n` block proposers, ordered by share of blocks produced in `W`, together produced > 50% of blocks in `W`.

**Methodology A.** Block proposers are identified by their proposer public key (the validator key that signed the block per ADR-011's FFG mechanism). Distinct entities are distinct proposer keys. The coefficient is computed over the most recent 90-day window.

```
def nakamoto_a(window_blocks):
    counts = Counter(block.proposer_key for block in window_blocks)
    sorted_shares = sorted(counts.values(), reverse=True)
    cumulative = 0
    total = sum(sorted_shares)
    for i, share in enumerate(sorted_shares, start=1):
        cumulative += share
        if cumulative > 0.5 * total:
            return i
    return len(sorted_shares)
```

**Methodology B.** Same computation, but distinct entities are merged where peer-reported data indicates collusion or shared infrastructure: shared IP addresses, shared ASN, shared signing patterns (correlated downtime, identical tx submission patterns), or self-reported common operator. Merged entities count as one for the coefficient.

Methodology B is more conservative (lower coefficient) when collusion indicators are present. The binding value is the lower of the two.

### 2.4 D-4 — Metric M-2: Distinct validator operators and jurisdictional spread

**M-2: Operator count.**

**Methodology A.** Count of validator keys in the active validator set at the snapshot block. Two keys are presumed distinct unless ADR-024 D-6 (controlling-relationship disclosure) merges them.

**Methodology B.** Same count, but additionally apply the collusion merging from M-1 Methodology B. Merged operators count as one.

**M-2.j: Jurisdictional spread.**

**Methodology A.** Operators self-attest jurisdiction at validator registration. Methodology A counts the number of distinct self-attested jurisdictions among validators that participated in block production in the most recent 30 days.

**Methodology B.** Cross-check self-attested jurisdiction against:

* IP address geolocation (from connection peer info, multiple sources).
* ASN registration country (WHOIS).
* Self-attested data center / hosting provider, cross-checked against the provider's known locations.

If self-attestation is inconsistent with two or more network-level signals, the validator is flagged "jurisdiction-disputed". Methodology B's count of distinct jurisdictions excludes disputed validators from its set; if removing disputed validators drops the count below 3, M-2.j is unsatisfied under Methodology B.

### 2.5 D-5 — Metric M-3: Client diversity

**Definition.** The largest client implementation, by validator count, must account for ≤ 65% of validators.

**Client identification.** Each block, when proposed, includes in its header a signed `client_id` field declaring the client implementation (e.g., `bloch-rust`, `bloch-go`, `bloch-zig`). The `client_id` is signed under the validator's key; misrepresentation is slashable misbehavior.

**Methodology A.** Count blocks per `client_id` over the most recent 30 days. Compute share of largest client.

**Methodology B.** Network-level fingerprinting: TCP/IP stack characteristics, libp2p protocol versions, gossip patterns, validator client-version-string in handshake. Each validator is classified by Methodology B independently. Counts are compared.

If A and B disagree on a validator's client classification by more than 5% of the validator set, Methodology B's classification is treated as the conservative one and binds.

### 2.6 D-6 — Metric M-4: Independent ADR ratification

**Definition.** At least 3 ADRs ratified through the on-chain process during the seasoning period, none authored by the founder.

**ADR ratification on-chain.** Each ADR, when proposed for ratification, is registered on-chain via an `ADRRegistration` transaction:

```rust
struct ADRRegistration {
    adr_id:        u32,           // monotonic
    title:         String,
    text_hash:     Hash,          // SHA-256 of canonical English text
    text_uri:      String,        // off-chain URI
    author_keys:   Vec<Address>,  // declared authors
    proposer:      Address,       // submitter (must equal first author)
    submitted_at:  BlockHeight,
}
```

Ratification is by validator-set super-majority signaling per ADR-011 and ADR-029 (TBD). When ratification crosses ⅔, the ADR is marked `ratified` in chain state.

**Methodology A.** Count ADRs ratified during seasoning where `founder_address ∉ author_keys`. Founder addresses are the immutable set declared at genesis (ADR-024 D-6).

**Methodology B.** Independent audit of git history for each ratified ADR: commit signatures, blame-trace of the ADR document, and known correspondence. If the on-chain `author_keys` omit a contributing author, that ADR is suspect; if the omitted author is the founder, it does not count toward M-4 under Methodology B.

This double-check exists because on-chain authorship is self-declared and could in principle be misrepresented. Git history is independently verifiable and harder to tamper with retroactively.

### 2.7 D-7 — Metric M-5: Founder-independent upgrade activation

**Definition.** At least 1 protocol upgrade activated during seasoning by validator-set super-majority signaling, where the founder did not propose the upgrade in an ADR.

**Upgrade signaling mechanism.** BLOCH adopts a BIP-9-style mechanism: validators set a bit in the block's `version` field to signal readiness for upgrade `U`. When ≥ 80% of blocks in any 1024-block window signal `U`, the upgrade activates at the next epoch boundary.

**Methodology A.** For each activated upgrade `U` during seasoning, look up the originating ADR. If `founder_address ∉ author_keys` of that ADR, count `U` toward M-5.

**Methodology B.** Audit of the upgrade discussion: was the founder the principal advocate, did the founder coordinate validator signaling, did the founder commit the activating code? If yes to any, the upgrade does not count toward M-5 under Methodology B.

This is the most subjective of the metrics — "founder coordination" is hard to define narrowly. The conservative interpretation is that an upgrade counts toward M-5 only if both A and B agree it is founder-independent.

### 2.8 D-8 — Computation frequency and storage

* **Per-block computation.** A reduced subset (incremental updates to running counts for M-1, M-2, M-3) is computed by validators every block as part of normal validation. This is cheap.
* **Daily snapshot.** Once every 24 hours (1 epoch ≈ 6 blocks at 150s = 15 min, so daily ≈ 96 epochs), validators commit a `MetricsSnapshot` to chain state:

```rust
struct MetricsSnapshot {
    snapshot_at:           BlockHeight,
    m1_value:              u32,        // Nakamoto coefficient (Methodology A)
    m1_satisfied:          bool,
    m2_count:              u32,        // operator count
    m2_jurisdictions:      u32,        // distinct jurisdictions
    m2_satisfied:          bool,
    m3_largest_share_bps:  u32,        // basis points (e.g., 6500 = 65%)
    m3_satisfied:          bool,
    m4_count_seasoning:    u32,        // cumulative
    m4_satisfied:          bool,
    m5_count_seasoning:    u32,        // cumulative
    m5_satisfied:          bool,
    all_satisfied:         bool,
    contiguous_days:       u32,        // how long all_satisfied has been true
}
```

* **Methodology B reports.** Published off-chain by the dashboard infrastructure on the same daily cadence. The off-chain report is signed by its author key and published at a stable URI; its hash is committed on-chain via a `MetricsCrosscheck` transaction (any participant may submit; first valid cross-check per day binds).

* **Discrepancy flagging.** If `methodology_a` and `methodology_b` disagree for 3 consecutive daily snapshots on any metric, an `MetricsDispute` event is emitted and the contiguous-day counter is paused until resolved.

### 2.9 D-9 — Public dashboard

The metrics dashboard is operated by:

* **For methodology A:** every full node running the canonical client. The data is in chain state; any node can serve it.
* **For methodology B:** initially, a service operated by the founder under temporary custody. **At Phase 3, the dashboard is transferred to the Foundation along with all other administrative custody (ADR-026).** Until then, multiple independent third-party operators are encouraged (and granted small BLOCH ecosystem grants from the validator/oracle pool) to operate parallel methodology-B dashboards. Disagreement among methodology-B operators triggers the same dispute flow as A-vs-B disagreement.

Dashboard requirements:

* Daily report archived publicly.
* Historical reports preserved (no rewriting of past data).
* Source code open under CC0 or MIT.
* Computation reproducible from the data the report claims to use.

### 2.10 D-10 — Dispute resolution

If A and B disagree for 3 consecutive snapshots, an `MetricsDispute` event is emitted and:

1. The contiguous-day counter is paused.
2. The dispute is open for 14 days for community investigation.
3. Validators may submit `DisputeEvidence` transactions: data, analysis, claims about the cause of disagreement.
4. After 14 days, validators vote (super-majority ⅔) on which methodology was correct for that period. The vote produces a `DisputeResolution` committed on-chain.
5. The contiguous-day counter resumes, with the disputed days counted under the resolved methodology.

This is heavyweight by design. Frequent disputes indicate a measurement problem and should not be resolved silently.

---

## 3. Rationale

### 3.1 Why two methodologies, not one

A single methodology is gameable. If the chain measures only on-chain proposer keys, an attacker can split a single operator into many keys (Sybil) and inflate the Nakamoto coefficient cheaply. Methodology B catches this: peer-reported data, IP/ASN, and shared signing patterns identify the Sybil. Conversely, Methodology B alone is gameable because its data sources are external (peer reports can be falsified, WHOIS can be inaccurate); Methodology A grounds it in chain state.

The "more restrictive value binds" rule means an attacker who games one methodology to inflate it does not gain — they would also have to game the other in the same direction, which is harder.

### 3.2 Why per-block incremental computation

Some metrics (M-1 in particular) are expensive to recompute from scratch. A 90-day rolling window at 150s block time contains ≈ 51,840 blocks. Recomputing the Nakamoto coefficient from scratch every block would cost ≈ 51,840 hash-table updates × 96 daily epochs = unacceptable validator overhead.

The per-block incremental approach maintains running counts in chain state and updates them as blocks come in and as the window slides. Daily snapshots produce the canonical published values from these running counts.

### 3.3 Why 90 contiguous days, not just 90 cumulative days

Contiguous satisfaction is harder to fake than cumulative. An attacker can satisfy each metric on different days and accumulate 90 cumulative days while the network has never simultaneously satisfied all metrics. The contiguous requirement forces continuous, simultaneous decentralization.

### 3.4 Why the dashboard transfers with custody

The methodology-B dashboard is, in custodial terms, an administrative asset of the protocol. Like the domains and repositories, it should not remain under the founder's control after Phase 4. Transferring it to the Foundation aligns the methodology-B authority with the Foundation's neutral stewardship.

The risk during Phase 1–3 (founder operates the dashboard) is mitigated by encouraging multiple independent third-party operators in parallel. If the founder's dashboard reports values inconsistent with third-party dashboards, the disagreement is itself evidence and triggers the dispute flow.

### 3.5 Why M-4 and M-5 are cumulative, not rolling

M-4 ("≥ 3 ADRs ratified") and M-5 ("≥ 1 upgrade activated") are accumulators of governance events. A rolling window would mean a successful Phase 2 could regress if too many ADRs were ratified early and no new ones came in later. That's a perverse incentive. The cumulative-since-seasoning-start design rewards continuous governance activity without punishing front-loaded activity.

### 3.6 Why M-3 specifies 65% and not 50%

Multi-client diversity is hard to achieve in early Layer-1s; most have a single dominant client for their first years. A 50% threshold would fail nearly every Layer-1 in history at year 1. 65% is a meaningful constraint (the dominant client must not exceed two-thirds) without being unattainable. As the ecosystem matures, the Foundation may amend this threshold downward in subsequent ADRs.

---

## 4. Consequences

### 4.1 Positive

* **Objective gating.** Phase 2 exit is determined by computable conditions, not by subjective judgment. Counsel can review the metrics and confirm that the conditions are clear.
* **Two-methodology design** reduces gameability significantly compared to single-methodology.
* **On-chain canonical record.** The `MetricsSnapshot` history is permanent and tamper-evident.
* **Public dashboard with multi-operator parallelism** distributes the methodology-B trust assumption.
* **Dispute flow is heavyweight,** which discourages spurious disputes and forces investigation when real disagreements arise.

### 4.2 Negative

* **Engineering complexity.** Five metrics, two methodologies each, daily snapshots, dispute flow, dashboard infrastructure. This is a substantial code path.
* **M-2.j (jurisdictions) depends on self-attestation,** which is fundamentally untrustworthy. The cross-check via IP/ASN/WHOIS is best-effort. A determined attacker can host across jurisdictions to satisfy M-2.j without the underlying decentralization being real.
* **M-5 (founder-independent upgrade) is the most subjective metric.** The "founder coordination" criterion is hard to define narrowly; reasonable people may disagree on whether a particular upgrade was founder-independent.
* **Dashboard during Phase 1–3 is operated by the founder** under temporary custody. The mitigation (third-party parallel operators) requires those operators to actually exist and to be incentivised; if they do not materialise, the founder's dashboard is the only methodology-B source.
* **Per-block incremental computation adds complexity to the validator state machine** and may have edge cases when the validator set changes mid-window.

### 4.3 Neutral

* The thresholds (Nakamoto ≥ 20, validators ≥ 100, jurisdictions ≥ 3, client share ≤ 65%) are calibrated for BLOCH's expected network size at Phase 2 exit and may be adjusted by future ADR.
* The 30-day window for M-2.j and M-3, vs. 90-day for M-1, is a design choice favoring fresher data on metrics that are sensitive to current state.
* Contributions to M-4 and M-5 require active participation by non-founder contributors. If no such contributors exist, M-4 and M-5 will not be satisfied and Phase 2 will not exit. This is the intended behaviour.

---

## 5. Alternatives considered

### 5.1 A-1 — Single canonical methodology (on-chain only)

**Description.** Compute metrics from chain state only, no off-chain cross-check.

**Why rejected.** Sybil attack is too cheap. An attacker inflates Nakamoto by running 50 validator keys from the same machine and the chain cannot detect it. The peer-data cross-check is essential.

### 5.2 A-2 — Single canonical methodology (peer-reported only)

**Description.** Compute metrics from peer-reported network data, not from chain state.

**Why rejected.** Peer reports are externally falsifiable. Without a chain-state ground truth, an attacker can seed false reports.

### 5.3 A-3 — Higher thresholds (e.g., Nakamoto ≥ 50, validators ≥ 1000)

**Description.** Require more demanding decentralization metrics before Phase 2 exit.

**Why rejected.** Too aggressive for a Layer-1 in its first 12–18 months. Real-world block-producer concentration in Layer-1s with ≥ 1 year of mainnet typically has Nakamoto coefficients in the 8–25 range. Setting thresholds above what successful precedents have achieved would mean Phase 2 never exits.

### 5.4 A-4 — Lower thresholds (e.g., Nakamoto ≥ 10)

**Description.** More lenient thresholds.

**Why rejected.** Insufficient for the Howey-defensibility argument. The decentralization metrics are the structural evidence that the network does not depend on the essential efforts of an identifiable group; weaker thresholds would not meet the standard counsel will require.

### 5.5 A-5 — Add staking-distribution metrics (e.g., Gini coefficient on stake)

**Description.** Include stake-distribution metrics (Gini, top-10 share, etc.).

**Why rejected.** Stake distribution and block-production distribution are correlated but not identical. The decision metric is who *produces* blocks, not who *stakes*. Adding stake metrics would add complexity without changing the substantive question. Future ADRs may add stake metrics if a specific failure mode emerges.

### 5.6 A-6 — Outsource methodology-B to a single trusted third party (e.g., a research institute)

**Description.** Have a single respected institution operate the methodology-B dashboard.

**Why rejected.** Single point of trust. The multi-operator parallel design distributes the trust and makes capture costlier. Future ADRs may upgrade methodology-B to involve specific recognized institutions if they emerge as natural operators.

---

## 6. Open questions for review

1. **Ecosystem grants for parallel methodology-B operators.** Funded from the validator/oracle pool? Operated under what disclosure regime?
2. **Dispute slashing.** Should validators face slashing for losing a `DisputeEvidence` argument? Default proposal: no slashing for losing a good-faith dispute, but slashing for proven malicious disputes.
3. **Client-id signing.** What is the exact signing format for `client_id` in the block header? Should `client_id` be in the consensus-critical part or the auxiliary part of the header?
4. **ADR-029 placeholder.** The ADR ratification mechanism (referenced in §2.6) needs its own ADR. ADR-029 (TBD) will specify it.
5. **Methodology-B IP/ASN data sources.** Which sources are canonical (MaxMind, IPinfo, RIPE/ARIN, multiple aggregated)? How are conflicting source values resolved?
6. **Reset on parameter change.** If the Foundation later amends thresholds, does the contiguous-day counter reset? Default proposal: yes, to prevent retroactive satisfaction by parameter relaxation.

---

## 7. Implementation notes

Module location: `crates/governance/metrics/`.

Key types: `MetricsSnapshot`, `MetricsCrosscheck`, `MetricsDispute`, `DisputeEvidence`, `DisputeResolution`, `ADRRegistration`, `UpgradeActivation`.

Storage: under `governance/` namespace, column families for snapshots (keyed by date), cross-checks (keyed by date + author), disputes (keyed by metric + date), and ADR registry.

Required tests:

* `m1_nakamoto_a` correctness on synthetic block-history fixtures.
* `m1_nakamoto_b_with_collusion_merging` correctness.
* `m2_j` jurisdictional spread, including disputed validators.
* `m3_client_diversity` with both A and B classifications.
* `m4_founder_authorship_filter`.
* `m5_upgrade_independence`.
* `contiguous_days` counter resets on any metric falling below threshold.
* `methodology_disagreement` triggers dispute after 3 consecutive snapshots.
* `dispute_resolution_flow` end-to-end.

Performance budget per block: ≤ 5 ms additional computation for incremental metric updates, measured on the reference validator hardware. Daily snapshot computation budget: ≤ 200 ms, run during the proposer's block construction time slot.

---

## 8. References

* ADR-011 — FFG BFT: ⅔ super-majority used for ADR ratification and dispute resolution.
* ADR-023 — Foundation Genesis Model: D-4 specifies the principles this ADR engineers.
* ADR-024 — Steward Council bootstrap: consumes `metrics_satisfied_for_contiguous_days()` from chain state.
* `BLOCH-FGM-001 v1.0` §4 Phase 2 — Decentralization seasoning (textual specification).
* Balaji Srinivasan & Leland Lee, "Quantifying Decentralization," Earn.com Blog, 2017 — origin of the Nakamoto coefficient definition.
* BIP-9 — Bitcoin upgrade signaling mechanism (model for M-5).

---

*This ADR is normative for the protocol's repository and for the implementation of the decentralization metrics. Threshold values may be amended by subsequent ADR or, post-incorporation, by Foundation board action; methodology and computation rules may not be changed without superseding this ADR. Released under CC BY 4.0.*
