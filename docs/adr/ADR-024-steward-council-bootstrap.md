# ADR-024 — Steward Council Bootstrap Procedure

| Field             | Value                                                              |
| ----------------- | ------------------------------------------------------------------ |
| **Status**        | **SUPERSEDED** (was: Proposed) — see the note directly below this table |
| **Date**          | 2026-05-01                                                         |
| **Authors**       | Founder (custodial)                                                |
| **Reviewers**     | (TBD — US securities counsel, governance engineering team)         |
| **Supersedes**    | None                                                               |
| **Superseded by** | Genesis-4 (proof of stake, live since 2026-08-13) — see note below |
| **Related ADRs**  | ADR-011 (FFG BFT), ADR-018 (oracle network), ADR-022 (signature curve), ADR-023 (Foundation Genesis Model) |
| **Reference doc** | `BLOCH-FGM-001 v1.0` §11                                            |


> **Status note, 2026-08-14.** The Steward Council **does not exist**. Genesis-4 launched without it, and the ADRs it depends on (ADR-011 FFG, ADR-022 BLS) are themselves superseded by a proof-of-stake design with no FFG committee and no BLS. Nothing in this procedure has been executed.
>
> The decision, context and consequences below are **not** rewritten:
> this is a decision log and what was decided, when, is the record.
> Read it as history, not as guidance. Genesis-3 (proof of work) stopped
> permanently at height **39,918** on 2026-08-13; the live chain is
> **Genesis-4, proof of stake**.

---

## 1. Context

ADR-023 D-3 establishes that the inaugural Steward Council — the body that incorporates the Foundation — is constituted by a community-led procedure with hard exclusions of the founder, holders above 1% of supply, and Postern Labs personnel. ADR-023 specifies the principles but defers the engineering and on-chain mechanics.

This ADR specifies the engineering. It defines the petition lifecycle, the smart-contract-equivalent on-chain logic for nomination and confirmation, the data structures, the eligibility computation, the anti-Sybil controls, and the cryptographic anchoring of off-chain documents.

The procedure must satisfy three properties:

* **Verifiable.** Each step (eligibility, nomination, vote, tally, exclusion) is independently reproducible from chain state plus a small set of openly published off-chain documents.
* **Capture-resistant.** No single party — including the founder, a coalition of large holders, a coalition of validators, or Postern Labs — can determine the outcome.
* **Bounded in time and resource.** The procedure executes within a defined window with defined gas costs, and does not require validators to do unbounded computation.

The procedure runs once for the inaugural Council. Subsequent Council elections are governed by the Foundation's statutes and are out of scope for this ADR.

---

## 2. Decision

### 2.1 D-1 — Procedure phases

The procedure has six phases, each with a fixed time window. The total duration from the start of phase P-1 to the end of phase P-6 is **88 days** (12.5 weeks).

| Phase | Name                       | Duration | Description                                                                  |
| ----- | -------------------------- | -------- | ---------------------------------------------------------------------------- |
| P-1   | Eligibility snapshot       | 7 days   | Eligibility for validators and holders is computed and frozen.               |
| P-2   | Petition opening           | 14 days  | Anyone may publish draft petitions. Petitions accumulate signatures.         |
| P-3   | Nomination                 | 21 days  | Eligible validators and holders submit nomination tickets for inclusion in the candidate set. |
| P-4   | Candidate finalization     | 7 days   | Top-N candidates by combined nomination score advance.                       |
| P-5   | Confirmation vote          | 14 days  | Quadratic-weighted holder vote, validator vote, statute ratification.        |
| P-6   | Tally and Council seating  | 7 days   | Tally finalized, Council members published, statute ratified.                |
| —     | Total                      | 88 days  | —                                                                            |

The procedure may be re-run from P-1 if any phase fails its own validity conditions (insufficient petitions, insufficient nominees, failed quorum). Re-runs do not reset the seasoning period of ADR-025; they only restart the bootstrap procedure itself.

### 2.2 D-2 — Eligibility (P-1)

**Validator eligibility.** A validator address `V` is eligible to participate in the bootstrap if all of the following hold at the snapshot block `B_snap`:

* `V` is in the active validator set at `B_snap`.
* `V` has continuous validator-set membership over the seasoning period (i.e., for `B_snap − seasoning_blocks ≤ b ≤ B_snap`, `V` was a member at `b`).
* `V`'s uptime over the seasoning period is ≥ 90%, computed as `signed_blocks / expected_blocks` where `expected_blocks` accounts for committee rotation.

**Holder eligibility.** A holder address `H` is eligible if all of the following hold:

* Balance of `H` at `B_snap` is ≥ `0.0005 × circulating_supply(B_snap)`.
* Balance has been ≥ that threshold continuously for the prior 60 days, measured at every block (a single dip below the threshold disqualifies for the inaugural procedure).
* `H` is not in the **excluded set** defined in §2.6.

Eligibility is computed by validators as part of normal block-production duties at `B_snap` and the eligibility set is committed to chain state in a Merkle root `eligibility_root`. This root is the canonical reference for all subsequent phases.

### 2.3 D-3 — Petition opening (P-2)

A **petition** is a record consisting of:

```rust
struct Petition {
    petition_id:       Hash,                  // SHA-256 of the petition text + statutes
    petition_text_uri: String,                // off-chain location (IPFS or HTTPS)
    petition_hash:     Hash,                  // SHA-256 of the petition text
    statutes_uri:      String,                // off-chain location of draft statutes
    statutes_hash:     Hash,                  // SHA-256 of the statutes draft
    proposer:          Address,               // any address; not required to be eligible
    opens_at:          BlockHeight,           // start of P-3 (inherited from P-2 schedule)
    closes_at:         BlockHeight,           // end of P-5
    eligibility_root:  Hash,                  // bound to the snapshot from P-1
    target_jurisdiction: Jurisdiction,        // Switzerland | Singapore
    created_at:        BlockHeight,
}
```

Anyone may publish a petition during P-2 by submitting a transaction containing the above record. Petitions are not exclusive: multiple petitions may be in flight in parallel. Each petition independently runs through P-3, P-4, P-5, and P-6.

The off-chain documents (petition text, statutes draft) are published before the on-chain transaction. The on-chain transaction commits to their hashes; tampering is detectable.

For P-3 to begin for a given petition, the petition must accumulate **endorsement signatures** from at least:

* **5 distinct eligible validators**, *and*
* **eligible holders representing ≥ 1% of circulating supply at the eligibility snapshot**.

Endorsement is non-binding: it expresses willingness for the petition to advance to nomination. Endorsements are collected during P-2.

If multiple petitions advance, the Foundation will be incorporated under whichever petition succeeds at P-6. If multiple petitions succeed at P-6, the procedure is invalid and re-runs from P-1 (this is an accepted edge case; the petition design discourages it through endorsement collection).

### 2.4 D-4 — Nomination (P-3)

For each advancing petition, eligible validators and eligible holders submit **nomination tickets**.

```rust
enum VoterKind { Validator, Holder }

struct NominationTicket {
    petition_id: Hash,
    voter:       Address,
    voter_kind:  VoterKind,
    nominees:    Vec<Address>,                // each ticket nominates 1 to 9 addresses
    signature:   MlDsa65Signature,            // signed by `voter`
}
```

Constraints:

* A given `voter` may submit at most one nomination ticket per petition.
* `nominees` must contain between 1 and 9 distinct addresses.
* Nominee addresses must not be in the excluded set (§2.6); tickets containing excluded nominees are rejected at submission.
* Nominees must self-attest acceptance of nomination by submitting an `AcceptanceTicket` (signed) before P-3 closes.

**Scoring.** Each nominee's score is computed as:

```
score(nominee) = α × validator_endorsements(nominee)
               + β × sqrt_holder_endorsements(nominee)
```

with `α = 1.0` and `β = 1.0` initial values. Top-30 nominees by score advance to P-4. Ties at the 30th position are broken by lexicographic order of nominee address.

The √-weighted holder endorsement count converts holder nominations into the same quadratic regime that applies in P-5, removing whale advantage at the nomination stage.

### 2.5 D-5 — Candidate finalization (P-4)

In P-4, the candidate set is finalized. The Council will have between 5 and 9 members; the petition's draft statutes specify the exact number `K` within this range. The top `K × 3` candidates from P-3 (capped at 30) advance to the confirmation vote.

Candidates may withdraw during P-4 by submitting a `WithdrawalTicket`. Withdrawals trigger backfill from the next-highest-scored candidate.

### 2.6 D-6 — Excluded set

The excluded set is computed at `B_snap` and is the union of:

* **Founder addresses.** The founder's premine wallet addresses, declared in genesis state and immutable.
* **Postern Labs addresses.** Addresses disclosed by Postern Labs in its quarterly transparency report most recently published before `B_snap`. Postern Labs is required to disclose; addresses not disclosed but later proven to be Postern Labs' result in invalidation of the procedure.
* **Large-holder addresses.** Any address whose balance at `B_snap` is ≥ `0.01 × circulating_supply(B_snap)`.
* **Controlled addresses.** Any address in a controlling relationship with the above. Controlling relationships are self-disclosed; undisclosed controlling relationships are addressed under §2.10 (challenge procedure).

Exclusion applies to:

* Eligibility to be **nominated** (P-3, P-4): excluded addresses cannot become Council candidates.
* Eligibility to be **a Council member** post-seating (P-6): if an excluded address is somehow elected, the Council is invalid.

Exclusion does not apply to:

* Eligibility to **endorse petitions** (P-2): any address may endorse.
* Eligibility to **nominate** (P-3): any eligible holder/validator may nominate, including those above the 1% threshold (their nominations have lower quadratic weight, but they may still nominate).
* Eligibility to **vote** (P-5): any eligible holder/validator may vote.

The exclusion is asymmetric: large holders and Postern Labs personnel can participate in selecting the Council but cannot be on it. This is the structural form of the rule that the Council is independent of the parties most likely to benefit from a captured Foundation.

### 2.7 D-7 — Confirmation vote (P-5)

```rust
struct ConfirmationVote {
    petition_id:    Hash,
    voter:          Address,
    voter_kind:     VoterKind,
    approvals:      BTreeMap<Address, bool>,  // approve or reject each candidate
    statute_vote:   bool,                      // ratify draft statutes
    signature:      MlDsa65Signature,
}
```

**Holder tally (quadratic, capped).**

For each candidate `C`, the holder approval weight is:

```
w_holder(C) = Σ over voting holders H who approved C:
                min(sqrt(balance(H)), p90_cap)
```

where `p90_cap` is the 90th percentile of `sqrt(balance)` across all voting holders. This caps the per-voter contribution at the 90th percentile, preventing a small number of large holders from determining outcomes while still allowing them voice.

**Validator tally.**

For each candidate `C`, the validator approval weight is the count of voting validators who approved `C`. Each validator counts as 1.

**Approval requirement.** Candidate `C` is approved if:

* `w_holder(C)` ≥ ⅔ of the total weighted holder vote, *and*
* `w_validator(C)` ≥ ⅔ of voting validators.

A candidate that fails either of the ⅔ thresholds is not on the Council, even if it is among the top `K`.

**Statute ratification.** The draft statutes are ratified if both:

* ⅔ of the weighted holder vote ratifies, *and*
* ⅔ of voting validators ratify.

If statutes fail ratification but Council members are confirmed, the procedure is invalid and re-runs.

**Quorum.** P-5 has a minimum participation quorum:

* At least **40% of weighted-eligible holders** (by sqrt(balance)) must vote.
* At least **40% of eligible validators** must vote.

If quorum is not met, the procedure is invalid and re-runs from P-2.

### 2.8 D-8 — Tally and Council seating (P-6)

In P-6, the canonical chain runs the tally as a deterministic computation over chain state. The tally output is:

```rust
struct CouncilSeating {
    petition_id:        Hash,
    council_members:    Vec<Address>,         // K members, sorted by approval weight
    statutes_hash:      Hash,                 // ratified statutes
    statutes_uri:       String,
    seated_at:          BlockHeight,
    quorum_met:         bool,
    holder_quorum_pct:  u32,                  // basis points
    validator_quorum_pct: u32,                // basis points
    eligibility_root:   Hash,
}
```

`CouncilSeating` is committed to chain state at the close of P-6. From that block forward, the Council is on-chain-recognized as the inaugural Steward Council. The Council members may then sign messages with their declared keys to legally engage counsel and incorporate the Foundation per the ratified statutes.

### 2.9 D-9 — Cryptographic anchoring

All off-chain documents in this procedure (petition text, statutes draft, jurisdiction analysis) are anchored on-chain by hash. Specifically:

* Petition text and statutes are hashed with SHA-256.
* The hash is committed in the on-chain `Petition` record.
* The off-chain document is published at a stable URI (IPFS CID or HTTPS with content-hash assertion).
* Verifiers compare the on-chain hash to the off-chain document; discrepancies invalidate the petition.

For statute ratification specifically, the on-chain `statutes_hash` is the binding reference. The Council, post-seating, uses the statutes corresponding to that hash to incorporate the Foundation. If a different statutes document is later used to incorporate, the incorporation is non-conforming with the bootstrap procedure and the Foundation's claim to be the BLOCH Foundation is contestable.

### 2.10 D-10 — Challenge procedure

Any participant may challenge the procedure by submitting a `Challenge` transaction during P-6 with evidence of:

* Eligibility computation error (e.g., an address was incorrectly counted in a balance threshold).
* Excluded-set omission (e.g., an address proven to be Postern Labs that was not disclosed).
* Vote tampering (e.g., signatures from non-voters).

Challenges are evaluated by the validator set as part of P-6 finalization. A challenge that is upheld invalidates the procedure and triggers a re-run from P-1. A challenge that is rejected has no effect; challengers face no penalty for good-faith challenges, but malicious challenges (proven to be made with knowledge of falsity) face slashing if submitted by a validator.

---

## 3. Rationale

### 3.1 Why two-stage selection (nominate, then confirm)

Single-stage selection (everyone votes among an open list of candidates) is vulnerable to vote-splitting: a small organized group can elect a slate even if the majority opposes it, because the majority's votes scatter across many uncoordinated candidates. The two-stage design — nomination produces a bounded candidate set, confirmation is approval-style across that set — concentrates the majority's voice at the confirmation stage where it can express opposition to specific candidates.

### 3.2 Why ⅔ thresholds in both validator and holder dimensions

A ⅔ supermajority of either alone is insufficient: a coalition of 51% of holders or 51% of validators could elect a captured Council. Requiring ⅔ in *both* dimensions means a captured Council requires capture of ⅔ of both groups simultaneously, which is materially harder.

The ⅔ threshold matches the FFG BFT super-majority parameter from ADR-011 (committee 21, super-majority 14 ≈ ⅔). This is intentional: governance and consensus use the same threshold, simplifying the reasoning about safety conditions.

### 3.3 Why quadratic voting with percentile-90 cap, not pure quadratic

Pure quadratic voting (weight = √balance) reduces but does not eliminate whale advantage; a holder with 100× the balance of another holder still has 10× the voting weight. The percentile-90 cap on √balance bounds any individual voter's contribution to no more than the contribution of the holder at the 90th percentile, regardless of how much larger their balance is. Above the 90th percentile, additional balance does not buy additional voting weight.

The trade-off is that the very largest holders (top 10%) have their effective influence reduced. This is acceptable for the inaugural Council bootstrap, where capture-resistance is the dominant concern. Subsequent elections under Foundation statutes may use a different vote-weighting rule.

### 3.4 Why the founder is in the excluded set as a hard rule

The founder's exclusion is the structural mechanism that makes ADR-023 D-2 verifiable. Without it, "the Foundation is incorporated by the community, not by the founder" is an aspirational claim; with it, the claim is enforced by the chain itself. The chain refuses to accept the founder's address as a Council nominee, regardless of how much support exists for that nomination.

This is more restrictive than necessary in the symbolic case (the founder may be a legitimate Council candidate by ordinary measures of merit) but is necessary in the structural case (the structural defense against Howey requires the founder's exclusion at the moment of incorporation).

### 3.5 Why no quorum on petitions, but quorum on confirmation

Petitions are an open invitation: any eligible holder/validator may publish one. Petitions that lack support simply fail to advance to P-3. Confirmation, by contrast, decides the outcome; without a quorum, the outcome would be determined by a self-selecting subset of voters and would not reflect the network's general willingness to accept the Council. The 40% quorum is calibrated to be high enough to ensure broad participation but low enough to be achievable in a network where many holders are passive.

### 3.6 Why 88 days

The procedure is long (≈ 3 months). This is intentional: the inaugural Council bootstrap is a one-time event, and rushing it favors organized minorities. The 88-day window gives passive holders time to receive notification, evaluate candidates, and vote. Subsequent Council elections under Foundation statutes may be shorter.

---

## 4. Consequences

### 4.1 Positive

* **Verifiable from chain state.** Every step except the off-chain documents (which are hash-anchored) is reproducible from the chain. An independent observer can verify that the Council was correctly seated.
* **Hard exclusion of founder and Postern Labs.** The structural defense in ADR-023 is enforced by code, not by promises.
* **Quadratic voting with percentile cap reduces whale capture** without disenfranchising large holders entirely.
* **Two-thirds-of-each thresholds** require coordinated capture across both validator and holder populations.
* **Time-bounded.** The procedure has a known completion horizon, which is important for the post-Phase-2 transition timeline.

### 4.2 Negative

* **Procedural complexity.** 88 days, six phases, on-chain state for petitions/nominations/votes is substantial engineering. The smart-contract-equivalent logic must be in the canonical client; this is non-trivial Rust work and adds a code path that must be audited.
* **Bootstrap dependency on validator set quality.** If the validator set at the eligibility snapshot is itself captured (e.g., a coalition holds a majority of validators), the procedure can be steered. The decentralization metrics in ADR-025 are designed to prevent this from being the case at the snapshot, but the dependency exists.
* **Re-runs are costly.** A failed procedure (insufficient quorum, multiple successful petitions, upheld challenge) restarts the 88-day clock. This delays Foundation incorporation but does not invalidate the model.
* **40% quorum is high.** In some Layer-1s, voter turnout for governance is well below 40%. If BLOCH's holder participation is similarly low, quorum may not be met and the procedure may need to be re-run with a lower threshold (which would require an ADR amendment).

### 4.3 Neutral

* The procedure runs once for the inaugural Council. Subsequent Council elections are governed by Foundation statutes and may differ.
* Multiple petitions in P-2 are technically permitted but practically disincentivized through endorsement collection.
* The procedure is observable but not interruptible by validators or by the founder once started.

---

## 5. Alternatives considered

### 5.1 A-1 — Single-stage approval voting

**Description.** No nomination phase; holders directly approve any address from an open list during a single vote.

**Why rejected.** Vote-splitting; no bounded candidate set to debate against; impractical with thousands of nominees.

### 5.2 A-2 — Random selection from eligible holders (sortition)

**Description.** Council is randomly selected from eligible holders weighted by stake.

**Why rejected.** Sortition produces uncorrelated random outcomes; some draws will produce Councils manifestly unfit for the role (insufficient legal/business expertise, geographic concentration in a high-risk jurisdiction). The community-led-petition design allows the community to signal preferences for fitness; sortition cannot.

### 5.3 A-3 — Founder appoints, community confirms

**Description.** Founder nominates Council; community votes to confirm.

**Why rejected.** Re-introduces the founder as the architect of the inaugural Council. Direct violation of ADR-023 D-2.

### 5.4 A-4 — Council selected by an existing trusted DAO

**Description.** Outsource the bootstrap to a respected existing DAO (e.g., Optimism Citizen House, Gitcoin).

**Why rejected.** Introduces a third-party dependency that has its own governance properties and may not be neutral toward BLOCH. Also, importing a DAO's selection process imports its capture risks. The bootstrap should be BLOCH-native.

### 5.5 A-5 — Direct election by validators only

**Description.** Validators alone select the Council; holders have no role.

**Why rejected.** Validators are a small, identifiable set; direct election by them invites validator-coalition capture. Holders' participation, even if quadratically diluted, expands the set of parties whose buy-in is required.

### 5.6 A-6 — No procedural exclusions; rely on community to not elect founder

**Description.** Allow founder to be nominated; trust voters to not confirm.

**Why rejected.** The structural defense in ADR-023 D-2 requires hard exclusion; soft norms are not enforceable from chain state and not credible to regulators reviewing the model.

---

## 6. Open questions for review

1. **Off-chain document availability.** What is the canonical off-chain anchor (IPFS, Arweave, foundation site)? IPFS pinning by whom?
2. **Acceptance ticket signature.** Should nominees be required to sign an `AcceptanceTicket` from a wallet or from a separate identity key? Identity key is more general but adds key management burden.
3. **Challenge slashing parameter.** What stake amount is slashed for a malicious challenge? Default proposal: 1% of validator stake.
4. **Quorum re-run policy.** If quorum fails twice in succession, should the threshold automatically lower? Or should the procedure pause for a community discussion period?
5. **Statute draft circulation.** Should there be a minimum review period for statutes between publication and ratification, separate from the petition window? Recommend: yes, ≥ 14 days within P-2.
6. **Multilingual statute translations.** Statutes will be ratified in English (per BLOCH convention). Translations for the incorporation jurisdiction (German for Switzerland, English for Singapore) are produced by the Council post-seating. Hash-binding applies only to the English original.

---

## 7. Implementation notes

The procedure is implemented as a built-in protocol module, not a smart contract, because (a) BLOCH's smart-contract layer is post-mainnet and may not be operational at the bootstrap moment, and (b) the procedure has consensus-critical aspects (eligibility computation, exclusion enforcement) that benefit from validator-side verification rather than VM execution.

Module location: `crates/governance/bootstrap/`.

Key types: `Petition`, `NominationTicket`, `ConfirmationVote`, `CouncilSeating`, `Challenge`, `EligibilityRoot`.

Storage: under `governance/` namespace in RocksDB, with column families for petitions, tickets, votes, and seating records.

Tests required (storage write e2e plus tally-correctness invariants):

* Eligibility computation deterministic across nodes.
* Exclusion-set enforcement at submission.
* Quadratic tally with percentile-90 cap correctness.
* Two-thirds-of-each tally correctness.
* Re-run on quorum failure, on multi-petition success, on upheld challenge.
* Edge case: zero eligible holders (procedure invalid, re-run).
* Edge case: zero nominees from P-3 (procedure invalid, re-run).

---

## 8. References

* ADR-011 — FFG BFT: ⅔ super-majority alignment.
* ADR-018 — Oracle network: precedent for on-chain registry with disclosure requirement (Postern Labs disclosure parallels Tier-1 oracle disclosure).
* ADR-022 — Signature curve: ML-DSA-65 used for all signatures in this procedure.
* ADR-023 — Foundation Genesis Model: D-2, D-3 specify the principles this ADR engineers.
* `BLOCH-FGM-001 v1.0` §11 — Community-governance bootstrap mechanism (textual specification).
* Vitalik Buterin, "Quadratic Payments: A Primer," 2019.
* Glen Weyl & E. Glen Weyl, *Radical Markets: Uprooting Capitalism and Democracy for a Just Society*, ch. 2 (Quadratic Voting).

---

*This ADR is normative for the protocol's repository and for the implementation of the inaugural Steward Council bootstrap. It is non-normative for subsequent Council elections, which are governed by the Foundation's statutes once incorporated. Released under CC BY 4.0.*
