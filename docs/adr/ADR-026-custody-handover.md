# ADR-026 — Custody Handover Protocol

| Field             | Value                                                              |
| ----------------- | ------------------------------------------------------------------ |
| **Status**        | Proposed                                                           |
| **Date**          | 2026-05-01                                                         |
| **Authors**       | Founder (custodial)                                                |
| **Reviewers**     | (TBD — Swiss/SG counsel, IP counsel, security engineering)         |
| **Supersedes**    | None                                                               |
| **Superseded by** | None                                                               |
| **Related ADRs**  | ADR-022 (signature curve), ADR-023 (Foundation Genesis Model), ADR-024 (Steward Council bootstrap), ADR-025 (decentralization metrics) |
| **Reference doc** | `BLOCH-FGM-001 v1.0` §4 Phase 4                                     |

---

## 1. Context

ADR-023 D-1 establishes Phase 4 — the irrevocable transfer of administrative custody from the founder to the Foundation, executed within 30 days of a valid handover request from the Foundation board after Phase 3 completes. Phase 4 is the moment at which the founder's temporary stewardship ends and the Foundation's permanent stewardship begins.

The handover is operationally complex because administrative custody comprises distinct asset classes, each with its own transfer mechanism, jurisdictional requirements, and tail-liability profile:

* **DNS authority** — registrar-mediated, requires registrar account access and may require ID verification.
* **Source code repositories** — platform-mediated (GitHub org transfer, GitLab group transfer), requires owner-level account access.
* **Trademarks** — jurisdiction-specific, requires assignment instrument and recordation with each trademark office.
* **Build infrastructure** — key rotation, requires re-issuing CI/CD signing keys and revoking old ones.
* **Public communication channels** — platform-mediated (X, Discord, Telegram), each platform has its own admin-transfer flow.
* **Validator/oracle pool multisig** — on-chain, requires re-keying the multisig.

This ADR specifies the protocol: what is transferred, in what order, by what mechanism, with what cryptographic record, and with what verification. It also specifies the emergency path (R-6 of `BLOCH-FGM-001`) for handover under founder incapacity.

The protocol prioritises:

* **Atomic-where-possible.** Where transfer can be atomic on-chain (multisig re-keying, on-chain registry updates), it is. Where transfer requires off-chain platform action (DNS, GitHub, trademarks), the on-chain Handover Certificate documents completion.
* **Ordered.** Some transfers depend on others. The order minimizes the window in which authority is split or contested.
* **Verifiable.** Each transfer step produces an artifact that can be independently verified by a community auditor.
* **Reversible only by mistake.** A completed handover is irrevocable from the founder's side. The only path to undo a handover is for the Foundation to voluntarily transfer back, on its own terms.

---

## 2. Decision

### 2.1 D-1 — Asset inventory

The following assets are within scope of the handover. The list is exhaustive; assets not on this list are not transferred and remain under whatever pre-existing arrangement applies (typically the founder's personal control, which is outside the protocol's scope).

| Asset class                      | Specific items                                                                | Transfer mechanism                                |
| -------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------- |
| DNS authority                    | `blochlayer.com`, `entl1.com`, any registered mirror domains           | Registrar account transfer                        |
| Source code repositories         | GitHub: `bloch/*` org; GitLab: `bloch/*` group; mirrors                          | Platform-mediated org/group transfer              |
| Trademark registrations          | "BLOCH" word mark, "Bloch-SIS Protocol" word mark, logos — in all jurisdictions where registered | Trademark assignment instrument + office recordation |
| Build infrastructure             | CI/CD accounts, release-artifact signing keys, package-registry publish credentials | Key rotation; account ownership transfer           |
| Public communication channels    | X (`@entl_chain`), Discord server, Telegram group, blog/Medium                | Platform-mediated admin-role transfer             |
| Documentation infrastructure     | docs.blochlayer.com hosting account, deployment keys                   | Account transfer; key rotation                     |
| Validator/oracle pool multisig   | 2-of-3 → 2-of-5 → multisig with Foundation-controlled keys                    | On-chain re-keying transaction                     |
| Methodology-B dashboard          | Hosting infrastructure for the metrics dashboard from ADR-025                 | Account transfer; key rotation                     |
| Founder identity key             | The founder's protocol-identity key used to sign protocol announcements        | **Not transferred.** Founder retains personal key. Foundation issues a new identity key for itself. |

**Out of scope:** founder's personal wallets and the premine they hold; Postern Labs Inc. assets; any asset not declared as protocol-related at genesis.

### 2.2 D-2 — Pre-handover prerequisites

Before a handover request can be issued, all of the following must be true:

* Phase 3 has completed: the inaugural Steward Council is seated on-chain per ADR-024 D-8, and the Foundation has been legally incorporated in the ratified jurisdiction.
* The Foundation board has appointed at least three signing keys for its first board (3-of-5 or similar threshold per the Foundation's statutes).
* The Foundation has published its first board's signing keys via an on-chain `FoundationKeyRegistration` transaction, signed by ⅔ of the Steward Council.
* A community auditor has been appointed by the Foundation board to verify the handover.

These prerequisites are verified by the founder before honoring a handover request. A handover request that lacks any of them is rejected; the founder publishes the rejection rationale on-chain and the Foundation rectifies before re-requesting.

### 2.3 D-3 — Handover Request

The Foundation initiates the handover by submitting a `HandoverRequest`:

```rust
struct HandoverRequest {
    request_id:           Hash,                  // SHA-256 of canonical serialization
    council_seating_ref:  Hash,                  // chain-state ref to Phase 3 CouncilSeating
    foundation_keys_ref:  Hash,                  // chain-state ref to FoundationKeyRegistration
    foundation_legal_ref: String,                // URI of incorporation certificate (off-chain, hash-anchored)
    foundation_legal_hash: Hash,                 // SHA-256 of incorporation certificate
    auditor:              Address,               // appointed community auditor
    requested_at:         BlockHeight,
    deadline:             BlockHeight,           // 30 days * blocks-per-day
    foundation_signatures: Vec<MlDsa65Signature>, // ≥ ⅔ of Foundation board
}
```

The request is submitted on-chain. Validators verify:

* Council seating reference resolves to a valid `CouncilSeating` from ADR-024.
* Foundation keys reference resolves to a valid `FoundationKeyRegistration`.
* Off-chain incorporation certificate matches the asserted hash.
* Foundation signatures are valid and cover ≥ ⅔ of the registered Foundation board.
* `deadline = requested_at + 30 days`.

A valid request starts the 30-day handover clock.

### 2.4 D-4 — Handover sequence

The handover proceeds in seven steps. Steps 1–6 are off-chain operational transfers; step 7 is the on-chain Handover Certificate that documents completion.

**Step 1 — Multisig re-keying (on-chain, atomic).** The validator/oracle pool multisig is re-keyed in a single on-chain transaction signed by the founder and the existing inaugural multisig signers. After this transaction, the multisig is controlled by the Foundation board's keys. This step is first because it is the only atomic step and fixes one piece of the puzzle immediately.

**Step 2 — DNS authority.** Registrar account access is transferred. For each domain (`blochlayer.com`, `entl1.com`, mirrors), the founder initiates a registrar-side transfer to the Foundation's account. This typically involves: (a) unlocking the domain at the source registrar; (b) issuing an authorization code; (c) Foundation initiates inbound transfer at its registrar; (d) confirmation. The auditor records each step.

**Step 3 — Trademark assignments.** For each registered trademark, the founder executes an assignment instrument in the form prescribed by the relevant trademark office (USPTO Form PTO-1594 in the U.S.; equivalent forms in other jurisdictions). The assignment is recorded with the trademark office. Recordation may take weeks; the Handover Certificate (step 7) documents the assignment as filed but recordation completion is acknowledged separately when each office completes.

**Step 4 — Source code repositories.** For each platform, the founder transfers org/group ownership to a Foundation-controlled account. GitHub: org transfer initiated, Foundation account accepts. GitLab: same flow. Mirror repositories are re-pointed to the new canonical source. CI/CD integrations are reconfigured.

**Step 5 — Build infrastructure and signing keys.** Release-artifact signing keys (used to sign published binaries, Rust crate publication, etc.) are rotated: new keys generated by the Foundation, old keys revoked. Old keys remain valid for already-published artifacts; new artifacts are signed under the new keys. The transition is announced via signed message under the old keys, with the new key fingerprints, before the old keys are revoked.

Account access for build platforms (GitHub Actions secrets, package registries) is transferred or re-issued under Foundation accounts.

**Step 6 — Public communication channels and documentation infrastructure.** Admin roles on X, Discord, Telegram are transferred or re-assigned to Foundation accounts. Hosting accounts for documentation infrastructure are transferred. The auditor verifies each platform's admin transfer.

**Step 7 — Handover Certificate (on-chain).** The founder publishes the `HandoverCertificate`:

```rust
struct HandoverCertificate {
    request_id:                  Hash,
    completed_at:                BlockHeight,
    asset_attestations:          Vec<AssetAttestation>,
    founder_signature:           MlDsa65Signature,    // founder's identity key
    foundation_signatures:       Vec<MlDsa65Signature>, // ≥ ⅔ of Foundation board
    auditor_signature:           MlDsa65Signature,
    auditor_attestation_uri:     String,              // off-chain detailed audit report
    auditor_attestation_hash:    Hash,
}

struct AssetAttestation {
    asset_class:        AssetClass,
    asset_identifier:   String,           // e.g., "blochlayer.com" or "GitHub:bloch/entl"
    transferred_at:     BlockHeight,      // approximate, off-chain action time
    transfer_evidence:  String,           // URI of evidence (transfer receipt, etc.)
    evidence_hash:      Hash,
}
```

The Handover Certificate is the binding artifact. From the block at which it is committed, the founder's administrative custody is terminated and the Foundation's stewardship is on-chain-recognized.

### 2.5 D-5 — 30-day window and extensions

The 30-day window begins at `requested_at` and ends at `deadline`. Within this window:

* Steps 1–7 must complete.
* If any step is blocked by external circumstance (e.g., a registrar requires a longer notice period; a trademark office is closed for holidays), the founder may submit a `HandoverDelayNotice` on-chain explaining the cause and requesting an extension.
* Extensions are granted by the Foundation board (requires ⅔ vote of the registered Foundation board, on-chain). Each extension is at most 30 additional days. Extensions cannot be requested by the founder for self-interested delay; the Foundation reviews the cause.
* If the founder fails to complete the handover by the (possibly extended) deadline, the Foundation may invoke the **emergency path** (§2.7).

### 2.6 D-6 — Auditor responsibilities

The community auditor appointed by the Foundation under §2.2 is responsible for verifying each handover step in real time. Specifically:

* Witnesses each off-chain step (auditor is given temporary observer access to the relevant accounts during the transfer).
* Records each step's evidence (screenshots, transaction IDs, registrar confirmations, platform notifications) with timestamps.
* Hashes the evidence and the audit report; commits hashes on-chain via `AuditorAttestation` transactions.
* Signs the final Handover Certificate as a third-party verifier.

Auditor disqualifications: the auditor cannot be a Foundation board member, the founder, or a Postern Labs employee/officer. The auditor may be a holder or validator. The auditor is compensated from the validator/oracle pool at a market rate set by the Foundation board.

If the auditor identifies a step that is not faithfully executed (e.g., founder retains hidden access to a transferred account), the auditor publishes a `HandoverDispute` on-chain and the matter is referred to the Foundation board for resolution. The dispute may pause the handover deadline.

### 2.7 D-7 — Emergency path: founder incapacity

If the founder is unable to execute the handover (medical incapacity, death, legal restraint, other unavailability), the emergency path applies.

The administrative-custody signing authority is held in a **2-of-3 multisig** from genesis, comprising:

* **Founder's primary key** (held personally by the founder).
* **Designated successor key** (held by a person nominated by the founder and registered on-chain at genesis; intended to be a family member or trusted advisor with no protocol role).
* **Notarial escrow key** (held by a Swiss notary under a notarial agreement; the notary is bound to release the key only upon presentation of a verifiable handover request from the Foundation, plus evidence of founder unavailability).

Under normal handover, the founder's key plus one other (typically successor) signs each step; the notary key is not used. Under emergency handover, the Foundation board petitions the notary; upon verification, the notary signs together with the successor, and the handover proceeds without the founder's participation.

The notarial agreement is a separate legal instrument deposited with the notary; its terms are publicly disclosed and the agreement's hash is committed on-chain at genesis. The notarial key is rotated when its holder retires; rotations are disclosed on-chain.

For assets that require account-holder identity (DNS registrar, GitHub, etc.), the emergency path may require more involved legal procedures (estate proceedings, court orders). The Foundation, with its incorporation already complete, has standing to pursue these. The on-chain artifacts required (multisig re-keying, certificate publication) can be produced via the notarial path.

### 2.8 D-8 — Post-handover obligations

After the Handover Certificate is committed:

* **Founder's obligations terminated:**
    - No further administrative custody.
    - No obligation to participate in protocol coordination beyond ordinary open-source contribution (which is voluntary).
    - No special signing authority.

* **Founder's obligations continuing:**
    - Premine vesting per ADR-010-A.
    - Postern Labs separation per ADR-023 D-5.
    - No-listing-solicitation prohibition per ADR-023 D-7 (until both gates met; the Foundation operability is now satisfied, but the audit gate may still be open).
    - Disclosure of conflicts.
    - Cooperation with reasonable Foundation requests for historical information needed for audit, regulatory inquiry, or technical archeology.

* **Foundation obligations starting:**
    - Stewardship of all transferred assets per its statutes.
    - Commissioning the independent security audit per ADR-023 D-7 / Phase 5.
    - Ongoing methodology-B dashboard operation.
    - Validator/oracle pool management per the protocol mandate.

The Handover Certificate, once committed, cannot be retracted by the founder. The Foundation may, on its own initiative and under its own statutes, voluntarily transfer assets back to the founder; this would be a new transaction governed by the Foundation's own rules.

### 2.9 D-9 — Tail liabilities

Some liabilities follow the asset across the handover. These are documented in a **Tail Liability Schedule** attached to the Handover Certificate as an off-chain document with on-chain hash anchor:

* **Existing contracts** (hosting agreements, registrar contracts, platform Terms of Service obligations) — assigned to the Foundation where assignable; founder remains on the hook for any pre-handover breach.
* **Pre-handover IP claims** — disputes that originated before handover remain the founder's responsibility unless the Foundation chooses to assume them.
* **Pre-handover regulatory inquiries** — addressed by the founder; Foundation cooperates with information.
* **Pre-handover bug bounties** — outstanding bounties are honored by the Foundation under terms previously published.

Counsel review (both founder's and Foundation's) of the Tail Liability Schedule is required before the Handover Certificate is committed.

---

## 3. Rationale

### 3.1 Why ordered, not parallel

Some transfers depend on others. The multisig re-keying (Step 1) is first because it is atomic and fixes the most consequential single piece — the validator/oracle pool's signing authority — without windowed risk. DNS (Step 2) is second because it gates many downstream platforms (GitHub auth, email, etc.). Trademarks (Step 3) are third because they are the slowest to complete and benefit from being initiated early. Repositories, build infra, and communications follow. The Handover Certificate is last because it documents what has been done, and what has been done must be done first.

Parallel execution is permitted within steps where there are no dependencies (e.g., transferring multiple unrelated trademarks simultaneously) but the ordering between major steps is binding.

### 3.2 Why on-chain certificate, not just off-chain

The Handover Certificate is consensus-critical: from its commit block, the chain treats the founder's administrative authority as terminated and the Foundation's as starting. Validators that received instructions signed by the founder before the certificate accept them as authorized; instructions signed by the founder after the certificate are not authorized.

This matters most for the validator/oracle pool: post-handover, the founder's signature alone cannot authorize disbursements from the pool. The on-chain certificate gives validators a clean check.

### 3.3 Why the founder's identity key is not transferred

The founder is a person, not an office. The Foundation is an office, not a person. Identity keys belong to identities; transferring an identity key would be transferring identity, which is conceptually wrong and operationally fragile.

The Foundation issues its own identity key under its own custody. Historical messages signed by the founder remain attributable to the founder; new messages from the Foundation are signed by the Foundation's key.

### 3.4 Why the notarial escrow path

Founder incapacity is a real risk that must be planned for. Without an escrow path, founder death would leave the protocol in administrative limbo — domains expire, repositories become abandoned, signing keys are lost — until estate proceedings resolve, which can take months or years.

The notarial path, with a Swiss notary bound by a published agreement, provides a credible third-party who can act when the founder cannot. Switzerland is chosen because Swiss notarial practice is highly formalized, professionally regulated, and internationally enforceable.

The 2-of-3 design ensures that the notary alone cannot release the keys — they require the cooperation of the designated successor. The successor alone cannot release them — they require the notary's signature. The founder alone cannot remove the notary — the notarial agreement is published and binding.

### 3.5 Why the auditor is not the Foundation board itself

The Foundation board is an interested party in the handover (it is the recipient). An interested-party audit is not an audit. The third-party auditor, drawn from the broader community, holders, or validators, provides independent verification.

The auditor cannot be a Foundation board member, the founder, or Postern Labs personnel — the same exclusion logic as ADR-024 D-6 for the inaugural Council.

### 3.6 Why 30 days is the default window

DNS transfers typically take 5–10 days. GitHub org transfers complete in hours to days. Trademark assignments are filed in days but recorded over weeks (recordation lag is acknowledged). Build infra rotation takes hours. Communication channel transfers take days. 30 days is a reasonable envelope that allows sequencing and minor delays without requiring extensions in the common case.

Extensions are available for genuine external blockers; they require Foundation board approval to prevent founder-driven delay.

---

## 4. Consequences

### 4.1 Positive

* **Clean transition moment.** The on-chain Handover Certificate provides a single block at which the protocol's recognized administrative authority changes. No ambiguous interregnum.
* **Verifiable by community auditor.** Each step has an evidence trail; the auditor's attestations make the handover independently checkable.
* **Emergency path planned.** Founder incapacity does not strand the protocol.
* **Tail liabilities documented.** Pre-handover obligations do not vanish into the new entity ambiguously.
* **Multisig re-keying first** removes the validator/oracle pool from any window of split authority quickly.

### 4.2 Negative

* **Operational complexity.** Seven distinct asset classes, each with its own platform-specific transfer procedure, is a project. The community auditor's role is a part-time job for the duration.
* **Trademark recordation lag.** Trademark offices in some jurisdictions take weeks to record assignments. The Handover Certificate is committed before all recordations complete; nominal transfer is at certificate time, but legal effect is at recordation time. This creates a brief window of legal ambiguity.
* **Notarial escrow depends on Swiss legal infrastructure.** If the chosen notary firm dissolves, the escrow agreement must be migrated, which requires new on-chain registration. There is operational risk in maintaining the escrow over decades.
* **Tail liabilities are case-by-case.** The Tail Liability Schedule is drafted manually by counsel. Errors in the Schedule create downstream disputes.
* **Off-chain platform behaviors are not under the protocol's control.** GitHub could change its org-transfer policy; X could rename. The protocol's ability to standardize the transfer procedure is limited by the platforms' own rules.

### 4.3 Neutral

* The 30-day window is a default; extensions are possible.
* Some assets (e.g., Discord servers) have weak transfer guarantees; the founder may need to create a new server under Foundation control and migrate community in lieu of a clean transfer. This is acceptable.
* The auditor's compensation is set by the Foundation board, providing a check against absurd compensation; no protocol-level cap is needed.

---

## 5. Alternatives considered

### 5.1 A-1 — Atomic on-chain handover only; off-chain assets remain founder's

**Description.** Only multisig and on-chain registries are transferred. Domains, repositories, etc. remain in the founder's name with a contractual obligation to follow Foundation direction.

**Why rejected.** This leaves the founder as the de facto controller of operationally critical assets. Domain expirations, repository takedowns, and platform account disputes would all run through the founder; the Foundation would be permanently dependent. Breaks ADR-023 D-2's structural separation.

### 5.2 A-2 — Single big-bang transfer in one transaction

**Description.** All assets transferred in one synchronized event.

**Why rejected.** Off-chain asset transfers cannot be synchronized atomically with on-chain transactions. The asynchrony is real and must be designed around, not pretended away.

### 5.3 A-3 — Phased transfer over 6+ months

**Description.** Long-window handover with assets transferred in waves.

**Why rejected.** Extends the period of split authority and ambiguity. The 30-day window forces the transfer to happen and produces a clean post-handover state.

### 5.4 A-4 — No emergency escrow; rely on legal estate proceedings

**Description.** If the founder is incapacitated, normal estate law applies.

**Why rejected.** Estate proceedings can take 1–3 years across multiple jurisdictions. The protocol cannot tolerate that gap. The notarial escrow is a small additional design overhead that prevents a large potential failure mode.

### 5.5 A-5 — Transfer founder's identity key to the Foundation

**Description.** The founder's protocol identity key is transferred along with other assets.

**Why rejected.** Identity keys are not assets; they identify a person. Transferring would either mean the Foundation can post messages as if it were the founder (impersonation) or means historical signatures are invalidated retrospectively (chaos). The Foundation issues its own key; the founder retains theirs.

---

## 6. Open questions for review

1. **Notarial agreement terms.** Drafted by Swiss counsel. Specific terms — release conditions, key custody requirements, notary fee, term of agreement — are open.
2. **Successor key designation.** Who? Family member, trusted advisor, professional executor? Discussed with personal counsel.
3. **Trademark recordation in Brazil.** BLOCH trademark may be registered in Brazil (founder's home jurisdiction). INPI recordation procedures are slower than USPTO; counsel review needed for whether registration in Brazil is appropriate at all.
4. **Platform-specific transfer evidence.** What constitutes adequate evidence for each platform? GitHub provides notification emails; Discord provides admin-role audit logs; X provides … less. Auditor may need to take screenshots in real time.
5. **Audit report public-disclosure scope.** The detailed audit report (off-chain) may contain sensitive operational details (account names, access tokens during rotation). Counsel review on what must be public vs. what can be private.
6. **Tail Liability Schedule format.** Is there a canonical format, or is it a counsel-drafted document per handover? Default proposal: counsel-drafted, with on-chain hash anchor; format is a counsel-best-practice document.

---

## 7. Implementation notes

The on-chain components (HandoverRequest, FoundationKeyRegistration, HandoverCertificate, AuditorAttestation, HandoverDispute, HandoverDelayNotice) are implemented as protocol-module messages, not smart contracts. They are simpler than the bootstrap procedure of ADR-024 (no quadratic vote, no multi-petition reconciliation) but require careful state-machine design for the request → execution → certificate flow.

Module location: `crates/governance/handover/`.

Required tests:

* HandoverRequest validation (signatures, references, deadline arithmetic).
* Multisig re-keying transaction acceptance with combined founder + existing-signer signatures.
* HandoverCertificate validation (≥ ⅔ Foundation signatures, founder signature, auditor signature, asset attestations consistent with prior chain events).
* HandoverDelayNotice and Foundation extension flow.
* Emergency path: notarial-key signing of multisig re-keying when founder is unresponsive (modeled in simulation).
* Post-handover authority transition: rejecting transactions signed by founder for assets now under Foundation authority.

---

## 8. References

* ADR-022 — Signature curve: ML-DSA-65 used for all signatures in this protocol.
* ADR-023 — Foundation Genesis Model: D-1 establishes Phase 4; D-7 establishes the listing-readiness gate that depends on this handover.
* ADR-024 — Steward Council bootstrap: produces the Foundation board that issues handover requests.
* ADR-025 — Decentralization metrics: methodology-B dashboard is one of the assets transferred.
* `BLOCH-FGM-001 v1.0` §4 Phase 4 — Custody handover (textual specification).
* USPTO Form PTO-1594 — Recordation form for assignments.
* Swiss Notarial Code (cantonal; to be selected with Swiss counsel).

---

*This ADR is normative for the protocol's repository and for the founder's commitments concerning the handover. It is non-normative for the Foundation's post-handover operations, which are governed by the Foundation's statutes. Released under CC BY 4.0.*
