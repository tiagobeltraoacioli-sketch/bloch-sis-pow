# ADR-027 — Founder Commitment Instrument

| Field             | Value                                                              |
| ----------------- | ------------------------------------------------------------------ |
| **Status**        | Proposed                                                           |
| **Date**          | 2026-05-01                                                         |
| **Authors**       | Founder (custodial)                                                |
| **Reviewers**     | (TBD — US securities counsel, Brazilian counsel, Swiss counsel)    |
| **Supersedes**    | None                                                               |
| **Superseded by** | None                                                               |
| **Related ADRs**  | ADR-010-A (premine schedule), ADR-023 (Foundation Genesis Model), ADR-026 (Custody handover) |
| **Reference doc** | `BLOCH-FGM-001 v1.0` §3 and §9                                      |

---

## 1. Context

ADR-023 §3 sets out ten binding commitments by the founder. These commitments are the personal-conduct counterpart of the protocol-level decisions in ADR-023's D-1 through D-7. Without legal force, however, they are aspirational — a public statement of intent that can be retracted, ignored, or quietly amended.

The regulatory defense in ADR-023 §4 depends in material part on these commitments being credible — credible to U.S. securities counsel writing the Howey opinion, credible to EU MiCA counsel writing the Title-II opinion, and credible to a court if a dispute later arises about whether the founder's behaviour matched the public posture.

This ADR specifies the **Founder Commitment Instrument** ("FCI"): the legal artifact that converts the §3 commitments from aspirational statements into enforceable obligations. The FCI is not a smart contract (most of the obligations are off-chain); it is a written instrument under specified governing law, deposited with counsel and published on-chain by hash anchor.

The instrument must satisfy:

* **Legal enforceability** under at least one specified jurisdiction whose courts can compel specific performance or award damages.
* **Credibility to counsel** — so that securities counsel, MiCA counsel, and any acquirer of regulated entities (exchanges, custodians, banks) can rely on it.
* **Public verifiability** — the instrument's terms are public, its execution is on-chain-anchored.
* **Survivability** — the instrument survives founder incapacity, founder death, and changes in protocol governance.

This is the legal-instrument layer; ADR-023 is the policy layer. They are paired.

---

## 2. Decision

### 2.1 D-1 — Form: Unilateral declaration with third-party beneficiaries

The FCI is a **unilateral declaration** by the founder, formally executed under Swiss law, in which the founder makes binding promises to identified third-party beneficiaries.

**Why unilateral.** The founder cannot contract with the Foundation that does not yet exist. A unilateral declaration (Swiss: *einseitige Verpflichtungserklärung*) is enforceable under Swiss Code of Obligations Article 8 and is the closest legal form to a "deed of commitment" under common-law systems.

**Third-party beneficiaries.** The instrument identifies the following beneficiaries, each with standing to enforce:

* **The Foundation, when incorporated** — receives all rights and remedies relating to commitments §3.2, §3.6, §3.7, §3.8, §3.9, §3.10 (those concerning the Foundation directly).
* **Each token holder of record at any block height after Phase 1 mainnet** — receives standing to enforce §3.1 (no pre-mainnet token sale), §3.3 (premine wallet disclosure), §3.4 (vesting), and §3.5 (no listing solicitation).
* **The protocol itself, represented by the inaugural Steward Council during Phase 3** — receives interim standing to enforce all commitments during the period after Phase 3 begins but before Foundation incorporation completes.

The Swiss third-party-beneficiary doctrine (*Vertrag zugunsten Dritter*, COA Art. 112) supports identified-class beneficiaries, including future-existing entities (the Foundation, future token holders) where the class is defined with sufficient specificity.

### 2.2 D-2 — Governing law and jurisdiction

**Governing law:** Swiss law, specifically the Swiss Code of Obligations and applicable Swiss federal civil procedure.

**Court of jurisdiction:** Zürich Commercial Court (*Handelsgericht des Kantons Zürich*) for disputes involving the Foundation, the protocol, or sophisticated third-party claimants. Ordinary Zürich courts for disputes with retail token holders.

**Why Swiss law and Swiss courts:**

* Swiss courts have substantial experience with crypto-asset disputes and with foundation-related litigation.
* Swiss law on unilateral declarations and third-party-beneficiary contracts is well-developed.
* Switzerland is jurisdictionally neutral with respect to the founder (Brazilian-resident), Postern Labs (U.S./Delaware), and the Foundation (Switzerland or Singapore).
* Swiss courts have a track record of enforcing foreign-resident defendants' Swiss-law obligations, with reciprocal recognition under the Lugano Convention (within Europe) and bilateral treaties (with several non-European jurisdictions).
* Swiss judgments are enforceable in Brazil under STJ (Superior Tribunal de Justiça) homologation procedures; the founder's personal nexus in Brazil makes Swiss judgment enforcement against Brazilian assets feasible.

### 2.3 D-3 — Schedule of commitments (C-1 through C-10)

The FCI's substantive content is a schedule mapping each ADR-023 §3 commitment to: (a) the operational specifics required, (b) the remedy available for breach, and (c) the term of the commitment.

| ID   | Commitment (summary)                                       | Remedy on breach                                          | Term                                                  |
| ---- | ---------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------- |
| C-1  | No pre-mainnet token sale                                  | Specific performance (rescission of sale); liquidated damages of 100% of consideration received | Until mainnet activation                              |
| C-2  | No Foundation incorporation by founder                     | Specific performance (founder withdraws from any incorporation); declaratory judgment that the founder-incorporated entity is not the BLOCH Foundation | Until Phase 3 community incorporation completes       |
| C-3  | Personal premine, with disclosed wallets                   | Specific performance (disclosure); damages for any loss caused by undisclosed holdings | Indefinite (premine duration + 5 years statute of limitations) |
| C-4  | 30-year linear vesting; no amendment sought                | Specific performance (no hard fork advocacy); damages for losses caused by improper unlock | 30 years from genesis                                 |
| C-5  | No listing solicitation pre-gate                           | Specific performance (founder withdraws from listing process); liquidated damages of CHF 5,000,000 per breach; disclosure of all communications with the listing party | Until both gates of ADR-023 D-7 met                   |
| C-6  | Postern Labs separation (no tokens, no authority, etc.)    | Specific performance; damages; mandatory divestment of Postern Labs ownership below 50% if breach is uncured | Indefinite                                            |
| C-7  | Custody handover within 30 days of valid request           | Specific performance (court orders handover steps); damages for losses to Foundation or holders | Triggered upon valid request post-Phase-3             |
| C-8  | No special governance role post-handover                   | Specific performance (founder vacates any role assumed); declaratory judgment | Indefinite                                            |
| C-9  | Disclosure of conflicts                                    | Specific performance (disclosure); damages for losses caused by undisclosed conflict | Indefinite while founder retains any protocol-relevant assets |
| C-10 | No use of premine to influence Foundation governance       | Voiding of votes cast in breach; damages | While premine is held by founder                      |

The schedule is the operative substantive part of the FCI. Each row is internally specified in a sub-schedule giving the conduct required, the conduct prohibited, the evidence sufficient to establish breach, and the procedure for invoking the remedy.

### 2.4 D-4 — Liquidated damages and their calibration

For two of the commitments (C-1 and C-5), the FCI specifies liquidated damages — pre-agreed sums payable on breach, distinct from actual damages. Liquidated damages are used where:

* Actual damages are hard to quantify (e.g., regulatory damage to the protocol from a premature listing is real but diffuse).
* The commitment's deterrent value depends on the breach being expensive ex ante.

The amounts are calibrated as follows:

* **C-1 (no pre-mainnet token sale):** 100% of consideration received. This is restitutionary in form; the founder forfeits the proceeds plus interest. Under Swiss law, this is enforceable as a *Konventionalstrafe* (penalty clause, COA Art. 160–163), provided the amount is proportionate.
* **C-5 (no listing solicitation):** CHF 5,000,000 per breach. Calibrated as a multiple of the typical exchange-listing fee (USD 100,000 to USD 1,000,000) and structured to make the breach materially expensive. Swiss courts apply a proportionality test (COA Art. 163(3)); CHF 5,000,000 against a founder with substantial premine is within the range of enforceable amounts.

For other commitments, actual damages plus specific performance are the primary remedies. Liquidated damages are not specified because the conduct is more directly remediable.

### 2.5 D-5 — Specific performance as primary remedy

For commitments where damages are an inadequate remedy (C-2, C-7, C-8 — these involve doing or refraining from doing identifiable acts), specific performance is the primary remedy.

Swiss courts grant specific performance more readily than common-law courts, particularly under COA Article 97 et seq. The FCI's Swiss governing law makes specific performance the default rather than the exception.

For C-7 specifically (custody handover): the court can order each handover step to be executed by the founder within a specified time, with daily fines (*Ordnungsbusse*) for noncompliance and ultimately substituted performance (the court appoints a third party to execute steps the founder fails to execute).

### 2.6 D-6 — Audit clause: annual attestation

The FCI requires the founder to issue an **annual attestation**, in writing, signed under Swiss-law form, certifying that:

1. The founder has complied with each commitment in C-1 through C-10 during the preceding 12 months.
2. There are no breaches the founder is aware of.
3. The founder discloses any potential breaches or close-call situations that arose during the period.

The attestation is delivered to:

* The Foundation board (post-incorporation), or to the Steward Council (during Phase 3), or to the regulatory counsel of record (during Phase 1–2).
* Public publication on the protocol's history page within 30 days of issuance.
* On-chain hash anchor.

The attestation is supplemented by an **independent verification** every two years: an external counsel or auditor reviews the attestation and the underlying evidence, and issues their own report. Disagreements between the founder's attestation and the verification are noted publicly and escalated to the Foundation board for resolution.

False attestation (knowingly false statements in the attestation) is a separate and severe breach, with damages plus specific performance plus public disclosure of the falsity.

### 2.7 D-7 — Death and incapacity

The FCI binds the **founder personally and the founder's estate**.

**On founder's death:**

* All commitments survive against the estate.
* The estate's executor is bound to perform any pending obligations (e.g., custody handover via the notarial escrow path of ADR-026 D-7).
* Premine vesting continues; vested premine becomes part of the estate, subject to the same prohibition on use to influence Foundation governance.
* Disclosure obligations continue until the premine is distributed out of the estate.

**On founder's legal incapacity** (mental, physical, or legal):

* The designated successor under ADR-026 D-7 acts as the founder's representative for FCI purposes.
* The notarial escrow path of ADR-026 D-7 is invoked for any custody handover obligations.
* Annual attestations during the period of incapacity are issued by the successor; they note the incapacity and identify the cause.

**Postern Labs survives the founder.** On founder's death or incapacity, Postern Labs continues under its own corporate governance. The FCI's commitments concerning Postern Labs (C-6) survive the founder by binding Postern Labs as an entity, through covenants in Postern Labs' charter and shareholder agreements (D-9 below).

### 2.8 D-8 — Modification, supersession, and termination

The FCI is **not unilaterally modifiable by the founder.**

**Modification by mutual agreement.** After Phase 3, the Foundation board may agree with the founder to modify portions of the FCI that concern the Foundation's interests (i.e., modifications can favor the Foundation but not the founder). Modifications are documented as amendments, executed under the same form requirements as the original FCI, and the amended FCI is published on-chain by hash anchor.

**Modification not affecting third-party rights.** Modifications cannot impair the rights of token-holder beneficiaries without their consent. Since obtaining consent of all token holders is impractical, this effectively means token-holder-beneficiary commitments (C-1, C-3, C-4, C-5) are non-modifiable absent a Foundation board ratification process that includes notice and an opt-out window.

**Supersession.** The FCI may be superseded only by a new FCI executed in the same form with the same beneficiaries. Supersession is announced on-chain.

**Termination.** Each commitment terminates per its own term (D-3 schedule). The FCI as a whole terminates when all commitments have terminated. Some commitments are indefinite (C-3, C-6, C-8, C-9); these are coterminous with the founder's life or assets in question.

### 2.9 D-9 — Postern Labs covenants

Because C-6 (Postern Labs separation) requires Postern Labs to act in particular ways, and because Postern Labs is a separate legal entity, the FCI alone cannot bind Postern Labs. The founder, as Postern Labs' controlling shareholder, undertakes to:

1. Cause Postern Labs' corporate charter to include covenants reflecting the C-6 separation rules.
2. Cause Postern Labs' shareholder agreement to bind any future shareholders (including transferees of the founder's shares) to the same covenants.
3. Cause Postern Labs to publish quarterly transparency reports per ADR-023 D-5.
4. Cause Postern Labs to refrain from entering exclusive arrangements with the Foundation, from accepting protocol-authority-equivalent roles, and from holding BLOCH above the de minimis threshold.

If the founder ceases to be controlling shareholder of Postern Labs (e.g., through partial divestment under ADR-023 R-4 mitigation, sale, or death), the founder undertakes that Postern Labs is sold or its charter amended only to a buyer/structure that agrees in writing to assume the same covenants.

These Postern Labs covenants are enforceable against Postern Labs directly (as corporate covenants in Delaware-law form) and against the founder personally (as obligations under the FCI to procure Postern Labs' compliance). The Foundation, post-incorporation, has third-party-beneficiary standing to enforce.

### 2.10 D-10 — Deposit and publication

The executed FCI is deposited with:

* **U.S. securities counsel** of record.
* **EU MiCA counsel** of record.
* **Brazilian counsel** of record (for personal-jurisdiction enforcement).
* **Swiss counsel** of record (governing law).
* **Notarial deposit** with the Swiss notary holding the escrow key under ADR-026 D-7.

The FCI is published in full on the protocol's history page. Its hash is committed on-chain via an `FCIPublication` transaction signed by the founder. The on-chain hash is the canonical reference; if the off-chain document is altered, the alteration is detectable.

Annual attestations and biennial verifications are similarly hash-anchored on-chain via `FCIAttestation` transactions.

---

## 3. Rationale

### 3.1 Why a written instrument, not just a public statement

Public statements have weak enforcement. A regulator can rely on them; a court can take notice of them; but a court cannot order specific performance of a public statement absent some legal form that makes the statement binding. The FCI, by being an instrument under specified governing law, gives every beneficiary a legal cause of action.

### 3.2 Why Swiss law, not Brazilian or U.S. law

* Swiss law has the most developed jurisprudence on unilateral declarations and third-party-beneficiary contracts, which is the legal form needed.
* The Foundation will be in Switzerland or Singapore. Same-jurisdiction governing law for the FCI and the Foundation is operationally simpler.
* Swiss courts are jurisdictionally neutral relative to the founder (BR-resident), Postern Labs (Delaware), and BLOCH token holders (worldwide).
* Brazilian law would make enforcement against Brazilian assets easier but would expose the FCI to the very regulatory uncertainty (CVM, Receita) that ADR-023 §8.3 identifies as a reason to avoid Brazilian incorporation. Brazilian counsel is engaged separately for personal-jurisdiction enforcement of Swiss judgments.
* U.S. law would tie the FCI to the same jurisdiction as Postern Labs, but Postern Labs' Delaware incorporation should not drag the protocol's commitments into U.S. jurisdiction.

### 3.3 Why third-party beneficiaries, including future token holders

The Foundation does not yet exist; the holders are a class that grows over time. Both are beneficiaries whose interests the FCI is designed to protect. Swiss law's third-party-beneficiary doctrine (*Vertrag zugunsten Dritter*, COA Art. 112) supports class-of-future-persons beneficiaries provided the class is defined with sufficient specificity. "Token holders of record at any block height after Phase 1 mainnet" is specific enough.

The token-holder beneficiary status is what makes commitments like C-1, C-4, C-5 legally consequential, not just morally so. A holder who suffered loss due to a pre-mainnet token sale or a premature listing has standing to sue the founder under Swiss law.

### 3.4 Why liquidated damages on C-1 and C-5 only

C-1 and C-5 are commitments where:

* Breach is more likely than for other commitments (commercial pressure to pre-sell or to list early is real and ongoing).
* Actual damages are diffuse and hard to prove (regulatory damage to the protocol does not show up neatly on a P&L).
* Deterrence requires a known ex-ante penalty.

Other commitments (C-2, C-3, C-7, C-8) have natural specific-performance remedies (do the thing; or court orders the thing) and don't need pre-set penalties. C-6 and C-9 are continuous and structural; C-10 is voidable on the chain itself (votes can be reversed); damages are an additional layer.

### 3.5 Why the audit clause

A binding instrument without an audit clause has no built-in mechanism to detect breach. The annual attestation forces the founder, every year, to formally state compliance, which creates a discrete signed document admissible in court if later proven false. The biennial independent verification adds an external check and creates a historical record from which patterns can be observed.

Public attestation also serves the "credibility to counsel" function: securities counsel writing a Howey opinion can rely on a public attestation more confidently than on an inferred ongoing posture.

### 3.6 Why Postern Labs covenants are layered (corporate + personal)

Postern Labs is a separate legal entity. The FCI cannot directly bind Postern Labs. But corporate covenants written into Postern Labs' charter and shareholder agreement *can* bind it. The founder's personal obligation under the FCI is to procure those corporate covenants.

This dual-layer structure is the standard pattern for binding entities under control. If the founder later loses control of Postern Labs (for whatever reason), the corporate covenants survive in Postern Labs' governing documents; new owners cannot remove them without the founder's (or successor-beneficiary's) consent.

### 3.7 Why Swiss notarial deposit

Swiss notarial deposit (*notarielle Hinterlegung*) provides:

* An independent, regulated third party who holds the document.
* Public-record-equivalent status (the notary is bound to produce the document on lawful demand, including by the Foundation, beneficiaries, or court).
* Continuity across the founder's incapacity or death.
* Cross-border recognition: a Swiss notarial deposit is presumed authentic in Brazilian and U.S. courts under standard authentication procedures.

The notarial deposit is not the only deposit (counsel in multiple jurisdictions also hold copies) but it is the canonical one.

---

## 4. Consequences

### 4.1 Positive

* **Regulatory credibility.** The FCI is a document U.S. securities counsel and EU MiCA counsel can rely on when writing their opinions. It is more credible than a public statement and more enforceable than a contract with a non-existent counterparty.
* **Standing for token holders.** Commitments C-1, C-3, C-4, C-5 become enforceable by holders, not just by the eventual Foundation. This is the structural answer to "what if the Foundation is captured and won't enforce against the founder" — holders have independent standing.
* **Continuity across founder mortality.** The estate is bound; the successor mechanism is specified; the Foundation has standing to enforce.
* **Public posture matches legal posture.** What the founder says publicly (no token sale, no listing solicitation) is what the founder is legally bound to do. Drift between public posture and actual conduct is detectable and remediable.
* **Postern Labs' separation is doubly enforced** (corporate covenants + personal obligation), making partial divestment a viable remedy if a regulator concludes Postern Labs is a synthetic foundation.

### 4.2 Negative

* **Founder's personal legal exposure expands materially.** Every commitment becomes a potential cause of action. Even good-faith ambiguity (e.g., did a particular communication "facilitate" a listing under C-5?) becomes a litigable question.
* **Friction in operational decisions.** Some decisions that would otherwise be founder discretion (e.g., responding to an exchange that emails about listing) now require careful counsel-mediated handling to avoid C-5 risk.
* **Litigation cost.** Counsel review for each significant act, periodic attestation audit, and the cost of defending against frivolous claims by holder-beneficiaries are real ongoing expenses. The founder bears these personally.
* **Annual attestation burden.** Annual is frequent enough that the founder must maintain ongoing records of conduct under each commitment. This is not free.
* **Jurisdictional complexity.** Swiss governing law, Brazilian personal jurisdiction, U.S. corporate covenants for Postern Labs — three legal systems intersect in non-trivial ways. Counsel coordination cost.
* **Commitment to perpetuity in some clauses.** C-3, C-6, C-8 are indefinite. The founder's lifetime conduct, and in some cases the estate's conduct, is bound. This is the price of credibility but it is a significant price.

### 4.3 Neutral

* The FCI's interaction with Brazilian tax law is handled by Brazilian counsel separately. The FCI itself is not a Brazilian-law document and does not create Brazilian-law obligations beyond personal-jurisdiction enforcement of Swiss judgments.
* The FCI does not constrain Postern Labs' commercial strategy beyond the C-6 separation rules. Postern Labs may pursue any product strategy consistent with those rules.
* The FCI does not anticipate the founder ceasing to be founder. There is no "founder's office" with successor founders. The FCI binds BLOCH Founder personally and is not transferable.

---

## 5. Alternatives considered

### 5.1 A-1 — No instrument; rely on public statements alone

**Description.** ADR-023 §3 stays as a public statement; no separate legal instrument.

**Why rejected.** Insufficient regulatory credibility and no enforcement mechanism. The principal value of the post-mainnet community-led model is the regulatory defense it constructs, and that defense requires the founder's commitments to be legally credible.

### 5.2 A-2 — Smart-contract enforcement only (on-chain)

**Description.** Encode commitments as smart-contract conditions; rely on on-chain enforcement.

**Why rejected.** Most of the commitments are off-chain in nature (custody handover, communications with exchanges, Postern Labs governance). On-chain enforcement is partial. A hybrid approach (some on-chain, most off-chain) is what the model already uses (ADR-024, ADR-025, ADR-026 are on-chain; FCI is off-chain). Smart-contract-only would leave the off-chain commitments unenforced.

### 5.3 A-3 — Multi-jurisdictional instruments (one per relevant jurisdiction)

**Description.** Separate FCIs under Swiss, U.S., and Brazilian law, each enforceable in its respective forum.

**Why rejected.** Three instruments create three sets of slightly different obligations, three sets of interpretive precedent, three sets of breach risks. The single Swiss-law instrument with reciprocal recognition under treaty and homologation procedures gives one canonical text and one interpretive precedent. Counsel in each jurisdiction reviews the same text.

### 5.4 A-4 — Trust-based structure (founder transfers premine into a trust)

**Description.** Place the premine in a Swiss or Liechtenstein trust with terms that enforce vesting and other commitments.

**Why rejected.** A trust structure has tax implications under Brazilian law (Receita treats foreign-trust beneficiaries with complex disclosure requirements) and may cause the premine to be classified as held by a separate legal entity, complicating the "personal premine" principle of ADR-023 D-6. The FCI achieves comparable enforceability without the entity complication.

### 5.5 A-5 — Swiss debt-acknowledgment (*Schuldanerkennung*) form

**Description.** Use a Swiss debt-acknowledgment form, which is a simpler unilateral commitment.

**Why rejected.** *Schuldanerkennung* is for monetary obligations only. Most of the FCI's commitments are non-monetary (specific performance, abstention). The unilateral declaration form covers both monetary and non-monetary commitments.

### 5.6 A-6 — Bond or escrow (monetary collateral)

**Description.** Founder posts a substantial monetary bond (e.g., CHF 50M) held in escrow; bond is forfeited on breach.

**Why rejected.** Capital-inefficient. The premine itself, with 30-year vesting, is the largest pool of founder-aligned value at risk. Adding an additional bond would require the founder to deploy substantial liquid assets unproductively for decades. The vesting + liquidated damages approach achieves comparable deterrence at lower capital cost.

---

## 6. Open questions for review

1. **Drafting jurisdiction of FCI text.** Drafted by Swiss counsel? By U.S. counsel and reviewed by Swiss? Default proposal: drafted by Swiss counsel, reviewed by U.S. and Brazilian counsel, finalized after all three concur.
2. **Liquidated damages for C-5 amount.** CHF 5,000,000 is a proposal. Counsel review for proportionality under Swiss law and for actual deterrent effect.
3. **Token-holder standing operational mechanics.** How does an individual holder, possibly retail, practically bring suit in Zürich? Is there a minimum threshold for claims (e.g., holdings ≥ X)? Class-action-equivalent procedures available?
4. **Annual attestation form.** Drafted as a sworn declaration? Notarized? Self-executed and counter-signed by counsel?
5. **Biennial verification scope.** Is the verification a full audit of the founder's records, or a review of the attestation plus selected sample? Cost trade-off.
6. **Postern Labs corporate covenants — Delaware specifics.** Delaware Court of Chancery jurisprudence on charter-level covenants binding on future shareholders is mature; specific language to be drafted by Delaware counsel.
7. **Estate planning interaction.** The FCI binds the estate; this must be coordinated with the founder's personal estate planning (will, trusts, beneficiary designations) to avoid conflict.
8. **Brazilian recognition.** Confirmation by Brazilian counsel that a Swiss judgment under the FCI is recognizable via STJ homologation in the founder's lifetime, and against the estate post-death.

---

## 7. Implementation notes

The FCI is an off-chain legal instrument; its on-chain interaction is limited to:

* `FCIPublication` transaction at execution: commits the FCI's hash to chain state.
* `FCIAttestation` transactions annually and biennially.
* `FCIAmendment` transactions (rare; require Foundation ratification post-incorporation).

Module location: `crates/governance/fci/`. The module is small — primarily transaction validation for the three message types and a getter for the current FCI hash and attestation history.

Required tests:

* `FCIPublication` transaction validation (founder signature, hash format, prior-FCI supersession reference if any).
* `FCIAttestation` transaction validation (founder signature, attestation document hash, period covered).
* Attestation gap detection: the chain emits a `FCIAttestationOverdue` event if no attestation has been committed within 13 months of the previous one (1 month grace).
* Foundation amendment flow post-Phase-3.

The substantive drafting of the FCI text is counsel work, not engineering work, and is out of scope for this ADR. This ADR specifies what the FCI must contain; the actual prose is delivered by counsel under separate work product.

---

## 8. References

* ADR-010-A — Premine schedule: the underlying terms that C-3 and C-4 reference.
* ADR-023 — Foundation Genesis Model: §3 lists the commitments this FCI codifies.
* ADR-024 — Steward Council bootstrap: produces the Foundation board that becomes a beneficiary post-incorporation.
* ADR-026 — Custody handover: C-7 (handover within 30 days) is the FCI counterpart.
* `BLOCH-FGM-001 v1.0` §3 and §9 — Founder commitments (textual specification).
* Swiss Code of Obligations — Articles 8 (unilateral declarations), 97 (specific performance), 112 (third-party beneficiaries), 160–163 (liquidated damages / penalty clauses).
* Lugano Convention on Jurisdiction and the Recognition and Enforcement of Judgments (2007).
* Brazilian STJ Resolution 9/2005 and successors — Homologation of foreign judgments.
* Delaware General Corporation Law §102, §141, §211, §242 — Charter covenants and shareholder rights.

---

*This ADR specifies the structure and content of a legal instrument to be executed by the founder. Execution itself is contingent on counsel finalization of the prose. Once executed, the FCI's terms become binding and supersede the policy-level statements in ADR-023 §3 to the extent of any inconsistency. Released under CC BY 4.0.*
