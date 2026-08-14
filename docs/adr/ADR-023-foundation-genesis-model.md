# ADR-023 — Foundation Genesis Model and Post-Mainnet Community-Led Incorporation

| Field             | Value                                                              |
| ----------------- | ------------------------------------------------------------------ |
| **Status**        | **SUPERSEDED** (was: Proposed) — see the note directly below this table |
| **Date**          | 2026-05-01                                                         |
| **Authors**       | Founder (custodial)                                                |
| **Reviewers**     | (TBD — US securities counsel, EU MiCA counsel, Swiss/SG counsel)   |
| **Supersedes**    | None                                                               |
| **Superseded by** | Genesis-4 (proof of stake, live since 2026-08-13) — see note below |
| **Related ADRs**  | ADR-010 (tokenomics), ADR-010-A (premine schedule), ADR-011 (FFG governance), ADR-018 (oracle network) |
| **Reference doc** | `BLOCH-FGM-001 v1.0` — Foundation Genesis Model (PDF)               |


> **Status note, 2026-08-14.** Written before mainnet, and mainnet has launched: Genesis-4 went live 2026-08-13 with the Foundation holding 29,000,000,000 BLCH across four buckets (VC, team, marketing, liquidity) and the founder 27,046,829,380 — together 56,046,829,380 of the 57,146,400,000 issued at slot 0. **The board does not exist and the Foundation is the founder** until it does (`BLOCH-TOKENOMICS-V4.md` §3.3.1). This ADR is the model that was adopted, not a description of what has been executed. Read the allocations as live and the governance as unbuilt.
>
> The decision, context and consequences below are **not** rewritten:
> this is a decision log and what was decided, when, is the record.
> Read it as history, not as guidance. Genesis-3 (proof of work) stopped
> permanently at height **39,918** on 2026-08-13; the live chain is
> **Genesis-4, proof of stake**.

---

## 1. Context

BLOCH is post-quantum, BlockDAG-organized, Layer-1 software. As of this ADR's date, BLOCH is in testnet. Mainnet activation is contingent on the conditions described below. No tokens of economic value have been launched on a production network. No SAFT, presale, IDO, IEO, or equivalent token-allocation-for-capital mechanism has occurred or is planned prior to mainnet.

Three governance and structural questions must be resolved before mainnet activation, and the answers materially affect both the protocol's regulatory exposure and its long-term decentralization properties:

1. **When is the Foundation incorporated** — before mainnet (industry default) or after mainnet (this ADR's choice)?
2. **By whom is the Foundation incorporated** — by the founder (industry default) or by community-elected stewards (this ADR's choice)?
3. **What is the relationship between the Foundation, the founder's personal premine, and the founder's commercial vehicle** — co-mingled (industry default in several reference protocols) or structurally separated (this ADR's choice)?

The industry-default answers to these three questions have produced most of the regulatory exposure visible in the United States and the European Union as of 2024–2026, including the suits brought by the SEC against centralized exchanges referencing SOL and AVAX (in which the foundation-controlled-by-founder pattern features prominently in the complaint), and the MiCA Title II offeror-and-issuer obligations that attach to founder-controlled foundations engaging in coordinated marketing. Ethereum's case is materially different on the public-trading question (no enforcement action, ETF approved) but its pre-mainnet incorporation by founders remains a structural feature, not a strength, of its model.

This ADR proposes a deliberately different structural answer to all three questions and codifies the founder's binding commitments to the resulting model.

The full normative reference for the model is `BLOCH-FGM-001` ("Foundation Genesis Model"), 27 pages, published as `/foundation/genesis-model.pdf` on the protocol's documentation site. This ADR is the in-tree, version-controlled record of the decision and is binding for the protocol's repository and engineering practice. Where this ADR and `BLOCH-FGM-001` diverge, this ADR controls.

---

## 2. Decision

This ADR establishes seven interlocking decisions, each of which is binding individually and which collectively constitute the **Foundation Genesis Model**.

### 2.1 D-1 — Foundation is incorporated *after* mainnet, not before

The BLOCH Foundation **shall not** exist at the moment of mainnet activation. Mainnet activates with the protocol under temporary administrative custody by the founder, with no foundation in legal existence and no party in the role of "issuer" or "offeror" within the meaning of U.S. securities law or MiCA Title II.

Foundation incorporation is gated on, in order:

* **Phase 1** — mainnet activation under continuing custodial stewardship.
* **Phase 2** — a decentralization seasoning period of minimum 12 months *and* with all decentralization metrics in §2.4 below satisfied for ≥ 90 consecutive days. Whichever condition is achieved later is the binding one.
* **Phase 3** — a community petition for incorporation, ratified per §2.3 below.

### 2.2 D-2 — Foundation is incorporated *by the community*, not by the founder

The act of incorporation is performed by community-elected stewards, not by the founder. The founder:

* shall not be the legal incorporator of the Foundation;
* shall not fund the legal costs of incorporation, except by a one-time unrestricted ecosystem grant denominated in fiat or stablecoin (not in BLOCH) and contractually structured with no governance attached;
* shall not appoint, nominate, or campaign for any member of the inaugural Steward Council;
* shall not sit on the inaugural board of the Foundation.

The Foundation, once incorporated, may at its own discretion later invite the founder to participate in advisory or contributing capacities. No such role is reserved or pre-negotiated.

### 2.3 D-3 — Steward Council bootstrap procedure

The community-led incorporation procedure is as follows.

**Eligibility to nominate.** Validator operators with continuous uptime ≥ 90% over the seasoning period, plus token holders meeting a quorum threshold (initial value: ≥ 0.05% of circulating supply, held for ≥ 60 days), may nominate Steward Council candidates.

**Eligibility to be nominated.** Any natural person, with the following exclusions for the inaugural Council only:

* the founder;
* anyone holding more than 1% of circulating supply;
* employees, officers, or directors of Postern Labs Inc.;
* anyone in a controlling relationship with the above.

**Confirmation.** Confirmation is by quadratic-funding-style holder vote: voting weight is the square root of token-weighted balance, capped at the 90th percentile to prevent whale dominance. Validator-operator nominations and quadratic-confirmed holder votes are combined in a two-thirds-of-each procedure (a candidate must achieve ≥ ⅔ approval among voting validators *and* ≥ ⅔ approval among quadratic-weighted voting holders).

**Council size.** 5–9 members, odd-numbered preferred to avoid deadlock.

**Statutes.** Draft statutes for the Foundation are circulated as part of the petition and ratified by the same procedure that confirms the Council. Statutes specify, at minimum: foundation purpose, board size and term, election procedure, conflict-of-interest rules, dissolution procedure, and the Foundation's relationship to the protocol's validator and oracle networks.

**Documentation.** The petition, the nominations, the confirmation results, the statutes, and the inaugural Council are documented on-chain or in cryptographically-anchored off-chain records.

### 2.4 D-4 — Decentralization metrics

Phase 2 (the seasoning period) cannot exit until *all* of the following metrics are satisfied for a contiguous window of ≥ 90 days:

* **M-1.** Nakamoto coefficient ≥ 20 for block production over a 90-day rolling window.
* **M-2.** Validator set ≥ 100 distinct, non-collusive operators across at least three jurisdictions (jurisdictional distribution measured by self-attested operator location, cross-checked against IP/ASN routing).
* **M-3.** No single client implementation accounts for more than 65% of validators (multi-client diversity).
* **M-4.** At least three independent ADRs ratified through the on-chain process during the seasoning period, none authored by the founder, all merged into the canonical client.
* **M-5.** At least one upgrade activated by validator-set super-majority signaling, executed without founder coordination.

Metrics are computed by at least two independent measurement methodologies (e.g., one stake-weighted, one IP/ASN-distributed) and published openly. Final judgment of "ready to exit Phase 2" rests with the community petition under §2.3, not with the metrics in isolation.

### 2.5 D-5 — Postern Labs Inc. structural separation

The founder operates **Postern Labs Inc.**, a Delaware C-Corp, as a commercial vehicle for products and services in the post-quantum infrastructure space. Postern Labs is not the Foundation, is not a synthetic foundation, and is bound by the following structural rules:

* **No token holdings.** Postern Labs Inc. holds no BLOCH tokens above a de minimis operational threshold of ≤ 100,000 BLOCH at any time. BLOCH receipts arising from ordinary commercial revenue (e.g., a customer paying in BLOCH for a service) are converted to fiat or stablecoin within 30 days. Holdings are disclosed quarterly in aggregate.
* **No protocol authority.** Postern Labs holds no administrative custody of domains, repositories, or signing keys. Postern Labs does not author ADRs as a corporate act. Employees of Postern Labs may author ADRs in their personal capacity as open-source contributors; the company does not.
* **No exclusivity.** Postern Labs does not enter into agreements with the Foundation that grant exclusivity, preferential access, or revenue rights of any kind. Services to the Foundation are on arm's-length, market-rate terms; the Foundation is free to source the same service from any other vendor.
* **No appointment power.** Postern Labs does not appoint Foundation board members.
* **Disclosure.** Postern Labs publishes an annual transparency report disclosing aggregate BLOCH receipts and dispositions, contractual relationships with the Foundation, and any concerted action with validators or oracle operators.

The premine allocated to the founder at genesis is held by the founder *personally*, not by Postern Labs. Postern Labs receives no premine and no genesis allocation.

### 2.6 D-6 — Token allocation and personal-premine rule

Genesis-fixed token allocation is bound to the values in ADR-010 and ADR-010-A and is *not* re-opened by this ADR. For convenience and unambiguous reference, the allocation is:

| Allocation              | Amount        | Share | Vesting                                 | Custody at genesis                                      |
| ----------------------- | ------------- | ----- | --------------------------------------- | ------------------------------------------------------- |
| Mining rewards (PoW)    | 800,000,000   | 80%   | block-by-block emission                 | n/a — emitted to miners                                 |
| Validator/oracle pool   |  30,000,000   |  3%   | per protocol mandate                    | community multisig at genesis; transferred to Foundation in Phase 4 |
| Founder premine         | 170,000,000   | 17%   | 12-month cliff; 348-month linear (30 y) | founder personal wallets, plural, geo-distributed       |
| **Total**               | **1,000,000,000** | **100%** | —                                  | —                                                       |

The personal-premine rule: the founder's premine is held in personal wallets. Postern Labs Inc. holds no portion of the premine. The premine wallet addresses are publicly disclosed at genesis and observable on-chain thereafter.

The 30-year linear vesting is enforced by genesis state and is not amendable except by hard fork. The founder commits not to seek such an amendment under any circumstance.

### 2.7 D-7 — Listing gate (conjunctive condition)

No party associated with the protocol — including the founder, Postern Labs, validators acting in concert, oracles, or temporary custodians of administrative assets — shall solicit, facilitate, pay for, or coordinate any centralized-exchange listing of the BLOCH token until **both** of the following conditions are satisfied:

* **Gate-A.** The Foundation has incorporated under §2.1–§2.3, has assumed administrative custody under Phase 4 (custody handover, see §3.4 of `BLOCH-FGM-001`), and has a functioning board.
* **Gate-B.** An independent security audit, commissioned by the Foundation (not by the founder), by a firm of recognised standing in the post-quantum and consensus space, has been completed and published in full, with all critical and high-severity findings remediated.

The prohibition is broad and captures: paying a listing fee, signing a listing agreement, granting market-maker exclusivity, introducing a willing exchange to a willing market-maker, providing audit materials to an exchange's listing team, and structuring promotional campaigns timed to a listing.

Decentralized exchanges may list the token at any time after mainnet, because no insider action is required. Insiders neither assist nor coordinate with such listings. If a centralized exchange lists BLOCH on its own initiative, without solicitation, the founder and Postern Labs do not engage with the listing — they neither endorse nor oppose it. The Foundation, when operational, may engage on a case-by-case basis under its own statutes.

---

## 3. Founder commitments — binding

The founder makes the following commitments, personally, surviving any future change in protocol governance. They are restated in a signed instrument deposited with regulatory counsel and published on the protocol's history page.

1. **No pre-mainnet token sale.** No SAFT, presale, IDO, IEO, public-sale auction, or equivalent prior to mainnet.
2. **No Foundation incorporation by the founder.** Per D-2.
3. **Personal premine, with disclosed wallets.** Per D-6. Postern Labs holds no premine.
4. **30-year linear vesting.** Per D-6. The founder will not seek to amend the schedule.
5. **No listing solicitation.** Per D-7.
6. **Postern Labs separation.** Per D-5.
7. **Custody handover on demand.** Once the Foundation is incorporated, the founder will execute custody handover within 30 days of receiving a valid handover request signed by the Foundation's first board.
8. **No special governance role post-handover.** After Phase 4, the founder is one open-source contributor among many. No veto, no special signer rights, no reserved board seat.
9. **Disclosure of conflicts.** Conflicts between Postern Labs and the Foundation, or between premine holdings and a protocol decision, are disclosed publicly at the time they arise.
10. **No use of premine to influence Foundation governance.** The founder will not use vested premine to vote in any token-weighted vote on matters affecting the Foundation's structure, statutes, or board composition. The premine may be used for ordinary on-chain transactions; it may not be used as governance weight against the Foundation.

---

## 4. Rationale

### 4.1 Why post-mainnet incorporation reduces regulatory exposure

The Howey Test, as applied to crypto-asset issuance by U.S. courts and by SEC enforcement, asks whether there is (a) an investment of money, (b) in a common enterprise, (c) with an expectation of profit, (d) derived from the essential efforts of others. The pre-mainnet, founder-incorporated foundation pattern fails (b) and (d) most cleanly: at the moment of issuance, a foundation exists, holds tokens, and is the entity coordinating development. Buyers' profit expectations are tied to that foundation's promotional and engineering efforts. The "common enterprise" prong is satisfied almost by construction.

The post-mainnet, community-led model defeats this construction at the moment of issuance. At mainnet:

* No foundation exists. There is no central party whose efforts the buyer is relying on.
* No one is offering tokens to the public. Tokens come into existence through PoW emission to miners; miners are not the foundation, not the founder, and not in any centrally-coordinated relationship with each other.
* The network is bootstrapped and runs autonomously.

The seasoning period (Phase 2) puts measurable time-distance and an objective set of decentralization metrics between issuance and any centralized stewardship. This interval is the structural counterpart of the "sufficient decentralization" doctrine articulated in Director Hinman's 2018 speech and treated favorably in *SEC v. Ripple Labs*. The community-led incorporation in Phase 3 is the additional fact pattern that distinguishes BLOCH from any model in which decentralization is asserted but a founder-controlled body remains in a managerial position.

The same logic applies to MiCA Title II. Article 4 imposes whitepaper and notification obligations on offerors and issuers of crypto-assets to the public. Under the Foundation Genesis Model, no offeror or issuer exists at mainnet in the MiCA sense. The Foundation, when later constituted, may take on offeror obligations if it chooses to engage in promotional activity; if it does not, Title II does not attach.

### 4.2 Why community incorporation matters more than just timing

Late incorporation by the founder would still leave the founder as the architect of the foundation's mandate, the appointer of its initial board, and the source of its initial endowment. Each of these is a regulatory marker and each is avoided by community incorporation.

The exclusion of the founder, > 1% holders, and Postern Labs personnel from the inaugural Steward Council is not symbolic. It is a structural answer to the question "whose efforts is the buyer relying on?" — at the moment of incorporation, the answer cannot be "the founder," because the founder is excluded.

### 4.3 Why Postern Labs holds approximately zero tokens

A commercial entity that holds the native token of a protocol it materially develops creates the cleanest possible Howey common-enterprise argument: equity in the company is, in substance, leveraged token exposure plus operating risk. It also creates a continuous conflict between the company's fiduciary duty to shareholders (maximize equity value) and the Foundation's mandate (steward the protocol neutrally).

Postern Labs avoids this by holding equity in itself and approximately zero BLOCH. The de minimis cap of 100,000 BLOCH exists for operational reality (gas, fees, product testing) but is structured to be unambiguously not a treasury position.

### 4.4 Why 30-year vesting

Industry-standard founder vesting (typically 4 years with a 1-year cliff) is incompatible with the Foundation Genesis Model's posture. Under a 4-year vest, a founder could in principle sell the entire premine within 5 years of genesis — a pattern indistinguishable from the "promoter exits at retail's expense" archetype that regulators have prosecuted.

A 30-year linear vest (348 months after a 12-month cliff) caps the founder's monthly maximum sale at 1/348 of 170M BLOCH ≈ 489,000 BLOCH, regardless of price. This is structurally incompatible with the dump pattern and aligns the founder's personal balance sheet with the network's multi-decade horizon.

### 4.5 Why the listing gate is conjunctive

The conjunctive structure (Foundation operational *and* audit published) addresses the two distinct failure modes:

* **Audit alone is insufficient.** A listed-but-founder-controlled network is exactly the configuration regulators most distrust, because a working audit does not remediate the absence of a neutral steward.
* **Foundation alone is insufficient.** A Foundation can be operational and yet ratify governance of a buggy or unsafe protocol. Both must be present before retail liquidity is invited.

Listing pre-Foundation creates an additional risk: the centralized-exchange listing is itself a marketing event under SEC and MiCA practice. Conducting it while the founder is the only steward maps the listing to the founder personally, regenerating the Howey common-enterprise argument the post-mainnet structure is designed to avoid.

### 4.6 Why Switzerland or Singapore, not Brazil

The Foundation will not be incorporated in Brazil. CVM Resolution 175 and the broader CVM posture toward token offerings creates significant uncertainty for any issuer with Brazilian nexus. The Banco Central's regulatory sandbox and Lei nº 14.478/2022 regulate VASPs but do not provide a clean path for a foundation issuer.

Switzerland and Singapore both have mature legal frameworks for blockchain foundations (Swiss *Stiftung* under Civil Code Articles 80–89bis; Singapore's Companies Act with MAS regulatory clarity). The choice between them is left to the Steward Council at the time of incorporation, based on then-current banking access, tax neutrality, and regulatory predictability. Both jurisdictions are pre-engaged with counsel in parallel during Phase 2.

### 4.7 Why the founder is, nonetheless, a Brazilian-resident person

The founder's personal Brazilian residence creates Brazilian tax nexus over the founder personally — IRPF on capital gains at the time of vested-premine disposal, beneficial-ownership disclosure for Postern Labs, ordinary AML obligations at the personal level. None of this attaches Brazilian-jurisdiction obligations to the Foundation (which is Swiss or Singaporean), to Postern Labs (which is Delaware), or to the protocol (which is software run by globally distributed validators). The Brazilian compliance is handled by Brazilian counsel separately and is not in this ADR's scope.

---

## 5. Consequences

### 5.1 Positive

* **Defensible Howey posture at issuance.** No foundation, no offeror, no common enterprise at mainnet. The seasoning period provides time-distance and metric-based evidence of decentralization before any centralized steward is constituted.
* **Defensible MiCA posture at issuance.** No Title II offeror exists at mainnet. The Foundation, if it later chooses to engage in promotional activity, can do so as an explicit and disclosed offeror under Title II rules.
* **Clean separation of personal, corporate, and protocol balance sheets.** The founder's premine, Postern Labs' equity and operating capital, and the Foundation's protocol-mandated treasury are three distinct pools with three distinct legal characters and three distinct disclosure regimes.
* **Long-horizon founder alignment.** The 30-year vest removes incentive for short-term price optimization and makes founder-dump theories structurally implausible.
* **Capture-resistant governance bootstrap.** The combination of validator-operator nomination, quadratic-confirmed holder vote, percentile-90 cap, and hard exclusion of founder/large-holders/Postern personnel makes inaugural-Council capture expensive and visible.
* **Listing posture aligns with regulatory clarity.** Listings are gated on the conditions that regulators most care about (independent audit, neutral steward), not on founder discretion.

### 5.2 Negative

* **Slower path to liquidity.** No CEX listings until Phase 6 (post-handover, post-audit) means the time-to-liquidity is materially longer than for protocols that list at or shortly after mainnet. This reduces near-term token holder utility and is acceptable only because it is the price of the regulatory posture.
* **Foundation may not emerge on schedule.** The community-led incorporation depends on a community that may not exist at sufficient scale at the end of Phase 2, may not coalesce on a Steward Council, or may produce a Council that fails to incorporate. There is no fallback in which the founder steps in to incorporate — by design.
* **Coordination overhead.** The seasoning period requires open infrastructure for measuring decentralization metrics, an open ADR process that is genuinely independent of the founder's authorship, and an open governance process for Phase 3 nominations and confirmation. Each is engineering work that does not produce immediate user value.
* **Personal regulatory exposure during Phase 1–3.** During the period between mainnet and custody handover, the founder is in temporary administrative custody and is the natural party for any regulator to address. The disclaimers, the on-chain vesting, the absence of a presale, and the publication of this ADR mitigate but do not eliminate this exposure.
* **Postern Labs' commercial flexibility is reduced.** Holding ≤ 100,000 BLOCH means Postern Labs cannot warehouse BLOCH for extended commercial integrations, cannot make BLOCH-denominated forward commitments to customers, and cannot benefit from token-price appreciation as a corporate strategy. Postern Labs' product roadmap must be denominated in fiat economics throughout.

### 5.3 Neutral

* Both Switzerland and Singapore are acceptable Foundation jurisdictions; the choice is deferred to Phase 3. Counsel in both is engaged in parallel during Phase 2.
* The Foundation, once operational, may amend portions of its own internal governance under its statutes. The portions of this ADR that bind the founder personally (premine vesting, separation from Postern Labs, listing prohibition, irrevocable handover commitment) are designed to survive any such amendment.
* This ADR does not change the protocol's tokenomics (ADR-010, ADR-010-A), its consensus mechanism (Sprint-2.1 family), its FFG governance (ADR-011), or its oracle network (ADR-018). It is purely organizational and structural.

---

## 6. Alternatives considered

### 6.1 A-1 — Pre-mainnet founder-incorporated Foundation (industry default)

**Description.** Founder incorporates a Foundation in Switzerland or Singapore before mainnet. Foundation receives an allocation at genesis (typical: 10–25%), funds initial development, coordinates the validator program, and runs marketing.

**Why rejected.** This is the structure prosecuted (or named in pleadings) against most other Layer-1s. Howey common-enterprise is satisfied by construction; MiCA Title II offeror status attaches at mainnet. Even when the protocol succeeds (Ethereum), the structure is a structural feature of the model rather than a strength. Adopting it would forfeit BLOCH's principal regulatory differentiator before reaching mainnet.

### 6.2 A-2 — Pre-mainnet community-incorporated Foundation

**Description.** Like A-1 but the Foundation is incorporated by community-elected stewards before mainnet.

**Why rejected.** "Community" before mainnet does not exist in any meaningful sense. Validators have not yet been selected, no token holders exist (no genesis has occurred), and any "community" claiming to incorporate would in practice be a proxy for the founder. The Howey defense would be cosmetic, not structural.

### 6.3 A-3 — Post-mainnet founder-incorporated Foundation

**Description.** Foundation is incorporated by the founder some time after mainnet, once decentralization is established.

**Why rejected.** Late incorporation by the founder still places the founder as the architect of the Foundation's mandate, the appointer of its initial board, and the source of its initial endowment. The Howey "essential efforts" prong is weakened by the time-distance but the "common enterprise" prong remains intact because the same principal-agent relationship is continuous from founder to Foundation. The community-led variant (D-2) is preferred because it breaks this continuity at the moment that matters.

### 6.4 A-4 — No Foundation, ever

**Description.** Bitcoin's de facto model. No formal foundation; protocol stewardship is handled informally by core developers and validator operators.

**Why rejected (with qualification).** This model is acceptable as a fallback if the community fails to constitute a Foundation in Phase 3. It is not preferred as the target state because (a) the protocol benefits from a legal entity capable of holding domains, contracting with auditors, and engaging with regulators in counterparty form; (b) the lack of a Foundation makes the validator/oracle pool's 30M BLOCH operationally awkward to manage; and (c) the absence of any neutral steward complicates engagement with enterprise users that require a counterparty for indemnification, licensing, or trademark questions. If Phase 3 fails, this fallback applies and the protocol continues — see also R-1 in `BLOCH-FGM-001` §10.

### 6.5 A-5 — Postern Labs holds a treasury position in BLOCH

**Description.** Postern Labs Inc. holds, e.g., 5–10% of supply as a corporate treasury position, paid by founder transfer or by genesis allocation.

**Why rejected.** This creates the cleanest possible Howey common-enterprise argument (equity in Postern Labs ≈ leveraged token exposure), creates continuous conflicts between corporate fiduciary duty and Foundation mandate, and exposes the protocol to commercial events (acquisition, dissolution, pivot) that have no business affecting protocol-relevant token holdings. The de minimis cap (D-5) is the only commercially viable position consistent with the model's regulatory posture.

### 6.6 A-6 — Industry-standard 4-year vesting

**Description.** 4-year linear vest with 1-year cliff for the founder premine.

**Why rejected.** 4-year vesting is incompatible with the regulatory defense the rest of the model is built on. A 4-year vest permits the founder to be substantially out of the premine within 5 years — a timeline that maps directly to the patterns regulators have prosecuted. The 30-year vest costs the founder little (the founder is presumed to be aligned with the protocol on a multi-decade horizon anyway) and gains a structural defense that is otherwise expensive to construct.

### 6.7 A-7 — Listing immediately after mainnet, with retroactive Foundation incorporation

**Description.** BLOCH lists on centralized exchanges shortly after mainnet, with the Foundation incorporated later.

**Why rejected.** A centralized-exchange listing is a marketing event in regulator practice. Listing while the founder is the only steward maps the listing to the founder personally, regenerating Howey common-enterprise. The conjunctive listing gate (D-7) exists precisely to prevent this.

---

## 7. Open questions for counsel

These questions are explicitly open and require formal opinions before Phase 1 (mainnet activation). They are restated from `BLOCH-FGM-001` §12.

1. **U.S. securities (Howey).** Does Phase-1 mainnet activation, with no Foundation existing, constitute the issuance of an "investment contract" under *Howey* and its progeny? What modifications, if any, would strengthen the defense?
2. **U.S. securities (secondary market).** If a centralized exchange unilaterally lists BLOCH during Phase 1 or 2, does the founder's silence (and absence of solicitation) suffice, or are affirmative public disclaimers required?
3. **MiCA offeror status.** Under MiCA Article 4, does the post-mainnet, community-led model avoid offeror status in the EU? If the Foundation later engages in promotional activity, what is the threshold at which Title II obligations attach?
4. **Swiss vs. Singaporean Foundation.** Comparative analysis of incorporation cost, ongoing compliance burden, banking access, and tax treatment for a Foundation of the size and mandate contemplated.
5. **Brazilian beneficial-ownership and tax.** Does the founder's Brazilian residence create any Brazilian-law nexus over the Foundation or Postern Labs that has not been addressed? What is the IRPF treatment of vested premine that is held but not sold?
6. **30-year vesting enforceability.** Is on-chain vesting enforced by genesis state legally enforceable as a unilateral commitment by the founder, or does it require additional contractual instruments?
7. **Custody handover liability.** When the founder transfers administrative custody to the Foundation in Phase 4, are there ongoing tail-liabilities (data privacy, prior commitments, IP) that survive the transfer?
8. **Postern Labs' partial divestment.** If a regulator concludes that Postern Labs is a synthetic foundation, what is the minimum founder beneficial-ownership reduction required to break the connection?

---

## 8. Implementation plan

### 8.1 Pre-mainnet (current and through Phase 0 exit)

* **By 2026-05-15:** Engage US securities counsel, EU MiCA counsel, audit firm (NCC / Trail of Bits / Kudelski), Swiss counsel, and Singapore counsel. Distribute `BLOCH-FGM-001` and this ADR as input.
* **By Phase 0 exit:** Receive written opinions on Open Questions 1, 3, and 6 (these are the gating items for mainnet activation).
* **Genesis-state engineering:** Implement the 12-month cliff and 348-month linear vesting for the founder premine in genesis state. Implement the validator/oracle pool multisig with initial community signers. Publish the founder premine wallet addresses in the genesis announcement.
* **Documentation surfaces:** All public-facing documentation (site, repository README, social channels) carries the experimental-software disclaimer, the no-token-sale notice, and the post-mainnet community-foundation commitment. The Foundation Genesis Model PDF is the canonical reference.

### 8.2 Phase 1 (mainnet activation)

* Mainnet genesis. PoW emission begins. Founder premine created at genesis with vesting enforced. Validator/oracle pool multisig created.
* Public statement of administrative custody (founder, transitional). No marketing of the token as an investment.
* Listing-gate prohibition is active and binding.

### 8.3 Phase 2 (seasoning, ≥ 12 months)

* Decentralization metrics published openly, computed by ≥ 2 independent methodologies.
* Open ADR process, with founder authorship explicitly tracked and disclosed.
* Counsel re-engaged at month 9 to begin Foundation incorporation preparatory work in parallel.
* No CEX listing solicitation by any insider party.

### 8.4 Phase 3 (community foundation genesis)

* Petition opened by qualifying validator operators and token holders.
* Steward Council nominations and confirmation by quadratic vote.
* Statutes drafted and ratified.
* Foundation incorporated in selected jurisdiction (Switzerland or Singapore), Council seated, board functional.

### 8.5 Phase 4 (custody handover)

* Within 30 days of valid handover request from Foundation board, founder executes irrevocable transfer of DNS authority, repository ownership, trademark assignments, build-infrastructure access, and public communication channel administrative roles.
* Handover Certificate signed and published on the protocol's history page.

### 8.6 Phase 5 (audit)

* Foundation commissions independent security audit. Audit report published in full. Critical findings remediated.

### 8.7 Phase 6 (listing readiness)

* Listing gate satisfied. Foundation may, but is not required to, engage with centralized exchanges. Founder remains uninvolved in any listing process.

---

## 9. Verification and acceptance

This ADR is **proposed** as of 2026-05-01.

It is **accepted** when all of the following are true:

* Written opinions from US securities counsel and EU MiCA counsel are on file confirming that the model as described is defensible in their respective jurisdictions, with any required modifications incorporated as ADR amendments.
* Genesis-state code implements the founder premine vesting per D-6 and the validator/oracle pool multisig per ADR-010-A.
* The Foundation Genesis Model PDF (`BLOCH-FGM-001`) is published at `/foundation/genesis-model.pdf` and linked from the protocol's documentation site.
* The founder's binding commitments in §3 of this ADR are restated in a signed instrument deposited with regulatory counsel.

Once accepted, this ADR cannot be unilaterally amended by the founder. Material amendments require either (a) new counsel opinions, in which case this ADR is superseded by a new ADR that cites this one as superseded; or (b) post-incorporation, ratification by the Foundation board under its statutes.

---

## 10. References

* `BLOCH-FGM-001 v1.0` — Foundation Genesis Model (full normative reference, 27 pages, `/foundation/genesis-model.pdf`).
* ADR-010 — Tokenomics: 1B supply, 80/3/17 split, halving to 25 BLOCH/block tail, 70/25/5 distribution.
* ADR-010-A — Premine schedule: 12-month cliff, 348-month linear vesting, founder personal custody.
* ADR-011 — FFG BFT: activation at block 210,000, committee 21 supermajority 14, ML-DSA-65 signatures.
* ADR-018 — Oracle network: 12 genesis oracles across 4 tiers, 1M BLOCH minimum bond, bidirectional ZK API.
* SEC v. W.J. Howey Co., 328 U.S. 293 (1946).
* SEC v. Ripple Labs, Inc., No. 20 Civ. 10832 (S.D.N.Y. 2023) — discussion of programmatic vs. institutional sales.
* William Hinman, "Digital Asset Transactions: When Howey Met Gary (Plastic)," Yahoo Finance All Markets Summit, June 14, 2018.
* Regulation (EU) 2023/1114 (MiCA), Title II — Crypto-Assets Other than Asset-Referenced Tokens or E-Money Tokens.
* Swiss Civil Code Articles 80–89bis — Stiftungen.
* Lei nº 14.478/2022 (Brazil) — VASP regulation; CVM Resolution 175 — Securities posture for crypto-assets.

---

*This ADR is normative for the protocol's repository and for the founder's personal commitments. It is non-normative for the Foundation once incorporated; the Foundation may adopt its own statutes that amend portions of this ADR concerning ongoing protocol stewardship. Portions binding the founder personally (D-5, D-6, D-7, and the commitments in §3) are designed to survive any such amendment. Released under CC BY 4.0.*
