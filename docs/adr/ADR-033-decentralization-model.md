# ADR-033 — Decentralization Model: Credible Neutrality vs. Compliance-First

**Status:** **SUPERSEDED** — **Retracted by ADR-036** (founder decision, 2026-08-10), which abandoned the ownerless thesis and adopted a Solana-style foundation. Its decentralisation reasoning is also written against a **proof-of-work** chain — miners, hashrate distribution, mining decentralisation — none of which applies. **The measured position on the live chain:** all 64 validators are operated by a single entity, 93.94% of the carried ledger sits at one address and is stakeable, 56,046,829,380 of the 57,146,400,000 BLOCH issued at genesis is founder- or Foundation-held, and a third party can neither join the network (fixed peer list, no discovery, no authentication) nor become a validator (`Deposit`/`Delegate` refused at every mempool). Bloch is not decentralised today by any metric in this ADR. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Accepted — **Option C (compliance-first retained) + decentralization refinements** (founder decision 2026-07-07)
**Date:** 2026-07-07
**Sprint:** (pre-genesis strategic decision; gates Phase 6)
**Author:** BLOCH Founder
**Related:** ADR-010 (emission), ADR-010-A (founder premine), ADR-010-Addendum-1 (oracle pool), ADR-018 (oracle network / PoBRS), ADR-019 (fork governance), ADR-023–027 (Foundation/Labs custody), ADR-028 (Tokenomics V2 activation)
**Supersedes:** None yet — this ADR *proposes* which of the above it would supersede depending on the decision taken.

---

## 1. Context

The founder has asked the project to **adopt a "total decentralization, no
controlling entity" model in the style of Bitcoin and Kaspa**, informed by a
comparative analysis of **Bitcoin, Litecoin, and Kaspa**.

This is not a parameter change. It is a decision about the project's **core
thesis**, and it stands in direct tension with the architecture recorded in
ADR-028 and the ROADMAP Sprint 11 "Compliance-First" program. This ADR:

1. records the comparative analysis of the three reference chains;
2. states the contradiction precisely;
3. enumerates the concrete changes each level of adoption would require,
   classified by consensus/economic/legal impact; and
4. frames the decision. **It does not, by itself, authorize ripping out
   consensus constants or subsystems** — each consensus-affecting change is
   flagged for explicit sign-off.

**Timing advantage.** Per the README, *"until genesis is mined, no chain is
live."* Every economic/consensus change below is therefore a **genesis-parameter
choice, not a hard fork.** There will never be a cheaper moment to make them.

---

## 2. Comparative analysis (Bitcoin / Litecoin / Kaspa)

| Dimension | **Bitcoin** | **Litecoin** | **Kaspa** | **BLOCH today (ADR-028 + Sprint 11)** |
|---|---|---|---|---|
| Launch | Fair; no premine/ICO; founder mined on equal rules (~1.1M BTC, never moved) | No premine, but low-difficulty **instamine** (~500k LTC day 1) | **Gold-standard fair launch**: no premine, no ICO, no allocation; DAGLabs *renounced ownership* pre-launch | **170M founder premine (17%) + 30M validator/oracle pool** minted/vested on-chain |
| Controlling entity | None controls protocol; Bitcoin Foundation collapsed, network unaffected | Litecoin Foundation *promotes*, does not control; founder divested 2017 to remove conflict | **No company/foundation controls protocol** (KEF is marketing only) | **BLOCH Labs (DE C-Corp) custodies treasury**; founder premine address |
| Protocol governance | BIP + rough consensus; **users/nodes hold final veto** (SegWit2x proved miners+corps lose) | BIP-style, tracks Bitcoin Core; miner-signaled soft forks (MWEB) | **KIP** + research forum + rough consensus; client-adoption hardforks (Crescendo) | GIP process (ADR-019) — *compatible with all three* |
| Treasury / dev fund | **None**; off-chain grants (Brink, Spiral, OpenSats) | **None**; Foundation donations only | **None**; community 2-of-4 multisig + crowdfunding | BLOCH Labs treasury + validator/oracle pools |
| KYC / freeze / sanctions | **None at protocol** (no admin key) | **None** (MWEB privacy → Korean delistings, no backdoor added) | **None** (pure permissionless PoW) | **Sprint 11: on-chain sanctions freeze/wipe, KYC/KYB miners, AML, sovereign freeze** |
| Consensus | PoW (SHA-256d), longest-work | PoW (Scrypt — ASIC-resistance **failed**), longest-work | **PoW + GhostDAG BlockDAG** (kHeavyHash); 10 BPS (Crescendo); DAGKnight R&D | **PoW (SHA-256d) + GhostDAG-Q**, plus **FFG-BFT finality (BLS) + validator bonding/slashing + PoBRS oracle quorum** |
| Supply | 21M hard cap | 84M | ~28.7B (smooth chromatic halving) | 1B nominal + perpetual 25/block tail |
| Post-quantum | No | No | **No** (community PQ proposal only; signatures are exposed surface) | **Yes — ML-DSA-65 signatures (BLOCH is *ahead* of all three here)** |

### Key transferable lessons (cited)

- **Fair launch is checkable and is the reference bar.** Kaspa's credibility
  rests on three facts: code open-sourced *before* launch, **zero allocation**,
  and a corporate sponsor that **formally renounced ownership**
  ([Kaspa Wiki – Fair Launch](https://kaspa-lens.com/kaspa/wiki/introduction-to-kaspa/history-of-kaspa-and-fair-launch)).
- **No premine is necessary but not sufficient.** Litecoin had no premine yet a
  low launch difficulty produced a concentrated instamine — a decade-long
  reputational overhang
  ([TheStreet](https://www.thestreet.com/crypto/markets/litecoins-fair-launch-model-would-fail-in-2025-says-creator-charlie-lee)).
  A fair-launch BLOCH must engineer **anti-instamine** genesis difficulty.
- **"No controlling entity" is enforced by software≠network separation + many
  independent validators, not by a legal structure.** Even a corporate + miner
  supermajority (SegWit2x, ~80%+ hashrate) *lost* to economic full-node users
  ([Bitcoin Magazine](https://bitcoinmagazine.com/technical/no2x-hard-fork-suspended-due-lack-consensus)).
- **A protocol treasury is in direct tension with "no controlling entity."**
  Whoever controls the treasury controls the protocol's direction over time
  (Bitcoin report §4).
- **Any admin key / freeze / KYC / sanctions function makes "credibly neutral"
  false by definition** (Bitcoin report §5). Litecoin accepted **exchange
  delistings** (Korea, 2022) rather than add a compliance backdoor
  ([CryptoSlate](https://cryptoslate.com/top-5-korean-exchanges-delist-litecoin-labeling-it-a-dark-coin-after-mweb-upgrade/)).
- **Treasury-less funding is survivable but chronically fragile** — Litecoin's
  founder-dependent donations, Kaspa's 2-of-4 elected multisig + crowdfunding.
  This is the price of the model, not a solved problem.
- **Design against your consensus's concentration vector.** For PoW+GhostDAG
  that is **mining-pool / block-construction centralization** (Bitcoin's worst
  real-world problem; Kaspa hit an ASIC duopoly within ~1.5 years). Adopt a
  **Stratum-V2 "miner-chooses-transactions"** posture from genesis — BLOCH
  already has `src/stratum_v2/`, which is an asset here.

---

## 3. The contradiction, stated precisely

ADR-028 chose the 17% premine + 30-year vesting **specifically** for "Howey
defense maximization" and "Tier-1 exchange listing readiness." Sprint 11 adds
sanctions/KYC/AML/freeze. These are the instruments of a **compliance-first,
legally-defensible** chain with an identifiable responsible entity (BLOCH Labs).

Bitcoin/Kaspa achieve credible neutrality by the **absence** of exactly those
instruments. You cannot hold both postures at once:

> A chain that can freeze an address, gate mining on KYC, and route issuance to
> a company treasury **has a controlling entity** — that is the definition. A
> chain with "no controlling entity like Bitcoin/Kaspa" **cannot** have those
> functions.

This is a genuine fork in the road, not a set of independent toggles.

---

## 4. Options

### Option A — Full adoption (Bitcoin/Kaspa credibly-neutral model)
Fair launch, no premine, no treasury, no compliance layer, pure PoW.
- **Requires (all genesis-time, no live chain to fork):**
  - **A1.** Remove the 170M founder premine and 30M validator/oracle pool →
    `FOUNDER_*`, `VALIDATOR_POOL`, `ORACLE_POOL` constants set to zero; coinbase
    becomes single-output (miner only). Revisit `MAX_SUPPLY`.
  - **A2.** Remove per-block 70/25/5 split → 100% miner (or miner + fee).
  - **A3.** Drop Sprint 11 entirely (sanctions/KYC/AML/sovereign freeze) —
    never implement.
  - **A4.** Drop or externalize the **FFG-BFT validator + bonding/slashing +
    PoBRS oracle** apparatus. A permissioned validator/oracle set is itself a
    centralization vector Bitcoin/Kaspa do not have. (Retaining pure-PoW +
    GhostDAG finality-by-depth, like Kaspa, is the neutral choice.)
  - **A5.** Replace BLOCH Labs treasury custody with a Kaspa-style
    community/crowdfunding funding model; renounce protocol control publicly.
  - **A6.** Engineer **anti-instamine** genesis difficulty (Litecoin lesson).
- **Consequences:** maximal neutrality/censorship-resistance; **loses** the
  Howey/MiCA posture ADR-028 was built for and the compliance-first market
  position; funding becomes fragile; large amount of existing code
  (ffg/, pobrs/, oracle/, bonding/, compliance) is removed or archived.

### Option B — Partial / hybrid
Fair launch + no protocol treasury + **no base-layer compliance**, but retain
FFG finality as a *permissionless* validator set (open bonding, no KYC) and keep
PQ signatures. Closest to "Kaspa + PQ + optional BFT finality."
- Keeps BLOCH's genuine technical differentiator (PQ, and optionally BFT
  finality) while dropping the premine, treasury, and compliance surface.
- **Open question:** can a bonded validator set ever be "no controlling
  entity"? Only if bonding is fully permissionless and slashing is
  consensus-enforced with no privileged operator. Needs its own ADR.

### Option C — Status quo (reject adoption)
Keep compliance-first + premine + Labs. Reject the Bitcoin/Kaspa framing.
Honest and internally consistent; simply not what was requested.

---

## 5. Proposed decision

**Adopt Option A** (full credibly-neutral model) **as the target**, executed as
genesis parameters before Phase 6, *conditional on explicit founder sign-off on
each consensus/economic change (A1–A6) and acknowledgement of the legal
trade-off in §6.* Rationale: a half-neutral chain earns neither the compliance
market nor the credibly-neutral market; the three reference chains show the
value comes from the *absence* of control levers, which only fully materializes
under Option A. Option B is the fallback if BFT finality is deemed
non-negotiable.

**This ADR is `Proposed`, not `Accepted`.** No code constant changes until the
founder confirms.

---

## 6. Risks and trade-offs (read before deciding)

- **Legal (largest).** Removing the premine + 30-year vesting **discards the
  Howey-defense structure ADR-028 was explicitly built to maximize.** A pure
  fair-launch coin is arguably *more* defensible as "not a security" (no
  issuer, no expectation of profit from an entity's efforts — the Bitcoin/Kaspa
  regulatory posture) — but this must be confirmed with the US securities and
  EU MiCA counsel already on the pre-mainnet checklist. **Do not treat this as
  settled.**
- **Funding.** No treasury/premine ⇒ Litecoin/Kaspa-style donation + multisig
  fragility. Plan it deliberately.
- **Sunk cost.** `ffg/`, `pobrs/`, `oracle/`, `bonding/`, and the Sprint 11
  design represent large effort. Option A archives much of it. This is a real
  cost and should be weighed, not waved away.
- **Market position.** BLOCH currently differentiates as "compliance-first PQ
  L1." Option A repositions it as "credibly-neutral PQ L1 (Kaspa + post-quantum
  signatures)" — arguably a *stronger, more unique* position (no live chain has
  shipped PQ signatures), but a different one.
- **Irreversibility.** Cheap now (pre-genesis); a hard fork later.

---

## 7. Change inventory (for execution, once/if accepted)

| ID | Change | Files (indicative) | Impact | Reversible pre-genesis? |
|---|---|---|---|---|
| A1 | Zero premine + pools | `src/core/tokenomics_v2.rs`, `src/core/mod.rs` coinbase validation | Consensus/economic | Yes |
| A2 | 100% miner split | `src/core/tokenomics_v2.rs`, `src/consensus/` | Consensus/economic | Yes |
| A3 | Cancel Sprint 11 | ROADMAP.md; never implemented | Roadmap | N/A |
| A4 | Remove/externalize FFG+PoBRS+bonding | `src/ffg/`, `src/pobrs/`, `src/oracle/`, `src/bonding/` | Architecture | Yes (archive) |
| A5 | Renounce treasury/control; community funding | docs, README, ROADMAP | Doctrine/legal | — |
| A6 | Anti-instamine genesis difficulty | `bloch-calibrate`, genesis params | Consensus | Yes |
| — | Doc reconciliation (Foundation vs Labs; stale premine figure) | README.md, ROADMAP.md | Docs | Yes (safe now) |

---

## 8. Founder decision (2026-07-07)

**Option C is retained**, with five refinements that move BLOCH toward
"compliance-first, but with a credibly-decentralized consensus layer and
eventual community ownership":

1. **Premine retained.** The 170M founder allocation + 30-year on-chain vesting
   (ADR-010-A, ADR-028) stands. No change to `MAX_SUPPLY` or the coinbase split.
2. **Jurisdictional mining compliance.** Add a compliance gate so miners in
   regulated jurisdictions (EU, US, BR) are subject to KYC/KYB attestation.
   **Feasibility constraint (§8.1):** this can only be an *identity/attestation*
   gate enforced by consensus (Sprint 11.3), **never** protocol-level IP/geo
   blocking, which is unenforceable in permissionless PoW. Requires legal
   counsel and its own ADR. Governs via the ADR-018 / Sprint-11.2 sanctions-root
   multisig+timelock+GIP path — **not** founder-unilateral, to preserve (3)/(4).
3. **Delivery to the community.** The ADR-023–027 handover model is retained;
   BLOCH Labs holds infrastructure/trademark, never protocol authority.
4. **FFG-BFT must be genuinely decentralized** — the founder holds no control
   over committee membership or seat rotation. **Finding (§8.2): already true.**
5. **Founder personal-tax review** (pessoa física, Brazil) for the premine/
   vesting — tracked as a pre-mainnet legal deliverable, professional counsel
   required. Not an engineering item.

### 8.1 Tension: jurisdictional gate vs. decentralization

A KYC/jurisdiction gate is a *permissioning* layer. It is compatible with
"no founder control" **only if** the attestation/sanctions list is maintained
by a multisig+timelock under GIP governance (ADR-018/Sprint-11.2), never by a
founder key. It is **not** compatible with a Bitcoin/Kaspa "permissionless"
claim — BLOCH under Option C is explicitly *not* permissionless at the mining
layer, and messaging must say so honestly (contrast Litecoin, which accepted
exchange delistings rather than add any gate). This is a deliberate,
defensible choice for a compliance-first chain; it is not credible neutrality.

### 8.2 Finding: FFG committee is already founder-free

Verified in code (2026-07-07):

- `src/ffg/election.rs::elect_committee` is a **pure, deterministic** function:
  the committee is the **top-21 miners by realized hashrate** over the prior
  2016-block window, tie-broken by XOR with the (unpredictable) window-end
  block hash. No founder input, no admin key, no whitelist.
- Seats **rotate every epoch** on a fresh snapshot.
- `src/ffg/dkg/bootstrap.rs` (lines 4–6): even the *first* committee "emerges
  naturally from the bonded validator set… not from a hardcoded genesis
  ceremony."
- `src/ffg/committee_registry.rs` mutation surface (`commit_pending`,
  `activate`, `finalize_genesis`) is DKG-lifecycle-driven; the only `inject_*`
  functions are test-only (`dkg/mock_network.rs`). **No founder backdoor.**

**Residual weakness to evolve (not a founder-control issue — a concentration
issue):** seats are hashrate-weighted, so mining-pool concentration can capture
committee seats — the same vector Bitcoin/Kaspa suffer. The `COMMITTEE_THRESHOLD
= 14/21` (66.7%) supermajority means an entity controlling >2/3 of hashrate
under distinct identities could control finality. Mitigations tracked in a
follow-up ADR: (a) per-operator seat concentration analysis, (b) tie the
existing `src/stratum_v2/` "miner-chooses-transactions" capability to hashrate
dispersion, (c) document the honest-majority assumption explicitly.

## 9. Open questions for the founder

1. **How far?** Option A (full), B (hybrid: keep permissionless BFT finality +
   PQ, drop premine/treasury/compliance), or C (status quo)?
2. **FFG finality:** non-negotiable (→ Option B) or droppable (→ Option A, pure
   PoW like Kaspa)?
3. **Legal:** has counsel confirmed a fair-launch coin is *at least as*
   defensible as the premine+vesting structure? (Blocks A1.)
4. **Funding:** accept Kaspa-style donation/crowdfunding fragility?
5. **Brand:** renounce protocol control publicly (Kaspa/DAGLabs precedent), or
   retain BLOCH Labs for infrastructure only (no protocol authority)?
