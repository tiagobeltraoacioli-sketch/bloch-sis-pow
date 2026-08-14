<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — site & explorer plan

```
Document:  SITE-PLAN
Status:    PLAN — nothing here is published; publishing is the founder's call
Created:   2026-08-12
Updated:   2026-08-14 — facts of record corrected after the Genesis-4 launch
           (Genesis-3 halted at 39,918; PoS live since 2026-08-13 21:31:19 UTC;
           supply cap FINAL at 100 B). The plan's *structure* is unchanged.
Direction: approved visual preview (white ground, emerald #0E6E5A, ink #0D1B17,
           violet #4B3FA8, amber #B4630F; Charter display / system sans body /
           mono data; canvas Bloch sphere; light+dark tokens already written)
Briefs:    docs/FLEET-BRIEF-2026-08-11.md, docs/FLEET-BRIEF-CERTIK-2026-08-12.md
```

## 0. Facts of record this plan is built on

These override anything stale in the repo or on the live site. Where a spec
still says otherwise, that is flagged, not followed.

| Fact | Value | Source |
|---|---|---|
| Genesis-3 terminal height | **39,918 — halted, permanently, on 2026-08-13.** Terminal DAG: 50,690 blocks. Planned ceilings of 80,000 and 50,000 appear in older documents; **neither was ever reached — do not copy either.** | `tokenomics_v4.rs:222` (`CARRYOVER_MEASURED_HEIGHT = 39_918`) |
| Consensus today | **Proof of stake, LIVE since 21:31:19 UTC on 2026-08-13.** 30 s slots, 32 slots/epoch, `COMMITTEE_SIZE = 128`, `SLOT_SUBCOMMITTEE_SIZE = 8`, 64 genesis validators, LMD-GHOST fork choice, Casper justification/finalisation **by epoch**. | `crates/bloch-pos-committee/src/params.rs` |
| Settlement rule | **Finality, not confirmation depth and not work depth.** Justification and finalisation are evaluated at epoch boundaries: **~32 min typical, ~48 min worst case.** Never publish a "N confirmations" rule for Genesis-4. | `crates/bloch-pos-committee/src/{finality,forkchoice}.rs`, `params.rs` |
| Total supply | **100,000,000,000 BLOCH. Hard-capped. FINAL — not "under review".** The redenomination landed; there is no open arithmetic problem. Publish the figure plainly. | `tokenomics_v4.rs:84` (`TOTAL_SUPPLY_BLOCH = 100_000_000_000`) plus the compile-time assert at `:354-361` that the components sum to it |
| Supply split | Issued at slot 0: **57,146,400,000**. Carryover **18,146,400,000** over 452,726 outputs. Validator emission **42,853,600,000** over 40 years, unissued. | `tokenomics_v4.rs:188, 224, 233-240, 251` |
| Validator bond | **25,000 BLOCH** — `MIN_DEPOSIT_SAT = 25_000 * SAT_PER_BLOCH`. Founder decision 2026-08-12; re-derived from the Ethereum fraction of supply (32 ETH ≈ 2.66e-7 of ETH supply ⇒ ~26,567 BLOCH, rounded down to `supply / 4,000,000`). **Not** tied to any "under review" flag. Publish with the code's own caveat: lowering the bond widens who *may* validate and does nothing about who *does*. | `crates/bloch-pos-committee/src/staking.rs:97` |
| Signature suite | `SUITE_MLDSA65_FALCON1024 = 0x0001`, both must verify | `crates/bloch-pos-committee/src/staking.rs:57`; brief 08-11 §Settled item 2 |
| Governance | **Not ownerless.** Two-entity foundation structure. | `docs/specs/BLOCH-ENTITY-STRUCTURE.md`, `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md` |
| Concentration | **93.94%** of the carryover sits at one address (17,046,829,380 of 18,146,400,000). **Founder total 27.04% of the cap** (27,046,829,380; pinned at 2704 bps). **Foundation a further 29.00%** (VC 10 B, team 10 B, marketing 4 B, liquidity 5 B). Together **56,046,829,380 of the 57,146,400,000 issued**, leaving **1,099,570,620 BLOCH — 1.92% — third-party.** Stated plainly, never softened. | `tokenomics_v4.rs:414, 434-435, 97-113` |
| Network openness | **A third party cannot join today.** The live transport is a point-to-point TCP full mesh with a fixed peer list, no discovery and no authentication. Deposit and Delegate are refused at every node's mempool, so there is no permissionless path to validating. | `crates/bloch-pos-node/src/{net.rs,main.rs}`; `engine.rs` (deposit/delegate refusal) |
| Public read RPC | `https://posternlabs.com/g4rpc` — version `0.1.0-mainnet` | live endpoint |

**Precision rule for the concentration figures:** write "founder and Foundation
together" for the 56.05 B. **Never write "one key holds 56.05 B"** — only the
founder's 27.04% is pinned in the repo.

**The security caveat that must appear wherever the old PoW caveats did.** Every
"51%-attackable", "low hashrate" or "zero-security testnet" line on the site is
now stale. Do not delete them — replace each, in the same voice and the same
position, with:

> The security question under Genesis-4 is not hashrate, it is concentration:
> all 64 validators are run by one entity, 93.94% of the carryover sits at a
> single address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by
> the founder and the Foundation. One operator can halt the chain and one holder
> can outvote every other.

Every "no external audit has been completed" statement stays, verbatim.

**Consequence for the approved preview itself:** the preview HTML was written
against the 100 B draft, and **100 B is now correct** — the block on publishing
it is lifted. What must still be regenerated from `tokenomics_v4.rs` and
`staking.rs` are the individual rows, which were drafted before the carryover
was measured: the preview's `43,029,120,000` becomes **42,853,600,000** and its
`17,970,880,000` becomes **18,146,400,000** (with bar widths recomputed). The
bond card's 25,000 BLOCH is correct and ships without an "under review" mark.
Drop the "under review" badge and the ×4.7619 redenomination paragraph
entirely. See §5.

---

## 1. Page map

Two properties, one brand system:

- **blochl1.com** — the protocol's own site + the explorer (protocol voice).
- **posternlabs.com** — Postern Labs, the company (product voice; links out to
  the protocol site, no longer *hosts* the protocol story).

Tabs on blochl1.com (nav order):

```
Protocol · Migration · Supply · Explorer · Brand · Build · Docs
```

| Route | Page | One line |
|---|---|---|
| `/` | Protocol | Hero + sphere, status strip, the three commitments with their costs |
| `/migration` | Migration | Halted at 39,918 → gap → Genesis-4 live from snapshot; anti-scam warning |
| `/supply` | Supply | 100 B hard cap, allocation table, the concentration card |
| `/explorer` | Explorer | The React app (rebranded); Genesis-3 pages in archive mode, Genesis-4 pages against the live PoS RPC |
| `/brand` | Brand | Swatches, type spec, logo SVG, downloadable tokens |
| `/build` | Build | What Genesis-4 validating takes, and the honest statement that it is not open yet |
| `/docs` | Docs | Placeholder structure + review queue; nothing unreviewed ships |

---

## 2. Content sources — where every piece comes from

Rule inherited from the briefs: **never restate a constant — cite or generate
from the path below.** Anything without a source line here does not go on a
page.

### 2.1 Protocol (`/`)

| Piece | Source |
|---|---|
| Hero copy, sphere canvas, status strip layout | Approved preview (`bloch-site.html`) verbatim, minus stale numbers (§5) |
| Status strip: current slot/epoch | Live Genesis-4 read RPC (`https://posternlabs.com/g4rpc`, version `0.1.0-mainnet`). Genesis-3 values are frozen and must be labelled "final", never "measured today" |
| Status strip: "Genesis-3 halted at 39,918" | `tokenomics_v4.rs:222`. Label it **final**, not a future trigger — the halt already happened |
| Status strip: block time | **30 s fixed slot**, labelled as the protocol constant (`params.rs`, `SLOT_DURATION_SECS`). Never a "trailing average" — PoS slots are fixed, not measured |
| Status strip: settlement | "Final by epoch — ~32 min" (`params.rs`). Never "N confirmations" |
| Signature card (hybrid, 4.6 KB cost, no hardware wallet) | Preview copy; suite constant `staking.rs:57`; brief 08-11 §Settled 2 |
| Coherence card (SHAKE-256, STARK, no trusted setup, unaudited) | `docs/specs/COHERENCE-C1.md`, `COHERENCE-C1.1.md`; brief 08-11 §Settled 3 |
| PoS card (slots, epochs, LMD-GHOST, Casper-style; concentrated start) | `crates/bloch-pos-committee/src/{forkchoice,finality,schedule}.rs`; `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` |
| EVM at L1 (mention only, as *design in progress*, no promises) | `docs/adr/ADR-040-evm-and-ustav-at-l1.md`, `docs/specs/BLOCH-L1-EVM-STATE-MODEL.md`. Never as "live", never with a chainId. |
| Ustav/Kirpich (mention only, as design) | `docs/specs/BLOCH-USTAV-L1.md`, `BLOCH-KIRPICH-UNDER-POS.md` |

### 2.2 Migration (`/migration`)

| Piece | Source |
|---|---|
| Four-phase timeline (PoW → halt → gap → Genesis-4 live) | Preview `#road` section, with **39,918** everywhere, and every phase in the **past** tense except the last — all four have happened |
| Halt mechanics ("consensus rule compiled into every node") | `BLOCH-TOKENOMICS-V4.md` §3.2.1 (mechanism only; both its 80,000 and the brief's 50,000 are stale — the chain stopped at 39,918) |
| Snapshot: signed balance set, carryover crosses untouched | `BLOCH-TOKENOMICS-V4.md` §1; `BLOCH-ECOSYSTEM-MIGRATION.md` (mechanism only — heights stale) |
| "No claim, no contract, anyone asking you to migrate tokens is stealing them" | Preview copy — keep verbatim; it is the single most important sentence on the site |
| Ecosystem wind-down (exchanges/L2 drain, explorer archive banner) | `BLOCH-ECOSYSTEM-MIGRATION.md` §5, §Timeline table |
| "Months with no chain" honesty framing | Preview copy; `BLOCH-ECOSYSTEM-MIGRATION.md` §Dead-period |

### 2.3 Supply (`/supply`)

| Piece | Source |
|---|---|
| Total: **100,000,000,000 BLOCH, hard-capped** — stated plainly. **No "under review" badge.** | `tokenomics_v4.rs:84` |
| Allocation table (carryover **18,146,400,000** / 18.15%; founder grant 10,000,000,000 / 10%, 10-yr cliff + 40-yr vest; VC 10%; team 10%; marketing 4%; liquidity 5%; validators **42,853,600,000** / 42.85% over 40 yrs) | `tokenomics_v4.rs:84–240` constants; prose framing from `BLOCH-TOKENOMICS-V4.md` §1 table |
| Issued at slot 0: **57,146,400,000** (everything except the unissued validator emission) | `tokenomics_v4.rs:251` (`GENESIS_ISSUED_SAT`) |
| Founder total **27.04%** = 27,046,829,380 BLOCH (largest carryover address + grant) | `tokenomics_v4.rs:434–435` (`FOUNDER_TOTAL_BLOCH`, compile-time assert `== 2704` bps) |
| Fixed cap as consensus invariant — stated at true strength ("no mechanism *inside* the protocol"; a universal hard fork can change any rule) | Brief 08-12 §Decisions item 2 (wording), V4 spec |
| Concentration card: **93.94%** of the carryover at one address; founder **27.04%** of cap and Foundation **29.00%**, together 56.05 B of the 57.15 B issued, leaving **1.92%** third-party; **Nakamoto coefficient 1** — all 64 validators run by one entity | `tokenomics_v4.rs:414, 434–435, 97–113`; `BLOCH-TOKENOMICS-V4.md` §4A. Never softened. Write "founder and Foundation together" — never "one key holds 56.05 B". |
| Bounding mechanisms: genesis-cohort → one third within a year; per-validator 1%-of-active-stake cap; churn 25 bps | `genesis_cohort.rs` (header comment derives the one-third choice), `staking.rs:106,295–301` (cap is 1% of active stake, derived by caller), `WARMUP_RATE_BPS = 25` (brief 08-11 §Settled 6; constant in the crate) |
| What the mechanisms do NOT reach (can't see beneficial ownership; G1 unreachable by emission alone) | `BLOCH-TOKENOMICS-V4.md` §4A.1 |
| Fees: burn during emission, then 100% to validators | Brief 08-11 §Settled 4; `fee_market.rs` |

### 2.4 Explorer (`/explorer` — see §3)

### 2.5 Brand (`/brand`)

| Piece | Source |
|---|---|
| Palette, dark tokens, type spec, logo SVG, usage rules | Approved preview `#brand` section + its `:root` token block — the preview **is** the brand source of truth |
| Downloadables: `bloch-tokens.css`, logo SVG (light/dark) | Generated from the preview tokens; new files under the site source tree |

### 2.6 Build (`/build`)

Two halves, honestly separated:

| Piece | Source |
|---|---|
| **Do NOT publish a "run a PoW node" guide.** Proof of work ended at height 39,918; a mining guide would now send readers to hash against a chain that does not exist. The old `run-a-node.html` becomes an archived page with a halt banner, not a live instruction | `tokenomics_v4.rs:222`; §5.C below |
| **Genesis-4 validating:** bond **25,000 BLOCH**, `MIN_DEPOSIT_SAT` — with the code's own caveat: lowering the bond widens who *may* validate and does nothing about who *does* | `staking.rs:97` |
| Delegation + shared slashing exposure | `delegation.rs`; preview card copy |
| **The limitation card — replaces the old "the node is devnet" card, whose four clauses are all now false.** The node has a JSON-RPC server, a real Transfer format with inputs and outputs, append-only persistence with deterministic replay, and a launch date that has passed. The true limitation to publish: **the live transport is a point-to-point TCP full mesh with a fixed peer list, no discovery and no authentication, which is why a third party cannot yet join the network; and Deposit and Delegate transactions are refused at every node's mempool because bonding is not yet funded from the UTXO set — so there is no permissionless path to validating today.** | `crates/bloch-pos-node/src/{net.rs,main.rs}`, `engine.rs`; `BLOCH-POS-NODE-INTEGRATION.md`, `BLOCH-POS-GAPS.md` |
| Do not claim a production libp2p/gossipsub network layer. A libp2p module exists in-tree; it is **not** what the fleet runs | `crates/bloch-pos-node/src/main.rs` (`Transport::Devnet` is the default and the live setting) |

### 2.7 Docs (`/docs` — see §4)

---

## 3. Explorer plan

The explorer already exists and serves blochl1.com: `apps/explorer` (React +
Vite, Cloudflare Pages project `bloch-explorer`; RPC via the Pages Function
`apps/explorer/functions/rpc.js` — see `apps/explorer/wrangler.toml` for the
full deploy story and why the RPC hostname must not be orange-clouded).

Work items:

1. **Rebrand to the approved direction.** `App.tsx` currently ships the
   Postern Labs triangle emblem and Postern styling. Replace with the Bloch
   sphere mark (SVG in the preview nav) and the preview token set in
   `styles.css` (light + dark, `data-theme` pattern copied exactly). The
   explorer is a *protocol* property; Postern branding moves to a footer
   credit ("built by Postern Labs"), matching the entity structure.
2. **Keep every existing page** (Dashboard, Blocks, Block/Tx/Address detail,
   Charts, DAG, DAG live, Mining, Leaderboard, Wallet) — but **they are no
   longer "the live product."** They render Genesis-3, which stopped at height
   39,918. The **DAG** and **Mining** pages in particular describe GhostDAG and
   proof of work, neither of which exists on the live chain; they ship as
   **archive views of a finished chain**, explicitly labelled, never as the
   protocol's current state. The live product is the Genesis-4 view: slots,
   epochs, the committee, and finality — which the explorer does not have yet
   and must not fake with Genesis-3 pages.
3. **Halt awareness — the halt already happened; this is not a trigger.** The
   banner is not height-driven any more: Genesis-3 is permanently at 39,918, so
   archive mode is the *only* mode for the Genesis-3 pages. Banner copy: "Chain
   halted permanently at height 39,918 on 2026-08-13; the canonical record is
   the signed snapshot. The live chain is Genesis-4, proof of stake." Mining and
   DAG-live get a frozen-state treatment rather than an error. Any code that
   compares live height against 50,000 must be deleted, not re-pointed.
4. **Nav bridge.** The explorer header gains the site tabs (Protocol,
   Migration, …) so blochl1.com feels like one property, with Explorer as the
   active tab.

---

## 4. Docs tab — structure with an honest placeholder

The founder's rule: **every technical document is reviewed by him before it
goes live.** So the Docs tab ships as a structure whose entries are either
"published" (none at launch) or visibly queued — not silently empty, and not
prematurely filled.

Placeholder copy (the honest version, on-brand):

> Documentation is being reviewed before publication. Nothing appears here
> until it has been read, checked against the code, and approved. The queue
> below is real and in order.

### Review queue (proposed order — founder reorders at will)

| # | Candidate | Repo source | Why this order |
|---|---|---|---|
| 1 | Migration & snapshot guide | `docs/SNAPSHOT-BOOTSTRAP.md` + `BLOCH-ECOSYSTEM-MIGRATION.md` (heights must be corrected to **39,918** first, and the halt written in the past tense) | Time-critical: the halt has happened and users are already past it |
| 2 | Tokenomics V4 | `docs/specs/BLOCH-TOKENOMICS-V4.md` + `tokenomics_v4.rs` | Carries the 100 B hard cap and the concentration figures; the "under review" flag is retired |
| 3 | PoS design overview | `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` | The "what comes next" reference |
| 4 | Threat models | `docs/specs/BLOCH-POS-THREAT-MODEL.md`, `-2.md` | Audit-facing; pairs with the CertiK dossier |
| 5 | Entity structure / governance | `docs/specs/BLOCH-ENTITY-STRUCTURE.md`, `ADR-036` | Replaces the retracted "ownerless" story publicly |
| 6 | Coherence (shielded pool) | `docs/specs/COHERENCE-C1.md`, `C1.1` | Carries the "no privacy claim until audited" caveat |
| 7 | Weak subjectivity & checkpoints | `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md` | Needed by node operators at Genesis-4 |
| 8 | RPC v4 | `docs/specs/BLOCH-RPC-V4.md`, `docs/openapi.yaml` | Developer surface |
| 9 | Builder portal | `legacy/portal/01–04` | Written for the PoW chain — needs a migration pass before review, not just approval |
| 10 | Paper | `docs/papers/Acioli_2026_The_Cryptographic_Constitution.*` | Standalone; no dependency |

Explicitly **not** queued: the EVM-at-L1 and Ustav-at-L1 specs
(`BLOCH-L1-EVM-*.md`, `BLOCH-USTAV-L1.md`) — designs in progress with an
unresolved authorization decision (brief 08-11: nobody picks silently);
publishing them now would read as commitments.

---

## 5. Claims on the current live site that are now FALSE

Scope: `~/dev/posternlabs-deploy` (posternlabs.com), listed only — **nothing
edited, nothing published, per instruction.** Line numbers from the files as
read on 2026-08-12.

### A. "Ownerless" — retracted by ADR-036

The word is the site's spine and it is no longer true (two-entity foundation,
founder-allocated genesis cohort):

- `index.html:7–8` (meta + title: "an ownerless proof-of-work base", "on an ownerless post-quantum base")
- `index.html:441–442` ("Postern Labs builds on Bloch-SIS-PoW. It does not own it." / "ownerless … no owner, no foundation, no token sale, no official website")
- `index.html:473` ("Ownerless base protocol · Genesis-3 mainnet")
- `index.html:931` ("what keeps an ownerless chain ownerless")
- `index.html:1048, 1119, 1142–1145` (footer block: "ownerless and is not a Postern Labs product … no official site to link to")
- `run-a-node.html:472` ("Nobody owns it, including us")
- `SECURITY.md:5–6, 29`
- `Bloch-Roadmap.md:3,5,20,28,119` ("An ownerless chain has no governance authority to roadmap")
- `Postern-Roadmap.md:9,13,17,86,89,93,103,105,122,158`
- The "no foundation" clause specifically contradicts `BLOCH-ENTITY-STRUCTURE.md`; the "no official website" clause is contradicted by this very plan (blochl1.com becomes the protocol site).

### B. EVM as an L2 / chainId 8400 as an L2 — superseded by ADR-040 (EVM at L1, no L2; `bloch-l2-evm` is being replaced, not extended)

- `Postern-Roadmap.md:105` (section "Layer-2 products — EVM L2, RWA, BaaS")
- `Postern-Roadmap.md:135` ("Bloch L2 (EVM) — zk-validity EVM rollup … sequencer + prover + base anchor")
- `Postern-Roadmap.md:136` (wBLCH lock-and-mint bridge to the L2)
- `Postern-Roadmap.md:137` (PosternDex "AMM DEX on the L2")
- `Postern-Roadmap.md:15` ("the Layer-2 RWA / BaaS products are on THIS [owned] list")
- `Postern-Two-Layers.pdf` — the entire two-layer framing (base + owned L2s) is the superseded architecture; the PDF also anchors the "ownerless" claim
- `Bloch-Roadmap.md:89–102` ("Neutral permissionless capability — tokens, forks, L2s"; "L2 anchoring pattern … done") — the neutral-capability point survives, but the framing that Postern's EVM lives there does not
- chainId 8400 (`bloch-l2-evm`, l2rpc.posternlabs.com) is the id of the service being replaced; any surviving reference to it as "the EVM chain" is stale. (It appears in the PDFs/whitepaper rather than index.html; the euvm audit PDFs at `index.html:1015,1019` also describe the eUTXO VM whose survival is an open question per brief 08-11.)

### C. Genesis-3 as perpetual / "never hard-capped" — reversed by the terminal height and the V4 fixed cap

- `index.html:596,615,643,647` ("perpetual tail of 60 BLCH/block", "supply grows forever, disinflationary, never hard-capped")
- `index.html:693` ("We will keep saying this until it stops needing to be said: **Bloch is not hard-capped** … Anyone who tells you BLCH has a 'fixed supply' is wrong, including us if we ever slip.") — under V4 the fixed supply becomes a consensus invariant; this paragraph flips from safeguard to falsehood
- `index.html:790,795–799` ("100 billion nominal, and not hard-capped", "A nominal, not a ceiling", "Hard cap: None", 100-year emission table) — doubly false now. The whole V3 forward schedule (halvings every 1.5 years, tail from ~9 years out) describes a future the chain never had: it stopped at 39,918. And the 100 billion figure survives with the **opposite** meaning — under Genesis-4 it is a **hard cap**, not a nominal. "Hard cap: None" must become "Hard cap: 100,000,000,000 BLOCH"
- `index.html:795` "3.57 B founder allocation" — the V2 locked premine; under V4 it is never emitted (replaced by the 10% grant + carryover-as-is)
- `run-a-node.html:7,192–194` (mandatory V3 upgrade framing "before block height 40,000" with the long-run V3 schedule) — **the V3 fork at 40,000 never activated: the chain stopped at 39,918, eighty-two blocks short.** Presenting V3 as the chain's future is false, and the guide as a whole now instructs readers to mine a chain that does not exist. It must be archived with a halt banner, not corrected in place
- `SECURITY.md:18–29` (Genesis-3 described as *the* live network with no end) — **now simply false**: Genesis-3 is not the live network and has no successor described anywhere on the page. The live network is Genesis-4, proof of stake

### D. Other statements that no longer hold

- **PoW as identity**: the project name "Bloch-SIS-PoW" used throughout both
  sites ties the brand to the consensus being retired; new brand is "Bloch
  Protocol" (approved preview).
- `index.html:475` "Relaunched from height zero on 29 July 2026, carrying
  every prior balance" — still true, but presented as the current chapter with
  no successor; every present-tense "the chain" claim has already expired — that
  chapter closed at height 39,918 on 2026-08-13.
- `index.html:936,941,967,972` operational guidance (flag-day 27,600 datadir
  rules, sync-from-zero workaround, "mandatory build" release names) — dead
  guidance for a stopped chain; archive rather than update.
- **Concentration silence**: neither site states that **93.94%** of carried-over
  supply sits at one address, that the founder holds **27.04%** of the cap and
  the Foundation a further **29.00%**, or that all 64 validators are run by one
  entity. Not a false sentence — a false impression, and the most material one
  on either property. The new Supply page fixes it and the old site should not
  outlive that fix.
- **Stale security caveats**: any "51%-attackable", "low hashrate" or
  "zero-security testnet" line is now describing a chain that has stopped. Do
  not simply delete it — substitute the concentration disclosure from §0 in the
  same position and voice. A page that loses its risk paragraph reads as a page
  with no risk.
- Note: memory records a "no listing effort" claim needing rewrite; I did not
  find that string in the current `index.html` — it may already have been
  removed, or live in a PDF I did not extract. Flagged as unverified rather
  than listed.

### E. Stale numbers in the *approved preview* (must be fixed before any publish)

- Supply section: **"100 billion, fixed" is now CORRECT and unblocked** — the
  cap is final at 100,000,000,000 BLOCH. Delete the ×4.7619 redenomination
  paragraph (it explains a conversion that no longer needs explaining) and drop
  the "under review" badge entirely. Two allocation rows are stale and must be
  regenerated from `tokenomics_v4.rs`: **43,029,120,000 → 42,853,600,000**
  (validator emission) and **17,970,880,000 → 18,146,400,000** (carryover, now
  measured at height 39,918 over 452,726 outputs), with bar widths recomputed.
  The 10 B / 5 B / 4 B rows are correct.
- Build card "25,000 BLCH bond" is **correct** (`staking.rs:97`), same
  "Ethereum fraction" framing, and ships **without** an under-review flag.
- Brand type-spec data line contains "43,029,120,000 · height 50,000" — **both**
  are wrong: the number becomes 42,853,600,000 and the height becomes 39,918.
- Status strip "37,731 measured today" — stale and mislabelled. Genesis-3's
  height is now a frozen final value (39,918) and must be labelled **final**,
  never "measured today". Genesis-4 figures come from the live read RPC
  (`https://posternlabs.com/g4rpc`) or are labelled as protocol constants.

---

## 6. Publication plan — two domains

Nothing below happens in this wave. The founder holds the publish gate on
both domains.

### blochl1.com — the protocol site (new)

- **Serves**: all seven tabs. This is where "official protocol site" now
  points, consistent with the foundation structure (and retiring the "no
  official website" posture).
- **Infrastructure**: already a Cloudflare Pages project (`bloch-explorer`)
  with the working `/rpc` Function. Recommended: the site pages join *this*
  project (static pages + the React explorer under one deploy), so one deploy
  atomically updates site + explorer and the Function keeps serving both.
  Alternative (separate Pages project + route split) rejected for now: two
  deploys that must agree on brand tokens will drift.
- **Sequencing**: (1) rebrand + halt banner in the explorer; (2) site pages
  land with Docs as placeholder; (3) docs go live one-by-one as the founder
  clears the §4 queue. **The old schedule driver is gone** — it was "ship
  before the chain reaches the terminal height." The chain reached it on
  2026-08-13. The driver now is that the live site still narrates a
  proof-of-work chain that has stopped, which is the worst state to sit in:
  every hour the correction is not published, the site is wrong about what the
  protocol *is*.

### posternlabs.com — the company site (corrected, not replaced)

- **Serves**: Postern Labs — products, institutional material, downloads
  (`/dl`), security policy. It stops narrating the protocol: the
  Bloch-SIS-PoW "world", the emission tables, and run-a-node move behind
  links to blochl1.com.
- **Correction pass** (separate wave, founder-approved diff): every §5 item —
  remove "ownerless", remove the L2-EVM story, replace the perpetual-tail
  supply section with a pointer to blochl1.com/supply, add the halt notice to
  run-a-node, revise `SECURITY.md`, mark `Postern-Two-Layers.pdf` and both
  roadmap files superseded (withdraw or banner them — same policy as the OS
  images precedent already on the page).
- **Deploy mechanics** (recorded, not executed): plain directory
  `~/dev/posternlabs-deploy/`, `wrangler pages deploy . --project-name
  posternlabs --branch main`. No build step.

### Cross-linking

Each site names the other once, in its own voice: posternlabs.com → "the
protocol's site is blochl1.com"; blochl1.com footer → "built by Postern Labs"
+ the not-investment-advice line from the preview footer.

---

## 7. What this wave did NOT do

- **Did not publish anything, anywhere** — no Pages deploy, no artifact, no
  DNS change.
- **Did not edit `~/dev/posternlabs-deploy`** — §5 is a list, as instructed.
- **Did not build the site pages or rebrand the explorer** — this is the
  plan for that work, not the work.
- ~~**Did not write the 100 B supply anywhere** — 21 B "under review"
  throughout, per the block on the redenomination arithmetic.~~
  **Reversed 2026-08-14.** The block is lifted: the cap is final at
  **100,000,000,000 BLOCH**, hard-capped, and this plan now states it in §0,
  §1 and §2.3. The 21 B denomination is retired — never regenerate toward it.
- Did not extract the PDFs (`Postern-Technical-Whitepaper.pdf`,
  `Postern-Two-Layers.pdf`, institutional decks) — their false claims are
  inferred from titles and the .md sources that generated them; a correction
  wave should grep the PDFs' text layers before withdrawing them.
- Did not verify the "no listing effort" claim (§5.D, last item).
- Did not correct the stale terminal heights inside
  `BLOCH-ECOSYSTEM-MIGRATION.md` / `BLOCH-TOKENOMICS-V4.md` — flagged here
  for the doc-sweep owner. **`tools/doc-sweep/check_stale.py` must pin 39,918**
  — the height the chain actually stopped at, sourced from
  `tokenomics_v4.rs:222` (`CARRYOVER_MEASURED_HEIGHT`). An earlier revision of
  this line told the sweeper to pin 50,000; that would have automated a number
  the chain never reached. The sweeper should flag **both** 80,000 and 50,000 as
  stale, and should also flag "not hard-capped", "perpetual tail" and
  "21 billion" as false-for-Genesis-4.
- Did not decide the EVM-at-L1 authorization question or anything else
  reserved to the founder; the Docs queue order in §4 is a proposal.
