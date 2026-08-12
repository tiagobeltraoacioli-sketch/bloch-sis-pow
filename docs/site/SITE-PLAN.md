<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — site & explorer plan

```
Document:  SITE-PLAN
Status:    PLAN — nothing here is published; publishing is the founder's call
Created:   2026-08-12
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
| Genesis-3 terminal height | **50,000** (lowered from 50,000 on 2026-08-12) | `docs/FLEET-BRIEF-CERTIK-2026-08-12.md` §Decisions item 4. `BLOCH-ECOSYSTEM-MIGRATION.md` and `BLOCH-TOKENOMICS-V4.md` §3.1 still say 50,000 — **stale, do not copy**. |
| Consensus after migration | Proof of stake (slots/epochs, LMD-GHOST, Casper-style finality, PQ signatures) | `crates/bloch-pos-committee/`, `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` |
| Total supply | **100,000,000,000 BLCH — published as "under review"**. The 100 B redenomination is **blocked by an open arithmetic problem and must not appear on the site.** | `crates/bloch-pos-committee/src/tokenomics_v4.rs:33` (`TOTAL_SUPPLY_BLOCH = 21_000_000_000`) |
| Validator bond | The Ethereum fraction of supply (32 ETH ≈ 2.66e-7 of ETH supply). Under the 21 B denomination that is **25,000 BLCH** — `MIN_DEPOSIT_SAT = 5_600 * SAT_PER_BLOCH`. Published tied to the supply's "under review" flag. | `crates/bloch-pos-committee/src/staking.rs:119` |
| Signature suite | `SUITE_MLDSA65_FALCON1024 = 0x0001`, both must verify | `crates/bloch-pos-committee/src/staking.rs:57`; brief 08-11 §Settled item 2 |
| Governance | **Not ownerless.** Two-entity foundation structure. | `docs/specs/BLOCH-ENTITY-STRUCTURE.md`, `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md` |
| Concentration | Founder ~94% of carried-over balance; stakeable (decided 2026-08-11); stated plainly, never softened | `docs/specs/BLOCH-TOKENOMICS-V4.md` §4A; brief 08-12 §2 |

**Consequence for the approved preview itself:** the preview HTML was written
against the 100 B draft. Before it ships, its Supply table (100 B /
43,029,120,000 / 17,970,880,000 / 10 B rows) and its Build card ("25,000 BLCH
bond") must be regenerated from `tokenomics_v4.rs` and `staking.rs` under the
21 B denomination, with the "under review" mark. The design is approved; those
numbers are not. See §5.

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
| `/migration` | Migration | Halt at 50,000 → gap → Genesis-4 from snapshot; anti-scam warning |
| `/supply` | Supply | 21 B (under review), allocation table, the concentration card |
| `/explorer` | Explorer | The React app (rebranded), live until halt, archive mode after |
| `/brand` | Brand | Swatches, type spec, logo SVG, downloadable tokens |
| `/build` | Build | Run a node today (PoW, until 50,000) + what validating will take |
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
| Status strip: current height, block time | Live RPC via the explorer's `/rpc` Function (`apps/explorer/functions/rpc.js`); after the halt, frozen values labelled "final" |
| Status strip: "Halts at 50,000" | Brief 08-12 item 4 (until the halt-release constant lands in the PoW repo; then cite that) |
| Signature card (hybrid, 4.6 KB cost, no hardware wallet) | Preview copy; suite constant `staking.rs:57`; brief 08-11 §Settled 2 |
| Coherence card (SHAKE-256, STARK, no trusted setup, unaudited) | `docs/specs/COHERENCE-C1.md`, `COHERENCE-C1.1.md`; brief 08-11 §Settled 3 |
| PoS card (slots, epochs, LMD-GHOST, Casper-style; concentrated start) | `crates/bloch-pos-committee/src/{forkchoice,finality,schedule}.rs`; `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` |
| EVM at L1 (mention only, as *design in progress*, no promises) | `docs/adr/ADR-040-evm-and-ustav-at-l1.md`, `docs/specs/BLOCH-L1-EVM-STATE-MODEL.md`. Never as "live", never with a chainId. |
| Ustav/Kirpich (mention only, as design) | `docs/specs/BLOCH-USTAV-L1.md`, `BLOCH-KIRPICH-UNDER-POS.md` |

### 2.2 Migration (`/migration`)

| Piece | Source |
|---|---|
| Four-phase timeline (live → halt → gap → Genesis-4) | Preview `#road` section, with **50,000** everywhere |
| Halt mechanics ("consensus rule compiled into every node") | `BLOCH-TOKENOMICS-V4.md` §3.2.1 (mechanism; its 50,000 figure is stale) |
| Snapshot: signed balance set, carryover crosses untouched | `BLOCH-TOKENOMICS-V4.md` §1; `BLOCH-ECOSYSTEM-MIGRATION.md` (mechanism only — heights stale) |
| "No claim, no contract, anyone asking you to migrate tokens is stealing them" | Preview copy — keep verbatim; it is the single most important sentence on the site |
| Ecosystem wind-down (exchanges/L2 drain, explorer archive banner) | `BLOCH-ECOSYSTEM-MIGRATION.md` §5, §Timeline table |
| "Months with no chain" honesty framing | Preview copy; `BLOCH-ECOSYSTEM-MIGRATION.md` §Dead-period |

### 2.3 Supply (`/supply`)

| Piece | Source |
|---|---|
| Total: **100,000,000,000 BLCH — marked "under review"** on the page itself, mono badge, amber `--signal` | `tokenomics_v4.rs:33` |
| Allocation table (carryover 17,970,880,000 / 17.97%; founder grant 10,000,000,000 / 10%, 10-yr cliff + 40-yr vest; VC 10%; team 10%; marketing 4%; liquidity 5%; validators 43,029,120,000 / 43.03% over 40 yrs) | `tokenomics_v4.rs:33–116` constants; prose framing from `BLOCH-TOKENOMICS-V4.md` §1 table |
| Founder total 26.89% (carryover largest address + grant) | `tokenomics_v4.rs:236–241` (`FOUNDER_TOTAL_BLOCH`, compile-time assert `== 2688` bps) |
| Fixed cap as consensus invariant — stated at true strength ("no mechanism *inside* the protocol"; a universal hard fork can change any rule) | Brief 08-12 §Decisions item 2 (wording), V4 spec |
| Concentration card (~94% of carryover, one holder; Nakamoto coefficient 1 if staked) | `BLOCH-TOKENOMICS-V4.md` §4A; brief 08-12 §2. Never softened — the preview card's wording is the model. |
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
| **Today (until 50,000):** run a PoW node — current release, snapshot bootstrap, systemd | Live-site `run-a-node.html` content *audited against §4*, `docs/SNAPSHOT-BOOTSTRAP.md`; must add the halt ("mining revenue ends at 50,000") which the current guide omits entirely |
| **Genesis-4 (planned):** bond 25,000 BLCH (Ethereum fraction; under review with the supply) | `staking.rs:119` |
| Delegation + shared slashing exposure | `delegation.rs`; preview card copy |
| "The node is devnet" card — no transactions, no p2p, no RPC, **no launch date** | Preview copy; `BLOCH-POS-NODE-INTEGRATION.md`, `BLOCH-POS-GAPS.md` |

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
   Charts, DAG, DAG live, Mining, Leaderboard, Wallet) — they are the live
   product; only the skin changes now.
3. **Halt awareness.** A banner component driven by height: below 50,000
   nothing; at/after 50,000 it switches to archive mode — "chain halted at
   height 50,000; the canonical record is the signed snapshot" (banner copy
   per `BLOCH-ECOSYSTEM-MIGRATION.md` timeline table, height corrected).
   Mining/DAG-live pages get a frozen-state treatment rather than an error.
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
| 1 | Migration & snapshot guide | `docs/SNAPSHOT-BOOTSTRAP.md` + `BLOCH-ECOSYSTEM-MIGRATION.md` (heights must be corrected to 50,000 first) | Time-critical: users need it before the halt |
| 2 | Tokenomics V4 | `docs/specs/BLOCH-TOKENOMICS-V4.md` + `tokenomics_v4.rs` | Blocks the Supply page's "under review" flag being lifted |
| 3 | PoS design overview | `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` | The "what comes next" reference |
| 4 | Threat models | `docs/specs/BLOCH-POS-THREAT-MODEL.md`, `-2.md` | Audit-facing; pairs with the CertiK dossier |
| 5 | Entity structure / governance | `docs/specs/BLOCH-ENTITY-STRUCTURE.md`, `ADR-036` | Replaces the retracted "ownerless" story publicly |
| 6 | Coherence (shielded pool) | `docs/specs/COHERENCE-C1.md`, `C1.1` | Carries the "no privacy claim until audited" caveat |
| 7 | Weak subjectivity & checkpoints | `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md` | Needed by node operators at Genesis-4 |
| 8 | RPC v4 | `docs/specs/BLOCH-RPC-V4.md`, `docs/openapi.yaml` | Developer surface |
| 9 | Builder portal | `docs/portal/01–04` | Written for the PoW chain — needs a migration pass before review, not just approval |
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
- `index.html:790,795–799` ("100 billion nominal, and not hard-capped", "A nominal, not a ceiling", "Hard cap: None", 100-year emission table) — the whole V3 forward schedule (halvings every 1.5 years, tail from ~9 years out) describes a future the chain will not have: it halts at 50,000
- `index.html:795` "3.57 B founder allocation" — the V2 locked premine; under V4 it is never emitted (replaced by the 10% grant + carryover-as-is)
- `run-a-node.html:7,192–194` (mandatory V3 upgrade framing "before block height 40,000" with the long-run V3 schedule) — the V3 fork at 40,000 does activate, but only ~10,000 blocks run under it; presenting V3 as the chain's future is false. The guide nowhere mentions that mining revenue ends at 50,000 — the single most material fact for its audience
- `SECURITY.md:18–29` (Genesis-3 described as *the* live network with no end; true only until the halt)

### D. Other statements that no longer hold

- **PoW as identity**: the project name "Bloch-SIS-PoW" used throughout both
  sites ties the brand to the consensus being retired; new brand is "Bloch
  Protocol" (approved preview).
- `index.html:475` "Relaunched from height zero on 29 July 2026, carrying
  every prior balance" — still true, but presented as the current chapter with
  no successor; every present-tense "the chain" claim expires at 50,000.
- `index.html:936,941,967,972` operational guidance (flag-day 27,600 datadir
  rules, sync-from-zero workaround, "mandatory build" release names) — will be
  superseded by the halt release, which becomes the only mandatory build.
- **Concentration silence**: neither site states that ~94% of carried-over
  supply sits with one holder. Not a false sentence — a false impression; the
  new Supply page fixes it and the old site should not outlive that fix.
- Note: memory records a "no listing effort" claim needing rewrite; I did not
  find that string in the current `index.html` — it may already have been
  removed, or live in a PDF I did not extract. Flagged as unverified rather
  than listed.

### E. Stale numbers in the *approved preview* (must be fixed before any publish)

- Supply section: "100 billion, fixed", the ×4.7619 redenomination paragraph,
  and every row of the allocation table (43,029,120,000 / 17,970,880,000 /
  10 B / 5 B / 4 B) — **blocked**; regenerate from `tokenomics_v4.rs` at 21 B
  with the "under review" badge.
- Build card "25,000 BLCH bond" → 25,000 BLCH (`staking.rs:119`), same
  "Ethereum fraction" framing, tied to the same under-review flag.
- Brand type-spec data line contains "43,029,120,000 · height 50,000" — the
  height stays, the number gets replaced with a 21-B-denominated one.
- Status strip height "37,731 measured today" — must be live or dated, never
  baked in.

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
  clears the §4 queue. Steps 1–2 should be live **before height 50,000** so
  the halt is announced by the protocol's own site while the chain still
  produces blocks (~days away — this is the schedule driver).

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
- **Did not write the 100 B supply anywhere** — 21 B "under review"
  throughout, per the block on the redenomination arithmetic.
- Did not extract the PDFs (`Postern-Technical-Whitepaper.pdf`,
  `Postern-Two-Layers.pdf`, institutional decks) — their false claims are
  inferred from titles and the .md sources that generated them; a correction
  wave should grep the PDFs' text layers before withdrawing them.
- Did not verify the "no listing effort" claim (§5.D, last item).
- Did not correct the stale 50,000 heights inside
  `BLOCH-ECOSYSTEM-MIGRATION.md` / `BLOCH-TOKENOMICS-V4.md` — flagged here
  for the doc-sweep owner (`tools/doc-sweep/check_stale.py` should pin
  50,000).
- Did not decide the EVM-at-L1 authorization question or anything else
  reserved to the founder; the Docs queue order in §4 is a proposal.
