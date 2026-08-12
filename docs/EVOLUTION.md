# Bloch-SIS-PoW / Postern Labs — Project Evolution Plan (APPROVED)

> **SUPERSEDED FRAMING — 2026-08-11.** Written 2026-07-09, before the
> **retraction of the ownerless thesis** (ADR-036; two-entity foundation,
> `docs/specs/BLOCH-ENTITY-STRUCTURE.md`) and before the Genesis-4 PoS
> relaunch decision (halt at height 80,000). The "ownerless / not-a-security"
> posture this plan leans on no longer describes the project; the product
> strategy sections are unaffected. Kept unrewritten as the approved record.

> **Approved by the founder 2026-07-09** — decisions **D1–D10 all accepted per the
> recommendations**: D1 Postern Suite flagship (hygiene wedge); D2 run the Sage
> estimator + canonical-regime flag; D3 grants (no user-KYC); D4 ePrint → then
> scoped paid audit; D5 rotate the leaked PAT (founder action); D6 freeze Postern
> product names (Bloch = protocol only); D7 free source + paid signed builds/
> support/enterprise; D8 park list (no new crates until Suite v0.1); D9 Panic Lock
> is the shipped duress form (active-erase stays deferred); D10 optional
> non-privileged DNS-seed fallback (`DEFAULT_SEEDS` stays empty).
> Prepared against `PRINCIPLES.md`, `docs/POSTERN-LABS.md`, `docs/PROJECT-STATUS.md`,
> `docs/POSTERN-APPS-ROADMAP.md`, `docs/specs/*`, and a direct read of the workspace.

---

## Executive summary (the honest one)

You have built something rare: a genuinely ownerless, post-quantum protocol design
with unusually honest documentation, plus a coherent product thesis (BlackBerry
model) — but the project is currently **wide, not deep**. The protocol is a
zero-security testnet whose PoW parameters are *known-broken* (`β=q/16` sits in
the trivial q-ary regime), Coherence's reorg safety is built but not live, and the
9 Postern product crates are tested *cores* of ~100–400 lines each — foundations,
not products. The single highest-leverage fact I found: **the Sage
lattice-estimator run — the gate everything else waits on — is not actually
external-gated. It needs no money and no third party; it needs a SageMath
container and a week.** The strategy for the next phase is therefore: (1) close
the two protocol gaps you can close alone (canonical PoW params + the Coherence
U.4/SP1 wiring), (2) stop widening the product line and ship ONE real thing —
Postern Desktop reborn as a "privacy toolbox" suite with the hygiene scrubber as
the wedge, targeting the journalist/lawyer document workflow — and (3) fund the
external gates (audit, hardware attestation, mobile SDKs) through grants that fit
the ethos (NLnet/OTF-class), never through the token. Mainnet remains honestly
6–12+ months away and audit-gated; nothing below changes that, and nothing below
requires an owner, a gatekeeper, KYC, or a token sale.

---

## 0. Where we actually are — verified vs. skeleton vs. external-gated

The constitutional discipline (honesty, Principle 8) demands this table sit at
the top of any plan.

| Layer | Component | Real status |
|---|---|---|
| Protocol | Module-SIS PoW, node, mining | ✅ Verified end-to-end — **but in the relaxed regime; canonical params known-broken (trivial regime)** |
| Protocol | Hybrid Falcon‖ML-DSA, SHAKE-256, tokenomics | ✅ Built + tested; **unaudited** |
| Protocol | Every-node-a-seed networking (mDNS/identify/PEX, empty `DEFAULT_SEEDS`) | ✅ Verified (9 tests) — **but LAN-proven only; no live multi-node WAN network has ever run** |
| Protocol | Security fixes (8 vulns), consensus audit pass, fuzzing, cargo-deny, gitleaks | ✅ Real, adversarially verified — internal only, not third-party |
| Coherence | C0/C1 spec, coherence-core, ShieldedEngine, mempool, reorg-undo | ✅ Built + tested — **latent (RejectAll); U.4 live wiring + SP1 verify NOT landed → zero privacy claim today** |
| Attestation | L1 repro build (verified digest), L2 hardening (verified), L3 pluggable design | ✅/📐 L1–L2 verified; **L3 never run on real SEV-SNP/TPM hardware** |
| Products | Postern Desktop (Tauri: node ctl, wallet, send-tx, miner, logs) | ✅ Builds, works — the most product-shaped artifact in the repo |
| Products | Explorer (deployed), Postern OS desktop/attested/mobile Nix profiles | ✅ Build/deploy — foundations, not daily-driver claims |
| Products | 9 Postern crates (tor/hygiene/messenger/vault/quarantine/seal-companion/courier/keys/panic) | 🧩 **Cores only** — 86–395 LOC each, tested, no UI, no packaging, no users |
| Products | Postern Container (Android) | 📐 Design spec only |
| Ops | Leaked GitLab PAT | 🔴 **Still unrotated — open security debt** |
| External | Sage estimator | ⚠️ Listed as gate — **actually runnable today** (free, dockerized SageMath) |
| External | Third-party audit, SEV-SNP host, mobile platform SDK builds | 🔒 Genuinely gated (money / hardware / time) |

**The structural diagnosis:** one maintainer, ~15 surfaces, no single finished
edge. The next phase must convert breadth into two finished edges: *a credible
canonical PoW* and *one shippable product*.

---

## 1. Protocol → credibility: the honest critical path to "auditable mainnet candidate"

### The chain of gates (strict order — each unlocks the next)

```
G1  Sage estimator run          (free, ~1 week)      ── the real numbers
 └► G2  Canonical params frozen  (design + code)      ── β = security floor,
        + difficulty-knob split                          leading-zeros = difficulty
     └► G3  Canonical regime default (feature-flagged, ── node mines/verifies the
            equivalence + regression tested)             hard instance
         └► G4  ePrint parameter rationale             ── free external scrutiny;
                                                          also the recruiting magnet
             └► G5  Live multi-node network (S3)       ── ≥3 WAN nodes, reorg/gossip
                    + adversarial harness                 proven across machines
                 └► G6  Third-party audit (S2)         ── 💰 the only paid gate
                     └► "auditable mainnet CANDIDATE"  ── still not mainnet;
                                                          a claim you can defend
```

Parallel, non-blocking: **Coherence U.4 + SP1 verifier** (buildable now, keeps
shielded txs RejectAll until done — safe), then C3/C4 review, then its own audit
gate *after* G6. Attestation-on-real-hardware (S4) is parallel and cheap-ish
(SEV-SNP VMs are rentable by the hour on Azure/GCP) — it validates the Seal story
but blocks nothing on the consensus path.

### Key calls inside this track

1. **Promote the estimator run from "external-gated" to "this month."**
   `POW-HARDNESS.md` already contains the exact Sage code and the sweep list. Run
   `malb/lattice-estimator` in the official SageMath Docker image, sweep the
   small-`k` window candidates from `deploy/pow-estimator/SCREEN-RESULTS.md`, do
   the BDD cross-check, and require `log2(rop) ≥ 128` classical **plus** the
   feasibility check. Deliverable: a results table appended to POW-HARDNESS with
   the chosen `(n, m, k, β)`.
2. **The difficulty-knob split is a consensus change — do it before any public
   testnet grows roots.** β becomes a fixed security floor; a leading-zeros
   threshold on `H(s)` becomes the ASERT-tuned knob. This is already specified;
   it needs implementation + the equivalence tests the k-row optimization got.
3. **Every-node-a-seed needs a WAN cold-start answer.** mDNS covers LAN only.
   The honest option consistent with Principle 2: an **optional DNS-seed
   fallback that anyone can run and replicate** — documented as a convenience,
   never privileged, never required, `DEFAULT_SEEDS` stays empty, and the docs
   list *how to run your own*. (Decision D10.)
4. **ePrint before paid audit.** A parameter-rationale preprint gets free expert
   eyes on the novel part (the ISIS PoW framing has *no* external verdict — you
   are the first through this door) and makes any later paid audit cheaper and
   better-scoped. It also is the single best maintainer-recruiting artifact.
5. **What "mainnet candidate" honestly requires:** G1–G6 **all** cleared + the
   live network having survived adversarial testing + the reorg/Coherence wiring
   either audited or explicitly excluded from launch scope (shielded pool can
   launch disabled). Realistic horizon: 6–12+ months, dominated by G6 funding.
   Say so publicly; it is the brand.

---

## 2. Products → shippable: pick the flagship, stop widening

### The candidates, judged

| Path | Time-to-real-users | Cost | Risk | Verdict |
|---|---|---|---|---|
| **A. Postern Desktop → "Postern Suite" hub** (fold hygiene/vault/seal-companion/panic/quarantine cores into the existing Tauri app) | **Weeks** — the app builds today; the cores are Rust in the same workspace | ~0 | Low: no app store, no platform SDK, no chain dependency for its value | ✅ **Flagship** |
| B. Postern Container (Android) | Months — DPC + StrongBox plumbing + device testing + distribution friction (Play policy on device-admin apps; F-Droid/APK sideload path) | Android device + SDK time | Medium-high | Phase 2 — it stays the strategic *entry* product, built second |
| C. Standalone hygiene CLI | **Days** | ~0 | None | ✅ Do it too — it's nearly free and it is the wedge in developer form |
| D. Messenger as first app | Long (matrix-rust-sdk client + UI + homeserver story) | High | High (metadata honesty burden, UI surface) | Defer to post-flagship |
| E. Postern OS as the product | Very long; competes with Graphene/Qubes mindshare on day one | High | High | It's the *destination*, not the wedge |

### The flagship: **Postern Suite (desktop)** — and the wedge inside it: **Hygiene**

Rationale, stated plainly:

- **It does not depend on the chain being valuable.** Every chain-coupled product
  (wallet, explorer) inherits "zero-security testnet, worth nothing by design."
  Hygiene, Vault, Quarantine, Panic Lock, Seal-Companion, Courier deliver value
  on day one with *no* token anywhere near them. That's the BlackBerry model
  executed honestly.
- **The user story is coherent and real:** a person who *handles sensitive
  documents* — receive an untrusted file → **Quarantine** rebuilds it safely;
  work on it → **Vault** holds the secrets, **Panic Lock** is the duress answer;
  publish or share it → **Hygiene** scrubs the metadata (opt-in seal/prove);
  send it → **Courier** over ephemeral Tor onion with ML-KEM sealing. One
  workflow, five existing cores, one app.
- **Hygiene is the wedge** because metadata is the leak *everyone* has and nobody
  fixes, the roadmap already calls it "the most ethos-defining app," the
  competitors are GPL/LGPL (ExifTool, mat2 — can't be embedded by anyone
  permissive, which is your moat), and it demos in 10 seconds: drag a file, see
  the author/GPS/revision-history horror, click scrub.

### What shipping v0.1 actually requires (all buildable now)

1. **Reframe the Desktop app**: today's identity is "node companion." New
   identity: *Postern Suite — privacy toolbox* with tabs: **Scrub** (hygiene,
   drag-drop, before/after metadata diff), **Vault** (secrets + TOTP per the
   roadmap's fold-in), **Quarantine** (image path first; PDF documented-honest),
   **Verify** (seal-companion self-audit + verify-any-sealed-file), **Panic**
   (lock everything now), and Node/Wallet demoted to an "Advanced / testnet
   (zero value)" tab with the caveat verbatim.
2. **Finish the crate gaps the roadmap already lists**: hygiene ODF support +
   CLI; vault TEE/OS-keychain key-wrap wiring on desktop (macOS Keychain /
   Secret Service) with Argon2 fallback; courier needs Arti circuit wiring
   beyond the PQ seal/open core.
3. **Packaging**: Tauri bundles for Linux/macOS/Windows; reproducible where the
   platform allows; signed checksums (Falcon‖ML-DSA + minisign for normies);
   release on GitLab. **Start the `tough` (TUF) update-channel core early** as
   the roadmap suggests — updates are where privacy apps get owned.
4. **Honesty in the UI, not just the README**: every pane states its limit
   (hygiene: "scrubs known fields of known formats, not steganography"; vault:
   "desktop keychain, not a TEE, until Container"; messenger absent until real).
5. **The hygiene CLI ships separately the same week** (static binaries,
   `postern-hygiene scrub file.docx`) — the developer/journalist-techie wedge,
   and the cheapest possible "Postern exists and is real" artifact.

Explicitly **parked** until the flagship ships: OS Mobile, Depot, Keys UI,
Messenger client, encrypted backup, contacts/calendar. The cores stay in-tree;
no new crates. (Decision D8.)

---

## 3. Positioning & the honest business

### The two-sentence positioning

> **Bloch-SIS-PoW** is an ownerless, post-quantum proof-of-work protocol — no
> owner, no site, no token sale, worth nothing by design until independently
> audited; anyone may build on it.
> **Postern Labs** sells privacy and security *software* — the BlackBerry model
> on permissive open source: you pay for protection, support, and provable
> integrity (reproducible + attestable builds), never for a coin.

### Why the KYC rejection was right (reaffirmed, for the record)

Any KYC-gated capability would (a) create an **authority** — someone must decide
whose identity passes, which re-introduces the owner/gatekeeper Principle 1
abolishes; (b) contradict Principle 6's compliance-*opt-in* inversion — the
protocol stays blind, the *user* holds the disclosure switch (view keys),
never the network; (c) poison the not-a-security posture — a gatekeeper who
grants privileges is a promoter-shaped entity; and (d) destroy the only
defensible market position: the users who need Postern most (journalists,
lawyers, dissidents) are precisely the ones a KYC gate excludes or endangers.
Compliance lives at the edge, in the user's hands, or it is surveillance.

### First real persona (the wedge user)

**The document-handling professional under adversarial pressure**: investigative
journalist, human-rights/criminal-defense lawyer, NGO researcher. Why them and
not "dissident" or "dev" first: they have (1) an acute, *legal*, describable need
(source protection, privilege, chain of custody), (2) organizations that procure
tools and pay for support (newsrooms, firms, NGOs — the honest revenue), (3)
intermediary orgs that evaluate and distribute tools (press-freedom and digital-
security trainers) so you don't have to market to at-risk individuals directly,
and (4) their workflow maps 1:1 onto the Suite (receive/work/publish/send).
Security-conscious devs are the secondary persona via the CLI. Dissidents are
served, never *marketed to* — overclaiming to the highest-risk users is the one
unforgivable sin, per Principle 8.

### Monetization that doesn't betray anything

| Stream | Fit | Notes |
|---|---|---|
| **Grants** (NLnet, OTF, Sovereign-Tech-class funds) | ✅ Best near-term | They fund exactly this (permissive privacy infra, repro builds, PQ). Diligence is on the *company*, not on users — no user KYC. This is the realistic audit-funding path. |
| **Paid convenience**: signed/notarized builds + update channel + priority support; source stays free | ✅ | The classic honest OSS model; the free build is always buildable from source. |
| **Enterprise/org deployments**: Container fleet setup, self-hosted homeserver/CalDAV, training — for newsrooms/firms/NGOs | ✅ Phase 3 | This is literally the BlackBerry model. |
| **Postern Seal as a service** (attestation verification for orgs) | ✅ later | Needs S4 done; a real differentiator vs Graphene/stock Linux. |
| Anything token-shaped: sale, listing effort, "ecosystem fund," mining products marketed on yield | ❌ **Never** | Principle 7. Also the legal shield: no promoter, no expectation of profit. |

One uncomfortable honesty item to keep visible: the **17% founder premine**
(10-yr cliff + 40-yr vest) is disclosed and structurally passive, but it is the
single fact a hostile reader will use against the "ownerless / not-a-security"
posture. Mitigation is what you're already doing — prominent disclosure, zero
sale, zero listing effort — plus never letting Postern Labs' revenue story touch
the token in any sentence.

---

## 4. Risks & de-risking (the real top list)

| # | Risk | Severity | Mitigation (concrete) |
|---|---|---|---|
| 1 | **Leaked GitLab PAT still live** | 🔴 Immediate | Rotate **day 1**; audit its scope + GitLab audit-log for use; scan git history (gitleaks already in CI — run against full history); if the token is in history, revoke > rewrite (revocation is the fix; rewriting pseudonymous history is optional). |
| 2 | **Unaudited crypto under real users** | 🔴 Structural | Already audit-gated in claims — keep it; ship *products whose day-one value doesn't rest on the novel crypto* (hygiene scrubbing is parsing, not new crypto); ePrint-first to get free expert review; scope the paid audit narrowly (PoW params + consensus + hybrid sigs) when funded. |
| 3 | **Bus factor = 1** | 🔴 Structural | The docs are the mitigation already begun — keep PROJECT-STATUS ruthlessly current. Add: reproducible-release discipline (anyone can rebuild), a `MAINTAINING.md`, and use the ePrint + first shipped product as the recruiting funnel. The protocol's ownerless design is itself succession; **Postern the company needs a named continuity plan** (even just: keys in escrow, a co-maintainer by Phase 3). |
| 4 | **Known-broken PoW params ossifying** | 🟠 | G1–G3 this month, before any public testnet accumulates participants who resist a consensus change. |
| 5 | **License minefield** | 🟠 | `deny.toml` + the roadmap's per-app license tables are ahead of the industry. Add: CI license-gate over the 9 product crates' full dep trees; re-verify the roadmap's "uncertainties" list at each adoption (continuwuity, LiveKit, Orbot text, matrix-rust-sdk pinning); keep the standing rules — **AGPL/GPL never embedded** (Element, libsignal, Bitwarden, ONLYOFFICE, Dangerzone, F-Droid code), MPL aggregation-only, PDFium(BSD)/LibreOffice(MPL, unmodified) as bounded exceptions. |
| 6 | **Legal exposure of privacy tooling** | 🟠 | Panic-Lock-not-wipe was the right ethics call — keep active erase deferred (reaffirm D9). Before shipping Courier/Deadbolt-adjacent features: one consult with a lawyer on the founder's jurisdiction (Brazil: Marco Civil, crypto-asset rules) + the informed-consent text verbatim in-product. Open-source public release keeps the classic export-control exception posture; the no-sale/no-listing stance is the securities shield. Keep protocol authorship pseudonymous as established. |
| 7 | **Breadth kills depth** (15 surfaces, 1 maintainer) | 🟠 | The park list (D8). No new crates until Suite v0.1 ships. Every sprint answers: "does this finish an edge?" |
| 8 | **"Live network" never materializes** (solo-node demo forever) | 🟡 | S3 is cheap: 3 disposable WAN nodes (Fly/Akash, explicitly non-official) + the convergence harness + adversarial matrix. Do a first pass in Phase 1. |
| 9 | **Trust-in-Google irony** (Container attestation chains to Google CA) | 🟡 | Already stated honestly in the spec — keep stating it; Postern OS Mobile remains the self-sovereign answer, later. |
| 10 | **Grant/funder strings** | 🟡 | Accept only funding compatible with permissive licensing and no user-KYC; NLnet/OTF-class funders are; decline anything else. |

---

## 5. The phased plan

### Phase 1 — next 2–4 weeks (buildable now, ~zero external cost)

**Goals:** kill the security debt, close the two self-serve protocol gaps, ship
the first real artifact.

| # | Work item | Track | Effort | Needs founder? |
|---|---|---|---|---|
| 1.0 | Rotate the leaked PAT; audit scope/usage; full-history gitleaks pass | Ops | hours | Do it / confirm done |
| 1.1 | **Run the lattice-estimator** (SageMath Docker + malb/lattice-estimator): sweep the small-`k` window, BDD cross-check, ≥2^128 + feasibility; append results to POW-HARDNESS | Protocol G1 | ~1 wk | D2 approval |
| 1.2 | Implement the **difficulty-knob split** (leading-zeros on `H(s)`; β frozen as floor) + canonical regime behind a feature flag; equivalence + regression tests | Protocol G2–G3 | 1–2 wks | — |
| 1.3 | **Coherence U.4**: selected-chain connect/disconnect wiring + `disconnect_block_self` + shielded-tx re-admission; SP1 prove/verify on the local toolchain (shielded stays RejectAll until verifier lands — safe default) | Protocol | 1–2 wks | — |
| 1.4 | **Ship `postern-hygiene` v0.1 CLI** (ODF added, static binaries, signed checksums, honest README) | Product | days | D6 (name freeze) |
| 1.5 | **Postern Suite v0.1**: fold hygiene/vault/seal-companion/panic/quarantine panes into the Tauri desktop; node/wallet demoted to Advanced-testnet tab with the zero-value caveat; per-pane honesty text | Product | 2–3 wks | D1 (flagship) |
| 1.6 | First **WAN multi-node run**: 3 disposable nodes + convergence harness; document "run your own seed" | Protocol G5 (start) | days | D10 (DNS-seed) |
| 1.7 | Draft the **ePrint parameter rationale** from 1.1's numbers | Protocol G4 | 1 wk | — |
| 1.8 | Grant applications drafted (NLnet call; OTF) — scoped to audit + Container | Business | days | D3 |
| 1.9 | CI license-gate over product-crate dep trees | Ops | day | — |

**Exit criteria:** PAT dead; canonical `(n,m,k,β)` chosen with published numbers;
node mines the canonical regime behind a flag; Suite v0.1 + hygiene CLI
downloadable; ePrint draft exists; ≥1 grant application submitted.

### Phase 2 — external-gated (money / hardware / people; ~1–4 months)

**Goals:** independent scrutiny + the entry product.

| # | Work item | Gate | Needs |
|---|---|---|---|
| 2.1 | ePrint submitted; solicit academic review (lattice community) | G4 | founder sign-off on the preprint |
| 2.2 | **Third-party audit**, scoped: canonical PoW params, consensus/reorg, hybrid sigs, serialization | G6 | 💰 (grant-funded per 1.8) — typically tens of thousands USD+; scope narrowly |
| 2.3 | **SEV-SNP end-to-end** on a rented confidential VM (Azure/GCP hourly): real quote, full L1→roothash→L3 verify; the Seal becomes demonstrable | S4 | small 💰 + days |
| 2.4 | **Mobile SDK builds**: cargo-ndk / xcframework for the wallet shells; then **Postern Container MVP** (DPC + StrongBox + Key-Attestation verify into the `mobile` backend + Orbot/Arti VPN) per the spec's build path | Product | Android hardware + weeks; D1 sequencing |
| 2.5 | Adversarial network matrix (equivocation, invalid blocks, eclipse) on the WAN testnet | G5 | — |
| 2.6 | Legal consult (BR jurisdiction; Courier/duress features; informed-consent text) | Risk 6 | small 💰 |
| 2.7 | TUF (`tough`) update channel live for Suite releases | Product | — |
| 2.8 | Coherence C3/C4 review; shielded pool remains disabled pending its own gate | Protocol | — |

### Phase 3 — shipping & users (post-audit-start; months)

**Goals:** real users, honest revenue, mainnet *candidacy* — not mainnet hype.

- **Suite 1.0**: signed builds, TUF updates, paid-support tier live; distribute
  the Container beta through digital-security-training orgs to the
  journalist/lawyer cohort (pilot, feedback loop, no at-risk-user marketing).
- **Public participatory testnet** on canonical params: outsiders run nodes/seeds
  (every-node-a-seed proven in the wild), still explicitly zero-value.
- **Audit remediation → "auditable mainnet candidate"** declaration only when
  G1–G6 all hold; shielded pool ships disabled unless separately audited.
- **Enterprise motion**: org deployments of Container + Suite + (post-S4) Seal
  verification for fleets.
- **Community stewardship**: publish MAINTAINING.md, take the first external
  maintainers from the ePrint/product funnels; Postern continuity plan executed.

---

## Decisions needed from you (approve/reject each)

| # | Decision | Recommendation |
|---|---|---|
| **D1** | Flagship: **(A)** Postern Desktop → *Postern Suite* privacy-toolbox hub (hygiene wedge), Container second — or **(B)** Container-first | **A** — weeks vs months to a real artifact; no chain dependency for value |
| **D2** | Run the Sage estimator + implement canonical-regime flag in Phase 1 (treat G1 as internal, not external) | **Yes** — it's free and everything waits on it |
| **D3** | Pursue grants (NLnet/OTF-class) as the audit-funding path, with the no-user-KYC / permissive-license compatibility rule | **Yes** |
| **D4** | Audit sequencing: **(A)** paid firm ASAP vs **(B)** ePrint + academic review first, then a narrowly-scoped paid audit | **B→A** — cheaper, better-scoped, and the preprint recruits |
| **D5** | PAT: rotate now + full-history secret scan (confirm if already done) | **Yes, day 1** |
| **D6** | Freeze product names ("Postern Suite", "Postern Hygiene", …) now — shipping v0.1 requires a name | **Yes** (names stay Postern's, protocol stays "Bloch") |
| **D7** | Monetization: **(A)** free source + paid signed builds/support/enterprise vs **(B)** donations/grants only | **A** — honest, standard, funds the mission |
| **D8** | Park list: freeze Messenger client, OS Mobile, Depot, Keys UI, backup, contacts until Suite v0.1 ships (cores stay in-tree; no new crates) | **Yes** |
| **D9** | Reaffirm: Deadbolt active-erase stays deferred; Panic Lock (deny-not-destroy) remains the shipped form | **Yes** |
| **D10** | WAN bootstrap: allow an **optional, non-privileged, anyone-can-replicate DNS-seed fallback** (documented, `DEFAULT_SEEDS` stays empty) | **Yes, with the framing exactly as stated** |

---

*Prepared as a decision draft. Nothing here proposes an owner, a gatekeeper, KYC,
a token sale, or a listing effort; every claim above stays behind its audit gate;
all proposed dependencies are MIT/Apache/BSD (MPL aggregation-only, flagged).*
