<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — Institutional Dossier, Edition 2 — PMO Plan

```
Document:   EDITION-2-PLAN
Status:     PLAN — chapter map frozen for this wave; prose not yet written
            (except Chapter 2, drafted in full in §4 of this plan)
Created:    2026-08-12
Revised:    2026-08-14 — **the transition this plan was written in
            anticipation of has happened.** Genesis-3 stopped permanently at
            height 39,918 on 2026-08-13 (not 50,000, which the chain never
            reached), and Genesis-4 has been live under proof of stake since
            21:31:19 UTC that day. Every chapter brief, status label and
            consistency trap below has been re-tensed against that fact.
            Writers: read §0 before anything else.
Edition 1:  "Bloch-SIS-PoW — Institutional Technical Dossier", Edition 1 · 2026,
            20 chapters, 71 pp (Bloch-SIS-PoW-Institutional-Dossier-EN.pdf)
Language:   English (docs/memory: official-language rule)
License:    AGPL-3.0-or-later, same as the codebase (ADR-039)
Publication: NOT published. Founder gate required. Nothing in this plan or in
            any chapter draft goes to posternlabs.com, an Artifact, or any
            public channel until the founder signs off.
```

---

## 0. The single most important correction to this plan

This plan was written on 2026-08-12 for a world in which Genesis-3 was still
mining, Genesis-4 was an internal devnet, and a review-and-audit pause of
roughly six months stood between them. **None of that is true any more, and
the direction of the writing rule reverses.**

| The plan said | The fact |
|---|---|
| Genesis-3 halts at height 50,000, days away | Genesis-3 **stopped permanently at height 39,918 on 2026-08-13**. It never reached 50,000. |
| The PoS node is "built, not booted — internal devnet" | **Genesis-4 is a live mainnet**, producing and finalising since 21:31:19 UTC on 2026-08-13. |
| A pause of ~6 months with no chain, for review and external audit | **There was no pause.** Genesis-4 launched the same day. There has been **no external audit**. |
| "Any sentence a reader could mistake for 'Genesis-4 is live' is a defect." | **Inverted.** Any sentence a reader could mistake for "Genesis-4 is not live", or for "there is a pause", or for "mining continues", is now the defect. |
| Launch gates G1–G4 stand between the code and a mainnet | The chain launched with **none of them met**. Chapters 17 and 21 must record that as what it is. |

The one thing that did **not** change is the discipline: *designed ≠ built ≠
booted*. Applied to today, the honest labels are that the PoS consensus rules
are **booted on a mainnet** — and that this mainnet is operated end to end by
one entity, running **64 of 64 validators**, on a transport with a fixed peer
list, no discovery and no authentication, with `Deposit` and `Delegate`
refused at every node's mempool. "Booted" is a fact about the code. It is not
a claim about decentralisation, and Edition 2 must never let the first be read
as the second.

**The replacement leading risk, to be used wherever Edition 1's
51%-attackability caveat sat:** the security question under Genesis-4 is not
hashrate, it is concentration — all 64 validators are run by one entity,
93.94% of the carryover sits at a single address, and 56.05 B of the 57.15 B
BLOCH issued at genesis is held by the founder and the Foundation. One
operator can halt the chain and one holder can outvote every other.

---

## 1. Why an Edition 2, stated the way Edition 1 would state it

Edition 1 is a well-written document whose central thesis has been retracted.
Its cover promises "an ownerless, post-quantum, pure proof-of-work BlockDAG."
Of those four claims, **post-quantum survives intact**; ownerless was retracted
in writing (ADR-036), pure proof-of-work **ended at Genesis-3 height 39,918 on
2026-08-13**, and the BlockDAG is retired with it (Genesis-4 is a linear PoS
chain, live since that day). The chain Edition 1 describes as live (Genesis-2)
was superseded by Genesis-3, which has itself now stopped.

A whitepaper whose thesis moves without a record is worth nothing. Edition 2
therefore does not quietly re-describe the project; it opens with a chapter
that names, one by one, every claim in Edition 1 that no longer holds, cites
the decision record that retired it, and says why. That chapter is mandatory,
it sits at the front (Chapter 2, immediately after the abstract), and its full
draft is in §4 of this plan. Everything else in Edition 2 is written in
Edition 1's best register — descriptive, non-promotional, every capability
labelled — because that register is the part of Edition 1 worth keeping.

**The inherited voice rule, kept verbatim: "designed ≠ built ≠ booted."**
Every feature in every chapter is labelled with which of the three states it
has reached. For Edition 2 this discipline matters *more* than in Edition 1,
and it now cuts in the opposite direction from the one this plan first
anticipated: the PoS consensus rules are **booted on a live mainnet**, and a
sentence a reader could mistake for "Genesis-4 has not launched" is a defect.
The discipline's job in Edition 2 is to stop "booted" from being read as
"decentralised, audited, or open to participants" — because on this chain it
is none of those. Sixty-four of sixty-four validators are one entity's; the
transport admits no strangers; the code is unaudited by any third party; and
`Deposit`/`Delegate` are refused at every node's mempool, so nobody outside
can bond stake. Each of those is a separate label and each must be carried
separately.

---

## 2. Edition 2 table of contents, with disposition against Edition 1

Legend — **SURVIVES**: carried over with edits only (name, cross-references,
tense). **REWRITE**: the subject survives but the text must be rebuilt.
**DIES**: the chapter is removed; its claims are either retracted (recorded in
Ch. 2) or moved to the historical record. **NEW**: no Edition 1 counterpart.

| # | Edition 2 chapter | Disposition | Ed. 1 ch. |
|---|---|---|---|
| 1 | Abstract & Executive Summary | REWRITE | 1 |
| 2 | **What Changed from Edition 1** | **NEW — mandatory, drafted in §4** | — |
| 3 | Introduction & Motivation | REWRITE | 2 |
| 4 | The Post-Quantum Imperative | **SURVIVES** | 3 |
| 5 | Cryptography | SURVIVES + additions | 10 |
| 6 | The Proof-of-Work Era — Genesis 1 through 3 (historical) | REWRITE (merge) | 5, 6, 7, 15 |
| 7 | The Halt at Height 39,918 and the Snapshot | NEW | — |
| 8 | Proof-of-Stake Consensus (Genesis-4) | NEW | — |
| 9 | Finality — Bloch-BFT | NEW (inverts Ed. 1's ch. 8) | 8 |
| 10 | Staking, Delegation & the Validator Economy | NEW | — |
| 11 | Weak Subjectivity & Checkpoints | NEW | — |
| 12 | Network Architecture | REWRITE | 9 |
| 13 | The Ledger — eUTXO, the Carryover, and EVM at L1 | REWRITE (merge) | 11, 12 |
| 14 | Ustav & Kirpich at L1 | REWRITE | 13 |
| 15 | Coherence — the ZK Ledger under PoS | REWRITE | 14 |
| 16 | Economics & Tokenomics V4 | NEW (replaces Ed. 1 ch. 16 entirely) | 16 |
| 17 | Concentration | NEW — Edition 1 did not treat this | — |
| 18 | Governance — the Retraction and the Two-Entity Structure | NEW (replaces Ed. 1 ch. 4 + 19.1–19.2) | 4, 19 |
| 19 | The Security Program & the External Audit | REWRITE + extend | 17 |
| 20 | Threat Model & Risk Factors | REWRITE | 18 |
| 21 | Roadmap — Gates and the Status Table | REWRITE | 19.3 |
| 22 | Honest Status, Disclaimers & Glossary | REWRITE | 20 |

**What survives intact:** Chapter 4 (harvest-now-decrypt-later, the NIST
FIPS 203/204/FN-DSA context, the hybrid-AND rationale) and the core of
Chapter 5 (the ML-DSA-65 ‖ Falcon-1024 suite, PQClean lineage, frozen
Cargo.lock posture) — the signature arrangement is an explicit fixed input of
the migration (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §1.2), so this prose
needs only renaming and cross-reference repair.

**What dies with no successor:** Edition 1's Chapter 4 ("The Ownerless
Commons") — its argument is retracted, not relocated. Edition 1's §16.3
(premine "structurally passive") — the 17% locked premine does not exist in
Genesis-4; describing the founder position now requires Chapter 17. Edition
1's §19.1–19.2 ("no foundation, no issuer") — factually false since
2026-08-10. The GhostDAG chapters survive only as history: Genesis-4 retires
the BlockDAG (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §5.2).

**What is inverted rather than deleted:** Edition 1's Chapter 8 told the
reader, correctly at the time, that Casper-FFG-style finality was "designed,
dropped — never integrated, never activated" and that PoW depth was the
finality story. Edition 2's Chapter 9 documents the opposite: a Casper-style
two-round, ≥ 2/3-stake, epoch-checkpoint finality rule (Bloch-BFT) **is** the
Genesis-4 design. Chapter 2 records the inversion explicitly so no reader of
both editions can think it happened silently.

---

## 3. Chapter briefs and repo sources

Every chapter cites its sources as file paths (and file:line where the claim
is load-bearing). Writers must not source claims from memory or from chat;
if a claim has no file behind it, it goes to the PMO as an open question.

### Ch. 1 — Abstract & Executive Summary (REWRITE)
Written **last**, after all chapters freeze. The four defining properties of
Ed. 1 §1.1 are replaced by: post-quantum from genesis (unchanged); fixed
100 B supply as a consensus invariant; PoS with finality by epoch (**live on
mainnet since 2026-08-13**, labelled); a foundation + development-company
structure with an identified issuer. The honest-status box moves with it:
live-but-unaudited consensus, one operator running all 64 validators, no
permissionless way to join, concentration stated in numbers up front.
Sources: all other chapters; `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` §0.1.

### Ch. 2 — What Changed from Edition 1 (NEW)
Drafted in full in §4 of this plan. PMO owns it.

### Ch. 3 — Introduction & Motivation (REWRITE)
The cryptographic pressure (Ed. 1 §2.1–2.2) survives nearly verbatim. The
structural pressure (§2.3–2.4, "the case for an ownerless commons") must be
rewritten honestly: the project now argues for *rule-binding by consensus
invariant* (the cap, the vesting, the gates) rather than *ownerlessness*, and
it must not pretend those are the same claim.
Sources: Ed. 1 ch. 2; `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`;
`docs/announcements/GENESIS3-HALT-AND-POS.md` §7;
`docs/papers/Acioli_2026_The_Cryptographic_Constitution.md` (self-binding
framing — use with care; parts predate the retraction).

### Ch. 4 — The Post-Quantum Imperative (SURVIVES)
Carry Ed. 1 ch. 3 with: name change; "every spending authorization on the
live chain" retensed across the halt — the live chain is now Genesis-4 and
the sentence is true of it; note that PQ signatures now also carry
**consensus** (proposals, attestations) on a live network for the first time
— pointer to ch. 8.
Sources: Ed. 1 ch. 3; `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §1.1,
§6.2; `crates/bloch-crypto/src/crypto/mod.rs` (suite constants).

### Ch. 5 — Cryptography (SURVIVES + additions)
Keep: hybrid ML-DSA-65 ‖ Falcon-1024 (both must verify), envelope/suite tags,
PQClean-derived vendored implementations. Add, each with a status label:
SHA-3/SHAKE-256 as the Genesis-4 consensus hash with domain separation
(designed; inventory exists); the hash-based commit-reveal randomness beacon
and why there is no PQ VRF (booted on Genesis-4); Falcon-1024 **online**
signing — G7 required external review *before* launch and **the chain
launched without it**, so this must be written as an open, live exposure and
not as a pending gate; genesis keys (they now exist and are signing; how they
were produced and are held is not evidenced in this repository).
Sources: `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §6.1–6.4;
`docs/specs/BLOCH-SHA3-MIGRATION-INVENTORY.md`;
`docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md`; `docs/specs/BLOCH-GENESIS-KEYS.md`.

### Ch. 6 — The Proof-of-Work Era, Genesis 1–3 (REWRITE, historical)
One chapter, past tense, merging Ed. 1's ch. 5 (PoW), 6 (GhostDAG), 7
(Genesis-2 fork) and 15 (mining ecosystem), extended through Genesis-3:
the 2026-07-29 relaunch (chain id 0xB10C_0004, SHA-256d little-endian from
height 0, carryover opening balance), AuxPoW merged mining live from h 8,500,
the difficulty-from-ancestry flag day (h 30,030), Emission V3 (h 40,000).
This is the only place GhostDAG, blue score, stratum, and the ASIC story now
live. It must state plainly that everything in it is **booted history that
ended at height 39,918 on 2026-08-13** — including the honest note that
Genesis-3's own risk register led with 51%-attackability at low hashrate, and
that the risk which replaced it is concentration, not the absence of risk.
Sources: Ed. 1 ch. 5–7, 15; `docs/PROJECT-STATUS.md` (superseded — use only
with its 2026-08-11 header warning); `legacy/MERGED-MINING.md`,
`legacy/MERGED-MINING-ACTIVATION.md`; `docs/CARRYOVER.md`;
`legacy/specs/TOKENOMICS_V3.md`, `docs/adr/ADR-035-emission-v3-schedule.md`;
`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §2 (baseline table).

### Ch. 7 — The Halt at Height 39,918 and the Snapshot (NEW)
Written in the **past tense**, because it happened. The halt as a consensus
rule, not an incident: why halt rather than run two chains; the signed
snapshot as the canonical record (the post-halt chain is not evidence); the
no-claim/no-swap/no-migration-tx rule and the scam warning.

Three things this chapter must not smooth over, because they are the
plan-versus-outcome record:
1. **The height moved twice and the chain stopped below both published
   values.** 80,000 → 50,000 (decided 2026-08-12, cutting public notice from
   ~2 weeks to ~4.4 days) → actual stop at **39,918** on 2026-08-13.
2. **The ~six-month review-and-audit pause did not happen.** Genesis-4
   launched the same day. Write what occurred; do not carry the planned
   duration as though it were a fact, and do not present the absence of a
   pause as an achievement.
3. **The external audit the pause existed for has not happened.** Neither
   have the G1–G4 distribution gates been met.

Sources: `docs/announcements/GENESIS3-HALT-AND-POS.md`;
`docs/specs/BLOCH-TOKENOMICS-V4.md` §3.1–3.2;
`crates/bloch-pos-committee/src/tokenomics_v4.rs` (`CARRYOVER_MEASURED_HEIGHT`
= 39,918 — the terminal snapshot, and the authority for the number);
`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` §0.0, §5.

### Ch. 8 — Proof-of-Stake Consensus (NEW)
Slots (30 s), 32-slot epochs, stake-weighted **public** sortition over a
hash-based beacon (and the DoS cost paid for publicness), the linear chain,
retiring GhostDAG, block identity `SHA3-256(DS_BLOCK ‖ header)`, state
commitment. Status label throughout: **booted — live mainnet since
2026-08-13**, paired every time with the operating reality that makes
"booted" not a decentralisation claim: 64 of 64 validators are one entity's;
the live transport is `Transport::Devnet`, a point-to-point TCP full mesh with
a fixed peer list, **no discovery and no authentication**, which is why a
third party cannot join; `Deposit`/`Delegate` are refused at every node's
mempool because bonding is not yet funded from the UTXO set. Do **not**
describe a production network layer as existing — a libp2p stack is in the
tree and is not what the fleet runs. Include §2's two inherited consensus
fragilities and how the design deletes the difficulty-validation bug class.
Sources: `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §3, §5, §6.3–6.5;
`docs/specs/BLOCH-POS-SORTITION-DOS.md`; `docs/specs/BLOCH-POS-INTERFACES.md`;
`crates/bloch-pos-node/`, `crates/bloch-pos-committee/`.

### Ch. 9 — Finality — Bloch-BFT (NEW)
The two-round, ≥ 2/3-stake, epoch-checkpoint finality rule; committee
partition (§6.5.3 — partition, do not sample); the 4.6 KB PQ signature as the
binding constraint and the measured attestation footprint; Casper-style
surround/double-vote slashing conditions. Must open by acknowledging the
inversion of Ed. 1 ch. 8.
Sources: `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §3, §6.5, §7.3;
`docs/specs/BLOCH-ATTESTATION-GOSSIP.md`;
`docs/specs/BLOCH-POS-NETWORK-CAPACITY.md`; `crates/bloch-ffg/` (naming: the
dossier term is **Bloch-BFT**; reconcile with the crate name in one sentence).

### Ch. 10 — Staking, Delegation & the Validator Economy (NEW)
Deposit / activation queue / attestation duty / rewards / slashing / exit /
withdrawal; the ~25,000 BLCH bond (post-split; supersedes 100,000) and its
32-ETH-fraction rationale; delegation including the **"what a delegator
risks"** section carried at full strength; commission (Solana revenue model);
fee policy (burn during the emission era, then to validators); warmup/churn.
Sources: `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §7;
`docs/specs/BLOCH-TOKENOMICS-V4.md` §6.3 (incl. 6.3.1 delegation, 6.3.2 fees);
`crates/bloch-pos-committee/src/delegation.rs`;
`docs/adr/ADR-038-warmup-churn-rate.md`; `docs/adr/ADR-037-carryover-stakeable.md`.

### Ch. 11 — Weak Subjectivity & Checkpoints (NEW)
Why PoS needs a subjective sync anchor at all; who signs — the Foundation,
per ADR-036, stated as the real centralisation cost it is; the phased 2-of-3
→ 3-of-5 m-of-n with a client-enforced external-signer minimum; the 12-month
review with a 15-month hard stop.
Sources: `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md` (§6 for the parameters);
`docs/specs/BLOCH-ENTITY-STRUCTURE.md` §5.3; ADR-036 ("an answer to weak
subjectivity").

### Ch. 12 — Network Architecture (REWRITE)
What survives of the libp2p stack; the attestation gossip load and the
epoch-boundary burst (≈ 588 KB) as a measured capacity requirement (gate
G10); lessons carried from Genesis-3 operations (gossipsub mesh scoring,
yamux stream caps) as engineering history informing the PoS mesh.
Sources: Ed. 1 ch. 9; `docs/specs/BLOCH-POS-NETWORK-CAPACITY.md`;
`docs/specs/BLOCH-ATTESTATION-GOSSIP.md`; `docs/post-mortems/` (as available).

### Ch. 13 — The Ledger: eUTXO, the Carryover, and EVM at L1 (REWRITE)
The eUTXO model as it crosses the snapshot; the carryover as **one
undifferentiated balance set, liquid at genesis, no founder line, no
exclusion list** (the taint machinery is retired — say so, and say what risk
disappeared with it); ADR-040's decision: EVM at the base layer, no L2,
`bloch-l2-evm` (chainId 8400) is being replaced, not extended. Status
labels: eUTXO booted (G3, historical); L1 EVM **designed** — an execution
plan and reuse audit exist, `bloch-pos-node` references euvm zero times
today. Include ADR-040's premise correction: Solana is *not* natively EVM
and must not be cited as EVM precedent.
Sources: Ed. 1 ch. 11–12; `docs/adr/ADR-040-evm-and-ustav-at-l1.md`;
`docs/specs/BLOCH-L1-EXECUTION-PLAN.md`; `docs/specs/BLOCH-L1-EVM-STATE-MODEL.md`;
`docs/specs/BLOCH-L1-EVM-REUSE-AUDIT.md`; `docs/specs/BLOCH-L1-FEE-MARKET.md`;
`docs/specs/BLOCH-L1-EVM-THREAT-MODEL.md`; `docs/specs/BLOCH-TOKENOMICS-V4.md` §2.

### Ch. 14 — Ustav & Kirpich at L1 (REWRITE)
Ustav promoted from "reference tooling" to a **consensus object** validated
by every node (ADR-040); Kirpich as the fail-closed charter gate under PoS.
Status: designed; under development.
Sources: Ed. 1 ch. 13; `docs/adr/ADR-040-evm-and-ustav-at-l1.md`;
`docs/specs/BLOCH-USTAV-L1.md`; `docs/specs/BLOCH-KIRPICH-UNDER-POS.md`;
`crates/bloch-euvm/` (as it exists today).

### Ch. 15 — Coherence: the ZK Ledger under PoS (REWRITE)
C1-frozen formats preserved byte-for-byte (SHAKE-256 commitments/nullifiers,
raw FRI-STARK, no elliptic-curve ZK — already PQ-consistent); the one new
consensus rule the shielded pool forces on staking (shielded state must be
finalized state); continuity across the transition; the pool is provably
empty on this mainnet, so the transition moves no shielded value.
Sources: Ed. 1 ch. 14; `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §6.6;
`docs/specs/BLOCH-COHERENCE-UNDER-POS.md`; `docs/specs/COHERENCE-C1.md`,
`COHERENCE-C1.1.md`; `crates/coherence-core/`, `crates/coherence-prover/`.

### Ch. 16 — Economics & Tokenomics V4 (NEW — full replacement)
Nothing in Ed. 1 ch. 16 survives. Contents: the fixed 100,000,000,000 BLCH
supply with the cap as a **consensus invariant** (committed state component;
`SupplyCapExceeded`; stated at true strength: no in-protocol path can raise
it — a universally adopted hard fork can change any rule of any chain); the
pure ×100/21 split (≈ 4.7619) and the three costs of the redenomination that
the CertiK dossier names (i64 overflow in the Go SDK; the emission constant
re-derived by binary search, not scaled; floor-division remainders absorbed
by the founder's carried balance); the allocation table, **restated against
the terminal snapshot** — carryover **18,146,400,000 BLOCH = 18.15%**, liquid
· founder grant 10%, 10-y cliff + 40-y linear · VC 10% · team 10% ·
marketing 4% · liquidity 5% · validator emission **42,853,600,000 = 42.85%**
over 40 years (`tokenomics_v4.rs`, compile-asserted to sum to the cap); 10%
annual disinflation and why not a halving; vesting schedules and their basis;
what the split does and does not preserve (share of eventual supply, not of
circulating supply). **Do not carry the 17.97% / 43.03% pair** — those were
computed against the provisional carryover measured at what was mislabelled
"height 43,172" and are superseded by the terminal figures above. Also state
plainly: **57,146,400,000 BLOCH was issued at slot 0** (`GENESIS_ISSUED_SAT`),
the remainder being the unissued 40-year validator emission.
Sources: `docs/specs/BLOCH-TOKENOMICS-V4.md` (primary);
`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` §0.1, §1.2;
`docs/announcements/GENESIS3-HALT-AND-POS.md` §5; `tokenomics_v4.rs` /
`state_root.rs` tag `0x14` / `transition.rs` (as cited by the CertiK dossier);
`legacy/specs/historical/TOKENOMICS_V1_SUPERSEDED.md`, `TOKENOMICS_V2.md`,
`TOKENOMICS_V3.md` (lineage only).

### Ch. 17 — Concentration (NEW)
Edition 1 did not treat this; Edition 2 treats it as a first-class subject,
numbers first, **all from one snapshot — the terminal Genesis-3 measurement at
height 39,918, 452,726 outputs, 16 addresses** (`tokenomics_v4.rs`:
`CARRYOVER_MEASURED_HEIGHT`, `CARRYOVER_MEASURED_UTXOS`,
`CARRYOVER_TOTAL_BLOCH`, `LARGEST_CARRYOVER_ADDRESS_BLOCH`). Every figure
must name the snapshot it came from; mixing two measurements is how this
project previously produced a phantom 0.8-point "drop" in concentration.

- The largest single address, the founder's, holds **17,046,829,380 of
  18,146,400,000 BLOCH — 93.94% of the carryover**, liquid and **stakeable**
  by decision of 2026-08-11. Staked and compounded it holds ~94% of active
  stake, and pro-rata rewards preserve that share, so it does not decay.
  **Nakamoto coefficient 1.**
- Founder total including the 10% grant: **27,046,829,380 BLOCH = 27.04% of
  the cap** (`FOUNDER_TOTAL_BLOCH`, pinned at 2704 bps). The Foundation holds
  a further **29.00%** across four buckets. Together
  **56,046,829,380 of the 57,146,400,000 issued at slot 0**, leaving
  **1,099,570,620 BLOCH — 1.92% of genesis supply — in third-party hands.**
  Write it as *founder and Foundation together*; the repository pins the
  founder figure and does not pin recipient keys for the Foundation buckets,
  so "one key holds 56 B" would be unverified and must not be written.
- **The operator fact, which outranks all of the above on a live chain: all
  64 Genesis-4 validators are operated by a single entity.** There is no
  independent validator, and **no permissionless path to becoming one** —
  the transport has a fixed peer list with no discovery and no
  authentication, and `Deposit`/`Delegate` are refused at every node's
  mempool. G1's observed value is 0% and cannot move until both are fixed.
- **Do not carry the superseded pairs**: "≈3.427 B of 3.634 B measured at
  h18,809" (a pre-split, pre-terminal reading), "16,886,549,523 BLCH", or
  "70.4% of circulating supply at slot 0". The terminal circulating-at-slot-0
  figure is **70.60%** (17,046,829,380 of 24,146,400,000 = carryover +
  liquidity 5 B + marketing TGE 1 B).

What bounds it: the founder grant's schedule, the genesis-cohort
one-third-within-a-year rule, per-validator limits — and what each does *not*
achieve, which on a one-operator chain is very nearly everything. The
gate-measurement rule: Foundation-delegated stake and insider stake do not
count toward G1–G4. **And the fact the chapter exists to state without
softening: Genesis-4 launched with G1–G4 unmet and with no external audit.**
Sources: `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §0.1, §4.1–4.2, §11;
`docs/specs/BLOCH-TOKENOMICS-V4.md` §4A, §4A.1, §5;
`docs/audit/CERTIK-CENTRALIZATION.md`; `docs/specs/BLOCH-ENTITY-STRUCTURE.md`
§5.1, §7.

### Ch. 18 — Governance: the Retraction and the Two-Entity Structure (NEW)
ADR-036 in full daylight: what was retracted (ADR-033, ADR-034), why
(Tokenomics V4's sold allocation implies an issuer; weak subjectivity needed
a signer), and what replaced it — Bloch Foundation (to be created; holds 29%
at genesis, the largest single holder for the first decade) beside Postern
Labs Ltda (builds, employs, signs releases; **no protocol authority**). The
who-signs-what table. The four naive-failure modes from the entity spec,
kept at full strength: the delegation program as a decentralisation
illusion; related-party funding controls; checkpoint publication as a
centralisation point; (the taint list is gone — record that the fourth risk
ceased to exist rather than being mitigated). Open items that need counsel:
jurisdiction, who sells to funds, board independence.
Sources: `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md` (primary);
`docs/specs/BLOCH-ENTITY-STRUCTURE.md`; `docs/adr/ADR-033`, `ADR-034`
(as retracted context only).

### Ch. 19 — The Security Program & the External Audit (REWRITE + extend)
Keep Ed. 1 ch. 17's named-instruments table (cargo-audit/deny/geiger, Miri,
cargo-fuzz, proptest, OSS-Fuzz, blocking supply-chain CI) — verify each still
runs against this repo before asserting it. Add: the internal audit plan; the
CertiK engagement posture — the pre-audit dossiers written so the auditor
does not have to discover anything, including the "findings we found and
fixed ourselves" and the open-gaps list. **And the correction this chapter
must lead with rather than bury: the external audit was the thing the pause
existed for, and neither happened.** Genesis-4 launched on 2026-08-13 with no
third-party review of the consensus crate, the node, or the hybrid signature
composition; G7 (external review of the Falcon online-signing path) was a
pre-launch gate and was not met. Write G7/G8 as **open live exposures**, not
as gates that still stand ahead of anything.
Sources: Ed. 1 ch. 17; `legacy/INTERNAL-AUDIT-PLAN.md`;
`docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`; `docs/audit/CERTIK-CENTRALIZATION.md`;
`docs/audit/CERTIK-MARKET-TRANSPARENCY.md`; `docs/FLEET-BRIEF-CERTIK-2026-08-12.md`;
`docs/SECURITY_SELF_ASSESSMENT.md`; `SECURITY.md`, `SECURITY_TOOLING.md`.

### Ch. 20 — Threat Model & Risk Factors (REWRITE)
The Ed. 1 risk list rebuilt for PoS. New or changed first-order risks:
stake concentration (cross-ref ch. 17) replaces 51%-attackability as the
headline; sortition DoS (public leader election); stake churn; long-range
attacks and the weak-subjectivity dependency; the Falcon online-signing
surface; single-client risk (G5); the discarded AuxPoW security budget named
as a real cost; the securities question moved **toward** the centre of the
investment-contract test (issuer + staking yield + VC round) with Phase 0
legal review blocking. And, replacing the "devnet-stage software risk" row
this plan originally anticipated, the four live risks that exist because the
chain launched anyway:
- **Unaudited consensus running a mainnet.** No third-party review of the
  consensus crate, the node, or the hybrid composition; G7 was a pre-launch
  gate and was not met.
- **Operator monoculture.** 64 of 64 validators, one entity; one operator can
  halt the chain. This is the concrete form stake concentration takes today,
  and it is stronger than the coin-concentration argument, not weaker.
- **A transport that admits nobody.** Fixed peer list, no discovery, no
  authentication — so the operator set cannot become plural by anyone else's
  choice. Do not describe the libp2p stack in the tree as a live production
  network layer; it is not what the fleet runs.
- **A transaction class disabled by node policy.** `Deposit`/`Delegate` are
  refused at every node's mempool because bonding is not funded from the UTXO
  set; a deposit would otherwise register stake without spending coins. State
  both halves: the refusal closes a real mint-stake-from-nothing exposure, and
  it also means nobody can bond.
Sources: Ed. 1 ch. 18; `docs/specs/BLOCH-POS-THREAT-MODEL.md`,
`BLOCH-POS-THREAT-MODEL-2.md`; `docs/specs/BLOCH-POS-SORTITION-DOS.md`;
`docs/specs/BLOCH-POS-STAKE-CHURN.md`; `docs/specs/BLOCH-WEAK-SUBJECTIVITY.md`;
ADR-036 ("what this obliges"); `docs/specs/BLOCH-POS-GAPS.md`.

### Ch. 21 — Roadmap: Gates and the Status Table (REWRITE)
Ed. 1 §19.3's table was the best page of the old document; rebuild it for
Genesis-4. Rows (illustrative, writers verify each against the repo):
hybrid signatures — **booted**, now on consensus paths too; halt rule —
**fired**, Genesis-3 stopped at height 39,918 on 2026-08-13; terminal snapshot
— **taken and pinned** (452,726 outputs, 18,146,400,000 BLOCH, root and file
digests in `tokenomics_v4.rs`); PoS node — **booted, live mainnet**;
Bloch-BFT finality — **booted**, finalising by epoch; supply-cap consensus
invariant — **booted** (`SupplyCapExceeded`); transfers — **live**;
deposits/delegations — **built, refused at the mempool**, so not usable;
network transport — **devnet mesh in production**: fixed peers, no discovery,
no authentication (libp2p exists in-tree, not in use by the fleet);
delegation — implemented, not exercisable; L1 EVM — designed; Ustav-at-L1 —
designed; weak-subjectivity m-of-n — designed with parameters adopted;
external audit — **not done, and the chain launched without it**; Foundation
— not yet created.

Then the Go/No-Go gates G1–G11 quoted in full — followed by the correction
the roadmap now owes its reader. The sentence that was the roadmap's spine
read: *if the coins do not distribute, the migration does not happen — and
that is the correct outcome, not a failure of the engineering.* **The coins
did not distribute and the migration happened.** Chapter 21 must print the
original sentence, then say plainly that it was not honoured, and give each
gate its observed value today (G1: 0% independent stake, and unreachable
while deposits are refused; G2/G3/G4: one entity, 64 validators, zero
unaffiliated). A roadmap that quietly drops its own no-go condition is worth
less than no roadmap.
Sources: `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §10, §11;
`docs/ROADMAP.md`, `docs/ROADMAP-GATED-ITEMS.md`; crate tree under `crates/`.

### Ch. 22 — Honest Status, Disclaimers & Glossary (REWRITE)
The disclaimer must change in one hard way: Edition 1 could write "BLCH is
not a security ... no listing effort ... nobody with standing to make a value
claim." After ADR-036 there **is** an issuer, there is a planned sale to
funds, and there is staking yield; Edition 2 states the securities question
as **open and under blocking legal review**, makes no value claim, and does
not assert the old defence. "Unaudited" gets the same two-layer treatment as
Ed. 1 §20.2, updated for the CertiK engagement. Glossary: drop
GhostDAG/blue_score to a "historical terms" subsection; add slot, epoch,
attestation, checkpoint, weak subjectivity, sortition, bond, delegation,
disinflation, snapshot, split.
Sources: Ed. 1 ch. 20; ADR-036; `docs/audit/CERTIK-MARKET-TRANSPARENCY.md`.

---

## 4. Chapter 2 draft — "What Changed from Edition 1" (PMO-authored, mandatory)

> The text between the rules below is the chapter draft, ready for the
> Edition 2 manuscript subject to founder review. It is deliberately placed
> at the front of the dossier, not in an appendix: a reader of Edition 1
> must be able to read this one chapter and know exactly which of that
> document's claims still stand.

---

Edition 1 of this dossier described a protocol named Bloch-SIS-PoW and made
four defining claims on its cover: that it was ownerless, post-quantum, pure
proof-of-work, and a BlockDAG. One of those four claims survives into this
edition. This chapter records what happened to the other three, and to
everything downstream of them, because this document's standard — set by
Edition 1 itself — is that a dossier whose claims move without a record is
worth nothing. Each retraction below names the decision record that made it.
Nothing here happened silently.

**1. "Ownerless" has been retracted.** Edition 1's Chapter 4 argued for, and
its Chapters 1, 16, and 19 repeatedly relied on, an ownerless commons: no
issuer, no foundation, no entity with standing to speak for the protocol or
make representations about BLCH. On 2026-08-10 the founder retracted that
thesis in writing (ADR-036, which revokes ADR-033 and ADR-034, the founder's
relinquishment pact). The reason is stated in the ADR rather than
reconstructed here: the Genesis-4 token design allocates 10% of supply for
sale to funds, and an allocation sold to investors cannot be sold by nobody —
it implies an issuer, and carrying "ownerless" and "issuer" at once would
have been false. The replacement structure is the Solana template: a
non-profit **Bloch Foundation** (to be created) that holds and distributes
the non-founder allocations, signs listing and subscription agreements, and
publishes weak-subjectivity checkpoints, beside **Postern Labs Ltda**, the
development company, which builds and signs releases and holds no protocol
authority. Every sentence in Edition 1 that says "no issuer," "no
foundation," "nobody with standing," or "ownerless" is superseded. The
governance chapters of this edition (Chapters 11 and 18) describe what
exists instead, including the centralisation costs the new structure pays
and the controls intended to keep the two-entity split from being letterhead.

**2. "Pure proof-of-work" ends at a known block height.** Edition 1 stated:
"no staking, no bonded validator set, and no delegated voting weight
standing in for hash power," and presented proof-of-work's externally
verifiable cost as half of the project's thesis. That design is being
retired. That retirement is complete: **the Genesis-3 chain stopped, by
consensus rule, at height 39,918 on 2026-08-13**, and **Genesis-4 has been
live as a proof-of-stake chain since 21:31:19 UTC that same day** —
stake-weighted leader election, a bonded validator set (~25,000 BLCH per
validator, post-split), delegation, and slashing
(BLOCH-POS-SHA3-LATTICE-MIGRATION.md). The migration design itself names the
costs, and this edition repeats them rather than softening them: the
merged-mined Bitcoin hashrate that secured Genesis-3 — the cheapest real
security this chain will ever have had — is discarded; staking rewards
strengthen an investment-contract reading of BLCH; and under proof-of-stake,
coins are consensus weight, which makes the concentration described in
point 6 below a consensus-security fact rather than only an economic one.
Two further facts belong here rather than in a footnote, because the plan and
the outcome differ: the review-and-audit pause the migration design placed
between the two chains **did not occur**, and **no external audit has been
performed**.
What the migration buys is also stated: deterministic finality, deletion of
an entire class of consensus bugs the PoW chain actually suffered
(order-dependent difficulty validation), and the end of the chain's
dependence on rented, departing hashrate.

**3. Finality: Edition 1's account is inverted.** Edition 1's Chapter 8 was
titled "Finality & the Dropped FFG" and said, accurately at the time, that a
Casper-FFG-style finality overlay "was never integrated, never activated,
and never shipped," and that the live finality story was proof-of-work depth
plus checkpoints. In Genesis-4 the design position is the opposite: a
Casper-style finality rule — **Bloch-BFT**, two voting rounds, a ≥ 2/3 stake
quorum, checkpoints at epoch boundaries, surround- and double-vote slashing —
is the core of the consensus design, carried by the same post-quantum
signatures as everything else (no BLS aggregation exists for lattice
schemes, and the design pays that bandwidth cost rather than adding a
classical primitive). Its status is **booted**: since 2026-08-13 it justifies
and finalises checkpoints on the live Genesis-4 mainnet. What "booted" does
not mean here, and Chapter 9 must say so in the same breath: the quorum it
measures is 64 validators operated by one entity, so a two-thirds
supermajority is currently one party's decision. Chapter 9 documents it.

**4. The chain Edition 1 described is now history — and it has stopped.**
Edition 1 documented Genesis-2 as the live chain. Since then: Genesis-3
relaunched the network on 2026-07-29 (fresh height 0, SHA-256d with
little-endian target comparison from genesis, the carryover as an opening
balance, merged mining with Bitcoin from height 8,500); and **Genesis-3
stopped permanently at height 39,918 on 2026-08-13**, by a consensus rule. A
signed snapshot of every balance at that height is the canonical record —
452,726 outputs, 18,146,400,000 BLOCH, its SHAKE-256 set root and both file
digests published in `tokenomics_v4.rs` so anyone can reproduce and compare.
Mining income ended there. **Genesis-4 opened with those balances the same
day, at 21:31:19 UTC.** Two things stated in this edition's own record
because the plan said otherwise: the announced halt height at the time was
50,000 and the chain stopped below it, and the planned months-long
review-and-audit pause between the chains did not happen — there was no
interval, and no external audit. There is no claim process, no swap, and no
migration transaction — a balance crossed by its holder doing nothing, and
anything that asks otherwise is an attempt at theft. Chapters 6 and 7 give the
full account. Readers of Edition 1 should note what this means for its text:
the BlockDAG and GhostDAG ordering described in its Chapter 6 are retired with
proof-of-work; Genesis-4 is a linear chain.

**5. The economics are replaced, not amended.** Edition 1's Chapter 16
described a 21-billion nominal supply that was explicitly not hard-capped (a
perpetual tail subsidy), a Bitcoin-style halving schedule, and a founder
premine of 17% locked behind a 10-year cliff and 40-year vest, presented as
"structurally passive." None of that describes Genesis-4. The supply is a
fixed **100,000,000,000 BLCH**, produced from the 21 B nominal by a pure
×100/21 redenomination (every balance and every allocation scaled by the
same factor — more units, identical shares, no new money), and the cap is
enforced as a **consensus invariant**: cumulative issuance is a committed
component of the state, and a block that would exceed the cap is invalid.
Stated at its true strength and no stronger: no in-protocol mechanism — no
vote, no key, no governance path — can raise it; a hard fork adopted by
every operator can change any rule of any chain. Emission goes to validators
over 40 years on a 10% annual disinflation curve (there is no halving), and
the allocation, measured against the terminal snapshot, is: carryover
**18,146,400,000 BLOCH = 18.15%** (liquid at genesis), founder grant 10%
(10-year cliff, then 40-year linear vest), VC 10%, team 10%, marketing 4%,
liquidity 5%, validator emission **42,853,600,000 = 42.85%**. Of that,
**57,146,400,000 BLOCH existed at slot 0**; the rest is unissued and arrives
over forty years. The 17% locked premine of Edition 1
**does not exist in Genesis-4**; the founder's position is instead the sum
of a new, strictly-vested 10% grant and a carried-over mined balance that is
liquid — which is the subject of the next point.

**6. Concentration is now treated as a first-class fact. Edition 1 did not
treat it.** Edition 1 disclosed the locked premine at length but was silent
on the distribution of the circulating, mined supply. The measured numbers,
all from the terminal Genesis-3 snapshot at height 39,918 (452,726 outputs,
16 addresses): **93.94% of the supply crossing that snapshot sits at one
address, the founder's** — **17,046,829,380 of 18,146,400,000 BLOCH**, which
is **70.60% of circulating supply at slot 0** — and by decision of 2026-08-11
that balance crossed liquid and **stakeable**, on the same terms as every
other carried balance, because it was mined under the same rules as every
other balance. Including the new grant, the founder holds **27.04% of the
100 B cap**; the Foundation holds a further **29.00%**; together
**56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0**, leaving
**1,099,570,620 — 1.92% — with everyone else.**

Under proof-of-stake this is not a footnote; it is the consensus. If that
balance is staked, independent participants cannot reach the migration's
distribution gate from emission alone — the gate moves only when coins change
hands. **And the harder fact, which is about operators rather than coins: all
64 Genesis-4 validators are run by a single entity, and no third party can
join today** — the live transport has a fixed peer list with no discovery and
no authentication, and `Deposit`/`Delegate` are refused at every node's
mempool because bonding is not yet funded from the UTXO set. One operator can
halt the chain; one holder can outvote every other.

The migration design made distribution a hard Go/No-Go condition (gates
G1–G4: independent stake ≥ 15% of circulating supply, no entity above 25% of
active stake, Nakamoto coefficient ≥ 7, ≥ 200 validators), measured while
excluding stake whose beneficial owner is the founder, the Foundation, or
Postern Labs — and said that if the gates were not met, the transition would
not activate. **The transition activated on 2026-08-13 with none of them
met.** This edition records that plainly rather than describing the gates in
the future tense; a Go/No-Go condition that did not stop anything is a
governance finding, and Chapter 21 carries it as one. Chapter 17 carries the
year-by-year arithmetic; nothing in it is flattering, and it is published
anyway, because the alternative is that someone else publishes it first.

**7. The securities posture is weaker, and this edition says so.** Edition 1
wrote: "BLCH is not a security and not an investment asset ... no token
sale, no listing effort, and no price or value claim made on its behalf by
anyone with standing to make one, because nobody has that standing." That
defence rested on the ownerless structure and has been retracted with it.
There is now an identifiable issuer, a planned sale to funds, and staking
yield — facts that move the question toward the centre of the
investment-contract test, not away from it. This edition does not assert a
legal conclusion in either direction: the question is under legal review
that the migration plan classifies as blocking, and until it concludes, the
only honest statements are that no value claim is made, nothing in this
document is investment advice, and the old "nobody has standing" argument
is no longer available.

**8. The name and the mark.** "Bloch-SIS-PoW" named the protocol by its
proof-of-work construction; with that construction retiring, the protocol is
now **Bloch Protocol**. The visual identity changes with it: Edition 1's
navy-and-triangle cover is replaced by the white-ground, emerald (#0E6E5A)
identity whose mark is the **Bloch sphere** — the protocol is named for
Felix Bloch, and the sphere is the canonical representation of a qubit,
which is the object this protocol's cryptography is built to survive
(docs/site/BRAND-KIT.md). A name is not a thesis, but a renamed document
owes its readers the note.

**What did not change.** The cryptography — the hybrid ML-DSA-65 ‖
Falcon-1024 signature suite in which both algorithms must verify, the
PQClean-derived implementations, the frozen-dependency posture — is carried
into Genesis-4 unchanged, and is an explicit fixed input of the migration
design. The harvest-now-decrypt-later argument of Edition 1's Chapter 3
stands word for word. The Coherence shielded pool's frozen formats are
preserved byte-for-byte (and the pool is provably empty on this mainnet, so
the transition moves no shielded value). The license is AGPL-3.0-or-later.
And the discipline this chapter itself obeys — **designed ≠ built ≠ booted**,
every capability labelled with the state it has actually reached — is
retained from Edition 1 in full, because it was the best thing in that
document, and it is the reason this chapter could be written at all.

---

*End of Chapter 2 draft.*

---

## 5. Voice and status-label rules (binding on all writers)

1. **designed ≠ built ≠ booted**, labelled per feature, every chapter. The
   refinement this plan originally carried — *devnet is not mainnet, so the
   PoS node is "built, not booted"* — **is obsolete and must not be used.**
   Genesis-4 is a mainnet and the PoS consensus rules are **booted** on it.
   The refinement that replaces it: ***booted is not decentralised, audited,
   or open.*** Wherever a chapter writes "booted" for a Genesis-4 capability,
   it carries in the same breath whichever of these apply: 64 of 64
   validators are one entity's; the transport has a fixed peer list with no
   discovery and no authentication, so a third party cannot join;
   `Deposit`/`Delegate` are refused at every node's mempool, so nobody can
   bond stake; and no third party has audited any of it. Never write "devnet"
   for the network, the chain, the binary, or the project's stage — that word
   is accurate **only** as the name of the transport
   (`Transport::Devnet`), and only when the sentence is about the transport.
2. Descriptive, non-promotional register. No value claims, no adoption
   forecasts, no "will" where the source says "planned."
3. Numbers are quoted with their measurement date and source (file:line or
   RPC + date). A number without a source goes back to the writer.
4. The securities language of Edition 1 ("not a security ... nobody has
   standing") is **forbidden**. Use the Ch. 22 formulation: question open,
   legal review blocking, no value claim, not investment advice.
5. "Ownerless," "commons," "no issuer," "no listing effort," "coins don't
   vote," and the civic-movement voice are usable **only** inside quoted
   Edition 1 material or historical narration, always with the retraction
   noted.
6. Do not cite Solana as EVM precedent (ADR-040 premise correction).
7. English. SPDX header `AGPL-3.0-or-later` on every source file of the
   manuscript. Author/copyright line as in Edition 1.
8. Unpublished until the founder gate. No Artifacts, no site copy, no PDFs
   circulated outside the repo.

## 6. Consistency traps — verified against the repo, 2026-08-12; re-verified 2026-08-14

Writers will meet contradictory numbers in the sources. The decisions of
record win, and where an event has overtaken a decision, **the event wins**.
Specifically:

1. **The halt height is a measured fact, not a decision: Genesis-3 stopped at
   height 39,918 on 2026-08-13.** The authority is
   `crates/bloch-pos-committee/src/tokenomics_v4.rs`
   `CARRYOVER_MEASURED_HEIGHT`, alongside `CARRYOVER_MEASURED_UTXOS` (452,726)
   and `CARRYOVER_TOTAL_BLOCH` (18,146,400,000). Two stale values persist
   across the repo and **neither may be copied into Edition 2**: **80,000**
   (`BLOCH-ENTITY-STRUCTURE.md:121`,
   `BLOCH-POS-SHA3-LATTICE-MIGRATION.md:832`,
   `BLOCH-POS-NODE-INTEGRATION.md:29,51,276`, `BLOCH-POS-INTERFACES.md:279`,
   `BLOCH-SHA3-MIGRATION-INVENTORY.md:9`, `BLOCH-L1-EVM-REUSE-AUDIT.md:359`,
   `docs/PROJECT-STATUS.md` header) and **50,000** (the 2026-08-12 decision,
   in the tokenomics spec §3.1/§3.2, the migration spec, the announcement, and
   the portal pages).
1a. **The block-count trap, which has already produced one wrong published
   number.** Earlier documents say the carryover was "measured at height
   43,172". The chain was never at that height — 43,172 was a **block count**,
   and in a DAG the two differ by design. Any writer quoting a snapshot must
   quote a *height* and name the artifact. Related: never mix figures from two
   snapshots. Updating the carryover total against a fresh measurement while
   leaving the largest-address figure at an older reading once moved reported
   concentration from 93.96% to 93.17% — a "drop" that was an artifact of
   mixing measurements, not a change in who holds what.
2. **The announcement draft has a copy bug**: `GENESIS3-HALT-AND-POS.md`
   twice reads "redenominated from 100,000,000,000 to 100,000,000,000" — the
   correct statement is 21 B → 100 B at ×100/21 (its own Telegram appendix
   has it right). Do not propagate.
3. **`BLOCH-TOKENOMICS-V4.md` §1 contains a garbled redenomination sentence**
   ("54.21% of `u64::MAX` rather than the earlier draft's 54.21%") — an
   artifact of the 2026-08-12 edit. The correct framing is in
   `CERTIK-PRE-AUDIT-DOSSIER.md` §0.1: supply = 54.2% of `u64::MAX` and
   **108% of `i64::MAX`** (hence the Go SDK `int64` migration requirement).
4. **Validator bond is 25,000 BLCH post-split**; 100,000 is superseded
   (`CERTIK-PRE-AUDIT-DOSSIER.md` §0.1).
5. **Founder grant is 10%**; 17% appears in earlier drafts and in Edition 1
   (where it was the locked premine). The two are different objects — the
   V2 premine (17%, consensus-locked, never emitted) died with Genesis-3's
   halt; the V4 grant (10%, 10-y cliff + 40-y linear) replaces it. Never
   conflate them.
6. **Validator emission is 42,853,600,000 BLOCH = 42.85%**, and the carryover
   is **18,146,400,000 = 18.15%**, both against the terminal snapshot and both
   compile-asserted in `tokenomics_v4.rs`. The pair **17.97% / 43.03%** was
   computed against the provisional pre-terminal carryover and is superseded;
   53.7% is an older dead draft figure (`BLOCH-ENTITY-STRUCTURE.md` §3 note).
6a. **Concentration figures, terminal snapshot, all from one measurement:**
   largest address **17,046,829,380 of 18,146,400,000 = 93.94%** of the
   carryover; founder total **27,046,829,380 = 27.04%** of the cap
   (pinned at 2704 bps); Foundation **29.00%**; issued at slot 0
   **57,146,400,000**, of which founder + Foundation hold **56,046,829,380**,
   leaving **1,099,570,620 (1.92%)** with third parties. Superseded values not
   to be copied: 93.96%, 93.97%, 16,886,549,523, 17,970,880,000, 26.89%,
   70.4%, "≈3.427 B of 3.634 B at h18,809". **Write "founder and Foundation
   together" — never "one key holds 56 B"**: the repo pins the founder figure
   and does not pin the Foundation buckets' recipient keys.
6b. **Operator concentration outranks coin concentration on a live chain.**
   All 64 Genesis-4 validators are operated by one entity; no third party can
   join (fixed peer list, no discovery, no authentication) and nobody can bond
   stake (`Deposit`/`Delegate` refused at every node's mempool). Any chapter
   that discusses concentration must state this, not only the coin figures.
7. **`docs/PROJECT-STATUS.md` is superseded framing** (its own 2026-08-11
   header says so). Use it for Genesis-3 history only, never for present
   tense.
8. **Taint/exclusion machinery is retired** (`…MIGRATION.md` §4 header).
   Any source text describing taint propagation, the 300 M holder cap, or
   premine ineligibility describes a design that no longer exists.
9. **Finality naming**: the dossier term is **Bloch-BFT** (migration spec
   §3); `crates/bloch-ffg` is the crate's historical name. One reconciling
   sentence in Ch. 9, then use Bloch-BFT throughout.
10. Emission V3 (ADR-035) was a **Genesis-3** flag day (h 40,000) and is
    itself superseded by V4 for Genesis-4. It belongs in Ch. 6 (history)
    only. Note that Genesis-3 stopped at 39,918 — *below* that flag day.
11. **Sources written before 2026-08-13 describe a pre-launch world.** The
    two CertiK dossiers, the migration spec, the tokenomics spec and the
    announcement all contain "the chain has not launched", "during the
    pause", "before an external audit", "not yet implemented". Some of those
    have been corrected in place; assume none of them is current until
    checked, and check against `crates/`, not against another document.

## 7. Work division — this wave

Seven workstreams; chapters are sized so no writer holds two chapters that
gate each other. Order of writing matters: Chapters 1 and 3 are written last,
against frozen content; Chapter 2 is already drafted (§4) and only tracks
late decision changes.

| Writer | Chapters | Note |
|---|---|---|
| **PMO** | 2 (drafted), plus: final consistency pass, status-label audit of every chapter, gatekeeping against §5–§6 | Owns the Ed.1→Ed.2 claim ledger; resolves source conflicts |
| **W1 — Cryptography** | 4, 5, 15 | Largest carry-over of Ed. 1 prose; least new invention. Must verify the §1.2 "fixed input" constraint still holds in code before asserting it |
| **W2 — Consensus** | 8, 9, 11 | The live-chain chapters; every "booted" claim paired with the operator/transport/audit caveats of §5.1; pulls measured attestation-footprint numbers, not design hopes |
| **W3 — History & transition** | 6, 7, 21 | Ch. 6 is the respectful burial of Ed. 1 ch. 5/6/7/15; Ch. 21 rebuilds the status table row by row against `crates/` |
| **W4 — Ledger & execution** | 13, 14 | ADR-040 chapters; status labels are the whole game here (designed, mostly). Carries the Solana premise correction |
| **W5 — Economics** | 16, 17 | The two hardest chapters. Ch. 17 publishes the unflattering arithmetic in full; PMO reviews against §6 traps 3–6 before anything else |
| **W6 — Governance & risk** | 18, 19, 20, 22 | ADR-036 chapters plus the rebuilt disclaimers; owns the securities-language rule (§5.4) across the whole manuscript |
| **PMO + W6 jointly** | 1, 3 | Written last, after chapter freeze |

Process gates, in order: (1) chapter drafts against this plan's briefs;
(2) PMO consistency pass (§6 traps, status labels, cross-references);
(3) W6 securities-language sweep over all chapters; (4) re-measure every
"measured" number if the chain has moved (the halt will likely have happened
mid-wave — Ch. 7 flips from future to past tense the day it does, and the
snapshot digest becomes citable); (5) founder gate; (6) only then, layout in
the Edition 2 brand (white ground, emerald `#0E6E5A`, Bloch-sphere mark,
`docs/site/BRAND-KIT.md` tokens — no webfonts, no external assets).

## 8. What this plan does not do

- It does not write any chapter except Chapter 2 (§4). All other chapters
  exist here as briefs with sources, not prose.
- It does not fix the stale-height and copy bugs listed in §6 in their
  source files; they are listed for writers, and fixing the sources is a
  separate, worthwhile task this plan does not claim.
- It does not decide open questions it found undecided in the sources:
  Foundation jurisdiction, board composition, who sells to funds, the
  external-audit contract status, the Genesis-4 launch date (deliberately
  unannounced), or the final L1-EVM design.
- It does not produce layout, the PDF, or any visual asset.
- It does not publish anything, anywhere.
