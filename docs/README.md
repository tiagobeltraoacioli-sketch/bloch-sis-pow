<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Documentation index

Four kinds of document live here, and mixing them up is how people end up
quoting a dead constant at an auditor:

1. **[Current — proof of stake](#1-current--proof-of-stake)** — the design
   Genesis-4 is being built to. Normative.
2. **[Decisions on record (ADRs)](#2-decisions-on-record-adrs)** — what was
   decided and when, *including the decisions that were later reversed*.
3. **[Audit and security](#3-audit-and-security)** — what has been reviewed,
   by whom, and what was found.
4. **[Legacy — the Genesis-3 record](#4-legacy--the-genesis-3-record)** —
   moved out of `docs/` entirely, to [`../legacy/`](../legacy/).

Two standing rules apply to everything below.

- **Never restate a constant.** Cite the path. Where a document and the code
  disagree, the code is the truth. `tools/doc-sweep/check_stale.py` exists
  because five tokenomics revisions left stale numbers in prose.
- **`designed ≠ built ≠ booted`.** Most of what is described here is
  designed. Very little of the proof-of-stake work is booted, and none of it
  on mainnet.

---

## 1. Current — proof of stake

### Start here

| Document | What it is |
| --- | --- |
| `THIRD-PARTY-QUICKSTART.md` | **For anyone outside Postern Labs running a node.** Exact commands from nothing to a synced, independently-validating observer: the published bootnodes, why the transport is `devnet` and not `libp2p`, the weak-subjectivity deadline of 2026-09-05 07:07 UTC, and what does not work yet. |
| `specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` | The master design: slots and epochs, retiring GhostDAG, `BlockHeaderV4`, state root, SHA-3 domain separation, RANDAO, staking lifecycle, gates, phases. |
| `specs/BLOCH-POS-GAPS.md` | The honest inventory: implemented / specified-but-not-implemented / neither, plus known defects. Read this before believing anything else is done. |
| `specs/BLOCH-POS-NODE-INTEGRATION.md` | Where the consensus loop lives, the crate/node boundary, and the build order. Also states that the Genesis-3 validation path is not touched. |
| `announcements/GENESIS3-HALT-AND-POS.md` | The public announcement of the halt and the PoS relaunch. Draft; not published. |

### Consensus and node

- `specs/BLOCH-POS-INTERFACES.md` — the frozen Phase-1 Rust traits and their
  open ambiguities.
- `specs/BLOCH-ATTESTATION-GOSSIP.md` — attestation propagation: topics,
  aggregation, slot and epoch timing.
- `specs/BLOCH-POS-NETWORK-CAPACITY.md` — the byte budget per block and per
  epoch burst, with load-test plan. Marks every figure `[measured]` or
  `[estimate]`.
- `specs/BLOCH-WEAK-SUBJECTIVITY.md` — checkpoint format, publication, sync
  rules. §7 prices the centralisation this costs. The problem it solves does
  not exist under proof of work.
- `specs/BLOCH-GENESIS-KEYS.md` — what key material must exist before the
  Genesis-4 ceremony, in what order, under what custody.
- `specs/BLOCH-FALCON-ONLINE-SIGNING.md` — whether a constant-time Falcon-1024
  signer exists for a machine that signs on a public schedule. An open
  blocker, not a solved problem.
- `specs/BLOCH-RPC-V4.md` — the Genesis-4 RPC surface: what dies with PoW,
  what changes meaning, what is new with staking.
- `specs/BLOCH-SATOSHI-ENCODING.md` — amounts as decimal strings on the wire.
  Normative for Genesis-4; supersedes `BLOCH-RPC-V4.md` §6 point 1.
- `specs/BLOCH-SHA3-MIGRATION-INVENTORY.md` — census of every SHA-2 use in
  the tree, labelled consensus / historical / non-consensus.

### Economics and governance

- `specs/BLOCH-TOKENOMICS-V4.md` — the PoS tokenomics. Authority is the code
  (`crates/bloch-pos-committee/src/tokenomics_v4.rs`), not this document.
- `specs/BLOCH-POS-STAKE-CHURN.md` — why the original warm-up rate was
  indefensible and what replaced it. Applied.
- `specs/BLOCH-L1-FEE-MARKET.md` — one market, one unit, one price across
  eUTXO, EVM and shielded classes. Wired into consensus 2026-08-12.
- `specs/BLOCH-ENTITY-STRUCTURE.md` — the two-entity foundation structure.

### EVM at L1 and Ustav at L1 — proposals, no code

Direction accepted (`adr/ADR-040-evm-and-ustav-at-l1.md`); **nothing is
implemented**, and the authorization model is an open founder decision.

- `specs/BLOCH-L1-EXECUTION-PLAN.md` — milestone sequencing for both tracks.
- `specs/BLOCH-L1-EVM-AUTHORIZATION.md` — the hard one: secp256k1 at L1, or
  PQ-only, or both. Each option priced. Nobody is authorised to pick silently.
- `specs/BLOCH-L1-EVM-STATE-MODEL.md` — how EVM account state coexists with
  the eUTXO base under one `state_root`. The state-root part is implemented.
- `specs/BLOCH-L1-EVM-RPC-SURFACE.md` — `eth_*` mapped onto a slot/epoch chain.
- `specs/BLOCH-L1-EVM-REUSE-AUDIT.md` — which execution code survives.
- `specs/BLOCH-L1-EVM-THREAT-MODEL.md` — attacks the *design premise*; there
  is no EVM code in the tree to attack.
- `specs/BLOCH-USTAV-L1.md` — promoting the PSTRN-1 token charter to a
  consensus object, and what that buys and costs.
- `specs/BLOCH-KIRPICH-UNDER-POS.md` — what "fail-closed" means when the
  closer is a validator set rather than a miner.

### Privacy — Coherence

- `specs/COHERENCE-v0.2.md` — the shielded-layer design and threat model.
- `specs/COHERENCE-C1.md` / `COHERENCE-C1.1.md` — the frozen formats, and the
  nullifier-set commitment amendment that proof of stake forced.
- `specs/COHERENCE-G11-SHADOW-FORKS.md` — the shadow-fork rehearsals for
  carrying the pool across the Genesis-3 → Genesis-4 seam.
- `specs/BLOCH-COHERENCE-UNDER-POS.md` — code audit F1–F13 plus the PoS
  integration plan. Records that the mainnet pool is provably empty.
- `specs/PQ-SHIELD-NONCUSTODIAL-NATIVE.md` — a vault for coins on chains with
  no PQ signature scheme. Design only: not built, not wired, not booted.

### Operations, migration and platform

- `THIRD-PARTY-QUICKSTART.md` — running your own node as an outsider; see
  "Start here" above.
- `../deploy/bootnodes/` — the published public entry list and
  `verify-bootnodes.sh`, which re-proves reachability, keylessness and
  transport. Run it after any fleet move: on the devnet transport a rotted
  peer list never raises an error, it just silently stops working.
- `CARRYOVER.md` — the carryover UTXO file. **Genesis-4 consumes this.**
- `SNAPSHOT-BOOTSTRAP.md` — bootstrapping from a datadir snapshot.
  **Genesis-4 launches from one.** Every concrete number in it is
  Genesis-3-specific; the mechanism is what carries forward.
- `specs/BLOCH-ECOSYSTEM-MIGRATION.md` — repointing RPC, explorer, wallets,
  SDKs off Genesis-3. Its §5 (L2 re-anchoring) is superseded by EVM-at-L1.
- `specs/BLOCH-SIS-ATTESTATION.md`, `specs/BLOCH-SIS-LINUX.md` — TEE
  attestation and the hardened node image. Consensus-independent.
- `API.md`, `openapi.yaml` — the Genesis-3 JSON-RPC surface. Its
  "Genesis-3 traps" section (DAG height, `getblocktemplate`) dies with PoW;
  the transport, auth and error conventions do not.
- `releases/RELEASE_PROCESS.md` — how a release is cut.
- `site/COPY.md`, `site/SITE-PLAN.md`, `site/BRAND-KIT.md` — the public site,
  written as the migration site.
- `whitepaper/EDITION-2-PLAN.md` and `whitepaper/ED2-*.md` — Institutional
  Dossier Edition 2. Edition 2 is proof-of-stake; it retires the PoW edition.

### Status and framing — read the seals

These carry supersession headers. They are kept because they are still the
best inventories in the repository, not because every line is current.

- `PROJECT-STATUS.md` — the fullest inventory of what exists. Its Genesis-3
  live-network block is dated.
- `EVOLUTION.md` — product strategy and the verified/skeleton/gated table.
  Its PoW hardness critical path is cancelled.
- `ROADMAP-GATED-ITEMS.md` — items blocked on external gates. The k=8 PoW
  reactivation and the hashrate-weighted FFG overlay lost their object.
- `PUBLIC-RELEASE-AUDIT.md` — secret scan and publication readiness,
  measured 2026-08-12. Current.
- `ENSAIO_2_PRE_COMMITMENT_DOCTRINE.md`,
  `papers/Acioli_2026_The_Cryptographic_Constitution.md` — the
  pre-commitment doctrine. Consensus-mechanism-agnostic, so nothing in them
  dies at the terminal height; but their ownerless thesis was retracted by
  ADR-036, and they are not current governance doctrine.
- `FLEET-BRIEF-2026-08-11.md`, `FLEET-BRIEF-CERTIK-2026-08-12.md` — the
  working briefs. Settled facts, not up for re-litigation.

---

## 2. Decisions on record (ADRs)

`adr/` holds every architecture decision record, **including the reversed
ones**. Nothing was moved to `legacy/`: the series is cross-referenced by
number, and an ADR that turned out wrong is evidence of when it became wrong.
There is no ADR index elsewhere and the numbering already has holes
(ADR-001, 008, 009, 012–017, 029 are cited but do not exist as files).

**There is no ADR recording the proof-of-work → proof-of-stake switch itself,
nor the Genesis-3 halt.** That is a gap. The decision lives in
`announcements/GENESIS3-HALT-AND-POS.md` and
`specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` instead.

### Binding

| ADR | Decision |
| --- | --- |
| ADR-019 | Fork governance policy — when an upstream crate may be forked, tagged, maintained, sunset. |
| ADR-036 | **Retracts the ownerless thesis**; adopts the two-entity foundation. Retracts ADR-033 and ADR-034. |
| ADR-037 | A carried-over balance that is liquid is also stakeable. |
| ADR-038 | Warm-up churn rate and the per-epoch churn floor. Applied. |
| ADR-039 | AGPL-3.0-or-later for the PoS crates; `bloch-sis-pow` stays permissive *because* it dies with the halt. |
| ADR-040 | EVM at L1 (no rollup) and Ustav promoted to a consensus object. Direction only; the authorization gate is open. |

### Retracted or superseded

| ADR | Status |
| --- | --- |
| ADR-002 | Superseded by rev1 → rev2. The file itself still says "Accepted" — stale. |
| ADR-002-rev1 | Superseded by rev2 (marked). |
| ADR-010, ADR-010-A, ADR-010-Addendum-1 | The founding emission curve, premine and 70/25/5 split. Superseded by V2 → V3 → V4. |
| ADR-023 | The "no issuer, foundation after mainnet" model. Contradicted by ADR-036, which does not name it — a gap. |
| ADR-027 | Founder commitment instrument. Amended by ADR-034, which ADR-036 then retracted. Net status genuinely unresolved. |
| ADR-028 | Tokenomics V2 activation. Superseded by ADR-035; its own header still says "Superseded by: None" — stale. |
| ADR-033 | Compliance-first decentralisation model. **Retracted by ADR-036.** |
| ADR-034 | Founder anonymisation and relinquishment pact. **Retracted by ADR-036.** |

### Proof-of-work-only — dead, kept as record

The decision had meaning only while there was mining or a hashrate-elected
committee. None of these can be executed now.

| ADR | Why it is dead |
| --- | --- |
| ADR-003 | Minimum committee policy — the input is a hashrate snapshot. |
| ADR-005 | Committee era rotation — seats are hashrate-weighted. |
| ADR-006 | PoW block time (the dual-finality half may be re-derived). |
| ADR-007 | Bonding and slashing keyed to FFG activation at height 210,000, on a chain that stops at 50,000. |
| ADR-011 | FFG activation at block 210,000 — never reached. |
| ADR-030 | Bridge from the DKG ceremony into the hashrate-elected registry. |
| ADR-031 | Sprint 2.1.D deferrals, scoped to `src/bonding/`. |
| ADR-035 | Emission V3 — a mining subsidy curve that was live for about 10,000 blocks. |

### Unresolved — need a ruling

ADR-002-rev2, ADR-004, ADR-018, ADR-020, ADR-021, ADR-022, ADR-024, ADR-025,
ADR-026, ADR-032. Each records something whose *principle* may survive under
proof of stake while its *object* (BLS, the FFG committee, `src/bonding/`,
hashrate-based metrics) does not. None has been formally re-ratified or
retracted.

`gips/GIP-0001.md` (repository root) also needs amendment before any
proof-of-stake GIP can activate: its activation clause is BIP-9-style
hashrate signalling, which no longer exists.

---

## 3. Audit and security

### Current — the pre-audit wave (2026-08-12)

- `audit/CERTIK-PRE-AUDIT-DOSSIER.md` — what an auditor asks, answered before
  they ask, with file:line evidence. Self-found findings and open gaps listed
  as gaps.
- `audit/CERTIK-CENTRALIZATION.md` — the concentration answer, unsoftened,
  plus what each bounding mechanism does and does not reach.
- `audit/CERTIK-MARKET-TRANSPARENCY.md` — market, transparency and general
  checks, including the open-source check, which currently fails because the
  repository is private.

### Threat models

- `specs/BLOCH-POS-THREAT-MODEL.md`, `specs/BLOCH-POS-THREAT-MODEL-2.md` —
  the two proof-of-stake adversarial passes. **These are the current ones.**
- `specs/BLOCH-POS-SORTITION-DOS.md` — the public proposer schedule as a DoS
  surface under partition.
- `specs/BLOCH-L1-EVM-THREAT-MODEL.md` — the EVM-at-L1 design premise.
- `THREAT_MODEL.md` (underscore) — STRIDE per subsystem, 2026-04-19. Its
  network, RPC, storage, wallet and quantum-adversary sections are alive; its
  consensus and mining sections are not. Cited by current work.
- `THREAT-MODEL.md` (hyphen) — the short security/privacy matrix. Its privacy
  half is the best privacy statement in the repository; its PoW-forgery and
  GhostDAG rows are dead.
- `THREAT-MODEL-AUDIT.md` — audit-scoping companion to `SPEC.md`.

> **Naming hazard.** `THREAT-MODEL.md`, `THREAT_MODEL.md` and
> `THREAT-MODEL-AUDIT.md` are three different documents whose names differ by
> one character, and `specs/BLOCH-POS-THREAT-MODEL.md` is a fourth. "See the
> threat model" is ambiguous in this repository. Cite the full path.

### Prior audits and incidents — historical, still cited

- `audit/AUDIT-2026-04-20_ERA1.md`, `audit/groundstate_audit.md` — the two
  Era-1 (pre-rebrand, GroundState) audits. Sealed as historical, and cited by
  the current CertiK dossier as the prior-audit evidence.
- `post-mortems/2026-04-21-ibd-reorg.md` — the IBD reorg incident. Its design
  invariants carry forward.
- `SECURITY_SELF_ASSESSMENT.md` — Bloch versus Bitcoin Core across 13
  dimensions, 2026-04-19. Its cryptography, memory-safety and wallet sections
  hold; its spine ("cost of a 51% attack: dollars") is a hashrate statement
  about a chain that is ending.
- `SPEC.md` — the frozen-for-audit Genesis-3 protocol specification. §1, §2,
  §4 and §10 (signature construction, addresses, transaction wire format,
  crypto-agility) are reused by Genesis-4; §3, §5, §7 and §8 (proof of work,
  block header, fork choice, hard-fork map) are not.
- `releases/` — release notes. All nine are proof-of-work builds; the Era-1
  six carry their own seals. Kept here because a reader looking for release
  notes looks under `releases/`.
- `WALLET_COMPATIBILITY_ERA1.md` — Era-1 wallet compatibility. Its ML-DSA
  seed-derivation limitation is a property of the signature scheme, so it is
  still true.
- `research/MOFN-CUSTODY-DECISION.md` — why no PQ threshold signing is
  shippable in 2026. The cryptographic argument is alive; its mining-pool
  Phase 0 is not.

---

## 4. Legacy — the Genesis-3 record

Moved out of `docs/` to [`../legacy/`](../legacy/). Read
[`../legacy/README.md`](../legacy/README.md) first — it says what in that
folder is still true and what is not.

In short: mining, GhostDAG, AuxPoW and merged mining, Stratum V1 and V2,
difficulty and retargeting, tokenomics V1/V2/V3, the PoW hardness research,
the developer portal written for the PoW chain, and the plans that die with
proof of work.

Paths mirror where each document used to live, so a pre-move reference of the
form `docs/X` reads as `legacy/X` now.

> Doc comments in `src/`, `crates/`, `deploy/` and `apps/` still cite the old
> `docs/…` paths. Those trees were deliberately not edited — the Genesis-3
> binary running on mainnet was built from them. Read `docs/…` in a code
> comment as `legacy/…` where the file is not in `docs/` any more.
