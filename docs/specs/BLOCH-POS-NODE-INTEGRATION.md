<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch PoS — Node Integration Plan (Genesis-4 binary)

```
Document:   BLOCH-POS-NODE-INTEGRATION
Status:     DRAFT — plan for review; the skeleton it describes is in-tree
Created:    2026-08-11
Owner:      PMO
Code:       crates/bloch-pos-node/  (binary: bloch-pos)
Normative:  BLOCH-POS-SHA3-LATTICE-MIGRATION.md, BLOCH-TOKENOMICS-V4.md
Relates:    BLOCH-POS-INTERFACES.md (frozen traits),
            BLOCH-WEAK-SUBJECTIVITY.md, BLOCH-ATTESTATION-GOSSIP.md
            (both partially superseded — read their seals first)
```

This document answers four questions: **where** the PoS consensus loop lives,
**how** its state is persisted, **where** the boundary sits between the pure
consensus crate and the node that does I/O, and **in what order** DEV-1/2/3
can build it without colliding. It turns the standalone
`crates/bloch-pos-committee` — today a library nothing composes — into a
running Genesis-4 node, without touching the chain that is about to halt.

---

## 0. The hard rule, restated as architecture

**The Genesis-3 validation path does not change.** The chain the repo-root
`src/main.rs` validates halts at height 80,000 (`BLOCH-TOKENOMICS-V4.md`
§3.2); its one remaining consensus job is to stop correctly. Genesis-4 is a
**new binary built from a fresh genesis**, not a patch, not a feature flag,
not a flag-day inside the old process. Any plan step that would require
editing the Genesis-3 acceptance path is, by that fact alone, wrong.

The rule is made structural rather than disciplinary, three ways:

1. **Separate binary.** `bloch-pos` (crate `bloch-pos-node`) is a new
   `[[bin]]`, so the Genesis-3 executable cannot gain PoS behaviour by
   accident, and the fleet's halt release contains zero PoS code.
2. **Separate build graph.** `crates/bloch-pos-node` carries its own
   `[workspace]`, exactly like `bloch-pos-committee` and `coherence-prover`.
   It is not a member of the node workspace, does not appear in the root
   `Cargo.lock`, and the root package never depends on it. Dependency flow is
   one-way and by path: `bloch-pos-node → bloch-pos-committee` (and later
   `→ bloch-crypto` for the hybrid verifier). Nothing flows back.
3. **Separate database.** The Genesis-4 node opens its own RocksDB in its own
   default data dir and **refuses** to open a Genesis-3 database (§3.4). The
   two chains share no storage, so no schema change here can corrupt the
   chain that must halt cleanly.

What Genesis-3 *does* need before height 80,000 — the terminal-height
consensus rule and the signed snapshot artifact (§3.2.1–3.2.2 of the
tokenomics doc) — is a **separate, minimal work item on the old tree**, owned
outside this plan precisely so this plan never has a reason to touch that
tree. This document assumes the snapshot artifact and its published digest as
an input.

### 0.1 Why not the two rejected alternatives

- **Feature flag in `bloch` (`--features pos`).** Puts PoS code inside the
  binary whose job is to stop; every PoS merge becomes a potential
  regression on the halt path; cfg-gated consensus is exactly how a
  "published binary ≠ fleet binary" incident happens again. Rejected.
- **Same binary, height-gated activation (the old §8 hybrid design).** The
  superseded seal on migration §8 already retired it: there is no hybrid
  period, no DAG→linear seam, no upgrade partition. The old chain is ended,
  not continued. Rejected by the founder decision of 2026-08-10.

Cost of the new-binary route, stated honestly: nothing in `src/`
(network, sync, RPC plumbing) is directly reusable by linkage, because the
root package is one crate and depending on it would drag the whole Genesis-3
node into the build graph. Reuse happens by **copy-and-adapt** of specific
files (gossipsub config with the two 2026-08-07 mesh fixes, yamux limits,
RPC scaffolding), which is also an opportunity: the copies start life without
the DAG machinery. Anything worth sharing properly gets extracted into a leaf
crate later, not reached into.

---

## 1. Where the consensus loop lives

### 1.1 The process

One process, `bloch-pos`, with a single consensus task (the **engine**)
owning all consensus state, and I/O subsystems around it. The engine is
driven by exactly two kinds of events, and nothing else mutates consensus
state:

```
                    ┌───────────────────────────────────────────┐
                    │              bloch-pos process            │
                    │                                           │
   slot timer ──────►  ENGINE (single task, owns the store)     │
                    │   ├─ on_slot(slot)                        │
   net/rpc in ──────►   ├─ on_block(envelope)                   │
                    │   ├─ on_attestation(att)                  │
                    │   └─ on_evidence / on_deposit / on_exit   │
                    │        │ calls into pure rules            │
                    │        ▼                                  │
                    │   bloch-pos-committee (frozen traits)     │
                    │        │ reads parent-committed state via │
                    │        ▼   StateReader                    │
                    │   store (RocksDB, §3)                     │
                    └───────────────────────────────────────────┘
```

- `on_slot(s)`: compute the schedule from the parent-committed state
  (`schedule::epoch_schedule` / `proposer`); if we are the proposer, build a
  block (mempool → body, reveal next RANDAO preimage, sign via the keystore)
  and publish; if we are in slot `s`'s committee (partition,
  `committees::committee_for_slot`), attest to the fork-choice head.
- `on_block`: validate via `ProposerDuties::validate_proposal` +
  `StateTransition::apply_block` against the **parent's** committed state,
  persist the post-state, feed the fork-choice `Store`, re-evaluate head.
- `on_attestation`: validate (`attestation::validate` ordering — cheap checks
  before the 4.6 KB hybrid verify), feed `forkchoice::Store::observe`; at
  epoch boundaries tally target votes and run
  `FinalityGadget::process_epoch_votes` inside `process_epoch`.

The single-task engine is a deliberate echo of §5.5: with one writer there is
no locking discipline to get wrong, and "consensus state" has exactly one
owner. Networking, RPC and the prover client run as separate tasks and talk
to the engine over channels; they never hold a reference into consensus
state.

The wall clock enters the engine in **exactly one place** — the slot timer
(`slot = (now - genesis_time) / SLOT_DURATION_SECS`, with the ±30 s skew
tolerance the chaos plan tests). No rule below the timer ever sees a clock;
that is the purity contract of the frozen interfaces, kept at the composition
level.

### 1.2 The module tree (ownership map)

```
crates/bloch-pos-node/src/
  main.rs            composition root — PMO change-controlled (like interfaces.rs)
  engine/            DEV-1  slot loop, fork-choice driver, block production
  rules/             pure trait implementations — NO I/O imports allowed here
    transition.rs    DEV-1  StateTransition + the concrete State object
    duties.rs        DEV-1  ProposerDuties
    finality.rs      DEV-1  FinalityGadget (wraps committees::is_supermajority)
    commitment.rs    DEV-2  StateCommitment + canonical serialization (KAT-pinned)
    beacon.rs        DEV-2  RandomnessBeacon (wraps beacon::RevealState/mix_in)
    staking.rs       DEV-3  StakingLifecycle
    slashing.rs      DEV-3  SlashingRules
  keys/              DEV-2  keystore, KeyVerifier adapter over bloch-crypto,
                            online Falcon signing path (§6.2 caveat), RANDAO
                            chain secret management
  store/             DEV-3  RocksDB layer (§3), StateReader implementation
  genesis/           DEV-3  genesis-file loader: snapshot digest, allocations,
                            vesting outputs, genesis cohort, validator set
  net/               DEV-3  libp2p: gossip topics, sync, checkpoint sync
  rpc/               DEV-3  JSON-RPC surface
  mempool/           DEV-3  txs + deposits/exits/evidence + attestation pool
```

`rules/` is the bridge zone: it lives in the node crate (so it can name the
node's transaction type and use `bloch-crypto`-adjacent types) but is held to
the same purity bar as the pure crate — **no rocksdb, no tokio, no clock, no
network import compiles in `rules/`**, enforced by review checklist and a CI
grep. If `rules/` grows painful to police, the escape hatch is extracting it
into a third standalone crate (`bloch-pos-rules`); that is a mechanical move
and needs no interface change, so we do not pay for it up front.

---

## 2. The boundary between the pure crate and the node

`bloch-pos-committee` stays exactly what it is: pure functions and frozen
traits, own workspace, `sha3` as its only dependency, no PQ linkage, no I/O.
**Nothing in this plan adds a dependency to it.** The node consumes it; the
seven trait boundaries and three capability traits of
`BLOCH-POS-INTERFACES.md` are the entire contract surface.

Who implements what, on the node side:

| Frozen trait | Impl lives in | Owner | Backed by |
|---|---|---|---|
| `StateReader` | `store/` | DEV-3 | block-id-keyed committed state (§3.2) |
| `StateCommitment` | `rules/commitment.rs` | DEV-2 | `state_root::Smt`, canonical serialization |
| `StateTransition` | `rules/transition.rs` | DEV-1 | everything above |
| `ProposerDuties` | `rules/duties.rs` | DEV-1 | `schedule::proposer`, `genesis_cohort::apply_cohort_cap` |
| `RandomnessBeacon` | `rules/beacon.rs` | DEV-2 | `beacon::*` |
| `FinalityGadget` | `rules/finality.rs` | DEV-1 | `committees::is_supermajority`, `finality::*` |
| `StakingLifecycle` | `rules/staking.rs` | DEV-3 | `staking::*`, `delegation::Registry::cap_sat` |
| `SlashingRules` | `rules/slashing.rs` | DEV-3 | `slashing::*` |
| `KeyVerifier` | `keys/` | DEV-2 | `bloch-crypto` hybrid verify (both halves, AND) |
| `StakeEligibility` | `store/` | DEV-3 | trivial at a fresh genesis — see §7.1 |

Three composition rules, all downstream of the 2026-08-08 consensus split:

1. **Every consensus read goes through a `StateReader` obtained from the
   parent block's committed state.** The engine constructs the reader from
   the parent's `block_id`; there is no "current state" object handed to
   validation. (§5.5 of the migration design, expressed as plumbing.)
2. **The genesis-cohort cap is applied inside the state pipeline, not ad
   hoc**: `active_validators()` returns the set with
   `apply_cohort_cap(…, epoch)` and the 1% delegation cap already applied, so
   schedule, committees and finality all see one consistent effective-stake
   view.
3. **Effective-stake truncation to `u64` happens in exactly one place** (the
   `Validator` view construction in `store/`), because `sample::Validator`
   carries `u64` effective stake while the ledger is `u128`. One clamp
   function, one KAT.

---

## 3. Persistence

### 3.1 One database, fresh

RocksDB with column families, same operational shape as the Genesis-3 node
(the fleet knows how to run, back up and snapshot it) but a **new database in
a new default data dir** (`~/.bloch-pos/genesis4`, overridable with
`--data-dir`). Schema identity is pinned in `meta` (`schema_version`,
`network_version = 0xB10C_0005`, the genesis snapshot digest); opening a
directory whose `meta` disagrees — including any Genesis-3 dir, which has no
such marker — is a refusal, not a migration.

### 3.2 The storage rule that is actually consensus-critical

The 2026-08-08 failure was storage-shaped: `CF_TIMESTAMPS` keyed by height in
a DAG, plus a mutable `current_bits`, made validation order-dependent. The
schema below encodes the lesson as two rules:

- **Consensus state is keyed by `block_id`, never by slot and never
  "current".** Any block's post-state must be reachable from its id alone,
  so validating against `B.parent` reads the same bytes on every node
  regardless of arrival order.
- **Slot-keyed rows exist only at or below the finalized checkpoint**, where
  the chain is fork-free by definition. Above finality there is no slot
  index; the fork-choice store answers "what is at slot s".

### 3.3 Column families

| CF | Key | Value | Class |
|---|---|---|---|
| `meta` | ascii string | schema version, network version, genesis digest, weak-subjectivity checkpoint consumed at boot | node |
| `headers` | block_id 32B | `BlockHeaderV4`, canonical 248 B | consensus |
| `bodies` | block_id 32B | proposer_sig + transactions + attestation quorum | consensus |
| `state_roots` | block_id 32B | `StateRoots` (7×32 B + the 80 B `EvmCommitment`, per `BLOCH-L1-EVM-STATE-MODEL.md` §2) + `FinalityState` at that block | consensus |
| `state_nodes` | node hash 32B | SMT node, content-addressed — structural sharing means a block's state costs only its delta | consensus |
| `registry` | epoch 8B BE | `Vec<ValidatorRecord>` at the epoch boundary (the registry only changes in `process_epoch`; intra-epoch reads resolve to the boundary snapshot) | consensus |
| `participation` | epoch 8B BE ‖ validator 4B BE | `ParticipationRecord` (current + previous epoch are committed state; older is archival) | consensus |
| `randao` | epoch 8B BE | boundary mix (committed window: last 2 epochs; older kept for RPC/archival) | consensus |
| `utxo` | outpoint 36B | `EutxoEntry` — materialized view at the current head | cache* |
| `undo` | block_id 32B | per-block undo data (same pattern as Genesis-3 `CF_UNDO`) for reorgs above finality | cache* |
| `final_index` | slot 8B BE | block_id — **written only when the block is ≤ finalized**; append-only | index |
| `latest_msgs` | validator 4B BE | LMD `LatestMessage` — persists the fork-choice store across restarts; rebuildable from `bodies`, so losing it is a slow start, not a fork | cache |
| `slashed` | validator 4B BE | offence record — evidence idempotence (`AlreadySlashed`) survives restart | consensus |
| `nullifiers` | nullifier 32B | ∅ — monotone forever (§6.6.1) | consensus |
| `coherence_meta` | ascii string | accumulator state (frozen C1 format, carried never recomputed) | consensus |

\* `utxo`/`undo` are "cache" in the sense that the committed truth is the SMT
under `state_roots`/`state_nodes`; the flat view exists so transaction
validation and RPC don't walk the tree. It must be rebuildable from the SMT,
and A2 gets a property test that the flat view and the committed
`utxo_root` never disagree.

**What is deliberately NOT in the database:** validator key material and the
RANDAO chain seed. A copied data dir must never leak future reveals (a leaked
chain hands out bias one bit per slot) or the bonded signing key. Keys live
in the keystore (`keys/`), same custody posture as the pool wallet.

**Pruning** follows §6.5.1: once an epoch is finalized, its attestation
signatures in `bodies` are prunable (archival nodes keep them). The schema
supports it because attestations hash under their own `attestation_root`,
separate from the tx tree. Pruning is a Phase-later feature; the schema just
must not preclude it, and this one doesn't.

### 3.4 Genesis input

The `genesis/` loader consumes one file (the "genesis manifest"), reviewed
and published ahead of launch:

- the **signed snapshot artifact digest** (the height-80,000 balance set —
  the artifact is canonical, not the halted chain; the digest is embedded in
  the genesis block per tokenomics §3.2.2),
- the carryover balance set itself (as `carryover.tsv`-style data, verified
  against the digest at load),
- the six allocation outputs with consensus-enforced vesting locks
  (tokenomics §8.2 — a schedule in a spreadsheet is not a schedule),
- the genesis validator set + the **genesis cohort** list
  (`genesis_cohort.rs` caps its combined weight, 100% → 33.3% over year one),
- `genesis_time` (slot-0 timestamp) and network version.

Block 0 is synthesized from the manifest; its `state_root` is computed by
`rules/commitment.rs` over the loaded state and pinned by an A1 KAT, so two
independently built nodes agree on genesis byte-for-byte before the first
slot ever ticks.

---

## 4. Networking and sync (DEV-3, summary)

Not this document's spec (see `BLOCH-ATTESTATION-GOSSIP.md`, respecting its
superseded seal: the committee is now a partition, and there is no hybrid
phase, so the "non-binding rehearsal on mainnet" sections do not apply). The
plan-level facts:

- **Copy-and-adapt the Genesis-3 libp2p layer**, keeping the two hard-won
  2026-08-07 fixes (no `add_explicit_peer` on every connection; explicit
  `TopicScoreParams` instead of `..Default::default()` inheriting a
  P3 penalty impossible under slow blocks) and the yamux stream-limit
  alignment. New network ID / protocol prefix so Genesis-3 and Genesis-4
  peers never mesh.
- Topics: blocks, attestations (per-slot-committee subnets can come later;
  at G4-scale validator counts a single attestation topic carries ~54 KB per
  slot, which is fine), deposits/exits/evidence travel as ordinary txs.
- **Sync = weak subjectivity, not genesis replay** for late joiners: consume
  a Foundation-published checkpoint (`BLOCH-WEAK-SUBJECTIVITY.md`) recorded
  in `meta`, fetch state at the checkpoint, then blocks forward. Fresh-fleet
  launch nodes sync from block 0 normally.

---

## 5. What the node does NOT contain (scope fences)

- **No prover in-process.** Epoch aggregation is an optional optimisation
  (§6.5.1 seal: measurement removed the dependency). The consensus path
  keeps raw signatures and degrades to "don't prune" when the prover service
  is unreachable. A prover *client* may arrive post-launch.
- **No AuxPoW, no stratum, no DAG code.** Nothing from the mining stack
  crosses. `reachability.rs`/GhostDAG do not exist here — with a fresh
  genesis there is no pre-transition DAG to serve; the halted Genesis-3
  history is served by the archived Genesis-3 node, not by `bloch-pos`.
- **No shield bridge.** A9's finding stands: value cannot enter or leave the
  Coherence pool today. The node carries the accumulator/nullifier roots in
  committed state from day one (so finality covers the pool the moment a
  bridge exists) but ships no bridge.
- **No L2 anchor changes** beyond exposing finalized checkpoints over RPC;
  the L2 re-points to it on its own schedule (ecosystem doc).

---

## 6. Work plan — DEV-1/2/3 without collisions

The collision-avoidance mechanism is the one §9.2 already bought: the traits
are frozen, so each DEV codes against the others' *interfaces*, not their
branches. This plan adds directory ownership (§1.2) and two change-controlled
files (`main.rs`, `interfaces.rs` — §9.4 two-reviewer rule) on top.

**Rules of engagement**

- A DEV writes only inside their directories; a needed change elsewhere is a
  PR into the owner's directory, reviewed by the owner.
- Shared vocabulary comes only from `bloch-pos-committee`. No DEV defines a
  type another DEV must import from `bloch-pos-node` internals.
- Every consensus constant or byte layout lands with a KAT (A1) in
  `tests/kats/` — the vector file is the tiebreaker when two impls disagree.
- `rules/` purity check (no I/O imports) is a merge blocker, per A4's
  standing checklist.

### M1 — foundations (parallel, zero file overlap)

| Who | Deliverable | Depends on |
|---|---|---|
| DEV-2 | `rules/commitment.rs`: canonical header/body serialization, `block_id`, `body_root`, `attestation_root`, `state_root` over `StateRoots`; the KAT vector file for all four | nothing — **this is the critical path**: every id every other module stores or gossips is these bytes |
| DEV-3 | `store/`: DB open/refuse logic, CF schema, `StateReader` impl over fixture states; `genesis/` manifest format + loader | interface types only |
| DEV-1 | `rules/transition.rs` + the concrete `State` object, developed against a **stub** `StateCommitment` (any injective placeholder) — the trait makes swapping in DEV-2's real impl a one-line change in composition | interface types only |

*Exit:* KATs green for commitment; genesis manifest loads and produces a
pinned genesis `state_root` (swapping DEV-1's stub for DEV-2's impl);
`apply_block`/`process_epoch` green on A2/A3 harness fixtures.

### M2 — the moving parts (each DEV still in own directories)

| Who | Deliverable |
|---|---|
| DEV-1 | `engine/`: slot timer, fork-choice driver over `forkchoice::Store` + `latest_msgs` persistence, block production path; `rules/duties.rs`, `rules/finality.rs` |
| DEV-2 | `keys/`: keystore, `KeyVerifier` over bloch-crypto (AND of both halves), online Falcon signing path (A4 review is the gate — §6.2 caveat), RANDAO chain custody; `rules/beacon.rs` |
| DEV-3 | `rules/staking.rs`, `rules/slashing.rs`, `mempool/`, `net/` (adapted gossip + new network ID), checkpoint sync; `rpc/` skeleton |

*Exit:* single-node devnet self-produces and self-finalizes from a test
manifest (one node = whole cohort); slashing evidence round-trips; A4 pass
on the Falcon online path.

### M3 — composition (one integration point, serialized on purpose)

`main.rs` grows its real wiring in **one PR** authored by DEV-1, reviewed by
DEV-2, DEV-3 *and* A4 — the only moment all three streams meet in a file,
which is why the file is change-controlled and the meeting is scheduled
rather than accidental. Then A3's multi-node devnet, chaos scenarios
(§12 of the migration doc), G10 capacity measurement at the partition's real
per-slot byte cost, and the Phase-3 exit criteria (7-day finalizing devnet
with induced partitions).

Dependency additions follow the milestones: M1 adds `rocksdb` +
serialization; M2 adds `bloch-crypto` (path) and `libp2p`/`tokio`; nothing
lands earlier than the milestone that needs it.

---

## 7. Decisions taken by this plan

1. **New standalone binary crate `crates/bloch-pos-node`, bin `bloch-pos`**,
   own workspace, never a member or dependency of the Genesis-3 workspace
   (§0). Genesis-3 reuse is copy-and-adapt, not linkage.
2. **Single-task engine** owns consensus state; clock enters at the slot
   timer only (§1.1).
3. **Fresh RocksDB, block-id-keyed consensus state, slot-keyed rows only
   below finality**, keys and RANDAO seeds outside the DB (§3).
4. **`rules/` purity zone** inside the node crate rather than a third crate,
   with extraction as a later mechanical option (§1.2).
5. **Emission binding:** composition binds
   `tokenomics_v4::validator_reward_decay_sat` — the 10%/year disinflation
   the normative tokenomics doc records as adopted (§6.1). The other two
   curves remain in the pure crate as the record of the analysis; the node
   names exactly one. (Resolves interface-doc open point 4.3 in the only
   direction the normative doc allows; PMO to record.)
6. **Genesis Coherence state is empty** (fresh accumulator, empty nullifier
   set): the shield bridge has never existed, so no value and no notes are in
   the pool at the halt — an empty start de-anonymises no one. Confirmation
   requested below (§8.2) because the claim rests on A9's audit, not on a
   scan of the halted chain.
7. **Epoch attestations feed LMD-GHOST — ruled YES** (PMO, 2026-08-11).
   Under the partition this was never really open: there is no separate slot
   subcommittee any more, so a "no" would leave fork choice weightless.
   `committees.rs` already states the design — committee *i* serves slot
   *i*; its members carry that slot's fork-choice weight **and** their votes
   accumulate toward the epoch's justification. One attestation does both
   jobs. Interface-doc open point 4.7 is closed; where the frozen prose in
   `interfaces.rs` suggested otherwise, the prose was stale, not the design
   (sealed — see decision 10).
8. **`StateRoots.taint_root` stays, zeroed and reserved — ruled** (PMO,
   2026-08-11). The frozen interface is NOT amended: removing a 32-byte slot
   would cost a re-freeze round over three DEVs already coding against the
   struct. DEV-2 freezes the `state_root` KAT with the field all-zeros and a
   comment in `rules/commitment.rs` saying why the slot exists and why it is
   empty (taint dissolved with the single-set carryover decision). This
   unblocks M1's KAT freeze.
9. **Deposit eligibility is parameterized, not constant** (PMO, 2026-08-11).
   Whether carried-over balances may stake (§8.1) is a founder decision that
   has not arrived; the code must be shaped so the ruling lands without
   rewriting the deposit path. The `StakeEligibility` implementation takes
   its policy — including the carryover treatment — as an explicit input
   from the genesis manifest / node configuration, threaded as an argument.
   No eligibility rule is compiled in as a constant.
10. **Stale-prose seals applied** (PMO ruling, 2026-08-11): `interfaces.rs`
    and `lib.rs` now open with a PARTIALLY-SUPERSEDED seal in the same
    format the spec documents use — listing *which* premises changed
    (sampled committee → partition; 100 B → 21 B; taint dissolved,
    `taint_root` reserved; hybrid phase erased) — with signatures and APIs
    explicitly unaffected. `BLOCH-POS-INTERFACES.md` already carried its
    seal. The remaining ecosystem-wide sweep stays with A5.

### 7.1 `StakeEligibility` at a fresh genesis

With taint dissolved, the oracle's day-one implementation is small: inputs
are `Eligible` if they exist transparently in the parent-committed UTXO set
and are not vesting-locked allocation outputs, `Shielded` is unreachable
until a bridge exists, `Unknown` fails closed. The `Tainted` variant is never
produced (kept in the enum — removing it is a frozen-interface change that
buys nothing). Whether *carryover* balances may stake at all is **not**
decided here — §8.1 — and per decision 9 the implementation receives that
policy as an argument (a carryover-eligibility flag/set in the genesis
manifest), so the founder's ruling changes a manifest field, not the deposit
path.

---

## 8. Ambiguities needing a ruling (blocking noted per item)

Items resolved by the 2026-08-11 PMO rulings moved to §7 (decisions 7–10):
epoch attestations feed LMD-GHOST (yes), `taint_root` reserved-zero with the
KAT frozen over it, and the stale-prose seals. What remains open:

1. **Is the carryover stakeable?** Both normative docs leave it open
   (migration §4.2, tokenomics §4A): liquid ≠ stakeable, and the answer
   decides whether gates G1–G4 are reachable before ~year five. **Founder
   decision**, explicitly not the PMO's or this plan's. Per decision 9 the
   code no longer blocks on it — eligibility policy arrives as a genesis-
   manifest input — so what it gates is the *launch manifest*, not a DEV
   milestone.
2. **Genesis Coherence state empty** (decision 6) — needs A9/founder
   confirmation that no shielded value can exist at the halt.
3. **Transaction format.** `StateTransition::Transaction` must bind to a
   concrete eUTXO tx type. Reusing `bloch-crypto`'s existing tx format
   (plus the two new tx types) is the obvious route and keeps wallets/SDKs
   mostly intact, but pulls `bloch-crypto` into M1 instead of M2 — and with
   it the license blocker below. Needs a DEV-1/DEV-3 joint decision at M1
   start. **Blocks `apply_block` beyond fixtures.**
4. **License — RESOLVED 2026-08-11, no longer a blocker.**
   `bloch-crypto` is AGPL-3.0-or-later and AGPL is viral, so the moment
   `bloch-pos` links it for PQ signatures the whole binary inherits AGPL
   whatever the leaf crates declare. The founder decided the node is born
   AGPL-3.0-or-later, like the Genesis-3 node it succeeds, rather than
   re-extracting the PQ verify surface into a permissive leaf crate.
   `bloch-pos-committee`, `bloch-pos-node` and `tools/genesis4-ceremony` were
   relicensed accordingly (SPDX headers and `Cargo.toml`). What this obliges,
   stated plainly: anyone who runs a modified Genesis-4 node as a network
   service must publish their modifications. A6 verifies the release carries
   the recorded license.
5. **Interface-doc open points** (`BLOCH-POS-INTERFACES.md` §4) remaining
   open, the ones that gate node milestones: 4.5 withdrawal-credential
   format (blocks DEV-3 deposits, M2), 4.2 delegator withdrawal-delay
   asymmetry, 4.8 inactivity-leak constants (KAT before Phase-3 exit).
   4.7 is closed by decision 7.
6. **Genesis time.** Slot 0's timestamp is a consensus constant nobody has
   proposed yet; it lands in the genesis manifest, decided at launch
   scheduling, but the manifest format (M1) must carry it.

---

## 9. The skeleton delivered with this plan

`crates/bloch-pos-node/` builds standalone
(`cargo build` inside the directory; binary `target/debug/bloch-pos`) with a
single dependency on `bloch-pos-committee`. It parses `--version`/`--help`,
runs a self-check over the frozen parameters it links — pairwise-distinct
domain tags, u64 supply headroom, the genesis-cohort taper endpoints
(100% at epoch 0, 33.33% at one year, held after), the 30 s × 32 cadence —
prints, and exits 0. It does nothing else, on purpose: it is the address at
which M1 work lands, and proof that the one-way dependency arrangement
compiles.

The Genesis-3 tree is untouched: no file under `src/`, no root `Cargo.toml`
or `Cargo.lock` change, no new workspace member.
