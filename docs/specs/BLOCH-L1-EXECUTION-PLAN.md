<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch L1 Execution Plan — EVM at L1 and Ustav at L1

```
Document:   BLOCH-L1-EXECUTION-PLAN
Status:     DRAFT — milestone plan for review; no code exists for either track
Created:    2026-08-11
Owner:      PMO
Decision:   ADR-040 (direction accepted; consequences under design — this
            document is where they get designed)
Normative:  docs/FLEET-BRIEF-2026-08-11.md (framing + premise correction),
            BLOCH-POS-NODE-INTEGRATION.md (the host plan this one composes
            with), BLOCH-POS-INTERFACES.md (frozen traits, §Boundary 7)
Relates:    BLOCH-POS-GAPS.md (the pending StateRoots spec change this plan
            deliberately merges with), BLOCH-TOKENOMICS-V4.md (fee model)
```

This document sequences the two founder directions of 2026-08-11 — EVM at
the base layer with no L2, and the Ustav charter as a consensus object — the
same way `BLOCH-POS-NODE-INTEGRATION.md` sequenced the node build: milestones
with **zero file overlap**, integration points that are **serialized on
purpose**, and estimates given in **dependencies and what-blocks-what**, not
dates. Nothing here re-derives the fleet brief; in particular the premise
correction (Solana is *not* natively EVM; the target is *one global L1 state
machine, no rollups*) and the three-way authorization problem are taken from
it as given.

---

## 0. What this plan inherits, and the one rule it adds

Inherited from the node-integration plan, unchanged:

- **The Genesis-3 tree is untouched.** Everything here lands in new crates
  or in `crates/bloch-pos-node` directories after their owning milestones.
- **Pure-crate discipline.** Execution engines are pure (state in →
  state + receipts out; no clock, no I/O), and consensus reads go through
  `StateReader` from the parent's committed state.
- **Frozen traits are the contract surface**; changes to them follow the
  two-reviewer rule.

The one rule this plan adds:

> **SR-2: the closed `StateRoots` component list is re-frozen exactly once.**
> Three demands on that list already exist: (1) the pending extension DEV-1
> flagged in `crates/bloch-pos-committee/src/transition.rs` (module docs,
> "What is honestly not committed yet") — finality bookkeeping,
> `reveals_used`, the deposit/delegation queues, pending fee rewards; (2) the
> EVM state commitment this plan introduces; (3) the Ustav charter-registry
> commitment. Each is a §Boundary-7 spec change needing the two-reviewer
> rule, and every re-freeze invalidates the commitment KATs three DEVs code
> against. Serializing them into **one re-freeze round (milestone X1)** is
> this plan's most important sequencing decision: one KAT re-pin, one review
> round, one moment of churn — instead of three.

---

## 1. The dependency spine

```
 E0 (auth dossier) ──► D-AUTH (founder decision) ──► E2 finalize ─┐
                                                    E5 (RPC)      │
 E1 (EVM L1 spec) ────────────┬───────────────────────────────────┤
                              │                                   │
 U0 (Kirpich/Ustav inventory)─┤                                   │
                              ▼                                   ▼
 U1 (charter-as-consensus spec)──► X1 (SR-2 re-freeze, ONCE) ──► X2 (transition
                              ▲          ▲                        wiring, one PR)
 GAP-1 (pending StateRoots ───┘          │                            │
        components ruling)               │                            ▼
                                         │                       X3 (devnet exit)
 node plan M1 (commitment KATs) ─────────┘
 node plan M3 (composition) ─────────────────────────────────────► X2 prerequisite
```

Reading of the spine, in words:

- **Nothing blocks E0, E1, U0.** They are paper and can start now, in
  parallel, by three different owners.
- **D-AUTH blocks surprisingly little code** — deliberately. The EVM engine
  (E2) is built with the sender-authorization boundary abstracted (a
  `TxAuthorizer` seam, mirroring how `attestation::SignatureVerifier`
  keeps the PQ stack out of the pure crate), so only its *finalization*
  (which authorizer ships) waits on the founder. What D-AUTH hard-blocks is
  E5 (whether `eth_sendRawTransaction` can exist at all), the public copy,
  and the security note.
- **X1 blocks everything state-root-visible** (X2, and the parts of E2/U2
  that pin final KATs). It sits late enough to collect all three demands,
  and E2/U2 develop against stub leaves until then — the same trick M1 used
  with the stub `StateCommitment`.
- **X2 requires node-plan M3** (a composed, self-finalizing node to wire
  into). The L1-execution tracks integrate *after* the node exists; they do
  not race it.

---

## 2. Track E — EVM at L1

### E0 — the authorization dossier (no code; blocks the founder decision)

| Deliverable | `docs/specs/BLOCH-L1-EVM-AUTH.md`: the three options priced |
|---|---|
| Owner | one author (DEV-4) + adversarial review by the security role |
| Depends on | nothing |
| Blocks | D-AUTH, and through it E2-finalize, E5, all public copy |

Prices, per the brief, with nobody picking silently: (a) secp256k1 accounts
at L1 — with the blunt statement of the quantum-vulnerable authorisation
path it installs; (b) PQ-only accounts with EVM semantics — with the honest
tooling forfeit (no MetaMask, no Ledger, every tool ported); (c) dual — with
the fee/consensus cost of two authorisation models and the analysis of what
a quantum adversary takes from the secp256k1 side and whether it
contaminates the PQ side. One recommendation. **The founder decides; the
decision amends ADR-040.**

### E1 — the execution-layer spec

| Deliverable | `docs/specs/BLOCH-L1-EVM.md` |
|---|---|
| Owner | DEV-4 |
| Depends on | nothing to start; E0's option space to conclude |
| Blocks | X1 (it defines the EVM leaf), E2, U1 (asset-plane question) |

Must answer, in writing, the second-order questions ADR-040 lists as open:

1. **State coexistence.** How the account-model EVM state lives beside the
   eUTXO set and the C1-frozen Coherence roots — three state planes under
   one `state_root`. The plan's working assumption (to be confirmed or
   killed by the spec, not silently): the EVM state is committed as **one
   foreign root leaf**, the same pattern `state_root.rs` already uses for
   the taint and Coherence roots — a root of a tree another module owns.
2. **Gas versus the V4 fee model.** One fee market is the point of
   L1-native execution: EVM gas fees must terminate in the same
   burn-during-emission / to-validators-after split the V4 model fixes
   (authority: `crates/bloch-pos-committee/src/rewards.rs` and the
   tokenomics spec — never a second fee constant).
3. **The fate of `bloch-euvm`** — survives beside the EVM, is absorbed, or
   dies. This spec recommends; the founder ratifies. Note while deciding:
   the in-tree adapter header (`src/euvm/mod.rs`) still describes the VM as
   feature-gated and not wired into `accept_block`, while the fleet brief
   records it consensus-wired at Genesis-3 height 0 — resolve which
   statement is stale as part of this analysis (flagged, unsure).
4. **Value flow between planes.** Whether and how native value moves
   between the eUTXO plane and EVM accounts (deposit/withdraw semantics at
   the transition level), and the supply-conservation invariant across
   planes (the property test analogous to the flat-view/`utxo_root`
   agreement test in the node plan §3.3).
5. **chainId.** Reusing 8400 versus a new id — if secp256k1 transactions
   are accepted in any form, reuse makes old `bloch-l2-evm` signed
   transactions replayable on the new chain; a decision, not a default.

### E2 — the engine crate

| Deliverable | `crates/bloch-l1-evm` — new crate, own workspace, pure |
|---|---|
| Owner | DEV-4 (sole owner of the directory) |
| Depends on | E1; D-AUTH only for finalization (authorizer seam until then) |
| Blocks | X2 |

Copy-and-adapt from the existing `bloch-l2-evm` revm harness — minus the
service loop, JSON persistence and sequencer assumptions; the copy starts
life pure, exactly the posture the node plan takes toward Genesis-3 network
code. Hard requirements:

- **Pure interface:** `execute(parent_evm_state, ordered_txs) →
  (post_state, receipts, evm_state_root)`. No clock, no I/O, no global.
- **revm becomes consensus-critical.** Pin the exact version, decide
  vendoring, and record that an upstream execution bug is now a chain bug —
  this goes in the crate header, not a footnote.
- **Determinism KATs.** `bloch-l2-evm` ran under a single sequencer;
  nothing ever exercised cross-node determinism. E2 ships KATs for state
  root, receipt encoding, and gas edge cases, pinned before X1.

### E5 — RPC surface and L2 sunset

| Deliverable | `eth_*` namespace in `bloch-pos-node/rpc/` + sunset note |
|---|---|
| Owner | DEV-4 (RPC files for the eth namespace only — DEV-3 owns `rpc/` per the node plan; this lands as a PR into DEV-3's directory, reviewed by DEV-3) |
| Depends on | X2, D-AUTH |
| Blocks | ecosystem migration (explorer, wallets), public announcement |

Includes the decision on what happens to `bloch-l2-evm`'s existing state
(migrated into the genesis manifest as EVM-plane allocations, or abandoned
with notice) — that is a user-facing promise and needs a founder sign-off,
listed in §5.

---

## 3. Track U — Ustav at L1

### U0 — inventory: what Kirpich/Ustav actually are today

| Deliverable | `docs/specs/BLOCH-L1-USTAV-INVENTORY.md` |
|---|---|
| Owner | DEV-5 |
| Depends on | nothing |
| Blocks | U1 |

Ground truth to build on (verified in-tree): the Ustav module compiler and
`TokenCharter` live in `crates/bloch-euvm/src/modules.rs`; Kirpich is the
deterministic, fail-closed audit dispatcher in
`crates/bloch-euvm/src/kirpich.rs` with four rule lanes
(`kirpich/{conflicts,completeness,params,emitted}.rs`), explicitly
documented as "FOUNDATION, tests-only, NOT consensus-wired", pure function
of the charter, no panics, canonical finding order. That determinism is
exactly the property consensus promotion needs — U0's job is to verify it
survives scrutiny (bounded run time on adversarial charters, no
`HashMap`-order or allocator dependence in any lane) and to inventory which
audit lanes are *decidable consensus rules* versus *advisory lint* (Warn/
Info findings cannot be consensus; Deny findings might be).

### U1 — charter-as-consensus-object spec

| Deliverable | `docs/specs/BLOCH-L1-USTAV.md` |
|---|---|
| Owner | DEV-5 |
| Depends on | U0; E1 (asset-plane answer) |
| Blocks | X1 (charter leaf), U2 |

The change of kind, specified honestly — what is gained (a charter that
cannot be bypassed by talking to the contract directly) and what is bought
(consensus surface; a charter bug is a chain bug; an issuer's mistake is
every node's validation cost). Must answer:

1. **Binding plane.** What the charter binds: eUTXO-native assets, EVM
   tokens, or both. Depends on E1 — if EVM tokens exist at L1 and charters
   bind only the eUTXO plane, the charter is bypassable via an ordinary
   ERC-20, which defeats the promotion's purpose. This is why U1 cannot
   freeze before E1.
2. **Violation semantics.** Fail-closed at consensus must be
   **transaction-level, not block-level** rejection, or a single charter
   edge case can halt the chain; the spec must state the liveness argument
   explicitly.
3. **The upgrade story — precondition, not afterthought.** Charter
   semantics become fork-choice-relevant; fixing a charter-validation bug
   is then a consensus change. The spec must define charter versioning and
   the amendment path *before* U2 wires anything.
4. **Cost bounding.** Charter validation cost per transaction must be
   metered (Kirpich's audit is charter-sized, not chain-sized — confirm the
   bound) and priced into the same single fee market as E1 point 2.

### U2 — the consensus validation crate

| Deliverable | `crates/bloch-l1-ustav` — new crate, pure, own workspace |
|---|---|
| Owner | DEV-5 (sole owner of the directory) |
| Depends on | U1; X1 for final KATs (stub leaf until then) |
| Blocks | X2 |

Extracts the *decidable core* identified by U0 out of `bloch-euvm`'s
tests-only tree into a consensus-grade crate (copy-and-adapt, same as E2 —
`bloch-euvm` itself is not mutated until its E1-decided fate is ratified).
Charter registry state, deterministic validation entry point, KATs for the
charter serialization and registry root.

---

## 4. Track X — the serialized integration points

### X1 — SR-2: the single StateRoots re-freeze

| Deliverable | one PR: `interfaces.rs` + `state_root.rs` + commitment KATs |
|---|---|
| Owner | authored by DEV-2-role (commitment owner), reviewed under the two-reviewer rule + DEV-1, DEV-4, DEV-5 |
| Depends on | E1, U1, and the ruling on the pending components (GAP-1 in `BLOCH-POS-GAPS.md`) |
| Blocks | X2; final KAT pins in E2/U2 |

One round, three inputs: the pending committed-state components flagged in
`transition.rs` (each ruled in or explicitly ruled node-local — fork-choice
latest messages in particular may belong outside committed state, and that
ruling must be written, not assumed), the EVM state leaf, the charter
registry leaf. Whether `taint_root`'s reserved-zero slot (node-plan
decision 8) is recycled for one of the new leaves or left reserved is
decided here, once, with the KATs re-pinned in the same PR.

### X2 — transition and composition wiring

| Deliverable | EVM + Ustav execution invoked from the state transition; one PR |
|---|---|
| Owner | authored by DEV-1-role (transition owner), reviewed by DEV-4, DEV-5 and the security role |
| Depends on | X1, E2, U2, node-plan M3 (a composed node to wire into) |
| Blocks | X3 |

The deliberate echo of the node plan's M3: the only moment the two new
tracks and the existing transition meet in change-controlled files
(`rules/transition.rs`, `main.rs`), so the meeting is scheduled, not
accidental. Body layout changes (EVM transactions in the block body,
charter operations as transactions) land here, against the X1-frozen
commitments.

### X3 — devnet exit

Multi-node devnet with EVM and charter load; the cross-node determinism
KATs of E2 exercised across architectures; the supply-conservation
invariant across planes (E1 point 4) run as a property test; chaos
scenarios inherited from the node plan. Exit criterion is dependency-shaped
like everything else: a finalizing devnet where an EVM contract call, a
charter-bound token transfer, and a plain eUTXO spend coexist in one block
and every node computes the same `state_root`.

---

## 5. Decisions this plan does NOT take (and who takes them)

| # | Decision | Taken by | Produced by |
|---|---|---|---|
| 1 | Authorization model (the three-way choice) | **Founder** | E0 dossier |
| 2 | Fate of `bloch-euvm` | **Founder** (spec recommends) | E1 |
| 3 | chainId reuse vs new | Founder (replay-safety framing) | E1 |
| 4 | Which pending components become StateRoots leaves | two-reviewer rule | GAP-1 + X1 |
| 5 | Charter binding plane (eUTXO / EVM / both) | two-reviewer rule, founder if scope changes | U1 |
| 6 | `bloch-l2-evm` state migration vs abandonment | **Founder** (user-facing promise) | E5 |

## 6. Risks stated up front

- **The quantum-vulnerable option is on the table.** If D-AUTH lands on
  secp256k1-at-L1 in any form, the security note must be blunt about what
  the chain gives up — the brief's words, kept: it is the one thing the
  project exists to avoid.
- **Consensus surface growth is the price of both tracks.** revm (E2) and
  the charter validator (U2) both become code every node must agree on.
  Version pinning, vendoring, and the U1 upgrade story are the mitigations;
  none of them make the surface small again.
- **The single re-freeze (X1) is a chokepoint by design.** If E1 or U1
  slips, X1 slips, and with it everything state-root-visible. That is the
  intended trade: one late chokepoint over three KAT-churning re-freezes.
  The escape hatch, if one track stalls indefinitely, is to run X1 with the
  stalled track's leaf reserved-zero — the exact precedent `taint_root`
  set.
