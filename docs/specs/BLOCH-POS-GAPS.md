<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch PoS — the honest list of what is missing

```
Document:   BLOCH-POS-GAPS
Status:     INVENTORY — findings, not fixes; each entry names an owner class
Created:    2026-08-11
Owner:      PMO
Method:     sweep of docs/specs/ and crates/bloch-pos-committee at the head of
            integration/pos-modules (post-f384292); file:line cited where code
            exists, "does not exist" written where it does not
Relates:    BLOCH-POS-NODE-INTEGRATION.md (the plan for most of §3),
            BLOCH-L1-EXECUTION-PLAN.md (consumes GAP-1 via its X1 re-freeze),
            BLOCH-POS-INTERFACES.md §4 (the nine frozen-time ambiguities)
```

Three buckets: **implemented** (code exists and is tested — which is not the
same as audited), **specified but not implemented**, and **neither specified
nor implemented**. A fourth section lists defects in implemented code —
things that exist and are wrong or divergent, which is a different kind of
missing.

The one-line summary, so nobody mistakes the state of the project: **the
pure consensus crate is substantially built and tested; the node is a
134-line skeleton; every I/O-shaped spec has zero corresponding code; and
the two validation stacks inside the pure crate do not agree with each
other.**

---

## 1. Implemented (in `crates/bloch-pos-committee`, pure logic only)

All paths relative to `crates/bloch-pos-committee/`. "Tests" counts inline
`#[test]`s; several untested-inline modules are covered from `tests/`
(noted). The crate has exactly one dependency (`sha3`), an isolated
workspace, no I/O, no clock, no serde — verified by grep, not just by its
own claims.

| Module | What actually exists | Tests |
|---|---|---|
| `committees.rs` | the current committee mechanism: shuffled partition of the active set into `SLOTS_PER_EPOCH` committees, seed look-ahead (F6), `is_supermajority` | via `tests/committee.rs` |
| `schedule.rs` | slot/epoch/time arithmetic (clock always injected), proposer draw | `tests/schedule.rs` |
| `beacon.rs` | RANDAO by SHAKE-256 preimage chain: reveal, mix, exhaustion + re-commit | 11 inline |
| `attestation.rs` | vote type, `DS_ATTEST` signing root, surround/double-vote predicates, membership-before-signature validation, verifier injected | via `tests/` |
| `forkchoice.rs` | LMD-GHOST store, weights, head, equivocator-discard observation policy (order-independent by construction, `forkchoice.rs:56-68`) | via `tests/properties.rs` probes — see GAP-4 |
| `finality.rs` | Casper FFG: 2/3 justification without division, finalization, inactivity-leak arithmetic, `from_history` | 17 inline |
| `state_root.rs` | fixed-depth SHA3-256 SMT, `build_state_tree`/`state_root`/`verify_inclusion`, manual serialization | 11 inline |
| `header.rs` | `BlockHeaderV4` (fixed-width), `BlockId` single-constructor discipline + the `single_derivation_path` source-scanning test | 10 inline |
| `derive.rs` + `produce.rs` | one block validation/production stack: `ParentState`/`ChainState`, `validate_block`, envelope assembly, single-use reveal enforcement (`ProducerRandao`) | 9 inline (produce) |
| `transition.rs` | the other validation stack plus the state transition: `CommittedState`, `apply_block`, `process_epoch`, deposit/delegation queues, fee accounting, emission | 17 inline |
| `staking.rs` | deposits with proof-of-possession under both hybrid halves, exits, withdrawal delay, activation queue, §4.1 eligibility | 18 inline |
| `delegation.rs` | delegation registry, warm-up/cool-down budget (`WARMUP_RATE_BPS`, `MIN_CHURN_SAT` — ADR-038), fixpoint per-validator cap, pro-rata slash, concentration metrics | via `tests/` |
| `rewards.rs` | the Solana reward model: fee split with burn, pro-rata issuance with commission | via `tests/` |
| `slashing.rs` | evidence validation (re-verifies both signatures), correlated amplification, whistleblower, anti-replay | 13 inline — **but orphaned, see GAP-3** |
| `genesis_cohort.rs` | declining genesis-cohort cap with `Deferred` escape, wired into `transition.rs` | via `tests/committee.rs` |
| `gossip.rs` | the *application* half of attestation gossip: accept/ignore/hold/reject verbs, 2-epoch window, equivocation cap, evidence capture — pure, no sockets | 15 inline |
| `tokenomics_v4.rs` | V4 constants, vesting curves, three emission curves, compile-time supply invariants | via `tests/properties.rs` |
| `interfaces.rs` | the seven frozen traits + `StateRoots` — zero implementations, by design | — |
| `sample.rs`, `params.rs`, `lib.rs` | legacy sampled sortition (kept in-tree), constants, re-exports | — |

Founder decisions already applied in code: churn re-rate (ADR-038,
`delegation.rs`), AGPL relicense (ADR-039, SPDX headers + `Cargo.toml`),
single-set liquid carryover (`tokenomics_v4.rs`, `CARRYOVER_TOTAL_BLOCH`
doc).

Also implemented: `crates/bloch-pos-node` — but only as the planned
skeleton: one file, `src/main.rs` (~134 lines, version `0.0.1-skeleton`),
parameter self-check, prints, exits. No consensus loop, no networking, no
storage. That is exactly what `BLOCH-POS-NODE-INTEGRATION.md` §9 promised
and nothing more.

---

## 2. Implemented, but defective or divergent (the found gaps)

### GAP-1 — the committed-state list is incomplete, and the spec change is pending (known; DEV-1's registration)

`transition.rs:69-80` ("What is honestly not committed yet"): the following
consensus-relevant fields of `CommittedState` are **not bound by the
header's `state_root`** — finality bookkeeping, per-validator RANDAO chain
positions (`reveals_used`, `transition.rs:197`), the deposit/delegation
queues, pending fee rewards (`transition.rs:246`), and fork-choice latest
messages. Extending the closed component list is a §Boundary-7 spec change
under the two-reviewer rule.

**Aggravating finding:** the comment says this is "recorded in
`BLOCH-POS-INTERFACES.md` as an open point" — **it is not**. Grep for
`reveals_used` across `docs/` returns nothing; §4 of the interfaces doc has
nine ambiguities and this is not among them. The registration exists only
in the module doc and in commit `e1657ed`'s message. Until it is in the
interfaces doc, the two-reviewer process has nothing to review.
**Consumed by:** `BLOCH-L1-EXECUTION-PLAN.md` milestone X1 — the ruling
(each component in, or explicitly ruled node-local) merges into the single
StateRoots re-freeze.

### GAP-2 — two block-validation stacks with divergent consensus-visible error orders

`derive::validate_block` (`derive.rs:426-505`) and
`transition::apply_block` (`transition.rs:840+`) are two independent
validation layers. `transition.rs:36-56` declares its error order **frozen
and consensus-visible** (`NonMonotonicSlot` → `WrongParent` → … →
`BadSignature` at step 7 → … → `StateRootMismatch` last). `derive.rs` runs
`WrongParent` (:436) *before* `NonMonotonicSlot` (:439) and verifies the
proposer signature **last** (:501); it also checks `BodyRootMismatch`
(:477) and `CoherenceRootMismatch` (:484), which `transition` never checks,
while `transition` executes transactions and the registry, which `derive`
never does. Two nodes validating the same bad block through different
stacks can emit different rejections, and no layer checks everything.
`header.rs::single_derivation_path` guards block *identity* against exactly
this defect family (the 2026-08-08 `expected_bits` lesson) — nothing guards
*validation*. No spec describes the duality; `derive.rs:23-28` still
describes `transition.rs` as not yet landed (stale). Companion defect: two
committed-state models (`derive::ParentState`/`ChainState` vs
`transition::CommittedState`) with no conversion and no cross-test.
**Needed:** a ruling on which stack is canonical (or a merge), then
deletion or subordination of the other — an integration decision the
node plan's M1/M3 must not inherit silently.

### GAP-3 — slashing is orphan logic

`transition.rs` never imports `slashing` (verified: grep for
`use crate::slashing` hits only `gossip.rs:45`), and `PosTransaction`
(`transition.rs:137-162`) has **no evidence variant**. Slashing evidence
therefore has no path into the state transition: 541 lines and 13 tests of
`slashing.rs` are unreachable from consensus. The node plan's trait table
assigns `SlashingRules` to `rules/slashing.rs` (node side), but the pure
transition still needs an evidence transaction type — today there is none.

### GAP-4 — the probe prose is stale: the four A2 findings were fixed, the tests still claim otherwise

`tests/properties.rs:25-28` and the section header at `:781-785` state that
`probe_` tests "are left failing on purpose" — properties the code does not
hold. **That is no longer true.** All four probes pass (verified by running
the suite on this tree, 2026-08-11: 270 passed, 0 failed), and the
underlying fixes are visible in the code:

- `Delegation::queue_key` now includes `amount_sat`
  (`delegation.rs:142-144`), closing the order-dependent-registry finding
  (`properties.rs:813`).
- `forkchoice::Store::observe` now **discards equivocators** instead of
  keeping the first-seen message; the module documents the old first-seen
  defect and why the discard is order-independent (`forkchoice.rs:56-68`),
  closing `properties.rs:850`.
- `properties.rs:788` (duplicate registry indices in `sample`) and `:890`
  (`Registry::state_of` vs the admitted registry) also pass.

The gap that remains is documentation debt with teeth: a reader of the test
suite is told four consensus-splitting bugs exist when they do not, and —
worse in the other direction — the convention "probes are expected to fail"
would mask a *future* probe regression as expected behaviour. The stale
header and the per-probe FINDING comments need rewriting to describe the
fixed state, and the probe convention needs a rule: a passing probe's
comment must say it pins a fix.

### GAP-5 — the frozen `StateRoots` and the concrete tree disagree

Frozen: `interfaces.rs:749-768` — `StateRoots` with **7** fields, one
`participation_root`. Concrete: `state_root.rs` — **8** component tags
(`TAG_PARTICIPATION_CURRENT` and `_PREVIOUS` separate; insertion at
`state_root.rs:433-470`), fields on `ConsensusState`
(`state_root.rs:400-419`). No code reconciles them, and
`StateCommitment` — the trait that would (`interfaces.rs:794`) — **has no
implementation anywhere in the repo**. `transition.rs:82-87` says so
honestly: `block_id`/`proposal_signing_root` are free functions awaiting
DEV-2's implementation, to be pinned equal by A1 KATs. Which leads to:

### GAP-6 — there are no KATs at all

`tests/kats/` does not exist; no vector files exist anywhere in the crate
(`find` for `*kat*`, `*vector*`, `*.json` under the crate: empty). The
interfaces doc and node plan both make A1 KATs the tiebreaker for every
consensus byte layout, and M1 calls the commitment KAT file "the critical
path". Nothing has started.

### GAP-7 — small divergences, cheap now, expensive later

- `reveals_used` is `u32` in `beacon.rs:188`/`transition.rs:197` but `u64`
  in the frozen `interfaces.rs:561` (`is_exhausted`).
- `rewards.rs` implements the Solana split while migration spec §7.4 still
  specifies the Ethereum 7/8‖1/8 shape — interfaces doc §4.4, open. Code
  merged against a normative spec that says otherwise.
- `DS_PROPOSE` exists in `params.rs:89-97` but the §6.1 domain-tag table
  in the spec has no row for it (interfaces doc §4.1).
- `params.rs:98-108`: orphan doc-comments (merge residue), and
  `SLOT_SUBCOMMITTEE_SIZE`/`COMMITTEE_SIZE` are dead constants under the
  partition model; `sample.rs` is the retained legacy mechanism with no
  seal saying so on the module itself (`lib.rs:5-15` carries the seal).
- `lib.rs:107-139`: three name collisions (`Checkpoint`, `FinalityState`,
  `ValidatorRecord`) deliberately visible, awaiting the integration
  decision.
- `tests/e2e.rs` still runs every scenario against its own
  `harness::RefTransition` (`e2e.rs:54`, `:411`) although the real
  `transition.rs`/`produce.rs` have landed; the SWAP POINT markers
  (`e2e.rs:27-29`) were never exercised. The e2e suite currently proves
  the harness, not the product.
- `transition.rs:1447`: the inactivity leak is *not* wired into the
  transition ("eventually the inactivity leak") — the arithmetic exists in
  `finality.rs`, nothing calls it on protracted non-finality.
- `slashing.rs:28-31`: no deferred penalty application — early offenders in
  a correlated event are under-punished relative to Ethereum's
  withdrawal-time repricing; declared as belonging to the (nonexistent)
  withdrawal path.

---

## 3. Specified but not implemented

The structural fact first: **everything allocated to the node has zero
lines of code.** `crates/bloch-pos-node/src/main.rs` is the entire node.
None of node-plan M1, M2 or M3 has started — no `rules/`, no `store/`, no
`genesis/`, no `net/`, no `rpc/`, no `mempool/`, no `keys/`. Consequently:

| Spec | Status of implementation |
|---|---|
| `BLOCH-POS-NODE-INTEGRATION.md` §3 (RocksDB schema, `StateReader`, refuse-foreign-db) | does not exist |
| §3.4 genesis manifest format + loader (incl. the carryover-eligibility field ADR-037 now fixes the value of) | does not exist — and the manifest *format* itself is unspecified beyond the plan's bullet list |
| `BLOCH-RPC-V4.md` | does not exist (no RPC code anywhere in Genesis-4; the crate has no serde by design, `state_root.rs:280`) |
| `BLOCH-WEAK-SUBJECTIVITY.md` (checkpoint format, publication, checkpoint sync) | only the margin constant exists (`staking.rs:105`, `WITHDRAWAL_DELAY_EPOCHS`, tied into `slashing.rs:70`); checkpoint artifact/validation/sync do not exist; `FinalityState::new` accepts a trusted seed checkpoint with nothing validating provenance |
| `BLOCH-ATTESTATION-GOSSIP.md` transport half (gossipsub topics, `TopicScoreParams`, token buckets, ingest channel) | does not exist — `gossip.rs:10-13` says so; only the pure policy half exists |
| `BLOCH-FALCON-ONLINE-SIGNING.md` | not in this crate by design (signing/verifying injected via traits); the real path is `bloch-crypto`'s, allocated to DEV-2 keystore work in M2 — node-side code does not exist |
| `BLOCH-POS-SORTITION-DOS.md` | assessment spec, "no code change proposed" — but its *node-side* mitigations (sentry posture, rate limiting) have no home until `net/` exists; the crate-side F6 look-ahead exists (`committees.rs:99`) and the spec itself notes it widens the F7 window |
| `BLOCH-COHERENCE-UNDER-POS.md` | only the commitment surface: two carried opaque roots (`state_root.rs:415-418`, `derive.rs:77-80`, `TransitionError::CoherenceRootMismatch`). No accumulator, no nullifier machinery, no bridge in Genesis-4 code — the no-bridge part is by design (node plan §5), the carry pipeline is simply unbuilt |
| `BLOCH-POS-STAKE-CHURN.md` Phase 2 (absolute churn cap) | flagged, deliberately unsized (`delegation.rs:81-84`) |
| Interfaces doc §4.2 (delegator withdrawal-delay asymmetry), §4.5 (withdrawal-credential format), §4.8 (inactivity-leak constants + KAT) | decisions pending, then code; nothing exists |

---

## 4. Neither specified nor implemented

Things the sweep surfaced that no document owns:

1. **A spec for delegation.** `rewards.rs:18-23` admits the
   delegation/commission model is "a genuine addition to the PoS design";
   it appears only in passing in the tokenomics, churn and interfaces docs.
   The registry semantics, `queue_key` identity (GAP-4b's root cause), cap
   fixpoint, and the concentration metrics (`top_share_bps`,
   `nakamoto_coefficient`) are specified nowhere.
2. **Fork-choice observation policy.** `Store::observe`'s
   equivocator-discard rule (`forkchoice.rs:56-68`) is implemented, tested
   and documented *in code* — but it is a consensus policy that appears in
   no spec; the LMD-GHOST spec material covers weights, not observation.
   Its history (a first-seen version that was order-dependent under
   equivocation, then replaced) is exactly the kind of decision that
   belongs in a spec or ADR, not only in a module comment.
3. **The fate of the Genesis-3 consensus ADRs under Genesis-4.** ADR-007's
   bonding model (seats, UIDs, 21-day unbonding) is incompatible with the
   implemented staking (`WITHDRAWAL_DELAY_EPOCHS` regime, no seats), and
   ADR-002's DKG/threshold-BLS has no counterpart at all (each validator
   signs individually with the hybrid). No document says these ADRs die
   with the halt. A one-page supersession ADR would close it.
4. **`CapStatus::Deferred`** (`genesis_cohort.rs:100-124`) — the cohort-cap
   escape clause born from the day-one-liveness bug (commit `dc64b3b`) is
   consensus behaviour absent from the tokenomics spec's cohort section.
5. **`ProducerRandao` crash-restart semantics** (`produce.rs:28-39`) —
   single-use reveal enforcement including "re-produce after crash needs a
   fresh tracker" is an operationally significant rule with no spec home.
6. **`close_epoch` infallibility on empty boundaries** — a deliberate
   design decision recorded only in commit `e1657ed`'s message and code.
7. **Genesis time and the genesis manifest format** — node plan §8.6 names
   the gap; no proposal exists.
8. **Everything EVM-at-L1 and Ustav-at-L1** — by definition of the new
   direction; owned by `BLOCH-L1-EXECUTION-PLAN.md` (E1/U1 are the specs
   to be written). Includes the unresolved contradiction flagged there:
   `src/euvm/mod.rs` (Genesis-3 tree) describes the eUTXO VM as
   feature-gated and not wired into `accept_block`, while the fleet brief
   records it consensus-wired at height 0 — one of the two is stale.
9. **A name-collision warning**: `BLOCH-SIS-ATTESTATION.md` (execution-
   environment attestation, Genesis-3 `src/attestation/`) and the crate's
   `attestation.rs` (consensus votes) share a word and nothing else;
   neither doc cross-references the other.
10. **Canonical emission curve in the spec text.** Node-plan decision 5
    binds `tokenomics_v4::validator_reward_decay_sat`, resolving
    interfaces §4.3 — but the tokenomics spec still presents three curves
    and its §7A gate analysis argues for a different one. The PMO record
    exists in the plan; the normative spec has not been amended.

---

## 5. Test-coverage holes worth naming

- `derive.rs` and `interfaces.rs` have no dedicated test file; `derive` is
  exercised only through `produce.rs`'s inline tests.
- `forkchoice.rs` has no inline tests; its coverage lives in
  `tests/properties.rs` probes whose prose is stale (GAP-4).
- The e2e suite validates a reference harness, not the shipped transition
  (GAP-7, e2e bullet).
- No KATs exist (GAP-6), so there is currently no tiebreaker if two
  implementations of any commitment disagree — which is exactly the
  situation GAP-5 already describes.
