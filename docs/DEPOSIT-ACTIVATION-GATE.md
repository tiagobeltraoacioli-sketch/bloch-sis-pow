<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# `DEPOSIT_ACTIVATION_EPOCH` — the gate that is not meant to be armed

Sibling of `docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` and
`docs/LEAKED-ROSTER-FLAG-DAY.md`, and the third element of this repo's rule:

> **The constant, the tripwire and this file land in the SAME commit.**

It differs from its two siblings in one way that matters more than everything
else in this document, so it goes first:

> **`ANCESTRY_SEED_ACTIVATION_EPOCH` and `LEAK_RECOVERY_ACTIVATION_EPOCH` are
> waiting to be armed. This one is not. Arming it is the failure mode, not the
> plan.**

Everything below is the argument for that sentence, and the reason the gate
exists anyway.

---

## 1. The defect this closes

`bloch-pos-node`'s `admissible` (`crates/bloch-pos-node/src/engine.rs`) has
refused `Deposit` and `Delegate` since 2026-08-13. It has exactly one non-test
caller: `Engine::on_transaction`, the mempool door, where gossip
(`NetEvent::Transaction`) and RPC (`SendRawTransaction`) converge.

Consensus is `bloch-pos-committee`. Before this commit,
`CommittedState::apply_transaction` applied both messages with **no height, no
epoch and no flag-day check at all**. The node's own comment said so:

> "This is a node-side refusal, not a consensus rule: a block that already
> carries a deposit still applies it."

That is mempool policy, and mempool policy is per-node. The consequence is
structural, and it is the reason this work was commissioned:

> **A single producer that lifts its local policy lifts it for the entire
> network.** Sixty-four validators would each have judged the resulting block
> with `compute_post_state`, and `compute_post_state` would have applied the
> deposit. There was no constant to arm, so the repo's own consensus-change
> rule could not be satisfied by any change to it.

Both messages mint consensus weight against nothing:

| | spends an input | carries a signature | reaches `effective_stake` |
|---|---|---|---|
| `Deposit` | no | no | after `ACTIVATION_DELAY_EPOCHS` |
| `Delegate` | no | no | at `epoch + 1` |

`Delegate` is the faster of the two: `consensus_roster_at` folds resolved
delegated stake straight into `effective_stake`, with no activation queue in
front of it. Closing only the deposit door would have been a fix that reads
like one and is not — hence one constant governing both.

---

## 2. Where the epoch comes from, and why two honest nodes cannot disagree

The gate is the first statement of each arm in
`CommittedState::apply_transaction`, and it reads `self.epoch`.

At that point in the transition, `self.epoch` is **exactly**
`crate::epoch_of(header.slot)` for the block being judged. The chain of
reasoning, all inside `compute_post_state`:

1. `let block_epoch = crate::epoch_of(header.slot);`
2. `if block_epoch < pre.epoch { return Err(NonMonotonicSlot) }`
3. `while st.epoch < block_epoch { st = st.close_epoch(); }`, and `close_epoch`
   advances by exactly one (`let next_epoch = closing + 1; … st.epoch =
   next_epoch;`)
4. therefore `st.epoch == block_epoch` when the transaction loop runs.

So the gate's input is a pure function of one header field, and the header is
what the block id commits to (`SHA3-256(DS_BLOCK ‖ canonical header)`). It is
not a wall clock, not the node's own head, not a field any node writes on its
own accepted-block path.

This is deliberately the same shape as the `TransferV2` gate four lines above
it, and deliberately **not** the shape of the 2026-08-08 `expected_bits`
consensus failure, where `expected_bits` came from `current_bits` — local
mutable state written on every accepted block — and nodes running *identical
binaries* diverged at every retarget height. The distinction is not "committed
vs. uncommitted"; it is "derived from the thing being judged vs. derived from
the judge."

`the_gate_is_a_function_of_the_block_epoch_alone` states this as a test: the
predicate's whole argument list is one `u64`.

---

## 3. Replay safety — measured, not assumed

Refusing below the flag day rewrites history only if history contains a
`Deposit`. It does not.

Measured 2026-09-02 against the two keyless archivals, `139.180.166.5` and
`139.180.173.231` on port 8080, **both required to agree**, and they did,
byte-for-byte:

```
height           35628
slot             56525
epoch            1766
state_root       71e71e6a5a0843af78d4bd2a63b0e4192a62f5108741ac3ed76797d57f063fa7
validators       { total: 64, active: 64 }
total_active_stake_sat  14258227737013640
```

`getvalidatorcount`'s `total` is `CommittedState::validator_count()`, which is
`self.validators.len()` — **every** record, including one queued at
`activation_epoch == u64::MAX`. The genesis cohort is 64. Therefore **no
`Deposit` has ever been applied on the canonical chain**, every historical
block replays through this gate unchanged, and the fleet can adopt it without a
coordinated flag day.

Corroborated in-tree: `bloch-pos-node`'s
`a_cold_node_builds_the_same_chain_from_genesis_without_a_donated_datadir`
passes with the gate in place.

Two honest caveats:

- `Delegate` leaves no queryable registry trace, so its absence is **argued**,
  not measured: `total_active_stake_sat` is uniform across the 64 validators,
  which a delegation would have moved, and nothing on this chain has had an
  incentive to delegate to a founder-held validator.
- The archivals do **not** run the release tag. They date *chain state* only.
  Nothing here dates node behaviour, and nothing here should be read as doing
  so.

---

## 4. `u64::MAX` here means the rule is LIVE, not dormant

The two sibling gates use `u64::MAX` to select the **old** behaviour while the
fleet rolls out. This one inverts that:

| | inert value selects | armed value selects |
|---|---|---|
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | old rule (`back = 1`) | new rule (`back = 2`) |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | old rule (no recovery) | new rule |
| **`DEPOSIT_ACTIVATION_EPOCH`** | **the refusal** | unfunded bonding, on every node |

At `u64::MAX` no epoch ever reaches it, so both messages are invalid in
consensus at **every** epoch, today, on any node running this crate. The gate
is not waiting to do its work. It is doing it.

This also means it is not the `fc_equivocators` antipattern — an inert constant
with no reader, where committed state barred 48 validators and every node's
engine barred zero. This constant has a reader on the only production path that
can apply either message, and deleting the reader turns two tests red (§6).

---

## 5. The decision: E closes the legacy encoding permanently

The question put to this work was whether the legacy unauthenticated `Deposit`
encoding should become valid again after E, or whether E should close it in
favour of a funded, authenticated form. **It closes it. Permanently.**

The reasoning is short. The encoding the gate governs is the one that spends no
input and carries no signature. Moving `DEPOSIT_ACTIVATION_EPOCH` to a
reachable epoch does not open deposits safely — it makes stake minted from
nothing a consensus-**valid** transaction on all sixty-four nodes at once,
which is strictly worse than the pre-gate tree, where at least the mempool
refused it. Measured on 2026-08-13: 25,000 BLCH per unauthenticated request,
roughly forty-six requests to a third of active stake and stalled finality, a
hundred and eighty to two thirds.

There is no field in the legacy `Deposit` variant that a funded form could set.
Deposits open by a **different message**: one that spends transparent eUTXO
inputs and proves possession of the key — the shape `staking::validate_deposit`
and `DepositTx` already describe and that no encoder emits. That message

- needs a **wire tag**, which this work deliberately does not assign. `0x06` is
  already collided inside the released space and the numbers above it are
  contested across live lineages. The frozen registry
  (`guard/wire-tag-registry-release`, guard at
  `crates/bloch-pos-committee/tests/wire_tag_registry.rs`) is where that is
  resolved, and the number is the founder's to pick.
- brings its **own** activation constant.

When it lands, `DEPOSIT_ACTIVATION_EPOCH` stays `u64::MAX` and the legacy arm
stays refused.

`deposit_gate_is_inert` pins the value, so arming it means deleting a test that
says all of this out loud.

---

## 6. Verification by violation, both directions

**Before**, at the pristine tree `g4-node-20260901` (`7a83ca89`), the defect
asserted as a passing test — a block carrying a `Deposit`, applied through
`apply_block`, minting a fifth validator record against no input spent:

```
test transition::tests::a_deposit_in_a_block_is_applied_with_no_consensus_gate ... ok
test result: ok. 1 passed; 0 failed
```

**After**, the same body refused by the transition. The block is *built* with
the gate forced open — so its `body_root` and `state_root` are real, exactly
the block a patched producer would gossip — and *judged* with the gate shut:

```
test transition::tests::a_deposit_in_a_block_is_refused_by_consensus_not_by_the_mempool ... ok
test transition::tests::a_delegation_in_a_block_is_refused_by_consensus_too ... ok
test transition::tests::the_gate_is_a_function_of_the_block_epoch_alone ... ok
test transition::tests::deposit_gate_is_inert ... ok
```

The refusal provably comes from consensus and not from local policy, because
`bloch-pos-node` is not in this test's dependency graph. There is no mempool
here to blame.

**Mutation.** With both gate bodies deleted and nothing else changed, the two
wiring tests go red and report the applied state:

```
a_deposit_in_a_block_is_refused_by_consensus_not_by_the_mempool ... FAILED
  left: Ok(CommittedState { slot: 33, epoch: 1, … validators: {0,1,2,3,4} … })
a_delegation_in_a_block_is_refused_by_consensus_too ... FAILED
test result: FAILED. 2 passed; 2 failed
```

Restored byte-identical, verified by digest
`3c136c6d4717c2f4395f7e79bac655561e7f08a21dab55809fc659570c8c8f0d`.

---

## 7. The test switch, and why it is its own switch

`params::rehearsal::bonding_gate_open_guard()` (thread-local, `#[cfg(test)]`,
cannot exist in a shipped binary) forces the gate open for one test thread.

It is **not** folded into the existing `GATES_OPEN` switch, because the two mean
opposite things: `GATES_OPEN` turns the *new* rule on for gates whose inert
value is the old behaviour; this one turns the *old* behaviour back on for a
gate whose inert value is the refusal. A test that asked for a
post-ancestry-seed roster and silently got a chain where stake mints from
nothing would be a fixture lying about the network it models.

Six pre-existing fixture functions bond through the legacy path and now opt in
explicitly, covering seven tests (`state_with_live_bookkeeping` is shared).
They were changed rather than the constant being weakened to keep them green:

- `transition.rs`: `deposit_queues_and_activates_through_the_epoch_pipeline`,
  `replay_is_delivery_order_independent`,
  `producer_fees_reach_delegators_through_the_commission_split`,
  `evidence_transaction_slashes_operator_and_delegators_and_pays_whistleblower`,
  `state_with_live_bookkeeping` (shared by
  `every_committed_state_field_is_bound_by_the_root`),
  `convergent_paths_commit_identical_roots_with_bookkeeping_live`.

Default is CLOSED: an unadorned `cargo test` exercises the rules the fleet runs.

---

## 8. What this does NOT unblock

This gate makes the refusal a property of the chain. It does not open the
network to validators. The following are verified against this tree
(`g4-node-20260901`, `7a83ca89`) by caller search, not restated from a briefing:

1. **No funded, authenticated deposit message exists.** `staking::validate_deposit`
   (`crates/bloch-pos-committee/src/staking.rs:285`) has **no non-test caller**
   anywhere in `crates/` — only its own unit tests and a re-export in `lib.rs`.
   `DepositTx` describes the form; nothing encodes or decodes it. It needs a
   wire tag (§5) and its own activation constant.
2. **Withdrawal has no production path.** `staking::validate_withdrawal`
   (`staking.rs:503`) likewise has **no non-test caller** — its only references
   are its own tests, `ws.rs` tests, and the `lib.rs` re-export. Voluntary
   *exit* does work at this tree (the `Exit` arm of `apply_transaction` sets
   `exit_epoch` and `withdrawable_epoch`), but nothing turns a withdrawable
   record back into a spendable output.

Both together are the real shape of the problem: a deposit that is refused by
consensus is a smaller problem than a deposit that is accepted and can never be
withdrawn. This commit fixes the first one and makes the second one visible.

Two further blockers are recorded elsewhere in the founder's notes — cold sync
not completing for a node joining from scratch, and no tool that signs a
checkpoint. **Neither was re-verified in this tree by this work**, and they are
listed here only so the reader does not mistake §8 for a complete list.
