# Genesis-4 relaunch — the decisions, and what each one costs

Branch `relanca/e1400`, on `deploy/armado-e1400`. This file records the choices
that are not obvious from the diff, so the next reader does not have to
re-derive them from the code.

## 1. The roster is unified by REMOVING the pre-shuffle filter

`committees::epoch_committees` filtered `effective_stake > 0` into `eligible`
*before* Fisher-Yates. The shuffle's XOF draws are length-dependent, so a list
of 64 and a list of 63 are not the same permutation minus one element — they
are unrelated permutations. `transition::with_leak_applied` zeroes a
fully-leaked validator but keeps it in the roster, so the leak-applied roster
(step 8 of `compute_post_state`) and the unleaked roster (`close_epoch` →
`finality::votes_from_partition`) partitioned differently the moment the leak
zeroed anybody. Attestations admitted into blocks were dropped at the boundary
tally.

**Committee MEMBERSHIP is now a pure function of (seed, epoch, index set).
Stake — delegation, cohort cap, leak — decides WEIGHT only.**

Why not the alternative, "drop the fully-leaked validator on both paths":

- `duty_roster_at` already excludes slashed, pre-activation and exited records.
  They never reach the partition. The filter's only live effect was dropping
  leaked-to-zero validators — it existed only to cause this bug.
- The leaked and unleaked rosters carry the same index set and differ only in
  stake. With no filter the partition is leak-invariant *by construction*: no
  call path can change it by holding a different roster variant.
- `finality::process_epoch` re-subtracts `self.leaked` from whatever roster it
  is handed. Feeding it a leak-applied roster double-charges the quorum
  denominator, so the alternative means editing the exact arithmetic that
  decides quorum. More risk, less coverage.
- Decisively: `derive.rs::active_validators` is a fourth roster producer —
  registry stake only, no delegation, no cohort cap, no leak. It has no leak
  information at all, so the alternative *cannot* make it agree with
  `transition.rs`. Removing the filter makes all four producers agree, because
  all four compute the same (activation, exit, slashed) predicate.

What it costs: a fully-leaked validator keeps an inert committee seat. Quorum
is stake-weighted over the whole active set, so it adds zero to numerator and
denominator alike. The liveness the leak buys back comes from the shrinking
denominator and from proposer selection (`schedule::sample` is stake-weighted
and still never draws a zero-stake validator), never from committee membership.

Consequence worth stating plainly: on a *healthy* network — no leak, no
zero-stake validator — the eligible list is identical either way, so the
partition, the blocks and the state roots are identical. The fix is a provable
no-op on a healthy chain. That is scenario 3 of the proof, and it is the
regression that protects the relaunch.

## 2. The guard: the requirement stands, the panic does NOT

The brief asked for the `debug_assert_eq!` in `close_epoch` to become an
unconditional `assert!`, so it would survive into the release binary
(`[profile.release]` sets `overflow-checks` but not `debug-assertions`, so
today it is simply not there).

**That was refuted, and the refutation is correct.** Untrusted input can drive
that assertion, so an unconditional panic would be a remotely triggerable halt:

`apply_slashing_evidence` sets `rec.slashed = true` and `rec.exit_epoch = epoch`
the moment a valid `SlashingEvidence` transaction is applied — MID-EPOCH.
`duty_roster_at` filters on exactly that predicate, so the roster's INDEX SET
shrinks between one block of an epoch and the next. Votes admitted at step 8
against the 64-member partition are then dropped by the 63-member partition at
the boundary — legitimately, by the rule as written — and the counts differ.
Anyone who can get valid equivocation evidence included can cause it.

What ships instead: the site carries an unconditional, NON-fatal detector —
present in release, no `cfg` — that emits a structured diagnostic (closing
epoch, vote counts, delta) plus a counter. Untrusted input can make it FIRE, so
it must not be fatal; but production must be able to SEE this divergence, and
today it cannot. The `debug_assert_eq!` and a test pinning the slashing
divergence stay alongside it.

The coverage guard in the same function, which untrusted input cannot drive,
DID become an unconditional `consensus_invariant!`.

## 3. Fork choice is NOT patched — but NOT for the reason we first gave

The first explanation on this branch was that fork choice is latched inside the
justified subtree: `head()` starts at `state.finality().justified.root` and
walks only downward, so a node that justified a point on its own branch can
never select a block outside that subtree. A comment in `engine.rs` (commit
`b96a633e`) states this as fact.

**It was measured and it is FALSE.** In both experiments — the in-process test
and the 8-node devnet — nothing beyond genesis was ever justified: `just=e0`,
`fin=e0`, on both sides. The justified checkpoint IS genesis in both nodes, and
both branches are children of it in both engines. The downward walk sees both
branches perfectly. The latch was never engaged.

**The real mechanism is a fourth one, and it is WEIGHT asymmetry.**
`forkchoice_head` (`engine.rs:1229-1238` on this branch) passes
`&self.state.active_validators()` — the stake table of the node's OWN head
state — into `lmd_ghost_head`. And `close_epoch` does
`rec.staked_sat += payout.operator` (`transition.rs:2678` and `:2762`) with
`credits: u64::from(attested)`. So every epoch
boundary inflates exactly those validators that participated on the branch that
node applied. Measured at 8.27%. Same blocks, same DAG, same anchor, opposite
winner: each node weighs its own branch more heavily.

The block does not die anywhere. `blocks_known=137` against `height=89` — 48
blocks received, stored, never selected — with `behind_by_slots` 0-2. It arrives
and fork choice does not pick it.

Why we still do not patch fork choice or the stake table: with n=4, where the
committee is everyone and `NotInCommittee=0`, the network heals through a
120-slot fork DESPITE the weight bias — live attestations dominate the 8.27%.
The boundary between healing and not healing is the COMMITTEE, not the fork
depth. So restoring attestation flow may be sufficient on its own, and
rewriting the fork-choice stake table would be a far deeper consensus change.
The deciding measurement is the n=8 arm against the corrected binary; it is
recorded with the proof scenarios.

Worth recording, because it is the same class: `state.active_validators()` is
`consensus_roster_at`, so fork-choice WEIGHT is coupled to the leak as well.
Committee membership is decoupled from stake by the fix in section 1; weight is
not, and deliberately is not being touched today.

Walking down from the justified checkpoint remains correct LMD-GHOST
regardless, and forcing fork choice outside the justified subtree would trade a
liveness bug for a safety bug.

## 4. What the flag day still is

`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` stays armed, with its tripwire. Item 1
is what makes keeping it armed safe: before it, the flag day fired straight
into the partition bug.

## 5. Known debts, deliberately not paid today

**The slashing half of the roster split.** Removing the pre-shuffle filter
closed the LEAK half: the leaked and unleaked rosters now carry the same index
set whatever the leak does. It does NOT close the slashing half, because there
the index set changes through committed membership, not through stake. A
mid-epoch slash still re-partitions the epoch and drops the votes admitted
before it. **This is live on mainnet today — it is not behind the epoch-1400
gate.** The fix is to freeze the epoch's roster at its first slot, which is a
consensus rule change; on a coordinated relaunch it would need no flag day, but
it does need proof, and it is not proven today.

**Fork-choice weight is still coupled to the leak.** `forkchoice_head` passes
`&self.state.active_validators()`, which IS `consensus_roster_at`. Committee
MEMBERSHIP is decoupled from stake by section 1; WEIGHT is not. Deliberately
untouched today — rewriting the fork-choice stake table is a far deeper change.

**The 8-node devnet cannot exercise section 1 at all.** It reaches epoch ~3 and
`consensus_roster_at` returns the unleaked roster while `epoch < 1400`, so the
roster split never operates there. A green n=8 run is NOT evidence for the
roster unification. The only proof of section 1 that exists is the in-process
test with its mutation switch.

## 6. The acceptance criterion as first written is unsatisfiable

The proposed criterion was "the divided n=8 arm must come back CONVERGED". It
cannot, and not because anything is broken.

`MIN_QUORUM_DENOMINATOR` is 1/2 of unleaked active stake, and the constant's own
documentation gives the consequence: the condition for `p < 1/2` is `3p >= 1`,
i.e. **`p >= 1/3`**. A set holding at least a third of the original stake still
justifies on its own. That is the designed behaviour and the residual the
founder accepted when he chose 1/2 over 3/4 (bounding divergence to at most
three disjoint one-third sets, rather than making the justified root unique).

The divided arm was 4 against 4. Each half holds 50%, and 50% >= 33.3%, so each
half justifies its own root — with the corrected binary, with the broken one,
with any binary. And since the floor is prophylactic rather than curative, once
justified each half stays anchored there. Reading that DIVERGED as "the weight
fix failed" would be a wrong conclusion drawn from an experiment that has only
one possible outcome.

The criterion that does discriminate: the minority must be **below 1/3**. In
n=8 the first split the floor actually blocks is **6 against 2** (25%), and the
test is that the pair fails to justify its own root and is reabsorbed. The 4/4
arm still has a use, but its question is "do both halves weigh with the same
ruler", not "do they converge".

## 7. Where the un-gated seed change came from

The removal of the `seed_for_epoch` flag day was an instruction from the
integration coordinator, on the premise that a coordinated stop makes a flag
day unnecessary. **The premise was wrong**: boot replay re-validates the state
root, so a new fold rule does not match the historical log. If the relaunch
preserves history, that gate has to come back. The origin of the fault is that
instruction, not the developer who carried it out.

The coordinator's recommendation to the founder is to preserve history and gate
both rules, on an argument worth recording because it is the strongest one:
the chain is split across 12 branches, so a new genesis forces a choice of
which branch's balances become the opening balances — a permanent and
unauditable choice — whereas preserving history keeps it reversible.

## 8. Open, not closed

- Severity of the mid-epoch slashing divergence: NOT assessed. The dev who
  found it stalled before answering.
- Formal coverage statement for the item-1 tests: NOT obtained, same reason.
- Fork-choice weight fix: design confirmed (snapshot the ROSTER per checkpoint,
  not the CommittedState — `lmd_ghost_head` already takes `&[Validator]`, so
  there is no replay and the 22.2x stands), but NOT written. It changes which
  head an honest node picks and needs the founder's explicit go.
- `b96a633e`'s justified-latch comment is on `pmo10/particao-repro`, not on this
  branch. Left as a noted debt.
