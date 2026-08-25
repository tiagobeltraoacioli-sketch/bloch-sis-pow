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

**This does NOT retract the measurement that found the weight bias, and both
facts have to stand together.** That run was made against a binary built from
the seed anchor ALONE — `pmo/leak-zero`, which carries
`MIN_QUORUM_DENOMINATOR`, was not in it. Its data show the mechanism above did
not operate: `fin=e0`, `just=e0` on all eight nodes, nothing justified beyond
genesis on either side. With no floor and no accrued leak, the denominator is
the full active stake and a 50% half holds 50% < 2/3, so neither half could
justify — which is exactly what was observed. The halves shared an identical
justified checkpoint, held all of each other's blocks, and still picked
opposite winners. That is the 8.27% weight bias, measured, and it was reached
independently by an in-process experiment. The paragraph above retires the 4/4
arm as an ACCEPTANCE criterion from the moment the floor ships; it does not
touch the earlier finding.

**A consequence worth stating, because it is the accepted residual made
concrete.** Once the floor and leak recovery ship, a 50/50 partition behaves
WORSE than it does today, not better: as the leak drains the denominator, 2/3
of the floored denominator falls to 1/3 of the original stake, so each half
crosses its own quorum and justifies its own root. Two justified checkpoints at
the same epoch on different branches, and the floor is prophylactic — it does
not undo them. That is precisely the residual the founder accepted when he
chose 1/2 over 3/4 (bounded divergence, not a unique justified root), stated
here in the form an operator will actually meet it.

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

## 9. In this repository, a clean merge is not a working merge

`git merge` reported "Automatic merge went well" for two branches that both
carried the same `finality.rs` material from `9c39fb75`, and the result did not
compile:

```
error[E0592]: duplicate definitions with name `denominator_ignores_leak`
```

One branch had MOVED the function out of `process_epoch`'s doc comment (a
correct cleanup — it had been wedged inside the comment, leaving `process_epoch`
documented by two sentences about a test hook); the other left it where it was.
To git those are two insertions at two different places, so it kept both. Clean
merge, two copies, and the doc comment now attached to the duplicate.

**Compile before trusting a merge.** This is exactly the class of failure a
green `git merge` hides, and on 2026-08-24 a branch was declared delivered while
not compiling for precisely this reason.

Checked on this branch: `denominator_ignores_leak` appears once, and there are
no duplicated `fn`/`const`/`static` identifiers in `finality.rs`. That is a
grep, not a compiler — see the status section of the handover for what has and
has not actually been built.

## 10. A narrowed, not closed, gap in the duty view

`rolled_to(e)` only rolls FORWARD. If a parked attestation's epoch is behind
`self.state`'s, it returns the current state, so the roster is the current
epoch's index set rather than that epoch's. The SEED is still correctly
anchored through the ancestry walk, so membership is derived with the right
seed but a possibly-later index set.

This is strictly better than what it replaced, which used the wall epoch's seed
AND roster. Section 1 narrows it further: once membership is a function of the
index set, the only thing that moves it is activations and exits. It is not
closed. Closing it needs per-epoch roster history, which is storage work rather
than policy work — the same family as the `handle_attestation` epoch gate,
which drops attestations outside `{wall_epoch, wall_epoch+1}` before the gossip
layer sees them and so bounds how much of the two-epoch window any of this can
recover.

## 11. Correction of an attribution I got wrong

I relayed the "`Ignore` replaced a `Hold`" finding to the gossip developer as a
regression that developer had introduced, and told them to fix it. **That was
false.** The reviewer had read the developer's BASE, not their tree, because
their work was still uncommitted — blocked in the build-token queue all night.
In their tree `judge` no longer decides Hold-vs-Ignore at all: it hands the pool
a `CommitteeView` and the pool splits on exactly the right axis — `Hold` while
the target root has not arrived, `Ignore` only when the target is known and the
ancestry walk still fails. The same applies to the `release_held` anchor
finding. The finding is real, it is in the base, and the commit under review IS
the fix. Three separate reviewers read a stale tree for the same reason.

The lesson is not about that developer. It is that **an unlanded fix costs more
than it saves**: every audit run against a branch whose fix cannot compile
burns effort re-discovering something already solved, and each of those reports
reached me as fact.

## 12. Two rules about evidence, learned the hard way today

**A mutation switch read from inside a consensus function must be
thread-local.** All five were process-global `AtomicBool`s guarded by a mutex
that the two tests flipping them take and the other ~260 do not, while `cargo
test` runs them in parallel. Since they are read from inside
`epoch_committees`, `with_leak_applied` and `seed_for_epoch`, a green suite was
a property of the thread scheduler. False reds AND false greens.

**Reverting a mutation with `mv file.rs.bak file.rs` restores the original
mtime**, so cargo skips recompilation and silently runs the mutant. Always
`touch` after restoring. Same family as section 9.

## 13. The limit of mutation keys, and the frozen vector

Mutation keys only flip rules that HAVE a key. A fourth rule changed tomorrow
without a gate passes green, because no key exists for it — and that is exactly
the class of error that cost this entire operation: **three consensus changes
passed a suite of hundreds of tests because every test builds the chain with
the same binary that validates it.**

Only a **frozen vector** catches that: a `blocks.log` recorded by an earlier
binary and versioned in the repository. It works precisely because it PREDATES
the change — it does not need to know what changed. Budgeted at ~6 MB
versioned, and the 6 MB should not be the argument against it.

Mutation keys fix the known case. The frozen vector fixes the unknown one,
which is the one that always gets us. **Recommended for adoption.**

## 14. A known limit of the call-site test

`the_two_call_sites_agree_on_the_index_set_with_a_real_leak` reaches epoch 1400
by assignment (`g.epoch = epoch`), not by transitioning there — reaching it
honestly costs 1,400 epochs of blocks. The leak itself IS real, accrued through
`process_epoch` over epochs nobody attests, with a guard that fails the test if
the fold never drove anybody to zero. Recorded as a known limit, not a defect.

## 15. The gate that would have caught all of it

```
cargo test --workspace --no-run
```

It compiles every test target without running anything. It catches the orphaned
`AtomicBool` in a `#[cfg(test)]` module (which a release build compiles happily
— the failure mode that does not show), an `E0063` in an integration test, a
helper called with the wrong arity — all at once, in seconds, without executing
a single test.

**Mandatory before any commit that claims a test result.** Not one of the three
false deliveries of 2026-08-24 would have survived it. If there is CI, it
belongs there too.

Two things static reading cannot settle, so they still need this gate: method
resolution on a typed receiver, and type mismatches inside `assert_eq!`. Both
need type inference.

And a scope note worth keeping, because it changed what a headline number
meant: `#[ignore]`d tests are NOT in a plain `cargo test` run. A suite reported
as "550 passed" never included the ignored performance tests. That is scope, not
fraud — but it was read as though the benchmark had passed, and it had not run.

## 16. POST-RELAUNCH MERGE HAZARD — read before merging perf with the ballast work

Not for the relaunch. Written down now because it is the kind of finding that
evaporates and then costs a network.

**Measured with `git merge-tree`, not inspected.** An earlier hand-written list
in this section was wrong in both directions — it named `staking.rs` and
`perf.rs`, which do NOT collide, and missed `rpc.rs`, `rpc/tests.rs` and
`cold_start.rs`. Use the measurement:

```
state_root.rs   ZERO conflict hunks
engine.rs       1 conflict, end of file only - 100% #[cfg(test)] additive
transition.rs   3 conflicts, ALL inside compute_root
rpc/tests.rs    NO conflict - and it is the dangerous one
```

**The one that hurts does not conflict at all.** `rpc/tests.rs` has a call with
8 arguments on one side and 9 on the other; git auto-merges it silently and
takes down the test target where proof suite #5 lives. No conflict, no warning,
and only `cargo test --workspace --no-run` sees it.

Also measured, and it retires an earlier fear: the `compute_root` seam is
**protected by the compiler**. In the auto-merge, `state_root_with_eutxo_leaves`
and `EutxoSet::leaves` cease to exist while `ConsensusState` requires the two new
fields, so BOTH one-sided resolutions fail to compile. The silent-divergence
scenario described below is what would happen if someone hand-resolved around
that; the compiler will not let a plain merge produce it.

The single file that conflicts is NOT the file that defines the leaves. Whoever
merges sees conflicts in one place, resolves by taking a whole side, and
silently drops the ballast branch's field bindings — with no marker anywhere in
the file that defines them.

**Both naive resolutions of `compute_root` are wrong, and asymmetrically:**

- Taking PERF's line (`state_root_with_eutxo_tree(..., tree())` replacing
  `state_root_with_eutxo_leaves(..., leaves())`) silently discards two committed
  columns — `TAG_WRITTEN_OFF` and `TAG_STAKE_LOW_WATER`. **Consensus divergence
  with no compile error.**
- Taking BALLAST's line does not compile, because it calls a function PERF
  deleted.

One fails loudly, the other fails silently. Anyone resolving toward the side
that compiles will believe they got it right.

**The correct resolution is unambiguous:** both of the ballast branch's fields
in the `ConsensusState` literal, PLUS perf's new callee. Never a whole side.

**Confirm these two tests survive the merge BEFORE running anything** — they are
what catches a wrong resolution, and a bad merge deletes the safety net along
with the guard:
- `every_component_field_is_load_bearing` (`state_root.rs:2107`, extended
  `:2205-2220`)
- `pre_gate_roots_are_byte_identical_to_the_ungated_code`

**A comment that becomes a lie on merge:** the ballast branch's `params.rs`
documents its gate as "the same idiom as `LEAKED_ROSTER_ACTIVATION_EPOCH` just
above" — meaning `u64::MAX`. After the merge the one above is 1400, so the
comment is false. A comment that lies about a consensus gate is the category
that bit us three times in one day.

**The tripwire behaves correctly here:** perf renamed it asserting `== 1400`,
ballast kept the old one asserting `== u64::MAX`. Resolving toward ballast
leaves `u64::MAX` asserted against `params.rs = 1400` and the suite fails loudly,
by design. Keep both tests.

**Correction to something stated repeatedly, including by me:** the incremental
part is the **eUTXO subtree** (`EutxoSet.tree: Smt`), not the state root. Every
non-eUTXO component is rebuilt from scratch on every call, on both sides. That
is good news and it retires a risk raised earlier: since the incremental path
and the full path are THE SAME FUNCTION, a replaying node and an updating node
cannot disagree. The 22.2x still stands; the mechanism was described wrongly.

**Residue to watch:** the ballast branch's new `remove` calls exercise perf's
`node_remove` and `collapse`, which did not exist in the base — new volume and
new shapes over `collapse`, whose fold-depth arithmetic has a margin of a single
test.

**An open question nobody has examined:** `params.rs` merges cleanly, 1400 on
one side and `u64::MAX` on the other with no line overlap — but nobody has
checked whether the two flag days INTERACT: ordering between them, and a roster
moving under a ballasted-bonus write-off.

**Confirmed false positives** (do not spend time on them): `lmd_ghost_head` does
not collide (the ballast hunks land in `admissible`'s doc comment; the function
is byte-identical to base); `perf.rs` has empty intersection; `staking.rs` has
empty intersection; the eUTXO mutation sites all go through `insert`/`remove`,
which move `entries` and `tree` together.

## 17. Two suites that run nothing, and a claim that never measured anything

`replay_hotpath_perf` (6 of 6) and `replay_bench` (3 of 3) are **entirely
`#[ignore]`d**. Run the way a reviewer runs them, they report `ok` having
executed nothing at all. Two whole suites, not a few stray tests.

**Any performance claim from this project needs an explicit
`--include-ignored`, or it measured nothing.** That includes the 22.2x number
whenever it is re-verified.

Related, and the reason this matters beyond bookkeeping: a suite reported as
"550 passed" never included the performance tests. Nobody lied; everybody read
it as though the benchmark had passed.

## 18. What three quarters would have bought, and what it would have cost

**This is analysis, not a decision.** The floor is one half, by the founder's
call, re-affirmed after this argument was put to him. Recorded so that if he
ever reopens it he does not have to pay for the work twice.

A floor of 3/4 makes the minimum recoverable fraction exceed 1/2, so no two
disjoint sets can both justify — it buys **uniqueness of the justified root**,
which 1/2 does not. A rehearsal showed a partition healing under 3/4.

The price, and it is the reason the answer is not obviously 3/4: under a 3/4
floor the chain **cannot recover finality from the loss of more than a quarter
of the stake** — with 64 validators, 33 must always be reachable. A fleet that
loses half its nodes never finalizes again, at all, rather than finalizing on
two roots. That is the trade: 1/2 keeps liveness and permits up to three
pairwise-disjoint justifying sets; 3/4 guarantees one root and forfeits recovery
from a majority outage.

The measurement that would actually settle it, and which has NOT been made:
given the partition observed today, does the chain heal under 1/2, under 3/4, or
under both? Answering it needs the 6-against-2 arm against a corrected binary,
which did not run.

A warning for whoever revisits this. The commit that moved the floor to 3/4 also
installed an assertion **about the shipped constant** requiring `NUM * 4 >= DEN *
3`. Anyone reverting only the value would have found the suite red and concluded
that 1/2 was the mistake. **The guard defended the change against its own
owner.** If you change the floor, change the assertion in the same commit, and
never write a guard that makes reverting your decision look like a failure.
