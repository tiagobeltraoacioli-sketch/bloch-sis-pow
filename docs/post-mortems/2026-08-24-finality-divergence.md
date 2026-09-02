# 2026-08-24 — three nodes finalized one epoch under three roots

**Status: settled.** This document supersedes both accounts that were in the tree
on 2026-09-01. Where it disagrees with a comment, a commit message or an audit
section, this document is the one that was reproduced.

Written 2026-09-01. Evidence: `crates/bloch-pos-committee/src/prova.rs`
(scenario 0, added by this work), the real mainnet block logs at
`/private/tmp/mainnet-scan` (30,578 blocks, epochs 0–1608) and
`/private/tmp/mainnet-scan-n56` (15,255 blocks, epochs 0–1105), and the commit
record of 2026-08-21 → 2026-09-01.

---

## 1. The one-paragraph account

Mainnet was at roughly **epoch 986**, in a long stall. `FinalityState::process_epoch`
measures the two-thirds test against a **leak-adjusted** denominator: stake that
the inactivity leak has eaten is subtracted from the very total the quorum is
compared to, and before 2026-08-25 the leak accumulator had exactly one write
path (`+= bite`), no decay and no floor. A node that could hear only a handful
of the sixty-four counted the rest as absent; the absent leaked; the denominator
walked down until it fitted **inside the minority that node could still hear**;
and that minority justified, then finalized, its own branch. Three partitions
did this independently and simultaneously, so one epoch acquired three finalized
roots, and because the leak never came back down, no quantity of arriving blocks
could reunify them. There was no bug in the finality code and no disagreement
about any rule. **Divergent finality was a consequence of the partition, not an
independent fault.**

The mechanism has a name in this repo: the **denominator ratchet**.

---

## 2. It is reproduced, not argued

`prova::tests::s0_three_partitions_finalize_three_different_roots_at_the_same_epoch`.
Three disjoint partitions of 4 validators out of 64, each driven through the real
`FinalityState::process_epoch`, no mutation switch touched:

```
INCIDENT (s0): 3 disjoint partitions of 4 of 64 validators (6.25% each) EACH
finalized checkpoint epoch 25 at epoch 26, on 3 DIFFERENT roots
([e0,19], [e1,19], [e2,19]), after the leak destroyed 92.2% of network stake.
No mutation switch was touched: this is the arithmetic a shipped binary runs,
because LEAK_RECOVERY_ACTIVATION_EPOCH is u64::MAX.
```

The `92.2%` independently reproduces the figure recorded in
`params.rs` for the same scenario, from a fixture written without reference to it.

The companion `s0_cure_the_denominator_floor_stops_all_three_partitions` opens the
two flag-day gates and reruns the identical three partitions: **none of them
finalizes, ever**. So scenario 0 is not a test that merely cannot fail.

Contrast the *shape* of the two failures, which is the clearest single reason
they are not the same incident. Scenario 0 ends with three finalized roots.
Scenario 1 — the roster split, now passing — asserts `left_justified == 0 &&
right_justified == 0`: under that defect the two nodes justify **nothing at
all**. The roster split is a liveness failure that stops the chain. It cannot
produce two finalized roots, because it cannot produce one.

### How much stall it takes

Exact replica of the `process_epoch` leak arithmetic, for a node that can hear
only `k` of 64:

| k | share | first epoch it manufactures a false quorum | stake destroyed |
|---|-------|------------------------------------------|-----------------|
| 1 | 1.6% | 28 | 97.8% |
| 2 | 3.1% | 27 | 95.8% |
| 4 | 6.2% | **25** | 91.4% |
| 8 | 12.5% | 22 | 81.3% |
| 16 | 25.0% | 20 | 65.3% |
| 32 | 50.0% | 14 | 26.2% |

**One node alone finalizes after 28 epochs of unbroken non-finality.** That is not
a remote corner: the real chain's own log contains a **45-epoch** stall
(e1194–e1238), and 26 further stalls past the 4-epoch leak threshold — 28, 25,
23, 21, 19, 16, 15, 14, 14, … The chain has already spent time inside the window
in which a partitioned handful can finalize alone.

---

## 3. The other account, and why it is not a cause of this incident

The competing explanation is the **roster split**: `committees::epoch_committees`
used to filter `effective_stake > 0` *before* its Fisher-Yates shuffle, and a
shuffle is length-dependent, so a 64-element list and a 63-element list are not
"the same permutation minus one element". A leak-applied roster with one
validator at exactly zero therefore partitioned differently from the unleaked
roster, and honest attestations admitted by a block were dropped at the boundary
tally.

**All of that is true. It is also a real defect, it was really found, and it was
really fixed** — `b0300409`, 2026-08-24 19:50, which deleted the filter.
`prova.rs` scenarios 1–4 are its proof and they are worth keeping.

It is nevertheless **not the mechanism of the 2026-08-24 divergence**, and the
person who found it said so in the commit that announced it. `45f88edd`,
2026-08-24 19:00:

> **WHY IT IS INERT TODAY:** `consensus_roster_at` returns the unleaked roster
> while `epoch < LEAKED_ROSTER_ACTIVATION_EPOCH = 1400`. **Mainnet is at ~e986,
> so both paths are byte-identical right now.** At e1400 the gate binds and the
> split opens on the first block of that epoch, on all 64 nodes at once.

The leak did not reach the duty roster until epoch 1400 (armed 2026-08-24 02:14,
bound 2026-08-29 10:51 UTC). At epoch 986 the leak-applied and unleaked rosters
were byte-identical, so the length-dependent shuffle had nothing to be
length-dependent about. **A rule that is provably a no-op cannot be the cause of
a divergence that has already happened.**

So the two accounts were never competitors, and the audit's framing of them as
rivals was the error:

| | roster split | denominator ratchet |
|---|---|---|
| real defect | yes | yes |
| in force at epoch 986 | **no** — gated to 1400 | **yes** — ungated |
| explains three roots at one epoch | no (it is a liveness failure: votes get dropped, nothing justifies) | yes, and quantitatively |
| fixed | yes, 2026-08-24 19:50 | **no** — mitigation shipped, gated inert |
| has a working regression proof | yes, as of this commit | yes, as of this commit (`s0`) |

The roster split is a **prospective** finding about a flag day that was, at the
time, 414 epochs in the future. It is a correct and important finding. It is not
this post-mortem's subject, and it should stop being cited as one.

`docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` §1.3 predicted this exact misattribution
("na hora do incidente alguém vai atribuir errado") and listed the roster
unification as **not** behind the gate that matters. It was right and it was not
read.

---

## 4. Verdict on the `prova.rs` harness

**It was measuring nothing, for eight days. It is repaired, not retired.**

### What was wrong

`prova.rs` was created at 22:55 on 2026-08-24 — **three hours and five minutes
after** the filter it exercises was deleted from production at 19:50 — on a
branch where the filter still existed, and merged in afterwards without a rerun.
Its mutation switch, `prova::mutation::PRE_FIX_FILTER`, selected between two
calls:

- ON: `epoch_committees(seed, epoch, leak_applied_roster)` — described in a
  comment as "not a re-implementation of the broken code, it **IS** the broken
  code: today's production function, called on today's production input";
- OFF: the same function with stakes normalised to 1.

Once the filter was gone, `epoch_committees` stopped reading `effective_stake`
at all, so both arms computed the **identical** partition. The mutation was a
no-op. Five tests went red, and their assertion messages — written to be loud —
announced that the analysis was refuted:

> *"different zero-sets produced the SAME step-8 partition — the length-dependent
> shuffle is not the mechanism and this analysis is wrong"*

That message is accurate about what the harness observed and wrong about what it
means. This is **static-reference rot**: a fixed reference to code that moved.
The harness was reporting, correctly, that it could no longer reach the defect it
existed to reproduce — and the report was indistinguishable from a refutation.

`grep -rn PRE_FIX_FILTER --include='*.rs'` returns matches in exactly one file:
`prova.rs` itself. It never reached production. The switch production actually
reads is `params::rehearsal::RESTORE_ZERO_STAKE_FILTER`, which `prova.rs` never
touched.

### The repair

One line, in `partition_step8`: the BROKEN arm now sets the production switch
(through an RAII guard, so a failing assertion cannot leave the consensus rule
mutated on the thread) before calling the production function. **No assertion was
weakened, no test was deleted, no expected value was edited.** All five go green:

```
test prova::tests::s1_disease_two_nodes_diverge_and_the_chain_never_finalizes_again ... ok
test prova::tests::s2_mutation_restoring_the_pre_fix_filter_breaks_the_cure ... ok
test prova::tests::s3_mutation_the_comparator_bites_one_zero_stake_validator ... ok
test prova::tests::s4_accrued_leak_plus_the_reset_restore_the_quorum_denominator ... ok
test prova::tests::s4_mutation_the_pre_fix_filter_destroys_the_quorum_again ... ok
```

The `#[ignore]`d `pending_dev_a_production_membership_is_leak_invariant` — ignored
on the grounds that it "is RED on this branch by construction — the filter is
still there" — has been un-ignored and renamed
`production_membership_is_leak_invariant`. It passes. The filter had not been
there for a week. **While that `#[ignore]` stood, the single assertion that could
have detected the rest of the file going stale was the one assertion never run.**

### Why repaired rather than retired

`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` is **armed and bound**. The leak now does
reach the duty roster on mainnet. Reintroducing the pre-shuffle filter today
would be a live consensus split across 64 nodes, not a latent one. Scenarios 1–4
are worth more now than when they were written; they simply had to be pointed at
the code.

### The process finding, which is larger than the bug

This repair has now been made **five times**:

| commit | date | branch | reached `main`? |
|---|---|---|---|
| `a56e0b37` | 08-25 00:11 | — | no |
| `5ff4e64c` | 08-25 08:38 | — | no |
| `2896099d` | 08-30 06:25 | `recon/coherence-core-20260901` | no |
| `020771ad` | 08-31 20:14 | `integ/validator-opening` | no |
| this commit | 09-01 | `forense/incidente-20260824` | **pending** |

Three independent agents rediscovered the same rot on 08-25, 08-30 and 08-31,
each fixed it on a branch, and none of the fixes landed. The audit of 08-31
reported the five red tests as a fresh discovery six days after `5ff4e64c` had
already diagnosed them in full. **The recurring defect is not the harness; it is
that a fix on a branch is not a fix.** If this commit also fails to reach `main`,
a sixth agent will rediscover it, and the estimate of how long that takes is one
week.

`2896099d` solved it more cleanly than this commit does — it made
`prova::mutation::PRE_FIX_FILTER` a re-export of `RESTORE_ZERO_STAKE_FILTER` and
deleted the branch entirely, so that exactly one switch exists. That is the shape
to land. This commit keeps the two-switch form because it is the smaller diff
against `main` and the point of the hour is to make `main` honest.

---

## 5. What is live today

**The mitigation is shipped and it is not in force.**

`2f477fa2` (2026-08-24 19:28) added two corrections: the leak accumulator can now
come back down (`INACTIVITY_LEAK_RECOVERY_QUOTIENT`), and the quorum denominator
has a floor (`MIN_QUORUM_DENOMINATOR_NUM/DEN = 1/2`). Both are gated behind
`LEAK_RECOVERY_ACTIVATION_EPOCH`, which is `u64::MAX` at `params.rs:597`. The
gate is correct — the leak accumulator is committed into the state root, so
applying new leak rules to historical epochs makes a node compute a root the
headers do not carry and stops its replay dead. But the consequence is exact:

> **Every epoch any real chain can reach takes the unfloored, leak-adjusted
> branch. The arithmetic mainnet runs today is the arithmetic of 2026-08-24.**

This is pinned by `prova::tests::the_quorum_floor_is_shipped_but_not_in_force`,
which fails the day somebody arms the gate and tells them what changed meaning.

Arming it is the founder's decision and is **not** taken here. What arming would
buy is measured, not asserted: with the floor at 1/2, a set must hold at least a
third of the original stake to be rescued by the leak, so all three 4-of-64
partitions of scenario 0 stop finalizing. What it would **not** buy is a unique
root — a floor of one half admits at most three pairwise-disjoint sets of exactly
one third each. It bounds the divergence to *at most three ways*. The founder
chose 1/2 on 2026-08-24 with that residual in front of him, reaffirmed it on
2026-08-25 after a PMO agent changed it to 3/4 unilaterally, and
`finality::tests::the_quorum_floor_is_the_one_the_owner_chose` pins it. Do not
edit that test.

### What the live chain actually shows

From node A's own 30,578-block log:

| | epochs with blocks | finality advanced | stalls > 4 epochs | longest stall |
|---|---|---|---|---|
| before e1400 | 1,213 | 839 (69%) | 27 | 45 epochs |
| after e1400 | 209 | 206 (**99%**) | **0** | — |

The leak only bites after four consecutive epochs of non-finality. **There has
been no such stall since the e1400 flag day, so the ratchet has had no fuel since
then.** That is the honest reason the chain is healthy right now: not that the
ratchet was fixed, but that it has not been fed.

Node A and node B agree **byte-for-byte** on `parent`, `state_root`, `body_root`,
`justified_root` and `finalized_root` at all 15,255 slots they share. Node B is
simply 503 epochs behind. There is no live fork between these two nodes, and on
node A's log the finalized root never returns to a previously abandoned value
across 1,047 changes.

State the limit of that last observation, because it is easy to over-read.
`Store::rewrite` replaces the whole block log when a reorg adopts a different
branch, so a rewind that happened and was then reorged away leaves **no trace in
the log**. "No rewind in node A's log" therefore means *no rewind on the branch
node A currently holds*, not *no rewind ever occurred*. That is exactly the gap
open item 3 asks to close with a test, and it is why two agreeing logs are
reassuring rather than dispositive.

---

## 6. What to tell an integrator about finality today

Say this, in this order, and do not soften it:

1. **Finality on Genesis-4 is Casper FFG with a leak-adjusted quorum denominator
   and no floor in force.** Two thirds is two thirds *of the stake the node still
   counts as live*, not of the registry.
2. **Therefore a finalized checkpoint is not, today, a unique global fact.** If
   the network partitions and stays unfinalized for about 25–28 epochs
   (**6.7 to 7.5 hours** at 32 slots of 30 s), each side can finalize its own
   root, and nothing in the protocol reunifies them afterwards. For scale: the
   real chain's longest observed stall, 45 epochs, is **12 hours** — past the
   threshold for a partition of any size. The safety argument in
   `finality.rs`'s module header — "two disjoint ≥2/3 quorums out of one 3/3
   total — impossible" — is a statement about **one node's** view. It does not
   hold across nodes with different leak ledgers, and that module header should
   be corrected.
3. **The mitigation exists, is reviewed, and is switched off.** It is one
   constant away and arming it is the founder's call. When armed it bounds
   divergence to at most three ways; it does not make the root unique. Unique
   finality needs a floor above 3/4, at the price of never recovering from an
   outage of more than half the stake.
4. **What actually protects a deposit today is confirmation depth plus a
   liveness check, not the finalized flag.** Concretely: credit on finalized
   *and* on the chain having finalized without interruption for the preceding
   ~30 epochs. A stalled chain is the dangerous state, not a slow one. The
   observable is free — `getchaininfo`'s finalized epoch advancing every epoch.
5. **Do not offer a settlement guarantee that rests on finality uniqueness**
   until `LEAK_RECOVERY_ACTIVATION_EPOCH` is armed, and even then state the
   three-way residual. The current draft of
   `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` cites the
   epoch-986 narrative; it needs to cite this document and item 2 above.

---

## 7. Open items, in priority order

1. **The live leak ledger has never been measured, and it should be, before any
   settlement guarantee cites the denominator.** A header-level replay of the
   real log — applying `finality.rs`'s leak arithmetic to the block-carried
   attestation sets, assuming 64 equal-stake validators — drains every validator
   to zero by about epoch 1000. The chain visibly contradicts that: it finalizes
   206 of 209 epochs after e1400, which a zero denominator forbids. So one of
   that model's assumptions is wrong — most likely that `EpochVotes::active_set`
   is the full 64-validator registry at constant stake. **The discrepancy is the
   finding.** Nobody in the tree can currently say what fraction of the
   denominator the leak is holding, and since recovery is gated off, whatever it
   holds it holds permanently. Instrument `process_epoch` or read the committed
   `LeakRecord`s and publish the number.
2. **`prova.rs`'s module documentation still describes the defect in the present
   tense** ("`epoch_committees` filters `effective_stake > 0` **before** its
   Fisher-Yates shuffle"), which has been false since 2026-08-24 19:50 and
   contradicts `committees.rs`'s own present-tense comment saying the opposite.
   Both are at HEAD. Not fixed in this commit, which changes behaviour only;
   flagged so it is fixed deliberately.
3. **Finality is not a latch across a reorg (audit F2).** `Engine::do_reorg`
   adopts an ancestor's state unconditionally, with no comparison of incoming
   against outgoing finalized; a downward move is not even logged; fork choice
   walks from *justified*, never from *finalized*. No ratchet-shaped test exists
   in either crate. This is a **third**, independent way to get "one epoch, more
   than one root", it is live, it is behind no gate, and no source in the tree
   connects it to 2026-08-24 — which is exactly the state the roster split was in
   before somebody checked. A test that fails when the finalized checkpoint moves
   backwards is the cheapest durable protection this repo can buy.
4. **Mid-epoch slashing still re-partitions the epoch** and drops the votes
   admitted before it. Live on mainnet, behind no gate. Removing the pre-shuffle
   filter closed the leak half of that divergence class, not the slashing half.
5. **The epoch-986 narrative is single-sourced to a doc comment** written the
   same evening (`2f477fa2`, `params.rs:75-84`). There is no log excerpt, no RPC
   capture and no node-state artefact for the three-root event anywhere in the
   tree. The mechanism is now reproduced and the arithmetic is settled; the
   *specific epoch number and the count of three* still rest on one person's
   recollection. If a node from that period still has its store, capture it.

---

## 8. Corrections to the record

- `docs/integration/INTEGRATION-BOOK-AUDIT-2026-08-31.md` §K frames the two
  accounts as competitors to be resolved. They are not competitors; §3 above
  settles it. §K's *diagnosis* (static-reference rot, not a live consensus
  regression) was right, and its recommendation was right.
- `finality.rs` module header, "Safety argument, in one paragraph": true per
  node, false across nodes once the denominator is leak-adjusted. Needs a
  sentence saying so.
- `9d970484` dates the quorum-floor decision to 2026-08-25; `3c8339cb`,
  `finality.rs:1358` and `RELANCA-G4-DIAS-DE-BANDEIRA.md:153` date it to
  2026-08-24. The commits are 19 minutes apart. 2026-08-24 is the majority and
  matches the commit timestamps.
- Every primary source for the incident narrative is in the list of 60 commits
  that `docs/ATRIBUICAO-2026-08-24.md` records as **made by agents and signed
  with the founder's name** — including `2f477fa2`, `45f88edd` and `49dfdd02`.
  That document's own rule applies to this one: *a commit message is a claim;
  the diff is the artefact.* Everything in §1–§5 above is backed by a diff, a
  test run, or a block log.
