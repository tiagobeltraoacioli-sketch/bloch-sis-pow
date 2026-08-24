<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The leaked-roster flag day — choosing and arming `LEAKED_ROSTER_ACTIVATION_EPOCH`

Operational runbook for activating commit `bf83f73` ("consensus: let the
inactivity leak reach the duty roster"). The code is shipped and inert behind
`LEAKED_ROSTER_ACTIVATION_EPOCH = u64::MAX`
(`crates/bloch-pos-committee/src/params.rs`). This document is the procedure
that turns it on without partitioning a live mainnet: how to choose the epoch,
in what order to roll the fleet, what "ready" means as a checkable predicate,
and what to watch afterwards. The activation diff itself sits next to this
file as `LEAKED-ROSTER-FLAG-DAY.activation.patch`, deliberately **not**
applied.

## What activates, in one paragraph

From the first boundary at which `state.epoch >= LEAKED_ROSTER_ACTIVATION_EPOCH`,
`consensus_roster_at` (transition.rs) subtracts each validator's accrued
inactivity leak before the proposer draw and the committee partition read the
roster. Validators the finality layer has already written off stop being drawn
to propose and stop holding committee seats. Measured on mainnet 2026-08-21:
seven live validators hold 6.19% of unleaked stake and blocks arrive every
~19.2 slots (~10 min against the 30 s slot), because ~94% of proposer draws
land on validators that produce nothing. The state root is untouched — the
leak values it commits (`FinalityRecord.leaked`) are committed today already;
only *who reads them* changes.

## Why this flag day is unlike a height gate

Two facts drive everything below.

**1. The epoch clock is wall time, not chain progress.** The node computes
`slot = (now_ms − genesis_time_ms) / slot_ms` (engine.rs) and
`epoch = slot / 32`. Mainnet genesis is `1786656679962` ms —
**2026-08-13 21:31:19.962 UTC** — with 30 s slots, so:

```
epoch length      = 32 × 30 s = 960 s = 16 min
epochs per day    = 90
utc(E)            = 2026-08-13T21:31:19.962Z + E × 960 s
```

The moment E is chosen, the activation instant is known to the second, and it
arrives **regardless of what the chain or the fleet is doing**. A PoW height
gate can be outrun by a stalled chain; this one cannot. An armed binary on a
half-rolled fleet does not wait — it forks the stragglers off at `utc(E)` on
schedule. Readiness is therefore a *precondition to arming*, not a goal to
chase after tagging.

**2. A restart is a replay.** The store is an append-only log; restart means
re-ingesting the 452,726-entry carryover (51 s cold state root) and replaying
every block through the full transition (store.rs). On today's chain that is
hours per box end-to-end, and it grows linearly with chain length. With ~12
boxes and the rollout serialized to protect finality, fleet-wide rollout time
is measured in days, and every added day of margin is cheap (90 epochs) while
every missing day is a partition.

One consequence worth stating plainly: the gate is `epoch < E → old roster`,
so the armed binary is **behaviorally identical to the inert one for all of
history before E**, and a replay under the armed binary reproduces pre-E
blocks exactly. That is what makes a *single* rollout safe: there is nothing a
two-phase deployment (inert first, armed second) would de-risk, and it would
double an hours-long replay bill across 12 boxes. The fleet rolls once, with
the armed binary, well before E.

## Choosing E

```
E = round_up_to_100( epoch_at_tag + 900 )
```

Derivation of the 900:

| component | epochs | basis |
|---|---:|---|
| rollout, serialized: 12 boxes × ~6 h (replay + validation) | ~270 | 3 days |
| fleet-green soak before E | 90 | 24 h, §Ready |
| decision margin at E−180 (postpone-or-proceed point) | 180 | 48 h |
| contingency ≈ 1× the plan (a box that will not come back, a re-roll) | ~360 | 4 days |
| **total** | **900** | **10 days** |

Rounding up to a multiple of 100 costs at most ~26 hours and makes the value
legible in every announcement and every log line.

Worked example: tagging at epoch 700 (≈ now, 2026-08-21) gives
`E = round_up_100(700 + 900) = 1600` → activation
**2026-08-31 16:11:19 UTC**. Tagging at 720 gives `E = 1700` →
**2026-09-01 18:51:19 UTC**.

The deadline the fleet must actually beat is the boundary that *computes* the
epoch-E roster, i.e. the E−1 → E transition at `utc(E)`; treat `utc(E−1)`
(16 minutes earlier) as the hard wall and never plan closer to it than the
180-epoch decision margin.

Do not choose a smaller margin because "the fleet is only 12 boxes". The
margin is not sized by optimism about the rollout; it is sized by the cost of
the failure mode. Too small and a slipped rollout means either a partition at
E or an emergency re-roll of every already-armed box (another full replay
round). Too large costs nothing but calendar days on a chain that is slow but
alive and finalising.

## Rollout order

Principle: **risk what the chain can afford to lose first.** A box in replay
is a box whose validators neither propose nor attest for hours. Losing a
low-stake box costs almost no quorum weight and few proposer draws; losing a
high-stake box widens the finality gap (already oscillating 2–6 epochs) and
silences most of what little production exists. So the procedure is rehearsed
on the boxes that matter least and reaches the boxes that matter most only
after it has worked several times in a row.

The unit of rollout is the **box**, ordered by the largest live stake it
hosts:

| wave | boxes hosting | live stake each | parallelism |
|---|---|---|---|
| 0 (canary) | v35 | 0.38% | one box, full soak before wave 1 |
| 1 | v63, v21 | 0.39%, 0.42% | max 2 at once, combined ≤ 1%, only while finality gap ≤ 3 |
| 2 | every remaining box not hosting v10/v7/v54/v0 | — | one at a time |
| 3 | v10, then v7, then v54, then v0 | 2.0%, 2.26%, 3.0%, 3.1% | strictly serial, v0's box last |

Per-box procedure:

1. **Pre-check.** Record `getblockcount` from this box and one reference box:
   height, slot, `finalized_epoch`, finality gap. Do not start if the fleet's
   finality gap is above its recent baseline — a restart on top of a widening
   gap compounds it.
2. **Deploy.** Swap the binary under systemd (unit drop-in, then restart the
   unit — never pkill+setsid; the unit is what guarantees Restart=always
   semantics survive). Verify the *running* process:
   `sha256sum /proc/$(systemctl show -p MainPID --value <unit>)/exe` must
   equal the pinned release digest. Hashing the file on disk is not the same
   check — a swapped file under an old process is exactly the failure it
   misses.
3. **Replay.** Wait for boot replay to finish; the node is caught up when its
   reported `slot` equals the wall-clock slot and its height matches the
   fleet head (±1 while a block is in flight).
4. **Post-check.** Head `block_id` equal to the reference box at the same
   height; the box's hosted validators attesting again; finality gap back to
   its pre-restart baseline. **Only then** move to the next box.

If a box fails to come back, stop the rollout, fix or fence that box, and
re-plan against the calendar: the remaining margin is `E − epoch_now` and it
shrinks by 90/day whether the rollout moves or not.

## "The fleet is ready" — the predicate

All of the following, simultaneously true, **no later than E − 180 epochs
(48 h before activation)**:

1. **Binary**: every box's running process (`/proc/<MainPID>/exe`) hashes to
   the pinned release digest of the armed build.
2. **Caught up**: every box reports `slot` == wall-clock slot and height ==
   fleet max (±1).
3. **One head**: `block_id` at one sampled height is byte-identical across
   all boxes.
4. **Finalising**: `finalized_epoch ≥ epoch − 6` on every box, and identical
   across boxes.
5. **Soaked**: conditions 1–4 have held for 90 consecutive epochs (24 h)
   with no box restarted in that window.
6. **Rehearsed** (before tagging, not before E): a two-node localhost devnet
   (`genesis` subcommand, `--slot-ms 500`, small E) crossed the activation
   boundary without a fork, and cadence visibly jumped. The control half, per
   the repo's own testing rule: the same devnet with an inert constant kept
   its empty slots. A rehearsal without the control proves only that the
   devnet runs.

If the predicate fails at E − 180, there are exactly two honest options:

- **Proceed anyway** — permitted only if every non-ready box is low-stake and
  the ready boxes alone hold > 2/3 of the post-leak stake (quorum survives).
  The stragglers fork off at E and are re-onboarded afterwards from a post-E
  snapshot. Cheaper than the alternative when the straggler is a 0.4% box.
- **Postpone** — new `E' = E + round_up_100(days_needed × 90)`, re-roll every
  already-armed box with the re-armed patch. This is the expensive path
  (another replay round across the fleet); the 900-epoch margin exists so
  that it is never forced by anything smaller than a real incident.

Never a third option. Letting E fire into a fleet where quorum is split
between armed and inert nodes partitions mainnet into two chains that each
finalise their own history — the one outcome with no cheap recovery.

## What to watch after E

First, the **control half, taken before E**: over the last three pre-E
epochs, record slots-per-block (expect ~19) and the finality gap (expect
2–6). Without the before-measurement the after-numbers prove nothing.

From the first boundary ≥ E:

- **Proposer set.** `proposer_index` of every new block must belong to the
  live set. One block proposed by a fully-leaked index means the gate did not
  bind on the proposing node — halt that node and diagnose before anything
  else; it is forked or mis-built.
- **Cadence.** Expect a step change, not instant perfection. Finality today
  is achieved *with* the leak in the denominator, which proves the live
  validators hold > 2/3 of the post-leak roster — so at most ~1/3 of draws
  can still land on leaked-but-not-zeroed absentees, and the floor at E is
  ≥ 2/3 of slots filled (≤ 45 s median inter-block). Success bands:
  median inter-block time ≤ 45 s in the first hour, ≤ 35 s over the first
  24 h. Reaching a clean 30 s/slot requires the residual absent stake to
  round to zero in the draw — it converges as absentees leak further (only
  during non-finality), exit, or are simply outdrawn; watch the trend, not
  the first epoch. The empty-slot rate *is* the direct measurement of the
  absentees' residual share of the consensus roster — publish it.
- **Finality.** Committees are now filled by live validators, so
  justification bitmaps should lose their holes and the finality gap should
  tighten from 2–6 epochs to 1–2. A gap that *widens* after E means committee
  membership moved against a node that disagrees about the roster — treat as
  a fork signal, not as jitter.
- **Fork tripwire.** Sample `block_id` across all boxes at slots `32·E` and
  `32·E + 31`. Any mismatch: halt the minority node(s) immediately. A forked
  node's blocks are ignored by the majority, but a halted node cannot gossip
  a competing schedule while you diagnose.

## There is no rollback

Once one post-E block exists, the schedule that produced it is consensus
history. Re-raising the constant is itself a consensus change — a second flag
day with its own rollout — and would orphan every post-E block. Problems after
E are fixed forward. This is the same asymmetry as every flag day, stated here
because the wall-clock epoch makes it tempting to think of E as a config value
rather than a cliff.

## Applying the activation patch (tag day)

The patch next to this file carries the placeholder `__ACTIVATION_EPOCH__` so
it cannot be applied thoughtlessly — unreplaced, it does not compile. It
changes exactly two things: the constant, and the inertness tripwire test
`leaked_roster_ships_inert`, which by design fails the moment the constant is
lowered and is replaced by a test pinning the armed value against this
runbook.

```sh
E=<chosen epoch>   # from the formula above, at tag time
sed "s/__ACTIVATION_EPOCH__/$E/g" docs/LEAKED-ROSTER-FLAG-DAY.activation.patch | git apply
cargo test -p bloch-pos-committee   # the armed tripwire now pins $E
```

Then record the armed values here before tagging:

| field | value |
|---|---|
| `LEAKED_ROSTER_ACTIVATION_EPOCH` | *(fill at tag time)* |
| `utc(E)` | *(genesis 2026-08-13T21:31:19.962Z + E × 960 s)* |
| release tag | |
| binary sha256 | |
| epoch at tag | |

A tag without this table filled in is not an armed release; it is an accident
waiting for `utc(E)`.
