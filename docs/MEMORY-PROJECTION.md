<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Genesis-4 fleet memory: the projection, and what keeps it honest

**Do not quote a date from this file without running the tool.** The numbers
below were true of the fleet on 2026-09-01 at chain slot 54,919, and the
tenancy, resident level, fork overhang, frame size and transaction volume were
re-verified against the live fleet, read-only, at slot 55,055. They are
reproduced here for reading; the artefact is:

```
scripts/fleet-memory-observe.sh          # read-only capture of the live fleet
scripts/fleet-memory-observations.tsv    # the capture, checked in
cargo run  -p bloch-memoria-projecao     # the projection, recomputed from it
cargo test -p bloch-memoria-projecao     # fails when the fleet stops matching
scripts/memoria-projecao-violacao.sh     # proves those tests actually bite
```

The reason for that instruction is the whole point of this document. Every
headline number in this programme that lacked a commit behind it has turned
out to be wrong: `0.0198 MiB/block`, `86.1% signature material`, a `367 MiB`
saving, an "early October" date, `60 MB per retained state` (wrong by ~750×,
corrected at its source in `crates/bloch-pos-node/src/engine.rs`), `10
validators per box`, `1,032 MiB mean resident`, and a `2026-09-28` wall that
would need 2.7–3.1× the measured growth rate. Each was published, each was
used, none was re-checked. So this projection is not a paragraph. It is a program that reads
the fleet and goes red when the fleet stops agreeing with it.

---

## 0. The contingency, before anything else

**Every far date in this document is a statement about an empty chain, not a
forecast about time.**

Once the resident block map is served from the log, what is left growing is
~3,174 B/block, and only ~297 B/block of that is the block index. **The rest is
the eUTXO ledger.** That slope was measured across a window carrying **1,048
transactions in 29,472 blocks** — 0.036 tx/block. Re-measured live on
2026-09-01: thirteen blocks sampled across slots 54,800–55,040 carried **zero**
transactions, and the mempool was empty.

The eUTXO term is a function of **transaction volume, not of the calendar**.
The validator-opening programme exists to add users. So the 2027 dates below
are not a prediction that the wall is far away; they are a statement that the
wall is far away *if nobody uses the chain*, and the programme's own roadmap is
designed to falsify that premise.

`the_chain_is_still_as_idle_as_the_surviving_eutxo_slope_assumes` is where this
is checked rather than hoped for. It reads frame size (which rises with
transaction volume) and tx/block out of the snapshot and goes red when either
moves. Falsified two ways in `memoria-projecao-violacao.sh`, both caught.

---

## 1. The dates

Two regimes, two dates. Confusing them is the error this artefact is shaped
to prevent.

### Headline — the fleet as it actually runs today

| regime | what it is | date | days out |
|---|---|---|---|
| **ROLL** | nine validators boot at once — the **peak** curve, paid at every restart | **2026-11-02** .. 2027-01-21 | 61.1 .. 141.7 |
| **DRIFT** | nine validators resident, nobody touching them — the **steady** curve | **2026-11-11** .. 2027-02-11 | 70.2 .. 162.7 |

Binding box in both: `139.84.201.52` (host652460), which carries the fleet's
largest boot peak (1,513.2 MiB, `bloch-n00`) and its largest resident sum
(11,366.1 MiB). Capacity is 28,794 MiB after a 3,072 MiB page-cache reserve.

**The roll date is 9.1 days earlier than the drift date — days, not weeks.**
The peak premium is a *constant* (86.7 MiB on an isolated node; 13–23% on the
live fleet), not a multiple, so the two curves run parallel instead of
diverging. A box that survives running can still die in replay.

### Contingent — if the store-backed block map ships

**This code is not deployed.** The arm below is what the measured −39.3% would
buy if it shipped and if its replay-measured residual transfers to the live
regime, which is *modelled*:

| regime | date | assumption |
|---|---|---|
| ROLL | 2027-03-04 .. 2027-11-02 | residual transfers unscaled (conservative) |
| DRIFT | 2027-03-28 .. 2027-12-29 | residual transfers unscaled (conservative) |
| ROLL | 2027-09-12 .. 2029-01-21 | residual also scales by the 1.99× regime gap |

A previously circulated headline put this arm at "2027-04-25 … 2027-06-15".
That window sits inside the conservative band above, but it is far narrower
than the evidence supports, and it was computed against a **retired** baseline
(the discredited `~2026-10-08` sketch, which rested on `0.0198 MiB/block`).
Against the correct slot-denominated baseline the improvement is real and the
precision is not.

### A date this document does **not** publish: 2026-09-28

Landing on 2026-09-28 requires 62.4 (ROLL) to 71.7 (DRIFT)
MiB/day/validator — **2.7× to 3.1× the live median of 23.0**. No measurement in
this programme supports it, and it is not reproducible from the snapshot. It is
recorded here so it stops circulating.

## 2. The denominator is slots, not blocks

This is the correction that matters most, and it arrived late enough to have
nearly been missed.

Measured **per block**, interval by interval on a real log, growth comes out
at 0.005, 0.032 and 0.011 MiB/block — a sixfold disagreement. Any two
endpoints would have produced any one of them, which is precisely what the
earlier two-point slopes did. Measured **per slot**, the same intervals are
far steadier. Between h=10,000 and h=15,000 the chain burned 21,187 slots to
produce 5,000 blocks, and memory followed the slots.

Slots arrive at **2,880/day on the wall clock** whether or not anybody
produces a block in them (`SLOT_DURATION_SECS = 30`, asserted at
`crates/bloch-pos-node/src/main.rs:914`). This chain's block cadence has run
anywhere from 24% to 100% of slots. Denominating in blocks folds a variable
that has moved by 4× into the rate; denominating in slots removes it, and the
date becomes a function of the calendar alone. That is normally a *tighter*
and more trustworthy projection, not a looser one.

Re-denominating moved the date **later**: from the retired mid-October sketch
to early November. Two things did that — dropping the discredited
`0.0198 MiB/block`, and taking the block cadence out of the rate.

The block cadence is therefore no longer an input.
`the_date_does_not_move_when_only_the_block_cadence_moves` proves it
structurally: halve the cadence in the snapshot and the dates must not move by
a second. It is still *recorded*, as a **tripwire** — it is the variable that
was hiding, and if it moves again that is the live natural experiment which
confirms or refutes the slot hypothesis.

---

## 3. Peak and steady are two curves

RSS is **not monotone across a replay**. It climbs while the block map fills,
peaks around h≈17,000–20,000, then *falls* before the replay ends: `VmHWM`
762.0 MiB against `VmRSS` 709.6 at h=20,000 and 675.3 at the end. So
`/usr/bin/time -v`'s maximum answers a different question from "how much is
resident once the chain is loaded", and the two answers enter the projection
at different moments.

(Run-to-run these levels move by a few tens of MiB while the *shape* does not:
the run anchored in §3b peaked at `VmHWM` 761.9 and ended at `VmRSS` 666.1.
Quote a run, not a number.)

The peak is a mid-replay transient, so it carries no growth information of its
own; the growth in the peak curve is the steady curve underneath it, plus a
constant premium. That the premium *stays* constant as the chain grows is
**modelled, not measured**, and it is the single most valuable thing left to
measure — `the_roll_date_is_earlier_than_the_drift_date_but_only_by_days`
fires if it starts to grow.

---

## 3b. The reconciliations

### The end-of-replay model was wrong by 1.8× because it omitted the chain

The model predicted 344–375 MiB at end of replay. Measured: **666.1 MiB**. The
peak/end distinction accounts for only ~96 MiB of a ~300 MiB gap. The gap is
now closed, and it was not a modelling error in the state term — it was an
omitted term:

```
pre-replay VmRSS                       317.2 MiB
+ what the replay retains              348.9 MiB   (identical in both runs)
= end-of-replay VmRSS                  666.1 MiB   exact
```

The model's 344–375 MiB **brackets the pre-replay footprint** (VmRSS 317.2 /
VmHWM 350.2), not the end-of-replay one. It costed the state correctly and
omitted the chain the replay keeps resident. Three independent checks agree
that the omitted 348.9 MiB *is* the block map:

* 348.9 MiB over 29,377 blocks = **12.5 kB/block**, against a measured frame
  of 13,888 B/block — 90% of the log, held in RAM.
* the store-backed change saves **410.4 MiB** (1,045.6 → 635.2) on a 410 MB
  (391 MiB) log — 105% of the log's own size. The saving *is* the log, plus
  the per-block struct overhead of holding it.
* baseline slope 0.01718 minus store-backed residual 0.0031 MiB/block =
  **14.4 kB/block removed**, against a 13,888 B frame — one frame per block,
  plus 4% overhead.

**Hypothesis confirmed.** The model omitted the chain; the store-backed change
removes exactly the term it omitted.

### The two slopes do not contradict — and their difference is the finding

`0.001234` and `0.01718` MiB/block disagree 14×, and averaging them would be
meaningless. Confirmed, not overturned:

* the four measured within-process intervals are 0.00506 / 0.03212 / 0.01050 /
  **0.00000** MiB/block. `0.01718` sits inside that range; `0.001234` is a
  two-point slope dragged toward zero by the interval that measures exactly
  zero, which is the `Arc::make_mut` release, not a growth regime.
* their **difference**, 14.4 kB/block, equals one block frame. That is the
  block map, and it is the only quantity here with a mechanical
  interpretation.

### Replay is not the regime the fleet lives in

This is the correction with the largest effect on the date, and it points the
*safe* way:

| regime | per-block growth | how measured |
|---|---|---|
| static replay | 17,592 B/block | `0.01718 MiB/block`, isolated box |
| **running validator** | **8,837 B/block** | fleet lineage (8.63 KiB/block) |
| corroboration | +23.0 MiB/day median | 18 of 18 live validators positive |

A replay costs **1.99×** what a running node costs. Two independent live
methods — fleet lineage and production drift — agree to ~6%. Dating the fleet
from a replay slope would have halved the time that actually exists.
`a_replay_slope_is_never_used_to_date_the_live_fleet` pins this.

---

## 3c. The 20-cell run did not find "no wall" — it re-measured the transient

A 20-cell sweep reported `slope_none +5.470 ± 2.640 kB/block (R²=0.349)`, a
non-monotone level series `454.3 → 471.6 → 601.8 → 654.4 → 549.8 MiB`, and
concluded *"no chain-growth wall is visible between 5,000 and 29,377 blocks."*
That conclusion is **not supported by its own data.** Arbitrated, not averaged:

**1. Its marginal costs are the within-process curve, re-measured.**

| interval | within-process (kB/block) | 20-cell (kB/block) | agreement |
|---|---|---|---|
| 1 | 5.181 | 5.18 | 0.0% |
| 2 | 32.891 | 32.92 | 0.1% |
| 3 | 10.752 | 10.36 | 3.6% |
| 4 | 0.000 | −4.53 | the release event |

Three consecutive intervals reproduce to under 4%. These are not two
independent results in conflict; they are **one result, measured twice**.

**2. Its non-monotonicity has a named, measured cause.** RSS peaks around
h≈17,663–20,000 and falls before the replay ends, because holding a state
across `REORG_STATE_WINDOW` makes the eUTXO `Arc` shared and the next mutation
copies the whole 452,726-entry map — 52.4 MiB, 892 times. The release is
**104.8 MiB in one 50 ms sample**. The 20-cell run's full-height point sits
**104.6 MiB** below its peak point. Same event, same size.

Each cell is one replay stopped at a different length, so *where in the
transient it stopped* varies with chain length by construction. Regressing
level on length across those cells regresses across the transient. R²=0.349 is
the contamination, not the absence of a wall.

**3. The run's own structure proves the contamination.** Its only clean number
is the **difference** between arms (`+4.103 ± 0.675, R²=0.9248`). A difference
is clean precisely when the contaminating term is **common mode** and cancels.
If the non-monotonicity were a property of chain length, it would not cancel in
the difference. It does. So the run has demonstrated that a large common term
sits in both arms — which is the transient — and then read the residue as
evidence of no growth.

**Verdict on the three questions.**

1. **Different quantities.** The cells measure end-of-replay RSS as a function
   of *where in a non-monotone transient the replay stopped*. The fleet
   measures resident growth of a running node. They are not comparable, and
   the cells do not measure what they claim to.
2. **The date charges the live regime.** Boxes die from resident validators and
   from simultaneous boots, never from a replay's stopping point. DRIFT and
   ROLL are both properties of running processes.
3. **Believe the live measurement.** Under a null of no growth, 18 of 18
   validators drifting positive is p ≈ 3.8 × 10⁻⁶. Two unrelated methods agree
   to 6%. The lab series' contradiction has an identified mechanism with a
   fingerprint match. The "no wall" reading requires all of that to be
   coincidence.

The run is nonetheless **right about one thing, and it matters**: block height
is a poor regressor, block density per slot varies 4×, and neither slots nor
epochs fully linearise. That is the same non-linearity recorded in §4 as the
dominant source of the range's width. It widens the band. It does not remove
the wall.

---

## 4. What sets the width of the range

| source | days |
|---|---|
| the growth curve's own **non-linearity** | 80.6 of an 80.6-day band — **dominates** |
| the page-cache reserve, if halved | 6.2 |
| best box vs worst box | 5.1 |

The three measured intervals are 11.9, 21.8 and 27.6 MiB/day/validator. They
differ by 2.3× **and they are rising**. That spread — not measurement error,
not the reserve, not the box variation — is essentially the entire width.
Narrowing these dates means measuring a fourth interval, not doing more
arithmetic on these three.

Because the intervals rise, the binding arm is a **lower bound on the rate**,
which makes the near date an **upper bound on the time available**.

### How far past the evidence this reaches

The chain is 54,919 slots old. The binding roll date is slot ~230,900 —
**4.2× the chain that exists today** — while every growth rate behind it was
measured on a log of at most ~30,600 blocks. This is an extrapolation several
times beyond the range of any measurement supporting it. That is a larger
source of error than everything in the table above, and it is *not* in the
band, because a band cannot express it.

---

## 4b. Four corrections that were handed to this programme as established

Three of them did not survive being checked. That is recorded here in full,
because the corrections were circulating as measured fact.

| claim handed over | verdict | what the fleet says |
|---|---|---|
| boxes run **10** validators, not 9; ceiling 2,879 MiB | **REJECTED** | 9 on all seven boxes, verified live 2026-09-01: `systemctl` shows `bloch-n00…n56` (step 7) and an argv scan of `/proc` returns 9 per box, 63 total. The three extra `bloch-*` units per box are socat RPC forwarders of 2–3 MiB. Ceiling stays **3,199 MiB**. |
| mean validator RSS is **1,032 MiB**, not 1,258 | **REJECTED** | 1,204.0 MiB across 63 validators; per box 10,425.7–11,366.1 MiB summed. Re-read live: 10,599–11,380 MiB, matching the snapshot to 0.1%. |
| **fork overhang is not zero** | **CONFIRMED** | `blocks_known` 34,385 − `height` 34,159 = **226** non-canonical blocks, on every box asked. |
| cadence 2,903 blocks/day; slots 2,880/day | **CONFIRMED, and not an input** | measured 2,859 blocks/day live this session, 2,826.9 in the snapshot. Slots are exact. §2 explains why the date does not read this. |

**On the tenancy claim specifically.** The brief for this work said the 9→10
change "went unnoticed and moves the ceiling by 10% — the test must bite on
that." The test *does* bite: `every_box_still_carries_the_validators…` asserts
row count per box and is falsified as case 2 of the violation script, which
catches it. But there was no 9→10 change to notice. The snapshot was right and
the correction was wrong, which is the same failure mode this artefact exists
to catch — a number asserted as measured, re-used, never re-checked — arriving
this time from the direction of the correction rather than the claim.

**On fork overhang.** It is real and it is the one term here that grows without
a bound, so it is now recorded in the snapshot and gated. It is also, today,
226 × 13,888 B = **3.0 MiB**, or 0.25% of a 1,205 MiB validator. Calling it a
dating term would misplace the risk; leaving it unrecorded would be how it
stops being 3 MiB without anyone noticing. It is therefore tracked with a
tolerance (2,000 blocks) rather than modelled in the arithmetic.

---

## 5. Inputs, with their standing

Printed in full by the tool. Summarised:

**Measured** — box RAM (31,866 MiB, `/proc/meminfo`, all 7 boxes); validators
per box (**9**, re-verified live 2026-09-01 by argv scan *and* by `systemctl`
unit names, 63 processes); mean resident per validator (1,204.0 MiB); fork
overhang (226 non-canonical blocks, 3.0 MiB); frame size (13,888 B/block);
transaction volume (0 tx in 13 sampled blocks, mempool 0); resident per
box (10,426–11,366 MiB, sum of `VmRSS`); boot peak per validator
(1,145–1,513 MiB, `VmHWM`, kernel-retained); slots per day (2,880, exact);
the three growth intervals (11.9 / 21.8 / 27.6 MiB/day/validator); the peak
premium (86.7 MiB isolated, 13–23% fleet); both signature-arm effects.

**Modelled — i.e. asserted, not measured.** Read this list before quoting any
date; it is where the dates would break first.

* the 3,072 MiB page-cache reserve — an operator *choice*. The boxes were
  observed holding 5,135–8,137 MiB of cache, so it is if anything too low,
  which makes these dates *later* than the truth.
* that the peak premium stays constant as the chain grows. Still the single
  most valuable thing left to measure.
* that growth stays linear in slots. The three measured intervals are rising,
  so linear is the optimistic reading.
* that the 17.5% signature level saving transfers to a fleet validator.
* **that the store-backed residual measured on a replay transfers to the live
  regime.** This carries the entire contingent 2027 arm. We now know the two
  regimes differ by 1.99×, so this assumption is *known* to be imperfect and
  the arm is quoted as a band across both transfer assumptions rather than a
  date. Nothing has measured a store-backed *running validator*.
* that fork overhang stays a rounding error. Gated at 2,000 blocks, currently
  226; the gate is a tripwire, not a model of its growth.

**A precondition, not a model** — the surviving eUTXO slope was measured on an
idle chain (§0). This is not an assumption that can be made more conservative
by widening a band: if the chain becomes used, the projection changes *shape*,
from a function of the calendar to a function of adoption, and no date derived
from an idle window bounds it. That is why it is a gate and a banner rather
than a term.

**Superseded** — the per-block rates (0.01473–0.01719 MiB/block) and
2,873 blocks/day. Correctly measured, wrong denominator. Kept visible because
deleting them is how they get quoted again next month.

**Discredited** — `0.0198 MiB/block` (measured on a tree lacking the boot-copy
fix; overestimates; behind the retired "early October" sketch) and
`86.1% of Engine::blocks is signature material` (the proposer signature is
32.9% of a frame; the ~90% figure counts attestations too).

### The one the fleet cannot answer for itself

It is tempting to read a growth rate off the fleet directly: 63 validators
booted at 63 different chain lengths, and `VmHWM` is free. Doing it yields
0.17–0.30 MiB/block within six of the seven boxes at r = 0.84–0.99 — ten to
twenty times any replay-measured rate — and the seventh box returns a
**negative** rate at r = −0.51.

It is not a rate. The fleet was migrated in batches, so within a box the k-th
validator to boot is *both* the k-th highest boot height *and* the one that
booted with k−1 siblings already resident competing for page cache. Boot order
and chain length are perfectly collinear within a box. The negative box is the
tell. Recorded in `Snapshot::fleet_slope_is_confounded` so nobody spends an
afternoon rediscovering it and, worse, publishing the answer.

---

## 6. Floor, never headroom

`VmHWM` is a lifetime high-water mark, so for every validator running right
now the boot peak it actually paid is already recorded, kernel-measured, at no
cost. That is why this projection can be checked against reality instead of
against a model.

It comes with one hard rule: **a mark set days ago was set against a shorter
chain.** It is a floor and never the headroom you have. On the 2026-09-01
capture the freshest mark on the whole fleet was 4,140 slots old (1.4 days);
`roll_arm_rests_on_marks_that_are_still_informative` fails past 20,160 slots
(seven days), because past that no process on the fleet has booted recently
enough to bound a boot today.

Staleness is counted in **slots**, deliberately. Counting it in blocks would
understate it by 1/cadence exactly when the chain is slow — exactly when it
matters.

**Do not restart a validator to refresh a mark.** That is a double-signing
risk incurred for a number. Measure a candidate boot on an *idle* box against
a tip-height `blocks.log` and pass it to `scripts/fleet-memory-gate.sh` as
`--peak-mib`. That script is the operational go/no-go for a specific roll;
this one is the dated projection behind it.

---

## 7. What this projection cannot do

Growth is linear in chain length — and the three measured intervals are
rising, so linear is the *optimistic* reading. **Nothing on the table makes
memory bounded.** Removing the signature term multiplies the date; it does not
move it to infinity, because what is left is still a line with positive slope.
Every improvement in flight removes a *constant factor* from a curve that
still rises forever. The date returns.

A bounded design would be **O(unfinalized + state)**, not O(chain): resident
cost set by the unfinalized suffix (85 blocks today) plus the state, with
history paged from the log. **No current workstream aims there.** That is not
a criticism of the work in flight, which is real and measured; it is the
difference between postponing a date and removing one.

And the irreducible term is not constant either. What survives every
optimisation is the **carryover eUTXO set**, and that grows with *usage*, not
with time. The validator-opening programme exists to add users. The one term
nobody can optimise away is the one the roadmap is designed to grow.

**Every way this projection is likely to be wrong points the same direction —
later than the truth.** The `VmHWM` marks it reads are floors. The reserve it
holds back is smaller than the page cache the boxes actually use. The growth
intervals are rising rather than flat. And it extrapolates 4.2× past its own
evidence. Read the dates as an upper bound on the time available, not as a
forecast.

---

## 8. How the staleness alarm works

`cargo test -p bloch-memoria-projecao` recomputes the dates from the snapshot
and fails when reality has moved them more than 7 days, when the snapshot is
more than 14 days old, when a box changes size or tenancy, when the block
cadence moves more than 0.15 blocks/slot, when no `VmHWM` mark is fresher than
20,160 slots, when the boot premium vanishes or becomes a multiple, or when
the recomputed date is already in the past. None of these re-assert a
constant; each compares a claim to a kernel-measured reading and names the box
that broke it.

Two are deliberately time-dependent. That is not a flake. A projection whose
inputs are 40 days old *is* broken, and a suite that cannot say so leaves the
staleness for a human to remember. Nobody remembered last time.

`scripts/memoria-projecao-violacao.sh` is the proof that the alarm is wired to
something. It falsifies the snapshot **eleven** ways — a resized box, a tenth
validator, a cadence collapse to 24%, a fleet 250 MiB/validator fatter, marks
ten days stale, a 40-day-old snapshot, a vanished boot premium, a
column-shifted file, **a doubled frame size, real transaction volume, and a
fork overhang an order of magnitude larger** — and requires the named test to
go red for each. If a falsification passes green, that script fails, because a
check that no longer bites is worse than no check: it is still being counted.

Last run: **11 caught, 0 missed, control green.**

### The one gate that had to be proved by mutating the code

Three of the checks guard invariants of the *arithmetic*, not of the snapshot,
so no edit to the TSV can falsify them. One of those was quietly broken.

`SIG_GROWTH_FACTOR` is a ratio of two **per-block** measurements
(6,410 / 10,579 B per block) applied to a **per-day** rate. It is the only
place a block denominator still survives inside the computation rather than in
prose, and the cadence tripwire did not cover it: the second-arm dates would
have silently mis-scaled if the cadence moved.
`the_date_does_not_move_when_only_the_block_cadence_moves` now asserts on
`roll_nosig`/`drift_nosig` as well as on the main arms.

Proved by violating it. With a cadence rescale injected into the second arm:

| test version | result |
|---|---|
| original (main arms only) | **passes green — misses the bug entirely** |
| extended (includes `*_nosig`) | **fails red**, naming the moved dates |

The mutation was reverted; the suite is 19 tests, all green.

---

## 9. Provenance of the fleet reading

`scripts/fleet-memory-observe.sh` is read-only with respect to the fleet by
construction: one `ssh` per box that reads `/proc` and curls the node's own
loopback RPC. It starts nothing, stops nothing, restarts no validator, writes
nothing on any box outside `/tmp`, and arms nothing.

Boot heights are read out of the chain's archive via `getblockbyslot`, not
inferred from wall-clock arithmetic. Slot↔time is exact (a fixed 30 s off
`genesis_time_ms`), so `started_unix` converts to a slot without error, and
the snapshot carries its own anchor error bar (`anchor_error_secs`).

Three portability traps are pinned in that script because each produced a file
that looked correct:

* `LC_ALL=C` — under a pt_BR locale `awk` emits `2826,8` and the parse fails
  days later with a message about a malformed field rather than about a locale.
* no `declare -A` — macOS ships bash 3.2, where it fails *non-fatally*,
  leaving every boot height `NA` and the roll arm silently unbounded.
* the RPC port is read as the argument *after* `--rpc-port`. Taking "the first
  five-digit argument" picks up `--listen`, which comes earlier in this argv,
  and every later probe then talks to the p2p port and finds nothing.
