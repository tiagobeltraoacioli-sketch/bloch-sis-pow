<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Genesis-4 fleet memory: the projection, and what keeps it honest

**Do not quote a date from this file without running the tool.** The numbers
below were true of the fleet on 2026-09-01 at chain slot 54,919. They are
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
saving, an "early October" date. Each was published, each was used, none was
re-checked. So this projection is not a paragraph. It is a program that reads
the fleet and goes red when the fleet stops agreeing with it.

---

## 1. The dates

Two regimes, two dates. Confusing them is the error this artefact is shaped
to prevent.

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

### Second arm: signature material removed

| regime | date | days out |
|---|---|---|
| ROLL | 2026-12-27 .. 2027-05-30 | 116.7 .. 270.6 |
| DRIFT | 2027-01-08 .. 2027-06-28 | 129.0 .. 299.2 |

Two measured effects, and they are not the same thing:

* a **one-off drop in the level** — 116.8 MiB, 17.5% of resident, at end of
  replay. At the *peak* the same change is worth only 55.3 MiB / 7.3%,
  because allocator arenas depress it.
* a **lower growth rate** — per-block growth above the 370.0 MiB
  genesis+carryover plateau falls from 10,579 to 6,410 B/block, a factor of
  0.606.

The level saving buys a fixed number of days. Only the rate saving multiplies
the date — and it multiplies it. It does not remove it.

---

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

The peak is a mid-replay transient, so it carries no growth information of its
own; the growth in the peak curve is the steady curve underneath it, plus a
constant premium. That the premium *stays* constant as the chain grows is
**modelled, not measured**, and it is the single most valuable thing left to
measure — `the_roll_date_is_earlier_than_the_drift_date_but_only_by_days`
fires if it starts to grow.

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

## 5. Inputs, with their standing

Printed in full by the tool. Summarised:

**Measured** — box RAM (31,866 MiB, `/proc/meminfo`, all 7 boxes); validators
per box (9; argv scan for `run` + `--data-dir`, 63 processes); resident per
box (10,426–11,366 MiB, sum of `VmRSS`); boot peak per validator
(1,145–1,513 MiB, `VmHWM`, kernel-retained); slots per day (2,880, exact);
the three growth intervals (11.9 / 21.8 / 27.6 MiB/day/validator); the peak
premium (86.7 MiB isolated, 13–23% fleet); both signature-arm effects.

**Modelled** — the 3,072 MiB page-cache reserve (an operator *choice*; the
boxes were observed holding 5,135–8,137 MiB of cache, so it is if anything
too low, which makes these dates *later* than the truth); that the peak
premium stays constant; that growth stays linear in slots; that a single-node
replay rate transfers to a nine-per-box fleet; that the 17.5% level saving
transfers to a fleet validator.

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
something. It falsifies the snapshot eight ways — a resized box, a tenth
validator, a cadence collapse to 24%, a fleet 250 MiB/validator fatter, marks
ten days stale, a 40-day-old snapshot, a vanished boot premium, and a
column-shifted file — and requires the named test to go red for each. If a
falsification passes green, that script fails, because a check that no longer
bites is worse than no check: it is still being counted.

Last run: **8 caught, 0 missed, control green.**

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
