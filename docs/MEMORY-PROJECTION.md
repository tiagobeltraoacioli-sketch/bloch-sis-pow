<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Genesis-4 fleet memory: the projection, and what keeps it honest

**Do not quote a date from this file without running the tool.** The numbers
below were true of the fleet on 2026-09-01 at chain height 34,104. The
artefact is:

```
scripts/fleet-memory-observe.sh          # read-only capture of the live fleet
scripts/fleet-memory-observations.tsv    # the capture, checked in
cargo run  -p bloch-memoria-projecao     # the projection, recomputed from it
cargo test -p bloch-memoria-projecao     # 21 tests; fail when the fleet moves
scripts/memoria-projecao-violacao.sh     # 10 falsifications; proves they bite
```

Every headline number in this programme that lacked a commit behind it has
turned out to be wrong: `0.0198 MiB/block`, `86.1% signature material`, a
`367 MiB` saving, `60 MB per CommittedState`, an "early October" date. So this
is not a paragraph. It is a program that reads the fleet and goes red when the
fleet stops agreeing with it.

---

## 1. The dates

| regime | curve | date | days |
|---|---|---|---|
| **ROLL** — nine boot at once | PEAK | **2026-10-06** | 34.6 |
| **DRIFT** — nine resident | STEADY | **2026-10-29 .. 2026-11-25** | 57.6 .. 84.1 |
| ROLL, block map store-backed | PEAK | 2027-04-30 .. 2027-06-20 | 240 .. 292 |
| DRIFT, block map store-backed | STEADY | 2027-05-16 .. 2027-07-10 | 257 .. 312 |

Binding box `139.84.201.52` in both regimes: largest boot peak (1,517.0 MiB,
`bloch-n00`) and largest resident sum (11,374.0 MiB). Capacity 28,794 MiB
after a 3,072 MiB page-cache reserve. Cadence 2,827 blocks/day, measured.

A box that survives running can still die in replay. The roll date is the one
an operator plans against; `scripts/fleet-memory-gate.sh` is the go/no-go for a
specific roll.

---

## 2. Reconciling the two slopes — confirmed, not averaged

Three numbers were in play. They are **three different quantities**, and the
apparent conflict dissolves once they are named:

| number | what it measures | standing |
|---|---|---|
| **0.01718** MiB/block | the **peak** curve across a replay | reproduced to four digits, three lengths, two chains |
| **0.01188** MiB/block | the **replay's own retention** (348.9 MiB over 29,377 blocks) | 50 ms curve, five runs |
| **0.00814** MiB/block | the **live fleet's steady drift** at the tip | 63 validators, 5,235 s (mine) |
| **0.001234** MiB/block | an artefact | discredited |

**The coordinator's reading is confirmed, and for a sharper reason than "the
pair spans a regime change."**

The slope agent's own intervals include one measuring **exactly 0.00000**
MiB/block. A term genuinely O(chain) cannot grow by exactly zero across an
interval; that reading is downstream of an allocator release, not a
data-structure size. We now know why: RSS peaks at 60% of the blocks and the
run *gives back 96 MiB*, so an end-of-replay reading past the peak measures the
post-release plateau. For a two-point fit over h=15,000→29,630 to land at
0.001234, the zero interval must dominate the span — the number is a property
of the window, not of the system.

And **0.01718 carries a confirmed mechanism with matching dimensions**: the
term store-backing removes is 13.9–14.6 KB/block against a measured on-disk
envelope of 13,934 B/block. 0.001234 carries none. Finally, 0.01718 lies
*inside* the slope agent's own interval range, so nothing has to be discarded.
No average was taken.

The denominator therefore reverts to **blocks**, and the slot-denominated model
is marked Superseded. It rested on that same end-of-replay interval series, and
a contaminated series is not decontaminated by changing its unit. Today's
cadence is 0.98 blocks/slot, so live data cannot separate the two denominators
at all — the mechanism decides: one envelope per block, and an empty slot
creates no envelope.

---

## 3. The four briefing corrections, checked

| # | claim | verdict |
|---|---|---|
| 1 | 10 validators/box; ceiling 2,879 MiB | **REFUTED** |
| 2 | mean RSS 1,032 MiB | **SUPERSEDED** — now 1,204 |
| 3 | fork overhang 225–226 blocks | **CONFIRMED** |
| 4 | cadence 2,903 blocks/day | **CONFIRMED** within 3% |

**(1)** Four independent lenses on all seven boxes — argv `run`+`--data-dir`,
`pgrep -f bloch-pos`, systemd `bloch-n*.service`, distinct `--data-dir` — all
return **9**, 63 total, indices n00..n62 on stride 7. The classic boxes are
near-empty (three boxes running one process each, 228–469 MiB), so the total
live population is 66, not 70. The ceiling is **3,199 MiB**, not 2,879.

The briefing's warning that idle classic boxes are running nine `bloch`
processes at load 9.5 is itself no longer true.

**(2)** The fleet measures 75,883 MiB across 63 validators = **1,204
MiB/validator**. 1,032 is not reproducible against any population I can find:
even the most generous set of 66 gives 1,166. It is most likely a *correct
reading that aged* — at the measured 23.4 MiB/day drift, 1,032 is about seven
days old, which puts it near G4's launch window.

**Worth flagging: corrections (1) and (2) nearly cancelled.** A 10% too-small
ceiling against an 18% too-small resident level gave 37 days where the
corrected inputs give 39.4 by the same method. Two wrong inputs cancelling is
exactly how a wrong number survives review.

**(3)** Confirmed independently, and it is now *measured* rather than quoted:
`blocks_known − height` off three validators gives 225 / 226 / 226. The
collector records it every run.

**(4)** 2,827/day over slot 49,382–55,000; 2,861/day over the last 83 minutes;
0.98 blocks/slot. The projection uses the snapshot's own figure.

---

## 4. The peak is copy-on-write, not a term that grows on its own

RSS is **not monotone**. At 50 ms sampling over five runs (noise floor 8 kB)
the peak lands at t≈253 s of a 376 s run, at height ~17,663 of 29,377 — 60% of
the blocks — and the run then gives back 96 MiB. End of replay 666.1 MiB
against `VmHWM` 761.9.

The alternatives were eliminated **by measurement**, not by argument:

* carryover and state-root work finish at t≈0.5 s and t≈52 s, long before the
  peak;
* `MEMO_CAP` twice over — `rolled_to` performed **zero** rolls in the entire
  replay, so the memo is never populated, and four extra mainnet-sized states
  measure **320 kB** anyway.

What remains: `REORG_STATE_WINDOW` holding a state makes the eUTXO `Arc`
**shared**, and a shared `Arc` sends the next mutation through
`Arc::make_mut` — a clone of the whole 452,726-entry map, **52.4 MiB** a time.
Counted directly: **892** mutations copied the map, **384,638** mutated in
place. The curve steps in units of exactly 52.4 MiB and releases exactly two of
them in a single 50 ms sample.

So the retention window is the **enabler, not the retention cost**, and the
premium scales with **the size of the eUTXO map**, not with chain length. At
0.0356 tx/block that map is near-constant, so the premium is a roughly fixed
1–2 copies and grows only when usage does — the same back wall as §6, reached
by a different road.

**Open, and stated rather than smoothed over:** a constant transient does not
by itself explain a peak slope of 0.01718 MiB/block reproduced to four digits
across three lengths. The mechanism is confirmed; it does not yet close the
arithmetic. Counting live CoW copies against replay length is the next
measurement, and until it exists the roll arm keeps the reproduced slope rather
than the mechanism's prediction.

### `60 MB per CommittedState` is wrong by ~750×

Four extra mainnet-sized states measure 320 kB, because `EutxoSet.entries` is
an `Arc<BTreeMap>` and holding a state is a refcount increment — states *do*
structurally share, which is exactly what the doc comment denies. The figure,
and the ~240 MB and ~300 MB totals built on it, are still live at
**`crates/bloch-pos-node/src/engine.rs:274-277`**. That file is not this
crate's to edit (it is on the consensus path and another agent's area); the
figure is recorded here as Discredited and the owner should strike it. The same
comment also says "EIGHT validators per host", which is wrong too.

---

## 5. The 1.8× end-of-replay gap: level, not slope — and not this date

The model predicted 344–375 MiB at end of replay; measured 666.1. The peak/end
distinction accounts for only 96 MiB of a ~300 MiB gap, so non-monotonicity
does not rescue it: **RSS is non-monotone *and* the model is refuted.** Both.

The measurer's hypothesis holds exactly. Pre-replay `VmRSS` is 317.2 MiB and
the replay retains +348.9 MiB in both runs; **317.2 + 348.9 = 666.1**, to
within a tenth of a MiB. The model costed the state and omitted the chain the
replay retains. That is a missing **additive term** — a level error.

**It does not move the dates here, and not by luck.** This projection never
reads a predicted level: it reads `VmRSS` and `VmHWM` off 63 live validators. A
model that mis-predicts the level cannot move a date computed from a measured
level. Any date computed *from* that model moves a great deal.

And the missing term **confirms the slope rather than changing it**. Spread
over 29,377 blocks, 348.9 MiB is 0.01188 MiB/block — a third independent route
to the block-map term, against 0.01329 MiB/block of on-disk envelope and a
store-backed removed term of 13.9–14.6 KB/block. Three methods, three
directions, one number. The gap is the strongest evidence yet *for* the
block-map slope, and it is now a test
(`the_replay_retention_term_still_reconciles_with_the_on_disk_envelope`).

It also recalibrated the drift arm. The live-fleet reading (0.00814) is used as
the **optimistic** end and the replay's retention rate (0.01188) as the
**binding** end, because a validator at the tip is filling allocator slack the
replay transient left behind — short-run RSS growth understates the durable
rate until that slack is gone.

---

## 6. The wall behind the wall

What survives store-backing is **not** the block map — that is 0.00029 of a
0.0031 MiB/block residual. About **90% is the committed state**, the eUTXO
ledger, measured across a window carrying 1,048 transactions in 29,472 blocks:
**0.0356 tx/block**, a nearly empty chain.

Dividing through gives **0.0785 MiB of resident state per transaction**
(derived — arithmetic on measured inputs, one low-volume window). At **one
transaction per block** the state term alone is 0.0785 MiB/block, which is
**4.6× the baseline block-map term store-backing removed**, and the
store-backed fleet exhausts a box in **10 days**.

The date does not merely return. It arrives *sooner than it would have without
the fix*, because the fix removed the term that does **not** grow with usage.
And the validator-opening programme exists to add users. Store-backing clears
the front wall; the back wall is made of transactions.

---

## 7. What this projection cannot do

Growth is linear in chain length. **Nothing on the table makes memory
bounded.** Store-backing multiplies the date by roughly seven; it does not move
it to infinity, because what is left is still a line with positive slope. Every
improvement in flight removes a *constant factor* from a curve that still rises
forever.

A bounded design would be **O(unfinalized + state)**, not O(chain): resident
cost set by the unfinalized suffix (88 blocks today) plus the state, with
history paged from the log. **No current workstream aims there.**

The **fork overhang** is the one growing term with no workstream at all: 225
non-canonical blocks held whole in RAM (~3 MiB), and store-backing does not
touch it — that change moves the *canonical* map to disk. Small today,
unbounded in principle, now measured every run and alarmed at 2,000 blocks.

**Every way this projection is likely to be wrong points the same direction —
later than the truth.** The `VmHWM` marks are stale floors. The reserve is
smaller than the page cache the boxes actually use (5,135–8,148 MiB observed
against 3,072 held back). The live-fleet drift rate is a lower bound. And the
dates extrapolate several times past the longest log ever replayed (~30,600
blocks) — a source of error larger than everything in the width table, and not
expressible as a band.

---

## 8. The staleness alarm, and the guard that was missing

21 tests recompute the dates from the snapshot and fail when a box changes size
or tenancy, when the four tenancy lenses disagree, when the fleet outgrows the
published date by a week, when the snapshot passes 14 days, when the cadence
moves 10%, when no `VmHWM` mark is fresher than 20,000 blocks, when the boot
premium vanishes or becomes a multiple, when the fork overhang runs away, when
the three routes to the block-map term stop agreeing, or when the recomputed
date is already in the past. None re-asserts a constant.

**The guard that was missing.** The previous round asserted "9 validators per
box" and passed — but it would have passed just as happily if the *collector*
had miscounted, because an under-count makes a box look emptier, moves the date
in the safe direction, and leaves every downstream check green. A tenancy claim
of 10-per-box reached this programme and was refuted only because four lenses
were read instead of one. So the box is now enumerated four independent ways,
the counts are carried in the snapshot, and
`the_four_independent_counts_of_tenancy_agree` fails when they part — whichever
of them is wrong. The falsification harness proves it by making systemd see ten
where argv sees nine.

Two tests are deliberately time-dependent. That is not a flake: a projection
whose inputs are 40 days old *is* broken, and a suite that cannot say so leaves
the staleness for a human to remember.

`scripts/memoria-projecao-violacao.sh` falsifies the snapshot ten ways and
requires the named test to go red for each; if one passes green, that script
fails. Last run: **10 caught, 0 missed, control green.**

---

## 9. Provenance of the fleet reading

`scripts/fleet-memory-observe.sh` is read-only by construction: one `ssh` per
box reading `/proc`, plus the node's own loopback RPC. It starts nothing, stops
nothing, restarts no validator, writes nothing on any box outside `/tmp`, and
arms nothing. Boot heights come from the chain's archive via `getblockbyslot`,
not from wall-clock arithmetic.

Four portability traps are pinned there, because each produced a file that
looked correct: `LC_ALL=C` (a pt_BR locale emits `2826,8` and the parse fails
days later complaining about a field, not a locale); no `declare -A` (macOS
ships bash 3.2, where it fails *non-fatally*, leaving boot heights `NA` and the
roll arm silently unbounded); the RPC port is read as the argument *after*
`--rpc-port` (taking "the first five-digit argument" picks up `--listen`, which
comes earlier in this argv); and the `BOXMETA` column indices, which were off
by one and put the hostname in `mem_total_mib` — caught by
`snapshot_is_structurally_whole`, and now a falsification case of its own.
