<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# VAD-04 — the validator lifecycle across real processes: what the first soak runs measured

Date: 2026-09-11. Tree: `main` after PR #19 (`5e5513e`). Harness:
`scripts/lifecycle-devnet-soak.py` (PR #16–#19). This is a measurement
report, not an audit: every number below comes from a run whose work
directory, logs and `verdict.json` were kept, and every mechanism claim
carries the file and line it was read from.

The admission review of 2026-09-08 left one finding open, VAD-04: the ADR-041
lifecycle had only been rehearsed between two `Engine` values inside one
process. `deploy/FLAG-DAY-LIFECYCLE.md` §3.3 lists what a release-grade
qualification must cover. This report says which of those items the harness
now discharges, which it refuted, and which it could not reach yet.

## 1. Set-up

Five real `bloch-pos` processes on the devnet TCP transport, each with its own
data directory, peered only through harness-owned TCP relays (a partition
cuts relays; no process is restarted). A disposable copy of the tree, built in
its own target directory, with:

| constant | copy | why |
|---|---|---|
| the five ADR-041 gates | 0 | the lifecycle under test |
| `LEAK_RECOVERY`, `LEAKED_ROSTER`, `TRANSFER_WITNESS_DEDUP`, `BLOCK_BYTES_V2` `_ACTIVATION_EPOCH` | 0 | mainnet is past 800/1400/2700 at any L; a devnet at epoch 0–100 must run the same rule set |
| `EXIT_DELAY_EPOCHS` / `WITHDRAWAL_DELAY_EPOCHS` | 4 / 64 | compress 32 / 2,048 into a run |
| `RANDAO_CHAIN_LENGTH` | 8,192 (unchanged) after the first run; 256 in the first run | see §4 |
| `DEPOSIT_ACTIVATION_EPOCH`, `ANCESTRY_SEED_ACTIVATION_EPOCH` | `u64::MAX` (unchanged) | never armed |

Slot 500 ms (epoch 16 s). Three genesis validators at 200k / 400k / 600k
BLOCH (`genesis` fixes stakes by position), one funded joiner at 25,000 BLOCH,
one keyless observer that joins late from an empty directory; 1.225M BLOCH
active once the joiner is in. The shipping binary, built from the same tree
without the rewrite, is the `unarmed-control` arm.

## 2. Runs

| run | arm | result | where it ended |
|---|---|---|---|
| 04:04 UTC | `unarmed-control` | **PASS, 20/20** | the shipping binary refused the deposit at the RPC door: `funded validator admission is not active` (−32008); CONVERGED over 97 slots |
| 04:04 UTC | `full`, split 9 epochs, chain 256 | FAIL at the heal | everything up to and including the split held (§3.1); the halves never reconverged (§3.2) |
| 04:34 UTC | `full`, split 3 epochs (`--allow-short-split`, chain 8,192) | FAIL at the heal | split epochs 19–22; no `NotInCommittee`, no `chain spent`, no `REORG` anywhere; the halves never reconverged and **both finalized different roots** (node0: epochs 29–31 = `949676c4`/`0631ba5c`/`f0686300`; node2: 30–31 = `6ee7862c`/`66fd7a72`) |
| 04:36 UTC | `full`, split 6 epochs (`--allow-short-split`, chain 8,192) | FAIL at the heal | split epochs 26–32; probed live through the heal (§3.3): both halves held each other's head within 40 s, `bloch_pos_blocks_parked = 0`, and each kept its own head; A justified epoch 37 alone |

Three checks were wrong in the harness and were corrected against what the
runs showed, never loosened: a fresh data directory prints no `replayed N
blocks` line (it prints `fresh node: syncing under the genesis anchor`);
attestations are packed once per epoch, one vote per block in the first slots
of the next epoch, so the evidence that the joiner votes is the per-epoch
total rising from 3 to 4; and the post-restart log slice used a byte offset on
decoded text (`—` is three bytes), so it read nothing for two epochs while the
log plainly carried `replayed 491 blocks`.

## 3. The 9-epoch partition

### 3.1 What held, on five separate processes

- Funded deposit prepared and signed offline (two roles, two keystores),
  accepted at the RPC door of a node that had never seen the keys, included
  in the same slot; `getvalidatorcount` 4 on every node; the funder's input
  spent; change output identical everywhere.
- The joiner's node booted **after** inclusion, learned its own registration
  from history, synced to the common head in one slot.
- Activation at epoch 11 = deposit epoch 3 + 8, and only after finality had
  passed epoch 3 (at epoch 6) — the finality-gated rule of PR #11, observed
  across processes.
- The observer joined from an empty directory at epoch 11 and matched heads,
  state roots and finality on all five nodes within a slot.
- The joiner proposed (`proposer_index 3` at slot 569) and attested; a
  SIGTERM restart replayed 603 blocks, re-resolved the same identity,
  kept `slashing_protection.bin`, and it proposed again; no peer reported an
  equivocation.
- Partition, epochs 29–37: `peers.devnet` fell from 8 to 2/4 on every node;
  finality stayed at 26 on both halves for the whole split (required by the
  harness, not tolerated); heads diverged at every sample; each half agreed
  internally; PIDs never changed.

### 3.2 What did not: the halves never reconverged

After the relays reopened at epoch 37, side A (v0 + v1, 600k) advanced and
**finalized epochs 40–45 alone**; side B (v2 + joiner, 625k) kept its own
branch for the ten epochs the harness waited. node2 and the joiner logged
`attestation from v0 REJECTED: NotInCommittee` (and v1) from slot 1344
onwards. No node printed `REORG`, `FINALITY_LATCH`, or a sync refusal.

The mechanism, read from the code against those logs (a second reader
re-derived it independently; where a claim is inference rather than a log
line it says so):

1. **Sync worked.** A block whose parent is unknown is parked, not stored
   (`engine.rs:2441-2447`); `sync_after_slot` asks 64 slots below the lowest
   parked orphan (`engine.rs:2139-2147`) and the pump fires every two slots
   while the node is behind (`engine.rs:5223-5231`); a peer answers 512
   blocks from its canonical log (`net.rs:894`, `SYNC_PAGE_BLOCKS`). From
   B's head 1118 three round trips reach the fork at slot 929 and A's
   branch chains in. The 256-orphan FIFO (`engine.rs:377`, `2490-2504`)
   held 156 A-blocks at peak and evicts by arrival, costing a round trip,
   never a fork. That node2 held A's branch is inferred: a `NotInCommittee`
   verdict needs the seed of the attestation's target block, which
   `ancestral_boundary_mix` reads from `self.blocks` (`engine.rs:1592-1599`).
2. **`NotInCommittee` is a symptom, not the cause.** The lines begin at
   epoch 42, not at the heal. A second funded deposit had been submitted to
   both halves during the split; it activated on A at epoch 42, once A's
   finality passed its epoch (`transition/lifecycle.rs:11-37`), and stayed
   queued on B. From then on A partitions five indices into committees and
   B four — different permutations (`committees.rs:195-206`), so v0/v1's
   duty slot on A is usually not their slot in B's draw. Membership is
   judged against the receiving node's **own** rolled state
   (`engine.rs:3745-3746`); `gossip.rs:372-374` assumes "both ends compute
   membership from the same finalized state", which a finality split
   breaks. The leak removes nobody from a committee: `with_leak_applied`
   keeps the zeroed record on purpose (`transition.rs:5316-5333`) and
   `epoch_committees` has no stake filter (`committees.rs:326`).
3. **Why neither side switched.** Fork-choice weight is the stake table of
   the node's own canonical state **with the leak applied**
   (`engine.rs:5442-5468`; `LEAKED_ROSTER_ACTIVATION_EPOCH` is live on the
   copy, as it is on mainnet since 1400). Each side leaks the other's
   validators, so each side weighs its own branch heavier: on B, v0/v1 had
   leaked to ≈427k against v2/v3's ≈482k; on A, v2/v3 to ≈445k against
   600k. Unleaked, B (625k) would have outweighed A (600k) everywhere.
4. **Why A finalized alone, and at epoch 40 exactly.** The floor is one half
   of the unleaked total (`params.rs:260-262`; `finality.rs:384-402`); the
   leak bites `remaining × t / 64` per epoch after four epochs of
   non-finality (`finality.rs:517-548`). Last shared finality 26; leak from
   epoch 31. At the epoch-40 tally B's absent 625k retains 0.4768 →
   denominator 898.0k > floor 612.5k; 3 × 600k = 1,800k ≥ 2 × 898.0k =
   1,795.9k — passes by 4k; at 39 it fails (946.7k). node0 logged
   `*** JUSTIFIED epoch 40` then `*** FINALIZED epoch 40`, the first epoch the
   arithmetic allows. After that B's branch is unreachable from A's
   justified root and `prune_below_finalized` (`engine.rs:2506-2548`) drops it.
5. **B could have finalized alone too.** Symmetrically, 625k against
   600k × 0.4768 passes at epoch 40. It did not because v2's RANDAO chain
   (256 on that run) was spent at slot 978 and the joiner proposed rarely,
   so B's own validators leaked on B for want of including blocks. With a
   dense B, the run would have produced **two conflicting finalized
   checkpoints** at epoch 40.

### 3.3 The shorter splits, and the live probe

The 3-epoch split ruled out three things at once: the leak threshold as a
*precondition* (the split itself was shorter than four epochs), the
mid-split activation (`NotInCommittee` never appeared) and the RANDAO
artefact (chain 8,192, B dense). It still did not heal, and it ended in two
finalized roots. The 6-epoch split was probed live from the heal at epoch 32
with `getblockbyid` of the other half's head and the `bloch_pos_blocks_parked`
metric on node0 (A) and node2 (B), every two seconds:

- within 40 s of the heal **both sides held the other side's head block**
  and had nothing parked — the sync path is not the problem;
- `getvalidators` on the two sides at 04:46 UTC (≈ 90 s after the heal;
  `effective_stake_sat` is the leak-applied weight fork choice reads):

  | index | side A's table | side B's table |
  |---|---|---|
  | 0 (on A) | 102,951,027,925,571 | 48,814,802,671,613 |
  | 1 (on A) | 205,902,055,840,231 | 105,016,960,082,360 |
  | 2 (on B) | 111,327,770,489,871 | 300,563,704,793,788 |
  | 3, joiner (on B) | 2,120,267,048,515 | 5,956,029,326,640 |

  Each side weighs its own validators at full value and the other side's at
  a third to a half. A's own weight on A's table (3.09 × 10¹⁴) beats B's
  (1.13 × 10¹⁴); B's own on B's (3.07 × 10¹⁴) beats A's (1.54 × 10¹⁴).
  A's `justified.epoch` was already 37 against a shared finality of 24/25.

The two halves are almost equal in real weight (v0 + v1 ≈ 50.6 %, v2 +
joiner ≈ 49.4 %), so the **first** leak bite — 1/64 of the absent side, at
`since_finality = 5` — is enough to make each side prefer itself. Finality
trails the head by one or two epochs, so a 3-epoch split heals at
`since_finality = 5`, already past the threshold; there is no window in which
the heavier side wins unless it is heavier by more than the leak that has
accrued by the time the mesh heals.

What this is, and is not:

- It is **inside the residual the post-mortem already records**: the ½ floor
  "bounds the divergence to at most three ways; it does not make the root
  unique" (`docs/post-mortems/2026-08-24-finality-divergence.md:248-253,
  303-308`). A 49/51 split is two sets each ≥ ⅓. Two documents overstated
  what epoch 2700 closes ("a shrunken partition can never vote itself a
  supermajority"; "no divergence between nodes … the failure mode this
  closes") and one said leaked validators "stop holding committee seats";
  all three sentences are corrected in this PR.
- It is **not** lifecycle-specific and not caused by ADR-041 code: the
  same rule set is live on mainnet today (1400 and 2700 are bound). What
  the lifecycle added was the mid-split deposit whose one-sided activation
  produced the visible `NotInCommittee` symptom.
- It is **not** the orphan cap, not a sync livelock, and not the finality
  latch (B's finalized 26 is below the fork at 929).
- **There is no in-protocol recovery.** Leak recovery only credits a
  validator whose vote is valid on that branch; a published weak-subjectivity
  checkpoint "never reorganizes a node that has finality of its own"
  (`ws_boot.rs:33-37`); `--allow-finality-rewind` is about the latch, which
  is not engaged. The operator procedure for the losing side is: stop,
  move the block log and `ws_latest.bin` aside **keeping
  `slashing_protection.bin`**, restart peered only with the winning side
  (a replay that also sees the losing branch may pick it again, since
  pre-leak weight favoured it), optionally with the winner's checkpoint as
  the anchor.

Consequence for the flag day (folded into `deploy/FLAG-DAY-LIFECYCLE.md`):
the VAD-04 requirement "a partition longer than `ACTIVATION_DELAY_EPOCHS`
(8) followed by finality recovery" cannot be met on the rule set the fleet
runs, with or without the lifecycle. Fork choice reads each node's **own,
leak-applied** stake table (`engine.rs:5442-5468`, the epoch-1400 roster
rule), and the leak is branch-specific, so two halves that were close in
weight each prefer themselves from the first bite onward — five epochs after
the last shared finality, **about 80 minutes on mainnet**, whatever the
split's own length — and then the ½ floor lets each finalize alone (§3.2,
item 4). The root cause is a design property, not a defect in sync: the
weights fork choice compares are not computed from a state both halves
share. The remedy is a consensus-layer decision for the founder, not a
harness one: read fork-choice weights from the last **justified** state (the
one both branches descend from) or without the leak, as the leak already
counts for nothing in `epoch_committees`. Until then the operating rule is:
a two-way partition of two sides each ≥ ⅓ is a fork the protocol will not
heal once finality has stalled five epochs, and the recovery is the
procedure above.

## 4. The RANDAO chain on the first run

With `RANDAO_CHAIN_LENGTH = 256`, v2 (≈ 49 % of proposer draws) spent a chain
every ≈ 520 slots. The first exhaustion was renewed on the mesh —
`randao_generation: 1` on every node, i.e. the ADR-041 recommit rider
working over the real transport — and the second fell inside the partition,
where the only other proposer on B held 2 %, so B produced almost no blocks
(`RANDAO chain spent — waiting for an included renewal`, slots 978–1079).
That is an artefact of a 49 %-share proposer on a 256-reveal chain; the copy
now keeps the shipping 8,192, and `--randao-chain 256` reproduces the renewal
observation on purpose.

## 5. Status against `deploy/FLAG-DAY-LIFECYCLE.md` §3.3

| requirement | status |
|---|---|
| separate processes and data directories over the real transport | discharged (§3.1) |
| late join after registrations (from history, empty directory) | discharged (§3.1) |
| restart of the joining node after several RANDAO reveals | discharged (§3.1) |
| partition longer than the activation delay, with finality recovery | **refuted as stated** (§3.2–3.3), and not only for long splits: two near-equal halves never reconverge once finality has stalled five epochs, because fork choice compares leak-applied weights that differ per branch; a founder decision on the fork-choice weight source is needed before any partition requirement can be met |
| pending authentication after registry growth | discharged: the mid-split registration stayed queued on the half whose finality never moved and activated only where finality passed its epoch |
| ≥ 3 epoch boundaries with a slashing prosecution and a post-slash withdrawal | **not reached** — the runs ended at the heal; the 3-epoch run is the first that can carry the lifecycle past it |
| load from many independently keyed candidates | **not reached** |
| shipping binary refuses the deposit (control) | discharged (`unarmed-control`, 20/20) |

This section is updated as the remaining runs report.
