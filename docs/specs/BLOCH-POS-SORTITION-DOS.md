<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Public Sortition as a DoS Surface — What Actually Mitigates It (F7)

```
Document:   BLOCH-POS-SORTITION-DOS
Status:     ASSESSMENT — closes threat-model finding F7 as an accepted,
            quantified surface; no code change proposed
Created:    2026-08-11
Owner:      A6
Responds:   BLOCH-POS-THREAT-MODEL.md §F7
Reads:      crates/bloch-pos-committee/src/{committees,schedule,sample,params}.rs,
            BLOCH-POS-SHA3-LATTICE-MIGRATION.md §6.4, §6.5.2
```

## Ground truth, updated for the partition

F7 was written against the sampled design (`SLOT_SUBCOMMITTEE_SIZE = 8`). The
F1 fix replaced the sample with a **partition** of the active set: the per-slot
committee is now the slot's partition cell, of size `⌊N/32⌋` or `⌈N/32⌉`. At
gate G4's minimum of 200 validators that is **6 or 7 validators per slot** —
the finding's number got slightly *worse*, and the knob it proposed turning
(`SLOT_SUBCOMMITTEE_SIZE`) no longer exists: under a partition, per-slot size
is `N/32` by construction and only a larger validator set raises it.

The schedule is public by design and that is not negotiable in this suite: no
PQ signature family gives the uniqueness a VRF needs (§6.4), so anyone holding
the seed mix and the registry computes every cell and every proposer. With the
F6 look-ahead, the seed for epoch `N` is fixed at the close of epoch `N − 2`,
so a given slot's committee is public **16 to 32 minutes** before the slot
opens (pre-F6 it was 0.5 to 16 minutes).

> **Correction, 2026-08-24.** The sentence above described the intended rule,
> not the shipped one. Until 2026-08-24 no production path read the F6
> look-ahead: both `CommittedState::seed_for_epoch` and `Engine::seed_for` took
> the boundary at `N − 1`. So the deployed warning window was the **pre-F6 0.5
> to 16 minutes**, not 16 to 32 — the DoS exposure this document priced was
> understated for as long as the claim stood. The wider window becomes real
> only with the binary that actually routes both readers through
> `committees::seed_epoch`.

## What the attack buys, priced

An attacker who can knock 6–7 known machines offline for one 30-second slot:

- **One-slot reorgs, cheap — CONFIRMED, still open.** A slot whose cell is
  silenced contributes zero LMD-GHOST weight, so the block proposed in it is
  protected by nothing but the next proposer's goodwill. Silence slot `S`'s
  cell and propose (or bribe the proposer of) `S + 1` on `S`'s parent: the
  honest block at `S` is orphaned at no cost beyond the DoS burst. This is
  exactly the cheap intra-epoch reorg §6.5.2 says the per-slot vote exists to
  prevent, and at `N = 200` the per-slot vote is 7 machines named in advance.
- **Finality stall, expensive but feasible.** Under the partition, a
  validator's *only* vote of the epoch is cast in its assigned slot. Silencing
  one cell therefore also deletes ~1/32 ≈ 3.1% of the epoch's justification
  stake. Stalling justification needs > 1/3 of stake silenced: **≥ 11 of 32
  cells, ~70 validators at N = 200, sustained every epoch**, with the target
  list re-derived each epoch. Botnet-scale, not nation-scale.
- **Safety: nothing.** No amount of DoS forges a 2/3 quorum. The attack
  surface is liveness and ordering, never false finality.

Perverse interaction to keep in view: after
`INACTIVITY_LEAK_THRESHOLD_EPOCHS` the leak starts bleeding the **victims** —
DoSed validators are indistinguishable from absent ones. The leak restores
liveness by destroying honest stake, which makes sustained targeted DoS a
griefing weapon as well as a stall. That is the designed trade of any
inactivity leak; it is listed here so nobody presents the leak as a defense.

## What is real mitigation

1. **Identity is an index, not an address — real, and eroding.** Everything
   consensus publishes is a `u32`. Turning an index into an IP requires
   correlating gossip origin and timing against the known schedule, which is
   work — but it is *one-time* work per validator, the validator attests on a
   public schedule forever, and the mapping only goes stale when the operator
   re-homes. Treat this as friction that prices the attack up, not as
   protection. It is strongest for fresh validators and weakest for exactly
   the long-lived, high-stake validators most worth silencing.
2. **Sentry topology — the only mitigation that absorbs the attack, and today
   it is a suggestion.** A validator whose signing node has no public inbound
   surface and speaks only through disposable sentries survives the burst; the
   attacker DoSes sentries that can be rotated faster than 30 seconds.
   Recommendation: make "validator client binds no public listener" the
   *default* in the shipped client, and put sentry deployment in the G-gate
   sign-off language. Honest caveat: topology is unverifiable on-chain; a gate
   can require attestation of it, not proof.
3. **Late attestation inclusion — a real design lever, not yet designed.** If
   a cell member's vote for slot `S` can be included in any later slot of the
   same epoch, a 30-second burst no longer deletes its justification stake —
   the attacker must sustain the DoS for the rest of the epoch to keep one
   vote out. This converts the finality-stall cost from "70 nodes × 30 s
   bursts" to "70 nodes × ~16 min sustained, every epoch". It does **not**
   protect fork choice at the tip (a vote that arrives late is too late to
   defend slot `S`'s block). Worth speccing for Phase 1.
4. **Proposer-boost-style fork-choice weighting — real, adopted by Ethereum
   for exactly this attack class.** Granting the timely proposer of `S + 1` a
   temporary weight bonus for building on `S` makes orphaning a weightless
   slot cost more than the DoS burst. A design change to `forkchoice.rs`, not
   a parameter; flagged as the concrete answer to the one-slot reorg above.
5. **A larger validator set.** Cell size is `N/32`; at `N = 1000` a slot is 31
   machines. This is the only thing that raises the per-slot number, and it is
   an outcome, not a knob.

## What is NOT mitigation

- **The F6 look-ahead.** It was suggested that fixing the seed earlier
  "shortens the warning." It does the opposite: the seed for epoch `N` is now
  fixed one epoch *earlier*, so the schedule is public *longer* — per-slot
  notice went from 0.5–16 min to 16–32 min. F6's fix is an anti-grinding
  measure and is worth that cost, but counting it as DoS mitigation would be
  claiming a defense that does not exist.
- **`SLOT_SUBCOMMITTEE_SIZE`.** A dead knob since the partition; per-slot size
  is `N/32` and the constant survives only in the legacy sampled primitives.
- **Schedule secrecy / private sortition.** Not available without a PQ VRF
  (§6.4); LB-VRF-class constructions are research-grade. This stays on the §14
  research track and must not be assumed in any Phase-1 security argument.
- **Slashing or penalties.** The victims are honest and the attacker stakes
  nothing. There is no protocol lever that punishes an off-chain DoS.
- **The inactivity leak.** See above: it is liveness *recovery* at the
  victims' expense, and in this scenario it works for the attacker.
- **"The attacker won't find the nodes."** That is mitigation #1 stated as
  hope. Priced there, once.

## Bottom line

With 200 validators the chain hands any attacker a list of ~7 machines that
carry each 30-second slot, 16–32 minutes in advance. One-slot reorgs are cheap
against a bare deployment; a sustained ~70-target campaign can stall finality;
safety is untouched. The mitigations that exist (index indirection, sentries)
price the attack up without removing it, and the two protocol levers that
would materially raise its cost — late attestation inclusion and proposer
boost — are identified, unimplemented, and recommended for Phase 1. Until a
PQ-VRF exists, this is an accepted surface and should be described as such in
the GIP, not papered over.
