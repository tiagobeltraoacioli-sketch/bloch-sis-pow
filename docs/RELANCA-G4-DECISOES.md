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

## 2. The guard has to exist in the shipped binary

The one check that would have caught this was a `debug_assert_eq!` in
`close_epoch`. Workspace `[profile.release]` sets `overflow-checks = true` and
does **not** set `debug-assertions`, so on the binary mainnet runs it was not
there. It is now an unconditional consensus invariant rather than a blanket
`debug-assertions = true`, which would enable every debug assert in every
dependency and change performance for a much larger blast radius.

A panic in the consensus path HALTS this node instead of letting it diverge
silently. On a 64-validator coordinated fleet a halted node is diagnosable and
recoverable; a diverged node poisons finality for everyone, which is precisely
what this defect did. Both sides of the compared condition are derived from
already-validated committed state, not from attacker-supplied input, so this is
not a remotely-triggerable denial of service.

## 3. Fork choice is NOT patched

Two forked nodes fed all blocks from both branches do not converge, because
`head()` starts at `state.finality().justified.root` and walks only downward.
That is a consequence of the refused attestation, not an independent defect:
with no accepted attestation the tally never includes the other branch, so the
`cp.epoch > current_justified.epoch` advance never fires. Walking down from the
justified checkpoint is correct LMD-GHOST; forcing fork choice outside the
justified subtree would trade a liveness bug for a safety bug.

## 4. What the flag day still is

`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` stays armed, with its tripwire. Item 1
is what makes keeping it armed safe: before it, the flag day fired straight
into the partition bug.
