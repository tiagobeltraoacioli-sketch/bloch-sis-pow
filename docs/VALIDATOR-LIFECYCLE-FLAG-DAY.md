<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The validator-lifecycle flag day — five ADR-041 gates `= 2700`

**ARMED 2026-09-09 by founder decision.** Chain was at ~epoch 2413 when the
constants were set; epoch 2700 lands ≈2026-09-12 21:31 UTC (30 s slots, 32
slots/epoch, 90 epochs/day), leaving ≈3 days for the coordinated fleet
rollout. This document is the versioned runbook the five tripwire tests check
the constants against:

| Constant (`crates/bloch-pos-committee/src/params.rs`) | Value | Tripwire (`transition.rs` unless noted) |
|---|---|---|
| `FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH` | `2_700` | `funded_admission_armed_epoch_matches_the_runbook` |
| `EXIT_AUTH_ACTIVATION_EPOCH` | `2_700` | `exit_auth_armed_epoch_matches_the_runbook` |
| `WITHDRAWAL_ACTIVATION_EPOCH` | `2_700` | `withdrawal_armed_epoch_matches_the_runbook` |
| `SLASHING_EVIDENCE_ACTIVATION_EPOCH` | `2_700` | `slashing_evidence_armed_epoch_matches_the_runbook`; node side `tests/slashing_backed_finality_claims.rs` |
| `RANDAO_RECOMMIT_ACTIVATION_EPOCH` | `2_700` | `randao_recommit_armed_epoch_matches_the_runbook` |
| `DEPOSIT_ACTIVATION_EPOCH` | `u64::MAX` | `deposit_gate_is_inert` — **permanent**, the legacy unfunded deposit never reopens |

The compile-time ordering block at the end of `params.rs` refuses a build in
which the five are not equal and `DEPOSIT_ACTIVATION_EPOCH` is not
`u64::MAX`. Changing the epoch again is a new flag day and requires updating
the constants, the tripwires and this document in one commit.

Epoch 2700 is also `LEAK_RECOVERY_ACTIVATION_EPOCH`
(`docs/LEAK-RECOVERY-FLAG-DAY.md`, armed 2026-09-06). **The fleet gets one
combined flag day**; a node that carries one of the two arming commits and not
the other is on the wrong side of the boundary either way.

## What activates at epoch 2700

From the first block whose committed epoch (`epoch_of(header.slot)`, never a
clock) is `>= 2700`:

- **Funded admission** — `FundedDeposit` (wire `0x0B`) becomes
  consensus-valid: a registration that spends real transparent eUTXO inputs
  worth at least the minimum bond, carries the two role-separated hybrid
  ML-DSA-65 ‖ Falcon-1024 authorizations, and names the 32-byte withdrawal
  credential in the signed intent. Activation follows the shipped queue rules
  (below). Spec: `docs/specs/BLOCH-FUNDED-VALIDATOR-ADMISSION.md`.
- **Authenticated exit** — `ExitV2` (`0x0C`) becomes the only voluntary exit:
  hybrid signature verified in consensus against the *registered* pubkey over
  `DS_EXIT`, signed epoch must equal the inclusion epoch, at most
  `MAX_EXITS_PER_EPOCH` per epoch. The legacy unauthenticated `Exit` (`0x03`,
  a bare registry index) becomes **consensus-invalid** at the same block.
- **Withdrawal** — `Withdraw` (`0x0D`, five bytes) becomes consensus-valid: an
  unsigned crank that pays a matured bond to the credential fixed at deposit.
  Funded bonds receive principal plus accrual; genesis-era bonds receive
  accrual only and their seeded principal leaves as `written_off_sat`. The
  first `Withdraw` a mainnet block can carry is not before epoch
  2700 + 32 + 2048 = 4780 (an exit signed at 2700 matures then), ≈23 days
  after the flag day. Each node auto-cranks its own matured withdrawal.
- **Slashing evidence** — `SlashingEvidence` (`0x05`, decodable since
  2026-09-05) is **applied** instead of refused: where the pair proves an
  offence, `apply_slashing_evidence` burns the offender's stake, ejects it
  (`exit_epoch = epoch + 1`), re-stamps `withdrawable_epoch`, and pays the
  whistleblower's share capped at the backed part of the slash. Nodes that
  observe an equivocation construct and broadcast the evidence themselves.
  Below 2700 every block carrying evidence is refused, as it always was.
- **RANDAO re-commit** — `RandaoRecommit` (`0x0A`) becomes consensus-valid:
  a validator whose 8,192-reveal chain is exhausted may install a fresh
  commitment, signed against its registered key over the inclusion epoch.
  Nodes renew their own chains automatically. Without this, the first
  genesis chains would have exhausted around 2027-02-11.
- **Legacy unfunded `Deposit`/`Delegate`** (`0x02`/`0x04`) stay refused by
  consensus at every epoch. Nothing about this flag day touches them.

Below 2700 every arm behaves byte-for-byte as it does on the chain today;
that is what lets a mixed fleet agree on every block until the boundary.

## Parameters that stay as shipped

No constant other than the five gates moves. In particular:

| Parameter | Value | Where |
|---|---|---|
| `MIN_DEPOSIT_SAT` | 25,000 BLCH | `staking.rs:97` |
| `ACTIVATION_DELAY_EPOCHS` | 8 | `staking.rs` |
| `MAX_ACTIVATIONS_PER_EPOCH` | 4 | `staking.rs` |
| `MAX_EXITS_PER_EPOCH` | 4 | `staking.rs` |
| `EXIT_DELAY_EPOCHS` | 32 | `staking.rs` |
| `WITHDRAWAL_DELAY_EPOCHS` | 2,048 (≈22.8 days) | `staking.rs` |
| `CORRELATION_WINDOW_EPOCHS` | 4,096 (compile-time `≥ 2 × WITHDRAWAL_DELAY_EPOCHS`) | `slashing.rs` |
| `RANDAO_CHAIN_LENGTH` | 8,192 | `params.rs` |
| Genesis-cohort cap taper | 10,000 bps at launch → 3,333 bps floor over one year (`EPOCHS_PER_YEAR`) | `genesis_cohort.rs` |
| Delegation | inert — `Delegate` refused at every epoch; delegation positions have no payout path (their own ADR) | `delegation.rs`, `params.rs` |

Funded activation additionally requires the registering deposit to be in a
finalized checkpoint (the finalized-eligibility rule of the ADR-041
implementation), with the existing eight-epoch minimum and four-per-boundary
churn, without backdating.

## Why this epoch

- **Strictly in the future at tag time** (tripwire requirement 1): armed at
  ~epoch 2413, binds at 2700 — 287 epochs of margin. An epoch already past
  would arm silently against the whole history.
- **After the rollout completes** (requirement 2): ≈3 days at 90 epochs/day.
  The fleet is 64 validators on 7 Edgevana hosts; the 2026-08-30/31 migration
  moved all 64 in under two days, and the leak-recovery rollout to the same
  epoch has to happen in this window anyway.
- **Matches this runbook** (requirement 3): 2700, here, in the five constants,
  and in `docs/LEAK-RECOVERY-FLAG-DAY.md`.
- **One boundary, not two.** Every flag day costs a coordinated fleet rebuild
  plus ~21 minutes of mute RPC and 40–198 slots of gap per node restart, run
  fleet-wide. Sharing the epoch with the leak recovery halves that cost and
  leaves one boundary to watch.

## Deployment deadline — the one hard rule

**Every validator MUST be running a binary carrying all six constants above
BEFORE epoch 2700.** At the boundary an armed binary and an un-armed binary
reach different verdicts on the first block that carries a lifecycle
transaction, a legacy `Exit`, or — through the leak recovery — a different
quorum denominator: a fleet split across the two DIVERGES. There is no
partial rollout; this is a flag day.

**The fleet today runs commit `46133196` (`bloch-pos-cinco`), which has NO
armed gate at all — not the five lifecycle gates and not
`LEAK_RECOVERY_ACTIVATION_EPOCH` either.** Every one of the 64 validators has
to be rebuilt from the armed commit (or a descendant of it) and restarted;
nothing currently deployed crosses epoch 2700 correctly.

Rollout order (same procedure as `LEAKED-ROSTER-FLAG-DAY.md`, which rolled
E=1400, and `LEAK-RECOVERY-FLAG-DAY.md`):

1. Build the release binary from the armed commit; record its hash.
2. Distribute to all 7 hosts; verify the hash on each box.
3. Restart the validators host by host (`bloch-nNN` units), confirming each
   node rejoins, replays, and attests before moving to the next host.
4. All 64 restarted and attesting = rollout complete. Confirm well before
   epoch 2700 (target: ≥1 day of margin — i.e. by 2026-09-11 21:30 UTC).
5. At epoch 2700, watch the first boundaries (below).

## What to watch afterwards

- Finality continuity across the 2700 boundary (finalized epoch advancing),
  and no divergence between nodes — same finalized root at the same epoch on
  independent nodes. This is the leak-recovery half's watch item too.
- `getvalidatoradmission` on any node: `active: true`,
  `activation_epoch: 2700` from the first post-2700 head.
- No node refusing its own block or reporting `NotInCommittee` at the
  boundary; no `EvidenceNotActive` / `StakingNotActive` rejections of blocks
  produced by upgraded peers.
- Any `SlashingEvidence` that lands: it must name a real equivocation, and
  the offender's record must show `slashed: true` on every node.
- RANDAO: no proposer drop-off attributable to an exhausted chain (none is
  expected before 2027, so this is a non-event if all is well).

## What this flag day does NOT do — open items, stated plainly

Copied from `docs/audit/VALIDATOR-LIFECYCLE-IMPLEMENTATION-2026-09-09.md`,
"Release work still required", with the status at arming:

1. **Epoch chosen** (item 1): done by this decision — `L = 2700`. The
   finalized-eligibility rule for funded activation ships as implemented.
2. **ADR-041 T-6 vs the one-prosecution rule: NOT reconciled.**
   `an_ejected_validator_is_not_punished_again` expressly rejects a second
   prosecution of the same validator; the implementation preserves that rule
   and does not implement a later correlated debit of an already-slashed
   residue. The withdrawal-lock tests must not be used to claim otherwise.
3. **Coordinated transport soak with the lifecycle enabled: NOT done.** The
   engine rehearsal (two `Engine` states exchanging real signed messages
   through the shipped codec, gates at zero in a disposable source copy) and
   the shipping-gate transport control are separate pieces of evidence, not
   the combined fleet gate.
4. **Weak-subjectivity signing ceremony: NOT done.** No fresh checkpoint has
   been signed with the required 2-of-3 independently controlled signatures
   including an external signer. An unsigned checkpoint does not replace the
   signed envelope.
5. **Reproducible release + fleet-wide verification: the rollout above.**
6. **No mainnet withdrawal has settled.** None can before epoch ≈4780.
   **Public validator admission is NOT announced by this flag day.** The
   admission spec's "not for public funds" sentence discharges only after
   `L` is past and one full withdrawal has settled on mainnet.

Also unchanged by arming: no independent cryptographic or consensus audit of
the combined lifecycle has been performed; the 2026-09-01 retractions of any
slashing-backed finality claim stay published (and are test-enforced) until a
prosecution has been observed on mainnet after 2700.

## Relationship to the other constants

`LEAK_RECOVERY_ACTIVATION_EPOCH` (2700) shares the boundary. `DEPOSIT_ACTIVATION_EPOCH`
stays `u64::MAX` permanently. `ANCESTRY_SEED`, `FEE_STAKE_DECOUPLE`,
`DUST_RULE`, `TX_BYTES_BOUND`, `ATTESTATION_DEDUP`, `REWARDS_V2`,
`FORKCHOICE_EQUIVOCATION_HORIZON`, `STAKING_TX_METERING` and
`SIGHASH_NETWORK_BINDING` remain `u64::MAX` (inert) and keep their own
tripwires; none of them is touched by this decision.
