<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ADR-038 — Warm-up churn rate lowered 900 → 25 bps, floor raised to `MIN_CHURN_SAT`

- **Status:** Accepted and applied (founder decision, 2026-08-11; commit
  `e268838`) — **in the code the live chain runs.** `WARMUP_RATE_BPS` and
  `MIN_CHURN_SAT` in `crates/bloch-pos-committee/src/delegation.rs` are
  consensus constants of Genesis-4, live since 2026-08-13. Note that no
  churn has been exercised: delegation is refused at every mempool while
  bonding is not funded from the UTXO set.
- **Responds to:** `BLOCH-POS-THREAT-MODEL.md` §F8;
  `docs/specs/BLOCH-POS-STAKE-CHURN.md` (A6's assessment and pricing — the
  analysis of record, not restated here)
- **Code:** `crates/bloch-pos-committee/src/delegation.rs` —
  `WARMUP_RATE_BPS`, `MIN_CHURN_SAT` (the constants are the authority; this
  ADR records why they changed, not what they are)

## Context

The previous value, `WARMUP_RATE_BPS = 900`, was Solana's warm-up numeral
ported without Solana's clock. A Solana epoch is ~48 hours; a Bloch epoch is
16 minutes; the same percentage therefore ran ~180× faster in wall-clock
time. From zero to the one-third finality-stall threshold took ~75 minutes —
the activation queue is public, but no human process reacts to a hostile
queue in 75 minutes, so the limit defended nothing. A6's conclusion stands
as the finding of record: *900 bps on a 16-minute epoch was a transcription
error, not a design choice.*

A churn limit buys exactly one thing — the interval during which a
takeover-in-progress is publicly visible, measured against detection and
response time. It stops nobody who already holds the coins. The full dial
(rate → wall-clock-to-1/3, and the diminishing returns past ~one day) is in
`BLOCH-POS-STAKE-CHURN.md`.

## Decision

1. **`WARMUP_RATE_BPS` lowered from 900 to 25** (zero → 1/3 now ≈162 epochs,
   ~43 hours — about two working days of visible hostile queue).
2. **The per-epoch budget floor rises** from `MIN_DELEGATION_SAT` to
   `MIN_CHURN_SAT = MIN_DEPOSIT_SAT` — one validator's minimum deposit per
   epoch. At 25 bps the proportional budget is below one deposit until the
   active set is large, so the old 10-BLCH floor would have been the
   effective limit and would have strangled onboarding on a young network.
   The floor also preserves the drain-termination property it always
   existed for.
3. **Retained unchanged:** the epoch-0 genesis exemption, and the F3 sliced
   activation/cool-down (the ceiling holds absolutely, in both directions).
4. **Tests derive, not restate.** The churn tests were re-pinned to derive
   their horizons from the constant (`epochs_to_grow_by`) and read the
   ceiling from `WARMUP_RATE_BPS`, instead of hard-coding epoch counts that
   would silently survive a future rate change.

## Consequences

- **The liveness bill is symmetric and accepted.** Warm-up and cool-down
  share the budget, so lowering the rate slows honest actors exactly as much
  as attackers: onboarding a large participant moves from minutes to hours,
  doubling the active set from hours to days, and — the cost that lands on
  honest validators — after a slashing scare or key-compromise disclosure,
  stake stays bonded and slashable for ~43 hours instead of ~1. The itemised
  bill is in the churn document; it was priced before the decision, not
  discovered after.
- **The defense is visibility time, and only that.** Beneficial ownership is
  invisible on-chain; the 1% per-validator cap is Sybil-bypassed by
  splitting. Nothing about this change claims otherwise.
- **Phase 2 is flagged, not sized:** an absolute cap
  (`clamp(total × rate, MIN_CHURN_SAT, MAX_CHURN)`) so attack time grows
  with the network instead of staying constant. Sizing `MAX_CHURN` needs
  real staking data and is deliberately deferred.
- **This is a consensus parameter.** Any future change is a founder decision
  with the tests re-pinned — the dial in `BLOCH-POS-STAKE-CHURN.md` is the
  whole trade space.
- The interaction between the epoch-0 exemption and the stakeable carryover
  is recorded as an open design item in **ADR-037**, not here.
