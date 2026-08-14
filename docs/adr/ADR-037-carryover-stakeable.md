<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ADR-037 — A carried-over balance that is liquid is also stakeable

- **Status:** Accepted (founder decision, 2026-08-11) — **in force on the
  live chain.** Genesis-4 launched 2026-08-13 with the whole Genesis-3
  ledger carried across as one undifferentiated, liquid, stakeable set:
  452,726 outputs, 18,146,400,000 BLOCH, of which **93.94%
  (17,046,829,380) sits at a single address**
  (`LARGEST_CARRYOVER_ADDRESS_BLOCH`). The consequence this ADR names is
  therefore live, not hypothetical: **if that balance stakes, the Nakamoto
  coefficient is 1.** One qualification of fact, not of principle — today
  nothing can stake at all, because `Deposit` and `Delegate` are refused at
  every node's mempool while bonding is not funded from the UTXO set
  (`crates/bloch-pos-node/src/engine.rs:1901`). The decision is in force;
  the mechanism it authorises is not yet reachable.
- **Resolves:** `BLOCH-POS-NODE-INTEGRATION.md` §8.1 (the open ruling), and the
  question left open by migration §4.2 and tokenomics §4A ("liquid ≠
  stakeable")
- **Relates to:** `docs/specs/BLOCH-TOKENOMICS-V4.md` §4/§4A,
  `BLOCH-POS-NODE-INTEGRATION.md` decision 9 and §7.1,
  `crates/bloch-pos-committee/src/tokenomics_v4.rs`, ADR-038 (churn)

## Context

Tokenomics V4 brings the Genesis-3 ledger across as **one undifferentiated
set, liquid at genesis** (`CARRYOVER_TOTAL_BLOCH` in `tokenomics_v4.rs`; the
taint set and the holder cap dissolved with that single-set decision). Liquid,
however, did not settle *stakeable*: both normative documents left that open
on purpose, and the node-integration plan parked it as a founder decision
(§8.1), shaping the code so the ruling would arrive as data rather than a
rewrite — `StakeEligibility` receives the carryover policy as a genesis-
manifest input, and no eligibility rule is compiled in as a constant
(decision 9, §7.1).

The question is not small. It decides whether the largest carried-over
address (`LARGEST_CARRYOVER_ADDRESS_BLOCH` in `tokenomics_v4.rs` — a
measurement, not a class of coin) can convert its balance into consensus
weight from slot 0, and therefore on what timeline the activation gates
G1–G4 are reachable at all.

## Decision

**A carried-over balance that is liquid is also stakeable.** There is no
eligibility distinction between a carried-over coin and any other liquid
coin. Mechanically: the carryover-eligibility field the genesis manifest
feeds `StakeEligibility` (node-integration decision 9) is set to *eligible*;
the deposit path itself does not change.

## Consequences

**Recorded as under design, deliberately.** This ADR records that the
decision was taken and what it closes; the downstream analysis has not been
done, and inventing it here would be worse than stating that it is pending.

What is settled by the decision itself:

- Node-integration §8.1 closes. What it gated was the *launch manifest*, not
  a DEV milestone (decision 9 already decoupled the code), so no
  implementation work is unblocked or created — a manifest field is.
- The `Tainted` eligibility variant remains unreachable (§7.1), unchanged.
- No balance changes. The concentration arithmetic recorded on
  `CARRYOVER_TOTAL_BLOCH` and in tokenomics §4A stands exactly as written.

What is open and being designed — each item needs an owner and a written
answer before the launch manifest freezes:

1. **Interaction with the churn limit.** `delegation.rs` exempts epoch 0 from
   the warm-up budget. A fully stakeable carryover plus that exemption means
   the day-one stake distribution can be set by the largest carryover
   holders before `WARMUP_RATE_BPS` (ADR-038) ever binds. Whether the
   genesis exemption should apply to carryover deposits, be bounded, or be
   accepted and measured by the gates, is not decided.
2. **Gate timelines.** Tokenomics §4A must be re-run under "carryover stakes
   from slot 0" — the existing gate analysis models unlock schedules, not a
   stake-eligible carryover.
3. **Composition with the genesis-cohort cap.** `genesis_cohort.rs` bounds
   the *founding cohort's* combined weight; carryover staked outside the
   cohort by the same beneficial owner is not obviously inside that cap.
   Whether it should be, and whether that is even enforceable on-chain, is
   open.
4. **Public statement.** The concentration consequence of this decision is
   the kind of fact that must be published before launch, not discovered by
   readers of the genesis manifest. Owner and venue undecided.
