# ADR-028: Tokenomics V2 Activation

**Sprint:** 2.2 (urgent — pre-mainnet activation gate)
**Status:** Accepted
**Date:** 2026-05-01
**Author:** BLOCH Founder
**Related:** ADR-010 (Tokenomics emission curve), ADR-010-A (Founder premine), ADR-010-Addendum-1 (Oracle pool), ADR-006 (Block time), ADR-018 (Oracle network)
**Supersedes:** None
**Superseded by:** None

> **Editorial note, 2026-08-12.** Two corrections to the header above, which
> was never updated: this ADR **is superseded** — its emission curve by
> ADR-035 (Emission V3), and the whole tokenomics model by V4
> (`crates/bloch-pos-committee/src/tokenomics_v4.rs`,
> `docs/specs/BLOCH-TOKENOMICS-V4.md`). And the tokenomics documents it
> references were moved to `legacy/` when the repository flipped to proof of
> stake; the paths below were rewritten to point at where the files actually
> are, so §3.1 and §4 read `legacy/specs/…` where in 2026-05 they said
> `docs/specs/…`. The decision itself is unchanged.

---

## 1. Context

Three tokenomics models existed in parallel in the repository as of 2026-05-01:

1. **TOKENOMICS_V1.md** (`docs/specs/TOKENOMICS_V1.md`, version 1.2) — specifies 4% founder premine (40M BLOCH) at genesis as a single coinbase output, 93/5/2 reward split (miner/oracle/treasury), 10-second block time, 1,000,020,000 BLOCH mining cap. **This was the model implemented in code** (commits `ac14295`, `825e0a1`).

2. **ADRs 010, 010-A, 010-Addendum-1** (committed at `5445935`) — specifies 17% founder premine (170M BLOCH) with 30-year linear vesting, 70/25/5 reward split (miner/validator/oracle), 150-second block time, 1B nominal supply with separate validator/oracle pool of 30M. **This model was approved at the architectural-decision level but not implemented in code.**

3. **Code** (`src/core/mod.rs:14-32` and `src/consensus/`) — implements model 1 (V1). The constants `MAX_SUPPLY = 1_000_020_000 * 100_000_000`, `FOUNDER_PERCENT = 4`, `BLOCK_REWARD = 2_381 * 100_000_000`, `TARGET_BLOCK_TIME = 10` are hardcoded. The 93/5/2 reward split is enforced in `src/consensus/`. No constants exist for `MINER_SHARE_BPS`, `VALIDATOR_SHARE_BPS`, `ORACLE_SHARE_BPS`, `TAIL_FLOOR_SAT`, or any `FOUNDER_VESTING_*` value.

4. **ROADMAP.md** — references model 1 numbers (4%, 1.00002B, 40M premine).

This three-way drift is a critical pre-mainnet defect. An audit firm reviewing the code against the ADRs would find immediate contradiction. Mainnet cannot activate with code and architectural-decision documentation specifying different consensus rules.

This ADR records the decision to resolve the drift in favor of the ADR-specified model (model 2), and renames it "Tokenomics V2".

## 2. Decision drivers

- **D1.** Howey defense maximization. 17% founder allocation with 30-year linear vesting is the most conservative founder structure of any major chain (ADR-010-A §3.3). 4% allocation with no on-chain vesting is significantly weaker for SEC and MiCA Article 6 defense.

- **D2.** Tier-1 exchange listing readiness. Coinbase, Kraken, and Binance review processes accept and reward conservative vesting schedules. 30-year lock removes vesting concerns from listing review entirely (ADR-010-A §3.3).

- **D3.** ADR authority. ADRs are the authoritative architectural decision record. When code and ADR diverge, code follows ADR (not the inverse). Treating the existing code as authoritative would invert the project's documentation discipline.

- **D4.** No backward-compatibility cost. Mainnet has not activated. V1 was specified and partially implemented but never deployed. Migrating to V2 has no user-facing cost.

- **D5.** ADR-006 consistency. ADR-006 specifies 150-second block time. Code's 10-second block time conflicts. V2 brings code into agreement with ADR-006 alongside the tokenomics changes.

- **D6.** Validator pool clarity. Distribution split 70/25/5 with explicit validator pool (25%) and oracle pool (5%) is more architecturally clean than 93/5/2 with implicit allocations. The 25% validator pool funds FFG validator incentives per ADR-007 bonding mechanism.

- **D7.** Tail floor robustness. V1 tail behavior is "subsidy → 0". V2 specifies 25 BLOCH/block tail floor, perpetual. Monte Carlo trajectories in `BLOCH_Tokenomics_MonteCarlo.pdf` showed tail-floor models produce significantly more robust security budgets in adverse scenarios (ADR-010 §3.5 M5 selection rationale).

- **D8.** Pre-mainnet timing window. The architectural decision in ADRs 010, 010-A, 010-Add-1 was made 2026-04-29. Implementing them takes ~4-6 days of focused work and must close before mainnet activation per `legacy/MAINNET-DEV-CHECKLIST.md`. Postponing reconciliation increases risk that genesis ceremony proceeds with inconsistent specs.

## 3. Considered options

### 3.1 Option A — V1 → V2 transition ✅ SELECTED

Implement the model specified in ADRs 010, 010-A, 010-Addendum-1. Rename V1 file to `TOKENOMICS_V1_SUPERSEDED.md` and place in `legacy/specs/historical/`. Create new `legacy/specs/TOKENOMICS_V2.md`. Refactor code per `legacy/MIGRATION-TOKENOMICS-V1-TO-V2.md`.

**Pros:**
- Aligns code with architectural decisions
- Maximizes Howey defense and listing readiness
- Resolves drift before audit
- Establishes clean V2 baseline for mainnet activation

**Cons:**
- 4-6 days of refactor work
- Re-tests required for all consensus tests
- Requires new founder address generation (ML-DSA-65 keystore) — already planned per `legacy/MAINNET-DEV-CHECKLIST.md` §9

### 3.2 Option B — Keep V1, mark ADRs Superseded

Reverse the resolution: keep code as-is, reject ADRs 010, 010-A, 010-Add-1 by marking them Superseded.

**Pros:**
- Zero refactor work
- Existing code coverage preserved

**Cons:**
- 4% premine without vesting is weak Howey defense
- 93/5/2 split has no separate validator pool (FFG validators receive nothing per-block; their compensation is entirely from fees, which is concerning if early fees are low)
- Block time 10s conflicts with ADR-006 (would need to change ADR-006 too, cascading)
- Indicates ADRs are aspirational rather than authoritative — bad organizational signal

### 3.3 Option C — Hybrid

Pick parts of V1 and V2 (e.g., V1's 4% premine but V2's 70/25/5 split). Document in a new V1.5 spec.

**Pros:**
- Less refactor than full V2

**Cons:**
- Multiplies complexity. The V1.5 spec would itself need an ADR. Auditors then face three specs to reconcile.
- No principled basis for selecting which V1 parts vs. V2 parts. Choices feel arbitrary.

## 4. Decision Outcome

**Option A — V1 → V2 transition.**

The decision was made by the BLOCH Founder on 2026-05-01 with the following confirmations:
- Cliff at block 207,260 (founder-specified)
- Vesting payout: per-block coinbase output to founder address (per V2 §5.3)
- No on-chain treasury (the 70/25/5 split has no separate treasury allocation; "BLOCH Labs treasury" exists only off-chain per ADR-023)
- Tail floor 25 BLOCH/block perpetual confirmed
- V1 file flagged as Superseded and archived in `legacy/specs/historical/`

V2 is the genesis configuration for mainnet activation per ADR-023 Phase 1.

## 5. Implementation

Per `legacy/MIGRATION-TOKENOMICS-V1-TO-V2.md`. Ten steps in execution order:

1. Documentation flip (V1 → SUPERSEDED, V2 in place, ADR-028)
2. Constants in `src/core/mod.rs`
3. Reward computation refactor
4. Founder vesting (new code)
5. Block time cascade 10s → 150s
6. Genesis tools update
7. Test refactor (V1 tests delete or rewrite, new V2 tests)
8. ROADMAP.md and README.md alignment
9. ADR closure (ADRs 010, 010-A, 010-Add-1 → "Accepted")
10. Final sanity checks + tag `v0.2.2-tokenomics-v2`

Estimated 4–6 days focused engineering. No backward-compatibility constraints.

## 6. Consequences

### Positive
- Code and ADR documentation consistent
- Genesis ceremony unblocked
- Audit-firm review will find no spec drift
- Howey-defense and listing-readiness positions strengthened
- FFG validator incentives properly funded (25% per-block)

### Negative
- Refactor effort (4–6 days)
- Test suite refactor with risk of introducing transient regressions
- Genesis tools need re-validation against V2 difficulty calibration

### Neutral
- Founder address generation timing unchanged (already planned per `legacy/MAINNET-DEV-CHECKLIST.md` §9)
- Mainnet activation timeline impact: small (4-6 days within an estimated 12-16 week pre-mainnet window)

## 7. Open questions

The following are flagged in `legacy/specs/TOKENOMICS_V2.md` §10 for resolution in a future ADR-010 revision (rev2). They do not block V2 activation:

- ADR-010 §3.5 quotes "asymptotic inflation ~0.05%/year"; actual math is 0.526%/year. Order-of-magnitude difference suggests typo or different baseline in ADR-010.
- ADR-010 mentions "endowment buffer (10% of fees)" and "emergency boost mode" but specific implementation is not yet present in code. To be added in Sprint 11+ work or an ADR-010-B.
- ADR-012 (validator/oracle pool internal distribution) marked "pending". The 30M pool exists in V2 but distribution mechanism within the pool is not specified by tokenomics; ADR-012 is the deliverable.

## 8. References

- `legacy/specs/TOKENOMICS_V2.md` — V2 specification (active)
- `legacy/specs/historical/TOKENOMICS_V1_SUPERSEDED.md` — V1 (archived)
- `legacy/MIGRATION-TOKENOMICS-V1-TO-V2.md` — engineering checklist
- `docs/adr/ADR-006-block-time.md` — 150s block time
- `docs/adr/ADR-010-tokenomics-emission.md` — emission curve specification
- `docs/adr/ADR-010-A-founder-premine.md` — 17% / 30-year vesting
- `docs/adr/ADR-010-Addendum-1-oracle-pool.md` — 70/25/5 split
- `docs/adr/ADR-018-oracle-network.md` — oracle compensation streams
- `legacy/MAINNET-DEV-CHECKLIST.md` — pre-mainnet engineering work
