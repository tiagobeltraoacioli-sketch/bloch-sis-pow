# ADR-011: FFG Activation Block Height

**Sprint:** 2.1.C (constant) / 2.1.D (bonding lifecycle) / 2.1.E (reward split) / 2.2 (testnet validation)
**Status:** **SUPERSEDED** — FFG never activated. This ADR sets an activation height on a chain that stopped at 39,918 without ever reaching it, and its entire risk analysis (§5 R1, and the "pre-activation 51% attack vulnerability" consequence) is about **proof-of-work hashrate**, which no longer secures anything. **The risk that replaced it, at the same prominence:** the live risk is **concentration**, not hashrate — all 64 Genesis-4 validators are operated by a single entity, 93.94% of the carried ledger sits at one address and is stakeable, and 56,046,829,380 of the 57,146,400,000 BLOCH issued at genesis is held by the founder and the Foundation. One operator can halt the chain and one holder can outvote every other. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Proposed (revision 1 — Monte Carlo re-run integrated, ready for commit pre-2026-05-15)
**Date:** 2026-04-29 (rev1 same day)
**Author:** BLOCH Core
**Related:** ADR-001 (FFG signature scheme), ADR-002-rev1 (DKG protocol family), ADR-005 (committee era), ADR-006 (block time + dual finality), ADR-007 (bonding contract), ADR-010 (tokenomics + emission curve), ADR-010-A (founder premine), ADR-013 (open — tiered slashing / boost capacity revision)
**Amends:** ADR-001 (adds activation gate), ADR-002-rev1 (cancels genesis ceremony §3.4 D2 and R3), ADR-005 (era 1 starts at activation, not genesis), ADR-006 (finality levels gated on activation), ADR-007 (bonding `Pending` lifecycle), ADR-010 (pre-activation reward split)

**Changelog rev1 (2026-04-29):**
1. §3.2 (option B4) — replaced optimistic robustness claim with re-run Monte Carlo findings. Seed produces 9× larger endowment but only ~1pp collapse-rate improvement in adverse scenarios (boost rate-limited at 1.5%/year). Honest framing: regulatory cleanliness + R3 elimination + future governance optionality, not Crypto Winter resistance.
2. §5.1 — corresponding correction to consequences: endowment is larger, not "robustness substantially upgraded".

---

## 1. Context

The architectural pivot of 2026-04-29 (decision D2 in the Sprint 2.1 architectural decision document) committed BLOCH to hybrid PoW+PoS via FFG with a 21-of-21 BLS+ML-DSA-65 committee. Subsequent ADRs (002-rev1, 005, 006) specified the FFG mechanics assuming committee formation from genesis via a one-time HSM ceremony with 21 founder-declared hardcoded keys (ADR-002-rev1 §3.4 option D2).

This approach has three structural problems that surfaced during the cross-review with ADR-010-A:

1. **Founder cannot be a genesis validator.** The premine of 170M BLOCH is locked under a 30-year vesting curve (ADR-010-A): cliff of 12 months + linear vesting over 348 months. At block 0, the founder has **zero free BLOCH**. A founder-declared committee at genesis is therefore a committee of placeholders — operationally indistinguishable from a multisig with the founder's offline keys.

2. **No real bonded set exists at genesis.** Phragmén-elected committees (ADR-005) require a non-trivial bonded set as input. At genesis, total supply in circulation is 170M premine (locked) + 30M validator/oracle pool (custody TBD per ADR-012). No public participant can bond. The first 21 validators are necessarily allocated by issuer fiat.

3. **Genesis 21-key ceremony is the highest-criticality risk in Sprint 2.1.C** (ADR-002-rev1 §5.3 R3). Leak of any of the 21 BLS+ML-DSA-65 private shares before mainnet enables forgery of `FinalityCertificate`, reorg of finalized blocks, and censorship — all from a single point of failure that exists only because of the genesis-bootstrap design.

The fix is to defer FFG activation by a fixed number of blocks — long enough for genuine bonded set accumulation via PoW mining, and short enough to not erode the network's competitive finality story.

## 2. Decision Drivers

- **D1.** Founder must not be the only viable genesis validator. The 30-year premine lock is a defensive structure that loses its meaning if reversed at genesis to enable validator participation.
- **D2.** First committee should emerge from a real bonded set, not from issuer allocation. Phragmén on a real distribution is the entire premise of decentralization metrics (Nakamoto coefficient ≥ 14, ADR-005 §5.1).
- **D3.** Genesis HSM ceremony for 21 keys is high-cost (multi-party offline, geographic shard distribution, audit lineage) and high-risk (R3). Eliminating it is a strict improvement.
- **D4.** Activation height should align with existing protocol milestones to minimize narrative complexity and maximize comprehensibility for integrators and counsel.
- **D5.** Pre-activation period must be honest about its security model — PoW only, no BFT finality. Marketing must not blur this.
- **D6.** Reward distribution during the pre-activation period must remain consistent with the post-activation split (70/30) to avoid double discontinuities. The 30% share that would go to validators must be redirected to a non-discretionary destination.

## 3. Considered Options

### 3.1 Activation height

| Option | Block | Approx. duration @ 150s | Alignment | Assessment |
|--------|-------|-------------------------|-----------|------------|
| A1 | 0 (genesis) | 0 | None | Rejected — founder has 0 BLOCH, no bonded set, R3 catastrophic |
| A2 | 21,000 | ~5 weeks | None | Rejected — too short; mining bootstrap insufficient for real bonded set |
| A3 | 105,000 | ~6 months | None | Rejected — partial bootstrap; premine cliff not yet released |
| **A4** | **210,000** | **~1 year (364.58 days)** | **First halving + premine cliff end** | **Selected — three-way alignment** |
| A5 | 420,000 | ~2 years | Second halving | Rejected — too long; delays finality benefits and integrator adoption |

Option A4 is the unique choice that aligns three independent protocol milestones at a single block height:

- **First halving** (ADR-010): reward drops from 1905 to 952 BLOCH/block at block 210,000.
- **Premine cliff release** (ADR-010-A): founder's 12-month cliff ends at ~210,000 blocks @ 150s.
- **FFG activation** (this ADR): committee/DKG/finality go live at the same boundary.

This is one discontinuity in the protocol life cycle, not three.

### 3.2 Pre-activation reward split

| Option | Pre-activation 30% destination | Assessment |
|--------|-------------------------------|------------|
| B1 | 100% to miner (split is 100/0 pre-activation, 70/30 post) | Rejected — creates a dual discontinuity (split changes AND validators appear) at block 210,000 |
| B2 | Validator escrow pool, distributed to first elected committee as bonus | Rejected — 120M BLOCH distributed to 21 wallets in a single moment is regulatory red flag (SEC/MiCA delivery-to-group concern); creates lottery dynamics and pre-activation centralization race |
| B3 | Partial escrow (10% of reward), plurianial distribution | Rejected — mitigates but does not eliminate B2's concerns; mixes mechanisms |
| **B4** | **Endowment buffer seed (state, no wallet, no recipient)** | **Selected — non-discretionary, regulatorily clean, strengthens boost mode robustness** |

B4 redirects the 30% share that would have gone to validators (~120M BLOCH over the pre-activation year) into the endowment buffer specified by ADR-010. The endowment is **not a wallet** — it is consensus-tracked state with no key, no holder, and no transferable identity. The 30% accumulates as a seed; post-activation, the endowment's role reverts to its ADR-010 specification (10% of fees + 3% yield + boost mode).

The seed of ~120M BLOCH substantially increases endowment balance — from a year-50 median of ~12M BLOCH (without seed) to ~114M BLOCH (with seed) per re-run Monte Carlo (`Monte_Carlo_120M_Seed_Update.md`, 2026-04-29). This 9× larger reserve **does not materially reduce collapse rates** in adverse scenarios (Crypto Winter collapse drops only from ~62% to ~61%), because boost mode is rate-limited at 1.5%/year of balance, and price-collapse scenarios reduce that rate's USD value below the security threshold. The seed's primary value is in: (a) **regulatory cleanliness** — the destination is consensus state, not a recipient group, removing the SEC/MiCA delivery-to-group concern that motivated rejection of B2; (b) **eliminating the ADR-002-rev1 R3 risk** by removing the genesis ceremony entirely (no 21 hardcoded keys to leak); (c) **preserving the 30-year founder premine lock's defensive meaning** (founder cannot reverse the lock to enable validator participation, as the bonded set forms organically); and (d) **creating optionality for future governance** (ADR-013 open) to expand boost capacity from the current 1.5%/year rate or enable principal access during declared emergencies — only feasible if the principal exists. **Sustained price collapse remains an external risk that no tokenomics mechanism can absorb; demand-side resilience (RWA partnerships, listings, ecosystem activity) is the only defense against that scenario.**

## 4. Decision Outcome

**Consolidated decision:** A4 + B4.

### 4.1 Constants (in `src/consensus/types.rs`)

```rust
/// Block height at which FFG (Friendly Finality Gadget) activates.
///
/// Pre-activation: PoW-only consensus, no committee, no DKG, no BFT
/// finality. `FinalityLevel::Included` is the only level reachable.
///
/// Post-activation (height >= FFG_ACTIVATION_HEIGHT): hybrid PoW+FFG
/// per ADR-001/005/006. First Phragmén election runs against the
/// bonded set accumulated during the pre-activation year.
///
/// 210,000 blocks @ 150s = 31,500,000s = 364.58 days. Aligned with:
/// - First halving (ADR-010): reward 1905 → 952 BLOCH/block
/// - Founder premine cliff release (ADR-010-A): 12-month cliff ends
pub const FFG_ACTIVATION_HEIGHT: u64 = 210_000;

/// Predicate for FFG activation. Used by consensus, mempool, RPC,
/// and reward distribution paths.
#[inline]
pub const fn ffg_active_at(height: u64) -> bool {
    height >= FFG_ACTIVATION_HEIGHT
}
```

### 4.2 Pre/post-activation behavior

| Subsystem | Pre-activation (height < 210,000) | Post-activation (height ≥ 210,000) |
|-----------|------------------------------------|-------------------------------------|
| Consensus | PoW only (longest chain by GHOSTDAG) | PoW + FFG (Casper-style finality) |
| Committee | None | 21-of-21 with supermajority 14 |
| DKG | None | Per ADR-002-rev1 + ADR-005 (era boundaries) |
| Finality levels | `Included` only | `Included` / `SoftFinalized` / `HardFinalized` |
| Reward split | 70% miner / 30% endowment-seed | 70% miner / 30% validator |
| Endowment fee share | 10% of fees | 10% of fees (unchanged) |
| Bonding contract | Accepts bonds, status = `Pending` (escrow) | Bonds activate, eligible for Phragmén |
| Slashing | None (no committee to attest) | Per ADR-007 |
| RPC `eth_getBlockByNumber("finalized", ...)` | Returns latest block (PoW depth ≥ 100) as fallback | Returns hard-finalized block per ADR-006 |

### 4.3 Reward distribution function

```rust
// src/tokenomics/reward.rs

use crate::consensus::types::{ffg_active_at, FFG_ACTIVATION_HEIGHT};
use crate::tokenomics::types::{
    MINER_SHARE_BPS, VALIDATOR_SHARE_BPS, ENDOW_FEE_SHARE_BPS,
};

pub struct Distribution {
    pub miner: u128,
    pub validator: u128,    // 0 pre-activation
    pub endowment: u128,    // pre-activation: validator share + fee share
                            // post-activation: fee share only
}

pub fn distribute_block_reward(
    height: u64,
    block_reward: u128,
    total_fees: u128,
) -> Distribution {
    // Endowment fee share is constant across activation.
    let fee_to_endowment = total_fees * ENDOW_FEE_SHARE_BPS as u128 / 10_000;
    let fee_remaining = total_fees - fee_to_endowment;

    let total_distributable = block_reward + fee_remaining;
    let miner_share = total_distributable * MINER_SHARE_BPS as u128 / 10_000;
    let validator_or_seed_share = total_distributable - miner_share;

    if ffg_active_at(height) {
        Distribution {
            miner: miner_share,
            validator: validator_or_seed_share,
            endowment: fee_to_endowment,
        }
    } else {
        // Pre-activation: validator share redirects to endowment seed.
        Distribution {
            miner: miner_share,
            validator: 0,
            endowment: fee_to_endowment + validator_or_seed_share,
        }
    }
}
```

This function is consensus-critical — its output determines block validity. Property tests must include: (a) sum of all shares equals `block_reward + total_fees` exactly (no rounding leak), (b) validator share is exactly 0 pre-activation, (c) post-activation behavior matches ADR-010 specification.

### 4.4 Bonding lifecycle modification (ADR-007 input)

Bonding contract MUST accept submissions from block 0. Pre-activation:

- Bond is recorded in `CF_BONDING_REGISTRY` with `BondStatus::Pending`.
- BLOCH stake is locked (transfer-out forbidden).
- No rewards are accrued.
- No slashing is applicable (no committee to attest, no equivocation possible).
- Voluntary unbonding starts the 21-day unbonding clock per ADR-007 §4.3 — but the clock counts blocks, not wall time.

At block 210,000, all `Pending` bonds with `bonded_amount >= MIN_BOND_AMOUNT` and `bonded_since_block + MIN_PRE_ACTIVATION_BONDING_BLOCKS <= 210_000` transition atomically to `BondStatus::Active` and become eligible for the first Phragmén election (era 1 selection at block 210,000 epoch 0).

`MIN_PRE_ACTIVATION_BONDING_BLOCKS` is set to 4032 blocks (~7 days @ 150s) to prevent last-minute strategic bonding. ADR-007 specifies the constant.

### 4.5 Migration semantics at block 210,000

Block 210,000 itself executes a state transition equivalent to a soft-fork activation. The transition is **atomic within the block executor**: either all sub-transitions succeed or the block is invalid.

```rust
// Pseudocode in src/consensus/executor.rs
pub fn execute_block(block: &Block, state: &mut State) -> Result<(), BlockError> {
    let height = block.header.height;

    // ... normal block execution (txs, reward distribution, etc.) ...

    // FFG activation transition (only at exactly height = 210_000)
    if height == FFG_ACTIVATION_HEIGHT {
        ffg_activation_transition(state)?;
    }

    Ok(())
}

fn ffg_activation_transition(state: &mut State) -> Result<(), BlockError> {
    // 1. Promote eligible Pending bonds → Active
    state.bonding_registry.activate_eligible_bonds(FFG_ACTIVATION_HEIGHT)?;

    // 2. Refuse activation if bonded set < 21 (ADR-003 cross-ref)
    let active_bonds = state.bonding_registry.active_count();
    if active_bonds < 21 {
        return Err(BlockError::FfgActivationInsufficientBonds(active_bonds));
    }

    // 3. Run first Phragmén → produces era 1 committee + alternates
    let phragmen_input = state.bonding_registry.to_phragmen_input();
    let phragmen_output = run_phragmen(phragmen_input)?;

    // 4. Initialize CommitteeRegistry with era 1 = first elected committee
    state.committee_registry.finalize_genesis(phragmen_output)?;

    // 5. Schedule first DKG ceremony (epoch 12 of era 1, per ADR-005 §4.5)
    state.dkg_storage.schedule_ceremony(genesis_dkg_config_for_era_1())?;

    // 6. Switch finality levels: Included only → Included/SoftFinalized/HardFinalized
    //    (no state change needed — gated by ffg_active_at() in finality computation)

    Ok(())
}
```

The fallback for step 2 (insufficient bonds at activation) is **chain-halt-pending-recovery** — the block is invalid, mining continues without ability to finalize block 210,000. ADR-009 (open) must specify the recovery protocol (likely: extend pre-activation period by N blocks, retry; if persistent, governance vote via off-chain coordination). This risk is judged low: with 1 year of bootstrap and reasonable mining hashrate, accumulating 21 bonded operators of 100k BLOCH each (~2.1M BLOCH total) is trivially achievable against ~280M BLOCH distributed via mining.

## 5. Consequences

### 5.1 Positive

- **Eliminates ADR-002-rev1 R3 entirely.** No genesis HSM ceremony, no 21 hardcoded keys, no single-point-of-failure key custody. The DKG ceremony at era 1 uses the first Phragmén-elected committee — the same mechanism that runs every era thereafter.
- **Founder premine architecture preserved.** The 30-year lock retains its defensive meaning. Founder participation as validator can occur naturally years later via vested BLOCH.
- **First committee is genuinely decentralized.** Phragmén over a year-bootstrapped bonded set produces Nakamoto coefficient ≥ 14 from era 1, not from era 2.
- **Three-way milestone alignment.** First halving + premine cliff release + FFG activation at block 210,000 is one event, not three. Whitepaper, integrator docs, and counsel narrative simplify accordingly.
- **Endowment balance substantially larger; collapse-rate impact modest.** ~120M BLOCH seed produces a 9× larger reserve at year 50 (~114M vs ~12M without seed). This does **not** materially reduce adverse-scenario collapse rates (Crypto Winter: ~62% → ~61%) because boost mode is rate-limited at 1.5%/year and price-collapse reduces its USD value below threshold. The seed's value is regulatory cleanliness, R3 elimination, and optionality for future governance to expand boost capacity (ADR-013 open). Demand-side resilience remains the only defense against sustained price collapse.
- **No regulatory red flag from validator pool distribution.** The 30% pre-activation share goes to consensus state (the endowment), not to a defined group of recipients.

### 5.2 Negative

- **One year without BFT finality.** During blocks 0 → 210,000, the chain is PoW-only. Re-orgs at PoW depths typical of low-hashrate chains are possible. Acceptable trade-off given the alternative (forged FFG via leaked genesis keys) is strictly worse.
- **Pre-activation 51% attack vulnerability.** Standard PoW concern; mitigated by initial reward of 1905 BLOCH/block (high attractiveness for honest miners) and by the fact that pre-activation has lower economic value (no FFG-finalized assets to double-spend). Post-activation, FFG provides safety against attacks even with hashrate volatility.
- **Bonding capital is locked without yield for up to 1 year.** Early bonders accept opportunity cost. Mitigation: era-1 committee selection is deterministic via Phragmén — early bonders with sufficient stake have predictable election odds, providing implicit time-value compensation through priority access to the post-activation reward stream.
- **Whitepaper and integrator documentation must clearly distinguish pre-FFG and post-FFG security models.** "BLOCH has 30-minute hard finality" is true only for blocks ≥ 210,000. Marketing failure here = R5.

### 5.3 Open risks

> **Editorial note, 2026-08-14 — none of R1–R5 is an open risk any more, and
> one of them must not be left standing as a disclosure.** FFG never activated;
> Genesis-3 stopped at 39,918 without reaching this ADR's activation height,
> and Genesis-4 is proof of stake with no mining. **R1's 51%-with-low-hashrate
> warning therefore describes nothing.** The risk that stands in its place, at
> the same weight: **concentration.** All 64 Genesis-4 validators are operated
> by a single entity; 93.94% of the carried ledger (17,046,829,380 of
> 18,146,400,000 BLOCH) sits at one address and is stakeable, so the Nakamoto
> coefficient is 1 if it stakes; 56,046,829,380 of the 57,146,400,000 BLOCH
> issued at genesis is founder- or Foundation-held; and a third party can
> neither join the network (fixed peer list, no discovery, no authentication)
> nor become a validator (`Deposit`/`Delegate` refused at every mempool). One
> operator can halt the chain. The list below is retained unedited as the
> record of what was foreseen at the time.

- **R1.** Pre-activation 51% attack with sustained low hashrate. Mitigation: initial reward calibrated for hashrate attractiveness; foundation-funded mining incentives if needed. Already an open consideration in ADR-010 (mining attractiveness ramp-up phase).
- **R2.** Bug in `ffg_active_at` predicate or its consumers. A wrong activation gate (e.g., off-by-one) causes silent consensus divergence. Mitigation: predicate is a single function, used in <10 call sites, exhaustively tested with property tests including height = 0, 209_999, 210_000, 210_001.
- **R3.** Insufficient bonded set at block 210,000 → activation fails per §4.5 step 2. Mitigation: monitor bonded set growth via dashboard; foundation incentivizes early bonding if accumulation is slow at month 9-10. ADR-009 (open) specifies recovery protocol.
- **R4.** Endowment seed accounting bug. Pre-activation, the validator share redirects to endowment; an off-by-one in `distribute_block_reward` or the endowment receiver could over- or under-credit by significant amounts (~120M BLOCH across the year). Mitigation: property tests assert exact conservation; auditing focuses on reward distribution as critical surface.
- **R5.** Public communication failure regarding pre-activation finality model. If users assume FFG safety pre-activation, real economic harm is possible. Mitigation: explicit disclaimers in RPC responses (`"finalityModel": "pow-only"` until activation), integrator SDK warnings, whitepaper section dedicated to the activation timeline.

## 6. Implementation Plan

### Sprint 2.1.C — Constants and predicate

- [ ] Add `FFG_ACTIVATION_HEIGHT` and `ffg_active_at` to `src/consensus/types.rs`.
- [ ] Property tests for predicate: heights 0, 209_999, 210_000, 210_001, u64::MAX.
- [ ] **Amend ADR-002-rev1**: remove §3.4 D2 (genesis 21 hardcoded keys) and §5.3 R3 (genesis key leak); replace with cross-ref to this ADR. The first DKG ceremony runs at era 1 epoch 12 = block 210_000 + 12 × 6 = 210_072, using the Phragmén-elected committee from §4.5 step 3.

### Sprint 2.1.D — Bonding lifecycle

- [ ] In ADR-007, specify `MIN_PRE_ACTIVATION_BONDING_BLOCKS = 4032`.
- [ ] `BondingRegistry::activate_eligible_bonds(activation_height)` method.
- [ ] `BondStatus::Pending` variant with full transition matrix to `Active`.
- [ ] Tests: bond at block 0, advance to 210_000, verify activation; bond at block 209_999, verify rejection due to insufficient pre-activation duration.

### Sprint 2.1.E — Reward distribution

- [ ] Implement `distribute_block_reward()` in `src/tokenomics/reward.rs`.
- [ ] Property tests: conservation, pre/post-activation invariants, edge cases at height 209_999/210_000.
- [ ] Integration test: simulate 100 blocks pre-activation, verify endowment accumulates ~190,500 × 30% × 100 = ~5.7M BLOCH of seed; advance to block 210_000, verify activation transition.

### Sprint 2.2 — Testnet validation

- [ ] Devnet with `FFG_ACTIVATION_HEIGHT` lowered to 1000 for fast iteration.
- [ ] End-to-end test: bond 21 operators at blocks 100-900, advance to block 1000, verify Phragmén runs, verify first committee active, verify DKG ceremony schedules.
- [ ] Adversarial tests: insufficient bonded set (only 20 active at activation), strategic last-minute bonding (rejected), endowment over-credit attempts.

### Sprint 2.3 — Documentation and counsel review

- [ ] Re-run Monte Carlo simulations with 120M endowment seed to confirm robustness profile.
- [ ] Whitepaper section on activation timeline with explicit pre/post-FFG security model.
- [ ] Integrator documentation: `docs/integrators/finality.md` includes "activation timeline" subsection.
- [ ] Counsel review of pre-activation period framing for SEC/MiCA opinion letters.

## 7. Future Work

- **ADR-009 (open):** activation failure recovery protocol (R3 fallback).
- **ADR-012 (open):** validator/oracle pool 30M structure — will reference this ADR for activation alignment.
- **Post-mainnet audit:** reward distribution (`distribute_block_reward`) is consensus-critical surface; specific audit module recommended.

## 8. References

- ADR-001 — FFG signature scheme
- ADR-002-rev1 — DKG protocol family (genesis ceremony obsoleted by this ADR)
- ADR-005 — Committee era and rotation
- ADR-006 — Block time and dual finality
- ADR-007 (open) — Bonding contract and slashing
- ADR-009 (open) — Activation/DKG failure recovery
- ADR-010 — Tokenomics and emission curve
- ADR-010-A — Founder premine (cliff release alignment)
- `BLOCH_Hybrid_MonteCarlo.pdf` (2026-04-29) — endowment growth analysis (to be re-run with 120M seed)
- `BLOCH_Adverse_Scenarios.pdf` (2026-04-29) — Crypto Winter resilience (to be re-run)
- Sprint 2.1 architectural decision document (BLOCH Core, 2026-04-29)
