// SPDX-License-Identifier: AGPL-3.0-or-later

//! The L1 fee market: one market, one unit (gas), one protocol-set price.
//!
//! Spec: `docs/specs/BLOCH-L1-FEE-MARKET.md`. This module is the arithmetic
//! authority for that spec, the same way `tokenomics_v4.rs` is for the
//! tokenomics: every number in the prose is the value of a constant here.
//!
//! ## The three transaction classes and the one price
//!
//! A Genesis-4 block carries eUTXO transfers, EVM transactions and Coherence
//! shielded transactions. They consume different resources — an eUTXO input
//! costs a hybrid ML-DSA-65 ‖ Falcon-1024 verification (measured **7,274,849**
//! RV32IM instructions, `spikes/prover-cost/RESULTS.md`) and ≈ 4.6 KB of
//! signature bytes; an EVM transaction costs computation and state; a shielded
//! transaction costs a FRI-STARK proof verification and tens-to-hundreds of KB
//! of proof bytes (`COHERENCE-C1.md`). The design still charges them in a
//! single unit, **gas**, through per-class cost functions, because the scarce
//! resource they all contend for is the same one: **block bytes under the
//! gossip budget** (gate G10 of the migration spec). A per-byte gas charge
//! makes that shared scarcity the dominant term for every class; per-class
//! verify charges price the CPU on top. The cost of the single market —
//! cross-subsidised congestion, where EVM demand raises shielded prices — is
//! accepted and stated in the spec (§2.3), and the controller below already
//! measures bytes and gas separately, so a second price dimension can be added
//! later without changing the unit.
//!
//! ## Units and overflow
//!
//! Gas is `u64` per transaction and per block. The price is in **millisatoshi
//! per gas** (1 msat = 10⁻³ sat = 10⁻¹¹ BLCH): with only 8 decimals, a price
//! quoted in whole satoshis per gas cannot step by ±1/8 near the floor without
//! 100% jumps. Fees settle in whole satoshis, rounded **up** — rounding down
//! would hand every transaction a fractional-satoshi subsidy. All fee
//! arithmetic is `u128`, per this crate's rule: it is the products that
//! overflow, not the totals. The compile-time assertions at the bottom pin the
//! headroom.
//!
//! ## What is deliberately NOT here
//!
//! Transaction parsing (transactions are opaque bytes to this crate, §1.2)
//! and the EVM's own opcode schedule (adopted 1:1 from Ethereum's live
//! schedule by the spec, with the calldata term zeroed because envelope bytes
//! are already charged here).
//!
//! What used to be on this list and no longer is, as of 2026-08-12: the
//! base-fee state leaf (`state_root::BaseFeeRecord` under `TAG_BASE_FEE`) and
//! the wiring itself. `transition.rs` now derives each block's price from the
//! parent's committed leaf, charges every transaction through [`charge`],
//! enforces both per-block caps, and settles the producer's share through
//! [`distribute_producer_fees`] at the epoch boundary. This module is still
//! only the arithmetic — but the arithmetic is called now.

use crate::rewards::{Payout, StakeAccount, BPS, MAX_COMMISSION_BPS};
use crate::tokenomics_v4::{SAT_PER_BLOCH, TOTAL_SUPPLY_SAT};

// ── Block capacity: the two consensus caps ──────────────────────────────────

/// Hard cap on the **transaction payload** bytes of one block (attestations
/// are budgeted separately by the protocol itself — committee sizes bound
/// them). 256 KiB: sized so that one worst-case C1 shielded proof
/// ("tens–hundreds of KB", `COHERENCE-C1.md` §; must be pinned by measurement
/// before activation) fits in a block at all. A block exceeding this is
/// invalid regardless of gas.
pub const MAX_BLOCK_TX_BYTES: u64 = 262_144;

/// Hard cap on gas per block. 60 M gas per 30 s slot = 2 M gas/s, the same
/// order as Ethereum's 36 M per 12 s. In practice bytes bind first for
/// signature-heavy traffic (the `bytes_bind_before_gas` test pins this); the
/// gas cap is the CPU/state backstop for compute-heavy EVM blocks.
pub const BLOCK_GAS_LIMIT: u64 = 60_000_000;

/// EIP-1559 targets: half of each cap. A block at target on both axes leaves
/// the base fee unchanged.
pub const BLOCK_GAS_TARGET: u64 = BLOCK_GAS_LIMIT / 2;
pub const BLOCK_TX_BYTES_TARGET: u64 = MAX_BLOCK_TX_BYTES / 2;

/// The post-flag-day payload cap: 512 KiB.
///
/// The V1 cap fits ~30 deduplicated-witness-free transfer inputs (8,560 B
/// each); doubling it doubles every byte-bound count on the chain, and bytes
/// are what bind — a payload-saturated block spends 8,388,608 of the 60 M gas
/// cap, so gas has room for the raise and the `capacity_v2_still_gas_bound`
/// assertion below pins that it still does.
pub const MAX_BLOCK_TX_BYTES_V2: u64 = 524_288;
pub const BLOCK_TX_BYTES_TARGET_V2: u64 = MAX_BLOCK_TX_BYTES_V2 / 2;

/// The payload cap in force at `epoch`.
///
/// Every consensus site must ask through here rather than reading a constant,
/// so that lowering [`crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH`] moves
/// the whole chain at once. `epoch` must be derived from the block's own
/// header slot: a cap read from node-local state is how a fleet on one binary
/// splits.
pub const fn max_block_tx_bytes(epoch: u64) -> u64 {
    if epoch < crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH {
        MAX_BLOCK_TX_BYTES
    } else {
        MAX_BLOCK_TX_BYTES_V2
    }
}

/// The EIP-1559 byte target in force at `epoch`. Always half of
/// [`max_block_tx_bytes`] at the same epoch — pinned by
/// `target_is_half_the_cap_in_both_eras`.
pub const fn block_tx_bytes_target(epoch: u64) -> u64 {
    if epoch < crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH {
        BLOCK_TX_BYTES_TARGET
    } else {
        BLOCK_TX_BYTES_TARGET_V2
    }
}

// ── Gas costing ─────────────────────────────────────────────────────────────

/// Gas per payload byte. Ethereum's non-zero-calldata price, kept because it
/// is the one number the entire EVM ecosystem has already internalised, and
/// because at 16 gas/byte the byte term dominates exactly the transactions
/// whose bytes dominate the network (a hybrid signature alone is
/// `HYBRID_SIG_BYTES * GAS_PER_BYTE` = 73,424 gas).
pub const GAS_PER_BYTE: u64 = 16;

/// Flat per-transaction overhead: mempool admission, nonce/UTXO lookup,
/// receipt. Deliberately small — the real costs are priced explicitly.
pub const TX_FLAT_GAS: u64 = 5_000;

/// Measured size of one hybrid ML-DSA-65 ‖ Falcon-1024 signature
/// (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §6.5).
pub const HYBRID_SIG_BYTES: u64 = 4_589;

/// Measured cost of one hybrid verification: 7,274,849 RV32IM instructions
/// (`spikes/prover-cost/RESULTS.md`, 2026-08-10, PQClean verifiers).
pub const HYBRID_VERIFY_INSTRUCTIONS: u64 = 7_274_849;

/// Calibration: 1 gas = 100 RV32IM instructions. Chosen so that native
/// verification costs land on the same scale as the adopted EVM opcode
/// schedule (a Keccak permutation, ~3–5 k instructions, prices at ~30–50 gas
/// against EVM's 30 + 6/word for SHA3). All native costs derive from measured
/// instruction counts through this one ratio, so recalibration is one edit.
pub const INSTRUCTIONS_PER_GAS: u64 = 100;

/// Gas for one hybrid PQ signature verification: 72,748.
pub const HYBRID_VERIFY_GAS: u64 = HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS;

/// Gas for one secp256k1 verification, **priced but gated**: it exists so the
/// dual-authorisation options in the fleet brief can be compared in fee terms
/// (ECRECOVER's 3,000 gas, the EVM precedent). Whether secp256k1 accounts
/// exist at L1 at all is the founder's decision, not this module's.
pub const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas for verifying one Coherence FRI-STARK proof. **PROVISIONAL** — set at
/// the hybrid-verify cost times a placeholder factor until the verifier is
/// measured the way the signature verifiers were (`coherence-prover` has the
/// harness). The spec forbids activation with this number unmeasured.
pub const SHIELDED_VERIFY_GAS_PROVISIONAL: u64 = 25 * HYBRID_VERIFY_GAS;

/// The transaction classes a block can carry, for intrinsic-gas purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxClass {
    /// eUTXO transfer: `inputs` is **the number of hybrid verifications the
    /// node will actually run**, one gas term per real check — gas buys node
    /// CPU. Under the V1 format that is one per input (each input carries
    /// its own witness); under the deduplicated `TransferV2` (tag `0x06`,
    /// inert until `params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`) it is
    /// one per witness-table entry — per owner — because a single signature
    /// over the shared signing root authorises all of that owner's inputs.
    /// Both callers derive the count from their lists; nothing asserts it.
    Eutxo { inputs: u32 },
    /// EVM transaction from a PQ (hybrid) account: one envelope verification.
    EvmPq,
    /// EVM transaction from a secp256k1 account — **gated** on the founder's
    /// dual-authorisation decision; priced so the options are comparable.
    EvmSecp256k1,
    /// Coherence shielded transaction: one proof verification. The proof's
    /// bytes are charged like any other bytes.
    Shielded,
}

/// Verification gas for a transaction class.
pub const fn verify_gas(class: TxClass) -> u64 {
    match class {
        TxClass::Eutxo { inputs } => HYBRID_VERIFY_GAS.saturating_mul(inputs as u64),
        TxClass::EvmPq => HYBRID_VERIFY_GAS,
        TxClass::EvmSecp256k1 => SECP256K1_VERIFY_GAS,
        TxClass::Shielded => SHIELDED_VERIFY_GAS_PROVISIONAL,
    }
}

/// Intrinsic gas: what a transaction owes before a single opcode runs —
/// flat + bytes + verification. Charged unconditionally on inclusion, so a
/// transaction that fails execution still pays for the bytes it made every
/// node carry and the signatures it made every node check. EVM execution gas
/// is on top of this, metered by the adopted EVM schedule.
pub const fn intrinsic_gas(class: TxClass, tx_bytes: u64) -> u64 {
    TX_FLAT_GAS
        .saturating_add(tx_bytes.saturating_mul(GAS_PER_BYTE))
        .saturating_add(verify_gas(class))
}

// ── The price: EIP-1559 base fee, one controller over two resources ─────────

/// Millisatoshis per satoshi — the price resolution.
pub const MILLISAT_PER_SAT: u128 = 1_000;

/// Price floor, and the genesis base fee. At the floor a minimal eUTXO
/// transfer costs on the order of a thousand satoshis (10⁻⁵ BLCH) — a spam
/// floor, not a revenue device.
pub const MIN_BASE_FEE_MILLISAT_PER_GAS: u128 = 10;

/// Price ceiling: the price at which ONE gas costs the entire supply. Nothing
/// economic happens near it; it exists so the controller's growth is bounded
/// by construction and the overflow assertions below are proofs, not hopes.
pub const MAX_BASE_FEE_MILLISAT_PER_GAS: u128 = TOTAL_SUPPLY_SAT * MILLISAT_PER_SAT;

/// Maximum base-fee change per block: ±1/8, Ethereum's constant.
pub const BASE_FEE_CHANGE_DENOMINATOR: u128 = 8;

/// What the parent block actually used, for the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockUsage {
    pub gas_used: u64,
    pub tx_bytes: u64,
}

/// Next block's base fee from the parent's base fee and usage.
///
/// EIP-1559's controller with one change: utilisation is the **maximum of the
/// gas axis and the byte axis**, compared by cross-multiplication so the whole
/// thing stays in integers. Plain EIP-1559 over gas alone would misprice this
/// chain: a block full of eUTXO transfers saturates `MAX_BLOCK_TX_BYTES`
/// while using well under a tenth of the gas cap (bytes bind first — see the
/// capacity test), and a gas-only controller would read that byte-saturated
/// block as slack and *lower* the price of the resource that is actually
/// exhausted. Taking the max means the base fee always tracks whichever
/// resource is scarce; the cost is that it cannot price both independently —
/// accepted, spec §2.3.
///
/// Deterministic from parent-committed values only (§5.5 — no node-local
/// state). Skipped slots produce no block and therefore no update; the base
/// fee carries over unchanged, which under-reacts to demand spikes during
/// outages and is preferred to any clock-dependent rule.
pub const fn next_base_fee(parent_base_fee: u128, parent: BlockUsage, epoch: u64) -> u128 {
    // The byte target is epoch-gated (`BLOCK_BYTES_V2_ACTIVATION_EPOCH`), so it
    // is read here rather than named as a constant. `epoch` is the epoch the
    // price will be CHARGED in, not the parent's: at the flag-day boundary the
    // parent's usage was produced under the old cap, but the block this price
    // applies to lives under the new one, and pricing it against the old target
    // would read a legal 300 KiB block as 2.3x over target.
    let byte_target = block_tx_bytes_target(epoch);
    // Which axis is more utilised: gas/GT >= bytes/BT  <=>  gas*BT >= bytes*GT.
    let gas_cross = parent.gas_used as u128 * byte_target as u128;
    let bytes_cross = parent.tx_bytes as u128 * BLOCK_GAS_TARGET as u128;
    let (used, target) = if gas_cross >= bytes_cross {
        (parent.gas_used as u128, BLOCK_GAS_TARGET as u128)
    } else {
        (parent.tx_bytes as u128, byte_target as u128)
    };

    let base = clamp_base_fee(parent_base_fee);
    if used == target {
        return base;
    }
    if used > target {
        let delta = base * (used - target) / target / BASE_FEE_CHANGE_DENOMINATOR;
        // A congested block must always move the price: floor the step at 1.
        let delta = if delta == 0 { 1 } else { delta };
        clamp_base_fee(base + delta)
    } else {
        let delta = base * (target - used) / target / BASE_FEE_CHANGE_DENOMINATOR;
        clamp_base_fee(base - delta)
    }
}

const fn clamp_base_fee(v: u128) -> u128 {
    if v < MIN_BASE_FEE_MILLISAT_PER_GAS {
        MIN_BASE_FEE_MILLISAT_PER_GAS
    } else if v > MAX_BASE_FEE_MILLISAT_PER_GAS {
        MAX_BASE_FEE_MILLISAT_PER_GAS
    } else {
        v
    }
}

/// Settle a transaction's fee in whole satoshis: `(base_sat, tip_sat)`.
///
/// Both parts round **up** (a truncating division would let `gas *
/// price < 1000` msat cost zero satoshis — free gas, and free gas is a DoS
/// invitation at exactly the granularity an attacker controls). These are the
/// two figures `rewards::split_fees_at` consumes as `base_fee` and
/// `priority_fee`.
pub const fn fee_parts_sat(
    gas_used: u64,
    base_fee_millisat_per_gas: u128,
    tip_millisat_per_gas: u128,
) -> (u128, u128) {
    (
        ceil_div(gas_used as u128 * base_fee_millisat_per_gas, MILLISAT_PER_SAT),
        ceil_div(gas_used as u128 * tip_millisat_per_gas, MILLISAT_PER_SAT),
    )
}

const fn ceil_div(n: u128, d: u128) -> u128 {
    n / d + if n % d != 0 { 1 } else { 0 }
}

// ── Producer fees through the delegation split ──────────────────────────────

/// Distribute a block producer's fee share (`FeeSplit::to_producer`) across
/// the producer's stake account — same commission rule as issuance
/// (`rewards::distribute`), **no credits scaling**: producing the block *is*
/// the performance, there is nothing further to forfeit.
///
/// This exists because of the year-40 boundary. `rewards::distribute` pays
/// delegators from `epoch_issuance`, which `tokenomics_v4` sets to zero after
/// `EMISSION_SLOTS` — at which point fees become validators' entire revenue
/// (spec §6.3.2). If fees were credited raw to the operator (as
/// `transition.rs` did until 2026-08-12), delegator revenue would go to
/// exactly zero at the moment fees become everything, and the delegation
/// design — the thing that lets stake exist without running a validator —
/// would collapse at the fee-only boundary. Routing fees through the same
/// commission split keeps delegation economically alive in both eras. The
/// `delegation_survives_fee_only_era` test pins the arithmetic;
/// `transition::tests::producer_fees_reach_delegators_through_the_commission_split`
/// pins that the transition actually calls it.
///
/// This answers "how much do delegators get". [`split_delegator_fees`]
/// answers "which delegator gets what".
pub fn distribute_producer_fees(acct: &StakeAccount, producer_fee_sat: u128) -> Payout {
    let stake = acct.self_stake + acct.delegated_stake;
    if stake == 0 {
        // No recorded stake: the fee still belongs to whoever produced the
        // block. Degenerate, but a defined answer beats a panic in consensus.
        return Payout { operator: producer_fee_sat, delegators: 0, forfeited: 0 };
    }
    let delegator_gross = producer_fee_sat * acct.delegated_stake / stake;
    let operator_gross = producer_fee_sat - delegator_gross;
    let commission = delegator_gross * acct.commission_bps.min(MAX_COMMISSION_BPS) / BPS;
    Payout {
        operator: operator_gross + commission,
        delegators: delegator_gross - commission,
        forfeited: 0,
    }
}

/// Split [`Payout::delegators`] across the individual delegator accounts that
/// backed the operator, pro-rata by the satoshis each had **actually
/// activated** — the same measure that gave the operator its consensus weight,
/// so a delegator earns exactly on what it made count.
///
/// `stakes` is `(delegator, activated_sat)`; the return is `(delegator,
/// reward_sat)` in the same order, plus the truncation remainder. Every
/// division truncates, so the parts sum to at most the whole; the shortfall is
/// returned rather than silently dropped, because a fee that vanishes is
/// unbacked burn and the caller (the epoch boundary) must place it explicitly.
/// Conservation is the property: `sum(parts) + remainder == delegators_sat`.
///
/// Deterministic by construction — one pass in the caller's order, which the
/// transition takes from committed, data-keyed state.
pub fn split_delegator_fees(
    stakes: &[(u32, u128)],
    delegators_sat: u128,
) -> (Vec<(u32, u128)>, u128) {
    let total: u128 = stakes.iter().map(|(_, s)| *s).sum();
    if total == 0 || delegators_sat == 0 {
        return (stakes.iter().map(|(d, _)| (*d, 0)).collect(), delegators_sat);
    }
    let mut paid: u128 = 0;
    let parts: Vec<(u32, u128)> = stakes
        .iter()
        .map(|(d, s)| {
            let share = delegators_sat * *s / total;
            paid += share;
            (*d, share)
        })
        .collect();
    (parts, delegators_sat - paid)
}

// ── Block accounting: what the two caps are measured against ────────────────

/// Gas and payload bytes owed by one transaction, and the fee it settles at a
/// given price. The transition sums these across a block, checks them against
/// the two caps (§5), and pays the producer out of the total.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxCharge {
    pub gas: u64,
    pub tx_bytes: u64,
    pub base_fee_sat: u128,
    pub priority_fee_sat: u128,
}

/// Charge one transaction: gas from its class and size
/// ([`intrinsic_gas`] — **derived, never declared**), then settled against the
/// protocol's `base_fee_millisat_per_gas` and the sender's tip.
///
/// The declared-fee alternative is what this replaces, and it was not a
/// modelling shortcut but a hole: a transaction that states its own satoshi
/// fee lets a proposer include one claiming any number it likes and pay itself
/// from a figure no rule constrains. Deriving gas from the class and pricing
/// it at the committed base fee means the only user-set quantity left is the
/// tip, which is what an ordering market is supposed to be.
pub const fn charge(
    class: TxClass,
    tx_bytes: u64,
    base_fee_millisat_per_gas: u128,
    tip_millisat_per_gas: u128,
) -> TxCharge {
    let gas = intrinsic_gas(class, tx_bytes);
    let (base_fee_sat, priority_fee_sat) =
        fee_parts_sat(gas, base_fee_millisat_per_gas, tip_millisat_per_gas);
    TxCharge { gas, tx_bytes, base_fee_sat, priority_fee_sat }
}

// ── Compile-time invariants ─────────────────────────────────────────────────

// A byte-full block is payable in gas: if the byte cap's gas cost exceeded the
// gas cap, the byte limit would be unreachable and the controller's byte axis
// dead code.
const _: () = assert!(
    MAX_BLOCK_TX_BYTES as u128 * GAS_PER_BYTE as u128 <= BLOCK_GAS_LIMIT as u128,
    "o teto de bytes nao cabe no teto de gas"
);

// Targets are exact halves — the controller's neutral point is well-defined.
const _: () = assert!(BLOCK_GAS_TARGET * 2 == BLOCK_GAS_LIMIT);
const _: () = assert!(BLOCK_TX_BYTES_TARGET * 2 == MAX_BLOCK_TX_BYTES);
const _: () = assert!(BLOCK_TX_BYTES_TARGET_V2 * 2 == MAX_BLOCK_TX_BYTES_V2);
/// The raise must not silently move the binding resource from bytes to gas:
/// if a payload-saturated V2 block could exceed the gas cap, the byte cap
/// would stop being the thing that limits a block and every capacity number
/// derived from it would be wrong.
const _: () = assert!(
    MAX_BLOCK_TX_BYTES_V2 as u128 * GAS_PER_BYTE as u128 <= BLOCK_GAS_LIMIT as u128,
    "a 512 KiB payload must still fit under BLOCK_GAS_LIMIT"
);

// Overflow headroom, as proofs:
// (1) fee settlement: block gas x the maximum representable price fits u128;
const _: () = assert!(
    BLOCK_GAS_LIMIT as u128 <= u128::MAX / (MAX_BASE_FEE_MILLISAT_PER_GAS + 1),
    "gas x preco maximo estoura u128"
);
// (2) controller cross-multiplication: price x (used - target) x 1 fits,
//     because used <= 2*target on either axis and base <= MAX price.
const _: () = assert!(
    MAX_BASE_FEE_MILLISAT_PER_GAS <= u128::MAX / (BLOCK_GAS_LIMIT as u128),
    "controlador estoura u128"
);

// The floor resolves ±1/8 steps: below the change denominator, every downward
// step would truncate to the floor in one hop and upward steps to +1 — legal,
// but then the floor is not a price, it is a cliff.
const _: () = assert!(MIN_BASE_FEE_MILLISAT_PER_GAS >= BASE_FEE_CHANGE_DENOMINATOR);

// The derived verify price is the number the spec quotes.
const _: () = assert!(HYBRID_VERIFY_GAS == 72_748);

// One satoshi is still the settlement quantum; the msat price never mints
// sub-satoshi value (ceil_div output is whole satoshis by construction, this
// pins the constants' relationship instead).
const _: () = assert!(MILLISAT_PER_SAT == 1_000 && SAT_PER_BLOCH == 100_000_000);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::{split_fees_at, StakeAccount};
    use crate::tokenomics_v4::{annual_inflation_bps, EMISSION_SLOTS};

    // ── Controller ──────────────────────────────────────────────────────────

    #[test]
    fn base_fee_rises_one_eighth_on_full_gas_block() {
        let b = next_base_fee(
            8_000,
            BlockUsage { gas_used: BLOCK_GAS_LIMIT, tx_bytes: 0 },
            0,
        );
        assert_eq!(b, 9_000); // +1/8
    }

    // ── The 512 KiB raise ───────────────────────────────────────────────
    //
    // The activation epoch is `u64::MAX`, so `epoch == u64::MAX` is the only
    // reachable point of the V2 era and every test below uses it as such. The
    // whole rest of this suite runs at epoch 0 and is the control: it passes
    // unchanged, which is the claim that nothing moves before the flag day.

    #[test]
    fn v1_era_is_untouched_by_the_raise() {
        // The control half. Both ends of the old era, including the last
        // epoch before activation.
        const ACT: u64 = crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;
        for e in [0, 1, ACT - 1] {
            assert_eq!(max_block_tx_bytes(e), 262_144, "cap moved at epoch {e}");
            assert_eq!(block_tx_bytes_target(e), 131_072, "target moved at epoch {e}");
        }
    }

    #[test]
    fn v2_era_doubles_the_cap() {
        const ACT: u64 = crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;
        assert_eq!(max_block_tx_bytes(ACT), 524_288);
        assert_eq!(block_tx_bytes_target(ACT), 262_144);
        assert_eq!(max_block_tx_bytes(ACT.saturating_add(1)), 524_288);
    }

    #[test]
    fn target_is_half_the_cap_in_both_eras() {
        // The EIP-1559 invariant, which the raise must not break in either
        // era: a block at target on both axes leaves the price alone.
        const ACT: u64 = crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;
        for e in [0, ACT - 1, ACT, ACT.saturating_add(1)] {
            assert_eq!(block_tx_bytes_target(e) * 2, max_block_tx_bytes(e));
        }
    }

    #[test]
    fn the_cap_and_the_target_are_one_switch_not_two() {
        // THE load-bearing test, and the reason `block_tx_bytes_target` is
        // gated at all rather than left at 131,072.
        //
        // A 256 KiB block is exactly the OLD cap. In the old era that is a
        // saturated block: twice its 131,072 target, so the controller raises
        // the price, correctly, because the resource really is exhausted.
        let saturated = BlockUsage { gas_used: 0, tx_bytes: 262_144 };
        assert!(
            next_base_fee(8_000, saturated, crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH - 1)
                > 8_000,
            "a full block in the old era must get more expensive"
        );

        // The same block in the new era is exactly AT target — half of a
        // 512 KiB cap — so the price must not move at all. Had the target
        // stayed at 131,072 while the cap doubled, this block would still
        // read as 2x over target and the chain would price a half-full block
        // as congested, forever.
        assert_eq!(
            next_base_fee(8_000, saturated, crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH),
            8_000,
            "a half-full block in the new era must be priced as at-target"
        );
    }

    #[test]
    fn a_saturated_v2_payload_still_fits_under_the_gas_cap() {
        // Bytes must remain the binding resource after the raise. If a full
        // V2 payload could exceed BLOCK_GAS_LIMIT, the byte cap would stop
        // being what limits a block and every capacity figure derived from it
        // would be wrong. (The const assertion pins this at compile time; this
        // is the runtime statement of the same fact, with the numbers visible.)
        let payload_gas =
            max_block_tx_bytes(crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH) * GAS_PER_BYTE;
        assert_eq!(payload_gas, 8_388_608);
        assert!(payload_gas < BLOCK_GAS_LIMIT, "{payload_gas} vs {BLOCK_GAS_LIMIT}");
    }

    #[test]
    fn raising_the_block_cap_is_a_flag_day() {
        // The tripwire does NOT forbid arming — it forbids arming the two
        // switches at DIFFERENT epochs. A fleet running two rule sets is a
        // partition, and the whole point of a flag day is that everyone
        // changes at once.
        assert_eq!(
            crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH,
            crate::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
            "both consensus switches must activate at the SAME epoch"
        );
    }

    #[test]
    fn base_fee_falls_one_eighth_on_empty_block() {
        let b = next_base_fee(8_000, BlockUsage { gas_used: 0, tx_bytes: 0 }, 0);
        assert_eq!(b, 7_000); // -1/8
    }

    #[test]
    fn base_fee_unchanged_at_target_on_both_axes() {
        let b = next_base_fee(
            8_000,
            BlockUsage { gas_used: BLOCK_GAS_TARGET, tx_bytes: BLOCK_TX_BYTES_TARGET },
            0,
        );
        assert_eq!(b, 8_000);
    }

    /// The reason this is not plain EIP-1559: a block that saturates bytes
    /// while using almost no gas is CONGESTED, and the price must rise even
    /// though a gas-only controller would lower it.
    #[test]
    fn byte_saturated_gas_light_block_raises_base_fee() {
        let b = next_base_fee(
            8_000,
            BlockUsage { gas_used: BLOCK_GAS_TARGET / 10, tx_bytes: MAX_BLOCK_TX_BYTES },
            0,
        );
        assert_eq!(b, 9_000); // byte axis fully utilised: +1/8
    }

    #[test]
    fn base_fee_clamps_at_floor_and_congestion_always_moves_price() {
        // Floor: cannot fall below MIN.
        let b = next_base_fee(
            MIN_BASE_FEE_MILLISAT_PER_GAS,
            BlockUsage { gas_used: 0, tx_bytes: 0 },
            0,
        );
        assert_eq!(b, MIN_BASE_FEE_MILLISAT_PER_GAS);
        // A congested block moves the price by at least 1 even when the
        // proportional delta truncates to zero.
        let b = next_base_fee(
            MIN_BASE_FEE_MILLISAT_PER_GAS,
            BlockUsage { gas_used: BLOCK_GAS_TARGET + 1, tx_bytes: 0 },
            0,
        );
        assert_eq!(b, MIN_BASE_FEE_MILLISAT_PER_GAS + 1);
        // Ceiling: clamped, no overflow.
        let b = next_base_fee(
            MAX_BASE_FEE_MILLISAT_PER_GAS,
            BlockUsage { gas_used: BLOCK_GAS_LIMIT, tx_bytes: MAX_BLOCK_TX_BYTES },
            0,
        );
        assert_eq!(b, MAX_BASE_FEE_MILLISAT_PER_GAS);
    }

    // ── Settlement ──────────────────────────────────────────────────────────

    #[test]
    fn no_free_gas_fees_round_up_to_a_whole_satoshi() {
        // 1 gas at 1 msat/gas = 0.001 sat -> must cost 1 sat, not 0.
        let (base, tip) = fee_parts_sat(1, 1, 0);
        assert_eq!((base, tip), (1, 0));
        // Exact multiples do not over-charge.
        let (base, _) = fee_parts_sat(2_000, 500, 0); // 1,000,000 msat
        assert_eq!(base, 1_000);
    }

    #[test]
    fn intrinsic_gas_prices_the_pq_byte_reality() {
        // A 1-input eUTXO transfer: flat + bytes + one hybrid verify.
        let tx_bytes = HYBRID_SIG_BYTES + 256;
        let g = intrinsic_gas(TxClass::Eutxo { inputs: 1 }, tx_bytes);
        assert_eq!(g, TX_FLAT_GAS + tx_bytes * GAS_PER_BYTE + HYBRID_VERIFY_GAS);
        // The dual-auth price gap the fleet brief asks to be made explicit:
        // a PQ-account EVM tx pays ~35x the authorisation cost of a
        // secp256k1 one (verify gap + signature-byte gap).
        let pq = intrinsic_gas(TxClass::EvmPq, HYBRID_SIG_BYTES + 200);
        let secp = intrinsic_gas(TxClass::EvmSecp256k1, 65 + 200);
        assert!(pq / secp >= 12, "pq={pq} secp={secp}");
    }

    /// Bytes bind before gas for signature-heavy traffic: a block packed to
    /// the byte cap with minimal eUTXO transfers uses well under half the gas
    /// cap. This is the fact that makes the max-utilisation controller
    /// necessary rather than decorative.
    #[test]
    fn bytes_bind_before_gas_for_eutxo_blocks() {
        let tx_bytes = HYBRID_SIG_BYTES + 256;
        let per_tx_gas = intrinsic_gas(TxClass::Eutxo { inputs: 1 }, tx_bytes);
        let n = MAX_BLOCK_TX_BYTES / tx_bytes; // byte-limited count
        assert!(n >= 50, "byte budget should hold at least 50 minimal transfers, got {n}");
        assert!(
            n * per_tx_gas < BLOCK_GAS_LIMIT / 2,
            "a byte-full transfer block must not approach the gas cap"
        );
    }

    // ── Fees x emission: the two eras ───────────────────────────────────────

    /// The founder's inflation requirement, checked against the recommended
    /// decay curve with the fee burn as pure subtraction: gross year-1
    /// issuance is 434 bps of total supply (`annual_inflation_bps(0)`), the
    /// burn can only lower the net figure, and after `EMISSION_SLOTS` both
    /// issuance and burn are zero — net inflation exactly 0.
    ///
    /// These moved down again at the terminal snapshot (436 -> 435 -> 434),
    /// and the direction is the whole story: re-measuring the carryover
    /// against the live ledger raised it, the validator emission is the
    /// remainder of a fixed cap, so there is less left to issue and inflation
    /// falls. A re-pin that raised these numbers would mean the cap had been
    /// breached somewhere.
    #[test]
    fn net_inflation_stays_under_the_7_percent_target() {
        assert_eq!(annual_inflation_bps(0), 434); // 4.34% year 1 — the peak
        assert_eq!(annual_inflation_bps(4), 285);
        assert_eq!(annual_inflation_bps(9), 168);
        assert!(annual_inflation_bps(0) < 700, "meta do fundador: < 7%/ano");
        // During emission the base-fee burn is subtracted from gross issuance;
        // burned >= 0, so net <= gross on every slot of era 1.
        let s = split_fees_at(1_000_000, 250_000, 0);
        assert!(s.burned > 0);
        // Era 2: no issuance (annual_inflation is a era-1 curve; the reward
        // fns return 0 past EMISSION_SLOTS) and no burn either.
        let s = split_fees_at(1_000_000, 250_000, EMISSION_SLOTS);
        assert_eq!(s.burned, 0);
        assert_eq!(s.to_producer, 1_250_000);
    }

    /// The year-40 coherence check: once fees are validators' only revenue,
    /// delegators must still earn — otherwise delegation dies exactly when it
    /// matters most. Producer fees therefore flow through the same
    /// stake-origin + commission split as issuance.
    #[test]
    fn delegation_survives_fee_only_era() {
        let acct = StakeAccount {
            self_stake: 100_000 * SAT_PER_BLOCH,
            delegated_stake: 900_000 * SAT_PER_BLOCH,
            commission_bps: 500, // 5%
            credits: 1,
            max_credits: 1,
        };
        let split = split_fees_at(2_000_000, 500_000, EMISSION_SLOTS);
        let p = distribute_producer_fees(&acct, split.to_producer);
        // Conservation, and delegators are alive in the fee-only era.
        assert_eq!(p.operator + p.delegators + p.forfeited, split.to_producer);
        assert_eq!(p.forfeited, 0);
        assert!(p.delegators > 0);
        // 90% of stake is delegated; at 5% commission delegators keep
        // 90% * 95% = 85.5% of the fee.
        assert_eq!(p.delegators, split.to_producer * 9 / 10 * 9_500 / BPS);
    }

    /// The per-account pass conserves: parts plus remainder equal the whole,
    /// on inputs chosen so the division cannot come out even. A pro-rata split
    /// that quietly loses satoshis is unbacked burn — the caller must be
    /// handed the shortfall so it can place it deliberately.
    #[test]
    fn delegator_split_is_pro_rata_and_conserves_every_satoshi() {
        // Three accounts on stakes that do not divide 1,000 evenly.
        let stakes = [(7u32, 1u128), (2, 2), (9, 4)];
        let (parts, dust) = split_delegator_fees(&stakes, 1_000);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts.iter().map(|(_, r)| *r).sum::<u128>() + dust, 1_000);
        assert!(dust > 0, "the fixture must actually exercise truncation");
        // Order and identity preserved, and bigger stake earns more.
        assert_eq!(parts[0].0, 7);
        assert!(parts[2].1 > parts[1].1 && parts[1].1 > parts[0].1);

        // No delegators at all: the whole amount comes back as remainder
        // rather than evaporating.
        let (empty, all) = split_delegator_fees(&[], 500);
        assert!(empty.is_empty());
        assert_eq!(all, 500);

        // Zero stake recorded: same — a defined answer, nothing lost.
        let (zeroed, all) = split_delegator_fees(&[(1, 0), (2, 0)], 500);
        assert!(zeroed.iter().all(|(_, r)| *r == 0));
        assert_eq!(all, 500);
    }

    /// `charge` is gas × price, with the gas derived — the property that makes
    /// a declared fee inexpressible. Two transactions of the same shape cost
    /// the same; a bigger one costs more; and the fee floor bites.
    #[test]
    fn charge_prices_shape_not_assertion() {
        let a = charge(TxClass::Eutxo { inputs: 1 }, 512, MIN_BASE_FEE_MILLISAT_PER_GAS, 0);
        let b = charge(TxClass::Eutxo { inputs: 1 }, 512, MIN_BASE_FEE_MILLISAT_PER_GAS, 0);
        assert_eq!(a, b);
        assert_eq!(a.gas, intrinsic_gas(TxClass::Eutxo { inputs: 1 }, 512));
        assert_eq!(a.tx_bytes, 512);
        assert!(a.base_fee_sat > 0, "no transaction is free, even at the floor");
        assert_eq!(a.priority_fee_sat, 0);

        let bigger = charge(TxClass::Eutxo { inputs: 4 }, 4_096, MIN_BASE_FEE_MILLISAT_PER_GAS, 0);
        assert!(bigger.gas > a.gas && bigger.base_fee_sat > a.base_fee_sat);

        // The tip is the only user-set price, and it is charged per gas like
        // the base fee — not as a flat amount the sender names.
        let tipped = charge(TxClass::Eutxo { inputs: 1 }, 512, MIN_BASE_FEE_MILLISAT_PER_GAS, 100);
        assert_eq!(tipped.base_fee_sat, a.base_fee_sat);
        assert_eq!(tipped.priority_fee_sat, ceil_div(a.gas as u128 * 100, MILLISAT_PER_SAT));
    }

    #[test]
    fn producer_fees_with_no_stake_go_to_operator() {
        let acct = StakeAccount {
            self_stake: 0,
            delegated_stake: 0,
            commission_bps: 0,
            credits: 0,
            max_credits: 0,
        };
        let p = distribute_producer_fees(&acct, 12_345);
        assert_eq!((p.operator, p.delegators, p.forfeited), (12_345, 0, 0));
    }
}
