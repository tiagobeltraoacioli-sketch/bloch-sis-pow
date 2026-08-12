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
//! Transaction parsing (transactions are opaque bytes to this crate, §1.2),
//! the EVM's own opcode schedule (adopted 1:1 from Ethereum's live schedule by
//! the spec, with the calldata term zeroed because envelope bytes are already
//! charged here), and the base-fee state leaf (a `state_root.rs` component
//! tag, specified in the spec §4.4 but not wired — the closed leaf list is an
//! integration decision).

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
    /// eUTXO transfer: one hybrid verification per input.
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
pub const fn next_base_fee(parent_base_fee: u128, parent: BlockUsage) -> u128 {
    // Which axis is more utilised: gas/GT >= bytes/BT  <=>  gas*BT >= bytes*GT.
    let gas_cross = parent.gas_used as u128 * BLOCK_TX_BYTES_TARGET as u128;
    let bytes_cross = parent.tx_bytes as u128 * BLOCK_GAS_TARGET as u128;
    let (used, target) = if gas_cross >= bytes_cross {
        (parent.gas_used as u128, BLOCK_GAS_TARGET as u128)
    } else {
        (parent.tx_bytes as u128, BLOCK_TX_BYTES_TARGET as u128)
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
/// `transition.rs` step 11 currently does), delegator revenue would go to
/// exactly zero at the moment fees become everything, and the delegation
/// design — the thing that lets stake exist without running a validator —
/// would collapse at the fee-only boundary. Routing fees through the same
/// commission split keeps delegation economically alive in both eras. The
/// `delegation_survives_fee_only_era` test pins this.
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
        );
        assert_eq!(b, 9_000); // +1/8
    }

    #[test]
    fn base_fee_falls_one_eighth_on_empty_block() {
        let b = next_base_fee(8_000, BlockUsage { gas_used: 0, tx_bytes: 0 });
        assert_eq!(b, 7_000); // -1/8
    }

    #[test]
    fn base_fee_unchanged_at_target_on_both_axes() {
        let b = next_base_fee(
            8_000,
            BlockUsage { gas_used: BLOCK_GAS_TARGET, tx_bytes: BLOCK_TX_BYTES_TARGET },
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
        );
        assert_eq!(b, 9_000); // byte axis fully utilised: +1/8
    }

    #[test]
    fn base_fee_clamps_at_floor_and_congestion_always_moves_price() {
        // Floor: cannot fall below MIN.
        let b = next_base_fee(
            MIN_BASE_FEE_MILLISAT_PER_GAS,
            BlockUsage { gas_used: 0, tx_bytes: 0 },
        );
        assert_eq!(b, MIN_BASE_FEE_MILLISAT_PER_GAS);
        // A congested block moves the price by at least 1 even when the
        // proportional delta truncates to zero.
        let b = next_base_fee(
            MIN_BASE_FEE_MILLISAT_PER_GAS,
            BlockUsage { gas_used: BLOCK_GAS_TARGET + 1, tx_bytes: 0 },
        );
        assert_eq!(b, MIN_BASE_FEE_MILLISAT_PER_GAS + 1);
        // Ceiling: clamped, no overflow.
        let b = next_base_fee(
            MAX_BASE_FEE_MILLISAT_PER_GAS,
            BlockUsage { gas_used: BLOCK_GAS_LIMIT, tx_bytes: MAX_BLOCK_TX_BYTES },
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
    /// issuance is 436 bps of total supply (`annual_inflation_bps(0)`), the
    /// burn can only lower the net figure, and after `EMISSION_SLOTS` both
    /// issuance and burn are zero — net inflation exactly 0.
    #[test]
    fn net_inflation_stays_under_the_7_percent_target() {
        assert_eq!(annual_inflation_bps(0), 436); // 4.36% year 1 — the peak
        assert_eq!(annual_inflation_bps(4), 286);
        assert_eq!(annual_inflation_bps(9), 169);
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
