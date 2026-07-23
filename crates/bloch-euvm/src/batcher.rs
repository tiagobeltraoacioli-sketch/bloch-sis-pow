//! # batcher — deterministic AMM batch-settlement for single-pool eUTXO contention
//!
//! **FOUNDATION / reference. Unaudited. NOT wired into node consensus.** This module
//! is a tests-only companion to [`crate`] (the eUTXO VM). It solves one concrete DeFi
//! problem the base VM exposes but does not answer:
//!
//! ## The contention problem
//!
//! A constant-product pool lives in *one* [`ExtOutput`] (see the `constant_product_amm`
//! test in `lib.rs`). To swap, you must **spend** that output and re-create it. But an
//! eUTXO can be spent exactly once per block — so if N traders each build a swap that
//! spends the same pool UTXO, only one of their transactions can land; the other N−1
//! are double-spends of the pool and get rejected. This is *eUTXO contention*: a hot
//! single-state contract cannot serve concurrent writers directly. (This is the same
//! reason Cardano DEXes use a batcher/aggregator.)
//!
//! ## What this module does
//!
//! It models a **deterministic batcher**: collect many [`SwapOrder`]s, put them in a
//! canonical total order (independent of submission order — no `HashMap`, no clock),
//! and **fold them all into a single pool continuation** by settling each order against
//! the *running* reserves with checked `i128` integer math. The result is exactly one
//! new pool [`ExtOutput`] plus one settlement output per order — a single transaction
//! that spends the pool once and serves every trader at once.
//!
//! ### The four guarantees (each has a test)
//!
//! - **(a) Determinism.** [`settle`] sorts orders by a canonical key before folding, so
//!   the *same multiset* of orders yields a byte-identical [`Settlement`] regardless of
//!   the order they were handed in. No wall-clock, no float, no hash-map iteration.
//! - **(b) Invariant preserved.** Every accepted fill uses the fee-adjusted floor
//!   formula, under which `k` is non-decreasing at every step, so the aggregate
//!   satisfies `new_a·new_b ≥ old_a·old_b`. The built transaction therefore **passes the
//!   real `lib.rs` pool validator** — proven by running `crate::validate_tx` on it.
//! - **(c) Never drains, deterministic drop.** The constant-product formula returns a
//!   strictly-less-than-reserve amount for any finite input, so no order can empty the
//!   pool. An order whose fill would fall below its `min_out` (slippage limit) — i.e.
//!   it asks for more than the pool can give at the invariant — is **dropped and
//!   refunded**, deterministically, never partially draining below its own limit.
//! - **(d) Value conservation.** Across the pool continuation and *all* fills/refunds,
//!   every asset balances exactly: what goes in equals what comes out.
//!
//! ### Honest limits
//!
//! Reference model only. The batcher here is a pure function over in-memory orders; it
//! does not gossip, does not choose a batcher operator, does not touch consensus. Order
//! *authorization* (each trader's PQ signature over their order) is out of scope for
//! this increment — the module assumes orders are already authenticated and focuses on
//! the deterministic settlement math. Gas is modelled as a flat per-order cost with a
//! budget (a DoS bound on batch size), consistent with the VM's metered discipline.

use crate::{value_get, AssetId, EuTx, EuTxInput, ExtOutput, Op, Val, Value};

/// Flat gas charged per order the batcher *considers* (a DoS bound on batch size). Once
/// the budget cannot cover the next order, that order and every later one (in canonical
/// order) are dropped and refunded — a deterministic, gas-bounded cutoff.
pub const GAS_PER_ORDER: u64 = 100;

/// A single swap request competing for the one pool UTXO. It offers `give_amount` of
/// `give_asset` and wants at least `min_out` of `want_asset` in return. `owner_validator`
/// is the validator hash that guards this order's funding input and receives its fill (or
/// refund) — the address the trader controls.
///
/// The two assets must be the pool's two reserve assets and must differ; an order that
/// names anything else is dropped (it cannot be settled against this pool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapOrder {
    pub owner_validator: [u8; 32],
    pub give_asset: AssetId,
    pub give_amount: u64,
    pub want_asset: AssetId,
    pub min_out: u64,
}

impl SwapOrder {
    /// Canonical, injective byte encoding — the sort key that makes settlement
    /// independent of submission order, and the tie-break for identical fields.
    /// Fixed-width, big-endian, field order fixed: two orders encode equal iff every
    /// field is equal.
    pub fn canonical_key(&self) -> Vec<u8> {
        let mut k = Vec::with_capacity(32 + 32 + 8 + 32 + 8);
        k.extend_from_slice(&self.owner_validator);
        k.extend_from_slice(&self.give_asset);
        k.extend_from_slice(&self.give_amount.to_be_bytes());
        k.extend_from_slice(&self.want_asset);
        k.extend_from_slice(&self.min_out.to_be_bytes());
        k
    }
}

/// What happened to one order in a settlement. `filled == true` means the trader
/// receives `out_amount` of `out_asset` (their want); `filled == false` means the order
/// was dropped and `out_amount` of `out_asset` (their give) is refunded intact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fill {
    pub order: SwapOrder,
    pub filled: bool,
    pub out_asset: AssetId,
    pub out_amount: u64,
}

/// The deterministic result of folding a batch into one pool continuation. `fills` is in
/// **canonical order** (the same order the reserves were updated in), so equal batches
/// produce equal `Settlement`s field-for-field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// The pool's two reserve assets, `asset0 < asset1` (canonical BTreeMap order).
    pub asset0: AssetId,
    pub asset1: AssetId,
    /// Reserves before the batch.
    pub old0: u64,
    pub old1: u64,
    /// Reserves of the single pool continuation after the whole batch.
    pub new0: u64,
    pub new1: u64,
    /// Per-order outcomes, in canonical order.
    pub fills: Vec<Fill>,
    /// Gas consumed (`GAS_PER_ORDER` × orders considered, capped at the budget).
    pub gas_used: u64,
}

impl Settlement {
    /// Old constant-product `k = old0·old1` as `i128`, or `None` on overflow.
    ///
    /// Fail-closed: two reserves near `u64::MAX` square past `i128::MAX`
    /// (`(2^64-1)^2 ≈ 3.4e38 > i128::MAX ≈ 1.7e38`). Using `checked_mul` (matching the
    /// VM's own `Op::Mul` -> `VmError::Overflow`) means these `pub` helpers never panic
    /// under `overflow-checks` and never wrap negative in release — the invariant check
    /// stays sound across build profiles. A `None` here is a determinism-preserving
    /// refusal, not a crash.
    pub fn old_k(&self) -> Option<i128> {
        (self.old0 as i128).checked_mul(self.old1 as i128)
    }
    /// New constant-product `k = new0·new1` as `i128`, or `None` on overflow (see [`Self::old_k`]).
    pub fn new_k(&self) -> Option<i128> {
        (self.new0 as i128).checked_mul(self.new1 as i128)
    }
}

/// Why a batch could not be set up (structural problems, before any folding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchError {
    /// The pool output does not hold exactly two distinct assets.
    NotTwoAssetPool,
}

/// Constant-product output with a fee, integer floor math (`i128` checked).
///
/// `dy = floor( (dx·(10000−fee_bps)·reserve_out) / (reserve_in·10000 + dx·(10000−fee_bps)) )`
///
/// Returns `None` only on arithmetic overflow (impossible for u64 reserves in practice,
/// but checked for determinism). Key properties, both relied on below:
/// - **Never drains:** the fraction is strictly `< reserve_out`, so `dy < reserve_out`
///   for any finite `dx` — the pool can never be emptied.
/// - **k non-decreasing:** with the fee-adjusted numerator and floor rounding,
///   `(reserve_in+dx)·(reserve_out−dy) ≥ reserve_in·reserve_out`.
pub fn amm_out(reserve_in: u64, reserve_out: u64, amount_in: u64, fee_bps: u16) -> Option<u64> {
    if amount_in == 0 || reserve_in == 0 || reserve_out == 0 {
        return Some(0);
    }
    let ri = reserve_in as i128;
    let ro = reserve_out as i128;
    let ain = amount_in as i128;
    let fee_num = (10_000i128).checked_sub(fee_bps.min(10_000) as i128)?; // 10000 − fee
    let ain_fee = ain.checked_mul(fee_num)?; // dx·(10000−fee)
    let num = ain_fee.checked_mul(ro)?; // dx·(10000−fee)·reserve_out
    let den = ri.checked_mul(10_000)?.checked_add(ain_fee)?; // reserve_in·10000 + dx·(10000−fee)
    let dy = num / den; // floor; strictly < reserve_out
    Some(dy as u64)
}

/// Deterministically settle a batch of `orders` against the single-pool `pool` output.
///
/// Steps: (1) read the pool's two reserve assets canonically; (2) sort orders by
/// [`SwapOrder::canonical_key`] so the fold is submission-order-independent; (3) fold —
/// for each order in turn, charge gas, validate it targets the two pool assets, compute
/// its fill against the *running* reserves, and either accept it (update reserves, emit a
/// fill) or drop it (reserves untouched, emit a refund). `fee_bps` is the pool's LP fee
/// (retained in the pool), applied per fill.
///
/// The returned [`Settlement`] is a pure function of the order *multiset*, `fee_bps`, and
/// `gas_budget` — never of submission order.
pub fn settle(
    pool: &ExtOutput,
    orders: &[SwapOrder],
    fee_bps: u16,
    gas_budget: u64,
) -> Result<Settlement, BatchError> {
    // (1) canonical reserve assets: the pool must hold exactly two distinct assets.
    // BTreeMap iteration is already canonical (sorted), so asset0 < asset1.
    let keys: Vec<AssetId> = pool.value.keys().copied().collect();
    if keys.len() != 2 {
        return Err(BatchError::NotTwoAssetPool);
    }
    let asset0 = keys[0];
    let asset1 = keys[1];
    let old0 = value_get(&pool.value, &asset0);
    let old1 = value_get(&pool.value, &asset1);

    // (2) canonical total order — independent of how `orders` was handed in.
    let mut ordered: Vec<SwapOrder> = orders.to_vec();
    ordered.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));

    // (3) fold against running reserves.
    let mut r0 = old0;
    let mut r1 = old1;
    let mut gas_used: u64 = 0;
    let mut fills: Vec<Fill> = Vec::with_capacity(ordered.len());

    for order in ordered {
        // Gas cutoff: if the budget cannot cover this order, drop it and every later
        // one (refund). Deterministic because we are in canonical order.
        if gas_used.checked_add(GAS_PER_ORDER).map_or(true, |g| g > gas_budget) {
            fills.push(refund(order.clone()));
            continue;
        }
        gas_used += GAS_PER_ORDER;

        // The order must swap between exactly the two pool assets, in some direction.
        let direction = if order.give_asset == asset0 && order.want_asset == asset1 {
            Some((r0, r1)) // give asset0, want asset1
        } else if order.give_asset == asset1 && order.want_asset == asset0 {
            Some((r1, r0)) // give asset1, want asset0
        } else {
            None
        };

        let (reserve_in, reserve_out) = match direction {
            Some(rr) => rr,
            None => {
                fills.push(refund(order));
                continue;
            }
        };

        // Compute the fill against the *running* reserves.
        let dy = match amm_out(reserve_in, reserve_out, order.give_amount, fee_bps) {
            Some(dy) => dy,
            None => {
                fills.push(refund(order));
                continue;
            }
        };

        // (c) slippage / capacity gate: below the trader's floor, or a zero fill →
        // drop & refund, deterministically. (dy < reserve_out always, so no drain.)
        if dy == 0 || dy < order.min_out {
            fills.push(refund(order));
            continue;
        }

        // Accept: move reserves and emit the fill. give_amount in, dy out.
        //
        // Fail-closed reserve update (checked, never `saturating_add`): if adding this
        // order's give would push a reserve past `u64::MAX`, the true conserved sum is
        // not representable — so the order is DROPPED and REFUNDED (reserves untouched),
        // exactly like every other rejection path. Saturating here would silently clamp
        // the reserve and make `Settlement.new{0,1}` a value-conservation lie. `dy < the
        // reserve being paid out` is guaranteed by `amm_out`, but the subtraction is
        // checked too so an adversarial/degenerate input can only refuse, never panic.
        let updated = if order.give_asset == asset0 {
            match (r0.checked_add(order.give_amount), r1.checked_sub(dy)) {
                (Some(n0), Some(n1)) => Some((n0, n1)),
                _ => None,
            }
        } else {
            match (r1.checked_add(order.give_amount), r0.checked_sub(dy)) {
                (Some(n1), Some(n0)) => Some((n0, n1)),
                _ => None,
            }
        };
        let (n0, n1) = match updated {
            Some(nn) => nn,
            None => {
                fills.push(refund(order));
                continue;
            }
        };
        r0 = n0;
        r1 = n1;
        let out_asset = order.want_asset;
        fills.push(Fill {
            order,
            filled: true,
            out_asset,
            out_amount: dy,
        });
    }

    Ok(Settlement {
        asset0,
        asset1,
        old0,
        old1,
        new0: r0,
        new1: r1,
        fills,
        gas_used,
    })
}

/// A dropped order refunds its give intact — the funds pass straight through.
fn refund(order: SwapOrder) -> Fill {
    let out_asset = order.give_asset;
    let out_amount = order.give_amount;
    Fill {
        order,
        filled: false,
        out_asset,
        out_amount,
    }
}

/// Single-asset [`Value`] helper (0 amounts omitted so the map stays canonical).
fn one_asset(asset: AssetId, amount: u64) -> Value {
    let mut v = Value::new();
    if amount > 0 {
        v.insert(asset, amount);
    }
    v
}

/// The pool's single continuation output: same validator hash and datum, reserves
/// advanced to the batch result. This is the `outputs[0]` the pool validator inspects
/// (via `TxOutAsset(0)` / `TxOutValidator(0)`).
pub fn pool_continuation(pool: &ExtOutput, s: &Settlement) -> ExtOutput {
    let mut value = Value::new();
    if s.new0 > 0 {
        value.insert(s.asset0, s.new0);
    }
    if s.new1 > 0 {
        value.insert(s.asset1, s.new1);
    }
    ExtOutput {
        value,
        validator_hash: pool.validator_hash,
        datum: pool.datum.clone(),
    }
}

/// The per-order settlement outputs, in canonical order — each fill (or refund) paid to
/// the order's `owner_validator`. Concatenated after [`pool_continuation`], these are the
/// full output set of the settling transaction.
pub fn fill_outputs(s: &Settlement) -> Vec<ExtOutput> {
    s.fills
        .iter()
        .map(|f| ExtOutput {
            value: one_asset(f.out_asset, f.out_amount),
            validator_hash: f.order.owner_validator,
            datum: Val::Int(0),
        })
        .collect()
}

/// Build the single settling [`EuTx`]: spend the pool once (`inputs[0]`), spend each
/// order's funding input, and create the pool continuation (`outputs[0]`) plus one
/// settlement output per order. Value is conserved per asset, so `crate::validate_tx`
/// only accepts it if the pool validator's `new_k ≥ old_k` also holds — which it does.
///
/// `pool_validator` is the pool's revealed program (must hash to `pool.validator_hash`);
/// `funding_validator` guards every order's funding input (e.g. a trivial `[PushInt(1)]`
/// in tests, or the trader's real spend program in production). `fee` is the BLCH
/// protocol fee for the whole tx (0 keeps the batch value-neutral; the LP fee is already
/// retained inside the pool reserves).
pub fn build_settlement_tx(
    pool: &ExtOutput,
    pool_validator: &[Op],
    s: &Settlement,
    funding_validator: &[Op],
    fee: u64,
    sighash: Vec<u8>,
) -> EuTx {
    let mut inputs = Vec::with_capacity(1 + s.fills.len());
    // inputs[0]: the pool itself.
    inputs.push(EuTxInput {
        prev_output: pool.clone(),
        validator: pool_validator.to_vec(),
        redeemer: vec![],
    });
    // one funding input per order, holding its give.
    for f in &s.fills {
        inputs.push(EuTxInput {
            prev_output: ExtOutput {
                value: one_asset(f.order.give_asset, f.order.give_amount),
                validator_hash: crate::validator_hash(funding_validator),
                datum: Val::Int(0),
            },
            validator: funding_validator.to_vec(),
            redeemer: vec![],
        });
    }

    let mut outputs = Vec::with_capacity(1 + s.fills.len());
    outputs.push(pool_continuation(pool, s)); // outputs[0]: the continuation
    outputs.extend(fill_outputs(s));

    EuTx {
        inputs,
        outputs,
        fee,
        sighash,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{validate_tx, validator_hash, SigVerifier, TxError};

    const A: AssetId = [1u8; 32];
    const B: AssetId = [2u8; 32];
    // A trader address (arbitrary, distinct from the pool/funding hashes).
    fn owner(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    /// No signatures are exercised in these settlement tests.
    struct Noop;
    impl SigVerifier for Noop {
        fn verify(&self, _msg: &[u8], _pk: &[u8], _sig: &[u8]) -> bool {
            false
        }
    }

    /// The real constant-product pool validator from `lib.rs`'s `constant_product_amm`
    /// test: continuation + `new_a·new_b ≥ old_a·old_b`. Reserves read as asset0=A,
    /// asset1=B. We settle against THIS to prove the batch would be accepted by consensus.
    fn pool_program() -> Vec<Op> {
        vec![
            Op::TxOutValidator(0),
            Op::SelfValidator,
            Op::Eq,
            Op::Verify, // same contract continues
            Op::PushBytes(A.to_vec()),
            Op::SelfAsset, // old_a
            Op::PushBytes(B.to_vec()),
            Op::SelfAsset,
            Op::Mul, // old_k
            Op::PushBytes(A.to_vec()),
            Op::TxOutAsset(0), // new_a
            Op::PushBytes(B.to_vec()),
            Op::TxOutAsset(0),
            Op::Mul, // new_k
            Op::Swap,
            Op::Lt,
            Op::Not, // new_k >= old_k
        ]
    }

    fn anyone() -> Vec<Op> {
        vec![Op::PushInt(1)]
    }

    fn pool(a: u64, b: u64) -> ExtOutput {
        let mut value = Value::new();
        value.insert(A, a);
        value.insert(B, b);
        ExtOutput {
            value,
            validator_hash: validator_hash(&pool_program()),
            datum: Val::Int(0),
        }
    }

    fn order(own: u8, give: AssetId, amt: u64, want: AssetId, min_out: u64) -> SwapOrder {
        SwapOrder {
            owner_validator: owner(own),
            give_asset: give,
            give_amount: amt,
            want_asset: want,
            min_out,
        }
    }

    /// amm_out never returns ≥ reserve_out (never drains) and keeps k non-decreasing,
    /// for a spread of inputs including an absurdly large one.
    #[test]
    fn amm_out_never_drains_and_grows_k() {
        for &fee in &[0u16, 30, 100, 300] {
            for &dx in &[1u64, 10, 1000, 1_000_000, u64::MAX / 2] {
                let (ri, ro) = (1_000_000u64, 1_000_000u64);
                let dy = amm_out(ri, ro, dx, fee).unwrap();
                assert!(dy < ro, "must never drain: dy={dy} ro={ro}");
                // k non-decreasing at this step
                let new_in = ri as i128 + dx as i128;
                let new_out = ro as i128 - dy as i128;
                assert!(
                    new_in * new_out >= ri as i128 * ro as i128,
                    "k shrank: fee={fee} dx={dx} dy={dy}"
                );
            }
        }
    }

    /// (a) DETERMINISM: the same multiset of orders in any submission order settles to a
    /// byte-identical Settlement.
    #[test]
    fn determinism_independent_of_submission_order() {
        let p = pool(1_000_000, 1_000_000);
        let os = vec![
            order(1, A, 5_000, B, 0),
            order(2, B, 8_000, A, 0),
            order(3, A, 1_234, B, 1),
            order(4, B, 50_000, A, 0),
        ];
        let base = settle(&p, &os, 30, 1_000_000).unwrap();

        // every rotation / reversal must give the identical settlement
        let mut rev = os.clone();
        rev.reverse();
        let s_rev = settle(&p, &rev, 30, 1_000_000).unwrap();
        assert_eq!(base, s_rev);

        let shuffles = [
            vec![os[2].clone(), os[0].clone(), os[3].clone(), os[1].clone()],
            vec![os[3].clone(), os[2].clone(), os[1].clone(), os[0].clone()],
            vec![os[1].clone(), os[3].clone(), os[0].clone(), os[2].clone()],
        ];
        for sh in shuffles {
            assert_eq!(settle(&p, &sh, 30, 1_000_000).unwrap(), base);
        }
    }

    /// (b) INVARIANT: the aggregate respects new_k ≥ old_k, AND the built transaction is
    /// accepted by the REAL lib.rs pool validator via validate_tx.
    #[test]
    fn batch_respects_invariant_and_passes_pool_validator() {
        let p = pool(1_000_000, 2_000_000);
        let os = vec![
            order(1, A, 10_000, B, 0),
            order(2, B, 30_000, A, 0),
            order(3, A, 7_500, B, 0),
        ];
        let s = settle(&p, &os, 30, 1_000_000).unwrap();
        assert!(s.new_k().unwrap() >= s.old_k().unwrap(), "aggregate invariant violated");

        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        // The pool validator is inputs[0]; it enforces continuation + new_k >= old_k.
        assert!(
            validate_tx(&tx, &Noop, 200_000).is_ok(),
            "settlement rejected by real pool validator"
        );
    }

    /// A hand-forged draining tx (pool pays out more than the invariant allows) is
    /// rejected — confirming the validator we settle against actually bites.
    #[test]
    fn draining_settlement_would_be_rejected() {
        let p = pool(1_000_000, 1_000_000);
        let s = settle(&p, &[order(1, A, 100_000, B, 0)], 0, 1_000_000).unwrap();
        let mut tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        // Tamper: hand the trader far more B than the pool gave, shrinking the pool.
        // outputs[0] = pool continuation, outputs[1] = the fill.
        let cont = &mut tx.outputs[0];
        cont.value.insert(B, value_get(&cont.value, &B) - 50_000);
        let fill = &mut tx.outputs[1];
        fill.value.insert(B, value_get(&fill.value, &B) + 50_000);
        assert_eq!(
            validate_tx(&tx, &Noop, 200_000),
            Err(TxError::ValidatorRejected(0))
        );
    }

    /// (c) DETERMINISTIC DROP / NEVER DRAIN: an order whose min_out exceeds what the pool
    /// can give is dropped and refunded intact; the pool is never emptied.
    #[test]
    fn unsatisfiable_order_dropped_and_refunded() {
        let p = pool(1_000_000, 1_000_000);
        // Wants 100_000 B for only 1_000 A — the pool cannot give that at the invariant.
        let greedy = order(1, A, 1_000, B, 100_000);
        let s = settle(&p, &[greedy.clone()], 30, 1_000_000).unwrap();

        assert_eq!(s.new0, s.old0, "pool asset0 must be untouched");
        assert_eq!(s.new1, s.old1, "pool asset1 must be untouched");
        assert_eq!(s.fills.len(), 1);
        let f = &s.fills[0];
        assert!(!f.filled, "must be dropped");
        assert_eq!(f.out_asset, A, "refund is in the give asset");
        assert_eq!(f.out_amount, 1_000, "give refunded intact");

        // Even a gigantic order cannot drain the want reserve.
        let whale = order(2, A, u64::MAX / 2, B, 0);
        let s2 = settle(&p, &[whale], 0, 1_000_000).unwrap();
        assert!(s2.new1 > 0, "want reserve must never hit zero");
        assert!(s2.fills[0].filled);
    }

    /// (d) VALUE CONSERVATION: across the pool continuation + every fill/refund, each
    /// asset balances exactly (inputs == outputs, no fee here).
    #[test]
    fn value_conserved_across_pool_and_fills() {
        let p = pool(500_000, 900_000);
        let os = vec![
            order(1, A, 20_000, B, 0),   // fill A->B
            order(2, B, 40_000, A, 0),   // fill B->A
            order(3, A, 3_000, B, 9_999_999), // dropped (min_out) -> refund A
            order(4, B, 12_000, A, 0),   // fill B->A
        ];
        let s = settle(&p, &os, 30, 1_000_000).unwrap();

        // total A in = pool old0 + every order that gives A
        // total A out = pool new0 + every fill/refund paying A
        for &asset in &[A, B] {
            let in_sum: u128 = {
                let mut acc = value_get(&p.value, &asset) as u128;
                for f in &s.fills {
                    if f.order.give_asset == asset {
                        acc += f.order.give_amount as u128;
                    }
                }
                acc
            };
            let cont = pool_continuation(&p, &s);
            let out_sum: u128 = {
                let mut acc = value_get(&cont.value, &asset) as u128;
                for out in fill_outputs(&s) {
                    acc += value_get(&out.value, &asset) as u128;
                }
                acc
            };
            assert_eq!(in_sum, out_sum, "asset {asset:?} not conserved");
        }

        // And the built tx passes real per-asset conservation + the pool validator.
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        assert!(validate_tx(&tx, &Noop, 500_000).is_ok());
    }

    /// Gas budget caps batch size: beyond the budget, later orders (canonical order) are
    /// dropped & refunded, and the cutoff is deterministic.
    #[test]
    fn gas_budget_caps_and_is_deterministic() {
        let p = pool(1_000_000, 1_000_000);
        let os = vec![
            order(1, A, 1_000, B, 0),
            order(2, A, 2_000, B, 0),
            order(3, A, 3_000, B, 0),
            order(4, A, 4_000, B, 0),
        ];
        // Budget for only 2 orders.
        let budget = 2 * GAS_PER_ORDER;
        let s = settle(&p, &os, 30, budget).unwrap();
        assert_eq!(s.gas_used, budget);
        let filled = s.fills.iter().filter(|f| f.filled).count();
        let dropped = s.fills.iter().filter(|f| !f.filled).count();
        assert_eq!(filled, 2, "only two orders fit the budget");
        assert_eq!(dropped, 2, "the rest are refunded");

        // Deterministic under shuffle with the same budget.
        let mut rev = os.clone();
        rev.reverse();
        assert_eq!(settle(&p, &rev, 30, budget).unwrap(), s);
        // Dropped-for-gas orders still conserve value (refunds carry their give).
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        assert!(validate_tx(&tx, &Noop, 500_000).is_ok());
    }

    /// An order naming an asset the pool does not hold is dropped (cannot settle).
    #[test]
    fn foreign_asset_order_dropped() {
        const C: AssetId = [9u8; 32];
        let p = pool(1_000, 1_000);
        let s = settle(&p, &[order(1, C, 100, A, 0)], 0, 1_000_000).unwrap();
        assert!(!s.fills[0].filled);
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
    }

    /// A non-two-asset pool is a structural error (the batcher needs exactly a pair).
    #[test]
    fn non_pair_pool_rejected() {
        let single = ExtOutput {
            value: one_asset(A, 1_000),
            validator_hash: [0u8; 32],
            datum: Val::Int(0),
        };
        assert_eq!(
            settle(&single, &[], 0, 1_000).unwrap_err(),
            BatchError::NotTwoAssetPool
        );
    }

    /// Running the fold on the SAME multiset with duplicate identical orders is stable:
    /// duplicates settle identically regardless of position.
    #[test]
    fn duplicate_orders_stable() {
        let p = pool(1_000_000, 1_000_000);
        let o = order(1, A, 5_000, B, 0);
        let os = vec![o.clone(), o.clone(), o.clone()];
        let s1 = settle(&p, &os, 30, 1_000_000).unwrap();
        // interleave with a different order and re-check the multiset settles the same
        let other = order(2, B, 5_000, A, 0);
        let mut m = vec![o.clone(), other.clone(), o.clone(), o.clone()];
        let n = vec![other, o.clone(), o.clone(), o];
        // m and n are the same multiset {3×o, 1×other}; wait n has 3×o too
        m.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        let mut n2 = n.clone();
        n2.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        assert_eq!(m, n2, "same multiset canonicalizes identically");
        assert_eq!(settle(&p, &m, 30, 1_000_000).unwrap(), settle(&p, &n, 30, 1_000_000).unwrap());
        // sanity: three identical A->B fills all succeeded and k grew
        assert!(s1.fills.iter().all(|f| f.filled));
        assert!(s1.new_k().unwrap() >= s1.old_k().unwrap());
    }

    // ── ADVERSARIAL + PROPERTY TESTS (appended; no logic changes above) ──────

    /// BUG PIN (found while adding adversarial coverage): `settle`'s reserve update
    /// uses `saturating_add` (see the `Accept:` arm), not checked arithmetic. When a
    /// pool reserve is already near `u64::MAX` and an order's `give_amount` pushes the
    /// true sum past `u64::MAX`, the overflow is swallowed silently: the fill is
    /// reported `filled: true` with a `Settlement.new0` that is NOT `old0 +
    /// give_amount` (the true, conserved value overflows u64 entirely and gets
    /// clamped). This contradicts the module's own documented guarantee (d) — "every
    /// asset balances exactly" — *inside the `Settlement` the batcher returns*, before
    /// the value ever reaches a validator.
    ///
    /// In this concrete repro it happens to be caught downstream: `validate_tx`
    /// rejects the built tx with `ValueNotConserved`, because the funding input still
    /// carries the *un-clamped* `give_amount` while the continuation only reflects the
    /// saturated reserve. So today the failure is closed (rejected), but only by
    /// accident of a second, independent conservation check — not because `settle`/
    /// `amm_out` itself refused the order the way it correctly refuses on i128
    /// overflow (see `amm_out`'s `checked_mul`/`?` chain). A future caller that reads
    /// `Settlement` fields directly (without round-tripping through
    /// `build_settlement_tx` + `validate_tx`) would observe a lying reserve number.
    /// Fix direction: use `checked_add` for the reserve update and drop/refund the
    /// order (like every other rejection path) when it would overflow, instead of
    /// `saturating_add`.
    ///
    /// REGRESSION (F5 fixed): the accept arm now updates reserves with `checked_add`
    /// (never `saturating_add`). An order whose fill would push a reserve past
    /// `u64::MAX` is DROPPED and REFUNDED — fail-closed, like every other rejection —
    /// so `Settlement.new{0,1}` are always the true, un-clamped reserves and guarantee
    /// (d) "every asset balances exactly" holds INSIDE the returned struct, before any
    /// validator sees it. This test fails if the silent saturation ever returns.
    #[test]
    fn bug_reserve_overflow_silently_saturates_instead_of_failing_closed() {
        let mut value = Value::new();
        value.insert(A, u64::MAX - 10);
        value.insert(B, 1_000_000);
        let p = ExtOutput {
            value,
            validator_hash: validator_hash(&pool_program()),
            datum: Val::Int(0),
        };
        // give_amount large enough that (a) dy is still nonzero (accept path reached)
        // and (b) old0 + give_amount truly overflows u64 — so the checked_add refuses.
        let o = order(1, A, u64::MAX / 2, B, 0);
        let s = settle(&p, &[o], 0, 1_000_000).unwrap();

        // Fixed: the overflowing order is refunded, not silently saturated.
        assert!(!s.fills[0].filled, "overflowing fill must be dropped & refunded");
        assert_eq!(s.fills[0].out_asset, A, "refund is in the give asset");
        assert_eq!(s.fills[0].out_amount, u64::MAX / 2, "give refunded intact");
        // Reserves untouched: new0 is the TRUE reserve (== old0), never a clamped lie.
        assert_eq!(s.new0, s.old0, "no saturation: reserve stays the true value");
        assert_eq!(s.new1, s.old1);

        // Because the give is refunded intact, the built tx now genuinely conserves
        // value and passes the real validator (no reliance on a downstream mismatch).
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        assert!(
            validate_tx(&tx, &Noop, 500_000).is_ok(),
            "fail-closed refund must conserve value end-to-end"
        );
    }

    /// GAS BOUNDS: a zero gas budget must refuse every order (deterministically) and
    /// must never panic, regardless of batch size.
    #[test]
    fn zero_gas_budget_refunds_every_order_no_panic() {
        let p = pool(1_000_000, 1_000_000);
        let os: Vec<SwapOrder> = (0u8..20).map(|i| order(i, A, 1_000, B, 0)).collect();
        let s = settle(&p, &os, 30, 0).unwrap();
        assert_eq!(s.gas_used, 0);
        assert!(s.fills.iter().all(|f| !f.filled), "budget 0 must fill nothing");
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        assert!(validate_tx(&tx, &Noop, 500_000).is_ok());
    }

    /// GAS BOUNDS: the gas cutoff is an exact boundary, not off-by-one either way.
    #[test]
    fn gas_budget_exact_boundary_no_off_by_one() {
        let p = pool(1_000_000, 1_000_000);
        let os = vec![
            order(1, A, 1_000, B, 0),
            order(2, A, 2_000, B, 0),
            order(3, A, 3_000, B, 0),
        ];
        // Budget covers exactly 2 orders and 1 gas short of a 3rd.
        let exact = 2 * GAS_PER_ORDER;
        let s_exact = settle(&p, &os, 30, exact).unwrap();
        assert_eq!(s_exact.fills.iter().filter(|f| f.filled).count(), 2);

        let one_short = 3 * GAS_PER_ORDER - 1;
        let s_short = settle(&p, &os, 30, one_short).unwrap();
        assert_eq!(s_short.fills.iter().filter(|f| f.filled).count(), 2);

        let just_enough = 3 * GAS_PER_ORDER;
        let s_full = settle(&p, &os, 30, just_enough).unwrap();
        assert_eq!(s_full.fills.iter().filter(|f| f.filled).count(), 3);
    }

    /// PROPERTY: an empty batch is a pure no-op — reserves unchanged, no gas spent, no
    /// panic, and the built (degenerate) tx still validates.
    #[test]
    fn empty_batch_is_a_pure_noop() {
        let p = pool(123_456, 654_321);
        let s = settle(&p, &[], 999, 1_000_000).unwrap();
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
        assert_eq!(s.gas_used, 0);
        assert!(s.fills.is_empty());
        assert_eq!(s.new_k(), s.old_k());
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        assert!(validate_tx(&tx, &Noop, 500_000).is_ok());
    }

    /// FAIL-CLOSED / MALFORMED INPUT: an order whose give and want asset are the same
    /// (nonsensical — there is no "direction" against a 2-asset pool) must be dropped,
    /// not panic and not silently accepted.
    #[test]
    fn give_equals_want_asset_dropped_not_panicking() {
        let p = pool(1_000_000, 1_000_000);
        let nonsense = order(1, A, 5_000, A, 0); // give A, want A
        let s = settle(&p, &[nonsense], 30, 1_000_000).unwrap();
        assert!(!s.fills[0].filled, "give==want must never be treated as a valid swap");
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
    }

    /// FAIL-CLOSED / EDGE CASE: a zero-amount order can never produce a nonzero fill
    /// (amm_out(..., 0, ...) == 0), so it must be dropped, not accepted as a free fill.
    #[test]
    fn zero_give_amount_order_dropped() {
        let p = pool(1_000_000, 1_000_000);
        let s = settle(&p, &[order(1, A, 0, B, 0)], 30, 1_000_000).unwrap();
        assert!(!s.fills[0].filled, "a zero-give order must not be filled");
        assert_eq!(s.fills[0].out_amount, 0);
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
    }

    /// EDGE CASE / NO PANIC: fee_bps beyond 10_000 (100%) must clamp, not panic or
    /// underflow, and must never allow a fill (clamped fee leaves zero output).
    #[test]
    fn fee_bps_over_10000_clamped_not_panicking() {
        let p = pool(1_000_000, 1_000_000);
        let s = settle(&p, &[order(1, A, 10_000, B, 0)], u16::MAX, 1_000_000).unwrap();
        assert!(!s.fills[0].filled, "clamped 100%+ fee must leave dy == 0 -> dropped");
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
    }

    /// EDGE CASE: fee_bps == 10_000 exactly (100% fee) must also always yield dy == 0
    /// (not a panic, not an off-by-one accept).
    #[test]
    fn fee_bps_exactly_10000_full_fee_always_zero_fill() {
        let p = pool(1_000_000, 1_000_000);
        for &amt in &[1u64, 100, 1_000_000, u64::MAX / 4] {
            let dy = amm_out(1_000_000, 1_000_000, amt, 10_000).unwrap();
            assert_eq!(dy, 0, "100% fee must zero the output for amt={amt}");
        }
        let s = settle(&p, &[order(1, A, 500_000, B, 0)], 10_000, 1_000_000).unwrap();
        assert!(!s.fills[0].filled);
    }

    /// PROPERTY / NO PANIC: amm_out must never panic across a wide spread of extreme
    /// reserves, amounts and fees — including values chosen to stress i128
    /// intermediate overflow — and whenever it returns `Some(dy)` (reserve_out > 0),
    /// `dy` must be strictly less than reserve_out (never drains).
    #[test]
    fn amm_out_extreme_property_no_panic_never_drains() {
        let reserves = [1u64, 2, 1_000, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        let amounts = [0u64, 1, 1_000, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        let fees = [0u16, 1, 30, 10_000, 10_001, u16::MAX];
        for &ri in &reserves {
            for &ro in &reserves {
                for &ain in &amounts {
                    for &fee in &fees {
                        // Must not panic for ANY combination (the whole point of the
                        // checked-i128 chain); a result of None is an acceptable,
                        // fail-closed outcome for pathological overflow inputs.
                        let res = amm_out(ri, ro, ain, fee);
                        if let Some(dy) = res {
                            if ro > 0 {
                                assert!(dy < ro, "drained: ri={ri} ro={ro} ain={ain} fee={fee} dy={dy}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// PROPERTY / NO PANIC: settle() must never panic on an adversarially mixed batch
    /// (foreign assets, zero amounts, huge amounts, give==want, unmet min_out, and
    /// ordinary fillable orders all in one batch), must always emit exactly one Fill
    /// per input order, and must remain deterministic under shuffling.
    #[test]
    fn settle_never_panics_on_adversarial_mixed_batch() {
        const FOREIGN: AssetId = [7u8; 32];
        let p = pool(2_000_000, 3_000_000);
        let os = vec![
            order(1, A, 10_000, B, 0),             // ordinary fill
            order(2, FOREIGN, 500, A, 0),           // foreign give asset -> drop
            order(3, A, 0, B, 0),                   // zero amount -> drop
            order(4, A, 20_000, A, 0),               // give==want -> drop
            order(5, B, 999_999_999, A, u64::MAX),   // unmet min_out -> drop
            order(6, B, 5_000, A, 0),                // ordinary fill, other direction
        ];
        let base = settle(&p, &os, 30, 1_000_000).unwrap();
        assert_eq!(base.fills.len(), os.len(), "one Fill per input order, always");

        let mut shuffled = os.clone();
        shuffled.reverse();
        let s_rev = settle(&p, &shuffled, 30, 1_000_000).unwrap();
        assert_eq!(base, s_rev, "adversarial batch must still be order-independent");

        // Value conservation still holds through the real validator despite the
        // adversarial entries (they just refund cleanly).
        let tx = build_settlement_tx(&p, &pool_program(), &base, &anyone(), 0, vec![]);
        assert!(validate_tx(&tx, &Noop, 500_000).is_ok());
    }

    /// PROPERTY: canonical_key is injective per documented field order — varying any
    /// single field (holding the rest fixed) must change the key. Guards against a
    /// future edit accidentally aliasing two distinct orders onto the same sort key
    /// (which would silently break determinism guarantee (a)).
    #[test]
    fn canonical_key_injective_across_field_variation() {
        let base = order(1, A, 1_000, B, 5);
        let variants = vec![
            order(2, A, 1_000, B, 5),       // owner differs
            order(1, B, 1_000, B, 5),       // give_asset differs (still well-formed key-wise)
            order(1, A, 1_001, B, 5),       // give_amount differs
            order(1, A, 1_000, A, 5),       // want_asset differs
            order(1, A, 1_000, B, 6),       // min_out differs
        ];
        for v in variants {
            assert_ne!(
                base.canonical_key(),
                v.canonical_key(),
                "single-field variation must change the canonical key: {v:?}"
            );
        }
        // identical fields -> identical key
        assert_eq!(base.canonical_key(), order(1, A, 1_000, B, 5).canonical_key());
    }

    /// FAIL-CLOSED / MALFORMED INPUT: a pool holding three distinct assets (not a
    /// pair) is rejected structurally, matching the two-asset-only contract.
    #[test]
    fn three_asset_pool_structurally_rejected() {
        const C: AssetId = [3u8; 32];
        let mut value = Value::new();
        value.insert(A, 1_000);
        value.insert(B, 1_000);
        value.insert(C, 1_000);
        let triple = ExtOutput { value, validator_hash: [0u8; 32], datum: Val::Int(0) };
        assert_eq!(settle(&triple, &[], 0, 1_000).unwrap_err(), BatchError::NotTwoAssetPool);
    }

    /// FAIL-CLOSED: a settlement tx carrying a nonzero protocol fee with no BLCH
    /// funding anywhere in the tx must be rejected by the real conservation check
    /// (BLCH in_sum 0 != out_sum 0 + fee) — confirms the batcher does not (and cannot)
    /// silently manufacture fee revenue out of thin air.
    #[test]
    fn nonzero_protocol_fee_without_blch_funding_fails_closed() {
        let p = pool(1_000_000, 1_000_000);
        let s = settle(&p, &[order(1, A, 10_000, B, 0)], 30, 1_000_000).unwrap();
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 1, vec![]); // fee=1, no BLCH anywhere
        match validate_tx(&tx, &Noop, 500_000) {
            Err(TxError::ValueNotConserved { asset, in_sum, out_plus_fee }) => {
                assert_eq!(asset, crate::BLCH);
                assert_eq!(in_sum, 0);
                assert_eq!(out_plus_fee, 1);
            }
            other => panic!("expected BLCH ValueNotConserved for the unfunded fee, got {other:?}"),
        }
    }

    /// VALUE CONSERVATION: a batch where literally every order is invalid/unfillable
    /// (foreign asset, zero amount, unmet min_out) leaves the pool byte-identical and
    /// still passes the real validator — the "all-refund" batch must be a safe no-op,
    /// never a partial or corrupting state transition.
    #[test]
    fn all_orders_invalid_batch_leaves_pool_untouched_and_conserves() {
        const FOREIGN: AssetId = [8u8; 32];
        let p = pool(777_777, 888_888);
        let os = vec![
            order(1, FOREIGN, 1_000, A, 0),
            order(2, A, 0, B, 0),
            order(3, B, 1, A, u64::MAX),
        ];
        let s = settle(&p, &os, 30, 1_000_000).unwrap();
        assert!(s.fills.iter().all(|f| !f.filled));
        assert_eq!(s.new0, s.old0);
        assert_eq!(s.new1, s.old1);
        assert_eq!(s.new_k(), s.old_k());
        let tx = build_settlement_tx(&p, &pool_program(), &s, &anyone(), 0, vec![]);
        assert!(validate_tx(&tx, &Noop, 500_000).is_ok());
    }
}
