// SPDX-License-Identifier: AGPL-3.0-or-later

//! Building one payment attempt: exact conservation, no dust, one base fee.
//!
//! ## What a Genesis-4 transfer commits to
//!
//! Consensus refuses a transfer unless `sum(inputs) == sum(outputs) + fee`
//! holds with **equality**, where the fee is `gas × price` — gas derived from
//! the declared size and input class (`fee_market::intrinsic_gas`), price the
//! base fee of the block that includes it plus the transfer's own tip. The
//! transaction carries no fee field: the arithmetic *is* the commitment. So a
//! transfer balanced at base fee B is invalid at every other base fee — not
//! underpriced, invalid — and resubmitting identical bytes after the fee
//! moves can never succeed. This module is where B is baked in, and
//! [`BuiltTransfer::base_fee_msat_per_gas`] is the record of it.
//!
//! ## The three coupled unknowns
//!
//! Declared size, change and tip depend on each other: the declared size sets
//! the fee, the fee sets the change, and the change (if it would be dust)
//! can only be disposed of by adjusting the tip — which changes the fee. The
//! build loop below resolves them in a bounded fixed point:
//!
//! 1. Compute the canonical size from the suite's MAXIMUM signature length
//!    and declare that. Overdeclaring is legal — you pay for the declared
//!    bytes — and it does two jobs at once: it breaks the circularity of
//!    "the size covers the signatures that sign the size" (Falcon signatures
//!    vary a few bytes run to run), and it makes the declaration — which is
//!    inside the signing root — a pure function of the transfer's terms, so
//!    the same terms always re-derive the same txid.
//! 2. Solve the change at that declaration. `0 < change < dust floor` is
//!    refused as an output (sub-dust change poisoned Genesis-3 blocks; this
//!    crate never emits it) and burned into the fee instead, by searching
//!    for a (declared size, tip) pair whose fee absorbs the remainder
//!    **exactly** — approximate absorption is `ValueNotConserved`.
//! 3. Sign, measure the real canonical size, and if it exceeds the
//!    declaration (Falcon signatures vary by a few bytes), raise the
//!    declaration and go again. Converges in one extra pass in practice.

use bloch_pos_committee::fee_market::{self, TxClass};
use bloch_pos_committee::transition::{
    canonicalize_witness_table, PosTransaction, TransferInput, TransferInputV2, TransferOutput,
    WitnessKey,
};

use crate::address::{KeyMaterial, ScriptHash};
use crate::store::Coin;

/// The default dust floor, in satoshis — Genesis-3's `DUST_THRESHOLD`
/// (`bloch-crypto/src/core/mod.rs`). Genesis-4 consensus does not currently
/// enforce a dust rule; this client enforces it on itself, because the
/// history of sub-dust outputs on this chain is a history of poisoned blocks.
pub const DUST_FLOOR_SAT: u64 = 546;

/// Upper bound on one suite-enveloped hybrid signature: 4-byte envelope +
/// ML-DSA-65's fixed 3,309 + Falcon-1024's maximum 1,280. Falcon signatures
/// vary by a few bytes run to run, so the declared size is computed from
/// this MAXIMUM rather than from a measured signature — that keeps the
/// declaration (which is inside the signing root, and therefore inside the
/// txid) **deterministic in the transfer's terms**: rebuild the same terms,
/// get the same txid. The convergence loop below still guards the bound.
const HYBRID_SIG_MAX_BYTES: u64 = 4 + 3309 + 1280;

/// Slack added per signature if a signature ever exceeds the stated maximum
/// (it cannot, but the loop refuses to assume so).
const SIG_SLACK_BYTES: u64 = 64;

/// Bound on the dust-burn search over declared-size bumps. Each step costs
/// 16 gas; at the fee floor the whole range is worth under a thousand
/// satoshis, and the search succeeds long before the bound in practice.
const BURN_SEARCH_STEPS: u64 = 4096;

/// Which wire encoding to emit. V2 (deduplicated witness, tag 0x06) carries
/// one hybrid signature for any number of same-owner inputs and is charged
/// for one verification; it is only valid from
/// `params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`. The caller picks per
/// the chain's current epoch ([`format_for_epoch`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferFormat {
    V1,
    V2,
}

/// The format a block in `epoch` accepts most cheaply.
pub fn format_for_epoch(epoch: u64) -> TransferFormat {
    if epoch >= bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH {
        TransferFormat::V2
    } else {
        TransferFormat::V1
    }
}

/// What to build. `payment: None` is the cancellation sweep: every pinned
/// coin back to the change script, no recipient output — the attempt that
/// conflicts with all payment attempts without paying anyone.
pub struct BuildRequest<'a> {
    pub key: &'a KeyMaterial,
    /// The pinned inputs. Spent in full, always — this is the invariant the
    /// double-payment argument rests on, and the builder has no path that
    /// spends a subset.
    pub coins: &'a [Coin],
    pub payment: Option<(ScriptHash, u64)>,
    pub change_script: ScriptHash,
    /// The base fee these bytes commit to — `next_base_fee_millisat_per_gas`
    /// from the node, i.e. the price of the block being aimed at.
    pub base_fee_msat_per_gas: u128,
    pub tip_msat_per_gas: u128,
    pub dust_floor_sat: u64,
    pub format: TransferFormat,
}

/// One signed, submittable attempt, with everything the store must remember
/// about it.
#[derive(Debug)]
pub struct BuiltTransfer {
    pub tx: PosTransaction,
    pub canonical: Vec<u8>,
    /// Derived id (`SHA3-256(DS_TXID ‖ signing root)`): fixed by spend points,
    /// outputs, declared size and tip — NOT by witnesses, so re-signing the
    /// same terms yields the same txid. This is the key of every output the
    /// attempt creates, and how inclusion is later recognized via `gettxout`.
    pub txid: [u8; 32],
    pub base_fee_msat_per_gas: u128,
    /// The tip actually encoded — differs from the requested tip when dust
    /// was burned into the fee.
    pub tip_msat_per_gas: u128,
    pub declared_tx_bytes: u64,
    /// Value of the change output, 0 when there is none.
    pub change_sat: u64,
    /// Total fee in satoshis (base + tip parts) at the committed base fee.
    pub fee_sat: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    NoCoins,
    /// Refused up front: a recipient output below the dust floor.
    PaymentBelowDust { amount: u64, floor: u64 },
    /// The pinned coins cannot cover amount + fee at this base fee. The
    /// caller's move is to grow the pinned set (never to swap it).
    InsufficientFunds { available: u128, needed: u128 },
    /// Change fell in `(0, dust)` and no exact fee-absorption exists within
    /// the search bound. The caller's move is to grow the pinned set.
    DustGap { change: u64 },
    Signing(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::NoCoins => write!(f, "no coins pinned"),
            BuildError::PaymentBelowDust { amount, floor } => {
                write!(f, "payment of {amount} sat is below the dust floor ({floor} sat)")
            }
            BuildError::InsufficientFunds { available, needed } => {
                write!(f, "pinned coins hold {available} sat, need {needed} sat")
            }
            BuildError::DustGap { change } => write!(
                f,
                "change of {change} sat is dust and no exact fee absorption was found"
            ),
            BuildError::Signing(m) => write!(f, "signing: {m}"),
        }
    }
}

/// Build and sign one attempt.
pub fn build_transfer(req: &BuildRequest) -> Result<BuiltTransfer, BuildError> {
    let n = req.coins.len();
    if n == 0 {
        return Err(BuildError::NoCoins);
    }
    if let Some((_, amount)) = req.payment {
        if amount < req.dust_floor_sat {
            return Err(BuildError::PaymentBelowDust {
                amount,
                floor: req.dust_floor_sat,
            });
        }
    }
    let spent: u128 = req.coins.iter().map(|c| u128::from(c.value_sat)).sum();

    let sig_len = HYBRID_SIG_MAX_BYTES;
    let pk_len = req.key.pubkey().len() as u64;
    let n_sigs: u64 = match req.format {
        TransferFormat::V1 => n as u64,
        TransferFormat::V2 => 1,
    };
    let class = match req.format {
        TransferFormat::V1 => TxClass::Eutxo { inputs: n as u32 },
        TransferFormat::V2 => TxClass::Eutxo { inputs: 1 },
    };

    // Size of the canonical encoding, assuming `n_out` outputs and the
    // probed signature length. Exact but for signature variance.
    let estimate = |n_out: u64| -> u64 {
        let fixed_tail = 4 + n_out * 40 + 8 + 16;
        match req.format {
            TransferFormat::V1 => 1 + 4 + (n as u64) * (36 + 4 + pk_len + 4 + sig_len) + fixed_tail,
            TransferFormat::V2 => {
                1 + 4 + (4 + pk_len + 4 + sig_len) + 4 + (n as u64) * 40 + fixed_tail
            }
        }
    };
    // Declare for the larger (with-change) shape even when the change output
    // ends up absent: overdeclaring is legal and keeps the fee independent of
    // the change decision, which is what makes the solve below linear.
    let mut declared_floor = estimate(2);

    for _round in 0..8 {
        let (outputs, declared, tip, fee_sat, change_sat) = solve(req, spent, declared_floor, class)?;

        // Assemble, sign once over the shared root, fill witnesses.
        let mut tx = assemble(req, &outputs, declared, tip);
        let root = tx.spend_signing_root();
        let signature = req.key.sign(&root).map_err(BuildError::Signing)?;
        fill_witnesses(&mut tx, req, signature);

        let canonical = tx.canonical_bytes();
        if canonical.len() as u64 <= declared {
            let txid = tx.txid();
            return Ok(BuiltTransfer {
                txid,
                canonical,
                tx,
                base_fee_msat_per_gas: req.base_fee_msat_per_gas,
                tip_msat_per_gas: tip,
                declared_tx_bytes: declared,
                change_sat,
                fee_sat,
            });
        }
        // A signature came out longer than the declaration covers. Raise the
        // floor past what we actually produced and rebuild (the root covers
        // `tx_bytes`, so the declaration cannot be patched in place).
        declared_floor = canonical.len() as u64 + SIG_SLACK_BYTES * n_sigs;
    }
    Err(BuildError::Signing(
        "declared size failed to converge over signature length".into(),
    ))
}

/// Resolve outputs, declared size, tip and fee so conservation holds with
/// equality and no output is dust.
fn solve(
    req: &BuildRequest,
    spent: u128,
    declared_floor: u64,
    class: TxClass,
) -> Result<(Vec<TransferOutput>, u64, u128, u128, u64), BuildError> {
    let dust = u128::from(req.dust_floor_sat);
    let (pay_script, amount) = match req.payment {
        Some((script, amount)) => (Some(script), u128::from(amount)),
        None => (None, 0),
    };

    // Plain path: requested tip, change as the slack variable.
    let charge = fee_market::charge(class, declared_floor, req.base_fee_msat_per_gas, req.tip_msat_per_gas);
    let fee = charge.base_fee_sat + charge.priority_fee_sat;
    let needed = amount + fee;
    if spent < needed {
        return Err(BuildError::InsufficientFunds { available: spent, needed });
    }
    let change = spent - needed;

    let mut outputs = Vec::new();
    if let Some(script) = pay_script {
        outputs.push(TransferOutput { value: amount as u64, script_hash: script });
    }

    if change == 0 && pay_script.is_some() {
        return Ok((outputs, declared_floor, req.tip_msat_per_gas, fee, 0));
    }
    if change >= dust {
        outputs.push(TransferOutput { value: change as u64, script_hash: req.change_script });
        return Ok((outputs, declared_floor, req.tip_msat_per_gas, fee, change as u64));
    }
    // A sweep whose single output would be dust (or zero) funds nothing.
    if pay_script.is_none() {
        return Err(BuildError::DustGap { change: change as u64 });
    }

    // Dust gap: 0 < change < dust. Never emitted. Burn it into the fee — but
    // conservation is EQUALITY, so the fee must absorb it exactly. The tip is
    // quantized (1 msat/gas moves the tip part by ~gas/1000 satoshis), so an
    // arbitrary remainder is not always reachable at one declared size; the
    // declared size is the second knob, and bumping it re-rolls the rounding
    // until a (size, tip) pair lands exactly. Bounded, deterministic, and
    // every candidate is checked with the same `fee_market` arithmetic
    // consensus runs.
    for k in 0..BURN_SEARCH_STEPS {
        let d = declared_floor + k;
        let base_only = fee_market::charge(class, d, req.base_fee_msat_per_gas, 0);
        let base_sat = base_only.base_fee_sat;
        if spent < amount + base_sat {
            break; // Larger declarations only get worse.
        }
        let remainder = spent - amount - base_sat;
        // Find a tip whose satoshi part is exactly `remainder`.
        let gas = u128::from(base_only.gas);
        let candidate_tip = remainder.saturating_mul(1000) / gas;
        for tip in [candidate_tip, candidate_tip.saturating_sub(1)] {
            let check = fee_market::charge(class, d, req.base_fee_msat_per_gas, tip);
            if check.priority_fee_sat == remainder {
                let fee = check.base_fee_sat + check.priority_fee_sat;
                debug_assert_eq!(amount + fee, spent);
                return Ok((outputs, d, tip, fee, 0));
            }
        }
    }
    Err(BuildError::DustGap { change: change as u64 })
}

fn assemble(req: &BuildRequest, outputs: &[TransferOutput], declared: u64, tip: u128) -> PosTransaction {
    match req.format {
        TransferFormat::V1 => PosTransaction::Transfer {
            inputs: req
                .coins
                .iter()
                .map(|c| TransferInput {
                    txid: c.txid,
                    vout: c.vout,
                    pubkey: Vec::new(),
                    signature: Vec::new(),
                })
                .collect(),
            outputs: outputs.to_vec(),
            tx_bytes: declared,
            tip_millisat_per_gas: tip,
        },
        TransferFormat::V2 => PosTransaction::TransferV2 {
            keys: Vec::new(),
            inputs: req
                .coins
                .iter()
                .map(|c| TransferInputV2 { txid: c.txid, vout: c.vout, key_index: 0 })
                .collect(),
            outputs: outputs.to_vec(),
            tx_bytes: declared,
            tip_millisat_per_gas: tip,
        },
    }
}

fn fill_witnesses(tx: &mut PosTransaction, req: &BuildRequest, signature: Vec<u8>) {
    match tx {
        PosTransaction::Transfer { inputs, .. } => {
            // One owner, one root: the same signature authorises every input,
            // carried per input as V1 demands.
            for input in inputs.iter_mut() {
                input.pubkey = req.key.pubkey().to_vec();
                input.signature = signature.clone();
            }
        }
        PosTransaction::TransferV2 { keys, inputs, .. } => {
            keys.push(WitnessKey { pubkey: req.key.pubkey().to_vec(), signature });
            // Single entry, but run the canonicalizer anyway — it is the
            // documented builder-side contract, and free at n=1.
            canonicalize_witness_table(keys, inputs);
        }
        _ => unreachable!("assemble only produces transfers"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{key_hash, owns, KeyMaterial};
    use crate::store::Coin;
    use bloch_pos_committee::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    use std::sync::OnceLock;

    /// One deterministic wallet key for the whole module — hybrid keygen is
    /// slow enough that per-test keys would dominate the suite.
    fn test_key() -> &'static KeyMaterial {
        static KEY: OnceLock<KeyMaterial> = OnceLock::new();
        KEY.get_or_init(|| KeyMaterial::from_seed(&[42u8; 32]).unwrap())
    }

    fn coin(tag: u8, value_sat: u64) -> Coin {
        Coin { txid: [tag; 32], vout: 0, value_sat }
    }

    /// A recipient's `script_hash`, in the native 32-byte shape. It used to be
    /// the carried shape (20 bytes then twelve zeroes) because the client
    /// derived payees from addresses; it does not any more.
    fn recipient() -> [u8; 32] {
        [0xEE; 32]
    }

    fn base_request<'a>(coins: &'a [Coin], amount: u64) -> BuildRequest<'a> {
        BuildRequest {
            key: test_key(),
            coins,
            payment: Some((recipient(), amount)),
            change_script: test_key().script_hash(),
            base_fee_msat_per_gas: MIN_BASE_FEE_MILLISAT_PER_GAS,
            tip_msat_per_gas: 0,
            dust_floor_sat: DUST_FLOOR_SAT,
            format: TransferFormat::V2,
        }
    }

    /// The consensus checks a built transfer must pass, re-run here exactly
    /// as `transition::apply_transfer*` runs them: declared size covers the
    /// canonical bytes, conservation holds with equality at the committed
    /// base fee, every output is spendable by its owner, nothing is dust.
    fn assert_consensus_valid(built: &BuiltTransfer, req: &BuildRequest, spent: u128) {
        assert!(built.canonical.len() as u64 <= built.declared_tx_bytes, "underdeclared");
        let (n_verifies, outputs, tip, declared) = match &built.tx {
            PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } => {
                (inputs.len(), outputs, *tip_millisat_per_gas, *tx_bytes)
            }
            PosTransaction::TransferV2 { keys, inputs: _, outputs, tx_bytes, tip_millisat_per_gas } => {
                (keys.len(), outputs, *tip_millisat_per_gas, *tx_bytes)
            }
            other => panic!("not a transfer: {other:?}"),
        };
        let charge = fee_market::charge(
            TxClass::Eutxo { inputs: n_verifies as u32 },
            declared,
            req.base_fee_msat_per_gas,
            tip,
        );
        let created: u128 = outputs.iter().map(|o| u128::from(o.value)).sum();
        assert_eq!(
            spent,
            created + charge.base_fee_sat + charge.priority_fee_sat,
            "ValueNotConserved"
        );
        for o in outputs {
            assert!(o.value >= DUST_FLOOR_SAT, "dust output emitted: {}", o.value);
        }
        // The signature verifies over the signing root under the carried key,
        // and the key owns the change script.
        let root = built.tx.spend_signing_root();
        match &built.tx {
            PosTransaction::TransferV2 { keys, .. } => {
                for k in keys {
                    assert!(bloch_crypto::crypto::verify(&k.pubkey, &root, &k.signature));
                }
            }
            PosTransaction::Transfer { inputs, .. } => {
                for i in inputs {
                    assert!(bloch_crypto::crypto::verify(&i.pubkey, &root, &i.signature));
                }
            }
            _ => unreachable!(),
        }
        assert!(owns(&key_hash(req.key.pubkey()), &req.change_script));
        // Round trip: the canonical bytes decode to the same transaction.
        let decoded = PosTransaction::from_canonical_bytes(&built.canonical).unwrap();
        assert_eq!(decoded, built.tx);
        assert_eq!(decoded.txid(), built.txid);
    }

    #[test]
    fn ordinary_payment_with_change() {
        let coins = [coin(1, 50_000_000)];
        let req = base_request(&coins, 10_000_000);
        let built = build_transfer(&req).unwrap();
        assert_consensus_valid(&built, &req, 50_000_000);
        assert!(built.change_sat > 0);
        match &built.tx {
            PosTransaction::TransferV2 { outputs, .. } => {
                assert_eq!(outputs[0].value, 10_000_000, "recipient is vout 0");
                assert_eq!(outputs[0].script_hash, recipient());
                assert_eq!(outputs[1].script_hash, test_key().script_hash());
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn v1_format_builds_and_verifies() {
        let coins = [coin(1, 50_000_000), coin(2, 3_000_000)];
        let mut req = base_request(&coins, 10_000_000);
        req.format = TransferFormat::V1;
        let built = build_transfer(&req).unwrap();
        assert_consensus_valid(&built, &req, 53_000_000);
    }

    #[test]
    fn dust_change_is_burned_exactly_never_emitted() {
        // Aim the change into (0, dust): coin = amount + fee + tiny remainder.
        // Fee at floor for this shape is a few thousand sat; probe it first.
        let probe_coins = [coin(1, 50_000_000)];
        let probe = build_transfer(&base_request(&probe_coins, 10_000_000)).unwrap();
        let fee = u64::try_from(probe.fee_sat).unwrap();
        for extra in [1u64, 100, 545] {
            let coins = [coin(1, 10_000_000 + fee + extra)];
            let req = base_request(&coins, 10_000_000);
            let built = build_transfer(&req).unwrap();
            assert_consensus_valid(&built, &req, u128::from(coins[0].value_sat));
            assert_eq!(built.change_sat, 0, "dust must be burned, not emitted");
        }
    }

    #[test]
    fn insufficient_funds_names_the_need() {
        let coins = [coin(1, 1_000_000)];
        let req = base_request(&coins, 10_000_000);
        match build_transfer(&req) {
            Err(BuildError::InsufficientFunds { available, needed }) => {
                assert_eq!(available, 1_000_000);
                assert!(needed > 10_000_000);
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn sub_dust_payment_refused() {
        let coins = [coin(1, 50_000_000)];
        let req = base_request(&coins, 100);
        assert!(matches!(
            build_transfer(&req),
            Err(BuildError::PaymentBelowDust { amount: 100, .. })
        ));
    }

    #[test]
    fn same_terms_same_txid_different_fee_different_txid() {
        // The txid is witness-free: rebuilding identical terms re-derives the
        // same id even though Falcon signatures differ run to run...
        let coins = [coin(1, 50_000_000)];
        let req = base_request(&coins, 10_000_000);
        let a = build_transfer(&req).unwrap();
        let b = build_transfer(&req).unwrap();
        assert_eq!(a.txid, b.txid);
        // ...and a different base fee moves the change, hence the outputs,
        // hence the txid — two attempts are different transactions.
        let mut moved = base_request(&coins, 10_000_000);
        moved.base_fee_msat_per_gas = MIN_BASE_FEE_MILLISAT_PER_GAS + 1;
        let c = build_transfer(&moved).unwrap();
        assert_ne!(a.txid, c.txid);
    }

    #[test]
    fn sweep_spends_everything_to_change() {
        let coins = [coin(1, 50_000_000), coin(2, 1_000_000)];
        let mut req = base_request(&coins, 0);
        req.payment = None;
        let built = build_transfer(&req).unwrap();
        assert_consensus_valid(&built, &req, 51_000_000);
        match &built.tx {
            PosTransaction::TransferV2 { outputs, .. } => {
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].script_hash, test_key().script_hash());
            }
            _ => panic!("expected V2"),
        }
    }
}
