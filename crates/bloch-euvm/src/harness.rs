//! # harness — a testable model of the `accept_block` activation hook (step 5.0)
//!
//! This module is the **reference harness** for how the eUTXO VM would engage inside
//! the node's block-acceptance path — modelled here, in-crate, with zero contact with
//! the real node. It exists to pin down, as executable tests, the two properties that
//! govern the whole integration (see `INTEGRATION.md`):
//!
//! 1. **Feature-off byte-identity.** Below the activation height the node must behave
//!    *byte-for-byte* as today — the eUTXO transactions are ignored and the committed
//!    block bytes equal the legacy bytes exactly, whether the feature is
//!    compiled-in-but-inactive or absent entirely. No silent fork on resync.
//! 2. **Deterministic, height-gated activation — NO committee / quorum / FFG.** The
//!    gate is a plain `height >= EUVM_ACTIVATION_HEIGHT` comparison, evaluated
//!    identically by every node. FFG was dropped: the base is pure PoW +
//!    deterministic proof-gated validation, so activation is a coordinated hard-fork
//!    *height*, never a vote.
//!
//! At or above the activation height the harness runs [`crate::validate_block`] over
//! the block's eUTXO transactions under a **per-tx** and a **block-wide** gas ceiling
//! (the DoS bound) and applies [`crate::fee_burn`] to the BLCH fee (§5-bis).
//!
//! ## Honest boundaries
//!
//! - Everything here is a **model**. [`BlockModel`] is NOT the node's real block;
//!   `legacy_bytes` is an opaque stand-in for the node's canonical legacy
//!   serialization; the eUTXO txs are [`crate::EuTx`], not the node `Transaction`.
//! - [`EUVM_ACTIVATION_HEIGHT`] is `4320` — a real coordinated fork height, **not**
//!   the inert `u64::MAX` sentinel this bullet claimed until 2026-09-02. Merely
//!   shipping this code still activates nothing, but for a structural reason worth
//!   naming rather than a sentinel: `bloch-euvm` is not a dependency of
//!   `bloch-pos-node` or `bloch-pos-committee`, so no consensus path reads this
//!   constant or calls [`is_feature_active`] — only this crate's own tests do. The
//!   inertness would end the moment the crate were wired in, with nobody editing
//!   this number, which is the opposite of what the sentinel wording promised.
//! - The harness **orchestrates** the existing lib.rs engine ([`validate_block`],
//!   [`EuTx`], [`TxError`], [`fee_burn`]); it does not reimplement value conservation,
//!   validator execution, or gas metering.
//!
//! Unaudited reference. Not consensus-wired.

use crate::state::SparseMerkleTree;
use crate::{fee_burn, validate_block, EuTx, ExtOutput, SigVerifier, TxError, Val};

/// **The activation height for the eUTXO VM feature.**
///
/// Currently `4320` — a coordinated Genesis-2 hard-fork height. Until 2026-09-02 this
/// doc block described the constant as an inert maximum-value sentinel, which was
/// false of the line directly below it; the `//` note that follows has carried the
/// real value and its reasoning all along. What keeps the feature off is not this number but the fact
/// that no consensus crate depends on `bloch-euvm`. This is a pure height gate: no
/// committee registry, no activation signatures, no quorum, no finality gadget (FFG
/// was dropped).
// COORDINATED Genesis-2 activation height. As of the Genesis-2/3 measurement that
// set it, 4320 was above the then-current network tip (~3757) — a dated statement
// about a chain that is no longer running, NOT a claim about Genesis-4, whose
// heights are far past 4320. On G2/G3, euvm/Ustav/Kirpich stayed INERT on every
// block the fleet produced — the canonical a397a9d2 binary and this one are
// byte-identical below
// 4320, so shipping this is NOT a hard fork for the live chain. (Was momentarily 10
// for an isolated single-node rehearsal; that value would have activated euvm
// immediately at the live tip and forked the fleet.)
pub const EUVM_ACTIVATION_HEIGHT: u64 = 4320;

/// Base-fee burn fraction, in basis points (§5-bis, EIP-1559-style). `2000` = 20% of
/// the BLCH fee is burned (removed from supply); the remainder goes to the miner.
/// Applied only on the active path.
pub const EUVM_BURN_BPS: u16 = 2_000;

/// **The activation gate — a pure, deterministic height comparison.**
///
/// `height >= EUVM_ACTIVATION_HEIGHT`. Every node computes this identically from the
/// block height alone; there is no per-node state, clock, or vote involved. Because
/// [`EUVM_ACTIVATION_HEIGHT`] is `4320`, this returns `true` at and above 4320 — it
/// is NOT `false` for every real height, which is what this sentence claimed until
/// 2026-09-02. What keeps the feature off is that no consensus crate calls this
/// function at all.
#[inline]
// This `#[allow]` is VESTIGIAL. It was added when the constant was the disabled
// sentinel, where Clippy flags `>=` as an absurd extreme comparison against
// `u64::MAX`. `EUVM_ACTIVATION_HEIGHT` is `4320` today, so the lint cannot fire
// and the attribute suppresses nothing. It is left in place because removing an
// attribute is a code change, not a prose fix; it is safe for the founder to
// delete. The `>=` itself is deliberate and correct either way: it is the
// activation predicate, not an equality test. Do not narrow it to `==`.
#[allow(clippy::absurd_extreme_comparisons)]
pub const fn is_feature_active(height: u64) -> bool {
    height >= EUVM_ACTIVATION_HEIGHT
}

/// Per-tx and block-wide gas ceilings — the DoS bound the harness enforces on the
/// active path. `per_tx` caps any single eUTXO transaction; `block` caps the sum of
/// gas used across the block. These mirror the two ceilings [`validate_block`] takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasCeilings {
    pub per_tx: u64,
    pub block: u64,
}

/// A conservative default schedule for the reference harness (illustrative, not a
/// consensus-blessed constant): a generous per-tx budget and a block budget an order
/// of magnitude larger. Real values are chosen at integration/audit time.
pub const DEFAULT_GAS_CEILINGS: GasCeilings = GasCeilings {
    per_tx: 10_000_000,
    block: 100_000_000,
};

/// A **model** of a block as the acceptance hook sees it. NOT the node's real block.
///
/// - `height` drives the activation gate.
/// - `legacy_bytes` is an opaque stand-in for the node's canonical legacy block
///   serialization — the bytes that must be reproduced *unchanged* below activation.
/// - `eu_txs` are the block's eUTXO transactions. They are **ignored entirely** below
///   activation (that is the byte-identity invariant); at/above activation they are
///   validated and their BLCH fees are burn-split.
#[derive(Clone, Debug)]
pub struct BlockModel {
    pub height: u64,
    pub legacy_bytes: Vec<u8>,
    pub eu_txs: Vec<EuTx>,
}

/// The result of accepting a block through the modelled hook.
///
/// `committed_bytes` is the invariant surface: below activation it equals
/// `legacy_bytes` exactly. `feature_active` records which path ran. The fee fields and
/// `eu_gas_used` are zero on the legacy path (the legacy fee accounting lives inside
/// the opaque `legacy_bytes` and is untouched here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptOutcome {
    /// The canonical bytes the node commits for this block. `== legacy_bytes` below
    /// activation; a legacy prefix followed by a deterministic eUTXO section above it.
    pub committed_bytes: Vec<u8>,
    /// Which path ran — `is_feature_active(height)`.
    pub feature_active: bool,
    /// Total gas used validating `eu_txs` (0 on the legacy path).
    pub eu_gas_used: u64,
    /// Sum of the BLCH fees of `eu_txs` (0 on the legacy path).
    pub total_fee: u64,
    /// Portion of `total_fee` burned per [`EUVM_BURN_BPS`] (0 on the legacy path).
    pub fee_burned: u64,
    /// Portion of `total_fee` paid to the miner (0 on the legacy path).
    pub fee_to_miner: u64,
}

/// Why a block was rejected on the active path. The legacy path never rejects here —
/// it reproduces `legacy_bytes` unconditionally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// An eUTXO transaction failed validation (value conservation, a rejecting
    /// validator, a VM fault, or the block gas ceiling). Carries the offending tx
    /// index and the underlying [`TxError`] from [`validate_block`].
    Euvm { tx_index: usize, err: TxError },
    /// The sum of the block's BLCH fees overflowed `u64` — rejected deterministically.
    FeeOverflow,
}

/// **The legacy (feature-absent) acceptance path.**
///
/// Models a node that does not know the eUTXO feature at all: it simply commits the
/// canonical legacy bytes. Used to prove byte-identity — a compiled-in-but-inactive
/// node must produce exactly these bytes below the activation height.
#[inline]
pub fn legacy_committed_bytes(block: &BlockModel) -> Vec<u8> {
    block.legacy_bytes.clone()
}

/// Canonical, deterministic byte encoding of a single eUTXO output — the leaf value
/// committed into the state tree. Length-prefixed and fully typed so that two outputs
/// differing in *any* field (a single asset amount, the validator hash, or the datum)
/// encode to distinct bytes and therefore distinct leaves. No float/clock/HashMap: the
/// multi-asset `Value` is a `BTreeMap` (canonical key order) and `datum` is tagged.
fn encode_output(o: &ExtOutput) -> Vec<u8> {
    let mut b = Vec::new();
    // Multi-asset value bundle: count, then each (asset_id, amount) in BTreeMap order.
    b.extend_from_slice(&(o.value.len() as u64).to_le_bytes());
    for (asset, amt) in &o.value {
        b.extend_from_slice(asset);
        b.extend_from_slice(&amt.to_le_bytes());
    }
    // The guarding validator's hash.
    b.extend_from_slice(&o.validator_hash);
    // The datum, domain-tagged so Int/Bytes spaces never collide.
    match &o.datum {
        Val::Int(n) => {
            b.push(0x00);
            b.extend_from_slice(&n.to_le_bytes());
        }
        Val::Bytes(bytes) => {
            b.push(0x01);
            b.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            b.extend_from_slice(bytes);
        }
    }
    b
}

/// **The resulting-eUTXO-state root (F1).** Commit the block's token movements as a
/// [`SparseMerkleTree::root`] over the resulting state, not a scalar summary. Every
/// consumed input and every created output is keyed by a domain-separated
/// `(kind ‖ tx_index ‖ index)` position and its value is the canonical
/// [`encode_output`] blob. Two blocks that move different amounts, spend different
/// inputs, or write different datums therefore land on distinct leaves and produce
/// distinct roots — the byte-identical-commitment collision (a scalar summary bound
/// only `n_txs/gas/burned/to_miner`) is closed.
///
/// Deterministic and no-panic: `SparseMerkleTree` is a `BTreeMap` (canonical order),
/// the encoding is length-prefixed little-endian, and no arithmetic here can overflow
/// (positions are `usize`→`u64` casts, never added).
fn eutxo_state_root(txs: &[EuTx]) -> [u8; 32] {
    let mut smt = SparseMerkleTree::new();
    for (ti, tx) in txs.iter().enumerate() {
        let ti = ti as u64;
        // Consumed inputs (kind 0x00) — bind what the block spent.
        for (ii, inp) in tx.inputs.iter().enumerate() {
            let mut key = Vec::with_capacity(1 + 8 + 8);
            key.push(0x00);
            key.extend_from_slice(&ti.to_le_bytes());
            key.extend_from_slice(&(ii as u64).to_le_bytes());
            smt.insert(&key, &encode_output(&inp.prev_output));
        }
        // Created outputs (kind 0x01) — bind the resulting UTXO set.
        for (oi, out) in tx.outputs.iter().enumerate() {
            let mut key = Vec::with_capacity(1 + 8 + 8);
            key.push(0x01);
            key.extend_from_slice(&ti.to_le_bytes());
            key.extend_from_slice(&(oi as u64).to_le_bytes());
            smt.insert(&key, &encode_output(out));
        }
    }
    smt.root()
}

/// Deterministic, canonical encoding of the eUTXO section appended to the legacy bytes
/// on the *active* path. Layout: `"EUV1" ‖ state_root(32) ‖ n_txs ‖ gas_used ‖ burned
/// ‖ to_miner`, all little-endian. The **32-byte state root binds the resulting eUTXO
/// state** (see [`eutxo_state_root`]); the four `u64`s are bound side-data (fee/gas
/// accounting), NOT the commitment itself. Same inputs → same bytes on every node.
fn encode_eu_section(
    state_root: &[u8; 32],
    n_txs: u64,
    gas_used: u64,
    burned: u64,
    to_miner: u64,
) -> Vec<u8> {
    let mut o = Vec::with_capacity(4 + 32 + 8 * 4);
    o.extend_from_slice(b"EUV1");
    o.extend_from_slice(state_root);
    o.extend_from_slice(&n_txs.to_le_bytes());
    o.extend_from_slice(&gas_used.to_le_bytes());
    o.extend_from_slice(&burned.to_le_bytes());
    o.extend_from_slice(&to_miner.to_le_bytes());
    o
}

/// **The modelled `accept_block` hook.**
///
/// Deterministic dispatch on the height gate:
///
/// - **Below [`EUVM_ACTIVATION_HEIGHT`]** (`is_feature_active(height) == false`): the
///   legacy path. `eu_txs` are ignored; `committed_bytes == legacy_bytes` byte-for-
///   byte; all eUTXO/fee fields are zero. This is the byte-identity invariant.
/// - **At or above it** (`true`): run [`validate_block`] over `eu_txs` under the
///   per-tx and block gas ceilings; on success, sum the BLCH fees, split them with
///   [`fee_burn`]`(total_fee, `[`EUVM_BURN_BPS`]`)`, and commit
///   `legacy_bytes ‖ eu_section`. Any tx failure (including the gas ceiling) rejects
///   the block deterministically with [`AcceptError::Euvm`].
///
/// The dispatch reads no wall-clock, no HashMap iteration order, and no float; given
/// the same `block`, `verifier` behaviour, and `ceilings`, every node returns the same
/// `Result`.
pub fn accept_block_model(
    block: &BlockModel,
    verifier: &dyn SigVerifier,
    ceilings: GasCeilings,
) -> Result<AcceptOutcome, AcceptError> {
    if !is_feature_active(block.height) {
        // ── Legacy path: byte-for-byte identical to today. eu_txs are IGNORED. ──
        return Ok(AcceptOutcome {
            committed_bytes: legacy_committed_bytes(block),
            feature_active: false,
            eu_gas_used: 0,
            total_fee: 0,
            fee_burned: 0,
            fee_to_miner: 0,
        });
    }

    // ── Active path: validate eUTXO txs under the gas ceilings (the DoS bound). ──
    let eu_gas_used = validate_block(&block.eu_txs, verifier, ceilings.per_tx, ceilings.block)
        .map_err(|(tx_index, err)| AcceptError::Euvm { tx_index, err })?;

    // Sum the BLCH fees (checked — no silent wrap) and apply the base-fee burn.
    let mut total_fee: u64 = 0;
    for tx in &block.eu_txs {
        total_fee = total_fee.checked_add(tx.fee).ok_or(AcceptError::FeeOverflow)?;
    }
    let (fee_burned, fee_to_miner) = fee_burn(total_fee, EUVM_BURN_BPS);

    // Commit a real root over the resulting eUTXO state (F1) — not a scalar summary.
    let state_root = eutxo_state_root(&block.eu_txs);
    let mut committed_bytes = block.legacy_bytes.clone();
    committed_bytes.extend_from_slice(&encode_eu_section(
        &state_root,
        block.eu_txs.len() as u64,
        eu_gas_used,
        fee_burned,
        fee_to_miner,
    ));

    Ok(AcceptOutcome {
        committed_bytes,
        feature_active: true,
        eu_gas_used,
        total_fee,
        fee_burned,
        fee_to_miner,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blch, validator_hash, AssetId, ExtOutput, EuTxInput, Op, Val, Value, VmError, BLCH};

    /// A no-op verifier: the harness tests use `PushInt(1)` ("anyone") validators, so
    /// no signature is ever checked. Kept local — lib.rs's mock lives in its own
    /// `#[cfg(test)]` module and is not importable.
    struct NoopVerifier;
    impl SigVerifier for NoopVerifier {
        fn verify(&self, _msg: &[u8], _pk: &[u8], _sig: &[u8]) -> bool {
            false
        }
    }

    /// The trivial "anyone-can-spend" validator and its hash — a value-conserving,
    /// cheap-gas building block for constructing well-formed eUTXO txs.
    fn anyone() -> (Vec<Op>, [u8; 32]) {
        let prog = vec![Op::PushInt(1)];
        let vh = validator_hash(&prog);
        (prog, vh)
    }

    /// A well-formed eUTXO tx: consumes `value` BLCH, emits `value - fee`, pays `fee`.
    fn ok_tx(value: u64, fee: u64) -> EuTx {
        let (prog, vh) = anyone();
        EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(0) },
                validator: prog,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(value - fee), validator_hash: vh, datum: Val::Int(0) }],
            fee,
            sighash: vec![],
        }
    }

    fn block(height: u64, legacy: &[u8], eu_txs: Vec<EuTx>) -> BlockModel {
        BlockModel { height, legacy_bytes: legacy.to_vec(), eu_txs }
    }

    /// Activation is pinned to the coordinated Genesis-2 height (4320), which is
    /// above the live tip — so shipping this binary activates nothing on any
    /// block the fleet has produced to date (byte-identical to a397a9d2 below it).
    #[test]
    fn activation_height_is_coordinated_future_height() {
        assert_eq!(EUVM_ACTIVATION_HEIGHT, 4320);
        // Every height at/below the live tip today is below activation → feature off.
        for h in [0u64, 1, 2_400, 3_000, 3_757, EUVM_ACTIVATION_HEIGHT - 1] {
            assert!(!is_feature_active(h), "height {h} must be inactive below activation");
        }
        // At/above the coordinated height the feature is on.
        for h in [EUVM_ACTIVATION_HEIGHT, EUVM_ACTIVATION_HEIGHT + 1, 1_000_000] {
            assert!(is_feature_active(h), "height {h} must be active at/above activation");
        }
    }

    /// (1) Feature-off byte-identity: below activation the committed bytes equal the
    /// legacy bytes EXACTLY, and are identical whether the feature is compiled-in-but-
    /// inactive (`accept_block_model`) or absent (`legacy_committed_bytes`). The
    /// eu_txs are ignored — present or not, the bytes do not move.
    #[test]
    fn feature_off_byte_identity() {
        let legacy = b"CANONICAL-LEGACY-BLOCK-BYTES-vULN01".to_vec();
        let v = NoopVerifier;

        // Compiled-in-but-inactive, WITH eu_txs present — they must be ignored.
        let with_eu = block(2_400, &legacy, vec![ok_tx(100, 10), ok_tx(50, 5)]);
        let out = accept_block_model(&with_eu, &v, DEFAULT_GAS_CEILINGS).unwrap();
        assert!(!out.feature_active);
        assert_eq!(out.committed_bytes, legacy, "inactive path must be byte-identical to legacy");
        assert_eq!((out.eu_gas_used, out.total_fee, out.fee_burned, out.fee_to_miner), (0, 0, 0, 0));

        // "Feature absent" reference == the compiled-in-but-inactive committed bytes.
        assert_eq!(legacy_committed_bytes(&with_eu), out.committed_bytes);

        // Same height, NO eu_txs (feature literally absent from the block): still equal.
        let no_eu = block(2_400, &legacy, vec![]);
        assert_eq!(accept_block_model(&no_eu, &v, DEFAULT_GAS_CEILINGS).unwrap().committed_bytes, legacy);
    }

    /// (2) Activation flips at EXACTLY `EUVM_ACTIVATION_HEIGHT`, not one block earlier,
    /// and does so identically for every simulated node (a pure height comparison with
    /// no per-node state).
    #[test]
    fn activation_flips_exactly_at_height_identically_per_node() {
        // Off at H-1, on at H — the boundary is exact.
        assert!(!is_feature_active(EUVM_ACTIVATION_HEIGHT - 1));
        assert!(is_feature_active(EUVM_ACTIVATION_HEIGHT));

        // Simulate many independent nodes: each must agree at every probed height.
        const N_NODES: usize = 32;
        for h in [0u64, EUVM_ACTIVATION_HEIGHT - 1, EUVM_ACTIVATION_HEIGHT] {
            let reference = is_feature_active(h);
            for node in 0..N_NODES {
                assert_eq!(is_feature_active(h), reference, "node {node} disagreed at height {h}");
            }
        }

        // And the hook's chosen path matches the gate at the boundary.
        let v = NoopVerifier;
        let below = block(EUVM_ACTIVATION_HEIGHT - 1, b"L", vec![ok_tx(100, 10)]);
        let at = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![ok_tx(100, 10)]);
        assert!(!accept_block_model(&below, &v, DEFAULT_GAS_CEILINGS).unwrap().feature_active);
        assert!(accept_block_model(&at, &v, DEFAULT_GAS_CEILINGS).unwrap().feature_active);
    }

    /// (3) A block over the gas ceiling is rejected deterministically (the DoS bound).
    /// Same input → same `AcceptError::Euvm(OutOfBlockGas)` on every call.
    #[test]
    fn over_gas_ceiling_rejected_deterministically() {
        let v = NoopVerifier;
        // Three cheap txs; a block ceiling of 2 gas cannot fit them.
        let txs = vec![ok_tx(30, 0), ok_tx(30, 0), ok_tx(30, 0)];
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", txs);
        let starved = GasCeilings { per_tx: 1_000, block: 2 };

        let first = accept_block_model(&b, &v, starved);
        assert!(matches!(first, Err(AcceptError::Euvm { err: TxError::OutOfBlockGas, .. })));
        // Determinism: identical rejection across repeated evaluation.
        for _ in 0..50 {
            assert_eq!(accept_block_model(&b, &v, starved), first);
        }
        // Ample ceiling accepts the very same block → the rejection was the gas bound.
        assert!(accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS).unwrap().feature_active);
    }

    /// A rejecting validator / non-conserving tx also fails closed on the active path,
    /// surfacing the underlying `TxError` with the offending tx index.
    #[test]
    fn active_path_fails_closed_on_bad_tx() {
        let v = NoopVerifier;
        let (prog, vh) = anyone();
        // Value not conserved: 100 in, 90 out, fee 5 → 95 != 100.
        let bad = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
                validator: prog,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(90), validator_hash: vh, datum: Val::Int(0) }],
            fee: 5,
            sighash: vec![],
        };
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![ok_tx(100, 0), bad]);
        let got = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS);
        assert!(matches!(
            got,
            Err(AcceptError::Euvm { tx_index: 1, err: TxError::ValueNotConserved { .. } })
        ));
    }

    /// (4) Fee burn splits correctly on the active path: the block's total BLCH fee is
    /// split by `fee_burn(total, EUVM_BURN_BPS)`, burned + to_miner == total, and the
    /// committed bytes carry the deterministic eUTXO section.
    #[test]
    fn fee_burn_splits_correctly() {
        let v = NoopVerifier;
        let legacy = b"L".to_vec();
        // Fees 100 + 50 + 250 = 400 BLCH. At 20% burn: 80 burned, 320 to miner.
        let txs = vec![ok_tx(1000, 100), ok_tx(500, 50), ok_tx(600, 250)];
        let b = block(EUVM_ACTIVATION_HEIGHT, &legacy, txs);

        let out = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS).unwrap();
        assert!(out.feature_active);
        assert_eq!(out.total_fee, 400);
        assert_eq!((out.fee_burned, out.fee_to_miner), fee_burn(400, EUVM_BURN_BPS));
        assert_eq!(out.fee_burned, 80);
        assert_eq!(out.fee_to_miner, 320);
        // Conservation of the split.
        assert_eq!(out.fee_burned + out.fee_to_miner, out.total_fee);

        // Active committed bytes = legacy prefix ‖ deterministic eu section (differs
        // from the legacy bytes, and is reproducible).
        assert!(out.committed_bytes.starts_with(&legacy));
        assert_ne!(out.committed_bytes, legacy);
        assert_eq!(
            accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS).unwrap().committed_bytes,
            out.committed_bytes
        );
    }

    /// The active-path fee accounting holds for the empty-block edge case (no txs,
    /// zero fee, zero burn) while still taking the active branch.
    #[test]
    fn active_empty_block_zero_fee() {
        let v = NoopVerifier;
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![]);
        let out = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS).unwrap();
        assert!(out.feature_active);
        assert_eq!((out.total_fee, out.fee_burned, out.fee_to_miner, out.eu_gas_used), (0, 0, 0, 0));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Adversarial + property tests (determinism, gas bounds, fail-closed on
    // malformed input, conservation, no-panic on edge cases).
    // ─────────────────────────────────────────────────────────────────────

    /// A validator whose gas cost (a `Sha256d`, 60 gas) exceeds a starved `per_tx`
    /// ceiling. Builds a value-conserving tx around it so the *only* possible
    /// rejection reason is the per-tx gas ceiling (not conservation).
    fn slow_tx(value: u64) -> EuTx {
        // Ends with a truthy Int on top (via Drop + PushInt(1)) so that, given ample
        // gas, this validator actually SUCCEEDS — isolating the ceiling as the only
        // possible rejection reason. `Sha256d` alone (60 gas) exceeds a starved
        // per-tx ceiling before the cheap ops around it ever get charged.
        let prog = vec![Op::PushBytes(vec![]), Op::Sha256d, Op::Drop, Op::PushInt(1)];
        let vh = validator_hash(&prog);
        let (_, out_vh) = anyone();
        EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(0) },
                validator: prog,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(value), validator_hash: out_vh, datum: Val::Int(0) }],
            fee: 0,
            sighash: vec![],
        }
    }

    /// A multi-asset `Value`: `blch_amt` BLCH plus `other_amt` of a distinct asset.
    fn multi_asset(blch_amt: u64, asset: AssetId, other_amt: u64) -> Value {
        let mut v = Value::new();
        if blch_amt > 0 {
            v.insert(BLCH, blch_amt);
        }
        if other_amt > 0 {
            v.insert(asset, other_amt);
        }
        v
    }

    /// Property: below activation, `eu_txs` are ignored UNCONDITIONALLY — even when
    /// they are individually malformed (non-conserving, or whose validator hash
    /// mismatches its own program). Byte-identity must not depend on the eu_txs being
    /// well-formed; a node that never learned the feature never inspects them at all.
    #[test]
    fn legacy_path_ignores_malformed_eu_txs_below_activation() {
        let v = NoopVerifier;
        let legacy = b"CANONICAL-LEGACY-BYTES".to_vec();
        let (prog, vh) = anyone();

        // Non-conserving: 100 in, 50 out, fee 0 -> 50 != 100.
        let non_conserving = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
                validator: prog.clone(),
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(50), validator_hash: vh, datum: Val::Int(0) }],
            fee: 0,
            sighash: vec![],
        };
        // Validator hash mismatch: program != the hash the output actually commits to.
        let hash_mismatch = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(10), validator_hash: [0xEE; 32], datum: Val::Int(0) },
                validator: prog,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(10), validator_hash: [0xEE; 32], datum: Val::Int(0) }],
            fee: 0,
            sighash: vec![],
        };

        for garbage in [vec![non_conserving], vec![hash_mismatch]] {
            let b = block(EUVM_ACTIVATION_HEIGHT - 1, &legacy, garbage);
            let out = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS)
                .expect("inactive path never rejects, however malformed eu_txs are");
            assert!(!out.feature_active);
            assert_eq!(out.committed_bytes, legacy);
            assert_eq!(out.committed_bytes, legacy_committed_bytes(&b));
        }
    }

    /// Property: determinism holds across many distinct scenarios — active/inactive,
    /// success/failure of every `AcceptError` kind — not just a single repeated call.
    /// Same `(block, ceilings)` in -> byte-identical `Result` out, every time.
    #[test]
    fn determinism_holds_across_many_scenarios() {
        let v = NoopVerifier;
        let (_, vh) = anyone();
        let overflow_tx = |fee: u64, value: u64| EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(value), validator_hash: vh, datum: Val::Int(0) },
                validator: anyone().0,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(value - fee), validator_hash: vh, datum: Val::Int(0) }],
            fee,
            sighash: vec![],
        };

        let scenarios: Vec<(BlockModel, GasCeilings)> = vec![
            (block(0, b"L", vec![ok_tx(100, 10)]), DEFAULT_GAS_CEILINGS),
            (block(EUVM_ACTIVATION_HEIGHT, b"L", vec![ok_tx(100, 10)]), DEFAULT_GAS_CEILINGS),
            (
                block(EUVM_ACTIVATION_HEIGHT, b"L", vec![ok_tx(30, 0), ok_tx(30, 0)]),
                GasCeilings { per_tx: 1_000, block: 1 },
            ),
            (block(EUVM_ACTIVATION_HEIGHT, b"L", vec![slow_tx(100)]), GasCeilings { per_tx: 5, block: 1_000 }),
            (
                block(EUVM_ACTIVATION_HEIGHT, b"L", vec![overflow_tx(u64::MAX, u64::MAX), overflow_tx(1, u64::MAX)]),
                DEFAULT_GAS_CEILINGS,
            ),
            (block(EUVM_ACTIVATION_HEIGHT, b"L", vec![]), GasCeilings { per_tx: 0, block: 0 }),
        ];

        for (b, ceilings) in &scenarios {
            let reference = accept_block_model(b, &v, *ceilings);
            for _ in 0..10 {
                assert_eq!(accept_block_model(b, &v, *ceilings), reference, "non-deterministic for {b:?}");
            }
        }
    }

    /// Gas bound (2): a single tx whose validator alone costs more gas than the
    /// **per-tx** ceiling is rejected deterministically, even though the block-wide
    /// ceiling is ample — isolating the per-tx bound from the block-wide one (already
    /// covered by `over_gas_ceiling_rejected_deterministically`).
    #[test]
    fn per_tx_gas_ceiling_rejects_single_tx_deterministically() {
        let v = NoopVerifier;
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![slow_tx(100)]);
        let starved = GasCeilings { per_tx: 5, block: 1_000_000 };

        let got = accept_block_model(&b, &v, starved);
        assert!(
            matches!(got, Err(AcceptError::Euvm { tx_index: 0, err: TxError::Vm(0, VmError::OutOfGas) })),
            "expected per-tx OutOfGas, got {got:?}"
        );
        // Determinism.
        for _ in 0..10 {
            assert_eq!(accept_block_model(&b, &v, starved), got);
        }
        // A generous per-tx ceiling accepts the identical tx.
        assert!(accept_block_model(&b, &v, GasCeilings { per_tx: 1_000, block: 1_000_000 }).is_ok());
    }

    /// Fail-closed, no-panic (malformed input): a spender that reveals a validator
    /// program whose hash does NOT match the output's committed `validator_hash` is
    /// rejected deterministically via the VM's binding check — it must not panic and
    /// must not be silently authorized.
    #[test]
    fn validator_hash_mismatch_fails_closed_no_panic() {
        let v = NoopVerifier;
        let (prog_a, vh_a) = anyone();
        let prog_b = vec![Op::PushInt(1), Op::PushInt(1), Op::Eq]; // different program, different hash
        assert_ne!(validator_hash(&prog_a), validator_hash(&prog_b));

        let tx = EuTx {
            inputs: vec![EuTxInput {
                // Output commits to vh_a, but the revealed program is prog_b.
                prev_output: ExtOutput { value: blch(100), validator_hash: vh_a, datum: Val::Int(0) },
                validator: prog_b,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(100), validator_hash: vh_a, datum: Val::Int(0) }],
            fee: 0,
            sighash: vec![],
        };
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![tx]);
        let got = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS);
        assert!(matches!(
            got,
            Err(AcceptError::Euvm { tx_index: 0, err: TxError::Vm(0, VmError::ValidatorHashMismatch) })
        ));
    }

    /// Fail-closed, no-panic (malformed input): a validator program that underflows
    /// the VM stack (more `Drop`s than values available) surfaces as a `TxError`, not
    /// a Rust panic — the VM's `checked` stack access must hold under adversarial
    /// programs the harness didn't author.
    #[test]
    fn stack_underflow_in_validator_fails_closed_no_panic() {
        let v = NoopVerifier;
        let prog = vec![Op::Drop, Op::Drop]; // 1st pops the seeded datum; 2nd underflows
        let vh = validator_hash(&prog);
        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) },
                validator: prog,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: blch(100), validator_hash: vh, datum: Val::Int(0) }],
            fee: 0,
            sighash: vec![],
        };
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![tx]);
        let got = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS);
        assert!(matches!(
            got,
            Err(AcceptError::Euvm { tx_index: 0, err: TxError::Vm(0, VmError::StackUnderflow) })
        ));
    }

    /// Value/supply conservation (3): conservation is enforced **per asset**, not only
    /// for BLCH. A native asset that fails to balance is rejected with its own asset
    /// id, even while the BLCH leg of the same tx balances exactly.
    #[test]
    fn non_blch_asset_conservation_enforced() {
        let v = NoopVerifier;
        let other: AssetId = [7u8; 32];
        let (prog, vh) = anyone();
        // BLCH balances (100 == 100 + 0 fee); `other` does not (50 in, 40 out).
        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: multi_asset(100, other, 50), validator_hash: vh, datum: Val::Int(0) },
                validator: prog,
                redeemer: vec![],
            }],
            outputs: vec![ExtOutput { value: multi_asset(100, other, 40), validator_hash: vh, datum: Val::Int(0) }],
            fee: 0,
            sighash: vec![],
        };
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![tx]);
        let got = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS);
        match got {
            Err(AcceptError::Euvm { tx_index: 0, err: TxError::ValueNotConserved { asset, in_sum, out_plus_fee } }) => {
                assert_eq!(asset, other);
                assert_eq!((in_sum, out_plus_fee), (50, 40));
            }
            other => panic!("expected ValueNotConserved on the non-BLCH asset, got {other:?}"),
        }
    }

    /// Fail-closed, no-panic: the block's total BLCH fee overflowing `u64` is caught by
    /// the harness's checked summation (not a wrapping add) and rejected
    /// deterministically as `AcceptError::FeeOverflow` — distinct from `AcceptError::
    /// Euvm` and not previously exercised by the other tests in this module.
    #[test]
    fn fee_sum_overflow_rejected_deterministically() {
        let v = NoopVerifier;
        // fee u64::MAX + fee 1 overflows u64. Each tx is individually value-conserving
        // (value == fee, or value - fee with no underflow).
        let txs = vec![ok_tx(u64::MAX, u64::MAX), ok_tx(u64::MAX, 1)];
        let b = block(EUVM_ACTIVATION_HEIGHT, b"L", txs);

        let got = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS);
        assert_eq!(got, Err(AcceptError::FeeOverflow));
        for _ in 0..10 {
            assert_eq!(accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS), got);
        }
    }

    /// No-panic edge case: an all-zero gas schedule (`per_tx: 0, block: 0`) must not
    /// panic. An empty block still succeeds (there is nothing to meter); a non-empty
    /// block fails closed on the very first op's gas charge.
    #[test]
    fn zero_gas_ceilings_no_panic() {
        let v = NoopVerifier;
        let starved = GasCeilings { per_tx: 0, block: 0 };

        let empty = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![]);
        let out = accept_block_model(&empty, &v, starved).unwrap();
        assert_eq!((out.eu_gas_used, out.total_fee), (0, 0));

        let nonempty = block(EUVM_ACTIVATION_HEIGHT, b"L", vec![ok_tx(30, 0)]);
        let got = accept_block_model(&nonempty, &v, starved);
        assert!(matches!(got, Err(AcceptError::Euvm { tx_index: 0, err: TxError::Vm(0, VmError::OutOfGas) })));
    }

    /// Canonical-encoding property (F1 fixed): the active-path eUTXO section is
    /// `"EUV1" ‖ state_root(32) ‖ four u64s` — it now carries a **32-byte root** over
    /// the resulting eUTXO state, not just a scalar header. The section is a fixed size
    /// (the root and the side-data are both fixed width, independent of tx count) AND
    /// the committed root DIFFERS across blocks with distinct resulting state — the
    /// regression guard for the scalar-summary collision the audit found.
    #[test]
    fn eu_section_carries_state_root_and_differs_across_distinct_states() {
        let v = NoopVerifier;
        let legacy = b"LEGACY".to_vec();
        // "EUV1"(4) + state_root(32) + n_txs/gas/burned/to_miner (4 * u64).
        const SECTION_LEN: usize = 4 + 32 + 8 * 4;

        let mut seen_roots: Vec<[u8; 32]> = Vec::new();
        for n in [0usize, 1, 2, 5] {
            // Distinct per-n movements so the resulting state genuinely differs.
            let txs: Vec<EuTx> = (0..n as u64).map(|i| ok_tx(1_000 + 10 * n as u64 + i, 1)).collect();
            let b = block(EUVM_ACTIVATION_HEIGHT, &legacy, txs);
            let out = accept_block_model(&b, &v, DEFAULT_GAS_CEILINGS).unwrap();

            // Fixed section size (root width is constant regardless of tx count).
            assert_eq!(
                out.committed_bytes.len(),
                legacy.len() + SECTION_LEN,
                "eu section length must not depend on tx count (n={n})"
            );
            assert!(out.committed_bytes.starts_with(&legacy));
            assert_eq!(&out.committed_bytes[legacy.len()..legacy.len() + 4], b"EUV1");

            // The 32 bytes after "EUV1" are the committed state root; distinct states
            // must yield distinct roots (no scalar-summary collisions).
            let root_off = legacy.len() + 4;
            let mut root = [0u8; 32];
            root.copy_from_slice(&out.committed_bytes[root_off..root_off + 32]);
            assert!(
                !seen_roots.contains(&root),
                "distinct resulting states collided on the same root (n={n})"
            );
            seen_roots.push(root);
        }
    }

    /// Property: `fee_burn` (as used by the active path) never over-allocates —
    /// `burned + to_miner == fee` and `burned <= fee` — across boundary fee values and
    /// burn-bps settings, including values that stress `u64`/`u128` arithmetic and an
    /// out-of-range bps (must clamp at 100%, never panic or exceed `fee`).
    #[test]
    fn fee_burn_bounds_hold_for_extreme_values() {
        for fee in [0u64, 1, EUVM_BURN_BPS as u64, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            for bps in [0u16, 1, EUVM_BURN_BPS, 9_999, 10_000, u16::MAX] {
                let (burned, to_miner) = fee_burn(fee, bps);
                assert_eq!(burned.checked_add(to_miner), Some(fee), "split must conserve for fee={fee} bps={bps}");
                assert!(burned <= fee, "burned must not exceed fee for fee={fee} bps={bps}");
            }
        }
    }
}
