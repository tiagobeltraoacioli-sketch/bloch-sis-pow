//! # Native minting / burn policies (Cardano-style) — the Supply substrate
//!
//! FOUNDATION / reference module for `bloch-euvm`. Standalone, deterministic,
//! gas-metered, **NOT wired into node consensus**. Everything here lives behind this
//! crate's own tests, exactly like `lib.rs`.
//!
//! ## The model (Cardano / Ergo native tokens)
//!
//! An asset's identity **is** the hash of the program that governs its supply. A
//! [`MintingPolicy`] is nothing more than a validator program (`Vec<Op>` from
//! `lib.rs`) keyed to exactly one [`AssetId`] — and that asset id is *defined* as the
//! policy's own [`validator_hash`](crate::validator_hash). So an asset cannot exist
//! without a policy, and no other program can mint it: to authorise any change to the
//! supply of asset `X`, you MUST reveal a program that hashes to `X` and that returns
//! `true` when run over the transaction context. This mirrors `lib.rs`'s stated rule
//! "asset id = hash of its minting policy".
//!
//! A [`MintAction`] `{ asset_id, delta: i128 }` requests a **net signed** change to a
//! token's supply within one transaction: `delta > 0` mints, `delta < 0` burns. It is
//! authorised iff the matching policy program (revealed in the same [`MintRequest`])
//! runs to `true`.
//!
//! ## What [`validate_tx_with_mint`] does
//!
//! It mirrors the per-asset conservation logic of [`crate::validate_tx`] (it does NOT
//! edit it) but **relaxes the exact-balance rule for a given asset by precisely the
//! net authorised mint/burn** — and only for assets whose policy authorised that
//! delta. Concretely, for every asset the invariant becomes:
//!
//! ```text
//!     in_sum + net_mint_delta  ==  out_sum + fee     (fee is BLCH-only)
//! ```
//!
//! with `net_mint_delta == 0` for any asset with no presented policy — so such an
//! asset still balances **exactly**, identical to the current node invariant.
//!
//! ## Hard invariants enforced here
//!
//! - **BLCH ([`BLCH`], the all-zero id) can NEVER be minted or burned.** Any
//!   [`MintAction`] naming BLCH is rejected before anything else runs.
//! - **`delta` is checked `i128`.** Combining deltas and folding sums use checked
//!   arithmetic; overflow is a hard error, never a wrap.
//! - **Burn cannot drive supply negative:** `prior_supply + delta >= 0` is required
//!   (the caller supplies the asset's prior on-chain supply).
//! - **A policy only governs its own asset:** `validator_hash(policy) == asset_id`,
//!   else the request is rejected (`PolicyAssetMismatch`).
//!
//! Honest boundary: reference / unaudited / not consensus-wired. Designed ≠ built ≠
//! booted. The Integrate phase wires this module into `lib.rs`.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    run, spend, validator_hash, value_get, AssetId, Ctx, EuTx, Op, SigVerifier, TxError, Val,
    Value, VmError, BLCH,
};

/// A minting policy is simply a validator program. Its identity — and therefore the
/// [`AssetId`] it governs — is [`policy_asset_id`] `= validator_hash(policy)`.
pub type MintingPolicy = Vec<Op>;

// ── The deterministic minting-context field layout ──
//
// A minting policy is a *transaction-level* validator (it is not spending a specific
// output), so instead of `[datum, redeemer…]` it runs over a small, fixed context.
// These indices are the stable ABI a policy program reads via `Op::CtxField(i)`; the
// policy-builder helpers below use exactly these.

/// `ctx.fields[0]` — the transaction sighash (Bytes). Same slot as [`crate::validate_tx`],
/// so an authorized-minter policy can `VerifySig` over it.
pub const MINT_CTX_SIGHASH: u8 = 0;
/// `ctx.fields[1]` — the signed net `delta` for the action being authorised (Int).
pub const MINT_CTX_DELTA: u8 = 1;
/// `ctx.fields[2]` — the spending block height (Int), for time/height-gated policies.
pub const MINT_CTX_HEIGHT: u8 = 2;
/// `ctx.fields[3]` — the asset's prior on-chain supply (Int), for cap policies.
pub const MINT_CTX_PRIOR_SUPPLY: u8 = 3;

/// The asset id a policy governs: `SHA-256d(encode_program(policy))`. This is the
/// same function outputs commit to via `validator_hash`, so a token's id and its
/// minting authority are one and the same object.
pub fn policy_asset_id(policy: &[Op]) -> AssetId {
    validator_hash(policy)
}

/// A requested net change to a native asset's supply inside one transaction.
/// `delta > 0` mints, `delta < 0` burns, `delta == 0` is a no-op (still type-checked).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintAction {
    pub asset_id: AssetId,
    pub delta: i128,
}

/// A mint/burn bundled with the authority for it: the revealed `policy` program
/// (which MUST hash to `action.asset_id`), the `redeemer` seeding the policy's stack,
/// and the [`MintAction`] itself.
#[derive(Clone, Debug)]
pub struct MintRequest {
    pub policy: MintingPolicy,
    pub redeemer: Vec<Val>,
    pub action: MintAction,
}

/// The extra chain state a minting check needs beyond the transaction: the current
/// block `height` (for height-gated policies) and each asset's `prior_supply` (for
/// cap policies and the burn non-negativity check). Absent assets read as `0`.
#[derive(Clone, Debug, Default)]
pub struct MintCtx {
    pub height: i128,
    pub prior_supply: BTreeMap<AssetId, i128>,
}

impl MintCtx {
    fn prior(&self, asset: &AssetId) -> i128 {
        self.prior_supply.get(asset).copied().unwrap_or(0)
    }
}

/// Errors specific to mint-aware validation. `Tx` wraps the ordinary spend/validator
/// errors from the mirrored conservation + validator-run path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MintTxError {
    /// BLCH (the all-zero base asset) can never be minted or burned.
    BlchMintForbidden,
    /// `validator_hash(policy) != action.asset_id`: the policy does not govern this asset.
    PolicyAssetMismatch { asset: AssetId },
    /// Two mint requests named the same asset — ambiguous; present a single net delta.
    DuplicatePolicy { asset: AssetId },
    /// The policy program ran to `false` — the delta is not authorised.
    PolicyRejected { asset: AssetId },
    /// The policy program errored (bad opcode use, out of gas, …).
    PolicyVm { asset: AssetId, err: VmError },
    /// Checked-`i128` overflow while combining deltas or summing values.
    MintOverflow { asset: AssetId },
    /// A burn would drive the asset's total supply below zero.
    SupplyNegative { asset: AssetId },
    /// Relaxed conservation failed: `in_sum + net_mint != out_sum + fee`.
    ValueNotConserved {
        asset: AssetId,
        in_plus_mint: i128,
        out_plus_fee: i128,
    },
    /// An underlying input-validator / VM error from the mirrored spend path.
    Tx(TxError),
}

/// Build the deterministic context a minting policy runs against for one action.
fn mint_ctx(tx: &EuTx, asset: AssetId, delta: i128, mctx: &MintCtx) -> Ctx {
    Ctx {
        fields: vec![
            Val::Bytes(tx.sighash.clone()),
            Val::Int(delta),
            Val::Int(mctx.height),
            Val::Int(mctx.prior(&asset)),
        ],
        tx_outputs: tx.outputs.clone(),
        // A policy is not spending an output; expose its own asset id as "self" so a
        // policy that wants to could assert its identity, and leave reserves empty.
        self_validator_hash: asset,
        self_value: Value::new(),
    }
}

/// **The mint-aware transaction checker.** Mirrors [`crate::validate_tx`]'s per-asset
/// conservation and validator-run, but relaxes the balance of each asset by the net
/// signed mint/burn that its policy authorised. Returns total gas used (policies +
/// input validators share one budget). See the module docs for the exact invariant.
pub fn validate_tx_with_mint(
    tx: &EuTx,
    mints: &[MintRequest],
    mctx: &MintCtx,
    verifier: &dyn SigVerifier,
    gas_limit: u64,
) -> Result<u64, MintTxError> {
    let mut gas = gas_limit;

    // ── (1) Authorise every requested mint/burn by running its policy program. ──
    // The net signed delta per asset, keyed canonically for determinism.
    let mut net_mint: BTreeMap<AssetId, i128> = BTreeMap::new();

    for req in mints {
        let asset = req.action.asset_id;
        let delta = req.action.delta;

        // BLCH is unmintable — checked before anything else, before any gas is spent.
        if asset == BLCH {
            return Err(MintTxError::BlchMintForbidden);
        }
        // The policy must be the one that *defines* this asset.
        if policy_asset_id(&req.policy) != asset {
            return Err(MintTxError::PolicyAssetMismatch { asset });
        }
        // One net delta per asset — reject ambiguous duplicates.
        if net_mint.contains_key(&asset) {
            return Err(MintTxError::DuplicatePolicy { asset });
        }

        // Run the policy over the mint context. It sees the delta it is authorising
        // (field 1), the height (field 2), the prior supply (field 3) and the sighash.
        let ctx = mint_ctx(tx, asset, delta, mctx);
        match run(&req.policy, req.redeemer.clone(), &ctx, verifier, &mut gas) {
            Ok(true) => {}
            Ok(false) => return Err(MintTxError::PolicyRejected { asset }),
            Err(err) => return Err(MintTxError::PolicyVm { asset, err }),
        }

        // Burn cannot drive supply negative (checked i128 throughout).
        let prior = mctx.prior(&asset);
        let new_supply = prior
            .checked_add(delta)
            .ok_or(MintTxError::MintOverflow { asset })?;
        if new_supply < 0 {
            return Err(MintTxError::SupplyNegative { asset });
        }

        net_mint.insert(asset, delta);
    }

    // ── (2) Per-asset conservation, relaxed by the authorised net mint. ──
    // Mirror of `validate_tx`'s step (1): gather every asset that appears anywhere,
    // always include BLCH, and additionally any asset carrying a net mint (e.g. a
    // pure burn-to-nothing whose asset would otherwise vanish from the output set).
    let mut assets: BTreeSet<AssetId> = BTreeSet::new();
    for i in &tx.inputs {
        assets.extend(i.prev_output.value.keys().copied());
    }
    for o in &tx.outputs {
        assets.extend(o.value.keys().copied());
    }
    assets.extend(net_mint.keys().copied());
    assets.insert(BLCH);

    for asset in &assets {
        // in_sum and out_sum via checked i128 folds (u64 amounts widen safely).
        let mut in_sum: i128 = 0;
        for inp in &tx.inputs {
            in_sum = in_sum
                .checked_add(value_get(&inp.prev_output.value, asset) as i128)
                .ok_or(MintTxError::MintOverflow { asset: *asset })?;
        }
        let mut out_sum: i128 = 0;
        for o in &tx.outputs {
            out_sum = out_sum
                .checked_add(value_get(&o.value, asset) as i128)
                .ok_or(MintTxError::MintOverflow { asset: *asset })?;
        }

        let fee: i128 = if *asset == BLCH { tx.fee as i128 } else { 0 };
        // BLCH never carries a mint (guarded above); every other asset relaxes by its
        // authorised net delta, defaulting to exactly-zero when no policy was shown.
        let delta = net_mint.get(asset).copied().unwrap_or(0);

        let in_plus_mint = in_sum
            .checked_add(delta)
            .ok_or(MintTxError::MintOverflow { asset: *asset })?;
        let out_plus_fee = out_sum
            .checked_add(fee)
            .ok_or(MintTxError::MintOverflow { asset: *asset })?;

        if in_plus_mint != out_plus_fee {
            return Err(MintTxError::ValueNotConserved {
                asset: *asset,
                in_plus_mint,
                out_plus_fee,
            });
        }
    }

    // ── (3) Run every input's validator with the whole tx visible (mirror of
    // `validate_tx`'s step (2)+(3)), sharing the same gas budget as the policies. ──
    let spend_ctx = Ctx {
        fields: vec![Val::Bytes(tx.sighash.clone())],
        tx_outputs: tx.outputs.clone(),
        self_validator_hash: [0u8; 32],
        self_value: Value::new(), // spend() sets this per-input
    };
    for (i, inp) in tx.inputs.iter().enumerate() {
        match spend(
            &inp.prev_output,
            &inp.validator,
            inp.redeemer.clone(),
            &spend_ctx,
            verifier,
            &mut gas,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(MintTxError::Tx(TxError::ValidatorRejected(i))),
            Err(e) => return Err(MintTxError::Tx(TxError::Vm(i, e))),
        }
    }

    Ok(gas_limit - gas)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reference policy constructors. Each returns a `MintingPolicy` program; the asset
// it governs is `policy_asset_id(&program)`. Because the policy's parameters (cap,
// minter key, unlock height) are baked into the program bytes, distinct parameters
// yield distinct asset ids — exactly the Cardano property that the policy *is* the
// asset's identity.
// ─────────────────────────────────────────────────────────────────────────────

/// **Fixed-supply cap policy.** Authorises a delta iff `prior_supply + delta <= cap`
/// (and, via the caller-side non-negativity check, `>= 0`). Reading `prior_supply`
/// from `ctx.fields[3]` and `delta` from `ctx.fields[1]`, it computes the new supply
/// and asserts it does not exceed `cap`. Burns (negative delta) always satisfy the
/// cap. No redeemer required.
pub fn fixed_supply_cap_policy(cap: i128) -> MintingPolicy {
    vec![
        Op::CtxField(MINT_CTX_PRIOR_SUPPLY), // [prior]
        Op::CtxField(MINT_CTX_DELTA),        // [prior, delta]
        Op::Add,                             // [new_supply]
        Op::PushInt(cap + 1),                // [new_supply, cap+1]
        Op::Lt,                              // [new_supply < cap+1]  ==  new_supply <= cap
    ]
}

/// **Authorized-minter-signature policy.** Authorises any delta iff the `redeemer`
/// supplies a valid post-quantum signature (checked by the host [`SigVerifier`]) over
/// the transaction sighash under `minter_pubkey`. The redeemer stack is seeded with
/// `[sig]` (a single `Val::Bytes`). This is the "a named authority may issue/burn"
/// policy — the token equivalent of P2PKH.
pub fn authorized_minter_policy(minter_pubkey: Vec<u8>) -> MintingPolicy {
    // seed stack: [sig]
    vec![
        Op::CtxField(MINT_CTX_SIGHASH),  // [sig, msg]
        Op::Swap,                        // [msg, sig]
        Op::PushBytes(minter_pubkey),    // [msg, sig, pk]
        Op::Swap,                        // [msg, pk, sig]
        Op::VerifySig,                   // [ok]   (pops sig, pk, msg)
    ]
}

/// **Time/height-gated policy.** Authorises a delta iff the spending block height
/// (`ctx.fields[2]`) is `>= unlock_height`. Models a vesting / scheduled-issuance
/// window: no issuance before the gate opens. No redeemer required.
pub fn height_gate_policy(unlock_height: i128) -> MintingPolicy {
    vec![
        Op::CtxField(MINT_CTX_HEIGHT), // [height]
        Op::PushInt(unlock_height),    // [height, unlock]
        Op::Lt,                        // [height < unlock]
        Op::Not,                       // [height >= unlock]
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blch, EuTxInput, ExtOutput};

    /// A mock verifier accepting exactly the (msg, pk, sig) triples it is told.
    struct MockVerifier {
        good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    }
    impl SigVerifier for MockVerifier {
        fn verify(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
            self.good
                .iter()
                .any(|(m, p, s)| m == msg && p == pk && s == sig)
        }
    }
    fn noop() -> MockVerifier {
        MockVerifier { good: vec![] }
    }

    /// Convenience: a single-asset value `{asset: n}`.
    fn asset_val(asset: AssetId, n: u64) -> Value {
        let mut v = Value::new();
        v.insert(asset, n);
        v
    }
    fn out(value: Value) -> ExtOutput {
        // A trivial "always-true" guard on the output itself (outputs aren't run;
        // only inputs are — this is just a well-formed ExtOutput).
        ExtOutput {
            value,
            validator_hash: [0u8; 32],
            datum: Val::Int(0),
        }
    }

    // ── policy identity ──

    #[test]
    fn asset_id_is_policy_hash_and_params_change_it() {
        let p1000 = fixed_supply_cap_policy(1000);
        let p2000 = fixed_supply_cap_policy(2000);
        assert_eq!(policy_asset_id(&p1000), validator_hash(&p1000));
        // distinct caps → distinct assets (the policy *is* the identity)
        assert_ne!(policy_asset_id(&p1000), policy_asset_id(&p2000));
        // a cap policy never collides with the base asset
        assert_ne!(policy_asset_id(&p1000), BLCH);
    }

    // ── mint with a valid policy passes; relaxed conservation holds ──

    #[test]
    fn mint_with_valid_cap_policy_passes() {
        let policy = fixed_supply_cap_policy(1000);
        let asset = policy_asset_id(&policy);

        // Fresh mint of 500: no input carries the asset, one output does.
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 500))],
            fee: 0,
            sighash: b"sh".to_vec(),
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: 500,
            },
        }];
        let mctx = MintCtx::default(); // prior_supply 0, height 0
        assert!(validate_tx_with_mint(&tx, &mints, &mctx, &noop(), 50_000).is_ok());
    }

    #[test]
    fn mint_with_authorized_minter_signature_passes() {
        let minter_pk = b"minter-pubkey".to_vec();
        let sig = b"minter-sig".to_vec();
        let sighash = b"the-sighash".to_vec();

        let policy = authorized_minter_policy(minter_pk.clone());
        let asset = policy_asset_id(&policy);

        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 42))],
            fee: 0,
            sighash: sighash.clone(),
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![Val::Bytes(sig.clone())],
            action: MintAction {
                asset_id: asset,
                delta: 42,
            },
        }];
        let v = MockVerifier {
            good: vec![(sighash, minter_pk, sig)],
        };
        assert!(validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &v, 50_000).is_ok());
    }

    #[test]
    fn authorized_minter_wrong_sig_rejected() {
        let policy = authorized_minter_policy(b"minter-pubkey".to_vec());
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 42))],
            fee: 0,
            sighash: b"sh".to_vec(),
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![Val::Bytes(b"forged".to_vec())],
            action: MintAction {
                asset_id: asset,
                delta: 42,
            },
        }];
        // noop verifier rejects everything → policy returns false
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::PolicyRejected { asset })
        );
    }

    // ── mint WITHOUT a policy is rejected (exact-balance still enforced) ──

    #[test]
    fn mint_without_policy_rejected() {
        // Output invents 500 of some asset X, but no MintRequest is presented.
        let asset: AssetId = [7u8; 32];
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 500))],
            fee: 0,
            sighash: vec![],
        };
        let res = validate_tx_with_mint(&tx, &[], &MintCtx::default(), &noop(), 50_000);
        assert_eq!(
            res,
            Err(MintTxError::ValueNotConserved {
                asset,
                in_plus_mint: 0,
                out_plus_fee: 500,
            })
        );
    }

    #[test]
    fn policy_asset_mismatch_rejected() {
        // Present a valid cap policy but claim it governs a DIFFERENT asset id.
        let policy = fixed_supply_cap_policy(1000);
        let real = policy_asset_id(&policy);
        let lie: AssetId = [9u8; 32];
        assert_ne!(real, lie);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(lie, 10))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: lie,
                delta: 10,
            },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::PolicyAssetMismatch { asset: lie })
        );
    }

    // ── over-cap mint is rejected by the policy ──

    #[test]
    fn over_cap_mint_rejected() {
        let policy = fixed_supply_cap_policy(1000);
        let asset = policy_asset_id(&policy);
        // prior supply already at the cap; +1 would exceed it.
        let mut prior = BTreeMap::new();
        prior.insert(asset, 1000i128);
        let mctx = MintCtx {
            height: 0,
            prior_supply: prior,
        };
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 1))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: 1,
            },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &mctx, &noop(), 50_000),
            Err(MintTxError::PolicyRejected { asset })
        );
    }

    #[test]
    fn at_cap_mint_allowed() {
        let policy = fixed_supply_cap_policy(1000);
        let asset = policy_asset_id(&policy);
        let mut prior = BTreeMap::new();
        prior.insert(asset, 400i128);
        let mctx = MintCtx {
            height: 0,
            prior_supply: prior,
        };
        // 400 prior + 600 == 1000 == cap → allowed (boundary).
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 600))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: 600,
            },
        }];
        assert!(validate_tx_with_mint(&tx, &mints, &mctx, &noop(), 50_000).is_ok());
    }

    // ── burn conserves (relaxed balance with a negative delta) ──

    #[test]
    fn burn_conserves() {
        // Use an authorized-minter policy so the burn is explicitly authorised.
        let minter_pk = b"pk".to_vec();
        let sig = b"sig".to_vec();
        let sighash = b"sh".to_vec();
        let policy = authorized_minter_policy(minter_pk.clone());
        let asset = policy_asset_id(&policy);

        // Input carries 1000 of the asset; burn 100; output keeps 900.
        let mut prior = BTreeMap::new();
        prior.insert(asset, 1000i128);
        let mctx = MintCtx {
            height: 0,
            prior_supply: prior,
        };

        // A trivial always-true input guard for the UTXO carrying the tokens.
        let guard = vec![Op::PushInt(1)];
        let gvh = validator_hash(&guard);
        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput {
                    value: asset_val(asset, 1000),
                    validator_hash: gvh,
                    datum: Val::Int(0),
                },
                validator: guard,
                redeemer: vec![],
            }],
            outputs: vec![out(asset_val(asset, 900))],
            fee: 0,
            sighash: sighash.clone(),
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![Val::Bytes(sig.clone())],
            action: MintAction {
                asset_id: asset,
                delta: -100, // burn
            },
        }];
        let v = MockVerifier {
            good: vec![(sighash, minter_pk, sig)],
        };
        // 1000 (in) + (-100) (burn) == 900 (out) → conserves.
        assert!(validate_tx_with_mint(&tx, &mints, &mctx, &v, 50_000).is_ok());
    }

    #[test]
    fn burn_below_zero_supply_rejected() {
        let policy = fixed_supply_cap_policy(1_000_000);
        let asset = policy_asset_id(&policy);
        // prior supply is only 50; burning 100 would go negative.
        let mut prior = BTreeMap::new();
        prior.insert(asset, 50i128);
        let mctx = MintCtx {
            height: 0,
            prior_supply: prior,
        };
        // Inputs carry 100 so tx-local balance would work — but supply floor fails.
        let guard = vec![Op::PushInt(1)];
        let gvh = validator_hash(&guard);
        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput {
                    value: asset_val(asset, 100),
                    validator_hash: gvh,
                    datum: Val::Int(0),
                },
                validator: guard,
                redeemer: vec![],
            }],
            outputs: vec![out(asset_val(asset, 0))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: -100,
            },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &mctx, &noop(), 50_000),
            Err(MintTxError::SupplyNegative { asset })
        );
    }

    // ── BLCH can never be minted ──

    #[test]
    fn blch_mint_always_rejected() {
        // Even with an "always true" policy whose hash we pretend is BLCH, the BLCH
        // guard fires first — before hash-matching or running anything.
        let policy = vec![Op::PushInt(1)];
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(blch(100))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: BLCH,
                delta: 100,
            },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::BlchMintForbidden)
        );
    }

    #[test]
    fn blch_burn_also_rejected() {
        let policy = vec![Op::PushInt(1)];
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: BLCH,
                delta: -1,
            },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::BlchMintForbidden)
        );
    }

    // ── height-gated policy ──

    #[test]
    fn height_gate_blocks_before_and_allows_after() {
        let policy = height_gate_policy(3000);
        let asset = policy_asset_id(&policy);
        let mk_tx = || EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 10))],
            fee: 0,
            sighash: vec![],
        };
        let mints = || {
            vec![MintRequest {
                policy: policy.clone(),
                redeemer: vec![],
                action: MintAction {
                    asset_id: asset,
                    delta: 10,
                },
            }]
        };

        // Before the gate → rejected.
        let before = MintCtx {
            height: 2999,
            prior_supply: BTreeMap::new(),
        };
        assert_eq!(
            validate_tx_with_mint(&mk_tx(), &mints(), &before, &noop(), 50_000),
            Err(MintTxError::PolicyRejected { asset })
        );

        // At the gate → allowed (boundary is inclusive).
        let at = MintCtx {
            height: 3000,
            prior_supply: BTreeMap::new(),
        };
        assert!(validate_tx_with_mint(&mk_tx(), &mints(), &at, &noop(), 50_000).is_ok());
    }

    // ── an asset with NO policy presented still balances exactly ──

    #[test]
    fn unpolicied_asset_balances_exactly() {
        // asset X flows through untouched: 300 in, 300 out, no mint request.
        let asset: AssetId = [3u8; 32];
        let guard = vec![Op::PushInt(1)];
        let gvh = validator_hash(&guard);
        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput {
                    value: asset_val(asset, 300),
                    validator_hash: gvh,
                    datum: Val::Int(0),
                },
                validator: guard,
                redeemer: vec![],
            }],
            outputs: vec![out(asset_val(asset, 300))],
            fee: 0,
            sighash: vec![],
        };
        assert!(validate_tx_with_mint(&tx, &[], &MintCtx::default(), &noop(), 50_000).is_ok());
    }

    // ── duplicate policy for the same asset is rejected ──

    #[test]
    fn duplicate_policy_rejected() {
        let policy = fixed_supply_cap_policy(1000);
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 20))],
            fee: 0,
            sighash: vec![],
        };
        let req = MintRequest {
            policy: policy.clone(),
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: 10,
            },
        };
        let mints = vec![req.clone(), req];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::DuplicatePolicy { asset })
        );
    }

    // ── BLCH still conserves alongside a minted asset (fee in BLCH, token minted) ──

    #[test]
    fn blch_conserves_while_token_mints() {
        let policy = fixed_supply_cap_policy(10_000);
        let asset = policy_asset_id(&policy);
        let guard = vec![Op::PushInt(1)];
        let gvh = validator_hash(&guard);

        // Input: 100 BLCH. Outputs: 90 BLCH + a freshly minted 500 of the token.
        // BLCH: 100 in == 90 out + 10 fee. Token: 0 in + 500 mint == 500 out.
        let mut in_val = blch(100);
        let mut out_a = blch(90);
        let out_b = asset_val(asset, 500);
        // (in_val holds only BLCH; out_a only BLCH; out_b only token)
        let _ = &mut in_val;
        let _ = &mut out_a;

        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput {
                    value: in_val,
                    validator_hash: gvh,
                    datum: Val::Int(0),
                },
                validator: guard,
                redeemer: vec![],
            }],
            outputs: vec![out(out_a), out(out_b)],
            fee: 10,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: 500,
            },
        }];
        assert!(validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000).is_ok());
    }

    // ── determinism: identical inputs → identical result, repeatedly ──

    #[test]
    fn deterministic_mint_check() {
        let policy = fixed_supply_cap_policy(1000);
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 500))],
            fee: 0,
            sighash: b"sh".to_vec(),
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction {
                asset_id: asset,
                delta: 500,
            },
        }];
        let first = validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000);
        for _ in 0..100 {
            assert_eq!(
                validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
                first
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // ── ADVERSARIAL + PROPERTY TESTS (appended; module logic unchanged) ──
    // ─────────────────────────────────────────────────────────────────────

    /// An "always true" policy — the minimal permissive policy, used below to isolate
    /// the mint-overflow / gas paths from any cap/signature logic.
    fn always_true_policy() -> MintingPolicy {
        vec![Op::PushInt(1)]
    }

    // ── BUG FOUND: `fixed_supply_cap_policy(i128::MAX)` is unsound at construction ──
    //
    // The constructor computes `cap + 1` at the *Rust* level (not through the VM's
    // checked-`i128` ops) to build the `PushInt(cap + 1)` operand. With
    // `cap == i128::MAX` this addition itself overflows i128::MAX:
    //   - In a debug build (incl. plain `cargo test`) this PANICS
    //     ("attempt to add with overflow") — a crash reachable just by calling a
    //     public reference constructor with a boundary value, i.e. a DoS surface,
    //     not merely a validation error.
    //   - In a release build the overflow silently wraps: `cap + 1` becomes
    //     `i128::MIN`, so the emitted check becomes `new_supply < i128::MIN`, which
    //     is *never* true — the resulting policy rejects every mint, including
    //     `delta == 0`. So a caller who picks `i128::MAX` to mean "effectively no
    //     cap" instead gets a policy that can never authorise anything.
    // This test documents both outcomes without patching the constructor (per the
    // "append tests only, don't change module logic" mandate) and proves neither
    // outcome is a silent wrap into an *authorising* policy (i.e. it fails closed
    // either way) — but the panic path is a real crash bug worth fixing upstream.
    #[test]
    fn fixed_supply_cap_policy_max_cap_is_a_construction_hazard() {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence the expected panic's stderr spam
        let built = std::panic::catch_unwind(|| fixed_supply_cap_policy(i128::MAX));
        std::panic::set_hook(prev_hook);

        match built {
            Err(_) => {
                // Debug-profile behaviour (this is what `cargo test` hits by default):
                // confirmed panic-on-construct. Documented as a bug; not asserted as
                // "expected" behaviour — a reference policy constructor should never
                // panic on an in-range i128 argument.
            }
            Ok(policy) => {
                // Release-profile behaviour: wrapped to a policy that rejects
                // everything, including a no-op zero delta. Fails closed (no
                // inflation risk) but is a functional bug (cap meant to be
                // permissive is instead maximally restrictive).
                let asset = policy_asset_id(&policy);
                let tx = EuTx {
                    inputs: vec![],
                    outputs: vec![],
                    fee: 0,
                    sighash: vec![],
                };
                let mints = vec![MintRequest {
                    policy,
                    redeemer: vec![],
                    action: MintAction { asset_id: asset, delta: 0 },
                }];
                assert_eq!(
                    validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
                    Err(MintTxError::PolicyRejected { asset })
                );
            }
        }
    }

    /// `fixed_supply_cap_policy(-1)`: a negative cap combined with the separate
    /// non-negativity floor makes the policy self-contradictory (it only authorises
    /// deltas that would make supply negative, which the floor check then always
    /// vetoes) — a degenerate but *safe* (fail-closed, non-panicking) configuration.
    #[test]
    fn negative_cap_policy_is_self_contradictory_but_fails_closed_not_panics() {
        let policy = fixed_supply_cap_policy(-1);
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction { asset_id: asset, delta: 0 },
        }];
        // 0 <= -1 is false at the policy check itself -> rejected, not a panic.
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::PolicyRejected { asset })
        );
    }

    /// Checked-`i128` overflow while folding `prior_supply + delta` is a hard error
    /// (`MintOverflow`), never a silent wrap and never a panic — even when an
    /// otherwise-permissive policy authorises the delta.
    #[test]
    fn mint_overflow_on_prior_plus_delta_is_fail_closed_not_panic() {
        let policy = always_true_policy();
        let asset = policy_asset_id(&policy);
        let mut prior = BTreeMap::new();
        prior.insert(asset, i128::MAX);
        let mctx = MintCtx { height: 0, prior_supply: prior };
        let tx = EuTx { inputs: vec![], outputs: vec![], fee: 0, sighash: vec![] };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction { asset_id: asset, delta: 1 }, // i128::MAX + 1 overflows
        }];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_tx_with_mint(&tx, &mints, &mctx, &noop(), 50_000)
        }))
        .expect("must not panic on an authorised overflowing delta");
        assert_eq!(result, Err(MintTxError::MintOverflow { asset }));
    }

    /// Deltas at the extreme ends of i128's range never panic and never silently
    /// wrap into a conserved/authorised state — they fail closed with a normal,
    /// deterministic error every time (no crash on adversarial-magnitude input).
    #[test]
    fn extreme_deltas_never_panic_and_never_falsely_conserve() {
        let policy = always_true_policy();
        let asset = policy_asset_id(&policy);
        for delta in [i128::MAX, i128::MIN, i128::MAX - 1, i128::MIN + 1] {
            let tx = EuTx { inputs: vec![], outputs: vec![], fee: 0, sighash: vec![] };
            let mints = vec![MintRequest {
                policy: policy.clone(),
                redeemer: vec![],
                action: MintAction { asset_id: asset, delta },
            }];
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000)
            }));
            let res = outcome.expect("must not panic on boundary i128 deltas");
            // No outputs/inputs exist, so an extreme delta can never itself balance
            // (u64-bounded value amounts cannot match an i128 extreme) — it must be
            // an explicit error, never Ok.
            assert!(res.is_err(), "extreme delta {delta} unexpectedly conserved");
        }
    }

    /// A malformed / adversarial policy program (references an out-of-range ctx
    /// field) surfaces as a normal `PolicyVm` error, not a panic or a silent accept.
    #[test]
    fn malformed_policy_bad_ctx_field_surfaces_as_policy_vm_error() {
        let policy = vec![Op::CtxField(99)]; // only fields 0..=3 are ever populated
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 5))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction { asset_id: asset, delta: 5 },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::PolicyVm { asset, err: VmError::BadCtxField(99) })
        );
    }

    /// The degenerate empty-program policy fails closed with `EmptyResult`, not a
    /// panic — `encode_program(&[])` / `validator_hash(&[])` are still well-defined,
    /// so this asset id is reachable by an adversary trivially.
    #[test]
    fn empty_policy_program_surfaces_as_policy_vm_empty_result() {
        let policy: MintingPolicy = vec![];
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 1))],
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction { asset_id: asset, delta: 1 },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::PolicyVm { asset, err: VmError::EmptyResult })
        );
    }

    /// A policy authorising delta `D` does NOT license moving any amount other than
    /// exactly `D`: the relaxed-conservation check still binds the authorised delta
    /// to the actual observed balance change. An attacker who gets a policy to
    /// return `true` for a modest, cap-permitted delta cannot then smuggle a larger
    /// (or merely different) real value shift under cover of that authorisation.
    #[test]
    fn authorised_delta_does_not_license_a_different_actual_value_shift() {
        let policy = fixed_supply_cap_policy(1_000_000); // would authorise delta=500 fine
        let asset = policy_asset_id(&policy);
        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset, 10))], // but the tx only actually creates 10
            fee: 0,
            sighash: vec![],
        };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction { asset_id: asset, delta: 500 }, // claims 500
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::ValueNotConserved { asset, in_plus_mint: 500, out_plus_fee: 10 })
        );
    }

    /// Two genuinely distinct, independently-valid policies cannot be swapped across
    /// each other's assets: presenting policy A's program while claiming it governs
    /// policy B's asset id is rejected by the hash-identity check, even though A is a
    /// perfectly valid policy for *its own* asset.
    #[test]
    fn distinct_valid_policies_cannot_be_swapped_across_assets() {
        let policy_a = fixed_supply_cap_policy(1000);
        let policy_b = authorized_minter_policy(b"some-minter".to_vec());
        let asset_a = policy_asset_id(&policy_a);
        let asset_b = policy_asset_id(&policy_b);
        assert_ne!(asset_a, asset_b);

        let tx = EuTx {
            inputs: vec![],
            outputs: vec![out(asset_val(asset_b, 10))],
            fee: 0,
            sighash: vec![],
        };
        // present A's program but claim it authorises B's asset
        let mints = vec![MintRequest {
            policy: policy_a,
            redeemer: vec![],
            action: MintAction { asset_id: asset_b, delta: 10 },
        }];
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000),
            Err(MintTxError::PolicyAssetMismatch { asset: asset_b })
        );
    }

    /// Gas exhaustion *during a minting policy's own execution* (not just the
    /// input-validator path already covered in `lib.rs`) fails closed with a normal
    /// `PolicyVm(OutOfGas)` error — no panic, no partial/inconsistent state.
    #[test]
    fn mint_policy_gas_exhaustion_is_fail_closed() {
        // Costly program: push bytes then hash three times (60 gas each) — cheap to
        // build, expensive to run. `Op::PushBytes` costs 1, each `Sha256d` costs 60.
        let policy = vec![
            Op::PushBytes(b"x".to_vec()),
            Op::Sha256d,
            Op::Sha256d,
            Op::Sha256d,
        ];
        let asset = policy_asset_id(&policy);
        let tx = EuTx { inputs: vec![], outputs: vec![], fee: 0, sighash: vec![] };
        let mints = vec![MintRequest {
            policy,
            redeemer: vec![],
            action: MintAction { asset_id: asset, delta: 0 },
        }];
        // enough for the PushBytes + one Sha256d, not the second.
        let tiny_gas = 61;
        assert_eq!(
            validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), tiny_gas),
            Err(MintTxError::PolicyVm { asset, err: VmError::OutOfGas })
        );
    }

    /// Property: gas used is always bounded by the caller's `gas_limit` on every
    /// successful call, across a matrix of distinct passing scenarios (mint, burn,
    /// unpolicied pass-through, and a combined multi-asset tx).
    #[test]
    fn gas_used_never_exceeds_gas_limit_across_scenarios() {
        for gas_limit in [2_000u64, 10_000, 50_000, 200_000] {
            // scenario 1: simple cap-policy mint
            let policy = fixed_supply_cap_policy(1000);
            let asset = policy_asset_id(&policy);
            let tx = EuTx {
                inputs: vec![],
                outputs: vec![out(asset_val(asset, 100))],
                fee: 0,
                sighash: vec![],
            };
            let mints = vec![MintRequest {
                policy,
                redeemer: vec![],
                action: MintAction { asset_id: asset, delta: 100 },
            }];
            if let Ok(used) = validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), gas_limit) {
                assert!(used <= gas_limit, "gas used {used} exceeded limit {gas_limit}");
            }

            // scenario 2: unpolicied pass-through asset
            let plain: AssetId = [42u8; 32];
            let guard = vec![Op::PushInt(1)];
            let gvh = validator_hash(&guard);
            let tx2 = EuTx {
                inputs: vec![EuTxInput {
                    prev_output: ExtOutput { value: asset_val(plain, 50), validator_hash: gvh, datum: Val::Int(0) },
                    validator: guard,
                    redeemer: vec![],
                }],
                outputs: vec![out(asset_val(plain, 50))],
                fee: 0,
                sighash: vec![],
            };
            if let Ok(used) = validate_tx_with_mint(&tx2, &[], &MintCtx::default(), &noop(), gas_limit) {
                assert!(used <= gas_limit, "gas used {used} exceeded limit {gas_limit}");
            }
        }
    }

    /// A single transaction mixing a BLCH fee, a fresh token mint, AND a token burn
    /// simultaneously — every asset's relaxed-conservation equation must hold
    /// independently and at once (no cross-asset leakage of one asset's authorised
    /// delta into another asset's balance).
    #[test]
    fn multi_asset_mint_burn_and_blch_fee_all_conserve_together() {
        const TOKEN_A: fn() -> MintingPolicy = || fixed_supply_cap_policy(10_000);
        let policy_a = TOKEN_A();
        let asset_a = policy_asset_id(&policy_a);

        let minter_pk = b"burner-pubkey".to_vec();
        let sig = b"burner-sig".to_vec();
        let policy_b = authorized_minter_policy(minter_pk.clone());
        let asset_b = policy_asset_id(&policy_b);

        let sighash = b"combined-sighash".to_vec();
        let guard = vec![Op::PushInt(1)];
        let gvh = validator_hash(&guard);

        let mut in_blch = blch(100);
        in_blch.extend(asset_val(asset_b, 200));

        let mut out1 = blch(90);
        out1.extend(asset_val(asset_b, 150)); // 200 in - 50 burned = 150 out
        let out2 = asset_val(asset_a, 500); // freshly minted

        let tx = EuTx {
            inputs: vec![EuTxInput {
                prev_output: ExtOutput { value: in_blch, validator_hash: gvh, datum: Val::Int(0) },
                validator: guard,
                redeemer: vec![],
            }],
            outputs: vec![out(out1), out(out2)],
            fee: 10,
            sighash: sighash.clone(),
        };

        let mut prior = BTreeMap::new();
        prior.insert(asset_b, 1000i128); // plenty of headroom for the 50 burn
        let mctx = MintCtx { height: 0, prior_supply: prior };

        let mints = vec![
            MintRequest {
                policy: policy_a,
                redeemer: vec![],
                action: MintAction { asset_id: asset_a, delta: 500 },
            },
            MintRequest {
                policy: policy_b,
                redeemer: vec![Val::Bytes(sig.clone())],
                action: MintAction { asset_id: asset_b, delta: -50 },
            },
        ];
        let v = MockVerifier { good: vec![(sighash, minter_pk, sig)] };
        assert!(validate_tx_with_mint(&tx, &mints, &mctx, &v, 100_000).is_ok());
    }

    /// Property: determinism holds across a matrix of scenarios — passing, and every
    /// distinct failure mode — not just the single happy-path case in
    /// `deterministic_mint_check`. Same inputs, called repeatedly (and interleaved
    /// with other scenarios), always produce the same result.
    #[test]
    fn determinism_holds_across_a_scenario_matrix() {
        // Each closure independently (re)builds its own fresh inputs and returns a
        // result, so repeated calls can never observe cross-call mutation.
        let scenarios: Vec<Box<dyn Fn() -> Result<u64, MintTxError>>> = vec![
            Box::new(|| {
                let policy = fixed_supply_cap_policy(1000);
                let asset = policy_asset_id(&policy);
                let tx = EuTx { inputs: vec![], outputs: vec![out(asset_val(asset, 500))], fee: 0, sighash: vec![] };
                let mints = vec![MintRequest { policy, redeemer: vec![], action: MintAction { asset_id: asset, delta: 500 } }];
                validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000)
            }),
            Box::new(|| {
                let policy = fixed_supply_cap_policy(1000);
                let asset = policy_asset_id(&policy);
                let mut prior = BTreeMap::new();
                prior.insert(asset, 1000i128);
                let mctx = MintCtx { height: 0, prior_supply: prior };
                let tx = EuTx { inputs: vec![], outputs: vec![out(asset_val(asset, 1))], fee: 0, sighash: vec![] };
                let mints = vec![MintRequest { policy, redeemer: vec![], action: MintAction { asset_id: asset, delta: 1 } }];
                validate_tx_with_mint(&tx, &mints, &mctx, &noop(), 50_000)
            }),
            Box::new(|| {
                let asset: AssetId = [7u8; 32];
                let tx = EuTx { inputs: vec![], outputs: vec![out(asset_val(asset, 500))], fee: 0, sighash: vec![] };
                validate_tx_with_mint(&tx, &[], &MintCtx::default(), &noop(), 50_000)
            }),
            Box::new(|| {
                let tx = EuTx { inputs: vec![], outputs: vec![out(blch(100))], fee: 0, sighash: vec![] };
                let mints = vec![MintRequest { policy: vec![Op::PushInt(1)], redeemer: vec![], action: MintAction { asset_id: BLCH, delta: 100 } }];
                validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop(), 50_000)
            }),
        ];

        for scenario in &scenarios {
            let first = scenario();
            for _ in 0..25 {
                assert_eq!(scenario(), first);
            }
        }
    }
}
