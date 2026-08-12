//! Adversarial audit — lens: Module-compiler bypass (modules.rs), Supply-cap defect.
//! Separate file so it does not touch src/ or another auditor's `audit_modules.rs`.
//!
//! FINDING (HIGH) — **FIXED 2026-08-11.** This file proved the defect; it now pins
//! the fix. The attack below is byte-for-byte what it was; only the expected result
//! changed, because rewriting the attack would discard the only evidence of what the
//! hole was. Original finding, kept verbatim:
//!
//! `ModuleKind::Supply` compiles a validator whose `cap` gate
//! compares a *redeemer-supplied* `requested` value to `cap` — a value with NO
//! binding to the actual amount minted. When that program is used as the token's
//! minting policy (which the module docs mandate: "its hash IS the token's
//! AssetId / policy id", and `CompiledToken::policy_id()` returns exactly this
//! hash), the real mint delta lives in `ctx.fields[MINT_CTX_DELTA]` and the
//! on-chain prior supply in `ctx.fields[MINT_CTX_PRIOR_SUPPLY]` — NEITHER of
//! which the compiled Supply program ever reads. Result: the advertised fixed
//! cap is unenforced; an authorized issuer can mint an unbounded amount past `cap`.

use bloch_euvm::minting::{
    fixed_supply_cap_policy, policy_asset_id, validate_tx_with_mint, MintAction, MintCtx,
    MintRequest, MintTxError,
};
use bloch_euvm::modules::{ModuleKind, SupplyConfig};
use bloch_euvm::{AssetId, EuTx, ExtOutput, SigVerifier, Val, Value};

struct MockVerifier {
    good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}
impl SigVerifier for MockVerifier {
    fn verify(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
        self.good.iter().any(|(m, p, s)| m == msg && p == pk && s == sig)
    }
}

fn asset_val(asset: AssetId, n: u64) -> Value {
    let mut v = Value::new();
    v.insert(asset, n);
    v
}
fn out(value: Value) -> ExtOutput {
    ExtOutput { value, validator_hash: [0u8; 32], datum: Val::Int(0) }
}

/// The historical attack, refused. With cap = 1_000 an authorized issuer used to mint
/// 1_000_000_000 in one shot — 1e6x the cap — by seeding a `requested` value in the
/// redeemer that nothing bound to the real delta.
///
/// The emitter now reads `MINT_CTX_PRIOR_SUPPLY` and `MINT_CTX_DELTA`, so the gate is
/// over TOTAL supply and the spender has no input to it. Note what *else* changed:
/// the advertised property moved from "maximum per single mint spend" to "fixed
/// maximum supply". A per-spend cap was never a supply cap — an issuer could always
/// mint the cap again next block — so the doc claim and the code are now the same
/// claim, which is the deeper repair.
#[test]
fn supply_module_cap_is_enforced_over_total_supply() {
    let issuer = b"issuer-pk".to_vec();
    let sig = b"issuer-sig".to_vec();
    let sighash = b"the-sighash".to_vec();

    // The token's Supply module — cap is advertised as 1_000.
    let supply_program = ModuleKind::Supply(SupplyConfig {
        cap: 1_000,
        issuer_pubkey: issuer.clone(),
    })
    .compile();

    // Per the module contract, the Supply program's hash IS the asset id / policy id.
    let asset = policy_asset_id(&supply_program);

    // Mint ONE MILLION TIMES the cap in a single transaction.
    let minted: u64 = 1_000_000_000;
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![out(asset_val(asset, minted))],
        fee: 0,
        sighash: sighash.clone(),
    };

    // THE ATTACK, unchanged: seed the policy stack `[requested, sig]` with
    // requested = 0, a value completely disconnected from `minted`/the delta.
    let mints = vec![MintRequest {
        policy: supply_program.clone(),
        redeemer: vec![Val::Int(0), Val::Bytes(sig.clone())],
        action: MintAction { asset_id: asset, delta: minted as i128 },
    }];

    let v = MockVerifier { good: vec![(sighash, issuer, sig.clone())] };

    // The over-cap mint is now REFUSED. (`Assert` and not a quiet `false`: an
    // over-cap mint is malformed, not merely unauthorized.)
    let res = validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &v, 100_000);
    assert!(
        res.is_err(),
        "REGRESSION: the Supply module authorized an over-cap mint again (1e9 vs cap \
         1e3) — the gate stopped reading MINT_CTX_DELTA/MINT_CTX_PRIOR_SUPPLY; got {res:?}"
    );

    // The refusal must be the CAP, not merely the arity pin tripping on the stale
    // redeemer shape. Same mint with the honest seed `[sig]` — still refused.
    let honest = vec![MintRequest {
        policy: supply_program.clone(),
        redeemer: vec![Val::Bytes(sig.clone())],
        action: MintAction { asset_id: asset, delta: minted as i128 },
    }];
    assert!(
        validate_tx_with_mint(&tx, &honest, &MintCtx::default(), &v, 100_000).is_err(),
        "the cap must refuse an over-cap delta even with a well-formed redeemer"
    );

    // And a within-cap mint by the same issuer still succeeds, so the fix did not
    // simply break the module. Without this, both assertions above would pass on a
    // Supply program that authorizes nothing at all.
    let small: u64 = 900;
    let ok_tx = EuTx {
        inputs: vec![],
        outputs: vec![out(asset_val(asset, small))],
        fee: 0,
        sighash: b"the-sighash".to_vec(),
    };
    let ok_mints = vec![MintRequest {
        policy: supply_program,
        redeemer: vec![Val::Bytes(sig)],
        action: MintAction { asset_id: asset, delta: small as i128 },
    }];
    assert!(
        validate_tx_with_mint(&ok_tx, &ok_mints, &MintCtx::default(), &v, 100_000).is_ok(),
        "a within-cap mint by the authorized issuer must still be allowed"
    );
}

/// Contrast: minting.rs's OWN `fixed_supply_cap_policy` — which correctly reads
/// MINT_CTX_PRIOR_SUPPLY + MINT_CTX_DELTA — DOES reject the same over-cap mint.
/// This isolates the defect to the modules.rs Supply emitter, not the mint machinery.
#[test]
fn contrast_correct_cap_policy_rejects_the_same_over_cap_mint() {
    let correct = fixed_supply_cap_policy(1_000);
    let asset = policy_asset_id(&correct);
    let minted: u64 = 1_000_000_000;
    let tx = EuTx {
        inputs: vec![],
        outputs: vec![out(asset_val(asset, minted))],
        fee: 0,
        sighash: b"sh".to_vec(),
    };
    let mints = vec![MintRequest {
        policy: correct,
        redeemer: vec![],
        action: MintAction { asset_id: asset, delta: minted as i128 },
    }];
    let noop = MockVerifier { good: vec![] };
    assert_eq!(
        validate_tx_with_mint(&tx, &mints, &MintCtx::default(), &noop, 100_000),
        Err(MintTxError::PolicyRejected { asset }),
        "the correct cap policy must reject an over-cap mint"
    );
}
