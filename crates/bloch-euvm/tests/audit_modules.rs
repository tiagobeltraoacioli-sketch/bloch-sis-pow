//! AUDIT (lens: module-compiler bypass) — adversarial integration tests against the
//! Ustav module compiler (`crates/bloch-euvm/src/modules.rs`). Separate test file; does
//! not touch src/ or other auditors' tests.

use bloch_euvm::modules::{
    compile_charter, ModuleKind, TokenCharter, TransferPolicyConfig, FIELD_SIGHASH,
};
use bloch_euvm::{blch, spend, Ctx, ExtOutput, SigVerifier, Val, VmError};

const MSG: &[u8] = b"ustav-sighash";

/// A verifier that NEVER accepts any PQ signature (the attacker holds no authority key)
/// and never accepts any ECDSA signature either.
struct DenyAll;
impl SigVerifier for DenyAll {
    fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
    fn verify_ecdsa(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
        false
    }
}

fn ctx() -> Ctx {
    Ctx {
        fields: vec![Val::Bytes(MSG.to_vec())], // FIELD_SIGHASH = 0
        ..Default::default()
    }
}

/// **CRITICAL — TransferPolicy freeze bypass via redeemer padding. FIXED 2026-08-11.**
///
/// This test proved the defect; it now pins the fix. The assertion was inverted
/// (`Ok(true)` -> `Err(Assert)`) and nothing else about the attack was softened —
/// the same frozen output, the same padded redeemer, the same verifier that accepts
/// no signature. A test that proved a hole is the right place to prove it stays shut,
/// and rewriting the attack would have thrown away the only evidence of what the
/// hole was.
///
/// The fix is `Op::ExpectDepth`, emitted as the first op of every compiled module:
/// the seed arity a validator was compiled for is now part of its program, hence
/// part of its `validator_hash`, and cannot be renegotiated by the spender.
///
/// `compile_transfer_policy` reads the `frozen` flag (the OUTPUT's datum, which the
/// output-creator committed to) from the stack via a *fixed, top-relative* `Pick(2)`.
/// The emitted program assumes the exact redeemer arity `[sig]` (stack `[frozen, sig]`).
/// But `spend()` / `run()` impose NO redeemer-length check: the spender seeds the stack
/// with `[datum] ++ redeemer` for ANY redeemer they choose. By padding the redeemer with
/// one extra leading value, every top-relative `Pick` offset shifts by one, so the
/// program's "read frozen" `Pick(2)` no longer reads the datum — it reads an
/// ATTACKER-CONTROLLED redeemer slot. Setting that slot to `Int(0)` makes the validator
/// believe the output is NOT frozen, so it allows the spend of a FROZEN output with NO
/// authority signature. The regulated-token freeze/allow control is fully defeated.
#[test]
fn transfer_policy_freeze_is_bypassed_by_padding_the_redeemer() {
    let cm = &compile_charter(&TokenCharter {
        token_name: b"REG".to_vec(),
        modules: vec![ModuleKind::TransferPolicy(TransferPolicyConfig {
            authority_pubkey: b"authority-pk".to_vec(),
        })],
    })
    .validators[0];

    // The output is FROZEN (datum == 1). Honest spend of a frozen output REQUIRES the
    // transfer authority's signature; the attacker has none.
    let frozen_output = ExtOutput {
        value: blch(1_000),
        validator_hash: cm.validator_hash,
        datum: Val::Int(1), // frozen
    };

    // Sanity: the honest redeemer `[sig]` on a frozen output with no authority sig is
    // correctly DENIED (Ok(false)).
    let mut g = 100_000;
    let honest = spend(
        &frozen_output,
        &cm.program,
        vec![Val::Bytes(b"not-the-authority-sig".to_vec())],
        &ctx(),
        &DenyAll,
        &mut g,
    );
    assert_eq!(honest, Ok(false), "control: honest frozen spend must be denied");

    // THE ATTACK, unchanged: pad the redeemer with a leading Int(0). This used to
    // shift the fixed Pick offsets so the "read frozen" Pick landed on this
    // attacker-supplied 0 instead of the real datum, making `not_frozen == 1` and
    // allowing the spend WITHOUT any authority signature.
    let mut g2 = 100_000;
    let bypass = spend(
        &frozen_output,
        &cm.program,
        vec![Val::Int(0), Val::Bytes(b"anything".to_vec())],
        &ctx(),
        &DenyAll,
        &mut g2,
    );

    assert_eq!(
        bypass,
        Err(VmError::Assert),
        "REGRESSION: the padded redeemer was accepted again — the arity pin is gone \
         or an emitter stopped leading with Op::ExpectDepth, and the freeze control \
         is defeated once more"
    );

    // And the pin is not a blanket ban on the value that was used to pad: the honest
    // arity still runs, so the fix costs no legitimate spend. Without this second
    // assertion the test above would also pass if the module had simply been broken.
    let mut g3 = 100_000;
    let honest_unfrozen = spend(
        &ExtOutput { value: blch(1_000), validator_hash: cm.validator_hash, datum: Val::Int(0) },
        &cm.program,
        vec![Val::Bytes(b"any".to_vec())],
        &ctx(),
        &DenyAll,
        &mut g3,
    );
    assert_eq!(honest_unfrozen, Ok(true), "an unfrozen output must still be spendable");
    let _ = FIELD_SIGHASH;
}
