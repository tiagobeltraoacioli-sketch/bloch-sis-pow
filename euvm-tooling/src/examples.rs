//! examples — the worked validator gallery (the eUVM "cookbook").
//!
//! Ready-made, tested reference programs plus end-to-end demos that each run **green
//! through the [`crate::sim`] simulator** — accepting on a valid witness and rejecting
//! on an invalid one. Every program is returned as a plain `Vec<`[`euvm::Op`]`>` so it
//! drops straight into an [`euvm::ExtOutput`]'s `validator_hash`, an
//! [`euvm::EuTxInput`]'s `validator`, or a [`crate::tx`] builder.
//!
//! The three headline contracts this component owns:
//!  1. **N-of-M multisig** — [`multisig_n_of_m`] (count verifying sigs, gate on a threshold).
//!  2. **Time-locks** — [`absolute_timelock`] (height ≥ unlock) and [`relative_timelock`]
//!     (age = height − creation ≥ min_age, the creation height carried in the datum).
//!  3. **A minimal Ustav token-charter** — [`minimal_ustav_charter`] /
//!     [`compile_minimal_ustav_charter`], compiled to a validator set via
//!     `euvm::modules::compile_charter`, with a runnable demo of its Supply (mint) guard.
//!
//! The gallery also ports the foundation reference validators (P2PKH, hash-lock,
//! continuation counter, constant-product AMM) into public builder functions.
//!
//! ## Ctx field convention (shared with `euvm::modules`)
//! Auth/stateful validators read fixed `ctx.fields` slots:
//! `fields[FIELD_SIGHASH=0]` = the tx sighash (Bytes); `fields[FIELD_HEIGHT=1]` = the
//! current block height (Int). A host running these validators must populate them so.

use crate::euvm::{blch, validator_hash, AssetId, Ctx, ExtOutput, Op, Val, Value};
use crate::euvm::modules::{
    self, CompiledToken, FIELD_HEIGHT, FIELD_SIGHASH, GovernanceConfig, ModuleKind, SupplyConfig,
    TokenCharter,
};
use crate::sim::{self, SimResult};

use sha2::{Digest, Sha256};

/// SHA-256d (double SHA-256) — matches the VM's [`euvm::Op::Sha256d`] and the
/// `validator_hash` preimage convention. Used by demos to derive pubkey-hashes and
/// hash-lock commitments.
fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(Sha256::digest(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// (1) N-of-M multisig
// ─────────────────────────────────────────────────────────────────────────────

/// **N-of-M multisig validator.** The `M` member public keys are baked into the
/// program (order is significant: redeemer signature slot `i` is checked against
/// `signer_pubkeys[i]`); `threshold` is the `N` signatures that must verify.
///
/// **Stack seed:** `[sig_0, sig_1, … sig_{M-1}]` — one signature slot per member, in
/// member order, supplied by the redeemer. A member that did not sign still occupies a
/// slot (fill it with any non-verifying placeholder bytes, exactly like Bitcoin's
/// `OP_CHECKMULTISIG` dummies). The signed message is read from `ctx.fields[FIELD_SIGHASH]`.
///
/// Finishes with a single truthy/falsy `Int`: `count(verifying sigs) >= threshold`.
///
/// **Fail-closed:** a degenerate configuration that could silently mis-gate a quorum
/// (a nonzero-signer `threshold == 0`, duplicate member keys, or `M > 253` — beyond
/// which the first slot's `Pick` depth truncates in the `u8` cast) compiles to the
/// unspendable sentinel `[PushInt(0)]`, which authorizes no spend. Mirrors the
/// `euvm::modules` Governance emitter.
pub fn multisig_n_of_m(signer_pubkeys: &[Vec<u8>], threshold: u32) -> Vec<Op> {
    let m = signer_pubkeys.len();

    let has_dup_signer = {
        let mut seen = std::collections::BTreeSet::new();
        signer_pubkeys.iter().any(|pk| !seen.insert(pk.as_slice()))
    };
    if (m != 0 && threshold == 0) || has_dup_signer || m > 253 {
        return vec![Op::PushInt(0)]; // unspendable: always false
    }

    let mut p = Vec::new();
    // acc := 0. Per-iteration invariant: stack = [sig_0 … sig_{M-1}, acc].
    p.push(Op::PushInt(0));
    for (i0, pk) in signer_pubkeys.iter().enumerate() {
        // At Pick time the stack is [sigs.., acc, msg, pk] (M+3 elements); this member's
        // signature sits (M + 3 − i) slots below the top, where i is the 1-based index.
        let i = i0 + 1;
        let depth = (m + 3 - i) as u8;
        p.push(Op::CtxField(FIELD_SIGHASH)); // push signed message
        p.push(Op::PushBytes(pk.clone())); // push this member's pubkey
        p.push(Op::Pick(depth)); // copy this member's signature to the top
        p.push(Op::VerifySig); // -> 0/1
        p.push(Op::Add); // fold into acc
    }
    // count >= threshold  ==  not(count < threshold)
    p.push(Op::PushInt(threshold as i128));
    p.push(Op::Lt);
    p.push(Op::Not);
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// (2) Time-locks
// ─────────────────────────────────────────────────────────────────────────────

/// **Absolute time-lock.** Spendable only once the chain height (read from
/// `ctx.fields[FIELD_HEIGHT]`, an `Int`) reaches `unlock_height`.
///
/// **Stack seed:** none required (`[]`). Finishes with `Int(height >= unlock_height)`.
pub fn absolute_timelock(unlock_height: i128) -> Vec<Op> {
    vec![
        Op::CtxField(FIELD_HEIGHT),   // [height]
        Op::PushInt(unlock_height),   // [height, unlock]
        Op::Lt,                       // (height < unlock)
        Op::Not,                      // (height >= unlock)
    ]
}

/// **Relative time-lock** (age-since-creation, à la `OP_CHECKSEQUENCEVERIFY`).
/// Spendable once `current_height − creation_height >= min_age`. The output's
/// **creation height is carried in its `datum`** (`Val::Int`); the current height is
/// read from `ctx.fields[FIELD_HEIGHT]`.
///
/// **Stack seed (spend model):** `[datum = creation_height]`. Finishes with
/// `Int(age >= min_age)`.
pub fn relative_timelock(min_age: i128) -> Vec<Op> {
    vec![
        Op::CtxField(FIELD_HEIGHT), // [creation, height]
        Op::Swap,                   // [height, creation]
        Op::Sub,                    // [height - creation] = age
        Op::PushInt(min_age),       // [age, min_age]
        Op::Lt,                     // (age < min_age)
        Op::Not,                    // (age >= min_age)
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// (3) Minimal Ustav token-charter
// ─────────────────────────────────────────────────────────────────────────────

/// Build a **minimal Ustav [`TokenCharter`]**: a fixed-cap Supply module (the mint
/// policy whose hash becomes the token's asset id) followed by a 2-of-3 Governance
/// multisig. Compiling it yields a deterministic validator set (see
/// [`compile_minimal_ustav_charter`]).
///
/// * `token_name` — the ticker, folded into the charter id for domain separation.
/// * `cap` — the fixed maximum authorizable by a single mint spend.
/// * `issuer_pubkey` — the sole authorized minter (its PQ signature over the sighash
///   is required to mint).
/// * `governors` — the three governance member keys (2 of 3 must sign to spend a
///   governance-guarded output).
pub fn minimal_ustav_charter(
    token_name: impl Into<Vec<u8>>,
    cap: u64,
    issuer_pubkey: Vec<u8>,
    governors: [Vec<u8>; 3],
) -> TokenCharter {
    TokenCharter {
        token_name: token_name.into(),
        modules: vec![
            ModuleKind::Supply(SupplyConfig { cap, issuer_pubkey }),
            ModuleKind::Governance(GovernanceConfig {
                signers: governors.to_vec(),
                threshold: 2,
            }),
        ],
    }
}

/// Compile [`minimal_ustav_charter`] to its [`CompiledToken`] validator set (the
/// ordered `(kind, program, validator_hash)` triples plus a `charter_id` committing to
/// the whole composition). Pure function of the charter — same charter ⇒ byte-identical
/// programs and identical ids.
pub fn compile_minimal_ustav_charter(
    token_name: impl Into<Vec<u8>>,
    cap: u64,
    issuer_pubkey: Vec<u8>,
    governors: [Vec<u8>; 3],
) -> CompiledToken {
    modules::compile_charter(&minimal_ustav_charter(token_name, cap, issuer_pubkey, governors))
}

// ─────────────────────────────────────────────────────────────────────────────
// Foundation reference validators (ported from bloch-euvm's own tests)
// ─────────────────────────────────────────────────────────────────────────────

/// **P2PKH-as-contract.** Hash-checks a revealed pubkey against `pubkey_hash`
/// (`sha256d`), then verifies the pubkey's signature over `ctx.fields[FIELD_SIGHASH]`.
///
/// **Stack seed:** `[pubkey, sig]` (both from the redeemer).
pub fn p2pkh(pubkey_hash: [u8; 32]) -> Vec<Op> {
    vec![
        Op::Pick(1),                       // copy pubkey to top: [pubkey, sig, pubkey]
        Op::Sha256d,                       // [pubkey, sig, sha256d(pubkey)]
        Op::PushBytes(pubkey_hash.to_vec()), // [.., h, pkh]
        Op::Eq,                            // [pubkey, sig, (h == pkh)]
        Op::Verify,                        // assert hash match: [pubkey, sig]
        Op::CtxField(FIELD_SIGHASH),       // [pubkey, sig, msg]
        Op::Pick(2),                       // copy pubkey: [.., msg, pubkey]
        Op::Pick(2),                       // copy sig:    [.., msg, pubkey, sig]
        Op::VerifySig,                     // -> [pubkey, sig, verified]
    ]
}

/// **Hash-lock / HTLC preimage gate.** Spendable by revealing a preimage whose
/// `sha256d` equals `lock`.
///
/// **Stack seed:** `[preimage]` (from the redeemer). Finishes with
/// `Int(sha256d(preimage) == lock)`.
pub fn hashlock(lock: [u8; 32]) -> Vec<Op> {
    vec![
        Op::Sha256d,               // [sha256d(preimage)]
        Op::PushBytes(lock.to_vec()),
        Op::Eq,                    // [(hash == lock)]
    ]
}

/// **Stateful continuation counter.** Spendable only if the transaction re-creates the
/// same contract (`tx_outputs[0].validator_hash == self`) with `datum + 1` as the new
/// datum. This is the exact self-recreation pattern an AMM pool uses.
///
/// **Stack seed (spend model):** `[datum = counter]`. Reads `ctx.tx_outputs[0]`.
pub fn continuation_counter() -> Vec<Op> {
    vec![
        Op::TxOutValidator(0), // [datum, outVH]
        Op::SelfValidator,     // [datum, outVH, selfVH]
        Op::Eq,
        Op::Verify,            // assert same contract continues: [datum]
        Op::PushInt(1),
        Op::Add,               // [datum + 1]
        Op::TxOutDatum(0),     // [datum + 1, outDatum]
        Op::Eq,                // [(datum + 1 == outDatum)]
    ]
}

/// **Constant-product AMM pool validator.** A pool eUTXO holds two native assets
/// (`asset_a`, `asset_b`) as reserves. A swap consumes it and must re-create the same
/// contract (`tx_outputs[0]`) such that `new_a·new_b ≥ old_a·old_b` — Uniswap's core
/// invariant, so no transaction may drain the pool.
///
/// **Stack seed (spend model):** `[datum]` (unused by the invariant). Reads the spent
/// output's reserves via `SelfAsset` and the continuation's via `TxOutAsset(0)`.
pub fn constant_product_amm(asset_a: AssetId, asset_b: AssetId) -> Vec<Op> {
    vec![
        Op::TxOutValidator(0),
        Op::SelfValidator,
        Op::Eq,
        Op::Verify, // same contract continues
        Op::PushBytes(asset_a.to_vec()),
        Op::SelfAsset, // old_a
        Op::PushBytes(asset_b.to_vec()),
        Op::SelfAsset,
        Op::Mul, // old_k = old_a * old_b
        Op::PushBytes(asset_a.to_vec()),
        Op::TxOutAsset(0), // new_a
        Op::PushBytes(asset_b.to_vec()),
        Op::TxOutAsset(0),
        Op::Mul, // new_k = new_a * new_b
        Op::Swap,
        Op::Lt,
        Op::Not, // new_k >= old_k
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Runnable demos — each returns a `sim::SimResult` for a VALID witness (green path).
// The reject (invalid-witness) paths are exercised in the test module below.
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical demo sighash used across the gallery demos.
fn demo_sighash() -> Vec<u8> {
    b"euvm-tooling::examples::sighash".to_vec()
}

/// A `ctx` carrying just the sighash in `fields[FIELD_SIGHASH]`.
fn ctx_with_sighash(sighash: &[u8]) -> Ctx {
    Ctx {
        fields: vec![Val::Bytes(sighash.to_vec())],
        ..Default::default()
    }
}

/// A `ctx` carrying the sighash and a block height (`fields[FIELD_HEIGHT]`).
fn ctx_with_height(sighash: &[u8], height: i128) -> Ctx {
    Ctx {
        fields: vec![Val::Bytes(sighash.to_vec()), Val::Int(height)],
        ..Default::default()
    }
}

/// Demo: a 2-of-3 multisig accepting a witness with two valid signatures.
pub fn demo_multisig_n_of_m() -> SimResult {
    let sighash = demo_sighash();
    let (pk1, pk2, pk3) = (b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec());
    let (s1, s3) = (b"sig-1".to_vec(), b"sig-3".to_vec());

    let program = multisig_n_of_m(&[pk1.clone(), pk2.clone(), pk3.clone()], 2);
    let ctx = ctx_with_sighash(&sighash);
    // Members 1 and 3 signed; member 2's slot carries a non-verifying placeholder.
    let verifier = sim::MockVerifier::accepting(vec![
        (sighash.clone(), pk1.clone(), s1.clone()),
        (sighash.clone(), pk3.clone(), s3.clone()),
    ]);
    let redeemer = vec![
        Val::Bytes(s1),
        Val::Bytes(b"placeholder".to_vec()),
        Val::Bytes(s3),
    ];
    sim::run_program(&program, redeemer, &ctx, &verifier, 50_000)
}

/// Demo: an absolute time-lock spent after its unlock height.
pub fn demo_absolute_timelock() -> SimResult {
    let sighash = demo_sighash();
    let program = absolute_timelock(100);
    let ctx = ctx_with_height(&sighash, 150); // height 150 >= unlock 100
    let verifier = sim::MockVerifier::never();
    sim::run_program(&program, vec![], &ctx, &verifier, 10_000)
}

/// Demo: a relative time-lock spent after `min_age` blocks have elapsed since creation.
pub fn demo_relative_timelock() -> SimResult {
    let sighash = demo_sighash();
    let program = relative_timelock(20);
    let creation_height: i128 = 100;
    let output = ExtOutput {
        value: blch(10),
        validator_hash: validator_hash(&program),
        datum: Val::Int(creation_height),
    };
    let ctx = ctx_with_height(&sighash, 130); // age = 130 - 100 = 30 >= 20
    let verifier = sim::MockVerifier::never();
    sim::run_spend(&output, &program, vec![], &ctx, &verifier, 10_000)
}

/// Demo: the Supply (mint) guard of a compiled minimal Ustav charter, authorizing a
/// within-cap mint signed by the issuer.
pub fn demo_ustav_charter() -> SimResult {
    let sighash = demo_sighash();
    let issuer = b"ustav-issuer".to_vec();
    let issuer_sig = b"ustav-issuer-sig".to_vec();
    let governors = [b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec()];

    let compiled = compile_minimal_ustav_charter("USTAV", 1_000_000, issuer.clone(), governors);
    let supply = compiled
        .validators
        .iter()
        .find(|m| m.kind == "supply")
        .expect("charter has a Supply module");

    let ctx = ctx_with_sighash(&sighash);
    let verifier = sim::MockVerifier::accepting(vec![(sighash.clone(), issuer, issuer_sig.clone())]);
    // Supply seed: [datum, requested:Int, sig:Bytes]; 500_000 <= cap 1_000_000.
    let redeemer = vec![
        Val::Int(0),
        Val::Int(500_000),
        Val::Bytes(issuer_sig),
    ];
    sim::run_program(&supply.program, redeemer, &ctx, &verifier, 50_000)
}

/// Demo: P2PKH — reveal a pubkey matching the committed hash and a valid signature.
pub fn demo_p2pkh() -> SimResult {
    let sighash = demo_sighash();
    let pubkey = b"p2pkh-pubkey".to_vec();
    let sig = b"p2pkh-sig".to_vec();
    let program = p2pkh(sha256d(&pubkey));
    let ctx = ctx_with_sighash(&sighash);
    let verifier = sim::MockVerifier::accepting(vec![(sighash.clone(), pubkey.clone(), sig.clone())]);
    sim::run_program(&program, vec![Val::Bytes(pubkey), Val::Bytes(sig)], &ctx, &verifier, 10_000)
}

/// Demo: a hash-lock unlocked by the correct preimage.
pub fn demo_hashlock() -> SimResult {
    let preimage = b"the-secret-preimage".to_vec();
    let program = hashlock(sha256d(&preimage));
    let verifier = sim::MockVerifier::never();
    sim::run_program(&program, vec![Val::Bytes(preimage)], &Ctx::default(), &verifier, 10_000)
}

/// Demo: the continuation counter spent into a correctly-incremented continuation.
pub fn demo_continuation_counter() -> SimResult {
    let program = continuation_counter();
    let vh = validator_hash(&program);
    let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
    let ctx = Ctx {
        tx_outputs: vec![ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(42) }],
        ..Default::default()
    };
    let verifier = sim::MockVerifier::never();
    sim::run_spend(&input, &program, vec![], &ctx, &verifier, 10_000)
}

/// A two-asset [`Value`] bundle, for AMM demos.
fn value_of(pairs: &[(AssetId, u64)]) -> Value {
    pairs.iter().cloned().collect()
}

/// Demo: a constant-product AMM swap that grows the invariant (accepted).
pub fn demo_constant_product_amm() -> SimResult {
    const A: AssetId = [1u8; 32];
    const B: AssetId = [2u8; 32];
    let program = constant_product_amm(A, B);
    let vh = validator_hash(&program);
    // +100 A in, 90 B out: 1100*910 = 1_001_000 >= 1000*1000.
    let pool = ExtOutput {
        value: value_of(&[(A, 1000), (B, 1000)]),
        validator_hash: vh,
        datum: Val::Int(0),
    };
    let ctx = Ctx {
        tx_outputs: vec![ExtOutput {
            value: value_of(&[(A, 1100), (B, 910)]),
            validator_hash: vh,
            datum: Val::Int(0),
        }],
        ..Default::default()
    };
    let verifier = sim::MockVerifier::never();
    sim::run_spend(&pool, &program, vec![], &ctx, &verifier, 50_000)
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── (1) N-of-M multisig ──────────────────────────────────────────────────
    #[test]
    fn multisig_accepts_at_threshold() {
        assert_eq!(demo_multisig_n_of_m().result, Ok(true));
    }

    #[test]
    fn multisig_rejects_below_threshold() {
        let sighash = demo_sighash();
        let (pk1, pk2, pk3) = (b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec());
        let program = multisig_n_of_m(&[pk1.clone(), pk2.clone(), pk3.clone()], 2);
        let ctx = ctx_with_sighash(&sighash);
        // Only one member's signature verifies -> count 1 < threshold 2.
        let verifier = sim::MockVerifier::accepting(vec![(
            sighash.clone(),
            pk1.clone(),
            b"sig-1".to_vec(),
        )]);
        let redeemer = vec![
            Val::Bytes(b"sig-1".to_vec()),
            Val::Bytes(b"x".to_vec()),
            Val::Bytes(b"x".to_vec()),
        ];
        assert_eq!(sim::run_program(&program, redeemer, &ctx, &verifier, 50_000).result, Ok(false));
    }

    #[test]
    fn multisig_degenerate_configs_are_unspendable() {
        // duplicate signer keys -> unspendable sentinel
        let dup = multisig_n_of_m(&[b"k".to_vec(), b"k".to_vec()], 1);
        // threshold 0 with real members -> unspendable sentinel
        let zero = multisig_n_of_m(&[b"a".to_vec(), b"b".to_vec()], 0);
        let ctx = Ctx::default();
        let v = sim::MockVerifier::never();
        assert_eq!(sim::run_program(&dup, vec![], &ctx, &v, 10_000).result, Ok(false));
        assert_eq!(sim::run_program(&zero, vec![], &ctx, &v, 10_000).result, Ok(false));
    }

    // ── (2) Time-locks ───────────────────────────────────────────────────────
    #[test]
    fn absolute_timelock_accepts_after_unlock() {
        assert_eq!(demo_absolute_timelock().result, Ok(true));
    }

    #[test]
    fn absolute_timelock_rejects_before_unlock() {
        let program = absolute_timelock(100);
        let ctx = ctx_with_height(&demo_sighash(), 50); // 50 < 100
        let v = sim::MockVerifier::never();
        assert_eq!(sim::run_program(&program, vec![], &ctx, &v, 10_000).result, Ok(false));
    }

    #[test]
    fn relative_timelock_accepts_after_min_age() {
        assert_eq!(demo_relative_timelock().result, Ok(true));
    }

    #[test]
    fn relative_timelock_rejects_before_min_age() {
        let program = relative_timelock(20);
        let output = ExtOutput {
            value: blch(10),
            validator_hash: validator_hash(&program),
            datum: Val::Int(100),
        };
        let ctx = ctx_with_height(&demo_sighash(), 110); // age 10 < 20
        let v = sim::MockVerifier::never();
        assert_eq!(sim::run_spend(&output, &program, vec![], &ctx, &v, 10_000).result, Ok(false));
    }

    // ── (3) Minimal Ustav charter ────────────────────────────────────────────
    #[test]
    fn ustav_charter_supply_accepts_valid_mint() {
        assert_eq!(demo_ustav_charter().result, Ok(true));
    }

    #[test]
    fn ustav_charter_supply_rejects_bad_issuer_sig() {
        let sighash = demo_sighash();
        let issuer = b"ustav-issuer".to_vec();
        let governors = [b"gov-1".to_vec(), b"gov-2".to_vec(), b"gov-3".to_vec()];
        let compiled = compile_minimal_ustav_charter("USTAV", 1_000_000, issuer, governors);
        let supply = compiled.validators.iter().find(|m| m.kind == "supply").unwrap();
        let ctx = ctx_with_sighash(&sighash);
        // Verifier accepts nothing -> the issuer signature check fails.
        let v = sim::MockVerifier::never();
        let redeemer = vec![Val::Int(0), Val::Int(500_000), Val::Bytes(b"forged".to_vec())];
        assert_eq!(sim::run_program(&supply.program, redeemer, &ctx, &v, 50_000).result, Ok(false));
    }

    #[test]
    fn ustav_charter_is_deterministic() {
        let mk = || {
            compile_minimal_ustav_charter(
                "USTAV",
                1_000_000,
                b"issuer".to_vec(),
                [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            )
        };
        assert_eq!(mk().charter_id, mk().charter_id);
        // The charter's policy id is its Supply module's validator hash.
        assert!(mk().policy_id().is_some());
    }

    // ── Foundation reference validators ──────────────────────────────────────
    #[test]
    fn p2pkh_accepts_and_rejects() {
        assert_eq!(demo_p2pkh().result, Ok(true));

        // Wrong signature -> validator returns false (not an error).
        let sighash = demo_sighash();
        let pubkey = b"p2pkh-pubkey".to_vec();
        let program = p2pkh(sha256d(&pubkey));
        let ctx = ctx_with_sighash(&sighash);
        let v = sim::MockVerifier::never();
        let r = sim::run_program(
            &program,
            vec![Val::Bytes(pubkey), Val::Bytes(b"bad".to_vec())],
            &ctx,
            &v,
            10_000,
        );
        assert_eq!(r.result, Ok(false));
    }

    #[test]
    fn hashlock_accepts_correct_preimage_rejects_wrong() {
        assert_eq!(demo_hashlock().result, Ok(true));

        let preimage = b"the-secret-preimage".to_vec();
        let program = hashlock(sha256d(&preimage));
        let v = sim::MockVerifier::never();
        let r = sim::run_program(
            &program,
            vec![Val::Bytes(b"wrong".to_vec())],
            &Ctx::default(),
            &v,
            10_000,
        );
        assert_eq!(r.result, Ok(false));
    }

    #[test]
    fn continuation_counter_accepts_increment() {
        assert_eq!(demo_continuation_counter().result, Ok(true));
    }

    #[test]
    fn continuation_counter_rejects_wrong_increment() {
        let program = continuation_counter();
        let vh = validator_hash(&program);
        let input = ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(41) };
        let ctx = Ctx {
            tx_outputs: vec![ExtOutput { value: blch(10), validator_hash: vh, datum: Val::Int(43) }],
            ..Default::default()
        };
        let v = sim::MockVerifier::never();
        assert_eq!(sim::run_spend(&input, &program, vec![], &ctx, &v, 10_000).result, Ok(false));
    }

    #[test]
    fn amm_accepts_growing_invariant_rejects_draining() {
        assert_eq!(demo_constant_product_amm().result, Ok(true));

        const A: AssetId = [1u8; 32];
        const B: AssetId = [2u8; 32];
        let program = constant_product_amm(A, B);
        let vh = validator_hash(&program);
        let pool = ExtOutput {
            value: value_of(&[(A, 1000), (B, 1000)]),
            validator_hash: vh,
            datum: Val::Int(0),
        };
        // Draining: 100 A in for 200 B out -> 1100*800 = 880_000 < 1_000_000.
        let ctx = Ctx {
            tx_outputs: vec![ExtOutput {
                value: value_of(&[(A, 1100), (B, 800)]),
                validator_hash: vh,
                datum: Val::Int(0),
            }],
            ..Default::default()
        };
        let v = sim::MockVerifier::never();
        assert_eq!(sim::run_spend(&pool, &program, vec![], &ctx, &v, 50_000).result, Ok(false));
    }
}
