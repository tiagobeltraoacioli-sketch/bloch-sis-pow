// SPDX-License-Identifier: AGPL-3.0-or-later
//! §9.2 — the named negative/control pairs.
//!
//! Every negative here is paired with a **control**: the same fixture, one
//! field changed back, which must be `Ok`. A rejection test that would also
//! pass against a `verify` that returned `Err` unconditionally proves nothing,
//! and this crate's whole value is in the rejections.
//!
//! Note the epoch used by every control: [`ACTIVATION_EPOCH`] is `u64::MAX`,
//! so the only epoch at which anything is authorizable today is `u64::MAX`
//! itself. That is the crate being inert, visible in its own tests.

mod common;

use bloch_l1_evm_auth::root::{call_message, evm_txid, signing_root};
use bloch_l1_evm_auth::verify::verify;
use bloch_l1_evm_auth::{
    address_from_pubkey, wrap_envelope, AuthReject, BlochTx, ACTIVATION_EPOCH, HYBRID_PK_BYTES,
    MLDSA65_SIG_BYTES, SUITE_MLDSA65_FALCON1024, SUITE_MLDSA65_ONLY, TX_TYPE_PQ_BATCH,
};
use common::{base_tx, first_use_tx, repeat_use_tx, sign_with, Dir, Key, MockVerifier, CHAIN_ID};

const V: MockVerifier = MockVerifier;
const EPOCH: u64 = ACTIVATION_EPOCH;

fn ok(tx: &BlochTx, dir: &Dir) -> Result<bloch_l1_evm_auth::Authorized, AuthReject> {
    verify(tx, EPOCH, CHAIN_ID, dir, &V)
}

// ---------------------------------------------------------------------------
// The happy paths — the controls everything else is measured against
// ---------------------------------------------------------------------------

#[test]
fn first_authorization_is_accepted_and_returns_the_key_to_record() {
    let key = Key::new(31);
    let tx = first_use_tx(&key);
    let authorized = ok(&tx, &Dir::empty()).expect("first authorization accepted");
    assert_eq!(authorized.sender, key.address());
    assert_eq!(
        authorized.pubkey_to_record.as_deref(),
        Some(key.enveloped.as_slice()),
        "the crate returns the key; the execution layer records it"
    );
    assert_eq!(
        authorized.evm_txid,
        evm_txid(&signing_root(&tx).unwrap())
    );
}

#[test]
fn repeat_authorization_is_accepted_and_records_nothing() {
    let key = Key::new(32);
    let dir = Dir::with(key.address(), &key.enveloped);
    let authorized = ok(&repeat_use_tx(&key), &dir).expect("repeat authorization accepted");
    assert_eq!(authorized.pubkey_to_record, None);
}

#[test]
fn the_batch_type_authorizes_the_same_way() {
    let key = Key::new(33);
    let mut tx = base_tx(&key);
    tx.type_byte = TX_TYPE_PQ_BATCH;
    tx.data = bloch_l1_evm_auth::batch::encode_batch(&[bloch_l1_evm_auth::BatchCall {
        to: Some([0x44; 20]),
        value: 1,
        calldata: vec![1, 2, 3],
    }])
    .unwrap();
    let tx = sign_with(tx, &key, Some(key.enveloped.clone()));
    assert!(ok(&tx, &Dir::empty()).is_ok());
}

// ---------------------------------------------------------------------------
// The sender_pk presence rule
// ---------------------------------------------------------------------------

#[test]
fn first_use_without_a_pubkey_is_rejected_control_with_it_is_accepted() {
    let key = Key::new(34);

    // NEGATIVE: a fresh account and nothing to verify against. A
    // non-recoverable suite cannot invent a key.
    let bare = sign_with(base_tx(&key), &key, None);
    assert_eq!(ok(&bare, &Dir::empty()), Err(AuthReject::MissingPubkey));

    // CONTROL: the same transaction carrying the correct pubkey.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}

#[test]
fn a_second_pubkey_is_rejected_even_when_the_bytes_are_identical() {
    let key = Key::new(35);
    let dir = Dir::with(key.address(), &key.enveloped);

    // NEGATIVE: the account already has this exact key recorded, and the
    // transaction reveals it again. "Present and equal is also fine" would
    // make two encodings of one transaction valid at the same instant, and
    // two encodings is malleability. The rule is PRESENCE, not equality.
    let redundant = sign_with(base_tx(&key), &key, Some(key.enveloped.clone()));
    assert_eq!(ok(&redundant, &dir), Err(AuthReject::RedundantPubkey));

    // CONTROL: the same transaction without the redundant reveal.
    assert!(ok(&repeat_use_tx(&key), &dir).is_ok());
}

#[test]
fn revealing_a_different_key_than_the_one_recorded_is_still_redundant() {
    // Not AddressMismatch — the rule fires before any key is chosen, which is
    // what stops "reveal a key of your choosing" from ever being a live path.
    let key = Key::new(36);
    let other = Key::new(37);
    let dir = Dir::with(key.address(), &key.enveloped);
    let tx = sign_with(base_tx(&key), &key, Some(other.enveloped.clone()));
    assert_eq!(ok(&tx, &dir), Err(AuthReject::RedundantPubkey));
}

// ---------------------------------------------------------------------------
// Theft — the test the whole crate exists for
// ---------------------------------------------------------------------------

#[test]
fn theft_a_valid_signature_by_another_key_cannot_authorize_your_address() {
    let victim = Key::new(38);
    let thief = Key::new(39);
    assert_ne!(victim.address(), thief.address());

    // NEGATIVE: the thief builds a transaction that debits the VICTIM's
    // address, signs it perfectly with his own key, and reveals his own key.
    // Everything about the signature is valid. It is simply not the victim's
    // key, and that must be the end of it.
    let mut tx = base_tx(&victim);
    tx.sender = victim.address();
    let stolen = sign_with(tx, &thief, Some(thief.enveloped.clone()));
    assert_eq!(ok(&stolen, &Dir::empty()), Err(AuthReject::AddressMismatch));

    // CONTROL: the identical transaction, signed by the identical key, with
    // `sender` set to the thief's own address, is accepted. The rejection
    // above is about *whose* address it is, not about the signature.
    let mut own = base_tx(&thief);
    own.sender = thief.address();
    let own = sign_with(own, &thief, Some(thief.enveloped.clone()));
    assert!(ok(&own, &Dir::empty()).is_ok());
}

#[test]
fn theft_by_literal_signature_reuse_is_rejected_before_any_crypto_runs() {
    // The address check precedes verification, so a replayed signature blob
    // over a victim's address fails on the binding, not on the maths.
    let victim = Key::new(40);
    let thief = Key::new(41);
    let thief_tx = first_use_tx(&thief);

    let mut replay = thief_tx.clone();
    replay.sender = victim.address();
    assert_eq!(ok(&replay, &Dir::empty()), Err(AuthReject::AddressMismatch));
}

#[test]
fn an_address_that_only_partly_matches_is_rejected() {
    // Guards the comparison's WIDTH. A check that compared only a prefix
    // would accept this, and a prefix check is not a binding.
    let key = Key::new(42);
    let real = key.address();
    for prefix_len in [1usize, 4, 8, 12, 16, 19] {
        let mut forged = real;
        forged[prefix_len] ^= 0xff;
        let mut tx = base_tx(&key);
        tx.sender = forged;
        let tx = sign_with(tx, &key, Some(key.enveloped.clone()));
        assert_eq!(
            ok(&tx, &Dir::empty()),
            Err(AuthReject::AddressMismatch),
            "a sender agreeing on only the first {prefix_len} bytes was accepted"
        );
    }
    // CONTROL: the untouched address.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}

#[test]
fn a_stored_key_that_is_not_the_senders_key_cannot_authorize_it() {
    // State-corruption direction: the directory hands back the wrong key.
    let key = Key::new(43);
    let other = Key::new(44);

    // NEGATIVE.
    let wrong_dir = Dir::with(key.address(), &other.enveloped);
    assert_eq!(
        ok(&repeat_use_tx(&key), &wrong_dir),
        Err(AuthReject::AddressMismatch)
    );

    // CONTROL.
    let right_dir = Dir::with(key.address(), &key.enveloped);
    assert!(ok(&repeat_use_tx(&key), &right_dir).is_ok());
}

// ---------------------------------------------------------------------------
// The hybrid: AND at the split point
// ---------------------------------------------------------------------------

#[test]
fn a_forged_mldsa_half_is_rejected_control_both_halves_valid_is_accepted() {
    let key = Key::new(45);
    let tx = first_use_tx(&key);
    let root = signing_root(&tx).unwrap();

    // NEGATIVE: garbage ML-DSA half, genuine Falcon half. Under an OR this
    // would be accepted.
    let mut body = vec![0xAAu8; MLDSA65_SIG_BYTES];
    body.extend_from_slice(&key.falcon_sig(&root));
    let mut forged = tx.clone();
    forged.signature = wrap_envelope(SUITE_MLDSA65_FALCON1024, &body);
    assert_eq!(ok(&forged, &Dir::empty()), Err(AuthReject::BadSignature));

    // CONTROL.
    assert!(ok(&tx, &Dir::empty()).is_ok());
}

#[test]
fn a_forged_falcon_half_is_rejected_control_both_halves_valid_is_accepted() {
    let key = Key::new(46);
    let tx = first_use_tx(&key);
    let root = signing_root(&tx).unwrap();

    // NEGATIVE: genuine ML-DSA half, garbage Falcon half.
    let mut body = key.mldsa_sig(&root);
    body.extend_from_slice(&vec![0xBBu8; common::FALCON_SIG_BYTES]);
    let mut forged = tx.clone();
    forged.signature = wrap_envelope(SUITE_MLDSA65_FALCON1024, &body);
    assert_eq!(ok(&forged, &Dir::empty()), Err(AuthReject::BadSignature));

    // CONTROL.
    assert!(ok(&tx, &Dir::empty()).is_ok());
}

#[test]
fn a_signature_with_no_room_for_a_falcon_half_is_malformed() {
    let key = Key::new(47);
    let tx = first_use_tx(&key);
    let root = signing_root(&tx).unwrap();

    // NEGATIVE: exactly MLDSA65_SIG_BYTES — a perfectly valid ML-DSA
    // signature, and *malformed as a hybrid*. Not "a valid ML-DSA-only
    // signature": rejecting it here is what keeps the 0x0002 escape hatch an
    // explicit decision rather than a parsing accident.
    let mut truncated = tx.clone();
    truncated.signature = wrap_envelope(SUITE_MLDSA65_FALCON1024, &key.mldsa_sig(&root));
    assert_eq!(
        ok(&truncated, &Dir::empty()),
        Err(AuthReject::MalformedSignature),
        "the length guard must be observable on its own"
    );

    // And one byte shorter still, for the boundary either side.
    let mut shorter = tx.clone();
    shorter.signature = wrap_envelope(
        SUITE_MLDSA65_FALCON1024,
        &key.mldsa_sig(&root)[..MLDSA65_SIG_BYTES - 1],
    );
    assert_eq!(
        ok(&shorter, &Dir::empty()),
        Err(AuthReject::MalformedSignature)
    );

    // CONTROL: one byte longer than the split point reaches the crypto —
    // it fails there, as a *signature* failure, not as a geometry failure.
    let mut one_over = tx.clone();
    let mut body = key.mldsa_sig(&root);
    body.push(0);
    one_over.signature = wrap_envelope(SUITE_MLDSA65_FALCON1024, &body);
    assert_eq!(ok(&one_over, &Dir::empty()), Err(AuthReject::BadSignature));

    // CONTROL: the full hybrid is accepted.
    assert!(ok(&tx, &Dir::empty()).is_ok());
}

#[test]
fn a_pubkey_of_the_wrong_length_is_rejected() {
    let key = Key::new(48);
    for delta in [-1isize, 1] {
        let len = (HYBRID_PK_BYTES as isize + delta) as usize;
        let mut body = key.body.clone();
        body.resize(len, 0);
        let enveloped = wrap_envelope(SUITE_MLDSA65_FALCON1024, &body);
        let mut tx = base_tx(&key);
        tx.sender = address_from_pubkey(&enveloped);
        let tx = sign_with(tx, &key, Some(enveloped));
        assert_eq!(ok(&tx, &Dir::empty()), Err(AuthReject::BadPubkeyLength));
    }
    // CONTROL.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}

// ---------------------------------------------------------------------------
// Suite discipline
// ---------------------------------------------------------------------------

#[test]
fn the_escape_hatch_suite_is_rejected_on_both_objects() {
    let key = Key::new(49);

    // NEGATIVE: a well-formed hybrid key and signature, wrapped in the
    // 0x0002 envelope, with `sender` derived from THAT envelope so the
    // address check would pass. Only the suite rule stands between this and
    // acceptance — which is the point: the escape hatch stays exactly as
    // available and exactly as unused as it is in staking.
    let pk_0002 = wrap_envelope(SUITE_MLDSA65_ONLY, &key.body);
    let mut tx = base_tx(&key);
    tx.sender = address_from_pubkey(&pk_0002);
    tx.sender_pk = Some(pk_0002);
    let root = signing_root(&tx).unwrap();
    tx.signature = wrap_envelope(SUITE_MLDSA65_ONLY, &key.sign_body(&root));
    assert_eq!(ok(&tx, &Dir::empty()), Err(AuthReject::WrongSuite));

    // NEGATIVE: 0x0002 on the signature alone.
    let mut sig_only = first_use_tx(&key);
    let root = signing_root(&sig_only).unwrap();
    sig_only.signature = wrap_envelope(SUITE_MLDSA65_ONLY, &key.sign_body(&root));
    assert_eq!(ok(&sig_only, &Dir::empty()), Err(AuthReject::WrongSuite));

    // CONTROL: 0x0001 on both.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}

#[test]
fn the_legacy_unenveloped_blob_is_rejected() {
    let key = Key::new(50);
    // A genuine hybrid body never starts with the magic, which is exactly why
    // `bloch_crypto` can fall back for carry-over wallets. This crate must
    // not: there is no carry-over EVM account, and accepting both encodings
    // would give one key two addresses.
    assert_ne!(&key.body[..2], &[0xB1, 0x0C]);

    // NEGATIVE: bare `mldsa ‖ falcon` pk, with `sender` derived from the raw
    // body so that a fallback would authorize it.
    let mut tx = base_tx(&key);
    tx.sender = address_from_pubkey(&key.body);
    tx.sender_pk = Some(key.body.clone());
    let root = signing_root(&tx).unwrap();
    tx.signature = key.sign(&root);
    assert_eq!(ok(&tx, &Dir::empty()), Err(AuthReject::WrongSuite));

    // NEGATIVE: bare signature body.
    let mut bare_sig = first_use_tx(&key);
    let root = signing_root(&bare_sig).unwrap();
    bare_sig.signature = key.sign_body(&root);
    assert_eq!(ok(&bare_sig, &Dir::empty()), Err(AuthReject::WrongSuite));

    // NEGATIVE: an empty signature, and a signature shorter than the header.
    let mut stub = first_use_tx(&key);
    stub.signature = Vec::new();
    assert_eq!(ok(&stub, &Dir::empty()), Err(AuthReject::WrongSuite));
    stub.signature = vec![0xB1, 0x0C, 0x01];
    assert_eq!(ok(&stub, &Dir::empty()), Err(AuthReject::WrongSuite));

    // CONTROL.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}

#[test]
fn a_suite_mismatch_between_key_and_signature_is_rejected() {
    let key = Key::new(51);
    let mut tx = first_use_tx(&key);
    let root = signing_root(&tx).unwrap();
    tx.signature = wrap_envelope(SUITE_MLDSA65_ONLY, &key.sign_body(&root));
    assert_eq!(ok(&tx, &Dir::empty()), Err(AuthReject::WrongSuite));

    // CONTROL.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}

#[test]
fn an_unrecognised_suite_id_is_rejected() {
    let key = Key::new(52);
    for suite in [0x0000u16, 0x0003, 0xffff] {
        let pk = wrap_envelope(suite, &key.body);
        let mut tx = base_tx(&key);
        tx.sender = address_from_pubkey(&pk);
        tx.sender_pk = Some(pk);
        let root = signing_root(&tx).unwrap();
        tx.signature = wrap_envelope(suite, &key.sign_body(&root));
        assert_eq!(
            ok(&tx, &Dir::empty()),
            Err(AuthReject::WrongSuite),
            "suite {suite:#06x} must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Replay domains
// ---------------------------------------------------------------------------

#[test]
fn a_transaction_for_another_chain_is_rejected() {
    let key = Key::new(53);
    let tx = first_use_tx(&key);

    // NEGATIVE.
    assert_eq!(
        verify(&tx, EPOCH, CHAIN_ID + 1, &Dir::empty(), &V),
        Err(AuthReject::WrongChain)
    );

    // CONTROL.
    assert!(verify(&tx, EPOCH, CHAIN_ID, &Dir::empty(), &V).is_ok());
}

#[test]
fn a_precompile_message_signature_cannot_authorize_a_transaction() {
    // The sharpest cross-domain case, and the reason the precompile hashes
    // with DS_EVM_CALL: a contract asks the user to "sign a message" whose
    // 32 bytes happen to BE a transaction's signing root. With domain
    // separation the resulting signature is worthless as an authorization.
    let key = Key::new(54);
    let tx = first_use_tx(&key);
    let root = signing_root(&tx).unwrap();

    let message = call_message(CHAIN_ID, &root);
    let mut cross = tx.clone();
    cross.signature = key.sign(&message);

    // NEGATIVE: the message signature does not authorize the transaction.
    assert_eq!(ok(&cross, &Dir::empty()), Err(AuthReject::BadSignature));

    // CONTROL: the transaction's own root does.
    assert!(ok(&tx, &Dir::empty()).is_ok());
}

#[test]
fn a_signature_over_a_neighbouring_transaction_does_not_transfer() {
    let key = Key::new(55);
    let tx = first_use_tx(&key);
    let mut other = base_tx(&key);
    other.nonce += 1;
    let other_root = signing_root(&other).unwrap();

    let mut swapped = tx.clone();
    swapped.signature = key.sign(&other_root);
    assert_eq!(ok(&swapped, &Dir::empty()), Err(AuthReject::BadSignature));

    assert!(ok(&tx, &Dir::empty()).is_ok());
}

// ---------------------------------------------------------------------------
// The flag day
// ---------------------------------------------------------------------------

#[test]
fn the_gate_holds_at_every_epoch_below_activation() {
    let key = Key::new(56);
    let tx = first_use_tx(&key);
    for epoch in [0u64, 1, 800, 27_000, ACTIVATION_EPOCH - 1] {
        assert_eq!(
            verify(&tx, epoch, CHAIN_ID, &Dir::empty(), &V),
            Err(AuthReject::NotActivated),
            "epoch {epoch} must be inert"
        );
    }
    // CONTROL: at the activation epoch itself the rules run. This is the only
    // epoch at which they do, because ACTIVATION_EPOCH is u64::MAX — the
    // crate's inertness, asserted rather than described.
    assert!(verify(&tx, ACTIVATION_EPOCH, CHAIN_ID, &Dir::empty(), &V).is_ok());
}

#[test]
fn the_gate_is_read_from_the_parameter_and_nowhere_else() {
    // Structural, not a convention: `verify` has no other source of an epoch.
    // On 2026-08-08 this chain forked because a consensus rule read local
    // mutable state instead of the block; the shape of this signature is the
    // fix for that class of bug, so it is asserted here.
    let key = Key::new(57);
    let tx = first_use_tx(&key);
    let below = verify(&tx, ACTIVATION_EPOCH - 1, CHAIN_ID, &Dir::empty(), &V);
    let at = verify(&tx, ACTIVATION_EPOCH, CHAIN_ID, &Dir::empty(), &V);
    assert_ne!(
        below.is_ok(),
        at.is_ok(),
        "the epoch parameter must be what decides"
    );
}

// ---------------------------------------------------------------------------
// Type discipline at the verify boundary
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_type_byte_is_rejected_even_on_an_in_memory_transaction() {
    // The decoder rejects unknown types on the wire; a transaction can also
    // reach `verify` having been built in memory, so the rule lives here too.
    let key = Key::new(58);
    for unknown in [0x00u8, 0x02, 0x4f, 0x52, 0xff] {
        let mut tx = base_tx(&key);
        tx.type_byte = unknown;
        let tx = sign_with(tx, &key, Some(key.enveloped.clone()));
        assert_eq!(ok(&tx, &Dir::empty()), Err(AuthReject::UnknownType));
    }
    // CONTROL.
    assert!(ok(&first_use_tx(&key), &Dir::empty()).is_ok());
}
