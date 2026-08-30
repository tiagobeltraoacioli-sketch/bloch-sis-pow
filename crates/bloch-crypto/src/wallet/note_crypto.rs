//! Per-output shielded-note encryption (Coherence, C1 §6 note-discovery gap).
//!
//! Closes the note-discovery gap: a `ShieldedTx` output is a bare 32-byte
//! commitment `cm`, so without a ciphertext travelling alongside it the
//! recipient can never learn (v, rho, psi) and can never spend the note. This
//! module implements the KEM/DEM hybrid that fixes that:
//!
//!   sender:    (ss, kem_ct) = ML-KEM-1024.Encaps(recipient kem_pk)
//!              k = SHAKE256(DOM_NOTE_CT ‖ ss)          (coherence_core::derive_note_aead_key)
//!              payload = AES-256-GCM.Seal(k, nonce, aad = DOM_NOTE_CT ‖ cm,
//!                                         LE64(v) ‖ rho ‖ psi)
//!   recipient: ss' = ML-KEM-1024.Decaps(kem_sk, kem_ct)  (implicit rejection —
//!              total function, pseudorandom garbage for not-my-ciphertext)
//!              AES-256-GCM.Open(...) → None = "not my note" (normal scan
//!              outcome), Some((v, rho, psi)) = mine.
//!
//! Security: IND-CCA2 KEM + IND-CCA2 AEAD composes to IND-CCA2 public-key
//! encryption (KEM/DEM composition). ML-KEM-1024 (FIPS 203 final) = NIST
//! Category 5; AES-256-GCM keeps ≥128-bit strength under Grover. The AAD binds
//! each ciphertext 1:1 to its on-chain commitment, so a copied ciphertext
//! presented against a different cm fails authentication.
//!
//! Why Category 5 when the signatures are ML-DSA-65 (Category 3): the note
//! ciphertext sits on-chain FOREVER, so breaking its confidentiality is a
//! retroactive harvest-now-decrypt-later attack with no deadline; forging a
//! signature requires a quantum adversary at spend time. Different threat
//! windows justify the stronger KEM. The domain tag
//! (`bloch:coherence:notect:mlkem1024:v1`) names the KEM, so any future swap
//! re-keys the entire derivation space unambiguously.
//!
//! Deliberately OUTSIDE the ZK statement: nothing here is an input to
//! `check_spend`, the SP1 guest, or the verifier — the entire cost is borne by
//! wallets (≈1 decapsulation + 1 AEAD open + 1 SHAKE-256 per scanned output).
//! Nodes check STRUCTURE only (`ShieldedTx::ciphertexts_well_formed`) and never
//! link this module — it is feature-gated (`note-crypto`).
//!
//! pk_d is NOT in the plaintext: the recipient reconstructs the full `Note`
//! with their own pk_d and MUST verify `Note::commitment() == cm` before
//! trusting the result (`decrypted_note_matches_commitment` helper).

use coherence_core::{
    derive_note_aead_key, note_ciphertext_aad, Note, NoteCiphertext,
    NOTE_AEAD_NONCE_LEN, NOTE_AEAD_TAG_LEN, NOTE_PLAINTEXT_LEN,
};
#[cfg(test)]
use coherence_core::NOTE_KEM_CT_LEN;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use zeroize::Zeroize;
use super::errors::WalletError;

/// Domain tag for PER-POSITION nullifier-key derivation (wallet-side; C1 §7
/// leaves the nk derivation explicitly open, so this is a C2-era wallet
/// convention, not a change to any frozen format).
const DOM_NK: &[u8] = b"bloch:wallet:nk:v1";

/// SHAKE-256 squeezed to 32 bytes (local copy of coherence-core's private
/// helper — same construction, wallet-side domains only).
fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts { h.update(p); }
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}

/// Derive the nullifier key for the note at commitment-tree `position`:
///
///   nk_p = SHAKE256(DOM_NK ‖ seed ‖ LE64(position))
///
/// PER POSITION, not wallet-global, on purpose. `nf = SHAKE256(DOM_NF ‖ nk ‖
/// rho ‖ position)` is a deterministic PRF of nk, so a wallet-global nk turns
/// ONE leaked `SpendWitness` (which carries nk per input — e.g. everything a
/// delegated prover receives in the clear) into retroactive AND future
/// deanonymization of the wallet's every spend: enumerate candidate notes,
/// recompute nullifiers, match against the public chain. With nk derived per
/// position, a leaked witness exposes only the notes IN that witness — the
/// blast radius shrinks from the wallet's lifetime to the transaction.
/// `SpendInput` already carries nk per input, so this costs nothing
/// structurally.
///
/// `seed` is the wallet's master secret (caller zeroizes); the returned nk is
/// itself secret material — zeroize it after building the witness.
///
/// NOT yet enforced by the ZK statement: proving that nk_p derives from the
/// spending key is a circuit change (C2), tracked separately. Until then this
/// is a wallet-side hygiene guarantee, and it is a PRECONDITION for any
/// delegated-prover deployment.
pub fn derive_nk_at(seed: &[u8], position: u64) -> [u8; 32] {
    shake256_32(&[DOM_NK, seed, &position.to_le_bytes()])
}

/// ML-KEM-1024 public (encapsulation) key length — published once per shielded
/// address, amortized over every note sent to it.
pub const NOTE_KEM_PK_LEN: usize = 1568;
/// ML-KEM-1024 secret (decapsulation) key length — held by the recipient only.
pub const NOTE_KEM_SK_LEN: usize = 3168;

/// Generate a fresh ML-KEM-1024 keypair for note reception.
/// Returns (kem_pk 1568 B, kem_sk 3168 B). The caller owns zeroizing the
/// secret key when persisting it (e.g. via the encrypted keystore).
pub fn note_kem_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mlkem1024::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// SENDER: encrypt `note` to the recipient's ML-KEM-1024 public key (obtained
/// out-of-band, e.g. a future shielded-address format — orthogonal to this
/// component).
///
/// Encapsulates a fresh shared secret (so no two outputs ever share an AEAD
/// key, even to the same recipient in the same tx), derives the AEAD key via
/// `derive_note_aead_key`, and seals LE64(v) ‖ rho ‖ psi under
/// AAD = DOM_NOTE_CT ‖ note.commitment(), binding the ciphertext to the
/// specific on-chain output.
pub fn encrypt_note_to(kem_pk: &[u8], note: &Note) -> Result<NoteCiphertext, WalletError> {
    if kem_pk.len() != NOTE_KEM_PK_LEN {
        return Err(WalletError::Crypto(format!(
            "note KEM public key must be {} bytes, got {}", NOTE_KEM_PK_LEN, kem_pk.len())));
    }
    let pk = mlkem1024::PublicKey::from_bytes(kem_pk)
        .map_err(|e| WalletError::Crypto(format!("invalid ML-KEM-1024 public key: {:?}", e)))?;
    let (ss, kem_ct) = mlkem1024::encapsulate(&pk);

    let mut key_bytes = derive_note_aead_key(ss.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    let mut nonce_bytes = [0u8; NOTE_AEAD_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cm = note.commitment();
    let aad = note_ciphertext_aad(&cm);

    let mut pt = Vec::with_capacity(NOTE_PLAINTEXT_LEN);
    pt.extend_from_slice(&note.v.to_le_bytes());
    pt.extend_from_slice(&note.rho);
    pt.extend_from_slice(&note.psi);
    debug_assert_eq!(pt.len(), NOTE_PLAINTEXT_LEN);

    let payload = cipher
        .encrypt(nonce, Payload { msg: &pt, aad: &aad })
        .map_err(|_| WalletError::Crypto("note AEAD encryption failed".into()));
    pt.zeroize();
    key_bytes.zeroize();
    let payload = payload?;
    debug_assert_eq!(payload.len(), NOTE_PLAINTEXT_LEN + NOTE_AEAD_TAG_LEN);

    Ok(NoteCiphertext { kem_ct: kem_ct.as_bytes().to_vec(), nonce: nonce_bytes, payload })
}

/// RECIPIENT: trial-decrypt one output during a wallet scan.
///
/// `cm` is the on-chain commitment (`tx.outputs[i]`, index-aligned with
/// `tx.output_ciphertexts[i]`) — required as AAD to check the tag. Returns
/// `None` (never `Err`) on any structural or authentication failure — that is
/// the normal "not my note" outcome, not an error condition.
///
/// On `Some((v, rho, psi))` the caller reconstructs the full `Note` with their
/// OWN pk_d and MUST verify `Note { v, pk_d, rho, psi }.commitment() == *cm`
/// before trusting it (see `decrypted_note_matches_commitment`).
pub fn trial_decrypt_note(
    kem_sk: &[u8],
    cm: &[u8; 32],
    ct: &NoteCiphertext,
) -> Option<(u64, [u8; 32], [u8; 32])> {
    if kem_sk.len() != NOTE_KEM_SK_LEN || !ct.well_formed() {
        return None;
    }
    let sk = mlkem1024::SecretKey::from_bytes(kem_sk).ok()?;
    let kem_ct = mlkem1024::Ciphertext::from_bytes(&ct.kem_ct).ok()?;
    // Total function (FO-transform implicit rejection): always yields 32 bytes,
    // pseudorandom garbage if this ciphertext was not encapsulated to our key —
    // the AEAD tag check below then fails with overwhelming probability.
    let ss = mlkem1024::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_note_aead_key(ss.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&ct.nonce);
    let aad = note_ciphertext_aad(cm);

    let pt = cipher.decrypt(nonce, Payload { msg: ct.payload.as_slice(), aad: &aad });
    key_bytes.zeroize();
    let mut pt = pt.ok()?; // wrong key / tampered / wrong cm → not my note

    if pt.len() != NOTE_PLAINTEXT_LEN {
        // Authenticated plaintext of the wrong shape = encoder bug, treat as
        // not-mine rather than panicking a chain scan.
        pt.zeroize();
        return None;
    }
    let v = u64::from_le_bytes(pt[0..8].try_into().expect("8-byte slice"));
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pt[8..40]);
    let mut psi = [0u8; 32];
    psi.copy_from_slice(&pt[40..72]);
    pt.zeroize();
    Some((v, rho, psi))
}

/// Mandatory post-decryption check: reconstruct the note with the recipient's
/// own `pk_d` and verify it recomputes the on-chain commitment. Returns the
/// full spendable `Note` only on a match — defense-in-depth independent of the
/// AEAD authentication (one extra SHAKE-256 call).
pub fn decrypted_note_matches_commitment(
    v: u64,
    pk_d: [u8; 32],
    rho: [u8; 32],
    psi: [u8; 32],
    cm: &[u8; 32],
) -> Option<Note> {
    let note = Note { v, pk_d, rho, psi };
    if &note.commitment() == cm { Some(note) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_note(v: u64, tag: u8) -> Note {
        Note { v, pk_d: [tag; 32], rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
    }

    #[test]
    fn roundtrip_recovers_exact_note_fields() {
        let (pk, sk) = note_kem_keypair();
        assert_eq!(pk.len(), NOTE_KEM_PK_LEN);
        assert_eq!(sk.len(), NOTE_KEM_SK_LEN);

        let note = test_note(123_456_789, 7);
        let cm = note.commitment();
        let ct = encrypt_note_to(&pk, &note).expect("encrypt");
        assert!(ct.well_formed());
        assert_eq!(ct.kem_ct.len(), NOTE_KEM_CT_LEN);
        assert_eq!(ct.payload.len(), NOTE_PLAINTEXT_LEN + NOTE_AEAD_TAG_LEN);
        // ML-KEM-1024: 1568 + 12 + 88 = 1668 bytes per output on the wire.
        assert_eq!(ct.kem_ct.len() + ct.nonce.len() + ct.payload.len(), 1668);

        let (v, rho, psi) = trial_decrypt_note(&sk, &cm, &ct).expect("my note");
        assert_eq!(v, note.v);
        assert_eq!(rho, note.rho);
        assert_eq!(psi, note.psi);

        // Full-note reconstruction with the recipient's own pk_d recomputes cm.
        let full = decrypted_note_matches_commitment(v, note.pk_d, rho, psi, &cm)
            .expect("commitment must recompute");
        assert_eq!(full, note);
        // Wrong pk_d → commitment mismatch → rejected.
        assert!(decrypted_note_matches_commitment(v, [0xFF; 32], rho, psi, &cm).is_none());
    }

    #[test]
    fn wrong_secret_key_yields_none() {
        let (pk, _sk) = note_kem_keypair();
        let (_pk2, sk2) = note_kem_keypair();
        let note = test_note(42, 3);
        let cm = note.commitment();
        let ct = encrypt_note_to(&pk, &note).expect("encrypt");
        // Not-my-note is None, never Err/panic (implicit rejection + tag fail).
        assert!(trial_decrypt_note(&sk2, &cm, &ct).is_none());
    }

    #[test]
    fn tampering_any_component_yields_none() {
        let (pk, sk) = note_kem_keypair();
        let note = test_note(1_000, 9);
        let cm = note.commitment();
        let ct = encrypt_note_to(&pk, &note).expect("encrypt");

        let mut bad_nonce = ct.clone();
        bad_nonce.nonce[0] ^= 1;
        assert!(trial_decrypt_note(&sk, &cm, &bad_nonce).is_none());

        let mut bad_payload = ct.clone();
        bad_payload.payload[0] ^= 1;
        assert!(trial_decrypt_note(&sk, &cm, &bad_payload).is_none());

        let mut bad_tag = ct.clone();
        let last = bad_tag.payload.len() - 1;
        bad_tag.payload[last] ^= 1;
        assert!(trial_decrypt_note(&sk, &cm, &bad_tag).is_none());

        let mut bad_kem = ct.clone();
        bad_kem.kem_ct[0] ^= 1;
        assert!(trial_decrypt_note(&sk, &cm, &bad_kem).is_none());

        // Malformed (short) components short-circuit to None, no panic.
        let mut short_kem = ct.clone();
        short_kem.kem_ct.pop();
        assert!(trial_decrypt_note(&sk, &cm, &short_kem).is_none());
    }

    #[test]
    fn aad_binds_ciphertext_to_its_commitment() {
        let (pk, sk) = note_kem_keypair();
        let note = test_note(555, 4);
        let cm = note.commitment();
        let ct = encrypt_note_to(&pk, &note).expect("encrypt");

        // Same key, decrypt against a DIFFERENT commitment → AAD mismatch → None.
        let other_cm = test_note(555, 5).commitment();
        assert_ne!(cm, other_cm);
        assert!(trial_decrypt_note(&sk, &other_cm, &ct).is_none());
        // Against the right cm it still opens.
        assert!(trial_decrypt_note(&sk, &cm, &ct).is_some());
    }

    #[test]
    fn same_note_twice_never_shares_kem_ct_or_key_stream() {
        // Fresh encapsulation per call: two ciphertexts of the SAME note to the
        // SAME recipient must differ in kem_ct (and payload, w.h.p.).
        let (pk, sk) = note_kem_keypair();
        let note = test_note(77, 2);
        let cm = note.commitment();
        let ct1 = encrypt_note_to(&pk, &note).expect("encrypt");
        let ct2 = encrypt_note_to(&pk, &note).expect("encrypt");
        assert_ne!(ct1.kem_ct, ct2.kem_ct);
        assert_ne!(ct1.payload, ct2.payload);
        assert_eq!(trial_decrypt_note(&sk, &cm, &ct1), trial_decrypt_note(&sk, &cm, &ct2));
    }

    #[test]
    fn per_position_nk_bounds_a_witness_leak_to_its_own_notes() {
        let seed = [0xA5u8; 64];
        // Deterministic (a wallet can re-derive on restore) …
        assert_eq!(derive_nk_at(&seed, 7), derive_nk_at(&seed, 7));
        // … but unlinkable across positions and across seeds.
        assert_ne!(derive_nk_at(&seed, 7), derive_nk_at(&seed, 8));
        assert_ne!(derive_nk_at(&seed, 7), derive_nk_at(&[0xA6u8; 64], 7));

        // The leak-bounding property itself: an adversary holding the nk for
        // position 7 (from a leaked witness) recomputes that note's nullifier —
        // but NOT the nullifier of the same wallet's note at another position,
        // because that one was keyed with a different nk.
        let note_a = test_note(100, 1);
        let note_b = test_note(200, 2);
        let nk_a = derive_nk_at(&seed, 7);
        let nk_b = derive_nk_at(&seed, 8);
        let nf_b_real = note_b.nullifier(&nk_b, 8);
        // Enumeration attack with the leaked nk_a against note_b fails:
        assert_ne!(note_b.nullifier(&nk_a, 8), nf_b_real);
        // while the legitimately-derived key still matches, of course:
        assert_eq!(note_a.nullifier(&nk_a, 7), note_a.nullifier(&derive_nk_at(&seed, 7), 7));
    }

    #[test]
    fn bad_public_key_is_an_error_not_a_panic() {
        let note = test_note(1, 1);
        assert!(encrypt_note_to(&[0u8; 10], &note).is_err());
        // A Kyber768/ML-KEM-768-sized key (1184 B) is also rejected up front:
        // the length gate makes the KEM-family mismatch loud, not garbage.
        assert!(encrypt_note_to(&[0u8; 1184], &note).is_err());
    }
}
