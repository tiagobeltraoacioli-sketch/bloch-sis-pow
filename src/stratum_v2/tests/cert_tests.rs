use crate::stratum_v2::cert::{SignatureNoiseMessage, CERT_LEN, CERT_VERSION};
use secp256k1::{Keypair, Secp256k1, SecretKey};

fn keypair_from_seed(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
    Keypair::from_secret_key(&secp, &sk)
}

#[test]
fn cert_sign_and_verify_happy_path() {
    let authority = keypair_from_seed(0x01);
    let static_kp = keypair_from_seed(0x02);
    let (authority_x, _) = authority.x_only_public_key();
    let (static_x, _) = static_kp.x_only_public_key();

    let valid_from = 1_700_000_000;
    let not_valid_after = valid_from + 30 * 86400;

    let cert = SignatureNoiseMessage::new(&authority, &static_x, valid_from, not_valid_after)
        .expect("new cert");

    assert_eq!(cert.version, CERT_VERSION);
    assert_eq!(cert.valid_from, valid_from);
    assert_eq!(cert.not_valid_after, not_valid_after);

    // Verify within window
    cert.verify(&authority_x, &static_x, valid_from + 1000)
        .expect("cert should verify");
}

#[test]
fn cert_rejects_wrong_static_key() {
    let authority = keypair_from_seed(0x03);
    let static_real = keypair_from_seed(0x04);
    let static_wrong = keypair_from_seed(0x05);
    let (authority_x, _) = authority.x_only_public_key();
    let (static_real_x, _) = static_real.x_only_public_key();
    let (static_wrong_x, _) = static_wrong.x_only_public_key();

    let cert = SignatureNoiseMessage::new(&authority, &static_real_x, 1000, 2000).unwrap();

    let result = cert.verify(&authority_x, &static_wrong_x, 1500);
    assert!(result.is_err(), "verify with wrong static key must fail");
}

#[test]
fn cert_rejects_wrong_authority() {
    let authority_real = keypair_from_seed(0x06);
    let authority_wrong = keypair_from_seed(0x07);
    let static_kp = keypair_from_seed(0x08);
    let (authority_wrong_x, _) = authority_wrong.x_only_public_key();
    let (static_x, _) = static_kp.x_only_public_key();

    let cert = SignatureNoiseMessage::new(&authority_real, &static_x, 1000, 2000).unwrap();

    let result = cert.verify(&authority_wrong_x, &static_x, 1500);
    assert!(result.is_err(), "verify with wrong authority must fail");
}

#[test]
fn cert_rejects_expired() {
    let authority = keypair_from_seed(0x09);
    let static_kp = keypair_from_seed(0x0a);
    let (authority_x, _) = authority.x_only_public_key();
    let (static_x, _) = static_kp.x_only_public_key();

    let cert = SignatureNoiseMessage::new(&authority, &static_x, 1000, 2000).unwrap();

    // Now == not_valid_after (exclusive boundary, must be rejected)
    let result = cert.verify(&authority_x, &static_x, 2000);
    assert!(result.is_err(), "cert at expiry must be rejected");

    // Before valid_from
    let result = cert.verify(&authority_x, &static_x, 999);
    assert!(result.is_err(), "cert before valid_from must be rejected");
}

#[test]
fn cert_rejects_inverted_validity_window() {
    let authority = keypair_from_seed(0x0b);
    let static_kp = keypair_from_seed(0x0c);
    let (static_x, _) = static_kp.x_only_public_key();

    // valid_from > not_valid_after
    let result = SignatureNoiseMessage::new(&authority, &static_x, 2000, 1000);
    assert!(result.is_err(), "inverted window must be rejected");

    // valid_from == not_valid_after
    let result = SignatureNoiseMessage::new(&authority, &static_x, 1500, 1500);
    assert!(result.is_err(), "zero-length window must be rejected");
}

#[test]
fn cert_wire_round_trip() {
    let authority = keypair_from_seed(0x0d);
    let static_kp = keypair_from_seed(0x0e);
    let (static_x, _) = static_kp.x_only_public_key();

    let cert = SignatureNoiseMessage::new(&authority, &static_x, 1000, 2000).unwrap();
    let bytes = cert.to_bytes();
    assert_eq!(bytes.len(), CERT_LEN);

    let parsed = SignatureNoiseMessage::from_bytes(&bytes).expect("parse");
    assert_eq!(parsed.version, cert.version);
    assert_eq!(parsed.valid_from, cert.valid_from);
    assert_eq!(parsed.not_valid_after, cert.not_valid_after);
    assert_eq!(parsed.signature, cert.signature);
}

#[test]
fn cert_wire_rejects_wrong_length() {
    let too_short = [0u8; CERT_LEN - 1];
    assert!(SignatureNoiseMessage::from_bytes(&too_short).is_err());

    let too_long = [0u8; CERT_LEN + 1];
    assert!(SignatureNoiseMessage::from_bytes(&too_long).is_err());
}
