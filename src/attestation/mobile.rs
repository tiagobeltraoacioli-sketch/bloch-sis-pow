//! Mobile device-TEE attestation (feature `mobile`).
//!
//! Unlike SEV-SNP, the ATTESTATION is produced by the mobile CLIENT (in its
//! app), and the node/verifier CHECKS it — so this module is verifier-side. The
//! mobile app uses the platform's free, ubiquitous device TEE:
//!
//! - **Android:** hardware-backed Keystore (StrongBox / TrustZone) + **Key
//!   Attestation** — an X.509 cert chain, rooted in Google's hardware
//!   attestation root, proving the key is hardware-backed and carrying an
//!   attestation extension with a caller-supplied `challenge` (our nonce).
//! - **iOS:** **Secure Enclave** + **App Attest** — a CBOR/WebAuthn-style
//!   assertion the app can produce, rooted in Apple's App Attest CA, bound to a
//!   caller-supplied challenge.
//!
//! HONEST LIMITS (Coherence): the mobile TEE is CLASSICAL crypto (P-256), so it
//! does NOT hold the post-quantum Falcon/ML-DSA key in hardware — it protects
//! it at rest and attests the DEVICE/APP integrity + challenge freshness. This
//! is a light-client role (wallet / relay), never a miner, and integrity-only,
//! not cryptographic secrecy.
//!
//! STUB: cert-chain verification needs the `mobile` app + the platform roots to
//! test end-to-end; the shape below is the intended verifier.

use super::{Tee, Verdict};

/// Verify an Android Key Attestation certificate chain: chains to the Google
/// hardware attestation root, the leaf's attestation extension carries our
/// `challenge`, and (optionally) enforces StrongBox + a bound public key.
pub fn verify_android_key_attestation(_cert_chain_der: &[Vec<u8>], _challenge: &[u8]) -> Verdict {
    // TODO(L3-mobile): parse the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17),
    // validate the chain to the Google root, check attestationChallenge == challenge,
    // securityLevel == StrongBox/TEE, and bind the attested key to the node identity.
    Verdict::Rejected("android key attestation verification not yet wired".into())
}

/// Verify an iOS App Attest assertion: chains to Apple's App Attest root, binds
/// the app id + our `challenge`, and yields the attested public key.
pub fn verify_ios_app_attest(_attestation_cbor: &[u8], _challenge: &[u8]) -> Verdict {
    // TODO(L3-mobile): validate the App Attest statement per Apple's spec.
    Verdict::Rejected("ios app attest verification not yet wired".into())
}

/// The backend tag this module verifies.
pub const TEE: Tee = Tee::Mobile;
