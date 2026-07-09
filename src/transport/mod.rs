//! Bloch-SIS Protocol — Post-Quantum Transport Primitives (Sprint A1)
//!
//! # Scope
//!
//! This module implements hardened cryptographic primitives for a
//! post-quantum secure channel: an authenticated ML-KEM-768 + ML-DSA-65
//! handshake, followed by a ChaCha20-Poly1305 stream cipher with
//! monotonic nonce counters and domain-separated key schedule.
//!
//! **Status:** primitives only. These are NOT wired into libp2p in
//! Sprint A1 — the P2P transport continues to use classical libp2p
//! Noise (Curve25519/Ed25519). Sprint A2 will implement the libp2p
//! `InboundConnectionUpgrade` / `OutboundConnectionUpgrade` traits.
//!
//! Keeping primitives separate from transport integration lets us
//! audit, test, and fuzz the cryptographic core in isolation.
//!
//! # Protocol overview
//!
//! Authenticated handshake in 1.5 round-trips:
//!
//! ```text
//!   INITIATOR                                    RESPONDER
//!   gen ephemeral Kyber keypair (sk, pk)
//!   t1 = H(MAGIC || v || pk || id_pk_i || nonce)
//!   sig_i = MLDSA_sign(id_sk_i, t1)
//!   ──── HandshakeInit { pk, id_pk_i, nonce, sig_i } ──>
//!                                                verify sig_i w/ id_pk_i
//!                                                (ss, ct) = Kyber_enc(pk)
//!                                                t2 = H(t1 || ct || id_pk_r)
//!                                                sig_r = MLDSA_sign(id_sk_r, t2)
//!                                                derive session keys (ss, t2)
//!   <─── HandshakeResp { ct, id_pk_r, sig_r } ────
//!   verify sig_r w/ id_pk_r
//!   ss = Kyber_dec(sk, ct)
//!   derive session keys (ss, t2)
//!   confirm_i = HMAC(k_conf, t2 || "i")
//!   ────── SessionConfirm { confirm_i } ──────>
//!                                                verify confirm_i
//!                                                confirm_r = HMAC(k_conf, t2 || "r")
//!   <───── SessionConfirm { confirm_r } ─────
//!   verify confirm_r
//!   [session established]
//! ```
//!
//! # Security properties claimed
//!
//! - PQ confidentiality of session keys: Kyber768 KEM
//! - PQ authentication of peer identities: ML-DSA-65 signatures
//! - Forward secrecy w.r.t. identity keys: ephemeral Kyber keypair per session
//! - Replay protection of handshakes: 32-byte initiator nonce, transcript-bound
//! - Transcript integrity: SHA3-256 over all handshake fields
//! - Session nonce non-reuse: u64 monotonic counter; refuses to overflow
//! - In-session replay/reorder: rx counter must advance monotonically
//! - Constant-time confirmation check via subtle::ConstantTimeEq
//!
//! # Security properties NOT claimed
//!
//! - Side-channel resistance of pqcrypto-kyber (KyberSlash was patched in
//!   upstream reference code Dec 2023; this crate may or may not track it).
//! - Post-compromise security within a session (no ratcheting).
//! - Traffic analysis resistance (no padding; message sizes leak).
//! - Formal proof of handshake security. No third-party audit.

pub mod stream;
pub mod upgrade;

use pqcrypto_kyber::kyber768;
#[allow(unused_imports)]
use pqcrypto_traits::kem::{PublicKey, SharedSecret, Ciphertext};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::{Sha3_256, Digest};
use subtle::ConstantTimeEq;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

use crate::crypto;

// ── Constants ───────────────────────────────────────────────────────────────

/// Protocol version for the PQ transport.
pub const PQ_PROTOCOL_VERSION: u8 = 1;

/// Domain-separation magic mixed into the initiator transcript hash.
pub const DOMAIN_MAGIC: &[u8] = b"BLOCH-PQ-v1-handshake";

/// HKDF label for the initiator→responder stream key.
pub const LABEL_I2R: &[u8] = b"BLOCH-PQ-v1 i->r stream";
/// HKDF label for the responder→initiator stream key.
pub const LABEL_R2I: &[u8] = b"BLOCH-PQ-v1 r->i stream";
/// HKDF label for the session confirmation key.
pub const LABEL_CONFIRM: &[u8] = b"BLOCH-PQ-v1 confirm";

/// Kyber768 public key size (FIPS 203).
pub const KYBER768_PK_SIZE: usize = 1184;
/// Kyber768 ciphertext size (FIPS 203).
pub const KYBER768_CT_SIZE: usize = 1088;
/// Peer-identity public-key size. Sprint B6b: identity signatures now use the
/// hybrid Falcon-1024 ‖ ML-DSA-65 scheme (via `crypto::sign`/`verify`), so the
/// identity pubkey is the hybrid pubkey (ML-DSA 1952 ‖ Falcon 1793 = 3745).
pub const MLDSA65_PK_SIZE: usize = crate::core::PUBKEY_SIZE;
/// Hybrid identity signature size (upper bound; Falcon is variable). Not
/// length-checked on the handshake path — `crypto::verify` validates it.
pub const MLDSA65_SIG_SIZE: usize = crate::core::SIG_SIZE;

/// Size of stream cipher keys (ChaCha20-Poly1305: 256 bits).
pub const STREAM_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size (96 bits).
pub const NONCE_SIZE: usize = 12;
/// Poly1305 AEAD tag size (128 bits).
pub const TAG_SIZE: usize = 16;

/// Handshake nonce size (prevents replay of full handshakes).
pub const HANDSHAKE_NONCE_SIZE: usize = 32;
/// Transcript hash size (SHA3-256).
pub const TRANSCRIPT_SIZE: usize = 32;
/// Confirmation MAC size (HMAC-SHA256 truncated).
pub const CONFIRM_MAC_SIZE: usize = 32;

// ── Wire messages ───────────────────────────────────────────────────────────

/// Initiator's first message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub version:     u8,
    pub kyber_pk:    Vec<u8>,
    pub identity_pk: Vec<u8>,
    pub nonce:       [u8; HANDSHAKE_NONCE_SIZE],
    pub signature:   Vec<u8>,
}

/// Responder's reply.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeResp {
    pub ciphertext:  Vec<u8>,
    pub identity_pk: Vec<u8>,
    pub signature:   Vec<u8>,
}

/// Session confirmation: each party sends after key derivation, verifies
/// the other's, then declares the session established.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionConfirm {
    pub mac: [u8; CONFIRM_MAC_SIZE],
}

// ── Transcript hashing ──────────────────────────────────────────────────────

/// t1 = SHA3-256(MAGIC || v || kyber_pk || id_pk_i || nonce)
fn transcript_t1(
    version:  u8,
    kyber_pk: &[u8],
    id_pk_i:  &[u8],
    nonce:    &[u8; HANDSHAKE_NONCE_SIZE],
) -> [u8; TRANSCRIPT_SIZE] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_MAGIC);
    h.update([version]);
    h.update(kyber_pk);
    h.update(id_pk_i);
    h.update(nonce);
    h.finalize().into()
}

/// t2 = SHA3-256(t1 || ciphertext || id_pk_r)
fn transcript_t2(
    t1:         &[u8; TRANSCRIPT_SIZE],
    ciphertext: &[u8],
    id_pk_r:    &[u8],
) -> [u8; TRANSCRIPT_SIZE] {
    let mut h = Sha3_256::new();
    h.update(t1);
    h.update(ciphertext);
    h.update(id_pk_r);
    h.finalize().into()
}

// ── Key derivation ──────────────────────────────────────────────────────────

/// Derive (i→r key, r→i key, confirmation key) from Kyber shared secret.
/// Uses HKDF-SHA256 with t2 as salt to bind keys to the full transcript,
/// and distinct labels to ensure domain separation.
fn derive_session_keys(
    shared_secret: &[u8],
    t2:            &[u8; TRANSCRIPT_SIZE],
) -> (
    [u8; STREAM_KEY_SIZE],
    [u8; STREAM_KEY_SIZE],
    [u8; STREAM_KEY_SIZE],
) {
    let hkdf = Hkdf::<Sha256>::new(Some(t2), shared_secret);
    let mut k_i2r  = [0u8; STREAM_KEY_SIZE];
    let mut k_r2i  = [0u8; STREAM_KEY_SIZE];
    let mut k_conf = [0u8; STREAM_KEY_SIZE];
    hkdf.expand(LABEL_I2R,     &mut k_i2r).expect("HKDF expand i2r");
    hkdf.expand(LABEL_R2I,     &mut k_r2i).expect("HKDF expand r2i");
    hkdf.expand(LABEL_CONFIRM, &mut k_conf).expect("HKDF expand confirm");
    (k_i2r, k_r2i, k_conf)
}

/// HMAC-SHA256(confirm_key, t2 || role), truncated to CONFIRM_MAC_SIZE.
fn confirm_mac(
    confirm_key: &[u8; STREAM_KEY_SIZE],
    t2:          &[u8; TRANSCRIPT_SIZE],
    role:        &[u8],
) -> [u8; CONFIRM_MAC_SIZE] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(confirm_key).expect("HMAC any key size");
    mac.update(t2);
    mac.update(role);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; CONFIRM_MAC_SIZE];
    result.copy_from_slice(&out[..CONFIRM_MAC_SIZE]);
    result
}

// ── Session keys (zeroized on drop) ─────────────────────────────────────────

/// Completed session state. Drops zeroize both keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub tx_key: [u8; STREAM_KEY_SIZE],
    pub rx_key: [u8; STREAM_KEY_SIZE],
    #[zeroize(skip)]
    pub is_initiator: bool,
}

// ── Initiator ───────────────────────────────────────────────────────────────

/// State held by the initiator between `begin()` and `finish()`.
pub struct Initiator {
    kyber_sk:    kyber768::SecretKey,
    /// Transcript hash t1, needed to re-derive t2 in finish().
    t1:          [u8; TRANSCRIPT_SIZE],
}

/// Result of `Initiator::finish()`: session keys + the material needed to
/// verify the responder's confirmation MAC.
pub struct InitiatorCompleted {
    pub keys:        SessionKeys,
    pub my_confirm:  SessionConfirm,
    /// The derived confirmation key — caller uses this to verify the
    /// responder's confirmation message when it arrives.
    pub confirm_key: [u8; STREAM_KEY_SIZE],
    pub t2:          [u8; TRANSCRIPT_SIZE],
}

impl Initiator {
    /// Begin a new handshake. Generates an ephemeral Kyber keypair and
    /// returns the init message to send + state to continue with.
    pub fn begin(
        identity_sk: &[u8],
        identity_pk: &[u8],
    ) -> Result<(Self, HandshakeInit), TransportError> {
        if identity_pk.len() != MLDSA65_PK_SIZE {
            return Err(TransportError::InvalidPublicKey);
        }

        let (kpk, ksk) = kyber768::keypair();
        let kyber_pk = kpk.as_bytes().to_vec();

        let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);

        let t1 = transcript_t1(PQ_PROTOCOL_VERSION, &kyber_pk, identity_pk, &nonce);

        let signature = crypto::sign(identity_sk, &t1)
            .map_err(|_| TransportError::SigningFailed)?;

        let msg = HandshakeInit {
            version:     PQ_PROTOCOL_VERSION,
            kyber_pk,
            identity_pk: identity_pk.to_vec(),
            nonce,
            signature,
        };
        let state = Initiator { kyber_sk: ksk, t1 };
        Ok((state, msg))
    }

    /// Process the responder's reply. Completes Kyber decapsulation,
    /// derives session keys, and prepares our confirmation MAC.
    ///
    /// `pin` — optional identity pinning. If Some(pk), the responder's
    /// identity_pk must match `pk` (constant-time compare). Useful when
    /// the initiator has out-of-band knowledge of who it should be talking
    /// to; prevents silent MITM where an attacker has their own valid
    /// identity. If None, any well-formed identity is accepted.
    pub fn finish(
        self,
        resp: &HandshakeResp,
        pin:  Option<&[u8]>,
    ) -> Result<InitiatorCompleted, TransportError> {
        // Structural sanity.
        if resp.ciphertext.len() != KYBER768_CT_SIZE {
            return Err(TransportError::InvalidCiphertext);
        }
        if resp.identity_pk.len() != MLDSA65_PK_SIZE {
            return Err(TransportError::InvalidPublicKey);
        }

        // Pinning (constant-time compare to avoid identity-guessing timing).
        if let Some(expected) = pin {
            if !bool::from(resp.identity_pk.ct_eq(expected)) {
                return Err(TransportError::IdentityMismatch);
            }
        }

        // Compute t2 and verify responder's signature.
        let t2 = transcript_t2(&self.t1, &resp.ciphertext, &resp.identity_pk);
        if !crypto::verify(&resp.identity_pk, &t2, &resp.signature) {
            return Err(TransportError::BadResponderSignature);
        }

        // Kyber decapsulate.
        let ct = kyber768::Ciphertext::from_bytes(&resp.ciphertext)
            .map_err(|_| TransportError::InvalidCiphertext)?;
        let ss = kyber768::decapsulate(&ct, &self.kyber_sk);

        let (k_i2r, k_r2i, k_conf) = derive_session_keys(ss.as_bytes(), &t2);
        let my_confirm = confirm_mac(&k_conf, &t2, b"i");

        let keys = SessionKeys {
            tx_key: k_i2r,
            rx_key: k_r2i,
            is_initiator: true,
        };

        Ok(InitiatorCompleted {
            keys,
            my_confirm: SessionConfirm { mac: my_confirm },
            confirm_key: k_conf,
            t2,
        })
    }
}

// ── Responder ───────────────────────────────────────────────────────────────

/// Intermediate state on the responder's side: has derived session keys
/// but is awaiting the initiator's confirmation before exposing them.
pub struct PendingResponder {
    confirm_key: [u8; STREAM_KEY_SIZE],
    t2:          [u8; TRANSCRIPT_SIZE],
    keys:        Option<SessionKeys>,
}

impl PendingResponder {
    /// Process the initiator's init message. Verifies the signature,
    /// performs Kyber encapsulation, derives keys, signs t2.
    pub fn respond(
        init:        &HandshakeInit,
        identity_sk: &[u8],
        identity_pk: &[u8],
    ) -> Result<(Self, HandshakeResp), TransportError> {
        if init.version != PQ_PROTOCOL_VERSION {
            return Err(TransportError::UnsupportedVersion(init.version));
        }
        if init.kyber_pk.len() != KYBER768_PK_SIZE {
            return Err(TransportError::InvalidPublicKey);
        }
        if init.identity_pk.len() != MLDSA65_PK_SIZE {
            return Err(TransportError::InvalidPublicKey);
        }
        if identity_pk.len() != MLDSA65_PK_SIZE {
            return Err(TransportError::InvalidPublicKey);
        }

        // Recompute t1 and verify initiator's signature.
        let t1 = transcript_t1(init.version, &init.kyber_pk, &init.identity_pk, &init.nonce);
        if !crypto::verify(&init.identity_pk, &t1, &init.signature) {
            return Err(TransportError::BadInitiatorSignature);
        }

        // Kyber encapsulate against the initiator's ephemeral pk.
        let kpk = kyber768::PublicKey::from_bytes(&init.kyber_pk)
            .map_err(|_| TransportError::InvalidPublicKey)?;
        let (ss, ct) = kyber768::encapsulate(&kpk);
        let ciphertext = ct.as_bytes().to_vec();

        let t2 = transcript_t2(&t1, &ciphertext, identity_pk);
        let signature = crypto::sign(identity_sk, &t2)
            .map_err(|_| TransportError::SigningFailed)?;

        let (k_i2r, k_r2i, k_conf) = derive_session_keys(ss.as_bytes(), &t2);

        let keys = SessionKeys {
            // Responder perspective: receives i→r, sends r→i.
            rx_key:       k_i2r,
            tx_key:       k_r2i,
            is_initiator: false,
        };
        let resp = HandshakeResp {
            ciphertext,
            identity_pk: identity_pk.to_vec(),
            signature,
        };
        Ok((Self { confirm_key: k_conf, t2, keys: Some(keys) }, resp))
    }

    /// Verify the initiator's confirmation MAC. On success, yield the
    /// session keys and our confirmation to send back.
    pub fn accept_confirmation(
        mut self,
        initiator_confirm: &SessionConfirm,
    ) -> Result<(SessionKeys, SessionConfirm), TransportError> {
        let expected = confirm_mac(&self.confirm_key, &self.t2, b"i");
        if !bool::from(expected.ct_eq(&initiator_confirm.mac)) {
            return Err(TransportError::BadConfirmation);
        }
        let my_confirm = confirm_mac(&self.confirm_key, &self.t2, b"r");
        let keys = self.keys.take().ok_or(TransportError::StateError)?;
        Ok((keys, SessionConfirm { mac: my_confirm }))
    }
}

impl SessionKeys {
    /// Verify the responder's confirmation MAC (called by the initiator
    /// after it receives the responder's confirm). Uses the confirm_key
    /// and t2 stashed in InitiatorCompleted.
    pub fn verify_responder_confirmation(
        confirm_key:       &[u8; STREAM_KEY_SIZE],
        t2:                &[u8; TRANSCRIPT_SIZE],
        responder_confirm: &SessionConfirm,
    ) -> Result<(), TransportError> {
        let expected = confirm_mac(confirm_key, t2, b"r");
        if !bool::from(expected.ct_eq(&responder_confirm.mac)) {
            return Err(TransportError::BadConfirmation);
        }
        Ok(())
    }
}

// ── Stream cipher ───────────────────────────────────────────────────────────

/// Sender half of a one-directional cipher stream.
pub struct TxStream {
    key:     [u8; STREAM_KEY_SIZE],
    counter: u64,
}

impl TxStream {
    pub fn new(key: [u8; STREAM_KEY_SIZE]) -> Self {
        Self { key, counter: 0 }
    }

    /// Encrypt one plaintext message. Returns ciphertext with appended tag.
    /// The nonce is derived from the monotonic counter — not sent on wire.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let nonce = counter_to_nonce(self.counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ct = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plaintext, aad },
        ).map_err(|_| TransportError::EncryptFailed)?;
        self.counter += 1;
        Ok(ct)
    }

    pub fn counter(&self) -> u64 { self.counter }
}

/// Receiver half. Enforces monotonic counter — rejects replay + reorder.
pub struct RxStream {
    key:          [u8; STREAM_KEY_SIZE],
    next_counter: u64,
}

impl RxStream {
    pub fn new(key: [u8; STREAM_KEY_SIZE]) -> Self {
        Self { key, next_counter: 0 }
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.next_counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let nonce = counter_to_nonce(self.next_counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let pt = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: ciphertext, aad },
        ).map_err(|_| TransportError::DecryptFailed)?;
        self.next_counter += 1;
        Ok(pt)
    }

    pub fn counter(&self) -> u64 { self.next_counter }
}

/// Derive a 96-bit nonce from a u64 counter.
/// Layout: 4 zero bytes (reserved for future direction/subprotocol bits)
/// + 8 big-endian counter bytes.
fn counter_to_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

// ── Framing (length-prefixed) ───────────────────────────────────────────────

/// Seal a message with length-prefixed framing for writing to a byte stream.
/// Layout: 4-byte BE ciphertext length || ciphertext (incl. 16-byte tag).
/// The length prefix is bound into the AEAD AAD, so truncation attacks fail.
pub fn frame_seal(tx: &mut TxStream, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    let ct = tx.seal(payload, &(payload.len() as u32).to_be_bytes())?;
    let mut out = Vec::with_capacity(4 + ct.len());
    out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse one framed message. Returns (bytes consumed, plaintext).
/// Returns IncompleteFrame if the buffer lacks a full frame — caller reads
/// more bytes and retries.
pub fn frame_open(rx: &mut RxStream, buf: &[u8]) -> Result<(usize, Vec<u8>), TransportError> {
    if buf.len() < 4 { return Err(TransportError::IncompleteFrame); }
    let ct_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + ct_len { return Err(TransportError::IncompleteFrame); }
    let ct = &buf[4..4 + ct_len];
    let plaintext_len = ct_len.checked_sub(TAG_SIZE).ok_or(TransportError::DecryptFailed)?;
    let pt = rx.open(ct, &(plaintext_len as u32).to_be_bytes())?;
    Ok((4 + ct_len, pt))
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("encryption failed")]                                     EncryptFailed,
    #[error("decryption failed (bad key, tag, or counter)")]          DecryptFailed,
    #[error("invalid ciphertext structure")]                          InvalidCiphertext,
    #[error("invalid public key")]                                    InvalidPublicKey,
    #[error("signing failed (bad identity secret key)")]              SigningFailed,
    #[error("bad initiator signature on handshake init")]             BadInitiatorSignature,
    #[error("bad responder signature on handshake resp")]             BadResponderSignature,
    #[error("bad session confirmation MAC")]                          BadConfirmation,
    #[error("responder identity does not match pinned value")]        IdentityMismatch,
    #[error("unsupported protocol version: {0}")]                     UnsupportedVersion(u8),
    #[error("stream nonce counter exhausted")]                        CounterExhausted,
    #[error("incomplete frame (need more bytes)")]                    IncompleteFrame,
    #[error("internal state error")]                                  StateError,
}
