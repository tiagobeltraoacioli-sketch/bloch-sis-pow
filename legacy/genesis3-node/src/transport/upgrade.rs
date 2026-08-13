//! Sprint A2 Phase 2 — libp2p upgrade integration.
//!
//! Wraps the Sprint A1 post-quantum primitives + Sprint A2 Phase 1 stream
//! adapter into a libp2p-compatible security upgrade.
//!
//! # Hybrid post-quantum model
//!
//! This upgrade uses:
//!
//! - **Kyber768 KEM** for session key establishment (post-quantum
//!   confidentiality: "harvest now, decrypt later" resistant).
//! - **libp2p identity signatures** (Ed25519 in practice, whatever the
//!   node's keypair is) for authenticating peer identities during the
//!   handshake.
//! - **ChaCha20-Poly1305** for the resulting session cipher, with the
//!   monotonic-counter nonce scheme from Sprint A1.
//!
//! This matches the "hybrid PQ" pattern deployed by AWS/Cloudflare/Google
//! in TLS 1.3 — PQ for the parts where retrospective attacks matter,
//! classical for the parts where only real-time forgery matters.
//!
//! ML-DSA-65 post-quantum signatures remain in use at the consensus layer
//! (blocks, transactions, addresses). This transport upgrade and the
//! consensus signatures are orthogonal.
//!
//! # Handshake
//!
//! ```text
//!     INITIATOR                                    RESPONDER
//!     generate ephemeral Kyber keypair (sk, pk)
//!     t1 = H(MAGIC || v || kyber_pk || id_pk_i || nonce)
//!     sig_i = libp2p_sign(id_sk_i, t1)
//!     ──── HandshakeInitLp { kyber_pk, id_pk_i_pb, nonce, sig_i } ──>
//!                                                verify sig_i w/ id_pk_i
//!                                                (ss, ct) = Kyber_enc(kyber_pk)
//!                                                t2 = H(t1 || ct || id_pk_r)
//!                                                sig_r = libp2p_sign(id_sk_r, t2)
//!                                                derive session keys (ss, t2)
//!     <───── HandshakeRespLp { ct, id_pk_r_pb, sig_r } ─────
//!     verify sig_r w/ id_pk_r
//!     ss = Kyber_dec(sk, ct)
//!     derive session keys (ss, t2)
//!     [wrap socket in KyberStream; return (peer_id, stream)]
//! ```

use std::pin::Pin;
use std::future::Future;
use std::iter;

use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use libp2p::identity;
use libp2p::PeerId;

use pqcrypto_kyber::kyber768;
#[allow(unused_imports)]
use pqcrypto_traits::kem::{PublicKey as _, SharedSecret as _, Ciphertext as _};

use rand::RngCore;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

use crate::transport::{
    stream::KyberStream,
    TxStream, RxStream,
    DOMAIN_MAGIC, PQ_PROTOCOL_VERSION,
    KYBER768_PK_SIZE, KYBER768_CT_SIZE,
    HANDSHAKE_NONCE_SIZE, STREAM_KEY_SIZE, TRANSCRIPT_SIZE,
    LABEL_I2R, LABEL_R2I,
};
use hkdf::Hkdf;
use sha2::Sha256;

// ── Protocol identifier ─────────────────────────────────────────────────────

/// The multistream-select protocol identifier for this transport.
/// Version 1.0.0: initial hybrid Kyber + libp2p-identity handshake.
pub const KYBER_PROTOCOL_ID: &str = "/bloch/kyber/1.0.0";

/// Maximum serialized handshake message size (defensive bound).
/// Kyber768 pk (1184) + libp2p pubkey (~42 bytes for Ed25519, more for RSA)
/// + nonce (32) + sig (64 for Ed25519, more for others) + bincode overhead.
/// 16 KiB leaves huge headroom and rejects absurd messages.
const MAX_HANDSHAKE_MSG_SIZE: u32 = 16 * 1024;

// ── Wire messages ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct HandshakeInitLp {
    version:             u8,
    kyber_pk:            Vec<u8>,
    /// libp2p `PublicKey::encode_protobuf()` bytes.
    identity_pk_proto:   Vec<u8>,
    nonce:               [u8; HANDSHAKE_NONCE_SIZE],
    /// libp2p signature over transcript hash t1.
    signature:           Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct HandshakeRespLp {
    ciphertext:          Vec<u8>,
    identity_pk_proto:   Vec<u8>,
    signature:           Vec<u8>,
}

// ── Config ──────────────────────────────────────────────────────────────────

/// Security upgrade configuration. Holds the local node's libp2p identity
/// keypair — required for signing handshake transcripts.
#[derive(Clone)]
pub struct KyberConfig {
    keypair: identity::Keypair,
}

impl KyberConfig {
    /// Construct a new config from a libp2p identity keypair. Usually
    /// called via the SwarmBuilder closure.
    pub fn new(keypair: &identity::Keypair) -> Self {
        Self { keypair: keypair.clone() }
    }
}

// ── UpgradeInfo ─────────────────────────────────────────────────────────────

impl UpgradeInfo for KyberConfig {
    type Info = &'static str;
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(KYBER_PROTOCOL_ID)
    }
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum KyberUpgradeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large ({got} bytes, max {max})")]
    MessageTooLarge { got: u32, max: u32 },
    #[error("bincode serialization: {0}")]
    Serialize(String),
    #[error("bincode deserialization: {0}")]
    Deserialize(String),
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid Kyber public key")]
    BadKyberPk,
    #[error("invalid Kyber ciphertext")]
    BadKyberCt,
    #[error("invalid libp2p identity public key: {0}")]
    BadIdentityPk(String),
    #[error("bad initiator signature")]
    BadInitiatorSignature,
    #[error("bad responder signature")]
    BadResponderSignature,
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("transport error: {0}")]
    Transport(#[from] crate::transport::TransportError),
}

// ── Transcript helpers (local to this module — Ed25519/libp2p-sig variant) ──

fn lp_transcript_t1(
    version:     u8,
    kyber_pk:    &[u8],
    id_pk_proto: &[u8],
    nonce:       &[u8; HANDSHAKE_NONCE_SIZE],
) -> [u8; TRANSCRIPT_SIZE] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_MAGIC);
    h.update(b"-libp2p"); // distinguish from Sprint A1 ML-DSA handshake
    h.update([version]);
    h.update(kyber_pk);
    h.update(id_pk_proto);
    h.update(nonce);
    h.finalize().into()
}

fn lp_transcript_t2(
    t1:          &[u8; TRANSCRIPT_SIZE],
    ciphertext:  &[u8],
    id_pk_proto: &[u8],
) -> [u8; TRANSCRIPT_SIZE] {
    let mut h = Sha3_256::new();
    h.update(t1);
    h.update(ciphertext);
    h.update(id_pk_proto);
    h.finalize().into()
}

/// Derive session keys. Same key schedule as Sprint A1 but does not derive
/// a confirmation key (we omit explicit confirmation — first encrypted
/// yamux frame serves as implicit confirmation, matching libp2p Noise XX).
fn lp_derive_session_keys(
    shared_secret: &[u8],
    t2:            &[u8; TRANSCRIPT_SIZE],
) -> ([u8; STREAM_KEY_SIZE], [u8; STREAM_KEY_SIZE]) {
    let hkdf = Hkdf::<Sha256>::new(Some(t2), shared_secret);
    let mut k_i2r = [0u8; STREAM_KEY_SIZE];
    let mut k_r2i = [0u8; STREAM_KEY_SIZE];
    hkdf.expand(LABEL_I2R, &mut k_i2r).expect("HKDF i2r");
    hkdf.expand(LABEL_R2I, &mut k_r2i).expect("HKDF r2i");
    (k_i2r, k_r2i)
}

// ── Wire I/O helpers ────────────────────────────────────────────────────────

/// Write one length-prefixed bincode-encoded message to an async stream.
async fn write_msg<S, T>(stream: &mut S, msg: &T) -> Result<(), KyberUpgradeError>
where
    S: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .map_err(|e| KyberUpgradeError::Serialize(e.to_string()))?;
    if bytes.len() > MAX_HANDSHAKE_MSG_SIZE as usize {
        return Err(KyberUpgradeError::MessageTooLarge {
            got: bytes.len() as u32,
            max: MAX_HANDSHAKE_MSG_SIZE,
        });
    }
    let len_prefix = (bytes.len() as u32).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one length-prefixed bincode-encoded message from an async stream.
async fn read_msg<S, T>(stream: &mut S) -> Result<T, KyberUpgradeError>
where
    S: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_HANDSHAKE_MSG_SIZE {
        return Err(KyberUpgradeError::MessageTooLarge {
            got: len,
            max: MAX_HANDSHAKE_MSG_SIZE,
        });
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    let (msg, _) = bincode::serde::decode_from_slice(&body, bincode::config::standard())
        .map_err(|e| KyberUpgradeError::Deserialize(e.to_string()))?;
    Ok(msg)
}

// ── Outbound upgrade (initiator / dialer) ───────────────────────────────────

impl<T> OutboundConnectionUpgrade<T> for KyberConfig
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = (PeerId, KyberStream<T>);
    type Error  = KyberUpgradeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, mut socket: T, _info: Self::Info) -> Self::Future {
        Box::pin(async move {
            // 1. Generate ephemeral Kyber keypair.
            let (kpk, ksk) = kyber768::keypair();
            let kyber_pk_bytes = kpk.as_bytes().to_vec();

            // 2. Fresh 32-byte nonce.
            let mut nonce = [0u8; HANDSHAKE_NONCE_SIZE];
            rand::rng().fill_bytes(&mut nonce);

            // 3. Encode our identity pubkey as protobuf for the wire.
            let id_pk = self.keypair.public();
            let id_pk_proto = id_pk.encode_protobuf();

            // 4. Compute transcript t1 and sign.
            let t1 = lp_transcript_t1(PQ_PROTOCOL_VERSION, &kyber_pk_bytes, &id_pk_proto, &nonce);
            let signature = self.keypair.sign(&t1)
                .map_err(|e| KyberUpgradeError::SigningFailed(e.to_string()))?;

            // 5. Send HandshakeInitLp.
            let init = HandshakeInitLp {
                version:           PQ_PROTOCOL_VERSION,
                kyber_pk:          kyber_pk_bytes,
                identity_pk_proto: id_pk_proto,
                nonce,
                signature,
            };
            write_msg(&mut socket, &init).await?;

            // 6. Read HandshakeRespLp.
            let resp: HandshakeRespLp = read_msg(&mut socket).await?;

            if resp.ciphertext.len() != KYBER768_CT_SIZE {
                return Err(KyberUpgradeError::BadKyberCt);
            }

            // 7. Verify responder signature.
            let resp_pk = identity::PublicKey::try_decode_protobuf(&resp.identity_pk_proto)
                .map_err(|e| KyberUpgradeError::BadIdentityPk(e.to_string()))?;
            let t2 = lp_transcript_t2(&t1, &resp.ciphertext, &resp.identity_pk_proto);
            if !resp_pk.verify(&t2, &resp.signature) {
                return Err(KyberUpgradeError::BadResponderSignature);
            }

            // 8. Kyber decapsulate → shared secret.
            let ct = kyber768::Ciphertext::from_bytes(&resp.ciphertext)
                .map_err(|_| KyberUpgradeError::BadKyberCt)?;
            let ss = kyber768::decapsulate(&ct, &ksk);

            // 9. Derive session keys.
            let (k_i2r, k_r2i) = lp_derive_session_keys(ss.as_bytes(), &t2);

            // 10. Wrap socket. Initiator: tx=i2r, rx=r2i.
            let stream = KyberStream::new(
                socket,
                TxStream::new(k_i2r),
                RxStream::new(k_r2i),
            );
            let peer_id = resp_pk.to_peer_id();
            Ok((peer_id, stream))
        })
    }
}

// ── Inbound upgrade (responder / listener) ──────────────────────────────────

impl<T> InboundConnectionUpgrade<T> for KyberConfig
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = (PeerId, KyberStream<T>);
    type Error  = KyberUpgradeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, mut socket: T, _info: Self::Info) -> Self::Future {
        Box::pin(async move {
            // 1. Read HandshakeInitLp.
            let init: HandshakeInitLp = read_msg(&mut socket).await?;

            if init.version != PQ_PROTOCOL_VERSION {
                return Err(KyberUpgradeError::UnsupportedVersion(init.version));
            }
            if init.kyber_pk.len() != KYBER768_PK_SIZE {
                return Err(KyberUpgradeError::BadKyberPk);
            }

            // 2. Decode initiator's identity pubkey.
            let init_pk = identity::PublicKey::try_decode_protobuf(&init.identity_pk_proto)
                .map_err(|e| KyberUpgradeError::BadIdentityPk(e.to_string()))?;

            // 3. Verify initiator's signature over t1.
            let t1 = lp_transcript_t1(init.version, &init.kyber_pk, &init.identity_pk_proto, &init.nonce);
            if !init_pk.verify(&t1, &init.signature) {
                return Err(KyberUpgradeError::BadInitiatorSignature);
            }

            // 4. Kyber encapsulate against initiator's ephemeral pk.
            let kpk = kyber768::PublicKey::from_bytes(&init.kyber_pk)
                .map_err(|_| KyberUpgradeError::BadKyberPk)?;
            let (ss, ct) = kyber768::encapsulate(&kpk);
            let ciphertext = ct.as_bytes().to_vec();

            // 5. Encode own pubkey, compute t2, sign.
            let own_pk = self.keypair.public();
            let own_pk_proto = own_pk.encode_protobuf();
            let t2 = lp_transcript_t2(&t1, &ciphertext, &own_pk_proto);
            let signature = self.keypair.sign(&t2)
                .map_err(|e| KyberUpgradeError::SigningFailed(e.to_string()))?;

            // 6. Send HandshakeRespLp.
            let resp = HandshakeRespLp {
                ciphertext,
                identity_pk_proto: own_pk_proto,
                signature,
            };
            write_msg(&mut socket, &resp).await?;

            // 7. Derive session keys.
            let (k_i2r, k_r2i) = lp_derive_session_keys(ss.as_bytes(), &t2);

            // 8. Wrap socket. Responder: rx=i2r, tx=r2i.
            let stream = KyberStream::new(
                socket,
                TxStream::new(k_r2i),
                RxStream::new(k_i2r),
            );
            let peer_id = init_pk.to_peer_id();
            Ok((peer_id, stream))
        })
    }
}
