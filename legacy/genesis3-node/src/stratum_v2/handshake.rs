// SPDX-License-Identifier: MIT OR Apache-2.0
//
// NOISE_NX handshake Responder for the Stratum V2 Pool role.
//
// The Responder (pool side) waits for the Initiator's Act 1 message
// (64-byte EllSwift-encoded ephemeral public key), then produces Act 2
// (234 bytes: responder ephemeral + encrypted static + encrypted
// SIGNATURE_NOISE_MESSAGE), and transitions into transport mode.
//
// The heavy crypto (ECDH, AEAD, Schnorr sig over cert, Drop zeroization)
// is handled by `stratum_core::noise_sv2::Responder`, which implements
// the canonical SV2 spec chapter 4. This module is the tokio async
// wrapper that feeds bytes to/from a TcpStream and enforces timeouts.

use std::time::Duration;

use stratum_core::noise_sv2::{
    NoiseCodec, Responder,
    ELLSWIFT_ENCODING_SIZE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::Sv2Error;

/// Default handshake timeout. Per SV2 spec, an initiator that doesn't
/// finish the handshake within a few seconds is either malicious or
/// on a broken network. Either way we don't want to hold a session slot.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default certificate validity window when generating the responder's
/// internal SIGNATURE_NOISE_MESSAGE. Per GIP-0003, default 30 days.
pub const DEFAULT_CERT_VALIDITY_SECS: u32 = 30 * 86400;

/// Size of the Act 1 message sent by the initiator.
/// Just the EllSwift-encoded ephemeral public key, unencrypted.
pub const ACT1_SIZE: usize = ELLSWIFT_ENCODING_SIZE; // 64

/// Size of the Act 2 message sent back by the responder.
/// See SV2 spec 4.5.2: ephemeral + encrypted static + encrypted signature.
pub const ACT2_SIZE: usize = 234;

/// Perform the NOISE_NX handshake as the Responder (pool role).
///
/// - Reads 64 bytes from `stream` (the initiator's ephemeral pubkey)
/// - Runs `Responder::step_1` to produce 234 bytes
/// - Writes those 234 bytes back on `stream`
/// - Returns the `NoiseCodec` ready for transport-mode encryption/decryption
///
/// The `authority_keypair` is the pool's long-lived identity key. The
/// responder internally generates a per-session static keypair, signs a
/// certificate binding it to the authority, and ships that certificate
/// inside Act 2's SIGNATURE_NOISE_MESSAGE field.
///
/// `timeout_duration` bounds the total time spent on both reads and
/// writes. If either the initiator is slow or the network is hostile,
/// we abort and close the connection.
pub async fn perform_handshake(
    stream:            &mut TcpStream,
    authority_public:  &[u8; 32],
    authority_secret:  &[u8; 32],
    cert_validity:     u32,
    timeout_duration:  Duration,
) -> Result<NoiseCodec, Sv2Error> {
    timeout(
        timeout_duration,
        perform_handshake_inner(stream, authority_public, authority_secret, cert_validity),
    )
    .await
    .map_err(|_| Sv2Error::Keypair("handshake timeout".to_string()))?
}

async fn perform_handshake_inner(
    stream:            &mut TcpStream,
    authority_public:  &[u8; 32],
    authority_secret:  &[u8; 32],
    cert_validity:     u32,
) -> Result<NoiseCodec, Sv2Error> {
    // ---- Act 1: read initiator's ephemeral pubkey (64 bytes) ----
    let mut act1 = [0u8; ACT1_SIZE];
    stream
        .read_exact(&mut act1)
        .await
        .map_err(|e| Sv2Error::Io(e))?;

    // ---- Build responder and run step_1 ----
    // Uses from_authority_kp which takes raw bytes, avoiding the
    // secp256k1-0.28 vs secp256k1-0.29 version conflict.
    let cert_validity_duration = std::time::Duration::from_secs(cert_validity as u64);
    let mut responder = Responder::from_authority_kp(
        authority_public,
        authority_secret,
        cert_validity_duration,
    )
    .map_err(|e| Sv2Error::Keypair(format!("noise responder init: {:?}", e)))?;

    let (act2, codec) = responder
        .step_1(act1)
        .map_err(|e| Sv2Error::Keypair(format!("noise step_1 failed: {:?}", e)))?;

    // ---- Act 2: write 234-byte response back ----
    stream
        .write_all(&act2)
        .await
        .map_err(|e| Sv2Error::Io(e))?;

    stream.flush().await.map_err(|e| Sv2Error::Io(e))?;

    Ok(codec)
}
