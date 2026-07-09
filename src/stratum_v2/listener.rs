// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 TCP listener.
//
// Flow per connection (Sprint 8 complete):
//   1. TCP accept
//   2. Enforce session cap (drop connection if exceeded)
//   3. Perform NOISE_NX handshake (src/stratum_v2/handshake.rs)
//   4. Hand off to Sv2Session state machine (src/stratum_v2/session.rs)
//   5. Session either reaches Live, errors, or times out
//   6. Session drop decrements session counter
//
// All failures in steps 3-5 just log and close — one bad initiator
// never affects other sessions.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use secp256k1::{Secp256k1, SecretKey};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::stratum::TipChanged;

use crate::stratum::{TemplateContext, submit::AcceptBlockFn};
use super::handshake::{perform_handshake, DEFAULT_CERT_VALIDITY_SECS, DEFAULT_HANDSHAKE_TIMEOUT};
use super::session::Sv2Session;
use super::{Sv2Config, Sv2StaticKeypair};

pub async fn run(
    config:       Sv2Config,
    authority_kp: Sv2StaticKeypair,
    tip_rx:       broadcast::Receiver<TipChanged>,
    node_ctx:     Option<Arc<TemplateContext>>,
    accept_block: Option<Arc<AcceptBlockFn>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    log::info!("stratum_v2: listening on {}", config.bind_addr);

    let session_count = Arc::new(AtomicUsize::new(0));
    let mut next_session_id: u64 = 1;

    // Pre-compute authority key bytes once (they don't change over the
    // lifetime of the listener).
    let auth_pub_bytes = authority_pubkey_x_bytes(&authority_kp);
    let auth_sec_bytes: [u8; 32] = *authority_kp.secret.as_ref();

    loop {
        let (mut socket, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                log::error!("stratum_v2: accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let current = session_count.load(Ordering::Relaxed);
        if current >= config.max_sessions {
            log::warn!(
                "stratum_v2: rejecting {} - session cap {} reached",
                peer_addr, config.max_sessions
            );
            drop(socket);
            continue;
        }

        session_count.fetch_add(1, Ordering::Relaxed);
        let id = next_session_id;
        next_session_id += 1;

        let session_count_task = session_count.clone();
        let auth_pub = auth_pub_bytes;
        let auth_sec = auth_sec_bytes;

        // Each session gets its own receiver — resubscribe() preserves
        // the broadcast lag semantics (new receiver starts at current head).
        let session_tip_rx = tip_rx.resubscribe();
        let session_node_ctx = node_ctx.clone();
        let session_accept_block = accept_block.clone();

        tokio::spawn(async move {
            // Step 3: handshake
            let codec = match perform_handshake(
                &mut socket,
                &auth_pub,
                &auth_sec,
                DEFAULT_CERT_VALIDITY_SECS,
                DEFAULT_HANDSHAKE_TIMEOUT,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    log::warn!(
                        "stratum_v2: session {} from {} handshake failed: {}",
                        id, peer_addr, e
                    );
                    session_count_task.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };

            log::info!(
                "stratum_v2: session {} from {} handshake OK",
                id, peer_addr
            );

            // Step 4: session state machine
            let session = Sv2Session::new(
                id,
                peer_addr,
                codec,
                session_count_task,
                session_tip_rx,
                session_node_ctx,
                session_accept_block,
            );
            session.run(socket).await;
            // counter decremented by Sv2Session Drop impl
        });
    }
}

/// Derive the 32-byte x-only authority public key from our
/// Sv2StaticKeypair secret. The noise_sv2::Responder wants the x-only
/// serialization, not the full compressed point.
fn authority_pubkey_x_bytes(keypair: &Sv2StaticKeypair) -> [u8; 32] {
    let secp = Secp256k1::new();
    let sk_bytes: [u8; 32] = *keypair.secret.as_ref();
    let sk = SecretKey::from_slice(&sk_bytes).expect("valid secret");
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let (xonly, _parity) = pk.x_only_public_key();
    xonly.serialize()
}
