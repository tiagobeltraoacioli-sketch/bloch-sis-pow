// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 Pool role implementation.
// GIP-0003: Mining Protocol + Template Distribution Protocol.
//
// Parallel implementation to crate::stratum (V1). Both V1 and V2
// subscribe to the same TipChanged broadcast channel produced by the
// node's DAG tip-update path. Their wire protocols and session state
// machines are fully independent.
//
// Sprint 7 (this commit): wire skeleton only. Empty listener binds
// port 3334 and drops incoming connections after logging peer address.
// NOISE handshake and SetupConnection arrive in Sprint 8.
//
// Uses SRI umbrella crate `stratum_core` which re-exports all
// low-level SV2 crates. Using the umbrella avoids the
// "could not find binary_sv2 in super" compile error that affects
// direct crates.io consumption of SRI library crates.

pub mod config;
pub mod keypair;
pub mod cert;
pub mod handshake;
pub mod session;
pub mod listener;

#[cfg(test)]
mod tests;

use crate::stratum::TipChanged;
use tokio::sync::broadcast;

pub use config::Sv2Config;
pub use keypair::Sv2StaticKeypair;

// Re-export stratum_core's modules so Sprint 8+ can reference them
// as crate::stratum_v2::binary_sv2 etc. without importing stratum_core
// directly everywhere.
#[allow(unused_imports)]
pub(crate) use stratum_core::{
    binary_sv2,
    codec_sv2,
    common_messages_sv2,
    framing_sv2,
    mining_sv2,
    noise_sv2,
    template_distribution_sv2,
};

pub async fn run(
    config:     Sv2Config,
    tip_rx:     broadcast::Receiver<TipChanged>,
) -> std::io::Result<()> {
    let keypair = Sv2StaticKeypair::load_or_generate(&config.cert_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    log::info!(
        "stratum_v2: binding {} max_sessions={} cert_fingerprint={}",
        config.bind_addr, config.max_sessions, keypair.fingerprint_hex()
    );

    let node_ctx     = config.node_ctx.clone();
    let accept_block = config.accept_block.clone();
    listener::run(config, keypair, tip_rx, node_ctx, accept_block).await
}

#[derive(Debug, thiserror::Error)]
pub enum Sv2Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("keypair: {0}")]
    Keypair(String),

    #[error("too many sessions (limit: {0})")]
    SessionLimit(usize),
}
pub mod setup_connection;
pub mod setup_connection_sri;
pub mod setup_connection_decode;
pub mod setup_connection_encode;
pub mod channel;
pub mod open_channel_decode;
pub mod open_channel_encode;
pub mod mining_job;
pub mod submit_shares;
pub mod submit_responses;
pub mod block_reconstruct;
pub mod template_adapter;
