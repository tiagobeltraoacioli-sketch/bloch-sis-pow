// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 runtime configuration. Mirrors the shape of
// crate::stratum::StratumConfig for symmetry.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::stratum::{TemplateContext, submit::AcceptBlockFn};
use super::Sv2Error;

pub const DEFAULT_SV2_PORT: u16 = 3334;
pub const DEFAULT_MAX_SESSIONS: usize = 500;

pub struct Sv2Config {
    pub bind_addr:    SocketAddr,
    pub max_sessions: usize,
    pub cert_path:    PathBuf,
    /// DAG / Storage / Mempool handles required to build templates.
    /// None for unit tests that don't exercise template generation.
    /// Sprint 10-delta: plumbing only — consumer arrives in a later etapa.
    pub node_ctx:     Option<Arc<TemplateContext>>,
    /// Callback into the node's accept_block path. Invoked when a V2 miner
    /// submits a share that also meets the block target. Shared by reference
    /// (Arc) with the V1 StratumConfig.accept_block — both protocols route
    /// blocks through the same consensus pipeline.
    /// Sprint 10-epsilon Phase 1: plumbing only — consumer arrives in ε.5.
    pub accept_block: Option<Arc<AcceptBlockFn>>,
}

impl std::fmt::Debug for Sv2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sv2Config")
            .field("bind_addr", &self.bind_addr)
            .field("max_sessions", &self.max_sessions)
            .field("cert_path", &self.cert_path)
            .field("node_ctx", &self.node_ctx.is_some())
            .field("accept_block", &self.accept_block.is_some())
            .finish()
    }
}

impl Sv2Config {
    pub fn new(
        bind_addr:    SocketAddr,
        max_sessions: usize,
        cert_path:    PathBuf,
    ) -> Result<Self, Sv2Error> {
        if max_sessions == 0 {
            return Err(Sv2Error::Config("max_sessions must be > 0".to_string()));
        }
        if max_sessions > 10_000 {
            return Err(Sv2Error::Config(format!(
                "max_sessions {} exceeds safety cap of 10000",
                max_sessions
            )));
        }
        Ok(Self { bind_addr, max_sessions, cert_path, node_ctx: None, accept_block: None })
    }

    pub fn default_for_test() -> Self {
        Self {
            bind_addr:    "127.0.0.1:0".parse().unwrap(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            cert_path:    PathBuf::from("/tmp/bloch-sv2-test-key.json"),
            node_ctx:     None,
            accept_block: None,
        }
    }
}
