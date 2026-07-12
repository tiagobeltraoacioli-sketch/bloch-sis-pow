// SPDX-License-Identifier: MIT OR Apache-2.0
//! A real blocking JSON-RPC transport over `ureq`, behind the `http` feature.
//!
//! Off by default so the crate builds fully offline. Enable with
//! `--features http` to talk to a live Bloch node's `POST /` on port `16210`
//! (roadmap §1.2).
//!
//! ```no_run
//! # #[cfg(feature = "http")] {
//! use bloch_anchoring::http::HttpTransport;
//! use bloch_anchoring::rpc::BlochRpc;
//!
//! let transport = HttpTransport::new("http://127.0.0.1:16210")
//!     .with_api_key("optional-x-api-key"); // writes may require it (roadmap §1.2)
//! let rpc = BlochRpc::new(transport);
//! let tip = rpc.get_block_count().unwrap();
//! # let _ = tip;
//! # }
//! ```

use crate::error::{AnchorError, Result};
use crate::rpc::RpcTransport;
use serde_json::Value;

/// Blocking HTTP JSON-RPC transport.
pub struct HttpTransport {
    url: String,
    api_key: Option<String>,
    agent: ureq::Agent,
}

impl HttpTransport {
    /// New transport pointed at a node URL (e.g. `http://127.0.0.1:16210`).
    pub fn new(url: impl Into<String>) -> Self {
        HttpTransport {
            url: url.into(),
            api_key: None,
            agent: ureq::Agent::new(),
        }
    }

    /// Attach an `X-API-Key` (optional shared secret for rate-limited writes).
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }
}

impl RpcTransport for HttpTransport {
    fn request(&self, body: &str) -> Result<Value> {
        let mut req = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json");
        if let Some(key) = &self.api_key {
            req = req.set("X-API-Key", key);
        }
        let resp = req
            .send_string(body)
            .map_err(|e| AnchorError::Transport(e.to_string()))?;
        let text = resp
            .into_string()
            .map_err(|e| AnchorError::Transport(e.to_string()))?;
        serde_json::from_str(&text)
            .map_err(|e| AnchorError::Transport(format!("bad response json: {e}")))
    }
}
