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
//! let transport = HttpTransport::new("https://node.example.com")
//!     .with_api_key("optional-x-api-key"); // writes may require it (roadmap §1.2)
//! let rpc = BlochRpc::new(transport);
//! let tip = rpc.get_block_count().unwrap();
//! # let _ = tip;
//! # }
//! ```

use crate::error::{AnchorError, Result};
use crate::rpc::RpcTransport;
use serde_json::Value;
use std::{io::Read, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

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
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout_read(Duration::from_secs(10))
                .timeout_write(Duration::from_secs(10))
                .timeout(Duration::from_secs(15))
                // Never forward credentials to a redirect target.
                .redirects(0)
                .build(),
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
        validate_endpoint(&self.url, self.api_key.is_some())?;
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
        if !(200..300).contains(&resp.status()) {
            return Err(AnchorError::Transport("RPC endpoint returned a non-success status".into()));
        }
        let mut bytes = Vec::new();
        resp.into_reader().take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut bytes)
            .map_err(|e| AnchorError::Transport(e.to_string()))?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(AnchorError::Transport("RPC response exceeds 1 MiB".into()));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| AnchorError::Transport(format!("bad response json: {e}")))
    }
}

fn validate_endpoint(endpoint: &str, authenticated: bool) -> Result<()> {
    let url = url::Url::parse(endpoint)
        .map_err(|_| AnchorError::Transport("invalid RPC URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some() {
        return Err(AnchorError::Transport("RPC URL must be HTTP(S), with no embedded credentials".into()));
    }
    if authenticated && url.scheme() != "https" {
        return Err(AnchorError::Transport("API keys require HTTPS".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_credentials_over_plaintext_before_connecting() {
        let transport = HttpTransport::new("http://127.0.0.1:1").with_api_key("secret");
        assert!(transport.request("{}").unwrap_err().to_string().contains("HTTPS"));
        assert!(validate_endpoint("https://node.example.com", true).is_ok());
        assert!(validate_endpoint("http://127.0.0.1:16210", false).is_ok());
        for url in ["file:///tmp/rpc", "https://user:pass@node.example.com", "not a URL"] {
            assert!(validate_endpoint(url, false).is_err());
        }
    }
}

#[cfg(test)]
mod audit_http_limits {
    use super::*;
    use std::{io::Write, net::TcpListener, thread};

    fn response_server(response: Vec<u8>, delay: Duration) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut input = [0; 1024];
            let _ = stream.read(&mut input);
            thread::sleep(delay);
            let _ = stream.write_all(&response);
        });
        (url, worker)
    }

    #[test]
    fn bounds_response_body_and_refuses_redirects() {
        let body = vec![b' '; MAX_RESPONSE_BYTES as usize + 1];
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
        response.extend(body);
        let (url, worker) = response_server(response, Duration::ZERO);
        assert!(HttpTransport::new(url).request("{}").unwrap_err().to_string().contains("exceeds"));
        worker.join().unwrap();
        let (url, worker) = response_server(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n".to_vec(), Duration::ZERO);
        assert!(HttpTransport::new(url).request("{}").unwrap_err().to_string().contains("non-success"));
        worker.join().unwrap();
    }

    #[test]
    fn read_deadline_interrupts_a_stalled_endpoint() {
        let (url, worker) = response_server(Vec::new(), Duration::from_millis(300));
        let mut transport = HttpTransport::new(url);
        transport.agent = ureq::AgentBuilder::new().timeout(Duration::from_millis(50)).build();
        let started = std::time::Instant::now();
        assert!(transport.request("{}").is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }
}
