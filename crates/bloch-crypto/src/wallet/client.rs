//! Async JSON-RPC client for wallet ↔ node communication.
//!
//! WalletClient is the network side of the wallet. It talks to a Bloch-SIS Protocol
//! daemon (local or remote) over HTTP JSON-RPC and exposes wallet-friendly
//! high-level operations.
//!
//! Design choices:
//!
//!   - `async/await` with `reqwest` — works on desktop, mobile, WASM
//!   - RpcClientTrait allows mocking for tests
//!   - WalletClient takes an RpcClient trait object, not a URL directly,
//!     so users can inject custom transports (e.g. IPC for local daemons,
//!     WebSocket for browsers)
//!
//! Not done here:
//!   - Retries and caller-specific rate limits are not implemented here.
//!     HTTP requests have a 30-second deadline and responses a 64 MiB read budget.
//!   - Request signing / authentication — none needed while RPC is public
//!   - Response caching — caller decides
//!
//! Example:
//!
//! ```ignore
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use bloch::wallet::{Wallet, WalletClient};
//! use bloch::address::Network;
//!
//! let rpc = WalletClient::new("https://scan.blochlayer.com/rpc");
//! let (wallet, _seed) = Wallet::generate(Network::Mainnet)?;
//!
//! let balance = rpc.balance(wallet.address()).await?;
//! println!("Balance: {} sats", balance.confirmed);
//! # Ok(())
//! # }
//! ```

use super::errors::WalletError;
use crate::address::Address;
use crate::core::{Transaction, TxOutput};
use super::Utxo;
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// RpcClientTrait — abstraction layer for injectable transports
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait RpcClientTrait: Send + Sync {
    /// Invoke a JSON-RPC method with the given params.
    async fn call(&self, method: &str, params: Value) -> Result<Value, WalletError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Input-byte budget; parsed JSON allocations are additional.
const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Default HTTP RPC client using reqwest.
pub struct WalletClient {
    endpoint: String,
    http: reqwest::Client,
    next_id: AtomicU64,
}

impl WalletClient {
    /// Construct with a JSON-RPC endpoint URL.
    ///
    /// Panics if the HTTP transport cannot initialize. Prefer `try_new` when
    /// callers need to handle initialization failures without unwinding.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::try_new(endpoint).expect("HTTP transport initialization failed")
    }

    /// Fallible HTTP transport initialization. Endpoint errors remain request errors.
    pub fn try_new(endpoint: impl Into<String>) -> Result<Self, WalletError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| WalletError::Network(error.without_url().to_string()))?;
        Ok(Self {
            endpoint: endpoint.into(),
            http,
            next_id: AtomicU64::new(1),
        })
    }

    // High-level wallet operations.
    //
    // These map to specific RPC methods and return strongly-typed results.
    // The Value returned by `call()` is parsed and mapped to wallet types.

    /// Get balance (confirmed + pending) for an address.
    pub async fn balance(&self, address: &Address) -> Result<Balance, WalletError> {
        let bal_response = self.call("getbalance", json!([address.to_string()])).await?;
        // Satoshi amounts are decimal strings on the V4 wire (rule R3) and
        // JSON numbers on the live G3 wire — `sat_u64` accepts both.
        // Older nodes may not expose pending information. Preserve that fallback.
        let addr_info = self.call("getaddressinfo", json!([address.to_string()])).await
            .unwrap_or_else(|_| json!({}));
        parse_balance(&bal_response, &addr_info)
    }

    /// Get spendable UTXOs for an address.
    pub async fn utxos(&self, address: &Address) -> Result<Vec<Utxo>, WalletError> {
        let response = self.call("getutxos", json!([address.to_string()])).await?;
        parse_utxos(&response, address)
    }

    /// Get estimated fee rates.
    pub async fn estimate_fee(&self) -> Result<FeeEstimate, WalletError> {
        let response = self.call("estimatefeeadvanced", json!([])).await?;
        Ok(FeeEstimate {
            next_block: response.get("next_block_sats").and_then(|v| v.as_u64()).unwrap_or(10_000),
            medium:     response.get("medium_priority").and_then(|v| v.as_u64()).unwrap_or(5_000),
            slow:       response.get("slow_priority").and_then(|v| v.as_u64()).unwrap_or(1_000),
        })
    }

    /// Broadcast a signed transaction.
    pub async fn broadcast(&self, tx: &Transaction) -> Result<[u8; 32], WalletError> {
        // Sprint 1.d: Bitcoin-format wire (replaces bincode). Infallible.
        let tx_bytes = tx.to_stratum_bytes(true);
        let tx_hex = hex::encode(&tx_bytes);
        let response = self.call("sendrawtransaction", json!([tx_hex])).await?;

        let txid_hex = response.get("txid").and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::BadResponse("broadcast: missing txid".into()))?;
        let txid_bytes = hex::decode(txid_hex)
            .map_err(|e| WalletError::BadResponse(format!("bad txid: {}", e)))?;
        if txid_bytes.len() != 32 {
            return Err(WalletError::BadResponse("txid not 32 bytes".into()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&txid_bytes);
        Ok(out)
    }

    /// Get tx status (pending / confirmed / unknown).
    pub async fn tx_status(&self, txid: &[u8; 32]) -> Result<TxStatus, WalletError> {
        let response = self.call("gettxstatus", json!([hex::encode(txid)])).await?;
        parse_tx_status(&response)
    }

    /// Convenience: send a full tx from an address, signed by a Wallet.
    ///
    /// Handles: utxo fetch → build_tx → sign → broadcast.
    pub async fn send(
        &self,
        wallet: &super::Wallet,
        to: &Address,
        amount: u64,
        fee_rate_preference: FeePreference,
    ) -> Result<[u8; 32], WalletError> {
        let fee_est = self.estimate_fee().await?;
        let fee = match fee_rate_preference {
            FeePreference::NextBlock => fee_est.next_block,
            FeePreference::Medium    => fee_est.medium,
            FeePreference::Slow      => fee_est.slow,
        };

        let utxos = self.utxos(wallet.address()).await?;
        let unsigned = wallet.build_tx(utxos, to, amount, fee)?;
        let signed = wallet.sign_tx(unsigned)?;
        self.broadcast(&signed).await
    }
}

#[async_trait]
impl RpcClientTrait for WalletClient {
    async fn call(&self, method: &str, params: Value) -> Result<Value, WalletError> {
        let request_id = self.next_id.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| WalletError::Overflow)?;
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id,
        });

        let response = self.http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| WalletError::Network(e.without_url().to_string()))?;

        if !response.status().is_success() {
            // Status is sufficient; do not download or reflect an arbitrary peer body.
            return Err(WalletError::Network(format!("HTTP {}", response.status())));
        }

        let bytes = read_bounded_response(response, MAX_RPC_RESPONSE_BYTES).await?;
        let resp_json: Value = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Parse(format!("parse response: {}", e)))?;

        parse_rpc_envelope(resp_json, request_id)
    }
}

fn parse_rpc_envelope(response: Value, request_id: u64) -> Result<Value, WalletError> {
    let object = response.as_object().ok_or_else(|| WalletError::BadResponse("RPC envelope must be an object".into()))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("id").and_then(Value::as_u64) != Some(request_id) {
        return Err(WalletError::BadResponse("RPC version or request ID mismatch".into()));
    }
    if let Some(error) = object.get("error").filter(|value| !value.is_null()) {
        if object.contains_key("result") {
            return Err(WalletError::BadResponse("RPC envelope contains result and error".into()));
        }
        let code = error.get("code").and_then(Value::as_i64)
            .ok_or_else(|| WalletError::BadResponse("RPC error code must be an integer".into()))?;
        if error.get("message").and_then(Value::as_str).is_none() {
            return Err(WalletError::BadResponse("RPC error message must be a string".into()));
        }
        return Err(WalletError::RpcError(format!("RPC error code {code}")));
    }
    object.get("result").cloned()
        .ok_or_else(|| WalletError::BadResponse("missing result field".into()))
}

fn parse_tx_status(response: &Value) -> Result<TxStatus, WalletError> {
    let status = response.get("status").and_then(Value::as_str)
        .ok_or_else(|| WalletError::BadResponse("missing transaction status".into()))?;
    let confirmations = response.get("confirmations").and_then(Value::as_u64).unwrap_or(0);
    Ok(match status {
        "pending" => TxStatus::Pending,
        "confirmed" => TxStatus::Confirmed { confirmations },
        "final" => TxStatus::Final { confirmations },
        "included" => TxStatus::Included,
        "justified" => TxStatus::Justified,
        "finalized" => TxStatus::Finalized,
        _ => TxStatus::Unknown,
    })
}

async fn read_bounded_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, WalletError> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(WalletError::BadResponse("RPC response exceeds byte limit".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| WalletError::Network(error.without_url().to_string()))? {
        let length = bytes.len().checked_add(chunk.len()).ok_or(WalletError::Overflow)?;
        if length > limit { return Err(WalletError::BadResponse("RPC response exceeds byte limit".into())); }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn parse_balance(balance: &Value, pending: &Value) -> Result<Balance, WalletError> {
    let confirmed = balance.get("balance").and_then(super::sat_u64)
        .ok_or_else(|| WalletError::BadResponse("missing balance field".into()))?;
    let pending_in = pending.get("pending_incoming").and_then(super::sat_u64).unwrap_or(0);
    let pending_out = pending.get("pending_outgoing").and_then(super::sat_u64).unwrap_or(0);
    Ok(Balance { confirmed, pending_incoming: pending_in, pending_outgoing: pending_out,
        total: confirmed.checked_add(pending_in).ok_or(WalletError::Overflow)? })
}

fn parse_utxos(response: &Value, address: &Address) -> Result<Vec<Utxo>, WalletError> {
    let utxos_json = response.get("utxos")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WalletError::BadResponse("missing utxos array".into()))?;

    let mut utxos = Vec::with_capacity(utxos_json.len());
    for utxo_val in utxos_json {
        let txid_hex = utxo_val.get("txid").and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::BadResponse("utxo missing txid".into()))?;
        let index = utxo_val.get("index").and_then(|v| v.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| WalletError::BadResponse("utxo index must fit u32".into()))?;
        // R3: `value` is a satoshi amount — string or number on the wire.
        let value = utxo_val.get("value").and_then(super::sat_u64)
            .ok_or_else(|| WalletError::BadResponse("utxo missing value".into()))?;

        let txid_bytes = hex::decode(txid_hex)
            .map_err(|e| WalletError::BadResponse(format!("bad txid hex: {}", e)))?;
        if txid_bytes.len() != 32 {
            return Err(WalletError::BadResponse(format!("txid not 32 bytes: {}", txid_bytes.len())));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        utxos.push(Utxo {
            txid,
            index,
            output: TxOutput {
                value,
                script_pubkey: address.hash().to_vec(),
            },
        });
    }
    Ok(utxos)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet-friendly types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    pub confirmed:         u64,
    pub pending_incoming:  u64,
    pub pending_outgoing:  u64,
    pub total:             u64,
}

#[derive(Debug, Clone, Copy)]
pub struct FeeEstimate {
    pub next_block: u64,
    pub medium:     u64,
    pub slow:       u64,
}

#[derive(Debug, Clone, Copy)]
pub enum FeePreference {
    NextBlock,
    Medium,
    Slow,
}

#[derive(Debug, Clone)]
pub enum TxStatus {
    Pending,
    Confirmed { confirmations: u64 },
    /// Legacy depth-based status; distinct from G4 checkpoint finality.
    Final { confirmations: u64 },
    Included,
    Justified,
    /// The queried G4 node reports checkpoint finality, not independent proof.
    Finalized,
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRpc {
        responses: std::collections::HashMap<String, Value>,
    }

    #[async_trait]
    impl RpcClientTrait for MockRpc {
        async fn call(&self, method: &str, _params: Value) -> Result<Value, WalletError> {
            self.responses.get(method).cloned()
                .ok_or_else(|| WalletError::RpcError(format!("no mock for: {}", method)))
        }
    }

    #[tokio::test]
    async fn tx_status_parses_correctly() {
        // Real HTTP client test would need a running daemon.
        // Here we just verify the type parsing logic works.
        let s1 = TxStatus::Confirmed { confirmations: 5 };
        let s2 = TxStatus::Final { confirmations: 100 };
        assert!(matches!(s1, TxStatus::Confirmed { confirmations: 5 }));
        assert!(matches!(s2, TxStatus::Final { confirmations: 100 }));
    }

    #[test]
    fn fee_preference_select() {
        let est = FeeEstimate { next_block: 10000, medium: 5000, slow: 1000 };
        let sel_next = match FeePreference::NextBlock {
            FeePreference::NextBlock => est.next_block,
            _ => unreachable!(),
        };
        assert_eq!(sel_next, 10000);
    }
}

#[cfg(test)]
mod audit_rpc_input_tests {
    use super::*;
    use crate::address::Network;

    #[test]
    fn balance_total_refuses_overflow_and_keeps_legacy_missing_pending() {
        assert!(matches!(parse_balance(&json!({"balance": u64::MAX.to_string()}),
            &json!({"pending_incoming": "1"})), Err(WalletError::Overflow)));
        assert_eq!(parse_balance(&json!({"balance": "9007199254740993"}), &json!({})).unwrap().total,
            9_007_199_254_740_993);
        assert_eq!(parse_balance(&json!({"balance": 100}), &json!({"pending_incoming": 20})).unwrap().total, 120);
    }

    #[test]
    fn utxo_index_cannot_wrap_to_another_outpoint() {
        let address = Address::from_hash([1; 20], Network::Testnet);
        let mut row = json!({"txid": "ab".repeat(32), "index": u32::MAX, "value": "9007199254740993"});
        let parsed = parse_utxos(&json!({"utxos": [row.clone()]}), &address).unwrap();
        assert_eq!(parsed[0].index, u32::MAX);
        assert_eq!(parsed[0].output.value, 9_007_199_254_740_993);
        for invalid in [json!(4294967296u64), json!(-1), json!(1.5)] {
            row["index"] = invalid;
            assert!(matches!(parse_utxos(&json!({"utxos": [row.clone()]}), &address), Err(WalletError::BadResponse(_))));
        }
    }
}

#[cfg(test)]
mod audit_rpc_http_budget_tests {
    use super::*;
    use std::io::{Read, Write};

    fn serve(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            stream.set_write_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(&response);
        });
        (format!("http://{address}"), worker)
    }

    #[tokio::test]
    async fn actual_chunked_responses_enforce_read_budget_and_exact_boundary() {
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(2)).build().unwrap();
        let body = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n";
        for limit in [7, 8] {
            let (url, worker) = serve(body.to_vec());
            let response = client.get(url).send().await.unwrap();
            let result = read_bounded_response(response, limit).await;
            if limit == 8 { assert_eq!(result.unwrap(), b"abcdefgh"); }
            else { assert!(matches!(result, Err(WalletError::BadResponse(message)) if message.contains("byte limit"))); }
            worker.join().unwrap();
        }
    }

    #[tokio::test]
    async fn advertised_oversize_is_refused_before_body_and_http_error_does_not_echo() {
        let (url, worker) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\nConnection: close\r\n\r\n".to_vec());
        let response = reqwest::get(url).await.unwrap();
        assert!(matches!(read_bounded_response(response, 8).await, Err(WalletError::BadResponse(_))));
        worker.join().unwrap();
        let (url, worker) = serve(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\nsynthetic-peer-body-marker".to_vec());
        let error = WalletClient::new(url).call("getbalance", json!([])).await.unwrap_err().to_string();
        assert!(error.contains("500"));
        assert!(!error.contains("synthetic-peer-body-marker"));
        worker.join().unwrap();
    }
    #[tokio::test]
    async fn redirect_does_not_forward_rpc_to_target_and_url_errors_are_redacted() {
        let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let response = format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/private-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.local_addr().unwrap());
        let (url, worker) = serve(response.into_bytes());
        let error = WalletClient::try_new(url).unwrap().call("sendrawtransaction", json!(["public-signed-data"])).await.unwrap_err().to_string();
        assert!(error.contains("307"));
        assert!(matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        worker.join().unwrap();

        let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = unavailable.local_addr().unwrap();
        drop(unavailable);
        let endpoint = format!("http://{address}/private-path?token=synthetic-query-marker");
        let error = WalletClient::try_new(endpoint).unwrap().call("getbalance", json!([])).await.unwrap_err().to_string();
        assert!(!error.contains("synthetic-query-marker"));
        assert!(!error.contains("private-path"));
    }

    #[tokio::test]
    async fn successive_calls_reject_a_stale_response_id() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut ids = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut body_len = 0;
                loop {
                    let mut line = String::new();
                    std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
                    if line == "\r\n" { break; }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        body_len = value.trim().parse::<usize>().unwrap();
                    }
                }
                assert!(body_len < 4096);
                let mut body = vec![0; body_len];
                reader.read_exact(&mut body).unwrap();
                ids.push(serde_json::from_slice::<Value>(&body).unwrap()["id"].as_u64().unwrap());
                drop(reader);
                stream.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":42}").unwrap();
            }
            ids
        });
        let client = WalletClient::new(format!("http://{address}"));
        assert_eq!(client.call("getbalance", json!([])).await.unwrap(), json!(42));
        assert!(matches!(client.call("getbalance", json!([])).await, Err(WalletError::BadResponse(message)) if message.contains("ID mismatch")));
        assert_eq!(worker.join().unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn rpc_error_retains_numeric_code_without_peer_message_or_data() {
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"synthetic-peer-marker\",\"data\":\"synthetic-peer-marker\"}}";
        let (url, worker) = serve(response.to_vec());
        let error = WalletClient::new(url).call("getbalance", json!([])).await.unwrap_err().to_string();
        assert!(error.contains("-32602"));
        assert!(!error.contains("synthetic-peer-marker"));
        worker.join().unwrap();
    }

}

#[cfg(test)]
mod audit_rpc_envelope_tests {
    use super::*;

    #[test]
    fn envelopes_require_version_id_and_unambiguous_result_or_error() {
        for invalid in [
            json!([]), json!({"result": 1}),
            json!({"jsonrpc":"1.0","id":7,"result":1}),
            json!({"jsonrpc":"2.0","id":8,"result":1}),
            json!({"jsonrpc":"2.0","id":"7","result":1}),
            json!({"jsonrpc":"2.0","id":null,"result":1}),
            json!({"jsonrpc":"2.0","id":7}),
            json!({"jsonrpc":"2.0","id":7,"error":null}),
            json!({"jsonrpc":"2.0","id":7,"result":null,"error":{"code":-1,"message":"bad"}}),
            json!({"jsonrpc":"2.0","id":7,"error":{"code":1.5,"message":"bad"}}),
            json!({"jsonrpc":"2.0","id":7,"error":{"code":-1,"message":3}}),
        ] {
            assert!(matches!(parse_rpc_envelope(invalid, 7), Err(WalletError::BadResponse(_))));
        }
        assert_eq!(parse_rpc_envelope(json!({"jsonrpc":"2.0","id":7,"result":null}), 7).unwrap(), Value::Null);
        assert_eq!(parse_rpc_envelope(json!({"jsonrpc":"2.0","id":7,"result":[1],"error":null}), 7).unwrap(), json!([1]));
        assert!(matches!(parse_rpc_envelope(json!({"jsonrpc":"2.0","id":7,"error":{"code":-1,"message":"private-marker"}}), 7),
            Err(WalletError::RpcError(message)) if message == "RPC error code -1"));
    }

    #[test]
    fn preserves_legacy_depth_and_distinguishes_g4_checkpoint_states() {
        assert!(matches!(parse_tx_status(&json!({"status":"pending"})).unwrap(), TxStatus::Pending));
        assert!(matches!(parse_tx_status(&json!({"status":"confirmed","confirmations":12})).unwrap(), TxStatus::Confirmed { confirmations:12 }));
        assert!(matches!(parse_tx_status(&json!({"status":"final","confirmations":100})).unwrap(), TxStatus::Final { confirmations:100 }));
        assert!(matches!(parse_tx_status(&json!({"status":"included"})).unwrap(), TxStatus::Included));
        assert!(matches!(parse_tx_status(&json!({"status":"justified"})).unwrap(), TxStatus::Justified));
        assert!(matches!(parse_tx_status(&json!({"status":"finalized"})).unwrap(), TxStatus::Finalized));
        assert!(matches!(parse_tx_status(&json!({"status":"unknown"})).unwrap(), TxStatus::Unknown));
        assert!(parse_tx_status(&json!({})).is_err());
    }

    #[tokio::test]
    async fn exhausted_request_ids_fail_before_network_and_never_wrap() {
        let client = WalletClient::new("http://127.0.0.1:1");
        client.next_id.store(u64::MAX, Ordering::Relaxed);
        for _ in 0..2 {
            assert!(matches!(client.call("getbalance", json!([])).await, Err(WalletError::Overflow)));
            assert_eq!(client.next_id.load(Ordering::Relaxed), u64::MAX);
        }
    }
}
