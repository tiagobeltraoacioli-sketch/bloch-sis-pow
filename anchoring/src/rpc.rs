// SPDX-License-Identifier: MIT OR Apache-2.0
//! The RPC seam: a [`RpcTransport`] trait, a typed [`BlochRpc`] client over it,
//! and an in-memory [`MockTransport`] so the whole crate builds and the example
//! runs **fully offline**.
//!
//! Why a trait? So this crate compiles and is testable without a live node and
//! without pulling a heavy async HTTP stack by default. A real blocking
//! transport over `ureq` is provided behind the `http` feature
//! ([`crate::http`]). Any client that can POST JSON-RPC 2.0 to a Bloch node's
//! `POST /` on port `16210` (roadmap §1.2) can implement [`RpcTransport`].

use crate::anchor::Txid;
use crate::error::{AnchorError, Result};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;

/// A raw JSON-RPC transport: POST a request body, get the parsed response.
///
/// Implementations only move bytes — normalization of Bloch's quirks lives in
/// [`BlochRpc`].
pub trait RpcTransport {
    /// POST a JSON-RPC 2.0 request body and return the parsed JSON response.
    fn request(&self, body: &str) -> Result<Value>;
}

/// Status of a transaction as read from the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxStatus {
    /// Confirmation depth (`0` = mempool).
    pub confirmations: u64,
    /// Mined block height, if known.
    pub height: Option<u64>,
}

/// A retrieved transaction, reduced to what the anchoring layer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievedTx {
    /// Ordered output `script_pubkey`s.
    pub output_scripts: Vec<Vec<u8>>,
    /// Confirmation depth.
    pub confirmations: u64,
    /// Mined block height, if known.
    pub height: Option<u64>,
}

/// Typed JSON-RPC client that normalizes Bloch's response shapes.
///
/// Handles the documented quirk (roadmap §1.2) that errors may appear either at
/// the standard top-level `error` **or** nested inside `result.error`.
pub struct BlochRpc<T: RpcTransport> {
    transport: T,
    id: RefCell<u64>,
}

impl<T: RpcTransport> BlochRpc<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        BlochRpc {
            transport,
            id: RefCell::new(0),
        }
    }

    /// Borrow the underlying transport (useful for a stateful mock in tests).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Call a method, returning the normalized `result` value (error shapes
    /// resolved).
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = {
            let mut g = self.id.borrow_mut();
            *g += 1;
            *g
        };
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();

        let resp = self.transport.request(&body)?;

        // Standard JSON-RPC error object.
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                return Err(AnchorError::Rpc(err.to_string()));
            }
        }
        let result = resp
            .get("result")
            .ok_or_else(|| AnchorError::BadResponse("missing `result`".into()))?;

        // Bloch quirk: error nested inside `result.error`.
        if let Some(inner) = result.get("error") {
            if !inner.is_null() {
                return Err(AnchorError::Rpc(inner.to_string()));
            }
        }
        Ok(result.clone())
    }

    /// `sendrawtransaction` — the primary write (roadmap §1.3). Returns the txid.
    pub fn send_raw_transaction(&self, raw_hex: &str) -> Result<Txid> {
        let result = self.call("sendrawtransaction", json!([raw_hex]))?;
        // Node may return a bare string or `{ "txid": "..." }`.
        let txid_hex = result
            .as_str()
            .map(str::to_string)
            .or_else(|| result.get("txid").and_then(Value::as_str).map(str::to_string))
            .ok_or_else(|| AnchorError::BadResponse("no txid in sendrawtransaction result".into()))?;
        Txid::from_hex(&txid_hex)
    }

    /// `getblockcount` — current chain tip height.
    pub fn get_block_count(&self) -> Result<u64> {
        let result = self.call("getblockcount", json!([]))?;
        result
            .as_u64()
            .or_else(|| result.get("count").and_then(Value::as_u64))
            .or_else(|| result.get("height").and_then(Value::as_u64))
            .ok_or_else(|| AnchorError::BadResponse("no height in getblockcount".into()))
    }

    /// `gettxstatus` — confirmation depth + (optional) height.
    pub fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus> {
        let result = self.call("gettxstatus", json!([txid.to_hex()]))?;
        let confirmations = result
            .get("confirmations")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let height = result
            .get("height")
            .and_then(Value::as_u64)
            .or_else(|| result.get("blockheight").and_then(Value::as_u64));
        Ok(TxStatus {
            confirmations,
            height,
        })
    }

    /// `gettransaction` — retrieve a tx and reduce it to its output scripts +
    /// depth. Accepts either an `outputs`/`vout` array of `{script_pubkey: hex}`
    /// objects, or a raw `hex` field parsed with the minimal codec.
    pub fn get_transaction(&self, txid: &Txid) -> Result<RetrievedTx> {
        let result = self.call("gettransaction", json!([txid.to_hex()]))?;

        let confirmations = result
            .get("confirmations")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let height = result
            .get("height")
            .and_then(Value::as_u64)
            .or_else(|| result.get("blockheight").and_then(Value::as_u64));

        // Preferred: explicit output list.
        let outputs = result
            .get("outputs")
            .or_else(|| result.get("vout"))
            .and_then(Value::as_array);

        if let Some(outs) = outputs {
            let mut scripts = Vec::with_capacity(outs.len());
            for o in outs {
                let spk = o
                    .get("script_pubkey")
                    .or_else(|| o.get("scriptPubKey"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| AnchorError::BadResponse("output missing script_pubkey".into()))?;
                scripts.push(hex::decode(spk)?);
            }
            return Ok(RetrievedTx {
                output_scripts: scripts,
                confirmations,
                height,
            });
        }

        // Fallback: raw tx hex.
        if let Some(raw) = result.get("hex").and_then(Value::as_str) {
            let tx = crate::tx::Transaction::from_hex(raw)?;
            return Ok(RetrievedTx {
                output_scripts: tx.output_scripts(),
                confirmations,
                height,
            });
        }

        Err(AnchorError::BadResponse(
            "gettransaction had neither outputs nor hex".into(),
        ))
    }
}

// ─────────────────────────── in-memory mock node ───────────────────────────

struct MockState {
    tip: u64,
    // txid hex -> (raw tx hex, mined height)
    txs: HashMap<String, (String, u64)>,
}

/// An in-memory Bloch node good enough to exercise the full submit → confirm →
/// retrieve → prove path offline. Not a simulator of consensus — a fixture.
///
/// Each `sendrawtransaction` mines the tx one block above the current tip.
/// Call [`MockTransport::mine`] to bury it deeper and grow confirmations.
pub struct MockTransport {
    state: RefCell<MockState>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new(0)
    }
}

impl MockTransport {
    /// New mock with a starting tip height.
    pub fn new(start_height: u64) -> Self {
        MockTransport {
            state: RefCell::new(MockState {
                tip: start_height,
                txs: HashMap::new(),
            }),
        }
    }

    /// Advance the chain tip by `n` blocks (grows every tx's confirmations).
    pub fn mine(&self, n: u64) {
        self.state.borrow_mut().tip += n;
    }

    fn confirmations_of(state: &MockState, mined_at: u64) -> u64 {
        // tip == mined_at means 1 confirmation (the block itself).
        state.tip.saturating_sub(mined_at) + 1
    }
}

impl RpcTransport for MockTransport {
    fn request(&self, body: &str) -> Result<Value> {
        let req: Value = serde_json::from_str(body)
            .map_err(|e| AnchorError::Transport(format!("bad request json: {e}")))?;
        let id = req.get("id").cloned().unwrap_or(json!(0));
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| AnchorError::Transport("missing method".into()))?;
        let params = req.get("params").cloned().unwrap_or(json!([]));

        let ok = |result: Value| Ok(json!({ "jsonrpc": "2.0", "id": id, "result": result }));

        match method {
            "getblockcount" => {
                let tip = self.state.borrow().tip;
                ok(json!(tip))
            }
            "sendrawtransaction" => {
                let raw = params
                    .get(0)
                    .and_then(Value::as_str)
                    .ok_or_else(|| AnchorError::Transport("sendrawtransaction: no hex".into()))?;
                let tx = crate::tx::Transaction::from_hex(raw)?;
                let txid_hex = hex::encode(tx.txid());
                let mut st = self.state.borrow_mut();
                st.tip += 1; // "mine" a block carrying this tx
                let mined = st.tip;
                st.txs.insert(txid_hex.clone(), (raw.to_string(), mined));
                ok(json!(txid_hex))
            }
            "gettxstatus" => {
                let txid = params.get(0).and_then(Value::as_str).unwrap_or("");
                let st = self.state.borrow();
                match st.txs.get(txid) {
                    Some((_, mined)) => {
                        let confs = Self::confirmations_of(&st, *mined);
                        ok(json!({ "confirmations": confs, "height": mined }))
                    }
                    None => ok(json!({ "confirmations": 0, "height": Value::Null })),
                }
            }
            "gettransaction" => {
                let txid = params.get(0).and_then(Value::as_str).unwrap_or("");
                let st = self.state.borrow();
                match st.txs.get(txid) {
                    Some((raw, mined)) => {
                        let confs = Self::confirmations_of(&st, *mined);
                        ok(json!({
                            "hex": raw,
                            "confirmations": confs,
                            "height": mined,
                        }))
                    }
                    None => Ok(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "error": "tx not found" }
                    })),
                }
            }
            other => Err(AnchorError::Transport(format!("mock: unhandled method {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_roundtrips_a_send_and_status() {
        let rpc = BlochRpc::new(MockTransport::new(10));
        // A trivial tx with one output.
        let tx = crate::tx::Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![crate::tx::TxOutput {
                value: 1,
                script_pubkey: vec![5u8; 20],
            }],
            locktime: 0,
        };
        let txid = rpc.send_raw_transaction(&tx.to_hex()).unwrap();
        let status = rpc.get_tx_status(&txid).unwrap();
        assert_eq!(status.confirmations, 1);
        rpc.transport().mine(4);
        let status = rpc.get_tx_status(&txid).unwrap();
        assert_eq!(status.confirmations, 5);
        let got = rpc.get_transaction(&txid).unwrap();
        assert_eq!(got.output_scripts.len(), 1);
    }

    #[test]
    fn result_error_quirk_is_surfaced() {
        let rpc = BlochRpc::new(MockTransport::new(0));
        let missing = Txid::from_bytes([0u8; 32]);
        // gettransaction on an unknown txid returns `result.error` (the quirk).
        assert!(matches!(
            rpc.get_transaction(&missing),
            Err(AnchorError::Rpc(_))
        ));
    }
}
