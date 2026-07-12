//! Bloch-SIS Protocol — JSON-RPC over HTTP (axum)
//!
//! Methods:
//!   getnetworkinfo, getblockcount, getmempoolinfo,
//!   getblockhash, getblock, getblockbyheight, getrecentblocks,
//!   gettransaction, getbalance, getutxos,
//!   sendrawtransaction,
//!   validateaddress, estimatefee, getrawmempool,
//!   decoderawtransaction, getdaginfo, listtransactions, getpeerinfo

pub mod auth;

use std::sync::Arc;
use parking_lot::RwLock;
use log::{info, error};
use axum::{routing::post, Router, extract::State, extract::DefaultBodyLimit, http::StatusCode, Json};
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower::limit::GlobalConcurrencyLimitLayer;

/// P0 RPC hardening (roadmap §1.6 / §4.3).
/// Max request body: JSON-RPC calls are tiny; 1 MiB is generous and tighter
/// than axum's 2 MiB default. Blocks oversized-payload memory abuse.
const RPC_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Global cap on concurrently in-flight RPC handlers, shared across all
/// connections (GlobalConcurrencyLimitLayer holds one Arc'd semaphore). Bounds
/// how many expensive storage-scanning methods can pile up at once. Value is a
/// conservative default — needs load-testing to tune (not yet done).
const RPC_MAX_CONCURRENCY: usize = 256;
/// Per-request wall-clock timeout (returns 408). Kills slow-loris / stuck
/// handlers so they can't hold a concurrency slot forever.
const RPC_REQUEST_TIMEOUT_SECS: u64 = 30;
use serde_json::{json, Value};
use crate::storage::Storage;
use crate::mempool::Mempool;
use crate::consensus::GhostDAG;
use crate::core::{Transaction, PROTOCOL_VERSION, MAINNET_PREFIX, TESTNET_PREFIX};
use tokio::sync::mpsc;
use crate::network::NetworkMessage;

#[derive(Clone, Debug, Default)]
pub struct NodeState {
    pub tip_blue_score: u64,
    pub block_count:    u64,
    pub peer_count:     u32,
    pub mempool_size:   usize,
    pub is_syncing:     bool,
    pub peer_addresses: Vec<String>,
    pub version:        String,
}

/// Block-submission hook — the B5f pool seam.
///
/// Stratum V1/V2 cannot carry the Module-SIS solution vector in their share
/// messages (see main.rs B5f), so external pools mine full SIS blocks and
/// hand them in over RPC instead. main.rs wires this with a closure that
/// mirrors the gossipsub NewBlock path: `Block::block_hash()` identity,
/// `validate_structure()` (PoW witness + merkle + coinbase), then the same
/// `accept_block` consensus pipeline, then network broadcast.
///
/// `None` (tests, or callers that don't wire it) makes `submitblock` return
/// a "not wired" error instead of silently accepting.
pub type SubmitBlockFn = dyn Fn(crate::core::Block) -> Result<String, String> + Send + Sync;

#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind_address:              String,
    pub port:                      u16,
    /// Sprint M: shared-secret API key. None = no auth layer.
    pub api_key:                   Option<String>,
    /// Sprint M: require X-API-Key for write methods (sendrawtransaction).
    pub require_auth_for_writes:   bool,
    /// Sprint M: per-IP read rate limit, requests/minute.
    pub rate_limit_reads_per_min:  u32,
    /// Sprint M: per-IP write rate limit, requests/minute.
    pub rate_limit_writes_per_min: u32,
    /// Sprint M-patch1: also trust RFC1918/ULA ranges as loopback.
    /// Needed when node runs in Docker with default bridge networking.
    /// SECURITY: only set true on trusted single-tenant hosts.
    pub trust_private_ranges:      bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            bind_address:              "127.0.0.1".into(),
            port:                      16210,
            api_key:                   None,
            require_auth_for_writes:   false,
            rate_limit_reads_per_min:  60,
            rate_limit_writes_per_min: 5,
            trust_private_ranges:      false,
        }
    }
}

#[derive(Clone)]
struct AppState {
    node_state:              Arc<RwLock<NodeState>>,
    store:                   Arc<Storage>,
    mempool:                 Arc<Mempool>,
    dag:                     Arc<RwLock<GhostDAG>>,
    outbound_tx:             mpsc::Sender<NetworkMessage>,
    // Sprint M additions:
    api_key:                 Option<String>,
    require_auth_for_writes: bool,
    rate_limiter:            Arc<auth::RateLimiterSet>,
    trust_private_ranges:    bool,
    // B5f pool seam: submitblock hook (None = method returns "not wired").
    submit_block:            Option<Arc<SubmitBlockFn>>,
}

pub async fn start_rpc_server(
    config:      RpcConfig,
    state:       Arc<RwLock<NodeState>>,
    store:       Arc<Storage>,
    mempool:     Arc<Mempool>,
    dag:         Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    // B5f pool seam — see `SubmitBlockFn`.
    submit_block: Option<Arc<SubmitBlockFn>>,
) {
    let addr = format!("{}:{}", config.bind_address, config.port);

    let rate_limiter = Arc::new(auth::RateLimiterSet::new(
        config.rate_limit_reads_per_min,
        config.rate_limit_writes_per_min,
    ));

    let app_state = AppState {
        node_state: state,
        store,
        mempool,
        dag,
        outbound_tx,
        api_key:                 config.api_key.clone(),
        require_auth_for_writes: config.require_auth_for_writes,
        rate_limiter,
        trust_private_ranges:    config.trust_private_ranges,
        submit_block,
    };

    // P0 RPC hardening (roadmap §1.6 / §4.3): body-size cap, global
    // concurrency limit, and a per-request timeout on top of the existing
    // per-IP auth/rate-limit. Auth behaviour is unchanged.
    let app = Router::new()
        .route("/", post(handle_rpc))
        .layer(CorsLayer::permissive())
        .layer(DefaultBodyLimit::max(RPC_MAX_BODY_BYTES))
        .layer(GlobalConcurrencyLimitLayer::new(RPC_MAX_CONCURRENCY))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS)))
        .with_state(app_state);

    info!("RPC on {} (auth={}, require_auth_writes={}, trust_private={}, limits: {}r/min, {}w/min)",
        addr,
        config.api_key.is_some(),
        config.require_auth_for_writes,
        config.trust_private_ranges,
        config.rate_limit_reads_per_min,
        config.rate_limit_writes_per_min,
    );
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l)  => l,
        Err(e) => { error!("RPC bind: {}", e); return; }
    };
    // Sprint M: connect_info makes the client IP available to handlers.
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    ).await {
        error!("RPC error: {}", e);
    }
}

async fn handle_rpc(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req):    Json<Value>,
) -> (StatusCode, Json<Value>) {
    let method = req["method"].as_str().unwrap_or("");
    let id     = req.get("id").cloned().unwrap_or(json!(null));
    let params = req.get("params");

    let client_ip = addr.ip();
    let presented_key = auth::extract_api_key(&headers);

    let decision = auth::authorize_with_trust(
        client_ip,
        method,
        presented_key,
        state.api_key.as_deref(),
        state.require_auth_for_writes,
        state.trust_private_ranges,
        &state.rate_limiter,
    );

    match decision {
        auth::AuthDecision::Allow => {
            let start = std::time::Instant::now();
            // P1 (roadmap §2): per-request tracing span, correlated with the
            // existing `rpc_requests{method,status}` metric so a slow method is
            // traceable to a client. `.instrument()` (not an entered guard) is
            // the correct form across the `dispatch` await. Inert unless a
            // subscriber is installed (init lives in main.rs, not owned here).
            use tracing::Instrument;
            let result = dispatch(method, params, &state)
                .instrument(tracing::info_span!(
                    "rpc_request",
                    method,
                    client_ip = %client_ip,
                    id = %id,
                ))
                .await;
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_millis();
            crate::metrics::observe_rpc_latency(method, elapsed.as_secs_f64());
            crate::metrics::inc_rpc_request(method, "ok");
            log::debug!("rpc ok ip={} method={} took={}ms", client_ip, method, elapsed_ms);
            (
                StatusCode::OK,
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
            )
        }
        auth::AuthDecision::Unauthorized => {
            crate::metrics::inc_rpc_request(method, "unauthorized");
            log::info!("rpc denied ip={} method={} reason=unauthorized", client_ip, method);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id":      id,
                    "error":   { "code": -32001, "message": "unauthorized: valid X-API-Key required" },
                })),
            )
        }
        auth::AuthDecision::RateLimited => {
            crate::metrics::inc_rpc_request(method, "rate_limited");
            log::info!("rpc denied ip={} method={} reason=rate_limited", client_ip, method);
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id":      id,
                    "error":   { "code": -32002, "message": "rate limit exceeded; retry after a minute" },
                })),
            )
        }
    }
}

async fn dispatch(method: &str, params: Option<&Value>, state: &AppState) -> Value {
    match method {
        "getnetworkinfo" => {
            let s = state.node_state.read();
            let pruned_h = state.store.pruned_height();
            json!({
                "network":         "mainnet",
                "version":         s.version,
                "protocol":        PROTOCOL_VERSION,
                "net_protocol":    crate::network::PROTOCOL_VERSION,
                "blue_score":      s.tip_blue_score,
                "blocks":          s.block_count,
                "peers":           s.peer_count,
                "mempool":         s.mempool_size,
                "syncing":         s.is_syncing,
                "chain":           "bloch-sis",
                "pruned_height":   pruned_h,
            })
        }
        "getblockcount"  => json!(state.node_state.read().block_count),
        "getmempoolinfo" => json!({ "size": state.node_state.read().mempool_size }),

        "getblockhash" => {
            let height = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            match state.store.get_block_hash_at_height(height) {
                Ok(Some(h)) => json!(hex::encode(h)),
                Ok(None)    => json!({ "error": "height not found" }),
                Err(e)      => json!({ "error": e.to_string() }),
            }
        }

        // ── Block explorer: full block with transaction details ──────
        "getblock" => {
            let hash_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let verbose  = params.and_then(|p| p.get(1)).and_then(|v| v.as_bool()).unwrap_or(false);
            match hex::decode(hash_hex).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) {
                Some(hash) => match state.store.get_block(&hash) {
                    Ok(Some(b)) => {
                        let mut result = json!({
                            "hash":        hash_hex,
                            "height":      b.height,
                            "blue_score":  b.blue_score,
                            "tx_count":    b.transactions.len(),
                            "timestamp":   b.header.timestamp,
                            "bits":        format!("0x{:08x}", b.header.bits),
                            "nonce":       b.header.nonce,
                            "parents":     b.header.parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                            "merkle_root": hex::encode(b.header.merkle_root),
                            "size":        b.size_bytes(),
                        });
                        if verbose {
                            result["transactions"] = json!(b.transactions.iter().map(|tx| {
                                format_tx(tx)
                            }).collect::<Vec<_>>());
                        } else {
                            result["txids"] = json!(b.transactions.iter().map(|tx| {
                                hex::encode(tx.txid())
                            }).collect::<Vec<_>>());
                        }
                        result
                    },
                    Ok(None)  => json!({ "error": "not found" }),
                    Err(e)    => json!({ "error": e.to_string() }),
                },
                None => json!({ "error": "invalid hash" }),
            }
        }

        // ── Block explorer: get block by height ──────────────────────
        "getblockbyheight" => {
            let height = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            let verbose = params.and_then(|p| p.get(1)).and_then(|v| v.as_bool()).unwrap_or(false);
            match state.store.get_block_hash_at_height(height) {
                Ok(Some(hash)) => match state.store.get_block(&hash) {
                    Ok(Some(b)) => {
                        let mut result = json!({
                            "hash":        hex::encode(hash),
                            "height":      b.height,
                            "blue_score":  b.blue_score,
                            "tx_count":    b.transactions.len(),
                            "timestamp":   b.header.timestamp,
                            "bits":        format!("0x{:08x}", b.header.bits),
                            "nonce":       b.header.nonce,
                            "parents":     b.header.parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                            "merkle_root": hex::encode(b.header.merkle_root),
                            "size":        b.size_bytes(),
                        });
                        if verbose {
                            result["transactions"] = json!(b.transactions.iter().map(|tx| {
                                format_tx(tx)
                            }).collect::<Vec<_>>());
                        } else {
                            result["txids"] = json!(b.transactions.iter().map(|tx| {
                                hex::encode(tx.txid())
                            }).collect::<Vec<_>>());
                        }
                        result
                    },
                    Ok(None)  => json!({ "error": "block data not found" }),
                    Err(e)    => json!({ "error": e.to_string() }),
                },
                Ok(None) => json!({ "error": "height not found" }),
                Err(e)   => json!({ "error": e.to_string() }),
            }
        }

        // ── Block explorer: recent blocks list ───────────────────────
        "getrecentblocks" => {
            let count = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(10)
                .min(50); // cap at 50
            let tip_height = state.node_state.read().block_count;
            let mut blocks = Vec::new();
            // Iterate ALL heights until we find enough blocks (DAG may have gaps)
            for h in (0..tip_height).rev() {
                if blocks.len() >= count as usize { break; }
                if let Ok(Some(hash)) = state.store.get_block_hash_at_height(h) {
                    if let Ok(Some(b)) = state.store.get_block(&hash) {
                        blocks.push(json!({
                            "hash":      hex::encode(hash),
                            "height":    b.height,
                            "tx_count":  b.transactions.len(),
                            "timestamp": b.header.timestamp,
                            "size":      b.size_bytes(),
                            "bits":      b.header.bits,
                        }));
                    }
                }
            }
            json!(blocks)
        }

        // ── Block explorer: transaction lookup (O(1) via TX index) ────
        "gettransaction" => {
            let txid_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let txid_bytes = match hex::decode(txid_hex).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) {
                Some(b) => b,
                None    => return json!({ "error": "invalid txid" }),
            };
            // O(1) lookup via CF_TX_INDEX
            match state.store.get_tx_location(&txid_bytes) {
                Ok(Some((block_hash, height))) => {
                    let tip = state.node_state.read().block_count;
                    match state.store.get_block(&block_hash) {
                        Ok(Some(block)) => {
                            let tx = block.transactions.iter().find(|t| t.txid() == txid_bytes);
                            match tx {
                                Some(tx) => json!({
                                    "txid":          txid_hex,
                                    "block_hash":    hex::encode(block_hash),
                                    "block_height":  height,
                                    "timestamp":     block.header.timestamp,
                                    "confirmations": tip.saturating_sub(height),
                                    "transaction":   format_tx(tx),
                                }),
                                None => json!({ "error": "tx index stale" }),
                            }
                        },
                        Ok(None) => json!({ "error": "block not found" }),
                        Err(e)   => json!({ "error": e.to_string() }),
                    }
                },
                Ok(None) => json!({ "error": "transaction not found" }),
                Err(e)   => json!({ "error": e.to_string() }),
            }
        }

        // ── Wallet: balance query ────────────────────────────────────
        "getbalance" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => match state.store.get_balance(&ab) {
                    Ok((sats, utxo_count)) => json!({
                        "satoshis":   sats,
                        "bloch":       sats as f64 / 1e8,
                        "utxo_count": utxo_count,
                        "address":    addr,
                    }),
                    Err(e) => json!({ "error": e.to_string() }),
                },
                None => json!({ "error": "invalid address" }),
            }
        }

        // ── Chain: distinct on-chain wallets (addresses with a balance) ──
        "getaddresscount" => {
            match state.store.count_addresses_with_balance() {
                Ok((addrs, utxos)) => json!({
                    "addresses_with_balance": addrs,
                    "utxo_entries":           utxos,
                    "note": "distinct addresses currently holding >=1 UTXO (on-chain wallets with a non-zero balance); addresses that spent to zero or never held a UTXO are not counted",
                }),
                Err(e) => json!({ "error": e.to_string() }),
            }
        }

        // ── Wallet: list UTXOs for address (needed by wallet CLI) ────
        "getutxos" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => match state.store.get_utxos_for_address(&ab) {
                    Ok(utxos) => {
                        let list: Vec<Value> = utxos.iter().map(|(txid, idx, out)| {
                            json!({
                                "txid":          hex::encode(txid),
                                "index":         idx,
                                "value":         out.value,
                                "script_pubkey": hex::encode(&out.script_pubkey),
                            })
                        }).collect();
                        let total: u64 = utxos.iter().map(|(_, _, o)| o.value).sum();
                        json!({
                            "address":    addr,
                            "utxo_count": list.len(),
                            "satoshis":   total,
                            "bloch":       total as f64 / 1e8,
                            "utxos":      list,
                        })
                    },
                    Err(e) => json!({ "error": e.to_string() }),
                },
                None => json!({ "error": "invalid address" }),
            }
        }

        "sendrawtransaction" => {
            let hex_tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex_tx) {
                Err(_)   => json!({ "error": "invalid hex" }),
                // Sprint 1.d: Bitcoin-format tx bytes (replaces bincode).
                // Wallet clients now send stratum_bytes(include_script_sig=true).
                Ok(raw)  => match Transaction::from_stratum_bytes(&raw) {
                    Err(_)  => json!({ "error": "deserialise failed" }),
                    Ok(tx)  => {
                        if tx.is_coinbase() { return json!({ "error": "coinbase not accepted" }); }
                        let current_height = state.dag.read().block_count() as u64;
                        // P0 (roadmap §1.2 / §2.5 #6): PQ signature verification is
                        // CPU-bound. Run it on the blocking pool so a flood of
                        // valid-but-expensive txs on this RPC can't stall the async
                        // reactor. Verification LOGIC is unchanged — only the thread
                        // it runs on. Costs one Transaction clone per call.
                        let store_v = state.store.clone();
                        let tx_v = tx.clone();
                        let verified = tokio::task::spawn_blocking(move || {
                            validate_tx_for_mempool(&tx_v, &store_v, current_height)
                        }).await;
                        match verified.unwrap_or_else(|e| Err(format!("verify task failed: {}", e))) {
                            Err(e)   => json!({ "error": e }),
                            Ok(fee)  => {
                                let txid = tx.txid();
                                match state.mempool.add(tx, fee) {
                                    Err(e) => json!({ "error": e.to_string() }),
                                    Ok(_)  => {
                                        let _ = state.outbound_tx.try_send(NetworkMessage::NewTransaction {
                                            txid, tx_data: raw,
                                        });
                                        json!({ "txid": hex::encode(txid) })
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }

        // ── Phase 2: validateaddress ─────────────────────────────────
        "validateaddress" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let is_mainnet = addr.starts_with(MAINNET_PREFIX);
            let is_testnet = addr.starts_with(TESTNET_PREFIX);
            let valid_prefix = is_mainnet || is_testnet;
            let stripped = addr.trim_start_matches(MAINNET_PREFIX).trim_start_matches(TESTNET_PREFIX);
            // Expect 40 hex (20-byte hash) + 8 hex (4-byte checksum) = 48 hex chars
            let valid_len = stripped.len() == 48;
            let valid_hex = hex::decode(stripped).is_ok();

            // Verify checksum
            let valid_checksum = if valid_prefix && valid_len && valid_hex {
                let bytes = hex::decode(stripped).unwrap_or_default();
                let payload = &bytes[..20];
                use sha3::{Sha3_256, Digest};
                let inner = Sha3_256::digest(payload);
                let outer = Sha3_256::digest(inner);
                &outer[..4] == &bytes[20..24]
            } else {
                false
            };

            let is_valid = valid_prefix && valid_len && valid_hex && valid_checksum;
            json!({
                "address":    addr,
                "isvalid":    is_valid,
                "network":    if is_mainnet { "mainnet" } else if is_testnet { "testnet" } else { "unknown" },
                "checksum":   valid_checksum,
            })
        }

        // ── Phase 2: estimatefee ─────────────────────────────────────
        "estimatefee" => {
            let median = state.mempool.median_fee();
            json!({
                "feerate_sats":  median,
                "feerate_bloch":  median as f64 / 1e8,
                "mempool_size":  state.mempool.size(),
                "note":          "median fee of current mempool entries",
            })
        }

        // ── Phase 2: getrawmempool ───────────────────────────────────
        "getrawmempool" => {
            let verbose = params.and_then(|p| p.get(0)).and_then(|v| v.as_bool()).unwrap_or(false);
            if verbose {
                let entries = state.mempool.entries();
                let list: Vec<serde_json::Value> = entries.iter().map(|(txid, fee, added)| {
                    json!({
                        "txid":     hex::encode(txid),
                        "fee":      fee,
                        "fee_bloch": *fee as f64 / 1e8,
                        "time":     added,
                    })
                }).collect();
                json!({ "size": list.len(), "transactions": list })
            } else {
                let txids: Vec<String> = state.mempool.txids().iter().map(|t| hex::encode(t)).collect();
                json!({ "size": txids.len(), "txids": txids })
            }
        }

        // ── Phase 2: decoderawtransaction ────────────────────────────
        "decoderawtransaction" => {
            let hex_tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex_tx) {
                Err(_)  => json!({ "error": "invalid hex" }),
                // Sprint 1.d: Bitcoin-format tx bytes.
                Ok(raw) => match Transaction::from_stratum_bytes(&raw) {
                    Err(e)  => json!({ "error": format!("decode failed: {}", e) }),
                    Ok(tx)  => {
                        let mut result = format_tx(&tx);
                        result["size"] = json!(raw.len());
                        result
                    }
                },
            }
        }

        // ── Phase 2: getdaginfo ──────────────────────────────────────
        // ── B5f pool seam: getblocktemplate / submitblock ─────────────────
        //
        // Stratum V1/V2 shares cannot carry the Module-SIS solution vector
        // (main.rs refuses to start them), so pool software mines complete
        // SIS blocks and talks to the node over these two methods instead:
        //
        //   getblocktemplate  — everything needed to assemble a candidate
        //                       block: parents, height, blue_score, the
        //                       expected `bits` (computed EXACTLY like
        //                       accept_block: ASERT-Lattice from the genesis
        //                       anchor + parent timestamp), subsidy/vesting
        //                       amounts, and mempool transactions with fees.
        //   submitblock       — full block (Bitcoin wire format hex, i.e.
        //                       Block::to_bitcoin_bytes) routed through the
        //                       same validation pipeline as gossiped blocks.
        //
        // The reference pool consuming this lives in pool/.
        "getblocktemplate" => {
            // Snapshot DAG state: parents = current tips; height = max
            // parent height + 1 (accept_block's VULN-02 rule); blue_score =
            // tip blue score + 1 (mirrors the solo miner loop).
            let (parents, height, blue_score) = {
                let d = state.dag.read();
                let tips = d.tips();
                if tips.is_empty() {
                    return json!({ "error": "node has no tip yet (still syncing genesis?)" });
                }
                let max_parent_height = tips.iter()
                    .filter_map(|t| d.get_block_data(t))
                    .map(|dd| dd.height)
                    .max()
                    .unwrap_or(0);
                (tips, max_parent_height + 1, d.tip_blue_score() + 1)
            };

            // Expected bits — the SAME function accept_block validates with
            // (VULN-01): ASERT-Lattice anchored at genesis, keyed on the
            // parent timestamp.
            let parent_ts = state.store.get_timestamp_at_height(height.saturating_sub(1))
                .ok().flatten().unwrap_or(crate::core::GENESIS_TIMESTAMP);
            let bits = crate::pow::next_bits(
                crate::core::GENESIS_BITS, crate::core::GENESIS_TIMESTAMP, parent_ts, height,
            );

            // Mempool selection + per-tx fees (mirrors stratum's
            // install_fresh_template).
            let txs = state.mempool.get_for_block(2000);
            let mut total_fees: u64 = 0;
            let tx_entries: Vec<Value> = txs.iter().map(|tx| {
                let fee = state.mempool.get_entry(&tx.txid()).map(|e| e.fee).unwrap_or(0);
                total_fees = total_fees.saturating_add(fee);
                json!({
                    "txid": hex::encode(tx.txid()),
                    "fee":  fee,
                    "data": hex::encode(tx.to_stratum_bytes(true)),
                })
            }).collect();

            let subsidy = crate::core::tokenomics_v2::block_subsidy_sat(height);
            let founder_vesting = crate::core::tokenomics_v2::founder_vesting_delta_sat(height);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs();

            json!({
                "parents":              parents.iter().map(hex::encode).collect::<Vec<_>>(),
                "height":               height,
                "blue_score":           blue_score,
                "bits":                 bits,
                "cur_time":             now,
                "parent_time":          parent_ts,
                "subsidy_sat":          subsidy,
                "founder_vesting_sat":  founder_vesting,
                "founder_address_hash": hex::encode(crate::core::tokenomics_v2::founder_address_hash()),
                "total_fees":           total_fees,
                "transactions":         tx_entries,
                // Honesty marker: the PoW regime this chain runs. Shares /
                // blocks are SHAKE-256 hashcash difficulty with a small-k
                // Module-SIS structural gate — NOT lattice bit-security.
                // Soft fork SF-1: the width is selected by the height of the
                // block THIS TEMPLATE mines (k = 4 below the activation
                // height, k = 8 at/above), so pool software that honors this
                // field mines witnesses `validate_pow` will actually accept.
                "residual_coeffs":      crate::pow::canonical_residual_coeffs(height),
            })
        }

        "submitblock" => {
            let block_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let bytes = match hex::decode(block_hex) {
                Ok(b)  => b,
                Err(_) => return json!({ "error": "invalid hex" }),
            };
            let block = match crate::core::Block::from_bitcoin_bytes(&bytes) {
                Ok(b)  => b,
                Err(e) => return json!({ "error": format!("deserialise failed: {}", e) }),
            };
            match &state.submit_block {
                None => json!({ "error": "submitblock not wired on this node (started without a block-submission hook)" }),
                Some(hook) => match hook(block) {
                    Ok(hash_hex) => json!({ "accepted": true, "hash": hash_hex }),
                    Err(reason)  => json!({ "error": format!("rejected: {}", reason) }),
                },
            }
        }

        "getdaginfo" => {
            let dag = state.dag.read();
            let tips = dag.tips();
            let chain = dag.selected_chain();
            let tip = dag.selected_tip();
            let tip_data = tip.and_then(|h| dag.get_block_data(&h).cloned());
            json!({
                "tip":            tip.map(|h| hex::encode(h)),
                "tip_blue_score": tip_data.as_ref().map(|d| d.blue_score).unwrap_or(0),
                "tip_blue_work":  tip_data.as_ref().map(|d| d.blue_work.to_string()).unwrap_or_default(),
                "tip_height":     tip_data.as_ref().map(|d| d.height).unwrap_or(0),
                "block_count":    dag.block_count(),
                "tip_count":      tips.len(),
                "tips":           tips.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
                "chain_length":   chain.len(),
                "k":              crate::core::GHOSTDAG_K,
            })
        }

                "listtransactions" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let limit = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(20).min(1000) as usize;
            let start_height = params.and_then(|p| p.get(2)).and_then(|v| v.as_u64()).unwrap_or(0);
            let end_height = params.and_then(|p| p.get(3)).and_then(|v| v.as_u64())
                .unwrap_or_else(|| state.node_state.read().block_count);
            let offset = params.and_then(|p| p.get(4)).and_then(|v| v.as_u64()).unwrap_or(0) as usize;

            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => {
                    let mut addr_hash = [0u8; 20];
                    if ab.len() >= 20 {
                        addr_hash.copy_from_slice(&ab[..20]);
                    } else {
                        return json!({ "error": "invalid address (too short)" });
                    }
                    match state.store.query_address_history(&addr_hash, start_height, end_height, limit, offset) {
                        Ok(entries) => {
                            let tip = state.node_state.read().block_count;
                            let total = state.store.count_address_history(&addr_hash, start_height, end_height).unwrap_or(0);
                            let txs: Vec<serde_json::Value> = entries.iter().map(|e| {
                                let timestamp = state.store.get_block_timestamp_at_height(e.height).unwrap_or(None).unwrap_or(0);
                                json!({
                                    "txid":          hex::encode(&e.txid),
                                    "block_height":  e.height,
                                    "timestamp":     timestamp,
                                    "confirmations": tip.saturating_sub(e.height),
                                    "direction":     e.direction_str(),
                                    "amount_sats":   e.amount,
                                    "amount_bloch":   e.amount as f64 / 1e8,
                                })
                            }).collect();
                            json!({
                                "address":         addr,
                                "count":           txs.len(),
                                "total_available": total,
                                "start_height":    start_height,
                                "end_height":      end_height,
                                "limit":           limit,
                                "offset":          offset,
                                "transactions":    txs,
                            })
                        }
                        Err(e) => json!({ "error": e.to_string() }),
                    }
                }
                None => json!({ "error": "invalid address" }),
            }
        }

// ── INSERT: gettxsbyblock ──

        // ── Phase 2: getpeerinfo ─────────────────────────────────────
        "getpeerinfo" => {
            let s = state.node_state.read();
            json!({
                "peer_count": s.peer_count,
                "syncing":    s.is_syncing,
            })
        }

        "getpeers" => {
            let s = state.node_state.read();
            let peers: Vec<serde_json::Value> = s.peer_addresses.iter().map(|addr| {
                // Extract IP from multiaddr like /ip4/1.2.3.4/tcp/16110/p2p/12D3...
                let ip = addr.split('/').enumerate()
                    .find(|(i, seg)| *i > 0 && seg.parse::<std::net::Ipv4Addr>().is_ok())
                    .map(|(_, s)| s.to_string())
                    .unwrap_or_default();
                let peer_id = addr.split("/p2p/").last().unwrap_or("").to_string();
                json!({
                    "address": addr,
                    "ip": ip,
                    "peer_id": peer_id,
                })
            }).collect();
            json!({
                "peer_count": s.peer_count,
                "peers": peers,
            })
        }

        // ── Treasury (community dev fund) ───────────────────────────────
        // V2 (ADR-028): replaces V1 "gettreasury" with multi-pool report.
        // Returns subsidy split for the next block + per-pool address/balance,
        // gracefully reporting "pending_phase_6" for pools whose address
        // constants are still None.
        "getpools" => {
            use crate::core::tokenomics_v2 as v2;
            let current_height = state.node_state.read().block_count;
            let next_height    = current_height.saturating_add(1);
            let subsidy        = v2::block_subsidy_sat(next_height);
            let (miner_subsidy, validator_subsidy, oracle_subsidy) =
                v2::split_subsidy_sat(subsidy);
            let founder_vesting = v2::founder_vesting_delta_sat(next_height);
            let vesting_per_month_sat: u64 = v2::founder_monthly_tranche_sat();

            let validator_pool = match v2::VALIDATOR_POOL_ADDRESS_HASH {
                Some(h) => {
                    let (balance, utxo_count) = state.store.get_balance(&h).unwrap_or((0, 0));
                    json!({
                        "share_bps":             v2::VALIDATOR_SHARE_BPS,
                        "subsidy_per_block_sat": validator_subsidy,
                        "address_hash_hex":      hex::encode(h),
                        "address":               crate::crypto::address_from_hash(&h, false),
                        "balance_sat":           balance,
                        "balance_bloch":          balance as f64 / 1e8,
                        "utxo_count":            utxo_count,
                        "status":                "active",
                    })
                }
                None => json!({
                    "share_bps":             v2::VALIDATOR_SHARE_BPS,
                    "subsidy_per_block_sat": validator_subsidy,
                    "address_hash_hex":      null,
                    "address":               null,
                    "balance_sat":           0,
                    "balance_bloch":          0.0,
                    "utxo_count":            0,
                    "status":                "pending_phase_6",
                }),
            };

            let oracle_pool = match v2::ORACLE_POOL_ADDRESS_HASH {
                Some(h) => {
                    let (balance, utxo_count) = state.store.get_balance(&h).unwrap_or((0, 0));
                    json!({
                        "share_bps":             v2::ORACLE_SHARE_BPS,
                        "subsidy_per_block_sat": oracle_subsidy,
                        "address_hash_hex":      hex::encode(h),
                        "address":               crate::crypto::address_from_hash(&h, false),
                        "balance_sat":           balance,
                        "balance_bloch":          balance as f64 / 1e8,
                        "utxo_count":            utxo_count,
                        "status":                "active",
                    })
                }
                None => json!({
                    "share_bps":             v2::ORACLE_SHARE_BPS,
                    "subsidy_per_block_sat": oracle_subsidy,
                    "address_hash_hex":      null,
                    "address":               null,
                    "balance_sat":           0,
                    "balance_bloch":          0.0,
                    "utxo_count":            0,
                    "status":                "pending_phase_6",
                }),
            };

            let founder = match v2::FOUNDER_ADDRESS_HASH {
                Some(h) => {
                    let (balance, utxo_count) = state.store.get_balance(&h).unwrap_or((0, 0));
                    json!({
                        "share_bps":                  null,
                        "vesting_per_month_sat":      vesting_per_month_sat,
                        "vesting_amount_at_next_sat": founder_vesting,
                        "vesting_active_at_next":     founder_vesting > 0,
                        "vesting_total_sat":          v2::FOUNDER_PREMINE_TOTAL_SAT,
                        "vesting_months":             v2::FOUNDER_VESTING_MONTHS,
                        "address_hash_hex":           hex::encode(h),
                        "address":                    crate::crypto::address_from_hash(&h, false),
                        "balance_sat":                balance,
                        "balance_bloch":               balance as f64 / 1e8,
                        "utxo_count":                 utxo_count,
                        "status":                     "active",
                    })
                }
                None => json!({
                    "share_bps":                  null,
                    "vesting_per_month_sat":      vesting_per_month_sat,
                    "vesting_amount_at_next_sat": founder_vesting,
                    "vesting_active_at_next":     founder_vesting > 0,
                    "vesting_total_sat":          v2::FOUNDER_PREMINE_TOTAL_SAT,
                    "vesting_months":             v2::FOUNDER_VESTING_MONTHS,
                    "address_hash_hex":           null,
                    "address":                    null,
                    "balance_sat":                0,
                    "balance_bloch":               0.0,
                    "utxo_count":                 0,
                    "status":                     "pending_phase_6",
                }),
            };

            json!({
                "current_height":         current_height,
                "next_block_height":      next_height,
                "subsidy_per_block_sat":  subsidy,
                "subsidy_per_block_bloch": subsidy as f64 / 1e8,
                "miner_share_sat":        miner_subsidy,
                "pools": {
                    "validator_pool": validator_pool,
                    "oracle_pool":    oracle_pool,
                    "founder":        founder,
                },
            })
        }

        // ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//      in src/rpc/mod.rs (last arm of the match in dispatch())
//
// ═════════════════════════════════════════════════════════════════════════════

        // ── Sprint B: Chain analytics ──────────────────────────────────────

        "getchainstats" => {
            match crate::analytics::chain_stats(&state.store, &state.mempool) {
                Ok(s) => json!({
                    "total_blocks":         s.total_blocks,
                    "total_txs":            s.total_txs,
                    "avg_txs_per_block":    s.avg_txs_per_block,
                    "blocks_last_24h":      s.blocks_last_24h,
                    "txs_last_24h":         s.txs_last_24h,
                    "avg_block_time_secs":  s.avg_block_time,
                    "current_difficulty":   s.current_difficulty,
                    "hashrate_hs":          s.hashrate_estimate,
                    "hashrate_human":       format_hashrate(s.hashrate_estimate),
                }),
                Err(e) => json!({ "error": e }),
            }
        }

        "getsupplydistribution" => {
            match crate::analytics::supply_distribution(&state.store) {
                Ok(d) => {
                    let tiers: Vec<Value> = d.tiers.iter().map(|t| json!({
                        "label":          t.label,
                        "address_count":  t.address_count,
                        "total_sats":     t.total_sats,
                        "total_bloch":     t.total_bloch,
                        "pct_of_supply":  t.pct_of_supply,
                    })).collect();
                    json!({
                        "tiers":            tiers,
                        "total_addresses":  d.total_addresses,
                        "total_sats":       d.total_sats,
                        "total_bloch":       d.total_bloch,
                    })
                }
                Err(e) => json!({ "error": e }),
            }
        }

        "gethashrate" => {
            match crate::analytics::chain_stats(&state.store, &state.mempool) {
                Ok(s) => json!({
                    "hashrate_hs":          s.hashrate_estimate,
                    "hashrate_human":       format_hashrate(s.hashrate_estimate),
                    "avg_block_time_secs":  s.avg_block_time,
                    "current_difficulty":   s.current_difficulty,
                }),
                Err(e) => json!({ "error": e }),
            }
        }

        "getdifficultyhistory" => {
            let limit = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as usize;
            let limit = limit.min(100); // cap at 100

            let points = crate::analytics::difficulty_history(&state.store, limit);
            let items: Vec<Value> = points.iter().map(|p| json!({
                "height":     p.height,
                "bits":       p.bits,
                "bits_hex":   format!("0x{:08x}", p.bits),
                "timestamp":  p.timestamp,
                "target_hex": p.target_hex,
            })).collect();
            json!({
                "count": items.len(),
                "points": items,
            })
        }

        "getblocktimepercentiles" => {
            let window = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_u64())
                .unwrap_or(100) as usize;
            let window = window.clamp(10, 1000);

            let stats = crate::analytics::block_time_percentiles(&state.store, window);
            json!({
                "sample_size":  stats.sample_size,
                "window":       window,
                "min_secs":     stats.min,
                "p50_secs":     stats.p50,
                "p90_secs":     stats.p90,
                "p99_secs":     stats.p99,
                "max_secs":     stats.max,
                "avg_secs":     stats.avg,
                "target_secs":  crate::core::TARGET_BLOCK_TIME,
            })
        }

        "gettxstatus" => {
            let txid_hex = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let txid_bytes = match hex::decode(txid_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => return json!({ "error": "invalid txid" }),
            };
            let mut txid_arr = [0u8; 32];
            txid_arr.copy_from_slice(&txid_bytes);

            // Check mempool first
            if state.mempool.contains(&txid_arr) {
                return json!({
                    "status":        "pending",
                    "in_mempool":    true,
                    "confirmations": 0,
                    "txid":          txid_hex,
                });
            }

            // Check storage
            match state.store.get_tx_location(&txid_arr) {
                Ok(Some((_block_hash, height))) => {
                    let tip = state.node_state.read().block_count;
                    let confirmations = tip.saturating_sub(height) + 1;
                    json!({
                        "status":        if confirmations >= 100 { "final" } else { "confirmed" },
                        "in_mempool":    false,
                        "confirmations": confirmations,
                        "block_height":  height,
                        "txid":          txid_hex,
                    })
                }
                _ => json!({
                    "status":        "unknown",
                    "in_mempool":    false,
                    "confirmations": 0,
                    "txid":          txid_hex,
                })
            }
        }

        "getaddressinfo" => {
            let addr_str = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let addr_bytes = match parse_address(addr_str) {
                Some(b) if b.len() == 20 => b,
                _ => return json!({ "error": "invalid address" }),
            };
            let mut addr_hash = [0u8; 20];
            addr_hash.copy_from_slice(&addr_bytes);

            match crate::analytics::address_info(&state.store, &state.mempool, addr_str, &addr_hash) {
                Ok(info) => json!({
                    "address":           info.address,
                    "balance_sats":      info.balance_sats,
                    "balance_bloch":      info.balance_bloch,
                    "utxo_count":        info.utxo_count,
                    "pending_incoming":  info.pending_incoming,
                    "pending_outgoing":  info.pending_outgoing,
                    "pool_role":         info.pool_role,
                }),
                Err(e) => json!({ "error": e }),
            }
        }

        "estimatefeeadvanced" => {
            let fee = crate::analytics::estimate_fee_advanced(&state.mempool);
            json!({
                "next_block_sats":  fee.next_block_sats,
                "medium_priority":  fee.medium_priority,
                "slow_priority":    fee.slow_priority,
                "mempool_median":   fee.mempool_median,
                "mempool_size":     fee.mempool_size,
                "recommended_bloch": format!("{:.8}", fee.medium_priority as f64 / 1e8),
            })
        }

        "getmempoolstats" => {
            let stats = crate::analytics::mempool_stats(&state.mempool);
            let buckets: Vec<Value> = stats.buckets.iter().map(|b| json!({
                "range":    b.range,
                "tx_count": b.tx_count,
            })).collect();
            json!({
                "size":        stats.size,
                "total_fees":  stats.total_fees,
                "min_fee":     stats.min_fee,
                "max_fee":     stats.max_fee,
                "median_fee":  stats.median_fee,
                "avg_fee":     stats.avg_fee,
                "buckets":     buckets,
            })
        }

        "validateaddressverbose" => {
            let addr_str = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            match crate::address::Address::parse(addr_str) {
                Ok(a) => json!({
                    "valid":    true,
                    "address":  addr_str,
                    "network":  if a.is_mainnet() { "mainnet" } else { "testnet" },
                    "hash_hex": hex::encode(a.hash()),
                    "prefix":   if a.is_mainnet() { crate::core::MAINNET_PREFIX } else { crate::core::TESTNET_PREFIX },
                }),
                Err(e) => json!({
                    "valid":   false,
                    "address": addr_str,
                    "reason":  format!("{}", e),
                }),
            }
        }

        // ── End of Sprint B additions ──────────────────────────────────────

"gettxsbyblock" => {
            // Accept either hash (hex string, 64 chars) or height (number).
            let p0 = params.and_then(|p| p.get(0));
            let block_hash = match p0 {
                Some(v) if v.is_string() => {
                    let s = v.as_str().unwrap();
                    if s.len() == 64 {
                        hex::decode(s).ok().and_then(|b| {
                            let mut h = [0u8; 32];
                            if b.len() == 32 { h.copy_from_slice(&b); Some(h) } else { None }
                        })
                    } else {
                        // try parse as height-as-string
                        s.parse::<u64>().ok().and_then(|h| state.store.get_block_hash_at_height(h).ok().flatten())
                    }
                }
                Some(v) if v.is_u64() => {
                    let h = v.as_u64().unwrap();
                    state.store.get_block_hash_at_height(h).ok().flatten()
                }
                _ => None,
            };

            match block_hash {
                Some(bh) => {
                    match state.store.get_block(&bh) {
                        Ok(Some(block)) => {
                            let txs: Vec<serde_json::Value> = block.transactions.iter().map(|tx| {
                                let txid = tx.txid();
                                // Sprint 1.d: size is length of stratum (Bitcoin-format) bytes.
                                // include_script_sig=true matches what lives on the wire and on disk.
                                let size_bytes = tx.to_stratum_bytes(true).len() as u32;
                                // Fee: sum(inputs_value) - sum(outputs_value). For coinbase, fee = 0 by convention.
                                let outputs_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
                                let fee_sats: u64 = if tx.is_coinbase() {
                                    0
                                } else {
                                    let inputs_total: u64 = tx.inputs.iter().map(|inp| {
                                        state.store.get_utxo_including_spent(&inp.prev_txid, inp.prev_index)
                                            .ok().flatten().map(|o| o.value).unwrap_or(0)
                                    }).sum();
                                    inputs_total.saturating_sub(outputs_total)
                                };
                                json!({
                                    "txid":           hex::encode(&txid),
                                    "size_bytes":     size_bytes,
                                    "inputs_count":   tx.inputs.len(),
                                    "outputs_count":  tx.outputs.len(),
                                    "fee_sats":       fee_sats,
                                    "is_coinbase":    tx.is_coinbase(),
                                })
                            }).collect();
                            json!({
                                "block_hash":      hex::encode(&bh),
                                "block_height":    block.height,
                                "block_timestamp": block.header.timestamp,
                                "count":           txs.len(),
                                "txs":             txs,
                            })
                        }
                        Ok(None) => json!({ "error": "block not found" }),
                        Err(e) => json!({ "error": e.to_string() }),
                    }
                }
                None => json!({ "error": "invalid block identifier (expected hex hash or height)" }),
            }
        }

// ── INSERT: getaddressbalance_at_height ──

"getaddressbalance_at_height" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let height = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(0);

            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => {
                    let mut addr_hash = [0u8; 20];
                    if ab.len() >= 20 {
                        addr_hash.copy_from_slice(&ab[..20]);
                    } else {
                        return json!({ "error": "invalid address" });
                    }
                    match state.store.balance_at_height(&addr_hash, height) {
                        Ok(balance) => {
                            let tx_count = state.store.count_address_history(&addr_hash, 0, height).unwrap_or(0);
                            json!({
                                "address":               addr,
                                "height":                height,
                                "balance_sats":          balance,
                                "balance_bloch":          balance as f64 / 1e8,
                                "tx_count_up_to_height": tx_count,
                            })
                        }
                        Err(e) => json!({ "error": e.to_string() }),
                    }
                }
                None => json!({ "error": "invalid address" }),
            }
        }

        // Bloch-SIS-Linux L3: attestation status (pluggable provider; reports
        // attested=false when no TEE is active).
        "getattestation" => {
            // Optional freshness nonce (params[0]) echoed into the report and,
            // for a real TEE, bound into the quote's report-data.
            let nonce = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).map(String::from);
            serde_json::to_value(crate::attestation::current_report(nonce))
                .unwrap_or_else(|e| json!({ "error": format!("attestation serialize: {}", e) }))
        }

        _ => json!({ "error": format!("unknown method: {}", method) }),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a bloch1q/bloch1t address to 20-byte pubkey hash
/// Sprint K: Checksum-validated address parsing.
/// Delegates to `Address::parse()` from Sprint A — enforces full 54-char
/// checksummed format (bloch1q + 20-byte hash + 4-byte checksum, hex-encoded).
/// Rejects the legacy 46-char checksum-less form that the previous implementation
/// silently accepted.
fn parse_address(addr: &str) -> Option<Vec<u8>> {
    crate::address::Address::parse(addr)
        .ok()
        .map(|a| a.hash().to_vec())
}

/// Format a transaction for JSON output
fn format_tx(tx: &Transaction) -> Value {
    json!({
        "txid":     hex::encode(tx.txid()),
        "version":  tx.version,
        "coinbase": tx.is_coinbase(),
        "inputs":   tx.inputs.iter().map(|inp| json!({
            "prev_txid":  hex::encode(inp.prev_txid),
            "prev_index": inp.prev_index,
            "sequence":   inp.sequence,
        })).collect::<Vec<_>>(),
        "outputs":  tx.outputs.iter().enumerate().map(|(i, out)| json!({
            "index":         i,
            "value":         out.value,
            "bloch":          out.value as f64 / 1e8,
            "script_pubkey": hex::encode(&out.script_pubkey),
        })).collect::<Vec<_>>(),
        "locktime": tx.locktime,
    })
}

/// Validate a transaction for mempool/broadcast acceptance.
/// Returns the fee (total_in - total_out) on success.
///
/// Sprint N-min: Now checks coinbase maturity (previously only gossip path did).
/// Callers must pass current chain height for the maturity check. Height of 0
/// (genesis only) skips the check since there is no matured coinbase to spend.
fn validate_tx_for_mempool(tx: &Transaction, store: &Arc<Storage>, current_height: u64) -> Result<u64, String> {
    use sha3::{Sha3_256, Digest};

    // Coinbase maturity check (VULN-03). Single source of truth in
    // core::check_coinbase_maturity; this call site is one of two.
    crate::core::check_coinbase_maturity(tx, current_height, |txid| {
        store.get_coinbase_height(txid).ok().flatten()
    })?;

    let mut total_in = 0u64;
    for (i, inp) in tx.inputs.iter().enumerate() {
        let utxo = store.get_utxo(&inp.prev_txid, inp.prev_index)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("UTXO {}:{} not found", hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;
        total_in = total_in.checked_add(utxo.value).ok_or("overflow")?;
        let (sig, pk) = Transaction::parse_script_sig(&inp.script_sig)
            .ok_or_else(|| format!("malformed script_sig at input {}", i))?;
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
        if pk_hash != utxo.script_pubkey { return Err(format!("pubkey mismatch at input {}", i)); }
        if !crate::crypto::verify(&pk, &tx.sighash(i, crate::core::node_chain_id()), &sig) {
            return Err(format!("invalid signature at input {}", i));
        }
    }
    let total_out: u64 = tx.outputs.iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or_else(|| "output sum overflow".to_string())?;
    if total_in < total_out { return Err("inputs < outputs".into()); }
    Ok(total_in - total_out)
}

// ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//      look for the "parse_address" helper (around line 560+)
//
// ═════════════════════════════════════════════════════════════════════════════

/// Format a hashrate in H/s into human-readable units (H/s, KH/s, MH/s, GH/s, TH/s, PH/s, EH/s).
fn format_hashrate(hs: f64) -> String {
    const UNITS: &[(&str, f64)] = &[
        ("EH/s", 1e18),
        ("PH/s", 1e15),
        ("TH/s", 1e12),
        ("GH/s", 1e9),
        ("MH/s", 1e6),
        ("KH/s", 1e3),
    ];
    for (label, threshold) in UNITS {
        if hs >= *threshold {
            return format!("{:.2} {}", hs / threshold, label);
        }
    }
    format!("{:.2} H/s", hs)
}
