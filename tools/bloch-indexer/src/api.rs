// SPDX-License-Identifier: AGPL-3.0-or-later

//! The read API — HTTP/1.1 and JSON over `std` only.
//!
//! Same shape and the same reasons as the node's `rpc.rs`: this serves a dozen
//! read methods, and pulling an async stack in for that would add ~90
//! transitive crates to a repository whose lock file is part of a reproducible
//! consensus build. The cost is stated rather than hidden — this speaks the
//! subset of HTTP/1.1 a JSON client needs (GET, `Content-Length`, no chunked
//! encoding, no keep-alive, no TLS, no compression) and is not a
//! general-purpose web server.
//!
//! ## What it is allowed to be, that the node's RPC is not
//!
//! The node's RPC is unauthenticated, unrated and on the consensus thread, so
//! every request it serves is a request consensus paid for. This server holds
//! the index in an `RwLock` behind a reader-per-connection pool with a hard
//! connection cap, and the only writer is the sync thread. A client that
//! hammers it degrades **this** process. That transfer of blast radius is the
//! entire point of the index.
//!
//! ## Every answer names its chain
//!
//! `slot` and `height` are positional and a reorg moves them. So every block
//! answer carries `block_id` alongside them, and every answer carries the tip's
//! `block_id` in `chain_tip`. A caller that cached a height can tell whether
//! the chain it cached from is the chain it is talking to now.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::index::Index;
use crate::json::Json;
use crate::model::*;

/// Worker threads. Fixed, not one-per-connection.
///
/// The first version of this server spawned a thread per connection with a
/// cap of 128. Measured on an explorer-shaped mix, that gave 1,088 req/s at
/// concurrency 4 and then **collapsed to 121 req/s with a p99 of 13 s at
/// concurrency 32** — thread churn plus a socket per request. A bounded pool
/// with keep-alive is what an explorer backend actually needs, and it means
/// the failure mode under overload is a queued or refused connection rather
/// than an unbounded thread count.
const WORKERS: usize = 64;

/// Connections waiting for a worker. Past this the listener answers 503 and
/// closes, which is a bounded, visible refusal — the thing the node's RPC
/// cannot do for a historical query because it has no rate limit at all.
const BACKLOG: usize = 256;

/// Requests served on one kept-alive connection before it is closed, so a
/// single client cannot hold a worker for ever.
const MAX_KEEPALIVE_REQUESTS: usize = 512;

/// How long one connection may hold a worker before it is politely retired.
///
/// Keep-alive and a fixed pool interact badly without this, and the failure is
/// invisible in the averages: with more open connections than workers, the
/// connections that got a worker keep it for their whole 512-request budget
/// while the rest sit in the queue. Measured at concurrency 64 against 16
/// workers, the p50 stayed at 5.6 ms and the **max reached 10.6 s** — the wait
/// of a connection that was accepted and then simply not served. A deadline
/// makes the pool rotate, so a slow answer is bounded by the deadline instead
/// of by another client's request budget.
const MAX_CONNECTION_HOLD: Duration = Duration::from_secs(2);

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_IDLE: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Largest page any list endpoint will return. An explorer that wants more
/// pages; a caller that wants everything at once is the load pattern this
/// index exists to stop.
const PAGE_MAX: usize = 1_000;
const PAGE_DEFAULT: usize = 100;

pub type Shared = Arc<RwLock<Index>>;

pub fn serve(bind: &str, index: Shared) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    eprintln!("bloch-indexer: read API on http://{bind}/ ({WORKERS} workers)");
    let (tx, rx): (SyncSender<TcpStream>, Receiver<TcpStream>) = sync_channel(BACKLOG);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let rx = Arc::clone(&rx);
        let ix = Arc::clone(&index);
        std::thread::spawn(move || loop {
            let stream = {
                let g = match rx.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                match g.recv() {
                    Ok(s) => s,
                    Err(_) => return,
                }
            };
            let _ = stream.set_read_timeout(Some(KEEPALIVE_IDLE));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_nodelay(true);
            serve_connection(&stream, &ix);
        });
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // `try_send` rather than `send`: a full queue must be an immediate,
        // stated refusal, not an accept that sits unanswered until a client
        // times out. Under the old design that wait was where the 13-second
        // p99 came from.
        if let Err(std::sync::mpsc::TrySendError::Full(s)) = tx.try_send(stream) {
            let _ = respond(&s, 503, &err("index busy; retry"), false);
        }
    }
    Ok(())
}

/// Serve one connection, keeping it alive across requests unless the client
/// asked otherwise or something went wrong.
fn serve_connection(stream: &TcpStream, index: &Shared) {
    let mut reader = BufReader::new(stream);
    let opened = Instant::now();
    for served in 0..MAX_KEEPALIVE_REQUESTS {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut head = line.len();
        let mut wants_close = line.contains("HTTP/1.0");
        loop {
            let mut h = String::new();
            match reader.read_line(&mut h) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    head += n;
                    if head > MAX_HEADER_BYTES {
                        let _ = respond(stream, 431, &err("request head too large"), false);
                        return;
                    }
                    let t = h.trim();
                    if t.is_empty() {
                        break;
                    }
                    if t.eq_ignore_ascii_case("connection: close") {
                        wants_close = true;
                    }
                }
            }
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("/");
        if method != "GET" {
            let _ = respond(stream, 405, &err("this index is read-only; GET only"), false);
            return;
        }
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target, ""),
        };
        // The LAST response this connection will serve says `Connection:
        // close`, so the client retires the socket itself. Hitting the cap and
        // simply hanging up looks to a client exactly like a server fault: an
        // earlier revision did that, and a load run showed a steady
        // `WORKERS x (requests / MAX_KEEPALIVE_REQUESTS)` trickle of client
        // errors that were nothing but this cap firing.
        let last =
            served + 1 == MAX_KEEPALIVE_REQUESTS || opened.elapsed() >= MAX_CONNECTION_HOLD;
        let (code, body) = route(path, query, index);
        if respond(stream, code, &body, !wants_close && !last).is_err() || wants_close || last {
            return;
        }
    }
}

fn err(msg: &str) -> Json {
    Json::Obj(vec![("error", Json::s(msg))])
}

fn qparam(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

fn qnum(query: &str, key: &str) -> Option<u64> {
    qparam(query, key)?.parse().ok()
}

fn page(query: &str) -> (usize, usize) {
    let limit = qnum(query, "limit").unwrap_or(PAGE_DEFAULT as u64) as usize;
    let offset = qnum(query, "offset").unwrap_or(0) as usize;
    (limit.min(PAGE_MAX), offset)
}

fn route(path: &str, query: &str, index: &Shared) -> (u16, Json) {
    let ix = match index.read() {
        Ok(g) => g,
        Err(_) => return (500, err("index lock poisoned")),
    };
    let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
    match seg.as_slice() {
        [""] | ["health"] => (200, Json::Obj(vec![("ok", Json::Bool(true))])),

        ["status"] => (200, status_json(&ix)),

        // ── Blocks ──────────────────────────────────────────────────────────
        ["block", "height", h] => match h.parse::<u64>().ok().and_then(|h| ix.block_at_height(h)) {
            Some(r) => (200, block_json(&ix, r)),
            None => (404, err("no block at that height")),
        },
        ["block", "slot", s] => match s.parse::<u64>().ok().and_then(|s| ix.block_at_slot(s)) {
            Some(r) => (200, block_json(&ix, r)),
            None => (404, err("no block at that slot (a slot may be empty)")),
        },
        ["block", "id", id] => match crate::parse_script_hash(id)
            .ok()
            .and_then(|id| ix.chain.iter().find(|r| r.block_id == id))
        {
            Some(r) => (200, block_json(&ix, r)),
            None => (404, err("no block with that id on the indexed chain")),
        },
        ["block", "height", h, "txs"] => match h.parse::<u64>() {
            Ok(h) => (
                200,
                Json::Obj(vec![
                    ("height", Json::u(h)),
                    (
                        "transactions",
                        Json::Arr(ix.txs_of_height(h).iter().map(tx_json).collect()),
                    ),
                    ("chain_tip", Json::hex32(&ix.tip().block_id)),
                ]),
            ),
            Err(_) => (400, err("height must be a number")),
        },
        ["blocks"] => {
            let from = qnum(query, "from").unwrap_or(0);
            let (limit, _) = page(query);
            let to = qnum(query, "to").unwrap_or(from + limit as u64 - 1).min(ix.height());
            if to < from {
                return (400, err("to < from"));
            }
            let n = ((to - from + 1) as usize).min(PAGE_MAX);
            let rows: Vec<Json> = (from..from + n as u64)
                .filter_map(|h| ix.block_at_height(h))
                .map(|r| block_summary_json(r))
                .collect();
            (
                200,
                Json::Obj(vec![
                    ("from", Json::u(from)),
                    ("count", Json::u(rows.len() as u64)),
                    ("blocks", Json::Arr(rows)),
                    ("chain_tip", Json::hex32(&ix.tip().block_id)),
                ]),
            )
        }

        // ── Transactions ────────────────────────────────────────────────────
        // The primary permalink: unique unconditionally.
        ["tx", block_id, idx] => {
            let Ok(id) = crate::parse_script_hash(block_id) else {
                return (400, err("block_id must be 64 hex characters"));
            };
            let Ok(i) = idx.parse::<u32>() else {
                return (400, err("tx index must be a number"));
            };
            match ix.txs.iter().find(|t| t.block_id == id && t.tx_index == i) {
                Some(t) => (200, tx_json(t)),
                None => (404, err("no such transaction on the indexed chain")),
            }
        }
        // The secondary index. Returns a LIST, because `txid` is unique for
        // transfers and NOT unique for the staking variants — see model.rs.
        ["txid", h] => {
            let Ok(id) = crate::parse_script_hash(h) else {
                return (400, err("txid must be 64 hex characters"));
            };
            let hits: Vec<Json> = ix
                .by_txid
                .get(&id)
                .map(|v| v.iter().filter_map(|i| ix.txs.get(*i)).map(tx_json).collect())
                .unwrap_or_default();
            if hits.is_empty() {
                return (404, err("no transaction with that id on the indexed chain"));
            }
            (
                200,
                Json::Obj(vec![
                    ("txid", Json::s(h.to_string())),
                    ("count", Json::u(hits.len() as u64)),
                    (
                        "note",
                        Json::s(
                            "a txid is unique for transfers; the staking variants carry no \
                             nonce, so two identical ones share an id. Every match is listed.",
                        ),
                    ),
                    ("matches", Json::Arr(hits)),
                ]),
            )
        }
        ["outpoint", txid, vout] => {
            let Ok(t) = crate::parse_script_hash(txid) else {
                return (400, err("txid must be 64 hex characters"));
            };
            let Ok(v) = vout.parse::<u32>() else {
                return (400, err("vout must be a number"));
            };
            match ix.utxo.get(&OutPoint { txid: t, vout: v }) {
                Some(u) => (
                    200,
                    Json::Obj(vec![
                        ("txid", Json::s(txid.to_string())),
                        ("vout", Json::u(v as u64)),
                        ("value_sat", Json::sat(u.value_sat as u128)),
                        ("script_hash", Json::hex32(&u.script_hash)),
                        ("created_height", Json::u(u.created_height)),
                        ("spent", Json::Bool(false)),
                    ]),
                ),
                None => (
                    404,
                    err("not in the unspent set: either never created, or already spent"),
                ),
            }
        }

        // ── Addresses (script_hash) ─────────────────────────────────────────
        ["script", h, "balance"] => match crate::parse_script_hash(h) {
            Err(e) => (400, err(&e)),
            Ok(sh) => (
                200,
                Json::Obj(vec![
                    ("script_hash", Json::hex32(&sh)),
                    ("balance_sat", Json::sat(ix.balance_of(&sh))),
                    (
                        "utxo_count",
                        Json::u(ix.by_script.get(&sh).map(|s| s.len()).unwrap_or(0) as u64),
                    ),
                    ("shape", Json::s(shape_of(&sh))),
                    ("height", Json::u(ix.height())),
                    ("chain_tip", Json::hex32(&ix.tip().block_id)),
                ]),
            ),
        },
        ["script", h, "utxos"] => match crate::parse_script_hash(h) {
            Err(e) => (400, err(&e)),
            Ok(sh) => {
                let (limit, offset) = page(query);
                let mut ops: Vec<OutPoint> =
                    ix.by_script.get(&sh).map(|s| s.iter().copied().collect()).unwrap_or_default();
                ops.sort();
                let total = ops.len();
                let items: Vec<Json> = ops
                    .into_iter()
                    .skip(offset)
                    .take(limit)
                    .filter_map(|op| ix.utxo.get(&op).map(|u| (op, u)))
                    .map(|(op, u)| {
                        Json::Obj(vec![
                            ("txid", Json::hex32(&op.txid)),
                            ("vout", Json::u(op.vout as u64)),
                            ("value_sat", Json::sat(u.value_sat as u128)),
                            ("created_height", Json::u(u.created_height)),
                        ])
                    })
                    .collect();
                (
                    200,
                    Json::Obj(vec![
                        ("script_hash", Json::hex32(&sh)),
                        ("total", Json::u(total as u64)),
                        ("offset", Json::u(offset as u64)),
                        ("utxos", Json::Arr(items)),
                    ]),
                )
            }
        },
        ["script", h, "history"] => match crate::parse_script_hash(h) {
            Err(e) => (400, err(&e)),
            Ok(sh) => {
                let (limit, offset) = page(query);
                let all = ix.history.get(&sh).map(|v| v.as_slice()).unwrap_or(&[]);
                let items: Vec<Json> = all
                    .iter()
                    .rev()
                    .skip(offset)
                    .take(limit)
                    .map(|e| {
                        Json::Obj(vec![
                            ("height", Json::u(e.height)),
                            ("slot", Json::u(e.slot)),
                            ("block_id", Json::hex32(&e.block_id)),
                            ("txid", Json::hex32(&e.txid)),
                            (
                                "direction",
                                Json::s(match e.direction {
                                    Direction::In => "in",
                                    Direction::Out => "out",
                                }),
                            ),
                            ("amount_sat", Json::sat(e.amount_sat)),
                        ])
                    })
                    .collect();
                (
                    200,
                    Json::Obj(vec![
                        ("script_hash", Json::hex32(&sh)),
                        ("total", Json::u(all.len() as u64)),
                        ("offset", Json::u(offset as u64)),
                        ("history", Json::Arr(items)),
                    ]),
                )
            }
        },

        // ── Epochs, finality, participation ─────────────────────────────────
        ["epochs"] => {
            let from = qnum(query, "from").unwrap_or(0);
            let (limit, _) = page(query);
            let rows: Vec<Json> =
                ix.epochs.range(from..).take(limit).map(|(_, r)| epoch_json(r)).collect();
            (
                200,
                Json::Obj(vec![
                    ("count", Json::u(rows.len() as u64)),
                    ("epochs", Json::Arr(rows)),
                ]),
            )
        }
        ["epoch", e] => match e.parse::<u64>().ok().and_then(|e| ix.epochs.get(&e)) {
            Some(r) => (200, epoch_json(r)),
            None => (404, err("no such epoch on the indexed chain")),
        },
        ["epoch", e, "participation"] => match e.parse::<u64>() {
            Err(_) => (400, err("epoch must be a number")),
            Ok(e) => {
                let rows: Vec<Json> = ix
                    .participation
                    .range((e, 0)..=(e, u32::MAX))
                    .map(|((_, v), p)| participation_json(*v, p))
                    .collect();
                (
                    200,
                    Json::Obj(vec![
                        ("epoch", Json::u(e)),
                        ("validators", Json::u(rows.len() as u64)),
                        ("participation", Json::Arr(rows)),
                    ]),
                )
            }
        },
        ["validator", v, "participation"] => match v.parse::<u32>() {
            Err(_) => (400, err("validator index must be a number")),
            Ok(v) => {
                let from = qnum(query, "from").unwrap_or(0);
                let (limit, _) = page(query);
                let rows: Vec<Json> = ix
                    .participation
                    .range((from, 0)..)
                    .filter(|((_, vi), _)| *vi == v)
                    .take(limit)
                    .map(|((e, _), p)| {
                        Json::Obj(vec![
                            ("epoch", Json::u(*e)),
                            ("attested_target", Json::u(p.attested_target as u64)),
                            ("included_here", Json::u(p.included_here as u64)),
                            ("proposed", Json::u(p.proposed as u64)),
                        ])
                    })
                    .collect();
                (
                    200,
                    Json::Obj(vec![
                        ("validator", Json::u(v as u64)),
                        ("count", Json::u(rows.len() as u64)),
                        ("epochs", Json::Arr(rows)),
                    ]),
                )
            }
        },

        // ── Supply ──────────────────────────────────────────────────────────
        ["supply"] => {
            let from = qnum(query, "from").unwrap_or(0);
            let to = qnum(query, "to").unwrap_or(ix.height()).min(ix.height());
            let step = qnum(query, "step").unwrap_or(1).max(1);
            let mut rows = Vec::new();
            let mut h = from;
            while h <= to && rows.len() < PAGE_MAX {
                if let Some(r) = ix.block_at_height(h) {
                    rows.push(Json::Obj(vec![
                        ("height", Json::u(r.height)),
                        ("slot", Json::u(r.slot)),
                        ("epoch", Json::u(r.epoch)),
                        ("eutxo_total_sat", Json::sat(r.eutxo_total_sat)),
                        ("eutxo_count", Json::u(r.eutxo_count)),
                        ("fees_sat", Json::sat(r.fees_sat)),
                    ]));
                }
                h += step;
            }
            (
                200,
                Json::Obj(vec![
                    (
                        "note",
                        Json::s(
                            "eutxo_total_sat is the satoshi held in unspent outputs, derived by \
                             replay. It is NOT the whole money supply: staked and delegated \
                             balances live in the validator records, not in the eUTXO set.",
                        ),
                    ),
                    ("count", Json::u(rows.len() as u64)),
                    ("series", Json::Arr(rows)),
                ]),
            )
        }

        _ => (404, err("no such route")),
    }
}

fn shape_of(sh: &ScriptHash) -> &'static str {
    if sh[20..] == [0u8; 12] {
        "carried (Genesis-3 hash160, zero-extended) — or a native hash that landed here by \
         chance, p = 2^-96"
    } else {
        "native (SHA3-256 of a hybrid public key)"
    }
}

fn status_json(ix: &Index) -> Json {
    let tip = ix.tip();
    Json::Obj(vec![
        ("height", Json::u(ix.height())),
        ("tip_slot", Json::u(tip.slot)),
        ("tip_epoch", Json::u(tip.epoch)),
        ("chain_tip", Json::hex32(&tip.block_id)),
        ("tip_state_root", Json::hex32(&tip.state_root)),
        ("eutxo_count", Json::u(tip.eutxo_count)),
        ("eutxo_total_sat", Json::sat(tip.eutxo_total_sat)),
        ("transactions", Json::u(ix.txs.len() as u64)),
        ("script_hashes_with_balance", Json::u(ix.balance.len() as u64)),
        ("blocks_applied", Json::u(ix.stats.blocks_applied)),
        ("blocks_rolled_back", Json::u(ix.stats.blocks_rolled_back)),
        ("reorgs_handled", Json::u(ix.stats.reorgs_handled)),
        ("deepest_reorg", Json::u(ix.stats.deepest_reorg)),
        ("rebuilds", Json::u(ix.stats.rebuilds)),
        ("undecodable_txs", Json::u(ix.stats.undecodable_txs)),
        (
            "finality_note",
            Json::s(
                "`finalized` on this chain is not a latch across a reorg — a node has been \
                 observed below its own finalized checkpoint — so this index keeps its undo \
                 journal regardless of finality and does not treat any height as settled.",
            ),
        ),
    ])
}

fn block_summary_json(r: &BlockRow) -> Json {
    Json::Obj(vec![
        ("height", Json::u(r.height)),
        ("slot", Json::u(r.slot)),
        ("epoch", Json::u(r.epoch)),
        ("block_id", Json::hex32(&r.block_id)),
        ("proposer_index", Json::u(r.proposer_index as u64)),
        ("tx_count", Json::u(r.tx_count as u64)),
        ("attestation_count", Json::u(r.attestation_count as u64)),
        ("bytes", Json::u(r.frame_len as u64)),
    ])
}

fn block_json(ix: &Index, r: &BlockRow) -> Json {
    Json::Obj(vec![
        ("height", Json::u(r.height)),
        ("slot", Json::u(r.slot)),
        ("epoch", Json::u(r.epoch)),
        ("block_id", Json::hex32(&r.block_id)),
        ("parent", Json::hex32(&r.parent)),
        ("proposer_index", Json::u(r.proposer_index as u64)),
        ("state_root", Json::hex32(&r.state_root)),
        ("body_root", Json::hex32(&r.body_root)),
        ("justified_root", Json::hex32(&r.justified_root)),
        ("finalized_root", Json::hex32(&r.finalized_root)),
        ("tx_count", Json::u(r.tx_count as u64)),
        ("attestation_count", Json::u(r.attestation_count as u64)),
        ("bytes", Json::u(r.frame_len as u64)),
        ("outputs_created_sat", Json::sat(r.outputs_created_sat)),
        ("inputs_spent_sat", Json::sat(r.inputs_spent_sat)),
        ("fees_sat", Json::sat(r.fees_sat)),
        ("eutxo_total_sat", Json::sat(r.eutxo_total_sat)),
        ("eutxo_count", Json::u(r.eutxo_count)),
        ("transactions", Json::Arr(ix.txs_of_height(r.height).iter().map(tx_json).collect())),
        ("chain_tip", Json::hex32(&ix.tip().block_id)),
    ])
}

fn tx_json(t: &TxRow) -> Json {
    Json::Obj(vec![
        ("permalink", Json::s(format!("/tx/{}/{}", crate::hex32(&t.block_id), t.tx_index))),
        ("txid", Json::hex32(&t.txid)),
        ("block_id", Json::hex32(&t.block_id)),
        ("height", Json::u(t.height)),
        ("slot", Json::u(t.slot)),
        ("tx_index", Json::u(t.tx_index as u64)),
        ("kind", Json::s(t.kind.name())),
        (
            "inputs",
            Json::Arr(
                t.inputs
                    .iter()
                    .map(|i| {
                        Json::Obj(vec![
                            ("txid", Json::hex32(&i.txid)),
                            ("vout", Json::u(i.vout as u64)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "outputs",
            Json::Arr(
                t.outputs
                    .iter()
                    .enumerate()
                    .map(|(v, (val, sh))| {
                        Json::Obj(vec![
                            ("vout", Json::u(v as u64)),
                            ("value_sat", Json::sat(*val as u128)),
                            ("script_hash", Json::hex32(sh)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("declared_bytes", Json::u(t.declared_bytes)),
        ("tip_millisat_per_gas", Json::sat(t.tip_millisat_per_gas)),
        ("fee_sat", t.fee_sat.map(Json::sat).unwrap_or(Json::Null)),
    ])
}

fn epoch_json(r: &EpochRow) -> Json {
    Json::Obj(vec![
        ("epoch", Json::u(r.epoch)),
        ("first_slot", Json::u(r.first_slot)),
        ("last_slot", Json::u(r.last_slot)),
        ("blocks", Json::u(r.blocks as u64)),
        ("slots", Json::u(bloch_pos_committee::SLOTS_PER_EPOCH)),
        ("attestations_included", Json::u(r.attestations_included)),
        ("distinct_proposers", Json::u(r.distinct_proposers as u64)),
        ("justified_root", Json::hex32(&r.justified_root)),
        ("finalized_root", Json::hex32(&r.finalized_root)),
        ("eutxo_total_sat", Json::sat(r.eutxo_total_sat)),
    ])
}

fn participation_json(v: u32, p: &Participation) -> Json {
    Json::Obj(vec![
        ("validator", Json::u(v as u64)),
        ("attested_target", Json::u(p.attested_target as u64)),
        ("included_here", Json::u(p.included_here as u64)),
        ("proposed", Json::u(p.proposed as u64)),
    ])
}

fn respond(
    mut stream: &TcpStream,
    code: u16,
    body: &Json,
    keep_alive: bool,
) -> std::io::Result<()> {
    let text = body.to_string();
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nConnection: {}\r\n\r\n",
        text.len(),
        if keep_alive { "keep-alive" } else { "close" }
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(text.as_bytes())?;
    stream.flush()
}
