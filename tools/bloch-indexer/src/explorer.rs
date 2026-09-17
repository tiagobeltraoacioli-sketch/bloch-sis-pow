// SPDX-License-Identifier: AGPL-3.0-or-later
//! Explorer API over a verified, canonical ledger snapshot.
use crate::{index::Index, json::Json, model::*};
fn error(code: u16, msg: &str) -> (u16, Json) { (code, Json::Obj(vec![("error", Json::s(msg))])) }
fn parameter<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').filter_map(|s| s.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v)
}
fn provenance(ix: &Index, height: u64, mut fields: Vec<(&'static str, Json)>) -> Json {
    let tip = &ix.chain[height as usize];
    fields.extend([
        ("as_of_slot", Json::u(tip.slot)), ("as_of_height", Json::u(height)),
        ("chain_tip", Json::hex32(&tip.block_id)),
        ("source", Json::s("local archival blocks.log")),
        ("verification", Json::s(if ix.replay.is_some() {
            "consensus replay and state-root verification"
        } else { "archival structure only; consensus replay disabled" })),
    ]);
    Json::Obj(fields)
}
fn output(ix: &Index, op: OutPoint, u: &Utxo, height: u64) -> Json {
    let spent = ix.spent_at.get(&op).copied().filter(|h| *h <= height);
    Json::Obj(vec![
        ("txid", Json::hex32(&op.txid)), ("vout", Json::u(op.vout as u64)),
        ("value_sat", Json::sat(u.value_sat as u128)), ("script_hash", Json::hex32(&u.script_hash)),
        ("created_height", Json::u(u.created_height)), ("created_slot", Json::u(ix.chain[u.created_height as usize].slot)),
        ("spent_height", spent.map(Json::u).unwrap_or(Json::Null)),
        ("spent_slot", spent.map(|h| Json::u(ix.chain[h as usize].slot)).unwrap_or(Json::Null)),
        ("as_of_slot", Json::u(ix.chain[height as usize].slot)),
    ])
}
pub fn transaction(t: &TxRow) -> Json {
    Json::Obj(vec![
        ("txid", Json::hex32(&t.txid)), ("block_id", Json::hex32(&t.block_id)),
        ("slot", Json::u(t.slot)), ("height", Json::u(t.height)), ("index", Json::u(t.tx_index as u64)),
        ("kind", Json::s(t.kind.name())), ("size_bytes", Json::u(t.size_bytes)),
        ("fee_sat", t.fee_sat.map(Json::sat).unwrap_or(Json::Null)), ("stake_sat", Json::sat(t.stake_sat)),
        ("inputs", Json::Arr(t.inputs.iter().zip(&t.input_values).map(|(op, u)| Json::Obj(vec![
            ("txid", Json::hex32(&op.txid)), ("vout", Json::u(op.vout as u64)),
            ("value_sat", Json::sat(u.value_sat as u128)), ("script_hash", Json::hex32(&u.script_hash)),
        ])).collect())),
        ("outputs", Json::Arr(t.outputs.iter().enumerate().map(|(v, (value, sh))| Json::Obj(vec![
            ("txid", Json::hex32(&t.txid)), ("vout", Json::u(v as u64)),
            ("value_sat", Json::sat(*value as u128)), ("script_hash", Json::hex32(sh)),
        ])).collect())),
    ])
}
/// Snapshot cursors stay valid across appends. A replaced anchor is a 409,
/// never an offset silently interpreted against a different canonical chain.
pub fn route(path: &str, query: &str, ix: &Index) -> (u16, Json) {
    if ix.sync_error.is_some() || ix.checked_at.elapsed().as_secs() > 30 {
        return error(503, "index synchronization unavailable; retry later");
    }
    for key in ["limit", "cursor", "block"] {
        let mut matches = query.split('&').filter(|part| part.split('=').next() == Some(key));
        if matches.next().is_some_and(|part| !part.contains('=')) || matches.next().is_some() {
            return error(400, "query parameters must have a unique value");
        }
    }
    let limit_text = parameter(query, "limit").unwrap_or("100");
    if !limit_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return error(400, "limit must be between 1 and 1000");
    }
    let limit = match limit_text.parse::<usize>() {
        Ok(n) if (1..=1000).contains(&n) => n,
        _ => return error(400, "limit must be between 1 and 1000"),
    };
    let (height, offset) = if let Some(cursor) = parameter(query, "cursor") {
        let parts: Vec<_> = cursor.split('-').collect();
        if parts.len() != 3 { return error(400, "invalid cursor"); }
        let (Ok(h), Ok(o), Ok(id)) = (parts[0].parse::<u64>(), parts[2].parse::<usize>(), crate::parse_script_hash(parts[1])) else {
            return error(400, "invalid cursor");
        };
        if ix.block_at_height(h).map(|b| b.block_id) != Some(id) { return error(409, "snapshot reorganized; restart pagination"); }
        (h, o)
    } else { (ix.height(), 0) };
    let next = |total: usize, count: usize| if offset.saturating_add(count) < total {
        Json::s(format!("{}-{}-{}", height, crate::hex32(&ix.chain[height as usize].block_id), offset + count))
    } else { Json::Null };
    let seg: Vec<_> = path.trim_matches('/').split('/').collect();
    match seg.as_slice() {
        ["health"] => (200, provenance(ix, ix.height(), vec![
            ("ok", Json::Bool(true)), ("indexed_to_slot", Json::u(ix.tip().slot)),
            ("indexed_to_height", Json::u(ix.height())),
            ("finalized_height", Json::u(ix.chain.iter().find(|b| b.block_id == ix.tip().finalized_root).map(|b| b.height).unwrap_or(0))),
            ("lag_slots", Json::u(0)), ("lag_basis", Json::s("local archival log; not network wall clock")),
            ("transactions", Json::u(ix.txs.len() as u64)),
        ])),
        ["transactions"] => {
            let rows = || ix.txs.iter().rev().filter(|t| t.height <= height);
            let total = rows().count();
            let mut items = Vec::new();
            let mut bytes = 0;
            for row in rows().skip(offset).take(limit) {
                let item = transaction(row);
                let size = item.to_string().len();
                if !items.is_empty() && bytes + size > 3 * 1024 * 1024 { break; }
                bytes += size; items.push(item);
            }
            let cursor = next(total, items.len());
            (200, provenance(ix, height, vec![("transactions", Json::Arr(items)), ("next_cursor", cursor)]))
        }
        ["tx", hash] => {
            let Ok(id) = crate::parse_script_hash(hash) else { return error(400, "invalid txid"); };
            let Some(hits) = ix.by_txid.get(&id) else { return error(404, "transaction not on indexed chain"); };
            let block = match parameter(query, "block") {
                Some(value) => match crate::parse_script_hash(value) {
                    Ok(block) => Some(block),
                    Err(_) => return error(400, "invalid block selector"),
                },
                None => None,
            };
            let matching = || hits.iter().filter_map(|i| ix.txs.get(*i))
                .filter(|t| t.height <= height && block.is_none_or(|b| b == t.block_id));
            let total = matching().count();
            if total == 0 { return error(404, "transaction not on the selected snapshot or block"); }
            if total != 1 { return (409, provenance(ix, height, vec![
                ("error", Json::s("ambiguous transaction; select a block")),
                ("total", Json::u(total as u64)),
                ("matches", Json::Arr(matching().skip(offset).take(limit).map(transaction).collect())),
                ("next_cursor", next(total, limit)),
            ])); }
            let Some(row) = matching().next() else { return error(500, "transaction index inconsistent"); };
            let Json::Obj(fields) = transaction(row) else { unreachable!() };
            (200, provenance(ix, height, fields))
        }
        ["block", hash, "transactions"] => {
            let Ok(id) = crate::parse_script_hash(hash) else { return error(400, "invalid block id"); };
            let Some(b) = ix.chain.iter().find(|b| b.block_id == id) else { return error(404, "block not indexed"); };
            if b.height > height { return error(404, "block is newer than the selected snapshot"); }
            (200, provenance(ix, height, vec![("block_id", Json::hex32(&id)), ("slot", Json::u(b.slot)), ("height", Json::u(b.height)), ("tx_count", Json::u(b.tx_count as u64)), ("transactions", Json::Arr(ix.txs_of_height(b.height).iter().map(transaction).collect()))]))
        }
        ["outpoint", hash, vout] => {
            let (Ok(id), Ok(vout)) = (crate::parse_script_hash(hash), vout.parse::<u32>()) else { return error(400, "invalid outpoint"); };
            let op = OutPoint { txid: id, vout };
            match ix.all_outputs.get(&op).filter(|u| u.created_height <= height) {
                Some(u) => { let Json::Obj(fields) = output(ix, op, u, height) else { unreachable!() }; (200, provenance(ix, height, fields.into_iter().filter(|(k, _)| *k != "as_of_slot").collect())) },
                None => error(404, "outpoint not indexed"),
            }
        }
        [kind @ ("utxos" | "history"), hash] => {
            let Ok(sh) = crate::parse_script_hash(hash) else { return error(400, "invalid script hash"); };
            let all = ix.history.get(&sh).map(Vec::as_slice).unwrap_or(&[]);
            let rows = || all.iter().rev().filter(|e| e.height <= height).filter(|e| {
                if *kind == "history" { return true; }
                let op = OutPoint { txid: e.outpoint_txid, vout: e.vout };
                e.direction == Direction::In && ix.spent_at.get(&op).is_none_or(|h| *h > height)
            });
            let total = rows().count();
            let items = rows().skip(offset).take(limit).map(|e| {
                if *kind == "utxos" {
                    let op = OutPoint { txid: e.outpoint_txid, vout: e.vout };
                    return output(ix, op, &ix.all_outputs[&op], height);
                }
                Json::Obj(vec![("kind", Json::s(if e.direction == Direction::In {"created"} else {"spent"})),
                    ("txid", Json::hex32(&e.outpoint_txid)), ("transaction_id", Json::hex32(&e.txid)),
                    ("vout", Json::u(e.vout as u64)), ("value_sat", Json::sat(e.amount_sat)),
                    ("slot", Json::u(e.slot)), ("height", Json::u(e.height)), ("block_id", Json::hex32(&e.block_id)),
                ])
            }).collect();
            (200, provenance(ix, height, vec![("script_hash", Json::hex32(&sh)), ("total", Json::u(total as u64)), (if *kind == "utxos" {"utxos"} else {"events"}, Json::Arr(items)), ("next_cursor", next(total, limit))]))
        }
        _ => error(404, "unknown read endpoint"),
    }
}
