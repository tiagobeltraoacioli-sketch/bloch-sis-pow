//! Stratum V1 share submission handler.
//!
//! Receives `mining.submit` from a miner, reconstructs the coinbase
//! transaction and full Block from the template + extranonce2 +
//! ntime + nonce, validates the PoW against the target, and routes
//! the block through the `AcceptBlockFn` callback into the node's
//! accept_block path.
//!
//! Wire format of mining.submit (stratum V1):
//! ```text
//! params: [username, job_id, extranonce2_hex, ntime_hex, nonce_hex]
//! ```
//!
//! Error codes returned (all Bitcoin-stratum standard):
//! - 20 Other               — malformed params, parse errors
//! - 21 JobNotFoundOrStale  — job_id not in retention window
//! - 22 DuplicateShare      — (job_id, en2, nonce) triple already seen
//! - 23 LowDifficulty       — hash does not meet the target
//! - 24 Unauthorized        — session not authorized
//!
//! Solo mode semantics: every accepted share IS a block. No
//! share-target / block-target distinction — if the hash meets
//! the declared bits, it's a valid block. This simplifies the
//! handler considerably; pool-mode variants (AA.2) will add share
//! accounting above this code.

use std::sync::Arc;
use serde_json::Value;
use log::{info, warn};

use crate::core::{
    Block, BlockHeader, MerkleRoot, MiningHeader, Transaction,
    bits_to_target, hash_meets_target, sha256d_pow_valid,
    difficulty_to_target, difficulty_from_bits,
};

use super::jobs::{walk_merkle_branch, stratum_txid_of_bytes};
use super::protocol::{ErrorCode, StratumError, StratumRequest, StratumResponse};
use super::session::{Session, MAX_JOB_ID_LEN};

/// True iff big-endian target `a` is >= `b` (i.e. `a` is EASIER-or-equal:
/// any hash meeting `b` also meets `a`). Used to enforce, in target space,
/// the consensus-firewall invariant that a share is never harder than a block.
fn target_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for (x, y) in a.iter().zip(b.iter()) {
        if x > y { return true; }
        if x < y { return false; }
    }
    true
}

/// Callback invoked on a valid share. The implementer (typically
/// main.rs wiring) does:
/// 1. Take the block
/// 2. Route through the node's accept_block path
/// 3. Return Ok(block_hash_hex) if accepted, Err(reason) if rejected
///
/// Rejection reasons from accept_block include already-known tip,
/// reorg loser, finality violation, etc. These get propagated back
/// to the miner as error-20 (Other).
pub type AcceptBlockFn = dyn Fn(Block) -> Result<String, String> + Send + Sync;

/// Handle a single mining.submit request.
pub fn handle_submit(
    session:       &Arc<Session>,
    req:           &StratumRequest,
    accept_block:  &AcceptBlockFn,
) -> StratumResponse {
    let id = req.id.clone();

    // 1. Rate limit before anything else — cheap, cuts off floods.
    if let Err(e) = session.check_submit_rate() {
        return StratumResponse::error(id, e);
    }

    // 2. Must be authorized.
    if !session.is_authorized() {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::Unauthorized, "unauthorized worker"));
    }

    // 3. Parse params array: [username, job_id, en2_hex, ntime_hex, nonce_hex]
    let params = match req.params.as_array() {
        Some(a) if a.len() >= 5 => a,
        _ => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other,
                "submit requires 5 params [username, job_id, en2, ntime, nonce]")),
    };

    let job_id = match params[1].as_str() {
        Some(s) => s.to_string(),
        None    => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "job_id must be string")),
    };

    // Bound job_id length BEFORE it is stored in the dedup set — a legit id
    // ('{sid:x}-{height}-{ctr:x}') is well under the cap; a longer one is an
    // attacker padding the per-session dedup set for memory amplification.
    if job_id.len() > MAX_JOB_ID_LEN {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::JobNotFoundOrStale, "job_id too long"));
    }

    let en2_hex = match params[2].as_str() {
        Some(s) => s.to_string(),
        None    => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "extranonce2 must be hex string")),
    };

    let ntime_hex = match params[3].as_str() {
        Some(s) => s.to_string(),
        None    => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "ntime must be hex string")),
    };

    let nonce_hex = match params[4].as_str() {
        Some(s) => s.to_string(),
        None    => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "nonce must be hex string")),
    };

    // Optional 6th param: the version-rolling (BIP320 / ASICBoost) nVersion the
    // miner actually hashed. A version-rolling ASIC (common via rentals) sends
    // it; without honoring it we re-hash the block with the job's UNROLLED
    // version and reject an otherwise-valid solve. Absent → use the job version.
    let version_rolled: Option<u32> = params.get(5)
        .and_then(|v| v.as_str())
        .and_then(|s| {
            let t = s.trim();
            let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
            u32::from_str_radix(t, 16).ok()
        });

    // 4. Decode hex.
    let en2 = match hex::decode(&en2_hex) {
        Ok(v) if v.len() == 4 => v,
        Ok(_)  => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "extranonce2 must be 4 bytes")),
        Err(_) => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "extranonce2 not valid hex")),
    };

    let ntime = match parse_hex_u32(&ntime_hex) {
        Ok(n)  => n,
        Err(_) => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "ntime not valid hex u32")),
    };

    let nonce = match parse_hex_u32(&nonce_hex) {
        Ok(n)  => n,
        Err(_) => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "nonce not valid hex u32")),
    };

    // 5. Duplicate detection. The (job_id, en2, nonce) triple uniquely
    //    identifies a share; submitting the same one twice is error-22.
    //    Note: we check duplicate BEFORE template lookup so that repeated
    //    submissions against a just-evicted job still get error-22
    //    (not error-21), matching miner expectations.
    //    ntime is part of the key: cpuminer rolls ntime by default, so two
    //    submissions differing only in ntime are DISTINCT solutions and must
    //    not collide as false duplicates.
    if session.record_submission(&job_id, &en2_hex, &ntime_hex, &nonce_hex).is_err() {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::DuplicateShare, "duplicate share"));
    }

    // 6. Look up the template. Stale/unknown → error-21.
    let template = match session.find_template(&job_id) {
        Some(t) => t,
        None    => return StratumResponse::error(id,
            StratumError::new(ErrorCode::JobNotFoundOrStale,
                format!("job_id '{}' not in retention window", job_id))),
    };

    // The header version the miner ACTUALLY hashed: the job version with the
    // BIP320-masked bits replaced by the miner's version-roll (if any). Used for
    // BOTH the PoW check and the assembled block, so a version-rolling ASIC's
    // solve hashes and stores consistently instead of being re-hashed with the
    // unrolled version (which would reject a valid block).
    const VERSION_ROLLING_MASK: u32 = 0x1fffe000;
    let eff_version = match version_rolled {
        Some(v) => (template.version & !VERSION_ROLLING_MASK) | (v & VERSION_ROLLING_MASK),
        None    => template.version,
    };

    // 7. Reconstruct the coinbase bytes:
    //    coinb1 || extranonce1 || extranonce2 || coinb2
    let mut coinbase_bytes = Vec::with_capacity(
        template.coinb1.len() + 4 + 4 + template.coinb2.len()
    );
    coinbase_bytes.extend_from_slice(&template.coinb1);
    coinbase_bytes.extend_from_slice(&session.extranonce1);
    coinbase_bytes.extend_from_slice(&en2);
    coinbase_bytes.extend_from_slice(&template.coinb2);

    // 8. Parse back into a Transaction (for block assembly).
    let coinbase_tx = match Transaction::from_stratum_bytes(&coinbase_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            warn!("stratum: session {} coinbase parse failed: {}", session.id, e);
            return StratumResponse::error(id,
                StratumError::new(ErrorCode::Other, format!("malformed coinbase: {}", e)));
        }
    };

    // Defense in depth: the reconstructed tx must be a valid coinbase.
    // A non-coinbase here means the template was constructed badly or
    // the miner swapped bytes outside the extranonce region.
    if !coinbase_tx.is_coinbase() {
        warn!("stratum: session {} reconstructed non-coinbase tx", session.id);
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "reconstructed tx is not a coinbase"));
    }

    // 9. Compute coinbase txid via stratum bytes (same algorithm the
    //    miner used), then walk the merkle branch up to merkle_root.
    let coinbase_txid = stratum_txid_of_bytes(&coinbase_bytes);
    let merkle_root   = walk_merkle_branch(coinbase_txid, &template.merkle_branch);

    // 10. Assemble the 80-byte mining header and check PoW.
    let mh = MiningHeader {
        version:     eff_version,
        prev_hash:   template.prev_hash,
        merkle_root,
        timestamp:   ntime,
        bits:        template.bits,
        nonce,
    };

    let hash         = mh.pow_hash();
    let block_target = bits_to_target(template.bits);   // consensus target — NEVER derived from share diff
    let net_diff     = difficulty_from_bits(template.bits);

    // DUAL-TARGET. The share target is the miner-facing accept bound; the
    // block target is the consensus bound. The share is capped to be no harder
    // than a block (share_diff <= net_diff), and the cap is re-enforced in
    // TARGET space below so rounding can never make the share harder than the
    // block: a hash meeting the block target ALWAYS meets the share target.
    let eff_share_diff = session.share_difficulty().min(net_diff);
    let share_target_raw = difficulty_to_target(eff_share_diff);
    let share_target = if target_ge(&share_target_raw, &block_target) {
        share_target_raw
    } else {
        block_target
    };

    // (a) SHARE GATE (weak) — the miner-facing accept/reject. Height-gated
    //     endianness: post-fork the hash is compared Bitcoin little-endian, so
    //     a standard SHA-256 miner's share is accepted (the whole point of the
    //     fork). Pre-fork it stays legacy big-endian.
    if !sha256d_pow_valid(&hash, &share_target, template.height) {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::LowDifficulty, "share above target"));
    }

    // (b) Accounting + vardiff: count the accepted share and, if the window
    //     criteria are met, retarget and push a fresh mining.set_difficulty
    //     now (ordered before any subsequent notify by the FIFO channel).
    if let Some(new_diff) = session.record_share_and_maybe_retarget(net_diff) {
        let _ = session.send_set_difficulty(new_diff);
    }

    // (c) BLOCK GATE (strong) — solo semantics preserved. A valid share that
    //     is NOT a block returns success WITHOUT assembling a Block or calling
    //     accept_block. Same height-gated endianness as the consensus check.
    if !sha256d_pow_valid(&hash, &block_target, template.height) {
        return StratumResponse::ok(id, Value::from(true));
    }

    // 11. Share meets the block target: this IS a block. Assemble the
    //     full Block and route through accept_block.
    let mut transactions = Vec::with_capacity(template.other_txs.len() + 1);
    transactions.push(coinbase_tx);
    transactions.extend(template.other_txs.iter().cloned());

    let block = Block {
        header: BlockHeader {
            version:     eff_version,
            parents:     template.parents.clone(),
            merkle_root: MerkleRoot(merkle_root),
            timestamp:   ntime as u64,
            bits:        template.bits,
            nonce:       nonce as u64,
        },
        transactions,
        blue_score: template.blue_score,
        height:     template.height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    };

    // Sanity: the assembled block's pow_hash must equal mh.pow_hash.
    // If not, the MiningHeader projection in core::BlockHeader has drifted
    // from MiningHeader::pow_hash and this block would be rejected by the DAG
    // despite passing our local target check. Promoted from debug_assert to a
    // LIVE (release) check: fail the submit rather than ship a drifted block.
    if block.header.pow_hash() != hash {
        warn!("stratum: session {} mining-header projection mismatch — refusing to ship drifted block", session.id);
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "internal: mining header projection mismatch"));
    }

    // 12. Deliver to node. Success → report block hash, log the find.
    //     Failure → propagate reason as error-20.
    match accept_block(block) {
        Ok(block_hash_hex) => {
            info!(
                "stratum: session {} BLOCK FOUND h={} hash={} (by {})",
                session.id,
                template.height,
                &block_hash_hex[..block_hash_hex.len().min(16)],
                session.authorized_addr().as_deref().unwrap_or("?"),
            );
            StratumResponse::ok(id, Value::from(true))
        }
        Err(reason) => {
            warn!("stratum: session {} block rejected by node: {}", session.id, reason);
            StratumResponse::error(id,
                StratumError::new(ErrorCode::Other, format!("rejected: {}", reason)))
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Parse an 8-character big-endian hex string as u32.
/// Accepts with or without "0x" prefix, case-insensitive.
fn parse_hex_u32(s: &str) -> Result<u32, ()> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(trimmed, 16).map_err(|_| ())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Transaction, TxInput, TxOutput};
    use crate::stratum::jobs::Template;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex as StdMutex};
    use serde_json::json;

    fn mk_session() -> Arc<Session> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let s = Arc::new(Session::new(1, addr));
        s.set_authorized_addr("bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45".to_string());
        s.set_state(crate::stratum::session::SessionState::Authorized);
        s
    }

    /// Accept-block callback that records every block it sees and
    /// always succeeds. For happy-path tests.
    fn accepting_callback() -> (Box<AcceptBlockFn>, Arc<StdMutex<Vec<Block>>>) {
        let recorded: Arc<StdMutex<Vec<Block>>> = Arc::new(StdMutex::new(Vec::new()));
        let r = recorded.clone();
        let cb: Box<AcceptBlockFn> = Box::new(move |block: Block| {
            let hash_hex = hex::encode(block.header.pow_hash());
            r.lock().unwrap().push(block);
            Ok(hash_hex)
        });
        (cb, recorded)
    }

    /// Callback that always fails — simulates accept_block rejecting.
    fn rejecting_callback(reason: &'static str) -> Box<AcceptBlockFn> {
        Box::new(move |_: Block| Err(reason.to_string()))
    }

    fn submit_req(
        id:    i64,
        job:   &str,
        en2:   &str,
        ntime: &str,
        nonce: &str,
    ) -> StratumRequest {
        StratumRequest {
            id:     Some(Value::from(id)),
            method: "mining.submit".to_string(),
            params: json!(["username", job, en2, ntime, nonce]),
        }
    }

    /// Find a nonce that makes the template's hash meet the target,
    /// given a concrete extranonce1/2 pair and ntime. Mimics what a
    /// real miner would do, except we bound the search so tests never
    /// hang. For easy targets (0x207fffff, ~50% per nonce) we expect
    /// to find a valid nonce in a handful of iterations.
    ///
    /// Without this helper the happy-path tests are flaky: nonce=0
    /// just happens to meet the target about half the time, which
    /// turns CI into a coin flip.
    fn find_valid_nonce(
        template: &crate::stratum::jobs::Template,
        en1:      &[u8; 4],
        en2:      &[u8; 4],
        ntime:    u32,
    ) -> Option<u32> {
        use crate::core::{MiningHeader, bits_to_target, hash_meets_target};
        use crate::stratum::jobs::{stratum_txid_of_bytes, walk_merkle_branch};

        let mut coinbase_bytes = Vec::new();
        coinbase_bytes.extend_from_slice(&template.coinb1);
        coinbase_bytes.extend_from_slice(en1);
        coinbase_bytes.extend_from_slice(en2);
        coinbase_bytes.extend_from_slice(&template.coinb2);

        let coinbase_txid = stratum_txid_of_bytes(&coinbase_bytes);
        let merkle_root   = walk_merkle_branch(coinbase_txid, &template.merkle_branch);
        let target        = bits_to_target(template.bits);

        for nonce in 0u32..10_000 {
            let mh = MiningHeader {
                version: template.version,
                prev_hash: template.prev_hash,
                merkle_root,
                timestamp: ntime,
                bits: template.bits,
                nonce,
            };
            if hash_meets_target(&mh.pow_hash(), &target) {
                return Some(nonce);
            }
        }
        None
    }

    /// Build a template whose target is so easy (0x207fffff, regtest-like)
    /// that nonce=0 will find a valid block in deterministic tests.
    fn easy_template(job_id: &str) -> Template {
        // 0x207fffff: mantissa 0x7fffff, exponent 0x20 = shift left 32*8=256 bits;
        // target is effectively a 256-bit max value, meaning every hash meets it.
        let bits_easy = 0x207fffff;
        let miner_spk = vec![0x11u8; 20];
        Template::build(
            vec![[0u8; 32]],
            1, 0, bits_easy, &miner_spk, 0,
            Vec::new(), b"test-pool",
            job_id.to_string(),
        )
    }

    // ── Error path: unauthorized session ─────────────────────────

    #[test]
    fn submit_unauthorized_returns_24() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let s = Arc::new(Session::new(1, addr));
        // NOT authorized.
        let (cb, _) = accepting_callback();
        let req = submit_req(1, "j1", "00000000", "00000000", "00000000");
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 24);
    }

    // ── Error path: missing params ───────────────────────────────

    #[test]
    fn submit_with_4_params_errors_20() {
        let s = mk_session();
        let (cb, _) = accepting_callback();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: "mining.submit".to_string(),
            params: json!(["user", "job1", "00000000", "00000000"]), // only 4
        };
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 20);
    }

    #[test]
    fn submit_with_malformed_en2_errors_20() {
        let s = mk_session();
        let (cb, _) = accepting_callback();
        let req = submit_req(1, "j1", "ZZZZZZZZ", "00000000", "00000000");
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 20);
    }

    #[test]
    fn submit_with_wrong_en2_length_errors_20() {
        let s = mk_session();
        let (cb, _) = accepting_callback();
        // "00" is 1 byte, not 4
        let req = submit_req(1, "j1", "00", "00000000", "00000000");
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 20);
    }

    // ── Error path: unknown job_id ───────────────────────────────

    #[test]
    fn submit_unknown_job_id_returns_21() {
        let s = mk_session();
        let (cb, _) = accepting_callback();
        let req = submit_req(1, "nonexistent-job", "00000000", "00000000", "00000000");
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 21);
    }

    // ── Duplicate detection ──────────────────────────────────────

    #[test]
    fn duplicate_share_returns_22() {
        let s = mk_session();
        s.push_template(easy_template("job-dup"));
        let (cb, _) = accepting_callback();

        // First submit succeeds (or fails w/ valid reason); second with
        // same (job, en2, nonce) gets error-22 unconditionally.
        let req1 = submit_req(1, "job-dup", "cafebabe", "00000000", "00000000");
        let _ = handle_submit(&s, &req1, &*cb);

        let req2 = submit_req(2, "job-dup", "cafebabe", "00000000", "00000000");
        let resp2 = handle_submit(&s, &req2, &*cb);
        assert_err_code(&resp2, 22);
    }

    #[test]
    fn different_en2_not_marked_as_duplicate() {
        let s = mk_session();
        s.push_template(easy_template("job-x"));
        let (cb, _) = accepting_callback();

        let r1 = submit_req(1, "job-x", "00000001", "00000000", "00000000");
        let r2 = submit_req(2, "job-x", "00000002", "00000000", "00000000");
        let _ = handle_submit(&s, &r1, &*cb);
        let resp2 = handle_submit(&s, &r2, &*cb);
        // r2 should NOT be a duplicate. It may fail for other reasons
        // (e.g., low difficulty on hard bits), but not error-22.
        if let Some(err) = &resp2.error {
            let arr = err.as_array().unwrap();
            let code = arr[0].as_u64().unwrap();
            assert_ne!(code, 22, "different en2 must not be flagged duplicate");
        }
    }

    // ── Happy path: easy target accepts ─────────────────────────

    #[test]
    fn submit_with_easy_target_produces_valid_block() {
        let s = mk_session();
        let tmpl = easy_template("easy-1");
        s.push_template(tmpl.clone());

        let (cb, recorded) = accepting_callback();

        // Find a nonce that meets the target. The easy target
        // (0x207fffff) has ~50% acceptance per nonce, so this should
        // converge in 1-3 iterations in practice.
        let en2 = [0xDE, 0xAD, 0xBE, 0xEF];
        let ntime: u32 = 0;
        let nonce = find_valid_nonce(&tmpl, &s.extranonce1, &en2, ntime)
            .expect("must find a valid nonce for easy target in <10k tries");

        let req = submit_req(
            1, "easy-1",
            &hex::encode(en2),
            &format!("{:08x}", ntime),
            &format!("{:08x}", nonce),
        );
        let resp = handle_submit(&s, &req, &*cb);

        assert!(resp.error.is_none(), "easy-target submit should succeed, got: {:?}", resp.error);
        assert_eq!(resp.result, Value::from(true));

        // Block delivered to callback.
        let blocks = recorded.lock().unwrap();
        assert_eq!(blocks.len(), 1, "exactly one block should reach accept_block");
        let b = &blocks[0];
        assert_eq!(b.transactions.len(), 1); // just the coinbase
        assert!(b.transactions[0].is_coinbase());
    }

    #[test]
    fn assembled_block_carries_consensus_bits_regardless_of_share_diff() {
        // Consensus firewall: the block's bits must ALWAYS be template.bits,
        // never the session share difficulty. Set an absurd share diff and
        // confirm the mined block still carries the template bits.
        let s = mk_session();
        s.set_share_difficulty(0.0001); // very easy share target
        let tmpl = easy_template("consensus-1");
        s.push_template(tmpl.clone());
        let (cb, recorded) = accepting_callback();

        let en2 = [0x01, 0x02, 0x03, 0x04];
        let ntime: u32 = 0;
        let nonce = find_valid_nonce(&tmpl, &s.extranonce1, &en2, ntime)
            .expect("must find a valid nonce for easy target");
        let req = submit_req(1, "consensus-1",
            &hex::encode(en2), &format!("{:08x}", ntime), &format!("{:08x}", nonce));
        let resp = handle_submit(&s, &req, &*cb);
        assert!(resp.error.is_none(), "should succeed: {:?}", resp.error);

        let blocks = recorded.lock().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header.bits, tmpl.bits,
            "assembled block must carry consensus bits, not the share difficulty");
    }

    #[test]
    fn ntime_rolled_share_is_not_a_duplicate() {
        // Same (job, en2, nonce) but DIFFERENT ntime must NOT be error-22 —
        // cpuminer rolls ntime and each is a distinct solution.
        let s = mk_session();
        s.push_template(easy_template("ntime-job"));
        let (cb, _) = accepting_callback();

        let r1 = submit_req(1, "ntime-job", "cafebabe", "00000001", "00000000");
        let r2 = submit_req(2, "ntime-job", "cafebabe", "00000002", "00000000");
        let _ = handle_submit(&s, &r1, &*cb);
        let resp2 = handle_submit(&s, &r2, &*cb);
        if let Some(err) = &resp2.error {
            let code = err.as_array().unwrap()[0].as_u64().unwrap();
            assert_ne!(code, 22, "different ntime must not be a duplicate");
        }
    }

    #[test]
    fn overlong_job_id_returns_21() {
        let s = mk_session();
        let (cb, _) = accepting_callback();
        let long_job = "j".repeat(MAX_JOB_ID_LEN + 1);
        let req = submit_req(1, &long_job, "00000000", "00000000", "00000000");
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 21);
    }

    // ── Hard target: rejects low-difficulty share ───────────────

    #[test]
    fn submit_with_hard_target_returns_23() {
        let s = mk_session();

        // Difficulty-1 target (0x1d00ffff). With nonce=0 and a fresh
        // template, overwhelmingly probable to fail the target test.
        // Pin the share difficulty to the network difficulty (1.0) so the
        // share target == block target and the test stays deterministic (a
        // lower share diff would make the gate easier and occasionally pass).
        s.set_share_difficulty(1.0);
        let miner_spk = vec![0x11u8; 20];
        let hard_tmpl = Template::build(
            vec![[0u8; 32]], 1, 0, 0x1d00ffff, &miner_spk, 0,
            Vec::new(), b"test", "hard-1".to_string(),
        );
        s.push_template(hard_tmpl);

        let (cb, _) = accepting_callback();
        let req = submit_req(1, "hard-1", "00000000", "00000000", "00000000");
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 23);
    }

    // ── Callback rejection propagated ───────────────────────────

    #[test]
    fn accept_block_rejection_propagates_as_error_20() {
        let s = mk_session();
        let tmpl = easy_template("easy-2");
        s.push_template(tmpl.clone());

        let cb = rejecting_callback("stale-tip");

        // Find a valid nonce so the share reaches the callback at all.
        let en2 = [0xAB, 0xAD, 0xCA, 0xFE];
        let ntime: u32 = 0;
        let nonce = find_valid_nonce(&tmpl, &s.extranonce1, &en2, ntime)
            .expect("must find a valid nonce for easy target");

        let req = submit_req(
            1, "easy-2",
            &hex::encode(en2),
            &format!("{:08x}", ntime),
            &format!("{:08x}", nonce),
        );
        let resp = handle_submit(&s, &req, &*cb);
        assert_err_code(&resp, 20);
        // Reason should be plumbed through.
        let err = resp.error.as_ref().unwrap().as_array().unwrap();
        assert!(err[1].as_str().unwrap().contains("stale-tip"));
    }

    // ── Template LRU eviction ───────────────────────────────────

    #[test]
    fn template_lru_evicts_oldest() {
        let s = mk_session();
        // Push MAX_TEMPLATES_PER_SESSION + 3 templates; oldest 3 should
        // be evicted.
        use crate::stratum::session::MAX_TEMPLATES_PER_SESSION;

        for i in 0..(MAX_TEMPLATES_PER_SESSION + 3) {
            s.push_template(easy_template(&format!("t{}", i)));
        }

        // t0..t2 should be gone.
        assert!(s.find_template("t0").is_none(), "t0 should have been evicted");
        assert!(s.find_template("t2").is_none(), "t2 should have been evicted");
        // t3 onwards still alive.
        assert!(s.find_template("t3").is_some());
        assert!(s.find_template(&format!("t{}", MAX_TEMPLATES_PER_SESSION + 2)).is_some());
    }

    #[test]
    fn replace_templates_clears_old_and_installs_new() {
        let s = mk_session();
        s.push_template(easy_template("old-1"));
        s.push_template(easy_template("old-2"));

        s.replace_templates(easy_template("new-1"));

        assert!(s.find_template("old-1").is_none());
        assert!(s.find_template("old-2").is_none());
        assert!(s.find_template("new-1").is_some());
    }

    // ── parse_hex_u32 corner cases ──────────────────────────────

    #[test]
    fn parse_hex_u32_accepts_various_forms() {
        assert_eq!(parse_hex_u32("0").unwrap(), 0);
        assert_eq!(parse_hex_u32("ffffffff").unwrap(), 0xffffffff);
        assert_eq!(parse_hex_u32("0x1234abcd").unwrap(), 0x1234abcd);
        assert_eq!(parse_hex_u32("0X1234ABCD").unwrap(), 0x1234abcd);
        assert!(parse_hex_u32("not-hex").is_err());
        assert!(parse_hex_u32("100000000").is_err()); // overflow u32
    }

    // ── helpers ─────────────────────────────────────────────────

    fn assert_err_code(resp: &StratumResponse, expected: u64) {
        let err = resp.error.as_ref().expect("expected error response");
        let arr = err.as_array().expect("error should be array");
        let code = arr[0].as_u64().expect("code should be integer");
        assert_eq!(code, expected, "error code mismatch: got {:?}", err);
    }

    // Touch unused imports so clippy doesn't scream at us.
    #[allow(dead_code)]
    fn _unused_warning_silencer() {
        let _ = TxInput { prev_txid: [0;32], prev_index: 0, script_sig: vec![], sequence: 0 };
        let _ = TxOutput { value: 0, script_pubkey: vec![] };
    }
}
