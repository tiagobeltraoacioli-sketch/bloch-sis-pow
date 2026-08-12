//! Upstream node client — JSON-RPC over HTTP against a real Bloch node.
//!
//! Uses only methods the node actually exposes (`src/rpc/mod.rs`):
//!
//! * `getdaginfo`        — cheap tip polling (tip hash, height).
//! * `getblocktemplate`  — the B5f pool seam: parents, height, blue_score,
//!                         expected `bits` (ASERT-Lattice, computed exactly
//!                         like `accept_block` validates), subsidy +
//!                         founder-vesting amounts, mempool txs + fees.
//! * `submitblock`       — full block, Bitcoin wire hex
//!                         (`Block::to_bitcoin_bytes()`), routed through the
//!                         node's gossip-equivalent validation pipeline.
//!
//! `ureq` is blocking; callers on the tokio runtime must wrap calls in
//! `spawn_blocking` (see `stratum.rs` / `main.rs`).

use std::time::Duration;

use bloch_crypto::core::Transaction;
use serde_json::{json, Value};

/// Read a satoshi-denominated template field.
///
/// V4 rule R3 (docs/specs/BLOCH-RPC-V4.md) makes every satoshi amount a
/// decimal STRING on the wire — the V4 supply exceeds both `i64::MAX` and
/// JavaScript's `Number.MAX_SAFE_INTEGER`. Live G3 nodes still send JSON
/// numbers, so the pool accepts BOTH forms and one pool binary can mine
/// against either wire. Anything else (float, null, garbage string) yields
/// `None`, which the reward-bearing fields below turn into a hard error
/// rather than a silent 0-sat coinbase.
fn sat_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.trim().parse::<u64>().ok())
}

/// A block template as served by the node's `getblocktemplate`.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub parents:              Vec<[u8; 32]>,
    pub height:               u64,
    /// The ABSOLUTE emission height the node computed `subsidy_sat` at
    /// (local height + carry-over offset on Genesis-2/3 chains). This — not
    /// `height` — is what `tokenomics_v2::block_subsidy_sat` takes: from the
    /// Emission V3 flag-day onward, checking the subsidy against the LOCAL
    /// height computes the wrong epoch. Falls back to `height` when the node
    /// predates the field (identity on non-carry-over chains).
    pub emission_height:      u64,
    pub blue_score:           u64,
    /// Expected compact difficulty bits for the next block. The node
    /// computes this with the same ASERT-Lattice call `accept_block`
    /// validates with — the pool never guesses difficulty.
    pub bits:                 u32,
    pub cur_time:             u64,
    pub subsidy_sat:          u64,
    pub founder_vesting_sat:  u64,
    pub founder_address_hash: [u8; 20],
    pub total_fees:           u64,
    /// Mempool transactions (already fee-ordered by the node).
    pub transactions:         Vec<Transaction>,
}

impl BlockTemplate {
    /// The subsidy CONSENSUS requires for this template, computed — like the
    /// validator's `validate_coinbase_value` — at the EMISSION height, never
    /// the local height. From the Emission V3 flag-day (local 40,000 =
    /// emission 453,743) onward those disagree: the local height would say
    /// 8,400 BLOCH while consensus pays 2,600, and every block built on the
    /// wrong figure is rejected.
    pub fn consensus_subsidy_sat(&self) -> u64 {
        bloch_crypto::core::tokenomics_v2::block_subsidy_sat(self.emission_height)
    }

    /// The founder-vesting delta CONSENSUS requires for this template — same
    /// emission-height keying as the subsidy (`validate_coinbase_value`
    /// enforces the exact value AND address of output[1] whenever this is
    /// non-zero).
    pub fn consensus_founder_vesting_sat(&self) -> u64 {
        bloch_crypto::core::tokenomics_v2::founder_vesting_delta_sat(self.emission_height)
    }

    /// Full divergence check: Err(reason) when the node's reward-bearing
    /// fields do not match consensus for this template's emission height —
    /// the pool must refuse to cut jobs from such a node (mining them
    /// produces only rejected blocks). This is THE choke point: every
    /// template goes through it before `Job::build` copies the node's
    /// figures into a coinbase.
    pub fn check_reward_consensus(&self) -> Result<(), String> {
        let expect_subsidy = self.consensus_subsidy_sat();
        if self.subsidy_sat != expect_subsidy {
            return Err(format!(
                "template subsidy {} sat != consensus {} sat at h={} (emission h={})",
                self.subsidy_sat, expect_subsidy, self.height, self.emission_height));
        }
        let expect_vesting = self.consensus_founder_vesting_sat();
        if self.founder_vesting_sat != expect_vesting {
            return Err(format!(
                "template founder vesting {} sat != consensus {} sat at h={} (emission h={})",
                self.founder_vesting_sat, expect_vesting, self.height, self.emission_height));
        }
        Ok(())
    }
}

pub struct Upstream {
    url:   String,
    agent: ureq::Agent,
}

impl Upstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Single JSON-RPC call. The node wraps results as
    /// `{"jsonrpc":"2.0","id":..,"result":..}` and signals method-level
    /// failures as `{"error": "..."} ` INSIDE result (see src/rpc/mod.rs),
    /// so both layers are unwrapped here.
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self.agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| format!("rpc {}: {}", method, e))?
            .into_json()
            .map_err(|e| format!("rpc {}: bad json: {}", method, e))?;

        let result = resp.get("result").cloned().unwrap_or(Value::Null);
        if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
            return Err(format!("rpc {}: {}", method, err));
        }
        Ok(result)
    }

    /// Cheap tip poll: (tip_hash_hex, tip_height).
    pub fn get_tip(&self) -> Result<(String, u64), String> {
        let v = self.call("getdaginfo", json!([]))?;
        let tip = v.get("tip").and_then(|t| t.as_str()).unwrap_or("").to_string();
        let height = v.get("tip_height").and_then(|h| h.as_u64()).unwrap_or(0);
        Ok((tip, height))
    }

    pub fn get_block_template(&self) -> Result<BlockTemplate, String> {
        let v = self.call("getblocktemplate", json!([]))?;
        parse_template(&v)
    }

    /// Canonical block hash at `height` (`getblockhash`), or None if
    /// the node has no canonical block there. Used by the confirmation
    /// loop: a found block is confirmed when it IS the canonical hash
    /// at its height at `confirm_depth`, orphaned when it is not.
    pub fn get_canonical_hash_at(&self, height: u64) -> Result<Option<String>, String> {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "getblockhash", "params": [height]
        });
        let resp: Value = self.agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| format!("rpc getblockhash: {}", e))?
            .into_json()
            .map_err(|e| format!("rpc getblockhash: bad json: {}", e))?;
        let result = resp.get("result").cloned().unwrap_or(Value::Null);
        // "height not found" is a definite answer (no canonical block),
        // not a transport error — map it to None, other errors to Err.
        if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
            if err.contains("not found") {
                return Ok(None);
            }
            return Err(format!("rpc getblockhash: {}", err));
        }
        Ok(result.as_str().map(|s| s.to_string()))
    }

    /// Submit a complete, SIS-mined block. Returns the node-side block
    /// hash hex on acceptance.
    pub fn submit_block(&self, block_wire_hex: &str) -> Result<String, String> {
        let v = self.call("submitblock", json!([block_wire_hex]))?;
        if v.get("accepted").and_then(|a| a.as_bool()) == Some(true) {
            Ok(v.get("hash").and_then(|h| h.as_str()).unwrap_or("").to_string())
        } else {
            Err(format!("submitblock: unexpected response {}", v))
        }
    }
}

/// Parse a `getblocktemplate` result. Split out of the HTTP call so the wire
/// contract — including the V4 R3 string amounts — is testable without a node.
fn parse_template(v: &Value) -> Result<BlockTemplate, String> {
    let parents = v.get("parents").and_then(|p| p.as_array())
        .ok_or("template missing parents")?
        .iter()
        .map(|h| {
            let bytes = hex::decode(h.as_str().unwrap_or("")).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "parent not 32 bytes".to_string())?;
            Ok(arr)
        })
        .collect::<Result<Vec<[u8; 32]>, String>>()?;

    let founder_hash_hex = v.get("founder_address_hash").and_then(|f| f.as_str()).unwrap_or("");
    let founder_bytes = hex::decode(founder_hash_hex).unwrap_or_default();
    let mut founder_address_hash = [0u8; 20];
    if founder_bytes.len() == 20 {
        founder_address_hash.copy_from_slice(&founder_bytes);
    }

    // Any undecodable mempool tx fails the WHOLE template: silently
    // dropping a tx while the coinbase still claims its fee would
    // make every block attempt fail node validation forever, with
    // miners' work silently wasted (advisor finding).
    let mut transactions: Vec<Transaction> = Vec::new();
    if let Some(arr) = v.get("transactions").and_then(|t| t.as_array()) {
        for e in arr {
            let hexstr = e.get("data").and_then(|d| d.as_str())
                .ok_or("template tx missing data")?;
            let bytes = hex::decode(hexstr)
                .map_err(|e| format!("template tx hex: {}", e))?;
            let tx = Transaction::from_stratum_bytes(&bytes)
                .map_err(|e| format!("template tx decode: {}", e))?;
            transactions.push(tx);
        }
    }

    // Compact bits must FIT u32 — `as u32` would truncate garbage
    // into a plausible-looking difficulty.
    let bits = v.get("bits").and_then(|x| x.as_u64()).ok_or("template missing bits")?;
    let bits = u32::try_from(bits).map_err(|_| "template bits exceeds u32".to_string())?;

    // Reward-bearing fields hard-error like height/bits: a renamed
    // or missing field must NOT silently become a 0-sat coinbase.
    let height = v.get("height").and_then(|x| x.as_u64()).ok_or("template missing height")?;
    Ok(BlockTemplate {
        parents,
        height,
        // Older nodes don't serve emission_height; fall back to the local
        // height (correct only on chains without a carry-over offset —
        // the divergence check in main.rs then degrades, it never lies).
        emission_height:     v.get("emission_height").and_then(|x| x.as_u64()).unwrap_or(height),
        blue_score:          v.get("blue_score").and_then(|x| x.as_u64()).unwrap_or(0),
        bits,
        cur_time:            v.get("cur_time").and_then(|x| x.as_u64()).ok_or("template missing cur_time")?,
        // Satoshi amounts: number (G3 wire) or decimal string (V4 R3).
        subsidy_sat:         v.get("subsidy_sat").and_then(sat_u64).ok_or("template missing subsidy_sat")?,
        founder_vesting_sat: v.get("founder_vesting_sat").and_then(sat_u64).unwrap_or(0),
        founder_address_hash,
        total_fees:          v.get("total_fees").and_then(sat_u64).ok_or("template missing total_fees")?,
        transactions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::core::tokenomics_v2::{
        EMISSION_V3_FORK_EMISSION_HEIGHT, EMISSION_V3_FORK_LOCAL_HEIGHT,
        EMISSION_V3_INITIAL_REWARD_SAT, INITIAL_BLOCK_REWARD_SAT,
        block_subsidy_sat,
    };

    /// A minimal template at (local, emission) heights with the given
    /// reward-bearing fields — everything else is irrelevant to the check.
    fn tmpl(height: u64, emission_height: u64, subsidy_sat: u64, vesting_sat: u64) -> BlockTemplate {
        BlockTemplate {
            parents:              vec![[0u8; 32]],
            height,
            emission_height,
            blue_score:           height,
            bits:                 0x203fffc0,
            cur_time:             1_786_000_000,
            subsidy_sat,
            founder_vesting_sat:  vesting_sat,
            founder_address_hash: [0u8; 20],
            total_fees:           0,
            transactions:         Vec::new(),
        }
    }

    // ── The Emission V3 fork boundary (local 40,000 = emission 453,743) ──

    #[test]
    fn pre_fork_template_pays_v2_subsidy() {
        // Last pre-fork block: consensus still pays the V2 curve (8,400).
        let t = tmpl(EMISSION_V3_FORK_LOCAL_HEIGHT - 1,
                     EMISSION_V3_FORK_EMISSION_HEIGHT - 1,
                     INITIAL_BLOCK_REWARD_SAT, 0);
        assert_eq!(t.consensus_subsidy_sat(), INITIAL_BLOCK_REWARD_SAT);
        t.check_reward_consensus().expect("V2 subsidy is correct pre-fork");
        // A node already paying the V3 figure pre-fork is divergent.
        let early = tmpl(EMISSION_V3_FORK_LOCAL_HEIGHT - 1,
                         EMISSION_V3_FORK_EMISSION_HEIGHT - 1,
                         EMISSION_V3_INITIAL_REWARD_SAT, 0);
        early.check_reward_consensus().expect_err("V3 subsidy pre-fork must be refused");
    }

    #[test]
    fn post_fork_template_must_pay_v3_subsidy() {
        // First fork block: consensus flips to 2,600 BLOCH.
        let t = tmpl(EMISSION_V3_FORK_LOCAL_HEIGHT,
                     EMISSION_V3_FORK_EMISSION_HEIGHT,
                     EMISSION_V3_INITIAL_REWARD_SAT, 0);
        assert_eq!(t.consensus_subsidy_sat(), EMISSION_V3_INITIAL_REWARD_SAT);
        t.check_reward_consensus().expect("V3 subsidy is correct at the fork");

        // THE latent bug this check exists for: a node still serving the V2
        // figure at the fork. Cutting that job would have every ASIC block
        // rejected by consensus — the pool must refuse the template instead.
        let stale = tmpl(EMISSION_V3_FORK_LOCAL_HEIGHT,
                         EMISSION_V3_FORK_EMISSION_HEIGHT,
                         INITIAL_BLOCK_REWARD_SAT, 0);
        let why = stale.check_reward_consensus().expect_err("8,400 at the fork must be refused");
        assert!(why.contains("subsidy"), "refusal names the divergent field: {}", why);
    }

    #[test]
    fn local_height_keying_is_the_bug_not_the_fix() {
        // Documents the trap: at the fork, the LOCAL height still computes
        // the pre-fork subsidy (40,000 is epochs away from any V2 halving),
        // while the EMISSION height computes the V3 one. Keying any check on
        // the local height silently blesses the wrong figure — which is why
        // check_reward_consensus (and the node's validate_coinbase_value)
        // key on emission height only.
        assert_eq!(block_subsidy_sat(EMISSION_V3_FORK_LOCAL_HEIGHT),
                   INITIAL_BLOCK_REWARD_SAT);
        assert_eq!(block_subsidy_sat(EMISSION_V3_FORK_EMISSION_HEIGHT),
                   EMISSION_V3_INITIAL_REWARD_SAT);
        assert_ne!(block_subsidy_sat(EMISSION_V3_FORK_LOCAL_HEIGHT),
                   block_subsidy_sat(EMISSION_V3_FORK_EMISSION_HEIGHT));
    }

    #[test]
    fn divergent_founder_vesting_is_refused() {
        // Vesting is cliff-locked (zero) for years around the fork; a node
        // claiming a non-zero vesting output is divergent — consensus
        // enforces output[1]'s exact value, so blocks built on it die too.
        let t = tmpl(EMISSION_V3_FORK_LOCAL_HEIGHT,
                     EMISSION_V3_FORK_EMISSION_HEIGHT,
                     EMISSION_V3_INITIAL_REWARD_SAT, 1);
        let why = t.check_reward_consensus().expect_err("phantom vesting must be refused");
        assert!(why.contains("vesting"), "refusal names the divergent field: {}", why);
    }

    // ── V4 rule R3: satoshi amounts arrive as decimal strings ──────────

    /// A template whose satoshi fields are decimal STRINGS (the V4 wire,
    /// docs/specs/BLOCH-RPC-V4.md R3) parses to exactly the same struct as the
    /// numeric G3 wire. Both must work: one pool binary mines against either.
    fn template_json(subsidy: Value, vesting: Value, fees: Value) -> Value {
        json!({
            "parents":              [hex::encode([0x11u8; 32])],
            "height":               42,
            "emission_height":      42,
            "blue_score":           42,
            "bits":                 0x2100ffffu64,
            "cur_time":             1_777_686_999u64,
            "subsidy_sat":          subsidy,
            "founder_vesting_sat":  vesting,
            "founder_address_hash": hex::encode([0x77u8; 20]),
            "total_fees":           fees,
            "transactions":         [],
        })
    }

    #[test]
    fn string_and_number_amounts_parse_identically() {
        let numeric = parse_template(&template_json(
            json!(238_100_000_000u64), json!(7u64), json!(1_234u64))).expect("numeric wire");
        let stringy = parse_template(&template_json(
            json!("238100000000"), json!("7"), json!("1234"))).expect("V4 string wire");

        assert_eq!(numeric.subsidy_sat, stringy.subsidy_sat);
        assert_eq!(numeric.founder_vesting_sat, stringy.founder_vesting_sat);
        assert_eq!(numeric.total_fees, stringy.total_fees);
        assert_eq!(stringy.subsidy_sat, 238_100_000_000);
        assert_eq!(stringy.total_fees, 1_234);
    }

    #[test]
    fn string_amount_beyond_f64_and_i64_survives() {
        // The whole point of R3: a value above 2^53 (and above i64::MAX once
        // scaled) must not be corrupted. u64::MAX round-trips through the
        // decimal-string form.
        let t = parse_template(&template_json(
            json!(u64::MAX.to_string()), json!("0"), json!("0"))).expect("huge string amount");
        assert_eq!(t.subsidy_sat, u64::MAX);
    }

    #[test]
    fn unparseable_amount_is_a_hard_error_not_a_zero_coinbase() {
        // A garbage or float amount must fail the template, never degrade to
        // a 0-sat coinbase that mines rejected blocks forever.
        for bad in [json!("not-a-number"), json!(1.5f64), json!(null)] {
            let e = parse_template(&template_json(bad.clone(), json!("0"), json!("0")))
                .expect_err("bad subsidy must fail the template");
            assert!(e.contains("subsidy_sat"), "error names the field: {e}");
        }
    }

    #[test]
    fn identity_chain_fallback_still_checks() {
        // Older nodes without `emission_height` fall back to the local
        // height (upstream parse). On a no-carry-over chain that is exact;
        // the check then still catches a wrong subsidy.
        let t = tmpl(42, 42, INITIAL_BLOCK_REWARD_SAT, 0);
        t.check_reward_consensus().expect("identity chain, correct subsidy");
        let bad = tmpl(42, 42, INITIAL_BLOCK_REWARD_SAT - 1, 0);
        bad.check_reward_consensus().expect_err("wrong subsidy on identity chain");
    }
}
