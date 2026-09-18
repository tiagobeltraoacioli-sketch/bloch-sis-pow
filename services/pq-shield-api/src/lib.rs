//! # pq-shield-api — a NON-CUSTODIAL developer HTTP API over `bloch-pq-vault`
//!
//! ## The server constructs and verifies public artifacts; it never signs.
//!
//! Every route does **construction + verification only**. It returns UNSIGNED
//! artifacts — a vault address, a witnessScript, an unsigned transaction, a
//! BIP-143 sighash, or the anchor commitment bytes — for the client to sign
//! **locally**. Clients must keep all secret material client-side:
//!
//! - the BTC hot/recovery secp256k1 **private keys** (sign the sighashes),
//! - the **PQ secret key** (ML-DSA-65 ‖ Falcon-1024 — signs the anchor commitment),
//! - the recovery **preimage `r`** (`H(r)` is derived from the PQ key; only `H(r)`
//!   — the hash — is ever sent to the server; `r` is revealed only in a witness the
//!   client assembles locally).
//!
//! To catch accidental disclosure under recognizable field names, every request
//! body is scanned by [`guard_no_secrets`] and rejected (HTTP 400) if any field
//! name looks like secret material (`secret`, `seed`, `priv`, `mnemonic`, `wif`,
//! `preimage`, a bare `r`/`sk`, …), and pubkey fields must be 33-byte compressed
//! secp256k1 keys (a 32-byte value — private-key length — is rejected).
//!
//! The endpoint wraps only the crate's PUBLIC, non-secret functions: the `vault`
//! script/address/tx/sighash builders, `PqShieldAnchor::commitment_bytes`,
//! `verify_anchor` (against a caller-supplied trusted PQ key), and the anchor
//! guard-hash helpers. It never calls
//! `sign_anchor`, `ecdsa_witness_sig`, `derive_vault_keys`, or the preimage
//! derivation — those require secrets and belong on the client.

use axum::{
    body::Bytes,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bitcoin::{Network, OutPoint, PublicKey, Txid};
use bloch_pq_vault as vaultlib;
use bloch_pq_vault::anchor::{PqShieldAnchor, SignedAnchor, TargetChain, ANCHOR_VERSION};
use bloch_pq_vault::vault::*;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::str::FromStr;

/// The banner attached to every response — the non-custodial contract, restated.
pub const SIGN_LOCALLY: &str =
    "SIGN LOCALLY — non-custodial. This server does not sign or require private keys. \
     Sign the returned artifact with your own key(s) on your device. Never send BTC \
     private keys, the PQ secret key, or the preimage r to this service.";

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// A structured API error rendered as JSON with the correct HTTP status.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    fn bad(msg: impl Into<String>) -> Self {
        ApiError { status: StatusCode::BAD_REQUEST, message: msg.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": self.message,
            "non_custodial": SIGN_LOCALLY,
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<JsonRejection> for ApiError {
    fn from(_r: JsonRejection) -> Self {
        ApiError::bad("invalid JSON body")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-custodial guard: reject anything that looks like a secret
// ─────────────────────────────────────────────────────────────────────────────

/// Field-name fragments that betray secret material. Scanned case-insensitively
/// against every key in the request JSON, at any depth.
const FORBIDDEN_FRAGMENTS: &[&str] = &[
    "secret", "seed", "priv", "mnemonic", "wif", "xpriv", "preimage", "passphrase",
];
/// Field names that are exactly a secret (the raw preimage `r`, a private scalar).
const FORBIDDEN_EXACT: &[&str] = &["r", "sk", "d", "privkey", "private_key"];

/// Recursively reject any request whose JSON contains a key that looks like a
/// private key, seed, or the raw preimage `r`. This is the enforcement half of the
/// input hygiene check; it cannot identify arbitrary secret bytes in allowed
/// string fields, nor undo disclosure once a request reaches the server.
pub fn guard_no_secrets(v: &Value) -> Result<(), ApiError> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let lk = k.to_ascii_lowercase();
                if FORBIDDEN_EXACT.iter().any(|f| lk == *f)
                    || FORBIDDEN_FRAGMENTS.iter().any(|f| lk.contains(f))
                    || lk.ends_with("_sk")
                    || lk.ends_with("_secret")
                {
                    return Err(ApiError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!(
                            "rejected: a field name looks like secret material. This API is \
                             NON-CUSTODIAL — never send a private key, seed, or the preimage \
                             r. Send only public keys and the hash H(r). {SIGN_LOCALLY}"
                        ),
                    });
                }
                guard_no_secrets(child)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for it in items {
                guard_no_secrets(it)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Parse `bytes` as JSON, run the [`guard_no_secrets`] scan, then deserialize into
/// the typed request `T`. The guard runs BEFORE typed parsing so secrets are caught
/// even in fields the typed struct would otherwise ignore.
fn parse_guarded<T: DeserializeOwned>(bytes: &Bytes) -> Result<T, ApiError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ApiError::bad("invalid JSON"))?;
    guard_no_secrets(&value)?;
    if let Some(delay) = value.get("csv_delay").and_then(Value::as_u64) {
        if delay < 144 { return Err(ApiError::bad("csv_delay must be at least 144 blocks for the vault construction API")); }
    }
    serde_json::from_value(value).map_err(|_| ApiError::bad("invalid or unknown request fields"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Field parsers (all reject secret-shaped input)
// ─────────────────────────────────────────────────────────────────────────────

fn parse_network(s: &str) -> Result<Network, ApiError> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(ApiError::bad("unknown network (use mainnet|testnet|signet|regtest)")),
    }
}

/// Parse a 33-byte compressed secp256k1 public key from hex. A 32-byte value is
/// rejected outright: that is private-key / x-only length, and this endpoint accepts
/// only compressed *public* keys.
fn parse_pubkey(field: &str, hexstr: &str) -> Result<PublicKey, ApiError> {
    let raw = hex::decode(hexstr.trim())
        .map_err(|_| ApiError::bad(format!("{field}: not hex")))?;
    if raw.len() == 32 {
        return Err(ApiError::bad(format!(
            "{field}: 32 bytes looks like a PRIVATE key or x-only key. This API is \
             non-custodial — send a 33-byte COMPRESSED public key only."
        )));
    }
    if raw.len() != 33 {
        return Err(ApiError::bad(format!(
            "{field}: expected a 33-byte compressed secp256k1 public key, got {} bytes",
            raw.len()
        )));
    }
    PublicKey::from_slice(&raw).map_err(|_| ApiError::bad(format!("{field}: invalid pubkey")))
}

fn parse_hash32(field: &str, hexstr: &str) -> Result<[u8; 32], ApiError> {
    let raw = hex::decode(hexstr.trim())
        .map_err(|_| ApiError::bad(format!("{field}: not hex")))?;
    if raw.len() != 32 {
        return Err(ApiError::bad(format!(
            "{field}: expected 32 bytes (SHA-256 H(r)), got {} bytes",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_txid(field: &str, s: &str) -> Result<Txid, ApiError> {
    Txid::from_str(s.trim()).map_err(|_| ApiError::bad(format!("{field}: invalid txid")))
}

fn hexbytes(field: &str, hexstr: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(hexstr.trim()).map_err(|_| ApiError::bad(format!("{field}: not hex")))
}

fn tx_hex(tx: &bitcoin::Transaction) -> String {
    hex::encode(bitcoin::consensus::serialize(tx))
}

fn script_hex(s: &bitcoin::ScriptBuf) -> String {
    hex::encode(s.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Request DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// The public parameters that define a vault instance. NONE are secret: two
/// compressed secp256k1 PUBLIC keys, the hash `H(r)` (never `r`), and Δ.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultParamsReq {
    hot_pubkey: String,
    recovery_pubkey: String,
    /// `H(r) = SHA256(r)` — the hash commitment. The client computed this locally
    /// from its PQ key; it sends only the HASH, never `r`.
    recovery_hash: String,
    csv_delay: u16,
}

impl VaultParamsReq {
    fn to_params(&self, network: Network) -> Result<VaultParams, ApiError> {
        if self.csv_delay < MIN_NEW_VAULT_CSV_DELAY { return Err(ApiError::bad("csv_delay must be at least 144 blocks")); }
        let params = VaultParams {
            hot_pubkey: parse_pubkey("hot_pubkey", &self.hot_pubkey)?,
            recovery_pubkey: parse_pubkey("recovery_pubkey", &self.recovery_pubkey)?,
            recovery_hash: parse_hash32("recovery_hash", &self.recovery_hash)?,
            csv_delay: self.csv_delay,
            network,
        };
        validate_new_vault_params(&params).map_err(|error| ApiError::bad(error.to_string()))?;
        Ok(params)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutpointReq {
    txid: String,
    vout: u32,
}
impl OutpointReq {
    fn to_outpoint(&self, field: &str) -> Result<OutPoint, ApiError> {
        Ok(OutPoint { txid: parse_txid(field, &self.txid)?, vout: self.vout })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressReq {
    network: String,
    hot_pubkey: String,
    recovery_pubkey: String,
    recovery_hash: String,
    csv_delay: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnvaultReq {
    network: String,
    vault: VaultParamsReq,
    deposit_outpoint: OutpointReq,
    deposit_amount_sat: u64,
    fee_sat: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BranchAReq {
    network: String,
    vault: VaultParamsReq,
    trigger_outpoint: OutpointReq,
    trigger_amount_sat: u64,
    destination: String,
    fee_sat: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClawbackReq {
    network: String,
    vault: VaultParamsReq,
    trigger_outpoint: OutpointReq,
    trigger_amount_sat: u64,
    /// The anchored `designated_safe_dest`: a FRESH, unexposed (hidden-pubkey) address.
    safe_destination: String,
    fee_sat: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorFields {
    #[serde(default = "default_chain")]
    target_chain: String,
    btc_vault_address: String,
    recovery_hash: String,
    /// The owner's enveloped ML-DSA-65 ‖ Falcon-1024 PUBLIC key (hex). Public, not secret.
    pq_recovery_pubkey: String,
    designated_safe_dest: String,
    /// Δ in blocks. `u16` — the width Bitcoin's CSV actually enforces; a wider value is
    /// rejected at parse time rather than truncated into a different on-chain delay.
    csv_delay: u16,
    #[serde(default)]
    policy: String,
    /// Optional companion BTC PUBLIC key (hex, 33-byte compressed) — if present, the
    /// response also returns the `Custody` 2-of-2 anchor guard hash.
    #[serde(default)]
    btc_pubkey: Option<String>,
}
fn default_chain() -> String {
    "bitcoin".into()
}

struct AnchorVerifyReq {
    fields: Option<AnchorFields>,
    signature: Option<String>,
    signed_anchor_hex: Option<String>,
    trusted_pq_pubkey: Option<String>,
}

// Explicitly split the two request forms. `flatten` plus optional nested fields
// does not reliably enforce `deny_unknown_fields` on either representation.
fn parse_anchor_verify(body: &Bytes) -> Result<AnchorVerifyReq, ApiError> {
    let value: Value = parse_guarded(body)?;
    let mut map = value.as_object().cloned().ok_or_else(|| ApiError::bad("expected object"))?;
    let mut string = |key: &str| -> Result<Option<String>, ApiError> {
        map.remove(key).map(|value| value.as_str().map(str::to_owned)
            .ok_or_else(|| ApiError::bad(format!("{key} must be a string")))).transpose()
    };
    let signature = string("signature")?;
    let signed_anchor_hex = string("signed_anchor_hex")?;
    let trusted_pq_pubkey = string("trusted_pq_pubkey")?;
    let fields = if signed_anchor_hex.is_some() {
        if signature.is_some() || !map.is_empty() {
            return Err(ApiError::bad("serialized anchor cannot be mixed with fields or signature"));
        }
        None
    } else {
        Some(serde_json::from_value(Value::Object(map))
            .map_err(|_| ApiError::bad("invalid or unknown anchor fields"))?)
    };
    Ok(AnchorVerifyReq { fields, signature, signed_anchor_hex, trusted_pq_pubkey })
}

fn validate_anchor_addresses(anchor: &PqShieldAnchor) -> Result<(), ApiError> {
    if anchor.csv_delay < 144 { return Err(ApiError::bad("csv_delay must be at least 144 blocks")); }
    // The native script construction service currently implements Bitcoin only.
    // Both addresses must be valid on one common Bitcoin network.
    if ![Network::Bitcoin, Network::Testnet, Network::Signet, Network::Regtest]
        .into_iter().any(|network| anchor.validate_bitcoin_addresses(network).is_ok()) {
        return Err(ApiError::bad("anchor requires valid Bitcoin addresses on the same network"));
    }
    Ok(())
}

fn parse_target_chain(s: &str) -> Result<TargetChain, ApiError> {
    match s.to_ascii_lowercase().as_str() {
        "bitcoin" | "btc" => Ok(TargetChain::Bitcoin),
        "litecoin" | "ltc" => Ok(TargetChain::Litecoin),
        "bitcoincash" | "bch" => Ok(TargetChain::BitcoinCash),
        "dogecoin" | "doge" => Ok(TargetChain::Dogecoin),
        "ethereuml1" | "eth" => Ok(TargetChain::EthereumL1),
        _ => Err(ApiError::bad("unknown target_chain")),
    }
}

impl AnchorFields {
    fn to_anchor(&self) -> Result<PqShieldAnchor, ApiError> {
        let anchor = PqShieldAnchor {
            version: ANCHOR_VERSION,
            target_chain: parse_target_chain(&self.target_chain)?,
            btc_vault_address: self.btc_vault_address.trim().as_bytes().to_vec(),
            recovery_hash: parse_hash32("recovery_hash", &self.recovery_hash)?,
            pq_recovery_pubkey: hexbytes("pq_recovery_pubkey", &self.pq_recovery_pubkey)?,
            designated_safe_dest: self.designated_safe_dest.trim().as_bytes().to_vec(),
            csv_delay: self.csv_delay,
            policy: self.policy.as_bytes().to_vec(),
        };
        validate_anchor_addresses(&anchor)?;
        Ok(anchor)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "pq-shield-api",
        "non_custodial": true,
        "signs": false,
        "note": SIGN_LOCALLY,
    }))
}

/// POST /vault/address — build the P2WSH deposit + trigger from PUBLIC inputs only.
async fn vault_address(body: Bytes) -> Result<Json<Value>, ApiError> {
    let req: AddressReq = parse_guarded(&body)?;
    let network = parse_network(&req.network)?;
    let p = VaultParams {
        hot_pubkey: parse_pubkey("hot_pubkey", &req.hot_pubkey)?,
        recovery_pubkey: parse_pubkey("recovery_pubkey", &req.recovery_pubkey)?,
        recovery_hash: parse_hash32("recovery_hash", &req.recovery_hash)?,
        csv_delay: req.csv_delay,
        network,
    };
    validate_new_vault_params(&p).map_err(|error| ApiError::bad(error.to_string()))?;

    let dep_script = deposit_script(&p.recovery_hash, &p.hot_pubkey);
    let dep_addr = deposit_address(&p);
    let trig_script = trigger_script(&p);
    let trig_addr = trigger_address(&p);

    Ok(Json(json!({
        "network": req.network,
        "csv_delay": p.csv_delay,
        "deposit": {
            "address": dep_addr.to_string(),
            "witness_script_hex": script_hex(&dep_script),
            "script_pubkey_hex": script_hex(&dep_addr.script_pubkey()),
            "spend_witness": "[ <hot_ECDSA_sig ‖ SIGHASH_ALL>, <r> ] then the witnessScript",
        },
        "trigger": {
            "address": trig_addr.to_string(),
            "witness_script_hex": script_hex(&trig_script),
            "script_pubkey_hex": script_hex(&trig_addr.script_pubkey()),
            "branch_a_witness": "[ <hot_sig>, 0x01 ]  (delayed normal spend, matures after Δ)",
            "branch_b_witness": "[ <recovery_sig>, <r>, <> ]  (immediate hashlocked recovery; r is public after unvault)",
        },
        "import_descriptor": format!("addr({})", dep_addr),
        "notes": [
            "P2WSH: every pubkey is behind SHA256 at rest (quantum-conservative; NOT Taproot).",
            "recovery_hash MUST be H(r) computed CLIENT-SIDE from your PQ key. Never send r.",
            "AUDIT M1 (hardened recovery): derive recovery_pubkey on a HARDENED path \
             (e.g. m/84'/coin'/1'/0/0), NOT a non-hardened sibling of hot_pubkey, so a hot-key \
             compromise + watch-only xpub cannot reach the recovery key.",
        ],
        "non_custodial": SIGN_LOCALLY,
    })))
}

/// POST /vault/unvault-tx — the DEPOSIT→TRIGGER unsigned tx + the hot-key sighash.
async fn unvault_tx(body: Bytes) -> Result<Json<Value>, ApiError> {
    let req: UnvaultReq = parse_guarded(&body)?;
    let network = parse_network(&req.network)?;
    let p = req.vault.to_params(network)?;
    let deposit_op = req.deposit_outpoint.to_outpoint("deposit_outpoint")?;

    let u = build_unvault_tx_checked(&p, deposit_op, req.deposit_amount_sat, req.fee_sat)
        .map_err(|error| ApiError::bad(error.to_string()))?;
    let dep_script = deposit_script(&p.recovery_hash, &p.hot_pubkey);
    let sighash = p2wsh_sighash_checked(&u, 0, &dep_script, req.deposit_amount_sat)
        .map_err(|error| ApiError::bad(error.to_string()))?;
    let trig_addr = trigger_address(&p);

    Ok(Json(json!({
        "unsigned_tx_hex": tx_hex(&u),
        "txid": u.compute_txid().to_string(),
        "sighashes": [{
            "input_index": 0,
            "sighash_hex": hex::encode(sighash),
            "sighash_type": "SIGHASH_ALL",
            "sign_with": "hot_key (secp256k1)",
            "witness_script_hex": script_hex(&dep_script),
            "prevout_amount_sat": req.deposit_amount_sat,
            "witness_stack": "[ <your_hot_sig ‖ 0x01>, <r> ]  — reveal r LOCALLY here",
        }],
        "trigger_output": {
            "address": trig_addr.to_string(),
            "vout": 0,
            "amount_sat": req.deposit_amount_sat.saturating_sub(req.fee_sat),
        },
        "non_custodial": SIGN_LOCALLY,
    })))
}

/// POST /vault/branch-a-tx — the normal, DELAYED withdrawal (trigger→destination).
async fn branch_a_tx(body: Bytes) -> Result<Json<Value>, ApiError> {
    let req: BranchAReq = parse_guarded(&body)?;
    let network = parse_network(&req.network)?;
    let p = req.vault.to_params(network)?;
    let trigger_op = req.trigger_outpoint.to_outpoint("trigger_outpoint")?;
    let dest = vaultlib::validate_destination(req.destination.trim(), network)
        .map_err(|_| ApiError::bad("invalid destination address"))?;
    let a = build_branch_a_tx_checked(&p, trigger_op, req.trigger_amount_sat, &dest, req.fee_sat)
        .map_err(|error| ApiError::bad(error.to_string()))?;
    let trig_script = trigger_script(&p);
    let sighash = p2wsh_sighash_checked(&a, 0, &trig_script, req.trigger_amount_sat)
        .map_err(|error| ApiError::bad(error.to_string()))?;

    Ok(Json(json!({
        "unsigned_tx_hex": tx_hex(&a),
        "txid": a.compute_txid().to_string(),
        "matures_after_blocks": p.csv_delay,
        "sighashes": [{
            "input_index": 0,
            "sighash_hex": hex::encode(sighash),
            "sighash_type": "SIGHASH_ALL",
            "sign_with": "hot_key (secp256k1)",
            "witness_script_hex": script_hex(&trig_script),
            "prevout_amount_sat": req.trigger_amount_sat,
            "witness_stack": "[ <your_hot_sig ‖ 0x01>, 0x01 ]  (0x01 selects branch A)",
        }],
        "note": format!(
            "This spend is CSV-locked: the network rejects it until {} blocks after the \
             trigger confirms (nSequence encodes Δ).",
            p.csv_delay
        ),
        "non_custodial": SIGN_LOCALLY,
    })))
}

/// POST /vault/clawback-tx — the immediate hashlocked recovery (trigger→safe dest).
async fn clawback_tx(body: Bytes) -> Result<Json<Value>, ApiError> {
    let req: ClawbackReq = parse_guarded(&body)?;
    let network = parse_network(&req.network)?;
    let p = req.vault.to_params(network)?;
    let trigger_op = req.trigger_outpoint.to_outpoint("trigger_outpoint")?;
    let safe = vaultlib::validate_destination(req.safe_destination.trim(), network)
        .map_err(|_| ApiError::bad("invalid safe_destination address"))?;
    let claw = build_clawback_tx_checked(trigger_op, req.trigger_amount_sat, &safe, req.fee_sat)
        .map_err(|error| ApiError::bad(error.to_string()))?;
    let trig_script = trigger_script(&p);
    let sighash = p2wsh_sighash_checked(&claw, 0, &trig_script, req.trigger_amount_sat)
        .map_err(|error| ApiError::bad(error.to_string()))?;

    Ok(Json(json!({
        "unsigned_tx_hex": tx_hex(&claw),
        "txid": claw.compute_txid().to_string(),
        "sighashes": [{
            "input_index": 0,
            "sighash_hex": hex::encode(sighash),
            "sighash_type": "SIGHASH_ALL",
            "sign_with": "recovery_key (secp256k1)",
            "witness_script_hex": script_hex(&trig_script),
            "prevout_amount_sat": req.trigger_amount_sat,
            "witness_stack": "[ <your_recovery_sig ‖ 0x01>, <r>, <> ]  — reveal r LOCALLY \
                              (trailing empty item selects branch B)",
        }],
        "safe_output": {
            "address": safe.to_string(),
            "vout": 0,
            "amount_sat": req.trigger_amount_sat.saturating_sub(req.fee_sat),
        },
        "notes": [
            "Immediate (no timelock) so you can beat the attacker's delayed branch A within Δ. \
             RBF-enabled; a keyless watchtower needs pre-signed replacements to fee-bump.",
            "safe_destination MUST equal the anchored designated_safe_dest and be a FRESH, \
             unexposed address (spec §9.4).",
        ],
        "non_custodial": SIGN_LOCALLY,
    })))
}

/// POST /anchor/commitment — the canonical bytes to PQ-sign CLIENT-SIDE.
async fn anchor_commitment(body: Bytes) -> Result<Json<Value>, ApiError> {
    let req: AnchorFields = parse_guarded(&body)?;
    let anchor = req.to_anchor()?;
    let commitment = anchor.commitment_bytes();
    if anchor.pq_recovery_pubkey.is_empty() || anchor.pq_recovery_pubkey.len() > 8192 {
        return Err(ApiError::bad("pq_recovery_pubkey must contain 1..8192 bytes"));
    }
    let gov_hash = vaultlib::anchor_guard_governance_hash(&anchor.pq_recovery_pubkey);

    let mut out = json!({
        "commitment_bytes_hex": hex::encode(&commitment),
        "commitment_len": commitment.len(),
        "anchor_version": ANCHOR_VERSION,
        "sign_algo": "ML-DSA-65 ‖ Falcon-1024 (hybrid, enveloped) — via bloch-crypto, CLIENT-SIDE",
        "bloch_governance_guard_hash": hex::encode(gov_hash),
        "next_step": "PQ-sign commitment_bytes_hex with your PQ SECRET key locally, then POST \
                      the fields + signature (plus your pq_recovery_pubkey as \
                      trusted_pq_pubkey) to /anchor/verify to check it before publishing.",
        "non_custodial": SIGN_LOCALLY,
    });
    if let Some(btc_pk_hex) = &req.btc_pubkey {
        let btc_pk = parse_pubkey("btc_pubkey", btc_pk_hex)?;
        let custody = vaultlib::anchor_guard_custody_hash(&btc_pk.to_bytes(), &anchor.pq_recovery_pubkey);
        out["bloch_custody_guard_hash"] = json!(hex::encode(custody));
    }
    Ok(Json(out))
}

/// POST /anchor/verify — verify a PQ signature over an anchor. No secrets involved.
async fn anchor_verify(body: Bytes) -> Result<Json<Value>, ApiError> {
    let req = parse_anchor_verify(&body)?;

    let signed = if let Some(blob) = &req.signed_anchor_hex {
        let raw = hexbytes("signed_anchor_hex", blob)?;
        SignedAnchor::deserialize(&raw)
            .map_err(|e| ApiError::bad(format!("signed_anchor_hex: malformed ({e:?})")))?
    } else {
        let fields = req
            .fields
            .as_ref()
            .ok_or_else(|| ApiError::bad("provide anchor fields + signature, or signed_anchor_hex"))?;
        let signature = req
            .signature
            .as_ref()
            .ok_or_else(|| ApiError::bad("missing `signature` (hex of the PQ signature)"))?;
        SignedAnchor { anchor: fields.to_anchor()?, signature: hexbytes("signature", signature)? }
    };

    validate_anchor_addresses(&signed.anchor)?;

    // The anchor cannot be its own trust root: anyone can sign a well-formed anchor
    // naming their own designated_safe_dest. Refuse to answer without an external key.
    let trusted_hex = req.trusted_pq_pubkey.as_ref().ok_or_else(|| {
        ApiError::bad(
            "missing `trusted_pq_pubkey`: an anchor is only meaningful against a PQ key \
             you already trust out-of-band (registration, or the anchor guard hash). \
             The pq_recovery_pubkey inside the blob proves nothing about who owns it.",
        )
    })?;
    let trusted = hexbytes("trusted_pq_pubkey", trusted_hex)?;

    let result = bloch_pq_vault::anchor::verify_anchor(&signed, &trusted);
    Ok(Json(json!({
        "valid": result.is_ok(),
        "reason": match &result {
            Ok(()) => "signature verifies over the committed fields under the SUPPLIED \
                       trusted_pq_pubkey".to_string(),
            Err(e) => format!("{e:?}"),
        },
        "non_custodial": SIGN_LOCALLY,
    })))
}

async fn landing() -> Html<&'static str> {
    Html(LANDING_HTML)
}

/// L-16 fix (audit finding): per-request wall-clock deadline. Every route
/// here does real, CPU-expensive work (P2WSH script assembly and, on
/// `/anchor/verify`, a hybrid ML-DSA-65 ‖ Falcon-1024 verification) with no
/// authentication or per-client rate limiting in the application. The binary
/// accepts only loopback listeners. A timeout bounds asynchronous waits but
/// cannot preempt synchronous cryptographic work; it does not bound aggregate concurrent
/// load, which is what [`MAX_CONCURRENT_REQUESTS`] is for.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// L-16 fix: ceiling on requests being handled at once, so a burst of
/// concurrent callers cannot each start an expensive verify/assembly and
/// collectively exhaust CPU. This is a non-custodial construction/
/// verification service with no per-caller identity to rate-limit by, so a
/// single process-wide ceiling is the appropriate coarse control here — the
/// L-16 fix also documents that a TLS-terminating reverse proxy in front of
/// this service (which itself speaks plain HTTP) is a deployment
/// requirement, not optional hardening.
const MAX_CONCURRENT_REQUESTS: usize = 64;

async fn require_json_request(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if request.method() == axum::http::Method::POST {
        let content_type = request.headers().get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()).unwrap_or("")
            .split(';').next().unwrap_or("").trim();
        if !content_type.eq_ignore_ascii_case("application/json") {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
        if request.headers().get("sec-fetch-site").and_then(|value| value.to_str().ok()) == Some("cross-site") {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(request).await
}

/// Build the router. Exposed so integration tests can drive it in-process.
///
/// **Deployment note (L-16 fix):** this service speaks plain HTTP and
/// performs no authentication of its own by design (it is a non-custodial
/// construction/verification tool, not a secrets-holding service) — running
/// it reachable from an untrusted network REQUIRES a TLS-terminating
/// reverse proxy in front of it (the same requirement `coherence-prover`'s
/// service documents for its own HTTP surface). The binary restricts its
/// listener to loopback; configure authentication and rate limits in the proxy.
pub fn router() -> Router {
    Router::new()
        .route("/", get(landing))
        .route("/health", get(health))
        .route("/vault/address", post(vault_address))
        .route("/vault/unvault-tx", post(unvault_tx))
        .route("/vault/branch-a-tx", post(branch_a_tx))
        .route("/vault/clawback-tx", post(clawback_tx))
        .route("/anchor/commitment", post(anchor_commitment))
        .route("/anchor/verify", post(anchor_verify))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(tower::limit::ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(axum::extract::DefaultBodyLimit::max(128 * 1024))
        .layer(axum::middleware::from_fn(require_json_request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pq_vault::anchor::{sign_anchor, verify_anchor};
    use bloch_pq_vault::preimage::derive_recovery;
    use bloch_pq_vault::{derive_vault_keys, VaultKeys};

    const NET: &str = "regtest";

    fn seed() -> Vec<u8> {
        let s = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        hex::decode(s.replace(char::is_whitespace, "")).unwrap()
    }

    /// Build PUBLIC inputs from a seed. The secrets here live ONLY in test code; they
    /// are used to derive the *public* material the client would send. The API never
    /// receives any of the secrets below.
    fn public_inputs() -> (VaultKeys, [u8; 32], [u8; 32]) {
        let keys = derive_vault_keys(&seed(), false);
        let (r, hr) = derive_recovery(&keys.pq_secret, b"api-test-vault");
        (keys, r, hr)
    }

    fn body(v: Value) -> Bytes {
        Bytes::from(serde_json::to_vec(&v).unwrap())
    }

    #[tokio::test]
    async fn address_matches_crate_and_is_public_only() {
        let (keys, _r, hr) = public_inputs();
        let req = json!({
            "network": NET,
            "hot_pubkey": keys.hot_pubkey.to_string(),
            "recovery_pubkey": keys.recovery_pubkey.to_string(),
            "recovery_hash": hex::encode(hr),
            "csv_delay": 144u16,
        });
        let resp = vault_address(body(req)).await.expect("ok").0;

        // Round-trip against the crate's own builder.
        let p = VaultParams {
            hot_pubkey: keys.hot_pubkey,
            recovery_pubkey: keys.recovery_pubkey,
            recovery_hash: hr,
            csv_delay: 144,
            network: Network::Regtest,
        };
        assert_eq!(resp["deposit"]["address"], deposit_address(&p).to_string());
        assert_eq!(resp["trigger"]["address"], trigger_address(&p).to_string());
        assert_eq!(
            resp["deposit"]["witness_script_hex"],
            script_hex(&deposit_script(&p.recovery_hash, &p.hot_pubkey))
        );
        assert!(resp["deposit"]["address"].as_str().unwrap().starts_with("bcrt1q"));
    }

    #[tokio::test]
    async fn unvault_tx_roundtrips_and_is_unsigned() {
        let (keys, _r, hr) = public_inputs();
        let txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let req = json!({
            "network": NET,
            "vault": {
                "hot_pubkey": keys.hot_pubkey.to_string(),
                "recovery_pubkey": keys.recovery_pubkey.to_string(),
                "recovery_hash": hex::encode(hr),
                "csv_delay": 144u16,
            },
            "deposit_outpoint": { "txid": txid, "vout": 0u32 },
            "deposit_amount_sat": 100_000u64,
            "fee_sat": 500u64,
        });
        let resp = unvault_tx(body(req)).await.expect("ok").0;

        let p = VaultParams {
            hot_pubkey: keys.hot_pubkey,
            recovery_pubkey: keys.recovery_pubkey,
            recovery_hash: hr,
            csv_delay: 144,
            network: Network::Regtest,
        };
        let op = OutPoint { txid: Txid::from_str(txid).unwrap(), vout: 0 };
        let u = build_unvault_tx(&p, op, 100_000, 500);
        assert_eq!(resp["unsigned_tx_hex"], tx_hex(&u));
        let dep = deposit_script(&p.recovery_hash, &p.hot_pubkey);
        assert_eq!(
            resp["sighashes"][0]["sighash_hex"],
            hex::encode(p2wsh_sighash(&u, 0, &dep, 100_000))
        );
        // Unsigned: the witness is empty in the returned tx.
        assert!(u.input[0].witness.is_empty());
    }

    #[tokio::test]
    async fn clawback_tx_sighash_matches_crate() {
        let (keys, _r, hr) = public_inputs();
        let txid = "0000000000000000000000000000000000000000000000000000000000000002";
        // a fresh safe P2WSH cold destination
        let p = VaultParams {
            hot_pubkey: keys.hot_pubkey,
            recovery_pubkey: keys.recovery_pubkey,
            recovery_hash: hr,
            csv_delay: 144,
            network: Network::Regtest,
        };
        let safe = trigger_address(&p).to_string(); // any valid regtest addr for the test
        let req = json!({
            "network": NET,
            "vault": {
                "hot_pubkey": keys.hot_pubkey.to_string(),
                "recovery_pubkey": keys.recovery_pubkey.to_string(),
                "recovery_hash": hex::encode(hr),
                "csv_delay": 144u16,
            },
            "trigger_outpoint": { "txid": txid, "vout": 0u32 },
            "trigger_amount_sat": 99_500u64,
            "safe_destination": safe,
            "fee_sat": 500u64,
        });
        let resp = clawback_tx(body(req)).await.expect("ok").0;

        let op = OutPoint { txid: Txid::from_str(txid).unwrap(), vout: 0 };
        let safe_addr = vaultlib::validate_destination(&trigger_address(&p).to_string(), Network::Regtest).unwrap();
        let claw = build_clawback_tx(op, 99_500, &safe_addr, 500);
        let trig = trigger_script(&p);
        assert_eq!(resp["unsigned_tx_hex"], tx_hex(&claw));
        assert_eq!(
            resp["sighashes"][0]["sighash_hex"],
            hex::encode(p2wsh_sighash(&claw, 0, &trig, 99_500))
        );
        assert_eq!(resp["sighashes"][0]["sign_with"], "recovery_key (secp256k1)");
    }

    fn fixture_address(opcode: u8) -> String {
        bitcoin::Address::p2wsh(&bitcoin::ScriptBuf::from_bytes(vec![opcode]), Network::Regtest).to_string()
    }

    #[tokio::test]
    async fn anchor_commitment_and_verify_roundtrip() {
        let (keys, _r, hr) = public_inputs();
        let fields = json!({
            "target_chain": "bitcoin",
            "btc_vault_address": fixture_address(0x51),
            "recovery_hash": hex::encode(hr),
            "pq_recovery_pubkey": hex::encode(&keys.pq_pubkey),
            "designated_safe_dest": fixture_address(0x52),
            "csv_delay": 144u32,
            "policy": "watchtower-01",
        });
        let commit = anchor_commitment(body(fields.clone())).await.expect("ok").0;

        // The commitment bytes match the crate's canonical serialization.
        let anchor = PqShieldAnchor {
            version: ANCHOR_VERSION,
            target_chain: TargetChain::Bitcoin,
            btc_vault_address: fixture_address(0x51).into_bytes(),
            recovery_hash: hr,
            pq_recovery_pubkey: keys.pq_pubkey.clone(),
            designated_safe_dest: fixture_address(0x52).into_bytes(),
            csv_delay: 144,
            policy: b"watchtower-01".to_vec(),
        };
        assert_eq!(commit["commitment_bytes_hex"], hex::encode(anchor.commitment_bytes()));

        // Sign CLIENT-SIDE (test-only secret) and verify via the API, against the PQ key
        // the caller already trusts for this vault.
        let signed = sign_anchor(&anchor, &keys.pq_secret).unwrap();
        assert!(verify_anchor(&signed, &keys.pq_pubkey).is_ok());
        let mut verify_req = fields.as_object().unwrap().clone();
        verify_req.insert("signature".into(), json!(hex::encode(&signed.signature)));
        verify_req.insert("trusted_pq_pubkey".into(), json!(hex::encode(&keys.pq_pubkey)));
        let vr = anchor_verify(body(Value::Object(verify_req.clone()))).await.expect("ok").0;
        assert_eq!(vr["valid"], json!(true));

        // Tamper the safe dest → verification must fail closed.
        let mut tampered = verify_req.clone();
        tampered.insert("designated_safe_dest".into(), json!(fixture_address(0x53)));
        let vr2 = anchor_verify(body(Value::Object(tampered))).await.expect("ok").0;
        assert_eq!(vr2["valid"], json!(false));
    }

    /// REGRESSION (K-M6-anchor-selfcert), at the HTTP boundary — the shield path.
    #[tokio::test]
    async fn anchor_verify_rejects_forgery_and_demands_a_trust_root() {
        let (owner, _r, hr) = public_inputs();
        // A second, unrelated hybrid identity: the attacker. No owner secret involved.
        let attacker = derive_vault_keys(&[0xA7u8; 64], false);
        assert_ne!(owner.pq_pubkey, attacker.pq_pubkey);

        // The attacker's anchor: same vault and same H(r), but THEIR payout address and
        // THEIR PQ key — signed correctly, so it is self-consistent in every way.
        let forged_anchor = PqShieldAnchor {
            version: ANCHOR_VERSION,
            target_chain: TargetChain::Bitcoin,
            btc_vault_address: fixture_address(0x51).into_bytes(),
            recovery_hash: hr,
            pq_recovery_pubkey: attacker.pq_pubkey.clone(),
            designated_safe_dest: fixture_address(0x53).into_bytes(),
            csv_delay: 144,
            policy: b"watchtower-01".to_vec(),
        };
        let forged = sign_anchor(&forged_anchor, &attacker.pq_secret).unwrap();

        let forged_req = json!({
            "target_chain": "bitcoin",
            "btc_vault_address": fixture_address(0x51),
            "recovery_hash": hex::encode(hr),
            "pq_recovery_pubkey": hex::encode(&attacker.pq_pubkey),
            "designated_safe_dest": fixture_address(0x53),
            "csv_delay": 144u16,
            "policy": "watchtower-01",
            "signature": hex::encode(&forged.signature),
        });

        // (a) With no trust root the endpoint refuses to answer at all.
        let err = anchor_verify(body(forged_req.clone())).await.err().expect("must refuse");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("trusted_pq_pubkey"));

        // (b) Against the OWNER's key the forgery is invalid — the old self-certifying
        //     check reported this same blob as valid.
        let mut against_owner = forged_req.as_object().unwrap().clone();
        against_owner
            .insert("trusted_pq_pubkey".into(), json!(hex::encode(&owner.pq_pubkey)));
        let vr = anchor_verify(body(Value::Object(against_owner))).await.expect("ok").0;
        assert_eq!(vr["valid"], json!(false), "attacker anchor must not verify as the owner's");
        assert_eq!(vr["reason"], json!("UntrustedKey"));

        // (c) Sanity: the forgery is only "valid" for someone who trusts the attacker.
        let mut against_attacker = forged_req.as_object().unwrap().clone();
        against_attacker
            .insert("trusted_pq_pubkey".into(), json!(hex::encode(&attacker.pq_pubkey)));
        let vr2 = anchor_verify(body(Value::Object(against_attacker))).await.expect("ok").0;
        assert_eq!(vr2["valid"], json!(true));
    }

    /// Δ wider than Bitcoin's CSV width is refused at the edge, not truncated: 65_680
    /// would become the honest 144 under `as u16`.
    #[tokio::test]
    async fn audit_anchor_refuses_bad_keys_and_unsafe_delay_without_panicking() {
        for (key, delay) in [(String::new(), 144), ("00".repeat(8193), 144), ("ab".repeat(32), 0)] {
            let req = json!({"target_chain":"bitcoin", "btc_vault_address":"bcrt1qexample",
                "recovery_hash":"00".repeat(32), "pq_recovery_pubkey":key,
                "designated_safe_dest":"bcrt1qsafe", "csv_delay":delay, "policy":"test"});
            let err = anchor_commitment(body(req)).await.err().expect("must reject");
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn anchor_rejects_oversized_csv_delay() {
        let (keys, _r, hr) = public_inputs();
        let req = json!({
            "target_chain": "bitcoin",
            "btc_vault_address": fixture_address(0x51),
            "recovery_hash": hex::encode(hr),
            "pq_recovery_pubkey": hex::encode(&keys.pq_pubkey),
            "designated_safe_dest": fixture_address(0x52),
            "csv_delay": 65_680u32,
            "policy": "watchtower-01",
        });
        assert_eq!(65_680u32 as u16, 144, "the truncation this rejection prevents");
        let err = anchor_commitment(body(req)).await.err().expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_secret_shaped_fields() {
        // A field literally named `seed` is rejected before any processing.
        let req = json!({ "network": NET, "seed": "abc", "csv_delay": 144u16 });
        let err = vault_address(body(req)).await.err().expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.to_lowercase().contains("secret material"));

        // The raw preimage `r` is rejected.
        let req2 = json!({ "network": NET, "r": "00", "csv_delay": 144u16 });
        assert!(vault_address(body(req2)).await.is_err());

        // A nested pq_secret is caught at depth.
        let deep = json!({ "network": NET, "vault": { "pq_secret": "ff" } });
        assert!(unvault_tx(body(deep)).await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_key_length_pubkey() {
        let (_keys, _r, hr) = public_inputs();
        // 32-byte value in a pubkey field = private-key / x-only length → rejected.
        let req = json!({
            "network": NET,
            "hot_pubkey": hex::encode([0x11u8; 32]),
            "recovery_pubkey": hex::encode([0x22u8; 33]),
            "recovery_hash": hex::encode(hr),
            "csv_delay": 144u16,
        });
        let err = vault_address(body(req)).await.err().expect("must reject 32-byte pubkey");
        assert!(err.message.to_lowercase().contains("private key"));
    }

    #[test]
    fn guard_scans_arrays_and_nested_objects() {
        assert!(guard_no_secrets(&json!({"ok": 1, "nested": {"mnemonic": "x"}})).is_err());
        assert!(guard_no_secrets(&json!([{"wif": "x"}])).is_err());
        assert!(guard_no_secrets(&json!({"hot_pubkey":"02..","recovery_hash":"..."})).is_ok());
    }

    /// L-16 regression: the whole point of the fix is a `TimeoutLayer` +
    /// `ConcurrencyLimitLayer` wrapping the ENTIRE router (every route, not
    /// just handlers called directly as in the tests above). This drives a
    /// real HTTP request through `router()` — layers included — via
    /// `tower::Service::call`, the same trait axum's `Router` implements
    /// and the same path a real TCP connection takes. Before this fix there
    /// was no such layer at all; the regression this guards against is the
    /// layer composition breaking ordinary request handling (a type
    /// mismatch or a mis-ordered layer stack would make EVERY request fail,
    /// not just a slow/concurrent one).
    #[tokio::test]
    async fn router_with_timeout_and_concurrency_layers_still_serves_health() {
        use tower::util::ServiceExt as _;

        let app = router();
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.expect("router must still serve a request");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}

const LANDING_HTML: &str = r#"<!doctype html><html><head><meta charset="utf-8">
<title>PQ-Shield API — non-custodial</title>
<style>body{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;line-height:1.5}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}
.banner{background:#fff3cd;border:1px solid #e0c060;padding:1rem;border-radius:6px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.4rem;text-align:left}</style>
</head><body>
<h1>PQ-Shield API</h1>
<p class="banner"><strong>SIGN LOCALLY — non-custodial.</strong> Never send private keys,
seeds or recovery preimages. This server never signs. Every route returns an <em>unsigned</em> artifact (address,
script, sighash, or commitment bytes) for you to sign on your own device. Requests that
use recognized secret field names are rejected (HTTP 400). This check cannot detect
secrets hidden in allowed values. Policy text is public and appears in commitment bytes.</p>
<h2>Routes</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Returns (all unsigned)</th></tr>
<tr><td>GET</td><td>/health</td><td>liveness</td></tr>
<tr><td>POST</td><td>/vault/address</td><td>P2WSH deposit + trigger address, witnessScripts, descriptor</td></tr>
<tr><td>POST</td><td>/vault/unvault-tx</td><td>unsigned DEPOSIT→TRIGGER tx + hot-key sighash</td></tr>
<tr><td>POST</td><td>/vault/branch-a-tx</td><td>unsigned delayed withdrawal + hot-key sighash</td></tr>
<tr><td>POST</td><td>/vault/clawback-tx</td><td>unsigned hashlocked recovery + recovery-key sighash</td></tr>
<tr><td>POST</td><td>/anchor/commitment</td><td>canonical bytes to PQ-sign client-side + Bloch guard hash</td></tr>
<tr><td>POST</td><td>/anchor/verify</td><td>verify a PQ signature over an anchor against a <em>trusted_pq_pubkey</em> you supply (valid/invalid)</td></tr>
</table>
<p>Full docs, request/response examples, and a curl walkthrough: see <code>README.md</code>.</p>
<p><strong>Hardened recovery (audit M1):</strong> derive your recovery key on a HARDENED path,
not a non-hardened sibling of the hot key.</p>
</body></html>"#;

#[cfg(test)]
mod audit_edge_regressions {
    use super::*;
    use tower::ServiceExt;

    fn fields() -> Value {
        let address = bitcoin::Address::p2wsh(&bitcoin::ScriptBuf::new(), Network::Regtest).to_string();
        json!({"target_chain":"bitcoin", "btc_vault_address":address,
            "designated_safe_dest":address, "recovery_hash":"00".repeat(32),
            "pq_recovery_pubkey":"01", "csv_delay":144})
    }
    fn bytes(value: Value) -> Bytes { Bytes::from(serde_json::to_vec(&value).unwrap()) }

    #[tokio::test]
    async fn error_responses_do_not_reflect_untrusted_keys_or_values() {
        const MARKER: &str = "private_seed_accidental_disclosure_marker";
        let mut unknown = fields();
        unknown[MARKER] = json!("value");
        let mut wrong_type = fields();
        wrong_type["csv_delay"] = json!(MARKER);
        let mut wrong_chain = fields();
        wrong_chain["target_chain"] = json!(MARKER);
        for request in [unknown, wrong_type, wrong_chain] {
            let request = axum::http::Request::builder().method("POST").uri("/anchor/commitment")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&request).unwrap())).unwrap();
            let response = router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
            assert!(!String::from_utf8_lossy(&body).contains(MARKER));
        }
        assert!(!parse_network(MARKER).unwrap_err().message.contains(MARKER));
    }

    #[tokio::test]
    async fn verification_does_not_echo_free_form_policy_or_trusted_input() {
        let marker = "accidentally supplied confidential policy";
        let trusted = hex::encode(b"accidental confidential trusted key input");
        let mut request = fields();
        request["policy"] = json!(marker);
        request["trusted_pq_pubkey"] = json!(trusted);
        request["signature"] = json!("00");
        let Json(response) = anchor_verify(bytes(request)).await.unwrap();
        assert_eq!(response["valid"], false);
        assert!(response.get("verified_against_pq_pubkey").is_none());
        assert!(response.get("commitment_bytes_hex").is_none());
        let encoded = response.to_string();
        assert!(!encoded.contains(marker));
        assert!(!encoded.contains(&hex::encode(marker)));
        assert!(!encoded.contains(&trusted));
    }

    #[test]
    fn anchor_forms_refuse_unknown_fields_and_ambiguous_encodings() {
        let mut request = fields();
        request["signature"] = json!("00");
        request["unrecognized"] = json!("do not echo me");
        assert!(parse_anchor_verify(&bytes(request)).is_err());
        assert!(parse_anchor_verify(&bytes(json!({"signed_anchor_hex":"00", "unknown":"value"}))).is_err());
        assert!(parse_anchor_verify(&bytes(json!({"signed_anchor_hex":"00", "signature":"00"}))).is_err());
        assert!(parse_anchor_verify(&bytes(json!({"signed_anchor_hex":"00", "trusted_pq_pubkey":"01"}))).is_ok());
    }

    #[test]
    fn anchor_addresses_require_valid_same_network_bitcoin_addresses() {
        let parse = |value| parse_guarded::<AnchorFields>(&bytes(value)).unwrap().to_anchor();
        assert!(parse(fields()).is_ok());
        let mut invalid = fields();
        invalid["designated_safe_dest"] = json!("bcrt1qinvalid");
        assert!(parse(invalid).is_err());
        let mut wrong_network = fields();
        wrong_network["designated_safe_dest"] = json!(bitcoin::Address::p2wsh(
            &bitcoin::ScriptBuf::new(), Network::Bitcoin).to_string());
        assert!(parse(wrong_network).is_err());
        let mut wrong_chain = fields();
        wrong_chain["target_chain"] = json!("ethereuml1");
        assert!(parse(wrong_chain).is_err());
    }

    #[test]
    fn nested_delay_cannot_be_bypassed() {
        let params = VaultParamsReq { hot_pubkey: String::new(), recovery_pubkey: String::new(),
            recovery_hash: String::new(), csv_delay: 0 };
        assert!(params.to_params(Network::Regtest).err().unwrap().message.contains("144"));
    }

    #[tokio::test]
    async fn unvault_route_uses_checked_builder_for_hostile_values() {
        let keys = vaultlib::derive_vault_keys(&[7; 32], false);
        let request = |txid: &str, vout: u32, amount: u64, fee: u64| json!({
            "network": "regtest",
            "vault": { "hot_pubkey": keys.hot_pubkey.to_string(),
                "recovery_pubkey": keys.recovery_pubkey.to_string(),
                "recovery_hash": hex::encode([8; 32]), "csv_delay": 144u16 },
            "deposit_outpoint": { "txid": txid, "vout": vout },
            "deposit_amount_sat": amount, "fee_sat": fee,
        });
        let valid = "0000000000000000000000000000000000000000000000000000000000000001";
        let null = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(unvault_tx(bytes(request(null, u32::MAX, 100_000, 500))).await.is_err());
        assert!(unvault_tx(bytes(request(valid, 0, 1, 0))).await.is_err());
        assert!(unvault_tx(bytes(request(valid, 0, 100_000, 10_001))).await.is_err());
        assert!(unvault_tx(bytes(request(valid, 0, BITCOIN_MAX_MONEY_SAT + 1, 0))).await.is_err());
        assert!(unvault_tx(bytes(request(valid, 0, 100_000, 500))).await.is_ok());
    }

    #[tokio::test]
    async fn http_refuses_form_cross_site_and_oversized_requests() {
        for (content_type, site, data, expected) in [
            ("text/plain", "same-origin", "{}".into(), StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ("application/json", "cross-site", "{}".into(), StatusCode::FORBIDDEN),
            ("application/json", "same-origin", " ".repeat(128 * 1024 + 1), StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let request = axum::http::Request::builder().method("POST").uri("/anchor/commitment")
                .header("content-type", content_type).header("sec-fetch-site", site)
                .body(axum::body::Body::from(data)).unwrap();
            assert_eq!(router().oneshot(request).await.unwrap().status(), expected);
        }
    }
}
