//! D5 — eUTXO RPC / wallet helpers: CONSTRUCT and SUBMIT eUTXO transactions,
//! INSPECT eUTXO UTXOs.
//!
//! Compiled only under `--features euvm` (the `mod` declaration in
//! `src/rpc/mod.rs` is feature-gated); the default build is unaffected and the
//! `euvm_*` RPC methods are simply not registered.
//!
//! This is NOT consensus code. Everything here PRODUCES transactions that go
//! through the normal validation pipeline (`sendrawtransaction` → mempool →
//! block), or QUERIES the UTXO set read-only. The one hard contract is that a
//! built transaction must be exactly what the consensus hook (D2) accepts —
//! which is why [`build_tx`] pre-checks its own output through the canonical
//! `crate::euvm::validate_node_tx` before the caller ever broadcasts it.
//!
//! # RPC methods (registered in `dispatch()` in `src/rpc/mod.rs`)
//!
//! - `euvm_buildtx`   — build a ready-to-broadcast raw transaction from UTXO
//!                      references + recipients (legacy address or eUTXO
//!                      contract outputs), signing legacy inputs (if keys are
//!                      supplied) and packing eUTXO witnesses into `script_sig`
//!                      in the pinned wire format. Returns hex for the EXISTING
//!                      `sendrawtransaction` — broadcast is not reimplemented.
//! - `euvm_listutxos` — scan the UTXO set for eUTXO (tagged) outputs, decoded
//!                      (validator_hash / datum / assets / BLCH value).
//! - `euvm_getutxo`   — inspect one UTXO by (txid, index), decoded.
//!
//! # eUTXO input witness — wire format (pinned by PMO)
//!
//! An eUTXO input's authorization travels in the EXISTING `TxInput.script_sig`
//! (no struct change):
//!
//! ```text
//! u32LE(validator_len) ‖ bloch_euvm::encode_program(&validator)
//! ‖ u32LE(redeemer_count) ‖ redeemer_items
//! ```
//!
//! each redeemer item a `Val` in D1's datum codec:
//! `Int → 0x00 ‖ i128 LE(16)`, `Bytes → 0x01 ‖ u32 LE(len) ‖ bytes`.
//! A legacy input keeps today's `sig ‖ pubkey` script_sig.

use serde_json::{json, Value as Json};

use crate::core::{ChainId, Transaction, TxInput, TxOutput};
use crate::euvm::{
    decode_eutxo_script, encode_eutxo_script, is_eutxo_script, is_legacy_p2pkh_script,
    legacy_pubkey_hash, validate_node_tx, EuWitness, EutxoScript,
};
use bloch_euvm::{encode_program, validator_hash, AssetId, Op, Val, Value as EuValue, BLCH};

/// Gas budget for the pre-broadcast `validate_node_tx` self-check. Generous
/// for wallet-sized transactions (a PQ sig check costs ~1000 gas); the real
/// consensus ceiling is the D2 hook's, not this.
const BUILDTX_VALIDATE_GAS: u64 = 10_000_000;

/// The node's transaction decoder rejects `script_sig` longer than 10 000
/// bytes (`Transaction::from_stratum_bytes`), so a witness that exceeds it
/// could never be broadcast — fail at build time with a clear message.
const MAX_SCRIPT_SIG_LEN: usize = 10_000;

/// Default / maximum page size for `euvm_listutxos`.
const LISTUTXOS_DEFAULT_LIMIT: usize = 100;
const LISTUTXOS_MAX_LIMIT: usize = 1_000;

// ═════════════════════════════════════════════════════════════════════════════
// Witness wire codec (script_sig payload for eUTXO inputs)
// ═════════════════════════════════════════════════════════════════════════════

/// Encode one redeemer/datum `Val` in D1's datum codec.
/// (Same layout `crate::euvm`'s script codec uses for the output datum.)
fn encode_val(out: &mut Vec<u8>, v: &Val) {
    match v {
        Val::Int(n) => {
            out.push(0x00);
            out.extend_from_slice(&n.to_le_bytes());
        }
        Val::Bytes(b) => {
            out.push(0x01);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
    }
}

// PMO-DEDUP: canonical is D2's `crate::euvm::encode_input_witness` (mod.rs).
// It was absent from this worktree at branch time; this local copy implements
// the same pinned wire format and must be deleted in favour of D2's once the
// branches merge.
/// Encode an [`EuWitness`] into the pinned `script_sig` wire format:
/// `u32LE(len(encode_program(validator))) ‖ encode_program(validator)
/// ‖ u32LE(redeemer_count) ‖ redeemer items (datum codec)`.
pub fn encode_input_witness(w: &EuWitness) -> Vec<u8> {
    let prog = encode_program(&w.validator);
    let mut out = Vec::with_capacity(8 + prog.len());
    out.extend_from_slice(&(prog.len() as u32).to_le_bytes());
    out.extend_from_slice(&prog);
    out.extend_from_slice(&(w.redeemer.len() as u32).to_le_bytes());
    for v in &w.redeemer {
        encode_val(&mut out, v);
    }
    out
}

/// Strict inverse of `bloch_euvm::encode_program` — needed to accept a
/// validator program over RPC as canonical program bytes (hex) and to verify
/// witness round-trips. Typed errors as strings; never panics; rejects
/// truncation, unknown tags, oversize programs/operands.
///
/// (`bloch_euvm` ships only the encoder — the hash preimage; if a canonical
/// decoder lands there, delete this one. PMO-DEDUP.)
pub fn decode_program(bytes: &[u8]) -> Result<Vec<Op>, String> {
    fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], String> {
        if buf.len() - *pos < n {
            return Err(format!(
                "program truncated at byte {}: need {} more, have {}",
                *pos,
                n,
                buf.len() - *pos
            ));
        }
        let s = &buf[*pos..*pos + n];
        *pos += n;
        Ok(s)
    }
    let mut ops = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if ops.len() >= bloch_euvm::MAX_PROGRAM_OPS {
            return Err(format!("program exceeds {} ops", bloch_euvm::MAX_PROGRAM_OPS));
        }
        let tag = take(bytes, &mut pos, 1)?[0];
        let op = match tag {
            0x01 => {
                let raw: [u8; 16] = take(bytes, &mut pos, 16)?.try_into().expect("16 bytes");
                Op::PushInt(i128::from_le_bytes(raw))
            }
            0x02 => {
                let raw: [u8; 4] = take(bytes, &mut pos, 4)?.try_into().expect("4 bytes");
                let len = u32::from_le_bytes(raw) as usize;
                if len > bloch_euvm::MAX_OPERAND_BYTES {
                    return Err(format!("PushBytes operand of {} bytes exceeds ceiling", len));
                }
                Op::PushBytes(take(bytes, &mut pos, len)?.to_vec())
            }
            0x10 => Op::Dup,
            0x11 => Op::Drop,
            0x12 => Op::Swap,
            0x13 => Op::Pick(take(bytes, &mut pos, 1)?[0]),
            0x20 => Op::Add,
            0x21 => Op::Sub,
            0x22 => Op::Mul,
            0x30 => Op::Eq,
            0x31 => Op::Lt,
            0x32 => Op::Not,
            0x40 => Op::Sha256d,
            0x41 => Op::Shake256,
            0x42 => Op::Size,
            0x50 => Op::CtxField(take(bytes, &mut pos, 1)?[0]),
            0x60 => Op::VerifySig,
            0x61 => Op::Verify,
            0x62 => Op::VerifyEcdsa,
            0x70 => Op::TxOutDatum(take(bytes, &mut pos, 1)?[0]),
            0x71 => Op::TxOutValidator(take(bytes, &mut pos, 1)?[0]),
            0x72 => Op::TxOutValue(take(bytes, &mut pos, 1)?[0]),
            0x73 => Op::SelfValidator,
            0x74 => Op::SelfAsset,
            0x75 => Op::TxOutAsset(take(bytes, &mut pos, 1)?[0]),
            t => return Err(format!("unknown opcode tag 0x{t:02x} at byte {}", pos - 1)),
        };
        ops.push(op);
    }
    Ok(ops)
}

/// Decode a witness `script_sig` back into an [`EuWitness`] — used by tests to
/// prove the wire round-trip; D2's consensus decoder is the canonical reader.
/// PMO-DEDUP: canonical is D2's.
pub fn decode_input_witness(script_sig: &[u8]) -> Result<EuWitness, String> {
    fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], String> {
        if buf.len() - *pos < n {
            return Err(format!("witness truncated: need {} more bytes at {}", n, *pos));
        }
        let s = &buf[*pos..*pos + n];
        *pos += n;
        Ok(s)
    }
    let mut pos = 0usize;
    let raw: [u8; 4] = take(script_sig, &mut pos, 4)?.try_into().expect("4 bytes");
    let vlen = u32::from_le_bytes(raw) as usize;
    let validator = decode_program(take(script_sig, &mut pos, vlen)?)?;
    let raw: [u8; 4] = take(script_sig, &mut pos, 4)?.try_into().expect("4 bytes");
    let count = u32::from_le_bytes(raw) as usize;
    let mut redeemer = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let v = match take(script_sig, &mut pos, 1)?[0] {
            0x00 => {
                let raw: [u8; 16] = take(script_sig, &mut pos, 16)?.try_into().expect("16 bytes");
                Val::Int(i128::from_le_bytes(raw))
            }
            0x01 => {
                let raw: [u8; 4] = take(script_sig, &mut pos, 4)?.try_into().expect("4 bytes");
                let len = u32::from_le_bytes(raw) as usize;
                Val::Bytes(take(script_sig, &mut pos, len)?.to_vec())
            }
            t => return Err(format!("unknown redeemer val tag 0x{t:02x}")),
        };
        redeemer.push(v);
    }
    if pos != script_sig.len() {
        return Err(format!("{} trailing bytes after witness", script_sig.len() - pos));
    }
    Ok(EuWitness { validator, redeemer })
}

// ═════════════════════════════════════════════════════════════════════════════
// JSON ↔ Val / assets
// ═════════════════════════════════════════════════════════════════════════════

/// Parse a JSON datum/redeemer value: `{"int": "123"}` (or a JSON number) |
/// `{"bytes": "<hex>"}`. Ints accept a string so the full i128 range is
/// representable (JSON numbers are not).
pub fn val_from_json(v: &Json) -> Result<Val, String> {
    if let Some(i) = v.get("int") {
        if let Some(n) = i.as_i64() {
            return Ok(Val::Int(n as i128));
        }
        if let Some(s) = i.as_str() {
            return s
                .parse::<i128>()
                .map(Val::Int)
                .map_err(|e| format!("bad int value {s:?}: {e}"));
        }
        return Err("\"int\" must be a number or decimal string".into());
    }
    if let Some(b) = v.get("bytes") {
        let s = b.as_str().ok_or("\"bytes\" must be a hex string")?;
        return hex::decode(s)
            .map(Val::Bytes)
            .map_err(|e| format!("bad bytes hex: {e}"));
    }
    Err("value must be {\"int\": ...} or {\"bytes\": \"<hex>\"}".into())
}

/// Render a `Val` to JSON (ints as decimal strings — full i128 range).
pub fn val_to_json(v: &Val) -> Json {
    match v {
        Val::Int(n) => json!({ "int": n.to_string() }),
        Val::Bytes(b) => json!({ "bytes": hex::encode(b) }),
    }
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| format!("{what} must be 32 bytes of hex"))
}

/// Parse `[{"asset_id": "<hex32>", "amount": u64}, ...]` into a `bloch_euvm`
/// value map (BLCH forbidden here — it rides in `value_sat`).
fn assets_from_json(v: &Json) -> Result<EuValue, String> {
    let arr = v.as_array().ok_or("\"assets\" must be an array")?;
    let mut out = EuValue::new();
    for (i, e) in arr.iter().enumerate() {
        let id_hex = e
            .get("asset_id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("assets[{i}]: missing asset_id"))?;
        let id: AssetId = hex32(id_hex, &format!("assets[{i}].asset_id"))?;
        if id == BLCH {
            return Err(format!("assets[{i}]: BLCH belongs in value_sat, not the asset table"));
        }
        let amount = e
            .get("amount")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("assets[{i}]: missing/invalid amount"))?;
        if amount == 0 {
            return Err(format!("assets[{i}]: zero amount"));
        }
        if out.insert(id, amount).is_some() {
            return Err(format!("assets[{i}]: duplicate asset_id"));
        }
    }
    Ok(out)
}

fn assets_to_json(assets: &EuValue) -> Json {
    json!(assets
        .iter()
        .filter(|(id, _)| **id != BLCH)
        .map(|(id, amount)| json!({ "asset_id": hex::encode(id), "amount": amount }))
        .collect::<Vec<_>>())
}

// ═════════════════════════════════════════════════════════════════════════════
// Transaction builder (pure — testable without Storage)
// ═════════════════════════════════════════════════════════════════════════════

/// How one input is authorized.
pub enum InputAuth {
    /// Legacy P2PKH input signed here: PQ keypair supplied by the caller.
    LegacyKey { public_key: Vec<u8>, secret_key: Vec<u8> },
    /// Legacy P2PKH input left unsigned (`script_sig` empty); the caller signs
    /// externally using the returned per-input sighash. Tx is `complete: false`.
    LegacyUnsigned,
    /// eUTXO (contract) input: revealed validator program + redeemer, packed
    /// into `script_sig` in the pinned witness wire format.
    Eutxo(EuWitness),
}

/// One fully-resolved input for [`build_tx`].
pub struct BuildInput {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
    /// The output being spent (resolved from the UTXO store by the RPC glue).
    pub prevout: TxOutput,
    pub auth: InputAuth,
}

/// A built transaction plus everything needed to self-check and report it.
pub struct BuiltTx {
    pub tx: Transaction,
    /// BLCH fee implied by inputs − outputs.
    pub fee_sat: u64,
    /// True iff every input is authorized (no `LegacyUnsigned`).
    pub complete: bool,
    /// Per-input sighash (for external signing of unsigned inputs).
    pub sighashes: Vec<[u8; 32]>,
    /// The resolved prevouts, aligned with `tx.inputs` — validation input.
    pub prevouts: Vec<TxOutput>,
    /// Per-input witnesses (`Some` for eUTXO inputs) — validation input.
    /// Empty vec when the tx has no eUTXO inputs (all-legacy).
    pub witnesses: Vec<Option<EuWitness>>,
}

/// Build a node [`Transaction`] spending `inputs` into `outputs`.
///
/// Guarantees on success:
/// - every output `script_pubkey` is either legacy 20-byte P2PKH or a valid
///   tagged eUTXO script (built by the caller via [`encode_eutxo_script`]);
/// - every eUTXO input's `script_sig` is the pinned witness wire format and
///   its validator hashes to the prevout's `validator_hash`;
/// - every `LegacyKey` input's `script_sig` is today's `sig ‖ pubkey` with a
///   REAL hybrid PQ signature over that input's own sighash, and the supplied
///   pubkey hashes to the prevout's 20-byte script;
/// - the BLCH fee (inputs − outputs) is non-negative.
///
/// This does NOT check non-BLCH asset conservation or run validators — that is
/// [`validate_node_tx`]'s job (the RPC glue runs it before returning).
pub fn build_tx(
    inputs: &[BuildInput],
    outputs: Vec<TxOutput>,
    chain_id: ChainId,
    locktime: u32,
) -> Result<BuiltTx, String> {
    if inputs.is_empty() {
        return Err("at least one input required".into());
    }
    if outputs.is_empty() {
        return Err("at least one output required".into());
    }

    // BLCH fee = inputs − outputs, must be ≥ 0.
    let in_sum: u128 = inputs.iter().map(|i| i.prevout.value as u128).sum();
    let out_sum: u128 = outputs.iter().map(|o| o.value as u128).sum();
    if out_sum > in_sum {
        return Err(format!("outputs ({out_sum} sat) exceed inputs ({in_sum} sat)"));
    }
    let fee_sat = u64::try_from(in_sum - out_sum).map_err(|_| "fee overflows u64".to_string())?;

    // Skeleton with empty script_sigs. The sighash strips every input's
    // script_sig, so sighashes are independent of the signing order below.
    let mut tx = Transaction {
        version: 1,
        inputs: inputs
            .iter()
            .map(|i| TxInput {
                prev_txid: i.prev_txid,
                prev_index: i.prev_index,
                script_sig: vec![],
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs,
        locktime,
    };

    let sighashes: Vec<[u8; 32]> =
        (0..inputs.len()).map(|i| tx.sighash(i, chain_id)).collect();

    let any_eutxo = inputs.iter().any(|i| matches!(i.auth, InputAuth::Eutxo(_)));
    let mut witnesses: Vec<Option<EuWitness>> = Vec::with_capacity(inputs.len());
    let mut complete = true;

    for (i, inp) in inputs.iter().enumerate() {
        let prev_is_eutxo = is_eutxo_script(&inp.prevout.script_pubkey);
        match &inp.auth {
            InputAuth::Eutxo(w) => {
                if !prev_is_eutxo {
                    return Err(format!(
                        "input {i}: prevout is legacy P2PKH — a witness (validator/redeemer) is not allowed; supply secret_key/public_key instead"
                    ));
                }
                // Early, clear check: the revealed program must hash to the
                // prevout's committed validator_hash (the VM would reject it
                // later with ValidatorHashMismatch — fail at build time).
                let script = decode_eutxo_script(&inp.prevout.script_pubkey)
                    .map_err(|e| format!("input {i}: prevout script does not decode: {e}"))?;
                let vh = validator_hash(&w.validator);
                if vh != script.validator_hash {
                    return Err(format!(
                        "input {i}: revealed validator hashes to {} but prevout commits to {}",
                        hex::encode(vh),
                        hex::encode(script.validator_hash)
                    ));
                }
                let ss = encode_input_witness(w);
                if ss.len() > MAX_SCRIPT_SIG_LEN {
                    return Err(format!(
                        "input {i}: witness is {} bytes — exceeds the {MAX_SCRIPT_SIG_LEN}-byte script_sig wire cap",
                        ss.len()
                    ));
                }
                tx.inputs[i].script_sig = ss;
                witnesses.push(Some(w.clone()));
            }
            InputAuth::LegacyKey { public_key, secret_key } => {
                if prev_is_eutxo {
                    return Err(format!(
                        "input {i}: prevout is an eUTXO contract output — supply validator/redeemer, not keys"
                    ));
                }
                if !is_legacy_p2pkh_script(&inp.prevout.script_pubkey) {
                    return Err(format!("input {i}: prevout script is neither legacy nor eUTXO"));
                }
                if legacy_pubkey_hash(public_key)[..] != inp.prevout.script_pubkey[..] {
                    return Err(format!(
                        "input {i}: public_key does not hash to the prevout's address"
                    ));
                }
                let sig = crate::crypto::sign(secret_key, &sighashes[i])
                    .map_err(|e| format!("input {i}: signing failed: {e:?}"))?;
                tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, public_key);
                witnesses.push(None);
            }
            InputAuth::LegacyUnsigned => {
                if prev_is_eutxo {
                    return Err(format!(
                        "input {i}: prevout is an eUTXO contract output — supply validator/redeemer"
                    ));
                }
                complete = false;
                witnesses.push(None);
            }
        }
    }

    Ok(BuiltTx {
        fee_sat,
        complete,
        sighashes,
        prevouts: inputs.iter().map(|i| i.prevout.clone()).collect(),
        witnesses: if any_eutxo { witnesses } else { Vec::new() },
        tx,
    })
}

// ═════════════════════════════════════════════════════════════════════════════
// RPC glue (called from dispatch() in src/rpc/mod.rs)
// ═════════════════════════════════════════════════════════════════════════════

/// `euvm_buildtx` — params: `[ { inputs, outputs, fee_sat?, locktime?, validate? } ]`.
/// See the module docs / tests for the exact shapes. Returns
/// `{ txid, raw_tx, fee_sat, complete, validated, gas_used, sighashes, ... }`
/// or `{ "error": ... }`.
pub(super) async fn rpc_buildtx(params: Option<&Json>, state: &super::AppState) -> Json {
    let req = match params.and_then(|p| p.get(0)) {
        Some(o) if o.is_object() => o.clone(),
        _ => return json!({ "error": "params[0] must be the build-request object" }),
    };

    // ── parse + resolve inputs against the confirmed UTXO set ──
    let in_arr = match req.get("inputs").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return json!({ "error": "\"inputs\" must be a non-empty array" }),
    };
    let mut inputs: Vec<BuildInput> = Vec::with_capacity(in_arr.len());
    for (i, e) in in_arr.iter().enumerate() {
        let txid_hex = match e.get("txid").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return json!({ "error": format!("inputs[{i}]: missing txid") }),
        };
        let prev_txid = match hex32(txid_hex, &format!("inputs[{i}].txid")) {
            Ok(h) => h,
            Err(e) => return json!({ "error": e }),
        };
        let prev_index = match e.get("index").and_then(|v| v.as_u64()) {
            Some(n) if n <= u32::MAX as u64 => n as u32,
            _ => return json!({ "error": format!("inputs[{i}]: missing/invalid index") }),
        };
        // Confirmed UTXOs only — mempool-chained spends are not resolved here.
        let prevout = match state.store.get_utxo(&prev_txid, prev_index) {
            Ok(Some(o)) => o,
            Ok(None) => {
                return json!({ "error": format!(
                    "inputs[{i}]: UTXO {}:{} not found (spent, unconfirmed, or never existed)",
                    txid_hex, prev_index
                ) })
            }
            Err(err) => return json!({ "error": format!("inputs[{i}]: storage: {err}") }),
        };

        let auth = if let Some(vhex) = e.get("validator").and_then(|v| v.as_str()) {
            let prog_bytes = match hex::decode(vhex) {
                Ok(b) => b,
                Err(err) => return json!({ "error": format!("inputs[{i}].validator: bad hex: {err}") }),
            };
            let validator = match decode_program(&prog_bytes) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("inputs[{i}].validator: {err}") }),
            };
            let mut redeemer = Vec::new();
            if let Some(items) = e.get("redeemer") {
                let arr = match items.as_array() {
                    Some(a) => a,
                    None => return json!({ "error": format!("inputs[{i}].redeemer must be an array") }),
                };
                for (j, it) in arr.iter().enumerate() {
                    match val_from_json(it) {
                        Ok(v) => redeemer.push(v),
                        Err(err) => {
                            return json!({ "error": format!("inputs[{i}].redeemer[{j}]: {err}") })
                        }
                    }
                }
            }
            InputAuth::Eutxo(EuWitness { validator, redeemer })
        } else if let (Some(sk), Some(pk)) = (
            e.get("secret_key").and_then(|v| v.as_str()),
            e.get("public_key").and_then(|v| v.as_str()),
        ) {
            let secret_key = match hex::decode(sk) {
                Ok(b) => b,
                Err(err) => return json!({ "error": format!("inputs[{i}].secret_key: bad hex: {err}") }),
            };
            let public_key = match hex::decode(pk) {
                Ok(b) => b,
                Err(err) => return json!({ "error": format!("inputs[{i}].public_key: bad hex: {err}") }),
            };
            InputAuth::LegacyKey { public_key, secret_key }
        } else {
            InputAuth::LegacyUnsigned
        };

        inputs.push(BuildInput { prev_txid, prev_index, prevout, auth });
    }

    // ── parse outputs ──
    let out_arr = match req.get("outputs").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a.clone(),
        _ => return json!({ "error": "\"outputs\" must be a non-empty array" }),
    };
    let mut outputs: Vec<TxOutput> = Vec::with_capacity(out_arr.len());
    for (i, o) in out_arr.iter().enumerate() {
        match parse_output_json(o) {
            Ok(out) => outputs.push(out),
            Err(e) => return json!({ "error": format!("outputs[{i}]: {e}") }),
        }
    }

    let locktime = req.get("locktime").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let declared_fee = req.get("fee_sat").and_then(|v| v.as_u64());
    let do_validate = req.get("validate").and_then(|v| v.as_bool()).unwrap_or(true);
    let chain_id = crate::core::node_chain_id();

    // PQ signing + VM validation are CPU-bound — off the async reactor,
    // mirroring sendrawtransaction's spawn_blocking pattern.
    let built = tokio::task::spawn_blocking(move || {
        let built = build_tx(&inputs, outputs, chain_id, locktime)?;
        if let Some(f) = declared_fee {
            if f != built.fee_sat {
                return Err(format!(
                    "declared fee_sat {} != implied fee {} (inputs − outputs)",
                    f, built.fee_sat
                ));
            }
        }
        let validation = if do_validate && built.complete {
            Some(
                validate_node_tx(
                    &built.tx,
                    &built.prevouts,
                    &built.witnesses,
                    chain_id,
                    BUILDTX_VALIDATE_GAS,
                )
                .map_err(|e| e.to_string()),
            )
        } else {
            None
        };
        Ok::<_, String>((built, validation))
    })
    .await;

    let (built, validation) = match built {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return json!({ "error": e }),
        Err(e) => return json!({ "error": format!("build task failed: {e}") }),
    };

    let raw = built.tx.to_stratum_bytes(true);
    let mut resp = json!({
        "txid":       hex::encode(built.tx.txid()),
        "raw_tx":     hex::encode(&raw),
        "size_bytes": raw.len(),
        "fee_sat":    built.fee_sat,
        "complete":   built.complete,
        "sighashes":  built.sighashes.iter().map(hex::encode).collect::<Vec<_>>(),
        "inputs": built.tx.inputs.iter().zip(&built.prevouts).map(|(inp, prev)| json!({
            "txid":      hex::encode(inp.prev_txid),
            "index":     inp.prev_index,
            "value_sat": prev.value,
            "type":      if is_eutxo_script(&prev.script_pubkey) { "eutxo" } else { "legacy" },
        })).collect::<Vec<_>>(),
        "note": "broadcast with sendrawtransaction(raw_tx)",
    });
    match validation {
        Some(Ok(gas)) => {
            resp["validated"] = json!(true);
            resp["gas_used"] = json!(gas);
        }
        Some(Err(e)) => {
            // Fail loud: this tx would be rejected by consensus. Raw tx is
            // still returned for debugging, but marked invalid.
            resp["validated"] = json!(false);
            resp["validate_error"] = json!(e);
            resp["error"] = json!(format!("built tx failed eUTXO validation: {e}"));
        }
        None => {
            resp["validated"] = json!(false);
            if !built.complete {
                resp["note"] = json!(
                    "tx is UNSIGNED (legacy inputs missing keys): sign each sighash externally, \
                     set script_sig = u32LE(sig_len)‖sig‖u32LE(pk_len)‖pk, then sendrawtransaction"
                );
            }
        }
    }
    resp
}

/// Parse one output object: `{"address": ..., "value_sat": ...}` (legacy) or
/// `{"value_sat": ..., "eutxo": {"validator_hash", "datum"?, "assets"?}}`.
fn parse_output_json(o: &Json) -> Result<TxOutput, String> {
    let value = o
        .get("value_sat")
        .and_then(|v| v.as_u64())
        .ok_or("missing/invalid value_sat")?;
    if let Some(addr) = o.get("address").and_then(|v| v.as_str()) {
        let a = crate::address::Address::parse(addr).map_err(|e| format!("bad address: {e}"))?;
        return Ok(TxOutput { value, script_pubkey: a.hash().to_vec() });
    }
    if let Some(eu) = o.get("eutxo") {
        let vh_hex = eu
            .get("validator_hash")
            .and_then(|v| v.as_str())
            .ok_or("eutxo output: missing validator_hash")?;
        let vh = hex32(vh_hex, "eutxo.validator_hash")?;
        let datum = match eu.get("datum") {
            Some(d) => val_from_json(d)?,
            None => Val::Int(0),
        };
        let assets = match eu.get("assets") {
            Some(a) => assets_from_json(a)?,
            None => EuValue::new(),
        };
        let spk = encode_eutxo_script(&EutxoScript { validator_hash: vh, datum, assets })
            .map_err(|e| format!("eutxo script encode: {e}"))?;
        return Ok(TxOutput { value, script_pubkey: spk });
    }
    Err("output must have \"address\" (legacy) or \"eutxo\" {...}".into())
}

/// `euvm_listutxos` — params: `[validator_hash_hex|null, limit?, offset?]`.
/// Scans the UTXO set for eUTXO (tagged) outputs and decodes them.
pub(super) fn rpc_listutxos(params: Option<&Json>, state: &super::AppState) -> Json {
    let vh_filter = match params.and_then(|p| p.get(0)) {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => match v.as_str().map(|s| hex32(s, "validator_hash")) {
            Some(Ok(h)) => Some(h),
            _ => return json!({ "error": "params[0] must be null or a 32-byte hex validator_hash" }),
        },
    };
    let limit = params
        .and_then(|p| p.get(1))
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(LISTUTXOS_DEFAULT_LIMIT)
        .min(LISTUTXOS_MAX_LIMIT);
    let offset = params
        .and_then(|p| p.get(2))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let all = match state.store.iter_utxos_sorted() {
        Ok(v) => v,
        Err(e) => return json!({ "error": e.to_string() }),
    };

    let mut total_matching = 0usize;
    let mut undecodable = 0usize;
    let mut list: Vec<Json> = Vec::new();
    for (txid, index, value, spk) in &all {
        if !is_eutxo_script(spk) {
            continue;
        }
        let script = match decode_eutxo_script(spk) {
            Ok(s) => s,
            Err(_) => {
                // A tagged-looking but malformed script in the UTXO set —
                // count it honestly instead of hiding it.
                undecodable += 1;
                continue;
            }
        };
        if let Some(f) = vh_filter {
            if script.validator_hash != f {
                continue;
            }
        }
        total_matching += 1;
        if total_matching > offset && list.len() < limit {
            list.push(json!({
                "txid":           hex::encode(txid),
                "index":          index,
                "value_sat":      value,
                "validator_hash": hex::encode(script.validator_hash),
                "datum":          val_to_json(&script.datum),
                "assets":         assets_to_json(&script.assets),
            }));
        }
    }

    json!({
        "total_matching":     total_matching,
        "returned":           list.len(),
        "offset":             offset,
        "limit":              limit,
        "undecodable_tagged": undecodable,
        "utxos":              list,
    })
}

/// `euvm_getutxo` — params: `[txid_hex, index]`. Decodes one UTXO (legacy or
/// eUTXO) from the confirmed UTXO set.
pub(super) fn rpc_getutxo(params: Option<&Json>, state: &super::AppState) -> Json {
    let txid_hex = match params.and_then(|p| p.get(0)).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": "params: [txid_hex, index]" }),
    };
    let txid = match hex32(txid_hex, "txid") {
        Ok(h) => h,
        Err(e) => return json!({ "error": e }),
    };
    let index = match params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()) {
        Some(n) if n <= u32::MAX as u64 => n as u32,
        _ => return json!({ "error": "params: [txid_hex, index]" }),
    };
    let out = match state.store.get_utxo(&txid, index) {
        Ok(Some(o)) => o,
        Ok(None) => {
            return json!({ "found": false, "txid": txid_hex, "index": index,
                           "note": "not in the confirmed UTXO set (spent or never existed)" })
        }
        Err(e) => return json!({ "error": e.to_string() }),
    };

    if is_eutxo_script(&out.script_pubkey) {
        match decode_eutxo_script(&out.script_pubkey) {
            Ok(s) => json!({
                "found":          true,
                "txid":           txid_hex,
                "index":          index,
                "type":           "eutxo",
                "value_sat":      out.value,
                "validator_hash": hex::encode(s.validator_hash),
                "datum":          val_to_json(&s.datum),
                "assets":         assets_to_json(&s.assets),
                "script_pubkey":  hex::encode(&out.script_pubkey),
            }),
            Err(e) => json!({
                "found":         true,
                "txid":          txid_hex,
                "index":         index,
                "type":          "eutxo_undecodable",
                "value_sat":     out.value,
                "script_pubkey": hex::encode(&out.script_pubkey),
                "decode_error":  e.to_string(),
            }),
        }
    } else if is_legacy_p2pkh_script(&out.script_pubkey) {
        let mut h = [0u8; 20];
        h.copy_from_slice(&out.script_pubkey);
        json!({
            "found":         true,
            "txid":          txid_hex,
            "index":         index,
            "type":          "legacy",
            "value_sat":     out.value,
            "address":       crate::crypto::address_from_hash(&h, false),
            "script_pubkey": hex::encode(&out.script_pubkey),
        })
    } else {
        json!({
            "found":         true,
            "txid":          txid_hex,
            "index":         index,
            "type":          "unknown",
            "value_sat":     out.value,
            "script_pubkey": hex::encode(&out.script_pubkey),
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::euvm::{legacy_pubkey_hash, validate_node_tx};
    use std::sync::OnceLock;

    const CHAIN: ChainId = ChainId::Genesis2Devnet;

    /// One shared real hybrid ML-DSA-65 ‖ Falcon-1024 keypair (keygen is
    /// expensive in debug builds).
    fn kp() -> &'static (Vec<u8>, Vec<u8>) {
        static K: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        K.get_or_init(bloch_crypto::crypto::generate_keypair)
    }

    fn every_op() -> Vec<Op> {
        vec![
            Op::PushInt(i128::MIN),
            Op::PushInt(-1),
            Op::PushBytes(vec![]),
            Op::PushBytes(vec![0xAA; 33]),
            Op::Dup,
            Op::Drop,
            Op::Swap,
            Op::Pick(3),
            Op::Add,
            Op::Sub,
            Op::Mul,
            Op::Eq,
            Op::Lt,
            Op::Not,
            Op::Sha256d,
            Op::Shake256,
            Op::Size,
            Op::CtxField(0),
            Op::VerifySig,
            Op::Verify,
            Op::VerifyEcdsa,
            Op::TxOutDatum(1),
            Op::TxOutValidator(2),
            Op::TxOutValue(3),
            Op::SelfValidator,
            Op::SelfAsset,
            Op::TxOutAsset(4),
        ]
    }

    #[test]
    fn decode_program_round_trips_every_op() {
        let prog = every_op();
        let enc = encode_program(&prog);
        let dec = decode_program(&enc).expect("decode");
        // Op has no PartialEq — compare via the canonical encoding.
        assert_eq!(encode_program(&dec), enc, "byte-exact round trip");
        assert_eq!(dec.len(), prog.len());

        // strict: every prefix fails, trailing byte fails, unknown tag fails
        for cut in 1..enc.len() {
            if decode_program(&enc[..cut]).is_ok() {
                // a prefix is only valid if it ends exactly on an op boundary;
                // re-encoding must then be that prefix
                let d = decode_program(&enc[..cut]).unwrap();
                assert_eq!(encode_program(&d), enc[..cut].to_vec());
            }
        }
        assert!(decode_program(&[0xFF]).is_err(), "unknown tag");
        assert!(decode_program(&[0x01, 0x00]).is_err(), "truncated PushInt");
    }

    /// The PINNED witness wire format, byte for byte:
    /// u32LE(validator_len) ‖ encode_program ‖ u32LE(redeemer_count) ‖ items
    /// (Int → 0x00‖i128LE, Bytes → 0x01‖u32LE(len)‖bytes).
    #[test]
    fn witness_wire_format_is_pinned() {
        let w = EuWitness {
            validator: vec![Op::PushInt(1)],
            redeemer: vec![Val::Int(7), Val::Bytes(vec![0xAB, 0xCD])],
        };
        let ss = encode_input_witness(&w);

        let prog = encode_program(&w.validator);
        let mut expect = Vec::new();
        expect.extend_from_slice(&(prog.len() as u32).to_le_bytes());
        expect.extend_from_slice(&prog);
        expect.extend_from_slice(&2u32.to_le_bytes());
        expect.push(0x00);
        expect.extend_from_slice(&7i128.to_le_bytes());
        expect.push(0x01);
        expect.extend_from_slice(&2u32.to_le_bytes());
        expect.extend_from_slice(&[0xAB, 0xCD]);
        assert_eq!(ss, expect, "witness bytes must match the pinned layout exactly");

        // round trip through the decoder
        let back = decode_input_witness(&ss).expect("decode witness");
        assert_eq!(encode_program(&back.validator), prog);
        assert_eq!(back.redeemer, w.redeemer);
    }

    /// END-TO-END SELF-CHECK: a transaction built by `build_tx` — one eUTXO
    /// contract input (with native assets) + one REAL-PQ-signed legacy input,
    /// paying an eUTXO continuation output + a legacy output — passes the
    /// canonical `crate::euvm::validate_node_tx`, i.e. is exactly what the D2
    /// consensus hook accepts. Also proves the raw bytes survive the
    /// sendrawtransaction wire round trip with the witness intact.
    #[test]
    fn built_tx_passes_validate_node_tx() {
        let (pk, _sk) = kp();
        let asset1: AssetId = {
            let mut a = [0u8; 32];
            a[0] = 1;
            a
        };

        // Contract prevout: always-true validator, datum Int(7), 5 of asset1.
        let contract_validator = vec![Op::PushInt(1)];
        let vh = validator_hash(&contract_validator);
        let contract_spk = encode_eutxo_script(&EutxoScript {
            validator_hash: vh,
            datum: Val::Int(7),
            assets: [(asset1, 5u64)].into_iter().collect(),
        })
        .expect("encode contract spk");
        let contract_prevout = TxOutput { value: 1_000, script_pubkey: contract_spk };

        // Legacy prevout locked to our real key.
        let legacy_prevout =
            TxOutput { value: 500, script_pubkey: legacy_pubkey_hash(pk).to_vec() };

        // Outputs: contract continuation (datum advances, assets conserved) +
        // a legacy payment. Fee = 1500 − 1450 = 50.
        let out_contract = TxOutput {
            value: 900,
            script_pubkey: encode_eutxo_script(&EutxoScript {
                validator_hash: vh,
                datum: Val::Int(8),
                assets: [(asset1, 5u64)].into_iter().collect(),
            })
            .expect("encode out spk"),
        };
        let out_legacy = TxOutput { value: 550, script_pubkey: vec![9u8; 20] };

        let inputs = vec![
            BuildInput {
                prev_txid: [1u8; 32],
                prev_index: 0,
                prevout: contract_prevout,
                auth: InputAuth::Eutxo(EuWitness {
                    validator: contract_validator,
                    redeemer: vec![Val::Int(1)],
                }),
            },
            BuildInput {
                prev_txid: [2u8; 32],
                prev_index: 1,
                prevout: legacy_prevout,
                auth: InputAuth::LegacyKey {
                    public_key: kp().0.clone(),
                    secret_key: kp().1.clone(),
                },
            },
        ];

        let built =
            build_tx(&inputs, vec![out_contract, out_legacy], CHAIN, 0).expect("build");
        assert!(built.complete);
        assert_eq!(built.fee_sat, 50);
        assert_eq!(built.witnesses.len(), 2);
        assert!(built.witnesses[0].is_some() && built.witnesses[1].is_none());

        // THE self-check: the built tx passes the canonical consensus-shape
        // validation (per-input sighash, real PQ verifier, asset conservation).
        let gas = validate_node_tx(&built.tx, &built.prevouts, &built.witnesses, CHAIN, 1_000_000)
            .expect("built tx must pass validate_node_tx");
        assert!(gas > 0, "the legacy sig check must have burned gas");

        // Wire round trip (what sendrawtransaction does): bytes → Transaction,
        // witness script_sig intact and decodable, txid stable.
        let raw = built.tx.to_stratum_bytes(true);
        let back = Transaction::from_stratum_bytes(&raw).expect("wire round trip");
        assert_eq!(back.txid(), built.tx.txid());
        let w = decode_input_witness(&back.inputs[0].script_sig).expect("witness survives wire");
        assert_eq!(validator_hash(&w.validator), vh);
        // and the re-parsed tx STILL validates
        validate_node_tx(&back, &built.prevouts, &built.witnesses, CHAIN, 1_000_000)
            .expect("wire-round-tripped tx still validates");
    }

    /// Builder guardrails: wrong validator for the prevout, witness on a
    /// legacy input, keys on a contract input, negative fee — all fail closed
    /// with clear errors at BUILD time (not deep in the VM).
    #[test]
    fn build_tx_fails_closed() {
        let contract_spk = encode_eutxo_script(&EutxoScript {
            validator_hash: validator_hash(&[Op::PushInt(1)]),
            datum: Val::Int(0),
            assets: EuValue::new(),
        })
        .expect("spk");
        let contract_prevout = TxOutput { value: 100, script_pubkey: contract_spk };
        let legacy_prevout = TxOutput { value: 100, script_pubkey: vec![7u8; 20] };
        let pay = TxOutput { value: 90, script_pubkey: vec![8u8; 20] };

        // wrong revealed validator → validator-hash mismatch at build time
        let err = build_tx(
            &[BuildInput {
                prev_txid: [0u8; 32],
                prev_index: 0,
                prevout: contract_prevout.clone(),
                auth: InputAuth::Eutxo(EuWitness {
                    validator: vec![Op::PushInt(2)], // hashes differently
                    redeemer: vec![],
                }),
            }],
            vec![pay.clone()],
            CHAIN,
            0,
        )
        .err().expect("build must fail");
        assert!(err.contains("hashes to"), "got: {err}");

        // witness supplied for a legacy prevout → rejected
        let err = build_tx(
            &[BuildInput {
                prev_txid: [0u8; 32],
                prev_index: 0,
                prevout: legacy_prevout.clone(),
                auth: InputAuth::Eutxo(EuWitness { validator: vec![Op::PushInt(1)], redeemer: vec![] }),
            }],
            vec![pay.clone()],
            CHAIN,
            0,
        )
        .err().expect("build must fail");
        assert!(err.contains("legacy"), "got: {err}");

        // keys supplied for a contract prevout → rejected
        let err = build_tx(
            &[BuildInput {
                prev_txid: [0u8; 32],
                prev_index: 0,
                prevout: contract_prevout,
                auth: InputAuth::LegacyKey { public_key: vec![1], secret_key: vec![2] },
            }],
            vec![pay.clone()],
            CHAIN,
            0,
        )
        .err().expect("build must fail");
        assert!(err.contains("contract"), "got: {err}");

        // outputs exceed inputs → negative fee rejected
        let err = build_tx(
            &[BuildInput {
                prev_txid: [0u8; 32],
                prev_index: 0,
                prevout: legacy_prevout,
                auth: InputAuth::LegacyUnsigned,
            }],
            vec![TxOutput { value: 200, script_pubkey: vec![8u8; 20] }],
            CHAIN,
            0,
        )
        .err().expect("build must fail");
        assert!(err.contains("exceed"), "got: {err}");
    }

    /// An unsigned build (legacy input without keys) reports complete: false
    /// and exposes the per-input sighash for external signing.
    #[test]
    fn unsigned_build_exposes_sighashes() {
        let legacy_prevout = TxOutput { value: 100, script_pubkey: vec![7u8; 20] };
        let built = build_tx(
            &[BuildInput {
                prev_txid: [3u8; 32],
                prev_index: 0,
                prevout: legacy_prevout,
                auth: InputAuth::LegacyUnsigned,
            }],
            vec![TxOutput { value: 90, script_pubkey: vec![8u8; 20] }],
            CHAIN,
            0,
        )
        .expect("build");
        assert!(!built.complete);
        assert!(built.tx.inputs[0].script_sig.is_empty());
        assert_eq!(built.sighashes.len(), 1);
        assert_eq!(built.sighashes[0], built.tx.sighash(0, CHAIN));
        assert!(built.witnesses.is_empty(), "all-legacy tx carries no witness vec");
    }

    #[test]
    fn val_json_round_trip() {
        let cases = vec![
            Val::Int(0),
            Val::Int(-1),
            Val::Int(i128::MAX),
            Val::Int(i128::MIN),
            Val::Bytes(vec![]),
            Val::Bytes(vec![0xDE, 0xAD]),
        ];
        for v in cases {
            let j = val_to_json(&v);
            assert_eq!(val_from_json(&j).expect("parse"), v, "round trip {j}");
        }
        // plain JSON numbers accepted for small ints
        assert_eq!(val_from_json(&json!({"int": 42})).unwrap(), Val::Int(42));
        // garbage rejected
        assert!(val_from_json(&json!({"bytes": "zz"})).is_err());
        assert!(val_from_json(&json!("nope")).is_err());
    }
}
