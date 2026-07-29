//! eUTXO VM integration adapter (step 5.1/5.2) — feature-gated, NOT wired into
//! `accept_block`.
//!
//! Compiled only under `--features euvm` (off by default). With the feature off,
//! this module does not exist in the build and node behaviour is byte-for-byte
//! unchanged. Even with the feature ON, nothing here is called from the block
//! acceptance path yet — this is the adapter layer the future hook will use:
//!
//! - [`NodePqVerifier`] bridges the VM's `SigVerifier` trait to the node's real
//!   hybrid ML-DSA-65 ‖ Falcon-1024 verifier (`bloch_crypto::crypto::verify`), so
//!   validators verify signatures with the exact consensus rule.
//! - [`euvm_active`] is a PLAIN, DETERMINISTIC HEIGHT gate — no committee, no
//!   quorum, no signatures, no FFG (the committee model was dropped; see
//!   `crates/bloch-euvm/src/harness.rs`: "Deterministic, height-gated
//!   activation — NO committee / quorum / FFG"). The activation height is
//!   per-chain via [`euvm_activation_height`]: 0 on Genesis-3 mainnet (active
//!   from genesis), `u64::MAX` (inert sentinel) everywhere else.
//!
//! # The adapter API (what the hook / miner-mirror / RPC consume)
//!
//! - **Tagged-output codec**: [`encode_eutxo_script`] / [`decode_eutxo_script`]
//!   (script-level, [`EutxoScript`]) and [`encode_output`] / [`decode_output`]
//!   (node-`TxOutput`-level, [`ExtOutput`]). A `script_pubkey` is either legacy
//!   P2PKH (exactly 20 bytes) or an eUTXO script tagged with
//!   [`EUTXO_SCRIPT_TAG`]; the two can never collide (tagged scripts are ≥
//!   [`EUTXO_SCRIPT_MIN_LEN`] = 40 bytes). Decode is STRICT: typed
//!   [`EuMapError`]s, byte-exact round-trip, never panics.
//! - **Transaction mapping**: [`map_tx_to_eutx`] maps a node
//!   [`Transaction`] + its resolved prevouts (+ per-input [`EuWitness`]es for
//!   contract inputs) to a [`bloch_euvm::EuTx`]. Legacy P2PKH inputs are
//!   auto-mapped to [`legacy_p2pkh_validator`] with the pubkey-hash binding
//!   checked host-side (the VM has no SHA3-256/20 opcode yet — see that fn's
//!   docs), so the old model is a strict subset.
//! - **Validation**: [`validate_node_tx`] / [`validate_node_block`] are the
//!   canonical, per-input-sighash validation entrypoints (each input's
//!   validator sees ITS OWN `tx.sighash(i, chain_id)` in `ctx.fields[0]`,
//!   matching the node's live signature rule in `main.rs`).
//!
//! See `crates/bloch-euvm/INTEGRATION.md` for the full plan and the consensus-test
//! gate that must pass before any activation.

// This module is the adapter API consumed by the (not-yet-wired) accept_block
// hook, the miner mirror and the RPC layer; until those land, its pub items are
// unreferenced from the binary — silence dead_code for the whole module rather
// than annotate every item. Remove once the hook is wired.
#![allow(dead_code)]

// D3 — miner/block-builder mirror of the validator (see miner.rs). The whole
// `euvm` module is already feature-gated at its declaration in main.rs; the
// explicit cfg here restates the contract for readers and future refactors.
#[cfg(feature = "euvm")]
pub mod miner;

/// The name of the height-gated VM feature (labels/metrics only — no
/// committee signs anything; activation is the pure height gate below).
pub const EUVM_FEATURE: &str = "euvm";

/// Fraction of the eUTXO transaction fee that is burned (basis points), per the
/// ETH-style fee-burn design (§5-bis). Illustrative until governance sets it.
pub const EUVM_BURN_BPS: u16 = 5_000; // 50%

/// Canonical eUTXO gas ceilings — the SINGLE source of truth shared by the
/// accept_block hook (D2) and the miner mirror (D3), so miner and validator
/// agree by construction. They live here (the euvm module compiles into BOTH
/// the bin and the lib crate) rather than at a crate root. DoS/IBD-conservative
/// and still covers the ~1.4M-gas max-input (1024) legacy tx. Raising either is
/// a consensus change.
pub const EUVM_PER_TX_GAS: u64 = 2_000_000;
pub const EUVM_BLOCK_GAS:  u64 = 8_000_000;

/// Bridges the VM `SigVerifier` trait to the node's real hybrid
/// post-quantum verifier. This is the single point where "a signature is valid"
/// means exactly what consensus means by it.
pub struct NodePqVerifier;

impl bloch_euvm::SigVerifier for NodePqVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, msg, sig)
    }
}

/// The eUTXO VM activation height for THIS node's chain — the canonical
/// per-chain gate value read by [`euvm_active`]. Exhaustive over [`ChainId`]
/// (no wildcard) so adding a chain forces an explicit decision:
///
/// - `Genesis3Mainnet`: **0** — the VM is considered active from genesis on
///   the fresh Genesis-3 mainnet (no legacy blocks below the gate exist, so
///   there is nothing to grandfather).
/// - every other chain: `u64::MAX` — the inert sentinel, matching the
///   pre-existing behaviour (merely shipping this code activates nothing on
///   Mainnet/Testnet/Genesis-2; a real activation there is a deliberate,
///   reviewable constant change, cf. `bloch_euvm::harness`).
///
/// NOTE: `euvm_active` is currently INERT even when it returns `true` — the
/// execution hook into `accept_block` is NOT implemented, so nothing calls
/// the VM during block acceptance. Block acceptance is byte-identical with
/// and without `--features euvm`.
pub fn euvm_activation_height() -> u64 {
    match bloch_crypto::core::node_chain_id() {
        ChainId::Mainnet        => u64::MAX,
        ChainId::Testnet        => u64::MAX,
        ChainId::Genesis2Devnet => u64::MAX,
        ChainId::Genesis3Mainnet => 0,
    }
}

/// Height-gated activation — a pure, deterministic comparison, mirroring
/// `bloch_euvm::harness::is_feature_active`. NO committee / quorum / FFG
/// (that model was dropped; `bloch-ffg` remains a standalone foundation crate
/// but the node's gate no longer depends on it). Every node computes the same
/// answer from the block height and its chain-id alone.
pub fn euvm_active(height: u64) -> bool {
    height >= euvm_activation_height()
}

// ═════════════════════════════════════════════════════════════════════════════
// Step 5.2 (finalized) — the node ↔ eUTXO data-model mapping.
//
// Still NOT called from accept_block; these are the pure mapping/validation
// functions the future hook (D2), miner-mirror (D3) and RPC (D5) consume.
// ═════════════════════════════════════════════════════════════════════════════

use bloch_crypto::core::{ChainId, Transaction, TxOutput};
use bloch_euvm::{
    blch, validator_hash, value_get, AssetId, Ctx as EuCtx, EuTx, EuTxInput, ExtOutput, Op,
    TxError, Val, Value, VmError, BLCH, MAX_TX_DISTINCT_ASSETS,
};
use sha3::{Digest, Sha3_256};

// ── Codec constants ───────────────────────────────────────────────────────────

/// Reserved first byte marking an eUTXO output `script_pubkey`. A legacy P2PKH
/// script is EXACTLY 20 bytes (`SHA3-256(pubkey)[..20]`); a valid tagged script
/// is at least [`EUTXO_SCRIPT_MIN_LEN`] (40) bytes and starts with this byte, so
/// the two classes can never collide — a 20-byte hash that happens to begin with
/// `0xE0` is still legacy (see [`decode_output`]). `0xE0` also serves as the
/// codec's FORMAT VERSION: any future layout revision MUST use a different
/// reserved tag byte, never reinterpret this one.
pub const EUTXO_SCRIPT_TAG: u8 = 0xE0;

/// Exact byte length of a legacy P2PKH `script_pubkey` (`SHA3-256(pubkey)[..20]`).
pub const LEGACY_P2PKH_LEN: usize = 20;

/// Minimum byte length of a valid tagged eUTXO script:
/// tag(1) ‖ validator_hash(32) ‖ shortest datum (Bytes tag 1 + u32 len 4, empty)
/// ‖ asset count(2). Strictly greater than [`LEGACY_P2PKH_LEN`] — the
/// non-collision guarantee.
pub const EUTXO_SCRIPT_MIN_LEN: usize = 1 + 32 + 1 + 4 + 2; // 40

/// Maximum `script_pubkey` length the adapter will encode or decode. Mirrors the
/// node's transaction-decode cap (`core::Transaction` deserialization rejects
/// `script_pubkey` longer than 10 000 bytes as implausible), so no encodable
/// script can ever be unserializable and no on-wire script exceeds this.
pub const MAX_SCRIPT_PUBKEY_LEN: usize = 10_000;

// Datum wire tags (private — the codec is the only reader/writer).
const DATUM_TAG_INT: u8 = 0x00; // ‖ 16-byte little-endian i128
const DATUM_TAG_BYTES: u8 = 0x01; // ‖ u32 LE length ‖ bytes

// ── Typed mapping errors ──────────────────────────────────────────────────────

/// Typed, non-panicking error for every node↔eUTXO mapping operation
/// (script codec, output codec, transaction mapping, ctx building).
/// `#[non_exhaustive]` so later increments can add variants without breaking
/// D2/D3/D5 matches.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EuMapError {
    /// Script exceeds [`MAX_SCRIPT_PUBKEY_LEN`] (encode or decode).
    ScriptTooLong { len: usize },
    /// Script does not start with [`EUTXO_SCRIPT_TAG`].
    NotTagged,
    /// Script ended before a declared field: `need` more bytes, `have` left.
    Truncated { need: usize, have: usize },
    /// Bytes remain after a complete, valid parse — strict decode rejects them.
    TrailingBytes { extra: usize },
    /// Unknown datum type tag.
    BadDatumTag(u8),
    /// Asset table not strictly ascending by asset id (unsorted or duplicate).
    AssetOutOfOrder,
    /// Asset table entry with a zero amount (canonical form omits it).
    ZeroAssetAmount,
    /// The BLCH asset id in the asset table — BLCH lives in `TxOutput.value`,
    /// never in the script.
    BlchInAssetTable,
    /// More asset entries than `bloch_euvm::MAX_TX_DISTINCT_ASSETS`.
    TooManyAssets { count: usize },
    /// `script_pubkey` is neither exactly-20-byte legacy P2PKH nor a valid
    /// tagged eUTXO script. Fail-closed: malformed outputs do not map.
    BadScriptLength { len: usize },
    /// Coinbase transactions mint — they have no spendable inputs and are the
    /// hook's own policy domain; they cannot be mapped to an `EuTx`.
    CoinbaseNotMappable,
    /// A transaction with zero inputs cannot be mapped (nothing to validate).
    NoInputs,
    /// `prevouts.len()` must equal `tx.inputs.len()`.
    PrevoutCountMismatch { inputs: usize, prevouts: usize },
    /// `witnesses` must be empty (all-legacy tx) or one entry per input.
    WitnessCountMismatch { inputs: usize, witnesses: usize },
    /// A tagged (contract) prevout was spent without an [`EuWitness`].
    MissingWitness { input: usize },
    /// A witness was supplied for a legacy P2PKH input (its authorization is
    /// the script_sig; a witness there is a protocol error — fail closed).
    UnexpectedWitness { input: usize },
    /// The input's `script_sig` did not parse as `sig ‖ pubkey`
    /// (`Transaction::parse_script_sig`).
    BadScriptSig { input: usize },
    /// `SHA3-256(revealed pubkey)[..20]` does not equal the legacy prevout's
    /// 20-byte `script_pubkey` — the host-side half of the P2PKH check.
    PubkeyHashMismatch { input: usize },
    /// BLCH outputs exceed BLCH inputs — the implied fee would be negative.
    FeeUnderflow { in_blch: u128, out_blch: u128 },
    /// The implied BLCH fee does not fit in `u64`.
    FeeOverflow,
    /// `input_index` out of range for this transaction.
    BadInputIndex { index: usize, len: usize },
    /// Unknown opcode tag while decoding a validator program from a witness
    /// ([`decode_program`] — strict inverse of `bloch_euvm::encode_program`).
    BadOpTag(u8),
    /// A single input witness (`script_sig`) exceeds [`MAX_WITNESS_BYTES`].
    WitnessTooLong { len: usize },
    /// Decoding input `input`'s witness from its `script_sig` failed; `source`
    /// is the underlying codec error (truncation, trailing bytes, bad tag, ...).
    WitnessDecode { input: usize, source: Box<EuMapError> },
}

impl std::fmt::Display for EuMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use EuMapError::*;
        match self {
            ScriptTooLong { len } => write!(f, "script_pubkey too long ({len} bytes)"),
            NotTagged => write!(f, "script_pubkey is not eUTXO-tagged"),
            Truncated { need, have } => write!(f, "script truncated: need {need} bytes, have {have}"),
            TrailingBytes { extra } => write!(f, "{extra} trailing bytes after eUTXO script"),
            BadDatumTag(t) => write!(f, "unknown datum tag 0x{t:02x}"),
            AssetOutOfOrder => write!(f, "asset table not strictly ascending"),
            ZeroAssetAmount => write!(f, "zero-amount asset entry"),
            BlchInAssetTable => write!(f, "BLCH asset id in script asset table"),
            TooManyAssets { count } => write!(f, "too many asset entries ({count})"),
            BadScriptLength { len } => write!(f, "script_pubkey has invalid length {len} (not 20-byte P2PKH, not valid eUTXO)"),
            CoinbaseNotMappable => write!(f, "coinbase transactions cannot be mapped to eUTXO"),
            NoInputs => write!(f, "transaction has no inputs"),
            PrevoutCountMismatch { inputs, prevouts } => write!(f, "{inputs} inputs but {prevouts} prevouts"),
            WitnessCountMismatch { inputs, witnesses } => write!(f, "{inputs} inputs but {witnesses} witnesses"),
            MissingWitness { input } => write!(f, "input {input} spends a contract output but has no witness"),
            UnexpectedWitness { input } => write!(f, "input {input} is legacy P2PKH but a witness was supplied"),
            BadScriptSig { input } => write!(f, "input {input}: malformed script_sig"),
            PubkeyHashMismatch { input } => write!(f, "input {input}: pubkey hash does not match prevout"),
            FeeUnderflow { in_blch, out_blch } => write!(f, "BLCH outputs {out_blch} exceed inputs {in_blch}"),
            FeeOverflow => write!(f, "implied BLCH fee overflows u64"),
            BadInputIndex { index, len } => write!(f, "input index {index} out of range (tx has {len} inputs)"),
            BadOpTag(t) => write!(f, "unknown op tag 0x{t:02x} in witness validator program"),
            WitnessTooLong { len } => write!(f, "witness script_sig too long ({len} bytes)"),
            WitnessDecode { input, source } => write!(f, "input {input}: witness decode failed: {source}"),
        }
    }
}

impl std::error::Error for EuMapError {}

// ── Strict byte cursor + Val codec (shared by script and witness codecs) ──────

/// Strict cursor: the next `n` bytes of `buf` or a typed truncation error.
/// Never panics; never reads past `buf`.
fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], EuMapError> {
    let have = buf.len() - *pos;
    if have < n {
        return Err(EuMapError::Truncated { need: n, have });
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

/// Canonical [`Val`] encoding — THE datum codec. Used byte-identically for a
/// tagged script's datum and for every witness redeemer item (PMO pinned wire
/// format): `Int → 0x00 ‖ i128 LE[16]`, `Bytes → 0x01 ‖ u32 LE len ‖ bytes`.
fn encode_val(v: &Val, out: &mut Vec<u8>) {
    match v {
        Val::Int(n) => {
            out.push(DATUM_TAG_INT);
            out.extend_from_slice(&n.to_le_bytes());
        }
        Val::Bytes(b) => {
            out.push(DATUM_TAG_BYTES);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
    }
}

/// Strict inverse of [`encode_val`]. Typed errors, never panics.
fn decode_val(buf: &[u8], pos: &mut usize) -> Result<Val, EuMapError> {
    match take(buf, pos, 1)?[0] {
        DATUM_TAG_INT => {
            let raw: [u8; 16] = take(buf, pos, 16)?.try_into().expect("slice is 16 bytes");
            Ok(Val::Int(i128::from_le_bytes(raw)))
        }
        DATUM_TAG_BYTES => {
            let raw: [u8; 4] = take(buf, pos, 4)?.try_into().expect("slice is 4 bytes");
            let len = u32::from_le_bytes(raw) as usize;
            Ok(Val::Bytes(take(buf, pos, len)?.to_vec()))
        }
        t => Err(EuMapError::BadDatumTag(t)),
    }
}

// ── Tagged-output codec (script level) ────────────────────────────────────────

/// The decoded payload of a tagged eUTXO `script_pubkey`:
/// `{ validator_hash, datum, non-BLCH assets }`. The output's BLCH amount is
/// NOT here — it lives in `TxOutput.value` (see [`decode_output`]).
///
/// Wire layout (strict, canonical — [`EUTXO_SCRIPT_TAG`] is the version):
/// ```text
/// 0xE0 ‖ validator_hash[32]
///      ‖ datum: (0x00 ‖ i128 LE[16]) | (0x01 ‖ u32 LE len ‖ bytes)
///      ‖ asset_count: u16 LE
///      ‖ asset_count × (asset_id[32] ‖ amount u64 LE)   — ids strictly
///        ascending, amounts non-zero, BLCH forbidden
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EutxoScript {
    /// `bloch_euvm::validator_hash` of the program guarding this output.
    pub validator_hash: [u8; 32],
    /// The output's local contract state.
    pub datum: Val,
    /// Non-BLCH native assets carried by the output (BLCH is `TxOutput.value`).
    pub assets: Value,
}

/// True iff `script_pubkey` COULD be a tagged eUTXO output (cheap structural
/// predicate: reserved tag + minimum length). Real validity is
/// [`decode_eutxo_script`] succeeding. Never true for a 20-byte legacy script.
pub fn is_eutxo_script(spk: &[u8]) -> bool {
    spk.first() == Some(&EUTXO_SCRIPT_TAG) && spk.len() >= EUTXO_SCRIPT_MIN_LEN
}

/// True iff `script_pubkey` is a legacy P2PKH script (exactly 20 bytes —
/// `SHA3-256(pubkey)[..20]`). Mutually exclusive with [`is_eutxo_script`].
pub fn is_legacy_p2pkh_script(spk: &[u8]) -> bool {
    spk.len() == LEGACY_P2PKH_LEN
}

/// Encode an [`EutxoScript`] into a tagged `script_pubkey`, byte-exact and
/// canonical (`BTreeMap` ordering). Strict: rejects BLCH or zero-amount entries
/// in `assets` (BLCH belongs in `TxOutput.value`; canonical form omits zeros),
/// too many assets, and scripts exceeding [`MAX_SCRIPT_PUBKEY_LEN`].
pub fn encode_eutxo_script(s: &EutxoScript) -> Result<Vec<u8>, EuMapError> {
    if s.assets.len() > MAX_TX_DISTINCT_ASSETS {
        return Err(EuMapError::TooManyAssets { count: s.assets.len() });
    }
    let mut out = Vec::with_capacity(EUTXO_SCRIPT_MIN_LEN + 16 + 40 * s.assets.len());
    out.push(EUTXO_SCRIPT_TAG);
    out.extend_from_slice(&s.validator_hash);
    encode_val(&s.datum, &mut out);
    // asset count fits u16: MAX_TX_DISTINCT_ASSETS (4096) < u16::MAX.
    out.extend_from_slice(&(s.assets.len() as u16).to_le_bytes());
    for (id, amount) in &s.assets {
        // BTreeMap iteration is strictly ascending — canonical for free.
        if *id == BLCH {
            return Err(EuMapError::BlchInAssetTable);
        }
        if *amount == 0 {
            return Err(EuMapError::ZeroAssetAmount);
        }
        out.extend_from_slice(id);
        out.extend_from_slice(&amount.to_le_bytes());
    }
    if out.len() > MAX_SCRIPT_PUBKEY_LEN {
        return Err(EuMapError::ScriptTooLong { len: out.len() });
    }
    Ok(out)
}

/// Strictly decode a tagged eUTXO `script_pubkey`. Inverse of
/// [`encode_eutxo_script`]: `encode(decode(spk)) == spk` byte-exact for every
/// accepted input. Typed errors, never panics; rejects truncation, trailing
/// bytes, unknown datum tags, unsorted/duplicate/zero/BLCH asset entries.
pub fn decode_eutxo_script(spk: &[u8]) -> Result<EutxoScript, EuMapError> {
    if spk.len() > MAX_SCRIPT_PUBKEY_LEN {
        return Err(EuMapError::ScriptTooLong { len: spk.len() });
    }
    let mut pos: usize = 0;

    if take(spk, &mut pos, 1)?[0] != EUTXO_SCRIPT_TAG {
        return Err(EuMapError::NotTagged);
    }
    let mut vh = [0u8; 32];
    vh.copy_from_slice(take(spk, &mut pos, 32)?);

    let datum = decode_val(spk, &mut pos)?;

    let raw: [u8; 2] = take(spk, &mut pos, 2)?.try_into().expect("slice is 2 bytes");
    let count = u16::from_le_bytes(raw) as usize;
    if count > MAX_TX_DISTINCT_ASSETS {
        return Err(EuMapError::TooManyAssets { count });
    }
    let mut assets = Value::new();
    let mut last: Option<AssetId> = None;
    for _ in 0..count {
        let mut id = [0u8; 32];
        id.copy_from_slice(take(spk, &mut pos, 32)?);
        let amt_raw: [u8; 8] = take(spk, &mut pos, 8)?.try_into().expect("slice is 8 bytes");
        let amount = u64::from_le_bytes(amt_raw);
        if let Some(prev) = last {
            if id <= prev {
                return Err(EuMapError::AssetOutOfOrder);
            }
        }
        if id == BLCH {
            return Err(EuMapError::BlchInAssetTable);
        }
        if amount == 0 {
            return Err(EuMapError::ZeroAssetAmount);
        }
        assets.insert(id, amount);
        last = Some(id);
    }

    if pos != spk.len() {
        return Err(EuMapError::TrailingBytes { extra: spk.len() - pos });
    }
    Ok(EutxoScript { validator_hash: vh, datum, assets })
}

// ── Tagged-output codec (node TxOutput level) ─────────────────────────────────

/// Encode a VM [`ExtOutput`] into a node [`TxOutput`], canonically:
/// - its BLCH amount becomes `TxOutput.value`; non-BLCH assets go into the
///   tagged script (zero-amount entries are dropped — canonical form);
/// - an output that is EXACTLY legacy-shaped (validator ==
///   [`legacy_p2pkh_validator`], datum == 20-byte pubkey hash, no other assets)
///   is emitted as the plain 20-byte P2PKH script, so the legacy and eUTXO
///   representations stay one-to-one (`decode_output` inverts both arms).
pub fn encode_output(out: &ExtOutput) -> Result<TxOutput, EuMapError> {
    let blch_amount = value_get(&out.value, &BLCH);
    let assets: Value = out
        .value
        .iter()
        .filter(|(id, amount)| **id != BLCH && **amount != 0)
        .map(|(id, amount)| (*id, *amount))
        .collect();

    // Canonical legacy arm: the trivial-P2PKH validator with a 20-byte pubkey
    // hash as datum and no native assets IS the legacy output.
    if assets.is_empty() && out.validator_hash == legacy_p2pkh_validator_hash() {
        if let Val::Bytes(pkh) = &out.datum {
            if pkh.len() == LEGACY_P2PKH_LEN {
                return Ok(TxOutput { value: blch_amount, script_pubkey: pkh.clone() });
            }
        }
    }

    let script_pubkey = encode_eutxo_script(&EutxoScript {
        validator_hash: out.validator_hash,
        datum: out.datum.clone(),
        assets,
    })?;
    Ok(TxOutput { value: blch_amount, script_pubkey })
}

/// Decode a node [`TxOutput`] into the VM's [`ExtOutput`]. Strict and total
/// over the two valid script classes:
/// - exactly 20 bytes → legacy P2PKH: validator = [`legacy_p2pkh_validator`],
///   datum = the 20-byte hash, value = BLCH only;
/// - valid tagged script → explicit `validator_hash`/`datum`, value = script
///   assets + `TxOutput.value` BLCH.
///
/// Anything else is a typed error (fail-closed): a malformed script does not
/// silently map to an unspendable-but-accepted output.
pub fn decode_output(o: &TxOutput) -> Result<ExtOutput, EuMapError> {
    if is_legacy_p2pkh_script(&o.script_pubkey) {
        return Ok(ExtOutput {
            value: blch(o.value),
            validator_hash: legacy_p2pkh_validator_hash(),
            datum: Val::Bytes(o.script_pubkey.clone()),
        });
    }
    if o.script_pubkey.first() != Some(&EUTXO_SCRIPT_TAG) {
        // Not legacy, not tagged: invalid by length/shape.
        return Err(EuMapError::BadScriptLength { len: o.script_pubkey.len() });
    }
    let s = decode_eutxo_script(&o.script_pubkey)?;
    let mut value = s.assets;
    if o.value > 0 {
        value.insert(BLCH, o.value);
    }
    Ok(ExtOutput { value, validator_hash: s.validator_hash, datum: s.datum })
}

// ── Legacy P2PKH as the trivial validator ─────────────────────────────────────

/// `SHA3-256(pubkey)[..20]` — the node's exact address/output hash (the same
/// rule `main.rs` enforces on the live spend path and the wallet uses to derive
/// addresses).
pub fn legacy_pubkey_hash(pubkey: &[u8]) -> [u8; 20] {
    let d = Sha3_256::digest(pubkey);
    let mut out = [0u8; 20];
    out.copy_from_slice(&d[..20]);
    out
}

/// The trivial eUTXO validator every legacy P2PKH output maps to: verify
/// exactly one PQ signature (hybrid ML-DSA-65 ‖ Falcon-1024, via
/// [`NodePqVerifier`]) over the input's own sighash (`ctx.fields[0]`).
///
/// Stack model: `spend` seeds `[datum(pkh), pubkey, sig]` (redeemer =
/// `[pubkey, sig]`, top = sig). The program pushes the sighash and `Pick`s
/// copies of pubkey and sig above it, then `VerifySig` leaves the boolean
/// result on top.
///
/// **Division of labour (mirrors the node's live rule):** the VM checks the
/// SIGNATURE; the PUBKEY-HASH binding (`SHA3-256(pubkey)[..20] == datum`) is
/// enforced HOST-SIDE by [`map_tx_to_eutx`] ([`EuMapError::PubkeyHashMismatch`],
/// fail-closed) because the foundation VM has no SHA3-256/20 opcode. Together
/// they are exactly `main.rs`'s legacy spend check, so the old model is a
/// strict subset. Once a `Sha3_20` opcode lands in `bloch-euvm`, the hash check
/// moves in-program and this becomes a new validator (new hash — a
/// consensus-visible change to coordinate).
pub fn legacy_p2pkh_validator() -> Vec<Op> {
    vec![
        // stack: [datum(pkh), pubkey, sig]
        Op::CtxField(0), // -> [datum, pubkey, sig, msg]
        Op::Pick(2),     // copy pubkey -> [datum, pubkey, sig, msg, pubkey]
        Op::Pick(2),     // copy sig    -> [datum, pubkey, sig, msg, pubkey, sig]
        Op::VerifySig,   // pops sig,pubkey,msg -> [datum, pubkey, sig, result]
    ]
}

/// `bloch_euvm::validator_hash` of [`legacy_p2pkh_validator`] — the
/// `validator_hash` every legacy 20-byte output decodes to.
pub fn legacy_p2pkh_validator_hash() -> [u8; 32] {
    validator_hash(&legacy_p2pkh_validator())
}

// ── Transaction → EuTx mapping ────────────────────────────────────────────────

/// The revealed spend authorization for one CONTRACT (tagged) input: the
/// validator program (must hash to the prevout's `validator_hash` — enforced by
/// `bloch_euvm::spend`, `VmError::ValidatorHashMismatch`) and its redeemer
/// values. How witnesses travel on the wire (script_sig encoding, RPC field,
/// ...) is the hook/RPC layer's contract — this adapter only consumes them.
#[derive(Clone, Debug)]
pub struct EuWitness {
    /// The revealed validator program guarding the spent output.
    pub validator: Vec<Op>,
    /// Redeemer values pushed above the datum (bottom → top).
    pub redeemer: Vec<Val>,
}

// ── CANONICAL witness wire codec (D2 owns this; D3/D5 reference it) ───────────
//
// Witnesses travel in the EXISTING `TxInput.script_sig` — no tx/block struct or
// serialization change. Parsing is driven by the spent PREVOUT's script type:
//
// - prevout is legacy 20-byte P2PKH → `script_sig` keeps the existing legacy
//   `sig ‖ pubkey` format; the witness slot is `None` (the adapter's
//   [`map_tx_to_eutx`] handles legacy inputs itself).
// - prevout [`is_eutxo_script`] → `script_sig` is:
//
//   ```text
//   u32 LE (validator_bytes length)
//   ‖ validator_bytes                  — bloch_euvm::encode_program(&validator)
//   ‖ u32 LE (redeemer_count)
//   ‖ redeemer_count × Val             — EXACTLY the datum codec (encode_val):
//                                        Int → 0x00 ‖ i128 LE[16]
//                                        Bytes → 0x01 ‖ u32 LE len ‖ bytes
//   ```
//
// Decode is STRICT: typed [`EuMapError`]s, the whole `script_sig` must be
// consumed, unknown tags rejected, never panics, no allocation driven by
// untrusted counts. `encode_input_witness(decode_input_witness(b)) == b` for
// every accepted byte string.

/// Maximum bytes of a single input witness (`script_sig`) the codec will
/// decode. Mirrors the node's transaction-decode cap (`core::Transaction`
/// deserialization rejects `script_sig` longer than 10 000 bytes), so nothing
/// this codec accepts can be unserializable on the wire — and a hostile
/// in-memory buffer cannot drive unbounded work.
pub const MAX_WITNESS_BYTES: usize = 10_000;

/// Strict inverse of `bloch_euvm::encode_program`: decode a validator program
/// from its canonical byte encoding. Unknown op tags and truncated operands
/// are typed errors; for every accepted byte string,
/// `bloch_euvm::encode_program(&decode_program(b)?) == b` byte-exact.
///
/// The tag map is pinned to `encode_program`'s (that match is exhaustive over
/// `Op` with no wildcard, so a new opcode in `bloch-euvm` breaks ITS compile
/// first and this decoder must be extended consciously — never silently).
pub fn decode_program(bytes: &[u8]) -> Result<Vec<Op>, EuMapError> {
    let mut pos: usize = 0;
    let mut ops = Vec::new(); // ≥ 1 byte per op ⇒ ops.len() ≤ bytes.len(): bounded
    while pos < bytes.len() {
        let tag = take(bytes, &mut pos, 1)?[0];
        let op = match tag {
            0x01 => {
                let raw: [u8; 16] =
                    take(bytes, &mut pos, 16)?.try_into().expect("slice is 16 bytes");
                Op::PushInt(i128::from_le_bytes(raw))
            }
            0x02 => {
                let raw: [u8; 4] =
                    take(bytes, &mut pos, 4)?.try_into().expect("slice is 4 bytes");
                let len = u32::from_le_bytes(raw) as usize;
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
            t => return Err(EuMapError::BadOpTag(t)),
        };
        ops.push(op);
    }
    Ok(ops)
}

/// Encode an [`EuWitness`] into the pinned `script_sig` wire format (the
/// inverse of [`decode_input_witness`]; D5 uses this to build contract
/// spends). Infallible: any witness encodes; one exceeding
/// [`MAX_WITNESS_BYTES`] simply produces a `script_sig` the node's tx wire
/// codec (and this codec's decoder) will reject.
pub fn encode_input_witness(w: &EuWitness) -> Vec<u8> {
    let vb = bloch_euvm::encode_program(&w.validator);
    let mut out = Vec::with_capacity(8 + vb.len());
    out.extend_from_slice(&(vb.len() as u32).to_le_bytes());
    out.extend_from_slice(&vb);
    out.extend_from_slice(&(w.redeemer.len() as u32).to_le_bytes());
    for v in &w.redeemer {
        encode_val(v, &mut out);
    }
    out
}

/// Strictly decode ONE input witness from raw `script_sig` bytes per the
/// pinned wire format. Typed errors, never panics, whole buffer must be
/// consumed. Callers normally go through [`decode_input_witnesses`], which
/// applies the prevout-type dispatch and adds the input index to errors.
pub fn decode_input_witness(script_sig: &[u8]) -> Result<EuWitness, EuMapError> {
    if script_sig.len() > MAX_WITNESS_BYTES {
        return Err(EuMapError::WitnessTooLong { len: script_sig.len() });
    }
    let mut pos: usize = 0;
    let raw: [u8; 4] = take(script_sig, &mut pos, 4)?.try_into().expect("slice is 4 bytes");
    let vlen = u32::from_le_bytes(raw) as usize;
    let validator = decode_program(take(script_sig, &mut pos, vlen)?)?;
    let raw: [u8; 4] = take(script_sig, &mut pos, 4)?.try_into().expect("slice is 4 bytes");
    let rcount = u32::from_le_bytes(raw) as usize;
    // Each Val is ≥ 1 byte, so a hostile rcount can only fail with Truncated —
    // and we never pre-allocate from it.
    let mut redeemer = Vec::new();
    for _ in 0..rcount {
        redeemer.push(decode_val(script_sig, &mut pos)?);
    }
    if pos != script_sig.len() {
        return Err(EuMapError::TrailingBytes { extra: script_sig.len() - pos });
    }
    Ok(EuWitness { validator, redeemer })
}

/// THE canonical per-input witness extraction for a whole transaction —
/// exactly what the accept_block hook feeds to [`validate_node_tx`] /
/// [`validate_node_block`], and the reference D3 (miner mirror) and D5 (RPC)
/// must match. Per input `i`:
///
/// - `prevouts[i]` legacy P2PKH (or anything not [`is_eutxo_script`]) →
///   `None` — the input's `script_sig` stays in the legacy `sig ‖ pubkey`
///   format and is handled by the adapter's legacy arm. A malformed prevout
///   script is NOT this codec's concern: [`map_tx_to_eutx`]'s strict
///   [`decode_output`] rejects it fail-closed.
/// - `prevouts[i]` tagged eUTXO → `Some(`[`decode_input_witness`]` of its
///   script_sig)`, errors wrapped with the input index
///   ([`EuMapError::WitnessDecode`]).
pub fn decode_input_witnesses(
    tx: &Transaction,
    prevouts: &[TxOutput],
) -> Result<Vec<Option<EuWitness>>, EuMapError> {
    if prevouts.len() != tx.inputs.len() {
        return Err(EuMapError::PrevoutCountMismatch {
            inputs: tx.inputs.len(),
            prevouts: prevouts.len(),
        });
    }
    tx.inputs
        .iter()
        .zip(prevouts)
        .enumerate()
        .map(|(i, (inp, prev))| {
            if is_eutxo_script(&prev.script_pubkey) {
                decode_input_witness(&inp.script_sig)
                    .map(Some)
                    .map_err(|e| EuMapError::WitnessDecode { input: i, source: Box::new(e) })
            } else {
                Ok(None)
            }
        })
        .collect()
}

/// Map a node [`Transaction`] to a [`bloch_euvm::EuTx`] for VM validation.
///
/// - `prevouts[i]` is the node `TxOutput` spent by input `i` (from the UTXO
///   store); count must match.
/// - `witnesses` is empty (all-legacy tx) or one `Option<EuWitness>` per input:
///   `Some` REQUIRED for tagged (contract) prevouts, FORBIDDEN for legacy ones.
/// - Legacy P2PKH inputs are auto-mapped: `(sig, pubkey)` parsed from
///   `script_sig`, host-side `SHA3-256(pubkey)[..20]` binding checked against
///   the prevout (fail-closed), validator = [`legacy_p2pkh_validator`],
///   redeemer = `[Bytes(pubkey), Bytes(sig)]`.
/// - `fee` = BLCH inputs − BLCH outputs (checked; negative → error). Non-BLCH
///   conservation is [`validate_node_tx`]'s job, not the mapper's.
/// - Coinbase and zero-input transactions do not map (typed errors).
///
/// **Sighash caveat:** `EuTx.sighash` is set to input 0's
/// `tx.sighash(0, chain_id)`. The node's sighash is PER-INPUT, so
/// `bloch_euvm::validate_tx` (which shows one sighash to every validator) is
/// only sound for single-input transactions. Consensus-path validation MUST use
/// [`validate_node_tx`], which builds each input its own ctx.
pub fn map_tx_to_eutx(
    tx: &Transaction,
    prevouts: &[TxOutput],
    witnesses: &[Option<EuWitness>],
    chain_id: ChainId,
) -> Result<EuTx, EuMapError> {
    if tx.is_coinbase() {
        return Err(EuMapError::CoinbaseNotMappable);
    }
    if tx.inputs.is_empty() {
        return Err(EuMapError::NoInputs);
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(EuMapError::PrevoutCountMismatch {
            inputs: tx.inputs.len(),
            prevouts: prevouts.len(),
        });
    }
    if !witnesses.is_empty() && witnesses.len() != tx.inputs.len() {
        return Err(EuMapError::WitnessCountMismatch {
            inputs: tx.inputs.len(),
            witnesses: witnesses.len(),
        });
    }

    let outputs: Vec<ExtOutput> =
        tx.outputs.iter().map(decode_output).collect::<Result<_, _>>()?;

    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for (i, (inp, prevout)) in tx.inputs.iter().zip(prevouts).enumerate() {
        let prev = decode_output(prevout)?;
        let witness = witnesses.get(i).and_then(|w| w.as_ref());
        let (validator, redeemer) = if is_legacy_p2pkh_script(&prevout.script_pubkey) {
            if witness.is_some() {
                return Err(EuMapError::UnexpectedWitness { input: i });
            }
            let (sig, pk) = Transaction::parse_script_sig(&inp.script_sig)
                .ok_or(EuMapError::BadScriptSig { input: i })?;
            // Host-side half of the P2PKH check (see legacy_p2pkh_validator).
            if legacy_pubkey_hash(&pk)[..] != prevout.script_pubkey[..] {
                return Err(EuMapError::PubkeyHashMismatch { input: i });
            }
            (legacy_p2pkh_validator(), vec![Val::Bytes(pk), Val::Bytes(sig)])
        } else {
            let w = witness.ok_or(EuMapError::MissingWitness { input: i })?;
            (w.validator.clone(), w.redeemer.clone())
        };
        inputs.push(EuTxInput { prev_output: prev, validator, redeemer });
    }

    // fee = BLCH in − BLCH out, checked (u128 sums cannot overflow: ≤ 2^10
    // entries of u64). Non-BLCH balances are validation's concern.
    let in_blch: u128 = inputs.iter().map(|i| value_get(&i.prev_output.value, &BLCH) as u128).sum();
    let out_blch: u128 = outputs.iter().map(|o| value_get(&o.value, &BLCH) as u128).sum();
    if out_blch > in_blch {
        return Err(EuMapError::FeeUnderflow { in_blch, out_blch });
    }
    let fee = u64::try_from(in_blch - out_blch).map_err(|_| EuMapError::FeeOverflow)?;

    Ok(EuTx { inputs, outputs, fee, sighash: tx.sighash(0, chain_id).to_vec() })
}

/// Build the VM [`Ctx`](EuCtx) for spending `input_index` of `tx`: that input's
/// own sighash in `fields[0]` (what a signature-checking validator verifies —
/// per-input, exactly like the node's live rule) and every created output
/// strictly decoded into `tx_outputs` (so a contract can constrain what the tx
/// produces — continuation, AMM invariants). `self_validator_hash`/`self_value`
/// are filled per-input by `bloch_euvm::spend`.
pub fn build_ctx(tx: &Transaction, input_index: usize, chain_id: ChainId) -> Result<EuCtx, EuMapError> {
    if input_index >= tx.inputs.len() {
        // tx.sighash silently produces a marker-less digest for an out-of-range
        // index — never let that become a verifiable message.
        return Err(EuMapError::BadInputIndex { index: input_index, len: tx.inputs.len() });
    }
    let tx_outputs: Vec<ExtOutput> =
        tx.outputs.iter().map(decode_output).collect::<Result<_, _>>()?;
    Ok(EuCtx {
        fields: vec![Val::Bytes(tx.sighash(input_index, chain_id).to_vec())],
        tx_outputs,
        self_validator_hash: [0u8; 32],
        self_value: Value::new(),
    })
}

// ── Validation (the shape of the future accept_block hook) ────────────────────

/// Typed error for tx/block-level eUTXO validation of node transactions.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EuvmTxError {
    /// The transaction failed to map (codec, witness, script_sig, pkh binding,
    /// fee underflow, ...).
    Map(EuMapError),
    /// A `bloch_euvm` structural resource ceiling fired (F2, fail-closed).
    Resource(&'static str),
    /// A non-BLCH asset does not balance exactly across the transaction.
    ValueNotConserved { asset: AssetId, in_sum: u128, out_sum: u128 },
    /// Input `i`'s validator ran to completion and returned false.
    ValidatorRejected(usize),
    /// Input `i`'s validator aborted (gas, type error, hash mismatch, ...).
    Vm(usize, VmError),
    /// The block resolver could not supply prevouts/witnesses for this tx.
    UnresolvedPrevouts,
    /// The block-wide gas ceiling was exceeded.
    OutOfBlockGas,
}

impl From<EuMapError> for EuvmTxError {
    fn from(e: EuMapError) -> Self {
        EuvmTxError::Map(e)
    }
}

impl std::fmt::Display for EuvmTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use EuvmTxError::*;
        match self {
            Map(e) => write!(f, "mapping failed: {e}"),
            Resource(what) => write!(f, "resource ceiling: {what}"),
            ValueNotConserved { asset, in_sum, out_sum } => write!(
                f,
                "asset {} not conserved: in {in_sum}, out {out_sum}",
                hex::encode(asset)
            ),
            ValidatorRejected(i) => write!(f, "input {i}: validator rejected the spend"),
            Vm(i, e) => write!(f, "input {i}: vm error {e:?}"),
            UnresolvedPrevouts => write!(f, "prevouts/witnesses unresolved"),
            OutOfBlockGas => write!(f, "block gas ceiling exceeded"),
        }
    }
}

impl std::error::Error for EuvmTxError {}

/// Validate one node transaction through the eUTXO model — the canonical
/// tx-level entrypoint the hook (D2) and miner-mirror (D3) call. Pure: no
/// consensus side effects; prevouts come from the caller's UTXO view.
///
/// Enforced, in order (all fail-closed):
/// 1. **Mapping** ([`map_tx_to_eutx`]): strict output/script decode, witness
///    discipline, legacy `script_sig` parse + host-side pubkey-hash binding,
///    non-negative BLCH fee.
/// 2. **Structural resource ceilings** (`bloch_euvm::check_tx_resource_limits`,
///    the F2 DoS bounds) BEFORE any unmetered work.
/// 3. **Per-asset conservation**: BLCH via the fee (step 1); every other asset
///    must balance exactly (no mint/burn without a policy).
/// 4. **Every input's validator**, each with ITS OWN sighash
///    (`tx.sighash(i, chain_id)` in `ctx.fields[0]`) and the whole tx's decoded
///    outputs visible, through the REAL PQ verifier ([`NodePqVerifier`]),
///    sharing one `gas_limit` budget.
///
/// Returns gas used.
pub fn validate_node_tx(
    tx: &Transaction,
    prevouts: &[TxOutput],
    witnesses: &[Option<EuWitness>],
    chain_id: ChainId,
    gas_limit: u64,
) -> Result<u64, EuvmTxError> {
    // (1) map — strict, typed, fail-closed.
    let eutx = map_tx_to_eutx(tx, prevouts, witnesses, chain_id)?;

    // (2) F2 structural ceilings before any unmetered scan.
    if let Err(e) = bloch_euvm::check_tx_resource_limits(&eutx) {
        return Err(match e {
            TxError::ResourceLimit { what } => EuvmTxError::Resource(what),
            // check_tx_resource_limits only returns ResourceLimit; stay
            // fail-closed if that ever changes.
            _ => EuvmTxError::Resource("transaction resource limits"),
        });
    }

    // (3) non-BLCH assets must balance exactly (BLCH fee already checked ≥ 0
    // by the mapper; the miner keeps the difference per the fee model).
    {
        let mut assets: std::collections::BTreeSet<AssetId> = std::collections::BTreeSet::new();
        for i in &eutx.inputs {
            assets.extend(i.prev_output.value.keys().copied());
        }
        for o in &eutx.outputs {
            assets.extend(o.value.keys().copied());
        }
        for asset in assets {
            if asset == BLCH {
                continue;
            }
            let in_sum: u128 =
                eutx.inputs.iter().map(|i| value_get(&i.prev_output.value, &asset) as u128).sum();
            let out_sum: u128 =
                eutx.outputs.iter().map(|o| value_get(&o.value, &asset) as u128).sum();
            if in_sum != out_sum {
                return Err(EuvmTxError::ValueNotConserved { asset, in_sum, out_sum });
            }
        }
    }

    // (4) every input's validator, per-input sighash, shared gas budget.
    let mut gas = gas_limit;
    for (i, inp) in eutx.inputs.iter().enumerate() {
        let ctx = EuCtx {
            fields: vec![Val::Bytes(tx.sighash(i, chain_id).to_vec())],
            tx_outputs: eutx.outputs.clone(),
            self_validator_hash: [0u8; 32], // spend() sets these per-input
            self_value: Value::new(),
        };
        match bloch_euvm::spend(
            &inp.prev_output,
            &inp.validator,
            inp.redeemer.clone(),
            &ctx,
            &NodePqVerifier,
            &mut gas,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(EuvmTxError::ValidatorRejected(i)),
            Err(e) => return Err(EuvmTxError::Vm(i, e)),
        }
    }
    Ok(gas_limit - gas)
}

/// Validate a block's transactions under a per-tx and a block-wide gas ceiling
/// (the block-level DoS bound). Coinbase transactions are SKIPPED (they spend
/// nothing; coinbase amount/maturity policy stays with the hook). For every
/// other tx, `resolve(tx_index, tx)` supplies its prevouts and witnesses
/// (`None` → [`EuvmTxError::UnresolvedPrevouts`], fail-closed). Returns total
/// gas used; errors carry the offending tx index.
pub fn validate_node_block<F>(
    txs: &[Transaction],
    chain_id: ChainId,
    mut resolve: F,
    per_tx_gas: u64,
    block_gas: u64,
) -> Result<u64, (usize, EuvmTxError)>
where
    F: FnMut(usize, &Transaction) -> Option<(Vec<TxOutput>, Vec<Option<EuWitness>>)>,
{
    let mut total: u64 = 0;
    for (ti, tx) in txs.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        let (prevouts, witnesses) =
            resolve(ti, tx).ok_or((ti, EuvmTxError::UnresolvedPrevouts))?;
        let used = validate_node_tx(tx, &prevouts, &witnesses, chain_id, per_tx_gas)
            .map_err(|e| (ti, e))?;
        total = total.checked_add(used).ok_or((ti, EuvmTxError::OutOfBlockGas))?;
        if total > block_gas {
            return Err((ti, EuvmTxError::OutOfBlockGas));
        }
    }
    Ok(total)
}

// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::core::{Transaction as NodeTx, TxInput, TxOutput as NodeOut};
    use std::sync::OnceLock;

    const CHAIN: ChainId = ChainId::Genesis2Devnet;

    /// One shared real hybrid ML-DSA-65 ‖ Falcon-1024 keypair (keygen is
    /// expensive in debug builds — generate once per test binary).
    fn kp() -> &'static (Vec<u8>, Vec<u8>) {
        static K: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        K.get_or_init(bloch_crypto::crypto::generate_keypair)
    }

    fn mk_input(prev_txid: [u8; 32]) -> TxInput {
        TxInput { prev_txid, prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff }
    }

    /// A 1-input legacy tx really signed by `kp()`, plus its prevout
    /// (`in_value` BLCH locked to the key's pubkey hash).
    fn legacy_signed_tx(in_value: u64, out_value: u64) -> (NodeTx, Vec<NodeOut>) {
        let (pk, sk) = kp();
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![mk_input([1u8; 32])],
            outputs: vec![NodeOut { value: out_value, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        let sighash = tx.sighash(0, CHAIN);
        let sig = bloch_crypto::crypto::sign(sk, &sighash).expect("sign");
        tx.inputs[0].script_sig = NodeTx::build_script_sig(&sig, pk);
        let prevout = NodeOut { value: in_value, script_pubkey: legacy_pubkey_hash(pk).to_vec() };
        (tx, vec![prevout])
    }

    fn asset(b: u8) -> AssetId {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    }

    fn val(pairs: &[(AssetId, u64)]) -> Value {
        pairs.iter().cloned().collect()
    }

    // ── activation gate (D4's; behaviour must not change) ──

    /// The height gate is CLOSED by default: an unpinned test process defaults
    /// to ChainId::Mainnet, whose activation height is the u64::MAX inert
    /// sentinel — no height activates the VM. (The Genesis3Mainnet => 0 arm
    /// can't also be asserted here: the process chain-id is a set-once
    /// OnceLock shared across tests in this binary.)
    #[test]
    fn activation_gate_defaults_closed() {
        assert_eq!(euvm_activation_height(), u64::MAX,
            "non-G3 chains must keep the inert sentinel");
        assert!(!euvm_active(0));
        assert!(!euvm_active(1_000_000));
        assert!(!euvm_active(u64::MAX - 1));
    }

    // ── tagged-output codec ──

    #[test]
    fn eutxo_script_codec_round_trip() {
        let cases = vec![
            EutxoScript { validator_hash: [7u8; 32], datum: Val::Int(0), assets: Value::new() },
            EutxoScript { validator_hash: [0u8; 32], datum: Val::Int(-5), assets: Value::new() },
            EutxoScript { validator_hash: [7u8; 32], datum: Val::Bytes(vec![]), assets: Value::new() },
            EutxoScript {
                validator_hash: [9u8; 32],
                datum: Val::Bytes(b"hello datum".to_vec()),
                assets: val(&[(asset(1), 1)]),
            },
            EutxoScript {
                validator_hash: [0xffu8; 32],
                datum: Val::Int(i128::MIN),
                assets: val(&[(asset(1), 5), (asset(2), u64::MAX), (asset(0x80), 77)]),
            },
        ];
        for s in cases {
            let enc = encode_eutxo_script(&s).expect("encode");
            assert!(is_eutxo_script(&enc), "encoded script must self-identify: {s:?}");
            assert!(!is_legacy_p2pkh_script(&enc));
            let dec = decode_eutxo_script(&enc).expect("decode");
            assert_eq!(dec, s, "struct round-trip");
            // byte-exact round trip
            assert_eq!(encode_eutxo_script(&dec).expect("re-encode"), enc, "byte round-trip");
        }
        // the shortest possible script is exactly EUTXO_SCRIPT_MIN_LEN
        let shortest = encode_eutxo_script(&EutxoScript {
            validator_hash: [0u8; 32],
            datum: Val::Bytes(vec![]),
            assets: Value::new(),
        })
        .expect("encode");
        assert_eq!(shortest.len(), EUTXO_SCRIPT_MIN_LEN);
    }

    #[test]
    fn eutxo_script_strict_decode_rejects() {
        let good = encode_eutxo_script(&EutxoScript {
            validator_hash: [3u8; 32],
            datum: Val::Bytes(b"d".to_vec()),
            assets: val(&[(asset(1), 4), (asset(2), 9)]),
        })
        .expect("encode");

        // every strict prefix is rejected (truncation), never panics
        for cut in 0..good.len() {
            assert!(decode_eutxo_script(&good[..cut]).is_err(), "prefix of {cut} bytes must fail");
        }
        // trailing garbage rejected
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(decode_eutxo_script(&trailing), Err(EuMapError::TrailingBytes { extra: 1 }));
        // wrong first byte
        let mut untagged = good.clone();
        untagged[0] = 0x00;
        assert_eq!(decode_eutxo_script(&untagged), Err(EuMapError::NotTagged));
        // unknown datum tag
        let mut bad_datum = good.clone();
        bad_datum[33] = 0x02;
        assert_eq!(decode_eutxo_script(&bad_datum), Err(EuMapError::BadDatumTag(0x02)));

        // hand-built asset-table violations: tag ‖ vh ‖ Int datum ‖ count=2 ‖ entries
        let build = |entries: &[(AssetId, u64)]| -> Vec<u8> {
            let mut v = vec![EUTXO_SCRIPT_TAG];
            v.extend_from_slice(&[3u8; 32]);
            v.push(0x00);
            v.extend_from_slice(&0i128.to_le_bytes());
            v.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            for (id, amt) in entries {
                v.extend_from_slice(id);
                v.extend_from_slice(&amt.to_le_bytes());
            }
            v
        };
        assert_eq!(
            decode_eutxo_script(&build(&[(asset(2), 1), (asset(1), 1)])),
            Err(EuMapError::AssetOutOfOrder),
            "unsorted"
        );
        assert_eq!(
            decode_eutxo_script(&build(&[(asset(1), 1), (asset(1), 2)])),
            Err(EuMapError::AssetOutOfOrder),
            "duplicate"
        );
        assert_eq!(
            decode_eutxo_script(&build(&[(asset(1), 0)])),
            Err(EuMapError::ZeroAssetAmount)
        );
        assert_eq!(decode_eutxo_script(&build(&[(BLCH, 5)])), Err(EuMapError::BlchInAssetTable));

        // oversize script rejected on both sides
        let huge = EutxoScript {
            validator_hash: [0u8; 32],
            datum: Val::Bytes(vec![0u8; MAX_SCRIPT_PUBKEY_LEN]),
            assets: Value::new(),
        };
        assert!(matches!(encode_eutxo_script(&huge), Err(EuMapError::ScriptTooLong { .. })));
        assert!(matches!(
            decode_eutxo_script(&vec![EUTXO_SCRIPT_TAG; MAX_SCRIPT_PUBKEY_LEN + 1]),
            Err(EuMapError::ScriptTooLong { .. })
        ));

        // encode strictness: BLCH / zero entries are caller errors at script level
        let blch_in = EutxoScript {
            validator_hash: [0u8; 32],
            datum: Val::Int(0),
            assets: val(&[(BLCH, 5)]),
        };
        assert_eq!(encode_eutxo_script(&blch_in), Err(EuMapError::BlchInAssetTable));
        let zero_in = EutxoScript {
            validator_hash: [0u8; 32],
            datum: Val::Int(0),
            assets: val(&[(asset(1), 0)]),
        };
        assert_eq!(encode_eutxo_script(&zero_in), Err(EuMapError::ZeroAssetAmount));

        // decode never panics on arbitrary bytes (deterministic mini-corpus)
        for len in 0..64usize {
            let junk: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(0xE0)).collect();
            let _ = decode_eutxo_script(&junk); // must return, not panic
        }
    }

    #[test]
    fn legacy_vs_eutxo_non_collision() {
        // static guarantee: the two classes are length-disjoint
        assert!(EUTXO_SCRIPT_MIN_LEN > LEGACY_P2PKH_LEN);

        // a REAL pubkey hash is always legacy, never eUTXO
        let (pk, _) = kp();
        let pkh = legacy_pubkey_hash(pk).to_vec();
        assert!(is_legacy_p2pkh_script(&pkh));
        assert!(!is_eutxo_script(&pkh));

        // a 20-byte hash that HAPPENS to start with the tag byte is still legacy
        let mut adversarial = vec![EUTXO_SCRIPT_TAG];
        adversarial.extend_from_slice(&[0xABu8; 19]);
        assert!(is_legacy_p2pkh_script(&adversarial));
        assert!(!is_eutxo_script(&adversarial));
        let decoded = decode_output(&NodeOut { value: 7, script_pubkey: adversarial.clone() })
            .expect("legacy decode");
        assert_eq!(decoded.validator_hash, legacy_p2pkh_validator_hash());
        assert_eq!(decoded.datum, Val::Bytes(adversarial));

        // a valid tagged script is never mistaken for legacy
        let tagged = encode_eutxo_script(&EutxoScript {
            validator_hash: [1u8; 32],
            datum: Val::Int(0),
            assets: Value::new(),
        })
        .expect("encode");
        assert!(is_eutxo_script(&tagged));
        assert!(!is_legacy_p2pkh_script(&tagged));

        // in-between lengths are neither — and decode fails closed
        for bad_len in [0usize, 1, 19, 21, 33, EUTXO_SCRIPT_MIN_LEN - 1] {
            let spk = vec![0x11u8; bad_len];
            assert!(!is_legacy_p2pkh_script(&spk) || bad_len == 20);
            assert!(!is_eutxo_script(&spk));
            if bad_len != 20 {
                assert!(
                    decode_output(&NodeOut { value: 1, script_pubkey: spk }).is_err(),
                    "len {bad_len} must not decode"
                );
            }
        }
    }

    #[test]
    fn output_codec_round_trip() {
        // legacy-shaped ExtOutput ↔ 20-byte script (canonical arm)
        let (pk, _) = kp();
        let pkh = legacy_pubkey_hash(pk);
        let legacy = ExtOutput {
            value: blch(500),
            validator_hash: legacy_p2pkh_validator_hash(),
            datum: Val::Bytes(pkh.to_vec()),
        };
        let node_out = encode_output(&legacy).expect("encode legacy");
        assert_eq!(node_out.value, 500);
        assert_eq!(node_out.script_pubkey, pkh.to_vec(), "canonical legacy form is the bare hash");
        assert_eq!(decode_output(&node_out).expect("decode"), legacy);

        // contract output with native assets + BLCH ↔ tagged script
        let contract = ExtOutput {
            value: val(&[(BLCH, 42), (asset(1), 7)]),
            validator_hash: [3u8; 32],
            datum: Val::Int(41),
        };
        let node_out = encode_output(&contract).expect("encode contract");
        assert_eq!(node_out.value, 42, "BLCH rides in TxOutput.value");
        assert!(is_eutxo_script(&node_out.script_pubkey));
        assert_eq!(decode_output(&node_out).expect("decode"), contract);

        // zero-BLCH contract output (asset-only) round-trips too
        let asset_only = ExtOutput {
            value: val(&[(asset(2), 9)]),
            validator_hash: [4u8; 32],
            datum: Val::Bytes(vec![1, 2, 3]),
        };
        let node_out = encode_output(&asset_only).expect("encode");
        assert_eq!(node_out.value, 0);
        assert_eq!(decode_output(&node_out).expect("decode"), asset_only);
    }

    // ── transaction mapping ──

    #[test]
    fn map_tx_to_eutx_legacy_correctness() {
        let (pk, _) = kp();
        let (tx, prevouts) = legacy_signed_tx(100, 90);
        let eutx = map_tx_to_eutx(&tx, &prevouts, &[], CHAIN).expect("map");

        assert_eq!(eutx.inputs.len(), 1);
        assert_eq!(eutx.outputs.len(), 1);
        assert_eq!(eutx.fee, 10, "fee = BLCH in − BLCH out");
        assert_eq!(eutx.sighash, tx.sighash(0, CHAIN).to_vec());

        let inp = &eutx.inputs[0];
        assert_eq!(inp.prev_output.value, blch(100));
        assert_eq!(inp.prev_output.validator_hash, legacy_p2pkh_validator_hash());
        assert_eq!(inp.prev_output.datum, Val::Bytes(legacy_pubkey_hash(pk).to_vec()));
        assert_eq!(validator_hash(&inp.validator), legacy_p2pkh_validator_hash());
        // redeemer = [pubkey, sig] exactly as parsed from script_sig
        let (sig, rpk) = NodeTx::parse_script_sig(&tx.inputs[0].script_sig).expect("parse");
        assert_eq!(inp.redeemer, vec![Val::Bytes(rpk), Val::Bytes(sig)]);
        assert_eq!(eutx.outputs[0].value, blch(90));
    }

    #[test]
    fn map_tx_to_eutx_typed_failures() {
        let (tx, prevouts) = legacy_signed_tx(100, 90);

        // prevout count mismatch
        assert_eq!(
            map_tx_to_eutx(&tx, &[], &[], CHAIN).unwrap_err(),
            EuMapError::PrevoutCountMismatch { inputs: 1, prevouts: 0 }
        );
        // witness count mismatch
        let w = Some(EuWitness { validator: vec![Op::PushInt(1)], redeemer: vec![] });
        assert_eq!(
            map_tx_to_eutx(&tx, &prevouts, &[w.clone(), w.clone()], CHAIN).unwrap_err(),
            EuMapError::WitnessCountMismatch { inputs: 1, witnesses: 2 }
        );
        // witness on a legacy input is a protocol error
        assert_eq!(
            map_tx_to_eutx(&tx, &prevouts, &[w], CHAIN).unwrap_err(),
            EuMapError::UnexpectedWitness { input: 0 }
        );
        // pubkey-hash binding: prevout locked to a DIFFERENT hash → fail closed
        let alien = vec![NodeOut { value: 100, script_pubkey: vec![0x33u8; 20] }];
        assert_eq!(
            map_tx_to_eutx(&tx, &alien, &[], CHAIN).unwrap_err(),
            EuMapError::PubkeyHashMismatch { input: 0 }
        );
        // malformed script_sig
        let mut bad_ss = tx.clone();
        bad_ss.inputs[0].script_sig = vec![1, 2, 3];
        assert_eq!(
            map_tx_to_eutx(&bad_ss, &prevouts, &[], CHAIN).unwrap_err(),
            EuMapError::BadScriptSig { input: 0 }
        );
        // negative implied fee
        let (rich_tx, _) = legacy_signed_tx(100, 90);
        let poor_prev = vec![NodeOut { value: 80, script_pubkey: prevouts[0].script_pubkey.clone() }];
        assert_eq!(
            map_tx_to_eutx(&rich_tx, &poor_prev, &[], CHAIN).unwrap_err(),
            EuMapError::FeeUnderflow { in_blch: 80, out_blch: 90 }
        );
        // tagged prevout without a witness
        let tagged_prev = encode_output(&ExtOutput {
            value: blch(100),
            validator_hash: [9u8; 32],
            datum: Val::Int(0),
        })
        .expect("encode");
        assert_eq!(
            map_tx_to_eutx(&tx, &[tagged_prev], &[], CHAIN).unwrap_err(),
            EuMapError::MissingWitness { input: 0 }
        );
        // coinbase never maps
        let coinbase = NodeTx {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: u32::MAX,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![NodeOut { value: 8400, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        assert_eq!(
            map_tx_to_eutx(&coinbase, &[NodeOut { value: 0, script_pubkey: vec![0u8; 20] }], &[], CHAIN)
                .unwrap_err(),
            EuMapError::CoinbaseNotMappable
        );
    }

    #[test]
    fn build_ctx_exposes_per_input_sighash_and_outputs() {
        let (tx, _) = legacy_signed_tx(100, 90);
        let ctx = build_ctx(&tx, 0, CHAIN).expect("ctx");
        assert_eq!(ctx.fields[0], Val::Bytes(tx.sighash(0, CHAIN).to_vec()));
        assert_eq!(ctx.tx_outputs.len(), 1);
        assert_eq!(ctx.tx_outputs[0].value, blch(90));
        // deterministic
        assert_eq!(build_ctx(&tx, 0, CHAIN).expect("ctx").fields, ctx.fields);
        // out-of-range index fails closed (never a marker-less sighash)
        assert_eq!(
            build_ctx(&tx, 1, CHAIN).unwrap_err(),
            EuMapError::BadInputIndex { index: 1, len: 1 }
        );
    }

    // ── legacy spend ≡ the node's direct P2PKH check ──

    /// The adapter's legacy path (host pkh binding + in-VM PQ sig check) agrees
    /// with the node's live rule in main.rs (SHA3-256(pk)[..20] == spk, then
    /// crypto::verify(pk, sighash(i), sig)) on accept AND on both reject axes.
    #[test]
    fn legacy_as_validator_equals_direct_p2pkh_check() {
        let direct_check = |tx: &NodeTx, prevout: &NodeOut| -> bool {
            let Some((sig, pk)) = NodeTx::parse_script_sig(&tx.inputs[0].script_sig) else {
                return false;
            };
            if Sha3_256::digest(&pk)[..20] != prevout.script_pubkey[..] {
                return false;
            }
            bloch_crypto::crypto::verify(&pk, &tx.sighash(0, CHAIN), &sig)
        };

        // accept: both paths say yes
        let (tx, prevouts) = legacy_signed_tx(100, 90);
        assert!(direct_check(&tx, &prevouts[0]));
        let used = validate_node_tx(&tx, &prevouts, &[], CHAIN, 100_000).expect("valid spend");
        assert!(used > 0);

        // tampered signature: both paths say no (VM: validator returns false)
        let mut bad_sig = tx.clone();
        let l = bad_sig.inputs[0].script_sig.len();
        bad_sig.inputs[0].script_sig[l / 2] ^= 0xff;
        assert!(!direct_check(&bad_sig, &prevouts[0]));
        assert_eq!(
            validate_node_tx(&bad_sig, &prevouts, &[], CHAIN, 100_000),
            Err(EuvmTxError::ValidatorRejected(0))
        );

        // foreign prevout (hash binding): both paths say no (adapter: host-side)
        let foreign = vec![NodeOut { value: 100, script_pubkey: vec![0x44u8; 20] }];
        assert!(!direct_check(&tx, &foreign[0]));
        assert_eq!(
            validate_node_tx(&tx, &foreign, &[], CHAIN, 100_000),
            Err(EuvmTxError::Map(EuMapError::PubkeyHashMismatch { input: 0 }))
        );
    }

    /// Each input verifies ITS OWN sighash: reusing input 0's (valid) signature
    /// on input 1 of the same key must fail — the binding the single-sighash
    /// `bloch_euvm::validate_tx` cannot express.
    #[test]
    fn per_input_sighash_binding() {
        let (pk, sk) = kp();
        let pkh = legacy_pubkey_hash(pk).to_vec();
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![mk_input([1u8; 32]), mk_input([2u8; 32])],
            outputs: vec![NodeOut { value: 150, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        let prevouts = vec![
            NodeOut { value: 100, script_pubkey: pkh.clone() },
            NodeOut { value: 100, script_pubkey: pkh.clone() },
        ];
        // sighashes really differ per input
        assert_ne!(tx.sighash(0, CHAIN), tx.sighash(1, CHAIN));

        // properly signed (each input over its own sighash) → valid
        for i in 0..2 {
            let sig = bloch_crypto::crypto::sign(sk, &tx.sighash(i, CHAIN)).expect("sign");
            tx.inputs[i].script_sig = NodeTx::build_script_sig(&sig, pk);
        }
        assert!(validate_node_tx(&tx, &prevouts, &[], CHAIN, 200_000).is_ok());

        // splice input 0's script_sig into input 1 (same key → pkh still
        // matches) → input 1's validator sees the wrong message → reject
        let mut spliced = tx.clone();
        spliced.inputs[1].script_sig = tx.inputs[0].script_sig.clone();
        assert_eq!(
            validate_node_tx(&spliced, &prevouts, &[], CHAIN, 200_000),
            Err(EuvmTxError::ValidatorRejected(1))
        );
    }

    // ── contract (tagged) spends end-to-end ──

    /// A hash-locked contract output is spent through the full adapter path:
    /// tagged prevout codec, witness discipline, native-asset conservation and
    /// the VM run — with a legacy change output alongside.
    #[test]
    fn contract_spend_end_to_end() {
        use sha2::{Digest as _, Sha256};
        let preimage = b"the-secret-preimage".to_vec();
        let lock = Sha256::digest(Sha256::digest(&preimage)).to_vec();
        // hashlock validator: redeemer = [preimage]; datum below is ignored
        let hashlock = vec![Op::Sha256d, Op::PushBytes(lock), Op::Eq];
        let a = asset(1);

        let prev_ext = ExtOutput {
            value: val(&[(BLCH, 100), (a, 7)]),
            validator_hash: validator_hash(&hashlock),
            datum: Val::Int(0),
        };
        let prevout = encode_output(&prev_ext).expect("encode prevout");
        assert!(is_eutxo_script(&prevout.script_pubkey));

        // spend: 90 BLCH to a legacy address, asset A carried on by a new
        // contract output, 10 BLCH fee. No signature needed — hashlock.
        let carry = encode_output(&ExtOutput {
            value: val(&[(a, 7)]),
            validator_hash: [8u8; 32],
            datum: Val::Int(1),
        })
        .expect("encode carry");
        let tx = NodeTx {
            version: 1,
            inputs: vec![mk_input([1u8; 32])],
            outputs: vec![NodeOut { value: 90, script_pubkey: vec![5u8; 20] }, carry.clone()],
            locktime: 0,
        };
        let witness = |redeemer: Vec<Val>| {
            vec![Some(EuWitness { validator: hashlock.clone(), redeemer })]
        };

        // correct preimage → accepted, fee = 10
        let eutx = map_tx_to_eutx(&tx, std::slice::from_ref(&prevout), &witness(vec![Val::Bytes(preimage.clone())]), CHAIN)
            .expect("map");
        assert_eq!(eutx.fee, 10);
        assert!(validate_node_tx(&tx, std::slice::from_ref(&prevout), &witness(vec![Val::Bytes(preimage.clone())]), CHAIN, 100_000)
            .is_ok());

        // wrong preimage → validator says no
        assert_eq!(
            validate_node_tx(&tx, std::slice::from_ref(&prevout), &witness(vec![Val::Bytes(b"wrong".to_vec())]), CHAIN, 100_000),
            Err(EuvmTxError::ValidatorRejected(0))
        );

        // wrong revealed program → hash mismatch surfaces as a VM error
        let other = vec![Op::PushInt(1)];
        let bad_wit = vec![Some(EuWitness { validator: other, redeemer: vec![] })];
        assert_eq!(
            validate_node_tx(&tx, std::slice::from_ref(&prevout), &bad_wit, CHAIN, 100_000),
            Err(EuvmTxError::Vm(0, VmError::ValidatorHashMismatch))
        );

        // dropping the asset-carrying output → non-BLCH conservation fails
        let mut burn_tx = tx.clone();
        burn_tx.outputs = vec![NodeOut { value: 90, script_pubkey: vec![5u8; 20] }];
        assert_eq!(
            validate_node_tx(&burn_tx, std::slice::from_ref(&prevout), &witness(vec![Val::Bytes(preimage)]), CHAIN, 100_000),
            Err(EuvmTxError::ValueNotConserved { asset: a, in_sum: 7, out_sum: 0 })
        );
    }

    // ── canonical witness wire codec (D2) ──

    /// A program exercising EVERY opcode (operand-carrying and unit), so the
    /// round-trip proves the whole tag map.
    fn every_op_program() -> Vec<Op> {
        vec![
            Op::PushInt(0),
            Op::PushInt(i128::MIN),
            Op::PushInt(i128::MAX),
            Op::PushBytes(vec![]),
            Op::PushBytes(b"witness bytes".to_vec()),
            Op::Dup,
            Op::Drop,
            Op::Swap,
            Op::Pick(2),
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
    fn witness_codec_round_trip() {
        let cases = vec![
            EuWitness { validator: vec![], redeemer: vec![] },
            EuWitness { validator: every_op_program(), redeemer: vec![] },
            EuWitness {
                validator: vec![Op::Sha256d, Op::PushBytes(vec![7u8; 32]), Op::Eq],
                redeemer: vec![
                    Val::Int(0),
                    Val::Int(-1),
                    Val::Int(i128::MAX),
                    Val::Bytes(vec![]),
                    Val::Bytes(b"preimage".to_vec()),
                ],
            },
        ];
        for w in &cases {
            let enc = encode_input_witness(w);
            let dec = decode_input_witness(&enc).expect("decode");
            // Op has no PartialEq — compare via the canonical program encoding
            // (injective per encode_program's contract).
            assert_eq!(
                bloch_euvm::encode_program(&dec.validator),
                bloch_euvm::encode_program(&w.validator),
                "validator round-trip"
            );
            assert_eq!(dec.redeemer, w.redeemer, "redeemer round-trip");
            // byte-exact re-encode
            assert_eq!(encode_input_witness(&dec), enc, "byte round-trip");
        }
        // decode_program alone is the strict inverse of encode_program
        let pb = bloch_euvm::encode_program(&every_op_program());
        let ops = decode_program(&pb).expect("program decode");
        assert_eq!(bloch_euvm::encode_program(&ops), pb);
    }

    #[test]
    fn witness_strict_decode_rejects() {
        let w = EuWitness {
            validator: vec![Op::Sha256d, Op::PushBytes(b"lock".to_vec()), Op::Eq],
            redeemer: vec![Val::Bytes(b"pre".to_vec()), Val::Int(7)],
        };
        let good = encode_input_witness(&w);
        assert!(decode_input_witness(&good).is_ok());

        // every strict prefix fails (truncation), never panics
        for cut in 0..good.len() {
            assert!(decode_input_witness(&good[..cut]).is_err(), "prefix {cut} must fail");
        }
        // trailing garbage rejected
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(
            decode_input_witness(&trailing),
            Err(EuMapError::TrailingBytes { extra: 1 })
        );
        // unknown op tag inside the validator (first program byte is Sha256d=0x40)
        let mut bad_op = good.clone();
        bad_op[4] = 0xFF;
        assert_eq!(decode_input_witness(&bad_op), Err(EuMapError::BadOpTag(0xFF)));
        // unknown Val tag in the redeemer: rebuild with a corrupted item tag
        let vb = bloch_euvm::encode_program(&w.validator);
        let mut bad_val = Vec::new();
        bad_val.extend_from_slice(&(vb.len() as u32).to_le_bytes());
        bad_val.extend_from_slice(&vb);
        bad_val.extend_from_slice(&1u32.to_le_bytes());
        bad_val.push(0x02); // not a datum tag
        assert_eq!(decode_input_witness(&bad_val), Err(EuMapError::BadDatumTag(0x02)));
        // oversize witness rejected up front
        let huge = vec![0u8; MAX_WITNESS_BYTES + 1];
        assert_eq!(
            decode_input_witness(&huge),
            Err(EuMapError::WitnessTooLong { len: MAX_WITNESS_BYTES + 1 })
        );
        // a hostile redeemer_count cannot allocate: claims u32::MAX items
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&0u32.to_le_bytes()); // empty program
        hostile.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode_input_witness(&hostile),
            Err(EuMapError::Truncated { .. })
        ));
        // deterministic junk mini-corpus: must return, never panic
        for len in 0..64usize {
            let junk: Vec<u8> =
                (0..len).map(|i| (i as u8).wrapping_mul(41).wrapping_add(0x13)).collect();
            let _ = decode_input_witness(&junk);
        }
    }

    #[test]
    fn decode_input_witnesses_is_prevout_driven() {
        let (pk, _) = kp();
        let hashlock = vec![Op::Sha256d, Op::PushBytes(vec![9u8; 32]), Op::Eq];
        let witness = EuWitness {
            validator: hashlock.clone(),
            redeemer: vec![Val::Bytes(b"pre".to_vec())],
        };
        // 2-input tx: input 0 spends legacy (script_sig = legacy sig‖pk blob),
        // input 1 spends a tagged output (script_sig = pinned witness format).
        let mut tx = NodeTx {
            version: 1,
            inputs: vec![mk_input([1u8; 32]), mk_input([2u8; 32])],
            outputs: vec![NodeOut { value: 10, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        tx.inputs[0].script_sig = NodeTx::build_script_sig(b"sig", pk);
        tx.inputs[1].script_sig = encode_input_witness(&witness);
        let legacy_prev = NodeOut { value: 50, script_pubkey: legacy_pubkey_hash(pk).to_vec() };
        let tagged_prev = encode_output(&ExtOutput {
            value: blch(50),
            validator_hash: validator_hash(&hashlock),
            datum: Val::Int(0),
        }).expect("encode");
        let prevouts = vec![legacy_prev.clone(), tagged_prev.clone()];

        let ws = decode_input_witnesses(&tx, &prevouts).expect("decode");
        assert_eq!(ws.len(), 2);
        assert!(ws[0].is_none(), "legacy prevout → None");
        let w1 = ws[1].as_ref().expect("tagged prevout → Some");
        assert_eq!(
            bloch_euvm::encode_program(&w1.validator),
            bloch_euvm::encode_program(&hashlock)
        );
        assert_eq!(w1.redeemer, witness.redeemer);

        // count mismatch is typed
        assert_eq!(
            decode_input_witnesses(&tx, &prevouts[..1]).unwrap_err(),
            EuMapError::PrevoutCountMismatch { inputs: 2, prevouts: 1 }
        );
        // garbage script_sig under a TAGGED prevout fails with the input index
        let mut bad = tx.clone();
        bad.inputs[1].script_sig = vec![1, 2, 3];
        match decode_input_witnesses(&bad, &prevouts).unwrap_err() {
            EuMapError::WitnessDecode { input: 1, .. } => {}
            e => panic!("expected WitnessDecode at input 1, got {e:?}"),
        }
        // garbage script_sig under a LEGACY prevout is NOT the codec's concern
        let mut legacy_garbage = tx.clone();
        legacy_garbage.inputs[0].script_sig = vec![1, 2, 3];
        assert!(decode_input_witnesses(&legacy_garbage, &prevouts).is_ok());
    }

    /// End-to-end: a witness built with `encode_input_witness`, carried in the
    /// REAL `script_sig`, decoded by `decode_input_witnesses`, authorizes a
    /// contract spend through `validate_node_tx` — the exact accept_block hook
    /// pipeline over the pinned wire format.
    #[test]
    fn witness_wire_format_is_consensus_executable() {
        use sha2::{Digest as _, Sha256};
        let preimage = b"wire-format-secret".to_vec();
        let lock = Sha256::digest(Sha256::digest(&preimage)).to_vec();
        let hashlock = vec![Op::Sha256d, Op::PushBytes(lock), Op::Eq];

        let prevout = encode_output(&ExtOutput {
            value: blch(100),
            validator_hash: validator_hash(&hashlock),
            datum: Val::Int(0),
        }).expect("encode prevout");

        let mut tx = NodeTx {
            version: 1,
            inputs: vec![mk_input([3u8; 32])],
            outputs: vec![NodeOut { value: 90, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        tx.inputs[0].script_sig = encode_input_witness(&EuWitness {
            validator: hashlock,
            redeemer: vec![Val::Bytes(preimage)],
        });

        let ws = decode_input_witnesses(&tx, std::slice::from_ref(&prevout)).expect("decode");
        let used = validate_node_tx(&tx, std::slice::from_ref(&prevout), &ws, CHAIN, 100_000)
            .expect("spend authorizes through the wire format");
        assert!(used > 0);

        // flipping one witness byte (inside the preimage) must fail the spend
        let mut bad = tx.clone();
        let l = bad.inputs[0].script_sig.len();
        bad.inputs[0].script_sig[l - 1] ^= 0xFF;
        let ws_bad = decode_input_witnesses(&bad, std::slice::from_ref(&prevout)).expect("decodes");
        assert_eq!(
            validate_node_tx(&bad, std::slice::from_ref(&prevout), &ws_bad, CHAIN, 100_000),
            Err(EuvmTxError::ValidatorRejected(0))
        );
    }

    // ── block-level orchestration ──

    #[test]
    fn block_level_validation_gas_ceiling_and_coinbase_skip() {
        let (tx1, prev1) = legacy_signed_tx(100, 100);
        let (tx2, prev2) = legacy_signed_tx(50, 50);
        let coinbase = NodeTx {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: u32::MAX,
                script_sig: b"g3".to_vec(),
                sequence: 0,
            }],
            outputs: vec![NodeOut { value: 8400, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        };
        let txs = vec![coinbase, tx1, tx2];
        let prevs = [Vec::new(), prev1, prev2];

        // ample gas → whole block validates; coinbase skipped (resolver is
        // never called for it — returning None there must not matter)
        let ok = validate_node_block(
            &txs,
            CHAIN,
            |ti, tx| {
                assert!(!tx.is_coinbase(), "resolver must not be called for coinbase");
                Some((prevs[ti].clone(), vec![]))
            },
            100_000,
            1_000_000,
        );
        assert!(ok.is_ok(), "block should validate: {ok:?}");

        // starved block gas (each PQ sig costs ~1000) → OutOfBlockGas
        let starved = validate_node_block(
            &txs,
            CHAIN,
            |ti, _| Some((prevs[ti].clone(), vec![])),
            100_000,
            1,
        );
        assert!(matches!(starved, Err((_, EuvmTxError::OutOfBlockGas))));

        // unresolved prevouts fail closed with the offending index
        let unresolved = validate_node_block(&txs, CHAIN, |_, _| None, 100_000, 1_000_000);
        assert_eq!(unresolved, Err((1, EuvmTxError::UnresolvedPrevouts)));
    }
}
