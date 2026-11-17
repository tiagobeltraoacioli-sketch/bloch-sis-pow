// SPDX-License-Identifier: AGPL-3.0-or-later
//! The L1 treasury collection, offline half: the observation file, the
//! unsigned `TransferV2` draft that spends treasury outputs, and the
//! inspection every signer runs before a signature exists.
//!
//! # What this module is for
//!
//! The protocol treasury `bloch1qe986…2073` is a carried-form script: the
//! 20-byte SHA3-256 prefix of one RAW (pre-envelope) hybrid public key,
//! followed by twelve zero bytes (`tokenomics_v4::FOUNDER_WITHDRAWAL_H160`,
//! zero-extended exactly as `genesis-mainnet` writes it). Consensus opens such
//! a script for any key whose SHA3-256 begins with those twenty bytes
//! (`transition::owns`). Nothing in the node could collect those outputs:
//! `validator-payout` and `transfer-v2` sign with a validator keystore and
//! spend one fixed outpoint; the owner's key is a legacy encrypted wallet.
//!
//! # The split, and why
//!
//! - `bloch-pos treasury-collect observe` (in the binary, `treasury_collect.rs`)
//!   is the only online step: it reads the treasury's outputs from TWO
//!   endpoints and writes what both agree on to an observation file.
//! - [`build_plan`] (`treasury-collect prepare`) is offline and builds the
//!   UNSIGNED draft from that file, the owner's PUBLIC key and the intent.
//! - [`inspect`] (`treasury-collect inspect`, and again inside the owner's
//!   offline signer `examples/sign-treasury-spend.rs`) re-derives every input,
//!   output and the exact fee from the observation and refuses anything it
//!   cannot account for, before and after the signature.
//!
//! The collection command never opens a key and never broadcasts; the signer
//! never reads the network. Submission is the owner's explicit
//! `sendrawtransaction`.
//!
//! # Refusals that protect something (do not relax without the argument)
//!
//! - A key that does not open the treasury script (wrong key; the ENVELOPED
//!   form of the right key, whose hash differs) — `check_owner_key`.
//! - An input whose committed script is not the treasury (a foreign output
//!   slipped into an edited observation) — `foreign output`.
//! - A genesis allocation outpoint (founder, VC, team, marketing, liquidity,
//!   validator emission buckets at the same script): `unlock_epoch` is not
//!   enforced today, but the vesting-lock flag day's go/no-go precondition is
//!   that these outpoints are still unspent (`rpc.rs`, doc of `TxOut`). A
//!   collection must never be the thing that silently removes that option.
//! - A dust output (below `MIN_TRANSFER_OUTPUT_SAT`): refused by every node's
//!   mempool door; and an input worth no more than the fee it adds (spending
//!   it destroys value): left out, listed.
//! - A fee above the owner's `--max-fee`; a tip above the consensus ceiling;
//!   a size or gas above the stated caps.
//! - An inclusion epoch at which the signing root is network-bound
//!   (`checked_signing_root` differs from `spend_signing_root`): this tool
//!   does not know the state's network domain, so it fails closed.

use crate::{codec, genesis::Manifest};
use bloch_pos_committee::{
    fee_market::{self, TxCharge},
    params::{
        hf3_slh_suite_active, MAX_TRANSFER_OUTPUTS, MIN_TRANSFER_OUTPUT_SAT,
        TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
    },
    state_root::EutxoEntry,
    tokenomics_v4::FOUNDER_WITHDRAWAL_H160,
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX, PosTransaction, TransferInputV2, TransferOutput,
        WitnessKey,
    },
};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// First line of every observation file. A new layout gets a new version.
pub const OBSERVATION_MAGIC: &str = "bloch-treasury-observation v1";
/// Largest observation file read (a full page of 1,000 outputs is ~170 KB).
pub const MAX_OBSERVATION_BYTES: u64 = 1 << 20;
/// Most inputs one draft spends. `listunspent` returns at most 1,000
/// (`rpc.rs` `UTXO_PAGE_MAX`), so one page is one transaction at most.
pub const MAX_INPUTS: usize = 1_000;
/// Largest declared size of one draft: a quarter of the V2 block byte cap
/// (`fee_market::MAX_BLOCK_TX_BYTES_V2`, 524,288), so a collection never
/// competes for a whole block. 1,000 inputs declare about 49 KB.
pub const MAX_DRAFT_TX_BYTES: u64 = fee_market::MAX_BLOCK_TX_BYTES_V2 / 4;
/// Canonical bytes one more `TransferInputV2` adds: txid 32, vout 4, key
/// index 4 (`transition.rs` canonical encoding of the V2 input).
pub const V2_INPUT_BYTES: u64 = 40;

/// The compiled treasury script: `FOUNDER_WITHDRAWAL_H160` + twelve zeros.
pub fn compiled_treasury_script() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..20].copy_from_slice(&FOUNDER_WITHDRAWAL_H160);
    s
}

/// A script in the carried form (twelve zero bytes at the end).
pub fn is_carried(script: &[u8; 32]) -> bool {
    script[20..] == [0u8; 12]
}

/// The consensus ownership rule, restated (`transition::owns`): a key opens
/// its own native script, and a carried script whose twenty bytes are its
/// hash prefix.
pub fn key_opens(key_hash: &[u8; 32], script: &[u8; 32]) -> bool {
    key_hash == script || (is_carried(script) && key_hash[..20] == script[..20])
}

/// The `bloch1q…` address of a carried-form script (the Genesis-3 address
/// format: 20-byte hash, 4-byte double-SHA3 checksum, hex). `None` for a
/// native 32-byte script, which has no such address.
pub fn carried_address(script: &[u8; 32]) -> Option<String> {
    if !is_carried(script) {
        return None;
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&script[..20]);
    Some(bloch_crypto::crypto::address_from_hash(&h, false))
}

/// A destination: a `bloch1q…` mainnet address (checksum verified; carried
/// form) or a 64-digit hex script. The zero script is refused (nobody can
/// produce a key for it; a payment there is a burn).
pub fn parse_destination(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim();
    let script = if let Some(body) = text.strip_prefix(bloch_crypto::core::MAINNET_PREFIX) {
        let raw = codec::unhex(body).map_err(|e| format!("address {text}: {e}"))?;
        if raw.len() != 24 {
            return Err(format!(
                "address {text}: expected 20 bytes and a 4-byte checksum"
            ));
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&raw[..20]);
        if bloch_crypto::crypto::address_from_hash(&h, false) != text {
            return Err(format!("address {text}: checksum mismatch"));
        }
        let mut s = [0u8; 32];
        s[..20].copy_from_slice(&h);
        s
    } else if text.starts_with(bloch_crypto::core::TESTNET_PREFIX) {
        return Err(format!(
            "address {text}: a testnet address is not a mainnet destination"
        ));
    } else {
        let raw = codec::unhex(text).map_err(|e| format!("script {text}: {e}"))?;
        raw.try_into().map_err(|_| {
            format!("script {text}: expected 32 bytes (64 hex digits) or a bloch1q address")
        })?
    };
    if script == [0u8; 32] {
        return Err("the zero script is not a destination (nobody can spend it)".into());
    }
    Ok(script)
}

/// One endpoint's read point, as recorded in the observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointRead {
    pub addr: String,
    pub head_slot: u64,
    pub head_block: [u8; 32],
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
}

/// What two endpoints agreed on about the treasury at one read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub treasury: [u8; 32],
    /// SHA3-256 of the genesis manifest file the observer was given.
    pub genesis_sha3: [u8; 32],
    /// The inclusion epoch the draft is priced and signed for: the later of
    /// the two endpoints' wall-clock epochs (`getchaininfo.wall_slot`).
    pub epoch: u64,
    /// `next_base_fee_millisat_per_gas`, equal on both endpoints.
    pub base_fee: u128,
    pub endpoints: Vec<EndpointRead>,
    /// The treasury's total output count as the first endpoint reported it
    /// (`listunspent.total`); 0 when outpoints were named one by one.
    pub page_total: u64,
    pub utxos: Vec<EutxoEntry>,
}

fn field<'a>(line: &'a str, name: &str) -> Result<Vec<&'a str>, String> {
    let mut parts = line.split(' ');
    if parts.next() != Some(name) {
        return Err(format!(
            "observation: expected `{name}` line, found {line:?}"
        ));
    }
    Ok(parts.collect())
}
fn h32(text: &str) -> Result<[u8; 32], String> {
    codec::unhex(text)?
        .try_into()
        .map_err(|_| format!("expected 32 bytes: {text}"))
}
fn num<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) || text.starts_with('+') {
        return Err(format!("not a canonical decimal: {text:?}"));
    }
    text.parse().map_err(|_| format!("not a decimal: {text:?}"))
}

impl Observation {
    /// The file text. Line-oriented, one fact per line, no optional fields:
    /// a reviewer can read it, and [`Self::parse`] accepts only this layout.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        out.push_str(OBSERVATION_MAGIC);
        out.push('\n');
        out.push_str(&format!("treasury {}\n", codec::hex32(&self.treasury)));
        out.push_str(&format!(
            "genesis-sha3 {}\n",
            codec::hex32(&self.genesis_sha3)
        ));
        out.push_str(&format!("epoch {}\n", self.epoch));
        out.push_str(&format!("base-fee {}\n", self.base_fee));
        out.push_str(&format!("endpoints {}\n", self.endpoints.len()));
        for e in &self.endpoints {
            out.push_str(&format!(
                "endpoint {} {} {} {} {}\n",
                e.addr,
                e.head_slot,
                codec::hex32(&e.head_block),
                e.finalized_epoch,
                codec::hex32(&e.finalized_root)
            ));
        }
        out.push_str(&format!("page-total {}\n", self.page_total));
        out.push_str(&format!("utxos {}\n", self.utxos.len()));
        for u in &self.utxos {
            out.push_str(&format!(
                "utxo {} {} {} {}\n",
                codec::hex32(&u.txid),
                u.vout,
                u.value,
                codec::hex32(&u.script_hash)
            ));
        }
        out.push_str("end\n");
        out
    }

    /// Strict parse: exact layout, canonical numbers, declared counts equal
    /// to the lines present, no duplicate outpoint, two distinct endpoints
    /// that agree on one finalized checkpoint, and a trailing `end`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let all: Vec<&str> = text.split('\n').collect();
        let mut at = 0usize;
        let mut next = || -> Result<&str, String> {
            let line = all
                .get(at)
                .copied()
                .ok_or_else(|| "observation: truncated".to_string())?;
            at = at.saturating_add(1);
            Ok(line)
        };
        if next()? != OBSERVATION_MAGIC {
            return Err(format!(
                "observation: first line must be `{OBSERVATION_MAGIC}`"
            ));
        }
        let one = |l: &str, name: &str| -> Result<String, String> {
            let v = field(l, name)?;
            if v.len() != 1 {
                return Err(format!("observation: `{name}` takes one value"));
            }
            Ok(v[0].to_string())
        };
        let treasury = h32(&one(next()?, "treasury")?)?;
        let genesis_sha3 = h32(&one(next()?, "genesis-sha3")?)?;
        let epoch: u64 = num(&one(next()?, "epoch")?)?;
        let base_fee: u128 = num(&one(next()?, "base-fee")?)?;
        let n_endpoints: usize = num(&one(next()?, "endpoints")?)?;
        if n_endpoints != 2 {
            return Err("observation: exactly two endpoints are required".into());
        }
        let mut endpoints = Vec::with_capacity(2);
        for _ in 0..n_endpoints {
            let v = field(next()?, "endpoint")?;
            if v.len() != 5 {
                return Err("observation: an endpoint line has five values".into());
            }
            endpoints.push(EndpointRead {
                addr: v[0].to_string(),
                head_slot: num(v[1])?,
                head_block: h32(v[2])?,
                finalized_epoch: num(v[3])?,
                finalized_root: h32(v[4])?,
            });
        }
        let page_total: u64 = num(&one(next()?, "page-total")?)?;
        let n_utxos: usize = num(&one(next()?, "utxos")?)?;
        if n_utxos > MAX_INPUTS {
            return Err(format!("observation: more than {MAX_INPUTS} outputs"));
        }
        let mut utxos = Vec::with_capacity(n_utxos);
        let mut seen = BTreeSet::new();
        for _ in 0..n_utxos {
            let v = field(next()?, "utxo")?;
            if v.len() != 4 {
                return Err("observation: a utxo line has four values".into());
            }
            let u = EutxoEntry {
                txid: h32(v[0])?,
                vout: num(v[1])?,
                value: num(v[2])?,
                script_hash: h32(v[3])?,
            };
            if !seen.insert((u.txid, u.vout)) {
                return Err(format!("observation: duplicate outpoint {}:{}", v[0], v[1]));
            }
            utxos.push(u);
        }
        // `end`, then the final newline's empty remainder, then nothing.
        if next()? != "end" || next()? != "" || next().is_ok() {
            return Err("observation: must end with one `end` line".into());
        }
        let obs = Observation {
            treasury,
            genesis_sha3,
            epoch,
            base_fee,
            endpoints,
            page_total,
            utxos,
        };
        obs.check_agreement()?;
        Ok(obs)
    }

    /// The agreement an observation states, re-checked wherever it is read.
    pub fn check_agreement(&self) -> Result<(), String> {
        let [a, b] = self.endpoints.as_slice() else {
            return Err("observation: exactly two endpoints are required".into());
        };
        if a.addr == b.addr {
            return Err("observation: the two endpoints are the same address".into());
        }
        if (a.finalized_epoch, a.finalized_root) != (b.finalized_epoch, b.finalized_root) {
            return Err("observation: the endpoints name different finalized checkpoints".into());
        }
        if !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
            .contains(&self.base_fee)
        {
            return Err("observation: base fee outside the consensus range".into());
        }
        Ok(())
    }

    /// SHA3-256 of the encoded file: printed so the owner can carry it to the
    /// signing machine and see the same observation there.
    pub fn digest(&self) -> [u8; 32] {
        Sha3_256::digest(self.encode().as_bytes()).into()
    }

    fn by_outpoint(&self) -> BTreeMap<([u8; 32], u32), &EutxoEntry> {
        self.utxos.iter().map(|u| ((u.txid, u.vout), u)).collect()
    }
}

/// The genesis allocation outpoints at `treasury` in a trusted manifest:
/// never spent by this tool (module doc). Returns them with the manifest's
/// SHA3-256 so the observation can be bound to the same file.
pub fn protected_outpoints(manifest: &Manifest, treasury: &[u8; 32]) -> BTreeSet<([u8; 32], u32)> {
    manifest
        .allocation_outputs()
        .into_iter()
        .filter(|e| &e.script_hash == treasury)
        .map(|e| (e.txid, e.vout))
        .collect()
}

/// Why an observed output is not in the draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exclusion {
    /// A genesis allocation bucket: kept unspent for the vesting-lock rule.
    GenesisAllocation,
    /// Worth no more than the fee one more input adds at this price.
    Uneconomic { marginal_fee_sat: u64 },
    /// Beyond `--max-inputs` (left for the next page).
    InputCap,
}

/// What the owner asked for.
#[derive(Clone, Debug)]
pub struct Intent {
    /// Payments, in output order (vout 0, 1, …). Empty = consolidation.
    pub pay: Vec<TransferOutput>,
    /// Where the remainder goes (the change, or the whole consolidation).
    /// Defaults to the treasury itself.
    pub change_to: [u8; 32],
    pub tip: u128,
    pub max_fee_sat: u64,
    pub max_inputs: usize,
}

/// The unsigned draft and everything shown about it.
#[derive(Clone, Debug)]
pub struct Plan {
    pub tx: PosTransaction,
    pub inputs: Vec<EutxoEntry>,
    pub excluded: Vec<(EutxoEntry, Exclusion)>,
    pub fee_sat: u64,
    pub input_sum_sat: u128,
    pub signing_root: [u8; 32],
    pub txid: [u8; 32],
}

/// The owner's key must be a live hybrid spend key whose SHA3-256 opens the
/// treasury script. The ENVELOPED form of the founder's raw legacy key does
/// NOT: its hash differs, and consensus would refuse every input with
/// `ScriptMismatch`. Said in the refusal so the owner exports the right form.
pub fn check_owner_key(pubkey: &[u8], treasury: &[u8; 32], epoch: u64) -> Result<(), String> {
    if !bloch_crypto::crypto::is_spend_public_key_admissible(pubkey, hf3_slh_suite_active(epoch)) {
        return Err(
            "wrong key: not a live hybrid spend public key (ML-DSA-65 and Falcon-1024)".into(),
        );
    }
    let hash: [u8; 32] = Sha3_256::digest(pubkey).into();
    if !key_opens(&hash, treasury) {
        let hint = if pubkey.len() > 4 && pubkey.starts_with(&[0xb1, 0x0c]) {
            let raw_hash: [u8; 32] = Sha3_256::digest(&pubkey[4..]).into();
            if key_opens(&raw_hash, treasury) {
                " (this is the suite-enveloped form of the treasury key: a carried script opens only under \
                 the RAW key the Genesis-3 address was derived from; export the raw public key)"
            } else {
                ""
            }
        } else {
            ""
        };
        return Err(format!(
            "wrong key: SHA3-256 of this public key ({}) does not open the treasury script {}{hint}",
            codec::hex32(&hash),
            codec::hex32(treasury)
        ));
    }
    Ok(())
}

/// The draft's declared size: the unsigned encoding plus the largest
/// signature the admission bound allows (the `validator-payout` rule), so the
/// signed transaction is never under-declared and over-declares by at most
/// one signature (inside `TX_BYTES_DECLARE_SLACK`).
pub fn reserved_tx_bytes(tx: &PosTransaction) -> Result<u64, String> {
    let mut unsigned = tx.clone();
    if let PosTransaction::TransferV2 { keys, .. } = &mut unsigned {
        for k in keys.iter_mut() {
            k.signature.clear();
        }
    } else {
        return Err("expected a TransferV2".into());
    }
    (unsigned.canonical_bytes().len() as u64)
        .checked_add(ADMISSION_PQ_SIGNATURE_MAX as u64)
        .ok_or_else(|| "size overflow".to_string())
}

fn price(
    pubkey: &[u8],
    tx_bytes: u64,
    base_fee: u128,
    tip: u128,
    epoch: u64,
) -> Result<(TxCharge, u64), String> {
    if tip > fee_market::MAX_TIP_MILLISAT_PER_GAS {
        return Err("tip exceeds the consensus maximum".into());
    }
    let class = fee_market::eutxo_class_for_keys(epoch, std::iter::once(pubkey));
    let charge = fee_market::charge(class, tx_bytes, base_fee, tip);
    if charge.gas > fee_market::MAX_TX_GAS {
        return Err("gas exceeds the per-transaction ceiling".into());
    }
    let total = charge
        .base_fee_sat
        .checked_add(charge.priority_fee_sat)
        .ok_or("fee overflow")?;
    let total = u64::try_from(total).map_err(|_| "fee does not fit u64".to_string())?;
    Ok((charge, total))
}

/// What one more input costs at this price, rounded UP (an input is spent
/// only when it is worth strictly more than this).
pub fn marginal_input_fee_sat(base_fee: u128, tip: u128) -> Result<u64, String> {
    let per_gas = base_fee.checked_add(tip).ok_or("price overflow")?;
    let millisat = u128::from(V2_INPUT_BYTES * fee_market::GAS_PER_BYTE)
        .checked_mul(per_gas)
        .ok_or("price overflow")?;
    let sat = millisat.div_ceil(fee_market::MILLISAT_PER_SAT);
    u64::try_from(sat).map_err(|_| "marginal fee does not fit u64".into())
}

fn signing_root(tx: &PosTransaction, epoch: u64) -> Result<[u8; 32], String> {
    let root = tx.checked_signing_root(epoch);
    if root != tx.spend_signing_root() {
        return Err(format!(
            "the signing root is network-bound at epoch {epoch}; this tool does not know the state's \
             network domain and refuses rather than produce a draft nobody can sign correctly"
        ));
    }
    Ok(root)
}

fn check_epoch(epoch: u64) -> Result<(), String> {
    if epoch < TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH || epoch == u64::MAX {
        return Err(format!(
            "TransferV2 is not active at epoch {epoch} (active from {TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH})"
        ));
    }
    Ok(())
}

fn check_output(o: &TransferOutput, what: &str) -> Result<(), String> {
    if o.value < MIN_TRANSFER_OUTPUT_SAT {
        return Err(format!(
            "dust: {what} of {} sat is below the minimum output of {MIN_TRANSFER_OUTPUT_SAT} sat",
            o.value
        ));
    }
    if o.script_hash == [0u8; 32] {
        return Err(format!("{what} pays the zero script (a burn)"));
    }
    Ok(())
}

/// Build the UNSIGNED draft. Offline: everything comes from the observation,
/// the protected set, the public key and the intent.
pub fn build_plan(
    obs: &Observation,
    protected: &BTreeSet<([u8; 32], u32)>,
    pubkey: &[u8],
    intent: &Intent,
) -> Result<Plan, String> {
    obs.check_agreement()?;
    check_epoch(obs.epoch)?;
    check_owner_key(pubkey, &obs.treasury, obs.epoch)?;
    if intent.max_inputs == 0 || intent.max_inputs > MAX_INPUTS {
        return Err(format!("--max-inputs must be 1 to {MAX_INPUTS}"));
    }
    if intent.pay.len().saturating_add(1) > MAX_TRANSFER_OUTPUTS {
        return Err(format!("at most {} payments", MAX_TRANSFER_OUTPUTS - 1));
    }
    for (i, p) in intent.pay.iter().enumerate() {
        check_output(p, &format!("payment {i}"))?;
    }
    if intent.change_to == [0u8; 32] {
        return Err("the change destination is the zero script (a burn)".into());
    }
    // Every observed output must be the treasury's: an observation that names
    // a foreign output was edited or written for another script.
    for u in &obs.utxos {
        if u.script_hash != obs.treasury {
            return Err(format!(
                "foreign output {}:{} (script {}) in a treasury observation",
                codec::hex32(&u.txid),
                u.vout,
                codec::hex32(&u.script_hash)
            ));
        }
    }
    let marginal = marginal_input_fee_sat(obs.base_fee, intent.tip)?;
    let mut ordered: Vec<EutxoEntry> = obs.utxos.clone();
    ordered.sort_by_key(|u| (u.txid, u.vout));
    let mut inputs = Vec::new();
    let mut excluded = Vec::new();
    for u in ordered {
        if protected.contains(&(u.txid, u.vout)) {
            excluded.push((u, Exclusion::GenesisAllocation));
        } else if u.value <= marginal {
            excluded.push((
                u,
                Exclusion::Uneconomic {
                    marginal_fee_sat: marginal,
                },
            ));
        } else if inputs.len() >= intent.max_inputs {
            excluded.push((u, Exclusion::InputCap));
        } else {
            inputs.push(u);
        }
    }
    if inputs.is_empty() {
        return Err("nothing to spend: every observed output was excluded (listed above)".into());
    }
    let input_sum: u128 = inputs.iter().map(|u| u128::from(u.value)).sum();
    let paid: u128 = intent.pay.iter().map(|o| u128::from(o.value)).sum();

    // Size depends on the output COUNT only (values are fixed-width), so
    // draft with a change output of 1 sat, measure, price, then fill it.
    let mut outputs = intent.pay.clone();
    outputs.push(TransferOutput {
        value: 1,
        script_hash: intent.change_to,
    });
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey: pubkey.to_vec(),
            signature: Vec::new(),
        }],
        inputs: inputs
            .iter()
            .map(|u| TransferInputV2 {
                txid: u.txid,
                vout: u.vout,
                key_index: 0,
            })
            .collect(),
        outputs,
        tx_bytes: 0,
        tip_millisat_per_gas: intent.tip,
    };
    let reserved = reserved_tx_bytes(&tx)?;
    let (_, fee) = price(pubkey, reserved, obs.base_fee, intent.tip, obs.epoch)?;
    let change = input_sum
        .checked_sub(paid)
        .and_then(|r| r.checked_sub(u128::from(fee)))
        .ok_or_else(|| {
            format!("the inputs ({input_sum} sat) do not cover the payments ({paid} sat) and the fee ({fee} sat)")
        })?;
    if change == 0 {
        return Err(
            "the payments and the fee use every satoshi of the inputs; leave a change of at least \
             1000 sat (the remainder goes to --change-to)"
                .into(),
        );
    }
    if fee > intent.max_fee_sat {
        return Err(format!(
            "the exact fee {fee} sat exceeds --max-fee {} sat",
            intent.max_fee_sat
        ));
    }
    if reserved > MAX_DRAFT_TX_BYTES {
        return Err(format!("declared size {reserved} exceeds the draft cap {MAX_DRAFT_TX_BYTES}; lower --max-inputs"));
    }
    if let PosTransaction::TransferV2 {
        tx_bytes, outputs, ..
    } = &mut tx
    {
        *tx_bytes = reserved;
        let last = outputs.last_mut().ok_or("missing change output")?;
        last.value =
            u64::try_from(change).map_err(|_| "change does not fit one output".to_string())?;
        check_output(last, "change")?;
    }
    let root = signing_root(&tx, obs.epoch)?;
    let txid = tx.txid();
    let plan = Plan {
        tx,
        inputs,
        excluded,
        fee_sat: fee,
        input_sum_sat: input_sum,
        signing_root: root,
        txid,
    };
    // The draft must pass the same inspection the signer runs.
    inspect(obs, protected, &plan.tx, intent.max_fee_sat)?;
    Ok(plan)
}

/// What [`inspect`] established, for printing.
#[derive(Clone, Debug)]
pub struct Inspection {
    pub inputs: Vec<EutxoEntry>,
    pub outputs: Vec<TransferOutput>,
    pub input_sum_sat: u128,
    pub output_sum_sat: u128,
    pub charge: TxCharge,
    pub fee_sat: u64,
    pub tx_bytes: u64,
    pub tip: u128,
    pub signing_root: [u8; 32],
    pub txid: [u8; 32],
    pub signed: bool,
}

/// Re-derive everything about a draft (unsigned or signed) from the
/// observation, and refuse what does not account exactly. Runs before any
/// key is opened and again after the signature.
pub fn inspect(
    obs: &Observation,
    protected: &BTreeSet<([u8; 32], u32)>,
    tx: &PosTransaction,
    max_fee_sat: u64,
) -> Result<Inspection, String> {
    obs.check_agreement()?;
    check_epoch(obs.epoch)?;
    let PosTransaction::TransferV2 {
        keys,
        inputs,
        outputs,
        tx_bytes,
        tip_millisat_per_gas,
    } = tx
    else {
        return Err("expected a TransferV2 (wire tag 0x06)".into());
    };
    let [key] = keys.as_slice() else {
        return Err("a treasury spend carries exactly one witness key".into());
    };
    check_owner_key(&key.pubkey, &obs.treasury, obs.epoch)?;
    if inputs.is_empty() || inputs.len() > MAX_INPUTS {
        return Err(format!("a treasury spend has 1 to {MAX_INPUTS} inputs"));
    }
    if outputs.is_empty() || outputs.len() > MAX_TRANSFER_OUTPUTS {
        return Err("output count outside 1..=MAX_TRANSFER_OUTPUTS".into());
    }
    let observed = obs.by_outpoint();
    let mut seen = BTreeSet::new();
    let mut spent = Vec::with_capacity(inputs.len());
    for i in inputs {
        if i.key_index != 0 {
            return Err("an input names a witness entry other than the one key".into());
        }
        if !seen.insert((i.txid, i.vout)) {
            return Err("duplicate input".into());
        }
        if protected.contains(&(i.txid, i.vout)) {
            return Err(format!(
                "input {}:{} is a genesis allocation outpoint; this tool never spends one",
                codec::hex32(&i.txid),
                i.vout
            ));
        }
        let Some(u) = observed.get(&(i.txid, i.vout)) else {
            return Err(format!(
                "input {}:{} is not in the observation: its value and owner are unknown here",
                codec::hex32(&i.txid),
                i.vout
            ));
        };
        if u.script_hash != obs.treasury {
            return Err(format!(
                "foreign output {}:{} as an input",
                codec::hex32(&i.txid),
                i.vout
            ));
        }
        spent.push((*u).clone());
    }
    for (n, o) in outputs.iter().enumerate() {
        check_output(o, &format!("output {n}"))?;
    }
    if *tx_bytes != reserved_tx_bytes(tx)? {
        return Err("declared size is not the unsigned size plus one maximal signature".into());
    }
    if *tx_bytes > MAX_DRAFT_TX_BYTES {
        return Err("declared size above the draft cap".into());
    }
    let (charge, fee) = price(
        &key.pubkey,
        *tx_bytes,
        obs.base_fee,
        *tip_millisat_per_gas,
        obs.epoch,
    )?;
    let input_sum: u128 = spent.iter().map(|u| u128::from(u.value)).sum();
    let output_sum: u128 = outputs.iter().map(|o| u128::from(o.value)).sum();
    if output_sum.checked_add(u128::from(fee)) != Some(input_sum) {
        return Err(format!(
            "not conserved at the observed base fee: inputs {input_sum} sat, outputs {output_sum} sat, fee {fee} sat"
        ));
    }
    if fee > max_fee_sat {
        return Err(format!(
            "the exact fee {fee} sat exceeds --max-fee {max_fee_sat} sat"
        ));
    }
    let root = signing_root(tx, obs.epoch)?;
    let signed = !key.signature.is_empty();
    if signed
        && (key.signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || !bloch_crypto::crypto::verify_spend(
                &key.pubkey,
                &root,
                &key.signature,
                hf3_slh_suite_active(obs.epoch),
            ))
    {
        return Err(
            "the signature does not verify over the signing root (consensus spend verifier)".into(),
        );
    }
    Ok(Inspection {
        inputs: spent,
        outputs: outputs.clone(),
        input_sum_sat: input_sum,
        output_sum_sat: output_sum,
        charge,
        fee_sat: fee,
        tx_bytes: *tx_bytes,
        tip: *tip_millisat_per_gas,
        signing_root: root,
        txid: tx.txid(),
        signed,
    })
}

fn label(script: &[u8; 32], treasury: &[u8; 32]) -> String {
    let addr = carried_address(script)
        .map(|a| format!(" ({a})"))
        .unwrap_or_default();
    if script == treasury {
        format!("{}{addr} = THE TREASURY ITSELF", codec::hex32(script))
    } else {
        format!("{}{addr}", codec::hex32(script))
    }
}

/// The text a signer reads: every input, every output, the fee and its
/// parts, the root and the txid. No field is elided.
pub fn render(obs: &Observation, i: &Inspection) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Treasury script: {}\n",
        label(&obs.treasury, &obs.treasury)
    ));
    s.push_str(&format!(
        "Observation SHA3-256: {}\n",
        codec::hex32(&obs.digest())
    ));
    for e in &obs.endpoints {
        s.push_str(&format!(
            "Endpoint {}: head slot {} block {}, finalized epoch {} root {}\n",
            e.addr,
            e.head_slot,
            codec::hex32(&e.head_block),
            e.finalized_epoch,
            codec::hex32(&e.finalized_root)
        ));
    }
    s.push_str(&format!(
        "Inputs ({}), each owned by the treasury script:\n",
        i.inputs.len()
    ));
    for u in &i.inputs {
        s.push_str(&format!(
            "  in  {}:{}  {} sat\n",
            codec::hex32(&u.txid),
            u.vout,
            u.value
        ));
    }
    s.push_str(&format!(
        "Outputs ({}), in order (position = vout):\n",
        i.outputs.len()
    ));
    for (n, o) in i.outputs.iter().enumerate() {
        s.push_str(&format!(
            "  out {n}  {} sat  to {}\n",
            o.value,
            label(&o.script_hash, &obs.treasury)
        ));
    }
    s.push_str(&format!(
        "Input total: {} sat\nOutput total: {} sat\nExact fee: {} sat (base {} sat + priority {} sat; gas {} at base fee {} + tip {} millisat/gas)\n",
        i.input_sum_sat,
        i.output_sum_sat,
        i.fee_sat,
        i.charge.base_fee_sat,
        i.charge.priority_fee_sat,
        i.charge.gas,
        obs.base_fee,
        i.tip
    ));
    s.push_str(&format!(
        "Declared bytes: {}\nInclusion epoch (prices and signing rules; not an expiry): {}\nSigning root: {}\nTransaction id: {}\nSignature present: {}\n",
        i.tx_bytes,
        obs.epoch,
        codec::hex32(&i.signing_root),
        codec::hex32(&i.txid),
        i.signed
    ));
    s.push_str(
        "Valid only at this exact base fee (exact conservation): if the next block's base fee differs, \
         the transaction is refused (never a loss); observe and prepare again. Nothing was broadcast.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(utxos: Vec<EutxoEntry>, treasury: [u8; 32]) -> Observation {
        Observation {
            treasury,
            genesis_sha3: [7; 32],
            epoch: 9_000,
            base_fee: 10,
            endpoints: vec![
                EndpointRead {
                    addr: "127.0.0.1:1".into(),
                    head_slot: 288_000,
                    head_block: [1; 32],
                    finalized_epoch: 8_998,
                    finalized_root: [2; 32],
                },
                EndpointRead {
                    addr: "127.0.0.1:2".into(),
                    head_slot: 288_001,
                    head_block: [3; 32],
                    finalized_epoch: 8_998,
                    finalized_root: [2; 32],
                },
            ],
            page_total: utxos.len() as u64,
            utxos,
        }
    }

    #[test]
    fn the_compiled_treasury_is_the_owners_published_address() {
        let s = compiled_treasury_script();
        assert!(is_carried(&s));
        assert_eq!(
            carried_address(&s).as_deref(),
            Some("bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073")
        );
        assert_eq!(
            parse_destination("bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073").unwrap(),
            s
        );
    }

    #[test]
    fn destinations_refuse_bad_checksums_testnet_zero_and_short_scripts() {
        assert!(
            parse_destination("bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242074")
                .unwrap_err()
                .contains("checksum")
        );
        assert!(parse_destination(&format!("bloch1t{}", "00".repeat(24))).is_err());
        assert!(parse_destination(&"00".repeat(32))
            .unwrap_err()
            .contains("zero script"));
        assert!(parse_destination(&"11".repeat(31)).is_err());
        assert_eq!(parse_destination(&"11".repeat(32)).unwrap(), [0x11; 32]);
    }

    #[test]
    fn ownership_rule_matches_consensus_for_native_carried_and_foreign() {
        let k = [0xab; 32];
        let mut carried = [0u8; 32];
        carried[..20].copy_from_slice(&k[..20]);
        assert!(key_opens(&k, &k));
        assert!(key_opens(&k, &carried));
        let mut not_zero_tail = carried;
        not_zero_tail[31] = 1;
        assert!(!key_opens(&k, &not_zero_tail));
        let mut other = carried;
        other[0] ^= 1;
        assert!(!key_opens(&k, &other));
    }

    #[test]
    fn observation_round_trips_and_parse_is_strict() {
        let t = compiled_treasury_script();
        let o = obs(
            vec![EutxoEntry {
                txid: [9; 32],
                vout: 2,
                value: 5_000,
                script_hash: t,
            }],
            t,
        );
        let text = o.encode();
        assert_eq!(Observation::parse(&text).unwrap(), o);
        // Every one of these edits must be refused.
        let cases = [
            text.replace(
                "bloch-treasury-observation v1",
                "bloch-treasury-observation v2",
            ),
            text.replace("utxos 1", "utxos 2"),
            text.replace("\nend\n", "\n"),
            format!("{text}extra\n"),
            text.replace("epoch 9000", "epoch 09000"),
            text.replace("endpoints 2", "endpoints 1"),
            text.replace("127.0.0.1:2", "127.0.0.1:1"),
            text.replace(
                &format!("{} 8998", "03".repeat(32)),
                &format!("{} 8997", "03".repeat(32)),
            ),
            text.replace("base-fee 10", "base-fee 0"),
        ];
        for (n, bad) in cases.iter().enumerate() {
            assert!(Observation::parse(bad).is_err(), "case {n} must be refused");
        }
        let dup = text
            .replace(
                "end\n",
                &format!(
                    "utxo {} 2 5000 {}\nend\n",
                    "09".repeat(32),
                    codec::hex32(&t)
                ),
            )
            .replace("utxos 1", "utxos 2");
        assert!(Observation::parse(&dup).unwrap_err().contains("duplicate"));
    }

    /// The numbers the runbook quotes: the exact fee of a consolidation of N
    /// inputs at the floor base fee, no tip, at a post-HF3 epoch, with a real
    /// raw hybrid key. Printed as `TREASURY_FEE_MEASURE` lines.
    #[test]
    fn consolidation_fee_by_input_count_at_the_floor() {
        let (pk, _) = bloch_crypto::crypto::generate_keypair_from_seed(&[0x5c; 32]).unwrap();
        let raw = pk[4..].to_vec();
        let h: [u8; 32] = Sha3_256::digest(&raw).into();
        let mut t = [0u8; 32];
        t[..20].copy_from_slice(&h[..20]);
        let mut last = 0u64;
        for n in [1usize, 10, 100, 1_000] {
            let utxos = (0..n)
                .map(|i| EutxoEntry {
                    txid: Sha3_256::digest((i as u64).to_le_bytes()).into(),
                    vout: 2,
                    value: 5_000,
                    script_hash: t,
                })
                .collect();
            let o = obs(utxos, t);
            let intent = Intent {
                pay: vec![],
                change_to: t,
                tip: 0,
                max_fee_sat: 1_000_000,
                max_inputs: MAX_INPUTS,
            };
            let plan = build_plan(&o, &BTreeSet::new(), &raw, &intent).unwrap();
            let bytes = match &plan.tx {
                PosTransaction::TransferV2 { tx_bytes, .. } => *tx_bytes,
                _ => unreachable!(),
            };
            println!(
                "TREASURY_FEE_MEASURE inputs {n} declared_bytes {bytes} fee_sat {}",
                plan.fee_sat
            );
            assert!(plan.fee_sat > last);
            assert!(bytes <= MAX_DRAFT_TX_BYTES);
            last = plan.fee_sat;
        }
    }

    #[test]
    fn marginal_input_fee_is_rounded_up_and_matches_the_measured_six_sat() {
        // 40 bytes x 16 gas x 10 millisat = 6,400 millisat = 6.4 sat -> 7.
        assert_eq!(marginal_input_fee_sat(10, 0).unwrap(), 7);
        assert_eq!(marginal_input_fee_sat(10, 5).unwrap(), 10); // 9.6 -> 10
    }
}
