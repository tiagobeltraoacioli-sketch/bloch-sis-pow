// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core of `bloch-partner-send` — the pure, testable half.
//!
//! ## What this is
//!
//! One purpose: move a **small, explicitly stated** amount of BLCH from one
//! source address to one partner address on Genesis-4, with the operator
//! seeing exactly what will be signed before anything is signed, and typing a
//! confirmation before anything leaves the machine.
//!
//! ## What this is deliberately incapable of
//!
//! - **No default amount, no default destination.** Both are required flags,
//!   strictly parsed; an empty or malformed value aborts.
//! - **No batch mode.** One run builds exactly one transfer with exactly one
//!   destination output (plus change back to the source, or no change at
//!   all). There is no list input, no loop, no CSV.
//! - **No unattended path.** The binary refuses to confirm when stdin/stdout
//!   are not a terminal (`main.rs`), and the confirmation is a typed phrase
//!   containing the amount and the destination tail — not a `-y` flag.
//! - **A hard amount cap** ([`MAX_PARTNER_SEND_SAT`], 10,000 BLCH) with no
//!   override flag. This tool exists for integration-test allocations; the
//!   treasury (~3.4B BLCH) is five orders of magnitude beyond the cap, and
//!   raising the cap requires editing this constant and rebuilding — a
//!   decision with a diff, not a flag.
//! - **No sub-dust output, ever.** Genesis-3's history includes a stuck
//!   sub-dust transaction poisoning every block that included it. Genesis-4
//!   consensus does not currently enforce a dust floor on transfer outputs,
//!   so this tool enforces one on itself: it refuses to *create* an output
//!   (payment or change) below [`DUST_THRESHOLD_SAT`], and tells the
//!   operator the exact amounts that would avoid it.
//!
//! ## The consensus math is imported, not reimplemented
//!
//! Fees, gas, the signing root, the txid and the wire encoding all come from
//! `bloch-pos-committee` — the crate the fleet's consensus runs. Genesis-4
//! conservation is **exact** (`spent == created + fee`, not `>=`), so a fee
//! computed by a second implementation that rounds differently would make
//! every transfer invalid. Nothing here derives a consensus quantity twice.

pub mod rpc;

use bloch_crypto::address::{Address, Network};
use bloch_pos_committee::fee_market::{self, TxClass};
use bloch_pos_committee::transition::{PosTransaction, TransferInput, TransferOutput};
use serde::{Deserialize, Serialize};

// ── Policy constants (this tool's, not consensus) ───────────────────────────

/// Minimum value this tool will give any output it creates, in satoshis.
///
/// 546 sat is the dust floor Genesis-3 consensus enforced
/// (`bloch_crypto::core::DUST_THRESHOLD`) and the figure the era-1 wallet
/// still uses for change. Genesis-4's transfer validation has no dust floor
/// today, which makes this a *courtesy to the network* as much as a
/// self-protection: the G3 dust incident (a sub-dust tx failing every block
/// that included it) is why this refusal exists at build time rather than
/// hoping admission catches it.
pub const DUST_THRESHOLD_SAT: u64 = 546;

/// Hard per-run ceiling: 10,000 BLCH. No flag raises it.
///
/// The tool's charter is integration-test allocations ("give a partner a
/// small amount to exercise the spend path"). Anything larger is a different
/// decision and deserves a different, deliberate process — starting with
/// editing this constant in source, which leaves a diff.
pub const MAX_PARTNER_SEND_SAT: u64 = 10_000 * SAT_PER_BLCH;

/// Fee sanity ceiling: refuse any transfer whose total fee exceeds 1 BLCH.
/// At today's floor base fee a one-input transfer costs ~0.0025 BLCH; a fee
/// three orders of magnitude above that means a mispriced base fee, a
/// fat-fingered tip, or a bug — all reasons to stop, none to proceed.
pub const MAX_FEE_SAT: u128 = 100_000_000;

/// Most inputs one partner send may consume. Well under the V1 transfer's
/// 61-input block ceiling; a small send needing more than 32 coins means the
/// source address is the wrong source.
pub const MAX_INPUTS: usize = 32;

/// Default tip, millisatoshi per gas — same default as the node's own
/// `submit-tx`. At the floor base fee this makes the whole fee ~0.0025 BLCH
/// for a one-input transfer.
pub const DEFAULT_TIP_MILLISAT_PER_GAS: u128 = 1_000;

pub const SAT_PER_BLCH: u64 = 100_000_000;

// ── Size budgets for `tx_bytes` ─────────────────────────────────────────────
//
// `tx_bytes` sits INSIDE the signing root, so it must be fixed before the
// signature exists, while the hybrid signature's length (Falcon-1024 is
// variable-length) is only known after. These budgets bound the real bytes:
// enveloped hybrid pubkey = 4 + 1952 (ML-DSA-65) + 1793 (Falcon-1024) = 3749;
// enveloped hybrid signature ≤ 4 + 3309 (ML-DSA-65) + ~1330 (Falcon-1024 max)
// ≈ 4643. Consensus only refuses tx_bytes BELOW the encoding
// (`UnderdeclaredSize`); above costs a few hundred satoshis of padding gas.
// `budget_fits_a_real_hybrid_witness` pins both budgets against real keygen.
const PUBKEY_BYTES_BUDGET: u64 = 3_800;
const SIG_BYTES_BUDGET: u64 = 4_700;
const TX_BYTES_SLACK: u64 = 128;

// ── Amounts ─────────────────────────────────────────────────────────────────

/// Parse a BLCH amount string ("25", "0.5", "1.00000001") into satoshis.
///
/// Strict on purpose — this is the flag a human types when real value moves:
/// digits, at most one '.', at most 8 fractional digits, no sign, no
/// exponent, no separators, must be > 0. Anything else is an error, never a
/// guess.
pub fn parse_blch(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".into());
    }
    let (whole, frac) = match s.split_once('.') {
        None => (s, ""),
        Some((w, f)) => (w, f),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(format!("`{s}` is not an amount"));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "`{s}` is not a plain decimal BLCH amount (digits and at most one '.')"
        ));
    }
    if frac.len() > 8 {
        return Err(format!(
            "`{s}` has {} fractional digits; BLCH has 8 (1 sat = 0.00000001 BLCH)",
            frac.len()
        ));
    }
    let whole_v: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse::<u128>().map_err(|_| format!("`{whole}` is too large"))?
    };
    let mut frac_sat: u64 = 0;
    for (i, c) in frac.chars().enumerate() {
        frac_sat += (c as u64 - '0' as u64) * 10u64.pow(7 - i as u32);
    }
    let sat = whole_v
        .checked_mul(SAT_PER_BLCH as u128)
        .and_then(|v| v.checked_add(frac_sat as u128))
        .ok_or_else(|| format!("`{s}` overflows"))?;
    if sat == 0 {
        return Err("amount must be greater than zero".into());
    }
    u64::try_from(sat).map_err(|_| format!("`{s}` exceeds the u64 satoshi range"))
}

/// Render satoshis as a BLCH string with no trailing zeros ("25", "0.5",
/// "1.00000001"). The inverse of [`parse_blch`] for every valid input —
/// pinned by `blch_roundtrip`.
pub fn format_blch(sat: u64) -> String {
    let whole = sat / SAT_PER_BLCH;
    let frac = sat % SAT_PER_BLCH;
    if frac == 0 {
        format!("{whole}")
    } else {
        let f = format!("{frac:08}");
        format!("{whole}.{}", f.trim_end_matches('0'))
    }
}

// ── Addresses ───────────────────────────────────────────────────────────────

/// The 32-byte `script_hash` the Genesis-4 UTXO set keys an address's
/// outputs by: the address's 20-byte pubkey hash, zero-padded to 32. This is
/// the padding `owns()` in `bloch-pos-committee` accepts
/// (`script_hash[20..] == 0 && key_hash[..20] == script_hash[..20]`), and the
/// derivation the RPC docs state for integrators.
pub fn script_hash32(addr: &Address) -> [u8; 32] {
    let mut sh = [0u8; 32];
    sh[..20].copy_from_slice(addr.hash_bytes());
    sh
}

// ── The plan ────────────────────────────────────────────────────────────────

/// One selectable coin of the source address, as read from `getutxos`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

/// Everything the operator is about to authorise, fixed before any key is
/// touched. Written to disk as JSON between the plan/sign/broadcast steps so
/// each later step re-derives and re-checks the whole thing instead of
/// trusting the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    /// "mainnet" or "testnet" — both addresses must agree.
    pub network: String,
    pub from_address: String,
    pub to_address: String,
    pub amount_sat: u64,
    /// The coins this transfer consumes. Selected largest-first,
    /// deterministically, and re-checked unspent before broadcast.
    pub inputs: Vec<PlanInput>,
    /// Change returned to `from_address`. Zero means no change output.
    /// Never in `1..DUST_THRESHOLD_SAT` — the plan builder refuses.
    pub change_sat: u64,
    /// Declared byte size (inside the signing root; consensus refuses less
    /// than the real encoding, so this is budgeted above it).
    pub tx_bytes: u64,
    pub tip_millisat_per_gas: u128,
    /// The base fee this plan was priced at. A transfer is valid at exactly
    /// one price point; if the chain's base fee moves before broadcast the
    /// transfer fails conservation and must be re-planned — it cannot
    /// silently pay more.
    pub base_fee_millisat_per_gas: u128,
    pub gas: u64,
    pub base_fee_sat: u128,
    pub tip_fee_sat: u128,
    /// SHA3-256 signing root of the transfer — what the key will sign.
    /// Recomputed from the fields above at every step; a mismatch aborts.
    pub signing_root: String,
    /// Derived transaction id (`SHA3-256(DS_TXID ‖ signing_root)`).
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanInput {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
}

/// A plan plus the witness that authorises it — the broadcast step's input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPlan {
    pub plan: Plan,
    pub pubkey: String,
    pub signature: String,
    /// The exact canonical bytes to broadcast. Decoded and cross-checked
    /// against `plan` before they are sent.
    pub raw_tx: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    NetworkMismatch { from: String, to: String },
    SelfSend,
    AmountBelowDust { amount_sat: u64 },
    AmountAboveCap { amount_sat: u64 },
    InsufficientFunds { need_sat: u128, have_sat: u128 },
    /// Every viable selection leaves change in `1..DUST`. Carries the exact
    /// alternative amounts that avoid it: send less (change lands on the
    /// dust floor) or send more (consume the inputs exactly, no change).
    DustChange { change_sat: u64, send_less_sat: u64, send_more_sat: u64 },
    FeeAboveSanityCap { fee_sat: u128 },
    TooManyInputs { needed_more_than: usize },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::NetworkMismatch { from, to } => write!(
                f,
                "source is {from} but destination is {to}; refusing a cross-network transfer"
            ),
            PlanError::SelfSend => write!(
                f,
                "destination equals the source address; a partner send goes to the partner"
            ),
            PlanError::AmountBelowDust { amount_sat } => write!(
                f,
                "amount {} BLCH ({amount_sat} sat) is below the {DUST_THRESHOLD_SAT}-sat dust \
                 floor; this tool creates no sub-dust output",
                format_blch(*amount_sat)
            ),
            PlanError::AmountAboveCap { amount_sat } => write!(
                f,
                "amount {} BLCH exceeds this tool's hard cap of {} BLCH per run. The cap has no \
                 override flag: a larger transfer is a different decision and requires editing \
                 MAX_PARTNER_SEND_SAT in tools/partner-send/src/lib.rs and rebuilding.",
                format_blch(*amount_sat),
                format_blch(MAX_PARTNER_SEND_SAT)
            ),
            PlanError::InsufficientFunds { need_sat, have_sat } => write!(
                f,
                "insufficient funds: need {need_sat} sat (amount + fee), source address holds \
                 {have_sat} sat across its first {MAX_INPUTS} largest coins"
            ),
            PlanError::DustChange { change_sat, send_less_sat, send_more_sat } => write!(
                f,
                "refusing to create sub-dust change of {change_sat} sat (< {DUST_THRESHOLD_SAT}). \
                 Sub-dust outputs have poisoned blocks before (Genesis-3). Send {} BLCH instead \
                 (change lands on the dust floor) or {} BLCH (consumes the selected coins \
                 exactly, no change).",
                format_blch(*send_less_sat),
                format_blch(*send_more_sat)
            ),
            PlanError::FeeAboveSanityCap { fee_sat } => write!(
                f,
                "computed fee {fee_sat} sat exceeds the {MAX_FEE_SAT}-sat sanity cap; the base \
                 fee or tip is mispriced — not sending"
            ),
            PlanError::TooManyInputs { needed_more_than } => write!(
                f,
                "covering this amount needs more than {needed_more_than} inputs; the source \
                 address is too fragmented for a partner send — consolidate first or use a \
                 different source"
            ),
        }
    }
}

/// Exact canonical size of a V1 `Transfer` (`transition.rs` encoding):
/// tag ‖ n_inputs ‖ inputs(outpoint + length-prefixed pubkey and signature)
/// ‖ n_outputs ‖ outputs ‖ tx_bytes ‖ tip.
fn v1_canonical_size(n_inputs: u64, pk_len: u64, sig_len: u64, n_outputs: u64) -> u64 {
    1 + 4 + n_inputs * (32 + 4 + 4 + pk_len + 4 + sig_len) + 4 + n_outputs * (8 + 32) + 8 + 16
}

/// The `tx_bytes` this tool declares for an `n_inputs`-coin transfer:
/// the exact V1 size at the witness budgets, two outputs assumed (payment +
/// change — one output only over-declares), plus slack.
pub fn planned_tx_bytes(n_inputs: u64) -> u64 {
    v1_canonical_size(n_inputs, PUBKEY_BYTES_BUDGET, SIG_BYTES_BUDGET, 2) + TX_BYTES_SLACK
}

fn fee_for(n_inputs: u64, base: u128, tip: u128) -> (u64, u64, u128, u128) {
    let tx_bytes = planned_tx_bytes(n_inputs);
    let charge = fee_market::charge(
        TxClass::Eutxo { inputs: n_inputs as u32 },
        tx_bytes,
        base,
        tip,
    );
    (tx_bytes, charge.gas, charge.base_fee_sat, charge.priority_fee_sat)
}

/// Build the plan: validate, select coins, price, and refuse anything the
/// policy above forbids. Pure — the caller supplies the coins and the base
/// fee it read from the chain.
pub fn build_plan(
    from: &Address,
    to: &Address,
    amount_sat: u64,
    coins: &[Coin],
    base_fee_millisat_per_gas: u128,
    tip_millisat_per_gas: u128,
) -> Result<Plan, PlanError> {
    if from.network() != to.network() {
        return Err(PlanError::NetworkMismatch {
            from: net_name(from.network()).into(),
            to: net_name(to.network()).into(),
        });
    }
    if from == to {
        return Err(PlanError::SelfSend);
    }
    if amount_sat < DUST_THRESHOLD_SAT {
        return Err(PlanError::AmountBelowDust { amount_sat });
    }
    if amount_sat > MAX_PARTNER_SEND_SAT {
        return Err(PlanError::AmountAboveCap { amount_sat });
    }

    // Largest-first, deterministic (ties broken by outpoint): fewest inputs
    // means fewest hybrid verifications bought and the smallest transfer.
    let mut sorted: Vec<&Coin> = coins.iter().collect();
    sorted.sort_by(|a, b| {
        b.value_sat.cmp(&a.value_sat).then(a.txid.cmp(&b.txid)).then(a.vout.cmp(&b.vout))
    });

    let take = sorted.len().min(MAX_INPUTS);
    let mut sum: u128 = 0;
    let mut dust_trap: Option<u64> = None; // best (largest) trapped change seen
    for n in 1..=take {
        sum += sorted[n - 1].value_sat as u128;
        let (tx_bytes, gas, base_fee_sat, tip_fee_sat) =
            fee_for(n as u64, base_fee_millisat_per_gas, tip_millisat_per_gas);
        let fee = base_fee_sat + tip_fee_sat;
        let need = amount_sat as u128 + fee;
        if sum < need {
            continue;
        }
        // Fits u64 by the supply cap (all coins sum below TOTAL_SUPPLY_SAT,
        // itself < u64::MAX); refuse rather than truncate if that ever broke.
        let Ok(change) = u64::try_from(sum - need) else {
            return Err(PlanError::FeeAboveSanityCap { fee_sat: fee });
        };
        if change > 0 && change < DUST_THRESHOLD_SAT {
            // Adding one more coin usually clears the trap; remember the
            // best trapped change for the error message if nothing does.
            dust_trap = Some(dust_trap.map_or(change, |c| c.max(change)));
            continue;
        }
        if fee > MAX_FEE_SAT {
            return Err(PlanError::FeeAboveSanityCap { fee_sat: fee });
        }
        let selected = &sorted[..n];
        return Ok(finish_plan(
            from,
            to,
            amount_sat,
            selected,
            change,
            tx_bytes,
            gas,
            base_fee_sat,
            tip_fee_sat,
            base_fee_millisat_per_gas,
            tip_millisat_per_gas,
        ));
    }

    if let Some(change) = dust_trap {
        // Suggestions are exact by construction: shrinking the amount by the
        // shortfall puts change on the floor; growing it by the trapped
        // change consumes the selection with change == 0. Fee is unchanged
        // in both because the input set is unchanged.
        return Err(PlanError::DustChange {
            change_sat: change,
            send_less_sat: amount_sat - (DUST_THRESHOLD_SAT - change),
            send_more_sat: amount_sat + change,
        });
    }
    let (_, _, b, t) = fee_for(take.max(1) as u64, base_fee_millisat_per_gas, tip_millisat_per_gas);
    let need = amount_sat as u128 + b + t;
    let total_all: u128 = coins.iter().map(|c| c.value_sat as u128).sum();
    if sorted.len() > MAX_INPUTS && total_all >= need {
        // The balance exists but not within the input budget of one send.
        return Err(PlanError::TooManyInputs { needed_more_than: MAX_INPUTS });
    }
    Err(PlanError::InsufficientFunds { need_sat: need, have_sat: sum })
}

#[allow(clippy::too_many_arguments)]
fn finish_plan(
    from: &Address,
    to: &Address,
    amount_sat: u64,
    selected: &[&Coin],
    change_sat: u64,
    tx_bytes: u64,
    gas: u64,
    base_fee_sat: u128,
    tip_fee_sat: u128,
    base_fee_millisat_per_gas: u128,
    tip_millisat_per_gas: u128,
) -> Plan {
    let mut plan = Plan {
        network: net_name(from.network()).into(),
        from_address: from.to_string(),
        to_address: to.to_string(),
        amount_sat,
        inputs: selected
            .iter()
            .map(|c| PlanInput { txid: hex::encode(c.txid), vout: c.vout, value_sat: c.value_sat })
            .collect(),
        change_sat,
        tx_bytes,
        tip_millisat_per_gas,
        base_fee_millisat_per_gas,
        gas,
        base_fee_sat,
        tip_fee_sat,
        signing_root: String::new(),
        txid: String::new(),
    };
    let tx = transfer_from_plan(&plan, &[], &[]).expect("a plan this function built re-derives");
    plan.signing_root = hex::encode(tx.spend_signing_root());
    plan.txid = hex::encode(tx.txid());
    plan
}

fn net_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

/// Reassemble the consensus transaction a plan describes. With an empty
/// pubkey/signature this yields the unsigned transfer whose signing root and
/// txid are the plan's (the root is witness-free by design); with the real
/// witness it yields the broadcastable transaction.
pub fn transfer_from_plan(
    plan: &Plan,
    pubkey: &[u8],
    signature: &[u8],
) -> Result<PosTransaction, String> {
    let from = Address::parse(&plan.from_address).map_err(|e| format!("from_address: {e}"))?;
    let to = Address::parse(&plan.to_address).map_err(|e| format!("to_address: {e}"))?;
    let mut inputs = Vec::with_capacity(plan.inputs.len());
    for i in &plan.inputs {
        let txid_v = hex::decode(&i.txid).map_err(|e| format!("input txid: {e}"))?;
        let txid: [u8; 32] =
            txid_v.try_into().map_err(|_| "input txid is not 32 bytes".to_string())?;
        inputs.push(TransferInput {
            txid,
            vout: i.vout,
            pubkey: pubkey.to_vec(),
            signature: signature.to_vec(),
        });
    }
    let mut outputs =
        vec![TransferOutput { value: plan.amount_sat, script_hash: script_hash32(&to) }];
    if plan.change_sat > 0 {
        outputs.push(TransferOutput { value: plan.change_sat, script_hash: script_hash32(&from) });
    }
    Ok(PosTransaction::Transfer {
        inputs,
        outputs,
        tx_bytes: plan.tx_bytes,
        tip_millisat_per_gas: plan.tip_millisat_per_gas,
    })
}

/// Re-derive the plan's signing root and txid and compare them to what the
/// plan file claims, plus every internal consistency rule. Every step after
/// `plan` calls this first — the file on disk is data, not authority.
pub fn check_plan_integrity(plan: &Plan) -> Result<(), String> {
    let from = Address::parse(&plan.from_address).map_err(|e| format!("from_address: {e}"))?;
    let to = Address::parse(&plan.to_address).map_err(|e| format!("to_address: {e}"))?;
    if from.network() != to.network() {
        return Err("plan crosses networks".into());
    }
    if net_name(from.network()) != plan.network {
        return Err("plan `network` does not match its addresses".into());
    }
    if plan.amount_sat < DUST_THRESHOLD_SAT {
        return Err("plan amount is sub-dust".into());
    }
    if plan.amount_sat > MAX_PARTNER_SEND_SAT {
        return Err(format!(
            "plan amount exceeds the {} BLCH cap",
            format_blch(MAX_PARTNER_SEND_SAT)
        ));
    }
    if plan.change_sat > 0 && plan.change_sat < DUST_THRESHOLD_SAT {
        return Err("plan carries sub-dust change".into());
    }
    if plan.inputs.is_empty() || plan.inputs.len() > MAX_INPUTS {
        return Err(format!("plan has {} inputs (allowed: 1..={MAX_INPUTS})", plan.inputs.len()));
    }
    // Exact conservation, the chain's own rule.
    let spent: u128 = plan.inputs.iter().map(|i| i.value_sat as u128).sum();
    let created = plan.amount_sat as u128 + plan.change_sat as u128;
    let fee = plan.base_fee_sat + plan.tip_fee_sat;
    if spent != created + fee {
        return Err(format!(
            "plan does not conserve value: inputs {spent} != outputs {created} + fee {fee}"
        ));
    }
    if fee > MAX_FEE_SAT {
        return Err(format!("plan fee {fee} sat exceeds the sanity cap"));
    }
    // The fee must be the consensus fee for these terms.
    let charge = fee_market::charge(
        TxClass::Eutxo { inputs: plan.inputs.len() as u32 },
        plan.tx_bytes,
        plan.base_fee_millisat_per_gas,
        plan.tip_millisat_per_gas,
    );
    if charge.gas != plan.gas
        || charge.base_fee_sat != plan.base_fee_sat
        || charge.priority_fee_sat != plan.tip_fee_sat
    {
        return Err("plan fee terms do not match the consensus fee market".into());
    }
    let tx = transfer_from_plan(plan, &[], &[])?;
    if hex::encode(tx.spend_signing_root()) != plan.signing_root {
        return Err("plan signing root does not match its own fields — the file was altered".into());
    }
    if hex::encode(tx.txid()) != plan.txid {
        return Err("plan txid does not match its signing root".into());
    }
    Ok(())
}

// ── Signing ─────────────────────────────────────────────────────────────────

/// Sign a checked plan with the supplied hybrid keypair and produce the
/// broadcastable [`SignedPlan`]. Refuses a key that does not own the source
/// address, an encoding that outgrows the declared `tx_bytes`, and a
/// signature that does not verify back.
pub fn sign_plan(plan: &Plan, pubkey: &[u8], secret: &[u8]) -> Result<SignedPlan, String> {
    check_plan_integrity(plan)?;
    let from = Address::parse(&plan.from_address).expect("checked");
    let derived = Address::from_pubkey(pubkey, from.network());
    if derived != from {
        return Err(format!(
            "this key does not own the source address: it derives {derived}, the plan spends \
             from {from}. Nothing was signed."
        ));
    }
    let root_v = hex::decode(&plan.signing_root).expect("checked");
    let root: [u8; 32] = root_v.try_into().expect("checked 32 bytes");
    let signature = bloch_crypto::crypto::sign(secret, &root)
        .map_err(|e| format!("hybrid signing failed: {e}"))?;
    if !bloch_crypto::crypto::verify(pubkey, &root, &signature) {
        return Err("the produced signature does not verify against the public key — refusing \
                    to emit it"
            .into());
    }
    let tx = transfer_from_plan(plan, pubkey, &signature)?;
    let raw = tx.canonical_bytes();
    if (raw.len() as u64) > plan.tx_bytes {
        return Err(format!(
            "the signed transaction is {} bytes but the plan declared tx_bytes {}; consensus \
             would refuse it (UnderdeclaredSize). Re-plan — the byte budget in this build is \
             too small for this key.",
            raw.len(),
            plan.tx_bytes
        ));
    }
    Ok(SignedPlan {
        plan: plan.clone(),
        pubkey: hex::encode(pubkey),
        signature: hex::encode(&signature),
        raw_tx: hex::encode(&raw),
    })
}

/// Everything `broadcast` re-checks before bytes leave the machine: plan
/// integrity, that `raw_tx` decodes to exactly the planned transfer with the
/// claimed witness, that the key owns the source, and that the signature
/// verifies over the recomputed root.
pub fn check_signed_plan(sp: &SignedPlan) -> Result<Vec<u8>, String> {
    check_plan_integrity(&sp.plan)?;
    let pubkey = hex::decode(&sp.pubkey).map_err(|e| format!("pubkey hex: {e}"))?;
    let signature = hex::decode(&sp.signature).map_err(|e| format!("signature hex: {e}"))?;
    let raw = hex::decode(&sp.raw_tx).map_err(|e| format!("raw_tx hex: {e}"))?;
    let expected = transfer_from_plan(&sp.plan, &pubkey, &signature)?;
    let decoded = PosTransaction::from_canonical_bytes(&raw)
        .map_err(|e| format!("raw_tx does not decode as a canonical transaction: {e:?}"))?;
    if decoded != expected {
        return Err("raw_tx does not match the plan it claims to implement".into());
    }
    let from = Address::parse(&sp.plan.from_address).expect("checked");
    if Address::from_pubkey(&pubkey, from.network()) != from {
        return Err("the witness key does not own the source address".into());
    }
    let root_v = hex::decode(&sp.plan.signing_root).expect("checked");
    let root: [u8; 32] = root_v.try_into().expect("checked 32 bytes");
    if !bloch_crypto::crypto::verify(&pubkey, &root, &signature) {
        return Err("signature does not verify over the signing root".into());
    }
    Ok(raw)
}

// ── Preview & confirmation ──────────────────────────────────────────────────

/// The text shown to the operator before anything is signed or sent — the
/// whole transfer, no elisions. This function IS the "what will be signed"
/// guarantee, so it renders from the plan's checked fields only.
pub fn preview(plan: &Plan) -> String {
    let mut s = String::new();
    let fee = plan.base_fee_sat + plan.tip_fee_sat;
    let spent: u128 = plan.inputs.iter().map(|i| i.value_sat as u128).sum();
    s.push_str("── TRANSFER TO BE SIGNED ─────────────────────────────────────\n");
    s.push_str(&format!("  network      {}\n", plan.network));
    s.push_str(&format!("  from         {}\n", plan.from_address));
    s.push_str(&format!("  to           {}\n", plan.to_address));
    s.push_str(&format!(
        "  amount       {} BLCH  ({} sat)\n",
        format_blch(plan.amount_sat),
        plan.amount_sat
    ));
    s.push_str(&format!("  inputs       {} coin(s), {} sat total\n", plan.inputs.len(), spent));
    for i in &plan.inputs {
        s.push_str(&format!(
            "               {}:{}  {} sat\n",
            &i.txid[..16],
            i.vout,
            i.value_sat
        ));
    }
    if plan.change_sat > 0 {
        s.push_str(&format!(
            "  change       {} BLCH ({} sat) back to the source address\n",
            format_blch(plan.change_sat),
            plan.change_sat
        ));
    } else {
        s.push_str("  change       none (inputs consumed exactly)\n");
    }
    s.push_str(&format!(
        "  fee          {} sat  ({} gas @ base {} + tip {} millisat/gas)\n",
        fee, plan.gas, plan.base_fee_millisat_per_gas, plan.tip_millisat_per_gas
    ));
    s.push_str(&format!("  tx_bytes     {} (declared, inside the signing root)\n", plan.tx_bytes));
    s.push_str(&format!("  signing root {}\n", plan.signing_root));
    s.push_str(&format!("  txid         {}\n", plan.txid));
    s.push_str("──────────────────────────────────────────────────────────────\n");
    s
}

/// The phrase the operator must type, verbatim, to proceed: it contains the
/// amount and the destination tail, so confirming *is* re-stating what moves
/// and to whom. Case-sensitive, exact.
pub fn confirmation_phrase(plan: &Plan) -> String {
    let tail = &plan.to_address[plan.to_address.len() - 8..];
    format!("SEND {} BLCH TO {}", format_blch(plan.amount_sat), tail)
}

// ── Key sources ─────────────────────────────────────────────────────────────

/// Parse a `bloch-pos` node keystore (`validator.key`, magic `BPOSKEY1`):
/// magic ‖ u32 index ‖ len-prefixed pubkey ‖ len-prefixed secret ‖ 32-byte
/// RANDAO seed. Implemented here because the node crate is a binary; the
/// format is four reads and a magic check.
pub fn parse_node_keystore(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let take = |b: &[u8], n: usize| -> Result<(Vec<u8>, usize), String> {
        if b.len() < n {
            return Err("truncated keystore".into());
        }
        Ok((b[..n].to_vec(), n))
    };
    if bytes.len() < 12 || &bytes[..8] != b"BPOSKEY1" {
        return Err("not a bloch-pos keystore (missing BPOSKEY1 magic)".into());
    }
    let mut off = 8 + 4; // magic + index
    let rd_len = |b: &[u8], off: usize| -> Result<usize, String> {
        if b.len() < off + 4 {
            return Err("truncated keystore".into());
        }
        Ok(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize)
    };
    let pk_len = rd_len(bytes, off)?;
    off += 4;
    let (pubkey, n) = take(&bytes[off..], pk_len)?;
    off += n;
    let sk_len = rd_len(bytes, off)?;
    off += 4;
    let (secret, n) = take(&bytes[off..], sk_len)?;
    off += n;
    if bytes.len() != off + 32 {
        return Err("trailing or missing bytes in keystore".into());
    }
    Ok((pubkey, secret))
}

/// Derive the hybrid keypair from a BIP39 seed phrase — the exact derivation
/// `bloch_crypto::wallet::Wallet::from_seed` performs (first 32 bytes of the
/// BIP39 seed into the seeded hybrid keygen), pinned against it by
/// `seed_derivation_matches_the_reference_wallet`.
pub fn keypair_from_seed_phrase(phrase: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let seed =
        bloch_crypto::wallet::SeedPhrase::parse(phrase).map_err(|e| format!("seed phrase: {e}"))?;
    let bytes = seed.to_seed_bytes();
    bloch_crypto::crypto::generate_keypair_from_seed(&bytes[..32])
        .map_err(|e| format!("keygen from seed: {e}"))
}

#[cfg(test)]
mod tests;
