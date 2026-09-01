// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core of `bloch-stake` — the pure, testable half.
//!
//! ## What this is
//!
//! The client side of the Genesis-4 staking lifecycle: build, preview, sign
//! and broadcast the four operator actions —
//!
//! - **deposit** — the eUTXO-funded validator registration
//!   (`PosTransaction::DepositV2`, wire tag `0x07`): real inputs and
//!   witnesses, the suite-framed hybrid key, a hybrid proof of possession
//!   over the key AND the withdrawal credentials, strict conservation
//!   (`sum(inputs) == amount + change + fee`), and a change output.
//! - **exit** — the signed voluntary exit (`staking::ExitTx`): a hybrid
//!   signature by the validator key over the exit signing root. The signed
//!   artifact is complete; a wire carrier for it does not exist yet (see
//!   `exit broadcast`'s refusal), so the artifact is produced and kept.
//! - **delegate** — the funded delegation. Its consensus seam
//!   (`CommittedState::apply_delegation`) exists behind
//!   `FUNDED_STAKING_ACTIVATION_EPOCH`; its wire format does not exist in
//!   any work stream yet, so the subcommand refuses with the full reason
//!   rather than inventing consensus bytes in a wallet.
//! - **withdraw** — the unauthenticated crank (`PosTransaction::Withdraw`)
//!   that pays an exited bond's residue to the credentials fixed at deposit
//!   time. Nothing to sign; everything to check.
//!
//! ## The consensus math is imported, not reimplemented
//!
//! Signing roots (`spend_signing_root`, `deposit_pop_signing_root`,
//! `ExitTx::signing_root`), canonical bytes, txids, the fee arithmetic
//! (`fee_market::charge`) and the per-validator cap
//! (`transition::deposit_cap_sat`) all come from `bloch-pos-committee` — the
//! crate the fleet's consensus runs. Conservation on this chain is an exact
//! equality; a second implementation of any of those quantities is a
//! one-satoshi drift away from a rejected bond.
//!
//! ## Refuse what the chain would refuse, at build time
//!
//! Every plan builder rejects, with the reason named:
//! - a format whose activation epoch has not arrived (naming the epoch);
//! - a bond below `MIN_DEPOSIT_SAT` or above the chain-derived
//!   per-validator cap;
//! - sub-dust change (and sub-dust anything this tool would create);
//! - a withdrawal before the record's committed `withdrawable_epoch`;
//! - an exit for a validator the signing key does not control
//!   (checked against the registry's committed `pubkey_hash`).
//!
//! ## The discipline is `partner-send`'s
//!
//! Typed confirmation phrase at a real terminal, no `--yes`, no unattended
//! path, hard caps with no override flags, `plan` / `sign` / `broadcast`
//! split so the key never has to touch the connected machine.

pub mod rpc;

use bloch_crypto::address::{Address, Network};
use bloch_pos_committee::beacon::RandaoChain;
use bloch_pos_committee::fee_market::{self, TxClass};
use bloch_pos_committee::staking::{
    self, parse_framed_pubkey, DepositInput, DepositReject, DepositTx, ExitTx,
    FRAMED_HYBRID_PK_BYTES, MIN_DEPOSIT_SAT,
};
use bloch_pos_committee::transition::{
    deposit_cap_sat, PosTransaction, TransferInput, TransferOutput,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// ── Policy constants (this tool's, not consensus) ───────────────────────────

/// Minimum value this tool will give any output it creates, in satoshis —
/// the Genesis-3 dust floor, kept as a build-time refusal for the same
/// reason `partner-send` keeps it: a sub-dust output once poisoned every
/// block that included it.
pub const DUST_THRESHOLD_SAT: u64 = 546;

/// Fee sanity ceiling: refuse any staking transaction whose fee exceeds
/// 1 BLCH. A deposit is one PoP plus one hybrid verification per input; a
/// fee orders of magnitude above the floor means a mispriced base fee, a
/// fat-fingered tip, or a bug — all reasons to stop.
pub const MAX_FEE_SAT: u128 = 100_000_000;

/// Most inputs one deposit may consume. A bond needing more than 32 coins
/// means the funding address is the wrong source — consolidate first.
pub const MAX_INPUTS: usize = 32;

/// Default tip, millisatoshi per gas — the node's own `submit-tx` default.
pub const DEFAULT_TIP_MILLISAT_PER_GAS: u128 = 1_000;

/// Satoshi per BLCH, for display only — **taken from the consensus crate**
/// rather than restated. It is the divisor in every amount this tool prints
/// and every amount an operator types back in a confirmation phrase, so a
/// drift here would not build an invalid transaction; it would build a valid
/// transaction for the wrong amount, which is worse (consensus cannot catch
/// it). The narrowing to `u64` is checked below.
pub const SAT_PER_BLCH: u64 = bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH as u64;

const _: () = assert!(
    SAT_PER_BLCH as u128 == bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH,
    "SAT_PER_BLCH must narrow tokenomics_v4::SAT_PER_BLOCH without loss"
);

// Witness size budgets for the declared `tx_bytes` (inside the signing
// root, so fixed before the variable-length Falcon half exists). The real
// framed pubkey is 3,749 bytes and a hybrid signature ≤ ~4,643; consensus
// only refuses a declaration BELOW the encoding.
const PUBKEY_BYTES_BUDGET: usize = 3_800;
const SIG_BYTES_BUDGET: usize = 4_700;
const TX_BYTES_SLACK: u64 = 128;

// ── Amounts (identical rules to partner-send) ───────────────────────────────

/// Parse a BLCH amount string ("25000", "0.5", "1.00000001") into satoshis.
/// Strict: digits, at most one '.', at most 8 fractional digits, > 0.
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

/// Render satoshis as a BLCH string with no trailing zeros.
pub fn format_blch(sat: u128) -> String {
    let whole = sat / SAT_PER_BLCH as u128;
    let frac = sat % SAT_PER_BLCH as u128;
    if frac == 0 {
        format!("{whole}")
    } else {
        let f = format!("{frac:08}");
        format!("{whole}.{}", f.trim_end_matches('0'))
    }
}

/// The 32-byte `script_hash` the Genesis-4 UTXO set keys an address's
/// outputs by: the 20-byte pubkey hash, zero-padded to 32.
pub fn script_hash32(addr: &Address) -> [u8; 32] {
    let mut sh = [0u8; 32];
    sh[..20].copy_from_slice(addr.hash_bytes());
    sh
}

fn net_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

/// One selectable coin of the funding address, as read from `getutxos`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

// ── Activation gates ────────────────────────────────────────────────────────

/// The four staking formats and their flag-day constants, spelled once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakingFormat {
    DepositV2,
    SignedExit,
    FundedDelegate,
    Withdraw,
}

impl StakingFormat {
    pub fn constant_name(self) -> &'static str {
        match self {
            StakingFormat::DepositV2 => "FUNDED_STAKING_ACTIVATION_EPOCH",
            StakingFormat::SignedExit => "SIGNED_EXIT_ACTIVATION_EPOCH",
            StakingFormat::FundedDelegate => "FUNDED_STAKING_ACTIVATION_EPOCH",
            StakingFormat::Withdraw => "WITHDRAWAL_ACTIVATION_EPOCH",
        }
    }
    /// The activation epoch, read from the consensus crate — never restated.
    pub fn activation_epoch(self) -> u64 {
        use bloch_pos_committee::params as p;
        match self {
            StakingFormat::DepositV2 => p::FUNDED_STAKING_ACTIVATION_EPOCH,
            StakingFormat::SignedExit => p::SIGNED_EXIT_ACTIVATION_EPOCH,
            StakingFormat::FundedDelegate => p::FUNDED_STAKING_ACTIVATION_EPOCH,
            StakingFormat::Withdraw => p::WITHDRAWAL_ACTIVATION_EPOCH,
        }
    }
    pub fn describe(self) -> &'static str {
        match self {
            StakingFormat::DepositV2 => "funded deposits (DepositV2, wire tag 0x07)",
            StakingFormat::SignedExit => "signed voluntary exits (staking::ExitTx)",
            StakingFormat::FundedDelegate => "funded delegation",
            StakingFormat::Withdraw => "withdrawals (PosTransaction::Withdraw)",
        }
    }
}

/// Refuse to build a transaction whose format the chain would refuse at the
/// current epoch — the same verdict the transition's flag-day gate reaches,
/// reached here before a key is touched. `rehearsal` lifts ONLY this gate
/// (the artifact is then marked non-broadcastable; `broadcast` refuses it).
pub fn check_format_active(
    format: StakingFormat,
    current_epoch: u64,
    rehearsal: bool,
) -> Result<(), String> {
    let activation = format.activation_epoch();
    if current_epoch >= activation {
        return Ok(());
    }
    if rehearsal {
        return Ok(());
    }
    let when = if activation == u64::MAX {
        "INERT (u64::MAX — no flag day has been armed)".to_string()
    } else {
        format!("epoch {activation}")
    };
    Err(format!(
        "{} are not active on this chain: the flag day `{}` is {}, and the chain is at epoch \
         {}. A block carrying this format today would be rejected by every node, so this tool \
         refuses to build it. To rehearse the flow without broadcasting, re-run with \
         --rehearsal: the artifact is marked and `broadcast` will refuse it.",
        format.describe(),
        format.constant_name(),
        when,
        current_epoch,
    ))
}

// ── Key sources (shared by the sign paths) ──────────────────────────────────

/// Parse a `bloch-pos` node keystore (`validator.key`, magic `BPOSKEY1`):
/// magic ‖ u32 index ‖ len-prefixed pubkey ‖ len-prefixed secret ‖ 32-byte
/// RANDAO seed.
pub fn parse_node_keystore(bytes: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>, [u8; 32]), String> {
    if bytes.len() < 12 || &bytes[..8] != b"BPOSKEY1" {
        return Err("not a bloch-pos keystore (missing BPOSKEY1 magic)".into());
    }
    let index = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mut off = 12;
    let rd_len = |b: &[u8], off: usize| -> Result<usize, String> {
        if b.len() < off + 4 {
            return Err("truncated keystore".into());
        }
        Ok(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize)
    };
    let pk_len = rd_len(bytes, off)?;
    off += 4;
    if bytes.len() < off + pk_len {
        return Err("truncated keystore".into());
    }
    let pubkey = bytes[off..off + pk_len].to_vec();
    off += pk_len;
    let sk_len = rd_len(bytes, off)?;
    off += 4;
    if bytes.len() < off + sk_len {
        return Err("truncated keystore".into());
    }
    let secret = bytes[off..off + sk_len].to_vec();
    off += sk_len;
    if bytes.len() != off + 32 {
        return Err("trailing or missing bytes in keystore".into());
    }
    let randao_seed: [u8; 32] = bytes[off..off + 32].try_into().unwrap();
    Ok((index, pubkey, secret, randao_seed))
}

/// Derive the hybrid keypair from a BIP39 seed phrase — the exact derivation
/// the reference wallet performs.
pub fn keypair_from_seed_phrase(phrase: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let seed =
        bloch_crypto::wallet::SeedPhrase::parse(phrase).map_err(|e| format!("seed phrase: {e}"))?;
    let bytes = seed.to_seed_bytes();
    bloch_crypto::crypto::generate_keypair_from_seed(&bytes[..32])
        .map_err(|e| format!("keygen from seed: {e}"))
}

/// The RANDAO commitment `c_0` for a keystore's seed — the one derivation
/// (`beacon::RandaoChain`), shared with the node's `keygen-public`.
pub fn randao_commitment_from_seed(seed: [u8; 32]) -> [u8; 32] {
    RandaoChain::generate(seed).commitment()
}

// ═════════════════════════════════════════════════════════════ DEPOSIT ═════

/// Everything a funded deposit commits to, fixed at `plan` time and carried
/// between the plan/sign/broadcast steps as JSON. Every later step re-derives
/// the roots from these fields — the file is data, not authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepositPlan {
    /// Always "deposit" — a plan file names what it is so `sign` cannot be
    /// pointed at the wrong artifact.
    pub kind: String,
    /// True when the activation-epoch gate was bypassed for rehearsal.
    /// A rehearsal artifact is NEVER broadcastable.
    pub rehearsal: bool,
    pub network: String,
    /// The address funding the bond (its coins are spent).
    pub funding_address: String,
    /// Where the principal returns after withdrawal — fixed here, covered by
    /// the PoP, never changeable later.
    pub withdrawal_address: String,
    /// Suite-framed hybrid validator pubkey (`B1 0C ‖ suite ‖ ML-DSA-65 ‖
    /// Falcon-1024`), hex. 3,749 bytes decoded.
    pub validator_pubkey: String,
    /// SHA3-256 of the framed pubkey — the registry identity.
    pub validator_pubkey_hash: String,
    /// `c_0`, head of the SHAKE-256 reveal chain.
    pub randao_commitment: String,
    pub commission_bps: u128,
    /// The bond, in satoshis.
    pub amount_sat: u128,
    pub inputs: Vec<PlanInput>,
    /// Change back to the funding address (0 = no change output).
    pub change_sat: u64,
    pub tx_bytes: u64,
    pub tip_millisat_per_gas: u128,
    pub base_fee_millisat_per_gas: u128,
    pub gas: u64,
    pub base_fee_sat: u128,
    pub tip_fee_sat: u128,
    /// Chain facts the plan was validated against (for the preview and the
    /// broadcast preflight; consensus re-checks against inclusion-time state).
    pub planned_epoch: u64,
    pub cap_sat: u128,
    /// DS_DEPOSIT_FUND root — what each funding input's owner signs.
    pub spend_signing_root: String,
    /// DS_DEPOSIT (§7.1) root — what the validator key signs as its proof
    /// of possession.
    pub pop_signing_root: String,
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanInput {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
}

/// A deposit plan plus its witnesses. Both roles may be filled in one `sign`
/// run or across two (split custody: the coin owner and the validator key
/// holder need never share a machine). `broadcast` requires both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDeposit {
    pub plan: DepositPlan,
    /// The funding owner's pubkey + signature over `spend_signing_root`
    /// (one key owns all inputs in this tool's plans).
    pub funding_pubkey: Option<String>,
    pub funding_signature: Option<String>,
    /// The validator key's hybrid signature over `pop_signing_root`.
    pub proof_of_possession: Option<String>,
}

/// Why a deposit could not be built. Every variant is a refusal the chain
/// itself would issue, reached before any key is touched.
#[derive(Debug, PartialEq, Eq)]
pub enum DepositBuildError {
    NotActive(String),
    BadValidatorKey(String),
    WrongSuite { suite: u16 },
    BelowMinimum { amount_sat: u128, min_sat: u128 },
    AboveCap { amount_sat: u128, cap_sat: u128 },
    AlreadyRegistered { index: u32 },
    NetworkMismatch { funding: String, withdrawal: String },
    InsufficientFunds { need_sat: u128, have_sat: u128 },
    DustChange { change_sat: u64, bond_less_sat: u128, bond_more_sat: u128 },
    FeeAboveSanityCap { fee_sat: u128 },
    TooManyInputs { needed_more_than: usize },
}

impl std::fmt::Display for DepositBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DepositBuildError::NotActive(msg) => write!(f, "{msg}"),
            DepositBuildError::BadValidatorKey(msg) => write!(
                f,
                "validator pubkey is not a suite-framed hybrid key ({msg}); consensus parses \
                 the frame (`B1 0C ‖ suite ‖ ML-DSA-65 ‖ Falcon-1024`, {FRAMED_HYBRID_PK_BYTES} \
                 bytes) and refuses any other shape"
            ),
            DepositBuildError::WrongSuite { suite } => write!(
                f,
                "validator key declares suite {suite:#06x}; consensus accepts only the hybrid \
                 ML-DSA-65 ‖ Falcon-1024 suite (0x0001) — DepositReject::WrongSuite"
            ),
            DepositBuildError::BelowMinimum { amount_sat, min_sat } => write!(
                f,
                "bond {} BLCH is below MIN_DEPOSIT_SAT ({} BLCH); consensus refuses it \
                 (DepositReject::BelowMinimum)",
                format_blch(*amount_sat),
                format_blch(*min_sat)
            ),
            DepositBuildError::AboveCap { amount_sat, cap_sat } => write!(
                f,
                "bond {} BLCH exceeds the per-validator cap of {} BLCH (1% of committed active \
                 stake, floored at the minimum deposit — derived by the consensus crate's \
                 deposit_cap_sat from the chain's total_active_stake_sat); consensus refuses \
                 it (DepositReject::AboveMaximum)",
                format_blch(*amount_sat),
                format_blch(*cap_sat)
            ),
            DepositBuildError::AlreadyRegistered { index } => write!(
                f,
                "this validator pubkey is already registered (validator index {index}); a \
                 second deposit of a registered key is refused by consensus — there is no \
                 top-up path"
            ),
            DepositBuildError::NetworkMismatch { funding, withdrawal } => write!(
                f,
                "funding address is {funding} but withdrawal address is {withdrawal}; refusing \
                 a cross-network deposit"
            ),
            DepositBuildError::InsufficientFunds { need_sat, have_sat } => write!(
                f,
                "insufficient funds: need {need_sat} sat (bond + fee), funding address holds \
                 {have_sat} sat across its first {MAX_INPUTS} largest coins"
            ),
            DepositBuildError::DustChange { change_sat, bond_less_sat, bond_more_sat } => write!(
                f,
                "refusing to create sub-dust change of {change_sat} sat (< \
                 {DUST_THRESHOLD_SAT}). Bond {} BLCH instead (change lands on the dust floor) \
                 or {} BLCH (consumes the selected coins exactly, no change).",
                format_blch(*bond_less_sat),
                format_blch(*bond_more_sat)
            ),
            DepositBuildError::FeeAboveSanityCap { fee_sat } => write!(
                f,
                "computed fee {fee_sat} sat exceeds the {MAX_FEE_SAT}-sat sanity cap; the base \
                 fee or tip is mispriced — not building"
            ),
            DepositBuildError::TooManyInputs { needed_more_than } => write!(
                f,
                "funding this bond needs more than {needed_more_than} inputs; consolidate the \
                 funding address first"
            ),
        }
    }
}

/// The exact canonical size a signed deposit can reach, measured through the
/// CONSENSUS ENCODER with witness placeholders at the byte budgets — never a
/// hand-written size formula that could drift from the codec.
fn deposit_tx_bytes_budget(n_inputs: usize, change_outputs: usize) -> u64 {
    let placeholder_inputs: Vec<TransferInput> = (0..n_inputs)
        .map(|i| TransferInput {
            txid: [0u8; 32],
            vout: i as u32,
            pubkey: vec![0xAA; PUBKEY_BYTES_BUDGET],
            signature: vec![0xAA; SIG_BYTES_BUDGET],
        })
        .collect();
    let change: Vec<TransferOutput> =
        (0..change_outputs).map(|_| TransferOutput { value: 1, script_hash: [0u8; 32] }).collect();
    let probe = PosTransaction::DepositV2 {
        inputs: placeholder_inputs,
        pubkey: vec![0xAA; PUBKEY_BYTES_BUDGET],
        amount_sat: u128::MAX,
        randao_commitment: [0u8; 32],
        withdrawal_addr: [0u8; 32],
        commission_bps: u128::MAX,
        proof_of_possession: vec![0xAA; SIG_BYTES_BUDGET],
        change,
        tx_bytes: u64::MAX,
        tip_millisat_per_gas: u128::MAX,
    };
    probe.canonical_bytes().len() as u64 + TX_BYTES_SLACK
}

fn deposit_fee_for(
    n_inputs: usize,
    change_outputs: usize,
    base: u128,
    tip: u128,
) -> (u64, u64, u128, u128) {
    let tx_bytes = deposit_tx_bytes_budget(n_inputs, change_outputs);
    // `inputs + 1`: one hybrid verification per input plus the PoP — the
    // gas class the consensus arm (`apply_deposit_v2`) charges.
    let charge = fee_market::charge(
        TxClass::Eutxo { inputs: (n_inputs as u32).saturating_add(1) },
        tx_bytes,
        base,
        tip,
    );
    (tx_bytes, charge.gas, charge.base_fee_sat, charge.priority_fee_sat)
}

/// Build a deposit plan. Pure — the caller supplies the coins, the chain
/// facts and the (already parsed) validator material.
#[allow(clippy::too_many_arguments)]
pub fn build_deposit_plan(
    funding: &Address,
    withdrawal: &Address,
    validator_pubkey_framed: &[u8],
    randao_commitment: [u8; 32],
    commission_bps: u128,
    amount_sat: u128,
    coins: &[Coin],
    chain_epoch: u64,
    total_active_stake_sat: u128,
    base_fee_millisat_per_gas: u128,
    tip_millisat_per_gas: u128,
    registered_pubkey_hashes: &[(u32, [u8; 32])],
    rehearsal: bool,
) -> Result<DepositPlan, DepositBuildError> {
    check_format_active(StakingFormat::DepositV2, chain_epoch, rehearsal)
        .map_err(DepositBuildError::NotActive)?;

    if funding.network() != withdrawal.network() {
        return Err(DepositBuildError::NetworkMismatch {
            funding: net_name(funding.network()).into(),
            withdrawal: net_name(withdrawal.network()).into(),
        });
    }

    // The framed key must parse to exactly the hybrid arrangement — the
    // consensus parser, not a re-derivation.
    let Some((suite, raw_pk)) = parse_framed_pubkey(validator_pubkey_framed) else {
        return Err(DepositBuildError::BadValidatorKey(format!(
            "{} bytes; wrong length or wrong magic",
            validator_pubkey_framed.len()
        )));
    };

    // §7.1/§4.1 field rules — the ONE derivation consensus itself runs
    // (`staking::validate_deposit_fields`), with the cap derived by the
    // consensus crate from the chain's committed active stake.
    let cap_sat = deposit_cap_sat(total_active_stake_sat);
    let dep = DepositTx {
        suite,
        amount_sat,
        validator_pubkey: *raw_pk,
        randao_commitment,
        withdrawal_addr: script_hash32(withdrawal),
        proof_of_possession: Vec::new(),
    };
    let facts = [DepositInput { transparent: true, tainted: false }];
    if let Err(e) = staking::validate_deposit_fields(&dep, &facts, cap_sat) {
        return Err(match e {
            DepositReject::WrongSuite => DepositBuildError::WrongSuite { suite },
            DepositReject::BelowMinimum => {
                DepositBuildError::BelowMinimum { amount_sat, min_sat: MIN_DEPOSIT_SAT }
            }
            DepositReject::AboveMaximum => DepositBuildError::AboveCap { amount_sat, cap_sat },
            other => DepositBuildError::BadValidatorKey(format!("{other:?}")),
        });
    }

    // Registry-dependent: a second deposit of a registered key is refused by
    // consensus; catch it now while it costs nothing.
    let pubkey_hash: [u8; 32] = Sha3_256::digest(validator_pubkey_framed).into();
    if let Some((index, _)) =
        registered_pubkey_hashes.iter().find(|(_, h)| *h == pubkey_hash)
    {
        return Err(DepositBuildError::AlreadyRegistered { index: *index });
    }

    // Coin selection: largest-first, deterministic, same discipline as
    // partner-send. The fee depends on the input count, so selection and
    // pricing iterate together.
    let mut sorted: Vec<&Coin> = coins.iter().collect();
    sorted.sort_by(|a, b| {
        b.value_sat.cmp(&a.value_sat).then(a.txid.cmp(&b.txid)).then(a.vout.cmp(&b.vout))
    });
    let take = sorted.len().min(MAX_INPUTS);
    let mut sum: u128 = 0;
    let mut dust_trap: Option<u64> = None;
    for n in 1..=take {
        sum += sorted[n - 1].value_sat as u128;
        // Priced with a change output; if change turns out zero the declared
        // tx_bytes over-declares by one output, which consensus permits.
        let (tx_bytes, gas, base_fee_sat, tip_fee_sat) =
            deposit_fee_for(n, 1, base_fee_millisat_per_gas, tip_millisat_per_gas);
        let fee = base_fee_sat + tip_fee_sat;
        let need = amount_sat + fee;
        if sum < need {
            continue;
        }
        let Ok(change) = u64::try_from(sum - need) else {
            return Err(DepositBuildError::FeeAboveSanityCap { fee_sat: fee });
        };
        if change > 0 && change < DUST_THRESHOLD_SAT {
            dust_trap = Some(dust_trap.map_or(change, |c| c.max(change)));
            continue;
        }
        if fee > MAX_FEE_SAT {
            return Err(DepositBuildError::FeeAboveSanityCap { fee_sat: fee });
        }
        let selected = &sorted[..n];
        let mut plan = DepositPlan {
            kind: "deposit".into(),
            rehearsal,
            network: net_name(funding.network()).into(),
            funding_address: funding.to_string(),
            withdrawal_address: withdrawal.to_string(),
            validator_pubkey: hex::encode(validator_pubkey_framed),
            validator_pubkey_hash: hex::encode(pubkey_hash),
            randao_commitment: hex::encode(randao_commitment),
            commission_bps,
            amount_sat,
            inputs: selected
                .iter()
                .map(|c| PlanInput {
                    txid: hex::encode(c.txid),
                    vout: c.vout,
                    value_sat: c.value_sat,
                })
                .collect(),
            change_sat: change,
            tx_bytes,
            tip_millisat_per_gas,
            base_fee_millisat_per_gas,
            gas,
            base_fee_sat,
            tip_fee_sat,
            planned_epoch: chain_epoch,
            cap_sat,
            spend_signing_root: String::new(),
            pop_signing_root: String::new(),
            txid: String::new(),
        };
        let tx = deposit_tx_from_plan(&plan, &[], &[], &[])
            .expect("a plan this function built re-derives");
        plan.spend_signing_root = hex::encode(tx.spend_signing_root());
        plan.pop_signing_root = hex::encode(
            tx.deposit_pop_signing_root()
                .expect("the framed pubkey parsed above"),
        );
        plan.txid = hex::encode(tx.txid());
        return Ok(plan);
    }

    if let Some(change) = dust_trap {
        return Err(DepositBuildError::DustChange {
            change_sat: change,
            bond_less_sat: amount_sat - (DUST_THRESHOLD_SAT - change) as u128,
            bond_more_sat: amount_sat + change as u128,
        });
    }
    let (_, _, b, t) =
        deposit_fee_for(take.max(1), 1, base_fee_millisat_per_gas, tip_millisat_per_gas);
    let need = amount_sat + b + t;
    let total_all: u128 = coins.iter().map(|c| c.value_sat as u128).sum();
    if sorted.len() > MAX_INPUTS && total_all >= need {
        return Err(DepositBuildError::TooManyInputs { needed_more_than: MAX_INPUTS });
    }
    Err(DepositBuildError::InsufficientFunds { need_sat: need, have_sat: sum })
}

/// Reassemble the consensus transaction a deposit plan describes. With empty
/// witnesses this yields the unsigned deposit whose roots and txid are the
/// plan's (both roots are witness-free by design); with the real witnesses
/// it yields the broadcastable transaction.
pub fn deposit_tx_from_plan(
    plan: &DepositPlan,
    funding_pubkey: &[u8],
    funding_signature: &[u8],
    proof_of_possession: &[u8],
) -> Result<PosTransaction, String> {
    if plan.kind != "deposit" {
        return Err(format!("this is a `{}` artifact, not a deposit plan", plan.kind));
    }
    let funding =
        Address::parse(&plan.funding_address).map_err(|e| format!("funding_address: {e}"))?;
    let withdrawal = Address::parse(&plan.withdrawal_address)
        .map_err(|e| format!("withdrawal_address: {e}"))?;
    let pubkey = hex::decode(&plan.validator_pubkey)
        .map_err(|e| format!("validator_pubkey hex: {e}"))?;
    let rc_v = hex::decode(&plan.randao_commitment)
        .map_err(|e| format!("randao_commitment hex: {e}"))?;
    let randao_commitment: [u8; 32] =
        rc_v.try_into().map_err(|_| "randao_commitment is not 32 bytes".to_string())?;
    let mut inputs = Vec::with_capacity(plan.inputs.len());
    for i in &plan.inputs {
        let txid_v = hex::decode(&i.txid).map_err(|e| format!("input txid: {e}"))?;
        let txid: [u8; 32] =
            txid_v.try_into().map_err(|_| "input txid is not 32 bytes".to_string())?;
        inputs.push(TransferInput {
            txid,
            vout: i.vout,
            pubkey: funding_pubkey.to_vec(),
            signature: funding_signature.to_vec(),
        });
    }
    let change = if plan.change_sat > 0 {
        vec![TransferOutput { value: plan.change_sat, script_hash: script_hash32(&funding) }]
    } else {
        Vec::new()
    };
    Ok(PosTransaction::DepositV2 {
        inputs,
        pubkey,
        amount_sat: plan.amount_sat,
        randao_commitment,
        withdrawal_addr: script_hash32(&withdrawal),
        commission_bps: plan.commission_bps,
        proof_of_possession: proof_of_possession.to_vec(),
        change,
        tx_bytes: plan.tx_bytes,
        tip_millisat_per_gas: plan.tip_millisat_per_gas,
    })
}

/// Re-derive everything a deposit plan claims and refuse a file that was
/// altered. Every step after `plan` calls this first.
pub fn check_deposit_plan(plan: &DepositPlan) -> Result<(), String> {
    if plan.kind != "deposit" {
        return Err(format!("this is a `{}` artifact, not a deposit plan", plan.kind));
    }
    let funding =
        Address::parse(&plan.funding_address).map_err(|e| format!("funding_address: {e}"))?;
    let withdrawal = Address::parse(&plan.withdrawal_address)
        .map_err(|e| format!("withdrawal_address: {e}"))?;
    if funding.network() != withdrawal.network() {
        return Err("plan crosses networks".into());
    }
    if net_name(funding.network()) != plan.network {
        return Err("plan `network` does not match its addresses".into());
    }
    let pubkey = hex::decode(&plan.validator_pubkey)
        .map_err(|e| format!("validator_pubkey hex: {e}"))?;
    let Some((suite, _)) = parse_framed_pubkey(&pubkey) else {
        return Err("plan validator_pubkey is not a suite-framed hybrid key".into());
    };
    if suite != staking::SUITE_MLDSA65_FALCON1024 {
        return Err(format!("plan validator key declares unsupported suite {suite:#06x}"));
    }
    let expect_hash: [u8; 32] = Sha3_256::digest(&pubkey).into();
    if hex::encode(expect_hash) != plan.validator_pubkey_hash {
        return Err("plan validator_pubkey_hash does not match its pubkey".into());
    }
    if plan.amount_sat < MIN_DEPOSIT_SAT {
        return Err(format!(
            "plan bond is below MIN_DEPOSIT_SAT ({} BLCH)",
            format_blch(MIN_DEPOSIT_SAT)
        ));
    }
    if plan.change_sat > 0 && plan.change_sat < DUST_THRESHOLD_SAT {
        return Err("plan carries sub-dust change".into());
    }
    if plan.inputs.is_empty() || plan.inputs.len() > MAX_INPUTS {
        return Err(format!(
            "plan has {} inputs (allowed: 1..={MAX_INPUTS})",
            plan.inputs.len()
        ));
    }
    // Exact conservation — the chain's own rule, checked byte-for-byte:
    // sum(inputs) == amount + change + fee.
    let spent: u128 = plan.inputs.iter().map(|i| i.value_sat as u128).sum();
    let fee = plan.base_fee_sat + plan.tip_fee_sat;
    if spent != plan.amount_sat + plan.change_sat as u128 + fee {
        return Err(format!(
            "plan does not conserve value: inputs {spent} != bond {} + change {} + fee {fee}",
            plan.amount_sat, plan.change_sat
        ));
    }
    if fee > MAX_FEE_SAT {
        return Err(format!("plan fee {fee} sat exceeds the sanity cap"));
    }
    // The fee must be the consensus fee for these terms (inputs + 1 for the
    // PoP — the gas class apply_deposit_v2 charges).
    let charge = fee_market::charge(
        TxClass::Eutxo { inputs: (plan.inputs.len() as u32).saturating_add(1) },
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
    let tx = deposit_tx_from_plan(plan, &[], &[], &[])?;
    if hex::encode(tx.spend_signing_root()) != plan.spend_signing_root {
        return Err(
            "plan spend signing root does not match its own fields — the file was altered".into()
        );
    }
    let pop_root = tx
        .deposit_pop_signing_root()
        .ok_or_else(|| "plan pubkey stopped parsing (impossible past the checks above)".to_string())?;
    if hex::encode(pop_root) != plan.pop_signing_root {
        return Err("plan PoP signing root does not match its own fields".into());
    }
    if hex::encode(tx.txid()) != plan.txid {
        return Err("plan txid does not match its signing root".into());
    }
    Ok(())
}

/// Fill the FUNDING role: sign the DS_DEPOSIT_FUND root with the key that
/// owns the spent coins. Refuses a key that does not own the funding address.
pub fn sign_deposit_funding(
    sd: &mut SignedDeposit,
    pubkey: &[u8],
    secret: &[u8],
) -> Result<(), String> {
    check_deposit_plan(&sd.plan)?;
    let funding = Address::parse(&sd.plan.funding_address).expect("checked");
    let derived = Address::from_pubkey(pubkey, funding.network());
    if derived != funding {
        return Err(format!(
            "this key does not own the funding address: it derives {derived}, the plan spends \
             from {funding}. Nothing was signed."
        ));
    }
    let root = root32(&sd.plan.spend_signing_root);
    let signature = bloch_crypto::crypto::sign(secret, &root)
        .map_err(|e| format!("hybrid signing failed: {e}"))?;
    if !bloch_crypto::crypto::verify(pubkey, &root, &signature) {
        return Err("the produced funding signature does not verify — refusing to emit it".into());
    }
    sd.funding_pubkey = Some(hex::encode(pubkey));
    sd.funding_signature = Some(hex::encode(signature));
    Ok(())
}

/// Fill the PROOF-OF-POSSESSION role: the VALIDATOR key signs the §7.1 root
/// covering the pubkey, amount, RANDAO commitment and withdrawal
/// credentials. Refuses a key that is not the plan's validator key.
pub fn sign_deposit_pop(
    sd: &mut SignedDeposit,
    validator_pubkey: &[u8],
    validator_secret: &[u8],
) -> Result<(), String> {
    check_deposit_plan(&sd.plan)?;
    if hex::encode(validator_pubkey) != sd.plan.validator_pubkey {
        return Err(
            "this keystore's pubkey is not the plan's validator key — the proof of possession \
             must be produced by the exact key being registered. Nothing was signed."
                .into(),
        );
    }
    let root = root32(&sd.plan.pop_signing_root);
    let pop = bloch_crypto::crypto::sign(validator_secret, &root)
        .map_err(|e| format!("hybrid signing failed: {e}"))?;
    if !bloch_crypto::crypto::verify(validator_pubkey, &root, &pop) {
        return Err("the produced proof of possession does not verify — refusing to emit it".into());
    }
    sd.proof_of_possession = Some(hex::encode(pop));
    Ok(())
}

fn root32(hex_root: &str) -> [u8; 32] {
    let v = hex::decode(hex_root).expect("checked by plan integrity");
    v.try_into().expect("checked 32 bytes")
}

/// Everything `broadcast` re-checks before deposit bytes leave the machine.
/// Returns the canonical bytes. Refuses a rehearsal artifact, an incomplete
/// witness set, a mismatched signature, and an encoding above the declared
/// `tx_bytes`.
pub fn check_signed_deposit(sd: &SignedDeposit) -> Result<Vec<u8>, String> {
    check_deposit_plan(&sd.plan)?;
    if sd.plan.rehearsal {
        return Err(
            "this is a REHEARSAL artifact: it was planned while the format's flag day \
             had not arrived, and it must never be broadcast. Re-plan without --rehearsal \
             once the activation epoch is live."
                .into(),
        );
    }
    let (Some(fpk), Some(fsig)) = (&sd.funding_pubkey, &sd.funding_signature) else {
        return Err("the funding witness is missing — run `deposit sign --only funding` \
                    (or a full `deposit sign`) first"
            .into());
    };
    let Some(pop) = &sd.proof_of_possession else {
        return Err("the proof of possession is missing — run `deposit sign --only pop` \
                    (or a full `deposit sign`) first"
            .into());
    };
    let fpk = hex::decode(fpk).map_err(|e| format!("funding_pubkey hex: {e}"))?;
    let fsig = hex::decode(fsig).map_err(|e| format!("funding_signature hex: {e}"))?;
    let pop = hex::decode(pop).map_err(|e| format!("proof_of_possession hex: {e}"))?;

    let funding = Address::parse(&sd.plan.funding_address).expect("checked");
    if Address::from_pubkey(&fpk, funding.network()) != funding {
        return Err("the funding witness key does not own the funding address".into());
    }
    let spend_root = root32(&sd.plan.spend_signing_root);
    if !bloch_crypto::crypto::verify(&fpk, &spend_root, &fsig) {
        return Err("funding signature does not verify over the spend signing root".into());
    }
    let vpk = hex::decode(&sd.plan.validator_pubkey).expect("checked");
    let pop_root = root32(&sd.plan.pop_signing_root);
    if !bloch_crypto::crypto::verify(&vpk, &pop_root, &pop) {
        return Err("proof of possession does not verify under the validator key".into());
    }

    let tx = deposit_tx_from_plan(&sd.plan, &fpk, &fsig, &pop)?;
    let raw = tx.canonical_bytes();
    if (raw.len() as u64) > sd.plan.tx_bytes {
        return Err(format!(
            "the signed deposit is {} bytes but the plan declared tx_bytes {}; consensus \
             would refuse it (UnderdeclaredSize). Re-plan — the byte budget in this build is \
             too small for these keys.",
            raw.len(),
            sd.plan.tx_bytes
        ));
    }
    // Round-trip through the REAL decoder: what will be gossiped must decode
    // to exactly what was authorised.
    let decoded = PosTransaction::from_canonical_bytes(&raw)
        .map_err(|e| format!("the signed deposit does not decode canonically: {e:?}"))?;
    if decoded != tx {
        return Err("the canonical bytes do not round-trip to the authorised deposit".into());
    }
    Ok(raw)
}

// ════════════════════════════════════════════════════════════════ EXIT ═════

/// A signed-exit plan: the §7.2 message fields plus everything needed to
/// verify authority before signing. The wire carrier for this message does
/// not exist yet (see `exit broadcast`); the artifact is the deliverable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitPlan {
    pub kind: String,
    pub rehearsal: bool,
    pub validator_index: u32,
    /// SHA3-256 of the validator's pubkey bytes as committed at registration
    /// — the identity the exit names, read from the registry.
    pub pubkey_hash: String,
    /// Epoch the exit is signed for. Consensus refuses an exit whose epoch
    /// is ahead of the including epoch, and the epoch is inside the signing
    /// root — so the exit must be included promptly after signing.
    pub epoch: u64,
    /// `SHA3-256(DS_EXIT ‖ pubkey_hash ‖ epoch)` — from the consensus crate.
    pub signing_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExit {
    pub plan: ExitPlan,
    /// Hybrid signature over the exit signing root, both halves required.
    pub signature: String,
}

/// Build an exit plan from the committed validator record.
pub fn build_exit_plan(
    v: &rpc::ValidatorInfo,
    chain_epoch: u64,
    rehearsal: bool,
) -> Result<ExitPlan, String> {
    check_format_active(StakingFormat::SignedExit, chain_epoch, rehearsal)?;
    if v.slashed {
        return Err(format!(
            "validator {} is slashed; consensus refuses a voluntary exit for a slashed record \
             (its exit and withdrawal clocks are set by the slashing itself)",
            v.index
        ));
    }
    if v.exit_epoch.is_some() {
        return Err(format!(
            "validator {} already exited (exit_epoch {}); a second exit would reset the \
             withdrawal clock, which must never move once started — consensus refuses it \
             (ExitReject::AlreadyExited)",
            v.index,
            v.exit_epoch.unwrap()
        ));
    }
    if v.activation_epoch.is_none() || v.activation_epoch.unwrap() > chain_epoch {
        return Err(format!(
            "validator {} is not active yet (activation_epoch {:?}); consensus refuses an exit \
             before activation",
            v.index, v.activation_epoch
        ));
    }
    let exit = ExitTx {
        pubkey_hash: v.pubkey_hash,
        epoch: chain_epoch,
        signature: Vec::new(),
    };
    Ok(ExitPlan {
        kind: "exit".into(),
        rehearsal,
        validator_index: v.index,
        pubkey_hash: hex::encode(v.pubkey_hash),
        epoch: chain_epoch,
        signing_root: hex::encode(exit.signing_root()),
    })
}

/// Re-derive the exit signing root from the plan's fields — the file is
/// data, not authority.
pub fn check_exit_plan(plan: &ExitPlan) -> Result<ExitTx, String> {
    if plan.kind != "exit" {
        return Err(format!("this is a `{}` artifact, not an exit plan", plan.kind));
    }
    let ph = hex::decode(&plan.pubkey_hash).map_err(|e| format!("pubkey_hash hex: {e}"))?;
    let pubkey_hash: [u8; 32] =
        ph.try_into().map_err(|_| "pubkey_hash is not 32 bytes".to_string())?;
    let exit = ExitTx { pubkey_hash, epoch: plan.epoch, signature: Vec::new() };
    if hex::encode(exit.signing_root()) != plan.signing_root {
        return Err("exit plan signing root does not match its own fields — the file was \
                    altered"
            .into());
    }
    Ok(exit)
}

/// Sign an exit with the validator key. Refuses a key whose committed hash
/// is not the one the exit names — an exit for a validator this key does not
/// control is exactly what consensus would refuse
/// (`ExitReject::UnknownValidator` / `BadSignature`), caught here before a
/// signature exists.
pub fn sign_exit(plan: &ExitPlan, pubkey: &[u8], secret: &[u8]) -> Result<SignedExit, String> {
    let exit = check_exit_plan(plan)?;
    let key_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
    if key_hash != exit.pubkey_hash {
        return Err(format!(
            "this key does not control validator {}: the registry commits pubkey hash {}, \
             this keystore's key hashes to {}. Consensus verifies an exit only against the \
             registered key — nothing was signed.",
            plan.validator_index,
            plan.pubkey_hash,
            hex::encode(key_hash)
        ));
    }
    let root = exit.signing_root();
    let signature = bloch_crypto::crypto::sign(secret, &root)
        .map_err(|e| format!("hybrid signing failed: {e}"))?;
    if !bloch_crypto::crypto::verify(pubkey, &root, &signature) {
        return Err("the produced exit signature does not verify — refusing to emit it".into());
    }
    Ok(SignedExit { plan: plan.clone(), signature: hex::encode(signature) })
}

/// Verify a signed-exit artifact end to end (root re-derived, signature
/// verified against the key hash the plan names — via the supplied pubkey,
/// which must hash to it).
pub fn check_signed_exit(se: &SignedExit, pubkey: &[u8]) -> Result<(), String> {
    let exit = check_exit_plan(&se.plan)?;
    let key_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
    if key_hash != exit.pubkey_hash {
        return Err("the supplied pubkey does not hash to the exit's pubkey_hash".into());
    }
    let sig = hex::decode(&se.signature).map_err(|e| format!("signature hex: {e}"))?;
    if !bloch_crypto::crypto::verify(pubkey, &exit.signing_root(), &sig) {
        return Err("exit signature does not verify over the signing root".into());
    }
    Ok(())
}

/// Why `exit broadcast` refuses today, in full. Kept as a function so the
/// refusal is testable and the wording lives in one place.
pub fn exit_broadcast_refusal() -> String {
    format!(
        "a signed exit cannot be broadcast yet: the consensus seam that applies it \
         (`CommittedState::apply_exit`, judged by `staking::validate_exit`) landed behind \
         `SIGNED_EXIT_ACTIVATION_EPOCH` (currently {}), but NO wire carrier exists — no \
         `PosTransaction` variant embeds a `staking::ExitTx`, so there are no bytes a block \
         could include. Keep the signed artifact; when the carrier format lands, re-plan \
         (the exit's epoch is inside its signing root and must match the inclusion epoch, \
         so this signature will need to be re-produced at inclusion time anyway).",
        activation_desc(StakingFormat::SignedExit)
    )
}

/// Why `delegate` refuses today, in full.
pub fn delegate_refusal() -> String {
    format!(
        "a funded delegation cannot be built yet: the consensus seam exists \
         (`CommittedState::apply_delegation`, behind `FUNDED_STAKING_ACTIVATION_EPOCH`, \
         currently {}), but the funded wire format — which outputs are bonded, how the \
         delegator authorises the bond — has not been designed in any work stream. This \
         tool does not invent consensus wire formats: a delegation encoding drafted in a \
         wallet would define the chain's bytes by accident. When the format lands in \
         `bloch-pos-committee`, this subcommand gains its plan/sign/broadcast flow.",
        activation_desc(StakingFormat::FundedDelegate)
    )
}

fn activation_desc(f: StakingFormat) -> String {
    let a = f.activation_epoch();
    if a == u64::MAX {
        "INERT — u64::MAX, no flag day armed".to_string()
    } else {
        format!("epoch {a}")
    }
}

// ════════════════════════════════════════════════════════════ WITHDRAW ═════

/// A withdrawal plan. The crank is unauthenticated by design — the payout
/// goes to the credentials fixed at deposit time, so there is nothing a
/// signature could redirect and no sign step. The plan carries the exact
/// canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawPlan {
    pub kind: String,
    pub rehearsal: bool,
    pub validator_index: u32,
    /// The committed record's facts at plan time, for the preview; consensus
    /// re-derives everything from inclusion-time state.
    pub state: String,
    pub own_stake_sat: u128,
    pub slashed: bool,
    pub exit_epoch: u64,
    pub withdrawable_epoch: u64,
    pub planned_epoch: u64,
    pub txid: String,
    /// The canonical bytes (`PosTransaction::Withdraw`), hex.
    pub raw_tx: String,
}

/// Build a withdrawal plan from the committed validator record. Refuses
/// everything `staking::validate_withdrawal` (via the transition's Withdraw
/// arm) would refuse: not exited, delay not elapsed, already withdrawn —
/// plus the flag-day gate.
pub fn build_withdraw_plan(
    v: &rpc::ValidatorInfo,
    chain_epoch: u64,
    rehearsal: bool,
) -> Result<WithdrawPlan, String> {
    check_format_active(StakingFormat::Withdraw, chain_epoch, rehearsal)?;
    let Some(exit_epoch) = v.exit_epoch else {
        return Err(format!(
            "validator {} has no exit on record — the stake is still bonded, and a withdrawal \
             before exit is refused (WithdrawReject::NotExited). Exit first; the bond becomes \
             withdrawable {} epochs after the exit is included.",
            v.index,
            staking::WITHDRAWAL_DELAY_EPOCHS
        ));
    };
    let Some(withdrawable_epoch) = v.withdrawable_epoch else {
        return Err(format!(
            "validator {} has an exit (epoch {exit_epoch}) but no withdrawable_epoch on \
             record — the bond was already withdrawn (the withdraw-once sentinel clears the \
             field), or the record predates the withdrawal format. Nothing to build.",
            v.index
        ));
    };
    if v.own_stake_sat == 0 {
        return Err(format!(
            "validator {} has zero remaining stake — already withdrawn, or fully slashed; \
             the crank would be refused (WithdrawReject::AlreadyWithdrawn)",
            v.index
        ));
    }
    if chain_epoch < withdrawable_epoch {
        return Err(format!(
            "validator {}'s bond is not withdrawable until epoch {withdrawable_epoch} (the \
             chain is at epoch {chain_epoch}; {} epochs to go). The delay is the \
             weak-subjectivity margin — consensus refuses an earlier withdrawal \
             (WithdrawReject::DelayNotElapsed), and every slashing included meanwhile \
             extends the committed withdrawable_epoch.",
            v.index,
            withdrawable_epoch - chain_epoch
        ));
    }
    let tx = PosTransaction::Withdraw { validator: v.index };
    Ok(WithdrawPlan {
        kind: "withdraw".into(),
        rehearsal,
        validator_index: v.index,
        state: v.state.clone(),
        own_stake_sat: v.own_stake_sat,
        slashed: v.slashed,
        exit_epoch,
        withdrawable_epoch,
        planned_epoch: chain_epoch,
        txid: hex::encode(tx.txid()),
        raw_tx: hex::encode(tx.canonical_bytes()),
    })
}

/// Re-derive the withdrawal's bytes and txid from the index the plan names,
/// and round-trip them through the real decoder.
pub fn check_withdraw_plan(plan: &WithdrawPlan) -> Result<Vec<u8>, String> {
    if plan.kind != "withdraw" {
        return Err(format!("this is a `{}` artifact, not a withdraw plan", plan.kind));
    }
    if plan.rehearsal {
        return Err(
            "this is a REHEARSAL artifact: it was planned while the withdrawal flag day had \
             not arrived, and it must never be broadcast. Re-plan without --rehearsal once \
             the activation epoch is live."
                .into(),
        );
    }
    let tx = PosTransaction::Withdraw { validator: plan.validator_index };
    let raw = tx.canonical_bytes();
    if hex::encode(&raw) != plan.raw_tx {
        return Err("withdraw plan raw_tx does not match its validator index — the file was \
                    altered"
            .into());
    }
    if hex::encode(tx.txid()) != plan.txid {
        return Err("withdraw plan txid does not match its bytes".into());
    }
    let decoded = PosTransaction::from_canonical_bytes(&raw)
        .map_err(|e| format!("withdraw bytes do not decode canonically: {e:?}"))?;
    if decoded != tx {
        return Err("withdraw bytes do not round-trip to the planned crank".into());
    }
    Ok(raw)
}

// ── Previews & confirmation phrases ─────────────────────────────────────────

pub fn deposit_preview(plan: &DepositPlan) -> String {
    let fee = plan.base_fee_sat + plan.tip_fee_sat;
    let spent: u128 = plan.inputs.iter().map(|i| i.value_sat as u128).sum();
    let mut s = String::new();
    s.push_str("── FUNDED DEPOSIT TO BE SIGNED ───────────────────────────────\n");
    if plan.rehearsal {
        s.push_str("  *** REHEARSAL — this artifact can never be broadcast ***\n");
    }
    s.push_str(&format!("  network          {}\n", plan.network));
    s.push_str(&format!(
        "  bond             {} BLCH  ({} sat) — leaves the spendable set\n",
        format_blch(plan.amount_sat),
        plan.amount_sat
    ));
    s.push_str(&format!("  validator key    {}… ({} bytes, suite-framed hybrid)\n",
        &plan.validator_pubkey[..16], plan.validator_pubkey.len() / 2));
    s.push_str(&format!("  pubkey hash      {}\n", plan.validator_pubkey_hash));
    s.push_str(&format!("  randao c_0       {}\n", plan.randao_commitment));
    s.push_str(&format!("  commission       {} bps\n", plan.commission_bps));
    s.push_str(&format!("  funding address  {}\n", plan.funding_address));
    s.push_str(&format!(
        "  withdrawal addr  {}  (fixed FOREVER by the PoP — the principal returns here)\n",
        plan.withdrawal_address
    ));
    s.push_str(&format!("  inputs           {} coin(s), {} sat total\n", plan.inputs.len(), spent));
    for i in &plan.inputs {
        s.push_str(&format!("                   {}:{}  {} sat\n", &i.txid[..16], i.vout, i.value_sat));
    }
    if plan.change_sat > 0 {
        s.push_str(&format!(
            "  change           {} BLCH ({} sat) back to the funding address\n",
            format_blch(plan.change_sat as u128),
            plan.change_sat
        ));
    } else {
        s.push_str("  change           none (inputs consumed exactly)\n");
    }
    s.push_str(&format!(
        "  fee              {} sat  ({} gas @ base {} + tip {} millisat/gas)\n",
        fee, plan.gas, plan.base_fee_millisat_per_gas, plan.tip_millisat_per_gas
    ));
    s.push_str(&format!(
        "  conservation     {} (inputs) == {} (bond) + {} (change) + {} (fee)  [exact]\n",
        spent, plan.amount_sat, plan.change_sat, fee
    ));
    s.push_str(&format!("  per-validator cap {} BLCH (at plan epoch {})\n",
        format_blch(plan.cap_sat), plan.planned_epoch));
    s.push_str(&format!("  tx_bytes         {} (declared, inside the signing root)\n", plan.tx_bytes));
    s.push_str(&format!("  spend root       {}\n", plan.spend_signing_root));
    s.push_str(&format!("  PoP root         {}\n", plan.pop_signing_root));
    s.push_str(&format!("  txid             {}\n", plan.txid));
    s.push_str("──────────────────────────────────────────────────────────────\n");
    s
}

pub fn exit_preview(plan: &ExitPlan) -> String {
    let mut s = String::new();
    s.push_str("── VOLUNTARY EXIT TO BE SIGNED ───────────────────────────────\n");
    if plan.rehearsal {
        s.push_str("  *** REHEARSAL — this artifact can never be broadcast ***\n");
    }
    s.push_str(&format!("  validator     {}\n", plan.validator_index));
    s.push_str(&format!("  pubkey hash   {}\n", plan.pubkey_hash));
    s.push_str(&format!("  exit epoch    {} (must match the inclusion epoch)\n", plan.epoch));
    s.push_str(&format!(
        "  consequences  duties stop {} epochs after inclusion; the bond becomes\n\
         \x20               withdrawable {} epochs after inclusion; an exit is IRREVOCABLE\n",
        staking::EXIT_DELAY_EPOCHS,
        staking::WITHDRAWAL_DELAY_EPOCHS
    ));
    s.push_str(&format!("  signing root  {}\n", plan.signing_root));
    s.push_str("──────────────────────────────────────────────────────────────\n");
    s
}

pub fn withdraw_preview(plan: &WithdrawPlan) -> String {
    let mut s = String::new();
    s.push_str("── WITHDRAWAL CRANK TO BE BROADCAST ──────────────────────────\n");
    if plan.rehearsal {
        s.push_str("  *** REHEARSAL — this artifact can never be broadcast ***\n");
    }
    s.push_str(&format!("  validator        {} ({})\n", plan.validator_index, plan.state));
    s.push_str(&format!(
        "  residue          {} BLCH ({} sat){}\n",
        format_blch(plan.own_stake_sat),
        plan.own_stake_sat,
        if plan.slashed { "  [slashed record — residue rules apply]" } else { "" }
    ));
    s.push_str(&format!("  exited           epoch {}\n", plan.exit_epoch));
    s.push_str(&format!(
        "  withdrawable     epoch {} (chain was at {} when planned)\n",
        plan.withdrawable_epoch, plan.planned_epoch
    ));
    s.push_str(
        "  payout           to the withdrawal credentials fixed at deposit time —\n\
         \x20                 this crank is unauthenticated and CANNOT redirect them\n",
    );
    s.push_str(&format!("  txid             {}\n", plan.txid));
    s.push_str("──────────────────────────────────────────────────────────────\n");
    s
}

/// The typed phrases. Each contains the quantities that matter, so
/// confirming is re-stating the action.
pub fn deposit_confirmation_phrase(plan: &DepositPlan) -> String {
    format!(
        "BOND {} BLCH VALIDATOR {}",
        format_blch(plan.amount_sat),
        &plan.validator_pubkey_hash[..8]
    )
}

pub fn exit_confirmation_phrase(plan: &ExitPlan) -> String {
    format!("EXIT VALIDATOR {} EPOCH {}", plan.validator_index, plan.epoch)
}

pub fn withdraw_confirmation_phrase(plan: &WithdrawPlan) -> String {
    format!("WITHDRAW VALIDATOR {}", plan.validator_index)
}

#[cfg(test)]
mod tests;
