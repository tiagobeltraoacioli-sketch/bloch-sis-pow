//! # vault — the Bitcoin-side commit-delay-reveal P2WSH vault + hashlocked recovery
//!
//! Implements spec §2: three outputs (DEPOSIT `V` → TRIGGER `T` → destination /
//! clawback), built with real `rust-bitcoin` primitives so the transactions are valid,
//! testable Bitcoin on testnet/regtest.
//!
//! ## Output-type choice (spec §0.1 / §2.0(1))
//! We lead with **P2WSH** for both the deposit and the trigger. P2WSH puts only
//! `SHA256(witnessScript)` in the `scriptPubKey`, so every pubkey in the script is
//! hidden behind a hash *at rest* — the quantum-conservative choice. Taproot would leak
//! a live EC output key at rest (§0.1); we do not use it for the deposit.
//!
//! ## The two script branches (spec §2.1)
//! The TRIGGER witnessScript is a single P2WSH script with an `OP_IF` split:
//! ```text
//!   OP_IF                                            # branch A — normal delayed spend
//!       <Δ> OP_CSV OP_DROP <hot_pubkey> OP_CHECKSIG
//!   OP_ELSE                                          # branch B — immediate hashlocked recovery
//!       OP_SHA256 <H(r)> OP_EQUALVERIFY <recovery_pubkey> OP_CHECKSIG
//!   OP_ENDIF
//! ```
//! Branch A carries the CSV relative-timelock delay Δ (BIP-112/BIP-68); branch B has NO
//! delay but requires the PQ-derived preimage `r` plus a recovery signature. Once the
//! unvault reveals `r`, the recovery signature is the remaining authorization check.
//!
//! ## The covenant caveat (spec §2.0(2) — stated, not papered over)
//! On stock Bitcoin there is **no covenant opcode**, so "the deposit may only be spent
//! by the delayed trigger" is NOT enforced by consensus here. It is enforced
//! only operationally by a separately designed pre-signing/deletion ceremony.
//! The legacy `VaultParams` here REUSES the hot key for deposit and branch A;
//! retaining that hot key or its derivation seed preserves the deposit bypass.
//! Deleting only a copy does not implement the advertised ceremony. New callers
//! can explicitly evaluate `construction::SeparatedDepositV1`, which separates
//! the public roles but cannot prove key independence, deletion or quantum safety.
//! Neither constructor is a Bitcoin covenant. See the crate HONEST LIMITS.

use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all as op;
use bitcoin::script::Builder;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

/// Conservative construction floor for new vaults. This is an application
/// policy, not a Bitcoin consensus rule.
pub const MIN_NEW_VAULT_CSV_DELAY: u16 = 144;
/// Bitcoin's maximum representable monetary supply, in satoshis.
pub const BITCOIN_MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;
/// Bound on pre-signed clawback replacements retained per vault. This limits
/// construction/backup size; it is not a Bitcoin relay-policy constant.
pub const MAX_CLAWBACK_FEE_LADDER_STEPS: usize = 32;

/// Refusals returned by the checked transaction-building API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultTxError {
    NullOutpoint,
    AmountOutOfRange,
    FeeExceedsAmount,
    ExcessiveFee,
    DustOutput,
    CsvDelayTooShort,
    UncompressedRoleKey,
    ReusedRoleKey,
    InvalidInputIndex,
    FeeLadderTooShort,
    FeeLadderTooLong,
    FeeLadderNotIncreasing,
}

impl std::fmt::Display for VaultTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NullOutpoint => "funding outpoint cannot be null",
            Self::AmountOutOfRange => "input amount exceeds Bitcoin's money range",
            Self::FeeExceedsAmount => "fee exceeds input amount",
            Self::ExcessiveFee => "fee exceeds the checked builder's 10% safety limit",
            Self::DustOutput => "output is below the script dust threshold",
            Self::CsvDelayTooShort => "new vaults require at least 144 blocks of CSV delay",
            Self::UncompressedRoleKey => "vault role keys must be compressed",
            Self::ReusedRoleKey => "hot and recovery keys must be distinct",
            Self::InvalidInputIndex => "sighash input index is out of range",
            Self::FeeLadderTooShort => "a clawback fee ladder requires at least two steps",
            Self::FeeLadderTooLong => "clawback fee ladder exceeds 32 steps",
            Self::FeeLadderNotIncreasing => "clawback fee ladder must be strictly increasing",
        })
    }
}

impl std::error::Error for VaultTxError {}

/// Validate parameters used for a new legacy-shaped vault. Existing funded
/// vaults may still need the unchecked compatibility functions below, but new
/// construction should reject short delays and shared role keys.
pub fn validate_new_vault_params(p: &VaultParams) -> Result<(), VaultTxError> {
    if !p.hot_pubkey.compressed || !p.recovery_pubkey.compressed {
        return Err(VaultTxError::UncompressedRoleKey);
    }
    if p.hot_pubkey == p.recovery_pubkey {
        return Err(VaultTxError::ReusedRoleKey);
    }
    if p.csv_delay < MIN_NEW_VAULT_CSV_DELAY {
        return Err(VaultTxError::CsvDelayTooShort);
    }
    Ok(())
}

fn checked_output_value(input_amount_sat: u64, fee_sat: u64, script_pubkey: &bitcoin::Script)
    -> Result<u64, VaultTxError> {
    if input_amount_sat > BITCOIN_MAX_MONEY_SAT {
        return Err(VaultTxError::AmountOutOfRange);
    }
    let output = input_amount_sat.checked_sub(fee_sat).ok_or(VaultTxError::FeeExceedsAmount)?;
    if fee_sat > input_amount_sat / 10 {
        return Err(VaultTxError::ExcessiveFee);
    }
    if output < script_pubkey.minimal_non_dust().to_sat() {
        return Err(VaultTxError::DustOutput);
    }
    Ok(output)
}

/// Parameters that define one vault instance. `hot_pubkey` guards the normal spend path
/// (deposit hash-gate + trigger branch A); `recovery_pubkey` guards the clawback
/// (trigger branch B). Both are on-chain secp256k1 keys; the *post-quantum* authority
/// lives in the preimage `r`/`H(r)` (see [`crate::preimage`]) and the Bloch anchor.
#[derive(Clone, Debug)]
pub struct VaultParams {
    /// The hot spend key (secp256k1) — deposit spend + branch A.
    pub hot_pubkey: PublicKey,
    /// The recovery key (secp256k1) — branch B clawback.
    pub recovery_pubkey: PublicKey,
    /// `H(r) = SHA256(r)` — the PQ-derived hash-lock (see [`crate::preimage`]).
    pub recovery_hash: [u8; 32],
    /// Δ — the CSV relative-timelock delay on branch A, in blocks (spec §7 default 144).
    pub csv_delay: u16,
    /// Which Bitcoin network the addresses render for.
    pub network: Network,
}

/// The DEPOSIT witnessScript `V` (spec §2.1): `OP_SHA256 <H(r)> OP_EQUALVERIFY
/// <hot_pubkey> OP_CHECKSIG`. Spending it requires revealing `r` (the unvault event that
/// first exposes a pubkey) plus a hot-key signature.
pub fn deposit_script(recovery_hash: &[u8; 32], hot_pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(op::OP_SHA256)
        .push_slice(recovery_hash)
        .push_opcode(op::OP_EQUALVERIFY)
        .push_key(hot_pubkey)
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}

/// The TRIGGER witnessScript `T` (spec §2.1) — branch A (delayed normal spend) OR
/// branch B (immediate hashlocked recovery), selected by the `OP_IF` boolean.
pub fn trigger_script(p: &VaultParams) -> ScriptBuf {
    Builder::new()
        .push_opcode(op::OP_IF)
        // Branch A: <Δ> OP_CSV OP_DROP <hot_pubkey> OP_CHECKSIG
        .push_int(p.csv_delay as i64)
        .push_opcode(op::OP_CSV)
        .push_opcode(op::OP_DROP)
        .push_key(&p.hot_pubkey)
        .push_opcode(op::OP_CHECKSIG)
        .push_opcode(op::OP_ELSE)
        // Branch B: OP_SHA256 <H(r)> OP_EQUALVERIFY <recovery_pubkey> OP_CHECKSIG
        .push_opcode(op::OP_SHA256)
        .push_slice(&p.recovery_hash)
        .push_opcode(op::OP_EQUALVERIFY)
        .push_key(&p.recovery_pubkey)
        .push_opcode(op::OP_CHECKSIG)
        .push_opcode(op::OP_ENDIF)
        .into_script()
}

/// The P2WSH deposit address `V` for this vault (funds at rest here, hidden behind
/// `SHA256(depositScript)`).
pub fn deposit_address(p: &VaultParams) -> Address {
    let s = deposit_script(&p.recovery_hash, &p.hot_pubkey);
    Address::p2wsh(&s, p.network)
}

/// The P2WSH trigger address `T` (the short-lived unvault output).
pub fn trigger_address(p: &VaultParams) -> Address {
    Address::p2wsh(&trigger_script(p), p.network)
}

/// The trigger output's `scriptPubKey` (P2WSH), used as the unvault tx's output.
pub fn trigger_script_pubkey(p: &VaultParams) -> ScriptBuf {
    trigger_address(p).script_pubkey()
}

/// Build the **unvault transaction `U`** (spec §2.1): spends the DEPOSIT `V` and creates
/// the TRIGGER `T`. Broadcasting `U` is the public "unvault trigger" event and the only
/// moment a pubkey / the preimage `r` is revealed. Version 2 (required for the CSV that
/// branch A of `T` will later use). The deposit input itself carries no relative
/// timelock, so its `nSequence` is set to enable RBF.
pub fn build_unvault_tx(
    p: &VaultParams,
    deposit_outpoint: OutPoint,
    deposit_amount_sat: u64,
    fee_sat: u64,
) -> Transaction {
    let out_value = deposit_amount_sat.saturating_sub(fee_sat);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: deposit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey: trigger_script_pubkey(p),
        }],
    }
}

/// Checked new-construction counterpart to [`build_unvault_tx`].
pub fn build_unvault_tx_checked(p: &VaultParams, deposit_outpoint: OutPoint,
    deposit_amount_sat: u64, fee_sat: u64) -> Result<Transaction, VaultTxError> {
    validate_new_vault_params(p)?;
    if deposit_outpoint.is_null() { return Err(VaultTxError::NullOutpoint); }
    checked_output_value(deposit_amount_sat, fee_sat, &trigger_script_pubkey(p))?;
    Ok(build_unvault_tx(p, deposit_outpoint, deposit_amount_sat, fee_sat))
}

/// Build the **branch A** (normal, delayed) spend of the TRIGGER `T` to `destination`.
/// Its input `nSequence` encodes the CSV relative timelock Δ (BIP-68), so the network
/// will only accept it once Δ blocks have matured since `T` confirmed.
pub fn build_branch_a_tx(
    p: &VaultParams,
    trigger_outpoint: OutPoint,
    trigger_amount_sat: u64,
    destination: &Address,
    fee_sat: u64,
) -> Transaction {
    let out_value = trigger_amount_sat.saturating_sub(fee_sat);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: trigger_outpoint,
            script_sig: ScriptBuf::new(),
            // BIP-68 relative-timelock: Δ blocks. This is what makes an early branch-A
            // spend invalid and a post-Δ one valid.
            sequence: Sequence::from_height(p.csv_delay),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey: destination.script_pubkey(),
        }],
    }
}

/// Checked new-construction counterpart to [`build_branch_a_tx`].
pub fn build_branch_a_tx_checked(p: &VaultParams, trigger_outpoint: OutPoint,
    trigger_amount_sat: u64, destination: &Address, fee_sat: u64)
    -> Result<Transaction, VaultTxError> {
    validate_new_vault_params(p)?;
    if trigger_outpoint.is_null() { return Err(VaultTxError::NullOutpoint); }
    checked_output_value(trigger_amount_sat, fee_sat, &destination.script_pubkey())?;
    Ok(build_branch_a_tx(p, trigger_outpoint, trigger_amount_sat, destination, fee_sat))
}

/// Build the **branch B** clawback spend of the TRIGGER `T` to `safe_destination`
/// (the anchored `designated_safe_dest`). Immediate — no relative timelock — so the
/// owner/watchtower can execute it during the delay window Δ. `nSequence` opts into RBF,
/// but a keyless watchtower needs pre-signed replacements; the bit alone grants no
/// third-party fee-bump authority (spec §2.2 / §4.1).
pub fn build_clawback_tx(
    trigger_outpoint: OutPoint,
    trigger_amount_sat: u64,
    safe_destination: &Address,
    fee_sat: u64,
) -> Transaction {
    let out_value = trigger_amount_sat.saturating_sub(fee_sat);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: trigger_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey: safe_destination.script_pubkey(),
        }],
    }
}

/// Checked new-construction counterpart to [`build_clawback_tx`]. The caller
/// must separately bind `safe_destination` to an authenticated anchor.
pub fn build_clawback_tx_checked(trigger_outpoint: OutPoint, trigger_amount_sat: u64,
    safe_destination: &Address, fee_sat: u64) -> Result<Transaction, VaultTxError> {
    if trigger_outpoint.is_null() { return Err(VaultTxError::NullOutpoint); }
    checked_output_value(trigger_amount_sat, fee_sat, &safe_destination.script_pubkey())?;
    Ok(build_clawback_tx(trigger_outpoint, trigger_amount_sat, safe_destination, fee_sat))
}

/// One unsigned replacement in a clawback fee ladder.
///
/// `SIGHASH_ALL` commits the input, destination and fee-dependent output, so
/// every step needs its own recovery-key signature before the package is
/// handed to a keyless watchtower.
#[derive(Clone, Debug)]
pub struct ClawbackReplacement {
    pub fee_sat: u64,
    pub transaction: Transaction,
    pub sighash: [u8; 32],
}

/// Build a bounded set of pre-signable RBF clawback replacements.
///
/// Fees must be strictly increasing and each candidate independently passes
/// the checked money-range, dust and ten-percent fee-policy checks. All steps
/// spend the same trigger outpoint to the same safe destination and opt into
/// RBF. This supplies authorization alternatives to a keyless watchtower; it
/// does not estimate fees or guarantee that a particular node will accept a
/// replacement under its current BIP-125/incremental-relay policy.
pub fn build_clawback_fee_ladder_checked(
    p: &VaultParams,
    trigger_outpoint: OutPoint,
    trigger_amount_sat: u64,
    safe_destination: &Address,
    fees_sat: &[u64],
) -> Result<Vec<ClawbackReplacement>, VaultTxError> {
    validate_new_vault_params(p)?;
    if fees_sat.len() < 2 {
        return Err(VaultTxError::FeeLadderTooShort);
    }
    if fees_sat.len() > MAX_CLAWBACK_FEE_LADDER_STEPS {
        return Err(VaultTxError::FeeLadderTooLong);
    }
    if fees_sat.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(VaultTxError::FeeLadderNotIncreasing);
    }

    let witness_script = trigger_script(p);
    let mut ladder = Vec::with_capacity(fees_sat.len());
    for &fee_sat in fees_sat {
        let transaction = build_clawback_tx_checked(
            trigger_outpoint,
            trigger_amount_sat,
            safe_destination,
            fee_sat,
        )?;
        let sighash = p2wsh_sighash_checked(
            &transaction,
            0,
            &witness_script,
            trigger_amount_sat,
        )?;
        ladder.push(ClawbackReplacement { fee_sat, transaction, sighash });
    }
    Ok(ladder)
}

/// Compute the BIP-143 P2WSH (segwit v0) sighash for `input_index`, over `witness_script`
/// with the spent output's `amount_sat`, `SIGHASH_ALL`. This is the message the hot /
/// recovery secp256k1 key signs.
pub fn p2wsh_sighash(
    tx: &Transaction,
    input_index: usize,
    witness_script: &ScriptBuf,
    amount_sat: u64,
) -> [u8; 32] {
    let mut cache = SighashCache::new(tx);
    let sh = cache
        .p2wsh_signature_hash(
            input_index,
            witness_script,
            Amount::from_sat(amount_sat),
            EcdsaSighashType::All,
        )
        .expect("valid input index for p2wsh sighash");
    let mut out = [0u8; 32];
    out.copy_from_slice(sh.as_ref());
    out
}

/// Fallible counterpart to [`p2wsh_sighash`] for untrusted transactions/indexes.
pub fn p2wsh_sighash_checked(tx: &Transaction, input_index: usize,
    witness_script: &ScriptBuf, amount_sat: u64) -> Result<[u8; 32], VaultTxError> {
    if input_index >= tx.input.len() { return Err(VaultTxError::InvalidInputIndex); }
    if amount_sat > BITCOIN_MAX_MONEY_SAT { return Err(VaultTxError::AmountOutOfRange); }
    let mut cache = SighashCache::new(tx);
    let sh = cache.p2wsh_signature_hash(input_index, witness_script,
        Amount::from_sat(amount_sat), EcdsaSighashType::All)
        .map_err(|_| VaultTxError::InvalidInputIndex)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(sh.as_ref());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::DisplayHex;
    use crate::{ecdsa_witness_sig, preimage::recovery_hash, script_eval::{eval, EvalCtx}};

    fn test_pubkey(byte: u8) -> PublicKey {
        // A valid, deterministic secp256k1 pubkey from a fixed secret.
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte.max(1); 32]).unwrap();
        PublicKey::new(sk.public_key(&secp))
    }

    fn params() -> VaultParams {
        VaultParams {
            hot_pubkey: test_pubkey(0x11),
            recovery_pubkey: test_pubkey(0x22),
            recovery_hash: [0xabu8; 32],
            csv_delay: 144,
            network: Network::Regtest,
        }
    }

    #[test]
    fn deposit_address_is_deterministic_p2wsh() {
        let p = params();
        let a1 = deposit_address(&p);
        let a2 = deposit_address(&p);
        assert_eq!(a1, a2, "same params → same deposit address");
        // regtest / testnet P2WSH is `bcrt1q…` (bech32, 32-byte witness program)
        assert!(a1.to_string().starts_with("bcrt1q"), "expected P2WSH bech32, got {a1}");
        // a different recovery_hash → a different address (hash-hiding is real)
        let mut p2 = p.clone();
        p2.recovery_hash = [0xcd; 32];
        assert_ne!(deposit_address(&p2), a1);
    }

    #[test]
    fn trigger_script_has_both_branches_and_csv() {
        let p = params();
        let s = trigger_script(&p);
        let asm = s.to_asm_string();
        assert!(asm.contains("OP_IF") && asm.contains("OP_ELSE") && asm.contains("OP_ENDIF"));
        assert!(asm.contains("OP_CSV"), "branch A must carry the CSV delay");
        assert!(asm.contains("OP_SHA256") && asm.contains("OP_EQUALVERIFY"), "branch B hash-lock");
        // deterministic
        assert_eq!(trigger_script(&p).to_bytes(), s.to_bytes());
    }

    #[test]
    fn sighash_is_deterministic() {
        let p = params();
        let dep = deposit_script(&p.recovery_hash, &p.hot_pubkey);
        let op = OutPoint::null();
        let u = build_unvault_tx(&p, op, 100_000, 300);
        let h1 = p2wsh_sighash(&u, 0, &dep, 100_000);
        let h2 = p2wsh_sighash(&u, 0, &dep, 100_000);
        assert_eq!(h1, h2);
        // a different spent amount changes the BIP-143 sighash
        let h3 = p2wsh_sighash(&u, 0, &dep, 99_999);
        assert_ne!(h1, h3, "sighash commits to the amount ({})", h1.to_lower_hex_string());
    }

    #[test]
    fn checked_builders_reject_adversarial_values() {
        use bitcoin::{hashes::Hash, Txid};
        let p = params();
        let outpoint = OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 };
        let destination = deposit_address(&p);
        assert!(build_unvault_tx_checked(&p, outpoint, 100_000, 500).is_ok());
        assert!(build_branch_a_tx_checked(&p, outpoint, 100_000, &destination, 500).is_ok());
        assert!(build_clawback_tx_checked(outpoint, 100_000, &destination, 500).is_ok());
        assert_eq!(build_unvault_tx_checked(&p, OutPoint::null(), 100_000, 500), Err(VaultTxError::NullOutpoint));
        assert_eq!(build_unvault_tx_checked(&p, outpoint, 1_000, 1_001), Err(VaultTxError::FeeExceedsAmount));
        assert_eq!(build_unvault_tx_checked(&p, outpoint, 10_000, 1_001), Err(VaultTxError::ExcessiveFee));
        assert_eq!(build_unvault_tx_checked(&p, outpoint, BITCOIN_MAX_MONEY_SAT + 1, 0), Err(VaultTxError::AmountOutOfRange));
        assert_eq!(build_clawback_tx_checked(outpoint, 1, &destination, 0), Err(VaultTxError::DustOutput));
        let mut short = p.clone(); short.csv_delay = MIN_NEW_VAULT_CSV_DELAY - 1;
        assert_eq!(build_branch_a_tx_checked(&short, outpoint, 100_000, &destination, 500), Err(VaultTxError::CsvDelayTooShort));
        let mut reused = p.clone(); reused.recovery_pubkey = reused.hot_pubkey;
        assert_eq!(validate_new_vault_params(&reused), Err(VaultTxError::ReusedRoleKey));
    }

    #[test]
    fn checked_sighash_and_legacy_compatibility() {
        let mut p = params();
        let tx = build_unvault_tx(&p, OutPoint::null(), 100_000, 500);
        let script = deposit_script(&p.recovery_hash, &p.hot_pubkey);
        assert_eq!(p2wsh_sighash_checked(&tx, 1, &script, 100_000), Err(VaultTxError::InvalidInputIndex));
        assert_eq!(p2wsh_sighash_checked(&tx, 0, &script, BITCOIN_MAX_MONEY_SAT + 1), Err(VaultTxError::AmountOutOfRange));
        assert_eq!(p2wsh_sighash_checked(&tx, 0, &script, 100_000).unwrap(), p2wsh_sighash(&tx, 0, &script, 100_000));

        // Historical unchecked builders retain their byte-level behavior.
        p.csv_delay = 0;
        let unvault = build_unvault_tx(&p, OutPoint::null(), 1, 2);
        assert_eq!(unvault.output[0].value, Amount::ZERO);
        let destination = deposit_address(&p);
        let branch_a = build_branch_a_tx(&p, OutPoint::null(), 1, &destination, 2);
        assert_eq!(branch_a.output[0].value, Amount::ZERO);
        assert_eq!(branch_a.input[0].sequence, Sequence::from_height(0));
        let clawback = build_clawback_tx(OutPoint::null(), 1, &destination, 2);
        assert_eq!(clawback.output[0].value, Amount::ZERO);
    }

    #[test]
    fn clawback_fee_ladder_is_bounded_ordered_and_individually_signable() {
        use bitcoin::{hashes::Hash, Txid};
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let recovery_secret = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let preimage = [0x44; 32];
        let mut p = params();
        p.recovery_hash = recovery_hash(&preimage);
        let outpoint = OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 1 };
        let safe = deposit_address(&p);
        let fees = [500, 1_000, 2_000, 5_000];
        let ladder = build_clawback_fee_ladder_checked(
            &p,
            outpoint,
            100_000,
            &safe,
            &fees,
        ).unwrap();

        assert_eq!(ladder.len(), fees.len());
        let trigger = trigger_script(&p);
        for (index, step) in ladder.iter().enumerate() {
            assert_eq!(step.fee_sat, fees[index]);
            assert_eq!(step.transaction.input[0].previous_output, outpoint);
            assert_eq!(step.transaction.input[0].sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
            assert_eq!(step.transaction.output[0].script_pubkey, safe.script_pubkey());
            assert_eq!(step.transaction.output[0].value.to_sat(), 100_000 - fees[index]);
            assert_eq!(
                step.sighash,
                p2wsh_sighash(&step.transaction, 0, &trigger, 100_000),
            );
            let ctx = EvalCtx {
                input_sequence: step.transaction.input[0].sequence,
                confirmations: 0,
                tx_version: step.transaction.version.0,
                sighash: step.sighash,
            };
            assert_eq!(
                eval(
                    &Secp256k1::new(),
                    &trigger,
                    vec![ecdsa_witness_sig(&step.sighash, &recovery_secret), preimage.to_vec(), vec![]],
                    &ctx,
                ),
                Ok(true),
                "every replacement must be independently signable for branch B",
            );
        }
        assert!(ladder.windows(2).all(|pair| {
            pair[0].transaction.compute_txid() != pair[1].transaction.compute_txid()
                && pair[0].sighash != pair[1].sighash
        }));
    }

    #[test]
    fn clawback_fee_ladder_rejects_unsafe_or_ambiguous_schedules() {
        use bitcoin::{hashes::Hash, Txid};
        let p = params();
        let outpoint = OutPoint { txid: Txid::from_byte_array([8; 32]), vout: 0 };
        let safe = deposit_address(&p);
        let build = |fees: &[u64]| {
            build_clawback_fee_ladder_checked(&p, outpoint, 100_000, &safe, fees)
                .map(|_| ())
        };
        assert_eq!(build(&[]), Err(VaultTxError::FeeLadderTooShort));
        assert_eq!(build(&[500]), Err(VaultTxError::FeeLadderTooShort));
        assert_eq!(build(&[500, 500]), Err(VaultTxError::FeeLadderNotIncreasing));
        assert_eq!(build(&[1_000, 500]), Err(VaultTxError::FeeLadderNotIncreasing));
        assert_eq!(
            build(&vec![1; MAX_CLAWBACK_FEE_LADDER_STEPS + 1]),
            Err(VaultTxError::FeeLadderTooLong),
        );
        assert_eq!(build(&[500, 10_001]), Err(VaultTxError::ExcessiveFee));
        assert_eq!(
            build_clawback_fee_ladder_checked(&p, OutPoint::null(), 100_000, &safe, &[500, 1_000])
                .map(|_| ()),
            Err(VaultTxError::NullOutpoint),
        );
    }
}
