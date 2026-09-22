//! Explicit opt-in construction with an independent deposit signing key.
//!
//! This changes the deposit script/address for NEW vaults only. It does not
//! migrate funded `VaultParams` outputs or alter V1/V2/V3 key derivation.
//! The caller supplies an ephemeral deposit key generated independently of any
//! retained seed. Distinct public keys are checked; independence and deletion
//! cannot be established from public keys and are not enforced by this type.
//! Once a deposit witness exposes its key and preimage, a quantum attacker may
//! still forge a competing bypass spend. This is NOT a Bitcoin covenant or a
//! quantum-security guarantee, and requires external script/operational review.

use bitcoin::{Address, OutPoint, PublicKey, ScriptBuf, Transaction};
use crate::vault::{self, VaultParams};

/// New-construction version, independent of the existing key-derivation versions.
/// Persist this label and all public parameters with the vault backup. Never
/// infer it when restoring a funded legacy shared-key deposit.
pub const CONSTRUCTION_NAME: &str = "separated-deposit-v1";

/// Public parameters for an independent deposit key plus retained spend keys.
/// Private fields prevent changing validated role keys or delay after creation.
#[derive(Clone, Debug)]
pub struct SeparatedDepositV1 {
    deposit_pubkey: PublicKey,
    trigger: VaultParams,
}

impl SeparatedDepositV1 {
    /// Validate public construction parameters. `deposit_pubkey` must come from
    /// a key the caller can actually remove after preparing the unvault package,
    /// not from the retained hot/recovery mnemonic. This API cannot verify that.
    pub fn new(deposit_pubkey: PublicKey, trigger: VaultParams) -> Result<Self, &'static str> {
        if !deposit_pubkey.compressed || !trigger.hot_pubkey.compressed || !trigger.recovery_pubkey.compressed {
            return Err("all vault role keys must be compressed");
        }
        if deposit_pubkey == trigger.hot_pubkey || deposit_pubkey == trigger.recovery_pubkey
            || trigger.hot_pubkey == trigger.recovery_pubkey {
            return Err("deposit, delayed-spend and recovery keys must be distinct");
        }
        if trigger.csv_delay < vault::MIN_NEW_VAULT_CSV_DELAY {
            return Err("new separated-deposit constructions require at least 144 blocks of delay");
        }
        Ok(Self { deposit_pubkey, trigger })
    }

    /// Public key guarding this construction's deposit, not branch A.
    pub fn deposit_pubkey(&self) -> PublicKey { self.deposit_pubkey }

    /// Existing trigger parameters, unchanged. Use these for branch A/B
    /// transactions; do not use their shared-key legacy deposit constructor.
    pub fn trigger_params(&self) -> &VaultParams { &self.trigger }

    /// Deposit witness script using the independent deposit key.
    pub fn deposit_script(&self) -> ScriptBuf {
        vault::deposit_script(&self.trigger.recovery_hash, &self.deposit_pubkey)
    }

    /// NEW deposit address. It differs from the legacy hot-key deposit address.
    pub fn deposit_address(&self) -> Address {
        Address::p2wsh(&self.deposit_script(), self.trigger.network)
    }

    /// The retained trigger remains the existing two-branch script.
    pub fn trigger_script(&self) -> ScriptBuf { vault::trigger_script(&self.trigger) }

    /// Build an unsigned, checked unvault transaction. Its deposit sighash must
    /// use `self.deposit_script()` and be signed by the independent deposit key.
    /// Funding existence, fee adequacy, package backup and key deletion are not
    /// checked here. No signing key is accepted or retained by this builder.
    pub fn build_unvault_tx(&self, outpoint: OutPoint, amount_sat: u64, fee_sat: u64)
        -> Result<Transaction, &'static str> {
        vault::build_unvault_tx_checked(&self.trigger, outpoint, amount_sat, fee_sat)
            .map_err(|error| match error {
                vault::VaultTxError::NullOutpoint => "deposit outpoint cannot be null",
                vault::VaultTxError::AmountOutOfRange => "deposit amount exceeds Bitcoin money range",
                vault::VaultTxError::FeeExceedsAmount => "fee exceeds deposit amount",
                vault::VaultTxError::ExcessiveFee => "fee exceeds the checked builder safety limit",
                vault::VaultTxError::DustOutput => "unvault output is below the script dust threshold",
                vault::VaultTxError::CsvDelayTooShort => "CSV delay is below the new-construction minimum",
                vault::VaultTxError::UncompressedRoleKey => "vault role keys must be compressed",
                vault::VaultTxError::ReusedRoleKey => "vault role keys must be distinct",
                vault::VaultTxError::InvalidInputIndex => "unexpected sighash input index",
                vault::VaultTxError::FeeLadderTooShort => "unexpected fee ladder error",
                vault::VaultTxError::FeeLadderTooLong => "unexpected fee ladder error",
                vault::VaultTxError::FeeLadderNotIncreasing => "unexpected fee ladder error",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, Network, Txid};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use crate::{ecdsa_witness_sig, preimage::recovery_hash, script_eval::{eval, EvalCtx}};

    fn key(value: u8) -> (SecretKey, PublicKey) {
        let secret = SecretKey::from_slice(&[value; 32]).unwrap();
        let public = PublicKey::new(secret.public_key(&Secp256k1::new()));
        (secret, public)
    }
    fn params() -> VaultParams {
        VaultParams { hot_pubkey: key(2).1, recovery_pubkey: key(3).1,
            recovery_hash: recovery_hash(&[4; 32]), csv_delay: 144, network: Network::Regtest }
    }
    fn outpoint() -> OutPoint { OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 } }

    #[test]
    fn independent_deposit_key_cannot_be_replaced_by_retained_hot_key() {
        let (deposit, public) = key(1);
        let construction = SeparatedDepositV1::new(public, params()).unwrap();
        assert_ne!(construction.deposit_address(), vault::deposit_address(&params()));
        assert_eq!(construction.trigger_script(), vault::trigger_script(&params()));
        let tx = construction.build_unvault_tx(outpoint(), 100_000, 500).unwrap();
        let script = construction.deposit_script();
        let hash = vault::p2wsh_sighash(&tx, 0, &script, 100_000);
        let ctx = EvalCtx { input_sequence: tx.input[0].sequence, confirmations: 0,
            tx_version: tx.version.0, sighash: hash };
        assert_eq!(eval(&Secp256k1::new(), &script,
            vec![ecdsa_witness_sig(&hash, &deposit), vec![4;32]], &ctx), Ok(true));
        assert_eq!(eval(&Secp256k1::new(), &script,
            vec![ecdsa_witness_sig(&hash, &key(2).0), vec![4;32]], &ctx), Ok(false));

        let destination = construction.deposit_address();
        let branch_a = vault::build_branch_a_tx(construction.trigger_params(), outpoint(), 99_500, &destination, 500);
        let trigger = construction.trigger_script();
        let hash = vault::p2wsh_sighash(&branch_a, 0, &trigger, 99_500);
        let ctx = EvalCtx { input_sequence: branch_a.input[0].sequence, confirmations: 144,
            tx_version: branch_a.version.0, sighash: hash };
        assert_eq!(eval(&Secp256k1::new(), &trigger,
            vec![ecdsa_witness_sig(&hash, &key(2).0), vec![1]], &ctx), Ok(true));
        assert_eq!(eval(&Secp256k1::new(), &trigger,
            vec![ecdsa_witness_sig(&hash, &deposit), vec![1]], &ctx), Ok(false));
    }

    #[test]
    fn new_construction_refuses_shared_roles_short_delay_and_bad_values() {
        assert!(SeparatedDepositV1::new(key(2).1, params()).is_err());
        assert!(SeparatedDepositV1::new(key(3).1, params()).is_err());
        let mut same = params(); same.recovery_pubkey = same.hot_pubkey;
        assert!(SeparatedDepositV1::new(key(1).1, same).is_err());
        let mut short = params(); short.csv_delay = 143;
        assert!(SeparatedDepositV1::new(key(1).1, short).is_err());
        let mut uncompressed = key(1).1; uncompressed.compressed = false;
        assert!(SeparatedDepositV1::new(uncompressed, params()).is_err());
        let construction = SeparatedDepositV1::new(key(1).1, params()).unwrap();
        for (amount, fee) in [(1,2), (1,0), (u64::MAX,0)] {
            assert!(construction.build_unvault_tx(outpoint(), amount, fee).is_err());
        }
        assert!(construction.build_unvault_tx(OutPoint::null(), 100_000, 500).is_err());
    }
}
