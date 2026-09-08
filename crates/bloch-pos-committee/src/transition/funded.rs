// SPDX-License-Identifier: AGPL-3.0-or-later
//! Funded validator admission. Wire tag 0x0B has no legacy claimant.
//!
//! One PQ funding authority may consume several ordered UTXOs. A second,
//! role-separated PQ signature proves control of the validator key. Both sign
//! the complete intent, including the manifest digest and the withdrawal route.
//! No signature, client-supplied input value or predicted registry index is
//! part of the intent. State application checks everything before mutation.

use super::*;
use crate::state_root::EutxoEntry;

pub const FUNDED_DEPOSIT_TAG: u8 = 0x0b;
pub const MAX_FUNDING_INPUTS: usize = 128;
pub const ADMISSION_PQ_KEY_BYTES: usize = 3_749;
pub const ADMISSION_PQ_SIGNATURE_MAX: usize = 4_593;
const HYBRID_HEADER: [u8; 4] = [0xb1, 0x0c, 1, 0];
const INTENT_DOMAIN: &[u8] = b"BLOCH:VALIDATOR:DEPOSIT:V1";
const FUNDING_DOMAIN: &[u8] = b"BLOCH:VALIDATOR:FUNDING:V1";
const POSSESSION_DOMAIN: &[u8] = b"BLOCH:VALIDATOR:POSSESSION:V1";
const CLASS: fee_market::TxClass = fee_market::TxClass::Eutxo { inputs: 2 };

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FundingInput {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedDeposit {
    /// SHA3-256 of the canonical genesis manifest, including its clock.
    pub network_domain: [u8; 32],
    /// Inclusive expiry, checked against the candidate block's epoch.
    pub valid_until_epoch: u64,
    pub funding_pubkey: Vec<u8>,
    /// Strict lexicographic order, with no duplicate outpoints.
    pub inputs: Vec<FundingInput>,
    pub validator_pubkey: Vec<u8>,
    pub amount_sat: u128,
    pub randao_commitment: [u8; 32],
    pub withdrawal_credentials: [u8; 32],
    pub commission_bps: u128,
    /// Guaranteed minimum change. Unused base-fee budget returns here too.
    pub change: TransferOutput,
    pub max_base_fee_millisat_per_gas: u128,
    pub tip_millisat_per_gas: u128,
    /// Fixed worst-case witness reservation, independent of Falcon randomness.
    pub tx_bytes: u64,
    pub funding_signature: Vec<u8>,
    pub proof_of_possession: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundedDepositReject {
    NotActive,
    Network,
    Expired,
    Shape,
    Signature,
    Stake,
    AlreadyRegistered,
    MissingInput,
    Ownership,
    FeeCap,
    Conservation,
    OutputCollision,
    RegistryFull,
    Arithmetic,
}

impl FundedDeposit {
    // Length prefixes remain explicit even for fixed-size keys, so invalid
    // in-memory values cannot create an ambiguous signing preimage.
    fn intent_bytes(&self) -> Vec<u8> {
        fn bytes(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        let mut b = vec![FUNDED_DEPOSIT_TAG];
        b.extend_from_slice(&self.network_domain);
        b.extend_from_slice(&self.valid_until_epoch.to_le_bytes());
        bytes(&mut b, &self.funding_pubkey);
        b.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            b.extend_from_slice(&input.txid);
            b.extend_from_slice(&input.vout.to_le_bytes());
        }
        bytes(&mut b, &self.validator_pubkey);
        b.extend_from_slice(&self.amount_sat.to_le_bytes());
        b.extend_from_slice(&self.randao_commitment);
        b.extend_from_slice(&self.withdrawal_credentials);
        b.extend_from_slice(&self.commission_bps.to_le_bytes());
        b.extend_from_slice(&self.change.value.to_le_bytes());
        b.extend_from_slice(&self.change.script_hash);
        b.extend_from_slice(&self.max_base_fee_millisat_per_gas.to_le_bytes());
        b.extend_from_slice(&self.tip_millisat_per_gas.to_le_bytes());
        b.extend_from_slice(&self.tx_bytes.to_le_bytes());
        b
    }

    pub fn intent_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(INTENT_DOMAIN);
        h.update(self.intent_bytes());
        h.finalize().into()
    }

    fn role_root(&self, role: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(role);
        h.update(self.intent_root());
        h.finalize().into()
    }

    pub fn funding_root(&self) -> [u8; 32] {
        self.role_root(FUNDING_DOMAIN)
    }
    pub fn possession_root(&self) -> [u8; 32] {
        self.role_root(POSSESSION_DOMAIN)
    }

    pub fn reserved_tx_bytes(&self) -> u64 {
        (self.intent_bytes().len() as u64)
            .saturating_add(8) // two u32 signature lengths
            .saturating_add((ADMISSION_PQ_SIGNATURE_MAX as u64).saturating_mul(2))
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = self.intent_bytes();
        for sig in [&self.funding_signature, &self.proof_of_possession] {
            b.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            b.extend_from_slice(sig);
        }
        b
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        fn bounded(r: &mut TxReader<'_>, max: usize) -> Result<Vec<u8>, TxDecodeError> {
            let n = r.u32()? as usize;
            if n > max {
                return Err(TxDecodeError::NotCanonical(FUNDED_DEPOSIT_TAG));
            }
            Ok(r.take(n)?.to_vec())
        }
        let network_domain = r.h32()?;
        let valid_until_epoch = r.u64()?;
        let funding_pubkey = bounded(r, ADMISSION_PQ_KEY_BYTES)?;
        let n = r.u32()? as usize;
        if n == 0 || n > MAX_FUNDING_INPUTS {
            return Err(TxDecodeError::NotCanonical(FUNDED_DEPOSIT_TAG));
        }
        let mut inputs = Vec::new();
        for _ in 0..n {
            inputs.push(FundingInput {
                txid: r.h32()?,
                vout: r.u32()?,
            });
        }
        let validator_pubkey = bounded(r, ADMISSION_PQ_KEY_BYTES)?;
        let tx = Self {
            network_domain,
            valid_until_epoch,
            funding_pubkey,
            inputs,
            validator_pubkey,
            amount_sat: r.u128()?,
            randao_commitment: r.h32()?,
            withdrawal_credentials: r.h32()?,
            commission_bps: r.u128()?,
            change: TransferOutput {
                value: r.u64()?,
                script_hash: r.h32()?,
            },
            max_base_fee_millisat_per_gas: r.u128()?,
            tip_millisat_per_gas: r.u128()?,
            tx_bytes: r.u64()?,
            funding_signature: bounded(r, ADMISSION_PQ_SIGNATURE_MAX)?,
            proof_of_possession: bounded(r, ADMISSION_PQ_SIGNATURE_MAX)?,
        };
        tx.validate_shape()
            .map_err(|_| TxDecodeError::NotCanonical(FUNDED_DEPOSIT_TAG))?;
        Ok(tx)
    }

    /// Also accepts unsigned drafts; neither consensus nor mempool stops here.
    pub fn validate_shape(&self) -> Result<(), FundedDepositReject> {
        let key_ok =
            |key: &[u8]| key.len() == ADMISSION_PQ_KEY_BYTES && key.starts_with(&HYBRID_HEADER);
        if !key_ok(&self.funding_pubkey)
            || !key_ok(&self.validator_pubkey)
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_FUNDING_INPUTS
            || self.inputs.windows(2).any(|w| w[0] >= w[1])
            || self.commission_bps > rewards::MAX_COMMISSION_BPS
            || self.amount_sat < staking::MIN_DEPOSIT_SAT
            || self.amount_sat > tokenomics_v4::TOTAL_SUPPLY_SAT
            || self.randao_commitment == [0; 32]
            || self.withdrawal_credentials == [0; 32]
            || self.change.value < crate::params::MIN_TRANSFER_OUTPUT_SAT
            || !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS
                ..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
                .contains(&self.max_base_fee_millisat_per_gas)
            || self.tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS
            || self.tx_bytes != self.reserved_tx_bytes()
            || fee_market::intrinsic_gas(CLASS, self.tx_bytes) > fee_market::MAX_TX_GAS
            || self.funding_signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || self.proof_of_possession.len() > ADMISSION_PQ_SIGNATURE_MAX
        {
            return Err(FundedDepositReject::Shape);
        }
        Ok(())
    }

    /// Both roles require the enveloped ML-DSA-65 AND Falcon-1024 suite.
    pub fn verify_authorizations(
        &self,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FundedDepositReject> {
        self.validate_shape()?;
        let signature_ok = |sig: &[u8]| sig.len() > 3_313 && sig.starts_with(&HYBRID_HEADER);
        if !signature_ok(&self.funding_signature)
            || !signature_ok(&self.proof_of_possession)
            || !verifier.verify_with_key(
                &self.funding_pubkey,
                &self.funding_root(),
                &self.funding_signature,
            )
            || !verifier.verify_with_key(
                &self.validator_pubkey,
                &self.possession_root(),
                &self.proof_of_possession,
            )
        {
            return Err(FundedDepositReject::Signature);
        }
        Ok(())
    }

    /// Maximum amount consumed from funding UTXOs; input values are resolved by
    /// consensus, never taken from an offline wallet's estimates.
    pub fn required_funding_sat(&self) -> Option<u128> {
        let c = self.charge(self.max_base_fee_millisat_per_gas);
        self.amount_sat
            .checked_add(u128::from(self.change.value))?
            .checked_add(c.base_fee_sat)?
            .checked_add(c.priority_fee_sat)
    }

    pub fn charge(&self, base_fee: u128) -> fee_market::TxCharge {
        fee_market::charge(CLASS, self.tx_bytes, base_fee, self.tip_millisat_per_gas)
    }
}

impl CommittedState {
    /// Immutable context supplied by genesis construction, not a mutable
    /// transaction field or an operator's runtime consensus override.
    pub fn admission_network_domain(&self) -> Option<[u8; 32]> {
        self.admission_network_domain
    }

    pub fn validator_index_by_pubkey(&self, pubkey: &[u8]) -> Option<u32> {
        let hash: [u8; 32] = Sha3_256::digest(pubkey).into();
        let index = *self.pubkey_index.get(&hash)?;
        (self.validators.get(&index)?.pubkey == pubkey).then_some(index)
    }

    pub fn validator_reveals_used(&self, index: u32) -> Option<u32> {
        self.reveals_used.get(&index).copied()
    }

    pub fn validator_index_by_hash(&self, hash: &[u8; 32]) -> Option<u32> {
        self.pubkey_index.get(hash).copied()
    }

    pub(super) fn apply_funded_deposit(
        &mut self,
        tx: &FundedDeposit,
        total_active: u128,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, FundedDepositReject> {
        use FundedDepositReject as R;
        if !crate::params::funded_validator_admission_active(self.epoch) {
            return Err(R::NotActive);
        }
        tx.validate_shape()?;
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if self.epoch > tx.valid_until_epoch {
            return Err(R::Expired);
        }
        let cap = total_active
            .checked_mul(delegation::MAX_VALIDATOR_STAKE_BPS)
            .ok_or(R::Arithmetic)?
            .checked_div(10_000)
            .ok_or(R::Arithmetic)?
            .max(staking::MIN_DEPOSIT_SAT);
        // deposit_shape owns the economic limits; the envelope has already
        // been checked above, so pass the raw suite-1 public-key geometry.
        staking::deposit_shape(
            staking::SUITE_MLDSA65_FALCON1024,
            staking::HYBRID_PK_BYTES,
            tx.amount_sat,
            cap,
        )
        .map_err(|_| R::Stake)?;
        let hash: [u8; 32] = Sha3_256::digest(&tx.validator_pubkey).into();
        if self.pubkey_index.contains_key(&hash) {
            return Err(R::AlreadyRegistered);
        }
        let index = match self.validators.keys().next_back() {
            Some(last) => last.checked_add(1).ok_or(R::RegistryFull)?,
            None => 0,
        };
        if base_fee > tx.max_base_fee_millisat_per_gas {
            return Err(R::FeeCap);
        }
        let mut spent = 0u128;
        let owner: [u8; 32] = Sha3_256::digest(&tx.funding_pubkey).into();
        for input in &tx.inputs {
            let utxo = self
                .eutxos
                .get(&(input.txid, input.vout))
                .ok_or(R::MissingInput)?;
            if utxo.script_hash != owner {
                return Err(R::Ownership);
            }
            spent = spent
                .checked_add(u128::from(utxo.value))
                .ok_or(R::Arithmetic)?;
        }
        if Some(spent) != tx.required_funding_sat() {
            return Err(R::Conservation);
        }
        let charge = tx.charge(base_fee);
        let refund = tx
            .charge(tx.max_base_fee_millisat_per_gas)
            .base_fee_sat
            .checked_sub(charge.base_fee_sat)
            .ok_or(R::Arithmetic)?;
        let change = u128::from(tx.change.value)
            .checked_add(refund)
            .ok_or(R::Arithmetic)?;
        let value = u64::try_from(change).map_err(|_| R::Arithmetic)?;
        let id = PosTransaction::FundedDeposit(tx.clone()).txid();
        if self.eutxos.contains_key(&(id, 0)) {
            return Err(R::OutputCollision);
        }
        tx.verify_authorizations(verifier)?;

        // All fallible work is complete. The outer transition also applies on
        // an isolated candidate state, preserving atomic block rejection.
        for input in &tx.inputs {
            self.eutxos.remove(&(input.txid, input.vout));
        }
        self.eutxos.insert(EutxoEntry {
            txid: id,
            vout: 0,
            value,
            script_hash: tx.change.script_hash,
        });
        self.validators.insert(
            index,
            ValidatorRecord {
                index,
                pubkey: tx.validator_pubkey.clone(),
                staked_sat: tx.amount_sat,
                randao_commitment: tx.randao_commitment,
                withdrawal_credentials: tx.withdrawal_credentials.to_vec(),
                activation_epoch: u64::MAX,
                exit_epoch: u64::MAX,
                withdrawable_epoch: u64::MAX,
                slashed: false,
                commission_bps: tx.commission_bps,
            },
        );
        self.pubkey_index.insert(hash, index);
        self.reveals_used.insert(index, 0);
        self.deposit_history.push(QueuedDeposit {
            pubkey_hash: hash,
            deposit_epoch: self.epoch,
            amount_sat: tx.amount_sat,
        });
        Ok(charge)
    }
}
