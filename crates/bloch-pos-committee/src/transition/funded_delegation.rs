// SPDX-License-Identifier: AGPL-3.0-or-later
//! UTXO-funded delegation lifecycle. Consensus remains inert until
//! `FUNDED_DELEGATION_ACTIVATION_EPOCH` is explicitly armed.

use super::*;
use crate::state_root::EutxoEntry;

pub const FUNDED_DELEGATE_TAG: u8 = 0x0e;
pub const FUNDED_UNDELEGATE_TAG: u8 = 0x0f;
pub const FUNDED_DELEGATION_WITHDRAW_TAG: u8 = 0x10;
pub const VALIDATOR_COMMISSION_UPDATE_TAG: u8 = 0x11;

const KEY_BYTES: usize = funded::ADMISSION_PQ_KEY_BYTES;
const SIGNATURE_MAX: usize = funded::ADMISSION_PQ_SIGNATURE_MAX;
const HYBRID_HEADER: [u8; 4] = [0xb1, 0x0c, 1, 0];
const DELEGATE_DOMAIN: &[u8] = b"BLOCH:DELEGATION:FUND:V1";
const UNDELEGATE_DOMAIN: &[u8] = b"BLOCH:DELEGATION:DEACTIVATE:V1";
const WITHDRAW_DOMAIN: &[u8] = b"BLOCH:DELEGATION:WITHDRAW:V1";
const COMMISSION_DOMAIN: &[u8] = b"BLOCH:VALIDATOR:COMMISSION:V1";
const DELEGATE_CLASS: fee_market::TxClass = fee_market::TxClass::Eutxo { inputs: 2 };

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedDelegate {
    pub network_domain: [u8; 32],
    pub valid_until_epoch: u64,
    pub funding_pubkey: Vec<u8>,
    pub inputs: Vec<FundingInput>,
    pub validator_pubkey_hash: [u8; 32],
    pub amount_sat: u128,
    pub change: TransferOutput,
    pub max_base_fee_millisat_per_gas: u128,
    pub tip_millisat_per_gas: u128,
    pub tx_bytes: u64,
    pub funding_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedUndelegate {
    pub network_domain: [u8; 32],
    pub epoch: u64,
    pub delegator_id: u32,
    pub position: u32,
    pub funding_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedDelegationWithdraw {
    pub network_domain: [u8; 32],
    pub epoch: u64,
    pub delegator_id: u32,
    pub position: u32,
    pub funding_pubkey: Vec<u8>,
    pub destination_script_hash: [u8; 32],
    pub max_base_fee_millisat_per_gas: u128,
    pub signature: Vec<u8>,
}

/// Validator-key-authorized update of the reward commission advertised to
/// future delegators. Increases are only valid while no live or pending
/// delegation targets the validator; reductions remain possible at any time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorCommissionUpdate {
    pub network_domain: [u8; 32],
    pub epoch: u64,
    pub validator: u32,
    pub commission_bps: u128,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundedDelegationReject {
    NotActive,
    Network,
    Expired,
    Epoch,
    Shape,
    Signature,
    Validator,
    Position,
    Ownership,
    Stake,
    MissingInput,
    FeeCap,
    Conservation,
    OutputCollision,
    AlreadyDeactivating,
    NotInactive,
    WithdrawalDelay,
    AlreadyWithdrawn,
    Commission,
    CommissionIncreaseWithDelegations,
    Arithmetic,
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn bounded(r: &mut TxReader<'_>, max: usize, tag: u8) -> Result<Vec<u8>, TxDecodeError> {
    let n = r.u32()? as usize;
    if n > max {
        return Err(TxDecodeError::NotCanonical(tag));
    }
    Ok(r.take(n)?.to_vec())
}

fn role_root(domain: &[u8], intent: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain);
    h.update(intent);
    h.finalize().into()
}

fn key_has_shape(key: &[u8]) -> bool {
    key.len() == KEY_BYTES && key.starts_with(&HYBRID_HEADER)
}

fn signature_has_shape(signature: &[u8]) -> bool {
    signature.len() > 3_313
        && signature.len() <= SIGNATURE_MAX
        && signature.starts_with(&HYBRID_HEADER)
}

impl FundedDelegate {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut out = vec![FUNDED_DELEGATE_TAG];
        out.extend_from_slice(&self.network_domain);
        out.extend_from_slice(&self.valid_until_epoch.to_le_bytes());
        put_bytes(&mut out, &self.funding_pubkey);
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.vout.to_le_bytes());
        }
        out.extend_from_slice(&self.validator_pubkey_hash);
        out.extend_from_slice(&self.amount_sat.to_le_bytes());
        out.extend_from_slice(&self.change.value.to_le_bytes());
        out.extend_from_slice(&self.change.script_hash);
        out.extend_from_slice(&self.max_base_fee_millisat_per_gas.to_le_bytes());
        out.extend_from_slice(&self.tip_millisat_per_gas.to_le_bytes());
        out.extend_from_slice(&self.tx_bytes.to_le_bytes());
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(DELEGATE_DOMAIN, &self.intent_bytes())
    }

    pub fn reserved_tx_bytes(&self) -> u64 {
        (self.intent_bytes().len() as u64)
            .saturating_add(4)
            .saturating_add(SIGNATURE_MAX as u64)
    }

    pub fn charge(&self, base_fee: u128) -> fee_market::TxCharge {
        fee_market::charge(
            DELEGATE_CLASS,
            self.tx_bytes,
            base_fee,
            self.tip_millisat_per_gas,
        )
    }

    pub fn required_funding_sat(&self) -> Option<u128> {
        let charge = self.charge(self.max_base_fee_millisat_per_gas);
        self.amount_sat
            .checked_add(u128::from(self.change.value))?
            .checked_add(charge.base_fee_sat)?
            .checked_add(charge.priority_fee_sat)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent_bytes();
        put_bytes(&mut out, &self.funding_signature);
        out
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        let network_domain = r.h32()?;
        let valid_until_epoch = r.u64()?;
        let funding_pubkey = bounded(r, KEY_BYTES, FUNDED_DELEGATE_TAG)?;
        let count = r.u32()? as usize;
        if count > funded::MAX_FUNDING_INPUTS {
            return Err(TxDecodeError::NotCanonical(FUNDED_DELEGATE_TAG));
        }
        let mut inputs = Vec::new();
        for _ in 0..count {
            inputs.push(FundingInput {
                txid: r.h32()?,
                vout: r.u32()?,
            });
        }
        Ok(Self {
            network_domain,
            valid_until_epoch,
            funding_pubkey,
            inputs,
            validator_pubkey_hash: r.h32()?,
            amount_sat: r.u128()?,
            change: TransferOutput {
                value: r.u64()?,
                script_hash: r.h32()?,
            },
            max_base_fee_millisat_per_gas: r.u128()?,
            tip_millisat_per_gas: r.u128()?,
            tx_bytes: r.u64()?,
            funding_signature: bounded(r, SIGNATURE_MAX, FUNDED_DELEGATE_TAG)?,
        })
    }

    /// Accepts unsigned drafts; consensus authorization is a separate check.
    pub fn validate_shape(&self) -> Result<(), FundedDelegationReject> {
        if !key_has_shape(&self.funding_pubkey)
            || self.inputs.is_empty()
            || self.inputs.len() > funded::MAX_FUNDING_INPUTS
            || self.inputs.windows(2).any(|w| w[0] >= w[1])
            || self.validator_pubkey_hash == [0; 32]
            || self.amount_sat < delegation::MIN_DELEGATION_SAT
            || self.amount_sat > tokenomics_v4::TOTAL_SUPPLY_SAT
            || self.change.value < crate::params::MIN_TRANSFER_OUTPUT_SAT
            || !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS
                ..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
                .contains(&self.max_base_fee_millisat_per_gas)
            || self.tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS
            || self.tx_bytes != self.reserved_tx_bytes()
            || fee_market::intrinsic_gas(DELEGATE_CLASS, self.tx_bytes) > fee_market::MAX_TX_GAS
            || self.funding_signature.len() > SIGNATURE_MAX
        {
            return Err(FundedDelegationReject::Shape);
        }
        Ok(())
    }

    pub fn verify_authorization(
        &self,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FundedDelegationReject> {
        self.validate_shape()?;
        if !signature_has_shape(&self.funding_signature)
            || !verifier.verify_with_key(
                &self.funding_pubkey,
                &self.signing_root(),
                &self.funding_signature,
            )
        {
            return Err(FundedDelegationReject::Signature);
        }
        Ok(())
    }
}

impl FundedUndelegate {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut out = vec![FUNDED_UNDELEGATE_TAG];
        out.extend_from_slice(&self.network_domain);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.delegator_id.to_le_bytes());
        out.extend_from_slice(&self.position.to_le_bytes());
        put_bytes(&mut out, &self.funding_pubkey);
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(UNDELEGATE_DOMAIN, &self.intent_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent_bytes();
        put_bytes(&mut out, &self.signature);
        out
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        Ok(Self {
            network_domain: r.h32()?,
            epoch: r.u64()?,
            delegator_id: r.u32()?,
            position: r.u32()?,
            funding_pubkey: bounded(r, KEY_BYTES, FUNDED_UNDELEGATE_TAG)?,
            signature: bounded(r, SIGNATURE_MAX, FUNDED_UNDELEGATE_TAG)?,
        })
    }

    pub fn validate_shape(&self) -> Result<(), FundedDelegationReject> {
        if !key_has_shape(&self.funding_pubkey) || self.signature.len() > SIGNATURE_MAX {
            return Err(FundedDelegationReject::Shape);
        }
        Ok(())
    }

    pub fn verify_authorization(
        &self,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FundedDelegationReject> {
        self.validate_shape()?;
        if !signature_has_shape(&self.signature)
            || !verifier.verify_with_key(
                &self.funding_pubkey,
                &self.signing_root(),
                &self.signature,
            )
        {
            return Err(FundedDelegationReject::Signature);
        }
        Ok(())
    }
}

impl FundedDelegationWithdraw {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut out = vec![FUNDED_DELEGATION_WITHDRAW_TAG];
        out.extend_from_slice(&self.network_domain);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.delegator_id.to_le_bytes());
        out.extend_from_slice(&self.position.to_le_bytes());
        put_bytes(&mut out, &self.funding_pubkey);
        out.extend_from_slice(&self.destination_script_hash);
        out.extend_from_slice(&self.max_base_fee_millisat_per_gas.to_le_bytes());
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(WITHDRAW_DOMAIN, &self.intent_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent_bytes();
        put_bytes(&mut out, &self.signature);
        out
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        Ok(Self {
            network_domain: r.h32()?,
            epoch: r.u64()?,
            delegator_id: r.u32()?,
            position: r.u32()?,
            funding_pubkey: bounded(r, KEY_BYTES, FUNDED_DELEGATION_WITHDRAW_TAG)?,
            destination_script_hash: r.h32()?,
            max_base_fee_millisat_per_gas: r.u128()?,
            signature: bounded(r, SIGNATURE_MAX, FUNDED_DELEGATION_WITHDRAW_TAG)?,
        })
    }

    pub fn validate_shape(&self) -> Result<(), FundedDelegationReject> {
        if !key_has_shape(&self.funding_pubkey)
            || self.destination_script_hash == [0; 32]
            || !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS
                ..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
                .contains(&self.max_base_fee_millisat_per_gas)
            || self.signature.len() > SIGNATURE_MAX
        {
            return Err(FundedDelegationReject::Shape);
        }
        Ok(())
    }

    pub fn verify_authorization(
        &self,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), FundedDelegationReject> {
        self.validate_shape()?;
        if !signature_has_shape(&self.signature)
            || !verifier.verify_with_key(
                &self.funding_pubkey,
                &self.signing_root(),
                &self.signature,
            )
        {
            return Err(FundedDelegationReject::Signature);
        }
        Ok(())
    }

    pub fn charge(&self, base_fee: u128) -> fee_market::TxCharge {
        fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            self.canonical_bytes().len() as u64,
            base_fee,
            0,
        )
    }
}

impl ValidatorCommissionUpdate {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut out = vec![VALIDATOR_COMMISSION_UPDATE_TAG];
        out.extend_from_slice(&self.network_domain);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.validator.to_le_bytes());
        out.extend_from_slice(&self.commission_bps.to_le_bytes());
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(COMMISSION_DOMAIN, &self.intent_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent_bytes();
        put_bytes(&mut out, &self.signature);
        out
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        Ok(Self {
            network_domain: r.h32()?,
            epoch: r.u64()?,
            validator: r.u32()?,
            commission_bps: r.u128()?,
            signature: bounded(r, SIGNATURE_MAX, VALIDATOR_COMMISSION_UPDATE_TAG)?,
        })
    }

    pub fn validate_shape(&self) -> Result<(), FundedDelegationReject> {
        if self.commission_bps > rewards::MAX_COMMISSION_BPS || self.signature.len() > SIGNATURE_MAX
        {
            return Err(FundedDelegationReject::Shape);
        }
        Ok(())
    }
}

impl CommittedState {
    fn funded_owner_matches(
        &self,
        delegator_id: u32,
        funding_pubkey: &[u8],
    ) -> Result<(), FundedDelegationReject> {
        let owner: [u8; 32] = Sha3_256::digest(funding_pubkey).into();
        match self.funded_delegation_owners.get(&delegator_id) {
            Some(committed) if *committed == owner => Ok(()),
            _ => Err(FundedDelegationReject::Ownership),
        }
    }

    pub(super) fn apply_funded_delegate(
        &mut self,
        tx: &FundedDelegate,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, FundedDelegationReject> {
        use FundedDelegationReject as R;
        if !crate::params::funded_delegation_active(self.epoch) {
            return Err(R::NotActive);
        }
        tx.validate_shape()?;
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if self.epoch > tx.valid_until_epoch {
            return Err(R::Expired);
        }
        let validator = self
            .validator_index_by_hash(&tx.validator_pubkey_hash)
            .ok_or(R::Validator)?;
        let record = self.validators.get(&validator).ok_or(R::Validator)?;
        if record.slashed || record.exit_epoch != u64::MAX || record.activation_epoch > self.epoch {
            return Err(R::Validator);
        }
        if base_fee > tx.max_base_fee_millisat_per_gas {
            return Err(R::FeeCap);
        }
        let owner: [u8; 32] = Sha3_256::digest(&tx.funding_pubkey).into();
        let mut spent = 0u128;
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
        let change = u64::try_from(change).map_err(|_| R::Arithmetic)?;
        let txid = PosTransaction::FundedDelegate(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(R::OutputCollision);
        }
        let delegator_id = self
            .delegations
            .iter()
            .map(|d| d.delegator)
            .chain(self.funded_delegation_owners.keys().copied())
            .max()
            .map_or(Some(0), |last| last.checked_add(1))
            .ok_or(R::Arithmetic)?;
        let requested_epoch = self.epoch.checked_add(1).ok_or(R::Arithmetic)?;
        let position = u32::try_from(self.delegations.len()).map_err(|_| R::Arithmetic)?;
        tx.verify_authorization(verifier)?;

        for input in &tx.inputs {
            self.eutxos.remove(&(input.txid, input.vout));
        }
        self.eutxos.insert(EutxoEntry {
            txid,
            vout: 0,
            value: change,
            script_hash: tx.change.script_hash,
        });
        self.delegations.push(Delegation {
            delegator: delegator_id,
            validator,
            amount_sat: tx.amount_sat,
            requested_epoch,
            deactivate_epoch: None,
            eligible: true,
        });
        self.funded_delegation_owners.insert(delegator_id, owner);
        debug_assert_eq!(position as usize + 1, self.delegations.len());
        Ok(charge)
    }

    pub(super) fn apply_validator_commission_update(
        &mut self,
        tx: &ValidatorCommissionUpdate,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, FundedDelegationReject> {
        use FundedDelegationReject as R;
        if !crate::params::funded_delegation_active(self.epoch) {
            return Err(R::NotActive);
        }
        tx.validate_shape()?;
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if tx.epoch != self.epoch {
            return Err(R::Epoch);
        }
        let record = self.validators.get(&tx.validator).ok_or(R::Validator)?;
        if record.slashed || record.exit_epoch != u64::MAX {
            return Err(R::Validator);
        }
        if tx.commission_bps == record.commission_bps {
            return Err(R::Commission);
        }
        if tx.commission_bps > record.commission_bps {
            let registry = delegation::Registry::resolve(&self.delegations, self.epoch);
            if self.delegations.iter().any(|delegation| {
                delegation.validator == tx.validator
                    && (registry.state_of(delegation) != delegation::StakeState::Inactive
                        || registry.activated_sat(delegation) != 0)
            }) {
                return Err(R::CommissionIncreaseWithDelegations);
            }
        }
        if !signature_has_shape(&tx.signature)
            || !verifier.verify_with_key(&record.pubkey, &tx.signing_root(), &tx.signature)
        {
            return Err(R::Signature);
        }

        self.validators
            .get_mut(&tx.validator)
            .expect("validator existence checked above")
            .commission_bps = tx.commission_bps;
        Ok(Self::staking_tx_charge(
            self.epoch,
            1,
            tx.canonical_bytes().len(),
        ))
    }

    pub(super) fn apply_funded_undelegate(
        &mut self,
        tx: &FundedUndelegate,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, FundedDelegationReject> {
        use FundedDelegationReject as R;
        if !crate::params::funded_delegation_active(self.epoch) {
            return Err(R::NotActive);
        }
        tx.validate_shape()?;
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if tx.epoch != self.epoch {
            return Err(R::Epoch);
        }
        self.funded_owner_matches(tx.delegator_id, &tx.funding_pubkey)?;
        let position = usize::try_from(tx.position).map_err(|_| R::Position)?;
        let delegation = self.delegations.get(position).ok_or(R::Position)?;
        if delegation.delegator != tx.delegator_id {
            return Err(R::Position);
        }
        if delegation.deactivate_epoch.is_some() {
            return Err(R::AlreadyDeactivating);
        }
        if self
            .funded_delegation_lifecycle
            .get(&tx.position)
            .is_some_and(|(_, withdrawn)| *withdrawn)
        {
            return Err(R::AlreadyWithdrawn);
        }
        let deactivate_epoch = self.epoch.checked_add(1).ok_or(R::Arithmetic)?;
        tx.verify_authorization(verifier)?;

        self.delegations[position].deactivate_epoch = Some(deactivate_epoch);
        self.funded_delegation_lifecycle
            .insert(tx.position, (u64::MAX, false));
        Ok(Self::staking_tx_charge(
            self.epoch,
            1,
            tx.canonical_bytes().len(),
        ))
    }

    pub(super) fn apply_funded_delegation_withdrawal(
        &mut self,
        tx: &FundedDelegationWithdraw,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, FundedDelegationReject> {
        use FundedDelegationReject as R;
        if !crate::params::funded_delegation_active(self.epoch) {
            return Err(R::NotActive);
        }
        tx.validate_shape()?;
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if tx.epoch != self.epoch {
            return Err(R::Epoch);
        }
        if base_fee > tx.max_base_fee_millisat_per_gas {
            return Err(R::FeeCap);
        }
        self.funded_owner_matches(tx.delegator_id, &tx.funding_pubkey)?;
        let position = usize::try_from(tx.position).map_err(|_| R::Position)?;
        let delegation = *self.delegations.get(position).ok_or(R::Position)?;
        if delegation.delegator != tx.delegator_id {
            return Err(R::Position);
        }
        let (inactive_since, withdrawn) = self
            .funded_delegation_lifecycle
            .get(&tx.position)
            .copied()
            .ok_or(R::NotInactive)?;
        if withdrawn {
            return Err(R::AlreadyWithdrawn);
        }
        if inactive_since == u64::MAX {
            return Err(R::NotInactive);
        }
        let withdrawable = inactive_since
            .checked_add(staking::WITHDRAWAL_DELAY_EPOCHS)
            .ok_or(R::Arithmetic)?;
        let registry = delegation::Registry::resolve(&self.delegations, self.epoch);
        if self.epoch < withdrawable
            || registry.state_of(&delegation) != delegation::StakeState::Inactive
            || registry.activated_sat(&delegation) != 0
        {
            return Err(R::WithdrawalDelay);
        }
        let loss = self
            .delegator_slash_losses
            .get(&tx.delegator_id)
            .copied()
            .unwrap_or(0);
        let fees = self
            .delegator_fee_rewards
            .get(&tx.delegator_id)
            .copied()
            .unwrap_or(0);
        let issuance = self
            .delegator_issuance_rewards
            .get(&tx.delegator_id)
            .copied()
            .unwrap_or(0);
        let charge = tx.charge(base_fee);
        let payout = delegation
            .amount_sat
            .checked_sub(loss)
            .and_then(|v| v.checked_add(fees))
            .and_then(|v| v.checked_add(issuance))
            .and_then(|v| v.checked_sub(charge.base_fee_sat))
            .ok_or(R::Arithmetic)?;
        let payout = u64::try_from(payout).map_err(|_| R::Arithmetic)?;
        if payout < crate::params::MIN_TRANSFER_OUTPUT_SAT {
            return Err(R::Stake);
        }
        let txid = PosTransaction::FundedDelegationWithdraw(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(R::OutputCollision);
        }
        tx.verify_authorization(verifier)?;

        self.eutxos.insert(EutxoEntry {
            txid,
            vout: 0,
            value: payout,
            script_hash: tx.destination_script_hash,
        });
        self.funded_delegation_lifecycle
            .insert(tx.position, (inactive_since, true));
        self.delegator_slash_losses.remove(&tx.delegator_id);
        self.delegator_fee_rewards.remove(&tx.delegator_id);
        self.delegator_issuance_rewards.remove(&tx.delegator_id);
        Ok(charge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> Vec<u8> {
        let mut key = vec![tag; KEY_BYTES];
        key[..HYBRID_HEADER.len()].copy_from_slice(&HYBRID_HEADER);
        key
    }

    fn delegate() -> FundedDelegate {
        let mut tx = FundedDelegate {
            network_domain: [1; 32],
            valid_until_epoch: 99,
            funding_pubkey: key(2),
            inputs: vec![FundingInput {
                txid: [3; 32],
                vout: 4,
            }],
            validator_pubkey_hash: [5; 32],
            amount_sat: delegation::MIN_DELEGATION_SAT,
            change: TransferOutput {
                value: crate::params::MIN_TRANSFER_OUTPUT_SAT,
                script_hash: [6; 32],
            },
            max_base_fee_millisat_per_gas: fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            tip_millisat_per_gas: 0,
            tx_bytes: 0,
            funding_signature: Vec::new(),
        };
        tx.tx_bytes = tx.reserved_tx_bytes();
        tx
    }

    #[test]
    fn funded_delegate_wire_round_trip() {
        let tx = delegate();
        assert_eq!(tx.validate_shape(), Ok(()));
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes[0], FUNDED_DELEGATE_TAG);
        let mut r = TxReader { b: &bytes, i: 1 };
        assert_eq!(FundedDelegate::decode(&mut r), Ok(tx));
        assert_eq!(r.i, bytes.len());
    }

    #[test]
    fn lifecycle_roots_are_role_separated() {
        let undelegate = FundedUndelegate {
            network_domain: [1; 32],
            epoch: 9,
            delegator_id: 7,
            position: 3,
            funding_pubkey: key(2),
            signature: Vec::new(),
        };
        let withdraw = FundedDelegationWithdraw {
            network_domain: undelegate.network_domain,
            epoch: undelegate.epoch,
            delegator_id: undelegate.delegator_id,
            position: undelegate.position,
            funding_pubkey: undelegate.funding_pubkey.clone(),
            destination_script_hash: [8; 32],
            max_base_fee_millisat_per_gas: fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            signature: Vec::new(),
        };
        assert_ne!(undelegate.signing_root(), withdraw.signing_root());

        let commission = ValidatorCommissionUpdate {
            network_domain: undelegate.network_domain,
            epoch: undelegate.epoch,
            validator: 0,
            commission_bps: 500,
            signature: Vec::new(),
        };
        assert_ne!(commission.signing_root(), undelegate.signing_root());
        assert_ne!(commission.signing_root(), withdraw.signing_root());
        let bytes = commission.canonical_bytes();
        assert_eq!(bytes[0], VALIDATOR_COMMISSION_UPDATE_TAG);
        let mut r = TxReader { b: &bytes, i: 1 };
        assert_eq!(ValidatorCommissionUpdate::decode(&mut r), Ok(commission));
        assert_eq!(r.i, bytes.len());
    }

    #[test]
    fn inputs_must_be_strictly_ordered() {
        let mut tx = delegate();
        tx.inputs.push(tx.inputs[0].clone());
        tx.tx_bytes = tx.reserved_tx_bytes();
        assert_eq!(tx.validate_shape(), Err(FundedDelegationReject::Shape));
    }
}
