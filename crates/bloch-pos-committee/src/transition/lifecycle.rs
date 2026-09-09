// SPDX-License-Identifier: AGPL-3.0-or-later
//! ADR-041 withdrawal accounting. Every check precedes every mutation.

use super::*;
use crate::EutxoEntry;

impl CommittedState {
    /// A finalized checkpoint at E covers the end of E-1. A deposit at E
    /// therefore needs finalized.epoch > E, in addition to the eight-epoch
    /// inclusion delay. Stalls cannot backdate activation or bypass churn.
    pub(super) fn activate_finalized_deposits(&mut self, next_epoch: u64) {
        let finalized = self.finality_engine.finalized().epoch;
        let mut eligible: Vec<_> = self
            .deposit_history
            .iter()
            .filter_map(|d| {
                let index = *self.pubkey_index.get(&d.pubkey_hash)?;
                let rec = self.validators.get(&index)?;
                (self.funded_validators.contains(&index)
                    && rec.activation_epoch == u64::MAX
                    && !rec.slashed
                    && d.deposit_epoch < finalized
                    && d.deposit_epoch
                        .checked_add(staking::ACTIVATION_DELAY_EPOCHS)
                        .is_some_and(|e| e <= next_epoch))
                .then_some((d.deposit_epoch, d.pubkey_hash, index))
            })
            .collect();
        eligible.sort_unstable();
        for (_, _, index) in eligible
            .into_iter()
            .take(staking::MAX_ACTIVATIONS_PER_EPOCH)
        {
            if let Some(rec) = self.validators.get_mut(&index) {
                rec.activation_epoch = next_epoch;
            }
        }
    }

    /// Unissued principal still inside this bond. Funded registrations carry
    /// explicit committed provenance; an unknown registration is never assumed
    /// funded. Historical legacy deposits remain unbacked even in a new binary.
    pub fn unbacked_principal_sat(&self, index: u32) -> u128 {
        let Some(rec) = self.validators.get(&index) else {
            return 0;
        };
        if self.funded_validators.contains(&index) {
            return 0;
        }
        let principal = self
            .genesis_principal_sat
            .get(&index)
            .copied()
            .or_else(|| {
                let hash: [u8; 32] = Sha3_256::digest(&rec.pubkey).into();
                self.deposit_history
                    .iter()
                    .find(|d| d.pubkey_hash == hash)
                    .map(|d| d.amount_sat)
            })
            .unwrap_or(u128::MAX);
        principal.min(
            self.stake_low_water
                .get(&index)
                .copied()
                .unwrap_or(rec.staked_sat),
        )
    }

    pub fn withdrawable_sat(&self, index: u32) -> u128 {
        self.validators.get(&index).map_or(0, |r| {
            r.staked_sat
                .saturating_sub(self.unbacked_principal_sat(index))
        })
    }

    pub fn written_off_sat(&self) -> u128 {
        self.written_off_sat
    }

    pub fn is_write_off_indeterminate(&self, index: u32) -> bool {
        self.validators.get(&index).is_some_and(|r| {
            !self.funded_validators.contains(&index)
                && r.slashed
                && !self.stake_low_water.contains_key(&index)
        })
    }

    pub fn validator_randao_generation(&self, index: u32) -> u32 {
        self.randao_generations.get(&index).copied().unwrap_or(0)
    }

    pub fn is_funded_validator(&self, index: u32) -> bool {
        self.funded_validators.contains(&index)
    }

    /// Read-only preflight shared with consensus and node admission. An output
    /// worth zero is omitted; its positive principal write-off still closes
    /// the bond without growing the UTXO set with dust.
    fn withdrawal_plan(
        &self,
        index: u32,
        tx: &PosTransaction,
    ) -> Result<(u128, u128, Option<EutxoEntry>), TxReject> {
        if !Self::withdrawal_active(self.epoch) || self.is_write_off_indeterminate(index) {
            return Err(TxReject::StakingNotActive);
        }
        let rec = self.validators.get(&index).ok_or(TxReject::StakingRule)?;
        if rec.exit_epoch == u64::MAX
            || rec.withdrawable_epoch == u64::MAX
            || self.epoch < rec.withdrawable_epoch
            || rec.staked_sat == 0
        {
            return Err(TxReject::StakingRule);
        }
        let script_hash = <[u8; 32]>::try_from(rec.withdrawal_credentials.as_slice())
            .map_err(|_| TxReject::StakingRule)?;
        let unbacked = self.unbacked_principal_sat(index).min(rec.staked_sat);
        let payout = rec
            .staked_sat
            .checked_sub(unbacked)
            .ok_or(TxReject::StakingRule)?;
        let value = u64::try_from(payout).map_err(|_| TxReject::StakingRule)?;
        let written_off = self
            .written_off_sat
            .checked_add(unbacked)
            .ok_or(TxReject::StakingRule)?;
        if payout.checked_add(unbacked) != Some(rec.staked_sat) {
            return Err(TxReject::StakingRule);
        }
        let txid = tx.txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(TxReject::StakingRule);
        }
        let output = (value > 0).then_some(EutxoEntry {
            txid,
            vout: 0,
            value,
            script_hash,
        });
        Ok((rec.staked_sat, written_off, output))
    }

    pub(super) fn apply_withdrawal(
        &mut self,
        index: u32,
        tx: &PosTransaction,
    ) -> Result<fee_market::TxCharge, TxReject> {
        let (_before, written_off, output) = self.withdrawal_plan(index, tx)?;
        let rec = self
            .validators
            .get_mut(&index)
            .ok_or(TxReject::StakingRule)?;
        rec.staked_sat = 0;
        self.written_off_sat = written_off;
        if let Some(output) = output {
            self.eutxos.insert(output);
        }
        // This capacity charge is unconditional for this new format. Its
        // separate legacy metering gate must never make withdrawals free gas.
        let tx_bytes = tx.canonical_bytes().len() as u64;
        Ok(fee_market::TxCharge {
            gas: fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 0 }, tx_bytes),
            tx_bytes,
            base_fee_sat: 0,
            priority_fee_sat: 0,
        })
    }

    /// State-aware relay validation. Consensus repeats the same checks on the
    /// block's pre-state. No successful mempool decision grants authority.
    pub fn validate_lifecycle_transaction(
        &self,
        tx: &PosTransaction,
        total_active_sat: u128,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), TxReject> {
        match tx {
            PosTransaction::FundedDeposit(deposit) => self
                .validate_funded_deposit(deposit, total_active_sat, base_fee, verifier)
                .map(|_| ())
                .map_err(TxReject::FundedDeposit),
            PosTransaction::Withdraw { validator } => {
                self.withdrawal_plan(*validator, tx).map(|_| ())
            }
            PosTransaction::SlashingEvidence(evidence) => {
                if !Self::slashing_evidence_active(self.epoch) {
                    return Err(TxReject::EvidenceNotActive);
                }
                self.clone()
                    .apply_slashing_evidence(evidence, 0, total_active_sat, verifier)
                    .map_err(|_| TxReject::StakingRule)
            }
            PosTransaction::ExitV2 { .. } | PosTransaction::RandaoRecommit { .. } => self
                .clone()
                .apply_transaction(tx, total_active_sat, base_fee, verifier)
                .map(|_| ()),
            _ => Ok(()),
        }
    }
}
