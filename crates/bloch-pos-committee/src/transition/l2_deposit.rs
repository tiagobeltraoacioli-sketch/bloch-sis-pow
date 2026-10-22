// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native L2 deposit (admitted when the installed L2's profile admits
//! deposits: development genesis with `devnet-l2-deposits`, or the
//! running-network activation). Wire tag 0x14
//! (moved from 0x10, which mainnet assigns to `FundedDelegationWithdraw`).
//!
//! One hybrid PQ funding key spends UTXOs it owns and escrows `amount_sat` for
//! an EVM recipient on the asynchronous L2. The escrowed value leaves the
//! spendable set and is appended to the L2 inbox; a later settlement must mint
//! exactly that record on L2 (see `l2_settlement::expected_body_commitment`).
//! The signature covers the complete witness-free intent, including the
//! network domain, so it cannot be replayed on another network or rewritten.

use super::*;
use crate::{
    l2_settlement::InboxRecord,
    state_root::EutxoEntry,
    transition::funded::{FundingInput, ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX},
};

pub const L2_DEPOSIT_TAG: u8 = 0x14;
pub const MAX_DEPOSIT_INPUTS: usize = 128;
/// Smallest deposit: 0.01 BLCH. Dust-sized escrow records only bloat the inbox.
pub const MIN_L2_DEPOSIT_SAT: u64 = 1_000_000;
/// Mirrors the L2 `ChainSpec::max_l1_sats`; a larger record could never be minted.
pub const MAX_L2_DEPOSIT_SAT: u64 = 100_000_000_000 * 100_000_000;
/// Escrow output index; change, when present, is output 0.
pub const ESCROW_VOUT: u32 = 1;
const INTENT_DOMAIN: &[u8] = b"BLOCH:L2:DEPOSIT:V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Deposit {
    /// The network's admission domain (manifest digest binding).
    pub network_domain: [u8; 32],
    pub funding_pubkey: Vec<u8>,
    /// Strict lexicographic order, no duplicates.
    pub inputs: Vec<FundingInput>,
    pub amount_sat: u64,
    /// L2 EVM recipient.
    pub recipient: [u8; 20],
    /// Change back to the depositor; value 0 means no change output.
    pub change: TransferOutput,
    pub tx_bytes: u64,
    pub tip_millisat_per_gas: u128,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2DepositReject {
    NotActive,
    Network,
    Shape,
    Amount,
    MissingInput,
    Ownership,
    UnderdeclaredSize,
    TipAboveCeiling,
    GasCeiling,
    Conservation,
    OutputCollision,
    Signature,
    Inbox,
    Arithmetic,
}

impl L2Deposit {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut b = vec![L2_DEPOSIT_TAG];
        b.extend_from_slice(&self.network_domain);
        b.extend_from_slice(&(self.funding_pubkey.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.funding_pubkey);
        b.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            b.extend_from_slice(&input.txid);
            b.extend_from_slice(&input.vout.to_le_bytes());
        }
        b.extend_from_slice(&self.amount_sat.to_le_bytes());
        b.extend_from_slice(&self.recipient);
        b.extend_from_slice(&self.change.value.to_le_bytes());
        b.extend_from_slice(&self.change.script_hash);
        b.extend_from_slice(&self.tx_bytes.to_le_bytes());
        b.extend_from_slice(&self.tip_millisat_per_gas.to_le_bytes());
        b
    }

    /// Witness-free root the funding key signs; also the txid preimage.
    pub fn intent_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(INTENT_DOMAIN);
        h.update(self.intent_bytes());
        h.finalize().into()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = self.intent_bytes();
        b.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        let network_domain = r.h32()?;
        let n = r.u32()? as usize;
        if n != ADMISSION_PQ_KEY_BYTES {
            return Err(TxDecodeError::NotCanonical(L2_DEPOSIT_TAG));
        }
        let funding_pubkey = r.take(n)?.to_vec();
        let count = r.u32()? as usize;
        if count == 0 || count > MAX_DEPOSIT_INPUTS {
            return Err(TxDecodeError::NotCanonical(L2_DEPOSIT_TAG));
        }
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(FundingInput { txid: r.h32()?, vout: r.u32()? });
        }
        let amount_sat = r.u64()?;
        let recipient: [u8; 20] = TxReader::fixed(r.take(20)?)?;
        let change = TransferOutput { value: r.u64()?, script_hash: r.h32()? };
        let tx_bytes = r.u64()?;
        let tip_millisat_per_gas = r.u128()?;
        let n = r.u32()? as usize;
        if n > ADMISSION_PQ_SIGNATURE_MAX {
            return Err(TxDecodeError::NotCanonical(L2_DEPOSIT_TAG));
        }
        let signature = r.take(n)?.to_vec();
        Ok(Self {
            network_domain,
            funding_pubkey,
            inputs,
            amount_sat,
            recipient,
            change,
            tx_bytes,
            tip_millisat_per_gas,
            signature,
        })
    }

    fn validate_shape(&self) -> Result<(), L2DepositReject> {
        use L2DepositReject as R;
        if self.funding_pubkey.len() != ADMISSION_PQ_KEY_BYTES
            || self.signature.is_empty()
            || self.signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_DEPOSIT_INPUTS
            || !self.inputs.windows(2).all(|w| w[0] < w[1])
            || self.recipient == [0; 20]
        {
            return Err(R::Shape);
        }
        if !(MIN_L2_DEPOSIT_SAT..=MAX_L2_DEPOSIT_SAT).contains(&self.amount_sat) {
            return Err(R::Amount);
        }
        if self.tx_bytes < self.canonical_bytes().len() as u64 {
            return Err(R::UnderdeclaredSize);
        }
        Ok(())
    }

    fn class(&self) -> fee_market::TxClass {
        fee_market::TxClass::Eutxo { inputs: self.inputs.len() as u32 }
    }
}

impl CommittedState {
    pub(super) fn apply_l2_deposit(
        &mut self,
        tx: &L2Deposit,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, L2DepositReject> {
        use L2DepositReject as R;
        // The installed L2's profile decides (development genesis: the
        // build's devnet feature; running-network activation: always).
        if !self.l2_settlement.as_ref().is_some_and(|s| s.deposits_enabled()) {
            return Err(R::NotActive);
        }
        tx.validate_shape()?;
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if tx.tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS {
            return Err(R::TipAboveCeiling);
        }
        if fee_market::intrinsic_gas(tx.class(), tx.tx_bytes) > fee_market::MAX_TX_GAS {
            return Err(R::GasCeiling);
        }
        let owner: [u8; 32] = Sha3_256::digest(&tx.funding_pubkey).into();
        let mut spent = 0u128;
        for input in &tx.inputs {
            let utxo = self.eutxos.get(&(input.txid, input.vout)).ok_or(R::MissingInput)?;
            if !owns(&owner, &utxo.script_hash) {
                return Err(R::Ownership);
            }
            spent = spent.checked_add(u128::from(utxo.value)).ok_or(R::Arithmetic)?;
        }
        let charge = fee_market::charge(tx.class(), tx.tx_bytes, base_fee, tx.tip_millisat_per_gas);
        let required = u128::from(tx.amount_sat)
            .checked_add(u128::from(tx.change.value))
            .and_then(|v| v.checked_add(charge.base_fee_sat))
            .and_then(|v| v.checked_add(charge.priority_fee_sat))
            .ok_or(R::Arithmetic)?;
        if spent != required {
            return Err(R::Conservation);
        }
        let txid = PosTransaction::L2Deposit(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(R::OutputCollision);
        }
        // Expensive check last.
        if !verifier.verify_with_key(&tx.funding_pubkey, &tx.intent_root(), &tx.signature) {
            return Err(R::Signature);
        }
        let l2 = self.l2_settlement.as_mut().ok_or(R::NotActive)?;
        let height = l2.height().checked_add(1).ok_or(R::Arithmetic)?;
        let record = InboxRecord {
            height,
            tx_index: l2.deposits_at_height(height),
            txid,
            vout: ESCROW_VOUT,
            sats: tx.amount_sat,
            recipient: tx.recipient,
        };
        // Inbox append is the last fallible step; spendable-set edits follow it.
        l2.append_deposit(record).map_err(|_| R::Inbox)?;
        for input in &tx.inputs {
            self.eutxos.remove(&(input.txid, input.vout));
        }
        if tx.change.value > 0 {
            self.eutxos.insert(EutxoEntry {
                txid,
                vout: 0,
                value: tx.change.value,
                script_hash: tx.change.script_hash,
            });
        }
        Ok(charge)
    }
}
