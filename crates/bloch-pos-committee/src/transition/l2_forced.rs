// SPDX-License-Identifier: AGPL-3.0-or-later
//! L1 forced inclusion of one L2 transaction (CANDIDATE, wire 0x1C). Refused
//! with `NotActive` on every L2 until `params::L2_FORCED_INCLUSION_EPOCH`
//! enables the queue (`l2_settlement::forced`), which it does only on an L2
//! whose configuration implements the rule.
//!
//! One hybrid PQ funding key pays the ordinary eUTXO fee for the bytes (the
//! envelope is its own data availability) plus a burned queue-depth surcharge
//! (`forced::surcharge_sat`), and the L2 state queues `(native height, txid,
//! keccak256(envelope), declared gas limit)`. Every later V3 settlement must
//! consume the queue in order, whoever settles. The signature covers the
//! complete witness-free intent, including the network domain and the L2 chain,
//! so a submission cannot be replayed on another network or L2.
//!
//! L1 never parses the envelope: the guest decides whether it executes, and
//! skips, without blocking the queue, anything that is not a valid transaction
//! at its position or whose own gas limit is above the declared one.

use super::*;
use crate::{
    l2_settlement::forced,
    state_root::EutxoEntry,
    transition::funded::{FundingInput, ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX},
};

pub const L2_FORCED_TRANSACTION_TAG: u8 = crate::wire_alloc::tx::L2_FORCED_TRANSACTION;
const INTENT_DOMAIN: &[u8] = b"BLOCH:L2:FORCED:V1";
/// Funding inputs of one forced transaction.
pub const MAX_INPUTS: usize = 4;

/// Largest canonical encoding: every bound above at its maximum.
pub const MAX_L2_FORCED_TRANSACTION_BYTES: usize = 1
    + 32
    + 4
    + ADMISSION_PQ_KEY_BYTES
    + 4
    + MAX_INPUTS * 36
    + 8
    + 8
    + 4
    + forced::MAX_ENVELOPE_BYTES
    + 8
    + 32
    + 8
    + 16
    + 4
    + ADMISSION_PQ_SIGNATURE_MAX;
const _: () = assert!(MAX_L2_FORCED_TRANSACTION_BYTES as u64 <= fee_market::BLOCK_TX_BYTES_TARGET);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2ForcedTransaction {
    /// The network's admission domain (manifest digest binding).
    pub network_domain: [u8; 32],
    pub funding_pubkey: Vec<u8>,
    /// Strict lexicographic order, no duplicates.
    pub inputs: Vec<FundingInput>,
    /// L2 chain the envelope belongs to (must equal the L2 policy's chain id).
    pub l2_chain_id: u64,
    /// Declared gas limit, in `forced::MIN_GAS..=forced::MAX_GAS`. The guest
    /// skips the envelope if its own gas limit is above it.
    pub gas_limit: u64,
    /// One signed EIP-2718 L2 envelope, at most `forced::MAX_ENVELOPE_BYTES`.
    pub envelope: Vec<u8>,
    /// Change back to the payer; value 0 means no change output.
    pub change: TransferOutput,
    pub tx_bytes: u64,
    pub tip_millisat_per_gas: u128,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2ForcedTransactionReject {
    NotActive,
    Network,
    Shape,
    MissingInput,
    Ownership,
    UnderdeclaredSize,
    TipAboveCeiling,
    GasCeiling,
    Conservation,
    OutputCollision,
    Signature,
    /// The envelope names another L2 chain.
    Chain,
    /// `forced::MAX_PENDING` records are queued.
    Full,
    Arithmetic,
}

impl L2ForcedTransaction {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.envelope.len() + ADMISSION_PQ_KEY_BYTES + 256);
        b.push(L2_FORCED_TRANSACTION_TAG);
        b.extend_from_slice(&self.network_domain);
        b.extend_from_slice(&(self.funding_pubkey.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.funding_pubkey);
        b.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            b.extend_from_slice(&input.txid);
            b.extend_from_slice(&input.vout.to_le_bytes());
        }
        b.extend_from_slice(&self.l2_chain_id.to_le_bytes());
        b.extend_from_slice(&self.gas_limit.to_le_bytes());
        b.extend_from_slice(&(self.envelope.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.envelope);
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
        let bad = TxDecodeError::NotCanonical(L2_FORCED_TRANSACTION_TAG);
        let network_domain = r.h32()?;
        let n = r.u32()? as usize;
        if n != ADMISSION_PQ_KEY_BYTES {
            return Err(bad);
        }
        let funding_pubkey = r.take(n)?.to_vec();
        let count = r.u32()? as usize;
        if count == 0 || count > MAX_INPUTS {
            return Err(bad);
        }
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(FundingInput { txid: r.h32()?, vout: r.u32()? });
        }
        let l2_chain_id = r.u64()?;
        let gas_limit = r.u64()?;
        // Bounded before any allocation.
        let n = r.u32()? as usize;
        if n == 0 || n > forced::MAX_ENVELOPE_BYTES {
            return Err(bad);
        }
        let envelope = r.take(n)?.to_vec();
        let change = TransferOutput { value: r.u64()?, script_hash: r.h32()? };
        let tx_bytes = r.u64()?;
        let tip_millisat_per_gas = r.u128()?;
        let n = r.u32()? as usize;
        if n > ADMISSION_PQ_SIGNATURE_MAX {
            return Err(bad);
        }
        let signature = r.take(n)?.to_vec();
        Ok(Self {
            network_domain,
            funding_pubkey,
            inputs,
            l2_chain_id,
            gas_limit,
            envelope,
            change,
            tx_bytes,
            tip_millisat_per_gas,
            signature,
        })
    }

    fn validate_shape(&self) -> Result<(), L2ForcedTransactionReject> {
        use L2ForcedTransactionReject as R;
        if self.funding_pubkey.len() != ADMISSION_PQ_KEY_BYTES
            || self.signature.is_empty()
            || self.signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_INPUTS
            || !self.inputs.windows(2).all(|w| w[0] < w[1])
            || self.envelope.is_empty()
            || self.envelope.len() > forced::MAX_ENVELOPE_BYTES
            || !(forced::MIN_GAS..=forced::MAX_GAS).contains(&self.gas_limit)
        {
            return Err(R::Shape);
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
    pub(super) fn apply_l2_forced_transaction(
        &mut self,
        tx: &L2ForcedTransaction,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, L2ForcedTransactionReject> {
        use L2ForcedTransactionReject as R;
        let pending = match self.l2_settlement.as_ref().and_then(|l2| l2.forced_queue()) {
            Some(queue) => queue.pending().len() as u64,
            None => return Err(R::NotActive),
        };
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
        let surcharge = forced::surcharge_sat(pending).ok_or(R::Full)?;
        let owner: [u8; 32] = Sha3_256::digest(&tx.funding_pubkey).into();
        let mut spent = 0u128;
        for input in &tx.inputs {
            let utxo = self.eutxos.get(&(input.txid, input.vout)).ok_or(R::MissingInput)?;
            if !owns(&owner, &utxo.script_hash) {
                return Err(R::Ownership);
            }
            spent = spent.checked_add(u128::from(utxo.value)).ok_or(R::Arithmetic)?;
        }
        let mut charge = fee_market::charge(tx.class(), tx.tx_bytes, base_fee, tx.tip_millisat_per_gas);
        // The surcharge is burned with the base fee: credited to no one.
        charge.base_fee_sat = charge.base_fee_sat.checked_add(u128::from(surcharge)).ok_or(R::Arithmetic)?;
        let required = u128::from(tx.change.value)
            .checked_add(charge.base_fee_sat)
            .and_then(|v| v.checked_add(charge.priority_fee_sat))
            .ok_or(R::Arithmetic)?;
        if spent != required {
            return Err(R::Conservation);
        }
        let txid = PosTransaction::L2ForcedTransaction(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(R::OutputCollision);
        }
        // Expensive check last.
        if !verifier.verify_with_key(&tx.funding_pubkey, &tx.intent_root(), &tx.signature) {
            return Err(R::Signature);
        }
        let l2 = self.l2_settlement.as_mut().ok_or(R::NotActive)?;
        // The record is the last fallible step; spendable-set edits follow it.
        l2.queue_forced(tx.l2_chain_id, txid, &tx.envelope, tx.gas_limit).map_err(|e| match e {
            forced::Refusal::NotActive => R::NotActive,
            forced::Refusal::Chain => R::Chain,
            forced::Refusal::Shape => R::Shape,
            forced::Refusal::Full => R::Full,
        })?;
        for input in &tx.inputs {
            self.eutxos.remove(&(input.txid, input.vout));
        }
        if tx.change.value > 0 {
            self.eutxos.insert(EutxoEntry { txid, vout: 0, value: tx.change.value, script_hash: tx.change.script_hash });
        }
        Ok(charge)
    }
}
