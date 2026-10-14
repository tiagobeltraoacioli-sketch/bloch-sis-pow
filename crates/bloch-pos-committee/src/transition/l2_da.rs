// SPDX-License-Identifier: AGPL-3.0-or-later
//! L2 data availability (M3; admitted when the installed L2's profile admits
//! user transactions: development genesis with `devnet-l2-user-txs`, or the
//! running-network activation). Wire tag
//! 0x15, the first byte after the L2 settlement/deposit tags; no mainnet tree
//! assigns it (see `tests/wire_tag_registry.rs`).
//!
//! One hybrid PQ funding key pays, at the ordinary eUTXO gas price
//! (`fee_market::intrinsic_gas`: 16 gas per declared byte plus one hybrid
//! verification per input), to publish the user-transaction batch of one
//! unsettled L2 block. The batch bytes live only in the native block; the L2
//! state records `(l2 block number, commitment, inclusion height)`
//! (`l2_settlement::da`). The signature covers the complete witness-free
//! intent, including the network domain and the L2 chain, so a batch cannot be
//! replayed on another network or re-targeted at another L2 block.

use super::*;
use crate::{
    l2_settlement::da,
    state_root::EutxoEntry,
    transition::funded::{FundingInput, ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX},
};

pub const L2_DATA_AVAILABILITY_TAG: u8 = 0x15;
const INTENT_DOMAIN: &[u8] = b"BLOCH:L2:DA:V1";

/// Largest canonical encoding: every bound above at its maximum. One such
/// transaction stays below the pre-V2 block byte target.
pub const MAX_L2_DATA_AVAILABILITY_BYTES: usize = 1
    + 32
    + 4
    + ADMISSION_PQ_KEY_BYTES
    + 4
    + da::MAX_INPUTS * 36
    + 8
    + 8
    + 4
    + da::MAX_PAYLOAD_BYTES
    + 8
    + 32
    + 8
    + 16
    + 4
    + ADMISSION_PQ_SIGNATURE_MAX;
const _: () = assert!(MAX_L2_DATA_AVAILABILITY_BYTES as u64 <= fee_market::BLOCK_TX_BYTES_TARGET);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2DataAvailability {
    /// The network's admission domain (manifest digest binding).
    pub network_domain: [u8; 32],
    pub funding_pubkey: Vec<u8>,
    /// Strict lexicographic order, no duplicates.
    pub inputs: Vec<FundingInput>,
    /// L2 chain the batch belongs to (must equal the L2 policy's chain id).
    pub l2_chain_id: u64,
    /// Unsettled L2 block whose user transactions `payload` carries.
    pub l2_block_number: u64,
    /// Canonical batch (`l2_settlement::da::batch_count`).
    pub payload: Vec<u8>,
    /// Change back to the payer; value 0 means no change output.
    pub change: TransferOutput,
    pub tx_bytes: u64,
    pub tip_millisat_per_gas: u128,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2DataAvailabilityReject {
    NotActive,
    Network,
    Shape,
    /// The payload is not one canonical batch within `da::MAX_PAYLOAD_BYTES`.
    Payload,
    MissingInput,
    Ownership,
    UnderdeclaredSize,
    TipAboveCeiling,
    GasCeiling,
    Conservation,
    OutputCollision,
    Signature,
    /// The batch names another L2 chain.
    Chain,
    /// The L2 block is already settled or beyond `da::WINDOW`.
    Number,
    /// This exact batch is already recorded for the block.
    Duplicate,
    Full,
    Arithmetic,
}

impl L2DataAvailability {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.payload.len() + ADMISSION_PQ_KEY_BYTES + 256);
        b.push(L2_DATA_AVAILABILITY_TAG);
        b.extend_from_slice(&self.network_domain);
        b.extend_from_slice(&(self.funding_pubkey.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.funding_pubkey);
        b.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            b.extend_from_slice(&input.txid);
            b.extend_from_slice(&input.vout.to_le_bytes());
        }
        b.extend_from_slice(&self.l2_chain_id.to_le_bytes());
        b.extend_from_slice(&self.l2_block_number.to_le_bytes());
        b.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.payload);
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

    /// The commitment a V3 settlement of `l2_block_number` must name.
    pub fn commitment(&self) -> [u8; 32] {
        da::commitment(self.l2_chain_id, self.l2_block_number, &self.payload)
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        let bad = TxDecodeError::NotCanonical(L2_DATA_AVAILABILITY_TAG);
        let network_domain = r.h32()?;
        let n = r.u32()? as usize;
        if n != ADMISSION_PQ_KEY_BYTES {
            return Err(bad);
        }
        let funding_pubkey = r.take(n)?.to_vec();
        let count = r.u32()? as usize;
        if count == 0 || count > da::MAX_INPUTS {
            return Err(bad);
        }
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(FundingInput {
                txid: r.h32()?,
                vout: r.u32()?,
            });
        }
        let l2_chain_id = r.u64()?;
        let l2_block_number = r.u64()?;
        // Bounded before any allocation.
        let n = r.u32()? as usize;
        if n > da::MAX_PAYLOAD_BYTES {
            return Err(bad);
        }
        let payload = r.take(n)?.to_vec();
        let change = TransferOutput {
            value: r.u64()?,
            script_hash: r.h32()?,
        };
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
            l2_block_number,
            payload,
            change,
            tx_bytes,
            tip_millisat_per_gas,
            signature,
        })
    }

    fn validate_shape(&self) -> Result<(), L2DataAvailabilityReject> {
        use L2DataAvailabilityReject as R;
        if self.funding_pubkey.len() != ADMISSION_PQ_KEY_BYTES
            || self.signature.is_empty()
            || self.signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || self.inputs.is_empty()
            || self.inputs.len() > da::MAX_INPUTS
            || !self.inputs.windows(2).all(|w| w[0] < w[1])
        {
            return Err(R::Shape);
        }
        if da::batch_count(&self.payload).is_none() {
            return Err(R::Payload);
        }
        if self.tx_bytes < self.canonical_bytes().len() as u64 {
            return Err(R::UnderdeclaredSize);
        }
        Ok(())
    }

    fn class(&self) -> fee_market::TxClass {
        fee_market::TxClass::Eutxo {
            inputs: self.inputs.len() as u32,
        }
    }
}

impl CommittedState {
    pub(super) fn apply_l2_data_availability(
        &mut self,
        tx: &L2DataAvailability,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, L2DataAvailabilityReject> {
        use L2DataAvailabilityReject as R;
        if !self.l2_settlement.as_ref().is_some_and(|l2| l2.user_transactions()) {
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
            let utxo = self
                .eutxos
                .get(&(input.txid, input.vout))
                .ok_or(R::MissingInput)?;
            if !owns(&owner, &utxo.script_hash) {
                return Err(R::Ownership);
            }
            spent = spent
                .checked_add(u128::from(utxo.value))
                .ok_or(R::Arithmetic)?;
        }
        let charge = fee_market::charge(tx.class(), tx.tx_bytes, base_fee, tx.tip_millisat_per_gas);
        let required = u128::from(tx.change.value)
            .checked_add(charge.base_fee_sat)
            .and_then(|v| v.checked_add(charge.priority_fee_sat))
            .ok_or(R::Arithmetic)?;
        if spent != required {
            return Err(R::Conservation);
        }
        let txid = PosTransaction::L2DataAvailability(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(R::OutputCollision);
        }
        // Expensive check last.
        if !verifier.verify_with_key(&tx.funding_pubkey, &tx.intent_root(), &tx.signature) {
            return Err(R::Signature);
        }
        let l2 = self.l2_settlement.as_mut().ok_or(R::NotActive)?;
        // The record is the last fallible step; spendable-set edits follow it.
        l2.record_data_availability(tx.l2_chain_id, tx.l2_block_number, tx.commitment())
            .map_err(|e| match e {
                da::Refusal::NotActive => R::NotActive,
                da::Refusal::Chain => R::Chain,
                da::Refusal::Number => R::Number,
                da::Refusal::Duplicate => R::Duplicate,
                da::Refusal::Full => R::Full,
            })?;
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
