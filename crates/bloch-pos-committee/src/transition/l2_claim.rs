// SPDX-License-Identifier: AGPL-3.0-or-later
//! L2 → L1 withdrawal claim (milestone M5; development networks with
//! `devnet-l2-user-txs`). Wire tag 0x16, the first byte after the L2 data
//! availability tag; no mainnet tree and no local ref assigns it (see
//! `tests/wire_tag_registry.rs`).
//!
//! The claim proves one leaf of the L2 outbox tree (`l2_settlement::withdrawal`)
//! against a retained withdrawal root that is at least
//! `withdrawal::WITHDRAW_DELAY_BLOCKS` native blocks old, marks the leaf index
//! claimed (once per leaf, ever) and moves exactly `sats` from the L2 escrow
//! to a new output locked to `l1_recipient` (the native script hash the L2
//! user named). Nothing about the claim is authorized by its recipient: the
//! L2 withdrawal itself is the authorization, so anyone may relay it.
//!
//! **Fee rule.** The recipient always receives exactly `sats`. The fee is
//! paid by the relayer's own funding inputs (one hybrid PQ funding key, like
//! the deposit and DA transactions) at the ordinary eUTXO gas price, with the
//! rest returned as change. A relayer therefore cannot burn any of the
//! withdrawn amount, and a recipient with no L1 coins yet can be served by
//! any funded relayer. The funding signature covers the whole witness-free
//! intent (network domain, claim and outputs), so the transaction cannot be
//! replayed on another network or re-pointed.
//!
//! **Outputs.** vout 0: the release (`sats` to `l1_recipient`, also carried
//! explicitly in `release` and required to match); vout 1: change (absent
//! when zero).
//!
//! **Versioned body.** The byte after the tag is the claim version. Version 1
//! is defined here; M6 can add an owner (PQ) signature for large withdrawals
//! as version 2 without a new wire tag. Any other version does not decode.

use super::*;
use crate::{
    l2_settlement::withdrawal::{self, ClaimRefusal, TREE_DEPTH},
    state_root::EutxoEntry,
    transition::funded::{FundingInput, ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX},
};

pub const L2_WITHDRAW_CLAIM_TAG: u8 = 0x16;
/// The only claim body version this build decodes.
pub const CLAIM_VERSION: u8 = 1;
/// Funding inputs of one claim (each costs one hybrid verification).
pub const MAX_CLAIM_INPUTS: usize = 16;
/// Release output index; change, when present, is output 1.
pub const RELEASE_VOUT: u32 = 0;
pub const CHANGE_VOUT: u32 = 1;
const INTENT_DOMAIN: &[u8] = b"BLOCH:L2:CLAIM:V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2WithdrawClaim {
    /// The network's admission domain (manifest digest binding).
    pub network_domain: [u8; 32],
    /// The relayer's funding key; it pays the fee, not the recipient.
    pub funding_pubkey: Vec<u8>,
    /// Strict lexicographic order, no duplicates.
    pub inputs: Vec<FundingInput>,
    /// L2 chain of the withdrawal (must equal the L2 policy's chain id).
    pub l2_chain_id: u64,
    /// Leaf index in the outbox tree, which is also the L2 outbox nonce.
    pub index: u64,
    /// Native script hash the L2 user named.
    pub l1_recipient: [u8; 32],
    pub sats: u64,
    /// Bottom-up Merkle siblings of the leaf against a retained root.
    pub siblings: [[u8; 32]; TREE_DEPTH],
    /// Output 0. Must be exactly `{ value: sats, script_hash: l1_recipient }`.
    pub release: TransferOutput,
    /// Change back to the relayer; value 0 means no change output.
    pub change: TransferOutput,
    pub tx_bytes: u64,
    pub tip_millisat_per_gas: u128,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2WithdrawClaimReject {
    NotActive,
    Network,
    Shape,
    /// `sats` below the L2 minimum withdrawal (no such leaf can exist).
    Amount,
    /// The release output is not exactly `sats` to `l1_recipient`.
    ReleaseOutput,
    MissingInput,
    Ownership,
    UnderdeclaredSize,
    TipAboveCeiling,
    GasCeiling,
    Conservation,
    OutputCollision,
    Signature,
    /// The claim names another L2 chain.
    Chain,
    /// The proof folds to no retained withdrawal root.
    Proof,
    /// The root it proves against is younger than the withdrawal delay.
    NotMatured,
    /// The index is not below that root's leaf count.
    Index,
    /// This leaf was already claimed.
    AlreadyClaimed,
    /// The escrow holds less than the claim.
    Escrow,
    /// The release window's cap is used up; retry in a later window.
    RateLimited,
    Arithmetic,
}

impl From<ClaimRefusal> for L2WithdrawClaimReject {
    fn from(r: ClaimRefusal) -> Self {
        match r {
            ClaimRefusal::NotActive => Self::NotActive,
            ClaimRefusal::Chain => Self::Chain,
            ClaimRefusal::Proof => Self::Proof,
            ClaimRefusal::NotMatured => Self::NotMatured,
            ClaimRefusal::Index => Self::Index,
            ClaimRefusal::Claimed => Self::AlreadyClaimed,
            ClaimRefusal::Escrow => Self::Escrow,
            ClaimRefusal::RateLimited => Self::RateLimited,
        }
    }
}

impl L2WithdrawClaim {
    fn intent_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(ADMISSION_PQ_KEY_BYTES + 1_400 + self.inputs.len() * 36);
        b.push(L2_WITHDRAW_CLAIM_TAG);
        b.push(CLAIM_VERSION);
        b.extend_from_slice(&self.network_domain);
        b.extend_from_slice(&(self.funding_pubkey.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.funding_pubkey);
        b.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            b.extend_from_slice(&input.txid);
            b.extend_from_slice(&input.vout.to_le_bytes());
        }
        b.extend_from_slice(&self.l2_chain_id.to_le_bytes());
        b.extend_from_slice(&self.index.to_le_bytes());
        b.extend_from_slice(&self.l1_recipient);
        b.extend_from_slice(&self.sats.to_le_bytes());
        for sibling in &self.siblings {
            b.extend_from_slice(sibling);
        }
        b.extend_from_slice(&self.release.value.to_le_bytes());
        b.extend_from_slice(&self.release.script_hash);
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

    /// `withdrawal::nullifier(l2_chain_id, index)`.
    pub fn nullifier(&self) -> [u8; 32] {
        withdrawal::nullifier(self.l2_chain_id, self.index)
    }

    /// The outbox leaf this claim proves.
    pub fn leaf(&self) -> [u8; 32] {
        withdrawal::leaf(self.l2_chain_id, self.index, &self.l1_recipient, self.sats)
    }

    pub(super) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        let bad = TxDecodeError::NotCanonical(L2_WITHDRAW_CLAIM_TAG);
        if r.u8()? != CLAIM_VERSION {
            return Err(bad);
        }
        let network_domain = r.h32()?;
        let n = r.u32()? as usize;
        if n != ADMISSION_PQ_KEY_BYTES {
            return Err(bad);
        }
        let funding_pubkey = r.take(n)?.to_vec();
        let count = r.u32()? as usize;
        if count == 0 || count > MAX_CLAIM_INPUTS {
            return Err(bad);
        }
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            inputs.push(FundingInput { txid: r.h32()?, vout: r.u32()? });
        }
        let l2_chain_id = r.u64()?;
        let index = r.u64()?;
        let l1_recipient = r.h32()?;
        let sats = r.u64()?;
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        for sibling in &mut siblings {
            *sibling = r.h32()?;
        }
        let release = TransferOutput { value: r.u64()?, script_hash: r.h32()? };
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
            index,
            l1_recipient,
            sats,
            siblings,
            release,
            change,
            tx_bytes,
            tip_millisat_per_gas,
            signature,
        })
    }

    /// State-free checks (also run at the mempool door).
    pub fn validate_shape(&self) -> Result<(), L2WithdrawClaimReject> {
        use L2WithdrawClaimReject as R;
        if self.funding_pubkey.len() != ADMISSION_PQ_KEY_BYTES
            || self.signature.is_empty()
            || self.signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_CLAIM_INPUTS
            || !self.inputs.windows(2).all(|w| w[0] < w[1])
            || self.index >> TREE_DEPTH != 0
        {
            return Err(R::Shape);
        }
        if self.sats < super::l2_deposit::MIN_L2_DEPOSIT_SAT {
            return Err(R::Amount);
        }
        if self.release.value != self.sats || self.release.script_hash != self.l1_recipient {
            return Err(R::ReleaseOutput);
        }
        if self.tx_bytes < self.canonical_bytes().len() as u64 {
            return Err(R::UnderdeclaredSize);
        }
        Ok(())
    }

    pub fn class(&self) -> fee_market::TxClass {
        fee_market::TxClass::Eutxo { inputs: self.inputs.len() as u32 }
    }
}

impl CommittedState {
    pub(super) fn apply_l2_withdraw_claim(
        &mut self,
        tx: &L2WithdrawClaim,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, L2WithdrawClaimReject> {
        use L2WithdrawClaimReject as R;
        if !crate::l2_settlement::USER_TRANSACTIONS_ENABLED || self.l2_settlement.is_none() {
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
        // The claim itself, before any input lookup (cheap, keccak only).
        self.l2_settlement
            .as_ref()
            .ok_or(R::NotActive)?
            .check_claim(tx.l2_chain_id, tx.index, &tx.l1_recipient, tx.sats, &tx.siblings)?;
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
        let required = u128::from(tx.change.value)
            .checked_add(charge.base_fee_sat)
            .and_then(|v| v.checked_add(charge.priority_fee_sat))
            .ok_or(R::Arithmetic)?;
        if spent != required {
            return Err(R::Conservation);
        }
        let txid = PosTransaction::L2WithdrawClaim(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, RELEASE_VOUT)) || self.eutxos.contains_key(&(txid, CHANGE_VOUT)) {
            return Err(R::OutputCollision);
        }
        // Expensive check last.
        if !verifier.verify_with_key(&tx.funding_pubkey, &tx.intent_root(), &tx.signature) {
            return Err(R::Signature);
        }
        let l2 = self.l2_settlement.as_mut().ok_or(R::NotActive)?;
        // The release is the last fallible step; spendable-set edits follow it.
        l2.release_withdrawal(tx.l2_chain_id, tx.index, &tx.l1_recipient, tx.sats, &tx.siblings)?;
        for input in &tx.inputs {
            self.eutxos.remove(&(input.txid, input.vout));
        }
        self.eutxos.insert(EutxoEntry {
            txid,
            vout: RELEASE_VOUT,
            value: tx.sats,
            script_hash: tx.l1_recipient,
        });
        if tx.change.value > 0 {
            self.eutxos.insert(EutxoEntry {
                txid,
                vout: CHANGE_VOUT,
                value: tx.change.value,
                script_hash: tx.change.script_hash,
            });
        }
        Ok(charge)
    }
}
