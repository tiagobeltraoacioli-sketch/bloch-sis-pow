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
//! carries no attestation. Version 2 (M6) appends the attestor set (threshold,
//! all n enveloped hybrid keys) and at least k of their signatures over
//! `withdrawal::attestation_digest(network_domain, l2_chain_id, root)`, the
//! root being the one the Merkle proof folds to; the set must hash to the
//! policy's `attestor_set`. With attestors configured, claims of at least
//! `withdrawal::ATTESTED_CLAIM_SAT` must be version 2. Any other version does
//! not decode.

use super::*;
use crate::{
    l2_settlement::withdrawal::{self, ClaimRefusal, TREE_DEPTH},
    state_root::EutxoEntry,
    transition::funded::{FundingInput, ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX},
};

pub const L2_WITHDRAW_CLAIM_TAG: u8 = 0x16;
/// Claim body without attestation.
pub const CLAIM_VERSION: u8 = 1;
/// Claim body with the attestors' co-signature (M6).
pub const CLAIM_VERSION_ATTESTED: u8 = 2;
/// Funding inputs of one claim (each costs one hybrid verification).
pub const MAX_CLAIM_INPUTS: usize = 16;
/// Release output index; change, when present, is output 1.
pub const RELEASE_VOUT: u32 = 0;
pub const CHANGE_VOUT: u32 = 1;
const INTENT_DOMAIN: &[u8] = b"BLOCH:L2:CLAIM:V1";

/// k-of-n hybrid PQ co-signature of a withdrawal root (claim version 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// k: signatures required.
    pub threshold: u8,
    /// All n attestor keys, in set order (each `ADMISSION_PQ_KEY_BYTES`).
    pub keys: Vec<Vec<u8>>,
    /// `(signer index, signature)`, indices strictly increasing, at least k.
    pub signatures: Vec<(u8, Vec<u8>)>,
}

impl Attestation {
    pub fn set_hash(&self) -> [u8; 32] {
        withdrawal::attestor_set_hash(self.threshold, &self.keys)
    }

    fn encode(&self, b: &mut Vec<u8>) {
        b.push(self.threshold);
        b.push(self.keys.len() as u8);
        for key in &self.keys {
            b.extend_from_slice(key);
        }
        b.push(self.signatures.len() as u8);
        for (index, signature) in &self.signatures {
            b.push(*index);
            b.extend_from_slice(&(signature.len() as u32).to_le_bytes());
            b.extend_from_slice(signature);
        }
    }

    fn decode(r: &mut TxReader<'_>, bad: TxDecodeError) -> Result<Self, TxDecodeError> {
        let threshold = r.u8()?;
        let n = r.u8()? as usize;
        if n == 0 || n > withdrawal::MAX_ATTESTORS {
            return Err(bad);
        }
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            keys.push(r.take(ADMISSION_PQ_KEY_BYTES)?.to_vec());
        }
        let m = r.u8()? as usize;
        if m > n {
            return Err(bad);
        }
        let mut signatures = Vec::with_capacity(m);
        for _ in 0..m {
            let index = r.u8()?;
            let len = r.u32()? as usize;
            if len > ADMISSION_PQ_SIGNATURE_MAX {
                return Err(bad);
            }
            signatures.push((index, r.take(len)?.to_vec()));
        }
        Ok(Self { threshold, keys, signatures })
    }

    /// State-free checks: 1 ≤ k ≤ n ≤ MAX, distinct keys, k ≤ signatures,
    /// increasing in-range indices, non-empty bounded signatures.
    pub fn validate_shape(&self) -> bool {
        let n = self.keys.len();
        let k = usize::from(self.threshold);
        k >= 1
            && k <= n
            && n <= withdrawal::MAX_ATTESTORS
            && self.keys.iter().all(|key| key.len() == ADMISSION_PQ_KEY_BYTES)
            && self.keys.iter().enumerate().all(|(i, a)| self.keys[..i].iter().all(|b| a != b))
            && self.signatures.len() >= k
            && self.signatures.len() <= n
            && self.signatures.windows(2).all(|w| w[0].0 < w[1].0)
            && self.signatures.iter().all(|(i, sig)| {
                usize::from(*i) < n && !sig.is_empty() && sig.len() <= ADMISSION_PQ_SIGNATURE_MAX
            })
    }

    /// Every listed signature verifies over the attestation of `root`.
    pub fn verify(&self, network_domain: &[u8; 32], chain_id: u64, root: &[u8; 32], verifier: &dyn SignatureVerifier) -> bool {
        let digest = withdrawal::attestation_digest(network_domain, chain_id, root);
        self.validate_shape()
            && self
                .signatures
                .iter()
                .all(|(i, sig)| verifier.verify_with_key(&self.keys[usize::from(*i)], &digest, sig))
    }
}

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
    /// Version 2 when present (M6).
    pub attestation: Option<Attestation>,
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
    /// The claim needs the attestors' co-signature (version 2) and has none.
    AttestationRequired,
    /// The attestation names another set, or a signature does not verify.
    Attestation,
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
        b.push(self.version());
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
        if let Some(attestation) = &self.attestation {
            attestation.encode(&mut b);
        }
        b
    }

    pub fn version(&self) -> u8 {
        if self.attestation.is_some() {
            CLAIM_VERSION_ATTESTED
        } else {
            CLAIM_VERSION
        }
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
        let version = r.u8()?;
        if version != CLAIM_VERSION && version != CLAIM_VERSION_ATTESTED {
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
        let attestation = if version == CLAIM_VERSION_ATTESTED {
            Some(Attestation::decode(r, bad.clone())?)
        } else {
            None
        };
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
            attestation,
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
            || self.attestation.as_ref().is_some_and(|a| !a.validate_shape())
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

    /// The withdrawal root the Merkle proof folds to (`None` off the tree).
    pub fn proven_root(&self) -> Option<[u8; 32]> {
        withdrawal::root_from_proof(&self.leaf(), self.index, &self.siblings)
    }

    /// The attestation's signatures over the proven root (state-free; the
    /// mempool runs it). True for a version-1 claim.
    pub fn verify_attestation(&self, verifier: &dyn SignatureVerifier) -> bool {
        match (&self.attestation, self.proven_root()) {
            (None, _) => true,
            (Some(a), Some(root)) => a.verify(&self.network_domain, self.l2_chain_id, &root, verifier),
            (Some(_), None) => false,
        }
    }

    pub fn class(&self) -> fee_market::TxClass {
        fee_market::TxClass::Eutxo { inputs: self.inputs.len() as u32 }
    }
}

impl CommittedState {
    /// Why this state would refuse `tx` in the next block, checking
    /// everything except the signatures (the mempool verified those). For
    /// logs and tooling: the block transition reports a refused claim only as
    /// the frozen `TransitionError::Transaction(i)`, which names no reason.
    pub fn l2_withdraw_claim_refusal(&self, tx: &L2WithdrawClaim) -> Option<L2WithdrawClaimReject> {
        self.check_l2_withdraw_claim(tx, self.next_base_fee()).err()
    }

    /// The state checks of [`Self::apply_l2_withdraw_claim`], in its order,
    /// up to (not including) the signatures.
    fn check_l2_withdraw_claim(
        &self,
        tx: &L2WithdrawClaim,
        base_fee: u128,
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
        let l2 = self.l2_settlement.as_ref().ok_or(R::NotActive)?;
        // Attestation first: a missing one is the more useful refusal than
        // the release window it would also exceed.
        match &tx.attestation {
            None if l2.attestation_required(tx.sats) => return Err(R::AttestationRequired),
            // An attestation must name the policy's set (none configured: refused).
            Some(a) if l2.policy().attestor_set == [0; 32] || a.set_hash() != l2.policy().attestor_set => {
                return Err(R::Attestation)
            }
            _ => {}
        }
        l2.check_claim(tx.l2_chain_id, tx.index, &tx.l1_recipient, tx.sats, &tx.siblings, tx.attestation.is_some())?;
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
        Ok(charge)
    }

    pub(super) fn apply_l2_withdraw_claim(
        &mut self,
        tx: &L2WithdrawClaim,
        base_fee: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, L2WithdrawClaimReject> {
        use L2WithdrawClaimReject as R;
        let charge = self.check_l2_withdraw_claim(tx, base_fee)?;
        let txid = PosTransaction::L2WithdrawClaim(tx.clone()).txid();
        // Expensive check last.
        if !verifier.verify_with_key(&tx.funding_pubkey, &tx.intent_root(), &tx.signature) {
            return Err(R::Signature);
        }
        // Up to MAX_ATTESTORS hybrid verifications, after the funding key.
        if !tx.verify_attestation(verifier) {
            return Err(R::Attestation);
        }
        let l2 = self.l2_settlement.as_mut().ok_or(R::NotActive)?;
        // The release is the last fallible step; spendable-set edits follow it.
        // An attestation reaching here names the policy's set and verified.
        l2.release_withdrawal(tx.l2_chain_id, tx.index, &tx.l1_recipient, tx.sats, &tx.siblings, tx.attestation.is_some())?;
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
