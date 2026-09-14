//! Real BLCH custody substrate, not an AMM, LP issuance or native-token release.
//! One admitted PQ owner funds and continues a reserve of exactly the same value.
//! All fees come from separate owner inputs. There is intentionally no withdrawal.
use super::{
    Error, JointTransferContext, PosTransaction, State, MAX_BASE_ITEMS, MAX_BASE_WITNESS_BYTES,
    MAX_ENVELOPE_BYTES,
};
use crate::fee_market;
use crate::state_root::EutxoEntry;
use crate::transition::{TransferInputV2, TransferOutput};
use crate::SignatureVerifier;
use bloch_euvm::ustav::Verifier;
use sha3::{Digest, Sha3_256};

pub type OutPoint = ([u8; 32], u32);
pub const MAX_RESERVES: usize = 128;
/// Only the private custody capability can authorize this key index. Ordinary
/// TransferV2 interprets it as an invalid index, never as a public bypass flag.
pub const RESERVE_KEY_INDEX: u32 = u32::MAX;
const RESERVE_GAS: u64 = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: [u8; 32],
    pub seed: [u8; 32],
    pub owner: Vec<u8>,
    pub outpoint: OutPoint,
    pub amount: u64,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Create { seed: [u8; 32], amount: u64 },
    Continue { reserve: [u8; 32], revision: u64 },
}

#[derive(Clone, Debug)]
pub struct Request {
    pub action: Action,
    pub valid_until: u64,
    /// Exactly one PQ key: the reserve owner also owns the separate fee inputs.
    /// Output zero is the exact reserve; every subsequent output is owner change.
    pub blch: PosTransaction,
}

#[derive(Clone, Debug)]
pub struct Receipt {
    pub reserve: Record,
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub charge: fee_market::TxCharge,
}

pub fn reserve_id(domain: &[u8; 32], seed: &[u8; 32], owner: &[u8]) -> Result<[u8; 32], Error> {
    if *domain == [0; 32]
        || *seed == [0; 32]
        || owner.is_empty()
        || owner.len() > MAX_BASE_WITNESS_BYTES
    {
        return Err(Error::InvalidReserve);
    }
    let mut h = Sha3_256::new();
    h.update(b"BLOCH-BASE-RESERVE-ID-v1");
    h.update(domain);
    h.update(seed);
    h.update((owner.len() as u64).to_le_bytes());
    h.update(owner);
    Ok(h.finalize().into())
}

/// A protocol condition commitment, not the hash of a fabricated owner key.
pub fn reserve_script(domain: &[u8; 32], id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BLOCH-BASE-RESERVE-SCRIPT-v1");
    h.update(domain);
    h.update(id);
    h.finalize().into()
}

impl Request {
    fn action_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41);
        match &self.action {
            Action::Create { seed, amount } => {
                bytes.push(0);
                bytes.extend_from_slice(seed);
                bytes.extend_from_slice(&amount.to_le_bytes());
            }
            Action::Continue { reserve, revision } => {
                bytes.push(1);
                bytes.extend_from_slice(reserve);
                bytes.extend_from_slice(&revision.to_le_bytes());
            }
        }
        bytes
    }

    pub fn canonical_bytes(&self, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &self.blch
        else {
            return Err(Error::InvalidShape);
        };
        if *domain == [0; 32]
            || keys.len() != 1
            || keys[0].pubkey.is_empty()
            || keys[0].pubkey.len() > MAX_BASE_WITNESS_BYTES
            || keys[0].signature.len() > MAX_BASE_WITNESS_BYTES
            || inputs.is_empty()
            || inputs.len() > MAX_BASE_ITEMS
            || outputs.is_empty()
            || outputs.len() > MAX_BASE_ITEMS
        {
            return Err(Error::ResourceLimit);
        }
        let base = self.blch.canonical_bytes();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BLCHRSRV");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&self.action_bytes());
        bytes.extend_from_slice(&(base.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&base);
        if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }

    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-BASE-RESERVE-AUTH-v1");
        h.update(domain);
        h.update(self.valid_until.to_le_bytes());
        h.update(self.action_bytes());
        h.update(self.blch.spend_signing_root());
        Ok(h.finalize().into())
    }

    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-BASE-RESERVE-OUT-v1");
        h.update(self.authorization(domain)?);
        Ok(h.finalize().into())
    }
}

/// Construction is private to this module. No external caller can grant an
/// ownership exception, and the capability cannot be cloned or serialized.
pub(in crate::transition) struct ReserveSpend {
    point: OutPoint,
    amount: u64,
    script: [u8; 32],
    authorization: [u8; 32],
}
impl ReserveSpend {
    pub(in crate::transition) fn claims(&self, point: &OutPoint) -> bool {
        self.point == *point
    }
    pub(in crate::transition) fn authorizes(
        &self,
        input: &TransferInputV2,
        entry: &EutxoEntry,
        outputs: &[TransferOutput],
        authorization: &[u8; 32],
    ) -> bool {
        self.point == (input.txid, input.vout)
            && self.point == (entry.txid, entry.vout)
            && input.key_index == RESERVE_KEY_INDEX
            && entry.value == self.amount
            && entry.script_hash == self.script
            && self.authorization == *authorization
            && outputs.first().is_some_and(|output| {
                output.value == self.amount && output.script_hash == self.script
            })
    }
}

impl State {
    pub fn base_reserve(&self, id: &[u8; 32]) -> Option<&Record> {
        self.base_reserves.get(id)
    }

    pub fn base_is_locked(&self, point: &OutPoint) -> bool {
        self.base_locks.contains_key(point)
    }

    pub fn spendable_base_output(&self, point: &OutPoint) -> Option<&EutxoEntry> {
        if self.base_is_locked(point) {
            None
        } else {
            self.base.utxo(&point.0, point.1)
        }
    }

    pub(super) fn ensure_base_unlocked(&self, inputs: &[TransferInputV2]) -> Result<(), Error> {
        if inputs.len() > MAX_BASE_ITEMS {
            return Err(Error::ResourceLimit);
        }
        if inputs
            .iter()
            .any(|input| self.base_is_locked(&(input.txid, input.vout)))
        {
            return Err(Error::LockedReserve);
        }
        Ok(())
    }

    pub fn quote_base_reserve(&self, request: &Request) -> Result<fee_market::TxCharge, Error> {
        let length = request.canonical_bytes(&self.domain)?.len() as u64;
        let PosTransaction::TransferV2 {
            tx_bytes,
            tip_millisat_per_gas,
            ..
        } = &request.blch
        else {
            return Err(Error::InvalidShape);
        };
        if *tx_bytes < length {
            return Err(Error::Base(super::TransferReject::UnderdeclaredSize));
        }
        if *tx_bytes > length.saturating_add(fee_market::TX_BYTES_DECLARE_SLACK) {
            return Err(Error::Base(super::TransferReject::OverdeclaredSize));
        }
        if *tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS {
            return Err(Error::Base(super::TransferReject::TipAboveCeiling));
        }
        let gas = fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 1 }, *tx_bytes)
            .checked_add(RESERVE_GAS)
            .filter(|gas| *gas <= fee_market::MAX_TX_GAS)
            .ok_or(Error::ResourceLimit)?;
        let (base_fee_sat, priority_fee_sat) =
            fee_market::fee_parts_sat(gas, self.base.next_base_fee(), *tip_millisat_per_gas);
        Ok(fee_market::TxCharge {
            gas,
            tx_bytes: *tx_bytes,
            base_fee_sat,
            priority_fee_sat,
        })
    }

    /// This never touches native assets, mints BLCH, issues LP or releases funds.
    /// The same admitted owner must provide at least one separate fee input.
    pub fn execute_base_reserve(
        &mut self,
        request: &Request,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        let charge = self.quote_base_reserve(request)?;
        if height > request.valid_until {
            return Err(Error::Expired);
        }
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &request.blch
        else {
            return Err(Error::InvalidShape);
        };
        let owner = &keys[0].pubkey;
        if !native_verifier.valid_pq_key(owner) {
            return Err(Error::InvalidReserve);
        }
        let authorization = request.authorization(&self.domain)?;
        let output_txid = request.output_txid(&self.domain)?;
        let (mut record, old_point) = match request.action {
            Action::Create { seed, amount } => {
                if amount == 0 || self.base_reserves.len() >= MAX_RESERVES {
                    return Err(Error::InvalidReserve);
                }
                let id = reserve_id(&self.domain, &seed, owner)?;
                if self.base_reserves.contains_key(&id) {
                    return Err(Error::InvalidReserve);
                }
                self.ensure_base_unlocked(inputs)?;
                (
                    Record {
                        id,
                        seed,
                        owner: owner.clone(),
                        amount,
                        revision: 0,
                        outpoint: (output_txid, 0),
                    },
                    None,
                )
            }
            Action::Continue { reserve, revision } => {
                if self.native.custody(&reserve).is_some() {
                    return Err(Error::LockedReserve);
                }
                let mut record = self
                    .base_reserves
                    .get(&reserve)
                    .cloned()
                    .ok_or(Error::InvalidReserve)?;
                if record.revision != revision {
                    return Err(Error::StaleReserve);
                }
                if record.owner != *owner {
                    return Err(Error::InvalidReserve);
                }
                let old = record.outpoint;
                if self.base_locks.get(&old) != Some(&record.id) {
                    return Err(Error::InvalidReserve);
                }
                record.revision = record.revision.checked_add(1).ok_or(Error::ResourceLimit)?;
                record.outpoint = (output_txid, 0);
                (record, Some(old))
            }
        };
        let script = reserve_script(&self.domain, &record.id);
        if outputs[0].value != record.amount || outputs[0].script_hash != script {
            return Err(Error::InvalidReserve);
        }
        let owner_hash: [u8; 32] = Sha3_256::digest(owner).into();
        if outputs[1..]
            .iter()
            .any(|output| output.script_hash != owner_hash)
        {
            return Err(Error::InvalidReserve);
        }
        let mut normal_count = 0usize;
        let mut reserve_count = 0usize;
        let mut funding = 0u128;
        for input in inputs {
            let point = (input.txid, input.vout);
            if Some(point) == old_point {
                if input.key_index != RESERVE_KEY_INDEX {
                    return Err(Error::InvalidReserve);
                }
                reserve_count += 1;
            } else {
                if self.base_is_locked(&point) {
                    return Err(Error::LockedReserve);
                }
                if input.key_index != 0 {
                    return Err(Error::InvalidReserve);
                }
                normal_count += 1;
                funding += u128::from(
                    self.base
                        .utxo(&point.0, point.1)
                        .ok_or(Error::InvalidReserve)?
                        .value,
                );
            }
        }
        if normal_count == 0 || reserve_count != usize::from(old_point.is_some()) {
            return Err(Error::InvalidReserve);
        }
        let change: u128 = outputs[1..]
            .iter()
            .map(|output| u128::from(output.value))
            .sum();
        let deposit = if old_point.is_none() {
            u128::from(record.amount)
        } else {
            0
        };
        if funding != change + deposit + charge.base_fee_sat + charge.priority_fee_sat {
            return Err(Error::Base(super::TransferReject::ValueNotConserved));
        }
        let base_fees = self
            .base_fees
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let priority_fees = self
            .priority_fees
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let permit = old_point.map(|point| ReserveSpend {
            point,
            amount: record.amount,
            script,
            authorization,
        });
        let plan = self
            .base
            .plan_transfer_v2_with_context(
                &request.blch,
                self.base.next_base_fee(),
                base_verifier,
                Some(JointTransferContext {
                    envelope_bytes: request.canonical_bytes(&self.domain)?.len() as u64,
                    output_txid,
                    charge,
                    authorization,
                    reserve: permit,
                }),
            )
            .map_err(Error::Base)?;
        // The base plan owns the exclusive base-state borrow; nothing below can fail.
        let charge = plan.commit();
        if let Some(point) = old_point {
            self.base_locks.remove(&point);
        }
        record.outpoint = (output_txid, 0);
        self.base_locks.insert(record.outpoint, record.id);
        self.base_reserves.insert(record.id, record.clone());
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(Receipt {
            reserve: record,
            authorization,
            blch_txid: output_txid,
            charge,
        })
    }

    pub(super) fn hash_base_reserves(&self, hash: &mut Sha3_256) {
        hash.update((self.base_reserves.len() as u64).to_le_bytes());
        for record in self.base_reserves.values() {
            hash.update(record.id);
            hash.update(record.seed);
            hash.update((record.owner.len() as u64).to_le_bytes());
            hash.update(&record.owner);
            hash.update(record.outpoint.0);
            hash.update(record.outpoint.1.to_le_bytes());
            hash.update(record.amount.to_le_bytes());
            hash.update(record.revision.to_le_bytes());
        }
    }

    pub(super) fn restore_base_reserves(
        &mut self,
        records: Vec<Record>,
        verifier: &dyn Verifier,
    ) -> Result<(), Error> {
        if records.len() > MAX_RESERVES || records.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(Error::InvalidRoot);
        }
        for record in records {
            if record.amount == 0
                || record.outpoint.1 != 0
                || record.id != reserve_id(&self.domain, &record.seed, &record.owner)?
                || !verifier.valid_pq_key(&record.owner)
            {
                return Err(Error::InvalidRoot);
            }
            let output = self
                .base
                .utxo(&record.outpoint.0, record.outpoint.1)
                .ok_or(Error::InvalidRoot)?;
            if output.value != record.amount
                || output.script_hash != reserve_script(&self.domain, &record.id)
                || self.base_locks.insert(record.outpoint, record.id).is_some()
            {
                return Err(Error::InvalidRoot);
            }
            self.base_reserves.insert(record.id, record);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
