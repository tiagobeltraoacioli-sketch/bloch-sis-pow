//! Atomic paired reserve creation and unconverted closing. Pool swaps use a separate dispatcher.
mod close;
#[cfg(test)]
pub(super) use close::tests::funded_close;
pub mod wire;
use super::base_reserves::{reserve_id, reserve_script, Record, MAX_RESERVES};
use super::*;
use bloch_euvm::ustav::{gateway::pools::custody, OutPoint};
pub use close::{CloseReceipt, CloseRequest};
#[derive(Clone, Debug)]
pub struct Request {
    pub blch: PosTransaction,
    pub native: transfer_wire::Envelope,
    pub seed: [u8; 32],
    pub blch_amount: u64,
    pub native_amount: u64,
    pub valid_until: u64,
    pub native_gas: u64,
}
pub(super) fn bounded_joint(
    blch: &PosTransaction,
    native: &transfer_wire::Envelope,
    valid_until: u64,
    native_gas: u64,
) -> Result<super::Request, Error> {
    let PosTransaction::TransferV2 {
        keys,
        inputs,
        outputs,
        ..
    } = blch
    else {
        return Err(Error::InvalidShape);
    };
    if keys.len() != 1
        || inputs.is_empty()
        || inputs.len() > MAX_BASE_ITEMS
        || outputs.is_empty()
        || outputs.len() > MAX_BASE_ITEMS
        || keys.iter().any(|k| {
            k.pubkey.is_empty()
                || k.pubkey.len() > MAX_BASE_WITNESS_BYTES
                || k.signature.len() > MAX_BASE_WITNESS_BYTES
        })
    {
        return Err(Error::ResourceLimit);
    }
    // Validate native vector/witness bounds before any payload cloning.
    transfer_wire::encode(native).map_err(Error::Wire)?;
    Ok(super::Request {
        blch: blch.clone(),
        native: native.clone(),
        valid_until: valid_until,
        native_gas: native_gas,
    })
}
impl Request {
    fn joint(&self) -> Result<super::Request, Error> {
        bounded_joint(&self.blch, &self.native, self.valid_until, self.native_gas)
    }
    pub fn canonical_bytes(&self, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let mut bytes = self.joint()?.canonical_bytes(domain)?;
        bytes[..8].copy_from_slice(b"BLCHPAIR");
        bytes.extend_from_slice(&self.seed);
        bytes.extend_from_slice(&self.blch_amount.to_le_bytes());
        bytes.extend_from_slice(&self.native_amount.to_le_bytes());
        if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-PAIRED-CUSTODY-AUTH-v1");
        h.update(self.joint()?.authorization(domain)?);
        h.update(self.seed);
        h.update(self.blch_amount.to_le_bytes());
        h.update(self.native_amount.to_le_bytes());
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(output_id(&self.authorization(domain)?))
    }
}
pub(super) fn output_id(authorization: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BLOCH-PAIRED-CUSTODY-OUT-v1");
    h.update(authorization);
    h.finalize().into()
}
#[derive(Clone, Debug)]
pub struct Receipt {
    pub reserve: Record,
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub native: bloch_euvm::ustav::Receipt,
    pub charge: fee_market::TxCharge,
}
impl State {
    pub fn paired_custody(&self, id: &[u8; 32]) -> Option<&custody::Record> {
        self.paired_reserves.get(id)
    }
    pub fn quote_paired_custody(&self, request: &Request) -> Result<fee_market::TxCharge, Error> {
        self.quote_paired_custody_with_context(request, self.base.next_base_fee(), 0)
    }
    pub(in crate::transition::native_dex) fn quote_paired_custody_with_context(
        &self,
        request: &Request,
        base_fee: u128,
        outer_bytes: u64,
    ) -> Result<fee_market::TxCharge, Error> {
        let length = (request.canonical_bytes(&self.domain)?.len() as u64)
            .checked_add(outer_bytes)
            .ok_or(Error::ResourceLimit)?;
        let PosTransaction::TransferV2 {
            keys,
            tx_bytes,
            tip_millisat_per_gas,
            ..
        } = &request.blch
        else {
            return Err(Error::InvalidShape);
        };
        if *tx_bytes < length {
            return Err(Error::Base(TransferReject::UnderdeclaredSize));
        }
        if *tx_bytes > length.saturating_add(fee_market::TX_BYTES_DECLARE_SLACK) {
            return Err(Error::Base(TransferReject::OverdeclaredSize));
        }
        if *tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS {
            return Err(Error::Base(TransferReject::TipAboveCeiling));
        }
        let native_work = request
            .native_gas
            .checked_mul(NATIVE_GAS_MULTIPLIER)
            .ok_or(Error::ResourceLimit)?;
        let gas = fee_market::intrinsic_gas(
            fee_market::TxClass::Eutxo {
                inputs: keys.len() as u32,
            },
            *tx_bytes,
        )
        .checked_add(native_work)
        .and_then(|gas| gas.checked_add(1000))
        .filter(|n| *n <= fee_market::MAX_TX_GAS)
        .ok_or(Error::ResourceLimit)?;
        let (base_fee_sat, priority_fee_sat) =
            fee_market::fee_parts_sat(gas, base_fee, *tip_millisat_per_gas);
        Ok(fee_market::TxCharge {
            gas,
            tx_bytes: *tx_bytes,
            base_fee_sat,
            priority_fee_sat,
        })
    }

    pub fn execute_paired_custody(
        &mut self,
        request: &Request,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        self.execute_paired_custody_with_context(
            request,
            height,
            self.base.next_base_fee(),
            0,
            base_verifier,
            native_verifier,
        )
    }
    pub(in crate::transition::native_dex) fn execute_paired_custody_with_context(
        &mut self,
        request: &Request,
        height: u64,
        base_fee: u128,
        outer_bytes: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        let charge = self.quote_paired_custody_with_context(request, base_fee, outer_bytes)?;
        if height > request.valid_until
            || request.native.transaction.valid_until > request.valid_until
        {
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
        if keys.len() != 1
            || outputs.is_empty()
            || request.blch_amount == 0
            || request.native_amount == 0
            || self.base_reserves.len() >= MAX_RESERVES
        {
            return Err(Error::InvalidReserve);
        }
        let owner = &keys[0].pubkey;
        if !native_verifier.valid_pq_key(owner) {
            return Err(Error::InvalidReserve);
        }
        self.ensure_base_unlocked(inputs)?;
        self.ensure_native_unlocked(&request.native.transaction.inputs)?;
        let id = reserve_id(&self.domain, &request.seed, owner)?;
        if self.base_reserves.contains_key(&id) {
            return Err(Error::InvalidReserve);
        }
        let owner_hash: [u8; 32] = Sha3_256::digest(owner).into();
        if outputs[0].value != request.blch_amount
            || outputs[0].script_hash != reserve_script(&self.domain, &id)
            || outputs[1..].iter().any(|o| o.script_hash != owner_hash)
        {
            return Err(Error::InvalidReserve);
        }
        let authorization = request.authorization(&self.domain)?;
        let output_txid = request.output_txid(&self.domain)?;
        let native_hash = request
            .native
            .transaction
            .signing_hash(&self.domain)
            .map_err(|_| Error::InvalidShape)?;
        let native_record = custody::Record {
            id,
            authorization,
            asset: request.native.transaction.asset,
            owner: owner.clone(),
            amount: request.native_amount,
            outpoint: OutPoint {
                transaction: native_hash,
                index: 0,
            },
        };
        let record = Record {
            id,
            seed: request.seed,
            owner: owner.clone(),
            amount: request.blch_amount,
            revision: 0,
            outpoint: (output_txid, 0),
        };
        self.validate_paired_funding(&native_record, &request.native.transaction)?;
        let base_fees = self
            .base_fees
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let priority_fees = self
            .priority_fees
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let encoded_len = (request.canonical_bytes(&self.domain)?.len() as u64)
            .checked_add(outer_bytes)
            .ok_or(Error::ResourceLimit)?;
        let decoding_gas = 100
            + transfer_wire::encode(&request.native)
                .map_err(Error::Wire)?
                .len()
                .div_ceil(32) as u64;
        let remaining = request
            .native_gas
            .checked_sub(decoding_gas + custody::FUNDING_GAS)
            .ok_or(Error::ResourceLimit)?;
        let scoped = NativeVerifier {
            inner: native_verifier,
            expected: native_hash,
            authorization,
        };
        let native = self
            .native
            .plan_transfer(
                &request.native.transaction,
                &request.native.witnesses,
                height,
                &scoped,
                remaining,
            )
            .map_err(Error::Native)?;
        let base = self
            .base
            .plan_transfer_v2_with_context(
                &request.blch,
                base_fee,
                base_verifier,
                Some(JointTransferContext {
                    envelope_bytes: encoded_len,
                    output_txid,
                    charge,
                    authorization,
                    reserve: None,
                }),
            )
            .map_err(Error::Base)?;
        // Both sealed plans validate before any state, lock, or fee is published.
        let charge = base.commit();
        let mut native = native.commit();
        native.gas_used += decoding_gas + custody::FUNDING_GAS;
        self.paired_locks.insert(native_record.outpoint, id);
        self.paired_reserves.insert(id, native_record);
        self.base_reserves.insert(id, record.clone());
        self.base_locks.insert(record.outpoint, id);
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(Receipt {
            reserve: record,
            authorization,
            blch_txid: output_txid,
            native,
            charge,
        })
    }
}

#[cfg(test)]
pub(super) mod tests;
