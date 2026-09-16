//! Same-owner paired close. Both plans remain inside the concrete State backend.
use super::super::base_reserves::{ReserveSpend, RESERVE_KEY_INDEX};
use super::*;
#[derive(Clone, Debug)]
pub struct CloseRequest {
    pub reserve: [u8; 32],
    pub creation_authorization: [u8; 32],
    pub blch: PosTransaction,
    pub native: transfer_wire::Envelope,
    pub valid_until: u64,
    pub native_gas: u64,
}
impl CloseRequest {
    fn joint(&self) -> Result<super::super::Request, Error> {
        bounded_joint(&self.blch, &self.native, self.valid_until, self.native_gas)
    }
    pub fn canonical_bytes(&self, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let mut bytes = self.joint()?.canonical_bytes(domain)?;
        bytes[..8].copy_from_slice(b"BLCHPCLS");
        bytes.extend_from_slice(&self.reserve);
        bytes.extend_from_slice(&self.creation_authorization);
        if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-PAIRED-CLOSE-AUTH-v1");
        h.update(self.joint()?.authorization(domain)?);
        h.update(self.reserve);
        h.update(self.creation_authorization);
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-PAIRED-CLOSE-OUT-v1");
        h.update(self.authorization(domain)?);
        Ok(h.finalize().into())
    }
}
#[derive(Clone, Debug)]
pub struct CloseReceipt {
    pub reserve: [u8; 32],
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub native: bloch_euvm::ustav::Receipt,
    pub charge: fee_market::TxCharge,
}
impl State {
    pub fn quote_paired_close(
        &self,
        request: &CloseRequest,
    ) -> Result<fee_market::TxCharge, Error> {
        self.quote_paired_close_with_context(request, self.base.next_base_fee(), 0)
    }
    pub(in crate::transition::native_dex) fn quote_paired_close_with_context(
        &self,
        request: &CloseRequest,
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

    pub fn execute_paired_close(
        &mut self,
        request: &CloseRequest,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<CloseReceipt, Error> {
        self.execute_paired_close_with_context(
            request,
            height,
            self.base.next_base_fee(),
            0,
            base_verifier,
            native_verifier,
        )
    }
    pub(in crate::transition::native_dex) fn execute_paired_close_with_context(
        &mut self,
        request: &CloseRequest,
        height: u64,
        base_fee: u128,
        outer_bytes: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<CloseReceipt, Error> {
        let charge = self.quote_paired_close_with_context(request, base_fee, outer_bytes)?;
        if self.reserve_pools.contains_key(&request.reserve) {
            return Err(Error::LockedReserve);
        }
        if height > request.valid_until
            || request.native.transaction.valid_until > request.valid_until
        {
            return Err(Error::Expired);
        }
        let record = self
            .base_reserves
            .get(&request.reserve)
            .ok_or(Error::InvalidReserve)?
            .clone();
        let paired = self
            .paired_reserves
            .get(&request.reserve)
            .ok_or(Error::InvalidReserve)?
            .clone();
        if paired.authorization != request.creation_authorization
            || paired.owner != record.owner
            || record.revision != 0
            || self.paired_locks.get(&paired.outpoint) != Some(&request.reserve)
        {
            return Err(Error::InvalidReserve);
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
            || keys[0].pubkey != record.owner
            || !native_verifier.valid_pq_key(&record.owner)
            || outputs.is_empty()
        {
            return Err(Error::InvalidReserve);
        }
        let owner_hash: [u8; 32] = Sha3_256::digest(&record.owner).into();
        if outputs[0].value != record.amount || outputs.iter().any(|o| o.script_hash != owner_hash)
        {
            return Err(Error::InvalidReserve);
        }
        let mut reserve_count = 0usize;
        let mut funding = 0u128;
        let mut fee_inputs = 0usize;
        for input in inputs {
            let point = (input.txid, input.vout);
            if point == record.outpoint {
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
                funding += self
                    .base
                    .utxo(&point.0, point.1)
                    .ok_or(Error::InvalidReserve)?
                    .value as u128;
                fee_inputs += 1;
            }
        }
        if reserve_count != 1 || fee_inputs == 0 {
            return Err(Error::InvalidReserve);
        }
        let change: u128 = outputs[1..].iter().map(|o| o.value as u128).sum();
        if funding != change + charge.base_fee_sat + charge.priority_fee_sat {
            return Err(Error::Base(TransferReject::ValueNotConserved));
        }
        let tx = &request.native.transaction;
        if tx.inputs.as_slice() != [paired.outpoint]
            || tx.outputs.len() != 1
            || tx.delta != 0
            || tx.asset != paired.asset
            || tx.outputs[0].owner != paired.owner
            || tx.outputs[0].amount != paired.amount
        {
            return Err(Error::InvalidReserve);
        }
        let authorization = request.authorization(&self.domain)?;
        let output_txid = request.output_txid(&self.domain)?;
        let permit = ReserveSpend::paired_close(self, &request.reserve, authorization)?;
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
            expected: tx
                .signing_hash(&self.domain)
                .map_err(|_| Error::InvalidShape)?,
            authorization,
        };
        let native = self
            .native
            .plan_transfer(tx, &request.native.witnesses, height, &scoped, remaining)
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
                    reserve: Some(permit),
                }),
            )
            .map_err(Error::Base)?;
        // No fallible work remains. Neither component nor a release plan is exported.
        let charge = base.commit();
        let mut native = native.commit();
        native.gas_used += decoding_gas + custody::FUNDING_GAS;
        self.base_locks.remove(&record.outpoint);
        self.paired_locks.remove(&paired.outpoint);
        self.base_reserves.remove(&request.reserve);
        self.paired_reserves.remove(&request.reserve);
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(CloseReceipt {
            reserve: request.reserve,
            authorization,
            blch_txid: output_txid,
            native,
            charge,
        })
    }
}

#[cfg(test)]
pub(super) mod tests;
