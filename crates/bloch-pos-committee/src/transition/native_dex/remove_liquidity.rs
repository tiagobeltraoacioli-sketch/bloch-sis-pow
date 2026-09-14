//! Owner-authorized proportional LP redemption; local rehearsal, not live admission.
use super::base_reserves::{ReserveSpend, RESERVE_KEY_INDEX};
use super::*;
use bloch_euvm::ustav::{amm, OutPoint};

pub const REMOVE_GAS: u64 = 5_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteRequest {
    pub domain: [u8; 32],
    pub pool: [u8; 32],
    pub revision: u64,
    pub lp: u64,
    /// Minimum payouts in raw [BLCH, native asset] units.
    pub minimum: [u64; 2],
    pub valid_until: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    pub request: QuoteRequest,
    pub height: u64,
    pub pool_state_root: [u8; 32],
    pub amounts_out: [u64; 2],
    pub reserves_before: [u64; 2],
    pub reserves_after: [u64; 2],
    pub lp_remaining: u64,
}
#[derive(Clone, Debug)]
pub struct Request {
    pub quote: QuoteRequest,
    pub pool_state_root: [u8; 32],
    pub blch: PosTransaction,
    pub native: transfer_wire::Envelope,
    pub native_gas: u64,
}
impl QuoteRequest {
    fn action(&self) -> amm::Request {
        amm::Request {
            pool: self.pool,
            revision: self.revision,
            valid_until: self.valid_until,
            action: amm::Action::Remove {
                lp: self.lp,
                minimum: self.minimum,
            },
        }
    }
}
impl Request {
    fn joint(&self) -> Result<super::Request, Error> {
        paired_custody::bounded_joint(
            &self.blch,
            &self.native,
            self.quote.valid_until,
            self.native_gas,
        )
    }
    fn intent_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96);
        bytes.extend_from_slice(&self.quote.pool);
        bytes.extend_from_slice(&self.pool_state_root);
        bytes.extend_from_slice(&self.quote.revision.to_le_bytes());
        bytes.extend_from_slice(&self.quote.lp.to_le_bytes());
        bytes.extend_from_slice(&self.quote.minimum[0].to_le_bytes());
        bytes.extend_from_slice(&self.quote.minimum[1].to_le_bytes());
        bytes
    }
    pub fn canonical_bytes(&self, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
        if self.quote.domain != *domain {
            return Err(Error::WrongDomain);
        }
        let mut bytes = self.joint()?.canonical_bytes(domain)?;
        bytes[..8].copy_from_slice(b"BLCHLPRM");
        bytes.extend_from_slice(&self.intent_bytes());
        if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(bytes)
    }
    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-BLCH-REMOVE-AUTH-v1");
        h.update(self.joint()?.authorization(domain)?);
        h.update(self.intent_bytes());
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-BLCH-REMOVE-OUT-v1");
        h.update(self.authorization(domain)?);
        Ok(h.finalize().into())
    }
}
#[derive(Clone, Debug)]
pub struct Receipt {
    pub quote: Quote,
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub native: bloch_euvm::ustav::Receipt,
    pub charge: fee_market::TxCharge,
}
impl State {
    /// An unsigned read-only calculation, not a proof of LP ownership or finality.
    pub fn quote_blch_remove(&self, request: &QuoteRequest, height: u64) -> Result<Quote, Error> {
        if request.domain != self.domain {
            return Err(Error::WrongDomain);
        }
        let record = self
            .initial_pools
            .get(&request.pool)
            .ok_or(Error::InvalidReserve)?;
        if self.reserve_pools.get(&record.reserve) != Some(&request.pool) {
            return Err(Error::InvalidReserve);
        }
        self.validate_blch_pool(record)?;
        let lp_remaining = record
            .lp_balance
            .checked_sub(request.lp)
            .ok_or(Error::InvalidReserve)?;
        let transition = record
            .pool
            .transition(&request.action(), height)
            .map_err(|e| Error::Native(PoolError::Amm(e)))?;
        Ok(Quote {
            request: request.clone(),
            height,
            pool_state_root: record.pool.state_root(),
            amounts_out: transition.user_credit,
            reserves_before: record.pool.reserves(),
            reserves_after: transition.next.reserves(),
            lp_remaining,
        })
    }
    pub fn quote_blch_remove_fee(&self, request: &Request) -> Result<fee_market::TxCharge, Error> {
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
        let gas = fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 1 }, *tx_bytes)
            .checked_add(native_work)
            .and_then(|g| g.checked_add(REMOVE_GAS))
            .filter(|g| *g <= fee_market::MAX_TX_GAS)
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
    pub fn execute_blch_remove(
        &mut self,
        request: &Request,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        let charge = self.quote_blch_remove_fee(request)?;
        let quote = self.quote_blch_remove(&request.quote, height)?;
        if quote.pool_state_root != request.pool_state_root {
            return Err(Error::StaleReserve);
        }
        if request.native.transaction.valid_until > request.quote.valid_until {
            return Err(Error::Expired);
        }
        let mut pool = self.initial_pools[&request.quote.pool].clone();
        let mut base_record = self.base_reserves[&pool.reserve].clone();
        let mut native_record = self.paired_reserves[&pool.reserve].clone();
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &request.blch
        else {
            return Err(Error::InvalidShape);
        };
        let owner = &pool.owner;
        let owner_hash: [u8; 32] = Sha3_256::digest(owner).into();
        if keys[0].pubkey != *owner
            || !native_verifier.valid_pq_key(owner)
            || outputs.len() < 2
            || outputs[0].value != quote.reserves_after[0]
            || outputs[0].script_hash != base_reserves::reserve_script(&self.domain, &pool.reserve)
            || outputs[1].value != quote.amounts_out[0]
            || outputs[1..].iter().any(|o| o.script_hash != owner_hash)
        {
            return Err(Error::InvalidReserve);
        }
        let mut funding = 0u128;
        let mut reserve_inputs = 0usize;
        let mut fee_inputs = 0usize;
        for input in inputs {
            let point = (input.txid, input.vout);
            if point == base_record.outpoint {
                if input.key_index != RESERVE_KEY_INDEX {
                    return Err(Error::InvalidReserve);
                }
                reserve_inputs += 1;
            } else {
                if self.base_is_locked(&point) {
                    return Err(Error::LockedReserve);
                }
                if input.key_index != 0 {
                    return Err(Error::InvalidReserve);
                }
                let output = self
                    .base
                    .utxo(&point.0, point.1)
                    .ok_or(Error::InvalidReserve)?;
                if output.script_hash != owner_hash {
                    return Err(Error::InvalidReserve);
                }
                funding += u128::from(output.value);
                fee_inputs += 1;
            }
        }
        if reserve_inputs != 1 || fee_inputs == 0 {
            return Err(Error::InvalidReserve);
        }
        let change: u128 = outputs[2..].iter().map(|o| u128::from(o.value)).sum();
        if funding != change + charge.base_fee_sat + charge.priority_fee_sat {
            return Err(Error::Base(TransferReject::ValueNotConserved));
        }
        let tx = &request.native.transaction;
        let w = &request.native.witnesses;
        if tx.asset != native_record.asset
            || tx.delta != 0
            || tx.inputs.as_slice() != [native_record.outpoint]
            || tx.outputs.len() != 2
            || tx.outputs[0].amount != quote.reserves_after[1]
            || tx.outputs[1].amount != quote.amounts_out[1]
            || tx.outputs.iter().any(|o| o.owner != *owner)
            || w.owners.len() != 1
            || w.owners[0].is_empty()
            || w.modules.len() != 1
            || !w.modules[0].is_empty()
            || !w.eligibility.is_empty()
        {
            return Err(Error::InvalidReserve);
        }
        let authorization = request.authorization(&self.domain)?;
        let output_txid = request.output_txid(&self.domain)?;
        let native_hash = tx
            .signing_hash(&self.domain)
            .map_err(|_| Error::InvalidShape)?;
        let permit = ReserveSpend::remove_liquidity(self, &quote, authorization)?;
        let base_fees = self
            .base_fees
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let priority_fees = self
            .priority_fees
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let next = pool
            .pool
            .transition(&request.quote.action(), height)
            .map_err(|e| Error::Native(PoolError::Amm(e)))?;
        let next_revision = base_record
            .revision
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let envelope_bytes = request.canonical_bytes(&self.domain)?.len() as u64;
        let decoding_gas = 100
            + transfer_wire::encode(&request.native)
                .map_err(Error::Wire)?
                .len()
                .div_ceil(32) as u64;
        let remaining = request
            .native_gas
            .checked_sub(decoding_gas)
            .ok_or(Error::ResourceLimit)?;
        // Both legs require real owner signatures. Redemption does not use the
        // swap-only empty-witness exception, even for the locked native input.
        let scoped = NativeVerifier {
            inner: native_verifier,
            expected: native_hash,
            authorization,
        };
        let native_plan = self
            .native
            .plan_transfer(tx, w, height, &scoped, remaining)
            .map_err(Error::Native)?;
        let base_plan = self
            .base
            .plan_transfer_v2_with_context(
                &request.blch,
                self.base.next_base_fee(),
                base_verifier,
                Some(JointTransferContext {
                    envelope_bytes,
                    output_txid,
                    charge,
                    authorization,
                    reserve: Some(permit),
                }),
            )
            .map_err(Error::Base)?;
        // All fallible work precedes both commits, including LP and fee arithmetic.
        let charge = base_plan.commit();
        let mut native = native_plan.commit();
        native.gas_used += decoding_gas;
        self.base_locks.remove(&base_record.outpoint);
        self.paired_locks.remove(&native_record.outpoint);
        base_record.outpoint = (output_txid, 0);
        base_record.amount = quote.reserves_after[0];
        base_record.revision = next_revision;
        native_record.outpoint = OutPoint {
            transaction: native_hash,
            index: 0,
        };
        native_record.amount = quote.reserves_after[1];
        pool.pool = next.next;
        pool.lp_balance = quote.lp_remaining;
        self.base_locks.insert(base_record.outpoint, pool.reserve);
        self.paired_locks
            .insert(native_record.outpoint, pool.reserve);
        self.base_reserves.insert(pool.reserve, base_record);
        self.paired_reserves.insert(pool.reserve, native_record);
        self.initial_pools.insert(request.quote.pool, pool);
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(Receipt {
            quote,
            authorization,
            blch_txid: output_txid,
            native,
            charge,
        })
    }
}
