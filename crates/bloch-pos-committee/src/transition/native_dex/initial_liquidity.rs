//! Initial BLCH/native LP ownership backed by an existing, completely funded pair.
//! Swaps and LP redemption use separate atomic dispatchers; no subsequent Add or LP transfer.
use super::*;
use bloch_euvm::ustav::amm::{self, PoolState};
pub const MAX_POOLS: usize = 128;
/// Fixed bounded initial arithmetic/record work, additional to full-byte/PQ fees.
pub const BOOTSTRAP_GAS: u64 = 5000;
#[derive(Clone, Debug)]
pub struct Request {
    pub reserve: [u8; 32],
    pub creation_authorization: [u8; 32],
    pub fee_bps: u16,
    pub minimum_lp: u64,
    pub valid_until: u64,
    pub blch: PosTransaction,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub pool: PoolState,
    pub initial_reserves: [u64; 2],
    pub reserve: [u8; 32],
    pub creation_authorization: [u8; 32],
    pub owner: Vec<u8>,
    pub lp_balance: u64,
}
#[derive(Clone, Debug)]
pub struct Receipt {
    pub pool: [u8; 32],
    pub lp_minted: u64,
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub charge: fee_market::TxCharge,
}
impl Request {
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
            || inputs.is_empty()
            || inputs.len() > MAX_BASE_ITEMS
            || outputs.len() > MAX_BASE_ITEMS
            || keys[0].pubkey.is_empty()
            || keys[0].pubkey.len() > MAX_BASE_WITNESS_BYTES
            || keys[0].signature.len() > MAX_BASE_WITNESS_BYTES
        {
            return Err(Error::ResourceLimit);
        }
        let base = self.blch.canonical_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(b"BLCHILIQ");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(domain);
        out.extend_from_slice(&self.reserve);
        out.extend_from_slice(&self.creation_authorization);
        out.extend_from_slice(&self.fee_bps.to_le_bytes());
        out.extend_from_slice(&self.minimum_lp.to_le_bytes());
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.extend_from_slice(&(base.len() as u64).to_le_bytes());
        out.extend_from_slice(&base);
        if out.len() as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(out)
    }
    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-INITIAL-LIQUIDITY-AUTH-v1");
        h.update(domain);
        h.update(self.reserve);
        h.update(self.creation_authorization);
        h.update(self.fee_bps.to_le_bytes());
        h.update(self.minimum_lp.to_le_bytes());
        h.update(self.valid_until.to_le_bytes());
        h.update(self.blch.spend_signing_root());
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-INITIAL-LIQUIDITY-OUT-v1");
        h.update(self.authorization(domain)?);
        Ok(h.finalize().into())
    }
}
fn amm_error(e: amm::Error) -> Error {
    Error::Native(PoolError::Amm(e))
}
impl State {
    pub fn blch_pool_for_reserve(&self, reserve: &[u8; 32]) -> Option<&PoolState> {
        self.reserve_pools
            .get(reserve)
            .and_then(|id| self.blch_pool(id))
    }
    pub fn blch_pool(&self, id: &[u8; 32]) -> Option<&PoolState> {
        self.initial_pools.get(id).map(|r| &r.pool)
    }
    pub fn blch_lp_position(&self, id: &[u8; 32], owner: &[u8]) -> u64 {
        self.initial_pools
            .get(id)
            .filter(|r| r.owner == owner)
            .map_or(0, |r| r.lp_balance)
    }
    pub(super) fn bootstrap(
        &self,
        reserve: &[u8; 32],
        creation: &[u8; 32],
        fee_bps: u16,
        minimum_lp: u64,
    ) -> Result<Record, Error> {
        let b = self
            .base_reserves
            .get(reserve)
            .ok_or(Error::InvalidReserve)?;
        let n = self
            .paired_reserves
            .get(reserve)
            .ok_or(Error::InvalidReserve)?;
        self.supported_paired_asset(&n.asset)?;
        if n.authorization != *creation
            || b.owner != n.owner
            || b.revision != 0
            || self.base_locks.get(&b.outpoint) != Some(reserve)
            || self.paired_locks.get(&n.outpoint) != Some(reserve)
        {
            return Err(Error::InvalidReserve);
        }
        let bo = self
            .base
            .utxo(&b.outpoint.0, b.outpoint.1)
            .ok_or(Error::InvalidReserve)?;
        let no = self
            .native
            .gateway()
            .native()
            .output(&n.outpoint)
            .ok_or(Error::InvalidReserve)?;
        if bo.value != b.amount
            || bo.script_hash != base_reserves::reserve_script(&self.domain, reserve)
            || no.asset != n.asset
            || no.output.owner != n.owner
            || no.output.amount != n.amount
            || self.native.is_locked(&n.outpoint)
        {
            return Err(Error::InvalidReserve);
        }
        let pool = PoolState::new(self.domain, bloch_euvm::BLCH, n.asset, fee_bps, *reserve)
            .map_err(amm_error)?;
        let transition = pool
            .transition(
                &amm::Request {
                    pool: pool.id(),
                    revision: 0,
                    valid_until: u64::MAX,
                    action: amm::Action::Add {
                        maximum: [b.amount, n.amount],
                        minimum_lp,
                    },
                },
                0,
            )
            .map_err(amm_error)?;
        if transition.user_debit != [b.amount, n.amount]
            || transition.user_credit != [0; 2]
            || transition.unused_maximum != [0; 2]
            || transition.lp_burn != 0
        {
            return Err(Error::InvalidReserve);
        }
        Ok(Record {
            pool: transition.next,
            initial_reserves: [b.amount, n.amount],
            reserve: *reserve,
            creation_authorization: *creation,
            owner: b.owner.clone(),
            lp_balance: transition.lp_mint,
        })
    }
    pub fn quote_initial_liquidity(
        &self,
        request: &Request,
    ) -> Result<fee_market::TxCharge, Error> {
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
        let gas = fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 1 }, *tx_bytes)
            .checked_add(BOOTSTRAP_GAS)
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
    pub fn execute_initial_liquidity(
        &mut self,
        request: &Request,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        let charge = self.quote_initial_liquidity(request)?;
        if height > request.valid_until {
            return Err(Error::Expired);
        }
        if self.initial_pools.len() >= MAX_POOLS
            || self.reserve_pools.contains_key(&request.reserve)
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
        self.ensure_base_unlocked(inputs)?;
        let record = self.bootstrap(
            &request.reserve,
            &request.creation_authorization,
            request.fee_bps,
            request.minimum_lp,
        )?;
        if keys[0].pubkey != record.owner
            || !native_verifier.valid_pq_key(&record.owner)
            || self.initial_pools.contains_key(&record.pool.id())
        {
            return Err(Error::InvalidReserve);
        }
        let owner_hash: [u8; 32] = Sha3_256::digest(&record.owner).into();
        if outputs.iter().any(|o| o.script_hash != owner_hash)
            || inputs.iter().any(|i| i.key_index != 0)
        {
            return Err(Error::InvalidReserve);
        }
        let authorization = request.authorization(&self.domain)?;
        let output_txid = request.output_txid(&self.domain)?;
        let base_fees = self
            .base_fees
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let priority_fees = self
            .priority_fees
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::ResourceLimit)?;
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
                    reserve: None,
                }),
            )
            .map_err(Error::Base)?;
        let charge = plan.commit();
        let pool = record.pool.id();
        let lp_minted = record.lp_balance;
        self.reserve_pools.insert(record.reserve, pool);
        self.initial_pools.insert(pool, record);
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(Receipt {
            pool,
            lp_minted,
            authorization,
            blch_txid: output_txid,
            charge,
        })
    }
    pub(super) fn hash_initial_pools(&self, h: &mut Sha3_256) {
        h.update((self.initial_pools.len() as u64).to_le_bytes());
        for r in self.initial_pools.values() {
            h.update(r.pool.state_root());
            h.update(r.initial_reserves[0].to_le_bytes());
            h.update(r.initial_reserves[1].to_le_bytes());
            h.update(r.reserve);
            h.update(r.creation_authorization);
            h.update((r.owner.len() as u64).to_le_bytes());
            h.update(&r.owner);
            h.update(r.lp_balance.to_le_bytes());
        }
    }
    /// Structural checks supplement, but do not replace, an authenticated host root.
    /// Swaps and redemption may evolve pools; initial funding and LP ownership stay fixed.
    pub(super) fn validate_blch_pool(&self, r: &Record) -> Result<(), Error> {
        let b = self
            .base_reserves
            .get(&r.reserve)
            .ok_or(Error::InvalidReserve)?;
        let n = self
            .paired_reserves
            .get(&r.reserve)
            .ok_or(Error::InvalidReserve)?;
        self.supported_paired_asset(&n.asset)?;
        let bo = self
            .base
            .utxo(&b.outpoint.0, b.outpoint.1)
            .ok_or(Error::InvalidReserve)?;
        let no = self
            .native
            .gateway()
            .native()
            .output(&n.outpoint)
            .ok_or(Error::InvalidReserve)?;
        if n.authorization != r.creation_authorization
            || b.owner != r.owner
            || n.owner != r.owner
            || b.id != r.reserve
            || n.id != r.reserve
            || b.outpoint.1 != 0
            || n.outpoint.index != 0
            || self.base_locks.get(&b.outpoint) != Some(&r.reserve)
            || self.paired_locks.get(&n.outpoint) != Some(&r.reserve)
            || bo.value != b.amount
            || bo.script_hash != base_reserves::reserve_script(&self.domain, &r.reserve)
            || no.asset != n.asset
            || no.output.owner != n.owner
            || no.output.amount != n.amount
            || self.native.is_locked(&n.outpoint)
            || r.pool.reserves() != [b.amount, n.amount]
            || b.revision.checked_add(1) != Some(r.pool.revision())
        {
            return Err(Error::InvalidReserve);
        }
        let initial = PoolState::new(
            self.domain,
            bloch_euvm::BLCH,
            n.asset,
            r.pool.fee_bps(),
            r.reserve,
        )
        .map_err(amm_error)?;
        let initial = initial
            .transition(
                &amm::Request {
                    pool: initial.id(),
                    revision: 0,
                    valid_until: u64::MAX,
                    action: amm::Action::Add {
                        maximum: r.initial_reserves,
                        minimum_lp: 0,
                    },
                },
                0,
            )
            .map_err(amm_error)?;
        if initial.next.id() != r.pool.id()
            || initial.next.assets() != r.pool.assets()
            || initial.next.domain() != r.pool.domain()
            || r.lp_balance > initial.lp_mint
            || r.lp_balance.checked_add(amm::MINIMUM_LIQUIDITY) != Some(r.pool.lp_supply())
            || (b.revision == 0
                && (initial.next != r.pool
                    || b.outpoint != (paired_custody::output_id(&n.authorization), 0)))
            || (r.lp_balance == initial.lp_mint
                && u128::from(b.amount) * u128::from(n.amount)
                    < u128::from(r.initial_reserves[0]) * u128::from(r.initial_reserves[1]))
        {
            return Err(Error::InvalidReserve);
        }
        PoolState::restore(r.pool.snapshot(), r.pool.state_root()).map_err(amm_error)?;
        Ok(())
    }
    pub(super) fn restore_initial_pools(&mut self, records: Vec<Record>) -> Result<(), Error> {
        if records.len() > MAX_POOLS || records.windows(2).any(|w| w[0].pool.id() >= w[1].pool.id())
        {
            return Err(Error::InvalidRoot);
        }
        for record in records {
            self.validate_blch_pool(&record)?;
            if self
                .reserve_pools
                .insert(record.reserve, record.pool.id())
                .is_some()
            {
                return Err(Error::InvalidRoot);
            }
            self.initial_pools.insert(record.pool.id(), record);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
