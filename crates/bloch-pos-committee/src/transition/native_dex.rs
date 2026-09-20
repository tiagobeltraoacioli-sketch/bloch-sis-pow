//! Explicit opt-in atomic BLCH/native transfer rehearsal, not block activation.
//! Uses real CommittedState UTXOs and sealed native plans. Its combined root and
//! fee escrow are NOT the current Genesis4 block state format or fee settlement.
use super::{CommittedState, JointTransferContext, PosTransaction, TransferReject};
use crate::{fee_market, SignatureVerifier};
use bloch_euvm::ustav::{
    gateway::pools::{Error as PoolError, PoolLedger},
    transfer_wire, Receipt, Verifier,
};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
pub mod base_reserves;
pub mod wire;

#[cfg(test)]
mod tests;

pub const MAX_ENVELOPE_BYTES: u64 = fee_market::MAX_BLOCK_TX_BYTES;
const MAX_BASE_ITEMS: usize = 128;
const MAX_BASE_WITNESS_BYTES: usize = 8192;
/// Conservative rehearsal conversion: native owner/VM PQ checks cost 1,000
/// native units, versus the live hybrid verification charge. Scale ALL native
/// work, including prepaid unused work; this is not production fee calibration.
pub const NATIVE_GAS_MULTIPLIER: u64 = fee_market::HYBRID_VERIFY_GAS.div_ceil(1000);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidShape,
    WrongDomain,
    Expired,
    ResourceLimit,
    InvalidRoot,
    InvalidReserve,
    LockedReserve,
    StaleReserve,
    Base(TransferReject),
    Native(PoolError),
    Wire(transfer_wire::Error),
}
#[derive(Clone, Debug)]
pub struct Request {
    pub blch: PosTransaction,
    pub native: transfer_wire::Envelope,
    pub valid_until: u64,
    /// Fully prepaid bounded work, including native decoding and staging.
    pub native_gas: u64,
}
impl Request {
    pub fn canonical_bytes(&self, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
        if self.native.domain != *domain {
            return Err(Error::WrongDomain);
        }
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &self.blch
        else {
            return Err(Error::InvalidShape);
        };
        if inputs.is_empty()
            || inputs.len() > MAX_BASE_ITEMS
            || keys.is_empty()
            || keys.len() > MAX_BASE_ITEMS
            || outputs.len() > MAX_BASE_ITEMS
            || keys.iter().any(|k| {
                k.pubkey.is_empty()
                    || k.pubkey.len() > MAX_BASE_WITNESS_BYTES
                    || k.signature.len() > MAX_BASE_WITNESS_BYTES
            })
            || self.native_gas == 0
            || self.native_gas > fee_market::MAX_TX_GAS
        {
            return Err(Error::ResourceLimit);
        }
        let native = transfer_wire::encode(&self.native).map_err(Error::Wire)?;
        let base = self.blch.canonical_bytes();
        let length = 8 + 2 + 32 + 8 + 8 + 8 + 8 + base.len() + native.len();
        if length as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(b"BLCHNATV");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(domain);
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.extend_from_slice(&self.native_gas.to_le_bytes());
        out.extend_from_slice(&(base.len() as u64).to_le_bytes());
        out.extend_from_slice(&base);
        out.extend_from_slice(&(native.len() as u64).to_le_bytes());
        out.extend_from_slice(&native);
        Ok(out)
    }
    /// Both sets of owners sign this digest. Witnesses affect charged bytes,
    /// while the intent hash excludes signature bytes to avoid self-reference.
    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-JOINT-NATIVE-AUTH-v1");
        h.update(domain);
        h.update(self.blch.spend_signing_root());
        h.update(
            self.native
                .transaction
                .signing_hash(domain)
                .map_err(|_| Error::InvalidShape)?,
        );
        h.update(self.valid_until.to_le_bytes());
        h.update(self.native_gas.to_le_bytes());
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-JOINT-NATIVE-OUT-v1");
        h.update(self.authorization(domain)?);
        Ok(h.finalize().into())
    }
}
#[derive(Clone, Debug)]
pub struct State {
    base: CommittedState,
    native: PoolLedger,
    domain: [u8; 32],
    /// Debited real BLCH retained in committed rehearsal accounting; no payout API.
    base_fees: u128,
    priority_fees: u128,
    base_reserves: BTreeMap<[u8; 32], base_reserves::Record>,
    base_locks: BTreeMap<base_reserves::OutPoint, [u8; 32]>,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub version: u32,
    pub base: CommittedState,
    pub native: bloch_euvm::ustav::gateway::pools::Snapshot,
    pub native_root: [u8; 32],
    pub base_fees: u128,
    pub priority_fees: u128,
    pub base_reserves: Vec<base_reserves::Record>,
}
#[derive(Clone, Debug)]
pub struct Execution {
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub native: Receipt,
    pub charge: fee_market::TxCharge,
}
impl State {
    /// Expected roots must come from independently authenticated host state.
    /// Comparing caller-provided roots alone does not authenticate their origin.
    /// Initializes a NEW rehearsal with zero fees; use restore for continuation.
    pub fn from_parts(
        base: CommittedState,
        native: PoolLedger,
        base_root: [u8; 32],
        native_root: [u8; 32],
    ) -> Result<Self, Error> {
        let domain = base.admission_network_domain.ok_or(Error::WrongDomain)?;
        if domain == [0; 32] || domain != *native.gateway().native().domain() {
            return Err(Error::WrongDomain);
        }
        if base.compute_root() != base_root || native.state_root() != native_root {
            return Err(Error::InvalidRoot);
        }
        Ok(Self {
            base,
            native,
            domain,
            base_fees: 0,
            priority_fees: 0,
            base_reserves: BTreeMap::new(),
            base_locks: BTreeMap::new(),
        })
    }
    pub fn base(&self) -> &CommittedState {
        &self.base
    }
    pub fn native(&self) -> &PoolLedger {
        &self.native
    }
    pub fn fee_escrow(&self) -> (u128, u128) {
        (self.base_fees, self.priority_fees)
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: 2,
            base: self.base.clone(),
            native: self.native.snapshot(),
            native_root: self.native.state_root(),
            base_fees: self.base_fees,
            priority_fees: self.priority_fees,
            base_reserves: self.base_reserves.values().cloned().collect(),
        }
    }
    pub fn restore(
        snapshot: Snapshot,
        trusted_root: [u8; 32],
        verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        if snapshot.version != 2 {
            return Err(Error::InvalidRoot);
        }
        let native = PoolLedger::restore(snapshot.native, snapshot.native_root, verifier)
            .map_err(Error::Native)?;
        let base_root = snapshot.base.compute_root();
        let mut state = Self::from_parts(snapshot.base, native, base_root, snapshot.native_root)?;
        state.base_fees = snapshot.base_fees;
        state.priority_fees = snapshot.priority_fees;
        state.restore_base_reserves(snapshot.base_reserves, verifier)?;
        if state.state_root() != trusted_root {
            return Err(Error::InvalidRoot);
        }
        Ok(state)
    }
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-JOINT-REHEARSAL-STATE-v2");
        h.update(self.domain);
        h.update(self.base.compute_root());
        h.update(self.native.state_root());
        h.update(self.base_fees.to_le_bytes());
        h.update(self.priority_fees.to_le_bytes());
        self.hash_base_reserves(&mut h);
        h.finalize().into()
    }
    pub fn quote(&self, request: &Request) -> Result<fee_market::TxCharge, Error> {
        let length = request.canonical_bytes(&self.domain)?.len() as u64;
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
        .filter(|n| *n <= fee_market::MAX_TX_GAS)
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
    /// Validate both plans before consuming either. No proposal/block path calls
    /// this opt-in rehearsal API, and its fee escrow needs future block integration.
    pub fn execute(
        &mut self,
        request: &Request,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Execution, Error> {
        if let PosTransaction::TransferV2 { inputs, .. } = &request.blch {
            self.ensure_base_unlocked(inputs)?;
        }
        let charge = self.quote(request)?;
        if height > request.valid_until
            || request.native.transaction.valid_until > request.valid_until
        {
            return Err(Error::Expired);
        }
        let authorization = request.authorization(&self.domain)?;
        let output_txid = request.output_txid(&self.domain)?;
        let PosTransaction::TransferV2 { keys, .. } = &request.blch else {
            return Err(Error::InvalidShape);
        };
        if keys
            .iter()
            .any(|k| !native_verifier.valid_pq_key(&k.pubkey))
        {
            return Err(Error::InvalidShape);
        }
        let encoded_len = request.canonical_bytes(&self.domain)?.len() as u64;
        let native_length = transfer_wire::encode(&request.native)
            .map_err(Error::Wire)?
            .len() as u64;
        let decoding_gas = 100 + native_length.div_ceil(32);
        let remaining = request
            .native_gas
            .checked_sub(decoding_gas)
            .ok_or(Error::ResourceLimit)?;
        let base_fees = self
            .base_fees
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let priority_fees = self
            .priority_fees
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let scoped = NativeVerifier {
            inner: native_verifier,
            expected: request
                .native
                .transaction
                .signing_hash(&self.domain)
                .map_err(|_| Error::InvalidShape)?,
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
                self.base.next_base_fee(),
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
        // Both sealed plans hold exclusive state borrows. All fallible work is over.
        let charge = base.commit();
        let mut native = native.commit();
        native.gas_used += decoding_gas;
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(Execution {
            authorization,
            blch_txid: output_txid,
            native,
            charge,
        })
    }
}
struct NativeVerifier<'a> {
    inner: &'a dyn Verifier,
    expected: [u8; 32],
    authorization: [u8; 32],
}
impl Verifier for NativeVerifier<'_> {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        self.inner.valid_pq_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        message == self.expected && self.inner.verify_pq(&self.authorization, key, signature)
    }
}
