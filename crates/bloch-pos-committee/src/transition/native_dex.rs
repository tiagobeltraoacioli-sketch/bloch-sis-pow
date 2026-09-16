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
pub mod add_liquidity;
pub mod backend;
pub mod base_reserves;
pub mod gateway;
pub mod initial_liquidity;
pub mod paired_custody;
pub mod pool_batch;
pub mod pool_candidate;
pub mod pool_intent;
pub mod pool_review;
pub mod pool_submission;
pub mod pool_wire;
pub mod remove_liquidity;
pub mod swap;
pub mod swap_quote;
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
    GatewayWire(bloch_euvm::ustav::gateway::wire::Error),
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
    paired_reserves: BTreeMap<[u8; 32], bloch_euvm::ustav::gateway::pools::custody::Record>,
    paired_locks: BTreeMap<bloch_euvm::ustav::OutPoint, [u8; 32]>,
    initial_pools: BTreeMap<[u8; 32], initial_liquidity::Record>,
    reserve_pools: BTreeMap<[u8; 32], [u8; 32]>,
}
/// Opaque native component storage, without ownership of a `CommittedState`.
///
/// Hosts may store this alongside their base state without recursive ownership.
/// Its commitment contains no base root, head or slot, so a host can commit this
/// component without recursive hashing. Rehearsal reassembly uses a separate pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeState {
    native: PoolLedger,
    domain: [u8; 32],
    /// Debited real BLCH retained in committed rehearsal accounting; no payout API.
    base_fees: u128,
    priority_fees: u128,
    base_reserves: BTreeMap<[u8; 32], base_reserves::Record>,
    base_locks: BTreeMap<base_reserves::OutPoint, [u8; 32]>,
    paired_reserves: BTreeMap<[u8; 32], bloch_euvm::ustav::gateway::pools::custody::Record>,
    paired_locks: BTreeMap<bloch_euvm::ustav::OutPoint, [u8; 32]>,
    initial_pools: BTreeMap<[u8; 32], initial_liquidity::Record>,
    reserve_pools: BTreeMap<[u8; 32], [u8; 32]>,
}
/// A native component bound to the exact base projection from a rehearsal.
/// Only `State::from_components` consumes this authenticated reassembly boundary.
#[derive(Clone, Debug)]
pub struct PinnedNativeState {
    base_root: [u8; 32],
    state: NativeState,
}

impl NativeState {
    /// Immutable network binding for the host's canonical-state checks.
    pub(super) fn domain(&self) -> [u8; 32] {
        self.domain
    }

    /// Empty component for the host's explicitly gated initialization path.
    pub(super) fn empty(domain: [u8; 32]) -> Result<Self, Error> {
        if domain == [0; 32] {
            return Err(Error::WrongDomain);
        }
        Ok(Self {
            native: PoolLedger::new(domain),
            domain,
            base_fees: 0,
            priority_fees: 0,
            base_reserves: BTreeMap::new(),
            base_locks: BTreeMap::new(),
            paired_reserves: BTreeMap::new(),
            paired_locks: BTreeMap::new(),
            initial_pools: BTreeMap::new(),
            reserve_pools: BTreeMap::new(),
        })
    }

    /// Native component commitment only; neither a finalized root nor a gateway proof.
    pub(super) fn commitment(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-NATIVE-COMPONENT-STATE-v1");
        h.update(self.domain);
        h.update(self.native.state_root());
        h.update(self.base_fees.to_le_bytes());
        h.update(self.priority_fees.to_le_bytes());
        base_reserves::hash_base_reserves(&self.base_reserves, &mut h);
        backend::hash_paired_reserves(&self.paired_reserves, &mut h);
        initial_liquidity::hash_initial_pools(&self.initial_pools, &mut h);
        h.update((self.base_locks.len() as u64).to_le_bytes());
        for ((txid, vout), reserve) in &self.base_locks {
            h.update(txid);
            h.update(vout.to_le_bytes());
            h.update(reserve);
        }
        h.update((self.paired_locks.len() as u64).to_le_bytes());
        for (outpoint, reserve) in &self.paired_locks {
            h.update(outpoint.transaction);
            h.update(outpoint.index.to_le_bytes());
            h.update(reserve);
        }
        h.update((self.reserve_pools.len() as u64).to_le_bytes());
        for (reserve, pool) in &self.reserve_pools {
            h.update(reserve);
            h.update(pool);
        }
        h.finalize().into()
    }
}

/// Opaque complete-state checkpoint. Only State::restore can consume it.
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::Snapshot;
/// fn extract(snapshot: Snapshot) { let ledger = snapshot.native; }
/// ```
#[derive(Clone, Debug)]
pub struct Snapshot {
    version: u32,
    base: CommittedState,
    native: bloch_euvm::ustav::gateway::pools::Snapshot,
    native_root: [u8; 32],
    base_fees: u128,
    priority_fees: u128,
    base_reserves: Vec<base_reserves::Record>,
    paired_reserves: Vec<bloch_euvm::ustav::gateway::pools::custody::Record>,
    initial_pools: Vec<initial_liquidity::Record>,
}
#[derive(Clone, Debug)]
pub struct Execution {
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub native: Receipt,
    pub charge: fee_market::TxCharge,
}
impl State {
    /// Separate host-owned base state from opaque native component storage.
    /// No roots, fees, locks or snapshot versions change at this boundary.
    pub fn into_parts(self) -> (CommittedState, PinnedNativeState) {
        let base_root = self.base.compute_root();
        let native = NativeState {
            native: self.native,
            domain: self.domain,
            base_fees: self.base_fees,
            priority_fees: self.priority_fees,
            base_reserves: self.base_reserves,
            base_locks: self.base_locks,
            paired_reserves: self.paired_reserves,
            paired_locks: self.paired_locks,
            initial_pools: self.initial_pools,
            reserve_pools: self.reserve_pools,
        };
        (
            self.base,
            PinnedNativeState {
                base_root,
                state: native,
            },
        )
    }

    /// Reassemble previously separated state against an authenticated joint root.
    /// The caller must obtain `trusted_root` independently; equality alone is
    /// not a finality proof. A changed base projection must not reuse custody
    /// records from a prior state, even when its network domain is unchanged.
    pub fn from_components(
        base: CommittedState,
        pinned: PinnedNativeState,
        trusted_root: [u8; 32],
    ) -> Result<Self, Error> {
        if base.native_state.is_some() {
            return Err(Error::InvalidRoot);
        }
        let native = pinned.state;
        if native.domain == [0; 32]
            || base.admission_network_domain != Some(native.domain)
            || *native.native.gateway().native().domain() != native.domain
        {
            return Err(Error::WrongDomain);
        }
        if base.compute_root() != pinned.base_root {
            return Err(Error::InvalidRoot);
        }
        let state = Self {
            base,
            native: native.native,
            domain: native.domain,
            base_fees: native.base_fees,
            priority_fees: native.priority_fees,
            base_reserves: native.base_reserves,
            base_locks: native.base_locks,
            paired_reserves: native.paired_reserves,
            paired_locks: native.paired_locks,
            initial_pools: native.initial_pools,
            reserve_pools: native.reserve_pools,
        };
        if state.state_root() != trusted_root {
            return Err(Error::InvalidRoot);
        }
        Ok(state)
    }

    /// Expected roots must come from independently authenticated host state.
    /// Comparing caller-provided roots alone does not authenticate their origin.
    /// Initializes a NEW rehearsal with zero fees; use restore for continuation.
    pub fn from_parts(
        base: CommittedState,
        native: PoolLedger,
        base_root: [u8; 32],
        native_root: [u8; 32],
    ) -> Result<Self, Error> {
        if native.custody_records().next().is_some() {
            return Err(Error::InvalidRoot);
        }
        Self::from_parts_for_restore(base, native, base_root, native_root)
    }
    fn from_parts_for_restore(
        base: CommittedState,
        native: PoolLedger,
        base_root: [u8; 32],
        native_root: [u8; 32],
    ) -> Result<Self, Error> {
        if base.native_state.is_some() {
            return Err(Error::InvalidRoot);
        }
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
            paired_reserves: BTreeMap::new(),
            paired_locks: BTreeMap::new(),
            initial_pools: BTreeMap::new(),
            reserve_pools: BTreeMap::new(),
        })
    }
    pub fn base(&self) -> &CommittedState {
        &self.base
    }
    /// Recomputed BLCH projection of this rehearsal state, not a finality proof.
    /// Hosts must authenticate expected roots independently before admission.
    pub fn base_state_root(&self) -> [u8; 32] {
        self.base.compute_root()
    }
    pub fn native(&self) -> backend::NativeView<'_> {
        backend::NativeView::new(self)
    }
    pub fn fee_escrow(&self) -> (u128, u128) {
        (self.base_fees, self.priority_fees)
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: 7,
            initial_pools: self.initial_pools.values().cloned().collect(),
            paired_reserves: self.paired_reserves.values().cloned().collect(),
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
        if snapshot.version != 7 {
            return Err(Error::InvalidRoot);
        }
        let native = PoolLedger::restore(snapshot.native, snapshot.native_root, verifier)
            .map_err(Error::Native)?;
        let base_root = snapshot.base.compute_root();
        let mut state =
            Self::from_parts_for_restore(snapshot.base, native, base_root, snapshot.native_root)?;
        state.base_fees = snapshot.base_fees;
        state.priority_fees = snapshot.priority_fees;
        state.restore_base_reserves(snapshot.base_reserves, verifier)?;
        state.restore_paired_reserves(snapshot.paired_reserves, verifier)?;
        state.restore_initial_pools(snapshot.initial_pools, verifier)?;
        if state
            .paired_reserves
            .keys()
            .any(|id| state.base_reserves[id].revision > 0 && !state.reserve_pools.contains_key(id))
        {
            return Err(Error::InvalidRoot);
        }
        if state.state_root() != trusted_root {
            return Err(Error::InvalidRoot);
        }
        Ok(state)
    }
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-JOINT-REHEARSAL-STATE-v7");
        h.update(self.domain);
        h.update(self.base.compute_root());
        h.update(self.native.state_root());
        h.update(self.base_fees.to_le_bytes());
        h.update(self.priority_fees.to_le_bytes());
        self.hash_base_reserves(&mut h);
        self.hash_paired_reserves(&mut h);
        self.hash_initial_pools(&mut h);
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
        self.ensure_native_unlocked(&request.native.transaction.inputs)?;
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

#[cfg(test)]
mod component_tests {
    use super::*;

    #[test]
    fn native_component_is_domain_bound_and_commits_every_owned_field() {
        assert!(matches!(
            NativeState::empty([0; 32]),
            Err(Error::WrongDomain)
        ));
        let empty = NativeState::empty(tests::DOMAIN).unwrap();
        assert_eq!(empty, empty.clone());
        assert_eq!(empty.commitment(), empty.clone().commitment());
        assert_ne!(
            empty.commitment(),
            NativeState::empty([99; 32]).unwrap().commitment()
        );
        let (mut state, request) = initial_liquidity::tests::funded();
        state
            .execute_initial_liquidity(&request, 1, &tests::BoundVerifier, &tests::BoundVerifier)
            .unwrap();
        let (_, pinned) = state.into_parts();
        let native = pinned.state;
        let mutations: &[fn(&mut NativeState)] = &[
            |s| s.domain = [99; 32],
            |s| s.native = PoolLedger::new(tests::DOMAIN),
            |s| s.base_fees += 1,
            |s| s.priority_fees += 1,
            |s| s.base_reserves.clear(),
            |s| s.base_locks.clear(),
            |s| s.paired_reserves.clear(),
            |s| s.paired_locks.clear(),
            |s| s.initial_pools.clear(),
            |s| s.reserve_pools.clear(),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut changed = native.clone();
            mutate(&mut changed);
            assert_ne!(native, changed, "field {i} missing from equality");
            assert_ne!(
                native.commitment(),
                changed.commitment(),
                "field {i} missing from commitment"
            );
        }
    }

    #[test]
    fn rehearsal_rejects_an_embedded_canonical_component() {
        let (state, _) = tests::fixture();
        let root = state.state_root();
        let (mut base, pinned) = state.into_parts();
        base.native_state = Some(NativeState::empty(tests::DOMAIN).unwrap());
        let ledger = PoolLedger::new(tests::DOMAIN);
        assert!(matches!(
            State::from_parts(
                base.clone(),
                ledger.clone(),
                base.compute_root(),
                ledger.state_root()
            ),
            Err(Error::InvalidRoot)
        ));
        assert!(matches!(
            State::from_components(base, pinned, root),
            Err(Error::InvalidRoot)
        ));
    }

    #[test]
    fn split_rejoin_preserves_execution_and_snapshot() {
        let (mut state, request) = tests::fixture();
        state
            .execute(&request, 1, &tests::BoundVerifier, &tests::BoundVerifier)
            .unwrap();
        let root = state.state_root();
        let fees = state.fee_escrow();
        let (base, native) = state.into_parts();
        let restored = State::from_components(base, native, root).unwrap();
        assert_eq!(restored.state_root(), root);
        assert_eq!(restored.fee_escrow(), fees);
        assert_eq!(
            State::restore(restored.snapshot(), root, &tests::BoundVerifier)
                .unwrap()
                .state_root(),
            root
        );
    }

    #[test]
    fn split_rejoin_preserves_populated_custody_and_pool_indexes() {
        let (mut state, request) = initial_liquidity::tests::funded();
        let receipt = state
            .execute_initial_liquidity(&request, 1, &tests::BoundVerifier, &tests::BoundVerifier)
            .unwrap();
        let root = state.state_root();
        let view = state.native().snapshot();
        let locks = (
            state.base_locks.clone(),
            state.paired_locks.clone(),
            state.reserve_pools.clone(),
        );
        let position = state.blch_lp_position(&receipt.pool, &tests::key(1));
        let (base, native) = state.into_parts();
        let restored = State::from_components(base, native, root).unwrap();
        assert_eq!(restored.native().snapshot(), view);
        assert_eq!(
            (
                &restored.base_locks,
                &restored.paired_locks,
                &restored.reserve_pools
            ),
            (&locks.0, &locks.1, &locks.2)
        );
        assert_eq!(
            restored.blch_lp_position(&receipt.pool, &tests::key(1)),
            position
        );
        assert_eq!(
            State::restore(restored.snapshot(), root, &tests::BoundVerifier)
                .unwrap()
                .state_root(),
            root
        );
    }

    #[test]
    fn rejoin_rejects_wrong_root_domain_and_base_projection() {
        let (state, _) = tests::fixture();
        let root = state.state_root();
        let (base, native) = state.into_parts();
        assert!(matches!(
            State::from_components(base.clone(), native.clone(), [0; 32]),
            Err(Error::InvalidRoot)
        ));
        let mut foreign_base = base.clone();
        foreign_base.admission_network_domain = Some([99; 32]);
        assert!(matches!(
            State::from_components(foreign_base, native.clone(), root),
            Err(Error::WrongDomain)
        ));
        // A valid same-network transition must not allow old native custody
        // components to attach to the resulting, different base ledger.
        let (mut advanced, request) = tests::fixture();
        advanced
            .execute(&request, 1, &tests::BoundVerifier, &tests::BoundVerifier)
            .unwrap();
        let (advanced_base, _) = advanced.into_parts();
        assert!(matches!(
            State::from_components(advanced_base, native.clone(), root),
            Err(Error::InvalidRoot)
        ));
        let mut mismatched = native;
        mismatched.base_root = [0; 32];
        assert!(matches!(
            State::from_components(base, mismatched, root),
            Err(Error::InvalidRoot)
        ));
    }
}
