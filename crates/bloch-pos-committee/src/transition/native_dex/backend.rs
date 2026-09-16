//! Read-only native queries for the concrete combined state. No executable inner
//! ledger, mutable borrow or component restore material crosses this boundary.
use super::*;
use bloch_euvm::{
    modules::ModuleKind,
    ustav::{
        gateway::{pools::custody, RouteState},
        OutPoint, Registration, UnspentOutput,
    },
    AssetId,
};

/// Opaque component snapshot for equality diagnostics, never a restore source.
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::backend::NativeSnapshot;
/// fn escape(snapshot: NativeSnapshot) { let inner = snapshot.native; }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSnapshot {
    native: bloch_euvm::ustav::gateway::pools::Snapshot,
    paired: Vec<custody::Record>,
    pools: Vec<initial_liquidity::Record>,
}
/// Queries retain the complete State's custody restrictions.
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::State;
/// fn escape(state: &State) { let mut ledger = state.native().clone(); }
/// ```
pub struct NativeView<'a> {
    state: &'a State,
}
/// Read-only bridge records cannot mutate the committed gateway.
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::backend::GatewayView;
/// fn change(view: GatewayView<'_>, route: &[u8; 32]) {
///     view.release_record(route, 0).unwrap().amount = 1;
/// }
/// ```
pub struct GatewayView<'a> {
    state: &'a State,
}
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::State;
/// fn escape(state: &State) -> bloch_euvm::ustav::Ledger {
///     state.native().gateway().native().clone()
/// }
/// ```
pub struct LedgerView<'a> {
    state: &'a State,
}
impl<'a> NativeView<'a> {
    pub(super) fn new(state: &'a State) -> Self {
        Self { state }
    }
    pub fn gateway(&self) -> GatewayView<'a> {
        GatewayView { state: self.state }
    }
    pub fn is_locked(&self, id: &OutPoint) -> bool {
        self.state.paired_locks.contains_key(id) || self.state.native.is_locked(id)
    }
    pub fn spendable_output(&self, id: &OutPoint) -> Option<&'a UnspentOutput> {
        if self.is_locked(id) {
            None
        } else {
            self.state.native.spendable_output(id)
        }
    }
    pub fn custody(&self, id: &[u8; 32]) -> Option<&'a custody::Record> {
        self.state.paired_reserves.get(id)
    }
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-OWNED-NATIVE-v4");
        h.update(self.state.native.state_root());
        self.state.hash_paired_reserves(&mut h);
        self.state.hash_initial_pools(&mut h);
        h.finalize().into()
    }
    pub fn snapshot(&self) -> NativeSnapshot {
        NativeSnapshot {
            native: self.state.native.snapshot(),
            paired: self.state.paired_reserves.values().cloned().collect(),
            pools: self.state.initial_pools.values().cloned().collect(),
        }
    }
    pub fn pool(&self, id: &[u8; 32]) -> Option<&'a bloch_euvm::ustav::amm::PoolState> {
        self.state.native.pool(id)
    }
    pub fn position(&self, id: &[u8; 32], owner: &[u8]) -> u64 {
        self.state.native.position(id, owner)
    }
}
impl<'a> GatewayView<'a> {
    /// Local supply reconciliation only; no source payout or reserve assertion.
    pub fn liabilities(
        &self,
        asset: &AssetId,
    ) -> Result<bloch_euvm::ustav::gateway::AssetLiabilities, bloch_euvm::ustav::gateway::Error>
    {
        self.state.native.gateway().liabilities(asset)
    }

    pub fn import_record(
        &self,
        route: &[u8; 32],
        nonce: u64,
    ) -> Option<&'a bloch_euvm::ustav::gateway::ImportRecord> {
        self.state.native.gateway().import_record(route, nonce)
    }
    pub fn release_record(
        &self,
        route: &[u8; 32],
        nonce: u64,
    ) -> Option<&'a bloch_euvm::ustav::gateway::Release> {
        self.state.native.gateway().release_record(route, nonce)
    }
    /// Local state records only. A page is not a finality proof or payout permit.
    pub fn releases_after(
        &self,
        route: &[u8; 32],
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<&'a bloch_euvm::ustav::gateway::Release>, bloch_euvm::ustav::gateway::Error>
    {
        self.state
            .native
            .gateway()
            .releases_after(route, after, limit)
    }
    pub fn native(&self) -> LedgerView<'a> {
        LedgerView { state: self.state }
    }
    pub fn route(&self, id: &[u8; 32]) -> Option<&'a RouteState> {
        self.state.native.gateway().route(id)
    }
}
impl<'a> LedgerView<'a> {
    pub fn domain(&self) -> &'a [u8; 32] {
        &self.state.domain
    }
    pub fn output(&self, id: &OutPoint) -> Option<&'a UnspentOutput> {
        self.state.native.gateway().native().output(id)
    }
    pub fn supply(&self, asset: &AssetId) -> Option<u64> {
        self.state.native.gateway().native().supply(asset)
    }
    pub fn policy_revision(&self, asset: &AssetId) -> Option<u64> {
        self.state.native.gateway().native().policy_revision(asset)
    }
    pub fn next_mint_nonce(&self, asset: &AssetId) -> Option<u64> {
        self.state.native.gateway().native().next_mint_nonce(asset)
    }
    pub fn registration(&self, asset: &AssetId) -> Option<&'a Registration> {
        self.state.native.gateway().native().registration(asset)
    }
    pub fn audit(&self, asset: &AssetId) -> Option<&'a bloch_euvm::kirpich::AuditReport> {
        self.state.native.gateway().native().audit(asset)
    }
}
impl State {
    pub(super) fn ensure_native_unlocked(&self, inputs: &[OutPoint]) -> Result<(), Error> {
        if inputs.len() > bloch_euvm::ustav::MAX_INPUTS {
            return Err(Error::ResourceLimit);
        }
        if inputs.iter().any(|p| self.paired_locks.contains_key(p)) {
            return Err(Error::LockedReserve);
        }
        Ok(())
    }
    pub(super) fn supported_paired_asset(&self, asset: &AssetId) -> Result<(), Error> {
        let r = self
            .native
            .gateway()
            .native()
            .registration(asset)
            .ok_or(Error::InvalidReserve)?;
        if *asset == bloch_euvm::BLCH
            || r.initial_kyc_root.is_some()
            || !matches!(r.charter.modules.as_slice(), [ModuleKind::Supply(_)])
        {
            return Err(Error::Native(PoolError::UnsupportedAsset));
        }
        Ok(())
    }
    pub(super) fn validate_paired_funding(
        &self,
        r: &custody::Record,
        tx: &bloch_euvm::ustav::Transaction,
    ) -> Result<(), Error> {
        self.supported_paired_asset(&r.asset)?;
        if self.paired_reserves.len() >= custody::MAX_CUSTODY
            || self.paired_reserves.contains_key(&r.id)
            || tx.delta != 0
            || tx.outputs.first().is_none_or(|o| o.amount != r.amount)
            || tx.outputs.iter().any(|o| o.owner != r.owner)
            || tx.inputs.iter().any(|p| {
                self.native
                    .gateway()
                    .native()
                    .output(p)
                    .is_none_or(|o| o.output.owner != r.owner)
            })
        {
            return Err(Error::InvalidReserve);
        }
        Ok(())
    }
    pub(super) fn hash_paired_reserves(&self, h: &mut Sha3_256) {
        hash_paired_reserves(&self.paired_reserves, h);
    }
    pub(super) fn restore_paired_reserves(
        &mut self,
        records: Vec<custody::Record>,
        verifier: &dyn Verifier,
    ) -> Result<(), Error> {
        if self.native.custody_records().next().is_some()
            || records.len() > custody::MAX_CUSTODY
            || records.windows(2).any(|w| w[0].id >= w[1].id)
        {
            return Err(Error::InvalidRoot);
        }
        for r in records {
            self.supported_paired_asset(&r.asset)?;
            let b = self.base_reserves.get(&r.id).ok_or(Error::InvalidRoot)?;
            let n = self
                .native
                .gateway()
                .native()
                .output(&r.outpoint)
                .ok_or(Error::InvalidRoot)?;
            if r.id == [0; 32]
                || r.authorization == [0; 32]
                || r.amount == 0
                || r.owner.is_empty()
                || r.owner.len() > MAX_BASE_WITNESS_BYTES
                || !verifier.valid_pq_key(&r.owner)
                || r.outpoint.index != 0
                || n.asset != r.asset
                || n.output.owner != r.owner
                || n.output.amount != r.amount
                || b.owner != r.owner
                || (b.revision == 0
                    && b.outpoint != (super::paired_custody::output_id(&r.authorization), 0))
                || self.native.is_locked(&r.outpoint)
                || self.paired_locks.insert(r.outpoint, r.id).is_some()
            {
                return Err(Error::InvalidRoot);
            }
            self.paired_reserves.insert(r.id, r);
        }
        Ok(())
    }
}

pub(super) fn hash_paired_reserves(
    records: &std::collections::BTreeMap<[u8; 32], custody::Record>,
    h: &mut Sha3_256,
) {
    h.update((records.len() as u64).to_le_bytes());
    for r in records.values() {
        h.update(r.id);
        h.update(r.authorization);
        h.update(r.asset);
        h.update((r.owner.len() as u64).to_le_bytes());
        h.update(&r.owner);
        h.update(r.amount.to_le_bytes());
        h.update(r.outpoint.transaction);
        h.update(r.outpoint.index.to_le_bytes());
    }
}
