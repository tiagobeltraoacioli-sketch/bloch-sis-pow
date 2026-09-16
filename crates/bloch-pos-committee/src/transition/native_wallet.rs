//! Bounded canonical wallet projections shared by official and laboratory nodes.
//! Data extraction never grants transaction admission or proves finality.
use super::*;

/// Bounded route accounting, not source-vault settlement evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteReport {
    pub supply: u64,
    pub imported: u128,
    pub burned: u128,
    pub next_release_nonce: u64,
    pub commitment: [u8; 32],
    pub first_release_burn: Option<[u8; 32]>,
}
impl CommittedState {
    pub fn native_lab_route_report(
        &self,
        asset: &[u8; 32],
        route: &[u8; 32],
    ) -> Option<RouteReport> {
        self.native_state.as_ref()?.lab_route_report(asset, route)
    }
}

/// Complete trusted-host review context. This is not a finality proof.
pub struct WalletView {
    pub snapshot: Vec<u8>,
    pub commitment: [u8; 32],
    pub utxos: Vec<crate::state_root::EutxoEntry>,
    pub base_fee: u128,
    pub block_gas_used: u64,
    pub block_tx_bytes: u64,
    pub epoch: u64,
}
impl CommittedState {
    pub fn native_lab_wallet_view(&self) -> Result<WalletView, &'static str> {
        let utxos: Vec<_> = self.utxos().take(4097).cloned().collect();
        self.native_wallet_view_with_utxos(utxos)
    }
    /// Indexed owner coins plus every canonical base custody output needed to
    /// validate the complete native snapshot. Never scan unrelated holder sets.
    pub fn native_wallet_view_for_owner(&self, owner: &[u8]) -> Result<WalletView, &'static str> {
        use sha3::{Digest, Sha3_256};
        if owner.is_empty() || owner.len() > 8192 {
            return Err("invalid owner key bound");
        }
        let hash: [u8; 32] = Sha3_256::digest(owner).into();
        let mut entries = std::collections::BTreeMap::new();
        for entry in self.utxos_for_script(&hash).take(4097) {
            entries.insert((entry.txid, entry.vout), entry.clone());
        }
        let native = self
            .native_state
            .as_ref()
            .ok_or("native state not initialized")?;
        for point in native.base_custody_points() {
            if entries.len() > 4096 {
                return Err("wallet UTXO projection exceeds limit");
            }
            let entry = self
                .utxo(&point.0, point.1)
                .ok_or("native custody output is absent")?;
            entries.insert(*point, entry.clone());
        }
        self.native_wallet_view_with_utxos(entries.into_values().collect())
    }
    fn native_wallet_view_with_utxos(
        &self,
        utxos: Vec<crate::state_root::EutxoEntry>,
    ) -> Result<WalletView, &'static str> {
        if utxos.len() > 4096 {
            return Err("wallet UTXO projection exceeds limit");
        }
        let native = self
            .native_state
            .as_ref()
            .ok_or("native state not initialized")?;
        let snapshot = native
            .encode_snapshot_bounded(4 * 1024 * 1024)
            .map_err(|_| "wallet native snapshot exceeds limit or is noncanonical")?;
        Ok(WalletView {
            snapshot,
            commitment: native.commitment(),
            utxos,
            base_fee: self.base_fee_millisat_per_gas,
            block_gas_used: self.block_gas_used,
            block_tx_bytes: self.block_tx_bytes,
            epoch: self.epoch,
        })
    }
}

/// Current sealed pool reserves, not an owner-spendable balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolReport {
    pub pool_id: [u8; 32],
    pub reserve_id: [u8; 32],
    pub assets: [[u8; 32]; 2],
    pub reserves: [u64; 2],
    pub pool_root: [u8; 32],
    pub revision: u64,
    pub lp_total: u64,
    pub fee_bps: u16,
}
impl CommittedState {
    pub fn native_lab_pool_report(&self, pool: &[u8; 32]) -> Option<PoolReport> {
        self.native_state.as_ref()?.lab_pool_report(pool)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletOperation {
    View,
    Pool,
    Withdrawal,
}
impl CommittedState {
    /// Official-network authorization: canonical domain/component and committed
    /// epoch gates only. No runtime flag, requested slot, or wallet input arms it.
    pub fn authorize_native_wallet(
        &self,
        expected_domain: [u8; 32],
        operation: WalletOperation,
    ) -> Result<(), &'static str> {
        if expected_domain == [0; 32] || self.admission_network_domain != Some(expected_domain) {
            return Err("native wallet network domain mismatch");
        }
        if !crate::params::native_state_active(self.epoch) {
            return Err("canonical native state activation is disabled");
        }
        let native = self
            .native_state
            .as_ref()
            .ok_or("canonical native state is absent")?;
        if native.domain() != expected_domain {
            return Err("canonical native component domain mismatch");
        }
        let active = match operation {
            WalletOperation::View => true,
            WalletOperation::Pool => crate::params::native_pool_active(self.epoch),
            WalletOperation::Withdrawal => crate::params::native_withdrawal_active(self.epoch),
        };
        if !active {
            return Err("canonical native operation activation is disabled");
        }
        Ok(())
    }
    pub fn native_wallet_view(&self) -> Result<WalletView, &'static str> {
        self.native_lab_wallet_view()
    }
    pub fn native_pool_report(&self, pool: &[u8; 32]) -> Option<PoolReport> {
        self.native_lab_pool_report(pool)
    }
}
