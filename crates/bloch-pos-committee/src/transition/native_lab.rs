//! Laboratory-only sponsor inspection and state-dependent admission.
//! This does not change official gates or bypass the canonical verifier.
use super::*;

pub fn is_native(tx: &PosTransaction) -> bool {
    matches!(
        tx,
        PosTransaction::NativeTransfer(_)
            | PosTransaction::NativeBootstrap(_)
            | PosTransaction::NativeImport(_)
            | PosTransaction::NativeWithdrawal(_)
            | PosTransaction::NativePool(_)
    )
}

pub fn sponsor(tx: &PosTransaction) -> Option<PosTransaction> {
    use native_dex::{bootstrap, gateway, pool_wire, wire};
    let payload = match tx {
        PosTransaction::NativeTransfer(p)
        | PosTransaction::NativeBootstrap(p)
        | PosTransaction::NativeImport(p)
        | PosTransaction::NativeWithdrawal(p)
        | PosTransaction::NativePool(p) => p.as_bytes(),
        _ => return None,
    };
    let domain: [u8; 32] = payload.get(10..42)?.try_into().ok()?;
    match tx {
        PosTransaction::NativeTransfer(_) => wire::decode(payload, &domain).ok().map(|r| r.blch),
        PosTransaction::NativeBootstrap(_) => bootstrap::decode(payload).ok().map(|r| r.blch),
        PosTransaction::NativeImport(_) | PosTransaction::NativeWithdrawal(_) => {
            gateway::decode(payload, &domain).ok().map(|r| r.blch)
        }
        PosTransaction::NativePool(_) => match pool_wire::decode(payload, &domain).ok()? {
            pool_wire::Request::CreatePair(r) => Some(r.blch),
            pool_wire::Request::Initialize(r) => Some(r.blch),
            pool_wire::Request::Add(r) => Some(r.blch),
            pool_wire::Request::Swap(r) => Some(r.blch),
            pool_wire::Request::Remove(r) => Some(r.blch),
            pool_wire::Request::ClosePair(r) => Some(r.blch),
            pool_wire::Request::Gateway(_) => None,
        },
        _ => None,
    }
}

impl<V: SignatureVerifier> Transition<V> {
    /// Dry-run on a private state. Admission reserves sponsors separately; a
    /// proposer still runs the complete block transition before publication.
    pub fn validate_native_lab_transaction(
        &self,
        base: &CommittedState,
        tx: &PosTransaction,
        slot: u64,
    ) -> Result<fee_market::TxCharge, &'static str> {
        if !self.native_lab_matches(base) {
            return Err("native laboratory domain not selected");
        }
        let mut staged = base.clone();
        if staged.native_state.is_none() {
            staged.native_state = Some(
                native_dex::NativeState::empty(base.admission_network_domain.unwrap())
                    .map_err(|_| "invalid laboratory domain")?,
            );
        }
        let fee = base.next_base_fee_at(crate::epoch_of(slot));
        let verifier = ConsensusNativeVerifier(&self.verifier);
        let failure = |_| "native laboratory execution refused";
        match tx {
            PosTransaction::NativeTransfer(p) => native_dex::consensus_transfer::apply_transfer(
                &mut staged,
                p.as_bytes(),
                slot,
                fee,
                &verifier,
                &verifier,
            )
            .map_err(failure),
            PosTransaction::NativeBootstrap(p) => native_dex::bootstrap::apply_bootstrap(
                &mut staged,
                p.as_bytes(),
                slot,
                fee,
                &verifier,
                &verifier,
            )
            .map_err(|_| "native bootstrap refused"),
            PosTransaction::NativeImport(p) => native_dex::consensus_gateway::apply_import(
                &mut staged,
                p.as_bytes(),
                slot,
                fee,
                &verifier,
                &verifier,
            )
            .map_err(|_| "native import refused"),
            PosTransaction::NativeWithdrawal(p) => native_dex::consensus_gateway::apply_withdrawal(
                &mut staged,
                p.as_bytes(),
                slot,
                fee,
                &verifier,
                &verifier,
            )
            .map_err(|_| "native withdrawal refused"),
            PosTransaction::NativePool(p) => native_dex::consensus_pool::apply_pool(
                &mut staged,
                p.as_bytes(),
                slot,
                fee,
                &verifier,
                &verifier,
            )
            .map_err(|_| "native pool operation refused"),
            _ => Err("not a native transaction"),
        }
    }
}

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
