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
