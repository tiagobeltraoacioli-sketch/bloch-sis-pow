//! Trusted-host wallet review projections, never canonical chain restoration.
//! The host authenticates the supplied records independently. The derived root
//! binds successive reviews only; it is NOT a block state root or finality proof.
use super::*;
use crate::{
    header::BlockHeaderV4,
    state_root::{EutxoEntry, EvmCommitment},
    BlockId,
};
pub fn base(
    domain: [u8; 32],
    utxos: &[EutxoEntry],
    price: u128,
    gas: u64,
    bytes: u64,
    epoch: u64,
) -> Result<CommittedState, Error> {
    if domain == [0; 32]
        || utxos.len() > 4096
        || price == 0
        || price > fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS
        || gas > fee_market::BLOCK_GAS_LIMIT
        || bytes > fee_market::max_block_tx_bytes(epoch)
    {
        return Err(Error::InvalidRoot);
    }
    let mut seen = std::collections::BTreeSet::new();
    if utxos
        .iter()
        .any(|u| u.value == 0 || !seen.insert((u.txid, u.vout)))
    {
        return Err(Error::InvalidRoot);
    }
    let id = BlockId::of(&BlockHeaderV4 {
        version: crate::transition::BLOCK_VERSION_V4,
        parent: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0; 32],
        randao_mix: [0; 32],
        justified_root: [0; 32],
        finalized_root: [0; 32],
        attestation_root: [0; 32],
        coherence_root: [0; 32],
    });
    let mut base = CommittedState::genesis_with_network_domain(
        domain,
        id,
        [0; 32],
        &[],
        &[],
        [0; 32],
        [0; 32],
        [0; 32],
        EvmCommitment {
            account_root: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        utxos,
    );
    base.base_fee_millisat_per_gas = price;
    base.block_gas_used = gas;
    base.block_tx_bytes = bytes;
    base.epoch = epoch;
    Ok(base)
}
impl State {
    /// Test fixtures only: normalize a rehearsal view for the wallet projection.
    /// This is NOT settlement or a canonical state transition. Already-debited
    /// BLCH UTXOs remain debited; no fees are refunded or paid to any account.
    #[cfg(feature = "native-wallet-fixtures")]
    pub fn fixture_review_projection(mut self) -> Self {
        self.base_fees = 0;
        self.priority_fees = 0;
        self
    }
    /// Restore only a bounded wallet projection. Snapshot validation checks all
    /// custody locks against the supplied complete BLCH UTXO projection.
    pub fn wallet_review_projection(
        base: CommittedState,
        bytes: &[u8],
        commitment: [u8; 32],
        verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Error::InvalidRoot);
        }
        let native = NativeState::restore_snapshot(bytes, &base, commitment, verifier)
            .map_err(|_| Error::InvalidRoot)?;
        Ok(Self {
            domain: native.domain,
            base,
            native: native.native,
            base_fees: 0,
            priority_fees: 0,
            base_reserves: native.base_reserves,
            base_locks: native.base_locks,
            paired_reserves: native.paired_reserves,
            paired_locks: native.paired_locks,
            initial_pools: native.initial_pools,
            reserve_pools: native.reserve_pools,
        })
    }
    /// Export the native component for an isolated wallet review fixture. Escrow
    /// must be zero, as required by the canonical snapshot codec.
    pub fn wallet_review_snapshot(&self) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let (_, pin) = self.clone().into_parts();
        Ok((
            pin.state
                .encode_snapshot()
                .map_err(|_| Error::InvalidRoot)?,
            pin.state.commitment(),
        ))
    }
}
