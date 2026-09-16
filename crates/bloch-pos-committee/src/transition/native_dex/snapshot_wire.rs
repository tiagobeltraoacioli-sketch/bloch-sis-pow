//! Versioned, bounded transport for the canonical native component.
//! This does not attach state, import a rehearsal, authenticate a checkpoint or
//! arm activation. Callers supply an independently authenticated commitment and
//! the corresponding base projection. Derived custody indexes are rebuilt.
use super::{base_reserves, initial_liquidity, CommittedState, NativeState, State};
use bloch_euvm::{modules as m, ustav as n};
use n::gateway::{self as g, pools as p};
use std::collections::BTreeMap;

const MAGIC: [u8; 8] = *b"BLCHNS01";
/// Transport bounds, not changes to ledger or consensus limits.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_COLLECTION_ITEMS: usize = 65_536;
/// Charge declared collection storage before allocating or decoding elements.
pub const MAX_DECODED_COLLECTION_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    ResourceLimit,
    Truncated,
    InvalidEncoding,
    WrongDomain,
    NonCanonicalFees,
    InvalidState,
    CommitmentMismatch,
}
type Result<T> = std::result::Result<T, SnapshotError>;

struct Writer {
    bytes: Vec<u8>,
    allocations: usize,
}
impl Writer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            allocations: 0,
        }
    }
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_SNAPSHOT_BYTES)
        {
            return Err(SnapshotError::ResourceLimit);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn collection<T>(&mut self, count: usize) -> Result<()> {
        charge::<T>(&mut self.allocations, count)
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    allocations: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(SnapshotError::ResourceLimit)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SnapshotError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn collection<T>(&mut self, count: usize) -> Result<()> {
        // Every collection element in this schema consumes at least one byte.
        // This check precedes allocation even for a forged count of u32::MAX.
        if count > self.bytes.len() - self.offset {
            return Err(SnapshotError::Truncated);
        }
        charge::<T>(&mut self.allocations, count)
    }
}
fn charge<T>(budget: &mut usize, count: usize) -> Result<()> {
    if count > MAX_COLLECTION_ITEMS {
        return Err(SnapshotError::ResourceLimit);
    }
    let bytes = count
        .checked_mul(std::mem::size_of::<T>().max(1))
        .ok_or(SnapshotError::ResourceLimit)?;
    *budget = budget
        .checked_add(bytes)
        .ok_or(SnapshotError::ResourceLimit)?;
    if *budget > MAX_DECODED_COLLECTION_BYTES {
        return Err(SnapshotError::ResourceLimit);
    }
    Ok(())
}
trait Codec: Sized {
    fn write(&self, out: &mut Writer) -> Result<()>;
    fn read(input: &mut Reader<'_>) -> Result<Self>;
}
macro_rules! integer {
    ($($ty:ty),*) => { $(impl Codec for $ty {
        fn write(&self, out: &mut Writer) -> Result<()> { out.put(&self.to_le_bytes()) }
        fn read(input: &mut Reader<'_>) -> Result<Self> {
            Ok(Self::from_le_bytes(input.take(std::mem::size_of::<Self>())?.try_into().map_err(|_| SnapshotError::Truncated)?))
        }
    })* };
}
integer!(u8, u16, u32, u64, u128, i128);
impl<const N: usize> Codec for [u8; N] {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.put(self)
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        input
            .take(N)?
            .try_into()
            .map_err(|_| SnapshotError::Truncated)
    }
}
impl Codec for bool {
    fn write(&self, out: &mut Writer) -> Result<()> {
        u8::from(*self).write(out)
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        match u8::read(input)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnapshotError::InvalidEncoding),
        }
    }
}
impl<T: Codec> Codec for Option<T> {
    fn write(&self, out: &mut Writer) -> Result<()> {
        match self {
            None => 0u8.write(out),
            Some(v) => {
                1u8.write(out)?;
                v.write(out)
            }
        }
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        match u8::read(input)? {
            0 => Ok(None),
            1 => Ok(Some(T::read(input)?)),
            _ => Err(SnapshotError::InvalidEncoding),
        }
    }
}
impl<T: Codec> Codec for Vec<T> {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.collection::<T>(self.len())?;
        (self.len() as u32).write(out)?;
        for item in self {
            item.write(out)?;
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let count = u32::read(input)? as usize;
        input.collection::<T>(count)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| SnapshotError::ResourceLimit)?;
        for _ in 0..count {
            values.push(T::read(input)?);
        }
        Ok(values)
    }
}
impl<A: Codec, B: Codec> Codec for (A, B) {
    fn write(&self, out: &mut Writer) -> Result<()> {
        self.0.write(out)?;
        self.1.write(out)
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok((A::read(input)?, B::read(input)?))
    }
}
impl<A: Codec, B: Codec, C: Codec> Codec for (A, B, C) {
    fn write(&self, out: &mut Writer) -> Result<()> {
        self.0.write(out)?;
        self.1.write(out)?;
        self.2.write(out)
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok((A::read(input)?, B::read(input)?, C::read(input)?))
    }
}
macro_rules! pair_array {
    ($($ty:ty),*) => { $(impl Codec for [$ty; 2] {
        fn write(&self, out: &mut Writer) -> Result<()> { self[0].write(out)?; self[1].write(out) }
        fn read(input: &mut Reader<'_>) -> Result<Self> { Ok([<$ty>::read(input)?, <$ty>::read(input)?]) }
    })* };
}
pair_array!(u64, [u8; 32], n::OutPoint);
impl Codec for BTreeMap<Vec<u8>, u64> {
    fn write(&self, out: &mut Writer) -> Result<()> {
        out.collection::<(Vec<u8>, u64)>(self.len())?;
        (self.len() as u32).write(out)?;
        for (key, value) in self {
            key.write(out)?;
            value.write(out)?;
        }
        Ok(())
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let entries = Vec::<(Vec<u8>, u64)>::read(input)?;
        if entries.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(SnapshotError::InvalidEncoding);
        }
        Ok(entries.into_iter().collect())
    }
}
macro_rules! fields {
    ($ty:path { $($field:ident),* $(,)? }) => {
        impl Codec for $ty {
            fn write(&self, out: &mut Writer) -> Result<()> { $(self.$field.write(out)?;)* Ok(()) }
            fn read(input: &mut Reader<'_>) -> Result<Self> { Ok(Self { $($field: Codec::read(input)?,)* }) }
        }
    };
}
fields!(m::SupplyConfig { cap, issuer_pubkey });
fields!(m::TransferPolicyConfig { authority_pubkey });
fields!(m::VestingConfig {
    unlock_height,
    beneficiary_pubkey
});
fields!(m::GovernanceConfig { signers, threshold });
fields!(m::CustodyConfig {
    btc_pubkey,
    pq_pubkey
});
impl Codec for m::ModuleKind {
    fn write(&self, out: &mut Writer) -> Result<()> {
        match self {
            Self::Supply(c) => {
                1u8.write(out)?;
                c.write(out)
            }
            Self::TransferPolicy(c) => {
                2u8.write(out)?;
                c.write(out)
            }
            Self::ComplianceKycGate(_) => 3u8.write(out),
            Self::Vesting(c) => {
                4u8.write(out)?;
                c.write(out)
            }
            Self::Governance(c) => {
                5u8.write(out)?;
                c.write(out)
            }
            Self::Custody(c) => {
                6u8.write(out)?;
                c.write(out)
            }
        }
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok(match u8::read(input)? {
            1 => Self::Supply(Codec::read(input)?),
            2 => Self::TransferPolicy(Codec::read(input)?),
            3 => Self::ComplianceKycGate(m::KycConfig {}),
            4 => Self::Vesting(Codec::read(input)?),
            5 => Self::Governance(Codec::read(input)?),
            6 => Self::Custody(Codec::read(input)?),
            _ => return Err(SnapshotError::InvalidEncoding),
        })
    }
}
fields!(m::TokenCharter {
    token_name,
    modules
});
fields!(n::Registration {
    charter,
    nonce,
    initial_kyc_root
});
fields!(n::TokenSnapshot {
    registration,
    supply,
    mint_nonce,
    revision,
    frozen,
    kyc_root
});
fields!(n::OutPoint { transaction, index });
fields!(n::Output { owner, amount });
fields!(n::UnspentOutput { asset, output });
fields!(n::Snapshot {
    version,
    domain,
    tokens,
    outputs
});
fields!(g::Route {
    source_domain,
    native_domain,
    native_asset,
    token,
    vault,
    decimals,
    cap,
    vault_code_hash
});
fields!(g::RouteConfig {
    route,
    committee,
    threshold
});
fields!(g::RouteState {
    config,
    imported,
    burned,
    next_release_nonce
});
fields!(g::Deposit {
    route,
    nonce,
    sender,
    amount,
    pq_recipient_hash
});
fields!(g::ImportRecord {
    deposit,
    source_transaction,
    source_block,
    event_index,
    native_transaction
});
fields!(g::Release {
    route,
    nonce,
    recipient,
    amount,
    native_burn
});
fields!(g::Snapshot {
    version,
    native,
    native_root,
    routes,
    imports,
    releases
});
fields!(n::amm::Snapshot {
    version,
    domain,
    seed,
    id,
    assets,
    fee_bps,
    reserves,
    lp_supply,
    revision
});
fields!(p::PoolSnapshot {
    state,
    root,
    reserves
});
fields!(p::custody::Record {
    id,
    authorization,
    asset,
    owner,
    amount,
    outpoint
});
fields!(p::Snapshot {
    version,
    gateway,
    gateway_root,
    pools,
    positions,
    custody
});
fields!(base_reserves::Record {
    id,
    seed,
    owner,
    outpoint,
    amount,
    revision
});
impl Codec for n::amm::PoolState {
    fn write(&self, out: &mut Writer) -> Result<()> {
        self.snapshot().write(out)
    }
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let snapshot = n::amm::Snapshot::read(input)?;
        let root = snapshot.state_root();
        Self::restore(snapshot, root).map_err(|_| SnapshotError::InvalidState)
    }
}
fields!(initial_liquidity::Record {
    pool,
    initial_reserves,
    reserve,
    creation_authorization,
    owner,
    lp_balance,
    positions
});

struct Payload {
    domain: [u8; 32],
    native_root: [u8; 32],
    native: p::Snapshot,
    base_reserves: Vec<base_reserves::Record>,
    paired_reserves: Vec<p::custody::Record>,
    initial_pools: Vec<initial_liquidity::Record>,
}
fields!(Payload {
    domain,
    native_root,
    native,
    base_reserves,
    paired_reserves,
    initial_pools
});

impl NativeState {
    fn snapshot_allocation_bytes(&self) -> Option<usize> {
        let mut bytes = self.native.snapshot_allocation_bytes()?;
        let mut add = |count: usize, width: usize| -> Option<()> {
            bytes = bytes.checked_add(count.checked_mul(width)?)?;
            Some(())
        };
        add(
            self.base_reserves.len(),
            std::mem::size_of::<base_reserves::Record>(),
        )?;
        for record in self.base_reserves.values() {
            add(record.owner.len(), 1)?;
        }
        add(
            self.paired_reserves.len(),
            std::mem::size_of::<p::custody::Record>(),
        )?;
        for record in self.paired_reserves.values() {
            add(record.owner.len(), 1)?;
        }
        add(
            self.initial_pools.len(),
            std::mem::size_of::<initial_liquidity::Record>(),
        )?;
        for record in self.initial_pools.values() {
            add(record.owner.len(), 1)?;
            add(
                record.positions.len(),
                std::mem::size_of::<(Vec<u8>, u64)>(),
            )?;
            for key in record.positions.keys() {
                add(key.len(), 1)?;
            }
        }
        Some(bytes)
    }
    /// Deterministic v1 transport. The returned bytes contain no trusted root.
    /// Canonical state has zero rehearsal fee escrow; importing that escrow is
    /// refused rather than silently changing consensus accounting.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>> {
        if self.base_fees != 0 || self.priority_fees != 0 {
            return Err(SnapshotError::NonCanonicalFees);
        }
        if self
            .snapshot_allocation_bytes()
            .is_none_or(|bytes| bytes > MAX_DECODED_COLLECTION_BYTES)
        {
            return Err(SnapshotError::ResourceLimit);
        }
        let payload = Payload {
            domain: self.domain,
            native_root: self.native.state_root(),
            native: self.native.snapshot(),
            base_reserves: self.base_reserves.values().cloned().collect(),
            paired_reserves: self.paired_reserves.values().cloned().collect(),
            initial_pools: self.initial_pools.values().cloned().collect(),
        };
        let mut out = Writer::new();
        MAGIC.write(&mut out)?;
        1u16.write(&mut out)?;
        payload.write(&mut out)?;
        Ok(out.bytes)
    }

    /// Restore an opaque component against independent host context. No mutation
    /// or attachment to `base` occurs. This is neither a consensus-finality proof
    /// nor authorization to populate/activate canonical native state.
    pub fn restore_snapshot(
        bytes: &[u8],
        base: &CommittedState,
        trusted_commitment: [u8; 32],
        verifier: &dyn n::Verifier,
    ) -> Result<Self> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::ResourceLimit);
        }
        let mut input = Reader {
            bytes,
            offset: 0,
            allocations: 0,
        };
        if <[u8; 8]>::read(&mut input)? != MAGIC || u16::read(&mut input)? != 1 {
            return Err(SnapshotError::InvalidEncoding);
        }
        // Refuse a wrong network before decoding or allocating ledger tables.
        let domain_offset = input.offset;
        let domain = <[u8; 32]>::read(&mut input)?;
        if domain == [0; 32] || base.admission_network_domain != Some(domain) {
            return Err(SnapshotError::WrongDomain);
        }
        input.offset = domain_offset;
        let payload = Payload::read(&mut input)?;
        if input.offset != bytes.len() {
            return Err(SnapshotError::InvalidEncoding);
        }
        if payload.domain == [0; 32]
            || base.admission_network_domain != Some(payload.domain)
            || payload.native.gateway.native.domain != payload.domain
        {
            return Err(SnapshotError::WrongDomain);
        }
        let native = p::PoolLedger::restore(payload.native, payload.native_root, verifier)
            .map_err(|_| SnapshotError::InvalidState)?;
        let mut projection = base.clone();
        projection.native_state = None;
        let root = projection.compute_root();
        let mut restored =
            State::from_parts_for_restore(projection, native, root, payload.native_root)
                .map_err(|_| SnapshotError::InvalidState)?;
        restored
            .restore_base_reserves(payload.base_reserves, verifier)
            .map_err(|_| SnapshotError::InvalidState)?;
        restored
            .restore_paired_reserves(payload.paired_reserves, verifier)
            .map_err(|_| SnapshotError::InvalidState)?;
        restored
            .restore_initial_pools(payload.initial_pools, verifier)
            .map_err(|_| SnapshotError::InvalidState)?;
        if restored.paired_reserves.keys().any(|id| {
            restored.base_reserves[id].revision > 0 && !restored.reserve_pools.contains_key(id)
        }) {
            return Err(SnapshotError::InvalidState);
        }
        let (_, pinned) = restored.into_parts();
        if pinned.state.commitment() != trusted_commitment {
            return Err(SnapshotError::CommitmentMismatch);
        }
        // Refuse alternate byte representations even if lower-level validation
        // accepts their semantic values. Encoder ordering is part of this schema.
        if pinned.state.encode_snapshot()? != bytes {
            return Err(SnapshotError::InvalidEncoding);
        }
        Ok(pinned.state)
    }
}

impl CommittedState {
    /// Export only the already-owned canonical component. Absence is retained;
    /// this interface does not initialize native state or arm an epoch gate.
    pub fn native_component_snapshot_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.native_state
            .as_ref()
            .map(NativeState::encode_snapshot)
            .transpose()
    }

    /// Restore a persisted component only against the component already derived
    /// by canonical replay. A sidecar cannot bootstrap previously absent state
    /// or supply its own trusted root. The caller remains unchanged on failure.
    pub fn with_restored_native_component(
        &self,
        bytes: &[u8],
        verifier: &dyn crate::SignatureVerifier,
    ) -> Result<Self> {
        let existing = self
            .native_state
            .as_ref()
            .ok_or(SnapshotError::InvalidState)?;
        let checked = NativeState::restore_snapshot(
            bytes,
            self,
            existing.commitment(),
            &super::super::ConsensusNativeVerifier(verifier),
        )?;
        let mut restored = self.clone();
        restored.native_state = Some(checked);
        if restored.compute_root() != self.compute_root() {
            return Err(SnapshotError::CommitmentMismatch);
        }
        Ok(restored)
    }
}

#[cfg(test)]
#[path = "snapshot_wire_tests.rs"]
mod tests;
