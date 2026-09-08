//! Color-Changing Chameleon v1: sealed PQ-native escrow for unrestricted Ustav.
//!
//! This owns a native Ledger and prevents normal spending of locked outputs.
//! Native supply is unchanged by export/return. Ethereum burn inclusion is
//! checked against an explicitly trusted checkpoint, not a caller-provided
//! success flag. Authenticating those checkpoints and activating this combined
//! state in consensus remain host integration work; this is not a live bridge.

pub mod wire;

use super::{
    encoding::HashWriter, Error as NativeError, Ledger, OutPoint, Output, Receipt, Registration,
    Snapshot as NativeSnapshot, Transaction, UnspentOutput, Verifier, Witnesses, MAX_INPUTS,
    MAX_LEDGER_OUTPUTS, MAX_SIGNATURE_BYTES,
};
use crate::modules::ModuleKind;
use std::collections::{BTreeMap, BTreeSet};
pub use wire::{Burn, EvmRoute, Export, InclusionProof};

pub const VERSION: u32 = 1;
pub const MAX_ROUTES: usize = 32;
pub const MAX_EXPORTS: usize = 65_536;
pub const MAX_RETURNS: usize = 65_536;
const AUTH_GAS: u64 = 1000;
const EXPORT_GAS: u64 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Native(NativeError),
    UnsupportedPolicy,
    InvalidRoute,
    AlreadyEnabled,
    EnableBeforeIssuance,
    UnknownRoute,
    LockedInput,
    InvalidExport,
    InvalidBurn,
    InvalidCheckpoint,
    InvalidProof,
    InvalidClaim,
    AlreadyClaimed,
    InsufficientBacking,
    ResourceLimit,
    ArithmeticOverflow,
    InvalidSnapshot,
    SnapshotRootMismatch,
}
impl From<NativeError> for Error {
    fn from(error: NativeError) -> Self {
        Self::Native(error)
    }
}

/// V1 preserves unrestricted fungibility only. Every extra Ustav module is
/// rejected rather than discarded by the ERC-20 adapter.
pub fn inspect_erc20_policy(registration: &Registration) -> Result<(), Error> {
    let report = crate::kirpich::chameleon::audit_erc20(
        &registration.charter,
        registration.initial_kyc_root.is_some(),
    );
    if report.denied {
        Err(Error::UnsupportedPolicy)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    pub route: [u8; 32],
    pub expected_nonce: u64,
    pub recipient: [u8; 20],
    pub lock_output: u32,
    pub transaction: Transaction,
}
impl ExportRequest {
    /// Owners sign this export digest, NOT the bare native transaction digest.
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let output = self
            .transaction
            .outputs
            .get(self.lock_output as usize)
            .ok_or(Error::InvalidExport)?;
        let export = Export {
            route: self.route,
            nonce: self.expected_nonce,
            recipient: self.recipient,
            amount: output.amount,
            native_transaction: self.transaction.signing_hash(domain)?,
        };
        // Bind the selected lock output as well: equal outputs cannot be swapped.
        let mut h = HashWriter::new(b"CHAMELEON-EXPORT-AUTH-v1");
        h.fixed(&export.id());
        h.u32(self.lock_output);
        Ok(h.finish())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnClaim {
    pub burn: Burn,
    pub pq_recipient: Vec<u8>,
    pub escrow_inputs: Vec<OutPoint>,
    pub valid_until: u64,
}
impl ReturnClaim {
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        if self.pq_recipient.len() > super::limits::MAX_KEY_BYTES
            || self.escrow_inputs.len() > MAX_INPUTS
        {
            return Err(Error::ResourceLimit);
        }
        let mut h = HashWriter::new(b"CHAMELEON-RETURN-AUTH-v1");
        h.fixed(domain);
        h.fixed(&self.burn.id());
        h.bytes(&self.pq_recipient);
        h.u64(self.escrow_inputs.len() as u64);
        for id in &self.escrow_inputs {
            h.fixed(&id.transaction);
            h.u32(id.index);
        }
        h.u64(self.valid_until);
        Ok(h.finish())
    }
}

/// Host-authenticated adapter checkpoint. This type verifies inclusion, NOT
/// Ethereum finality or code identity. The host must obtain all these fields
/// through an authenticated consensus/light-client/explicitly trusted process.
/// Never deserialize an untrusted claim and treat its chosen root as this input.
#[derive(Clone, Debug)]
pub struct TrustedBurnCheckpoint {
    pub route: [u8; 32],
    pub adapter_code_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub root: [u8; 32],
    pub leaf_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteState {
    pub config: EvmRoute,
    pub next_export_nonce: u64,
    pub locked: u64,
    pub returned: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub native: NativeSnapshot,
    pub native_root: [u8; 32],
    pub routes: Vec<([u8; 32], RouteState)>,
    pub locks: Vec<(OutPoint, [u8; 32])>,
    pub exports: Vec<Export>,
    pub claimed: Vec<([u8; 32], u64)>,
}

/// The complete reference state. There is deliberately no mutable native-ledger
/// accessor and no conversion that discards escrow or replay bookkeeping.
#[derive(Clone, Debug)]
pub struct ChameleonLedger {
    native: Ledger,
    routes: BTreeMap<[u8; 32], RouteState>,
    locks: BTreeMap<OutPoint, [u8; 32]>,
    exports: Vec<Export>,
    claimed: BTreeSet<([u8; 32], u64)>,
}
impl ChameleonLedger {
    pub fn new(domain: [u8; 32]) -> Self {
        Self {
            native: Ledger::new(domain),
            routes: BTreeMap::new(),
            locks: BTreeMap::new(),
            exports: Vec::new(),
            claimed: BTreeSet::new(),
        }
    }
    pub fn native(&self) -> &Ledger {
        &self.native
    }
    pub fn route(&self, id: &[u8; 32]) -> Option<&RouteState> {
        self.routes.get(id)
    }
    pub fn is_locked(&self, id: &OutPoint) -> bool {
        self.locks.contains_key(id)
    }
    pub fn escrow_inputs(&self, route: &[u8; 32]) -> Vec<OutPoint> {
        self.locks
            .iter()
            .filter_map(|(id, r)| (r == route).then_some(*id))
            .collect()
    }
    pub fn exports(&self) -> &[Export] {
        &self.exports
    }
    pub fn register(
        &mut self,
        registration: Registration,
        signature: &[u8],
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<[u8; 32], Error> {
        Ok(self
            .native
            .register(registration, signature, verifier, gas)?)
    }
    /// Enable one route per asset, before any issuance. No existing holders have
    /// their charter amended, and every export still needs owner PQ signatures.
    pub fn enable(
        &mut self,
        config: EvmRoute,
        signature: &[u8],
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<[u8; 32], Error> {
        if self.routes.len() >= MAX_ROUTES {
            return Err(Error::ResourceLimit);
        }
        validate_route(&self.native, &config)?;
        if self.routes.values().any(|r| r.config.asset == config.asset) {
            return Err(Error::AlreadyEnabled);
        }
        if self.native.supply(&config.asset) != Some(0)
            || self.native.next_mint_nonce(&config.asset) != Some(0)
        {
            return Err(Error::EnableBeforeIssuance);
        }
        check_auth_budget(signature, gas, 100)?;
        let registration = self
            .native
            .registration(&config.asset)
            .ok_or(Error::InvalidRoute)?;
        let ModuleKind::Supply(supply) = &registration.charter.modules[0] else {
            return Err(Error::UnsupportedPolicy);
        };
        if !verifier.verify_pq(&config.enable_hash(), &supply.issuer_pubkey, signature) {
            return Err(NativeError::InvalidSignature.into());
        }
        let id = config.id();
        self.routes.insert(
            id,
            RouteState {
                config,
                next_export_nonce: 0,
                locked: 0,
                returned: 0,
            },
        );
        Ok(id)
    }
    pub fn apply(
        &mut self,
        tx: &Transaction,
        witnesses: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<Receipt, Error> {
        self.unlocked_inputs(&tx.inputs)?;
        Ok(self.native.apply(tx, witnesses, height, verifier, gas)?)
    }
    pub fn update_policy(
        &mut self,
        update: &super::PolicyUpdate,
        witnesses: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<u64, Error> {
        // Enabled v1 assets have Supply only, so the native kernel rejects
        // policy updates. Other registered native assets retain their behavior.
        Ok(self
            .native
            .update_policy(update, witnesses, height, verifier, gas)?)
    }
    fn unlocked_inputs(&self, inputs: &[OutPoint]) -> Result<(), Error> {
        if inputs.len() > MAX_INPUTS {
            return Err(Error::ResourceLimit);
        }
        if inputs.iter().any(|id| self.locks.contains_key(id)) {
            return Err(Error::LockedInput);
        }
        Ok(())
    }
    pub fn export(
        &mut self,
        request: &ExportRequest,
        witnesses: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<(Export, Receipt), Error> {
        if self.exports.len() >= MAX_EXPORTS {
            return Err(Error::ResourceLimit);
        }
        self.unlocked_inputs(&request.transaction.inputs)?;
        let state = self.routes.get(&request.route).ok_or(Error::UnknownRoute)?;
        let tx = &request.transaction;
        if tx.asset != state.config.asset
            || tx.delta != 0
            || tx.mint_nonce != 0
            || tx.inputs.is_empty()
            || request.expected_nonce != state.next_export_nonce
            || request.recipient == [0; 20]
            || request.recipient == state.config.adapter
        {
            return Err(Error::InvalidExport);
        }
        let output = tx
            .outputs
            .get(request.lock_output as usize)
            .ok_or(Error::InvalidExport)?;
        let amount = output.amount;
        let next_nonce = state
            .next_export_nonce
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let locked = state
            .locked
            .checked_add(amount)
            .ok_or(Error::ArithmeticOverflow)?;
        if locked > state.config.cap {
            return Err(Error::InsufficientBacking);
        }
        let native_transaction = tx.signing_hash(self.native.domain())?;
        let authorization = request.signing_hash(self.native.domain())?;
        // Only this private adapter remaps the bare native hash to the complete
        // PQ-authorized export hash. No legacy transfer signature can export.
        let scoped = ExportVerifier {
            verifier,
            native_transaction,
            authorization,
        };
        let native_gas = gas.checked_sub(EXPORT_GAS).ok_or(NativeError::OutOfGas)?;
        let state = self
            .routes
            .get_mut(&request.route)
            .ok_or(Error::UnknownRoute)?;
        let mut receipt = self
            .native
            .apply(tx, witnesses, height, &scoped, native_gas)?;
        receipt.gas_used = receipt.gas_used.saturating_add(EXPORT_GAS); // Bounded above by the supplied gas limit.
        let record = Export {
            route: request.route,
            nonce: request.expected_nonce,
            recipient: request.recipient,
            amount,
            native_transaction,
        };
        self.locks
            .insert(receipt.outputs[request.lock_output as usize], request.route);

        state.next_export_nonce = next_nonce;
        state.locked = locked;
        self.exports.push(record.clone());
        Ok((record, receipt))
    }
    pub fn export_root(&self) -> Result<([u8; 32], u64), Error> {
        let ids: Vec<_> = self.exports.iter().map(Export::id).collect();
        let (root, _) = wire::root_and_proof(&ids, None).ok_or(Error::ResourceLimit)?;
        Ok((root, ids.len() as u64))
    }
    pub fn export_proof(&self, index: usize) -> Option<InclusionProof> {
        let ids: Vec<_> = self.exports.iter().map(Export::id).collect();
        wire::root_and_proof(&ids, Some(index)).and_then(|(_, proof)| proof)
    }
    /// Release authenticated backing to a PQ owner. The checkpoint is a trusted
    /// host input, separate from the untrusted claim/proof. No timeout refund.
    pub fn claim(
        &mut self,
        claim: &ReturnClaim,
        proof: &InclusionProof,
        checkpoint: &TrustedBurnCheckpoint,
        signature: &[u8],
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<OutPoint, Error> {
        if self.claimed.len() >= MAX_RETURNS {
            return Err(Error::ResourceLimit);
        }
        let message = claim.signing_hash(self.native.domain())?;
        // Fixed-depth proof hashing, key hashing and bounded escrow lookups are
        // charged in addition to the PQ verification. These are protocol units,
        // not a claim about calibrated live-node execution costs.
        let work = 100u64
            .saturating_add(10u64.saturating_mul(wire::TREE_DEPTH as u64))
            .saturating_add(claim.pq_recipient.len().div_ceil(32) as u64)
            .saturating_add(32u64.saturating_mul(claim.escrow_inputs.len() as u64));
        check_auth_budget(signature, gas, work)?;
        let burn = &claim.burn;
        let state = self.routes.get(&burn.route).ok_or(Error::UnknownRoute)?;
        if burn.amount == 0 || burn.sender == [0; 20] || burn.pq_recipient_hash == [0; 32] {
            return Err(Error::InvalidBurn);
        }
        if checkpoint.route != burn.route
            || checkpoint.adapter_code_hash != state.config.adapter_code_hash
            || checkpoint.block_hash == [0; 32]
            || checkpoint.root == [0; 32]
        {
            return Err(Error::InvalidCheckpoint);
        }
        if proof.index != burn.nonce
            || !wire::verify_inclusion(&burn.id(), proof, &checkpoint.root, checkpoint.leaf_count)
        {
            return Err(Error::InvalidProof);
        }
        let nullifier = (burn.route, burn.nonce);
        if self.claimed.contains(&nullifier) {
            return Err(Error::AlreadyClaimed);
        }
        if height > claim.valid_until
            || claim.escrow_inputs.is_empty()
            || claim.escrow_inputs.windows(2).any(|w| w[0] >= w[1])
            || !verifier.valid_pq_key(&claim.pq_recipient)
            || wire::sha256(&claim.pq_recipient) != burn.pq_recipient_hash
        {
            return Err(Error::InvalidClaim);
        }
        if !verifier.verify_pq(&message, &claim.pq_recipient, signature) {
            return Err(NativeError::InvalidSignature.into());
        }
        let mut total = 0u64;
        for id in &claim.escrow_inputs {
            if self.locks.get(id) != Some(&burn.route) {
                return Err(Error::InvalidClaim);
            }
            let output = self.native.output(id).ok_or(Error::InvalidClaim)?;
            if output.asset != state.config.asset {
                return Err(Error::InvalidClaim);
            }
            total = total
                .checked_add(output.output.amount)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        let change = total
            .checked_sub(burn.amount)
            .ok_or(Error::InsufficientBacking)?;
        let locked = state
            .locked
            .checked_sub(burn.amount)
            .ok_or(Error::InsufficientBacking)?;
        let returned = state
            .returned
            .checked_add(u128::from(burn.amount))
            .ok_or(Error::ArithmeticOverflow)?;
        let recipient_id = OutPoint {
            transaction: message,
            index: 0,
        };
        let change_id = OutPoint {
            transaction: message,
            index: 1,
        };
        if self.native.outputs.contains_key(&recipient_id)
            || (change > 0 && self.native.outputs.contains_key(&change_id))
        {
            return Err(NativeError::OutputCollision.into());
        }
        if self
            .native
            .outputs
            .len()
            .checked_sub(claim.escrow_inputs.len())
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(usize::from(change > 0)))
            .ok_or(Error::ArithmeticOverflow)?
            > MAX_LEDGER_OUTPUTS
        {
            return Err(Error::ResourceLimit);
        }
        let asset = state.config.asset;
        // All fallible checks precede commit. The recipient owns change too,
        // but the wrapper keeps it locked and forbids ordinary spending.
        let state = self
            .routes
            .get_mut(&burn.route)
            .ok_or(Error::UnknownRoute)?;
        for id in &claim.escrow_inputs {
            self.native.outputs.remove(id);
            self.locks.remove(id);
        }
        self.native.outputs.insert(
            recipient_id,
            UnspentOutput {
                asset,
                output: Output {
                    owner: claim.pq_recipient.clone(),
                    amount: burn.amount,
                },
            },
        );
        if change > 0 {
            self.native.outputs.insert(
                change_id,
                UnspentOutput {
                    asset,
                    output: Output {
                        owner: claim.pq_recipient.clone(),
                        amount: change,
                    },
                },
            );
            self.locks.insert(change_id, burn.route);
        }

        state.locked = locked;
        state.returned = returned;
        self.claimed.insert(nullifier);
        Ok(recipient_id)
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: VERSION,
            native: self.native.snapshot(),
            native_root: self.native.state_root(),
            routes: self.routes.iter().map(|(id, r)| (*id, r.clone())).collect(),
            locks: self.locks.iter().map(|(id, route)| (*id, *route)).collect(),
            exports: self.exports.clone(),
            claimed: self.claimed.iter().copied().collect(),
        }
    }
    /// Combined root: the native root alone does not commit escrow/replay state
    /// and MUST NOT be accepted as the consensus root of a Chameleon ledger.
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = HashWriter::new(b"CHAMELEON-STATE-v1");
        h.u32(VERSION);
        h.fixed(&self.native.state_root());
        h.u64(self.routes.len() as u64);
        for (id, state) in &self.routes {
            h.fixed(id);
            h.fixed(&state.config.enable_hash());
            h.u64(state.next_export_nonce);
            h.u64(state.locked);
            h.fixed(&state.returned.to_le_bytes());
        }
        h.u64(self.locks.len() as u64);
        for (id, route) in &self.locks {
            h.fixed(&id.transaction);
            h.u32(id.index);
            h.fixed(route);
        }
        h.u64(self.exports.len() as u64);
        for export in &self.exports {
            h.fixed(&export.id());
        }
        h.u64(self.claimed.len() as u64);
        for (route, nonce) in &self.claimed {
            h.fixed(route);
            h.u64(*nonce);
        }
        h.finish()
    }
    pub fn restore(
        snapshot: Snapshot,
        expected_combined_root: [u8; 32],
        verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        if snapshot.version != VERSION
            || snapshot.routes.len() > MAX_ROUTES
            || snapshot.exports.len() > MAX_EXPORTS
            || snapshot.claimed.len() > MAX_RETURNS
            || snapshot.locks.len() > MAX_LEDGER_OUTPUTS
            || snapshot.routes.windows(2).any(|w| w[0].0 >= w[1].0)
            || snapshot.locks.windows(2).any(|w| w[0].0 >= w[1].0)
            || snapshot.claimed.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(Error::InvalidSnapshot);
        }
        let native = Ledger::restore(snapshot.native, snapshot.native_root, verifier)?;
        let mut routes = BTreeMap::new();
        let mut assets = BTreeSet::new();
        for (id, route) in snapshot.routes {
            validate_route(&native, &route.config)?;
            if route.config.id() != id || !assets.insert(route.config.asset) {
                return Err(Error::InvalidSnapshot);
            }
            routes.insert(id, route);
        }
        let mut backing = BTreeMap::<[u8; 32], u64>::new();
        for (id, route) in &snapshot.locks {
            let state = routes.get(route).ok_or(Error::InvalidSnapshot)?;
            let output = native.output(id).ok_or(Error::InvalidSnapshot)?;
            if output.asset != state.config.asset {
                return Err(Error::InvalidSnapshot);
            }
            let sum = backing.entry(*route).or_default();
            *sum = sum
                .checked_add(output.output.amount)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        let mut exported = BTreeMap::<[u8; 32], (u64, u128)>::new();
        for export in &snapshot.exports {
            if !routes.contains_key(&export.route)
                || export.amount == 0
                || export.recipient == [0; 20]
            {
                return Err(Error::InvalidSnapshot);
            }
            let (nonce, sum) = exported.entry(export.route).or_default();
            if *nonce != export.nonce {
                return Err(Error::InvalidSnapshot);
            }
            *nonce = nonce.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            *sum = sum
                .checked_add(u128::from(export.amount))
                .ok_or(Error::ArithmeticOverflow)?;
        }
        for (id, state) in &routes {
            let (nonce, total) = exported.get(id).copied().unwrap_or_default();
            if nonce != state.next_export_nonce
                || backing.get(id).copied().unwrap_or(0) != state.locked
                || total.checked_sub(state.returned) != Some(u128::from(state.locked))
            {
                return Err(Error::InvalidSnapshot);
            }
        }
        if snapshot
            .claimed
            .iter()
            .any(|(route, nonce)| !routes.contains_key(route) || *nonce >= wire::MAX_LEAVES)
        {
            return Err(Error::InvalidSnapshot);
        }
        let ledger = Self {
            native,
            routes,
            locks: snapshot.locks.into_iter().collect(),
            exports: snapshot.exports,
            claimed: snapshot.claimed.into_iter().collect(),
        };
        if ledger.state_root() != expected_combined_root {
            return Err(Error::SnapshotRootMismatch);
        }
        Ok(ledger)
    }
}

fn validate_route(native: &Ledger, config: &EvmRoute) -> Result<(), Error> {
    if config.origin_domain != *native.domain()
        || config.origin_domain == [0; 32]
        || config.asset == [0; 32]
        || config.chain_id == 0
        || config.adapter == [0; 20]
        || config.adapter_code_hash == [0; 32]
        || config.decimals > 18
        || config.cap == 0
    {
        return Err(Error::InvalidRoute);
    }
    let registration = native
        .registration(&config.asset)
        .ok_or(Error::InvalidRoute)?;
    inspect_erc20_policy(registration)?;
    let ModuleKind::Supply(supply) = &registration.charter.modules[0] else {
        return Err(Error::UnsupportedPolicy);
    };
    if supply.cap != config.cap {
        return Err(Error::InvalidRoute);
    }
    Ok(())
}
fn check_auth_budget(signature: &[u8], gas: u64, work: u64) -> Result<(), Error> {
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(Error::ResourceLimit);
    }
    if gas
        < AUTH_GAS
            .saturating_add(signature.len().div_ceil(32) as u64)
            .saturating_add(work)
    {
        return Err(NativeError::OutOfGas.into());
    }
    Ok(())
}
struct ExportVerifier<'a> {
    verifier: &'a dyn Verifier,
    native_transaction: [u8; 32],
    authorization: [u8; 32],
}
impl Verifier for ExportVerifier<'_> {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        self.verifier.valid_pq_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        message == self.native_transaction
            && self.verifier.verify_pq(&self.authorization, key, signature)
    }
}
