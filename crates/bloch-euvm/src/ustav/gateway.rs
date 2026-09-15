//! Federated external-USDT ingress and redemption for the native reference ledger.
//!
//! Not a light client or live bridge. The configured PQ committee attests source
//! deposits/finality; collusion can issue unbacked claims. Ordinary holders retain
//! owner-only transfers. The issuer AND bridge quorum authorize supply changes.
//! The host must persist this entire sealed state, never only its inner ledger.

pub mod pools;
pub mod wire;

use super::encoding::HashWriter;
use super::{
    charge, words, Error as NativeError, Ledger, Receipt, Registration, Snapshot as NativeSnapshot,
    Transaction, Verifier, Witnesses, MAX_SIGNATURE_BYTES,
};
use crate::modules::{ModuleKind, SupplyConfig};
use crate::AssetId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u32 = 1;
pub const MAX_ROUTES: usize = 32;
pub const MAX_RECORDS: usize = 65_536;
pub const MAX_COMMITTEE: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Native(NativeError),
    Pair(super::pairs::Error),
    InvalidRoute,
    UnknownRoute,
    InvalidRequest,
    Replay,
    Unauthorized,
    SupplyChangeRequiresBridge,
    InsufficientBacking,
    ResourceLimit,
    InvalidSnapshot,
}
impl From<NativeError> for Error {
    fn from(error: NativeError) -> Self {
        Self::Native(error)
    }
}

pub fn recipient_hash(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

fn tag(value: &[u8]) -> [u8; 32] {
    let mut word = [0; 32];
    word[..value.len()].copy_from_slice(value);
    word
}
fn number(n: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&n.to_be_bytes());
    word
}
fn address(a: &[u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(a);
    word
}
fn hash_words(parts: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for word in parts {
        h.update(word);
    }
    h.finalize().into()
}

/// Immutable source network identity and canonical 20-byte account payloads.
/// TRON adapters validate Base58Check/0x41 prefixes before passing these bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub source_domain: [u8; 32],
    pub native_domain: [u8; 32],
    pub native_asset: AssetId,
    pub token: [u8; 20],
    pub vault: [u8; 20],
    pub decimals: u8,
    pub cap: u64,
    pub vault_code_hash: [u8; 32],
}
impl Route {
    /// Matches USDTSourceVault's sha256(abi.encode(...)) exactly.
    pub fn id(&self) -> [u8; 32] {
        hash_words(&[
            tag(b"BLOCH-USDT-ROUTE-v1"),
            self.source_domain,
            self.native_domain,
            self.native_asset,
            address(&self.token),
            address(&self.vault),
            number(u64::from(self.decimals)),
            number(self.cap),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteConfig {
    pub route: Route,
    pub committee: Vec<Vec<u8>>,
    pub threshold: u16,
}
impl RouteConfig {
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = HashWriter::new(b"USTAV-USDT-ENABLE-v1");
        h.fixed(&self.route.id());
        h.fixed(&self.route.vault_code_hash);
        h.u32(u32::from(self.threshold));
        h.u64(self.committee.len() as u64);
        for key in &self.committee {
            h.bytes(key);
        }
        h.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub route: [u8; 32],
    pub nonce: u64,
    pub sender: [u8; 20],
    pub amount: u64,
    pub pq_recipient_hash: [u8; 32],
}
impl Deposit {
    pub fn id(&self) -> [u8; 32] {
        hash_words(&[
            tag(b"BLOCH-USDT-DEPOSIT-v1"),
            self.route,
            number(self.nonce),
            address(&self.sender),
            number(self.amount),
            self.pq_recipient_hash,
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRequest {
    pub deposit: Deposit,
    pub source_transaction: [u8; 32],
    pub source_block: [u8; 32],
    pub event_index: u32,
    pub valid_until: u64,
    pub transaction: Transaction,
}
impl ImportRequest {
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let native = self.transaction.signing_hash(domain)?;
        let mut h = HashWriter::new(b"USTAV-USDT-IMPORT-v1");
        h.fixed(domain);
        h.fixed(&self.deposit.id());
        h.fixed(&self.source_transaction);
        h.fixed(&self.source_block);
        h.u32(self.event_index);
        h.u64(self.valid_until);
        h.fixed(&native);
        Ok(h.finish())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalRequest {
    pub route: [u8; 32],
    pub nonce: u64,
    pub recipient: [u8; 20],
    pub transaction: Transaction,
}
impl WithdrawalRequest {
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let native = self.transaction.signing_hash(domain)?;
        let mut h = HashWriter::new(b"USTAV-USDT-WITHDRAW-v1");
        h.fixed(domain);
        h.fixed(&self.route);
        h.u64(self.nonce);
        h.fixed(&self.recipient);
        h.fixed(&native);
        Ok(h.finish())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub route: [u8; 32],
    pub nonce: u64,
    pub recipient: [u8; 20],
    pub amount: u64,
    pub native_burn: [u8; 32],
}
impl Release {
    pub fn id(&self) -> [u8; 32] {
        hash_words(&[
            tag(b"BLOCH-USDT-RELEASE-v1"),
            self.route,
            number(self.nonce),
            address(&self.recipient),
            number(self.amount),
            self.native_burn,
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteState {
    pub config: RouteConfig,
    pub imported: u128,
    pub burned: u128,
    pub next_release_nonce: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRecord {
    pub deposit: Deposit,
    pub source_transaction: [u8; 32],
    pub source_block: [u8; 32],
    pub event_index: u32,
    pub native_transaction: [u8; 32],
}
type EventKey = ([u8; 32], [u8; 20], [u8; 32], u32);

/// Bound each read-only release query independently of total stored history.
pub const MAX_RELEASE_PAGE: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub native: NativeSnapshot,
    pub native_root: [u8; 32],
    pub routes: Vec<RouteState>,
    pub imports: Vec<ImportRecord>,
    pub releases: Vec<Release>,
}

/// Supply mutation of an enabled bridge asset is reachable only via import/burn.
/// No mutable ledger accessor, escrow-key exemption, or arbitrary issuer mint.
#[derive(Clone, Debug)]
pub struct GatewayLedger {
    native: Ledger,
    routes: BTreeMap<[u8; 32], RouteState>,
    imports: BTreeMap<([u8; 32], u64), ImportRecord>,
    events: BTreeSet<EventKey>,
    releases: BTreeMap<([u8; 32], u64), Release>,
}
impl GatewayLedger {
    /// A locally executed import record, not independent source-finality proof.
    pub fn import_record(&self, route: &[u8; 32], nonce: u64) -> Option<&ImportRecord> {
        self.imports.get(&(*route, nonce))
    }

    /// A locally executed burn record, not proof of finality or external payment.
    pub fn release_record(&self, route: &[u8; 32], nonce: u64) -> Option<&Release> {
        self.releases.get(&(*route, nonce))
    }

    /// Return a bounded page for exactly one route, in ascending nonce order.
    /// `after` is exclusive; None starts at nonce zero. No snapshot is cloned.
    pub fn releases_after(
        &self,
        route: &[u8; 32],
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<&Release>, Error> {
        use std::ops::Bound::{Excluded, Included};
        if limit == 0 || limit > MAX_RELEASE_PAGE {
            return Err(Error::ResourceLimit);
        }
        if !self.routes.contains_key(route) {
            return Err(Error::UnknownRoute);
        }
        // Avoid both cursor overflow and an empty excluded/included endpoint.
        if after == Some(u64::MAX) {
            return Ok(Vec::new());
        }
        let start = match after {
            Some(nonce) => Excluded((*route, nonce)),
            None => Included((*route, 0)),
        };
        Ok(self
            .releases
            .range((start, Included((*route, u64::MAX))))
            .take(limit)
            .map(|(_, release)| release)
            .collect())
    }

    pub fn new(domain: [u8; 32]) -> Self {
        Self {
            native: Ledger::new(domain),
            routes: BTreeMap::new(),
            imports: BTreeMap::new(),
            events: BTreeSet::new(),
            releases: BTreeMap::new(),
        }
    }
    pub fn native(&self) -> &Ledger {
        &self.native
    }
    pub fn route(&self, id: &[u8; 32]) -> Option<&RouteState> {
        self.routes.get(id)
    }
    pub fn register(
        &mut self,
        r: Registration,
        sig: &[u8],
        v: &dyn Verifier,
        gas: u64,
    ) -> Result<AssetId, Error> {
        Ok(self.native.register(r, sig, v, gas)?)
    }
    pub fn enable(
        &mut self,
        config: RouteConfig,
        issuer_signature: &[u8],
        approvals: &[Vec<u8>],
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<[u8; 32], Error> {
        if self.routes.len() >= MAX_ROUTES {
            return Err(Error::ResourceLimit);
        }
        validate_config(&self.native, &config, verifier)?;
        let route = &config.route;
        if self.native.supply(&route.native_asset) != Some(0)
            || self.native.next_mint_nonce(&route.native_asset) != Some(0)
            || self.routes.values().any(|s| {
                s.config.route.source_domain == route.source_domain
                    && s.config.route.vault == route.vault
            })
        {
            return Err(Error::InvalidRoute);
        }
        let mut gas = gas_limit;
        let message = config.signing_hash();
        verify_quorum(&config, &message, approvals, verifier, &mut gas)?;
        let supply = supply_profile(&self.native, &route.native_asset)?;
        if issuer_signature.len() > MAX_SIGNATURE_BYTES {
            return Err(Error::ResourceLimit);
        }
        charge(&mut gas, 1000)?;
        if !verifier.verify_pq(&message, &supply.issuer_pubkey, issuer_signature) {
            return Err(Error::Unauthorized);
        }
        let id = route.id();
        self.routes.insert(
            id,
            RouteState {
                config,
                imported: 0,
                burned: 0,
                next_release_nonce: 0,
            },
        );
        Ok(id)
    }
    pub fn apply(
        &mut self,
        tx: &Transaction,
        w: &Witnesses,
        height: u64,
        v: &dyn Verifier,
        gas: u64,
    ) -> Result<Receipt, Error> {
        if tx.delta != 0
            && self
                .routes
                .values()
                .any(|s| s.config.route.native_asset == tx.asset)
        {
            return Err(Error::SupplyChangeRequiresBridge);
        }
        Ok(self.native.apply(tx, w, height, v, gas)?)
    }
    pub fn settle_pair(
        &mut self,
        swap: &super::pairs::PairSwap,
        w: &[Witnesses; 2],
        height: u64,
        v: &dyn Verifier,
        gas: u64,
    ) -> Result<super::pairs::PairReceipt, Error> {
        self.native
            .settle_pair(swap, w, height, v, gas)
            .map_err(Error::Pair)
    }
    pub fn import(
        &mut self,
        request: &ImportRequest,
        witnesses: &Witnesses,
        approvals: &[Vec<u8>],
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<Receipt, Error> {
        if self.imports.len() >= MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        let state = self
            .routes
            .get(&request.deposit.route)
            .ok_or(Error::UnknownRoute)?;
        let route = &state.config.route;
        let deposit = &request.deposit;
        let tx = &request.transaction;
        let message = request.signing_hash(self.native.domain())?;
        if deposit.amount == 0
            || deposit.sender == [0; 20]
            || deposit.pq_recipient_hash == [0; 32]
            || request.source_transaction == [0; 32]
            || request.source_block == [0; 32]
            || height > request.valid_until
            || tx.valid_until > request.valid_until
            || tx.asset != route.native_asset
            || !tx.inputs.is_empty()
            || tx.outputs.len() != 1
            || tx.delta != i128::from(deposit.amount)
            || tx.outputs[0].amount != deposit.amount
            || recipient_hash(&tx.outputs[0].owner) != deposit.pq_recipient_hash
        {
            return Err(Error::InvalidRequest);
        }
        let event = (
            route.source_domain,
            route.vault,
            request.source_transaction,
            request.event_index,
        );
        let key = (deposit.route, deposit.nonce);
        if self.imports.contains_key(&key) || self.events.contains(&event) {
            return Err(Error::Replay);
        }
        let imported = state
            .imported
            .checked_add(u128::from(deposit.amount))
            .ok_or(NativeError::ArithmeticOverflow)?;
        if imported
            .checked_sub(state.burned)
            .ok_or(Error::InsufficientBacking)?
            > u128::from(route.cap)
        {
            return Err(Error::InsufficientBacking);
        }
        let native_message = tx.signing_hash(self.native.domain())?;
        let mut gas = gas_limit;
        verify_quorum(&state.config, &message, approvals, verifier, &mut gas)?;
        let scoped = ScopedVerifier {
            verifier,
            native_message,
            message,
        };
        let mut receipt = self.native.apply(tx, witnesses, height, &scoped, gas)?;
        receipt.gas_used += gas_limit - gas;
        // Nothing below can reject: commit supply and replay accounting together.
        self.routes
            .get_mut(&deposit.route)
            .expect("validated route")
            .imported = imported;
        self.events.insert(event);
        self.imports.insert(
            key,
            ImportRecord {
                deposit: deposit.clone(),
                source_transaction: request.source_transaction,
                source_block: request.source_block,
                event_index: request.event_index,
                native_transaction: receipt.transaction,
            },
        );
        Ok(receipt)
    }
    pub fn withdraw(
        &mut self,
        request: &WithdrawalRequest,
        witnesses: &Witnesses,
        approvals: &[Vec<u8>],
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<(Release, Receipt), Error> {
        if self.releases.len() >= MAX_RECORDS {
            return Err(Error::ResourceLimit);
        }
        let state = self.routes.get(&request.route).ok_or(Error::UnknownRoute)?;
        let tx = &request.transaction;
        let message = request.signing_hash(self.native.domain())?;
        if tx.asset != state.config.route.native_asset
            || tx.delta >= 0
            || request.nonce != state.next_release_nonce
            || request.recipient == [0; 20]
            || request.recipient == state.config.route.vault
            || request.recipient == state.config.route.token
        {
            return Err(Error::InvalidRequest);
        }
        let amount = u64::try_from(tx.delta.unsigned_abs()).map_err(|_| Error::InvalidRequest)?;
        let burned = state
            .burned
            .checked_add(u128::from(amount))
            .ok_or(NativeError::ArithmeticOverflow)?;
        if burned > state.imported {
            return Err(Error::InsufficientBacking);
        }
        let next_nonce = state
            .next_release_nonce
            .checked_add(1)
            .ok_or(NativeError::ArithmeticOverflow)?;
        let native_message = tx.signing_hash(self.native.domain())?;
        let release = Release {
            route: request.route,
            nonce: request.nonce,
            recipient: request.recipient,
            amount,
            native_burn: native_message,
        };
        let mut gas = gas_limit;
        verify_quorum(&state.config, &message, approvals, verifier, &mut gas)?;
        let scoped = ScopedVerifier {
            verifier,
            native_message,
            message,
        };
        let mut receipt = self.native.apply(tx, witnesses, height, &scoped, gas)?;
        receipt.gas_used += gas_limit - gas;
        let state = self
            .routes
            .get_mut(&request.route)
            .expect("validated route");
        state.burned = burned;
        state.next_release_nonce = next_nonce;
        self.releases
            .insert((release.route, release.nonce), release.clone());
        Ok((release, receipt))
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: VERSION,
            native: self.native.snapshot(),
            native_root: self.native.state_root(),
            routes: self.routes.values().cloned().collect(),
            imports: self.imports.values().cloned().collect(),
            releases: self.releases.values().cloned().collect(),
        }
    }
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = HashWriter::new(b"USTAV-USDT-STATE-v1");
        h.u32(VERSION);
        h.fixed(&self.native.state_root());
        h.u64(self.routes.len() as u64);
        for state in self.routes.values() {
            h.fixed(&state.config.signing_hash());
            h.fixed(&state.imported.to_le_bytes());
            h.fixed(&state.burned.to_le_bytes());
            h.u64(state.next_release_nonce);
        }
        h.u64(self.imports.len() as u64);
        for record in self.imports.values() {
            h.fixed(&record.deposit.id());
            h.fixed(&record.source_transaction);
            h.fixed(&record.source_block);
            h.u32(record.event_index);
            h.fixed(&record.native_transaction);
        }
        h.u64(self.releases.len() as u64);
        for release in self.releases.values() {
            h.fixed(&release.id());
        }
        h.finish()
    }
    pub fn restore(
        snapshot: Snapshot,
        expected_root: [u8; 32],
        verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        if snapshot.version != VERSION
            || snapshot.routes.len() > MAX_ROUTES
            || snapshot.imports.len() > MAX_RECORDS
            || snapshot.releases.len() > MAX_RECORDS
            || snapshot
                .routes
                .windows(2)
                .any(|w| w[0].config.route.id() >= w[1].config.route.id())
            || snapshot.imports.windows(2).any(|w| {
                (w[0].deposit.route, w[0].deposit.nonce) >= (w[1].deposit.route, w[1].deposit.nonce)
            })
            || snapshot
                .releases
                .windows(2)
                .any(|w| (w[0].route, w[0].nonce) >= (w[1].route, w[1].nonce))
        {
            return Err(Error::InvalidSnapshot);
        }
        let native = Ledger::restore(snapshot.native, snapshot.native_root, verifier)?;
        let mut restored = Self {
            native,
            routes: BTreeMap::new(),
            imports: BTreeMap::new(),
            events: BTreeSet::new(),
            releases: BTreeMap::new(),
        };
        let mut endpoints = BTreeSet::new();
        let mut counts: BTreeMap<[u8; 32], (u128, u128, u64, u64)> = BTreeMap::new();
        for state in snapshot.routes {
            validate_config(&restored.native, &state.config, verifier)?;
            let route = &state.config.route;
            if !endpoints.insert((route.source_domain, route.vault)) {
                return Err(Error::InvalidSnapshot);
            }
            counts.insert(route.id(), (0, 0, 0, 0));
            restored.routes.insert(route.id(), state);
        }
        let mut native_ids = BTreeSet::new();
        for record in snapshot.imports {
            let route = &restored
                .routes
                .get(&record.deposit.route)
                .ok_or(Error::InvalidSnapshot)?
                .config
                .route;
            if record.deposit.amount == 0
                || record.deposit.sender == [0; 20]
                || record.deposit.pq_recipient_hash == [0; 32]
                || record.source_transaction == [0; 32]
                || record.source_block == [0; 32]
                || record.native_transaction == [0; 32]
                || !native_ids.insert(record.native_transaction)
                || !restored.events.insert((
                    route.source_domain,
                    route.vault,
                    record.source_transaction,
                    record.event_index,
                ))
            {
                return Err(Error::InvalidSnapshot);
            }
            let count = counts
                .get_mut(&record.deposit.route)
                .ok_or(Error::InvalidSnapshot)?;
            count.0 = count
                .0
                .checked_add(u128::from(record.deposit.amount))
                .ok_or(Error::InvalidSnapshot)?;
            count.3 = count.3.checked_add(1).ok_or(Error::InvalidSnapshot)?;
            restored
                .imports
                .insert((record.deposit.route, record.deposit.nonce), record);
        }
        for release in snapshot.releases {
            let route = &restored
                .routes
                .get(&release.route)
                .ok_or(Error::InvalidSnapshot)?
                .config
                .route;
            let count = counts
                .get_mut(&release.route)
                .ok_or(Error::InvalidSnapshot)?;
            if release.amount == 0
                || release.recipient == [0; 20]
                || release.recipient == route.vault
                || release.recipient == route.token
                || release.native_burn == [0; 32]
                || !native_ids.insert(release.native_burn)
                || release.nonce != count.2
            {
                return Err(Error::InvalidSnapshot);
            }
            count.1 = count
                .1
                .checked_add(u128::from(release.amount))
                .ok_or(Error::InvalidSnapshot)?;
            count.2 = count.2.checked_add(1).ok_or(Error::InvalidSnapshot)?;
            restored
                .releases
                .insert((release.route, release.nonce), release);
        }
        let mut by_asset: BTreeMap<AssetId, (u128, u64)> = BTreeMap::new();
        for (id, state) in &restored.routes {
            let count = counts.get(id).ok_or(Error::InvalidSnapshot)?;
            let outstanding = count.0.checked_sub(count.1).ok_or(Error::InvalidSnapshot)?;
            if state.imported != count.0
                || state.burned != count.1
                || state.next_release_nonce != count.2
                || outstanding > u128::from(state.config.route.cap)
            {
                return Err(Error::InvalidSnapshot);
            }
            let tally = by_asset.entry(state.config.route.native_asset).or_default();
            tally.0 = tally
                .0
                .checked_add(outstanding)
                .ok_or(Error::InvalidSnapshot)?;
            tally.1 = tally.1.checked_add(count.3).ok_or(Error::InvalidSnapshot)?;
        }
        for (asset, (supply, mints)) in by_asset {
            if restored.native.supply(&asset).map(u128::from) != Some(supply)
                || restored.native.next_mint_nonce(&asset) != Some(mints)
            {
                return Err(Error::InvalidSnapshot);
            }
        }
        if restored.state_root() != expected_root {
            return Err(Error::InvalidSnapshot);
        }
        Ok(restored)
    }
}

fn supply_profile<'a>(native: &'a Ledger, asset: &AssetId) -> Result<&'a SupplyConfig, Error> {
    let registration = native.registration(asset).ok_or(Error::InvalidRoute)?;
    match registration.charter.modules.as_slice() {
        [ModuleKind::Supply(supply)] => Ok(supply),
        _ => Err(Error::InvalidRoute),
    }
}
fn validate_config(
    native: &Ledger,
    config: &RouteConfig,
    verifier: &dyn Verifier,
) -> Result<(), Error> {
    let r = &config.route;
    if r.native_domain != *native.domain()
        || r.source_domain == [0; 32]
        || r.source_domain == r.native_domain
        || r.native_asset == crate::BLCH
        || r.token == [0; 20]
        || r.vault == [0; 20]
        || r.token == r.vault
        || r.vault_code_hash == [0; 32]
        || r.decimals != 6
        || r.cap == 0
        || config.committee.len() > MAX_COMMITTEE
        || config.threshold < 2
        || usize::from(config.threshold) > config.committee.len()
        || config.committee.windows(2).any(|w| w[0] >= w[1])
        || config.committee.iter().any(|key| {
            key.len() > crate::kirpich::limits::MAX_KEY_BYTES || !verifier.valid_pq_key(key)
        })
        || supply_profile(native, &r.native_asset)?.cap < r.cap
    {
        return Err(Error::InvalidRoute);
    }
    Ok(())
}
fn verify_quorum(
    config: &RouteConfig,
    message: &[u8; 32],
    approvals: &[Vec<u8>],
    verifier: &dyn Verifier,
    gas: &mut u64,
) -> Result<(), Error> {
    if approvals.len() != config.committee.len()
        || approvals.iter().any(|sig| sig.len() > MAX_SIGNATURE_BYTES)
    {
        return Err(Error::Unauthorized);
    }
    charge(gas, 200)?;
    let mut accepted = 0;
    for (key, sig) in config.committee.iter().zip(approvals) {
        if sig.is_empty() {
            continue;
        }
        charge(gas, 1000u64.saturating_add(words(key.len() + sig.len())))?;
        if !verifier.verify_pq(message, key, sig) {
            return Err(Error::Unauthorized);
        }
        accepted += 1;
    }
    if accepted < config.threshold {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
struct ScopedVerifier<'a> {
    verifier: &'a dyn Verifier,
    native_message: [u8; 32],
    message: [u8; 32],
}

impl Verifier for ScopedVerifier<'_> {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        self.verifier.valid_pq_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        message == self.native_message && self.verifier.verify_pq(&self.message, key, signature)
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;

    #[test]
    fn release_pages_are_bounded_route_scoped_and_use_exclusive_cursors() {
        let mut ledger = GatewayLedger::new([1; 32]);
        // Query-only table fixtures; authorization is exercised by PQ integration tests.
        let mut routes = Vec::new();
        for n in [2, 3] {
            let config = RouteConfig {
                route: Route {
                    source_domain: [n; 32],
                    native_domain: [1; 32],
                    native_asset: [4; 32],
                    token: [5; 20],
                    vault: [6; 20],
                    decimals: 6,
                    cap: 1000,
                    vault_code_hash: [7; 32],
                },
                committee: vec![vec![8; 32], vec![9; 32]],
                threshold: 2,
            };
            let id = config.route.id();
            ledger.routes.insert(
                id,
                RouteState {
                    config,
                    imported: 0,
                    burned: 0,
                    next_release_nonce: 0,
                },
            );
            routes.push(id);
        }
        let route = routes[0];
        for nonce in (0..130).rev().chain([u64::MAX]) {
            for id in &routes {
                ledger.releases.insert(
                    (*id, nonce),
                    Release {
                        route: *id,
                        nonce,
                        recipient: [10; 20],
                        amount: 1,
                        native_burn: [11; 32],
                    },
                );
            }
        }
        let before = ledger.snapshot();
        let first = ledger
            .releases_after(&route, None, MAX_RELEASE_PAGE)
            .unwrap();
        assert_eq!(first.len(), MAX_RELEASE_PAGE);
        assert!(first.iter().all(|r| r.route == route));
        assert_eq!(
            first.iter().map(|r| r.nonce).collect::<Vec<_>>(),
            (0..128).collect::<Vec<_>>()
        );
        let second = ledger
            .releases_after(&route, Some(127), MAX_RELEASE_PAGE)
            .unwrap();
        assert_eq!(
            second.iter().map(|r| r.nonce).collect::<Vec<_>>(),
            vec![128, 129, u64::MAX]
        );
        assert_eq!(
            ledger
                .releases_after(&route, Some(u64::MAX - 1), 1)
                .unwrap()[0]
                .nonce,
            u64::MAX
        );
        assert!(ledger
            .releases_after(&route, Some(u64::MAX), 1)
            .unwrap()
            .is_empty());
        assert_eq!(ledger.release_record(&route, 0), Some(first[0]));
        assert!(ledger.release_record(&route, 130).is_none());
        for limit in [0, MAX_RELEASE_PAGE + 1, usize::MAX] {
            assert_eq!(
                ledger.releases_after(&route, None, limit),
                Err(Error::ResourceLimit)
            );
        }
        assert_eq!(
            ledger.releases_after(&[0; 32], None, 1),
            Err(Error::UnknownRoute)
        );
        assert_eq!(
            ledger.releases_after(&[0; 32], Some(u64::MAX), 1),
            Err(Error::UnknownRoute)
        );
        assert_eq!(ledger.snapshot(), before);
    }
}
