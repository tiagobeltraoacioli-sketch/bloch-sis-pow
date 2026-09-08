//! Versioned Ustav transition kernel. Not connected to Genesis-4 consensus.
//!
//! Only this ledger owns registered-token balances. Transactions name authenticated
//! outpoints, not caller-supplied previous outputs or replacement validators. The
//! kernel resolves and executes the immutable charter itself. Raw `EuTx` validation
//! is a different, legacy model and cannot modify this ledger.
//!
//! The host supplies the canonical block height, a trusted snapshot root on restore,
//! a deterministic cryptographic verifier, persistence and fee/block admission.
//! See `docs/ustav-kernel.md` for the operation matrix and remaining node work.

use crate::kirpich::{limits, AuditReport, RULESET_VERSION};
use crate::modules::{compile_charter_with_report, CompiledToken, ModuleKind, TokenCharter};
use crate::state::{self, Proof, SparseMerkleTree};
use crate::{AssetId, Ctx, SigVerifier, Val, VmError};
use std::collections::{BTreeMap, BTreeSet};

mod encoding;
use encoding::HashWriter;

pub const KERNEL_VERSION: u32 = 2;
pub const MAX_INPUTS: usize = 128;
pub const MAX_OUTPUTS: usize = 128;
pub const MAX_WITNESS_BYTES: usize = 1024 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 8192;
/// Reference in-memory store ceilings, also enforced by snapshot restoration.
pub const MAX_LEDGER_TOKENS: usize = 1024;
pub const MAX_LEDGER_OUTPUTS: usize = 65_536;
const SIGNATURE_GAS: u64 = 1000;

/// Required key admission as well as signature verification. There is deliberately
/// no permissive default. `bloch-ustav` supplies the concrete Bloch hybrid adapter.
pub trait Verifier: SigVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool;
    fn valid_ecdsa_key(&self, key: &[u8]) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Audit(AuditReport),
    ResourceLimit(&'static str),
    InvalidCharter(&'static str),
    InvalidKey,
    InvalidSignature,
    AlreadyRegistered,
    UnknownAsset,
    MissingInput,
    WrongAsset,
    NonCanonicalInputs,
    InvalidAmount,
    ValueNotConserved,
    SupplyOutOfRange,
    InvalidMintNonce,
    StalePolicy,
    Expired,
    InvalidWitness,
    InvalidEligibility,
    ModuleRejected(usize),
    ModuleVm(usize, VmError),
    OutOfGas,
    ArithmeticOverflow,
    OutputCollision,
    InvalidSnapshot,
    SnapshotRootMismatch,
}

/// Immutable registration. KYC roots can subsequently change only through a signed
/// policy update. `nonce` distinguishes otherwise identical registrations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub charter: TokenCharter,
    pub nonce: [u8; 32],
    pub initial_kyc_root: Option<[u8; 32]>,
}

impl Registration {
    /// Bounded, canonical registration authorization. This is a signing helper,
    /// not validation; `Ledger::register` always audits and validates keys again.
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        if let Some((_, reason)) = limits::resource_error(&self.charter) {
            return Err(Error::ResourceLimit(reason));
        }
        Ok(encoding::registration_hash(domain, self))
    }
    /// The only native identity used by this v2 ledger. It binds the domain, full
    /// charter, nonce, kernel version and audit ruleset version. The initial root
    /// is bound by the registration signature, not identity: KYC leaf keys use
    /// the asset ID, so including that root here would create a circular hash.
    pub fn asset_id(&self, domain: &[u8; 32]) -> Result<AssetId, Error> {
        if let Some((_, reason)) = limits::resource_error(&self.charter) {
            return Err(Error::ResourceLimit(reason));
        }
        Ok(encoding::asset_hash(domain, self))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutPoint {
    pub transaction: [u8; 32],
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub owner: Vec<u8>,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnspentOutput {
    pub asset: AssetId,
    pub output: Output,
}

/// One asset per transition. Positive delta mints, negative delta burns; zero
/// transfers. A mint nonce is required only for positive delta (zero otherwise).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub asset: AssetId,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<Output>,
    pub delta: i128,
    pub mint_nonce: u64,
    pub policy_revision: u64,
    pub valid_until: u64,
}

impl Transaction {
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.check_shape()?;
        Ok(encoding::transaction_hash(domain, self))
    }
    fn check_shape(&self) -> Result<(), Error> {
        if self.inputs.len() > MAX_INPUTS || self.outputs.len() > MAX_OUTPUTS {
            return Err(Error::ResourceLimit("transaction input/output count"));
        }
        if self.inputs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::NonCanonicalInputs);
        }
        if self.outputs.iter().any(|o| o.amount == 0) {
            return Err(Error::InvalidAmount);
        }
        let mut bytes = 0usize;
        for output in &self.outputs {
            if output.owner.is_empty() || output.owner.len() > limits::MAX_KEY_BYTES {
                return Err(Error::InvalidKey);
            }
            bytes = bytes.saturating_add(output.owner.len());
        }
        if bytes > MAX_WITNESS_BYTES {
            return Err(Error::ResourceLimit("output key bytes"));
        }
        if self.inputs.is_empty() && self.delta <= 0 {
            return Err(Error::InvalidAmount);
        }
        if self.delta > i128::from(u64::MAX) || self.delta < -i128::from(u64::MAX) {
            return Err(Error::SupplyOutOfRange);
        }
        if self.delta <= 0 && self.mint_nonce != 0 {
            return Err(Error::InvalidMintNonce);
        }
        Ok(())
    }
}

/// Module redeemers are indexed by the registered charter's module order. The
/// kernel rejects missing, extra and nonempty inapplicable redeemers. Owners are
/// signed in input order. Eligibility proofs must be ordered by their subject key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witnesses {
    pub owners: Vec<Vec<u8>>,
    pub modules: Vec<Vec<Val>>,
    pub eligibility: Vec<Proof>,
}

impl Witnesses {
    fn check(&self, modules: usize, owners: usize) -> Result<usize, Error> {
        if self.modules.len() != modules
            || self.owners.len() != owners
            || self.eligibility.len() > MAX_INPUTS + MAX_OUTPUTS
        {
            return Err(Error::InvalidWitness);
        }
        let mut bytes = 0usize;
        for sig in &self.owners {
            if sig.len() > MAX_SIGNATURE_BYTES {
                return Err(Error::ResourceLimit("owner signature"));
            }
            bytes = bytes.saturating_add(sig.len());
        }
        for redeemer in &self.modules {
            if redeemer.len() > 253 {
                return Err(Error::ResourceLimit("module witness arity"));
            }
            for value in redeemer {
                match value {
                    Val::Bytes(b) => {
                        if b.len() > MAX_SIGNATURE_BYTES {
                            return Err(Error::ResourceLimit("module signature"));
                        }
                        bytes = bytes.saturating_add(b.len());
                    }
                    Val::Int(_) => return Err(Error::InvalidWitness),
                }
            }
        }
        for proof in &self.eligibility {
            if proof.key.len() != 32
                || proof.value.as_ref().is_none_or(|v| v.len() != 8)
                || proof.siblings.len() != state::TREE_DEPTH
            {
                return Err(Error::InvalidEligibility);
            }
            bytes = bytes.saturating_add(40 + state::TREE_DEPTH * 32);
        }
        if bytes > MAX_WITNESS_BYTES {
            return Err(Error::ResourceLimit("total witness bytes"));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyAction {
    SetFrozen(bool),
    SetKycRoot([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyUpdate {
    pub asset: AssetId,
    pub revision: u64,
    pub valid_until: u64,
    pub action: PolicyAction,
}

impl PolicyUpdate {
    pub fn signing_hash(&self, domain: &[u8; 32]) -> [u8; 32] {
        encoding::update_hash(domain, self)
    }
}

#[derive(Clone, Debug)]
struct Token {
    registration: Registration,
    compiled: CompiledToken,
    audit: AuditReport,
    supply: u64,
    mint_nonce: u64,
    revision: u64,
    frozen: bool,
    kyc_root: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSnapshot {
    pub registration: Registration,
    pub supply: u64,
    pub mint_nonce: u64,
    pub revision: u64,
    pub frozen: bool,
    pub kyc_root: Option<[u8; 32]>,
}

/// Host transport is not specified by this type. Restoration validates all entries
/// and requires an independently authenticated root, never a root from the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub domain: [u8; 32],
    pub tokens: Vec<(AssetId, TokenSnapshot)>,
    pub outputs: Vec<(OutPoint, UnspentOutput)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub transaction: [u8; 32],
    pub outputs: Vec<OutPoint>,
    pub supply: u64,
    pub gas_used: u64,
}

/// Sealed state: no balance setter, mutable registry access, external prior_supply
/// input or caller-selected validator. Rejected operations do not mutate any field.
#[derive(Clone, Debug)]
pub struct Ledger {
    domain: [u8; 32],
    tokens: BTreeMap<AssetId, Token>,
    outputs: BTreeMap<OutPoint, UnspentOutput>,
}

impl Ledger {
    pub fn new(domain: [u8; 32]) -> Self {
        Self {
            domain,
            tokens: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }
    }
    pub fn domain(&self) -> &[u8; 32] {
        &self.domain
    }
    pub fn output(&self, id: &OutPoint) -> Option<&UnspentOutput> {
        self.outputs.get(id)
    }
    pub fn supply(&self, asset: &AssetId) -> Option<u64> {
        self.tokens.get(asset).map(|t| t.supply)
    }
    pub fn policy_revision(&self, asset: &AssetId) -> Option<u64> {
        self.tokens.get(asset).map(|t| t.revision)
    }
    pub fn next_mint_nonce(&self, asset: &AssetId) -> Option<u64> {
        self.tokens.get(asset).map(|t| t.mint_nonce)
    }
    pub fn audit(&self, asset: &AssetId) -> Option<&AuditReport> {
        self.tokens.get(asset).map(|t| &t.audit)
    }
    pub fn registration(&self, asset: &AssetId) -> Option<&Registration> {
        self.tokens.get(asset).map(|t| &t.registration)
    }

    pub fn register(
        &mut self,
        registration: Registration,
        signature: &[u8],
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<AssetId, Error> {
        if self.tokens.len() >= MAX_LEDGER_TOKENS {
            return Err(Error::ResourceLimit("ledger token count"));
        }
        // Shape before hashing, allocating compiler output or calling crypto.
        registration.signing_hash(&self.domain)?;
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err(Error::ResourceLimit("registration signature"));
        }
        let mut gas = gas_limit;
        charge(&mut gas, registration_cost(&registration))?;
        let token = validate_registration(registration, verifier)?;
        let asset = token.registration.asset_id(&self.domain)?;
        if self.tokens.contains_key(&asset) {
            return Err(Error::AlreadyRegistered);
        }
        let message = token.registration.signing_hash(&self.domain)?;
        charge(&mut gas, SIGNATURE_GAS)?;
        if !verifier.verify(&message, issuer(&token), signature) {
            return Err(Error::InvalidSignature);
        }
        self.tokens.insert(asset, token);
        Ok(asset)
    }

    pub fn apply(
        &mut self,
        tx: &Transaction,
        witnesses: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<Receipt, Error> {
        tx.check_shape()?;
        let token = self.tokens.get(&tx.asset).ok_or(Error::UnknownAsset)?;
        if height > tx.valid_until {
            return Err(Error::Expired);
        }
        if tx.policy_revision != token.revision {
            return Err(Error::StalePolicy);
        }
        let witness_bytes = witnesses.check(token.compiled.validators.len(), tx.inputs.len())?;
        let mut gas = gas_limit;
        let output_bytes: usize = tx.outputs.iter().map(|o| o.owner.len() + 16).sum();
        if witness_bytes.saturating_add(output_bytes) > MAX_WITNESS_BYTES {
            return Err(Error::ResourceLimit("transaction and witness bytes"));
        }
        charge(
            &mut gas,
            100 + words(witness_bytes + output_bytes) + tx.inputs.len() as u64,
        )?;
        let message = tx.signing_hash(&self.domain)?;
        let mut total_in = 0i128;
        let mut subjects = BTreeSet::new();
        for (id, signature) in tx.inputs.iter().zip(&witnesses.owners) {
            let input = self.outputs.get(id).ok_or(Error::MissingInput)?;
            if input.asset != tx.asset {
                return Err(Error::WrongAsset);
            }
            total_in = total_in
                .checked_add(i128::from(input.output.amount))
                .ok_or(Error::ArithmeticOverflow)?;
            charge(&mut gas, SIGNATURE_GAS)?;
            if !verifier.verify(&message, &input.output.owner, signature) {
                return Err(Error::InvalidSignature);
            }
            subjects.insert(eligibility_key(
                &self.domain,
                &tx.asset,
                &input.output.owner,
            ));
        }
        let mut total_out = 0i128;
        for output in &tx.outputs {
            charge(&mut gas, words(output.owner.len()) + 1)?;
            if !verifier.valid_pq_key(&output.owner) {
                return Err(Error::InvalidKey);
            }
            total_out = total_out
                .checked_add(i128::from(output.amount))
                .ok_or(Error::ArithmeticOverflow)?;
            subjects.insert(eligibility_key(&self.domain, &tx.asset, &output.owner));
        }
        if total_in.checked_add(tx.delta) != Some(total_out) {
            return Err(Error::ValueNotConserved);
        }
        let supply = i128::from(token.supply)
            .checked_add(tx.delta)
            .ok_or(Error::ArithmeticOverflow)?;
        if supply < 0 || supply > i128::from(cap(token)) {
            return Err(Error::SupplyOutOfRange);
        }
        let next_nonce = if tx.delta > 0 {
            if tx.mint_nonce != token.mint_nonce {
                return Err(Error::InvalidMintNonce);
            }
            token
                .mint_nonce
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?
        } else {
            token.mint_nonce
        };
        run_modules(
            token,
            witnesses,
            &message,
            height,
            tx.delta,
            !tx.inputs.is_empty(),
            false,
            verifier,
            &mut gas,
        )?;
        check_eligibility(token, &subjects, witnesses, height, &mut gas)?;
        let ids: Vec<_> = (0..tx.outputs.len())
            .map(|i| OutPoint {
                transaction: message,
                index: i as u32,
            })
            .collect();
        if ids.iter().any(|id| self.outputs.contains_key(id)) {
            return Err(Error::OutputCollision);
        }
        if self.outputs.len() - tx.inputs.len() + tx.outputs.len() > MAX_LEDGER_OUTPUTS {
            return Err(Error::ResourceLimit("ledger output count"));
        }

        // All fallible validation and checked arithmetic precedes the commit.
        for id in &tx.inputs {
            self.outputs.remove(id);
        }
        for (id, output) in ids.iter().zip(&tx.outputs) {
            self.outputs.insert(
                *id,
                UnspentOutput {
                    asset: tx.asset,
                    output: output.clone(),
                },
            );
        }
        let token = self
            .tokens
            .get_mut(&tx.asset)
            .expect("validated registry entry");
        token.supply = supply as u64;
        token.mint_nonce = next_nonce;
        Ok(Receipt {
            transaction: message,
            outputs: ids,
            supply: supply as u64,
            gas_used: gas_limit - gas,
        })
    }

    /// Policy updates require the transfer authority AND any declared Governance
    /// and Custody gates. They never replace charter bytes, keys or the supply cap.
    pub fn update_policy(
        &mut self,
        update: &PolicyUpdate,
        witnesses: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<u64, Error> {
        let token = self.tokens.get(&update.asset).ok_or(Error::UnknownAsset)?;
        if update.revision != token.revision {
            return Err(Error::StalePolicy);
        }
        if height > update.valid_until {
            return Err(Error::Expired);
        }
        if !token
            .registration
            .charter
            .modules
            .iter()
            .any(|m| matches!(m, ModuleKind::TransferPolicy(_)))
        {
            return Err(Error::InvalidCharter("no policy update authority"));
        }
        if matches!(update.action, PolicyAction::SetKycRoot(_)) && token.kyc_root.is_none() {
            return Err(Error::InvalidCharter("no KYC module"));
        }
        let bytes = witnesses.check(token.compiled.validators.len(), 0)?;
        if !witnesses.eligibility.is_empty() {
            return Err(Error::InvalidWitness);
        }
        let next = token
            .revision
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut gas = gas_limit;
        charge(&mut gas, 100 + words(bytes))?;
        run_modules(
            token,
            witnesses,
            &update.signing_hash(&self.domain),
            height,
            0,
            false,
            true,
            verifier,
            &mut gas,
        )?;
        let token = self
            .tokens
            .get_mut(&update.asset)
            .expect("validated registry entry");
        match update.action {
            PolicyAction::SetFrozen(frozen) => token.frozen = frozen,
            PolicyAction::SetKycRoot(root) => token.kyc_root = Some(root),
        }
        token.revision = next;
        Ok(gas_limit - gas)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: KERNEL_VERSION,
            domain: self.domain,
            tokens: self
                .tokens
                .iter()
                .map(|(asset, token)| {
                    (
                        *asset,
                        TokenSnapshot {
                            registration: token.registration.clone(),
                            supply: token.supply,
                            mint_nonce: token.mint_nonce,
                            revision: token.revision,
                            frozen: token.frozen,
                            kyc_root: token.kyc_root,
                        },
                    )
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|(id, output)| (*id, output.clone()))
                .collect(),
        }
    }

    pub fn restore(
        snapshot: Snapshot,
        expected_root: [u8; 32],
        verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        if snapshot.version != KERNEL_VERSION
            || snapshot.tokens.len() > MAX_LEDGER_TOKENS
            || snapshot.outputs.len() > MAX_LEDGER_OUTPUTS
        {
            return Err(Error::InvalidSnapshot);
        }
        if snapshot.tokens.windows(2).any(|w| w[0].0 >= w[1].0)
            || snapshot.outputs.windows(2).any(|w| w[0].0 >= w[1].0)
        {
            return Err(Error::InvalidSnapshot);
        }
        let mut ledger = Self::new(snapshot.domain);
        for (asset, state) in snapshot.tokens {
            let mut token = validate_registration(state.registration, verifier)?;
            if token.registration.asset_id(&ledger.domain)? != asset
                || state.supply > cap(&token)
                || token.kyc_root.is_some() != state.kyc_root.is_some()
                || (state.revision == 0 && (state.frozen || state.kyc_root != token.kyc_root))
            {
                return Err(Error::InvalidSnapshot);
            }
            token.supply = state.supply;
            token.mint_nonce = state.mint_nonce;
            token.revision = state.revision;
            token.frozen = state.frozen;
            token.kyc_root = state.kyc_root;
            ledger.tokens.insert(asset, token);
        }
        let mut totals: BTreeMap<AssetId, u128> = BTreeMap::new();
        for (id, output) in snapshot.outputs {
            if output.output.amount == 0
                || output.output.owner.len() > limits::MAX_KEY_BYTES
                || !verifier.valid_pq_key(&output.output.owner)
                || !ledger.tokens.contains_key(&output.asset)
            {
                return Err(Error::InvalidSnapshot);
            }
            let total = totals.entry(output.asset).or_default();
            *total = total
                .checked_add(u128::from(output.output.amount))
                .ok_or(Error::ArithmeticOverflow)?;
            ledger.outputs.insert(id, output);
        }
        for (asset, token) in &ledger.tokens {
            if totals.get(asset).copied().unwrap_or(0) != u128::from(token.supply) {
                return Err(Error::InvalidSnapshot);
            }
        }
        if ledger.state_root() != expected_root {
            return Err(Error::SnapshotRootMismatch);
        }
        Ok(ledger)
    }

    /// Reference commitment, recomputed from canonical state. Production hosts
    /// should implement an equivalent incremental store and meter persistence.
    pub fn state_root(&self) -> [u8; 32] {
        let mut tree = SparseMerkleTree::new();
        let mut config = HashWriter::new(b"USTAV-LEDGER-v2");
        config.fixed(&self.domain);
        config.u32(KERNEL_VERSION);
        config.u32(RULESET_VERSION);
        tree.insert(b"config", &config.finish());
        for (asset, token) in &self.tokens {
            let mut key = vec![1];
            key.extend_from_slice(asset);
            let mut value = HashWriter::new(b"USTAV-TOKEN-STATE-v2");
            // Commit initial authorization state as well as the emitted artifact.
            value.fixed(&encoding::registration_hash(
                &self.domain,
                &token.registration,
            ));
            value.fixed(&token.compiled.charter_id);
            value.u64(token.supply);
            value.u64(token.mint_nonce);
            value.u64(token.revision);
            value.byte(u8::from(token.frozen));
            value.optional_hash(token.kyc_root);
            tree.insert(&key, &value.finish());
        }
        for (id, output) in &self.outputs {
            let mut key = vec![2];
            key.extend_from_slice(&id.transaction);
            key.extend_from_slice(&id.index.to_le_bytes());
            let mut value = HashWriter::new(b"USTAV-OUTPUT-v2");
            value.fixed(&output.asset);
            value.bytes(&output.output.owner);
            value.u64(output.output.amount);
            tree.insert(&key, &value.finish());
        }
        tree.root()
    }
}

fn validate_registration(
    registration: Registration,
    verifier: &dyn Verifier,
) -> Result<Token, Error> {
    if let Some((_, reason)) = limits::resource_error(&registration.charter) {
        return Err(Error::ResourceLimit(reason));
    }
    // Kernel v2 has one module of each kind, an issuance policy, and a named token.
    if registration.charter.token_name.is_empty() {
        return Err(Error::InvalidCharter("empty token name"));
    }
    let mut tags = BTreeSet::new();
    for module in &registration.charter.modules {
        if !tags.insert(module.tag()) {
            return Err(Error::InvalidCharter("duplicate module"));
        }
        if matches!(module, ModuleKind::Vesting(c) if c.unlock_height > i128::from(u64::MAX)) {
            return Err(Error::InvalidCharter(
                "vesting height exceeds host u64 range",
            ));
        }
        limits::visit_keys(module, |ecdsa, key| {
            let valid = if ecdsa {
                verifier.valid_ecdsa_key(key)
            } else {
                verifier.valid_pq_key(key)
            };
            if valid {
                Ok(())
            } else {
                Err(Error::InvalidKey)
            }
        })?;
    }
    if !tags.contains("supply") {
        return Err(Error::InvalidCharter("missing Supply module"));
    }
    if tags.contains("kyc-gate") != registration.initial_kyc_root.is_some() {
        return Err(Error::InvalidCharter("KYC module/root mismatch"));
    }
    if tags.contains("kyc-gate") && !tags.contains("transfer-policy") {
        return Err(Error::InvalidCharter(
            "KYC requires an explicit update authority",
        ));
    }
    let (compiled, audit) =
        compile_charter_with_report(&registration.charter).map_err(Error::Audit)?;
    Ok(Token {
        kyc_root: registration.initial_kyc_root,
        registration,
        compiled,
        audit,
        supply: 0,
        mint_nonce: 0,
        revision: 0,
        frozen: false,
    })
}

fn issuer(token: &Token) -> &[u8] {
    token
        .registration
        .charter
        .modules
        .iter()
        .find_map(|m| match m {
            ModuleKind::Supply(c) => Some(c.issuer_pubkey.as_slice()),
            _ => None,
        })
        .expect("registered Supply")
}
fn cap(token: &Token) -> u64 {
    token
        .registration
        .charter
        .modules
        .iter()
        .find_map(|m| match m {
            ModuleKind::Supply(c) => Some(c.cap),
            _ => None,
        })
        .expect("registered Supply")
}
fn charge(gas: &mut u64, cost: u64) -> Result<(), Error> {
    *gas = gas.checked_sub(cost).ok_or(Error::OutOfGas)?;
    Ok(())
}
fn words(bytes: usize) -> u64 {
    (bytes as u64).saturating_add(31) / 32
}
fn registration_cost(registration: &Registration) -> u64 {
    let mut bytes = registration.charter.token_name.len();
    for module in &registration.charter.modules {
        let _: Result<(), ()> = limits::visit_keys(module, |_, key| {
            bytes = bytes.saturating_add(key.len());
            Ok(())
        });
    }
    // Reference units only: bounds the cost before compilation, not a mainnet fee.
    1000 + words(bytes).saturating_mul(16) + registration.charter.modules.len() as u64 * 100
}

// Each module gets its own typed host context and stack; never concatenate
// programs with incompatible stack arities or mint/spend field layouts.
#[allow(clippy::too_many_arguments)]
fn run_modules(
    token: &Token,
    witnesses: &Witnesses,
    message: &[u8; 32],
    height: u64,
    delta: i128,
    spends: bool,
    admin: bool,
    verifier: &dyn Verifier,
    gas: &mut u64,
) -> Result<(), Error> {
    for (index, ((module, compiled), redeemer)) in token
        .registration
        .charter
        .modules
        .iter()
        .zip(&token.compiled.validators)
        .zip(&witnesses.modules)
        .enumerate()
    {
        let applicable = match module {
            ModuleKind::Supply(_) => delta != 0 && !admin,
            ModuleKind::ComplianceKycGate(_) => false, // authenticated SMT check below
            ModuleKind::Vesting(_) => spends && !admin,
            _ => true,
        };
        if !applicable {
            if !redeemer.is_empty() {
                return Err(Error::InvalidWitness);
            }
            continue;
        }
        let arity = match module {
            ModuleKind::Governance(c) => c.signers.len(),
            ModuleKind::Custody(_) => 2,
            _ => 1,
        };
        if redeemer.len() != arity {
            return Err(Error::InvalidWitness);
        }
        let mut ctx = Ctx::default();
        let mut initial = Vec::new();
        if matches!(module, ModuleKind::Supply(_)) {
            ctx.fields = vec![
                Val::Bytes(message.to_vec()),
                Val::Int(delta),
                Val::Int(i128::from(height)),
                Val::Int(i128::from(token.supply)),
            ];
        } else {
            ctx.fields = vec![
                Val::Bytes(message.to_vec()),
                Val::Int(i128::from(height)),
                Val::Bytes(token.kyc_root.unwrap_or([0; 32]).to_vec()),
            ];
            initial.push(Val::Int(i128::from(token.frozen || admin)));
        }
        initial.extend_from_slice(redeemer);
        match crate::run(&compiled.program, initial, &ctx, verifier, gas) {
            Ok(true) => {}
            Ok(false) => return Err(Error::ModuleRejected(index)),
            Err(VmError::OutOfGas) => return Err(Error::OutOfGas),
            Err(error) => return Err(Error::ModuleVm(index, error)),
        }
    }
    Ok(())
}

/// Public KYC leaf key. Registration nonce and network are transitively bound by
/// the asset; domain is explicit too. Values are valid-until heights in u64 LE.
pub fn eligibility_key(domain: &[u8; 32], asset: &AssetId, owner: &[u8]) -> [u8; 32] {
    let mut h = HashWriter::new(b"USTAV-ELIGIBILITY-v2");
    h.fixed(domain);
    h.fixed(asset);
    h.bytes(owner);
    h.finish()
}

fn check_eligibility(
    token: &Token,
    subjects: &BTreeSet<[u8; 32]>,
    witnesses: &Witnesses,
    height: u64,
    gas: &mut u64,
) -> Result<(), Error> {
    let Some(root) = token.kyc_root else {
        return if witnesses.eligibility.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidWitness)
        };
    };
    if subjects.len() != witnesses.eligibility.len() {
        return Err(Error::InvalidEligibility);
    }
    for (subject, proof) in subjects.iter().zip(&witnesses.eligibility) {
        charge(gas, state::verify_gas())?;
        if proof.key.as_slice() != subject || !state::verify(&root, proof) {
            return Err(Error::InvalidEligibility);
        }
        let bytes: [u8; 8] = proof
            .value
            .as_deref()
            .ok_or(Error::InvalidEligibility)?
            .try_into()
            .map_err(|_| Error::InvalidEligibility)?;
        if height > u64::from_le_bytes(bytes) {
            return Err(Error::InvalidEligibility);
        }
    }
    Ok(())
}
