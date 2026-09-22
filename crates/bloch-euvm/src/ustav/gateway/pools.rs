//! Sealed Supply-only native-token pool custody and authenticated LP positions.
//! Reference integration only: base BLCH requires the real consensus UTXO adapter.
//! Persist this complete state; never dispatch against an extracted inner ledger.
pub mod wire;
use super::{GatewayLedger, ImportRequest, Release, RouteConfig, WithdrawalRequest};
use crate::modules::ModuleKind;
use crate::ustav::amm::{self, PoolState};
use crate::ustav::encoding::HashWriter;
use crate::ustav::{
    charge, words, Error as NativeError, OutPoint, Output, Receipt, Registration, Transaction,
    UnspentOutput, Verifier, Witnesses, MAX_INPUTS, MAX_LEDGER_OUTPUTS, MAX_SIGNATURE_BYTES,
};
use crate::{AssetId, BLCH};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u32 = 1;
pub const MAX_POOLS: usize = 128;
pub const MAX_POSITIONS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Native(NativeError),
    Gateway(super::Error),
    Amm(amm::Error),
    Wire(super::wire::Error),
    InvalidPool,
    UnsupportedAsset,
    Unauthorized,
    LockedInput,
    InvalidFunding,
    InsufficientPosition,
    ResourceLimit,
    InvalidSnapshot,
}
impl From<NativeError> for Error {
    fn from(e: NativeError) -> Self {
        Self::Native(e)
    }
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Gateway(e)
    }
}
impl From<amm::Error> for Error {
    fn from(e: amm::Error) -> Self {
        Self::Amm(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolAction {
    pub request: amm::Request,
    /// Owns every funding input and receives LP, change and swap/withdrawal payouts.
    pub owner: Vec<u8>,
    /// Canonically ordered real outpoints per sorted pool asset; no client balances.
    pub funding: [Vec<OutPoint>; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolReceipt {
    pub authorization: [u8; 32],
    pub reserves: [OutPoint; 2],
    pub payouts: [Option<OutPoint>; 2],
    pub lp_balance: u64,
    pub gas_used: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolSnapshot {
    pub state: amm::Snapshot,
    pub root: [u8; 32],
    pub reserves: Option<[OutPoint; 2]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub gateway: super::Snapshot,
    pub gateway_root: [u8; 32],
    pub pools: Vec<PoolSnapshot>,
    pub positions: Vec<([u8; 32], Vec<u8>, u64)>,
}
#[derive(Clone, Debug)]
struct Pool {
    state: PoolState,
    reserves: Option<[OutPoint; 2]>,
}
#[derive(Clone, Debug)]
pub struct PoolLedger {
    gateway: GatewayLedger,
    pools: BTreeMap<[u8; 32], Pool>,
    positions: BTreeMap<([u8; 32], Vec<u8>), u64>,
    locks: BTreeMap<OutPoint, [u8; 32]>,
}

/// A validated zero-supply transfer, exclusively borrowing the sealed ledger.
/// Dropping it changes nothing; consuming it commits once without fallible work.
pub struct TransferPlan<'a> {
    ledger: &'a mut PoolLedger,
    inputs: Vec<OutPoint>,
    outputs: BTreeMap<OutPoint, UnspentOutput>,
    receipt: Receipt,
}
impl TransferPlan<'_> {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn commit(self) -> Receipt {
        for id in self.inputs {
            self.ledger.gateway.native.outputs.remove(&id);
        }
        self.ledger.gateway.native.outputs.extend(self.outputs);
        self.receipt
    }
}

/// Creation authorization binds the complete empty pool and creator identity.
pub fn creation_hash(state: &PoolState, creator: &[u8]) -> Result<[u8; 32], Error> {
    check_key_size(creator)?;
    let mut h = HashWriter::new(b"USTAV-POOL-CREATE-v1");
    h.fixed(&state.state_root());
    h.bytes(creator);
    Ok(h.finish())
}
fn check_key_size(key: &[u8]) -> Result<(), Error> {
    if key.is_empty() || key.len() > crate::kirpich::limits::MAX_KEY_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}
fn point(h: &mut HashWriter, id: &OutPoint) {
    h.fixed(&id.transaction);
    h.u32(id.index);
}
fn funding_hash(action: &PoolAction) -> Result<[u8; 32], Error> {
    check_key_size(&action.owner)?;
    let mut h = HashWriter::new(b"USTAV-POOL-FUNDING-v1");
    h.bytes(&action.owner);
    for inputs in &action.funding {
        if inputs.len() > MAX_INPUTS || inputs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::InvalidFunding);
        }
        h.u64(inputs.len() as u64);
        for id in inputs {
            point(&mut h, id);
        }
    }
    Ok(h.finish())
}

impl PoolLedger {
    /// Prepare only a zero-delta transfer, retaining all charter/owner checks and
    /// pool locks. Stage touched token/inputs only; no copy of unrelated state.
    pub fn plan_transfer<'a>(
        &'a mut self,
        tx: &Transaction,
        w: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<TransferPlan<'a>, Error> {
        if tx.delta != 0 {
            return Err(Error::InvalidFunding);
        }
        let hash = tx.signing_hash(self.gateway.native.domain())?;
        self.unlocked(&tx.inputs)?;
        let token = self
            .gateway
            .native
            .tokens
            .get(&tx.asset)
            .ok_or(NativeError::UnknownAsset)?;
        w.check(token.compiled.validators.len(), tx.inputs.len())?;
        let mut gas = gas_limit;
        charge(
            &mut gas,
            100u64.saturating_add(crate::ustav::registration_cost(&token.registration)),
        )?;
        let mut staged = crate::ustav::Ledger::new(*self.gateway.native.domain());
        staged.tokens.insert(tx.asset, token.clone());
        for id in &tx.inputs {
            let output = self
                .gateway
                .native
                .output(id)
                .ok_or(NativeError::MissingInput)?;
            if output.asset != tx.asset {
                return Err(NativeError::WrongAsset.into());
            }
            charge(&mut gas, words(output.output.owner.len()).saturating_add(1))?;
            staged.outputs.insert(*id, output.clone());
        }
        for index in 0..tx.outputs.len() {
            if self.gateway.native.outputs.contains_key(&OutPoint {
                transaction: hash,
                index: index as u32,
            }) {
                return Err(NativeError::OutputCollision.into());
            }
        }
        let size = self
            .gateway
            .native
            .outputs
            .len()
            .checked_sub(tx.inputs.len())
            .and_then(|n| n.checked_add(tx.outputs.len()))
            .ok_or(NativeError::ArithmeticOverflow)?;
        if size > MAX_LEDGER_OUTPUTS {
            return Err(Error::ResourceLimit);
        }
        let mut receipt = staged.apply(tx, w, height, verifier, gas)?;
        let verification_gas = gas_limit
            .checked_sub(gas)
            .ok_or(NativeError::ArithmeticOverflow)?;
        receipt.gas_used = receipt
            .gas_used
            .checked_add(verification_gas)
            .ok_or(NativeError::ArithmeticOverflow)?;
        Ok(TransferPlan {
            ledger: self,
            inputs: tx.inputs.clone(),
            outputs: staged.outputs,
            receipt,
        })
    }
    pub fn new(domain: [u8; 32]) -> Self {
        Self {
            gateway: GatewayLedger::new(domain),
            pools: BTreeMap::new(),
            positions: BTreeMap::new(),
            locks: BTreeMap::new(),
        }
    }
    /// Read-only query access, not an alternative transition/persistence boundary.
    pub fn gateway(&self) -> &GatewayLedger {
        &self.gateway
    }
    pub fn pool(&self, id: &[u8; 32]) -> Option<&PoolState> {
        self.pools.get(id).map(|p| &p.state)
    }
    pub fn position(&self, id: &[u8; 32], owner: &[u8]) -> u64 {
        if check_key_size(owner).is_err() {
            return 0;
        }
        self.positions
            .get(&(*id, owner.to_vec()))
            .copied()
            .unwrap_or(0)
    }
    pub fn is_locked(&self, id: &OutPoint) -> bool {
        self.locks.contains_key(id)
    }

    /// Wallet-facing lookup excludes protocol-custodied reserve outputs.
    pub fn spendable_output(&self, id: &OutPoint) -> Option<&UnspentOutput> {
        if self.is_locked(id) {
            return None;
        }
        self.gateway.native.output(id)
    }

    fn unlocked(&self, inputs: &[OutPoint]) -> Result<(), Error> {
        if inputs.len() > MAX_INPUTS {
            return Err(Error::ResourceLimit);
        }
        if inputs.iter().any(|id| self.locks.contains_key(id)) {
            return Err(Error::LockedInput);
        }
        Ok(())
    }
    fn asset(&self, asset: &AssetId) -> Result<(), Error> {
        if *asset == BLCH {
            return Err(Error::UnsupportedAsset);
        }
        let registration = self
            .gateway
            .native
            .registration(asset)
            .ok_or(Error::UnsupportedAsset)?;
        if registration.initial_kyc_root.is_some()
            || !matches!(
                registration.charter.modules.as_slice(),
                [ModuleKind::Supply(_)]
            )
        {
            return Err(Error::UnsupportedAsset);
        }
        Ok(())
    }
    pub fn register(
        &mut self,
        registration: Registration,
        signature: &[u8],
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<AssetId, Error> {
        Ok(self
            .gateway
            .register(registration, signature, verifier, gas)?)
    }
    pub fn enable(
        &mut self,
        config: RouteConfig,
        issuer: &[u8],
        approvals: &[Vec<u8>],
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<[u8; 32], Error> {
        Ok(self
            .gateway
            .enable(config, issuer, approvals, verifier, gas)?)
    }
    pub fn apply(
        &mut self,
        tx: &Transaction,
        w: &Witnesses,
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<Receipt, Error> {
        self.unlocked(&tx.inputs)?;
        Ok(self.gateway.apply(tx, w, height, verifier, gas)?)
    }
    pub fn import(
        &mut self,
        request: &ImportRequest,
        w: &Witnesses,
        approvals: &[Vec<u8>],
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<Receipt, Error> {
        self.unlocked(&request.transaction.inputs)?;
        Ok(self
            .gateway
            .import(request, w, approvals, height, verifier, gas)?)
    }
    pub fn withdraw(
        &mut self,
        request: &WithdrawalRequest,
        w: &Witnesses,
        approvals: &[Vec<u8>],
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<(Release, Receipt), Error> {
        self.unlocked(&request.transaction.inputs)?;
        Ok(self
            .gateway
            .withdraw(request, w, approvals, height, verifier, gas)?)
    }

    /// Shared gateway envelope, dispatched through the outer reserve lock checks.
    pub fn apply_encoded_gateway(
        &mut self,
        bytes: &[u8],
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<super::wire::Applied, Error> {
        use super::wire::{self, Operation};
        if bytes.len() > wire::MAX_ENCODED_BYTES {
            return Err(Error::Wire(wire::Error::TooLarge));
        }
        let decoding_gas = 100u64.saturating_add((bytes.len() as u64).div_ceil(32));
        let remaining = gas_limit
            .checked_sub(decoding_gas)
            .ok_or(Error::Wire(wire::Error::OutOfGas))?;
        let envelope = wire::decode(bytes).map_err(Error::Wire)?;
        if envelope.domain != *self.gateway.native.domain() {
            return Err(Error::Wire(wire::Error::WrongDomain));
        }
        let (mut receipt, release) = match envelope.operation {
            Operation::Import(request) => (
                self.import(
                    &request,
                    &envelope.witnesses,
                    &envelope.approvals,
                    height,
                    verifier,
                    remaining,
                )?,
                None,
            ),
            Operation::Withdraw(request) => {
                let (release, receipt) = self.withdraw(
                    &request,
                    &envelope.witnesses,
                    &envelope.approvals,
                    height,
                    verifier,
                    remaining,
                )?;
                (receipt, Some(release))
            }
        };
        debug_assert!(receipt.gas_used <= remaining);
        receipt.gas_used = receipt.gas_used.saturating_add(decoding_gas);
        Ok(wire::Applied { receipt, release })
    }
    pub fn settle_pair(
        &mut self,
        swap: &crate::ustav::pairs::PairSwap,
        w: &[Witnesses; 2],
        height: u64,
        verifier: &dyn Verifier,
        gas: u64,
    ) -> Result<crate::ustav::pairs::PairReceipt, Error> {
        for tx in &swap.legs {
            self.unlocked(&tx.inputs)?;
        }
        Ok(self.gateway.settle_pair(swap, w, height, verifier, gas)?)
    }
    pub fn create(
        &mut self,
        state: PoolState,
        creator: &[u8],
        signature: &[u8],
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<[u8; 32], Error> {
        let message = creation_hash(&state, creator)?;
        if self.pools.len() >= MAX_POOLS {
            return Err(Error::ResourceLimit);
        }
        if state.snapshot().domain != *self.gateway.native.domain()
            || state.revision() != 0
            || state.lp_supply() != 0
            || state.reserves() != [0; 2]
            || self.pools.contains_key(&state.id())
        {
            return Err(Error::InvalidPool);
        }
        for asset in state.assets() {
            self.asset(&asset)?;
        }
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut gas = gas_limit;
        charge(
            &mut gas,
            1200u64.saturating_add(words(creator.len().saturating_add(signature.len()))),
        )?;
        if !verifier.valid_pq_key(creator) || !verifier.verify_pq(&message, creator, signature) {
            return Err(Error::Unauthorized);
        }
        let id = state.id();
        self.pools.insert(
            id,
            Pool {
                state,
                reserves: None,
            },
        );
        Ok(id)
    }
    pub fn signing_hash(&self, action: &PoolAction) -> Result<[u8; 32], Error> {
        let commitment = funding_hash(action)?;
        let pool = self
            .pools
            .get(&action.request.pool)
            .ok_or(Error::InvalidPool)?;
        Ok(pool.state.signing_hash(&action.request, commitment)?)
    }

    /// Atomic protocol custody transition. Every funding input belongs to the
    /// one PQ signer; reserve inputs instead require the sealed pool rule.
    /// No issuer mint, fake key, permissive verifier or caller-supplied balance.
    pub fn execute(
        &mut self,
        action: &PoolAction,
        signature: &[u8],
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<PoolReceipt, Error> {
        let message = self.signing_hash(action)?;
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut gas = gas_limit;
        let count = action.funding.iter().map(Vec::len).sum::<usize>();
        charge(
            &mut gas,
            1500u64
                .saturating_add(words(action.owner.len().saturating_add(signature.len())))
                .saturating_add(
                    50u64
                        .saturating_add(words(action.owner.len()))
                        .saturating_mul(count as u64),
                ),
        )?;
        if !verifier.valid_pq_key(&action.owner)
            || !verifier.verify_pq(&message, &action.owner, signature)
        {
            return Err(Error::Unauthorized);
        }
        let pool = self
            .pools
            .get(&action.request.pool)
            .ok_or(Error::InvalidPool)?;
        let transition = pool.state.transition(&action.request, height)?;
        let assets = pool.state.assets();
        let mut spent = BTreeSet::new();
        let mut available = [0u64; 2];
        for i in 0..2 {
            self.asset(&assets[i])?;
            self.unlocked(&action.funding[i])?;
            for id in &action.funding[i] {
                if !spent.insert(*id) {
                    return Err(Error::InvalidFunding);
                }
                let output = self
                    .gateway
                    .native
                    .output(id)
                    .ok_or(Error::InvalidFunding)?;
                if output.asset != assets[i] || output.output.owner != action.owner {
                    return Err(Error::InvalidFunding);
                }
                available[i] = available[i]
                    .checked_add(output.output.amount)
                    .ok_or(NativeError::ArithmeticOverflow)?;
            }
        }
        if let Some(ids) = pool.reserves {
            for i in 0..2 {
                let output = self
                    .gateway
                    .native
                    .output(&ids[i])
                    .ok_or(Error::InvalidPool)?;
                if self.locks.get(&ids[i]) != Some(&action.request.pool)
                    || output.asset != assets[i]
                    || output.output.amount != pool.state.reserves()[i]
                    || !spent.insert(ids[i])
                {
                    return Err(Error::InvalidPool);
                }
            }
        } else if pool.state.reserves() != [0; 2] {
            return Err(Error::InvalidPool);
        }
        let old_position = self.position(&action.request.pool, &action.owner);
        let new_position = old_position
            .checked_sub(transition.lp_burn)
            .ok_or(Error::InsufficientPosition)?
            .checked_add(transition.lp_mint)
            .ok_or(NativeError::ArithmeticOverflow)?;
        if old_position == 0 && new_position > 0 && self.positions.len() >= MAX_POSITIONS {
            return Err(Error::ResourceLimit);
        }
        let reserve_ids = std::array::from_fn(|i| OutPoint {
            transaction: message,
            index: i as u32,
        });
        let mut payouts = [None; 2];
        let mut outputs = Vec::new();
        for i in 0..2 {
            let payout = available[i]
                .checked_sub(transition.user_debit[i])
                .ok_or(Error::InvalidFunding)?
                .checked_add(transition.user_credit[i])
                .ok_or(NativeError::ArithmeticOverflow)?;
            // Explicit conservation including authenticated old pool backing.
            let before = u128::from(pool.state.reserves()[i])
                .checked_add(u128::from(available[i]))
                .ok_or(NativeError::ArithmeticOverflow)?;
            let after = u128::from(transition.next.reserves()[i])
                .checked_add(u128::from(payout))
                .ok_or(NativeError::ArithmeticOverflow)?;
            if before != after
            {
                return Err(Error::InvalidFunding);
            }
            outputs.push((
                reserve_ids[i],
                UnspentOutput {
                    asset: assets[i],
                    output: Output {
                        owner: action.owner.clone(),
                        amount: transition.next.reserves()[i],
                    },
                },
            ));
            if payout > 0 {
                let id = OutPoint {
                    transaction: message,
                    index: i
                        .checked_add(2)
                        .ok_or(NativeError::ArithmeticOverflow)? as u32,
                };
                payouts[i] = Some(id);
                outputs.push((
                    id,
                    UnspentOutput {
                        asset: assets[i],
                        output: Output {
                            owner: action.owner.clone(),
                            amount: payout,
                        },
                    },
                ));
            }
        }
        if outputs
            .iter()
            .any(|(id, _)| self.gateway.native.outputs.contains_key(id))
        {
            return Err(NativeError::OutputCollision.into());
        }
        let final_count = self
            .gateway
            .native
            .outputs
            .len()
            .checked_sub(spent.len())
            .and_then(|n| n.checked_add(outputs.len()))
            .ok_or(NativeError::ArithmeticOverflow)?;
        if final_count > MAX_LEDGER_OUTPUTS {
            return Err(Error::ResourceLimit);
        }
        charge(
            &mut gas,
            100u64
                .saturating_mul(outputs.len() as u64)
                .saturating_add(
                    words(action.owner.len()).saturating_mul(outputs.len() as u64),
                ),
        )?;
        let gas_used = gas_limit
            .checked_sub(gas)
            .ok_or(NativeError::ArithmeticOverflow)?;
        // Complete validation above; all following changes are infallible and
        // leave native supply/mint counters and bridge source liabilities intact.
        for id in spent {
            self.gateway.native.outputs.remove(&id);
            self.locks.remove(&id);
        }
        self.gateway.native.outputs.extend(outputs);
        for id in reserve_ids {
            self.locks.insert(id, action.request.pool);
        }
        let position = (action.request.pool, action.owner.clone());
        if new_position == 0 {
            self.positions.remove(&position);
        } else {
            self.positions.insert(position, new_position);
        }
        self.pools.insert(
            action.request.pool,
            Pool {
                state: transition.next,
                reserves: Some(reserve_ids),
            },
        );
        Ok(PoolReceipt {
            authorization: message,
            reserves: reserve_ids,
            payouts,
            lp_balance: new_position,
            gas_used,
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            version: VERSION,
            gateway: self.gateway.snapshot(),
            gateway_root: self.gateway.state_root(),
            pools: self
                .pools
                .values()
                .map(|p| PoolSnapshot {
                    state: p.state.snapshot(),
                    root: p.state.state_root(),
                    reserves: p.reserves,
                })
                .collect(),
            positions: self
                .positions
                .iter()
                .map(|((pool, key), amount)| (*pool, key.clone(), *amount))
                .collect(),
        }
    }
    pub fn state_root(&self) -> [u8; 32] {
        let mut h = HashWriter::new(b"USTAV-POOL-CUSTODY-v1");
        h.u32(VERSION);
        h.fixed(&self.gateway.state_root());
        h.u64(self.pools.len() as u64);
        for (id, pool) in &self.pools {
            h.fixed(id);
            h.fixed(&pool.state.state_root());
            if let Some(ids) = pool.reserves {
                h.u32(1);
                for id in ids {
                    point(&mut h, &id);
                }
            } else {
                h.u32(0);
            }
        }
        h.u64(self.positions.len() as u64);
        for ((pool, key), amount) in &self.positions {
            h.fixed(pool);
            h.bytes(key);
            h.u64(*amount);
        }
        h.finish()
    }
    /// The outer root must come from authenticated host state, never its sender.
    pub fn restore(
        snapshot: Snapshot,
        trusted_root: [u8; 32],
        verifier: &dyn Verifier,
    ) -> Result<Self, Error> {
        if snapshot.version != VERSION
            || snapshot.pools.len() > MAX_POOLS
            || snapshot.positions.len() > MAX_POSITIONS
            || snapshot
                .pools
                .windows(2)
                .any(|p| p[0].state.id >= p[1].state.id)
            || snapshot
                .positions
                .windows(2)
                .any(|p| (&p[0].0, &p[0].1) >= (&p[1].0, &p[1].1))
        {
            return Err(Error::InvalidSnapshot);
        }
        let gateway = GatewayLedger::restore(snapshot.gateway, snapshot.gateway_root, verifier)?;
        let mut ledger = Self {
            gateway,
            pools: BTreeMap::new(),
            positions: BTreeMap::new(),
            locks: BTreeMap::new(),
        };
        for record in snapshot.pools {
            let state = PoolState::restore(record.state, record.root)?;
            if state.snapshot().domain != *ledger.gateway.native.domain() {
                return Err(Error::InvalidSnapshot);
            }
            for asset in state.assets() {
                ledger.asset(&asset)?;
            }
            match record.reserves {
                Some(ids) => {
                    if state.lp_supply() == 0 {
                        return Err(Error::InvalidSnapshot);
                    }
                    for i in 0..2 {
                        let output = ledger
                            .gateway
                            .native
                            .output(&ids[i])
                            .ok_or(Error::InvalidSnapshot)?;
                        if output.asset != state.assets()[i]
                            || output.output.amount != state.reserves()[i]
                            || ledger.locks.insert(ids[i], state.id()).is_some()
                        {
                            return Err(Error::InvalidSnapshot);
                        }
                    }
                }
                None if state.lp_supply() != 0 => return Err(Error::InvalidSnapshot),
                None => {}
            }
            ledger.pools.insert(
                state.id(),
                Pool {
                    state,
                    reserves: record.reserves,
                },
            );
        }
        let mut totals = BTreeMap::<[u8; 32], u128>::new();
        for (pool, key, amount) in snapshot.positions {
            check_key_size(&key)?;
            if amount == 0 || !verifier.valid_pq_key(&key) || !ledger.pools.contains_key(&pool) {
                return Err(Error::InvalidSnapshot);
            }
            let total = totals.entry(pool).or_default();
            *total = total
                .checked_add(u128::from(amount))
                .ok_or(Error::InvalidSnapshot)?;
            ledger.positions.insert((pool, key), amount);
        }
        for (id, pool) in &ledger.pools {
            let circulating = pool
                .state
                .lp_supply()
                .saturating_sub(amm::MINIMUM_LIQUIDITY);
            if totals.get(id).copied().unwrap_or(0) != u128::from(circulating) {
                return Err(Error::InvalidSnapshot);
            }
        }
        if ledger.state_root() != trusted_root {
            return Err(Error::InvalidSnapshot);
        }
        Ok(ledger)
    }
}
