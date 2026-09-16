//! Laboratory-only unsigned builders over current committed custody.
use super::*;
use crate::transition::{NativeTransferPayload, TransferInputV2, TransferOutput, WitnessKey};
use bloch_euvm::ustav as n;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    CreatePair {
        asset: [u8; 32],
        seed: [u8; 32],
        blch_amount: u64,
        native_amount: u64,
    },
    Initialize {
        reserve: [u8; 32],
        fee_bps: u16,
        minimum_lp: u64,
    },
    Swap {
        pool: [u8; 32],
        input_asset: [u8; 32],
        amount: u64,
        minimum_out: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub owner: Vec<u8>,
    pub valid_until: u64,
    pub operation: Operation,
}
pub struct Quote {
    pub transaction: Vec<u8>,
    pub fee_sat: u128,
    pub reserve_id: Option<[u8; 32]>,
    pub pool_id: Option<[u8; 32]>,
}
fn base_mut(r: &mut pool_wire::Request) -> &mut PosTransaction {
    match r {
        pool_wire::Request::CreatePair(r) => &mut r.blch,
        pool_wire::Request::Initialize(r) => &mut r.blch,
        pool_wire::Request::Swap(r) => &mut r.blch,
        _ => unreachable!("builder only constructs supported operations"),
    }
}
impl CommittedState {
    pub fn native_lab_pool_quote(&self, query: &Query, height: u64) -> Result<Quote, &'static str> {
        if query.owner.is_empty()
            || query.owner.len() > 8192
            || query.valid_until <= height
            || query.valid_until > height.saturating_add(128)
        {
            return Err("invalid owner or validity window");
        }
        // Bound the complete state before cloning a private review projection.
        self.native_lab_wallet_view()?;
        let mut base = self.clone();
        let native = base
            .native_state
            .take()
            .ok_or("native state not initialized")?;
        let state = State {
            base,
            domain: native.domain,
            native: native.native,
            base_fees: 0,
            priority_fees: 0,
            base_reserves: native.base_reserves,
            base_locks: native.base_locks,
            paired_reserves: native.paired_reserves,
            paired_locks: native.paired_locks,
            initial_pools: native.initial_pools,
            reserve_pools: native.reserve_pools,
        };
        state.lab_build(query, height)
    }
}
impl State {
    pub fn lab_build(&self, q: &Query, height: u64) -> Result<Quote, &'static str> {
        if q.owner.is_empty()
            || q.owner.len() > 8192
            || q.valid_until <= height
            || q.valid_until > height.saturating_add(128)
        {
            return Err("invalid owner or validity window");
        }
        let owner_hash: [u8; 32] = Sha3_256::digest(&q.owner).into();
        let payer = self
            .base
            .utxos()
            .filter(|u| u.script_hash == owner_hash && !self.base_is_locked(&(u.txid, u.vout)))
            .max_by_key(|u| u.value)
            .ok_or("no spendable BLCH payer output")?;
        let make_base = |reserve: Option<base_reserves::OutPoint>, outputs: Vec<TransferOutput>| {
            let mut inputs = vec![];
            if let Some(p) = reserve {
                inputs.push(TransferInputV2 {
                    txid: p.0,
                    vout: p.1,
                    key_index: base_reserves::RESERVE_KEY_INDEX,
                });
            }
            inputs.push(TransferInputV2 {
                txid: payer.txid,
                vout: payer.vout,
                key_index: 0,
            });
            PosTransaction::TransferV2 {
                keys: vec![WitnessKey {
                    pubkey: q.owner.clone(),
                    signature: vec![0; 4593],
                }],
                inputs,
                outputs,
                tx_bytes: 0,
                tip_millisat_per_gas: 0,
            }
        };
        let change = || TransferOutput {
            value: 1,
            script_hash: owner_hash,
        };
        let envelope = |asset,
                        inputs: Vec<n::OutPoint>,
                        outputs,
                        locked: Option<n::OutPoint>|
         -> Result<n::transfer_wire::Envelope, &'static str> {
            let ledger = self.native.gateway().native();
            let registration = ledger.registration(&asset).ok_or("unknown native asset")?;
            // Other policies require explicitly supplied redeemers, never guessed data.
            if registration.charter.modules.len() != 1
                || !matches!(
                    registration.charter.modules[0],
                    bloch_euvm::modules::ModuleKind::Supply(_)
                )
            {
                return Err("native policy requires explicit redeemers");
            }
            Ok(n::transfer_wire::Envelope {
                domain: self.domain,
                transaction: n::Transaction {
                    asset,
                    inputs: inputs.clone(),
                    outputs,
                    delta: 0,
                    mint_nonce: 0,
                    policy_revision: ledger
                        .policy_revision(&asset)
                        .ok_or("unknown native policy")?,
                    valid_until: q.valid_until,
                },
                witnesses: n::Witnesses {
                    owners: inputs
                        .iter()
                        .map(|p| {
                            if Some(*p) == locked {
                                vec![]
                            } else {
                                vec![0; 4593]
                            }
                        })
                        .collect(),
                    modules: vec![vec![]],
                    eligibility: vec![],
                },
            })
        };
        let mut request = match q.operation {
            Operation::CreatePair {
                asset,
                seed,
                blch_amount,
                native_amount,
            } => {
                if blch_amount == 0 || native_amount == 0 {
                    return Err("pair amounts must be positive");
                }
                let reserve = base_reserves::reserve_id(&self.domain, &seed, &q.owner)
                    .map_err(|_| "invalid reserve seed")?;
                if self.base_reserves.contains_key(&reserve) {
                    return Err("reserve already exists");
                }
                let ledger = self.native.gateway().native().snapshot();
                let (point, coin) = ledger
                    .outputs
                    .iter()
                    .filter(|(p, o)| {
                        o.asset == asset
                            && o.output.owner == q.owner
                            && !self.native.is_locked(p)
                            && !self.paired_locks.contains_key(p)
                            && o.output.amount >= native_amount
                    })
                    .min_by_key(|(_, o)| o.output.amount)
                    .ok_or("no sufficient spendable native output")?;
                let mut outputs = vec![n::Output {
                    owner: q.owner.clone(),
                    amount: native_amount,
                }];
                if coin.output.amount > native_amount {
                    outputs.push(n::Output {
                        owner: q.owner.clone(),
                        amount: coin.output.amount - native_amount,
                    });
                }
                pool_wire::Request::CreatePair(paired_custody::Request {
                    blch: make_base(
                        None,
                        vec![
                            TransferOutput {
                                value: blch_amount,
                                script_hash: base_reserves::reserve_script(&self.domain, &reserve),
                            },
                            change(),
                        ],
                    ),
                    native: envelope(asset, vec![*point], outputs, None)?,
                    seed,
                    blch_amount,
                    native_amount,
                    valid_until: q.valid_until,
                    native_gas: 100_000,
                })
            }
            Operation::Initialize {
                reserve,
                fee_bps,
                minimum_lp,
            } => {
                let record = self
                    .paired_reserves
                    .get(&reserve)
                    .ok_or("unknown paired reserve")?;
                if record.owner != q.owner || self.reserve_pools.contains_key(&reserve) {
                    return Err("reserve is not an uninitialized owner pair");
                }
                pool_wire::Request::Initialize(initial_liquidity::Request {
                    reserve,
                    creation_authorization: record.authorization,
                    fee_bps,
                    minimum_lp,
                    valid_until: q.valid_until,
                    blch: make_base(None, vec![change()]),
                })
            }
            Operation::Swap {
                pool,
                input_asset,
                amount,
                minimum_out,
            } => {
                let record = self.initial_pools.get(&pool).ok_or("unknown pool")?;
                let b = self
                    .base_reserves
                    .get(&record.reserve)
                    .ok_or("missing base reserve")?;
                let n = self
                    .paired_reserves
                    .get(&record.reserve)
                    .ok_or("missing native reserve")?;
                let query = swap_quote::Request {
                    domain: self.domain,
                    pool,
                    revision: record.pool.revision(),
                    input_asset,
                    amount,
                    minimum_out,
                    valid_until: q.valid_until,
                };
                let quoted = self
                    .quote_blch_swap(&query, height)
                    .map_err(|_| "pool quote refused")?;
                let blch_in = input_asset == bloch_euvm::BLCH;
                let mut base_outputs = vec![TransferOutput {
                    value: quoted.reserves_after[0],
                    script_hash: base_reserves::reserve_script(&self.domain, &record.reserve),
                }];
                let mut native_inputs = vec![n.outpoint];
                let mut native_outputs = vec![n::Output {
                    owner: n.owner.clone(),
                    amount: quoted.reserves_after[1],
                }];
                if blch_in {
                    native_outputs.push(n::Output {
                        owner: q.owner.clone(),
                        amount: quoted.amount_out,
                    });
                } else {
                    if input_asset != n.asset {
                        return Err("input asset does not belong to this pool");
                    }
                    // Select one sufficient owner coin. Both native AMM locks
                    // and paired BLCH/native custody locks exclude candidates.
                    let ledger = self.native.gateway().native().snapshot();
                    let (point, coin) = ledger
                        .outputs
                        .iter()
                        .filter(|(p, o)| {
                            o.asset == n.asset
                                && o.output.owner == q.owner
                                && o.output.amount >= amount
                                && !self.native.is_locked(p)
                                && !self.paired_locks.contains_key(p)
                        })
                        .min_by_key(|(_, o)| o.output.amount)
                        .ok_or("no sufficient spendable native output")?;
                    native_inputs.push(*point);
                    native_inputs.sort();
                    if coin.output.amount > amount {
                        native_outputs.push(n::Output {
                            owner: q.owner.clone(),
                            amount: coin.output.amount - amount,
                        });
                    }
                    base_outputs.push(TransferOutput {
                        value: quoted.amount_out,
                        script_hash: owner_hash,
                    });
                }
                base_outputs.push(change());
                pool_wire::Request::Swap(swap::Request {
                    quote: query,
                    pool_state_root: quoted.pool_state_root,
                    blch: make_base(Some(b.outpoint), base_outputs),
                    native: envelope(n.asset, native_inputs, native_outputs, Some(n.outpoint))?,
                    native_gas: 100_000,
                })
            }
        };
        let length = pool_wire::encode(&request, &self.domain)
            .map_err(|_| "invalid packet")?
            .len() as u64
            + 5;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = base_mut(&mut request) {
            *tx_bytes = length;
        }
        let charge = pool_wire::quote_request(self, &request).map_err(|_| "fee quote refused")?;
        let fee = charge
            .base_fee_sat
            .checked_add(charge.priority_fee_sat)
            .ok_or("fee overflow")?;
        if let PosTransaction::TransferV2 {
            inputs, outputs, ..
        } = base_mut(&mut request)
        {
            let funded = inputs
                .iter()
                .try_fold(0u128, |sum, p| {
                    self.base
                        .utxo(&p.txid, p.vout)
                        .and_then(|u| sum.checked_add(u.value as u128))
                })
                .ok_or("missing funding")?;
            let reserved = outputs[..outputs.len() - 1]
                .iter()
                .try_fold(0u128, |sum, o| sum.checked_add(o.value as u128))
                .ok_or("output overflow")?;
            let remaining = funded
                .checked_sub(reserved)
                .and_then(|n| n.checked_sub(fee))
                .and_then(|n| u64::try_from(n).ok())
                .filter(|n| *n > 0)
                .ok_or("insufficient BLCH funding")?;
            outputs.last_mut().ok_or("missing change")?.value = remaining;
        }
        let (reserve_id, pool_id) = match &request {
            pool_wire::Request::CreatePair(r) => (
                Some(
                    base_reserves::reserve_id(&self.domain, &r.seed, &q.owner)
                        .map_err(|_| "invalid reserve")?,
                ),
                None,
            ),
            pool_wire::Request::Initialize(r) => (
                Some(r.reserve),
                Some(
                    self.bootstrap(
                        &r.reserve,
                        &r.creation_authorization,
                        r.fee_bps,
                        r.minimum_lp,
                    )
                    .map_err(|_| "initial liquidity quote refused")?
                    .pool
                    .id(),
                ),
            ),
            pool_wire::Request::Swap(r) => (
                self.initial_pools.get(&r.quote.pool).map(|p| p.reserve),
                Some(r.quote.pool),
            ),
            _ => unreachable!(),
        };
        let payload = pool_wire::encode(&request, &self.domain).map_err(|_| "invalid packet")?;
        pool_review::FundingReview::prepare(self, &payload, &q.owner, height)
            .map_err(|_| "funding review refused")?;
        let transaction = PosTransaction::NativePool(
            NativeTransferPayload::new(payload).map_err(|_| "packet too large")?,
        )
        .canonical_bytes();
        Ok(Quote {
            transaction,
            fee_sat: fee,
            reserve_id,
            pool_id,
        })
    }
}
