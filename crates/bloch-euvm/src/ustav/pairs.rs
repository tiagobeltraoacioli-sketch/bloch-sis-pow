//! Atomic, jointly PQ-authorized settlement of two registered native assets.
//!
//! Reference kernel only: no Genesis-4 activation, order matching, pool custody,
//! AMM pricing, collateral oracle or stablecoin peg. Both legs are exact transfers;
//! every owner and applicable charter authority signs the entire exchange.

pub mod wire;

use super::encoding::HashWriter;
use super::{
    charge, registration_cost, words, Error as NativeError, Ledger, OutPoint, Receipt, Transaction,
    Verifier, Witnesses, KERNEL_VERSION, MAX_LEDGER_OUTPUTS,
};
use crate::AssetId;

pub const PAIR_VERSION: u32 = 1;
const SETTLEMENT_GAS: u64 = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Native(NativeError),
    InvalidPair,
    InvalidSwap,
}

impl From<NativeError> for Error {
    fn from(value: NativeError) -> Self {
        Self::Native(value)
    }
}

/// Deterministic market identity. Construction alone does not register assets.
/// No separate pool or mutable market registry is needed for bilateral settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    domain: [u8; 32],
    assets: [AssetId; 2],
}

impl Pair {
    pub fn new(domain: [u8; 32], a: AssetId, b: AssetId) -> Result<Self, Error> {
        // Base BLCH is not an Ustav registered asset. Do not silently invent a
        // wrapper or base-coin accounting adapter to admit it here.
        if a == b || a == crate::BLCH || b == crate::BLCH {
            return Err(Error::InvalidPair);
        }
        let assets = if a < b { [a, b] } else { [b, a] };
        Ok(Self { domain, assets })
    }

    pub fn assets(&self) -> [AssetId; 2] {
        self.assets
    }

    pub fn id(&self) -> [u8; 32] {
        let mut h = HashWriter::new(b"USTAV-PAIR-v1");
        h.fixed(&self.domain);
        h.u32(KERNEL_VERSION);
        h.u32(PAIR_VERSION);
        h.fixed(&self.assets[0]);
        h.fixed(&self.assets[1]);
        h.finish()
    }
}

/// Exact transfer legs in ascending asset-ID order. Outputs include both the
/// counterparty payment and any change; no implied price, decimals or recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairSwap {
    pub legs: [Transaction; 2],
}

impl PairSwap {
    pub fn signing_hash(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(self.authorization(domain)?.2)
    }

    fn authorization(&self, domain: &[u8; 32]) -> Result<(Pair, [[u8; 32]; 2], [u8; 32]), Error> {
        let pair = Pair::new(*domain, self.legs[0].asset, self.legs[1].asset)?;
        if pair.assets != [self.legs[0].asset, self.legs[1].asset]
            || self.legs.iter().any(|tx| {
                tx.delta != 0 || tx.mint_nonce != 0 || tx.inputs.is_empty() || tx.outputs.is_empty()
            })
        {
            return Err(Error::InvalidSwap);
        }
        // Native signing helpers enforce resource ceilings before hashing.
        let hashes = [
            self.legs[0].signing_hash(domain)?,
            self.legs[1].signing_hash(domain)?,
        ];
        let mut h = HashWriter::new(b"USTAV-PAIR-SWAP-v1");
        h.fixed(&pair.id());
        h.fixed(&hashes[0]);
        h.fixed(&hashes[1]);
        Ok((pair, hashes, h.finish()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairReceipt {
    pub pair: [u8; 32],
    pub authorization: [u8; 32],
    /// Native outpoint identifiers remain each leg's canonical transaction hash.
    pub legs: [Receipt; 2],
    /// Includes staging overhead and both legs under one shared gas budget.
    pub gas_used: u64,
}

impl Ledger {
    /// Discover a canonical market only when both assets are registered locally.
    pub fn pair(&self, a: AssetId, b: AssetId) -> Result<Pair, Error> {
        let pair = Pair::new(self.domain, a, b)?;
        if !self.tokens.contains_key(&a) || !self.tokens.contains_key(&b) {
            return Err(NativeError::UnknownAsset.into());
        }
        Ok(pair)
    }

    /// Settle both exact transfers or leave every ledger field unchanged.
    /// The authenticated host supplies height and gas, as for `Ledger::apply`.
    pub fn settle_pair(
        &mut self,
        swap: &PairSwap,
        witnesses: &[Witnesses; 2],
        height: u64,
        verifier: &dyn Verifier,
        gas_limit: u64,
    ) -> Result<PairReceipt, Error> {
        let (pair, hashes, authorization) = swap.authorization(&self.domain)?;
        self.pair(pair.assets[0], pair.assets[1])?;
        let mut gas = gas_limit;
        charge(&mut gas, SETTLEMENT_GAS)?;

        // Stage only the two registered assets and referenced inputs, never a
        // copy of the entire ledger. Native shape bounds cap this work at 256
        // inputs and 256 outputs, regardless of unrelated balances.
        let mut staged = Ledger::new(self.domain);
        for (index, tx) in swap.legs.iter().enumerate() {
            let token = self
                .tokens
                .get(&tx.asset)
                .ok_or(NativeError::UnknownAsset)?;
            witnesses[index].check(token.compiled.validators.len(), tx.inputs.len())?;
            charge(&mut gas, registration_cost(&token.registration))?;
            staged.tokens.insert(tx.asset, token.clone());
            for input in &tx.inputs {
                let output = self.outputs.get(input).ok_or(NativeError::MissingInput)?;
                if output.asset != tx.asset {
                    return Err(NativeError::WrongAsset.into());
                }
                charge(&mut gas, words(output.output.owner.len()).saturating_add(1))?;
                staged.outputs.insert(*input, output.clone());
            }
            // Check collisions against the full ledger, not just staged inputs.
            for output_index in 0..tx.outputs.len() {
                let id = OutPoint {
                    transaction: hashes[index],
                    index: output_index as u32,
                };
                if self.outputs.contains_key(&id) {
                    return Err(NativeError::OutputCollision.into());
                }
            }
        }
        let input_count = swap.legs.iter().map(|tx| tx.inputs.len()).sum::<usize>();
        let output_count = swap.legs.iter().map(|tx| tx.outputs.len()).sum::<usize>();
        let final_count = self
            .outputs
            .len()
            .checked_sub(input_count)
            .and_then(|n| n.checked_add(output_count))
            .ok_or(NativeError::ArithmeticOverflow)?;
        if final_count > MAX_LEDGER_OUTPUTS {
            return Err(NativeError::ResourceLimit("ledger output count").into());
        }
        let scoped = PairVerifier {
            verifier,
            hashes,
            authorization,
        };
        let first = staged.apply(&swap.legs[0], &witnesses[0], height, &scoped, gas)?;
        gas = gas
            .checked_sub(first.gas_used)
            .ok_or(NativeError::OutOfGas)?;
        let second = staged.apply(&swap.legs[1], &witnesses[1], height, &scoped, gas)?;
        gas = gas
            .checked_sub(second.gas_used)
            .ok_or(NativeError::OutOfGas)?;

        // No fallible transition remains after this point. Both legs have passed
        // the same native owner/module/KYC/expiry/conservation checks as apply().
        for tx in &swap.legs {
            for input in &tx.inputs {
                self.outputs.remove(input);
            }
        }
        self.outputs.extend(staged.outputs);
        self.tokens.extend(staged.tokens);
        Ok(PairReceipt {
            pair: pair.id(),
            authorization,
            legs: [first, second],
            gas_used: gas_limit - gas,
        })
    }
}

/// All applicable signatures, including module authorities, bind the full swap.
/// No owner exemptions, synthetic pool keys, classical signatures or fallback to
/// independently signed transfers are admitted by this adapter.
struct PairVerifier<'a> {
    verifier: &'a dyn Verifier,
    hashes: [[u8; 32]; 2],
    authorization: [u8; 32],
}

impl Verifier for PairVerifier<'_> {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        self.verifier.valid_pq_key(key)
    }

    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        (message == self.hashes[0] || message == self.hashes[1])
            && self.verifier.verify_pq(&self.authorization, key, signature)
    }
}
