//! Local, single-BLCH-payer review. Not user consent or execution authorization.
use super::{
    base_reserves::RESERVE_KEY_INDEX, pool_intent::DecodedIntent, pool_wire, PosTransaction, State,
};
use crate::{fee_market::TxCharge, SignatureVerifier};
use bloch_euvm::ustav::gateway::wire::Operation;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Wire(super::wire::Error),
    UnsupportedPayer,
    InvalidFunding,
    InvalidExpiry,
    Expired,
    AccountChanged,
    PacketChanged,
    StateChanged,
    HeightRegressed,
    InvalidSignature,
    FeeChanged,
}

/// Exact packet, selected payer, network fee and local state reviewed together.
/// This type deliberately has no Clone implementation. Finishing consumes it,
/// including failed attempts. All context arguments must originate in trusted
/// wallet/host state, not values echoed by a website.
///
/// This checks only BLCH funding ownership and fee sizing. Reserve semantics,
/// native funding, slippage, liquidity, signatures and bridge finality still need
/// executor validation. Funds are not reserved and no account grant is minted.
/// ```compile_fail
/// use bloch_pos_committee::transition::native_dex::{pool_review::FundingReview, State};
/// fn reuse(review: FundingReview, state: &State, key: &[u8], bytes: &[u8]) {
///     let _ = review.finish(state, key, 1, bytes);
///     let _ = review.finish(state, key, 1, bytes);
/// }
/// ```
#[derive(Debug)]
pub struct FundingReview {
    intent: DecodedIntent,
    payer: Box<[u8]>,
    root: [u8; 32],
    height: u64,
    valid_until: u64,
    charge: TxCharge,
    funding_sats: u128,
    wallet_outputs_sats: u128,
}

fn parts(request: &pool_wire::Request) -> Result<(&PosTransaction, u64), Error> {
    let (base, outer, inner, certificate) = match request {
        pool_wire::Request::Gateway(r) => match &r.gateway.operation {
            Operation::Import(g) => (
                &r.blch,
                r.valid_until,
                g.transaction.valid_until,
                g.valid_until,
            ),
            Operation::Withdraw(g) => (
                &r.blch,
                r.valid_until,
                g.transaction.valid_until,
                r.valid_until,
            ),
        },
        pool_wire::Request::Initialize(r) => (&r.blch, r.valid_until, r.valid_until, r.valid_until),
        pool_wire::Request::CreatePair(r) => (
            &r.blch,
            r.valid_until,
            r.native.transaction.valid_until,
            r.valid_until,
        ),
        pool_wire::Request::Add(r) => (
            &r.blch,
            r.quote.valid_until,
            r.native.transaction.valid_until,
            r.quote.valid_until,
        ),
        pool_wire::Request::Swap(r) => (
            &r.blch,
            r.quote.valid_until,
            r.native.transaction.valid_until,
            r.quote.valid_until,
        ),
        pool_wire::Request::Remove(r) => (
            &r.blch,
            r.quote.valid_until,
            r.native.transaction.valid_until,
            r.quote.valid_until,
        ),
        pool_wire::Request::ClosePair(r) => (
            &r.blch,
            r.valid_until,
            r.native.transaction.valid_until,
            r.valid_until,
        ),
    };
    if inner > outer || certificate > outer {
        return Err(Error::InvalidExpiry);
    }
    Ok((base, outer.min(inner).min(certificate)))
}

impl FundingReview {
    /// Deliberately supports one BLCH payer. A bridge issuer/committee member
    /// without the BLCH funding key needs a different role-specific review.
    pub fn prepare(state: &State, bytes: &[u8], payer: &[u8], height: u64) -> Result<Self, Error> {
        let intent = DecodedIntent::decode(bytes, &state.domain).map_err(Error::Wire)?;
        let (base, valid_until) = parts(intent.request())?;
        if height > valid_until {
            return Err(Error::Expired);
        }
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = base
        else {
            return Err(Error::UnsupportedPayer);
        };
        if keys.len() != 1 || keys[0].pubkey != payer {
            return Err(Error::UnsupportedPayer);
        }
        let pool = match intent.request() {
            pool_wire::Request::Add(r) => Some(r.quote.pool),
            pool_wire::Request::Swap(r) => Some(r.quote.pool),
            pool_wire::Request::Remove(r) => Some(r.quote.pool),
            _ => None,
        };
        let reserve = match intent.request() {
            pool_wire::Request::ClosePair(r) => Some(r.reserve),
            _ => pool.and_then(|id| state.initial_pools.get(&id).map(|r| r.reserve)),
        };
        let reserve_point = reserve.and_then(|id| state.base_reserves.get(&id).map(|r| r.outpoint));
        let owner: [u8; 32] = Sha3_256::digest(payer).into();
        let mut seen = BTreeSet::new();
        let mut funding_sats = 0u128;
        for input in inputs {
            let point = (input.txid, input.vout);
            if !seen.insert(point) {
                return Err(Error::InvalidFunding);
            }
            if input.key_index == RESERVE_KEY_INDEX {
                // A locked reserve is not the payer's spendable balance. Its
                // operation-specific authorization is still checked at execution.
                if reserve_point != Some(point) || !state.base_is_locked(&point) {
                    return Err(Error::InvalidFunding);
                }
                continue;
            }
            let coin = state
                .base
                .utxo(&input.txid, input.vout)
                .ok_or(Error::InvalidFunding)?;
            if input.key_index != 0 || state.base_is_locked(&point) || coin.script_hash != owner {
                return Err(Error::InvalidFunding);
            }
            funding_sats += u128::from(coin.value);
        }
        if funding_sats == 0 {
            return Err(Error::InvalidFunding);
        }
        let wallet_outputs_sats = outputs
            .iter()
            .filter(|o| o.script_hash == owner)
            .map(|o| u128::from(o.value))
            .sum();
        let charge = pool_wire::quote_request(state, intent.request()).map_err(Error::Wire)?;
        let fee = charge
            .base_fee_sat
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::InvalidFunding)?;
        if funding_sats < fee {
            return Err(Error::InvalidFunding);
        }
        Ok(Self {
            intent,
            payer: payer.into(),
            root: state.state_root(),
            height,
            valid_until,
            charge,
            funding_sats,
            wallet_outputs_sats,
        })
    }
    pub fn intent(&self) -> &DecodedIntent {
        &self.intent
    }
    pub fn payer(&self) -> &[u8] {
        &self.payer
    }
    pub fn state_root(&self) -> [u8; 32] {
        self.root
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    /// Full packet network charge, not an AMM fee or externally guaranteed price.
    pub fn charge(&self) -> &TxCharge {
        &self.charge
    }
    /// Sum of existing, unlocked payer inputs. Excludes pool reserves.
    pub fn funding_sats(&self) -> u128 {
        self.funding_sats
    }
    /// Outputs addressed to the payer, including proceeds where applicable.
    /// This is not necessarily change, net cost or an executable payout.
    pub fn wallet_outputs_sats(&self) -> u128 {
        self.wallet_outputs_sats
    }

    /// Attach only the selected BLCH payer's signature to the retained request.
    /// The caller signs `intent().authorization()` with its own trusted signer
    /// after human approval. This method neither accesses keys nor grants consent.
    /// Other witnesses are preserved and still require full submission preflight.
    /// A changed final network charge requires a new review; no fee is repriced.
    pub fn finish_with_payer_signature(
        self,
        state: &State,
        payer: &[u8],
        height: u64,
        signature: &[u8],
        verifier: &dyn SignatureVerifier,
    ) -> Result<DecodedIntent, Error> {
        self.check_context(state, payer, height, self.intent.canonical_bytes())?;
        if signature.is_empty()
            || signature.len() > super::MAX_BASE_WITNESS_BYTES
            || !verifier.verify_with_key(payer, &self.intent.authorization(), signature)
        {
            return Err(Error::InvalidSignature);
        }
        let mut request = self.intent.request().clone();
        let base = match &mut request {
            pool_wire::Request::Gateway(r) => &mut r.blch,
            pool_wire::Request::CreatePair(r) => &mut r.blch,
            pool_wire::Request::Initialize(r) => &mut r.blch,
            pool_wire::Request::Add(r) => &mut r.blch,
            pool_wire::Request::Swap(r) => &mut r.blch,
            pool_wire::Request::Remove(r) => &mut r.blch,
            pool_wire::Request::ClosePair(r) => &mut r.blch,
        };
        let PosTransaction::TransferV2 { keys, .. } = base else {
            return Err(Error::UnsupportedPayer);
        };
        // Preparation established exactly one matching payer key. Replacing
        // only this signature leaves all transaction and other witness fields.
        keys[0].signature = signature.to_vec();
        let bytes = pool_wire::encode(&request, &self.intent.domain()).map_err(Error::Wire)?;
        let signed = DecodedIntent::decode(&bytes, &self.intent.domain()).map_err(Error::Wire)?;
        if signed.authorization() != self.intent.authorization() {
            return Err(Error::PacketChanged);
        }
        let charge = pool_wire::quote_request(state, signed.request()).map_err(Error::Wire)?;
        if charge != self.charge {
            return Err(Error::FeeChanged);
        }
        Ok(signed)
    }

    fn check_context(
        &self,
        state: &State,
        payer: &[u8],
        height: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if payer != self.payer.as_ref() {
            return Err(Error::AccountChanged);
        }
        if !self.intent.matches_packet(bytes) {
            return Err(Error::PacketChanged);
        }
        if height < self.height {
            return Err(Error::HeightRegressed);
        }
        if height > self.valid_until {
            return Err(Error::Expired);
        }
        if state.domain != self.intent.domain() || state.state_root() != self.root {
            return Err(Error::StateChanged);
        }
        Ok(())
    }

    /// Recheck local context immediately before the caller's next step.
    /// Consumes this review even on refusal. Success is not user consent, a
    /// signature, a state lock, or a promise of future inclusion. The caller must
    /// still validate context at signing/submission and use the real executor.
    pub fn finish(
        self,
        state: &State,
        payer: &[u8],
        height: u64,
        bytes: &[u8],
    ) -> Result<DecodedIntent, Error> {
        self.check_context(state, payer, height, bytes)?;
        Ok(self.intent)
    }
}
