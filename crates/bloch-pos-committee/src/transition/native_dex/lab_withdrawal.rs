//! Laboratory-only withdrawal preparation. External authorities never sign in the wallet.
use super::*;
use crate::transition::{NativeTransferPayload, TransferInputV2, TransferOutput, WitnessKey};
use bloch_euvm::{ustav as n, ustav::gateway as g};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub owner: Vec<u8>,
    pub route: [u8; 32],
    pub amount: u64,
    pub recipient: [u8; 20],
    pub nonce: u64,
    pub valid_until: u64,
}
#[derive(Clone, Debug)]
pub struct Quote {
    pub transaction: Vec<u8>,
    pub authorization: [u8; 32],
    pub fee_sat: u128,
    pub issuer_pubkey: Vec<u8>,
    /// Signatures use these exact indices; an absent approval is an empty vector.
    pub committee: Vec<Vec<u8>>,
    pub threshold: u16,
}
impl CommittedState {
    pub fn native_lab_withdrawal_quote(
        &self,
        q: &Query,
        height: u64,
    ) -> Result<Quote, &'static str> {
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
        state.lab_build_withdrawal(q, height)
    }
}
impl State {
    pub fn lab_build_withdrawal(&self, q: &Query, height: u64) -> Result<Quote, &'static str> {
        if q.owner.is_empty()
            || q.owner.len() > 8192
            || q.amount == 0
            || q.valid_until <= height
            || q.valid_until > height.saturating_add(128)
        {
            return Err("invalid owner, amount or validity window");
        }
        let gateway = self.native.gateway();
        let route = gateway.route(&q.route).ok_or("unknown route")?;
        if route.config.route.native_domain != self.domain
            || q.nonce != route.next_release_nonce
            || q.nonce == u64::MAX
            || q.recipient == [0; 20]
            || q.recipient == route.config.route.vault
            || q.recipient == route.config.route.token
            || route
                .burned
                .checked_add(q.amount as u128)
                .filter(|n| *n <= route.imported)
                .is_none()
        {
            return Err("invalid recipient, nonce or route backing");
        }
        let asset = route.config.route.native_asset;
        let ledger = gateway.native();
        let registration = ledger.registration(&asset).ok_or("unknown asset")?;
        let [bloch_euvm::modules::ModuleKind::Supply(supply)] =
            registration.charter.modules.as_slice()
        else {
            return Err("native policy requires explicit redeemers");
        };
        let snapshot = ledger.snapshot();
        let (point, coin) = snapshot
            .outputs
            .iter()
            .filter(|(p, o)| {
                o.asset == asset
                    && o.output.owner == q.owner
                    && o.output.amount >= q.amount
                    && !self.native.is_locked(p)
                    && !self.paired_locks.contains_key(p)
            })
            .min_by_key(|(_, o)| o.output.amount)
            .ok_or("no sufficient spendable native output")?;
        let owner_hash: [u8; 32] = Sha3_256::digest(&q.owner).into();
        let payer = self
            .base
            .utxos()
            .filter(|u| u.script_hash == owner_hash && !self.base_is_locked(&(u.txid, u.vout)))
            .max_by_key(|u| u.value)
            .ok_or("no spendable BLCH payer output")?;
        let mut outputs = vec![];
        if coin.output.amount > q.amount {
            outputs.push(n::Output {
                owner: q.owner.clone(),
                amount: coin.output.amount - q.amount,
            });
        }
        let mut request = gateway::Request {
            blch: PosTransaction::TransferV2 {
                keys: vec![WitnessKey {
                    pubkey: q.owner.clone(),
                    signature: vec![0; 4593],
                }],
                inputs: vec![TransferInputV2 {
                    txid: payer.txid,
                    vout: payer.vout,
                    key_index: 0,
                }],
                outputs: vec![TransferOutput {
                    value: 1,
                    script_hash: owner_hash,
                }],
                tx_bytes: 0,
                tip_millisat_per_gas: 0,
            },
            gateway: g::wire::Envelope {
                domain: self.domain,
                operation: g::wire::Operation::Withdraw(g::WithdrawalRequest {
                    route: q.route,
                    nonce: q.nonce,
                    recipient: q.recipient,
                    transaction: n::Transaction {
                        asset,
                        inputs: vec![*point],
                        outputs,
                        delta: -(q.amount as i128),
                        mint_nonce: 0,
                        policy_revision: ledger.policy_revision(&asset).ok_or("missing policy")?,
                        valid_until: q.valid_until,
                    },
                }),
                witnesses: n::Witnesses {
                    owners: vec![vec![0; 4593]],
                    modules: vec![vec![bloch_euvm::Val::Bytes(vec![0; 4593])]],
                    eligibility: vec![],
                },
                approvals: vec![vec![0; 4593]; route.config.committee.len()],
            },
            valid_until: q.valid_until,
            native_gas: 100_000,
        };
        let length = request
            .canonical_bytes(&self.domain)
            .map_err(|_| "invalid packet")?
            .len() as u64
            + 5;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
            *tx_bytes = length;
        }
        let charge = self
            .quote_gateway_with_context(&request, self.base.next_base_fee(), 5)
            .map_err(|_| "fee quote refused")?;
        let fee = charge
            .base_fee_sat
            .checked_add(charge.priority_fee_sat)
            .ok_or("fee overflow")?;
        let change = (payer.value as u128)
            .checked_sub(fee)
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or("insufficient BLCH funding")?;
        if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
            outputs[0].value = change;
        }
        let authorization = request
            .authorization(&self.domain)
            .map_err(|_| "invalid authorization")?;
        let packet = request
            .canonical_bytes(&self.domain)
            .map_err(|_| "invalid packet")?;
        pool_review::FundingReview::prepare(self, &packet, &q.owner, height)
            .map_err(|_| "funding review refused")?;
        Ok(Quote {
            transaction: PosTransaction::NativeWithdrawal(
                NativeTransferPayload::new(packet).map_err(|_| "packet too large")?,
            )
            .canonical_bytes(),
            authorization,
            fee_sat: fee,
            issuer_pubkey: supply.issuer_pubkey.clone(),
            committee: route.config.committee.clone(),
            threshold: route.config.threshold,
        })
    }

    /// Rebuild from current state before attaching external witnesses. This also
    /// refuses stale funding, nonce, owner, route or policy selection.
    pub fn lab_certify_withdrawal(
        &self,
        q: &Query,
        height: u64,
        expected_authorization: [u8; 32],
        issuer_signature: Vec<u8>,
        approvals: Vec<Vec<u8>>,
        verifier: &dyn Verifier,
    ) -> Result<Quote, &'static str> {
        let mut quote = self.lab_build_withdrawal(q, height)?;
        if quote.authorization != expected_authorization
            || issuer_signature.len() > 4593
            || !verifier.verify_pq(
                &quote.authorization,
                &quote.issuer_pubkey,
                &issuer_signature,
            )
            || approvals.len() != quote.committee.len()
            || approvals.iter().any(|s| s.len() > 4593)
        {
            return Err("invalid external certificate");
        }
        let mut accepted = 0;
        for (key, sig) in quote.committee.iter().zip(&approvals) {
            if sig.is_empty() {
                continue;
            }
            if !verifier.verify_pq(&quote.authorization, key, sig) {
                return Err("invalid committee signature");
            }
            accepted += 1;
        }
        if accepted < quote.threshold as usize {
            return Err("insufficient committee quorum");
        }
        let PosTransaction::NativeWithdrawal(payload) =
            PosTransaction::from_canonical_bytes(&quote.transaction)
                .map_err(|_| "invalid packet")?
        else {
            return Err("wrong operation");
        };
        let pool_wire::Request::Gateway(mut request) =
            pool_wire::decode(payload.as_bytes(), &self.domain)
                .map_err(|_| "invalid gateway packet")?
        else {
            return Err("wrong operation");
        };
        request.gateway.witnesses.modules[0] = vec![bloch_euvm::Val::Bytes(issuer_signature)];
        request.gateway.approvals = approvals;
        if request
            .authorization(&self.domain)
            .map_err(|_| "invalid authorization")?
            != expected_authorization
        {
            return Err("certificate changed authorization");
        }
        self.quote_gateway_with_context(&request, self.base.next_base_fee(), 5)
            .map_err(|_| "certificate exceeds declared witness slack")?;
        quote.transaction = PosTransaction::NativeWithdrawal(
            NativeTransferPayload::new(
                request
                    .canonical_bytes(&self.domain)
                    .map_err(|_| "invalid packet")?,
            )
            .map_err(|_| "packet too large")?,
        )
        .canonical_bytes();
        Ok(quote)
    }
}
