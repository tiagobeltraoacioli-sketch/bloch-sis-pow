//! Inactive sponsored zero-supply asset registration and gateway route setup.
//! Request-supplied authorities authorize one typed operation; this establishes
//! neither source-chain backing nor operator endorsement of a configured route.
use super::{CommittedState, JointTransferContext, PosTransaction, NATIVE_GAS_MULTIPLIER};
use crate::{fee_market, SignatureVerifier};
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::{
    gateway::{Route, RouteConfig, MAX_COMMITTEE},
    Registration, Verifier,
};
use sha3::{Digest, Sha3_256};

const MAGIC: &[u8; 8] = b"BLCHBOOT";
const MAX_NAME: usize = 128;
const MAX_KEY: usize = 8192;
const MAX_SIGNATURE: usize = 8192;
const MAX_BASE_ITEMS: usize = 128;
const MAX_BYTES: usize = crate::transition::MAX_NATIVE_TRANSFER_PAYLOAD_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Domain,
    Bounds,
    Truncated,
    Trailing,
    Expired,
    Native,
    Sponsor,
}
#[derive(Clone, Debug)]
pub struct Request {
    pub domain: [u8; 32],
    pub blch: PosTransaction,
    pub registration: Registration,
    pub route: RouteConfig,
    pub valid_until: u64,
    /// Total prepaid native budget, split between registration and enablement.
    pub native_gas: u64,
    pub issuer_signature: Vec<u8>,
    pub approvals: Vec<Vec<u8>>,
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}
impl Request {
    fn shape(&self) -> Result<&SupplyConfig, Error> {
        if self.domain == [0; 32] || self.route.route.native_domain != self.domain {
            return Err(Error::Domain);
        }
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &self.blch
        else {
            return Err(Error::Shape);
        };
        if keys.is_empty()
            || keys.len() > MAX_BASE_ITEMS
            || inputs.is_empty()
            || inputs.len() > MAX_BASE_ITEMS
            || outputs.len() > MAX_BASE_ITEMS
            || keys.iter().any(|k| {
                k.pubkey.is_empty() || k.pubkey.len() > MAX_KEY || k.signature.len() > MAX_SIGNATURE
            })
            || self.native_gas < 2
            || self.native_gas > fee_market::MAX_TX_GAS
        {
            return Err(Error::Bounds);
        }
        let [ModuleKind::Supply(supply)] = self.registration.charter.modules.as_slice() else {
            return Err(Error::Shape);
        };
        if self.registration.initial_kyc_root.is_some()
            || self.registration.charter.token_name.is_empty()
            || self.registration.charter.token_name.len() > MAX_NAME
            || supply.issuer_pubkey.is_empty()
            || supply.issuer_pubkey.len() > MAX_KEY
            || self.issuer_signature.len() > MAX_SIGNATURE
            || self.route.committee.len() < 2
            || self.route.committee.len() > MAX_COMMITTEE
            || self.route.threshold < 2
            || usize::from(self.route.threshold) > self.route.committee.len()
            || self.route.committee.windows(2).any(|w| w[0] >= w[1])
            || self
                .route
                .committee
                .iter()
                .any(|k| k.is_empty() || k.len() > MAX_KEY)
            || self.approvals.len() != self.route.committee.len()
            || self.approvals.iter().any(|s| s.len() > MAX_SIGNATURE)
        {
            return Err(Error::Bounds);
        }
        if self
            .registration
            .asset_id(&self.domain)
            .map_err(|_| Error::Shape)?
            != self.route.route.native_asset
        {
            return Err(Error::Shape);
        }
        Ok(supply)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let supply = self.shape()?;
        // Bound aggregate caller-owned variable data before serializing any of it.
        let PosTransaction::TransferV2 { keys, .. } = &self.blch else {
            return Err(Error::Shape);
        };
        let variable_bytes = keys
            .iter()
            .map(|k| k.pubkey.len() + k.signature.len())
            .chain(self.route.committee.iter().map(Vec::len))
            .chain(self.approvals.iter().map(Vec::len))
            .chain([
                supply.issuer_pubkey.len(),
                self.issuer_signature.len(),
                self.registration.charter.token_name.len(),
            ])
            .try_fold(0usize, |sum, length| sum.checked_add(length))
            .filter(|sum| *sum <= MAX_BYTES)
            .ok_or(Error::Bounds)?;
        let mut out = Vec::with_capacity(variable_bytes);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&self.domain);
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.extend_from_slice(&self.native_gas.to_le_bytes());
        bytes(&mut out, &self.blch.canonical_bytes());
        bytes(&mut out, &self.registration.charter.token_name);
        bytes(&mut out, &supply.issuer_pubkey);
        out.extend_from_slice(&supply.cap.to_le_bytes());
        out.extend_from_slice(&self.registration.nonce);
        let route = &self.route.route;
        out.extend_from_slice(&route.source_domain);
        out.extend_from_slice(&route.native_asset);
        out.extend_from_slice(&route.token);
        out.extend_from_slice(&route.vault);
        out.push(route.decimals);
        out.extend_from_slice(&route.cap.to_le_bytes());
        out.extend_from_slice(&route.vault_code_hash);
        out.extend_from_slice(&(self.route.committee.len() as u16).to_le_bytes());
        for key in &self.route.committee {
            bytes(&mut out, key);
        }
        out.extend_from_slice(&self.route.threshold.to_le_bytes());
        bytes(&mut out, &self.issuer_signature);
        for signature in &self.approvals {
            bytes(&mut out, signature);
        }
        if out.len() > MAX_BYTES {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    pub fn authorization(&self) -> Result<[u8; 32], Error> {
        self.shape()?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-NATIVE-BOOTSTRAP-AUTH-v1");
        h.update(self.domain);
        h.update(self.blch.spend_signing_root());
        h.update(
            self.registration
                .signing_hash(&self.domain)
                .map_err(|_| Error::Shape)?,
        );
        h.update(self.route.signing_hash());
        h.update(self.valid_until.to_le_bytes());
        h.update(self.native_gas.to_le_bytes());
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-NATIVE-BOOTSTRAP-OUT-v1");
        h.update(self.authorization()?);
        Ok(h.finalize().into())
    }
    pub fn quote(&self, base_fee: u128) -> Result<fee_market::TxCharge, Error> {
        let length = self.canonical_bytes()?.len() as u64
            + crate::transition::NATIVE_TRANSFER_FRAME_BYTES as u64;
        let PosTransaction::TransferV2 {
            keys,
            tx_bytes,
            tip_millisat_per_gas,
            ..
        } = &self.blch
        else {
            return Err(Error::Shape);
        };
        if *tx_bytes < length
            || *tx_bytes > length.saturating_add(fee_market::TX_BYTES_DECLARE_SLACK)
            || *tx_bytes > fee_market::MAX_BLOCK_TX_BYTES
            || *tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS
            || base_fee > fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS
        {
            return Err(Error::Bounds);
        }
        let gas = self
            .native_gas
            .checked_mul(NATIVE_GAS_MULTIPLIER)
            .and_then(|native| {
                fee_market::intrinsic_gas(
                    fee_market::TxClass::Eutxo {
                        inputs: keys.len() as u32,
                    },
                    *tx_bytes,
                )
                .checked_add(native)
            })
            .filter(|gas| *gas <= fee_market::MAX_TX_GAS)
            .ok_or(Error::Bounds)?;
        let (base_fee_sat, priority_fee_sat) =
            fee_market::fee_parts_sat(gas, base_fee, *tip_millisat_per_gas);
        Ok(fee_market::TxCharge {
            gas,
            tx_bytes: *tx_bytes,
            base_fee_sat,
            priority_fee_sat,
        })
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Reader<'_> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::Bounds)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(bytes.try_into().map_err(|_| Error::Truncated)?)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let length = u32::from_le_bytes(self.fixed()?) as usize;
        if length > max {
            return Err(Error::Bounds);
        }
        let end = self.offset.checked_add(length).ok_or(Error::Bounds)?;
        let value = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(value.to_vec())
    }
}
pub fn decode(bytes: &[u8]) -> Result<Request, Error> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(Error::Bounds);
    }
    let mut r = Reader { bytes, offset: 0 };
    if &r.fixed::<8>()? != MAGIC || r.u16()? != 1 {
        return Err(Error::Shape);
    }
    let domain = r.fixed()?;
    let valid_until = r.u64()?;
    let native_gas = r.u64()?;
    let blch =
        PosTransaction::from_canonical_bytes(&r.bytes(MAX_BYTES)?).map_err(|_| Error::Shape)?;
    let name = r.bytes(MAX_NAME)?;
    let issuer = r.bytes(MAX_KEY)?;
    let cap = r.u64()?;
    let nonce = r.fixed()?;
    let registration = Registration {
        charter: TokenCharter {
            token_name: name,
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap,
                issuer_pubkey: issuer,
            })],
        },
        nonce,
        initial_kyc_root: None,
    };
    let route = Route {
        source_domain: r.fixed()?,
        native_domain: domain,
        native_asset: r.fixed()?,
        token: r.fixed()?,
        vault: r.fixed()?,
        decimals: r.fixed::<1>()?[0],
        cap: r.u64()?,
        vault_code_hash: r.fixed()?,
    };
    let count = usize::from(r.u16()?);
    if !(2..=MAX_COMMITTEE).contains(&count) {
        return Err(Error::Bounds);
    }
    let mut committee = Vec::new();
    for _ in 0..count {
        committee.push(r.bytes(MAX_KEY)?);
    }
    let threshold = r.u16()?;
    let issuer_signature = r.bytes(MAX_SIGNATURE)?;
    let mut approvals = Vec::new();
    for _ in 0..count {
        approvals.push(r.bytes(MAX_SIGNATURE)?);
    }
    if r.offset != bytes.len() {
        return Err(Error::Trailing);
    }
    let request = Request {
        domain,
        blch,
        registration,
        route: RouteConfig {
            route,
            committee,
            threshold,
        },
        valid_until,
        native_gas,
        issuer_signature,
        approvals,
    };
    if request.canonical_bytes()? != bytes {
        return Err(Error::Shape);
    }
    Ok(request)
}
struct Scoped<'a> {
    inner: &'a dyn Verifier,
    registration: [u8; 32],
    route: [u8; 32],
    authorization: [u8; 32],
}
impl Verifier for Scoped<'_> {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        self.inner.valid_pq_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        (message == self.registration || message == self.route)
            && self.inner.verify_pq(&self.authorization, key, signature)
    }
}
pub(in crate::transition) fn apply_bootstrap(
    base: &mut CommittedState,
    payload: &[u8],
    slot: u64,
    base_fee: u128,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<fee_market::TxCharge, Error> {
    let request = decode(payload)?;
    let charge = request.quote(base_fee)?;
    if slot > request.valid_until {
        return Err(Error::Expired);
    }
    let mut native = base.native_state.clone().ok_or(Error::Native)?;
    if base.admission_network_domain != Some(request.domain)
        || native.domain != request.domain
        || native.native.gateway().native().domain() != &request.domain
        || native.base_fees != 0
        || native.priority_fees != 0
    {
        return Err(Error::Domain);
    }
    let PosTransaction::TransferV2 { keys, inputs, .. } = &request.blch else {
        return Err(Error::Shape);
    };
    if keys
        .iter()
        .any(|key| !native_verifier.valid_pq_key(&key.pubkey))
        || inputs
            .iter()
            .any(|input| native.base_is_locked(&(input.txid, input.vout)))
    {
        return Err(Error::Sponsor);
    }
    let authorization = request.authorization()?;
    let scoped = Scoped {
        inner: native_verifier,
        registration: request
            .registration
            .signing_hash(&request.domain)
            .map_err(|_| Error::Shape)?,
        route: request.route.signing_hash(),
        authorization,
    };
    let remaining = request
        .native_gas
        .checked_sub(100 + (payload.len() as u64).div_ceil(32))
        .ok_or(Error::Bounds)?;
    // Each stage has its own bounded sub-budget; their sum never exceeds the
    // total prepaid native work, including the payload decoding charge above.
    let registered = native
        .native
        .register(
            request.registration.clone(),
            &request.issuer_signature,
            &scoped,
            remaining / 2,
        )
        .map_err(|_| Error::Native)?;
    if registered != request.route.route.native_asset {
        return Err(Error::Native);
    }
    native
        .native
        .enable(
            request.route.clone(),
            &request.issuer_signature,
            &request.approvals,
            &scoped,
            remaining - remaining / 2,
        )
        .map_err(|_| Error::Native)?;
    let mut staged = base.clone();
    let plan = staged
        .plan_transfer_v2_with_context(
            &request.blch,
            base_fee,
            base_verifier,
            Some(JointTransferContext {
                envelope_bytes: payload.len() as u64
                    + crate::transition::NATIVE_TRANSFER_FRAME_BYTES as u64,
                output_txid: request.output_txid()?,
                charge,
                authorization,
                reserve: None,
            }),
        )
        .map_err(|_| Error::Sponsor)?;
    let charge = plan.commit();
    staged.native_state = Some(native);
    *base = staged;
    Ok(charge)
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
pub(in crate::transition) mod tests;
