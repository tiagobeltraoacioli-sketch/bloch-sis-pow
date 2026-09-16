//! BLCH-funded gateway import/withdrawal in the complete rehearsal State.
//! Committee attestations are not source-chain proofs or external payments.
use super::*;
use bloch_euvm::ustav::gateway::wire as gateway_wire;

#[derive(Clone, Debug)]
pub struct Request {
    pub blch: PosTransaction,
    pub gateway: gateway_wire::Envelope,
    pub valid_until: u64,
    pub native_gas: u64,
}
impl Request {
    fn transaction(&self) -> &bloch_euvm::ustav::Transaction {
        match &self.gateway.operation {
            gateway_wire::Operation::Import(r) => &r.transaction,
            gateway_wire::Operation::Withdraw(r) => &r.transaction,
        }
    }
    fn gateway_authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        match &self.gateway.operation {
            gateway_wire::Operation::Import(r) => r.signing_hash(domain),
            gateway_wire::Operation::Withdraw(r) => r.signing_hash(domain),
        }
        .map_err(|e| Error::GatewayWire(gateway_wire::Error::Gateway(e)))
    }
    pub fn canonical_bytes(&self, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
        if *domain == [0; 32] || self.gateway.domain != *domain {
            return Err(Error::WrongDomain);
        }
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &self.blch
        else {
            return Err(Error::InvalidShape);
        };
        if keys.is_empty()
            || keys.len() > MAX_BASE_ITEMS
            || inputs.is_empty()
            || inputs.len() > MAX_BASE_ITEMS
            || outputs.len() > MAX_BASE_ITEMS
            || keys.iter().any(|k| {
                k.pubkey.is_empty()
                    || k.pubkey.len() > MAX_BASE_WITNESS_BYTES
                    || k.signature.len() > MAX_BASE_WITNESS_BYTES
            })
            || self.native_gas == 0
            || self.native_gas > fee_market::MAX_TX_GAS
        {
            return Err(Error::ResourceLimit);
        }
        let gateway = gateway_wire::encode(&self.gateway).map_err(Error::GatewayWire)?;
        let base = self.blch.canonical_bytes();
        let length = 74 + base.len() + gateway.len();
        if length as u64 > MAX_ENVELOPE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(b"BLCHGWAY");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&self.native_gas.to_le_bytes());
        bytes.extend_from_slice(&(base.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&base);
        bytes.extend_from_slice(&(gateway.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&gateway);
        Ok(bytes)
    }
    /// Sponsor, issuer, withdrawing owners and committee sign this same digest.
    /// A standalone gateway certificate cannot authorize a sponsored operation.
    pub fn authorization(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.canonical_bytes(domain)?;
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-JOINT-GATEWAY-AUTH-v1");
        h.update(domain);
        h.update(self.blch.spend_signing_root());
        h.update(self.gateway_authorization(domain)?);
        h.update(self.valid_until.to_le_bytes());
        h.update(self.native_gas.to_le_bytes());
        Ok(h.finalize().into())
    }
    pub fn output_txid(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-JOINT-GATEWAY-OUT-v1");
        h.update(self.authorization(domain)?);
        Ok(h.finalize().into())
    }
}
#[derive(Clone, Debug)]
pub struct Receipt {
    pub authorization: [u8; 32],
    pub blch_txid: [u8; 32],
    pub gateway: gateway_wire::Applied,
    pub charge: fee_market::TxCharge,
}
impl State {
    pub fn quote_gateway(&self, request: &Request) -> Result<fee_market::TxCharge, Error> {
        self.quote_gateway_with_context(request, self.base.next_base_fee(), 0)
    }
    pub(super) fn quote_gateway_with_context(
        &self,
        request: &Request,
        base_fee: u128,
        outer_bytes: u64,
    ) -> Result<fee_market::TxCharge, Error> {
        let length = (request.canonical_bytes(&self.domain)?.len() as u64)
            .checked_add(outer_bytes)
            .ok_or(Error::ResourceLimit)?;
        let PosTransaction::TransferV2 {
            keys,
            tx_bytes,
            tip_millisat_per_gas,
            ..
        } = &request.blch
        else {
            return Err(Error::InvalidShape);
        };
        if *tx_bytes < length {
            return Err(Error::Base(TransferReject::UnderdeclaredSize));
        }
        if *tx_bytes > length.saturating_add(fee_market::TX_BYTES_DECLARE_SLACK) {
            return Err(Error::Base(TransferReject::OverdeclaredSize));
        }
        if *tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS {
            return Err(Error::Base(TransferReject::TipAboveCeiling));
        }
        let native_work = request
            .native_gas
            .checked_mul(NATIVE_GAS_MULTIPLIER)
            .ok_or(Error::ResourceLimit)?;
        let gas = fee_market::intrinsic_gas(
            fee_market::TxClass::Eutxo {
                inputs: keys.len() as u32,
            },
            *tx_bytes,
        )
        .checked_add(native_work)
        .filter(|n| *n <= fee_market::MAX_TX_GAS)
        .ok_or(Error::ResourceLimit)?;
        let (base_fee_sat, priority_fee_sat) =
            fee_market::fee_parts_sat(gas, base_fee, *tip_millisat_per_gas);
        Ok(fee_market::TxCharge {
            gas,
            tx_bytes: *tx_bytes,
            base_fee_sat,
            priority_fee_sat,
        })
    }
    /// All fallible gateway work happens in private staging. The real BLCH plan
    /// remains uncommitted until the gateway succeeds, preserving both ledgers.
    pub fn execute_gateway(
        &mut self,
        request: &Request,
        height: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        self.execute_gateway_with_context(
            request,
            height,
            self.base.next_base_fee(),
            0,
            base_verifier,
            native_verifier,
        )
    }
    pub(super) fn execute_gateway_with_context(
        &mut self,
        request: &Request,
        height: u64,
        base_fee: u128,
        outer_bytes: u64,
        base_verifier: &dyn SignatureVerifier,
        native_verifier: &dyn Verifier,
    ) -> Result<Receipt, Error> {
        let charge = self.quote_gateway_with_context(request, base_fee, outer_bytes)?;
        if height > request.valid_until || request.transaction().valid_until > request.valid_until {
            return Err(Error::Expired);
        }
        if let gateway_wire::Operation::Import(r) = &request.gateway.operation {
            if r.valid_until > request.valid_until {
                return Err(Error::Expired);
            }
        }
        let PosTransaction::TransferV2 { keys, inputs, .. } = &request.blch else {
            return Err(Error::InvalidShape);
        };
        self.ensure_base_unlocked(inputs)?;
        self.ensure_native_unlocked(&request.transaction().inputs)?;
        if keys
            .iter()
            .any(|k| !native_verifier.valid_pq_key(&k.pubkey))
        {
            return Err(Error::InvalidShape);
        }
        let authorization = request.authorization(&self.domain)?;
        let blch_txid = request.output_txid(&self.domain)?;
        let envelope_bytes = (request.canonical_bytes(&self.domain)?.len() as u64)
            .checked_add(outer_bytes)
            .ok_or(Error::ResourceLimit)?;
        let encoded = gateway_wire::encode(&request.gateway).map_err(Error::GatewayWire)?;
        let scoped = NativeVerifier {
            inner: native_verifier,
            expected: request.gateway_authorization(&self.domain)?,
            authorization,
        };
        let base_fees = self
            .base_fees
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let priority_fees = self
            .priority_fees
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::ResourceLimit)?;
        let base = self
            .base
            .plan_transfer_v2_with_context(
                &request.blch,
                base_fee,
                base_verifier,
                Some(JointTransferContext {
                    envelope_bytes,
                    output_txid: blch_txid,
                    charge,
                    authorization,
                    reserve: None,
                }),
            )
            .map_err(Error::Base)?;
        let mut staged = self.native.clone();
        let gateway = staged
            .apply_encoded_gateway(&encoded, height, &scoped, request.native_gas)
            .map_err(Error::Native)?;
        let charge = base.commit();
        self.native = staged;
        self.base_fees = base_fees;
        self.priority_fees = priority_fees;
        Ok(Receipt {
            authorization,
            blch_txid,
            gateway,
            charge,
        })
    }
}

/// Bounded canonical transport; domain is supplied by the receiving host.
pub fn decode(bytes: &[u8], domain: &[u8; 32]) -> Result<Request, wire::Error> {
    use wire::{preflight_base_shape, Error as E, Reader};
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(E::TooLarge);
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(8)? != b"BLCHGWAY" {
        return Err(E::InvalidHeader);
    }
    if u16::from_le_bytes(reader.fixed()?) != 1 {
        return Err(E::InvalidVersion);
    }
    if *domain == [0; 32] || reader.fixed::<32>()? != *domain {
        return Err(E::WrongDomain);
    }
    let valid_until = u64::from_le_bytes(reader.fixed()?);
    let native_gas = u64::from_le_bytes(reader.fixed()?);
    let base = reader.section(MAX_ENVELOPE_BYTES)?;
    preflight_base_shape(base, MAX_BASE_ITEMS, false)?;
    let native = reader.section(gateway_wire::MAX_ENCODED_BYTES as u64)?;
    if reader.offset != bytes.len() {
        return Err(E::TrailingBytes);
    }
    let request = Request {
        blch: PosTransaction::from_canonical_bytes(base).map_err(E::Base)?,
        gateway: gateway_wire::decode(native).map_err(|e| E::Joint(Error::GatewayWire(e)))?,
        valid_until,
        native_gas,
    };
    if request.canonical_bytes(domain).map_err(E::Joint)? != bytes {
        return Err(E::NonCanonical);
    }
    Ok(request)
}
