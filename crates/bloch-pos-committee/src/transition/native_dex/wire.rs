//! Canonical joint rehearsal transport; no network or consensus activation.
use super::{
    Execution, Request, State, MAX_BASE_ITEMS, MAX_BASE_WITNESS_BYTES, MAX_ENVELOPE_BYTES,
};
use crate::transition::{PosTransaction, TxDecodeError};
use crate::SignatureVerifier;
use bloch_euvm::ustav::{transfer_wire, Verifier};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Truncated,
    InvalidHeader,
    InvalidVersion,
    WrongDomain,
    InvalidOperation,
    TrailingBytes,
    NonCanonical,
    Base(TxDecodeError),
    Native(transfer_wire::Error),
    Joint(super::Error),
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(count).ok_or(Error::TooLarge)?;
        let slice = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(slice)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
    fn section(&mut self, limit: u64) -> Result<&'a [u8], Error> {
        let count = u64::from_le_bytes(self.fixed()?);
        if count > limit {
            return Err(Error::TooLarge);
        }
        self.take(usize::try_from(count).map_err(|_| Error::TooLarge)?)
    }
}
/// Check the rehearsal's tighter shape limits without allocating witness or
/// item vectors. The shared transaction decoder remains the canonical decoder;
/// its general-purpose byte bound alone permits much larger tables than this API.
fn preflight_base(bytes: &[u8]) -> Result<(), Error> {
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(1)? != [0x06] {
        return Err(Error::InvalidOperation);
    }
    let keys = u32::from_le_bytes(reader.fixed()?) as usize;
    if keys == 0 || keys > MAX_BASE_ITEMS {
        return Err(Error::TooLarge);
    }
    for _ in 0..keys {
        for public_key in [true, false] {
            let length = u32::from_le_bytes(reader.fixed()?) as usize;
            if length > MAX_BASE_WITNESS_BYTES || (public_key && length == 0) {
                return Err(Error::TooLarge);
            }
            reader.take(length)?;
        }
    }
    for inputs in [true, false] {
        let count = u32::from_le_bytes(reader.fixed()?) as usize;
        if count > MAX_BASE_ITEMS || (inputs && count == 0) {
            return Err(Error::TooLarge);
        }
        // TransferV2 inputs and outputs each occupy 40 canonical bytes.
        reader.take(count * 40)?;
    }
    reader.take(8 + 16)?;
    if reader.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(())
}
/// Total and section limits are checked before their decoders allocate.
/// The domain is authenticated by the caller, never selected by this envelope.
pub fn decode(bytes: &[u8], expected_domain: &[u8; 32]) -> Result<Request, Error> {
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(8)? != b"BLCHNATV" {
        return Err(Error::InvalidHeader);
    }
    if u16::from_le_bytes(reader.fixed()?) != 1 {
        return Err(Error::InvalidVersion);
    }
    let domain: [u8; 32] = reader.fixed()?;
    if domain == [0; 32] || domain != *expected_domain {
        return Err(Error::WrongDomain);
    }
    let valid_until = u64::from_le_bytes(reader.fixed()?);
    let native_gas = u64::from_le_bytes(reader.fixed()?);
    let base = reader.section(MAX_ENVELOPE_BYTES)?;
    preflight_base(base)?;
    let blch = PosTransaction::from_canonical_bytes(base).map_err(Error::Base)?;
    if !matches!(blch, PosTransaction::TransferV2 { .. }) {
        return Err(Error::InvalidOperation);
    }
    if blch.canonical_bytes() != base {
        return Err(Error::NonCanonical);
    }
    let native_bytes = reader.section(transfer_wire::MAX_ENCODED_BYTES as u64)?;
    let native = transfer_wire::decode(native_bytes).map_err(Error::Native)?;
    if reader.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    let request = Request {
        blch,
        native,
        valid_until,
        native_gas,
    };
    if request
        .canonical_bytes(expected_domain)
        .map_err(Error::Joint)?
        != bytes
    {
        return Err(Error::NonCanonical);
    }
    Ok(request)
}
/// Uses existing full-envelope fee accounting: no second parsing fee is added.
pub fn apply_encoded(
    state: &mut State,
    bytes: &[u8],
    height: u64,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Execution, Error> {
    let domain = *state.native().gateway().native().domain();
    let request = decode(bytes, &domain)?;
    state
        .execute(&request, height, base_verifier, native_verifier)
        .map_err(Error::Joint)
}

#[cfg(test)]
mod tests {
    use super::super::{CommittedState, Request, State};
    use super::*;
    use crate::header::BlockHeaderV4;
    use crate::state_root::{EutxoEntry, EvmCommitment};
    use crate::transition::{TransferInputV2, TransferOutput, WitnessKey};
    use crate::BlockId;
    use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
    use bloch_euvm::ustav::gateway::pools::PoolLedger;
    use bloch_euvm::ustav::{Output, Registration, Transaction, Witnesses};
    use bloch_euvm::Val;
    use sha3::{Digest, Sha3_256};
    const DOMAIN: [u8; 32] = [42; 32];
    const GAS: u64 = 1_000_000;
    const COIN: u64 = 100_000_000;
    struct BoundVerifier;
    fn key(n: u8) -> Vec<u8> {
        vec![n; 32]
    }
    fn signature(message: &[u8], key: &[u8]) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(key);
        h.update(message);
        h.finalize().to_vec()
    }
    impl SignatureVerifier for BoundVerifier {
        fn verify_with_key(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            key.len() == 32 && key[0] != 0 && sig == signature(root, key)
        }
    }
    impl Verifier for BoundVerifier {
        fn valid_pq_key(&self, key: &[u8]) -> bool {
            key.len() == 32 && key[0] != 0
        }
        fn verify_pq(&self, message: &[u8], key: &[u8], sig: &[u8]) -> bool {
            self.valid_pq_key(key) && sig == signature(message, key)
        }
    }
    fn base_state() -> CommittedState {
        let id = BlockId::of(&BlockHeaderV4 {
            version: crate::transition::BLOCK_VERSION_V4,
            parent: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0; 32],
            randao_mix: [7; 32],
            justified_root: [0; 32],
            finalized_root: [0; 32],
            attestation_root: [0; 32],
            coherence_root: [0; 32],
        });
        CommittedState::genesis_with_network_domain(
            DOMAIN,
            id,
            [7; 32],
            &[],
            &[],
            [0; 32],
            [0; 32],
            [0; 32],
            EvmCommitment {
                account_root: [0; 32],
                receipts_root: [0; 32],
                gas_used: 0,
                base_fee_per_gas: 0,
            },
            &[EutxoEntry {
                txid: [8; 32],
                vout: 0,
                value: COIN,
                script_hash: Sha3_256::digest(key(1)).into(),
            }],
        )
    }
    fn fixture() -> (State, Request) {
        let base = base_state();
        let mut native = PoolLedger::new(DOMAIN);
        let registration = Registration {
            charter: TokenCharter {
                token_name: b"Quote".to_vec(),
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 1000,
                    issuer_pubkey: key(2),
                })],
            },
            nonce: [1; 32],
            initial_kyc_root: None,
        };
        let sig = signature(&registration.signing_hash(&DOMAIN).unwrap(), &key(2));
        let asset = native
            .register(registration, &sig, &BoundVerifier, GAS)
            .unwrap();
        let mint = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: key(3),
                amount: 100,
            }],
            delta: 100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let w = Witnesses {
            modules: vec![vec![Val::Bytes(signature(
                &mint.signing_hash(&DOMAIN).unwrap(),
                &key(2),
            ))]],
            ..Witnesses::default()
        };
        let receipt = native.apply(&mint, &w, 1, &BoundVerifier, GAS).unwrap();
        let tx = Transaction {
            inputs: receipt.outputs,
            outputs: vec![Output {
                owner: key(1),
                amount: 100,
            }],
            delta: 0,
            ..mint
        };
        let state = State::from_parts(
            base.clone(),
            native.clone(),
            base.compute_root(),
            native.state_root(),
        )
        .unwrap();
        let mut request = Request {
            blch: PosTransaction::TransferV2 {
                keys: vec![WitnessKey {
                    pubkey: key(1),
                    signature: vec![0; 32],
                }],
                inputs: vec![TransferInputV2 {
                    txid: [8; 32],
                    vout: 0,
                    key_index: 0,
                }],
                outputs: vec![TransferOutput {
                    value: 1,
                    script_hash: Sha3_256::digest(key(3)).into(),
                }],
                tx_bytes: 0,
                tip_millisat_per_gas: 2,
            },
            native: transfer_wire::Envelope {
                domain: DOMAIN,
                transaction: tx,
                witnesses: Witnesses {
                    owners: vec![vec![0; 32]],
                    modules: vec![vec![]],
                    eligibility: vec![],
                },
            },
            valid_until: 100,
            native_gas: 100_000,
        };
        reprice(&state, &mut request);
        resign(&mut request);
        (state, request)
    }
    fn reprice(state: &State, request: &mut Request) {
        let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
            *tx_bytes = length;
        }
        let charge = state.quote(request).unwrap();
        if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
            outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
        }
    }
    fn resign(request: &mut Request) {
        let message = request.authorization(&DOMAIN).unwrap();
        if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
            keys[0].signature = signature(&message, &key(1));
        }
        request.native.witnesses.owners[0] = signature(&message, &key(3));
    }

    #[test]
    fn canonical_roundtrip_every_truncation_header_length_domain_and_trailing() {
        let (_, request) = fixture();
        let bytes = request.canonical_bytes(&DOMAIN).unwrap();
        let decoded = decode(&bytes, &DOMAIN).unwrap();
        assert_eq!(decoded.canonical_bytes(&DOMAIN).unwrap(), bytes);
        assert_eq!(
            decoded.authorization(&DOMAIN).unwrap(),
            request.authorization(&DOMAIN).unwrap()
        );
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n], &DOMAIN).is_err(), "prefix {n}");
        }
        for offset in [0, 8] {
            let mut bad = bytes.clone();
            bad[offset] = 255;
            assert!(decode(&bad, &DOMAIN).is_err());
        }
        let mut bad = bytes.clone();
        bad[10] ^= 1;
        assert!(matches!(decode(&bad, &DOMAIN), Err(Error::WrongDomain)));
        let mut bad = bytes.clone();
        bad[58..66].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TooLarge)));
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TrailingBytes)));
        assert!(matches!(
            decode(&vec![0; MAX_ENVELOPE_BYTES as usize + 1], &DOMAIN),
            Err(Error::TooLarge)
        ));
        // The canonical base variant tag cannot be changed to an unrelated operation.
        let mut bad = bytes.clone();
        bad[66] = 0xff;
        assert!(decode(&bad, &DOMAIN).is_err());
        let unrelated = PosTransaction::Exit { validator: 7 }.canonical_bytes();
        let original_base_len = u64::from_le_bytes(bytes[58..66].try_into().unwrap()) as usize;
        let mut other = bytes[..58].to_vec();
        other.extend_from_slice(&(unrelated.len() as u64).to_le_bytes());
        other.extend_from_slice(&unrelated);
        other.extend_from_slice(&bytes[66 + original_base_len..]);
        assert!(matches!(
            decode(&other, &DOMAIN),
            Err(Error::InvalidOperation)
        ));
        let base_length = u64::from_le_bytes(bytes[58..66].try_into().unwrap()) as usize;
        let mut bad = bytes.clone();
        bad[66 + base_length..74 + base_length].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TooLarge)));
    }
    #[test]
    fn base_shape_limits_reject_before_reading_or_allocating_declared_items() {
        let (_, request) = fixture();
        let bytes = request.canonical_bytes(&DOMAIN).unwrap();
        let base_length = u64::from_le_bytes(bytes[58..66].try_into().unwrap()) as usize;
        let wrap = |base: &[u8]| {
            let mut encoded = bytes[..58].to_vec();
            encoded.extend_from_slice(&(base.len() as u64).to_le_bytes());
            encoded.extend_from_slice(base);
            encoded.extend_from_slice(&bytes[66 + base_length..]);
            encoded
        };
        // No entries follow the count: TooLarge, rather than Truncated, proves
        // rejection happens before the generic decoder visits any declared item.
        for count in [0, MAX_BASE_ITEMS as u32 + 1, u32::MAX] {
            let mut base = vec![0x06];
            base.extend_from_slice(&count.to_le_bytes());
            assert!(matches!(
                decode(&wrap(&base), &DOMAIN),
                Err(Error::TooLarge)
            ));
        }
        let mut prefix = vec![0x06];
        prefix.extend_from_slice(&1u32.to_le_bytes());
        for signature in [false, true] {
            let mut base = prefix.clone();
            if signature {
                base.extend_from_slice(&1u32.to_le_bytes());
                base.push(1);
            }
            base.extend_from_slice(&(MAX_BASE_WITNESS_BYTES as u32 + 1).to_le_bytes());
            assert!(matches!(
                decode(&wrap(&base), &DOMAIN),
                Err(Error::TooLarge)
            ));
        }
        prefix.extend_from_slice(&1u32.to_le_bytes());
        prefix.push(1);
        prefix.extend_from_slice(&0u32.to_le_bytes());
        for outputs in [false, true] {
            let mut base = prefix.clone();
            if outputs {
                base.extend_from_slice(&1u32.to_le_bytes());
                base.extend_from_slice(&[0; 40]);
            }
            base.extend_from_slice(&(MAX_BASE_ITEMS as u32 + 1).to_le_bytes());
            assert!(matches!(
                decode(&wrap(&base), &DOMAIN),
                Err(Error::TooLarge)
            ));
        }
        // Unsupported operations are rejected without decoding their payload.
        assert!(matches!(
            decode(&wrap(&[0x02]), &DOMAIN),
            Err(Error::InvalidOperation)
        ));
    }

    #[test]
    fn preflight_preserves_canonical_shape_at_supported_boundaries() {
        let (_, mut request) = fixture();
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } = &mut request.blch
        else {
            unreachable!()
        };
        keys.resize(MAX_BASE_ITEMS, keys[0].clone());
        keys[0].pubkey.resize(MAX_BASE_WITNESS_BYTES, 1);
        keys[0].signature.resize(MAX_BASE_WITNESS_BYTES, 2);
        inputs.resize(MAX_BASE_ITEMS, inputs[0].clone());
        outputs.resize(MAX_BASE_ITEMS, outputs[0].clone());
        // This is a codec test, not an executable transaction: duplicated
        // witnesses/inputs remain subject to transition validation afterward.
        let bytes = request.canonical_bytes(&DOMAIN).unwrap();
        assert_eq!(
            decode(&bytes, &DOMAIN)
                .unwrap()
                .canonical_bytes(&DOMAIN)
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn sealed_execution_matches_direct_fees_and_failures_preserve_combined_state() {
        let (mut state, request) = fixture();
        let mut direct = state.clone();
        let bytes = request.canonical_bytes(&DOMAIN).unwrap();
        let before = state.state_root();
        let mut wrong = bytes.clone();
        wrong[10] ^= 1;
        assert!(apply_encoded(&mut state, &wrong, 2, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), before);
        assert!(apply_encoded(&mut state, &bytes, 101, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), before);
        let mut forged = request.clone();
        forged.native.witnesses.owners[0][0] ^= 1;
        assert!(apply_encoded(
            &mut state,
            &forged.canonical_bytes(&DOMAIN).unwrap(),
            2,
            &BoundVerifier,
            &BoundVerifier
        )
        .is_err());
        assert_eq!(state.state_root(), before);
        let expected = direct
            .execute(&request, 2, &BoundVerifier, &BoundVerifier)
            .unwrap();
        let actual = apply_encoded(&mut state, &bytes, 2, &BoundVerifier, &BoundVerifier).unwrap();
        assert_eq!(actual.charge, expected.charge);
        assert_eq!(actual.native, expected.native);
        assert_eq!(actual.blch_txid, expected.blch_txid);
        assert_eq!(state.state_root(), direct.state_root());
        assert_eq!(state.fee_escrow(), direct.fee_escrow());
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 2, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}
