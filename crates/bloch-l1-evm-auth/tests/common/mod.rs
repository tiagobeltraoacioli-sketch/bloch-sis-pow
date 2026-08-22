// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixtures.
//!
//! The signature primitives are a **test double**, not a weakened cipher. This
//! crate deliberately does not link the PQClean FFI (the verifier arrives
//! through a trait, exactly as `staking.rs` takes its verifier), so the double
//! stands in for the two halves while the *rules* — the AND-composition, the
//! split points, the suite, the address binding, the presence rule — are the
//! real thing under test, and they are what this crate owns.
//!
//! The double is built so that forgery tests mean something: a half is valid
//! **iff** it equals a deterministic expansion of (that half's public key,
//! that signing root). Garbage fails; a signature over a different root fails;
//! a signature by a different key fails; a half of the wrong length fails.

#![allow(dead_code)]

use std::collections::BTreeMap;

use bloch_l1_evm_auth::{
    address_from_pubkey, wrap_envelope, BlochTx, HybridKeyVerifier, PubkeyDirectory,
    FALCON1024_PK_BYTES, HYBRID_PK_BYTES, MLDSA65_PK_BYTES, MLDSA65_SIG_BYTES,
    SUITE_MLDSA65_FALCON1024, TX_TYPE_PQ_CALL,
};
use sha3::{Digest, Sha3_256};

/// The live payload cap (`fee_market::MAX_BLOCK_TX_BYTES_V2`), used as the
/// decoder budget in tests. Passed in, never assumed by the crate.
pub const BUDGET: u64 = 524_288;

/// Falcon-1024's typical signature length. Variable in reality; fixed in the
/// double, which is what makes a wrong-length half detectable.
pub const FALCON_SIG_BYTES: usize = 1280;

/// The chain id the fixtures sign for.
pub const CHAIN_ID: u64 = 8400;

/// Deterministic byte expansion: `SHA3-256(tag ‖ key ‖ root ‖ counter_le)`,
/// concatenated and truncated.
fn expand(tag: &[u8], key: &[u8], root: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut counter: u32 = 0;
    while out.len() < n {
        let mut h = Sha3_256::new();
        h.update(tag);
        h.update(key);
        h.update(root);
        h.update(counter.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(n);
    out
}

/// A stand-in hybrid keypair. The "secret" is the seed; the double derives
/// signatures from the public halves, so possession of the seed is not what
/// makes a signature valid — matching the public key is. That is what makes
/// the theft test (§9.2) sharp: signing with the wrong key produces a
/// signature that verifies **against that key**, never against the victim's.
pub struct Key {
    pub enveloped: Vec<u8>,
    pub body: Vec<u8>,
}

impl Key {
    pub fn new(seed: u8) -> Self {
        let body = expand(b"MOCK-HYBRID-PK", &[seed], b"", HYBRID_PK_BYTES);
        assert_eq!(body.len(), HYBRID_PK_BYTES);
        Self {
            enveloped: wrap_envelope(SUITE_MLDSA65_FALCON1024, &body),
            body,
        }
    }

    pub fn address(&self) -> [u8; 20] {
        address_from_pubkey(&self.enveloped)
    }

    pub fn mldsa_pk(&self) -> &[u8] {
        &self.body[..MLDSA65_PK_BYTES]
    }

    pub fn falcon_pk(&self) -> &[u8] {
        &self.body[MLDSA65_PK_BYTES..]
    }

    /// A well-formed enveloped hybrid signature over `root`.
    pub fn sign(&self, root: &[u8; 32]) -> Vec<u8> {
        wrap_envelope(SUITE_MLDSA65_FALCON1024, &self.sign_body(root))
    }

    /// The signature body: ML-DSA half ‖ Falcon half, split positionally.
    pub fn sign_body(&self, root: &[u8; 32]) -> Vec<u8> {
        let mut body = expand(b"MOCK-MLDSA", self.mldsa_pk(), root, MLDSA65_SIG_BYTES);
        body.extend_from_slice(&expand(
            b"MOCK-FALCON",
            self.falcon_pk(),
            root,
            FALCON_SIG_BYTES,
        ));
        body
    }

    /// The ML-DSA half alone.
    pub fn mldsa_sig(&self, root: &[u8; 32]) -> Vec<u8> {
        expand(b"MOCK-MLDSA", self.mldsa_pk(), root, MLDSA65_SIG_BYTES)
    }

    /// The Falcon half alone.
    pub fn falcon_sig(&self, root: &[u8; 32]) -> Vec<u8> {
        expand(b"MOCK-FALCON", self.falcon_pk(), root, FALCON_SIG_BYTES)
    }
}

/// The injected verifier. Exposes the halves separately, as the trait
/// requires, so the AND lives in the crate and not here.
pub struct MockVerifier;

impl HybridKeyVerifier for MockVerifier {
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        if pubkey.len() != MLDSA65_PK_BYTES || sig.len() != MLDSA65_SIG_BYTES {
            return false;
        }
        sig == expand(b"MOCK-MLDSA", pubkey, signing_root, MLDSA65_SIG_BYTES)
    }

    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        if pubkey.len() != FALCON1024_PK_BYTES || sig.len() != FALCON_SIG_BYTES {
            return false;
        }
        sig == expand(b"MOCK-FALCON", pubkey, signing_root, FALCON_SIG_BYTES)
    }
}

/// The account → pubkey map, as the EVM state would present it. `BTreeMap`,
/// not `HashMap`: ordering is observable in a debug dump and iteration order
/// must not vary between nodes.
#[derive(Default)]
pub struct Dir {
    map: BTreeMap<[u8; 20], Vec<u8>>,
}

impl Dir {
    pub fn empty() -> Self {
        Self::default()
    }

    /// An account that has already authorized once — its key is recorded.
    pub fn with(sender: [u8; 20], pk_enveloped: &[u8]) -> Self {
        let mut d = Self::default();
        d.map.insert(sender, pk_enveloped.to_vec());
        d
    }
}

impl PubkeyDirectory for Dir {
    fn pubkey_of(&self, sender: &[u8; 20]) -> Option<&[u8]> {
        self.map.get(sender).map(|v| v.as_slice())
    }
}

/// An unsigned transaction with realistic fields, `sender` set to `key`'s
/// address.
pub fn base_tx(key: &Key) -> BlochTx {
    BlochTx {
        type_byte: TX_TYPE_PQ_CALL,
        chain_id: CHAIN_ID,
        nonce: 7,
        gas_limit: 200_000,
        max_fee: 1_000_000,
        to: Some([0x11; 20]),
        value: 42,
        data: vec![0xde, 0xad, 0xbe, 0xef],
        sender: key.address(),
        sender_pk: None,
        signature: Vec::new(),
    }
}

/// Sign `tx` with `key`, after setting `sender_pk` to `reveal`.
///
/// Order does not matter — `sender_pk` is not in the signing root (§4.1) —
/// but it is set first so the fixture reads the way the wallet would build it.
pub fn sign_with(mut tx: BlochTx, key: &Key, reveal: Option<Vec<u8>>) -> BlochTx {
    tx.sender_pk = reveal;
    let root = bloch_l1_evm_auth::root::signing_root(&tx).expect("fixture encodes");
    tx.signature = key.sign(&root);
    tx
}

/// The canonical happy path: a fresh account's first authorization.
pub fn first_use_tx(key: &Key) -> BlochTx {
    sign_with(base_tx(key), key, Some(key.enveloped.clone()))
}

/// The canonical happy path: an account whose key is already recorded.
pub fn repeat_use_tx(key: &Key) -> BlochTx {
    sign_with(base_tx(key), key, None)
}

/// Solidity ABI encoding of `(bytes pk, bytes32 msg, bytes sig)` — the input
/// shape a contract produces with `abi.encode(...)`.
pub fn abi_encode(pk: &[u8], msg32: &[u8; 32], sig: &[u8]) -> Vec<u8> {
    fn word(n: usize) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    }
    fn tail(out: &mut Vec<u8>, body: &[u8]) {
        out.extend_from_slice(&word(body.len()));
        out.extend_from_slice(body);
        let pad = (32 - body.len() % 32) % 32;
        out.extend(std::iter::repeat(0u8).take(pad));
    }
    let pk_padded = body_len_padded(pk.len());
    let mut out = Vec::new();
    out.extend_from_slice(&word(96));
    out.extend_from_slice(msg32);
    out.extend_from_slice(&word(96 + 32 + pk_padded));
    tail(&mut out, pk);
    tail(&mut out, sig);
    out
}

fn body_len_padded(len: usize) -> usize {
    (len + 31) / 32 * 32
}
