//! Shared deterministic fixtures for the P9e fuzz targets.
//!
//! Every key and signature is produced by Bloch's own `crypto::{generate_
//! keypair_from_seed, sign}` under `with_seeded_rng_scope`, so a crash input
//! reproduces byte-for-byte on any machine. (Seeded signing here is test-only;
//! production signing stays randomized.)
#![allow(dead_code)]
use std::sync::OnceLock;

pub const HDR: usize = 4;
pub const MAGIC: [u8; 2] = [0xB1, 0x0C];
pub const MLDSA_PK: usize = 1952;
pub const MLDSA_SK: usize = 4032;
pub const MLDSA_SIG: usize = 3309;
pub const FALCON_PADDED_SIG: usize = 1280;

pub struct Key {
    pub suite: u16,
    pub pk_env: Vec<u8>,
    pub pk_body: Vec<u8>,
    pub sk_env: Vec<u8>,
}

pub struct Fixture {
    pub keys: Vec<Key>,
    pub msgs: Vec<Vec<u8>>,
    /// sigs[k][m][j]: enveloped signature j of key k over msgs[m].
    pub sigs: Vec<Vec<Vec<Vec<u8>>>>,
}

pub fn envelope(suite: u16, body: &[u8]) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(&suite.to_le_bytes());
    v.extend_from_slice(body);
    v
}

pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        use bloch_crypto::crypto::{generate_keypair_from_seed, sign};
        let mut keys = Vec::new();
        for seed in [[0x01u8; 32], [0x02u8; 32]] {
            let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
            keys.push(Key { suite: 1, pk_body: pk[HDR..].to_vec(), pk_env: pk, sk_env: sk });
        }
        // Suite 0x0002 (ML-DSA-65 only) key, independent seed.
        let (pk, sk) = generate_keypair_from_seed(&[0x03u8; 32]).unwrap();
        let mpk = pk[HDR..HDR + MLDSA_PK].to_vec();
        let msk = sk[HDR..HDR + MLDSA_SK].to_vec();
        keys.push(Key { suite: 2, pk_env: envelope(2, &mpk), pk_body: mpk, sk_env: envelope(2, &msk) });

        let msgs = vec![[0x5Au8; 32].to_vec(), b"bloch p9e message one".to_vec()];
        let mut sigs = Vec::new();
        for (k, key) in keys.iter().enumerate() {
            let mut per_m = Vec::new();
            for (m, msg) in msgs.iter().enumerate() {
                let mut per_j = Vec::new();
                for j in 0..2u8 {
                    let seed = [0x40 | (k as u8), m as u8, j, 0x9E].repeat(8);
                    let seed: [u8; 32] = seed.try_into().unwrap();
                    let s = pqcrypto_internals::with_seeded_rng_scope(&seed, || sign(&key.sk_env, msg).unwrap());
                    per_j.push(s);
                }
                per_m.push(per_j);
            }
            sigs.push(per_m);
        }
        Fixture { keys, msgs, sigs }
    })
}

/// Falcon half of an enveloped suite-0x0001 signature (compact encoding).
pub fn falcon_half(sig_env: &[u8]) -> &[u8] {
    &sig_env[HDR + MLDSA_SIG..]
}
pub fn mldsa_half(sig_env: &[u8]) -> &[u8] {
    &sig_env[HDR..HDR + MLDSA_SIG]
}

/// Tiny byte cursor for structured fuzz input.
pub struct Cur<'a>(pub &'a [u8]);
impl<'a> Cur<'a> {
    pub fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => { self.0 = rest; *b }
            None => 0,
        }
    }
    pub fn u16(&mut self) -> u16 { u16::from_le_bytes([self.u8(), self.u8()]) }
    pub fn take(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.0.len());
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}
