// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]
//! Shared fixture. Falcon keygen is expensive; generate once.

use bloch_crypto::crypto;
use std::sync::OnceLock;

pub struct Signer {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

impl Signer {
    pub fn sign(&self, msg: &[u8; 32]) -> Vec<u8> {
        crypto::sign(&self.sk, msg).expect("sign")
    }
    /// 12 zero bytes ‖ address — what a successful precompile call returns.
    pub fn expected_word(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&Sha3_256::digest(&self.pk)[..20]);
        w
    }
    pub fn address20(&self) -> [u8; 20] {
        let mut a = [0u8; 20];
        a.copy_from_slice(&self.expected_word()[12..]);
        a
    }
}

fn make(seed_byte: u8) -> Signer {
    let (pk, sk) = crypto::generate_keypair_from_seed(&[seed_byte; 32]).expect("keygen");
    Signer { pk, sk }
}

pub fn alice() -> &'static Signer {
    static S: OnceLock<Signer> = OnceLock::new();
    S.get_or_init(|| make(0x11))
}

pub fn mallory() -> &'static Signer {
    static S: OnceLock<Signer> = OnceLock::new();
    S.get_or_init(|| make(0x99))
}

/// Re-wrap an enveloped object under a different suite id, body unchanged.
pub fn rewrap(enveloped: &[u8], suite: u16) -> Vec<u8> {
    let mut v = vec![0xB1, 0x0C];
    v.extend_from_slice(&suite.to_le_bytes());
    v.extend_from_slice(&enveloped[4..]);
    v
}

/// Strip the 4-byte suite envelope — the legacy, pre-envelope encoding.
pub fn strip(enveloped: &[u8]) -> Vec<u8> {
    enveloped[4..].to_vec()
}
