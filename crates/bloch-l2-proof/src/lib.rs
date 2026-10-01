// SPDX-License-Identifier: AGPL-3.0-or-later
//! CPU-only, network-free SP1 6.8.0 Groth16 verification. No prover/SDK dependency.
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
pub const CIRCUIT_VERSION: &str = "v6.1.0";
pub const STATEMENT_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:2";
pub const PROOF_BYTES: usize = 356;
pub const STATEMENT_BYTES: usize = 590;

/// Same complete-key policy commitment used by the pinned L2 host.
pub fn policy_commitment() -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-PROOF-POLICY:1");
    h.update(b"SP1_GROTH16");
    h.update((PROOF_BYTES as u64).to_le_bytes());
    h.update((CIRCUIT_VERSION.len() as u16).to_le_bytes());
    h.update(CIRCUIT_VERSION.as_bytes());
    h.update(b"SHA256:FULL-WRAPPER-VK");
    h.update(Sha256::digest(*GROTH16_VK_BYTES));
    h.update((STATEMENT_TAG.len() as u16).to_le_bytes());
    h.update(STATEMENT_TAG);
    h.update(b"PUBLIC-VALUES:EXACT-SETTLEMENT-V2-BYTES");
    h.finalize().into()
}
/// Program identity and all other public fields must be selected and compared
/// against committed state by the caller. This function checks the BN254 key
/// matches the statement and invokes the actual pairing verifier.
pub fn verify(policy: &[u8; 32], program: &[u8; 32], values: &[u8], proof: &[u8]) -> bool {
    if *policy != policy_commitment()
        || *program == [0; 32]
        || values.len() != STATEMENT_BYTES
        || proof.len() != PROOF_BYTES
        || !values.starts_with(STATEMENT_TAG)
        || &values[STATEMENT_TAG.len() + 6 * 32..STATEMENT_TAG.len() + 7 * 32] != program
        || proof[..4] != Sha256::digest(*GROTH16_VK_BYTES)[..4]
    {
        return false;
    }
    use std::fmt::Write;
    let mut key = String::from("0x");
    for byte in program {
        write!(key, "{byte:02x}").unwrap();
    }
    Groth16Verifier::verify(proof, values, &key, &GROTH16_VK_BYTES).is_ok()
}
