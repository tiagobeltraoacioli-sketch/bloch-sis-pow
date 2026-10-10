// SPDX-License-Identifier: AGPL-3.0-or-later
//! CPU-only, network-free SP1 6.8.0 Groth16 verification. No prover/SDK dependency.
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
pub const CIRCUIT_VERSION: &str = "v6.1.0";
pub const STATEMENT_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:2";
pub const PROOF_BYTES: usize = 356;
pub const STATEMENT_BYTES: usize = 590;

/// V3 statement (`bloch_l2_evm::proof_statement::SettlementStatementV3`).
pub const STATEMENT_V3_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:3";
pub const STATEMENT_V3_BYTES: usize = 766;

fn policy_for(full_vk_sha256: &[u8; 32], tag: &[u8], public_values: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"BLOCH:EXPERIMENTAL:SETTLEMENT-PROOF-POLICY:1");
    h.update(b"SP1_GROTH16");
    h.update((PROOF_BYTES as u64).to_le_bytes());
    h.update((CIRCUIT_VERSION.len() as u16).to_le_bytes());
    h.update(CIRCUIT_VERSION.as_bytes());
    h.update(b"SHA256:FULL-WRAPPER-VK");
    h.update(full_vk_sha256);
    h.update((tag.len() as u16).to_le_bytes());
    h.update(tag);
    h.update(public_values);
    h.finalize().into()
}
fn full_vk_sha256() -> [u8; 32] {
    Sha256::digest(*GROTH16_VK_BYTES).into()
}

/// Same complete-key policy commitment used by the pinned L2 host.
pub fn policy_commitment() -> [u8; 32] {
    policy_for(&full_vk_sha256(), STATEMENT_TAG, b"PUBLIC-VALUES:EXACT-SETTLEMENT-V2-BYTES")
}
/// V3 policy: same construction with the V3 tag and public-values policy
/// (`settlement_v3_groth16_proof_policy_commitment` on the L2 host). A
/// network pins exactly one of the two policies in its genesis.
pub fn policy_commitment_v3() -> [u8; 32] {
    policy_for(&full_vk_sha256(), STATEMENT_V3_TAG, b"PUBLIC-VALUES:EXACT-SETTLEMENT-V3-BYTES")
}
/// Program identity and all other public fields must be selected and compared
/// against committed state by the caller. This function checks the BN254 key
/// matches the statement and invokes the actual pairing verifier.
pub fn verify(policy: &[u8; 32], program: &[u8; 32], values: &[u8], proof: &[u8]) -> bool {
    // The policy selects exactly one statement version; the other never verifies.
    let (tag, length) = if *policy == policy_commitment() {
        (STATEMENT_TAG, STATEMENT_BYTES)
    } else if *policy == policy_commitment_v3() {
        (STATEMENT_V3_TAG, STATEMENT_V3_BYTES)
    } else {
        return false;
    };
    if *program == [0; 32]
        || values.len() != length
        || proof.len() != PROOF_BYTES
        || !values.starts_with(tag)
        || &values[tag.len() + 6 * 32..tag.len() + 7 * 32] != program
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

#[cfg(test)]
mod v3_tests {
    use super::*;

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Same inputs and value as the L2 host's
    /// `settlement_v3_proof_policy_is_distinct_and_has_a_golden_vector`
    /// (bloch-l2-evm integrations/native-domain-devnet).
    #[test]
    fn v3_policy_matches_the_l2_host_golden_vector() {
        let vk = [42; 32];
        assert_eq!(
            hex(policy_for(&vk, STATEMENT_V3_TAG, b"PUBLIC-VALUES:EXACT-SETTLEMENT-V3-BYTES")),
            "70443a9010c089a683469f86ac9568dc3d09f23ada88afd87ffc441ec60b1eb4"
        );
        // And the V2 construction still equals the L2 host's V2 golden vector.
        assert_eq!(
            hex(policy_for(&vk, STATEMENT_TAG, b"PUBLIC-VALUES:EXACT-SETTLEMENT-V2-BYTES")),
            "ee1de4c43782fad793fd7803a40e4a58c2990126" .to_string() + "74bf6247f8782321595fccf4"
        );
        assert_ne!(policy_commitment(), policy_commitment_v3());
    }

    #[test]
    fn a_policy_never_admits_the_other_statement_version() {
        let program = [7; 32];
        let mut v3 = vec![0; STATEMENT_V3_BYTES];
        v3[..STATEMENT_V3_TAG.len()].copy_from_slice(STATEMENT_V3_TAG);
        v3[STATEMENT_V3_TAG.len() + 192..STATEMENT_V3_TAG.len() + 224].copy_from_slice(&program);
        let mut v2 = vec![0; STATEMENT_BYTES];
        v2[..STATEMENT_TAG.len()].copy_from_slice(STATEMENT_TAG);
        v2[STATEMENT_TAG.len() + 192..STATEMENT_TAG.len() + 224].copy_from_slice(&program);
        let proof = [0; PROOF_BYTES];
        // Shape checks fail before pairing: wrong version for the policy.
        assert!(!verify(&policy_commitment(), &program, &v3, &proof));
        assert!(!verify(&policy_commitment_v3(), &program, &v2, &proof));
        assert!(!verify(&[1; 32], &program, &v3, &proof));
        // A V3 statement with a V2 tag (or vice versa) is refused.
        let mut relabelled = v3.clone();
        relabelled[..STATEMENT_TAG.len()].copy_from_slice(STATEMENT_TAG);
        assert!(!verify(&policy_commitment_v3(), &program, &relabelled, &proof));
    }
}
