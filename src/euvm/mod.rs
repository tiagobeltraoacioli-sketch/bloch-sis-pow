//! eUTXO VM integration adapter (step 5.1) — feature-gated, NOT wired into
//! `accept_block`.
//!
//! Compiled only under `--features euvm` (off by default). With the feature off,
//! this module does not exist in the build and node behaviour is byte-for-byte
//! unchanged. Even with the feature ON, nothing here is called from the block
//! acceptance path yet — this is the adapter layer the future hook will use:
//!
//! - [`NodePqVerifier`] bridges the VM's `SigVerifier` trait to the node's real
//!   hybrid ML-DSA-65 ‖ Falcon-1024 verifier (`bloch_crypto::crypto::verify`), so
//!   validators verify signatures with the exact consensus rule.
//! - [`euvm_active`] is the committee-governed activation gate: the VM engages only
//!   at/after the activation height AND when a 14-of-21 committee quorum has signed
//!   the activation (`bloch_ffg`). Until then it returns `false` and no eUTXO code
//!   runs.
//!
//! See `crates/bloch-euvm/INTEGRATION.md` for the full plan and the consensus-test
//! gate that must pass before any activation.

use bloch_ffg::{Committee, FeatureActivation, SeatSig, SigVerifier as FfgVerifier};

/// The feature name the committee signs to switch the VM on.
pub const EUVM_FEATURE: &str = "euvm";

/// Fraction of the eUTXO transaction fee that is burned (basis points), per the
/// ETH-style fee-burn design (§5-bis). Illustrative until governance sets it.
pub const EUVM_BURN_BPS: u16 = 5_000; // 50%

/// Bridges the VM/committee `SigVerifier` trait to the node's real hybrid
/// post-quantum verifier. This is the single point where "a signature is valid"
/// means exactly what consensus means by it.
pub struct NodePqVerifier;

impl bloch_euvm::SigVerifier for NodePqVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, msg, sig)
    }
}

impl FfgVerifier for NodePqVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, msg, sig)
    }
}

/// Committee-governed activation gate. The eUTXO VM engages at `height` iff the
/// committee has authorized activation at `activation_height` with a 14-of-21
/// quorum AND `height >= activation_height`. Deterministic — every node computes
/// the same answer from the same on-chain committee + activation record.
pub fn euvm_active(
    committee: &Committee,
    activation_height: u64,
    committee_sigs: &[SeatSig],
    height: u64,
) -> bool {
    let act = FeatureActivation {
        feature: EUVM_FEATURE.to_string(),
        activation_height,
    };
    bloch_ffg::is_feature_active(committee, &act, committee_sigs, &NodePqVerifier, height)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adapter compiles and the activation gate is closed until the committee
    /// signs. (Uses a committee whose members carry no real keys, so a real quorum
    /// cannot form here — the gate must stay closed, which is the safe default.)
    #[test]
    fn activation_gate_defaults_closed() {
        let pks: Vec<Vec<u8>> = (0..bloch_ffg::COMMITTEE_SIZE)
            .map(|i| format!("seat-{i}").into_bytes())
            .collect();
        let committee = Committee::new(pks).unwrap();
        // no signatures → never active, even above the height
        assert!(!euvm_active(&committee, 1000, &[], 2000));
        assert!(!euvm_active(&committee, 1000, &[], 0));
    }
}
