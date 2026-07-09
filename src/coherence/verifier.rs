//! Pluggable shielded-proof verifier (Coherence P1).
//!
//! The node decides whether a shielded tx's proof is valid here. The default
//! `RejectAll` admits no shielded txs (safe: no unverifiable value enters the
//! chain) — the current behaviour. The real SP1/FRI verifier lives behind the
//! `sp1-verify` feature (heavy `sp1-sdk` dep), so the default node build stays
//! lean and this file compiles + tests without SP1. Flipping the default to the
//! SP1 backend (env `BLOCH_SHIELDED_VERIFY=sp1`) is what turns private
//! transactions ON.

use coherence_core::SpendPublic;

/// How the node verifies shielded-spend proofs.
#[derive(Debug, Clone, Default)]
pub enum ShieldedVerifier {
    /// Reject every shielded proof — safe default until SP1 is wired.
    #[default]
    RejectAll,
    /// Verify the raw FRI proof with SP1 (feature `sp1-verify`).
    #[cfg(feature = "sp1-verify")]
    Sp1(sp1_backend::Sp1Verifier),
}

impl ShieldedVerifier {
    /// Verify `proof` against the public inputs. `false` rejects the tx.
    pub fn verify(&self, public: &SpendPublic, proof: &[u8]) -> bool {
        match self {
            ShieldedVerifier::RejectAll => false,
            #[cfg(feature = "sp1-verify")]
            ShieldedVerifier::Sp1(v) => v.verify(public, proof),
        }
    }

    /// Build from configuration. `BLOCH_SHIELDED_VERIFY=sp1` selects the SP1
    /// backend when compiled with `--features sp1-verify`; anything else (and any
    /// build without the feature) keeps the safe `RejectAll` default.
    pub fn from_env() -> Self {
        match std::env::var("BLOCH_SHIELDED_VERIFY").ok().as_deref() {
            #[cfg(feature = "sp1-verify")]
            Some("sp1") => ShieldedVerifier::Sp1(sp1_backend::Sp1Verifier::from_env()),
            _ => ShieldedVerifier::RejectAll,
        }
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, ShieldedVerifier::RejectAll)
    }
}

// The real SP1/FRI verifier — compiled only under `sp1-verify` (pulls sp1-sdk).
// The verify path checks the RAW FRI proof (never a Groth16 wrap), matching the
// prover service (deploy/sp1-prover) and the C1 post-quantum rule.
#[cfg(feature = "sp1-verify")]
mod sp1_backend {
    use super::SpendPublic;

    #[derive(Debug, Clone)]
    pub struct Sp1Verifier {
        // The guest program's verifying key (from `client.setup(ELF)`), loaded
        // once. Bytes so the type stays cloneable/Debug here.
        vkey: std::sync::Arc<sp1_sdk::SP1VerifyingKey>,
    }

    impl Sp1Verifier {
        /// Load the verifying key baked at build (or a path from env).
        pub fn from_env() -> Self {
            // TODO(P1): load the ELF/vkey shipped with the node, e.g.
            //   let client = sp1_sdk::ProverClient::new();
            //   let (_, vk) = client.setup(GUEST_ELF);
            // and cache it. Kept minimal here; completed when SP1 is wired.
            unimplemented!("wire the SP1 guest vkey (see deploy/sp1-prover)")
        }

        /// Verify the raw FRI proof and check its committed public values equal
        /// `public`. Returns true only if both hold.
        pub fn verify(&self, _public: &SpendPublic, _proof: &[u8]) -> bool {
            // TODO(P1):
            //   let proof: sp1_sdk::SP1ProofWithPublicValues = decode(_proof);
            //   let client = sp1_sdk::ProverClient::new();
            //   client.verify(&proof, &self.vkey).is_ok()
            //     && proof.public_values.matches(_public)
            let _ = &self.vkey;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pub_() -> SpendPublic {
        SpendPublic { anchor: [0; 32], nullifiers: vec![], out_commitments: vec![], fee: 0 }
    }

    #[test]
    fn default_rejects_all() {
        let v = ShieldedVerifier::default();
        assert!(!v.verify(&pub_(), &[1, 2, 3]));
        assert!(!v.is_active());
    }

    #[test]
    fn from_env_without_feature_is_reject_all() {
        // Without the sp1-verify feature, from_env always yields the safe default.
        assert!(!ShieldedVerifier::from_env().is_active());
    }
}
