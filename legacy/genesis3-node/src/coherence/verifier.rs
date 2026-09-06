//! Pluggable shielded-proof verifier (Coherence P1).
//!
//! The node decides whether a shielded tx's proof is valid here. The default
//! `RejectAll` admits no shielded txs (safe: no unverifiable value enters the
//! chain). The real SP1/FRI verifier lives behind the `sp1-verify` feature
//! (heavy `sp1-sdk` dep), so the default node build stays lean.
//!
//! SECURITY (Round-2 audit P123, P-1) — the SP1 backend is REAL and fail-closed:
//!   1. **vkey pinning**: the guest program's verifying key is loaded from
//!      `BLOCH_SP1_VKEY` (a bincode-serialized `SP1VerifyingKey` shipped with
//!      the node release) and its SP1 hash (`vk.bytes32()`) MUST equal the
//!      compile-time constant [`SHIELDED_SPEND_VKEY_HASH`]. An empty pin, a
//!      missing file, or a mismatch aborts startup — a proof for a DIFFERENT
//!      guest program (or an attacker-supplied vkey) can never validate.
//!   2. **public-values binding**: the guest commits the `SpendPublic` it
//!      proved; [`public_values_bind`] requires the proof's committed bytes to
//!      equal the canonical serialization of the `SpendPublic` the node is
//!      validating. A valid proof re-bound to different public inputs is
//!      rejected.
//!   3. **no mock prover**: verification uses the explicit CPU prover client
//!      (never the env-driven one), the raw core STARK/FRI proof shape is
//!      required (never a mock/Groth16/PLONK wrap), and `SP1_PROVER=mock` in
//!      the environment aborts startup of the SP1 backend outright.
//!
//! The binding/pinning decision logic is feature-independent pure code below so
//! the default (no-SP1) build unit-tests it.

use coherence_core::SpendPublic;

/// Pinned SP1 verifying-key hash of the Coherence spend guest program
/// (`vk.bytes32()` from `sp1_sdk`, i.e. `0x` + 64 hex chars).
///
/// EMPTY means "no guest release pinned yet" and is FAIL-CLOSED: the SP1
/// backend refuses to construct, so no proof whatsoever validates. The release
/// process bakes the real value here: build the guest with `cargo prove build`
/// in `crates/coherence-prover/program`, run the script host
/// (`crates/coherence-prover/script`) which prints the vkey hash and writes the
/// vkey file, then set this constant in the same release commit that ships the
/// vkey file. Do NOT make this env-overridable — that would defeat the pin.
pub const SHIELDED_SPEND_VKEY_HASH: &str = "";

/// Canonical byte serialization of `SpendPublic` — exactly what the SP1 guest
/// commits via `sp1_zkvm::io::commit(&public)` (bincode v1 wire format;
/// bincode 2's `legacy()` config reproduces it). `None` only on a serializer
/// error, which the caller must treat as "reject".
pub fn expected_public_bytes(public: &SpendPublic) -> Option<Vec<u8>> {
    bincode::serde::encode_to_vec(public, bincode::config::legacy()).ok()
}

/// TRUE iff the proof's committed public values are byte-for-byte the canonical
/// serialization of the `SpendPublic` the node is validating against. This is
/// the public-values binding: without it, one valid proof would validate ANY
/// (anchor, nullifiers, out_commitments, fee) — i.e. arbitrary shielded mints.
pub fn public_values_bind(committed: &[u8], public: &SpendPublic) -> bool {
    match expected_public_bytes(public) {
        Some(expected) => !expected.is_empty() && committed == expected.as_slice(),
        None => false,
    }
}

/// TRUE iff `got_bytes32` (the loaded vkey's SP1 hash, `0x` + 64 hex) matches
/// the compile-time pin. An empty or malformed pin matches NOTHING (fail-closed
/// until a guest release is pinned).
pub fn vkey_pin_ok(pinned: &str, got_bytes32: &str) -> bool {
    let well_formed = |s: &str| {
        s.len() == 66
            && s.get(..2).is_some_and(|p| p == "0x" || p == "0X")
            && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
    };
    well_formed(pinned) && well_formed(got_bytes32) && pinned[2..].eq_ignore_ascii_case(&got_bytes32[2..])
}

/// TRUE iff the `SP1_PROVER` env value selects the mock prover, which produces
/// proofs that env-driven clients "verify" successfully. The node must refuse
/// to bring the SP1 backend up under it (audit P123 P-2).
pub fn mock_prover_env_refused(sp1_prover_env: Option<&str>) -> bool {
    matches!(sp1_prover_env.map(str::trim), Some(v) if v.eq_ignore_ascii_case("mock"))
}

/// How the node verifies shielded-spend proofs.
#[derive(Debug, Clone, Default)]
pub enum ShieldedVerifier {
    /// Reject every shielded proof — safe default until SP1 is enabled.
    #[default]
    RejectAll,
    /// Verify the raw FRI proof with SP1 (feature `sp1-verify`).
    #[cfg(feature = "sp1-verify")]
    Sp1(sp1_backend::Sp1Verifier),
}

impl ShieldedVerifier {
    /// Verify `proof` against the public inputs. `false` rejects the tx.
    pub fn verify(&self, public: &SpendPublic, proof: &[u8]) -> bool {
        #[cfg(not(feature = "sp1-verify"))]
        let _ = (public, proof); // only the SP1 arm consumes them
        match self {
            ShieldedVerifier::RejectAll => false,
            #[cfg(feature = "sp1-verify")]
            ShieldedVerifier::Sp1(v) => v.verify(public, proof),
        }
    }

    /// Build from configuration. `BLOCH_SHIELDED_VERIFY=sp1` selects the SP1
    /// backend when compiled with `--features sp1-verify`; anything else (and any
    /// build without the feature) keeps the safe `RejectAll` default.
    ///
    /// Fail-closed: selecting `sp1` with a missing/mismatched vkey pin or with
    /// `SP1_PROVER=mock` in the environment PANICS at startup rather than
    /// running a verifier that could accept (or silently reject) everything.
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
// The verify path checks the RAW core STARK/FRI proof (never a Groth16/PLONK
// wrap), matching the prover service (deploy/sp1-prover) and the C1
// post-quantum rule.
#[cfg(feature = "sp1-verify")]
mod sp1_backend {
    use super::{
        mock_prover_env_refused, public_values_bind, vkey_pin_ok, SpendPublic,
        SHIELDED_SPEND_VKEY_HASH,
    };
    use sp1_sdk::{
        CpuProver, HashableKey, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues,
        SP1VerifyingKey,
    };
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct Sp1Verifier {
        /// Explicit CPU prover client used ONLY for verification — never the
        /// env-driven client (`SP1_PROVER=mock` must not select a mock
        /// verifier).
        client: Arc<CpuProver>,
        /// The guest program's verifying key, pinned against
        /// `SHIELDED_SPEND_VKEY_HASH` at load.
        vkey: Arc<SP1VerifyingKey>,
    }

    impl std::fmt::Debug for Sp1Verifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Sp1Verifier").field("vkey", &self.vkey.bytes32()).finish()
        }
    }

    impl Sp1Verifier {
        /// Load the verifying key shipped with the node and pin it.
        ///
        /// Panics (fail-closed, at startup, only when the operator explicitly
        /// selected `BLOCH_SHIELDED_VERIFY=sp1`) when:
        /// - `SP1_PROVER=mock` is set (mock prover env — audit P123 P-2);
        /// - `SHIELDED_SPEND_VKEY_HASH` is empty (no guest release pinned);
        /// - `BLOCH_SP1_VKEY` is unset/unreadable/undecodable;
        /// - the loaded vkey's hash does not equal the pin.
        pub fn from_env() -> Self {
            assert!(
                !mock_prover_env_refused(std::env::var("SP1_PROVER").ok().as_deref()),
                "SP1_PROVER=mock is refused: the mock prover accepts fabricated proofs; \
                 unset it (verification uses the explicit CPU client)"
            );
            let path = std::env::var("BLOCH_SP1_VKEY").unwrap_or_else(|_| {
                panic!("BLOCH_SHIELDED_VERIFY=sp1 requires BLOCH_SP1_VKEY=<path to the released guest vkey>")
            });
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("cannot read SP1 vkey at {path}: {e}"));
            let (vk, _): (SP1VerifyingKey, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
                    .unwrap_or_else(|e| panic!("cannot decode SP1 vkey at {path}: {e}"));
            let got = vk.bytes32();
            assert!(
                vkey_pin_ok(SHIELDED_SPEND_VKEY_HASH, &got),
                "SP1 guest vkey NOT pinned: loaded {got}, pinned {:?}. Refusing to \
                 verify against an unpinned guest program (empty pin = no release yet).",
                SHIELDED_SPEND_VKEY_HASH
            );
            let client = ProverClient::builder().cpu().build();
            Self { client: Arc::new(client), vkey: Arc::new(vk) }
        }

        /// Verify the raw FRI proof and check its committed public values equal
        /// `public`. Returns true only if ALL of the following hold:
        /// decode ok, proof shape is the raw core STARK (non-empty), SP1
        /// verification against the PINNED vkey passes, and the committed
        /// public values bind byte-for-byte to `public`.
        pub fn verify(&self, public: &SpendPublic, proof: &[u8]) -> bool {
            let Ok((proof, _)) = bincode::serde::decode_from_slice::<SP1ProofWithPublicValues, _>(
                proof,
                bincode::config::legacy(),
            ) else {
                return false;
            };
            if !proof_shape_admissible(&proof) {
                return false;
            }
            if self.client.verify(&proof, &self.vkey).is_err() {
                return false;
            }
            public_values_bind(proof.public_values.as_slice(), public)
        }
    }

    /// Raw core STARK/FRI only: rejects MOCK proofs (`SP1Proof::Core(vec![])`
    /// — exactly what `SP1ProofWithPublicValues::create_mock_proof` emits, and
    /// what a mock `ProverClient` returns) and any Groth16/PLONK/compressed
    /// wrap (C1 post-quantum rule). The non-empty check also prevents a
    /// remote panic: sp1-sdk's `verify_proof` does `proof.last().unwrap()`
    /// on the shard vec, so an attacker-supplied empty core proof would
    /// otherwise crash the node.
    pub(crate) fn proof_shape_admissible(proof: &SP1ProofWithPublicValues) -> bool {
        matches!(&proof.proof, SP1Proof::Core(shards) if !shards.is_empty())
    }

    #[cfg(test)]
    mod sp1_tests {
        use super::*;
        use sp1_sdk::SP1PublicValues;

        /// Audit P123 test: a MOCK proof (empty core shards — the exact shape
        /// `create_mock_proof`/the mock ProverClient produce) is rejected by
        /// the admissibility gate, even with perfectly matching public values.
        #[test]
        fn mock_proof_is_rejected_by_shape() {
            let public = SpendPublic {
                anchor: [7; 32],
                nullifiers: vec![[1; 32]],
                out_commitments: vec![[3; 32]],
                fee: 42,
            };
            let committed = super::super::expected_public_bytes(&public).unwrap();
            let mock = SP1ProofWithPublicValues {
                proof: SP1Proof::Core(vec![]),
                public_values: SP1PublicValues::from(&committed),
                sp1_version: sp1_sdk::SP1_CIRCUIT_VERSION.to_string(),
                tee_proof: None,
            };
            assert!(!proof_shape_admissible(&mock), "mock (empty-core) proof admitted");
            // And its public values DO bind — proving the rejection above is
            // the shape gate, not an accidental binding failure.
            assert!(super::super::public_values_bind(mock.public_values.as_slice(), &public));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pub_() -> SpendPublic {
        SpendPublic {
            anchor: [7; 32],
            nullifiers: vec![[1; 32], [2; 32]],
            out_commitments: vec![[3; 32]],
            fee: 42,
        }
    }

    #[test]
    fn default_rejects_all() {
        let v = ShieldedVerifier::default();
        assert!(!v.verify(&pub_(), &[1, 2, 3]));
        assert!(!v.is_active());
    }

    #[test]
    fn from_env_without_sp1_selected_is_reject_all() {
        // BLOCH_SHIELDED_VERIFY unset in the test env ⇒ safe default.
        assert!(!ShieldedVerifier::from_env().is_active());
    }

    // ── public-values binding (audit P123 P-1) ────────────────────────────────
    // These FAIL if the binding is stubbed to `true` or the serialization stops
    // matching what the guest commits.

    #[test]
    fn binding_accepts_the_exact_committed_bytes() {
        let p = pub_();
        let committed = expected_public_bytes(&p).expect("serialize");
        assert!(public_values_bind(&committed, &p));
    }

    #[test]
    fn tampered_public_values_are_rejected() {
        let p = pub_();
        let committed = expected_public_bytes(&p).expect("serialize");
        // Flip every single byte position, one at a time: no bit of the
        // committed (anchor, nullifiers, out_commitments, fee) is unbound.
        for i in 0..committed.len() {
            let mut t = committed.clone();
            t[i] ^= 0x01;
            assert!(!public_values_bind(&t, &p), "tampered byte {i} accepted");
        }
        // Truncation / extension / empty are rejected too.
        assert!(!public_values_bind(&committed[..committed.len() - 1], &p));
        let mut ext = committed.clone();
        ext.push(0);
        assert!(!public_values_bind(&ext, &p));
        assert!(!public_values_bind(&[], &p));
    }

    #[test]
    fn rebound_public_values_are_rejected() {
        // A proof committed for one SpendPublic must not validate another
        // (different fee, extra out_commitment = shielded counterfeiting).
        let p = pub_();
        let committed = expected_public_bytes(&p).expect("serialize");
        let cheaper = SpendPublic { fee: 0, ..p.clone() };
        let minted = SpendPublic {
            out_commitments: vec![[3; 32], [9; 32]],
            ..p.clone()
        };
        assert!(!public_values_bind(&committed, &cheaper));
        assert!(!public_values_bind(&committed, &minted));
    }

    // ── vkey pinning (audit P123 P-1) ─────────────────────────────────────────

    const VK: &str = "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn empty_pin_is_fail_closed() {
        // No release pinned yet ⇒ NOTHING matches (this is the current state of
        // SHIELDED_SPEND_VKEY_HASH; the SP1 backend refuses to construct).
        assert!(!vkey_pin_ok("", VK));
        assert!(!vkey_pin_ok(SHIELDED_SPEND_VKEY_HASH, VK));
    }

    #[test]
    fn mismatched_vkey_is_rejected() {
        let other = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(!vkey_pin_ok(VK, other));
        // Malformed values never match.
        assert!(!vkey_pin_ok(VK, "0x1234"));
        assert!(!vkey_pin_ok(VK, ""));
        assert!(!vkey_pin_ok("not-a-hash", "not-a-hash"));
    }

    #[test]
    fn pinned_vkey_matches_itself_case_insensitively() {
        assert!(vkey_pin_ok(VK, VK));
        assert!(vkey_pin_ok(VK, &VK.to_uppercase().replace("0X", "0x")));
    }

    // ── mock prover refusal (audit P123 P-2) ──────────────────────────────────

    #[test]
    fn mock_prover_env_is_refused() {
        assert!(mock_prover_env_refused(Some("mock")));
        assert!(mock_prover_env_refused(Some("MOCK")));
        assert!(mock_prover_env_refused(Some(" mock ")));
        assert!(!mock_prover_env_refused(Some("cpu")));
        assert!(!mock_prover_env_refused(Some("cuda")));
        assert!(!mock_prover_env_refused(None));
    }
}
