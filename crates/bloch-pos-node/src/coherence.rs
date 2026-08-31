// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coherence shielded-proof verification for the Genesis-4 node.
//!
//! Port of the Genesis-3 verifier (commit `407cffc`, branch `feat/zk-ledger`,
//! `legacy/genesis3-node/src/coherence/verifier.rs`) onto the PoS node,
//! adapted to sp1-sdk 6.5.0 (blocking API — the same SDK the measurement
//! harness `crates/coherence-prover/measure/` runs).
//!
//! # This module is DOUBLY INERT
//!
//! It is `pub` and has **no callers**, deliberately, until the application
//! items land:
//!
//! 1. **No wire surface.** The Genesis-4 node has no shielded-transaction tag:
//!    nothing in `codec.rs`/`p2p.rs` can even carry a `ShieldedTx`, so there
//!    is no code path that could reach [`ShieldedVerifier::verify`].
//! 2. **Fail-closed by default even when called.** Every layer defaults to
//!    reject: built without the `sp1-verify` feature the only backend is
//!    [`ShieldedVerifier::RejectAll`]; built with it but without
//!    `BLOCH_SHIELDED_VERIFY=sp1` the default is still `RejectAll`; requested
//!    but unable to initialize (missing ELF, pin mismatch) it logs loudly and
//!    falls back to `RejectAll`. There is no shortcut accept anywhere.
//!
//! # Consensus notes (carried over from the Genesis-3 port, still binding)
//!
//! - `verify` is a **pure function of `(public, proof)`** — no clock, no
//!   network state, no randomness. Two honest nodes given the same inputs
//!   return the same bool. Under Genesis-4 that purity is what lets the check
//!   sit on the block-validation path at all (interfaces.rs §"pure function of
//!   committed state" rule).
//! - The prover client is built with the **explicit `.cpu()` builder, never
//!   `ProverClient::from_env()`**: `SP1_PROVER=mock` must not be able to swap
//!   in an accepting mock verifier. An environment variable must never be able
//!   to weaken consensus.
//! - [`sp1_backend::PINNED_ELF_SHAKE256_HEX`] is the compiled-in consensus pin
//!   and **beats the env**; while it is `None` the verifier is dev-grade and
//!   says so at startup.
//!
//! # Boundary rule: `bloch-pos-committee` NEVER links sp1-sdk
//!
//! The committee crate takes capabilities by trait (`interfaces.rs`:
//! `KeyVerifier` is how the PQ signature suite enters without the committee
//! linking the PQClean FFI tree). Shielded-proof verification enters the same
//! way: the committee-facing wiring, when it exists, consumes
//! [`ShieldedProofVerifier`] as a trait object supplied by this binary — the
//! heavy `sp1-sdk` dependency stays behind this module's feature gate, in the
//! node, only.

// This module is intentionally uncalled until the shielded-tx application
// items land (wire tag, mempool admission, block validation hook). Remove
// this allow in the commit that wires the first caller.
#![allow(dead_code)]

use coherence_core::SpendPublic;

/// The capability boundary through which shielded-proof verification will be
/// handed to consensus wiring — the `interfaces.rs` pattern: consumers depend
/// on this trait, never on `sp1-sdk`.
///
/// Object-safe on purpose (`&dyn ShieldedProofVerifier`), like `KeyVerifier`.
pub trait ShieldedProofVerifier: Send + Sync {
    /// Verify `proof` against the public inputs of one shielded spend.
    /// `false` rejects the transaction. Must be a pure function of the
    /// arguments — see the module docs.
    fn verify_spend(&self, public: &SpendPublic, proof: &[u8]) -> bool;
}

/// Which SP1 proof modes the node admits — THE single configurable decision
/// point for the mode check ([`sp1_backend::mode_admitted`] is its only
/// consumer).
///
/// Background, and why this is a policy value instead of the Genesis-3 port's
/// hard-coded `matches!(proof, SP1Proof::Core(_))`:
///
/// - What C1 §3 forbids is **pairing-based wraps** (Plonk/Groth16 over
///   BN254). Those are rejected under EVERY policy, unconditionally — no
///   variant of this enum admits them, so extending the enum can never
///   reintroduce pairings by accident.
/// - `Compressed` is **FRI recursion**: a STARK verifying a STARK,
///   hash-based, post-quantum. It is NOT the wrap C1 §3 forbids. The
///   measurement (`docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md`) puts it at
///   1.21 MiB constant-size vs Core's 2.66 MiB — 2.43x vs 5.32x of
///   `MAX_BLOCK_TX_BYTES_V2` — which is why it is under evaluation: neither
///   mode fits a block today, and Compressed is the only candidate that could
///   ever get close.
/// - **ADVISOR-D owns the decision** on whether Compressed is acceptable
///   (verifier cost, recursion-circuit trust surface, artifact provenance).
///   Until that ruling lands, [`PROOF_MODE_POLICY`] stays `CoreOnly`. Do not
///   flip the default here without it.
///
/// The policy is a **compiled constant**, not an env var: which proofs are
/// valid is a consensus rule, and (same principle as the ELF pin and the
/// `.cpu()` builder) the environment must not be able to change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofModePolicy {
    /// Only raw core STARK/FRI proofs (the 407cffc behaviour).
    CoreOnly,
    /// Core plus FRI-recursion (`Compressed`) proofs. NOT the default —
    /// pending the ADVISOR-D ruling described above.
    CoreOrCompressed,
}

/// The compiled-in mode policy every verifier built by [`ShieldedVerifier::
/// from_env`] uses. Changing this value is a consensus change.
pub const PROOF_MODE_POLICY: ProofModePolicy = ProofModePolicy::CoreOnly;

/// How the node verifies shielded-spend proofs.
#[derive(Debug, Clone, Default)]
pub enum ShieldedVerifier {
    /// Reject every shielded proof — the safe default at every layer.
    #[default]
    RejectAll,
    /// Verify the raw FRI proof with SP1 (feature `sp1-verify`). `Arc`
    /// because the SP1 client + vkey are heavy and not `Clone`-cheap; the
    /// enum stays cheap to clone into every validation context.
    #[cfg(feature = "sp1-verify")]
    Sp1(std::sync::Arc<sp1_backend::Sp1Verifier>),
}

impl ShieldedVerifier {
    /// Verify `proof` against the public inputs. `false` rejects the tx.
    pub fn verify(&self, public: &SpendPublic, proof: &[u8]) -> bool {
        match self {
            // Without the feature this arm is the whole function; touch the
            // arguments so the signature stays identical (and warning-free)
            // across both feature states.
            ShieldedVerifier::RejectAll => {
                let _ = (public, proof);
                false
            }
            #[cfg(feature = "sp1-verify")]
            ShieldedVerifier::Sp1(v) => v.verify(public, proof),
        }
    }

    /// Build from configuration. `BLOCH_SHIELDED_VERIFY=sp1` selects the SP1
    /// backend when compiled with `--features sp1-verify`; anything else (and
    /// any build without the feature) keeps the safe `RejectAll` default. If
    /// SP1 was requested but cannot initialize (missing/unreadable ELF,
    /// pinned-hash mismatch), we log and FALL BACK to `RejectAll` — never a
    /// shortcut accept.
    ///
    /// Note the asymmetry with the `.cpu()`/pin rules: the env may choose to
    /// verify LESS (stay at `RejectAll`) but can never make verification more
    /// permissive — the backend selected here still enforces the compiled
    /// [`PROOF_MODE_POLICY`] and the compiled ELF pin.
    pub fn from_env() -> Self {
        match std::env::var("BLOCH_SHIELDED_VERIFY").ok().as_deref() {
            #[cfg(feature = "sp1-verify")]
            Some("sp1") => match sp1_backend::Sp1Verifier::from_env(PROOF_MODE_POLICY) {
                Ok(v) => ShieldedVerifier::Sp1(std::sync::Arc::new(v)),
                Err(e) => {
                    eprintln!(
                        "coherence: BLOCH_SHIELDED_VERIFY=sp1 requested but the SP1 verifier \
                         failed to initialize: {e}. Falling back to RejectAll — ALL shielded \
                         txs will be rejected on this node until fixed."
                    );
                    ShieldedVerifier::RejectAll
                }
            },
            _ => ShieldedVerifier::RejectAll,
        }
    }

    /// Whether any shielded proof could be accepted at all on this node.
    pub fn is_active(&self) -> bool {
        !matches!(self, ShieldedVerifier::RejectAll)
    }
}

impl ShieldedProofVerifier for ShieldedVerifier {
    fn verify_spend(&self, public: &SpendPublic, proof: &[u8]) -> bool {
        self.verify(public, proof)
    }
}

// The real SP1/FRI verifier — compiled only under `sp1-verify` (pulls
// sp1-sdk 6.5.0, default-features = false + "blocking": no alloy/tonic remote
// proving stack, no tokio-runtime requirement on the caller).
#[cfg(feature = "sp1-verify")]
pub mod sp1_backend {
    use super::{ProofModePolicy, SpendPublic};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    use sp1_sdk::blocking::{Prover, ProverClient};
    use sp1_sdk::{
        Elf, ProvingKey as _, SP1ProofMode, SP1ProofWithPublicValues, SP1VerifyingKey,
    };

    /// CONSENSUS PIN (freeze before any activation): SHAKE-256 digest (hex,
    /// 64 chars) of the guest ELF every node must verify against. The vkey —
    /// and therefore which shielded txs are valid — is a deterministic
    /// function of the guest ELF; a divergent ELF is a silent hard-fork, and
    /// under Genesis-4 there is no PoW depth to eventually expose it — the
    /// divergent node just stops finalizing with everyone else. While `None`,
    /// the pin can be supplied via `BLOCH_SP1_ELF_SHAKE256` (dev/test);
    /// running fully unpinned only logs a loud warning.
    ///
    /// The compiled constant WINS over the env var: an environment variable
    /// must not be able to override a frozen consensus rule.
    ///
    /// What has to exist before this stops being `None`:
    /// 1. a REPRODUCIBLE guest build (`cargo prove build` of
    ///    `crates/coherence-prover/program` pinned to one cargo-prove /
    ///    toolchain release, verified bit-identical from two independent
    ///    machines);
    /// 2. the ELF published where the fleet fetches artifacts, with its
    ///    SHAKE-256 recorded in the release notes;
    /// 3. the ADVISOR-D proof-mode ruling (the pin freezes which proofs
    ///    verify; freezing it before the mode decision would freeze the wrong
    ///    surface).
    pub const PINNED_ELF_SHAKE256_HEX: Option<&str> = None;

    /// Upper bound on serialized proof bytes we will even attempt to decode
    /// (DoS guard). Sized from the 2026-08-29 measurement: core proofs are
    /// ~2.70 MiB and compressed ~1.21 MiB, both effectively constant in the
    /// number of spend inputs/outputs, so 32 MiB is an order of magnitude of
    /// headroom without letting a peer feed us a multi-GiB decode.
    const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;

    fn shake256_32(data: &[u8]) -> [u8; 32] {
        let mut h = Shake256::default();
        h.update(data);
        let mut xof = h.finalize_xof();
        let mut out = [0u8; 32];
        xof.read(&mut out);
        out
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// THE mode check — sole consumer of [`super::ProofModePolicy`], and the
    /// single place in the codebase that decides which SP1 proof modes are
    /// admissible. Pairing-based wraps (Plonk/Groth16, C1 §3) are rejected
    /// under every policy; `Compressed` (FRI recursion — STARK, post-quantum)
    /// is admitted only under `CoreOrCompressed`, which is not the default
    /// pending the ADVISOR-D ruling (see the policy enum's docs).
    pub fn mode_admitted(policy: ProofModePolicy, mode: SP1ProofMode) -> bool {
        match mode {
            SP1ProofMode::Core => true,
            SP1ProofMode::Compressed => matches!(policy, ProofModePolicy::CoreOrCompressed),
            // Never: BN254 pairings (C1 §3), plus these paths pull SP1's
            // gnark artifact download machinery the node must not depend on.
            SP1ProofMode::Plonk | SP1ProofMode::Groth16 => false,
        }
    }

    pub struct Sp1Verifier {
        /// Explicit CPU prover client. NEVER built via
        /// `ProverClient::from_env()`: `SP1_PROVER=mock` would swap in the
        /// mock verifier, which accepts mock proofs — an environment variable
        /// must not be able to weaken consensus.
        client: sp1_sdk::blocking::CpuProver,
        /// The guest program's verifying key, derived once from the ELF at
        /// startup (`client.setup`) and cached — never re-derived per tx.
        vkey: SP1VerifyingKey,
        /// SHAKE-256 of the loaded guest ELF (logged; checked against the pin).
        elf_shake256: [u8; 32],
        /// Compiled-in mode policy ([`super::PROOF_MODE_POLICY`] in
        /// production; parameterized so tests can exercise both values).
        policy: ProofModePolicy,
    }

    // CpuProver/SP1VerifyingKey aren't Debug; identify by the ELF digest.
    impl std::fmt::Debug for Sp1Verifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Sp1Verifier")
                .field("elf_shake256", &hex_lower(&self.elf_shake256))
                .field("policy", &self.policy)
                .finish_non_exhaustive()
        }
    }

    impl Sp1Verifier {
        /// Load the guest ELF from `BLOCH_SP1_ELF_PATH` (default
        /// `coherence-spend.elf` next to the binary — the ELF is a build
        /// artifact of `cargo prove build` in `crates/coherence-prover/
        /// program`, shipped/CI-published alongside the node; the node build
        /// itself must NOT require the SP1 RISC-V toolchain), hash-check it,
        /// and derive + cache the verifying key. Errors (not panics) so
        /// `from_env` can fall back to the safe `RejectAll`.
        pub fn from_env(policy: ProofModePolicy) -> Result<Self, String> {
            let elf_path = std::env::var("BLOCH_SP1_ELF_PATH")
                .unwrap_or_else(|_| "coherence-spend.elf".into());
            let elf = std::fs::read(&elf_path)
                .map_err(|e| format!("cannot read guest ELF at {elf_path}: {e}"))?;
            let elf_shake256 = shake256_32(&elf);
            let digest_hex = hex_lower(&elf_shake256);

            // Consensus pin: the compiled-in constant wins (an env var must
            // not be able to override a frozen consensus rule); the env pin
            // is the dev/test stand-in until the constant is frozen.
            let pin = PINNED_ELF_SHAKE256_HEX
                .map(str::to_owned)
                .or_else(|| std::env::var("BLOCH_SP1_ELF_SHAKE256").ok());
            match pin {
                Some(expected) => {
                    let expected = expected.trim().to_ascii_lowercase();
                    if expected != digest_hex {
                        return Err(format!(
                            "guest ELF SHAKE-256 mismatch at {elf_path}: expected {expected}, \
                             got {digest_hex} — refusing to activate (a divergent guest ELF is \
                             a silent hard-fork)"
                        ));
                    }
                }
                None => eprintln!(
                    "coherence: WARNING — SP1 guest ELF at {elf_path} is UNPINNED \
                     (shake256={digest_hex}). Dev only: freeze PINNED_ELF_SHAKE256_HEX (or set \
                     BLOCH_SP1_ELF_SHAKE256) before any network activation — nodes with \
                     divergent ELFs silently hard-fork."
                ),
            }

            let client = ProverClient::builder().cpu().build();
            // setup() derives the proving key; the node only ever verifies —
            // we keep the vkey and drop the rest.
            let pk = client
                .setup(Elf::from(elf))
                .map_err(|e| format!("SP1 setup on the guest ELF failed: {e}"))?;
            let vkey = pk.verifying_key().clone();
            drop(pk);
            eprintln!(
                "coherence: SP1 shielded-proof verifier active: elf={elf_path} \
                 shake256={digest_hex} policy={policy:?}"
            );
            Ok(Self { client, vkey, elf_shake256, policy })
        }

        /// Verify the raw FRI proof and check its committed public values
        /// equal `public`. Returns true only if ALL hold:
        ///   1. `proof` decodes as an `SP1ProofWithPublicValues` — bincode-1
        ///      fixint wire format, i.e. bincode-2 `config::legacy()`,
        ///      matching what the prover emits (`measure/host` serializes
        ///      with bincode 1) — NOT `standard()`/varint;
        ///   2. its mode passes [`mode_admitted`] under the compiled policy
        ///      (default: raw core STARK/FRI only);
        ///   3. the FRI verification passes against the cached vkey;
        ///   4. the guest-committed public values decode (fully — no trailing
        ///      bytes) to exactly `public` (the bind check: a valid proof for
        ///      a DIFFERENT spend must not be replayable against this one).
        /// Any failure returns `false` (never panics).
        pub fn verify(&self, public: &SpendPublic, proof: &[u8]) -> bool {
            if proof.len() > MAX_PROOF_BYTES {
                return false;
            }
            let cfg = bincode::config::legacy();
            // (1) decode the proof envelope (bincode-1-compatible fixint).
            let Ok((proof, _)) =
                bincode::serde::decode_from_slice::<SP1ProofWithPublicValues, _>(proof, cfg)
            else {
                return false;
            };
            // (2) proof-mode policy — the single configurable point.
            if !mode_admitted(self.policy, SP1ProofMode::from(&proof.proof)) {
                return false;
            }
            // (3) the actual FRI verification (also checks the committed-value
            // digest against the public-values stream and the SP1 version
            // tag). `None` = require the success status code.
            if self.client.verify(&proof, &self.vkey, None).is_err() {
                return false;
            }
            // (4) bind check: the guest committed exactly one SpendPublic via
            // sp1_zkvm::io::commit (bincode-1 fixint); decode it back and
            // require exact equality + full consumption. Field-by-field
            // because coherence-core's SpendPublic does not derive PartialEq
            // and that crate is frozen to other owners (DEV-1/DEV-2) — do not
            // "fix" this by deriving it there.
            let pv = proof.public_values.as_slice();
            match bincode::serde::decode_from_slice::<SpendPublic, _>(pv, cfg) {
                Ok((committed, consumed)) if consumed == pv.len() => {
                    committed.anchor == public.anchor
                        && committed.nullifiers == public.nullifiers
                        && committed.out_commitments == public.out_commitments
                        && committed.fee == public.fee
                }
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env-touching tests below mutate process-global state; the default
    /// parallel test runner would let them race. Every test that reads or
    /// writes `BLOCH_*` env vars holds this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn pub_() -> SpendPublic {
        SpendPublic { anchor: [0; 32], nullifiers: vec![], out_commitments: vec![], fee: 0 }
    }

    #[test]
    fn default_rejects_all() {
        let v = ShieldedVerifier::default();
        assert!(!v.verify(&pub_(), &[1, 2, 3]));
        assert!(!v.is_active());
        // And through the trait boundary the committee wiring will use.
        let dyn_v: &dyn ShieldedProofVerifier = &v;
        assert!(!dyn_v.verify_spend(&pub_(), &[1, 2, 3]));
    }

    #[test]
    fn compiled_default_policy_is_core_only() {
        // ADVISOR-D has not ruled on Compressed; the default must stay
        // CoreOnly until that decision is recorded. This test is the tripwire.
        assert_eq!(PROOF_MODE_POLICY, ProofModePolicy::CoreOnly);
    }

    #[test]
    fn from_env_without_request_is_reject_all() {
        let _env = ENV_LOCK.lock().unwrap();
        // Without BLOCH_SHIELDED_VERIFY=sp1 the default is always RejectAll,
        // with or without the feature.
        std::env::remove_var("BLOCH_SHIELDED_VERIFY");
        assert!(!ShieldedVerifier::from_env().is_active());
    }

    #[cfg(not(feature = "sp1-verify"))]
    #[test]
    fn from_env_without_feature_is_reject_all_even_when_requested() {
        let _env = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCH_SHIELDED_VERIFY", "sp1");
        assert!(!ShieldedVerifier::from_env().is_active());
        std::env::remove_var("BLOCH_SHIELDED_VERIFY");
    }

    /// With the feature compiled in but no readable guest ELF, requesting sp1
    /// must FALL BACK to RejectAll (fail-closed), never panic or accept.
    #[cfg(feature = "sp1-verify")]
    #[test]
    fn sp1_with_missing_elf_falls_back_to_reject_all() {
        let _env = ENV_LOCK.lock().unwrap();
        std::env::set_var("BLOCH_SHIELDED_VERIFY", "sp1");
        std::env::set_var("BLOCH_SP1_ELF_PATH", "/nonexistent/coherence-spend.elf");
        let v = ShieldedVerifier::from_env();
        assert!(!v.is_active());
        assert!(!v.verify(&pub_(), &[1, 2, 3]));
        std::env::remove_var("BLOCH_SHIELDED_VERIFY");
        std::env::remove_var("BLOCH_SP1_ELF_PATH");
    }

    /// The mode check itself: pairings never pass; Compressed only under the
    /// non-default policy; Core always.
    #[cfg(feature = "sp1-verify")]
    #[test]
    fn mode_policy_single_point() {
        use super::sp1_backend::mode_admitted;
        use sp1_sdk::SP1ProofMode as M;
        for policy in [ProofModePolicy::CoreOnly, ProofModePolicy::CoreOrCompressed] {
            assert!(mode_admitted(policy, M::Core));
            assert!(!mode_admitted(policy, M::Plonk), "pairings admitted under {policy:?}");
            assert!(!mode_admitted(policy, M::Groth16), "pairings admitted under {policy:?}");
        }
        assert!(!mode_admitted(ProofModePolicy::CoreOnly, M::Compressed));
        assert!(mode_admitted(ProofModePolicy::CoreOrCompressed, M::Compressed));
    }
}
