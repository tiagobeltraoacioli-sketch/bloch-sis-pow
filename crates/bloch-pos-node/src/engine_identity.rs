// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure boot identity checks shared by the runtime and manifest tests.
use bloch_pos_committee::{beacon::RandaoChain, epoch_of, interfaces::StateReader, transition::CommittedState};

/// Verdict of the boot-time keystore identity gate ("gate 3").
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeystoreIdentity {
    /// The keystore is the manifest's validator at that index, and its local
    /// RANDAO chain opens the committed head.
    Ok,
    /// No manifest validator carries this (index, pubkey) pair.
    NotInGenesisSet,
    /// The validator is in the manifest, but the local RANDAO seed does not
    /// regenerate the committed commitment.
    RandaoMismatch,
}

/// The boot-time identity gate, extracted from `run` so it can be tested.
///
/// # This gate is the third thing blocking an open network, and it is
/// # independent of the verifier
///
/// A validator added by an on-chain deposit is, by construction, NOT in the
/// genesis manifest. So even once the verifier reads the registry and the
/// network can *count* a newcomer's votes, the newcomer's own node still
/// refuses to boot with `keystore does not match the genesis manifest's
/// validator set`. Fixing the verifier alone gets you a validator everyone
/// else can verify and that cannot start.
///
/// The root cause is the same one the verifier had: **identity is being read
/// from the genesis manifest instead of from the committed registry.** A
/// validator's index, key and RANDAO commitment are all committed state
/// (`ValidatorRecord`), and a deposit writes all three. The manifest is only
/// the registry's value at height 0.
///
/// **That fix is now made, in [`check_registry_identity`] below, and this
/// function is no longer authoritative.** It survives as a *fast pre-pass*
/// only: the registry is not reachable here (the store is not open, the log
/// and neither replay nor the local restart cache has reconstructed the
/// committed registry), so the authoritative check waits for state recovery. Keeping a cheap
/// manifest look first means a genesis operator who mistyped a seed still
/// learns it in a second instead of after a replay.
///
/// What changed is which verdicts are fatal. `NotInGenesisSet` is no longer
/// an error at all — it is the *normal and expected* state of every validator
/// the network will ever add by deposit, and refusing to boot on it is
/// precisely the wall that kept a deposit-added validator off the network.
/// It is now advisory, and [`check_registry_identity`] decides.
///
/// # One latent defect fixed in the extraction
///
/// The original read the RANDAO commitment as
/// `manifest.validators[keys.index as usize]` — indexing by POSITION after
/// having found the record by its `index` FIELD. Those coincide only while
/// the manifest is dense and sorted; otherwise it compares against another
/// validator's commitment, or panics out of bounds. This version uses the
/// record it already found. On the live fleet's dense manifest the two are
/// identical; everywhere else this one is correct and the old one was not.
/// (`Manifest::pubkeys()` carries the same position-vs-index assumption and
/// silently yields an EMPTY key for an out-of-range index — see
/// `genesis::tests::the_manifest_table_silently_empties_sparse_indices`.)
pub(crate) fn check_keystore_identity(
    manifest: &crate::genesis::Manifest,
    index: u32,
    pubkey: &[u8],
    randao_seed: [u8; 32],
) -> KeystoreIdentity {
    let Some(v) = manifest.validators.iter().find(|v| v.index == index) else {
        return KeystoreIdentity::NotInGenesisSet;
    };
    if v.pubkey != pubkey {
        return KeystoreIdentity::NotInGenesisSet;
    }
    if RandaoChain::generate(randao_seed).commitment() != v.randao_commitment {
        return KeystoreIdentity::RandaoMismatch;
    }
    KeystoreIdentity::Ok
}

/// Verdict of the authoritative, registry-backed identity gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegistryIdentity {
    /// The committed registry holds this index, it carries exactly this
    /// keystore's key, and the local RANDAO chain opens its committed
    /// commitment. Duties are armed.
    Active,
    /// Registered identity, but its exit has taken effect. Keep following
    /// the chain so automatic withdrawal can run when the lock matures.
    Inactive,
    /// The registry has no such index *yet*. Not an error: it is what a
    /// deposit-added validator looks like before its deposit is applied.
    /// Boot, follow the chain, sign nothing, re-check every slot.
    PendingActivation,
    /// The registry holds this index and it belongs to a DIFFERENT key.
    /// Fatal — see the double-signing note on [`check_registry_identity`].
    WrongValidator,
    /// The right key at the right index, but the local RANDAO seed does not
    /// regenerate the committed commitment. Fatal: this node cannot produce a
    /// reveal the network will accept, so every block it proposes is refused.
    RandaoMismatch,
}

/// The identity gate that actually decides, read from the **committed
/// registry** rather than from the genesis manifest.
///
/// # Why this had to move past replay
///
/// The committed registry is reconstructed by full replay or a compatible
/// local cache plus verified tail replay. At the point `run` loads the
/// keystore neither recovery path has run, so there is no registry to
/// consult — no `Store`, no log, no `Engine`. The only registry that exists
/// before replay is the manifest's, i.e. the height-0 one, which by
/// construction cannot contain anyone added since height 0. Any gate placed
/// there can only ever ask "were you in the genesis set?", which is the wrong
/// question. This one runs after replay, where `engine.state` is the registry
/// as of the node's own head. The weak-subjectivity gate already sets that
/// precedent for the same reason.
///
/// # Why absence must not be fatal, and why a mismatch must be
///
/// The two cases were one branch before, and collapsing them is what closed
/// the network:
///
/// - **Absent** means "your deposit has not been applied on this node's head
///   yet" — a newcomer that has just deposited, or one still replaying. It is
///   a temporary, self-healing condition, and the honest response is to
///   follow the chain and keep checking.
/// - **Present but a different key** means another validator already owns
///   this index. Signing there is signing *as them*: two conflicting messages
///   under one index is exactly the equivocation `slashing.rs` exists to
///   punish. This must refuse to boot, and it is the real safety value the
///   old gate was providing — preserved here, and now aimed at the case that
///   actually warrants it.
///
/// # The re-check is a safety requirement, not a convenience
///
/// It is tempting to conclude that pending-activation needs no machinery,
/// because `attest` and `propose` already return early when the index is not
/// in the roster they derive from committed state. That is true and it is not
/// sufficient. Indices are allocated `keys().next_back() + 1`, so an operator
/// whose keystore was minted for index 64 *before* depositing can be beaten
/// to index 64 by somebody else's deposit. The roster check would then pass —
/// the index is active — and this node would sign under a key that is not
/// its own. So the duty path re-checks the *key*, not just the index, every
/// time it is about to sign: see `Engine::duty_index`.
pub(crate) fn check_registry_identity(
    state: &CommittedState, index: u32, pubkey: &[u8], randao_seed: [u8; 32],
) -> RegistryIdentity {
    let Some(rec) = state.validator_record(index) else { return RegistryIdentity::PendingActivation };
    if rec.pubkey != pubkey { return RegistryIdentity::WrongValidator; }
    let mut chain = RandaoChain::generate(randao_seed);
    let mut commitment = chain.commitment();
    for _ in 0..state.validator_reveals_used(index).unwrap_or(0) {
        let Some(reveal) = chain.next_reveal() else { return RegistryIdentity::RandaoMismatch };
        commitment = reveal;
    }
    if commitment != rec.randao_commitment { return RegistryIdentity::RandaoMismatch; }
    if rec.activation_epoch > epoch_of(state.slot()) { return RegistryIdentity::PendingActivation; }
    if epoch_of(state.slot()) >= rec.exit_epoch { return RegistryIdentity::Inactive; }
    RegistryIdentity::Active
}
