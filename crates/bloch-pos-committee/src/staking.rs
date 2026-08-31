// SPDX-License-Identifier: AGPL-3.0-or-later

//! Staking lifecycle — deposit, exit, withdrawal, and the activation queue
//! (§7 of the migration design), with the §4.1 eligibility rules enforced at
//! the deposit boundary.
//!
//! ## What is enforced here and why
//!
//! - **Deposits spend transparent inputs only** (§6.6.3). A validator's bond
//!   must be attributable: slashing and the concentration gates both need a
//!   bond that traces to visible coins, so a deposit funded from the shielded
//!   pool would be stake with no owner on record. This is an attributability
//!   rule, not a coin-class rule — the §4.1 taint set it used to feed is
//!   retired (the carryover crosses as one undifferentiated set), and a
//!   carried-over balance that is liquid is also stakeable, the founder's
//!   included (founder decision, 2026-08-11).
//! - **Proof of possession under BOTH halves of the hybrid suite** (§6.2:
//!   "AND, not OR"). The AND-composition lives in *this* crate, not in the
//!   injected verifier, so a caller cannot accidentally weaken the hybrid to
//!   whichever half its verifier happens to implement. Without a PoP at all, a
//!   rogue-key registration could claim someone else's key material.
//! - **At most [`MAX_ACTIVATIONS_PER_EPOCH`] activations per epoch** (§4.1.4).
//!   The committee is stake-weighted, so instant activation is instant
//!   control; the queue makes materialising a majority take many epochs and be
//!   visible while it happens. (Honest limit, from the spec: this raises the
//!   cost and visibility of capture, it does not prevent it — it is
//!   Sybil-gameable by splitting stake.)
//! - **Withdrawal only after [`WITHDRAWAL_DELAY_EPOCHS`]** (§7.2). This is
//!   the weak-subjectivity margin, not an arbitrary cooling-off period: after
//!   the stake is returned, an exited validator can sign a conflicting history
//!   at zero cost, so the delay must exceed the window in which any client
//!   could be convinced by such a history. A client offline longer than the
//!   delay must resync from a trusted checkpoint; a client offline less than
//!   the delay is safe because the equivocator's stake was still slashable.
//!
//! ## What is deliberately NOT here
//!
//! Signature verification. Like `attestation.rs`, this crate takes verifiers
//! through traits so the committee logic is testable without dragging in the
//! PQClean C FFI stack, and so the choice of implementation stays a caller
//! decision. The crate still owns the *rules about* signatures: the hybrid
//! split points, the AND-composition, and the signing roots.

use crate::params::{DS_DEPOSIT, DS_EXIT};
use sha3::{Digest, Sha3_256};

// ---------------------------------------------------------------------------
// Suite geometry (§6.2). These are properties of the frozen signature
// arrangement, restated here so the split points are consensus constants of
// this module rather than implicit knowledge of the injected verifier.
// ---------------------------------------------------------------------------

/// Suite tag of the one arrangement every consensus role uses (§6.2).
/// `SUITE_MLDSA65_ONLY = 0x0002` exists as an escape hatch but is NOT valid
/// for staking: a deposit under a single-family suite would silently drop the
/// hybrid property for that validator's entire consensus lifetime.
pub const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;

/// ML-DSA-65 public key size in bytes.
pub const MLDSA65_PK_BYTES: usize = 1952;
/// Falcon-1024 public key size in bytes.
pub const FALCON1024_PK_BYTES: usize = 1793;
/// Hybrid public key: ML-DSA-65 pk ‖ Falcon-1024 pk (§7.1's `[u8; 3745]`).
pub const HYBRID_PK_BYTES: usize = MLDSA65_PK_BYTES + FALCON1024_PK_BYTES;

/// ML-DSA-65 signatures are fixed-size; Falcon-1024 signatures are variable
/// (~1,280 B). The hybrid signature is therefore split positionally: the first
/// [`MLDSA65_SIG_BYTES`] are the ML-DSA half, everything after is the Falcon
/// half. A length prefix would allow two encodings of the same signature;
/// a fixed split point allows exactly one.
pub const MLDSA65_SIG_BYTES: usize = 3309;

// ---------------------------------------------------------------------------
// Lifecycle constants (§5.1). All epochs; one epoch = 32 slots ≈ 16 min.
// ---------------------------------------------------------------------------

/// Satoshis per BLCH, mirrored from `tokenomics_v4` to keep the constant next
/// to the values it scales.
pub const SAT_PER_BLOCH: u128 = crate::tokenomics_v4::SAT_PER_BLOCH;

/// Minimum deposit: 25,000 BLCH (founder decision, 2026-08-12; was 100,000
/// under the 21 B supply).
///
/// Sized against Ethereum's bond as a fraction of supply: 32 ETH is 2.66e-7 of
/// ETH's ~120.45 M supply, and the same fraction of the 100 B supply is
/// ~26,567 BLCH. Rounded **down** to 25,000 — exactly `supply / 4,000,000` —
/// on purpose: down is cheaper, and cheaper widens who *may* validate, which
/// is the only direction a rounding choice on a bond should ever err. A pure
/// x100/21 split of the old 100,000 floor would have landed at 476,190.47
/// (not an integer, and 19x the Ethereum-equivalent bond), so this constant
/// deliberately does NOT follow the split — it is re-derived from the
/// benchmark instead.
///
/// Honest scope, from the CertiK brief: lowering the bond widens who MAY
/// validate and does nothing about who DOES. It is not a fix for stake
/// concentration and must not be described as one.
pub const MIN_DEPOSIT_SAT: u128 = 25_000 * SAT_PER_BLOCH;

/// Epochs between a deposit being included and it becoming eligible for the
/// activation queue (§5.1: ~2.1 h). Exists so the validator set used by epoch
/// N is fully determined before N starts — a deposit can never change the
/// committee of the epoch that includes it.
pub const ACTIVATION_DELAY_EPOCHS: u64 = 8;

/// Validators admitted from the activation queue per epoch (§4.1.4). Four per
/// epoch means even an attacker with unlimited eligible coins needs
/// `set_size / 4` epochs of publicly visible queue traffic to take a majority.
pub const MAX_ACTIVATIONS_PER_EPOCH: usize = 4;

/// Epochs between a voluntary exit and the validator no longer being assigned
/// duties (§5.1: ~8.5 h). Non-zero so an exit cannot be used to dodge duties
/// — or slashing for duties already assigned — within the same epoch.
pub const EXIT_DELAY_EPOCHS: u64 = 32;

/// Epochs between a voluntary exit and the stake becoming spendable
/// (§5.1, §7.2: 2,048 ≈ 22.8 days). This is the weak-subjectivity margin —
/// see the module docs. It must exceed the longest window in which an exited
/// validator could sign a conflicting history "for free"; shortening it is a
/// consensus-security decision, not a UX tweak.
pub const WITHDRAWAL_DELAY_EPOCHS: u64 = 2048;

// ---------------------------------------------------------------------------
// Injected verification
// ---------------------------------------------------------------------------

/// Injected verification of the two halves of the hybrid suite over a raw
/// public key. Distinct from `attestation::SignatureVerifier`, which is keyed
/// by validator index: at deposit time the key is not registered yet, so
/// verification must run against the bytes in the transaction itself.
///
/// The trait exposes the halves *separately* on purpose: the AND-composition
/// (§6.2 "both must pass") is enforced by this module, so no implementation
/// can turn the hybrid into an OR by construction.
pub trait HybridKeyVerifier {
    /// Verify the ML-DSA-65 half. `pubkey` is exactly [`MLDSA65_PK_BYTES`].
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
    /// Verify the Falcon-1024 half. `pubkey` is exactly [`FALCON1024_PK_BYTES`].
    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
}

/// Verify a hybrid signature over `signing_root` for a hybrid pubkey,
/// enforcing the fixed split points and the AND rule.
///
/// `pub(crate)` — not private — because the weak-subjectivity envelope
/// ([`crate::ws`]) verifies the same hybrid arrangement over raw pubkeys, and
/// a second copy of the AND-composition would be a second place for the OR
/// bug to enter. One derivation path, called from both sites.
pub(crate) fn verify_hybrid(
    pubkey: &[u8; HYBRID_PK_BYTES],
    signing_root: &[u8; 32],
    sig: &[u8],
    verifier: &dyn HybridKeyVerifier,
) -> bool {
    // A signature with no room for a Falcon half is malformed, not "a valid
    // ML-DSA-only signature" — rejecting it here is what keeps the escape
    // hatch (`SUITE_MLDSA65_ONLY`) an explicit decision rather than a parsing
    // accident.
    if sig.len() <= MLDSA65_SIG_BYTES {
        return false;
    }
    let (mldsa_pk, falcon_pk) = pubkey.split_at(MLDSA65_PK_BYTES);
    let (mldsa_sig, falcon_sig) = sig.split_at(MLDSA65_SIG_BYTES);
    // AND, not OR (§6.2). Short-circuiting is safe: validity requires both
    // halves, so the first failure already decides the outcome, and this is a
    // verification path, not a signing path — there is no secret here for a
    // timing side channel to leak.
    verifier.verify_mldsa65(mldsa_pk, signing_root, mldsa_sig)
        && verifier.verify_falcon1024(falcon_pk, signing_root, falcon_sig)
}

// ---------------------------------------------------------------------------
// Deposit (§7.1)
// ---------------------------------------------------------------------------

/// Address the stake returns to. Committed at deposit time and never taken
/// from a later transaction: the validator key is a hot, online key, and a
/// compromise of it must not be able to redirect the principal.
pub type Address = [u8; 32];

/// What the deposit's inputs look like to consensus. The crate does not
/// depend on the node's UTXO types; the caller resolves each spent output
/// against the ledger and reports the facts that matter here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositInput {
    /// False for shielded (Coherence) outputs. Deposits must be transparent
    /// (§6.6.3) — stake must be attributable.
    pub transparent: bool,
    /// Retained-inert. The §4.1 taint set this bit used to report is retired
    /// (§4 of the migration design, rewritten): in Genesis-4 the set is
    /// **empty** and no eligibility oracle may produce `true`. The carryover —
    /// the founder's balance included — crosses liquid, and a liquid balance
    /// is also stakeable (founder decision, 2026-08-11). The field and its
    /// reject variant survive only because the admission interface is frozen
    /// (`interfaces.rs`: "`Tainted` variants are never produced") and the
    /// fail-closed direction must stay testable; repopulating the set would
    /// resurrect the exclusion power §4 deliberately dissolved.
    pub tainted: bool,
}

/// `DEPOSIT` transaction (§7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositTx {
    /// Suite tag; must equal [`SUITE_MLDSA65_FALCON1024`].
    pub suite: u16,
    /// Stake amount in satoshis. `u128` even though `u64` would fit today:
    /// every product with a basis-point factor overflows `u64` near the top of
    /// the supply range, and mixed-width stake arithmetic is how silent
    /// truncation bugs enter consensus. The rest of the crate (delegation,
    /// tokenomics) is already `u128`-native.
    pub amount_sat: u128,
    /// Hybrid public key, ML-DSA-65 ‖ Falcon-1024 (§6.2). One key pair serves
    /// identity, proposal and attestation — there is no separate attestation
    /// key because there is no separate attestation algorithm.
    pub validator_pubkey: [u8; HYBRID_PK_BYTES],
    /// RANDAO commitment `c_0` (§6.3) — the head of the validator's hash
    /// chain, committed up front so reveals can be checked by preimage.
    pub randao_commitment: [u8; 32],
    /// Where the stake returns after withdrawal. See [`Address`] for why this
    /// is fixed here and not supplied at withdrawal time.
    pub withdrawal_addr: Address,
    /// Hybrid signature (≈4,589 B) over [`DepositTx::signing_root`], proving
    /// possession of BOTH private keys. Without it, an attacker could register
    /// a pubkey derived from someone else's (rogue-key) or register a key it
    /// cannot use, bricking a queue slot.
    pub proof_of_possession: Vec<u8>,
}

impl DepositTx {
    /// Domain-separated SHA3-256 root the PoP signs:
    /// `SHA3-256(DS_DEPOSIT ‖ fields)` (§7.1).
    ///
    /// Every field is fixed-width, so no two distinct deposits serialize to
    /// the same bytes — the same argument `AttestationData::signing_root`
    /// makes. The PoP itself is excluded, obviously: a signature cannot cover
    /// itself.
    pub fn signing_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_DEPOSIT);
        h.update(self.suite.to_le_bytes());
        h.update(self.amount_sat.to_le_bytes());
        h.update(self.validator_pubkey);
        h.update(self.randao_commitment);
        h.update(self.withdrawal_addr);
        h.finalize().into()
    }
}

/// Why a deposit was rejected. Distinct variants for the same reason
/// `attestation::RejectReason` has them: "invalid" alone makes a divergence
/// undebuggable from logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositReject {
    /// Suite tag is not [`SUITE_MLDSA65_FALCON1024`].
    WrongSuite,
    /// An input is a shielded output (§6.6.3).
    ShieldedInput,
    /// An input the eligibility oracle reported as tainted. **Never produced
    /// in Genesis-4** — the taint set is empty and a liquid carried-over
    /// balance is stakeable (founder decision, 2026-08-11); see
    /// [`DepositInput::tainted`] for why the variant survives.
    TaintedInput,
    /// Amount below [`MIN_DEPOSIT_SAT`].
    BelowMinimum,
    /// Amount above the per-validator cap the caller derived from committed
    /// state (§4.1.3).
    AboveMaximum,
    /// Proof of possession failed — malformed, or either half of the hybrid
    /// did not verify.
    BadProofOfPossession,
}

/// Validate a `DEPOSIT` against §7.1 and §4.1.
///
/// `max_stake_sat` is a parameter, not a constant, because
/// `MAX_VALIDATOR_STAKE` is defined as 1% of *active stake* (§4.1.3) — a value
/// that lives in the parent block's committed state. This crate obeys the
/// §5.5 rule (no consensus value from node-local mutable state), so the
/// caller derives the cap (e.g. `delegation::Registry::cap_sat`, floored at
/// [`MIN_DEPOSIT_SAT`] at genesis where active stake is zero and a naive 1%
/// cap would deadlock the bootstrap) and passes it in explicitly.
///
/// Check order is cheapest-first, the same DoS argument `attestation::validate`
/// makes: verifying a 4.6 KB hybrid signature costs far more than every other
/// check combined, so spam must be rejected before the PoP runs.
pub fn validate_deposit(
    tx: &DepositTx,
    inputs: &[DepositInput],
    max_stake_sat: u128,
    verifier: &dyn HybridKeyVerifier,
) -> Result<(), DepositReject> {
    if tx.suite != SUITE_MLDSA65_FALCON1024 {
        return Err(DepositReject::WrongSuite);
    }
    // Shielded before tainted: a shielded input has no public ancestry, so
    // its taint status is unknowable — reporting it as "tainted" would imply
    // the taint check ran, which it cannot.
    if inputs.iter().any(|i| !i.transparent) {
        return Err(DepositReject::ShieldedInput);
    }
    if inputs.iter().any(|i| i.tainted) {
        return Err(DepositReject::TaintedInput);
    }
    if tx.amount_sat < MIN_DEPOSIT_SAT {
        return Err(DepositReject::BelowMinimum);
    }
    if tx.amount_sat > max_stake_sat {
        return Err(DepositReject::AboveMaximum);
    }
    if !verify_hybrid(&tx.validator_pubkey, &tx.signing_root(), &tx.proof_of_possession, verifier)
    {
        return Err(DepositReject::BadProofOfPossession);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Activation queue (§4.1.4)
// ---------------------------------------------------------------------------

/// A validated deposit waiting for activation, as committed in state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuedDeposit {
    /// SHA3-256 of the hybrid pubkey — 32 bytes of identity instead of 3,745.
    pub pubkey_hash: [u8; 32],
    /// Epoch of the block that included the deposit.
    pub deposit_epoch: u64,
    pub amount_sat: u128,
}

impl QueuedDeposit {
    /// Deterministic queue order: by deposit epoch, then pubkey hash. Never by
    /// position in the input slice — that was a real consensus bug in the
    /// sampling path, where the committee depended on how the caller happened
    /// to lay the registry out in memory. The pubkey hash is a tiebreak no
    /// participant controls cheaply: grinding a low hash costs a keypair per
    /// attempt and buys at most intra-epoch ordering.
    fn queue_key(&self) -> (u64, [u8; 32]) {
        (self.deposit_epoch, self.pubkey_hash)
    }
}

/// Resolve activation epochs for every queued deposit, up to and including
/// `epoch`.
///
/// Returns `(pubkey_hash, activation_epoch)` for each activated deposit, in
/// activation order. Deposits still waiting are absent. Rules:
///
/// - a deposit becomes *eligible* at `deposit_epoch + ACTIVATION_DELAY_EPOCHS`
///   (the set for an epoch must be fixed before the epoch starts);
/// - each epoch admits at most [`MAX_ACTIVATIONS_PER_EPOCH`] eligible
///   deposits, in [`QueuedDeposit::queue_key`] order.
///
/// Like `delegation::Registry::resolve`, this is a reference implementation:
/// a single deterministic pass from the full list, O(epochs × deposits), so
/// two nodes with identical state always agree and the rule is stated once.
/// A production node would carry the activation epoch in committed state.
pub fn resolve_activations(
    deposits: &[QueuedDeposit],
    epoch: u64,
) -> Vec<([u8; 32], u64)> {
    let mut queue: Vec<&QueuedDeposit> = deposits.iter().collect();
    // Sorting here is what makes the result independent of slice order.
    queue.sort_by_key(|d| d.queue_key());

    let mut activated: Vec<([u8; 32], u64)> = Vec::new();
    let mut done = vec![false; queue.len()];

    for e in 0..=epoch {
        let mut admitted_this_epoch = 0usize;
        for (i, d) in queue.iter().enumerate() {
            if admitted_this_epoch == MAX_ACTIVATIONS_PER_EPOCH {
                break;
            }
            if done[i] || d.deposit_epoch.saturating_add(ACTIVATION_DELAY_EPOCHS) > e {
                continue;
            }
            done[i] = true;
            admitted_this_epoch += 1;
            activated.push((d.pubkey_hash, e));
        }
    }
    activated
}

// ---------------------------------------------------------------------------
// Exit and withdrawal (§7.2)
// ---------------------------------------------------------------------------

/// A validator's staking record, as committed in state after activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// The registered hybrid pubkey — exits verify against this, never against
    /// a key supplied in the exit message itself.
    pub pubkey: [u8; HYBRID_PK_BYTES],
    pub amount_sat: u128,
    pub activation_epoch: u64,
    /// Epoch the voluntary exit was included, if any.
    pub exit_epoch: Option<u64>,
    /// Fixed at deposit time (§7.1) — see [`Address`].
    pub withdrawal_addr: Address,
    /// True once the stake has been paid out; a record can be withdrawn once.
    pub withdrawn: bool,
}

impl ValidatorRecord {
    /// Is the validator still assigned duties at `epoch`? Duties stop
    /// [`EXIT_DELAY_EPOCHS`] after the exit, not immediately — an exit must
    /// not be a same-epoch escape from already-assigned duties or their
    /// slashing exposure.
    pub fn assigned_duties_at(&self, epoch: u64) -> bool {
        match self.exit_epoch {
            Some(x) => epoch < x.saturating_add(EXIT_DELAY_EPOCHS),
            None => epoch >= self.activation_epoch,
        }
    }
}

/// Voluntary exit message (§7.2). Hybrid-signed by the validator key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitTx {
    /// SHA3-256 of the exiting validator's hybrid pubkey.
    pub pubkey_hash: [u8; 32],
    /// Epoch the exit is intended for. Signed, so a captured exit message
    /// cannot be replayed at a different (earlier or much later) time — the
    /// epoch in the signature must match the epoch of inclusion.
    pub epoch: u64,
    /// Hybrid signature over [`ExitTx::signing_root`], both halves required.
    pub signature: Vec<u8>,
}

impl ExitTx {
    /// `SHA3-256(DS_EXIT ‖ pubkey_hash ‖ epoch)` — fixed-width fields, own
    /// domain tag, same construction and same rationale as the deposit root.
    pub fn signing_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_EXIT);
        h.update(self.pubkey_hash);
        h.update(self.epoch.to_le_bytes());
        h.finalize().into()
    }
}

/// Why an exit was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReject {
    /// The message's pubkey hash does not match the record it targets.
    UnknownValidator,
    /// The validator already exited; a second exit would reset the withdrawal
    /// clock, which must never move once started.
    AlreadyExited,
    /// Exit epoch is ahead of the including epoch — pre-signing exits for the
    /// future would decouple the withdrawal clock from inclusion time.
    FutureEpoch,
    /// Hybrid signature invalid (either half).
    BadSignature,
}

/// Validate a voluntary exit against the validator's committed record.
pub fn validate_exit(
    exit: &ExitTx,
    record: &ValidatorRecord,
    current_epoch: u64,
    verifier: &dyn HybridKeyVerifier,
) -> Result<(), ExitReject> {
    let expected: [u8; 32] = Sha3_256::digest(record.pubkey).into();
    if exit.pubkey_hash != expected {
        return Err(ExitReject::UnknownValidator);
    }
    if record.exit_epoch.is_some() {
        return Err(ExitReject::AlreadyExited);
    }
    if exit.epoch > current_epoch {
        return Err(ExitReject::FutureEpoch);
    }
    // Signature last: cheapest-first, as everywhere else in the crate.
    if !verify_hybrid(&record.pubkey, &exit.signing_root(), &exit.signature, verifier) {
        return Err(ExitReject::BadSignature);
    }
    Ok(())
}

/// Why a withdrawal was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawReject {
    /// No exit on record — the stake is still bonded.
    NotExited,
    /// The weak-subjectivity margin has not elapsed. Paying out early would
    /// let the validator equivocate about recent history with its principal
    /// already safe.
    DelayNotElapsed,
    /// Already paid out.
    AlreadyWithdrawn,
}

/// Validate a withdrawal at `current_epoch`.
///
/// On success returns `(withdrawal_addr, amount_sat)` — the payout is fully
/// determined by the committed record: the address from deposit time, the
/// amount from the record (already reduced by any slashing). A withdrawal
/// transaction carries no spending authority of its own, which is why there is
/// no signature to verify here: after [`WITHDRAWAL_DELAY_EPOCHS`] the transfer
/// to `withdrawal_addr` is the only thing that can happen to these coins.
///
/// **Reference-spec only — the consensus gate is stricter.** This function
/// recomputes the ripeness clock from `exit_epoch + WITHDRAWAL_DELAY_EPOCHS`;
/// the transaction that actually pays (`transition.rs`, the `Withdraw` arm of
/// `apply_transaction`, behind `params::WITHDRAWAL_ACTIVATION_EPOCH`) gates on
/// the COMMITTED `withdrawable_epoch` field instead, which every slash
/// *extends* — post-activation to the full correlation window — and also
/// settles the inactivity leak and re-prices a slashed residue at the door.
/// The two agree exactly on the unslashed voluntary path this module states;
/// where they differ, the committed field wins, by the §5.5 rule that no
/// consensus value is recomputed from parts when the whole is committed.
pub fn validate_withdrawal(
    record: &ValidatorRecord,
    current_epoch: u64,
) -> Result<(Address, u128), WithdrawReject> {
    let Some(exit_epoch) = record.exit_epoch else {
        return Err(WithdrawReject::NotExited);
    };
    if record.withdrawn {
        return Err(WithdrawReject::AlreadyWithdrawn);
    }
    // `>=` on exit_epoch + delay: the delay counts from the exit's inclusion,
    // the same reference point EXIT_DELAY_EPOCHS uses, so the two clocks can
    // never disagree about when they started.
    if current_epoch < exit_epoch.saturating_add(WITHDRAWAL_DELAY_EPOCHS) {
        return Err(WithdrawReject::DelayNotElapsed);
    }
    Ok((record.withdrawal_addr, record.amount_sat))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test verifier: each half accepts iff its slice of the signature is
    /// filled with a magic byte. This lets tests fail exactly one half of the
    /// hybrid, which no real verifier stub keyed on the whole signature could.
    struct HalfwiseVerifier {
        accept_mldsa: bool,
        accept_falcon: bool,
    }

    impl HybridKeyVerifier for HalfwiseVerifier {
        fn verify_mldsa65(&self, pubkey: &[u8], _root: &[u8; 32], sig: &[u8]) -> bool {
            assert_eq!(pubkey.len(), MLDSA65_PK_BYTES, "crate must pass the ML-DSA half");
            assert_eq!(sig.len(), MLDSA65_SIG_BYTES, "crate must split at the fixed point");
            self.accept_mldsa
        }
        fn verify_falcon1024(&self, pubkey: &[u8], _root: &[u8; 32], sig: &[u8]) -> bool {
            assert_eq!(pubkey.len(), FALCON1024_PK_BYTES, "crate must pass the Falcon half");
            assert!(!sig.is_empty(), "Falcon half must be non-empty");
            self.accept_falcon
        }
    }

    fn accept_all() -> HalfwiseVerifier {
        HalfwiseVerifier { accept_mldsa: true, accept_falcon: true }
    }

    fn deposit(amount_sat: u128) -> DepositTx {
        DepositTx {
            suite: SUITE_MLDSA65_FALCON1024,
            amount_sat,
            validator_pubkey: [7u8; HYBRID_PK_BYTES],
            randao_commitment: [1u8; 32],
            withdrawal_addr: [2u8; 32],
            // ML-DSA half (3309) + a plausible Falcon half (1280) ≈ 4,589 B.
            proof_of_possession: vec![0u8; MLDSA65_SIG_BYTES + 1280],
        }
    }

    fn transparent_clean() -> Vec<DepositInput> {
        vec![DepositInput { transparent: true, tainted: false }]
    }

    const MAX_STAKE: u128 = 10_000_000 * SAT_PER_BLOCH;

    #[test]
    fn valid_deposit_accepted() {
        let tx = deposit(MIN_DEPOSIT_SAT);
        assert_eq!(validate_deposit(&tx, &transparent_clean(), MAX_STAKE, &accept_all()), Ok(()));
    }

    #[test]
    fn shielded_input_rejected() {
        let tx = deposit(MIN_DEPOSIT_SAT);
        let inputs = vec![
            DepositInput { transparent: true, tainted: false },
            DepositInput { transparent: false, tainted: false },
        ];
        assert_eq!(
            validate_deposit(&tx, &inputs, MAX_STAKE, &accept_all()),
            Err(DepositReject::ShieldedInput)
        );
    }

    #[test]
    fn tainted_input_rejected() {
        let tx = deposit(MIN_DEPOSIT_SAT);
        let inputs = vec![
            DepositInput { transparent: true, tainted: false },
            DepositInput { transparent: true, tainted: true },
        ];
        assert_eq!(
            validate_deposit(&tx, &inputs, MAX_STAKE, &accept_all()),
            Err(DepositReject::TaintedInput)
        );
    }

    /// Fixes the founder decision of 2026-08-11: **a carried-over balance
    /// that is liquid is also stakeable — the founder's included.** There is
    /// no provenance dimension in the admission path: a deposit input carries
    /// exactly two facts (transparent, tainted), the Genesis-4 taint set is
    /// empty so the oracle can only ever report a carried-over coin as
    /// untainted, and the only thing that can reject a carryover-funded
    /// deposit is its SIZE against the per-validator cap — never its origin.
    /// Reverting the decision requires reintroducing an origin check, and
    /// this test is where that reintroduction must first break.
    #[test]
    fn carryover_liquid_balance_is_stakeable() {
        // A carried-over UTXO exactly as the eligibility oracle must report
        // it: transparent (an ordinary eUTXO) and untainted (the taint set is
        // empty — there is no class of coin left to mark).
        let carryover = vec![DepositInput { transparent: true, tainted: false }];

        // Founder-scale is bounded by the cap alone. The whole carried-over
        // founder balance cannot enter through ONE validator...
        let whole_balance =
            crate::tokenomics_v4::LARGEST_CARRYOVER_ADDRESS_BLOCH * SAT_PER_BLOCH;
        assert_eq!(
            validate_deposit(&deposit(whole_balance), &carryover, MAX_STAKE, &accept_all()),
            Err(DepositReject::AboveMaximum),
            "the rejection is about size, never about origin"
        );
        // ...but a cap-sized slice of it is admitted with no further question.
        assert_eq!(
            validate_deposit(&deposit(MAX_STAKE), &carryover, MAX_STAKE, &accept_all()),
            Ok(())
        );
    }

    #[test]
    fn shielded_reported_before_tainted() {
        // A shielded input has no public ancestry, so its taint bit is
        // meaningless; the shielded rejection must win regardless of flags.
        let tx = deposit(MIN_DEPOSIT_SAT);
        let inputs = vec![DepositInput { transparent: false, tainted: true }];
        assert_eq!(
            validate_deposit(&tx, &inputs, MAX_STAKE, &accept_all()),
            Err(DepositReject::ShieldedInput)
        );
    }

    #[test]
    fn amount_out_of_bounds_rejected() {
        let low = deposit(MIN_DEPOSIT_SAT - 1);
        assert_eq!(
            validate_deposit(&low, &transparent_clean(), MAX_STAKE, &accept_all()),
            Err(DepositReject::BelowMinimum)
        );
        let high = deposit(MAX_STAKE + 1);
        assert_eq!(
            validate_deposit(&high, &transparent_clean(), MAX_STAKE, &accept_all()),
            Err(DepositReject::AboveMaximum)
        );
        // Boundaries themselves are inclusive.
        let at_max = deposit(MAX_STAKE);
        assert_eq!(
            validate_deposit(&at_max, &transparent_clean(), MAX_STAKE, &accept_all()),
            Ok(())
        );
    }

    #[test]
    fn wrong_suite_rejected() {
        let mut tx = deposit(MIN_DEPOSIT_SAT);
        tx.suite = 0x0002; // SUITE_MLDSA65_ONLY — the escape hatch is not valid for staking.
        assert_eq!(
            validate_deposit(&tx, &transparent_clean(), MAX_STAKE, &accept_all()),
            Err(DepositReject::WrongSuite)
        );
    }

    #[test]
    fn pop_requires_both_halves() {
        let tx = deposit(MIN_DEPOSIT_SAT);
        // ML-DSA passes, Falcon fails → invalid. The AND lives in this crate.
        let mldsa_only = HalfwiseVerifier { accept_mldsa: true, accept_falcon: false };
        assert_eq!(
            validate_deposit(&tx, &transparent_clean(), MAX_STAKE, &mldsa_only),
            Err(DepositReject::BadProofOfPossession)
        );
        // Falcon passes, ML-DSA fails → invalid.
        let falcon_only = HalfwiseVerifier { accept_mldsa: false, accept_falcon: true };
        assert_eq!(
            validate_deposit(&tx, &transparent_clean(), MAX_STAKE, &falcon_only),
            Err(DepositReject::BadProofOfPossession)
        );
    }

    #[test]
    fn truncated_pop_rejected_before_verifier_runs() {
        let mut tx = deposit(MIN_DEPOSIT_SAT);
        // Exactly the ML-DSA half, no Falcon bytes: malformed, not
        // "ML-DSA-only" — must fail even with an accept-everything verifier.
        tx.proof_of_possession = vec![0u8; MLDSA65_SIG_BYTES];
        assert_eq!(
            validate_deposit(&tx, &transparent_clean(), MAX_STAKE, &accept_all()),
            Err(DepositReject::BadProofOfPossession)
        );
    }

    // -- activation queue ---------------------------------------------------

    fn queued(deposit_epoch: u64, id: u8) -> QueuedDeposit {
        QueuedDeposit { pubkey_hash: [id; 32], deposit_epoch, amount_sat: MIN_DEPOSIT_SAT }
    }

    #[test]
    fn queue_respects_max_per_epoch() {
        // Ten deposits all included at epoch 0, eligible from epoch 8.
        let deposits: Vec<QueuedDeposit> = (0..10).map(|i| queued(0, i as u8)).collect();
        let acts = resolve_activations(&deposits, ACTIVATION_DELAY_EPOCHS + 2);
        assert_eq!(acts.len(), 10);
        // Epoch 8: four; epoch 9: four; epoch 10: two.
        let per_epoch = |e: u64| acts.iter().filter(|(_, a)| *a == e).count();
        assert_eq!(per_epoch(ACTIVATION_DELAY_EPOCHS), MAX_ACTIVATIONS_PER_EPOCH);
        assert_eq!(per_epoch(ACTIVATION_DELAY_EPOCHS + 1), MAX_ACTIVATIONS_PER_EPOCH);
        assert_eq!(per_epoch(ACTIVATION_DELAY_EPOCHS + 2), 2);
        for (_, a) in &acts {
            assert!(*a >= ACTIVATION_DELAY_EPOCHS, "nothing activates inside the delay");
        }
    }

    #[test]
    fn queue_nothing_before_delay() {
        let deposits = vec![queued(0, 1)];
        assert!(resolve_activations(&deposits, ACTIVATION_DELAY_EPOCHS - 1).is_empty());
        assert_eq!(resolve_activations(&deposits, ACTIVATION_DELAY_EPOCHS).len(), 1);
    }

    #[test]
    fn queue_order_deterministic_and_slice_order_independent() {
        // Six deposits across two epochs, handed over in scrambled order.
        let a = queued(0, 0x0a);
        let b = queued(0, 0x0b);
        let c = queued(0, 0x0c);
        let d = queued(1, 0x01); // earlier hash but LATER epoch: epoch wins
        let e = queued(0, 0x0e);
        let f = queued(0, 0x0f);

        let horizon = ACTIVATION_DELAY_EPOCHS + 4;
        let order1 = resolve_activations(&[a, b, c, d, e, f], horizon);
        let order2 = resolve_activations(&[f, d, b, e, a, c], horizon);
        assert_eq!(order1, order2, "activation must not depend on slice layout");

        // Queue order is (deposit_epoch, pubkey_hash): the four epoch-0
        // deposits with the smallest hashes go first, then the last epoch-0
        // deposit, then the epoch-1 deposit — even though its hash is lowest.
        let ids: Vec<u8> = order1.iter().map(|(h, _)| h[0]).collect();
        assert_eq!(ids, vec![0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x01]);
    }

    // -- exit and withdrawal ------------------------------------------------

    fn record() -> ValidatorRecord {
        ValidatorRecord {
            pubkey: [7u8; HYBRID_PK_BYTES],
            amount_sat: MIN_DEPOSIT_SAT,
            activation_epoch: 10,
            exit_epoch: None,
            withdrawal_addr: [2u8; 32],
            withdrawn: false,
        }
    }

    fn exit_for(record: &ValidatorRecord, epoch: u64) -> ExitTx {
        ExitTx {
            pubkey_hash: Sha3_256::digest(record.pubkey).into(),
            epoch,
            signature: vec![0u8; MLDSA65_SIG_BYTES + 1280],
        }
    }

    #[test]
    fn voluntary_exit_lifecycle() {
        let mut rec = record();
        let exit = exit_for(&rec, 100);
        assert_eq!(validate_exit(&exit, &rec, 100, &accept_all()), Ok(()));
        rec.exit_epoch = Some(100);

        // Duties continue through the exit delay, then stop.
        assert!(rec.assigned_duties_at(100 + EXIT_DELAY_EPOCHS - 1));
        assert!(!rec.assigned_duties_at(100 + EXIT_DELAY_EPOCHS));

        // A second exit is rejected: the withdrawal clock must never reset.
        let again = exit_for(&rec, 101);
        assert_eq!(validate_exit(&again, &rec, 101, &accept_all()), Err(ExitReject::AlreadyExited));
    }

    #[test]
    fn exit_requires_both_signature_halves() {
        let rec = record();
        let exit = exit_for(&rec, 100);
        let mldsa_only = HalfwiseVerifier { accept_mldsa: true, accept_falcon: false };
        assert_eq!(validate_exit(&exit, &rec, 100, &mldsa_only), Err(ExitReject::BadSignature));
    }

    #[test]
    fn exit_for_future_epoch_rejected() {
        let rec = record();
        let exit = exit_for(&rec, 101);
        assert_eq!(validate_exit(&exit, &rec, 100, &accept_all()), Err(ExitReject::FutureEpoch));
    }

    #[test]
    fn withdrawal_before_delay_rejected() {
        let mut rec = record();
        rec.exit_epoch = Some(100);
        // One epoch short of the weak-subjectivity margin: still bonded.
        assert_eq!(
            validate_withdrawal(&rec, 100 + WITHDRAWAL_DELAY_EPOCHS - 1),
            Err(WithdrawReject::DelayNotElapsed)
        );
        // At the boundary the stake is payable, to the address fixed at
        // deposit time and for the recorded amount.
        assert_eq!(
            validate_withdrawal(&rec, 100 + WITHDRAWAL_DELAY_EPOCHS),
            Ok(([2u8; 32], MIN_DEPOSIT_SAT))
        );
    }

    #[test]
    fn withdrawal_without_exit_rejected() {
        let rec = record();
        assert_eq!(validate_withdrawal(&rec, u64::MAX), Err(WithdrawReject::NotExited));
    }

    #[test]
    fn double_withdrawal_rejected() {
        let mut rec = record();
        rec.exit_epoch = Some(0);
        rec.withdrawn = true;
        assert_eq!(
            validate_withdrawal(&rec, WITHDRAWAL_DELAY_EPOCHS),
            Err(WithdrawReject::AlreadyWithdrawn)
        );
    }

    #[test]
    fn deposit_signing_root_binds_every_field() {
        // Two deposits differing in any single field must sign different
        // roots — otherwise one PoP could be replayed for the other.
        let base = deposit(MIN_DEPOSIT_SAT);
        let mut m1 = base.clone();
        m1.amount_sat += 1;
        let mut m2 = base.clone();
        m2.randao_commitment[0] ^= 1;
        let mut m3 = base.clone();
        m3.withdrawal_addr[0] ^= 1;
        let mut m4 = base.clone();
        m4.validator_pubkey[0] ^= 1;
        let roots = [base.signing_root(), m1.signing_root(), m2.signing_root(),
                     m3.signing_root(), m4.signing_root()];
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(roots[i], roots[j]);
            }
        }
    }
}
