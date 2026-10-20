// SPDX-License-Identifier: AGPL-3.0-or-later
//! Post-quantum suite migration: moving value and validator withdrawal
//! credentials from the lattice hybrid (`ML-DSA-65 ‖ Falcon-1024`, suite
//! `0x0001`) to the hash-based suite (`SLH-DSA-128s ‖ Falcon-1024`, suite
//! `0x0003`), including the emergency case where the lattice families are
//! publicly broken. Design and threat model: `docs/PQ-SUITE-MIGRATION.md`.
//!
//! Every rule here is behind an INERT gate:
//!
//! - [`crate::params::HF3_PQ_MIGRATION_EPOCH`] — the
//!   withdrawal-credential rotation (wire `0x18`);
//! - [`crate::params::LATTICE_EMERGENCY_ACTIVATION_EPOCH`] — the lattice
//!   spend freeze and the commit-reveal rescue (wire `0x19`/`0x1A`).
//!
//! Below the gates every new tag is refused before any field is read, the
//! rescue-commitment map stays empty (zero state-root leaves, no local-cache
//! section), and the freeze check is never evaluated, so replay is
//! byte-identical to a binary without this module.

use super::*;
use crate::state_root::EutxoEntry;

/// Wire tags from the HF3 allocation table ([`crate::wire_alloc`]).
pub const WITHDRAWAL_CREDENTIAL_ROTATION_TAG: u8 = crate::wire_alloc::tx::WITHDRAWAL_CREDENTIAL_ROTATION;
pub const RESCUE_COMMIT_TAG: u8 = crate::wire_alloc::tx::RESCUE_COMMIT;
pub const RESCUE_REVEAL_TAG: u8 = crate::wire_alloc::tx::RESCUE_REVEAL;

/// Suite ids, mirrored from `bloch-crypto::crypto` (this crate takes its
/// verifier through a trait and does not link the crypto stack). `0x0003`
/// MUST equal the id the suite prototype assigns on
/// `codex/bloch-p9a-slhdsa-20261019`; a mismatch is a consensus split.
pub const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;
pub const SUITE_MLDSA65_ONLY: u16 = 0x0002;
pub const SUITE_SLHDSA128S_FALCON1024: u16 = 0x0003;

const SUITE_MAGIC: [u8; 2] = [0xb1, 0x0c];
/// Raw (pre-envelope) hybrid key length: ML-DSA-65 pk ‖ Falcon-1024 pk.
const LEGACY_HYBRID_PK_BYTES: usize = staking::HYBRID_PK_BYTES;
/// Envelope ‖ SLH-DSA-128s pk (32) ‖ Falcon-1024 pk (1793).
pub const SLH_SUITE_PUBKEY_BYTES: usize = 4 + 32 + 1_793;
/// Envelope ‖ SLH-DSA-128s sig (7856) ‖ Falcon-1024 sig (≤ 1280).
pub const SLH_SUITE_SIGNATURE_MAX: usize = 4 + 7_856 + 1_280;
/// Largest key/signature any accepted suite produces.
const PUBKEY_MAX: usize = funded::ADMISSION_PQ_KEY_BYTES;
const SIGNATURE_MAX: usize = SLH_SUITE_SIGNATURE_MAX;

const ROTATION_DOMAIN: &[u8] = b"BLOCH:VALIDATOR:WITHDRAWAL-CREDENTIAL:V1";
const RESCUE_SPEND_DOMAIN: &[u8] = b"BLOCH:PQ-RESCUE:SPEND-COMMIT:V1";
const RESCUE_CREDENTIAL_DOMAIN: &[u8] = b"BLOCH:PQ-RESCUE:CREDENTIAL-COMMIT:V1";
const RESCUE_REVEAL_DOMAIN: &[u8] = b"BLOCH:PQ-RESCUE:REVEAL:V1";
const RESCUE_COMMIT_ID_DOMAIN: &[u8] = b"BLOCH:PQ-RESCUE:COMMIT-ID:V1";

/// Suite of an authorising public key. Enveloped keys report their tag; a
/// raw legacy hybrid key (exact legacy length, the same disambiguation
/// `bloch-crypto` applies) is the lattice hybrid. Anything else is `None`.
pub fn key_suite(pubkey: &[u8]) -> Option<u16> {
    if pubkey.len() == LEGACY_HYBRID_PK_BYTES {
        return Some(SUITE_MLDSA65_FALCON1024);
    }
    if pubkey.len() < 4 || pubkey[..2] != SUITE_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes([pubkey[2], pubkey[3]]))
}

/// Does this key's authority survive a break of the lattice families?
/// Only the hash-based suite does; unknown or malformed keys fail closed.
pub fn is_hash_based_key(pubkey: &[u8]) -> bool {
    key_suite(pubkey) == Some(SUITE_SLHDSA128S_FALCON1024)
        && pubkey.len() == SLH_SUITE_PUBKEY_BYTES
}

/// The script hash a key opens in native form: `SHA3-256(pubkey)`. Because
/// the hashed bytes are the ENVELOPED key, the hash already commits to the
/// suite — an address is a commitment to (suite, key), never to a bare key.
pub fn native_script(pubkey: &[u8]) -> [u8; 32] {
    Sha3_256::digest(pubkey).into()
}

/// The carried (Genesis-3) form of the same key: first 20 bytes, rest zero.
pub fn carried_script(pubkey: &[u8]) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..20].copy_from_slice(&native_script(pubkey)[..20]);
    s
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn bounded(r: &mut TxReader<'_>, max: usize, tag: u8) -> Result<Vec<u8>, TxDecodeError> {
    let n = r.u32()? as usize;
    if n > max {
        return Err(TxDecodeError::NotCanonical(tag));
    }
    Ok(r.take(n)?.to_vec())
}

fn role_root(domain: &[u8], intent: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain);
    h.update(intent);
    h.finalize().into()
}

/// Commitment a lattice-key holder publishes BEFORE revealing its key, for a
/// rescue sweep of every output that key opens to `destination`.
///
/// Binds the key (unknown to anyone else while unspent: the chain stores only
/// its hash), the destination and the tip. The tip is bound because the
/// reveal's hybrid signature proves nothing after a break: an unbound tip
/// would let anyone re-price an honest reveal into the proposer's pocket.
/// `tx_bytes` needs no binding — a reveal must declare exactly its own length.
pub fn rescue_spend_commitment(pubkey: &[u8], destination: &[u8; 32], tip: u128) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(RESCUE_SPEND_DOMAIN);
    h.update((pubkey.len() as u32).to_le_bytes());
    h.update(pubkey);
    h.update(destination);
    h.update(tip.to_le_bytes());
    h.finalize().into()
}

/// Commitment for rotating `validator`'s lattice-key withdrawal credential to
/// `new_credential` after the emergency gate binds.
pub fn rescue_credential_commitment(
    validator: u32,
    current_pubkey: &[u8],
    new_credential: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(RESCUE_CREDENTIAL_DOMAIN);
    h.update(validator.to_le_bytes());
    h.update((current_pubkey.len() as u32).to_le_bytes());
    h.update(current_pubkey);
    h.update(new_credential);
    h.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqMigrationReject {
    /// The gate for this message has not arrived.
    NotActive,
    Network,
    Epoch,
    Shape,
    /// `tx_bytes` is not exactly this transaction's canonical length.
    Size,
    Validator,
    /// The authorising key does not open the validator's current credential.
    Credential,
    /// The new credential key is not the hash-based suite.
    NotHashBased,
    /// The rotation would not change the credential.
    Unchanged,
    Signature,
    NewKeySignature,
    /// After the emergency, a lattice-key spend/rotation without a rescue.
    LatticeSpendFrozen,
    /// A rescue reveal by a key that is not lattice (it should just transfer).
    NotLatticeKey,
    CommitmentExists,
    CommitmentUnknown,
    CommitmentImmature,
    CommitmentNotFinal,
    CommitmentExpired,
    MissingInput,
    DuplicateInput,
    Ownership,
    /// A rescue must sweep EVERY output the revealed key opens (both forms);
    /// anything left behind is exposed to whoever can now forge.
    IncompleteSweep,
    Conservation,
    OutputCollision,
}

// ─── Withdrawal-credential rotation (wire 0x18) ─────────────────────────────

/// Replace a validator's withdrawal credential (a 32-byte script hash, see
/// `lifecycle::withdrawal_plan`) with the script hash of a hash-based-suite
/// key.
///
/// Authorised by the key that opens the CURRENT credential — the owner of the
/// stake's destination — never by the validator's consensus key: the
/// consensus key is hot, public and lattice, so letting it rewrite where the
/// bond goes would make a lattice forgery a bond theft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalCredentialRotation {
    pub network_domain: [u8; 32],
    /// Must equal the inclusion epoch (no replay at a time not chosen).
    pub epoch: u64,
    pub validator: u32,
    /// Key whose hash is the current credential (native or carried form).
    pub authorizing_pubkey: Vec<u8>,
    /// Hash-based-suite key; the new credential is `SHA3-256(new_pubkey)`.
    pub new_pubkey: Vec<u8>,
    /// By `authorizing_pubkey` over [`Self::signing_root`].
    pub authorizing_signature: Vec<u8>,
    /// By `new_pubkey` over the same root: proof the new credential is
    /// spendable, so a typo cannot brick a bond.
    pub new_key_signature: Vec<u8>,
}

impl WithdrawalCredentialRotation {
    pub fn new_credential(&self) -> [u8; 32] {
        native_script(&self.new_pubkey)
    }

    fn intent_bytes(&self) -> Vec<u8> {
        let mut out = vec![WITHDRAWAL_CREDENTIAL_ROTATION_TAG];
        out.extend_from_slice(&self.network_domain);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.validator.to_le_bytes());
        put_bytes(&mut out, &self.authorizing_pubkey);
        put_bytes(&mut out, &self.new_pubkey);
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(ROTATION_DOMAIN, &self.intent_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent_bytes();
        put_bytes(&mut out, &self.authorizing_signature);
        put_bytes(&mut out, &self.new_key_signature);
        out
    }

    pub(in crate::transition) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        let t = WITHDRAWAL_CREDENTIAL_ROTATION_TAG;
        Ok(Self {
            network_domain: r.h32()?,
            epoch: r.u64()?,
            validator: r.u32()?,
            authorizing_pubkey: bounded(r, PUBKEY_MAX, t)?,
            new_pubkey: bounded(r, PUBKEY_MAX, t)?,
            authorizing_signature: bounded(r, SIGNATURE_MAX, t)?,
            new_key_signature: bounded(r, SIGNATURE_MAX, t)?,
        })
    }
}

// ─── Rescue commitment (wire 0x19) ──────────────────────────────────────────

/// A 32-byte commitment, published while the key it commits to is still
/// secret. Unauthenticated and fee-free by design: after the emergency a
/// lattice-only holder has nothing it can sign or pay with. Rate-limited by
/// gas ([`crate::params::RESCUE_COMMITS_PER_BLOCK`]) and pruned after
/// [`crate::params::RESCUE_COMMIT_TTL_EPOCHS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueCommit {
    pub network_domain: [u8; 32],
    pub commitment: [u8; 32],
}

impl RescueCommit {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![RESCUE_COMMIT_TAG];
        out.extend_from_slice(&self.network_domain);
        out.extend_from_slice(&self.commitment);
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(RESCUE_COMMIT_ID_DOMAIN, &self.canonical_bytes())
    }

    pub(in crate::transition) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        Ok(Self { network_domain: r.h32()?, commitment: r.h32()? })
    }
}

// ─── Rescue reveal (wire 0x1A) ──────────────────────────────────────────────

/// Sweep every output a lattice key opens into ONE output at `destination`,
/// citing a matured, finalized [`RescueCommit`] made before the key was
/// public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RescueReveal {
    pub network_domain: [u8; 32],
    pub pubkey: Vec<u8>,
    /// Every outpoint whose script is `native_script(pubkey)` or
    /// `carried_script(pubkey)` — no more, no fewer — in ascending order.
    pub inputs: Vec<FundingInput>,
    pub destination_script_hash: [u8; 32],
    pub tip_millisat_per_gas: u128,
    /// Must equal the canonical length exactly.
    pub tx_bytes: u64,
    /// Lattice hybrid signature over [`Self::signing_root`]. Worthless if
    /// BOTH lattice families are broken, still binding if only one is (the
    /// hybrid is an AND), so it is kept.
    pub signature: Vec<u8>,
}

impl RescueReveal {
    pub fn commitment(&self) -> [u8; 32] {
        rescue_spend_commitment(&self.pubkey, &self.destination_script_hash, self.tip_millisat_per_gas)
    }

    fn intent_bytes(&self) -> Vec<u8> {
        let mut out = vec![RESCUE_REVEAL_TAG];
        out.extend_from_slice(&self.network_domain);
        put_bytes(&mut out, &self.pubkey);
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            out.extend_from_slice(&i.txid);
            out.extend_from_slice(&i.vout.to_le_bytes());
        }
        out.extend_from_slice(&self.destination_script_hash);
        out.extend_from_slice(&self.tip_millisat_per_gas.to_le_bytes());
        out.extend_from_slice(&self.tx_bytes.to_le_bytes());
        out
    }

    pub fn signing_root(&self) -> [u8; 32] {
        role_root(RESCUE_REVEAL_DOMAIN, &self.intent_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.intent_bytes();
        put_bytes(&mut out, &self.signature);
        out
    }

    /// Canonical length for a reveal with these inputs, key and signature
    /// length — what a wallet writes into `tx_bytes`.
    pub fn exact_tx_bytes(&self) -> u64 {
        self.canonical_bytes().len() as u64
    }

    pub(in crate::transition) fn decode(r: &mut TxReader<'_>) -> Result<Self, TxDecodeError> {
        let t = RESCUE_REVEAL_TAG;
        let network_domain = r.h32()?;
        let pubkey = bounded(r, PUBKEY_MAX, t)?;
        let n = r.u32()?;
        let mut inputs = Vec::new();
        for _ in 0..n {
            inputs.push(FundingInput { txid: r.h32()?, vout: r.u32()? });
        }
        Ok(Self {
            network_domain,
            pubkey,
            inputs,
            destination_script_hash: r.h32()?,
            tip_millisat_per_gas: r.u128()?,
            tx_bytes: r.u64()?,
            signature: bounded(r, SIGNATURE_MAX, t)?,
        })
    }
}

// ─── The rules ──────────────────────────────────────────────────────────────

impl CommittedState {
    /// Committed rescue commitments (commitment → inclusion epoch). Empty on
    /// every network until the emergency gate binds.
    pub fn pq_rescue_commitment_epoch(&self, commitment: &[u8; 32]) -> Option<u64> {
        self.pq_rescue_commits.get(commitment).copied()
    }

    /// The emergency spend freeze for `Transfer`/`TransferV2`: once the gate
    /// binds, a coin may move under a plain signature only if that signature
    /// is hash-based. Lattice-locked coins move through the rescue instead.
    /// Never evaluated below the gate.
    pub(super) fn check_lattice_spend_freeze(&self, tx: &PosTransaction) -> Result<(), TxReject> {
        if !crate::params::lattice_emergency_active(self.epoch) {
            return Ok(());
        }
        let frozen = match tx {
            PosTransaction::Transfer { inputs, .. } => {
                inputs.iter().any(|i| !is_hash_based_key(&i.pubkey))
            }
            PosTransaction::TransferV2 { keys, .. } => {
                keys.iter().any(|k| !is_hash_based_key(&k.pubkey))
            }
            _ => false,
        };
        if frozen {
            return Err(TxReject::PqMigration(PqMigrationReject::LatticeSpendFrozen));
        }
        Ok(())
    }

    /// A commitment usable at this epoch: present, aged
    /// [`crate::params::RESCUE_COMMIT_MIN_DELAY_EPOCHS`], inside a finalized
    /// epoch (so no reorg can re-order it against an attacker's), not expired.
    fn matured_commitment(&self, commitment: &[u8; 32]) -> Result<(), PqMigrationReject> {
        use PqMigrationReject as R;
        let at = *self.pq_rescue_commits.get(commitment).ok_or(R::CommitmentUnknown)?;
        if at.saturating_add(crate::params::RESCUE_COMMIT_TTL_EPOCHS) < self.epoch {
            return Err(R::CommitmentExpired);
        }
        if at.saturating_add(crate::params::RESCUE_COMMIT_MIN_DELAY_EPOCHS) > self.epoch {
            return Err(R::CommitmentImmature);
        }
        // A finalized checkpoint at E covers the end of E-1.
        if at >= self.finality_engine.finalized().epoch {
            return Err(R::CommitmentNotFinal);
        }
        Ok(())
    }

    /// Drop commitments past their TTL. Called at every epoch boundary; a
    /// no-op on the empty map every pre-emergency network holds.
    pub(super) fn prune_pq_rescue_commits(&mut self, epoch: u64) {
        if self.pq_rescue_commits.is_empty() {
            return;
        }
        self.pq_rescue_commits
            .retain(|_, at| at.saturating_add(crate::params::RESCUE_COMMIT_TTL_EPOCHS) >= epoch);
    }

    pub(super) fn apply_withdrawal_credential_rotation(
        &mut self,
        tx: &WithdrawalCredentialRotation,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, PqMigrationReject> {
        use PqMigrationReject as R;
        if !crate::params::hf3_pq_migration_active(self.epoch) {
            return Err(R::NotActive);
        }
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if tx.epoch != self.epoch {
            return Err(R::Epoch);
        }
        if tx.authorizing_pubkey.is_empty()
            || tx.authorizing_pubkey.len() > PUBKEY_MAX
            || tx.authorizing_signature.len() > SIGNATURE_MAX
            || tx.new_key_signature.len() > SIGNATURE_MAX
        {
            return Err(R::Shape);
        }
        let record = self.validators.get(&tx.validator).ok_or(R::Validator)?;
        // Nothing left to protect once the bond has been paid out.
        if record.staked_sat == 0 {
            return Err(R::Validator);
        }
        let current = <[u8; 32]>::try_from(record.withdrawal_credentials.as_slice())
            .map_err(|_| R::Credential)?;
        if !owns(&native_script(&tx.authorizing_pubkey), &current) {
            return Err(R::Credential);
        }
        if !is_hash_based_key(&tx.new_pubkey) {
            return Err(R::NotHashBased);
        }
        let new_credential = tx.new_credential();
        if new_credential == current {
            return Err(R::Unchanged);
        }
        // After the emergency a lattice signature authorises nothing by
        // itself: the rotation must cite a commitment made while the key
        // was still secret.
        let rescue = crate::params::lattice_emergency_active(self.epoch)
            && !is_hash_based_key(&tx.authorizing_pubkey);
        let commitment =
            rescue_credential_commitment(tx.validator, &tx.authorizing_pubkey, &new_credential);
        if rescue {
            self.matured_commitment(&commitment)?;
        }
        let root = tx.signing_root();
        if !verifier.verify_with_key(&tx.authorizing_pubkey, &root, &tx.authorizing_signature) {
            return Err(R::Signature);
        }
        if !verifier.verify_with_key(&tx.new_pubkey, &root, &tx.new_key_signature) {
            return Err(R::NewKeySignature);
        }

        if rescue {
            self.pq_rescue_commits.remove(&commitment);
        }
        let record = self.validators.get_mut(&tx.validator).ok_or(R::Validator)?;
        record.withdrawal_credentials = new_credential.to_vec();
        Ok(Self::staking_tx_charge(self.epoch, 2, tx.canonical_bytes().len()))
    }

    pub(super) fn apply_rescue_commit(
        &mut self,
        tx: &RescueCommit,
    ) -> Result<fee_market::TxCharge, PqMigrationReject> {
        use PqMigrationReject as R;
        if !crate::params::lattice_emergency_active(self.epoch) {
            return Err(R::NotActive);
        }
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        // First writer keeps its epoch: a later duplicate cannot reset the
        // age of a commitment someone else is waiting on.
        if self.pq_rescue_commits.contains_key(&tx.commitment) {
            return Err(R::CommitmentExists);
        }
        self.pq_rescue_commits.insert(tx.commitment, self.epoch);
        let tx_bytes = tx.canonical_bytes().len() as u64;
        Ok(fee_market::TxCharge {
            gas: fee_market::BLOCK_GAS_LIMIT / crate::params::RESCUE_COMMITS_PER_BLOCK,
            tx_bytes,
            base_fee_sat: 0,
            priority_fee_sat: 0,
        })
    }

    pub(super) fn apply_rescue_reveal(
        &mut self,
        tx: &RescueReveal,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, PqMigrationReject> {
        use PqMigrationReject as R;
        if !crate::params::lattice_emergency_active(self.epoch) {
            return Err(R::NotActive);
        }
        if self.admission_network_domain != Some(tx.network_domain) {
            return Err(R::Network);
        }
        if tx.pubkey.is_empty() || tx.pubkey.len() > PUBKEY_MAX || tx.inputs.is_empty() {
            return Err(R::Shape);
        }
        if is_hash_based_key(&tx.pubkey) {
            return Err(R::NotLatticeKey);
        }
        if tx.tx_bytes != tx.exact_tx_bytes() {
            return Err(R::Size);
        }
        if tx.tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS {
            return Err(R::Shape);
        }
        let class = fee_market::TxClass::Eutxo { inputs: 1 };
        if fee_market::intrinsic_gas(class, tx.tx_bytes) > fee_market::MAX_TX_GAS {
            return Err(R::Shape);
        }

        // Inputs: strictly ascending (one encoding), present, owned.
        let native = native_script(&tx.pubkey);
        let carried = carried_script(&tx.pubkey);
        let mut spent: u128 = 0;
        let mut prev: Option<([u8; 32], u32)> = None;
        for i in &tx.inputs {
            let key = (i.txid, i.vout);
            if prev.is_some_and(|p| p >= key) {
                return Err(R::DuplicateInput);
            }
            prev = Some(key);
            let entry = self.eutxos.get(&key).ok_or(R::MissingInput)?;
            if entry.script_hash != native && entry.script_hash != carried {
                return Err(R::Ownership);
            }
            spent += u128::from(entry.value);
        }
        // Sweep-all: once this key is public nothing it opens may stay behind.
        let owned = self.eutxos.script_len(&native)
            + if carried != native { self.eutxos.script_len(&carried) } else { 0 };
        if owned != tx.inputs.len() {
            return Err(R::IncompleteSweep);
        }

        self.matured_commitment(&tx.commitment())?;

        let charge = fee_market::charge(
            class,
            tx.tx_bytes,
            base_fee_millisat_per_gas,
            tx.tip_millisat_per_gas,
        );
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        let value = spent.checked_sub(fee).ok_or(R::Conservation)?;
        let value = u64::try_from(value).map_err(|_| R::Conservation)?;
        if value < crate::params::MIN_TRANSFER_OUTPUT_SAT {
            return Err(R::Conservation);
        }
        let txid = PosTransaction::RescueReveal(tx.clone()).txid();
        if self.eutxos.contains_key(&(txid, 0)) {
            return Err(R::OutputCollision);
        }
        if !verifier.verify_with_key(&tx.pubkey, &tx.signing_root(), &tx.signature) {
            return Err(R::Signature);
        }

        for i in &tx.inputs {
            self.eutxos.remove(&(i.txid, i.vout));
        }
        self.eutxos.insert(EutxoEntry {
            txid,
            vout: 0,
            value,
            script_hash: tx.destination_script_hash,
        });
        self.pq_rescue_commits.remove(&tx.commitment());
        Ok(charge)
    }
}
