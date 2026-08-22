// SPDX-License-Identifier: AGPL-3.0-or-later
//! The authorization rules (§5) — the whole point of the crate.

use crate::codec::CodecError;
use crate::root::{evm_txid, signing_root};
use crate::tx::BlochTx;
use crate::{
    address_from_pubkey, parse_envelope_strict, HybridKeyVerifier, PubkeyDirectory, ADDRESS_BYTES,
    ACTIVATION_EPOCH, HYBRID_PK_BYTES, MLDSA65_PK_BYTES, MLDSA65_SIG_BYTES,
    SUITE_MLDSA65_FALCON1024, TX_TYPE_PQ_BATCH, TX_TYPE_PQ_CALL,
};

/// Why an authorization was rejected.
///
/// One variant per reason, following `DepositReject`: "invalid" alone makes a
/// divergence undebuggable from logs, and a log you cannot read is how a
/// consensus fork costs a day instead of an hour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthReject {
    /// `epoch < ACTIVATION_EPOCH`. At `u64::MAX` that is every epoch that will
    /// ever exist — which is the intended state today.
    NotActivated,
    /// Leading type byte is neither [`TX_TYPE_PQ_CALL`] nor
    /// [`TX_TYPE_PQ_BATCH`].
    UnknownType,
    /// `chain_id` does not match the caller-supplied chain id.
    WrongChain,
    /// Envelope missing, magic wrong, or suite not exactly
    /// [`SUITE_MLDSA65_FALCON1024`]. Covers the `0x0002` escape hatch and the
    /// un-enveloped legacy blob alike.
    WrongSuite,
    /// The account has no recorded key and the transaction revealed none. A
    /// non-recoverable suite cannot invent one.
    MissingPubkey,
    /// The account already has a recorded key and the transaction revealed one
    /// anyway — **even if the bytes are identical**.
    RedundantPubkey,
    /// `SHA3-256(pk)[..20] != sender`. If an address could be authorized by a
    /// key that is not its own, that would be theft.
    AddressMismatch,
    /// The public key body is not exactly [`HYBRID_PK_BYTES`].
    BadPubkeyLength,
    /// The signature body has no room for a Falcon half.
    ///
    /// Distinct from [`AuthReject::BadSignature`] on purpose. A signature of
    /// exactly [`MLDSA65_SIG_BYTES`] is **malformed, not "a valid ML-DSA-only
    /// signature"** (`verify_hybrid`'s own words), and giving the geometry
    /// check its own variant is what makes the guard observable: with a shared
    /// variant, relaxing `<=` to `<` produces the same rejection through a
    /// different path and the mutation survives the suite. It is the
    /// `DepositReject` "one variant per reason" rule doing exactly the work it
    /// exists for.
    MalformedSignature,
    /// A cryptographic half did not verify. AND-composition: either half
    /// failing lands here.
    BadSignature,
    /// A field could not be canonically encoded for hashing. Unreachable for
    /// any transaction that arrived over the wire (the decoder's budget check
    /// already bounds it); present so the hashing path fails closed instead of
    /// panicking on an in-memory transaction built by a caller.
    OversizedField,
}

impl From<CodecError> for AuthReject {
    fn from(_: CodecError) -> Self {
        AuthReject::OversizedField
    }
}

/// What a successful authorization yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized {
    /// The account the execution layer must debit.
    pub sender: [u8; ADDRESS_BYTES],
    /// `SHA3-256(DS_EVM_TXID ‖ signing_root)`.
    pub evm_txid: [u8; 32],
    /// `Some(pk)` exactly when this was the account's first authorization.
    ///
    /// **This crate does not write state.** It returns the key; the execution
    /// layer records it, inside the EVM state, where the account→pubkey map
    /// belongs (§8.1).
    pub pubkey_to_record: Option<Vec<u8>>,
}

/// Authorize a PQ-typed transaction.
///
/// `epoch` is supplied **by the caller, derived from the block's own header
/// slot**, and is never read from node-local state — this crate has no way to
/// read node state. That is structural, not a convention: on 2026-08-08 this
/// chain forked because `expected_bits` came from local mutable state and
/// nodes with identical binaries diverged.
///
/// Nonce, balance, gas and fee sufficiency are **not** this function's job.
/// They are execution-layer checks against state this crate cannot see.
pub fn verify(
    tx: &BlochTx,
    epoch: u64,
    chain_id: u64,
    dir: &dyn PubkeyDirectory,
    verifier: &dyn HybridKeyVerifier,
) -> Result<Authorized, AuthReject> {
    // 1. Flag day. Inert until the founder lowers ACTIVATION_EPOCH.
    if epoch < ACTIVATION_EPOCH {
        return Err(AuthReject::NotActivated);
    }

    // 2. Type. Checked here as well as in the decoder: a transaction can also
    //    reach this function having been built in memory rather than parsed.
    if tx.type_byte != TX_TYPE_PQ_CALL && tx.type_byte != TX_TYPE_PQ_BATCH {
        return Err(AuthReject::UnknownType);
    }

    // 3. Replay domain.
    if tx.chain_id != chain_id {
        return Err(AuthReject::WrongChain);
    }

    // 4. Suite, strictly, on the signature and on any revealed key. The
    //    0x0002 escape hatch is rejected, and so is the un-enveloped legacy
    //    blob — see `parse_envelope_strict` for why the fallback that
    //    `bloch_crypto::verify` performs must not happen here.
    let sig_body = strict_body(&tx.signature)?;
    if let Some(revealed) = &tx.sender_pk {
        strict_body(revealed)?;
    }

    // 5. The sender_pk presence rule. Presence, NOT equality.
    let stored = dir.pubkey_of(&tx.sender);
    let pk_enveloped: &[u8] = match (stored, tx.sender_pk.as_deref()) {
        (None, None) => return Err(AuthReject::MissingPubkey),
        // "Present and equal is also fine" would make two encodings of one
        // transaction valid at the same instant, and two encodings is
        // malleability — the same reason the hybrid signature has a fixed
        // split point instead of a length prefix. The bytes are not compared,
        // because comparing them is the bug.
        (Some(_), Some(_)) => return Err(AuthReject::RedundantPubkey),
        (Some(recorded), None) => recorded,
        (None, Some(revealed)) => revealed,
    };
    let first_authorization = stored.is_none();

    // The key that is actually in play must carry the envelope too — the
    // stored one no less than the revealed one. One parse path, both sources.
    let pk_body = strict_body(pk_enveloped)?;

    // 6. Address consistency. `sender` is a claim; this is what makes it
    //    binding. Nothing is recovered.
    if address_from_pubkey(pk_enveloped) != tx.sender {
        return Err(AuthReject::AddressMismatch);
    }

    // 7. Hybrid verification, AND at the split point.
    if pk_body.len() != HYBRID_PK_BYTES {
        return Err(AuthReject::BadPubkeyLength);
    }
    if sig_body.len() <= MLDSA65_SIG_BYTES {
        return Err(AuthReject::MalformedSignature);
    }
    let root = signing_root(tx)?;
    let (mldsa_pk, falcon_pk) = pk_body.split_at(MLDSA65_PK_BYTES);
    let (mldsa_sig, falcon_sig) = sig_body.split_at(MLDSA65_SIG_BYTES);
    // AND, never OR. Read `staking.rs:128-149` and follow it. Short-circuiting
    // is safe: this is a verification path, not a signing path, and there is
    // no secret here for a timing side channel to leak.
    let ok = verifier.verify_mldsa65(mldsa_pk, &root, mldsa_sig)
        && verifier.verify_falcon1024(falcon_pk, &root, falcon_sig);
    if !ok {
        return Err(AuthReject::BadSignature);
    }

    // 8. Success.
    Ok(Authorized {
        sender: tx.sender,
        evm_txid: evm_txid(&root),
        pubkey_to_record: if first_authorization {
            Some(pk_enveloped.to_vec())
        } else {
            None
        },
    })
}

/// Strict envelope parse yielding the body, or [`AuthReject::WrongSuite`].
fn strict_body(enveloped: &[u8]) -> Result<&[u8], AuthReject> {
    match parse_envelope_strict(enveloped) {
        Some((suite, body)) if suite == SUITE_MLDSA65_FALCON1024 => Ok(body),
        _ => Err(AuthReject::WrongSuite),
    }
}
