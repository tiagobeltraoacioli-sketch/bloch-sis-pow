// SPDX-License-Identifier: AGPL-3.0-or-later
//! The signing root, the transaction id, and the precompile's message (§4, §8.2).

use sha3::{Digest, Sha3_256};

use crate::codec::CodecError;
use crate::tx::BlochTx;
use crate::{DS_EVM_CALL, DS_EVM_TX, DS_EVM_TXID};

/// `SHA3-256(DS_EVM_TX ‖ type_byte ‖ canonical execution fields ‖ sender)`.
///
/// All scalars little-endian, matching `DepositTx::signing_root`.
///
/// **`sender_pk` and `signature` are deliberately NOT in the root.** The
/// signature cannot be inside the root it is produced over; the pubkey is
/// excluded for a reason worth stating, because the obvious alternative has a
/// live failure mode:
///
/// - The root binds the 20-byte `sender`, which **is** `SHA3-256(enveloped
///   pk)[..20]`. Covering the address covers the key up to second-preimage
///   resistance on 160 bits — the tier this chain already accepts for every
///   carried Genesis-3 output (`transition.rs::owns`). A key-substitution
///   attack needs a *second preimage* of an existing account's address, not a
///   birthday collision: grinding two of your own keys to one address buys
///   nothing, because both keys are yours.
/// - Had the pk been inside the root, the root would depend on whether the
///   account is at first use — a fact the wallet learns only from state at
///   *inclusion* time. Two transactions in flight, the first replaced or
///   dropped, and the second's encoding assumption breaks. Excluding the pk
///   makes the signature independent of that race.
///
/// Consequence, stated so nobody discovers it in production: an attacker who
/// strips a required `sender_pk`, or adds a forbidden one, produces a
/// transaction that **fails validation**. That is drop-equivalent censorship,
/// never theft, and it cannot change the id.
pub fn signing_root(tx: &BlochTx) -> Result<[u8; 32], CodecError> {
    let mut preimage = Vec::with_capacity(96 + tx.data.len());
    preimage.push(tx.type_byte);
    tx.encode_unsigned_into(&mut preimage)?;
    preimage.extend_from_slice(&tx.sender);

    let mut h = Sha3_256::new();
    h.update(DS_EVM_TX);
    h.update(&preimage);
    Ok(h.finalize().into())
}

/// `SHA3-256(DS_EVM_TXID ‖ signing_root)`.
///
/// Derived from the **witness-free** root, following `DS_TXID` exactly: nobody
/// can re-key a transaction in flight by re-encoding its witness. Both
/// encodings of one authorization therefore share one id, which is what keeps
/// the mempool from holding two entries for one effect.
pub fn evm_txid(signing_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_EVM_TXID);
    h.update(signing_root);
    h.finalize().into()
}

/// `SHA3-256(DS_EVM_CALL ‖ chain_id ‖ msg32)` — what the precompile actually
/// verifies over (§8.2).
///
/// Never `msg32` directly. Without the tag a contract can hand a user an
/// arbitrary 32-byte digest to sign, and a digest is a digest: if it happens
/// to be some transaction's signing root, the "signature over a message" is
/// also a signature that moves that user's funds. Domain separation makes a
/// precompile signature and a transaction authorization mutually unreplayable
/// — which is what every tag in `params.rs` exists for. The chain id is inside
/// for the same reason it is inside the transaction root.
pub fn call_message(chain_id: u64, msg32: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_EVM_CALL);
    h.update(chain_id.to_le_bytes());
    h.update(msg32);
    h.finalize().into()
}
