// SPDX-License-Identifier: MIT OR Apache-2.0
//! The **anchoring convention** — how a 32-byte commitment is embedded in a
//! Bloch transaction using ONLY today's primitives.
//!
//! ## Why a convention at all?
//!
//! Bloch today has **no data-carrier / `OP_RETURN` output and no script system**
//! (roadmap §1.6). The single output form is a **fixed 20-byte P2PKH**
//! `script_pubkey = SHA3-256(pubkey)[..20]` (roadmap §1.3). There is no opcode
//! to say "these bytes are data, not a spend."
//!
//! So this reference embeds the commitment the only way today's model allows:
//! it writes the commitment bytes **into the 20-byte `script_pubkey` fields of a
//! small number of provably-unspendable P2PKH outputs** (a "burn" anchor). A
//! reader recovers the commitment by reading those outputs straight back off the
//! chain — no script execution required.
//!
//! ## Layout (Bloch Anchor v1)
//!
//! A 32-byte commitment maps to **two** 20-byte carrier outputs:
//!
//! ```text
//! carrier[0].script_pubkey = MAGIC(4) ‖ commitment[0..16]         (4 + 16 = 20)
//! carrier[1].script_pubkey = commitment[16..32] ‖ ZERO_PAD(4)     (16 + 4 = 20)
//! ```
//!
//! where `MAGIC = b"BLA1"`. Decoding: find the output whose first 4 bytes equal
//! `MAGIC`; the immediately following output is `carrier[1]`; reassemble
//! `commitment = carrier[0][4..20] ‖ carrier[1][0..16]`.
//!
//! Each carrier output is funded with a tiny `dust` value that is **economically
//! burned** — no keypair is known for these hashes, so the coins are
//! unspendable. That is the honest cost of the current model.
//!
//! ## What a data-carrier GIP would fix
//!
//! A first-class data-carrier output (a future GIP, roadmap §1.6 / §2.2) would
//! let you anchor a full 32-byte (or larger) commitment in **one** explicit,
//! prunable, non-UTXO-bloating output **without burning value** and **without
//! overloading the P2PKH address space**. Until then, this convention is the
//! pragmatic path. See the README.

use crate::commitment::{Commitment, COMMITMENT_LEN};
use crate::error::{AnchorError, Result};

/// 4-byte magic prefixing the first carrier output. `b"BLA1"` = Bloch Anchor v1.
pub const ANCHOR_MAGIC: [u8; 4] = *b"BLA1";

/// Length of a single P2PKH `script_pubkey` on Bloch.
pub const SCRIPT_PUBKEY_LEN: usize = 20;

/// Number of carrier outputs a v1 anchor uses.
pub const CARRIER_OUTPUTS: usize = 2;

/// Default dust value (in satoshis) burned per carrier output.
///
/// 1 BLOCH = 10^8 sat (roadmap §1.3). This is deliberately tiny — it is
/// destroyed, not recoverable. A data-carrier GIP would remove the burn.
pub const DEFAULT_DUST_SATS: u64 = 1;

/// One anchor carrier output: a `value` and a 20-byte `script_pubkey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorOutput {
    /// Burned dust value in satoshis.
    pub value: u64,
    /// The 20-byte P2PKH-shaped script carrying commitment bytes.
    pub script_pubkey: [u8; SCRIPT_PUBKEY_LEN],
}

/// Encode a commitment into the v1 carrier outputs, each funded with `dust`.
pub fn encode(commitment: &Commitment, dust: u64) -> [AnchorOutput; CARRIER_OUTPUTS] {
    let c = commitment.as_bytes();

    let mut s0 = [0u8; SCRIPT_PUBKEY_LEN];
    s0[..4].copy_from_slice(&ANCHOR_MAGIC);
    s0[4..20].copy_from_slice(&c[0..16]);

    let mut s1 = [0u8; SCRIPT_PUBKEY_LEN];
    s1[..16].copy_from_slice(&c[16..32]);
    // s1[16..20] stays zero-padded (reserved).

    [
        AnchorOutput {
            value: dust,
            script_pubkey: s0,
        },
        AnchorOutput {
            value: dust,
            script_pubkey: s1,
        },
    ]
}

/// Encode with the [`DEFAULT_DUST_SATS`] burn value.
pub fn encode_default(commitment: &Commitment) -> [AnchorOutput; CARRIER_OUTPUTS] {
    encode(commitment, DEFAULT_DUST_SATS)
}

/// Scan a transaction's output `script_pubkey`s and recover the commitment plus
/// the exact carrier scripts that encoded it.
///
/// `scripts` is the ordered list of every output `script_pubkey` in the tx.
/// Returns [`AnchorError::NoAnchor`] if no valid v1 anchor is present.
pub fn decode(scripts: &[Vec<u8>]) -> Result<(Commitment, Vec<Vec<u8>>)> {
    for (i, s0) in scripts.iter().enumerate() {
        if s0.len() != SCRIPT_PUBKEY_LEN || s0[..4] != ANCHOR_MAGIC {
            continue;
        }
        // The next output must be the second carrier.
        let s1 = match scripts.get(i + 1) {
            Some(s) if s.len() == SCRIPT_PUBKEY_LEN => s,
            _ => continue,
        };
        let mut bytes = [0u8; COMMITMENT_LEN];
        bytes[0..16].copy_from_slice(&s0[4..20]);
        bytes[16..32].copy_from_slice(&s1[0..16]);
        let commitment = Commitment::from_bytes(bytes);
        return Ok((commitment, vec![s0.clone(), s1.clone()]));
    }
    Err(AnchorError::NoAnchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let c = Commitment::hash_payload(b"checkpoint #7");
        let outs = encode_default(&c);
        assert_eq!(outs[0].script_pubkey[..4], ANCHOR_MAGIC);
        let scripts: Vec<Vec<u8>> = outs.iter().map(|o| o.script_pubkey.to_vec()).collect();
        let (recovered, carriers) = decode(&scripts).unwrap();
        assert_eq!(recovered, c);
        assert_eq!(carriers.len(), 2);
    }

    #[test]
    fn decode_finds_anchor_among_unrelated_outputs() {
        let c = Commitment::hash_payload(b"batch digest");
        let anchor = encode_default(&c);
        // A realistic tx: a change output, then the two carriers.
        let mut scripts = vec![vec![7u8; SCRIPT_PUBKEY_LEN]]; // ordinary P2PKH change
        scripts.push(anchor[0].script_pubkey.to_vec());
        scripts.push(anchor[1].script_pubkey.to_vec());
        let (recovered, _) = decode(&scripts).unwrap();
        assert_eq!(recovered, c);
    }

    #[test]
    fn decode_rejects_when_absent() {
        let scripts = vec![vec![1u8; SCRIPT_PUBKEY_LEN], vec![2u8; SCRIPT_PUBKEY_LEN]];
        assert!(matches!(decode(&scripts), Err(AnchorError::NoAnchor)));
    }
}
