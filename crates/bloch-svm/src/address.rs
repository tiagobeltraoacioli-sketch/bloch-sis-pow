// SPDX-License-Identifier: AGPL-3.0-or-later

//! SVM addresses — the PQ divergence from Solana, spec §3.1.
//!
//! A Solana address IS a 32-byte ed25519 public key. A Bloch hybrid key
//! (ML-DSA-65 ‖ Falcon-1024) is ≈3.7 KB, so the address cannot be the key.
//! This module follows the exact trick the eUTXO plane uses (`script_hash`
//! stores the hash; the key only hits the wire when spending —
//! `TransferInput.pubkey`, transition.rs):
//!
//! ```text
//! wallet:  SHA3-256(DS_SVM_ADDR ‖ 0x00 ‖ hybrid_pubkey_bytes)
//! PDA:     SHA3-256(DS_SVM_ADDR ‖ 0x01 ‖ program_id ‖ seed_count:u8 ‖ (len:u16_le ‖ seed)*)
//! ```
//!
//! The marker byte rebuilds Solana's off-curve guarantee by domain
//! separation (params.rs docs). Seeds are length-prefixed **individually**
//! because `["ab","c"]` and `["a","bc"]` must not collide — a real bug class
//! in seed schemes, pinned red by `seed_boundaries_do_not_collide` below.
//! No bump search: there is no on-curve case to skip, so Solana's find-bump
//! loop has nothing to do here (`create_with_seed` compatibility is
//! consequently out — spec §11).

use crate::errors::TxStructError;
use crate::params::{ADDR_MARK_PDA, ADDR_MARK_WALLET, DS_SVM_ADDR};
use sha3::{Digest, Sha3_256};

/// Maximum seeds per PDA and maximum bytes per seed. `u8` count and `u16_le`
/// length prefixes make larger values unrepresentable on the wire; the named
/// caps keep hostile in-memory inputs bounded too.
pub const MAX_PDA_SEEDS: usize = 16;
/// See [`MAX_PDA_SEEDS`].
pub const MAX_PDA_SEED_LEN: usize = 32;

fn sha3_addr(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_SVM_ADDR);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The wallet address of a hybrid public key (spec §3.1).
///
/// Total: any byte string hashes. Whether the bytes are a well-formed hybrid
/// key is the signature verifier's business ([`crate::runtime::SignatureVerifier`]) —
/// address derivation must not need to parse a key, exactly as `script_hash`
/// derivation does not.
pub fn wallet_address(hybrid_pubkey: &[u8]) -> [u8; 32] {
    sha3_addr(&[&[ADDR_MARK_WALLET], hybrid_pubkey])
}

/// The program-derived address for `(program_id, seeds)` (spec §3.1).
///
/// Errors with the cap that was violated; a PDA that cannot be derived
/// deterministically by every node is not an address.
pub fn pda(program_id: &[u8; 32], seeds: &[&[u8]]) -> Result<[u8; 32], TxStructError> {
    if seeds.len() > MAX_PDA_SEEDS {
        return Err(TxStructError::CapExceeded { what: "pda seeds", len: seeds.len(), cap: MAX_PDA_SEEDS });
    }
    let mut h = Sha3_256::new();
    h.update(DS_SVM_ADDR);
    h.update([ADDR_MARK_PDA]);
    h.update(program_id);
    // seed_count as u8 is total after the cap check (MAX_PDA_SEEDS = 16).
    h.update([seeds.len() as u8]);
    for s in seeds {
        if s.len() > MAX_PDA_SEED_LEN {
            return Err(TxStructError::CapExceeded { what: "pda seed", len: s.len(), cap: MAX_PDA_SEED_LEN });
        }
        // The individual length prefix IS the collision defence: without it
        // the concatenation ["ab","c"] / ["a","bc"] merges. u16_le per spec —
        // wider than the cap needs, but the spec fixed the wire shape.
        h.update((s.len() as u16).to_le_bytes());
        h.update(s);
    }
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT: pin the exact derivation bytes. Any change to the separator, the
    /// marker, or the layout is a visible red test, not a silent re-keying of
    /// every address (the state_root.rs test idiom).
    #[test]
    fn wallet_address_kat() {
        let a = wallet_address(b"example hybrid pubkey bytes");
        // Independently recomputed with the documented preimage layout.
        let mut h = Sha3_256::new();
        h.update(DS_SVM_ADDR);
        h.update([0x00]);
        h.update(b"example hybrid pubkey bytes");
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(a, expect);
        // And pinned as hex so the preimage layout itself cannot drift along
        // with a "matching" recomputation.
        assert_eq!(
            hex::encode(a),
            "fb048f4fbbfa63b3816e0b2266b5adf82353bc08505a9014d0e661e5648892f2"
        );
    }

    /// The wallet and PDA preimage spaces never meet: identical trailing
    /// bytes under the two markers give different addresses. This is the
    /// off-curve guarantee, rebuilt (spec §3.1).
    #[test]
    fn wallet_and_pda_domains_are_disjoint() {
        let raw = [0u8; 37]; // program_id(32) + count(1) + len(2) + seed(2) shaped
        let as_wallet = wallet_address(&raw);
        let as_pda = pda(&[0u8; 32], &[&[0u8, 0u8]]).unwrap();
        assert_ne!(as_wallet, as_pda);
    }

    /// The seed-boundary collision the individual length prefixes exist to
    /// kill: `["ab","c"]` vs `["a","bc"]`. Control half: the same seed list
    /// derives the same address twice (determinism), so the negative cannot
    /// be passing because derivation is random.
    #[test]
    fn seed_boundaries_do_not_collide() {
        let p = [7u8; 32];
        let a = pda(&p, &[b"ab", b"c"]).unwrap();
        let b = pda(&p, &[b"a", b"bc"]).unwrap();
        assert_ne!(a, b, "seed boundaries must be part of the preimage");
        // Control: derivation is a pure function.
        assert_eq!(a, pda(&p, &[b"ab", b"c"]).unwrap());
    }

    /// Different programs never share a PDA for the same seeds — the
    /// program_id is bound into the preimage. Control: same program, same
    /// seeds, same address.
    #[test]
    fn pda_binds_program_id() {
        let a = pda(&[1u8; 32], &[b"vault"]).unwrap();
        let b = pda(&[2u8; 32], &[b"vault"]).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, pda(&[1u8; 32], &[b"vault"]).unwrap());
    }

    /// Cap violations are typed errors, not truncation. Control: at-cap
    /// inputs derive.
    #[test]
    fn pda_caps_are_enforced() {
        let p = [3u8; 32];
        let long = [0u8; MAX_PDA_SEED_LEN + 1];
        assert!(matches!(pda(&p, &[&long]), Err(TxStructError::CapExceeded { .. })));
        let at_cap = [0u8; MAX_PDA_SEED_LEN];
        assert!(pda(&p, &[&at_cap]).is_ok(), "control: at-cap seed derives");
        let many: Vec<&[u8]> = vec![b"s"; MAX_PDA_SEEDS + 1];
        assert!(matches!(pda(&p, &many), Err(TxStructError::CapExceeded { .. })));
        let many_ok: Vec<&[u8]> = vec![b"s"; MAX_PDA_SEEDS];
        assert!(pda(&p, &many_ok).is_ok(), "control: at-cap count derives");
    }
}
