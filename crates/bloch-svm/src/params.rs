// SPDX-License-Identifier: AGPL-3.0-or-later

//! Constants of the SVM plane.
//!
//! Two very different kinds live here, and the file keeps them visibly apart:
//!
//! 1. **Domain separators and structural caps** (spec §3.1, §5.1, §5.2).
//!    These are format identity: changing one re-keys every hash or changes
//!    which transactions parse, so once anything outside a test pins bytes
//!    against them they are flag-day material.
//! 2. **PROVISIONAL-NOT-CONSENSUS economics** (fee, bond, meter costs). The
//!    spec is explicit that fee-market *constants* are owned by
//!    `fee_market.rs` (spec §1.2, §9.3) and the account bond is "priced
//!    there with a written derivation, not invented here" (§4.2-2). This
//!    crate is standalone software, so until the X1 round decides
//!    `TxClass::Svm` these values exist only so the machine can run and be
//!    tested. They are never to be cited outside this crate.

// ---------------------------------------------------------------------------
// Domain separators — the params.rs §6.1 convention: exactly 16 bytes,
// `BLCH4:` prefix, NUL-padded, and no tag equal to any other (all tags being
// fixed 16-byte arrays, "prefix of another" cannot arise between them; the
// prefix rule bites for variable-length tags, which none of these are).
// Compare crates/bloch-pos-committee/src/params.rs:174-241 for the registry
// this set extends. None of these four appears there — collision with a
// consensus separator would let an SVM hash be replayed as a consensus hash.
// ---------------------------------------------------------------------------

/// Address derivation (spec §3.1):
/// `wallet = SHA3-256(DS_SVM_ADDR ‖ 0x00 ‖ hybrid_pubkey_bytes)`,
/// `pda    = SHA3-256(DS_SVM_ADDR ‖ 0x01 ‖ program_id ‖ seed_count:u8 ‖ (len:u16_le ‖ seed)*)`.
pub const DS_SVM_ADDR: [u8; 16] = *b"BLCH4:SVMADDR\0\0\0";

/// The SVM state tree (spec §4.1). Every SHA3 of `tree.rs` starts with this,
/// exactly as every SHA3 of the consensus tree starts with `DS_STATE`
/// (state_root.rs:212) — own separator because an SVM leaf must never be
/// presentable as a consensus leaf in a proof.
pub const DS_SVM_STATE: [u8; 16] = *b"BLCH4:SVMSTATE\0\0";

/// Transaction signing root (spec §5.1):
/// `SHA3-256(DS_SVM_TX ‖ canonical_bytes_without_witnesses)`.
pub const DS_SVM_TX: [u8; 16] = *b"BLCH4:SVMTX\0\0\0\0\0";

/// Transaction identity: `txid = SHA3-256(DS_SVM_TXID ‖ signing_root)` —
/// mirroring the DS_SPEND/DS_TXID split (committee params.rs:198-207) and its
/// rationale: an identity hash and a signature preimage must never share a
/// preimage space.
pub const DS_SVM_TXID: [u8; 16] = *b"BLCH4:SVMTXID\0\0\0";

/// Address-preimage marker for wallet addresses (spec §3.1). Solana keeps
/// PDAs unspendable by requiring them off-curve; hashes have no curve, so the
/// guarantee is rebuilt by domain separation — forging a hybrid key whose
/// `0x00`-tagged hash equals a `0x01`-tagged PDA is a second-preimage attack
/// on SHA3-256.
pub const ADDR_MARK_WALLET: u8 = 0x00;
/// Address-preimage marker for program-derived addresses (spec §3.1).
pub const ADDR_MARK_PDA: u8 = 0x01;

/// The System program's id. All-zero on purpose: a wallet address is
/// `SHA3-256(DS_SVM_ADDR ‖ 0x00 ‖ pubkey)` and a PDA is a tagged SHA3 too, so
/// occupying the all-zero point would require a preimage of zero — the same
/// reasoning that lets Solana park native programs on unreachable ed25519
/// points. Genesis-registered as `executable`, owner = itself (v0 programs
/// are immutable, §11 "no deploy path").
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Structural caps (spec §5.2) — "small on purpose; each raise needs a cost
// argument". These bound parsing, memory, and the scheduler's O(n²) conflict
// scan, and they are why `u8` indices in the wire format are total.
// ---------------------------------------------------------------------------

/// Hard cap on `accounts.len()` per transaction (spec §5.2: 64).
pub const MAX_TX_ACCOUNTS: usize = 64;
/// Hard cap on `instructions.len()` per transaction (spec §5.2: 16).
pub const MAX_TX_INSTRUCTIONS: usize = 16;
/// Hard cap on one instruction's `data` (spec §5.2: 1 KiB).
pub const MAX_INSTRUCTION_DATA: usize = 1024;
/// Hard cap on `Account::data` (spec §3.2: 10 KiB, "deliberately small;
/// raising it is a parameter change with a fee argument attached").
pub const MAX_ACCOUNT_DATA: usize = 10 * 1024;
/// Decode-time cap on a witness pubkey or signature field. A hybrid
/// ML-DSA-65 ‖ Falcon-1024 pubkey is ≈3.7 KB and a signature 4,589 B
/// (committee params.rs module docs); 16 KiB bounds a hostile length prefix
/// without ever rejecting a real hybrid witness.
pub const MAX_WITNESS_FIELD_BYTES: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// PROVISIONAL-NOT-CONSENSUS economics. Everything below this line is a
// placeholder with a written derivation, pending the X1 re-freeze round
// (spec §9.3: one fee market, `TxClass::Svm` priced in fee_market.rs; spec
// §4.2-2: bond constants priced in fee_market.rs). MIGRATION NOTE: when that
// round happens, these constants move there, this file keeps `pub` re-exports
// only if the crate still needs names, and every KAT that pinned a fee or a
// bond value is expected to change — that churn is the point of keeping them
// quarantined here until then. Never cite these values outside this crate.
// ---------------------------------------------------------------------------

/// Ceiling on a transaction's declared `compute_budget` (spec §5.2).
/// PROVISIONAL-NOT-CONSENSUS. Sized so that at `COST_INSTRUCTION_DISPATCH`
/// (1,000 CU) a maximal transaction still dispatches its 16 instructions with
/// budget left for real work, while `MAX_TX_COMPUTE_UNITS / SVM_CU_PER_SAT`
/// keeps the worst-case fee in whole satoshis.
pub const MAX_TX_COMPUTE_UNITS: u32 = 1_400_000;

/// Flat per-transaction fee, satoshis. PROVISIONAL-NOT-CONSENSUS: the real
/// number is `TxClass::Svm` in fee_market.rs converting CU to L1 gas via the
/// `INSTRUCTIONS_PER_GAS` precedent (fee_market.rs:140) and paying the
/// committed base fee. This placeholder only makes fees nonzero so the
/// abort-still-pays and conservation tests exercise real value movement.
pub const SVM_FEE_FLAT_SAT: u64 = 5_000;

/// Compute units bought per satoshi of variable fee.
/// PROVISIONAL-NOT-CONSENSUS, same migration note as [`SVM_FEE_FLAT_SAT`].
/// Integer division (`budget / SVM_CU_PER_SAT`) is deliberate: deterministic,
/// and rounding down at most under-charges 999 CU ≈ 1 sat.
pub const SVM_CU_PER_SAT: u64 = 1_000;

/// Flat part of the account-creation bond, satoshis (spec §4.2-2).
/// PROVISIONAL-NOT-CONSENSUS. Derivation being priced: the consensus state
/// root is linear in entry count and rebuilt per block — measured 0.59 s for
/// 452,726 entries (engine.rs:1609, 2026-08-21) ≈ **1.3 µs per entry per
/// block per validator, forever**. A bond prices exactly entry-count and
/// byte-count without introducing a rent *clock* into consensus. 2,000,000
/// sat (0.02 BLCH nominal) per entry is a placeholder magnitude: high enough
/// that a million-account spam run costs 20,000 BLCH of locked (not spent —
/// the bond refunds on delete) capital, low enough not to price out real use.
/// The final number is a fee_market.rs decision with its own derivation.
pub const ACCOUNT_BOND_FLAT: u64 = 2_000_000;

/// Per-byte part of the account bond, satoshis (spec §4.2-2).
/// PROVISIONAL-NOT-CONSENSUS, same derivation base: bytes are hashed by every
/// validator on every rebuild of the account's leaf, so byte-count is the
/// second axis the bond prices.
pub const ACCOUNT_BOND_PER_BYTE: u64 = 1_000;

/// Compute cost charged by the *runtime* for dispatching one instruction,
/// before the program runs (spec §6.3 "per-instruction-dispatch flat cost").
/// PROVISIONAL-NOT-CONSENSUS: v0-honest calibration — bounds worst-case block
/// time, does NOT claim Solana-equivalent CU pricing (spec §11).
pub const COST_INSTRUCTION_DISPATCH: u32 = 1_000;

/// Compute cost of one native-program operation ("per-syscall-equivalent",
/// spec §6.3). PROVISIONAL-NOT-CONSENSUS.
pub const COST_NATIVE_OP: u32 = 150;

/// Compute cost per byte written to account data (spec §6.3).
/// PROVISIONAL-NOT-CONSENSUS.
pub const COST_PER_DATA_BYTE_WRITE: u32 = 10;

/// Compute cost per byte read from account data (spec §6.3).
/// PROVISIONAL-NOT-CONSENSUS.
pub const COST_PER_DATA_BYTE_READ: u32 = 1;

/// The bond an account of `data_len` bytes must keep locked (spec §4.2-2):
/// `ACCOUNT_BOND_FLAT + data_len * ACCOUNT_BOND_PER_BYTE`. Checked u64: with
/// `data_len ≤ MAX_ACCOUNT_DATA` this cannot overflow, but the execution path
/// carries no unchecked arithmetic anywhere (spec §2), so the impossible case
/// saturates rather than trusting the cap.
pub fn bond_for(data_len: usize) -> u64 {
    let per_byte = (data_len as u64).saturating_mul(ACCOUNT_BOND_PER_BYTE);
    ACCOUNT_BOND_FLAT.saturating_add(per_byte)
}

/// The provisional fee for a transaction with the given compute budget.
/// PROVISIONAL-NOT-CONSENSUS — see [`SVM_FEE_FLAT_SAT`]. Pure and total:
/// `budget ≤ MAX_TX_COMPUTE_UNITS` keeps the sum far from u64::MAX, and the
/// saturating form documents that even a hostile budget cannot wrap.
pub fn fee_for(compute_budget: u32) -> u64 {
    SVM_FEE_FLAT_SAT.saturating_add(u64::from(compute_budget) / SVM_CU_PER_SAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four separators must be pairwise distinct — equal separators would
    /// merge two preimage spaces the design keeps apart — and must not equal
    /// the consensus DS_STATE, which is the one external separator this crate
    /// deliberately reuses (dev-only, tree.rs cross-KAT) and must never
    /// alias in production.
    #[test]
    fn domain_separators_are_distinct() {
        let all = [DS_SVM_ADDR, DS_SVM_STATE, DS_SVM_TX, DS_SVM_TXID, *b"BLCH4:STATE\0\0\0\0\0"];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "separator {i} collides with {j}");
            }
        }
    }

    /// fee_for is monotone in the budget and pins the provisional formula, so
    /// an accidental constant change is a visible test diff, not silence.
    #[test]
    fn provisional_fee_formula_pinned() {
        assert_eq!(fee_for(0), 5_000);
        assert_eq!(fee_for(999), 5_000, "sub-unit CU rounds down");
        assert_eq!(fee_for(1_000), 5_001);
        assert_eq!(fee_for(MAX_TX_COMPUTE_UNITS), 5_000 + 1_400);
    }

    /// bond_for pins the §4.2-2 shape: flat + linear in bytes.
    #[test]
    fn provisional_bond_formula_pinned() {
        assert_eq!(bond_for(0), ACCOUNT_BOND_FLAT);
        assert_eq!(bond_for(10), ACCOUNT_BOND_FLAT + 10 * ACCOUNT_BOND_PER_BYTE);
        assert_eq!(bond_for(MAX_ACCOUNT_DATA), ACCOUNT_BOND_FLAT + 10_240_000);
    }
}
