// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SVM transaction: format (spec §5.1), canonical codec, structural
//! validation (§5.2), signing root and txid.
//!
//! One deliberate split from the spec's §5.2 list, documented rather than
//! smuggled: §5.2 includes "the program account is not `executable`" among
//! the structural checks, but that predicate needs *state* (the parent's
//! committed accounts), while everything else in the list is a pure function
//! of the bytes. This front runs the stateless checks here
//! ([`SvmTransaction::validate_structure`]) and the two state-dependent ones
//! (program exists / program executable) as execution pre-checks
//! ([`crate::errors::RejectCause::ProgramMissing`] /
//! [`crate::errors::RejectCause::ProgramNotExecutable`]) — both still run at
//! mempool AND block validation, which is what the §5.2 rule is actually
//! protecting. Determinism is unchanged: the pre-checks read only declared
//! accounts from the committed snapshot, so the §7 waves serialize any
//! writer before this reader.

use crate::account::Reader;
use crate::address::wallet_address;
use crate::errors::TxStructError;
use crate::params::{
    ADDR_MARK_WALLET, DS_SVM_TX, DS_SVM_TXID, MAX_INSTRUCTION_DATA, MAX_TX_ACCOUNTS,
    MAX_TX_COMPUTE_UNITS, MAX_TX_INSTRUCTIONS, MAX_WITNESS_FIELD_BYTES,
};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

/// One declared account: just the address. Solana's per-meta signer/writable
/// flags live in the section layout here (spec §5.1) — the counts ARE the
/// encoding, so redundant/conflicting encodings of the same declaration are
/// impossible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    /// The account's address (spec §3.1).
    pub address: [u8; 32],
}

/// One instruction: a program (by index into `accounts`) applied to a subset
/// of the declared accounts with opaque data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// Index into `SvmTransaction::accounts` of the program to run.
    pub program_index: u8,
    /// Indices into `accounts` of the accounts this instruction hands the
    /// program, in the order the program will see them.
    pub account_indices: Vec<u8>,
    /// Program-interpreted bytes (≤ [`MAX_INSTRUCTION_DATA`]).
    pub data: Vec<u8>,
}

/// One hybrid (ML-DSA-65 ‖ Falcon-1024) witness. The pubkey travels here —
/// the state stores only hashes (spec §3.1/§5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    /// The full hybrid pubkey whose [`wallet_address`] must equal the signer
    /// section address it accompanies.
    pub pubkey: Vec<u8>,
    /// Signature over the signing root, verified by the host callback
    /// ([`crate::runtime::SignatureVerifier`]).
    pub sig: Vec<u8>,
}

/// How index `i` of the flat account list is declared, given the header
/// `(n_ws, n_rs, n_w)`: `[ writable signers | readonly signers | writable |
/// readonly ]` (spec §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclKind {
    /// Writable + signer. `accounts[0]` (the fee payer) is always this.
    WritableSigner,
    /// Readonly + signer.
    ReadonlySigner,
    /// Writable, not a signer.
    Writable,
    /// Readonly, not a signer — the implied tail section.
    Readonly,
}

impl DeclKind {
    /// Whether this declaration grants mutation (§6.1: the capability the
    /// handle is built from).
    pub fn is_writable(self) -> bool {
        matches!(self, DeclKind::WritableSigner | DeclKind::Writable)
    }
    /// Whether a witness vouches for this account in this transaction.
    pub fn is_signer(self) -> bool {
        matches!(self, DeclKind::WritableSigner | DeclKind::ReadonlySigner)
    }
}

/// The SVM transaction (spec §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SvmTransaction {
    /// Format version. 0. Bump = consensus change, flag-day rules.
    pub version: u8,
    /// Compute units requested (§6.3). Declared, not discovered, so the
    /// scheduler and fee market know the worst case before running.
    pub compute_budget: u32,
    /// Replay protection: must equal the fee payer's committed nonce (§5.3).
    pub nonce: u64,
    /// The flat, deduplicated account list in canonical section order.
    pub accounts: Vec<AccountMeta>,
    /// Section boundaries `(n_ws, n_rs, n_w)`; the readonly tail is implied.
    pub header: (u8, u8, u8),
    /// The instructions, executed in order, no nesting (no CPI — §11).
    pub instructions: Vec<Instruction>,
    /// One witness per signer-section entry, in section order.
    pub witnesses: Vec<Witness>,
}

impl SvmTransaction {
    /// The declaration of `accounts[i]`, or `None` past the end. Pure
    /// arithmetic over the header — this is the single definition every
    /// other module (runtime handles, scheduler sets) reads, so "writable"
    /// cannot mean two things in two places.
    pub fn decl_kind(&self, i: usize) -> Option<DeclKind> {
        if i >= self.accounts.len() {
            return None;
        }
        let (n_ws, n_rs, n_w) = self.header;
        let (n_ws, n_rs, n_w) = (n_ws as usize, n_rs as usize, n_w as usize);
        Some(if i < n_ws {
            DeclKind::WritableSigner
        } else if i < n_ws + n_rs {
            DeclKind::ReadonlySigner
        } else if i < n_ws + n_rs + n_w {
            DeclKind::Writable
        } else {
            DeclKind::Readonly
        })
    }

    /// Declared writable addresses, `W(t)` of the §7.1 conflict relation.
    pub fn writable_set(&self) -> BTreeSet<[u8; 32]> {
        self.accounts
            .iter()
            .enumerate()
            .filter(|(i, _)| self.decl_kind(*i).is_some_and(DeclKind::is_writable))
            .map(|(_, m)| m.address)
            .collect()
    }

    /// Declared readonly addresses, `R(t)` of the §7.1 conflict relation.
    pub fn readonly_set(&self) -> BTreeSet<[u8; 32]> {
        self.accounts
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.decl_kind(*i).is_some_and(DeclKind::is_writable))
            .map(|(_, m)| m.address)
            .collect()
    }

    /// Canonical bytes WITHOUT witnesses — the signing preimage. Field order
    /// is declaration order (§5.1); integers LE fixed-width; every
    /// variable-length list carries an explicit count (the transition.rs
    /// codec idiom).
    pub fn canonical_bytes_unsigned(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + 32 * self.accounts.len());
        b.push(self.version);
        b.extend_from_slice(&self.compute_budget.to_le_bytes());
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.push(self.header.0);
        b.push(self.header.1);
        b.push(self.header.2);
        // accounts.len() ≤ 64 (validated) so u8 is total; the decoder
        // re-checks the cap before trusting the count.
        b.push(self.accounts.len() as u8);
        for m in &self.accounts {
            b.extend_from_slice(&m.address);
        }
        b.push(self.instructions.len() as u8);
        for ins in &self.instructions {
            b.push(ins.program_index);
            b.push(ins.account_indices.len() as u8);
            b.extend_from_slice(&ins.account_indices);
            b.extend_from_slice(&(ins.data.len() as u16).to_le_bytes());
            b.extend_from_slice(&ins.data);
        }
        b
    }

    /// Full canonical bytes: unsigned preimage + witnesses.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut b = self.canonical_bytes_unsigned();
        b.push(self.witnesses.len() as u8);
        for w in &self.witnesses {
            b.extend_from_slice(&(w.pubkey.len() as u32).to_le_bytes());
            b.extend_from_slice(&w.pubkey);
            b.extend_from_slice(&(w.sig.len() as u32).to_le_bytes());
            b.extend_from_slice(&w.sig);
        }
        b
    }

    /// Decode + full structural validation. There is no decode-without-
    /// validation entry point on purpose: a transaction that exists as a
    /// value has passed §5.2, which is what lets the runtime and scheduler
    /// trust `decl_kind` and the index bounds without re-checking.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TxStructError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        let compute_budget = r.u32()?;
        let nonce = r.u64()?;
        let header = (r.u8()?, r.u8()?, r.u8()?);
        let n_accounts = r.u8()? as usize;
        if n_accounts > MAX_TX_ACCOUNTS {
            return Err(TxStructError::CapExceeded { what: "accounts", len: n_accounts, cap: MAX_TX_ACCOUNTS });
        }
        let mut accounts = Vec::with_capacity(n_accounts);
        for _ in 0..n_accounts {
            accounts.push(AccountMeta { address: r.array32()? });
        }
        let n_instructions = r.u8()? as usize;
        if n_instructions > MAX_TX_INSTRUCTIONS {
            return Err(TxStructError::CapExceeded { what: "instructions", len: n_instructions, cap: MAX_TX_INSTRUCTIONS });
        }
        let mut instructions = Vec::with_capacity(n_instructions);
        for _ in 0..n_instructions {
            let program_index = r.u8()?;
            let n_idx = r.u8()? as usize;
            if n_idx > MAX_TX_ACCOUNTS {
                return Err(TxStructError::CapExceeded { what: "instruction accounts", len: n_idx, cap: MAX_TX_ACCOUNTS });
            }
            let account_indices = r.bytes(n_idx)?.to_vec();
            let data_len = r.u16()? as usize;
            if data_len > MAX_INSTRUCTION_DATA {
                return Err(TxStructError::CapExceeded { what: "instruction data", len: data_len, cap: MAX_INSTRUCTION_DATA });
            }
            let data = r.bytes(data_len)?.to_vec();
            instructions.push(Instruction { program_index, account_indices, data });
        }
        let n_witnesses = r.u8()? as usize;
        if n_witnesses > MAX_TX_ACCOUNTS {
            return Err(TxStructError::CapExceeded { what: "witnesses", len: n_witnesses, cap: MAX_TX_ACCOUNTS });
        }
        let mut witnesses = Vec::with_capacity(n_witnesses);
        for _ in 0..n_witnesses {
            let pk_len = r.u32()? as usize;
            if pk_len > MAX_WITNESS_FIELD_BYTES {
                return Err(TxStructError::CapExceeded { what: "witness pubkey", len: pk_len, cap: MAX_WITNESS_FIELD_BYTES });
            }
            let pubkey = r.bytes(pk_len)?.to_vec();
            let sig_len = r.u32()? as usize;
            if sig_len > MAX_WITNESS_FIELD_BYTES {
                return Err(TxStructError::CapExceeded { what: "witness sig", len: sig_len, cap: MAX_WITNESS_FIELD_BYTES });
            }
            let sig = r.bytes(sig_len)?.to_vec();
            witnesses.push(Witness { pubkey, sig });
        }
        r.finish()?; // trailing-byte rejection (§5.2)
        let tx = SvmTransaction { version, compute_budget, nonce, accounts, header, instructions, witnesses };
        tx.validate_structure()?;
        Ok(tx)
    }

    /// The stateless §5.2 checks, in a fixed order so the FIRST violation is
    /// the deterministic error every node reports.
    pub fn validate_structure(&self) -> Result<(), TxStructError> {
        if self.version != 0 {
            return Err(TxStructError::UnsupportedVersion(self.version));
        }
        if self.compute_budget > MAX_TX_COMPUTE_UNITS {
            return Err(TxStructError::ComputeBudgetTooLarge { budget: self.compute_budget });
        }
        if self.accounts.len() > MAX_TX_ACCOUNTS {
            return Err(TxStructError::CapExceeded { what: "accounts", len: self.accounts.len(), cap: MAX_TX_ACCOUNTS });
        }
        if self.instructions.len() > MAX_TX_INSTRUCTIONS {
            return Err(TxStructError::CapExceeded { what: "instructions", len: self.instructions.len(), cap: MAX_TX_INSTRUCTIONS });
        }
        let (n_ws, n_rs, n_w) = self.header;
        let section_sum = n_ws as usize + n_rs as usize + n_w as usize;
        if section_sum > self.accounts.len() {
            return Err(TxStructError::HeaderInconsistent { n_ws, n_rs, n_w, accounts: self.accounts.len() });
        }
        // accounts[0] is the fee payer and MUST be a writable signer (§5.1).
        if self.accounts.is_empty() || n_ws == 0 {
            return Err(TxStructError::FeePayerSectionEmpty);
        }
        // Address dedup across ALL sections — the aliasing dodge dies at
        // parse time (§5.2).
        let mut seen = BTreeSet::new();
        for m in &self.accounts {
            if !seen.insert(m.address) {
                return Err(TxStructError::DuplicateAccount { address: m.address });
            }
        }
        for (n, ins) in self.instructions.iter().enumerate() {
            if ins.account_indices.len() > MAX_TX_ACCOUNTS {
                return Err(TxStructError::CapExceeded { what: "instruction accounts", len: ins.account_indices.len(), cap: MAX_TX_ACCOUNTS });
            }
            if ins.data.len() > MAX_INSTRUCTION_DATA {
                return Err(TxStructError::CapExceeded { what: "instruction data", len: ins.data.len(), cap: MAX_INSTRUCTION_DATA });
            }
            if (ins.program_index as usize) >= self.accounts.len() {
                return Err(TxStructError::IndexOutOfRange { instruction: n, index: ins.program_index });
            }
            let mut idx_seen = BTreeSet::new();
            for &i in &ins.account_indices {
                if (i as usize) >= self.accounts.len() {
                    return Err(TxStructError::IndexOutOfRange { instruction: n, index: i });
                }
                // Handles are exclusive borrows; the same account twice in
                // one instruction would alias mutable state (errors.rs doc).
                if !idx_seen.insert(i) {
                    return Err(TxStructError::DuplicateIndexInInstruction { instruction: n, index: i });
                }
            }
        }
        // One witness per signer, in section order (§5.1), each pubkey
        // hashing to its address with the wallet tag (§5.2). ADDR_MARK_WALLET
        // is what makes a PDA unable to "sign": a PDA lives in the 0x01
        // preimage space and no pubkey can hash into it (§3.1).
        let n_signers = n_ws as usize + n_rs as usize;
        if self.witnesses.len() != n_signers {
            return Err(TxStructError::WitnessCountMismatch { expected: n_signers, got: self.witnesses.len() });
        }
        debug_assert_eq!(ADDR_MARK_WALLET, 0x00);
        for (i, w) in self.witnesses.iter().enumerate() {
            if w.pubkey.len() > MAX_WITNESS_FIELD_BYTES || w.sig.len() > MAX_WITNESS_FIELD_BYTES {
                return Err(TxStructError::CapExceeded {
                    what: "witness field",
                    len: w.pubkey.len().max(w.sig.len()),
                    cap: MAX_WITNESS_FIELD_BYTES,
                });
            }
            if wallet_address(&w.pubkey) != self.accounts[i].address {
                return Err(TxStructError::WitnessAddressMismatch { witness: i });
            }
        }
        Ok(())
    }

    /// Signing root: `SHA3-256(DS_SVM_TX ‖ canonical_bytes_without_witnesses)`
    /// (spec §5.1). Witnesses are excluded so a signature does not sign
    /// itself.
    pub fn signing_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_SVM_TX);
        h.update(self.canonical_bytes_unsigned());
        h.finalize().into()
    }

    /// `txid = SHA3-256(DS_SVM_TXID ‖ signing_root)` — the DS_SPEND/DS_TXID
    /// split mirrored (committee params.rs:198-207): identity and signature
    /// preimages never share a space, and (deliberately, like the eUTXO
    /// plane) the txid does not cover witnesses, so malleating a signature
    /// cannot change a transaction's identity.
    pub fn txid(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_SVM_TXID);
        h.update(self.signing_root());
        h.finalize().into()
    }
}

/// A builder shared by tests across the crate (pub because scheduler and
/// runtime tests construct many transactions; carrying no unsafe defaults —
/// every field is explicit at the call sites that matter).
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// A transaction whose signer addresses are derived from the given
    /// pubkeys (witness sigs empty — pair with the accept-all verifier).
    /// Sections: `ws_pubkeys` become writable signers (payer first),
    /// `writable` and `readonly` are non-signer addresses.
    pub(crate) fn tx(
        ws_pubkeys: &[&[u8]],
        writable: &[[u8; 32]],
        readonly: &[[u8; 32]],
        nonce: u64,
        compute_budget: u32,
        instructions: Vec<Instruction>,
    ) -> SvmTransaction {
        let mut accounts = Vec::new();
        let mut witnesses = Vec::new();
        for pk in ws_pubkeys {
            accounts.push(AccountMeta { address: wallet_address(pk) });
            witnesses.push(Witness { pubkey: pk.to_vec(), sig: vec![0xEE] });
        }
        for a in writable {
            accounts.push(AccountMeta { address: *a });
        }
        for a in readonly {
            accounts.push(AccountMeta { address: *a });
        }
        SvmTransaction {
            version: 0,
            compute_budget,
            nonce,
            header: (ws_pubkeys.len() as u8, 0, writable.len() as u8),
            accounts,
            instructions,
            witnesses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::tx;
    use super::*;

    fn two_account_tx() -> SvmTransaction {
        tx(&[b"payer key"], &[[0x22; 32]], &[[0x33; 32]], 0, 10_000, vec![])
    }

    /// Round-trip + the decoder runs full validation (a decoded value has
    /// passed §5.2 by construction).
    #[test]
    fn codec_round_trips_and_validates() {
        let t = two_account_tx();
        let b = t.to_canonical_bytes();
        assert_eq!(SvmTransaction::from_canonical_bytes(&b).unwrap(), t);
    }

    /// §5.2 trailing bytes; control in the same test.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut b = two_account_tx().to_canonical_bytes();
        assert!(SvmTransaction::from_canonical_bytes(&b).is_ok(), "control");
        b.push(0);
        assert_eq!(SvmTransaction::from_canonical_bytes(&b), Err(TxStructError::TrailingBytes));
    }

    /// §8-4: the aliasing rejection. The same address declared readonly AND
    /// writable is refused at parse time; **control:** the identical
    /// two-account transaction with distinct addresses is accepted.
    #[test]
    fn aliasing_across_sections_is_refused() {
        let dup = [0x22; 32];
        let mut t = tx(&[b"payer key"], &[dup], &[dup], 0, 10_000, vec![]);
        assert_eq!(
            t.validate_structure(),
            Err(TxStructError::DuplicateAccount { address: dup })
        );
        // Control: distinct addresses, same shape ⇒ accepted.
        t = two_account_tx();
        assert_eq!(t.validate_structure(), Ok(()));
    }

    /// Duplicate index inside one instruction (the aliasing dodge one level
    /// down) is refused; control: distinct indices accepted.
    #[test]
    fn duplicate_index_in_instruction_is_refused() {
        let ins = Instruction { program_index: 2, account_indices: vec![1, 1], data: vec![] };
        let t = tx(&[b"payer key"], &[[0x22; 32]], &[[0x33; 32]], 0, 10_000, vec![ins]);
        assert!(matches!(
            t.validate_structure(),
            Err(TxStructError::DuplicateIndexInInstruction { instruction: 0, index: 1 })
        ));
        let ins_ok = Instruction { program_index: 2, account_indices: vec![0, 1], data: vec![] };
        let t_ok = tx(&[b"payer key"], &[[0x22; 32]], &[[0x33; 32]], 0, 10_000, vec![ins_ok]);
        assert_eq!(t_ok.validate_structure(), Ok(()));
    }

    /// Out-of-range program/account indices are refused; header inconsistency
    /// is refused; fee-payer section may not be empty.
    #[test]
    fn index_and_header_bounds() {
        let bad_prog = Instruction { program_index: 9, account_indices: vec![], data: vec![] };
        let t = tx(&[b"payer key"], &[], &[], 0, 1, vec![bad_prog]);
        assert!(matches!(t.validate_structure(), Err(TxStructError::IndexOutOfRange { .. })));

        let bad_idx = Instruction { program_index: 0, account_indices: vec![7], data: vec![] };
        let t = tx(&[b"payer key"], &[], &[], 0, 1, vec![bad_idx]);
        assert!(matches!(t.validate_structure(), Err(TxStructError::IndexOutOfRange { .. })));

        let mut t = two_account_tx();
        t.header = (5, 0, 0); // counts exceed accounts.len()
        assert!(matches!(t.validate_structure(), Err(TxStructError::HeaderInconsistent { .. })));

        let mut t = two_account_tx();
        t.header = (0, 0, 0); // no writable signer ⇒ no fee payer
        // (witness count now also mismatches, but the payer check runs first
        // only after dedup — assert on whichever typed error arrives, the
        // point is refusal with a §5.2 error, deterministically the same one.)
        assert_eq!(t.validate_structure(), Err(TxStructError::FeePayerSectionEmpty));
    }

    /// §5.2: a witness pubkey that does not hash to its section's address is
    /// refused; control: the honest pubkey passes.
    #[test]
    fn witness_address_binding() {
        let mut t = two_account_tx();
        assert_eq!(t.validate_structure(), Ok(()), "control");
        t.witnesses[0].pubkey = b"some other key".to_vec();
        assert_eq!(
            t.validate_structure(),
            Err(TxStructError::WitnessAddressMismatch { witness: 0 })
        );
    }

    /// Witness count must equal the signer sections exactly.
    #[test]
    fn witness_count_must_match_signers() {
        let mut t = two_account_tx();
        t.witnesses.push(Witness { pubkey: vec![], sig: vec![] });
        assert!(matches!(
            t.validate_structure(),
            Err(TxStructError::WitnessCountMismatch { expected: 1, got: 2 })
        ));
    }

    /// Caps: budget, instruction data. Controls at the cap boundary.
    #[test]
    fn caps_are_enforced() {
        let mut t = two_account_tx();
        t.compute_budget = MAX_TX_COMPUTE_UNITS + 1;
        assert!(matches!(t.validate_structure(), Err(TxStructError::ComputeBudgetTooLarge { .. })));
        t.compute_budget = MAX_TX_COMPUTE_UNITS;
        assert_eq!(t.validate_structure(), Ok(()), "control: at cap");

        let big = Instruction { program_index: 0, account_indices: vec![], data: vec![0; MAX_INSTRUCTION_DATA + 1] };
        let t = tx(&[b"payer key"], &[], &[], 0, 1, vec![big]);
        assert!(matches!(t.validate_structure(), Err(TxStructError::CapExceeded { what: "instruction data", .. })));
        let at_cap = Instruction { program_index: 0, account_indices: vec![], data: vec![0; MAX_INSTRUCTION_DATA] };
        let t = tx(&[b"payer key"], &[], &[], 0, 1, vec![at_cap]);
        assert_eq!(t.validate_structure(), Ok(()), "control: at cap");
    }

    /// The signing root ignores witnesses (a signature must not sign
    /// itself); the txid therefore survives witness malleation, and body
    /// changes move both. The DS_SPEND/DS_TXID-split property, §5.1.
    #[test]
    fn signing_root_excludes_witnesses() {
        let t = two_account_tx();
        let (root, id) = (t.signing_root(), t.txid());
        let mut malleated = t.clone();
        malleated.witnesses[0].sig = vec![0xFF; 64];
        assert_eq!(malleated.signing_root(), root);
        assert_eq!(malleated.txid(), id);
        let mut changed = t.clone();
        changed.nonce += 1;
        assert_ne!(changed.signing_root(), root, "control: body reaches the root");
        assert_ne!(changed.txid(), id);
        assert_ne!(root, id, "identity and signing preimages are separated");
    }

    /// decl_kind partitions the list exactly as §5.1 draws it.
    #[test]
    fn section_layout_is_exact() {
        let mut t = two_account_tx(); // 1 ws + 1 w + 1 ro
        t.header = (1, 0, 1);
        assert_eq!(t.decl_kind(0), Some(DeclKind::WritableSigner));
        assert_eq!(t.decl_kind(1), Some(DeclKind::Writable));
        assert_eq!(t.decl_kind(2), Some(DeclKind::Readonly));
        assert_eq!(t.decl_kind(3), None);
        assert_eq!(t.writable_set().len(), 2);
        assert_eq!(t.readonly_set().len(), 1);
    }
}
