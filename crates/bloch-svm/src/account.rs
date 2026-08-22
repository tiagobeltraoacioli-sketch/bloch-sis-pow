// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SVM account and its canonical codec (spec §3.2).
//!
//! Serialization is canonical by construction — the transition.rs codec
//! idiom exactly (fixed field order, fixed little-endian widths, explicit
//! `u32` length prefix on the one variable-length field, decoder rejects
//! trailing bytes; compare `TxDecodeError::TrailingBytes`,
//! transition.rs:856). There is no serde and no derive-based format: a format
//! that can change when a dependency changes is a consensus break waiting
//! for a version bump (state_root.rs, "Committed state components").
//!
//! What is deliberately NOT here (spec §3.2): `rent_epoch` — state growth is
//! priced by the §4.2 bond precisely because a rent *clock* is a consensus
//! input this design refuses to add; Solana's `executable_data` split and
//! loader versioning — there are no loaders (§11).

use crate::errors::TxStructError;
use crate::params::MAX_ACCOUNT_DATA;

/// One SVM-plane account. Field order is the canonical serialization order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// Balance in satoshis. u64 per entry — the same width the committed
    /// `EutxoEntry.value` uses (state_root.rs:530) — because no single
    /// account may hold more than u64::MAX sat; SUMS are u128 end-to-end
    /// (the interfaces.rs arithmetic contract: the danger was always the
    /// totals, not one entry).
    pub balance_sat: u64,
    /// The program that owns this account. Only the owner may debit
    /// `balance_sat` or mutate `data` (spec §6.2).
    /// [`crate::params::SYSTEM_PROGRAM_ID`] for wallets.
    pub owner: [u8; 32],
    /// Replay protection for fee payers (spec §5.3). Increments on every
    /// transaction this account fee-pays, aborted or not.
    pub nonce: u64,
    /// True if this account is a program. v0: only genesis-registered native
    /// programs; immutable thereafter (no deploy path — spec §11).
    pub executable: bool,
    /// Program-owned bytes. Hard cap [`MAX_ACCOUNT_DATA`] (10 KiB in v0 —
    /// deliberately small; raising it is a parameter change with a fee
    /// argument attached, spec §4.2).
    pub data: Vec<u8>,
}

impl Account {
    /// A fresh system-owned wallet holding `balance_sat`.
    pub fn wallet(balance_sat: u64) -> Self {
        Account {
            balance_sat,
            owner: crate::params::SYSTEM_PROGRAM_ID,
            nonce: 0,
            executable: false,
            data: Vec::new(),
        }
    }

    /// Canonical bytes: `balance_sat u64le ‖ owner 32 ‖ nonce u64le ‖
    /// executable u8(0|1) ‖ data_len u32le ‖ data`. One encoding per value —
    /// `executable` serializes as exactly 0 or 1 so a "true" cannot have 255
    /// encodings.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + 32 + 8 + 1 + 4 + self.data.len());
        b.extend_from_slice(&self.balance_sat.to_le_bytes());
        b.extend_from_slice(&self.owner);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.push(u8::from(self.executable));
        b.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.data);
        b
    }

    /// Decode canonical bytes. Rejects: truncation, a non-0/1 `executable`
    /// byte, `data` beyond [`MAX_ACCOUNT_DATA`] (a decoder that allocates
    /// whatever a hostile length prefix says is a memory-exhaustion vector),
    /// and trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TxStructError> {
        let mut r = Reader::new(bytes);
        let balance_sat = r.u64()?;
        let owner = r.array32()?;
        let nonce = r.u64()?;
        let executable = match r.u8()? {
            0 => false,
            1 => true,
            // Any other byte is a second encoding of a bool — canonicity
            // violation, same family as trailing bytes.
            _ => return Err(TxStructError::TrailingBytes),
        };
        let data_len = r.u32()? as usize;
        if data_len > MAX_ACCOUNT_DATA {
            return Err(TxStructError::CapExceeded { what: "account data", len: data_len, cap: MAX_ACCOUNT_DATA });
        }
        let data = r.bytes(data_len)?.to_vec();
        r.finish()?;
        Ok(Account { balance_sat, owner, nonce, executable, data })
    }
}

/// Minimal cursor over a byte slice. Shared by every decoder in the crate so
/// "rejects trailing bytes" is one implementation, not a per-format habit.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], TxStructError> {
        let end = self.pos.checked_add(n).ok_or(TxStructError::Truncated)?;
        if end > self.bytes.len() {
            return Err(TxStructError::Truncated);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, TxStructError> {
        Ok(self.bytes(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, TxStructError> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, TxStructError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, TxStructError> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    pub(crate) fn array32(&mut self) -> Result<[u8; 32], TxStructError> {
        let b = self.bytes(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
    /// The trailing-byte rejection every canonical decoder ends with.
    pub(crate) fn finish(&self) -> Result<(), TxStructError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(TxStructError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::account_value_hash;

    fn sample() -> Account {
        Account {
            balance_sat: 123_456_789,
            owner: [0xAB; 32],
            nonce: 42,
            executable: false,
            data: vec![1, 2, 3, 4, 5],
        }
    }

    /// §8-9 round-trip half.
    #[test]
    fn codec_round_trips() {
        let a = sample();
        let b = a.to_canonical_bytes();
        assert_eq!(Account::from_canonical_bytes(&b).unwrap(), a);
        // Empty-data account too — the length-prefix edge.
        let w = Account::wallet(7);
        assert_eq!(Account::from_canonical_bytes(&w.to_canonical_bytes()).unwrap(), w);
    }

    /// §8-9 trailing-byte rejection, with the control (exact bytes accept)
    /// in the same test so the negative cannot pass because decoding is
    /// broken wholesale.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut b = sample().to_canonical_bytes();
        assert!(Account::from_canonical_bytes(&b).is_ok(), "control: exact bytes decode");
        b.push(0x00);
        assert_eq!(Account::from_canonical_bytes(&b), Err(TxStructError::TrailingBytes));
        // Truncation is the mirror failure.
        let b2 = sample().to_canonical_bytes();
        assert_eq!(
            Account::from_canonical_bytes(&b2[..b2.len() - 1]),
            Err(TxStructError::Truncated)
        );
    }

    /// A bool with 255 encodings is a canonicity hole: only 0 and 1 decode.
    #[test]
    fn executable_byte_is_canonical() {
        let mut b = Account::wallet(1).to_canonical_bytes();
        b[8 + 32 + 8] = 2;
        assert!(Account::from_canonical_bytes(&b).is_err());
    }

    /// Hostile data length prefix is refused before allocation.
    #[test]
    fn oversized_data_length_is_refused() {
        let mut b = Account::wallet(1).to_canonical_bytes();
        let off = 8 + 32 + 8 + 1;
        b[off..off + 4].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(matches!(
            Account::from_canonical_bytes(&b),
            Err(TxStructError::CapExceeded { .. })
        ));
    }

    /// §8-9 mutation sweep: perturbing every field changes the committed
    /// value hash — the state_root.rs test idiom ("every field perturbed ⇒
    /// root changes"). If any field were missing from the canonical bytes,
    /// its perturbation would leave the hash unchanged and this goes red.
    #[test]
    fn every_field_reaches_the_value_hash() {
        let base = sample();
        let h0 = account_value_hash(&base);
        let mut m1 = base.clone();
        m1.balance_sat += 1;
        let mut m2 = base.clone();
        m2.owner[0] ^= 1;
        let mut m3 = base.clone();
        m3.nonce += 1;
        let mut m4 = base.clone();
        m4.executable = true;
        let mut m5 = base.clone();
        m5.data[0] ^= 1;
        let mut m6 = base.clone();
        m6.data.push(9);
        for (i, m) in [m1, m2, m3, m4, m5, m6].iter().enumerate() {
            assert_ne!(h0, account_value_hash(m), "field perturbation {i} did not reach the hash");
        }
        // Control: the unperturbed account hashes identically twice.
        assert_eq!(h0, account_value_hash(&base));
    }
}
