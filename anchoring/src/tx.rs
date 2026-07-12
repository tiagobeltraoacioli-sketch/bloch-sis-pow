// SPDX-License-Identifier: MIT OR Apache-2.0
//! A **minimal, self-contained** transaction codec — enough to build an anchor
//! tx skeleton and to decode outputs back off the chain.
//!
//! This is intentionally NOT the node's exact wire format. The real byte layout,
//! the hybrid Falcon-1024 ‖ ML-DSA-65 `script_sig`, coin selection, and the
//! non-malleable `txid` (which excludes `script_sig`) all live in the node /
//! `bloch-crypto` `WalletCore`, which is byte-compatible with consensus
//! (roadmap §1.4). A production integration signs via that wallet and only
//! *uses* this crate for the commitment convention.
//!
//! What this codec IS: a faithful UTXO shape (version, inputs, outputs,
//! locktime) with varint-prefixed fields, so the reference example can do a real
//! encode → hex → decode round-trip and the [`crate::rpc::MockTransport`] can
//! parse what the signer produced. See the README for the boundary.

use crate::error::{AnchorError, Result};
use sha3::{Digest, Sha3_256};

/// A transaction input (spends a previous output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    /// The txid being spent.
    pub prev_txid: [u8; 32],
    /// The output index within that tx.
    pub prev_index: u32,
    /// Signature script (empty in an unsigned skeleton).
    pub script_sig: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    /// Value in satoshis.
    pub value: u64,
    /// Locking script (20-byte P2PKH, or a 20-byte anchor carrier).
    pub script_pubkey: Vec<u8>,
}

/// A minimal UTXO transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Format version.
    pub version: u32,
    /// Inputs.
    pub inputs: Vec<TxInput>,
    /// Outputs.
    pub outputs: Vec<TxOutput>,
    /// Locktime.
    pub locktime: u32,
}

fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    // LEB128-style varint (self-contained; not consensus-critical here).
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *buf
            .get(*pos)
            .ok_or_else(|| AnchorError::TxDecode("truncated varint".into()))?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(AnchorError::TxDecode("varint overflow".into()));
        }
    }
    Ok(result)
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .ok_or_else(|| AnchorError::TxDecode("length overflow".into()))?;
    if end > buf.len() {
        return Err(AnchorError::TxDecode("truncated field".into()));
    }
    let slice = &buf[*pos..end];
    *pos = end;
    Ok(slice)
}

impl Transaction {
    /// Serialize to the minimal wire bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prev_txid);
            out.extend_from_slice(&i.prev_index.to_le_bytes());
            write_varint(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(&i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            out.extend_from_slice(&o.value.to_le_bytes());
            write_varint(&mut out, o.script_pubkey.len() as u64);
            out.extend_from_slice(&o.script_pubkey);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// Serialize and hex-encode (what `sendrawtransaction` expects).
    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize())
    }

    /// Parse from the minimal wire bytes.
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let version = u32::from_le_bytes(
            read_bytes(buf, &mut pos, 4)?
                .try_into()
                .map_err(|_| AnchorError::TxDecode("version".into()))?,
        );
        let in_count = read_varint(buf, &mut pos)?;
        let mut inputs = Vec::with_capacity(in_count.min(1024) as usize);
        for _ in 0..in_count {
            let prev_txid: [u8; 32] = read_bytes(buf, &mut pos, 32)?
                .try_into()
                .map_err(|_| AnchorError::TxDecode("prev_txid".into()))?;
            let prev_index = u32::from_le_bytes(
                read_bytes(buf, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| AnchorError::TxDecode("prev_index".into()))?,
            );
            let sig_len = read_varint(buf, &mut pos)? as usize;
            let script_sig = read_bytes(buf, &mut pos, sig_len)?.to_vec();
            let sequence = u32::from_le_bytes(
                read_bytes(buf, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| AnchorError::TxDecode("sequence".into()))?,
            );
            inputs.push(TxInput {
                prev_txid,
                prev_index,
                script_sig,
                sequence,
            });
        }
        let out_count = read_varint(buf, &mut pos)?;
        let mut outputs = Vec::with_capacity(out_count.min(1024) as usize);
        for _ in 0..out_count {
            let value = u64::from_le_bytes(
                read_bytes(buf, &mut pos, 8)?
                    .try_into()
                    .map_err(|_| AnchorError::TxDecode("value".into()))?,
            );
            let spk_len = read_varint(buf, &mut pos)? as usize;
            if spk_len > 10_000 {
                return Err(AnchorError::TxDecode("implausible script_pubkey length".into()));
            }
            let script_pubkey = read_bytes(buf, &mut pos, spk_len)?.to_vec();
            outputs.push(TxOutput {
                value,
                script_pubkey,
            });
        }
        let locktime = u32::from_le_bytes(
            read_bytes(buf, &mut pos, 4)?
                .try_into()
                .map_err(|_| AnchorError::TxDecode("locktime".into()))?,
        );
        Ok(Transaction {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    /// Parse from hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        Self::deserialize(&hex::decode(s.trim())?)
    }

    /// A reference txid: SHA3-256 over the serialization **excluding
    /// `script_sig`** (non-malleable, matching the node's `SIGHASH_ALL` rule
    /// in spirit — roadmap §1.3). This is NOT byte-identical to the node txid;
    /// a real integration reads the txid the node returns.
    pub fn txid(&self) -> [u8; 32] {
        let mut stripped = self.clone();
        for i in &mut stripped.inputs {
            i.script_sig.clear();
        }
        let mut h = Sha3_256::new();
        h.update(stripped.serialize());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// The ordered output `script_pubkey`s (what the convention decoder scans).
    pub fn output_scripts(&self) -> Vec<Vec<u8>> {
        self.outputs.iter().map(|o| o.script_pubkey.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_roundtrip() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [9u8; 32],
                prev_index: 3,
                script_sig: vec![1, 2, 3],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                TxOutput {
                    value: 500,
                    script_pubkey: vec![8u8; 20],
                },
                TxOutput {
                    value: 1,
                    script_pubkey: vec![0xAB; 20],
                },
            ],
            locktime: 0,
        };
        let hex = tx.to_hex();
        let back = Transaction::from_hex(&hex).unwrap();
        assert_eq!(tx, back);
        assert_eq!(back.output_scripts().len(), 2);
    }

    #[test]
    fn txid_excludes_script_sig() {
        let base = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![],
            locktime: 0,
        };
        let mut signed = base.clone();
        signed.inputs[0].script_sig = vec![42u8; 100];
        assert_eq!(base.txid(), signed.txid(), "txid must ignore script_sig");
    }
}
