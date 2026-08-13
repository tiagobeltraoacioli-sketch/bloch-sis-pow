// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire/disk codec for the Genesis-4 devnet node.
//!
//! The **header** bytes are never encoded here: they come from
//! [`BlockHeaderV4::canonical_serialize`] / `canonical_deserialize`, the single
//! derivation path the committee crate pins (§5.4). This module only frames
//! what the pure crate deliberately leaves to the node: the envelope around
//! the header (signature, attestation quorum, opaque transactions), the
//! attestation wire form, and the devnet's genesis-manifest / keystore files.
//!
//! Everything is fixed-order, little-endian, length-prefixed — injective by
//! construction, no serde, no reflection. `decode_*` functions are strict:
//! trailing bytes are an error, because a decoder that accepts
//! `encode(x) ‖ junk` breaks the encode→hash injectivity the log digest and
//! frame dedup rely on.

use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body};

/// Hard cap on any decoded length field, so a corrupt frame cannot ask for a
/// multi-gigabyte allocation. Generous for a devnet block (12 validators ×
/// ~4.7 KB attestation ≈ 56 KB).
pub const MAX_FIELD_LEN: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct DecodeErr(pub &'static str);

impl std::fmt::Display for DecodeErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decode error: {}", self.0)
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, at: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeErr> {
        if self.buf.len() - self.at < n {
            return Err(DecodeErr("truncated"));
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeErr> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeErr> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeErr> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeErr> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn u128(&mut self) -> Result<u128, DecodeErr> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }

    pub fn h32(&mut self) -> Result<[u8; 32], DecodeErr> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeErr> {
        let n = self.u32()? as usize;
        if n > MAX_FIELD_LEN {
            return Err(DecodeErr("length over cap"));
        }
        Ok(self.take(n)?.to_vec())
    }

    pub fn finish(self) -> Result<(), DecodeErr> {
        if self.at != self.buf.len() {
            return Err(DecodeErr("trailing bytes"));
        }
        Ok(())
    }
}

pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

// ── Attestations ────────────────────────────────────────────────────────────

pub fn encode_attestation(out: &mut Vec<u8>, a: &Attestation) {
    out.extend_from_slice(&a.data.slot.to_le_bytes());
    out.extend_from_slice(&a.data.head);
    out.extend_from_slice(&a.data.source_epoch.to_le_bytes());
    out.extend_from_slice(&a.data.source_root);
    out.extend_from_slice(&a.data.target_epoch.to_le_bytes());
    out.extend_from_slice(&a.data.target_root);
    out.extend_from_slice(&a.validator.to_le_bytes());
    put_bytes(out, &a.signature);
}

pub fn decode_attestation(r: &mut Reader<'_>) -> Result<Attestation, DecodeErr> {
    let data = AttestationData {
        slot: r.u64()?,
        head: r.h32()?,
        source_epoch: r.u64()?,
        source_root: r.h32()?,
        target_epoch: r.u64()?,
        target_root: r.h32()?,
    };
    let validator = r.u32()?;
    let signature = r.bytes()?;
    Ok(Attestation { data, validator, signature })
}

// ── Block envelope ──────────────────────────────────────────────────────────

pub fn encode_envelope(env: &BlockEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(512 + env.proposer_sig.len());
    out.extend_from_slice(&env.header.canonical_serialize());
    put_bytes(&mut out, &env.proposer_sig);
    out.extend_from_slice(&(env.body.attestations.len() as u32).to_le_bytes());
    for a in &env.body.attestations {
        encode_attestation(&mut out, a);
    }
    out.extend_from_slice(&(env.body.transactions.len() as u32).to_le_bytes());
    for tx in &env.body.transactions {
        put_bytes(&mut out, tx);
    }
    out
}

pub fn decode_envelope(buf: &[u8]) -> Result<BlockEnvelope, DecodeErr> {
    let mut r = Reader::new(buf);
    let hb = r.take(BlockHeaderV4::ENCODED_LEN)?;
    let header =
        BlockHeaderV4::canonical_deserialize(hb).map_err(|_| DecodeErr("bad header"))?;
    let proposer_sig = r.bytes()?;
    let natt = r.u32()? as usize;
    if natt > 4096 {
        return Err(DecodeErr("too many attestations"));
    }
    let mut attestations = Vec::with_capacity(natt);
    for _ in 0..natt {
        attestations.push(decode_attestation(&mut r)?);
    }
    let ntx = r.u32()? as usize;
    if ntx > 65_536 {
        return Err(DecodeErr("too many transactions"));
    }
    let mut transactions = Vec::with_capacity(ntx);
    for _ in 0..ntx {
        transactions.push(r.bytes()?);
    }
    r.finish()?;
    Ok(BlockEnvelope { header, proposer_sig, body: Body { transactions, attestations } })
}

// ── Small helpers ───────────────────────────────────────────────────────────

pub fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Lower-case hex of an arbitrary byte string.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse lower- or upper-case hex. Strict: an odd length or a non-hex digit
/// is an error, never a silently truncated or zero-filled value — this parses
/// outpoints, keys and signatures, where a quietly mangled byte is a
/// transaction that spends the wrong coin or verifies against nothing.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex ({} digits)", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or_else(|| format!("bad hex digit {:?}", pair[0] as char))?;
        let lo = (pair[1] as char).to_digit(16).ok_or_else(|| format!("bad hex digit {:?}", pair[1] as char))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::attestation::AttestationData;
    use bloch_pos_committee::header::{BlockHeaderV4, Body, VERSION_G4};

    fn sample_envelope() -> BlockEnvelope {
        let header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: [1; 32],
            state_root: [2; 32],
            body_root: [3; 32],
            slot: 77,
            proposer_index: 3,
            randao_reveal: [4; 32],
            randao_mix: [5; 32],
            justified_root: [6; 32],
            finalized_root: [7; 32],
            attestation_root: [8; 32],
            coherence_root: [9; 32],
        };
        let att = Attestation {
            data: AttestationData {
                slot: 76,
                head: [1; 32],
                source_epoch: 1,
                source_root: [0xAA; 32],
                target_epoch: 2,
                target_root: [0xBB; 32],
            },
            validator: 9,
            signature: vec![0xC0; 4589],
        };
        BlockEnvelope {
            header,
            proposer_sig: vec![0xDD; 4589],
            body: Body { transactions: vec![vec![0xEE, 0xFF]], attestations: vec![att] },
        }
    }

    #[test]
    fn envelope_round_trips() {
        let env = sample_envelope();
        let bytes = encode_envelope(&env);
        let back = decode_envelope(&bytes).expect("round trip");
        assert_eq!(back.header, env.header);
        assert_eq!(back.proposer_sig, env.proposer_sig);
        assert_eq!(back.body.transactions, env.body.transactions);
        assert_eq!(back.body.attestations.len(), 1);
        assert_eq!(back.body.attestations[0].data, env.body.attestations[0].data);
        assert_eq!(back.body.attestations[0].signature, env.body.attestations[0].signature);
        // Identity is preserved through the codec — same bytes, same id.
        assert_eq!(back.block_id(), env.block_id());
    }

    #[test]
    fn envelope_decode_rejects_trailing_bytes() {
        let mut bytes = encode_envelope(&sample_envelope());
        bytes.push(0);
        assert!(decode_envelope(&bytes).is_err(), "encode(x) ‖ junk must not decode");
    }

    #[test]
    fn envelope_decode_rejects_truncation() {
        let bytes = encode_envelope(&sample_envelope());
        assert!(decode_envelope(&bytes[..bytes.len() - 1]).is_err());
    }
}
