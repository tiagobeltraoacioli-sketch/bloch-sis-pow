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
use std::io::{self, Write};

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
        // Removed by construction: `self.at` never exceeds `self.buf.len()`
        // (it is only ever advanced here, by exactly the amount checked
        // below), but a plain `buf.len() - at` still asks clippy to trust
        // that invariant across the whole module. `checked_add` instead
        // proves the bound locally, and a length field large enough to
        // overflow `usize` now takes the same "truncated" refusal as one
        // that is merely too long — an untrusted input that would have
        // panicked is refused instead.
        let end = match self.at.checked_add(n) {
            Some(end) if end <= self.buf.len() => end,
            _ => return Err(DecodeErr("truncated")),
        };
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeErr> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeErr> {
        // `take(2)` returns a slice of exactly 2 bytes or an `Err` above, so
        // the length check `try_into` performs can never fail; the `else`
        // arm is unreachable but keeps the conversion panic-free by
        // construction rather than by an `unwrap`.
        let Ok(a) = self.take(2)?.try_into() else {
            return Err(DecodeErr("truncated"));
        };
        Ok(u16::from_le_bytes(a))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeErr> {
        // See `u16`: `take(4)` guarantees exactly 4 bytes.
        let Ok(a) = self.take(4)?.try_into() else {
            return Err(DecodeErr("truncated"));
        };
        Ok(u32::from_le_bytes(a))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeErr> {
        // See `u16`: `take(8)` guarantees exactly 8 bytes.
        let Ok(a) = self.take(8)?.try_into() else {
            return Err(DecodeErr("truncated"));
        };
        Ok(u64::from_le_bytes(a))
    }

    pub fn u128(&mut self) -> Result<u128, DecodeErr> {
        // See `u16`: `take(16)` guarantees exactly 16 bytes.
        let Ok(a) = self.take(16)?.try_into() else {
            return Err(DecodeErr("truncated"));
        };
        Ok(u128::from_le_bytes(a))
    }

    pub fn h32(&mut self) -> Result<[u8; 32], DecodeErr> {
        // See `u16`: `take(32)` guarantees exactly 32 bytes.
        let Ok(a) = self.take(32)?.try_into() else {
            return Err(DecodeErr("truncated"));
        };
        Ok(a)
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
    write_attestation(out, a).expect("writing to Vec cannot fail");
}

/// Exact wire length of [`encode_attestation`] without allocating and copying
/// its signature solely to measure the resulting buffer.
pub(crate) fn encoded_attestation_len(a: &Attestation) -> usize {
    // Fixed fields: slot (8), head (32), source epoch/root (8 + 32), target
    // epoch/root (8 + 32), validator (4), and signature length prefix (4).
    128usize.saturating_add(a.signature.len())
}

fn write_attestation<W: Write>(out: &mut W, a: &Attestation) -> io::Result<()> {
    out.write_all(&a.data.slot.to_le_bytes())?;
    out.write_all(&a.data.head)?;
    out.write_all(&a.data.source_epoch.to_le_bytes())?;
    out.write_all(&a.data.source_root)?;
    out.write_all(&a.data.target_epoch.to_le_bytes())?;
    out.write_all(&a.data.target_root)?;
    out.write_all(&a.validator.to_le_bytes())?;
    write_bytes(out, &a.signature)
}

fn write_bytes<W: Write>(out: &mut W, bytes: &[u8]) -> io::Result<()> {
    out.write_all(&(bytes.len() as u32).to_le_bytes())?;
    out.write_all(bytes)
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

/// Exact wire/disk length of [`encode_envelope`] without allocating a second
/// attacker-sized buffer. Saturation is fail-closed for retention callers:
/// an object whose component lengths cannot be represented is larger than
/// every finite byte budget.
pub fn encoded_envelope_len(env: &BlockEnvelope) -> usize {
    let mut len = BlockHeaderV4::ENCODED_LEN
        .saturating_add(4)
        .saturating_add(env.proposer_sig.len())
        .saturating_add(4);
    for attestation in &env.body.attestations {
        len = len.saturating_add(encoded_attestation_len(attestation));
    }
    len = len.saturating_add(4);
    for transaction in &env.body.transactions {
        len = len.saturating_add(4).saturating_add(transaction.len());
    }
    len
}

pub fn encode_envelope(env: &BlockEnvelope) -> Vec<u8> {
    // `with_capacity` is a size hint, not a correctness bound: saturating is
    // the intended semantics here (the alternative to saturation is "guess
    // low", not "refuse to encode"), and `proposer_sig` is capped at
    // `MAX_FIELD_LEN` (8 MiB) everywhere it is produced, far below
    // `usize::MAX - 512`, so saturation is not reachable in practice either.
    let mut out = Vec::with_capacity(512usize.saturating_add(env.proposer_sig.len()));
    write_envelope(&mut out, env).expect("writing to Vec cannot fail");
    out
}

/// Emit the canonical envelope bytes without first aggregating them in a
/// second payload buffer. This is the shared authority for public encoding and
/// persistence; callers that write to fallible storage must preflight their
/// own frame cap before invoking it.
pub(crate) fn write_envelope<W: Write>(out: &mut W, env: &BlockEnvelope) -> io::Result<()> {
    out.write_all(&env.header.canonical_serialize())?;
    write_bytes(out, &env.proposer_sig)?;
    out.write_all(&(env.body.attestations.len() as u32).to_le_bytes())?;
    for attestation in &env.body.attestations {
        write_attestation(out, attestation)?;
    }
    out.write_all(&(env.body.transactions.len() as u32).to_le_bytes())?;
    for transaction in &env.body.transactions {
        write_bytes(out, transaction)?;
    }
    Ok(())
}

pub fn decode_envelope(buf: &[u8]) -> Result<BlockEnvelope, DecodeErr> {
    let mut r = Reader::new(buf);
    let hb = r.take(BlockHeaderV4::ENCODED_LEN)?;
    let header =
        BlockHeaderV4::canonical_deserialize(hb).map_err(|_| DecodeErr("bad header"))?;
    let proposer_sig = r.bytes()?;
    let natt = r.u32()? as usize;
    if natt > bloch_pos_committee::params::MAX_ATTESTATIONS_PER_BLOCK {
        return Err(DecodeErr("too many attestations"));
    }
    // Every attestation has 128 fixed bytes including its signature length.
    // Reserve only after the frame proves it can contain the declared count.
    if natt > r.buf.len().saturating_sub(r.at) / 128 {
        return Err(DecodeErr("truncated attestation collection"));
    }
    let mut attestations = Vec::with_capacity(natt);
    for _ in 0..natt {
        attestations.push(decode_attestation(&mut r)?);
    }
    let ntx = r.u32()? as usize;
    if ntx > 65_536 {
        return Err(DecodeErr("too many transactions"));
    }
    if ntx > r.buf.len().saturating_sub(r.at) / 4 {
        return Err(DecodeErr("truncated transaction collection"));
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
        // `to_digit(16)` guarantees hi, lo ∈ 0..=15, so hi*16+lo ∈ 0..=255:
        // cannot overflow u32 and fits u8 exactly.
        #[allow(clippy::arithmetic_side_effects)]
        let byte = hi * 16 + lo;
        out.push(byte as u8);
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
    fn encoded_envelope_len_tracks_empty_collections_fields_and_limits() {
        let mut env = sample_envelope();
        env.proposer_sig.clear();
        env.body.attestations.clear();
        env.body.transactions.clear();
        assert_eq!(encoded_envelope_len(&env), encode_envelope(&env).len());

        env.body.attestations.push(sample_envelope().body.attestations.remove(0));
        assert_eq!(encoded_envelope_len(&env), encode_envelope(&env).len());

        env.body.transactions.push(vec![0xA5; 4097]);
        assert_eq!(encoded_envelope_len(&env), encode_envelope(&env).len());

        env.proposer_sig.resize(MAX_FIELD_LEN, 0x5A);
        assert_eq!(encoded_envelope_len(&env), encode_envelope(&env).len());
    }

    #[test]
    fn encoded_attestation_len_matches_encoder_for_empty_realistic_and_large_signatures() {
        let mut attestation = sample_envelope().body.attestations.remove(0);
        for signature_len in [0, 4_589, 1 << 20] {
            attestation.signature.resize(signature_len, 0xA5);
            let mut encoded = Vec::new();
            encode_attestation(&mut encoded, &attestation);

            assert_eq!(encoded_attestation_len(&attestation), encoded.len());
            assert_eq!(encoded.len(), 128usize.saturating_add(signature_len));
        }
    }

    #[test]
    fn canonical_envelope_emitter_matches_public_bytes_across_short_writes() {
        #[derive(Default)]
        struct ShortWriter {
            bytes: Vec<u8>,
            writes: usize,
        }

        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes = self.writes.saturating_add(1);
                let accepted = bytes.len().min(17);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }

        let full = sample_envelope();
        let mut empty = sample_envelope();
        empty.proposer_sig.clear();
        empty.body.attestations.clear();
        empty.body.transactions.clear();
        let mut large = sample_envelope();
        large.body.transactions.push(vec![0xA5; 1 << 20]);

        for envelope in [empty, full, large] {
            let expected = encode_envelope(&envelope);
            let mut writer = ShortWriter::default();
            write_envelope(&mut writer, &envelope).expect("stream canonical envelope");
            assert_eq!(writer.bytes, expected);
            assert_eq!(writer.bytes.len(), encoded_envelope_len(&envelope));
            assert!(writer.writes > 1, "fixture must exercise write_all retries");
        }
    }

    #[test]
    fn audit_collection_counts_must_fit_the_remaining_frame() {
        let mut env = sample_envelope();
        env.proposer_sig.clear();
        env.body.attestations.clear();
        env.body.transactions.clear();
        let mut bytes = encode_envelope(&env);
        let counts = BlockHeaderV4::ENCODED_LEN + 4;
        bytes[counts..counts + 4].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(decode_envelope(&bytes).err().unwrap().0, "truncated attestation collection");
        bytes[counts..counts + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[counts + 4..counts + 8].copy_from_slice(&65536u32.to_le_bytes());
        assert_eq!(decode_envelope(&bytes).err().unwrap().0, "truncated transaction collection");
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
