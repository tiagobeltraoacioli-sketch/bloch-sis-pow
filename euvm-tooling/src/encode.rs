//! encode — hex / textual encoders and decoders for the VM's on-the-wire objects
//! (Ops, Vals, whole programs, validator hashes, ExtOutputs), built on
//! `bloch_euvm::encode_program` and `bloch_euvm::validator_hash`.
//!
//! This module is the crate's canonical serialization layer. Because
//! `bloch_euvm::Op` derives only `Clone, Debug` (no `PartialEq`/`Eq`), the
//! byte/hex encoding produced here is also the canonical way to *compare* two
//! programs: `program_to_hex(a) == program_to_hex(b)`.
//!
//! `bloch_euvm` ships an encoder (`encode_program`) but **no** decoder; the
//! [`decode_program`] here is the hand-written inverse, mirroring the exact tag
//! byte table and little-endian operand layout of `encode_program`.

use bloch_euvm::{self as euvm, AssetId, ExtOutput, Op, Val};

/// Errors produced by the codecs in this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A hex string was not valid hex (odd length or non-hex digit).
    BadHex(String),
    /// A hex byte string had the wrong length for a fixed-width target
    /// (e.g. a 32-byte hash or asset id). `(expected, got)`.
    BadLength(usize, usize),
    /// A textual `Val`/`AssetId` spec did not match a known form
    /// (`int:<n>`, `hex:<bytes>`, `bytes:<bytes>`).
    BadValSpec(String),
    /// An integer literal in a textual spec did not parse as `i128`.
    BadInt(String),
    /// The program byte stream ended in the middle of an op or operand.
    UnexpectedEof,
    /// An unknown op tag byte was encountered while decoding a program.
    UnknownTag(u8),
    /// A `PushBytes` length prefix claimed more bytes than remain in the stream.
    OperandTooShort {
        /// how many operand bytes the length prefix asked for
        want: usize,
        /// how many bytes were actually left
        have: usize,
    },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::BadHex(s) => write!(f, "invalid hex: {s}"),
            EncodeError::BadLength(exp, got) => {
                write!(f, "wrong byte length: expected {exp}, got {got}")
            }
            EncodeError::BadValSpec(s) => write!(f, "unrecognized value spec: {s}"),
            EncodeError::BadInt(s) => write!(f, "invalid integer literal: {s}"),
            EncodeError::UnexpectedEof => write!(f, "unexpected end of program bytes"),
            EncodeError::UnknownTag(t) => write!(f, "unknown op tag byte: 0x{t:02x}"),
            EncodeError::OperandTooShort { want, have } => {
                write!(f, "PushBytes operand truncated: want {want}, have {have}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

// ---------------------------------------------------------------------------
// Hex / hash helpers
// ---------------------------------------------------------------------------

/// Lower-case hex of a raw byte slice.
pub fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// Decode a hex string (with optional `0x` prefix) into raw bytes.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, EncodeError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|_| EncodeError::BadHex(s.to_string()))
}

/// Lower-case hex of a 32-byte hash / validator hash.
pub fn hash_to_hex(h: &[u8; 32]) -> String {
    hex::encode(h)
}

/// Parse a 32-byte hash from hex (accepts an optional `0x` prefix).
pub fn hex_to_hash(s: &str) -> Result<[u8; 32], EncodeError> {
    let bytes = hex_to_bytes(s)?;
    if bytes.len() != 32 {
        return Err(EncodeError::BadLength(32, bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Lower-case hex of a 32-byte native-asset id.
pub fn asset_to_hex(a: &AssetId) -> String {
    hex::encode(a)
}

/// Parse a 32-byte asset id from hex (accepts an optional `0x` prefix).
pub fn hex_to_asset(s: &str) -> Result<AssetId, EncodeError> {
    hex_to_hash(s)
}

// ---------------------------------------------------------------------------
// Program <-> hex/bytes
// ---------------------------------------------------------------------------

/// Canonical byte encoding of a program (delegates to `bloch_euvm`).
pub fn program_to_bytes(program: &[Op]) -> Vec<u8> {
    euvm::encode_program(program)
}

/// Canonical lower-case hex encoding of a program.
pub fn program_to_hex(program: &[Op]) -> String {
    hex::encode(euvm::encode_program(program))
}

/// Hex of the validator hash (`SHA-256d(encode_program(program))`) for a program.
pub fn program_hash_hex(program: &[Op]) -> String {
    hash_to_hex(&euvm::validator_hash(program))
}

/// Decode a program hex string back into `Vec<Op>`.
pub fn hex_to_program(s: &str) -> Result<Vec<Op>, EncodeError> {
    let bytes = hex_to_bytes(s)?;
    decode_program(&bytes)
}

/// Decode a canonical program byte stream back into `Vec<Op>`.
///
/// This is the hand-written inverse of `bloch_euvm::encode_program`. It mirrors
/// the exact tag byte table (`PushInt 0x01`, `PushBytes 0x02`, …) and the
/// little-endian operand layout: `PushInt` carries a 16-byte `i128`, `PushBytes`
/// a `u32` LE length prefix followed by that many bytes, and the index ops
/// (`Pick`, `CtxField`, `TxOut*`) a single byte.
pub fn decode_program(bytes: &[u8]) -> Result<Vec<Op>, EncodeError> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let tag = bytes[i];
        i += 1;
        let op = match tag {
            0x01 => {
                let n = read_i128(bytes, &mut i)?;
                Op::PushInt(n)
            }
            0x02 => {
                let b = read_lp_bytes(bytes, &mut i)?;
                Op::PushBytes(b)
            }
            0x10 => Op::Dup,
            0x11 => Op::Drop,
            0x12 => Op::Swap,
            0x13 => Op::Pick(read_u8(bytes, &mut i)?),
            0x20 => Op::Add,
            0x21 => Op::Sub,
            0x22 => Op::Mul,
            0x30 => Op::Eq,
            0x31 => Op::Lt,
            0x32 => Op::Not,
            0x40 => Op::Sha256d,
            0x41 => Op::Shake256,
            0x42 => Op::Size,
            0x50 => Op::CtxField(read_u8(bytes, &mut i)?),
            0x60 => Op::VerifySig,
            0x61 => Op::Verify,
            0x62 => Op::VerifyEcdsa,
            0x70 => Op::TxOutDatum(read_u8(bytes, &mut i)?),
            0x71 => Op::TxOutValidator(read_u8(bytes, &mut i)?),
            0x72 => Op::TxOutValue(read_u8(bytes, &mut i)?),
            0x73 => Op::SelfValidator,
            0x74 => Op::SelfAsset,
            0x75 => Op::TxOutAsset(read_u8(bytes, &mut i)?),
            other => return Err(EncodeError::UnknownTag(other)),
        };
        ops.push(op);
    }
    Ok(ops)
}

fn read_u8(bytes: &[u8], i: &mut usize) -> Result<u8, EncodeError> {
    let b = *bytes.get(*i).ok_or(EncodeError::UnexpectedEof)?;
    *i += 1;
    Ok(b)
}

fn read_i128(bytes: &[u8], i: &mut usize) -> Result<i128, EncodeError> {
    let end = i.checked_add(16).ok_or(EncodeError::UnexpectedEof)?;
    let slice = bytes.get(*i..end).ok_or(EncodeError::UnexpectedEof)?;
    let mut buf = [0u8; 16];
    buf.copy_from_slice(slice);
    *i = end;
    Ok(i128::from_le_bytes(buf))
}

fn read_lp_bytes(bytes: &[u8], i: &mut usize) -> Result<Vec<u8>, EncodeError> {
    let end = i.checked_add(4).ok_or(EncodeError::UnexpectedEof)?;
    let lenb = bytes.get(*i..end).ok_or(EncodeError::UnexpectedEof)?;
    let mut lbuf = [0u8; 4];
    lbuf.copy_from_slice(lenb);
    let len = u32::from_le_bytes(lbuf) as usize;
    *i = end;
    let bend = i.checked_add(len).ok_or(EncodeError::UnexpectedEof)?;
    let payload = bytes.get(*i..bend).ok_or(EncodeError::OperandTooShort {
        want: len,
        have: bytes.len().saturating_sub(*i),
    })?;
    *i = bend;
    Ok(payload.to_vec())
}

// ---------------------------------------------------------------------------
// Val <-> text
// ---------------------------------------------------------------------------

/// Render a [`Val`] to a compact, round-trippable textual form:
/// `int:<n>` for integers, `hex:<lower-hex>` for byte strings.
pub fn val_to_string(v: &Val) -> String {
    match v {
        Val::Int(n) => format!("int:{n}"),
        Val::Bytes(b) => format!("hex:{}", hex::encode(b)),
    }
}

/// Parse a [`Val`] from the textual form produced by [`val_to_string`].
///
/// Accepted forms:
/// - `int:<i128>` — a signed decimal integer.
/// - `hex:<bytes>` — a byte string given as hex (optional `0x`).
/// - `bytes:<bytes>` — alias for `hex:`.
/// - a bare decimal integer (e.g. `42`) — treated as `int:`.
pub fn parse_val(s: &str) -> Result<Val, EncodeError> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("int:") {
        let n: i128 = rest
            .trim()
            .parse()
            .map_err(|_| EncodeError::BadInt(rest.to_string()))?;
        return Ok(Val::Int(n));
    }
    if let Some(rest) = s.strip_prefix("hex:").or_else(|| s.strip_prefix("bytes:")) {
        return Ok(Val::Bytes(hex_to_bytes(rest.trim())?));
    }
    // Bare integer fallback.
    if let Ok(n) = s.parse::<i128>() {
        return Ok(Val::Int(n));
    }
    Err(EncodeError::BadValSpec(s.to_string()))
}

// ---------------------------------------------------------------------------
// Op <-> text (human-readable disassembly, not the canonical wire form)
// ---------------------------------------------------------------------------

/// Render a single [`Op`] to a short human-readable mnemonic (for logs/CLI
/// dumps). This is a display form, not the canonical wire encoding — use
/// [`program_to_hex`] for anything that must round-trip byte-exactly.
pub fn op_to_string(op: &Op) -> String {
    match op {
        Op::PushInt(n) => format!("PushInt {n}"),
        Op::PushBytes(b) => format!("PushBytes 0x{}", hex::encode(b)),
        Op::Dup => "Dup".into(),
        Op::Drop => "Drop".into(),
        Op::Swap => "Swap".into(),
        Op::Pick(n) => format!("Pick {n}"),
        Op::Add => "Add".into(),
        Op::Sub => "Sub".into(),
        Op::Mul => "Mul".into(),
        Op::Eq => "Eq".into(),
        Op::Lt => "Lt".into(),
        Op::Not => "Not".into(),
        Op::Sha256d => "Sha256d".into(),
        Op::Shake256 => "Shake256".into(),
        Op::Size => "Size".into(),
        Op::CtxField(i) => format!("CtxField {i}"),
        Op::VerifySig => "VerifySig".into(),
        Op::VerifyEcdsa => "VerifyEcdsa".into(),
        Op::Verify => "Verify".into(),
        Op::TxOutDatum(i) => format!("TxOutDatum {i}"),
        Op::TxOutValidator(i) => format!("TxOutValidator {i}"),
        Op::TxOutValue(i) => format!("TxOutValue {i}"),
        Op::SelfValidator => "SelfValidator".into(),
        Op::SelfAsset => "SelfAsset".into(),
        Op::TxOutAsset(i) => format!("TxOutAsset {i}"),
    }
}

/// Render a whole program as a newline-separated, index-prefixed disassembly.
pub fn program_to_asm(program: &[Op]) -> String {
    program
        .iter()
        .enumerate()
        .map(|(i, op)| format!("{i:04}  {}", op_to_string(op)))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// ExtOutput <-> text
// ---------------------------------------------------------------------------

/// Render an [`ExtOutput`] as a multi-line, human-readable summary: its
/// multi-asset value (asset-hex → amount), its validator hash, and its datum.
pub fn ext_output_to_string(out: &ExtOutput) -> String {
    let mut lines = Vec::new();
    lines.push("ExtOutput {".to_string());
    lines.push("  value:".to_string());
    if out.value.is_empty() {
        lines.push("    (empty)".to_string());
    } else {
        for (asset, amount) in &out.value {
            let label = if *asset == euvm::BLCH {
                "BLCH".to_string()
            } else {
                asset_to_hex(asset)
            };
            lines.push(format!("    {label} => {amount}"));
        }
    }
    lines.push(format!(
        "  validator_hash: {}",
        hash_to_hex(&out.validator_hash)
    ));
    lines.push(format!("  datum: {}", val_to_string(&out.datum)));
    lines.push("}".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_program() -> Vec<Op> {
        vec![
            Op::PushInt(42),
            Op::PushBytes(vec![0xde, 0xad, 0xbe, 0xef]),
            Op::Dup,
            Op::Pick(3),
            Op::Sha256d,
            Op::CtxField(0),
            Op::VerifySig,
            Op::Verify,
            Op::TxOutAsset(2),
            Op::SelfValidator,
            Op::PushInt(-7),
        ]
    }

    #[test]
    fn program_hex_roundtrips_through_decoder() {
        let prog = sample_program();
        let hexed = program_to_hex(&prog);
        let back = hex_to_program(&hexed).expect("decode");
        // Op has no Eq — compare via the canonical encoding instead.
        assert_eq!(program_to_hex(&back), hexed);
        // And the validator hash is stable across the round trip.
        assert_eq!(program_hash_hex(&prog), program_hash_hex(&back));
    }

    #[test]
    fn decode_matches_encode_program_byte_for_byte() {
        let prog = sample_program();
        let bytes = euvm::encode_program(&prog);
        let decoded = decode_program(&bytes).expect("decode");
        assert_eq!(euvm::encode_program(&decoded), bytes);
    }

    #[test]
    fn hash_hex_roundtrips() {
        let h = euvm::validator_hash(&sample_program());
        let s = hash_to_hex(&h);
        assert_eq!(s.len(), 64);
        assert_eq!(hex_to_hash(&s).unwrap(), h);
        // 0x prefix is tolerated.
        assert_eq!(hex_to_hash(&format!("0x{s}")).unwrap(), h);
    }

    #[test]
    fn val_text_roundtrips() {
        let a = Val::Int(-1234567890123);
        let b = Val::Bytes(vec![0, 1, 2, 255]);
        assert_eq!(parse_val(&val_to_string(&a)).unwrap(), a);
        assert_eq!(parse_val(&val_to_string(&b)).unwrap(), b);
        // Alternate spellings.
        assert_eq!(parse_val("42").unwrap(), Val::Int(42));
        assert_eq!(parse_val("bytes:ab12").unwrap(), Val::Bytes(vec![0xab, 0x12]));
    }

    #[test]
    fn bad_inputs_error_cleanly() {
        assert!(matches!(hex_to_bytes("zz"), Err(EncodeError::BadHex(_))));
        assert!(matches!(hex_to_hash("ab"), Err(EncodeError::BadLength(32, 1))));
        assert!(matches!(parse_val("weird:x"), Err(EncodeError::BadValSpec(_))));
        assert!(matches!(decode_program(&[0xff]), Err(EncodeError::UnknownTag(0xff))));
        // A PushInt tag with a truncated operand.
        assert!(matches!(decode_program(&[0x01, 0x00]), Err(EncodeError::UnexpectedEof)));
        // A PushBytes claiming more than is present.
        assert!(matches!(
            decode_program(&[0x02, 0x10, 0x00, 0x00, 0x00]),
            Err(EncodeError::OperandTooShort { .. })
        ));
    }

    #[test]
    fn program_compare_via_hex() {
        let a = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
        let b = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
        let c = vec![Op::PushInt(1), Op::PushInt(3), Op::Add];
        assert_eq!(program_to_hex(&a), program_to_hex(&b));
        assert_ne!(program_to_hex(&a), program_to_hex(&c));
    }

    #[test]
    fn ext_output_renders() {
        let out = ExtOutput {
            value: euvm::blch(500),
            validator_hash: euvm::validator_hash(&sample_program()),
            datum: Val::Int(7),
        };
        let s = ext_output_to_string(&out);
        assert!(s.contains("BLCH => 500"));
        assert!(s.contains("datum: int:7"));
    }
}
