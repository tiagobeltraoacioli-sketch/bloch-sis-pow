//! Integration tests for the `encode` component, exercised from OUTSIDE the
//! crate (i.e. against the published `euvm_tooling::encode` surface + the
//! re-exported VM at `euvm_tooling::euvm`).
//!
//! Focus: edge cases, malformed / fail-closed input, and byte-exact round trips
//! between `encode_program` (bloch-euvm) and the hand-written `decode_program`
//! inverse. Reject-cases are treated as first-class as accept-cases.

use euvm_tooling::encode::{
    asset_to_hex, bytes_to_hex, decode_program, ext_output_to_string, hash_to_hex, hex_to_asset,
    hex_to_bytes, hex_to_hash, hex_to_program, op_to_string, parse_val, program_hash_hex,
    program_to_asm, program_to_bytes, program_to_hex, val_to_string, EncodeError,
};
use euvm_tooling::euvm::{self, AssetId, ExtOutput, Op, Val};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A program that touches every distinct `Op` variant exactly once, so a
/// round-trip through `program_to_hex`/`decode_program` proves the full tag
/// table and every operand layout (i128, length-prefixed bytes, 1-byte index).
fn every_op_program() -> Vec<Op> {
    vec![
        Op::PushInt(0),
        Op::PushInt(i128::MAX),
        Op::PushInt(i128::MIN),
        Op::PushInt(-1),
        Op::PushBytes(vec![]),                  // empty operand
        Op::PushBytes(vec![0xde, 0xad, 0xbe, 0xef]),
        Op::PushBytes(vec![0xff; 300]),         // >255 so the u32 len prefix matters
        Op::Dup,
        Op::Drop,
        Op::Swap,
        Op::Pick(0),
        Op::Pick(255),
        Op::Add,
        Op::Sub,
        Op::Mul,
        Op::Eq,
        Op::Lt,
        Op::Not,
        Op::Sha256d,
        Op::Shake256,
        Op::Size,
        Op::CtxField(0),
        Op::CtxField(200),
        Op::VerifySig,
        Op::VerifyEcdsa,
        Op::Verify,
        Op::TxOutDatum(1),
        Op::TxOutValidator(2),
        Op::TxOutValue(3),
        Op::SelfValidator,
        Op::SelfAsset,
        Op::TxOutAsset(4),
    ]
}

// ---------------------------------------------------------------------------
// Program <-> bytes/hex round trips
// ---------------------------------------------------------------------------

#[test]
fn every_op_round_trips_byte_for_byte() {
    let prog = every_op_program();
    let bytes = program_to_bytes(&prog);
    // program_to_bytes must equal the VM's own canonical encoder.
    assert_eq!(bytes, euvm::encode_program(&prog));

    let decoded = decode_program(&bytes).expect("decode every-op program");
    // Op has no Eq — assert byte-exact re-encoding instead.
    assert_eq!(euvm::encode_program(&decoded), bytes);
}

#[test]
fn program_hex_round_trips() {
    let prog = every_op_program();
    let hexed = program_to_hex(&prog);
    // hex is lower-case and even length.
    assert_eq!(hexed.len() % 2, 0);
    assert_eq!(hexed, hexed.to_lowercase());

    let back = hex_to_program(&hexed).expect("hex_to_program");
    assert_eq!(program_to_hex(&back), hexed);
    // Identity contract: the validator hash survives the round trip.
    assert_eq!(program_hash_hex(&prog), program_hash_hex(&back));
}

#[test]
fn hex_to_program_tolerates_0x_prefix() {
    let prog = vec![Op::PushInt(7), Op::Dup, Op::Add];
    let hexed = program_to_hex(&prog);
    let prefixed = format!("0x{hexed}");
    let back = hex_to_program(&prefixed).expect("0x-prefixed program hex");
    assert_eq!(program_to_hex(&back), hexed);
}

#[test]
fn empty_program_encodes_and_decodes_to_empty() {
    let empty: Vec<Op> = Vec::new();
    assert_eq!(program_to_bytes(&empty), Vec::<u8>::new());
    assert_eq!(program_to_hex(&empty), "");
    let decoded = decode_program(&[]).expect("decode empty");
    assert!(decoded.is_empty());
    // Empty hex string also decodes to the empty program.
    assert!(hex_to_program("").expect("empty hex").is_empty());
}

#[test]
fn push_int_boundary_values_survive() {
    for n in [0i128, 1, -1, i128::MAX, i128::MIN, i64::MIN as i128, i64::MAX as i128] {
        let prog = vec![Op::PushInt(n)];
        let back = decode_program(&program_to_bytes(&prog)).expect("decode PushInt");
        match back.as_slice() {
            [Op::PushInt(got)] => assert_eq!(*got, n, "PushInt {n} corrupted"),
            other => panic!("expected single PushInt, got {other:?}"),
        }
    }
}

#[test]
fn push_bytes_empty_and_large_survive() {
    for len in [0usize, 1, 255, 256, 1024, 70_000] {
        let payload = vec![0xa5u8; len];
        let prog = vec![Op::PushBytes(payload.clone())];
        let back = decode_program(&program_to_bytes(&prog)).expect("decode PushBytes");
        match back.as_slice() {
            [Op::PushBytes(got)] => assert_eq!(got, &payload, "PushBytes len {len} corrupted"),
            other => panic!("expected single PushBytes, got {other:?}"),
        }
    }
}

#[test]
fn decode_program_is_exact_inverse_of_encode_over_wire_bytes() {
    // Encode -> decode -> encode must be a fixed point.
    let prog = every_op_program();
    let bytes = program_to_bytes(&prog);
    let d1 = decode_program(&bytes).expect("d1");
    let b1 = program_to_bytes(&d1);
    let d2 = decode_program(&b1).expect("d2");
    assert_eq!(b1, bytes);
    assert_eq!(program_to_bytes(&d2), bytes);
}

// ---------------------------------------------------------------------------
// Program comparison (encode is the canonical Eq path)
// ---------------------------------------------------------------------------

#[test]
fn hex_is_the_canonical_program_equality() {
    let a = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
    let b = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
    let c = vec![Op::PushInt(1), Op::PushInt(3), Op::Add];
    assert_eq!(program_to_hex(&a), program_to_hex(&b));
    assert_ne!(program_to_hex(&a), program_to_hex(&c));
    // A differing opcode also diverges.
    let d = vec![Op::PushInt(1), Op::PushInt(2), Op::Sub];
    assert_ne!(program_to_hex(&a), program_to_hex(&d));
}

#[test]
fn distinct_programs_have_distinct_hashes() {
    let a = vec![Op::PushInt(1)];
    let b = vec![Op::PushInt(2)];
    assert_ne!(program_hash_hex(&a), program_hash_hex(&b));
    // program_hash_hex must equal hex of validator_hash.
    assert_eq!(program_hash_hex(&a), hash_to_hex(&euvm::validator_hash(&a)));
}

// ---------------------------------------------------------------------------
// Malformed program decoding (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_unknown_tag() {
    // 0x00 and 0xff are not assigned tags.
    assert_eq!(decode_program(&[0x00]).unwrap_err(), EncodeError::UnknownTag(0x00));
    assert_eq!(decode_program(&[0xff]).unwrap_err(), EncodeError::UnknownTag(0xff));
    // An unknown tag mid-stream (after a valid Dup) also fails.
    assert_eq!(decode_program(&[0x10, 0x7f]).unwrap_err(), EncodeError::UnknownTag(0x7f));
}

#[test]
fn decode_rejects_truncated_pushint_operand() {
    // 0x01 (PushInt) needs 16 operand bytes; give fewer.
    assert_eq!(decode_program(&[0x01]).unwrap_err(), EncodeError::UnexpectedEof);
    assert_eq!(decode_program(&[0x01, 0x00]).unwrap_err(), EncodeError::UnexpectedEof);
    let mut fifteen = vec![0x01];
    fifteen.extend_from_slice(&[0u8; 15]);
    assert_eq!(decode_program(&fifteen).unwrap_err(), EncodeError::UnexpectedEof);
    // Exactly 16 operand bytes decodes cleanly.
    let mut sixteen = vec![0x01];
    sixteen.extend_from_slice(&0i128.to_le_bytes());
    assert!(decode_program(&sixteen).is_ok());
}

#[test]
fn decode_rejects_truncated_pushbytes_length_prefix() {
    // 0x02 (PushBytes) needs a 4-byte u32 len prefix; give fewer.
    assert_eq!(decode_program(&[0x02]).unwrap_err(), EncodeError::UnexpectedEof);
    assert_eq!(decode_program(&[0x02, 0x01, 0x00]).unwrap_err(), EncodeError::UnexpectedEof);
}

#[test]
fn decode_rejects_pushbytes_operand_shorter_than_claimed() {
    // len prefix says 0x10 = 16 bytes but the stream ends immediately after it.
    match decode_program(&[0x02, 0x10, 0x00, 0x00, 0x00]) {
        Err(EncodeError::OperandTooShort { want, have }) => {
            assert_eq!(want, 16);
            assert_eq!(have, 0);
        }
        other => panic!("expected OperandTooShort, got {other:?}"),
    }
    // len prefix says 4 but only 2 payload bytes follow.
    match decode_program(&[0x02, 0x04, 0x00, 0x00, 0x00, 0xaa, 0xbb]) {
        Err(EncodeError::OperandTooShort { want, have }) => {
            assert_eq!(want, 4);
            assert_eq!(have, 2);
        }
        other => panic!("expected OperandTooShort, got {other:?}"),
    }
}

#[test]
fn decode_rejects_missing_index_byte() {
    // Every 1-byte-index op fails if the index byte is absent at EOF.
    for tag in [0x13u8, 0x50, 0x70, 0x71, 0x72, 0x75] {
        assert_eq!(
            decode_program(&[tag]).unwrap_err(),
            EncodeError::UnexpectedEof,
            "tag 0x{tag:02x} without index byte must be UnexpectedEof"
        );
    }
}

#[test]
fn hex_to_program_rejects_bad_hex_before_decoding() {
    assert!(matches!(hex_to_program("zz"), Err(EncodeError::BadHex(_))));
    assert!(matches!(hex_to_program("abc"), Err(EncodeError::BadHex(_)))); // odd length
}

// ---------------------------------------------------------------------------
// Hex / hash / asset helpers
// ---------------------------------------------------------------------------

#[test]
fn bytes_hex_round_trip() {
    let raw = vec![0x00, 0x01, 0x7f, 0x80, 0xff, 0xab];
    let h = bytes_to_hex(&raw);
    assert_eq!(h, "00017f80ffab");
    assert_eq!(hex_to_bytes(&h).unwrap(), raw);
    // Empty is valid.
    assert_eq!(bytes_to_hex(&[]), "");
    assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());
    // 0x prefix accepted.
    assert_eq!(hex_to_bytes("0x00017f80ffab").unwrap(), raw);
}

#[test]
fn hex_to_bytes_rejects_bad_input() {
    assert!(matches!(hex_to_bytes("zz"), Err(EncodeError::BadHex(_))));
    assert!(matches!(hex_to_bytes("f"), Err(EncodeError::BadHex(_)))); // odd length
    assert!(matches!(hex_to_bytes("0xg1"), Err(EncodeError::BadHex(_))));
}

#[test]
fn hash_hex_round_trips_and_validates_length() {
    let h = euvm::validator_hash(&every_op_program());
    let s = hash_to_hex(&h);
    assert_eq!(s.len(), 64);
    assert_eq!(hex_to_hash(&s).unwrap(), h);
    // 0x prefix tolerated.
    assert_eq!(hex_to_hash(&format!("0x{s}")).unwrap(), h);
}

#[test]
fn hex_to_hash_rejects_wrong_length() {
    // Too short.
    assert_eq!(hex_to_hash("ab"), Err(EncodeError::BadLength(32, 1)));
    // 31 bytes.
    let short = "ab".repeat(31);
    assert_eq!(hex_to_hash(&short), Err(EncodeError::BadLength(32, 31)));
    // 33 bytes.
    let long = "ab".repeat(33);
    assert_eq!(hex_to_hash(&long), Err(EncodeError::BadLength(32, 33)));
    // Empty -> 0 bytes.
    assert_eq!(hex_to_hash(""), Err(EncodeError::BadLength(32, 0)));
    // Bad hex still surfaces as BadHex, not BadLength.
    assert!(matches!(hex_to_hash("zz"), Err(EncodeError::BadHex(_))));
}

#[test]
fn asset_hex_round_trips() {
    // The base coin BLCH is all zeros.
    assert_eq!(asset_to_hex(&euvm::BLCH), "0".repeat(64));
    let mut asset: AssetId = [0u8; 32];
    asset[0] = 0xaa;
    asset[31] = 0xff;
    let s = asset_to_hex(&asset);
    assert_eq!(hex_to_asset(&s).unwrap(), asset);
    // Wrong length rejected (asset id is also 32 bytes).
    assert_eq!(hex_to_asset("aabb"), Err(EncodeError::BadLength(32, 2)));
}

// ---------------------------------------------------------------------------
// Val <-> text
// ---------------------------------------------------------------------------

#[test]
fn val_int_round_trips_including_boundaries() {
    for n in [0i128, 1, -1, 42, -1234567890123, i128::MAX, i128::MIN] {
        let v = Val::Int(n);
        assert_eq!(parse_val(&val_to_string(&v)).unwrap(), v);
    }
    assert_eq!(val_to_string(&Val::Int(-7)), "int:-7");
}

#[test]
fn val_bytes_round_trips() {
    for payload in [vec![], vec![0u8], vec![0x00, 0x01, 0x02, 0xff], vec![0xab; 64]] {
        let v = Val::Bytes(payload.clone());
        assert_eq!(parse_val(&val_to_string(&v)).unwrap(), v);
    }
    assert_eq!(val_to_string(&Val::Bytes(vec![0xde, 0xad])), "hex:dead");
}

#[test]
fn parse_val_accepts_alternate_spellings() {
    assert_eq!(parse_val("int:42").unwrap(), Val::Int(42));
    assert_eq!(parse_val("42").unwrap(), Val::Int(42)); // bare int
    assert_eq!(parse_val("-9").unwrap(), Val::Int(-9));
    assert_eq!(parse_val("hex:ab12").unwrap(), Val::Bytes(vec![0xab, 0x12]));
    assert_eq!(parse_val("bytes:ab12").unwrap(), Val::Bytes(vec![0xab, 0x12])); // alias
    assert_eq!(parse_val("hex:0xab12").unwrap(), Val::Bytes(vec![0xab, 0x12])); // nested 0x
    // Leading/trailing whitespace tolerated.
    assert_eq!(parse_val("  int:5  ").unwrap(), Val::Int(5));
    assert_eq!(parse_val("hex:").unwrap(), Val::Bytes(vec![])); // empty hex payload
}

#[test]
fn parse_val_rejects_malformed() {
    // Unknown prefix / bare non-integer.
    assert!(matches!(parse_val("weird:x"), Err(EncodeError::BadValSpec(_))));
    assert!(matches!(parse_val("notanumber"), Err(EncodeError::BadValSpec(_))));
    assert!(matches!(parse_val(""), Err(EncodeError::BadValSpec(_))));
    // int: with a non-numeric / overflowing body.
    assert!(matches!(parse_val("int:abc"), Err(EncodeError::BadInt(_))));
    assert!(matches!(parse_val("int:"), Err(EncodeError::BadInt(_))));
    let overflow = format!("int:{}0", i128::MAX); // one digit past i128::MAX
    assert!(matches!(parse_val(&overflow), Err(EncodeError::BadInt(_))));
    // hex: with bad hex bubbles up as BadHex.
    assert!(matches!(parse_val("hex:zz"), Err(EncodeError::BadHex(_))));
}

// ---------------------------------------------------------------------------
// Op / program disassembly (display form, not wire form)
// ---------------------------------------------------------------------------

#[test]
fn op_to_string_covers_operand_and_nullary_ops() {
    assert_eq!(op_to_string(&Op::PushInt(-5)), "PushInt -5");
    assert_eq!(op_to_string(&Op::PushBytes(vec![0xde, 0xad])), "PushBytes 0xdead");
    assert_eq!(op_to_string(&Op::PushBytes(vec![])), "PushBytes 0x");
    assert_eq!(op_to_string(&Op::Dup), "Dup");
    assert_eq!(op_to_string(&Op::Add), "Add");
    assert_eq!(op_to_string(&Op::Pick(3)), "Pick 3");
    assert_eq!(op_to_string(&Op::CtxField(0)), "CtxField 0");
    assert_eq!(op_to_string(&Op::TxOutAsset(2)), "TxOutAsset 2");
    assert_eq!(op_to_string(&Op::SelfValidator), "SelfValidator");
}

#[test]
fn op_to_string_never_panics_over_every_variant() {
    // A crude but real invariant: the disassembler must handle all variants.
    for op in every_op_program() {
        let s = op_to_string(&op);
        assert!(!s.is_empty());
    }
}

#[test]
fn program_to_asm_is_index_prefixed_and_line_per_op() {
    let prog = vec![Op::PushInt(1), Op::PushInt(2), Op::Add];
    let asm = program_to_asm(&prog);
    let lines: Vec<&str> = asm.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("0000"));
    assert!(lines[0].contains("PushInt 1"));
    assert!(lines[2].contains("Add"));
    // Empty program disassembles to an empty string.
    assert_eq!(program_to_asm(&[]), "");
}

// ---------------------------------------------------------------------------
// ExtOutput rendering
// ---------------------------------------------------------------------------

#[test]
fn ext_output_renders_blch_and_datum() {
    let out = ExtOutput {
        value: euvm::blch(500),
        validator_hash: euvm::validator_hash(&every_op_program()),
        datum: Val::Int(7),
    };
    let s = ext_output_to_string(&out);
    assert!(s.contains("BLCH => 500"), "rendered: {s}");
    assert!(s.contains("datum: int:7"), "rendered: {s}");
    assert!(s.contains(&hash_to_hex(&out.validator_hash)));
}

#[test]
fn ext_output_renders_empty_value_and_non_blch_asset() {
    // Empty multi-asset bundle.
    let empty = ExtOutput {
        value: euvm::Value::new(),
        validator_hash: [0u8; 32],
        datum: Val::Bytes(vec![0xaa]),
    };
    let s = ext_output_to_string(&empty);
    assert!(s.contains("(empty)"), "rendered: {s}");
    assert!(s.contains("datum: hex:aa"), "rendered: {s}");

    // A non-BLCH asset is rendered by its hex id, not the "BLCH" label.
    let mut asset: AssetId = [0u8; 32];
    asset[0] = 0x11;
    let mut value = euvm::Value::new();
    value.insert(asset, 9);
    let out = ExtOutput { value, validator_hash: [0u8; 32], datum: Val::Int(0) };
    let s = ext_output_to_string(&out);
    assert!(s.contains(&asset_to_hex(&asset)), "rendered: {s}");
    assert!(s.contains("=> 9"), "rendered: {s}");
    assert!(!s.contains("BLCH"), "non-BLCH asset must not be labelled BLCH: {s}");
}
