//! Integration tests for the `asm` component, exercised from OUTSIDE the crate
//! (i.e. only through the public surface `euvm_tooling::asm::*`, the re-exported
//! VM `euvm_tooling::euvm`, and the exported `euvm_tooling::prog!` macro).
//!
//! `asm` is a syntactic builder: every method is infallible and simply appends
//! one `euvm::Op`. It therefore has no `Result`-returning "reject" API — the only
//! fail-closed guard it exposes is the advisory `within_op_limit()` boundary
//! against `euvm::MAX_PROGRAM_OPS`. These tests pin:
//!   * exact byte-level encodings against the documented tag table (accept-cases),
//!   * operand faithfulness (a dropped/garbled operand is a defect),
//!   * the identity contract `hash == SHA-256d(encode_program)` verified with an
//!     INDEPENDENT sha2 computation (not just against the VM's own helper),
//!   * asm→program→encode round-trips and builder/free-fn/macro equivalence,
//!   * the `within_op_limit` fail-closed boundary AND the deliberate design that
//!     `build()`/`hash()` do NOT pre-validate (semantically nonsense programs and
//!     over-limit programs still assemble — the VM rejects at spend time).
//!
//! NB on call style: the builder methods return `&mut Self`, but `build(self)`
//! consumes `self`, so the fluent `Asm::new().dup().build()` chain does not
//! compile (E0507, move out of a mutable reference). External callers must use a
//! named binding, an owned temporary from `from_ops(...)`, or the `prog!` macro.

use euvm_tooling::asm::{program, Asm};
use euvm_tooling::euvm;
use euvm_tooling::prog;

use sha2::{Digest, Sha256};

// --- helpers ---------------------------------------------------------------

/// Canonical bytes of a single-op program built through the public builder.
fn enc(build: impl FnOnce(&mut Asm)) -> Vec<u8> {
    let mut a = Asm::new();
    build(&mut a);
    a.encode()
}

/// Independent double-SHA256 (does NOT call any bloch-euvm helper), so the
/// identity contract is checked against an outside implementation.
fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let once = Sha256::digest(bytes);
    let twice = Sha256::digest(once);
    let mut out = [0u8; 32];
    out.copy_from_slice(&twice);
    out
}

// --- empty program ---------------------------------------------------------

#[test]
fn empty_program_encodes_empty_and_hashes_canonically() {
    let a = Asm::new();
    assert!(a.is_empty());
    assert_eq!(a.len(), 0);
    assert_eq!(a.encode(), Vec::<u8>::new());
    // hash of the empty program == SHA-256d of empty input, independently computed.
    assert_eq!(a.hash(), sha256d(&[]));
    // ...and agrees with the VM's own helpers on the empty slice.
    assert_eq!(a.hash(), euvm::validator_hash(&[]));
    assert_eq!(a.encode(), euvm::encode_program(&[]));

    let built = Asm::new().build();
    assert!(built.is_empty());
}

// --- byte-exact tag table (accept-cases) -----------------------------------

#[test]
fn nullary_ops_encode_to_their_single_tag_byte() {
    assert_eq!(enc(|a| { a.dup(); }), vec![0x10]);
    assert_eq!(enc(|a| { a.drop_(); }), vec![0x11]);
    assert_eq!(enc(|a| { a.swap(); }), vec![0x12]);
    assert_eq!(enc(|a| { a.add(); }), vec![0x20]);
    assert_eq!(enc(|a| { a.sub(); }), vec![0x21]);
    assert_eq!(enc(|a| { a.mul(); }), vec![0x22]);
    assert_eq!(enc(|a| { a.eq(); }), vec![0x30]);
    assert_eq!(enc(|a| { a.lt(); }), vec![0x31]);
    assert_eq!(enc(|a| { a.not(); }), vec![0x32]);
    assert_eq!(enc(|a| { a.sha256d(); }), vec![0x40]);
    assert_eq!(enc(|a| { a.shake256(); }), vec![0x41]);
    assert_eq!(enc(|a| { a.size(); }), vec![0x42]);
    assert_eq!(enc(|a| { a.verify_sig(); }), vec![0x60]);
    // NOTE: the tag table interleaves these — Verify is 0x61, VerifyEcdsa is 0x62.
    assert_eq!(enc(|a| { a.verify(); }), vec![0x61]);
    assert_eq!(enc(|a| { a.verify_ecdsa(); }), vec![0x62]);
    assert_eq!(enc(|a| { a.self_validator(); }), vec![0x73]);
    assert_eq!(enc(|a| { a.self_asset(); }), vec![0x74]);
}

#[test]
fn index_ops_encode_tag_then_single_operand_byte() {
    assert_eq!(enc(|a| { a.pick(5); }), vec![0x13, 5]);
    assert_eq!(enc(|a| { a.ctx_field(7); }), vec![0x50, 7]);
    assert_eq!(enc(|a| { a.tx_out_datum(3); }), vec![0x70, 3]);
    assert_eq!(enc(|a| { a.tx_out_validator(9); }), vec![0x71, 9]);
    assert_eq!(enc(|a| { a.tx_out_value(1); }), vec![0x72, 1]);
    assert_eq!(enc(|a| { a.tx_out_asset(4); }), vec![0x75, 4]);
}

#[test]
fn index_ops_carry_the_full_u8_range() {
    // Operand must survive to the last byte; 0xFF is the boundary value.
    assert_eq!(enc(|a| { a.pick(u8::MAX); }), vec![0x13, 0xFF]);
    assert_eq!(enc(|a| { a.ctx_field(u8::MAX); }), vec![0x50, 0xFF]);
    assert_eq!(enc(|a| { a.tx_out_datum(u8::MAX); }), vec![0x70, 0xFF]);
    assert_eq!(enc(|a| { a.tx_out_validator(u8::MAX); }), vec![0x71, 0xFF]);
    assert_eq!(enc(|a| { a.tx_out_value(u8::MAX); }), vec![0x72, 0xFF]);
    assert_eq!(enc(|a| { a.tx_out_asset(u8::MAX); }), vec![0x75, 0xFF]);
}

// --- PushInt operand faithfulness (16-byte i128 LE) ------------------------

#[test]
fn push_int_encodes_tag_plus_16_le_bytes_including_extremes() {
    for n in [0i128, 1, -1, 42, i128::MIN, i128::MAX] {
        let bytes = enc(|a| { a.push_int(n); });
        let mut expected = vec![0x01u8];
        expected.extend_from_slice(&n.to_le_bytes());
        assert_eq!(bytes.len(), 17, "PushInt is 1 tag + 16 operand bytes");
        assert_eq!(bytes, expected, "PushInt({n}) operand mismatch");
    }
    // -1 must be all-ones little-endian, distinctly from 0.
    assert_eq!(enc(|a| { a.push_int(-1); })[1..], [0xFFu8; 16]);
    assert_eq!(enc(|a| { a.push_int(0); })[1..], [0x00u8; 16]);
}

#[test]
fn push_int_distinct_values_produce_distinct_encodings() {
    assert_ne!(enc(|a| { a.push_int(1); }), enc(|a| { a.push_int(2); }));
    assert_ne!(enc(|a| { a.push_int(0); }), enc(|a| { a.push_int(-1); }));
}

// --- PushBytes length prefix (u32 LE) --------------------------------------

#[test]
fn push_bytes_encodes_tag_u32le_len_then_payload() {
    // empty payload
    assert_eq!(enc(|a| { a.push_bytes(Vec::<u8>::new()); }), vec![0x02, 0, 0, 0, 0]);

    // small payload
    assert_eq!(
        enc(|a| { a.push_bytes(vec![0xaa, 0xbb]); }),
        vec![0x02, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb]
    );

    // payload whose length crosses the first byte of the u32 prefix (300 = 0x012C)
    let payload = vec![0xABu8; 300];
    let bytes = enc(|a| { a.push_bytes(payload.clone()); });
    let mut expected = vec![0x02u8, 0x2C, 0x01, 0x00, 0x00];
    expected.extend_from_slice(&payload);
    assert_eq!(bytes, expected);
    assert_eq!(bytes.len(), 1 + 4 + 300);
}

#[test]
fn push_bytes_accepts_array_and_vec_into_impls() {
    // impl Into<Vec<u8>> covers both [u8; N] and Vec<u8>; encodings must agree.
    let from_array = enc(|a| { a.push_bytes([1u8, 2, 3]); });
    let from_vec = enc(|a| { a.push_bytes(vec![1u8, 2, 3]); });
    assert_eq!(from_array, from_vec);
}

#[test]
fn push_bytes_distinct_payloads_differ() {
    assert_ne!(
        enc(|a| { a.push_bytes(b"a".to_vec()); }),
        enc(|a| { a.push_bytes(b"b".to_vec()); })
    );
    // same length, different content must still differ (content is encoded, not just len).
    assert_ne!(
        enc(|a| { a.push_bytes(vec![0x00, 0x01]); }),
        enc(|a| { a.push_bytes(vec![0x01, 0x00]); })
    );
}

// --- Pick(0) vs Dup: semantically equal, syntactically distinct ------------

#[test]
fn pick_zero_is_distinct_from_dup_on_the_wire() {
    // Pick(0) == Dup semantically, but they are different Op variants and MUST
    // encode/hash differently (0x10 vs 0x13 0x00). This guards against the
    // builder collapsing them.
    let dup = enc(|a| { a.dup(); });
    let pick0 = enc(|a| { a.pick(0); });
    assert_eq!(dup, vec![0x10]);
    assert_eq!(pick0, vec![0x13, 0x00]);
    assert_ne!(dup, pick0);

    let mut da = Asm::new();
    da.dup();
    let mut pa = Asm::new();
    pa.pick(0);
    assert_ne!(da.hash(), pa.hash());
}

// --- identity contract: hash == SHA-256d(encode) (independent) -------------

#[test]
fn hash_equals_independent_double_sha256_of_encoding() {
    // A program touching several op families.
    let p = prog![
        push_bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        sha256d(),
        push_bytes(vec![0x11; 32]),
        eq(),
        verify()
    ];
    let a = Asm::from_ops(p.clone());
    let encoded = a.encode();

    // encode agrees with the VM's canonical encoder,
    assert_eq!(encoded, euvm::encode_program(&p));
    // hash agrees with the VM's validator_hash,
    assert_eq!(a.hash(), euvm::validator_hash(&p));
    // and, crucially, with an INDEPENDENT double-SHA256 of those bytes.
    assert_eq!(a.hash(), sha256d(&encoded));
}

// --- builder / free-fn / macro equivalence & round-trip --------------------

#[test]
fn from_ops_round_trips_program_bytes() {
    let p = prog![push_int(1), push_int(2), add(), push_int(3), eq(), verify()];
    let round = Asm::from_ops(p.clone()).build();
    // asm -> program -> Asm::from_ops -> program: canonical bytes preserved.
    assert_eq!(euvm::encode_program(&round), euvm::encode_program(&p));

    // empty round-trips too.
    assert!(Asm::from_ops(Vec::new()).build().is_empty());
}

#[test]
fn op_escape_hatch_matches_named_builder_method() {
    let mut via_op = Asm::new();
    via_op.op(euvm::Op::Dup).op(euvm::Op::Add);
    let mut via_named = Asm::new();
    via_named.dup().add();
    assert_eq!(via_op.encode(), via_named.encode());
    assert_eq!(via_op.hash(), via_named.hash());
}

#[test]
fn extend_concatenates_fragments_in_order() {
    let head = prog![push_int(1)];
    let tail = prog![push_int(2), add()];

    let mut joined = Asm::from_ops(head.clone());
    joined.extend(Asm::from_ops(tail.clone()));
    let expected = prog![push_int(1), push_int(2), add()];
    assert_eq!(joined.encode(), euvm::encode_program(&expected));

    // Order matters: swapping head/tail must change the encoding.
    let mut reversed = Asm::from_ops(tail);
    reversed.extend(Asm::from_ops(head));
    assert_ne!(reversed.encode(), joined.encode());
}

#[test]
fn program_passthrough_is_identity() {
    let ops = prog![self_validator(), size()];
    let same = program(ops.clone());
    assert_eq!(euvm::encode_program(&same), euvm::encode_program(&ops));
    // and on an empty vector.
    assert!(program(Vec::new()).is_empty());
}

#[test]
fn prog_macro_empty_and_trailing_comma() {
    let empty = prog![];
    assert!(empty.is_empty());

    // trailing comma after the last method call must parse.
    let one = prog![dup(),];
    assert_eq!(euvm::encode_program(&one), vec![0x10]);
}

#[test]
fn prog_macro_matches_named_builder() {
    let via_macro = prog![push_int(2), push_int(2), add(), push_int(4), eq(), verify()];
    let mut b = Asm::new();
    b.push_int(2).push_int(2).add().push_int(4).eq().verify();
    let via_builder = b.build();
    assert_eq!(
        euvm::encode_program(&via_macro),
        euvm::encode_program(&via_builder)
    );
}

// --- accessors don't consume / stay consistent -----------------------------

#[test]
fn len_is_empty_and_ops_accessor_track_pushes() {
    let mut a = Asm::new();
    assert!(a.is_empty());
    a.push_int(0).push_bytes(vec![1, 2, 3]).dup();
    assert!(!a.is_empty());
    assert_eq!(a.len(), 3);
    // ops() borrows, does not consume — callable twice, matches len.
    assert_eq!(a.ops().len(), 3);
    assert_eq!(a.ops().len(), 3);
    // build() reproduces exactly what ops() showed.
    let ops_bytes = euvm::encode_program(a.ops());
    let built = a.build();
    assert_eq!(euvm::encode_program(&built), ops_bytes);
    assert_eq!(built.len(), 3);
}

// --- fail-closed boundary: within_op_limit ---------------------------------

#[test]
fn within_op_limit_boundary_is_fail_closed() {
    let max = euvm::MAX_PROGRAM_OPS;

    // Exactly at the ceiling: allowed.
    let mut at = Asm::new();
    for _ in 0..max {
        at.dup();
    }
    assert_eq!(at.len(), max);
    assert!(at.within_op_limit(), "exactly MAX_PROGRAM_OPS must be within limit");

    // One over the ceiling: rejected by the advisory guard.
    at.dup();
    assert_eq!(at.len(), max + 1);
    assert!(
        !at.within_op_limit(),
        "MAX_PROGRAM_OPS + 1 must report over-limit"
    );
}

#[test]
fn build_and_hash_do_not_pre_enforce_the_op_limit() {
    // Design contract: within_op_limit is advisory. build()/hash() still succeed
    // over the ceiling (the VM enforces at spend time, not the assembler).
    let over = euvm::MAX_PROGRAM_OPS + 1;
    let mut a = Asm::new();
    for _ in 0..over {
        a.dup();
    }
    assert!(!a.within_op_limit());
    // hash() must still compute without panicking...
    let h = a.hash();
    // ...and equal the independent double-SHA256 of the (all-0x10) encoding.
    let expected = sha256d(&vec![0x10u8; over]);
    assert_eq!(h, expected);
    // build() returns the full, over-limit program unmodified.
    let built = a.build();
    assert_eq!(built.len(), over);
}

// --- asm does NOT pre-validate semantics (reject vs accept boundary) -------

#[test]
fn semantically_invalid_programs_still_assemble() {
    // asm is a syntactic layer: an `Add` with no operands, or a `Verify` on an
    // empty stack, is a runtime error at spend — but MUST still assemble/encode
    // here. This documents that "rejection" is the VM's job, not the builder's.
    let underflow_add = prog![add()];
    assert_eq!(euvm::encode_program(&underflow_add), vec![0x20]);

    let dangling_verify = prog![verify()];
    assert_eq!(euvm::encode_program(&dangling_verify), vec![0x61]);

    // A type-mismatched skeleton (push bytes, then integer Add) also assembles.
    let type_mismatch = prog![push_bytes(vec![0xff]), push_int(1), add()];
    assert_eq!(type_mismatch.len(), 3);
    // hash is still well-defined for a nonsense program.
    let _ = Asm::from_ops(type_mismatch).hash();
}

// --- distinct programs are distinct on the wire ----------------------------

#[test]
fn distinct_programs_have_distinct_encodings_and_hashes() {
    let a = prog![push_int(1), add()];
    let b = prog![push_int(1), sub()];
    let c = prog![push_int(2), add()];

    let ea = euvm::encode_program(&a);
    let eb = euvm::encode_program(&b);
    let ec = euvm::encode_program(&c);
    assert_ne!(ea, eb, "differing terminal op must differ");
    assert_ne!(ea, ec, "differing operand must differ");

    let ha = euvm::validator_hash(&a);
    let hb = euvm::validator_hash(&b);
    let hc = euvm::validator_hash(&c);
    assert_ne!(ha, hb);
    assert_ne!(ha, hc);
}

// --- a full-coverage program: every builder family in one encoding ---------

#[test]
fn all_op_families_assemble_and_match_vm_encoder() {
    // Build one program exercising every builder method, then confirm the
    // assembler's encoding/hash match the VM's canonical functions byte-for-byte
    // (the asm -> program faithfulness round-trip across the whole opset).
    let p = prog![
        push_int(-7),
        push_bytes(vec![0xca, 0xfe]),
        dup(),
        drop_(),
        swap(),
        pick(2),
        add(),
        sub(),
        mul(),
        eq(),
        lt(),
        not(),
        sha256d(),
        shake256(),
        size(),
        ctx_field(0),
        verify_sig(),
        verify_ecdsa(),
        verify(),
        tx_out_datum(0),
        tx_out_validator(1),
        tx_out_value(2),
        self_validator(),
        self_asset(),
        tx_out_asset(3)
    ];
    assert_eq!(p.len(), 25);

    let a = Asm::from_ops(p.clone());
    assert_eq!(a.encode(), euvm::encode_program(&p));
    assert_eq!(a.hash(), euvm::validator_hash(&p));
    assert_eq!(a.hash(), sha256d(&a.encode()));
    assert!(a.within_op_limit());
}
