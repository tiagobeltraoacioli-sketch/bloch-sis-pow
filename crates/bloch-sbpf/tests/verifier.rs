//! Verifier tests — spec §10 V-series plus container sanity.
//!
//! Repo rule: every negative test ships with its control half — the
//! minimally-different legitimate program that PASSES and whose Outcome is
//! asserted exactly — otherwise the negative can pass for the wrong reason
//! (e.g. the loader rejecting the container, not the verifier rejecting the
//! jump).

mod common;
use common::*;

use bloch_sbpf::{load, VerifyError};

// ── V1: jump target bounds ──

#[test]
fn v1_jump_past_end_rejected() {
    // ja +5 from slot 0 of a 2-slot program → target 6, out of [0, 2).
    let c = simple(&[ja(5), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadJumpTarget { pc: 0, target: 6 });
}

#[test]
fn v1_jump_before_start_rejected() {
    // ja -3 from slot 0 → target -2. i16::MIN-style wrap must not pass either.
    let c = simple(&[ja(-3), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadJumpTarget { pc: 0, target: -2 });
}

#[test]
fn v1_control_jump_to_next_insn_runs() {
    // Same shape, target = next instruction: mov r0, 7 is SKIPPED, so r0
    // keeps the mov before the jump. Pins both the jump math and the result.
    let c = simple(&[mov64_imm(0, 3), ja(1), mov64_imm(0, 7), exit()]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(3));
    assert_eq!(o.cu_used, 3); // mov + ja + exit; the skipped mov costs nothing
}

// ── V2: lddw second slot is not a jump target ──

#[test]
fn v2_jump_into_lddw_second_slot_rejected() {
    // slot0 ja +2 → slot 3 = second slot of the lddw at slot 2… build:
    // 0: ja +2 (target 3), 1: exit, 2..3: lddw, 4: exit
    let [l1, l2] = lddw(0, 0xdead_beef);
    let c = simple(&[ja(2), exit(), l1, l2, exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadJumpTarget { pc: 0, target: 3 });
}

#[test]
fn v2_control_jump_past_the_pair_runs() {
    // Identical program, off by one more: target 4 = the exit AFTER the pair.
    // r0 keeps the lddw value? No — the lddw is skipped; r0 stays 0. Then
    // prove the pair itself runs when reached: second fixture jumps TO the
    // first slot.
    let [l1, l2] = lddw(0, 0xdead_beef);
    let c = simple(&[ja(2), exit(), l1, l2, exit()]);
    // can't build "same bytes but legal" from THAT container (it is rejected);
    // the minimal legal twin uses off=3 → target 4:
    let c_ok = simple(&[ja(3), exit(), l1, l2, exit()]);
    assert!(load(&c).is_err());
    let o = run(&c_ok, &[], 100);
    assert_eq!(o.result, Ok(0)); // lddw skipped
    // and jumping exactly onto the lddw FIRST slot is legal and executes it:
    let c_first = simple(&[ja(1), exit(), l1, l2, exit()]);
    let o = run(&c_first, &[], 100);
    assert_eq!(o.result, Ok(0xdead_beef));
}

// ── V3: whitelist ──

#[test]
fn v3_unknown_opcode_rejected() {
    let c = simple(&[ins(0xff, 0, 0, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0xff });
}

#[test]
fn v3_control_same_slot_as_mov_runs() {
    let c = simple(&[mov64_imm(0, 9), exit()]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(9));
    assert_eq!(o.cu_used, 2);
}

#[test]
fn v3_atomic_lock_class_rejected() {
    // STX-class atomic (BPF_STX | BPF_ATOMIC | BPF_DW = 0xdb) — §2-OUT.
    let c = simple(&[ins(0xdb, 0, 1, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0xdb });
}

#[test]
fn v3_legacy_abs_load_rejected() {
    // BPF_LD | BPF_ABS | BPF_W = 0x20 — Linux-networking legacy, §2-OUT.
    let c = simple(&[ins(0x20, 0, 0, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0x20 });
}

#[test]
fn v3_alu64_class_end_rejected() {
    // RFC 9669 bswap (0xd7) is NOT in §2-IN — only the ALU32-class 0xd4/0xdc.
    let c = simple(&[ins(0xd7, 0, 0, 0, 64), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0xd7 });
}

#[test]
fn v3_endian_bad_width_rejected() {
    // le with imm=24: not one of {16,32,64} — a whitelist rejects what it
    // does not positively recognize.
    let c = simple(&[le(0, 24), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0xd4 });
}

#[test]
fn v3_alu_nonzero_offset_rejected_except_signed_divmod() {
    // add64 with off=1 is not a listed encoding (§12-A: off selects signed
    // div/mod ONLY on the div/mod opcodes).
    let c = simple(&[ins(0x07, 0, 0, 1, 1), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0x07 });
    // control: div64 with off=1 (sdiv) is legal and runs.
    let c = simple(&[mov64_imm(0, 8), mov64_imm(2, 2), ins(0x3f, 0, 2, 1, 0), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(4));
}

// ── V4: callx ──

#[test]
fn v4_callx_rejected() {
    // callx = 0x8d — THE classic CFG escape, §2-OUT.
    let c = simple(&[ins(0x8d, 0, 0, 0, 1), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ForbiddenOpcode { pc: 0, opcode: 0x8d });
}

#[test]
fn v4_control_call_to_table_fn_runs() {
    // 0: call fn 1, 1: exit, 2 (fn 1): mov r0, 5, 3: exit
    let t = text(&[call_fn(1), exit(), mov64_imm(0, 5), exit()]);
    let c = bsc0(0, &[(0, 0), (1, 16)], &t, &[]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(5));
    assert_eq!(o.cu_used, 4);
}

// ── V5: r10 is read-only, across every dst-writing class ──

#[test]
fn v5_write_r10_rejected_all_classes() {
    let [l1, l2] = lddw(10, 1);
    let cases: Vec<(&str, Vec<Slot>)> = vec![
        ("mov", vec![mov64_imm(10, 0), exit()]),
        ("mov32", vec![mov32_imm(10, 0), exit()]),
        ("add", vec![add64_imm(10, 8), exit()]),
        ("neg", vec![neg64(10), exit()]),
        ("endian", vec![be(10, 64), exit()]),
        ("lddw", vec![l1, l2, exit()]),
        ("ldx", vec![ldxdw(10, 1, 0), exit()]),
    ];
    for (name, slots) in cases {
        let c = simple(&slots);
        assert_eq!(
            load(&c).unwrap_err(),
            VerifyError::FrameRegisterWrite { pc: 0 },
            "class `{name}` must reject r10 as dst"
        );
    }
}

#[test]
fn v5_control_write_r9_runs_and_r10_reads_allowed() {
    // Same shapes with r9: legal. And r10 as a STORE BASE is a read — the
    // stack is addressed through it (spec §4 check 4 rationale).
    let c = simple(&[
        mov64_imm(9, 1),
        add64_imm(9, 1),
        stxdw(10, 9, -8),   // *(r10 - 8) = r9 — r10 read, allowed
        ldxdw(0, 10, -8),   // r0 = *(r10 - 8)
        exit(),
    ]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(2));
}

#[test]
fn v5_src_register_out_of_range_rejected() {
    // src nibble 12: registers stop at r10 (§4 check 4).
    let c = simple(&[ins(0xbf, 0, 12, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadRegister { pc: 0, reg: 12 });
}

#[test]
fn v5_dst_register_out_of_range_rejected() {
    // dst nibble 12 — a SEPARATE check from src, and load-bearing: the
    // interpreter's register file is exactly 11 wide, so an unchecked dst of
    // 12 would index out of bounds. (Added after a mutation run showed the
    // src-only test survived deleting the dst check — spec §10 discipline:
    // a test that survives the mutation of its own rule is decorative.)
    let c = simple(&[ins(0xbf, 12, 0, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadRegister { pc: 0, reg: 12 });
    // Control: the same instruction with dst = r10 is rejected for the OTHER
    // reason (frame-pointer write), and with dst = r9 it verifies and runs.
    let c = simple(&[ins(0xbf, 10, 0, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::FrameRegisterWrite { pc: 0 });
    let c = simple(&[ins(0xbf, 9, 0, 0, 0), mov64_reg(0, 9), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

// ── V6: call resolution ──

#[test]
fn v6_call_unregistered_syscall_id_rejected() {
    let c = simple(&[call_sys(99), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::UnresolvedCall { pc: 0, imm: 99 });
}

#[test]
fn v6_call_unknown_internal_fn_rejected() {
    let c = simple(&[call_fn(7), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::UnresolvedCall { pc: 0, imm: 7 });
}

#[test]
fn v6_call_bad_src_rejected() {
    // src=2 is neither syscall (0) nor internal (1) — §12-B pins the set.
    let c = simple(&[ins(0x85, 0, 2, 0, 1), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::UnresolvedCall { pc: 0, imm: 1 });
}

#[test]
fn v6_control_registered_log_id_runs_log_pinned() {
    // log(r1 = INPUT, r2 = 3) with input "abc" → one log entry "abc".
    let c = simple(&[mov64_imm(2, 3), call_sys(SYS_LOG), exit()]);
    let o = run(&c, b"abc", 1000);
    assert_eq!(o.result, Ok(0));
    assert_eq!(o.log, vec![b"abc".to_vec()]);
    // CU pinned: mov(1) + call(1) + log(100+3) + exit(1)
    assert_eq!(o.cu_used, 106);
}

// ── lddw pairing (§4 check 3) ──

#[test]
fn lddw_truncated_at_end_rejected() {
    // First slot as the LAST slot of text: no second slot exists.
    let [l1, _] = lddw(0, 1);
    let c = simple(&[l1]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadLddwPair { pc: 0 });
}

#[test]
fn lddw_malformed_second_slot_rejected() {
    // Second slot must be op/dst/src/off all zero (§12-A); op=0x07 here.
    let [l1, _] = lddw(0, 1);
    let c = simple(&[l1, ins(0x07, 0, 0, 0, 0), exit()]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadLddwPair { pc: 0 });
}

#[test]
fn lddw_control_well_formed_pair_runs() {
    let [l1, l2] = lddw(0, 0x1122_3344_5566_7788);
    let c = simple(&[l1, l2, exit()]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(0x1122_3344_5566_7788));
    assert_eq!(o.cu_used, 2); // lddw is ONE instruction: 1 CU (§12-H) + exit
}

// ── container sanity (§4 check 1, §12-F) ──

#[test]
fn container_bad_magic_rejected() {
    let mut c = simple(&[exit()]);
    c[0] = b'X';
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadMagic);
}

#[test]
fn container_bad_version_rejected() {
    let mut c = simple(&[exit()]);
    c[4] = 1; // version u32 LE = 1
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadVersion(1));
}

#[test]
fn container_trailing_bytes_rejected() {
    let mut c = simple(&[exit()]);
    c.push(0);
    assert_eq!(load(&c).unwrap_err(), VerifyError::TrailingBytes);
}

#[test]
fn container_truncated_rejected() {
    let c = simple(&[exit()]);
    assert_eq!(load(&c[..c.len() - 1]).unwrap_err(), VerifyError::Truncated);
}

#[test]
fn container_text_not_slot_aligned_rejected() {
    let mut t = text(&[exit()]);
    t.push(0x95); // 9 bytes
    let c = bsc0(0, &[(0, 0)], &t, &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::TextNotSlotAligned(9));
}

#[test]
fn container_function_offset_out_of_bounds_rejected() {
    let c = bsc0(0, &[(0, 8)], &text(&[exit()]), &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadFunctionOffset { id: 0, offset: 8 });
}

#[test]
fn container_function_offset_unaligned_rejected() {
    let c = bsc0(0, &[(0, 4)], &text(&[exit(), exit()]), &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::BadFunctionOffset { id: 0, offset: 4 });
}

#[test]
fn container_duplicate_function_id_rejected() {
    let c = bsc0(0, &[(0, 0), (0, 8)], &text(&[exit(), exit()]), &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::DuplicateFunction(0));
}

#[test]
fn container_unresolved_entry_rejected() {
    let c = bsc0(3, &[(0, 0)], &text(&[exit()]), &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::UnresolvedEntry(3));
}

#[test]
fn container_entry_into_lddw_second_slot_rejected() {
    let [l1, l2] = lddw(0, 1);
    // fn 1 declared AT the second slot (offset 8): must be rejected even
    // though it is never called — a table entry is a potential call target.
    let c = bsc0(0, &[(0, 0), (1, 8)], &text(&[l1, l2, exit()]), &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::EntryIntoLddw(1));
}

#[test]
fn container_program_too_large_rejected() {
    // 65 537 slots of `exit` — one over MAX_PROGRAM_SLOTS.
    let t = vec![0x95u8, 0, 0, 0, 0, 0, 0, 0].repeat(65_537);
    let c = bsc0(0, &[(0, 0)], &t, &[]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::ProgramTooLarge(65_537));
}

#[test]
fn container_rodata_too_large_rejected() {
    let c = bsc0(0, &[(0, 0)], &text(&[exit()]), &vec![0u8; 512 * 1024 + 1]);
    assert_eq!(load(&c).unwrap_err(), VerifyError::RodataTooLarge(512 * 1024 + 1));
}

#[test]
fn container_control_max_sizes_accepted() {
    // Exactly AT both ceilings: verifies the bounds are `>` not `>=`.
    let t = vec![0x95u8, 0, 0, 0, 0, 0, 0, 0].repeat(65_536);
    let c = bsc0(0, &[(0, 0)], &t, &vec![0u8; 512 * 1024]);
    assert!(load(&c).is_ok());
}

#[test]
fn rodata_is_readable_at_text_end() {
    // TEXT+RO region = text ‖ rodata (§5): rodata byte 0 lives at
    // TEXT_BASE + text_len. Program: r0 = *(u8*)(TEXT_BASE + 16).
    // 4 slots → text_len = 32; rodata[0] is at TEXT_BASE + 32.
    let [l1, l2] = lddw(2, TEXT_BASE);
    let c = bsc0(0, &[(0, 0)], &text(&[l1, l2, ldxb(0, 2, 32), exit()]), &[0xab]);
    let o = run(&c, &[], 100);
    assert_eq!(o.result, Ok(0xab));
}
