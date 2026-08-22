//! A1 series — ALU edge KATs (spec §3, §10). Every §3 edge semantics is a
//! consensus rule, so each gets a known-answer test with a benign control.

mod common;
use common::*;

use bloch_sbpf::FaultKind;

// ── sdiv overflow (§3) ──

#[test]
fn a1_sdiv_i64_min_by_minus_one_faults() {
    let [l1, l2] = lddw(0, i64::MIN as u64);
    let c = simple(&[l1, l2, mov64_imm(2, -1), sdiv64_reg(0, 2), exit()]);
    let o = run(&c, &[], 100);
    let f = o.result.unwrap_err();
    assert_eq!(f.kind, FaultKind::SdivOverflow);
    assert_eq!(f.pc, 3);
}

#[test]
fn a1_control_sdiv_i64_min_by_one_runs() {
    let [l1, l2] = lddw(0, i64::MIN as u64);
    let c = simple(&[l1, l2, mov64_imm(2, 1), sdiv64_reg(0, 2), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(i64::MIN as u64));
}

#[test]
fn a1_sdiv_negative_truncates_toward_zero() {
    // -7 / 2 = -3 (truncation, not floor) — the C/eBPF rule.
    let c = simple(&[mov64_imm(0, -7), mov64_imm(2, 2), sdiv64_reg(0, 2), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(-3i64 as u64));
}

#[test]
fn a1_sdiv32_i32_min_by_minus_one_faults() {
    let c = simple(&[
        mov32_imm(0, i32::MIN),
        mov32_imm(2, -1),
        sdiv32_reg(0, 2),
        exit(),
    ]);
    assert_eq!(run(&c, &[], 100).result.unwrap_err().kind, FaultKind::SdivOverflow);
}

#[test]
fn a1_smod_i64_min_by_minus_one_is_zero() {
    // Pinned in interp.rs: smod MIN % -1 = 0 (RFC 9669), NOT a fault and NOT
    // a host panic — Rust's bare `%` would abort under overflow-checks.
    let [l1, l2] = lddw(0, i64::MIN as u64);
    let c = simple(&[l1, l2, mov64_imm(2, -1), smod64_reg(0, 2), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

// ── shift masking (§3) ──

#[test]
fn a1_shift_by_64_masks_to_zero() {
    // lsh r0, 64 → shift amount 64 & 63 = 0 → value unchanged. An unmasked
    // shift would be a Rust panic (overflow-checks) or UB-adjacent in C.
    let c = simple(&[mov64_imm(0, 7), lsh64_imm(0, 64), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(7));
}

#[test]
fn a1_shift_by_65_masks_to_one() {
    let c = simple(&[mov64_imm(0, 7), lsh64_imm(0, 65), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(14));
}

#[test]
fn a1_control_shift_by_63_runs() {
    let c = simple(&[mov64_imm(0, 1), lsh64_imm(0, 63), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(1u64 << 63));
}

#[test]
fn a1_shift32_masks_at_31() {
    // lsh32 by 32 → & 31 = 0 → unchanged (and zero-extended).
    let c = simple(&[mov32_imm(0, 5), lsh32_imm(0, 32), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(5));
}

#[test]
fn a1_arsh_is_arithmetic() {
    // -8 >> 1 arithmetic = -4; logical would give a huge positive.
    let c = simple(&[mov64_imm(0, -8), arsh64_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(-4i64 as u64));
    let c = simple(&[mov64_imm(0, -8), rsh64_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok((-8i64 as u64) >> 1));
}

// ── ALU32 zero-extension (§3) ──

#[test]
fn a1_alu32_zero_extends() {
    // r0 = u64::MAX; add32 r0, 1 → low 32 wrap to 0, ZERO-extended → r0 == 0.
    let [l1, l2] = lddw(0, u64::MAX);
    let c = simple(&[l1, l2, add32_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

#[test]
fn a1_control_alu64_carries_past_bit32() {
    // Same shape, 64-bit add: wraps the whole register → 0 only because MAX.
    let [l1, l2] = lddw(0, 0xffff_ffff);
    let c = simple(&[l1, l2, add64_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x1_0000_0000));
    let c32 = simple(&[l1, l2, add32_imm(0, 1), exit()]);
    assert_eq!(run(&c32, &[], 100).result, Ok(0));
}

#[test]
fn a1_mov32_imm_zero_extends_negative() {
    // mov32 r0, -1 → 0x0000_0000_ffff_ffff (zero-extend, §3)…
    let c = simple(&[mov32_imm(0, -1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0xffff_ffff));
    // …while mov64 r0, -1 sign-extends to the full register (classic eBPF).
    let c = simple(&[mov64_imm(0, -1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(u64::MAX));
}

// ── 64-bit wrap (§3) ──

#[test]
fn a1_add64_wraps_two_complement() {
    let [l1, l2] = lddw(0, u64::MAX);
    let c = simple(&[l1, l2, add64_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

#[test]
fn a1_mul64_wraps() {
    let [l1, l2] = lddw(0, 1u64 << 63);
    let c = simple(&[l1, l2, mul64_imm(0, 2), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

#[test]
fn a1_neg_is_two_complement() {
    let c = simple(&[mov64_imm(0, 1), neg64(0), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(u64::MAX));
}

// ── byte swap (§12-E) ──

#[test]
fn a1_be_swaps_bytes() {
    let [l1, l2] = lddw(0, 0x1122_3344_5566_7788);
    let c = simple(&[l1, l2, be(0, 64), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x8877_6655_4433_2211));
    let c = simple(&[l1, l2, be(0, 32), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x8877_6655));
    let c = simple(&[l1, l2, be(0, 16), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x8877));
}

#[test]
fn a1_le_truncates_zero_extends() {
    // The VM is little-endian: leN keeps the low N bits (§12-E).
    let [l1, l2] = lddw(0, 0x1122_3344_5566_7788);
    let c = simple(&[l1, l2, le(0, 32), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x5566_7788));
    let c = simple(&[l1, l2, le(0, 16), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x7788));
    let c = simple(&[l1, l2, le(0, 64), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x1122_3344_5566_7788));
}

// ── signed vs unsigned compare, 64 vs 32 (§2 JMP32) ──

#[test]
fn a1_jgt_unsigned_vs_jsgt_signed() {
    // r2 = -1 (= u64::MAX unsigned). jgt r2, 1 → TAKEN (unsigned).
    let c = simple(&[
        mov64_imm(2, -1),
        jgt_imm(2, 1, 1),
        exit(),           // not taken path: r0 = 0
        mov64_imm(0, 1),  // taken path
        exit(),
    ]);
    assert_eq!(run(&c, &[], 100).result, Ok(1));
    // jsgt r2, 1 → NOT taken (signed: -1 < 1).
    let c = simple(&[
        mov64_imm(2, -1),
        jsgt_imm(2, 1, 1),
        exit(),
        mov64_imm(0, 1),
        exit(),
    ]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

#[test]
fn a1_jmp32_compares_low_bits_only() {
    // r2 = 0x1_0000_0001: jeq32 r2, 1 → taken; jeq64 r2, 1 → not taken.
    let [l1, l2] = lddw(2, 0x1_0000_0001);
    let c = simple(&[l1, l2, jeq32_imm(2, 1, 1), exit(), mov64_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(1));
    let c = simple(&[l1, l2, jeq_imm(2, 1, 1), exit(), mov64_imm(0, 1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0));
}

// ── unaligned access (§3) ──

#[test]
fn a1_unaligned_store_load_roundtrip() {
    // 8-byte store at r10 - 5: crosses natural alignment; must behave
    // identically everywhere (checked byte copies).
    let [l1, l2] = lddw(3, 0x0102_0304_0506_0708);
    let c = simple(&[l1, l2, stxdw(10, 3, -5), ldxdw(0, 10, -5), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0x0102_0304_0506_0708));
}

#[test]
fn a1_partial_width_load_zero_extends() {
    // ldxh from input "\xff\xff…": r0 = 0xffff, never sign-extended.
    let c = simple(&[ldxh(0, 1, 0), exit()]);
    assert_eq!(run(&c, &[0xff; 8], 100).result, Ok(0xffff));
    let c = simple(&[ldxb(0, 1, 3), exit()]);
    assert_eq!(run(&c, &[0xff; 8], 100).result, Ok(0xff));
    let c = simple(&[ldxw(0, 1, 0), exit()]);
    assert_eq!(run(&c, &[0xff; 8], 100).result, Ok(0xffff_ffff));
}

// ── store-immediate sign-extension truncation ──

#[test]
fn a1_st_imm_writes_le_truncation() {
    // stdw imm -1 → 8 bytes of 0xff (imm sign-extends to i64, §3 LE store).
    let c = simple(&[stdw(10, -8, -1), ldxdw(0, 10, -8), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(u64::MAX));
    // stb imm 0x1ff → single byte 0xff (LE truncation).
    let c = simple(&[stb(10, -1, 0x1ff), ldxb(0, 10, -1), exit()]);
    assert_eq!(run(&c, &[], 100).result, Ok(0xff));
}
