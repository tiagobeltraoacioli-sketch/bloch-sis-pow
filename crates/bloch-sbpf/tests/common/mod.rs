//! Tiny macro-assembler + BSC-0 builder for test fixtures (spec §11 M3 —
//! dev-only, never shipped in the library).
//!
//! DELIBERATE: opcode bytes are written out here independently rather than
//! imported from `bloch_sbpf::isa`, so a mutation to the crate's encoding
//! tables cannot silently re-encode the fixtures to match itself — the
//! mutation-proof discipline (§10) requires the test side to be a second,
//! independent statement of the encoding.

#![allow(dead_code)] // each integration test binary uses a subset

pub type Slot = [u8; 8];

/// Raw slot: {op, dst | src<<4, off LE, imm LE} — spec §12-A.
pub fn ins(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Slot {
    let o = off.to_le_bytes();
    let i = imm.to_le_bytes();
    [op, (src << 4) | (dst & 0x0f), o[0], o[1], i[0], i[1], i[2], i[3]]
}

// ── ALU64 ──
pub fn mov64_imm(dst: u8, imm: i32) -> Slot { ins(0xb7, dst, 0, 0, imm) }
pub fn mov64_reg(dst: u8, src: u8) -> Slot { ins(0xbf, dst, src, 0, 0) }
pub fn add64_imm(dst: u8, imm: i32) -> Slot { ins(0x07, dst, 0, 0, imm) }
pub fn add64_reg(dst: u8, src: u8) -> Slot { ins(0x0f, dst, src, 0, 0) }
pub fn sub64_imm(dst: u8, imm: i32) -> Slot { ins(0x17, dst, 0, 0, imm) }
pub fn mul64_imm(dst: u8, imm: i32) -> Slot { ins(0x27, dst, 0, 0, imm) }
pub fn div64_imm(dst: u8, imm: i32) -> Slot { ins(0x37, dst, 0, 0, imm) }
pub fn div64_reg(dst: u8, src: u8) -> Slot { ins(0x3f, dst, src, 0, 0) }
pub fn sdiv64_reg(dst: u8, src: u8) -> Slot { ins(0x3f, dst, src, 1, 0) }
pub fn mod64_imm(dst: u8, imm: i32) -> Slot { ins(0x97, dst, 0, 0, imm) }
pub fn smod64_reg(dst: u8, src: u8) -> Slot { ins(0x9f, dst, src, 1, 0) }
pub fn and64_imm(dst: u8, imm: i32) -> Slot { ins(0x57, dst, 0, 0, imm) }
pub fn or64_imm(dst: u8, imm: i32) -> Slot { ins(0x47, dst, 0, 0, imm) }
pub fn xor64_imm(dst: u8, imm: i32) -> Slot { ins(0xa7, dst, 0, 0, imm) }
pub fn lsh64_imm(dst: u8, imm: i32) -> Slot { ins(0x67, dst, 0, 0, imm) }
pub fn rsh64_imm(dst: u8, imm: i32) -> Slot { ins(0x77, dst, 0, 0, imm) }
pub fn arsh64_imm(dst: u8, imm: i32) -> Slot { ins(0xc7, dst, 0, 0, imm) }
pub fn neg64(dst: u8) -> Slot { ins(0x87, dst, 0, 0, 0) }

// ── ALU32 ──
pub fn mov32_imm(dst: u8, imm: i32) -> Slot { ins(0xb4, dst, 0, 0, imm) }
pub fn mov32_reg(dst: u8, src: u8) -> Slot { ins(0xbc, dst, src, 0, 0) }
pub fn add32_imm(dst: u8, imm: i32) -> Slot { ins(0x04, dst, 0, 0, imm) }
pub fn sub32_imm(dst: u8, imm: i32) -> Slot { ins(0x14, dst, 0, 0, imm) }
pub fn mul32_imm(dst: u8, imm: i32) -> Slot { ins(0x24, dst, 0, 0, imm) }
pub fn div32_imm(dst: u8, imm: i32) -> Slot { ins(0x34, dst, 0, 0, imm) }
pub fn sdiv32_reg(dst: u8, src: u8) -> Slot { ins(0x3c, dst, src, 1, 0) }
pub fn lsh32_imm(dst: u8, imm: i32) -> Slot { ins(0x64, dst, 0, 0, imm) }
pub fn arsh32_imm(dst: u8, imm: i32) -> Slot { ins(0xc4, dst, 0, 0, imm) }

// ── byte swap (§12-A/E): 0xd4 = le, 0xdc = be; imm ∈ {16,32,64} ──
pub fn le(dst: u8, bits: i32) -> Slot { ins(0xd4, dst, 0, 0, bits) }
pub fn be(dst: u8, bits: i32) -> Slot { ins(0xdc, dst, 0, 0, bits) }

// ── lddw: two slots ──
pub fn lddw(dst: u8, v: u64) -> [Slot; 2] {
    [ins(0x18, dst, 0, 0, v as u32 as i32), ins(0x00, 0, 0, 0, (v >> 32) as u32 as i32)]
}

// ── memory ──
pub fn ldxb(dst: u8, src: u8, off: i16) -> Slot { ins(0x71, dst, src, off, 0) }
pub fn ldxh(dst: u8, src: u8, off: i16) -> Slot { ins(0x69, dst, src, off, 0) }
pub fn ldxw(dst: u8, src: u8, off: i16) -> Slot { ins(0x61, dst, src, off, 0) }
pub fn ldxdw(dst: u8, src: u8, off: i16) -> Slot { ins(0x79, dst, src, off, 0) }
pub fn stb(dst: u8, off: i16, imm: i32) -> Slot { ins(0x72, dst, 0, off, imm) }
pub fn stdw(dst: u8, off: i16, imm: i32) -> Slot { ins(0x7a, dst, 0, off, imm) }
pub fn stxb(dst: u8, src: u8, off: i16) -> Slot { ins(0x73, dst, src, off, 0) }
pub fn stxdw(dst: u8, src: u8, off: i16) -> Slot { ins(0x7b, dst, src, off, 0) }

// ── control flow ──
pub fn ja(off: i16) -> Slot { ins(0x05, 0, 0, off, 0) }
pub fn jeq_imm(dst: u8, imm: i32, off: i16) -> Slot { ins(0x15, dst, 0, off, imm) }
pub fn jeq32_imm(dst: u8, imm: i32, off: i16) -> Slot { ins(0x16, dst, 0, off, imm) }
pub fn jne_imm(dst: u8, imm: i32, off: i16) -> Slot { ins(0x55, dst, 0, off, imm) }
pub fn jgt_imm(dst: u8, imm: i32, off: i16) -> Slot { ins(0x25, dst, 0, off, imm) }
pub fn jsgt_imm(dst: u8, imm: i32, off: i16) -> Slot { ins(0x65, dst, 0, off, imm) }
/// call src=0 → syscall id (§12-B).
pub fn call_sys(id: u32) -> Slot { ins(0x85, 0, 0, 0, id as i32) }
/// call src=1 → internal function id (§12-B).
pub fn call_fn(id: u32) -> Slot { ins(0x85, 0, 1, 0, id as i32) }
pub fn exit() -> Slot { ins(0x95, 0, 0, 0, 0) }

/// Flatten slots to text bytes.
pub fn text(slots: &[Slot]) -> Vec<u8> {
    let mut t = Vec::with_capacity(slots.len() * 8);
    for s in slots {
        t.extend_from_slice(s);
    }
    t
}

/// Build a BSC-0 container (spec §8) from parts.
pub fn bsc0(entry_fn: u32, funcs: &[(u32, u32)], text_bytes: &[u8], rodata: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(b"BSC0");
    c.extend_from_slice(&0u32.to_le_bytes()); // version
    c.extend_from_slice(&entry_fn.to_le_bytes());
    c.extend_from_slice(&(funcs.len() as u32).to_le_bytes());
    for &(id, off) in funcs {
        c.extend_from_slice(&id.to_le_bytes());
        c.extend_from_slice(&off.to_le_bytes());
    }
    c.extend_from_slice(&(text_bytes.len() as u32).to_le_bytes());
    c.extend_from_slice(text_bytes);
    c.extend_from_slice(&(rodata.len() as u32).to_le_bytes());
    c.extend_from_slice(rodata);
    c
}

/// The common case: one function, id 0, at offset 0, no rodata.
pub fn simple(slots: &[Slot]) -> Vec<u8> {
    bsc0(0, &[(0, 0)], &text(slots), &[])
}

/// Region VA constants, duplicated from mem.rs on purpose (same independence
/// argument as the opcodes above).
pub const TEXT_BASE: u64 = 0x1_0000_0000;
pub const STACK_BASE: u64 = 0x2_0000_0000;
pub const HEAP_BASE: u64 = 0x3_0000_0000;
pub const INPUT_BASE: u64 = 0x4_0000_0000;

/// v0 syscall ids (§12-C), independent copies.
pub const SYS_ABORT: u32 = 1;
pub const SYS_LOG: u32 = 2;
pub const SYS_SHA3: u32 = 3;

/// load + execute with the v0 registry — the happy path most tests want.
pub fn run(container: &[u8], input: &[u8], budget: u64) -> bloch_sbpf::Outcome {
    let p = bloch_sbpf::load(container).expect("fixture must verify");
    bloch_sbpf::execute(&p, input, budget, &bloch_sbpf::SyscallRegistry::v0())
}
