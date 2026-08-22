//! Instruction encoding/decoding and the opcode whitelist (spec §2, §12-A).
//!
//! The byte encoding is the classic eBPF one pinned by spec §12-A (RFC 9669
//! layout): 8-byte little-endian slots `{op: u8, regs: u8, off: i16, imm: i32}`
//! where `dst` is the LOW nibble of the regs byte and `src` the HIGH nibble.
//!
//! `classify()` is the whitelist: it returns `Some(kind)` ONLY for the §2-IN
//! subset and `None` for everything else — an opcode is rejected because it is
//! not listed, never accepted because it is not known to be bad (§2-OUT).
//! There is deliberately no deny-list anywhere in this crate.

/// One decoded 8-byte instruction slot. `lddw` occupies two slots; the second
/// slot never reaches the interpreter (spec §4 checks 3+5 make it unreachable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub op: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

/// Slot width in bytes. The container's `text_len` must be a multiple of this
/// (spec §4 check 1) and jump offsets are counted in slots, not bytes.
pub const SLOT_BYTES: usize = 8;

/// Decode one slot. Infallible: every 8-byte pattern decodes to *some* `Insn`;
/// whether that `Insn` is legal is `classify()`'s job (the split keeps the
/// decoder trivially total, so the verifier — not the decoder — is the single
/// place bytes get rejected).
pub fn decode_slot(b: &[u8; 8]) -> Insn {
    Insn {
        op: b[0],
        dst: b[1] & 0x0f,
        src: (b[1] >> 4) & 0x0f,
        off: i16::from_le_bytes([b[2], b[3]]),
        imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    }
}

/// ALU operation, shared by the 64- and 32-bit classes. `Div`/`Mod` are the
/// unsigned forms; `SDiv`/`SMod` are the same opcodes with `off == 1`
/// (spec §12-A, RFC 9669 encoding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    SDiv,
    Mod,
    SMod,
    And,
    Or,
    Xor,
    Lsh,
    Rsh,
    Arsh,
    Neg,
    Mov,
}

/// Conditional-jump predicate (JMP and JMP32 classes share these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JmpOp {
    Jeq,
    Jne,
    Jgt,
    Jge,
    Jlt,
    Jle,
    Jsgt,
    Jsge,
    Jslt,
    Jsle,
    Jset,
}

/// The whitelisted instruction kinds — spec §2-IN, nothing more. The verifier
/// stores one of these per first slot so the interpreter never re-derives
/// legality at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsnKind {
    /// ALU64/ALU32 with `wide` distinguishing them; `reg_src` = X form.
    Alu { op: AluOp, wide: bool, reg_src: bool },
    /// Byte swap (spec §12-E): `be = false` is `leN`, `bits ∈ {16, 32, 64}`.
    Endian { be: bool, bits: u8 },
    /// Two-slot 64-bit immediate load; second slot validated by the verifier.
    Lddw,
    /// `ldx{b,h,w,dw}` — `size` in bytes (1/2/4/8).
    LoadReg { size: u8 },
    /// `st{b,h,w,dw}` — immediate store, `size` in bytes.
    StoreImm { size: u8 },
    /// `stx{b,h,w,dw}` — register store, `size` in bytes.
    StoreReg { size: u8 },
    /// Unconditional `ja` (JMP class only; a JMP32-class `ja` is NOT
    /// whitelisted — spec §12-A).
    JumpAlways,
    /// Conditional jump; `wide = false` compares the low 32 bits (JMP32).
    JumpCond { op: JmpOp, wide: bool, reg_src: bool },
    /// `call imm` — src=0 syscall, src=1 internal (spec §12-B); the verifier
    /// resolves the target, the interpreter only dispatches.
    Call,
    Exit,
}

/// Map a size-bits pattern (opcode bits 3..5) to a byte width.
fn mem_size(op: u8) -> u8 {
    match op & 0x18 {
        0x00 => 4, // W
        0x08 => 2, // H
        0x10 => 1, // B
        _ => 8,    // DW (0x18)
    }
}

fn alu_op(op: u8, off: i16) -> Option<AluOp> {
    // High nibble selects the operation; spec §12-A requires off == 0 for all
    // ALU ops EXCEPT div/mod, where off == 1 selects the signed form. Any
    // other off value is rejected — a whitelist rejects what it does not
    // positively recognize.
    Some(match (op & 0xf0, off) {
        (0x00, 0) => AluOp::Add,
        (0x10, 0) => AluOp::Sub,
        (0x20, 0) => AluOp::Mul,
        (0x30, 0) => AluOp::Div,
        (0x30, 1) => AluOp::SDiv,
        (0x40, 0) => AluOp::Or,
        (0x50, 0) => AluOp::And,
        (0x60, 0) => AluOp::Lsh,
        (0x70, 0) => AluOp::Rsh,
        (0x80, 0) => AluOp::Neg,
        (0x90, 0) => AluOp::Mod,
        (0x90, 1) => AluOp::SMod,
        (0xa0, 0) => AluOp::Xor,
        (0xb0, 0) => AluOp::Mov,
        (0xc0, 0) => AluOp::Arsh,
        _ => return None,
    })
}

fn jmp_op(op: u8) -> Option<JmpOp> {
    Some(match op & 0xf0 {
        0x10 => JmpOp::Jeq,
        0x20 => JmpOp::Jgt,
        0x30 => JmpOp::Jge,
        0x40 => JmpOp::Jset,
        0x50 => JmpOp::Jne,
        0x60 => JmpOp::Jsgt,
        0x70 => JmpOp::Jsge,
        0xa0 => JmpOp::Jlt,
        0xb0 => JmpOp::Jle,
        0xc0 => JmpOp::Jslt,
        0xd0 => JmpOp::Jsle,
        _ => return None,
    })
}

/// THE whitelist (spec §4 check 2). Returns `None` for every opcode outside
/// §2-IN: callx (0x8d), atomics (class 0xc0/0xdb `lock`), BPF_ABS/IND
/// (classes 0x20/0x40 within LD), tail calls, and any unknown byte — all fall
/// through to `None` because nothing matches them, which is the point.
pub fn classify(insn: &Insn) -> Option<InsnKind> {
    let op = insn.op;
    match op & 0x07 {
        // ── ALU32 (0x04) and ALU64 (0x07) ──
        0x04 | 0x07 => {
            let wide = op & 0x07 == 0x07;
            // END (byteswap) is the 0xd0 row of the ALU32 class only
            // (spec §12-A): 0xd4 = le, 0xdc = be. An ALU64-class END (0xd7 /
            // 0xdf, RFC 9669 bswap) is NOT whitelisted.
            if op & 0xf0 == 0xd0 {
                if wide {
                    return None;
                }
                let be = op & 0x08 != 0;
                let bits = match insn.imm {
                    16 => 16,
                    32 => 32,
                    64 => 64,
                    _ => return None,
                };
                if insn.off != 0 {
                    return None;
                }
                return Some(InsnKind::Endian { be, bits });
            }
            let reg_src = op & 0x08 != 0;
            let a = alu_op(op, insn.off)?;
            // neg has no register form in the ISA (0x84/0x87 only).
            if a == AluOp::Neg && reg_src {
                return None;
            }
            Some(InsnKind::Alu { op: a, wide, reg_src })
        }
        // ── JMP (0x05) and JMP32 (0x06) ──
        0x05 | 0x06 => {
            let wide = op & 0x07 == 0x05;
            match op {
                0x05 => Some(InsnKind::JumpAlways),
                // call/exit live in the JMP class only.
                0x85 => Some(InsnKind::Call),
                0x95 => Some(InsnKind::Exit),
                // callx (0x8d) matches nothing here → None. Deliberate.
                _ => {
                    let j = jmp_op(op)?;
                    let reg_src = op & 0x08 != 0;
                    // 0x06 (JMP32-class ja) and 0x8e etc. never reach here:
                    // jmp_op() has no 0x00/0x80/0x90 rows.
                    Some(InsnKind::JumpCond { op: j, wide, reg_src })
                }
            }
        }
        // ── LD (0x00): only lddw (0x18) is whitelisted; BPF_ABS/IND and every
        //    other LD-class mode fall to None. ──
        0x00 => {
            if op == 0x18 {
                Some(InsnKind::Lddw)
            } else {
                None
            }
        }
        // ── LDX (0x01): register loads, BPF_MEM mode only (0x61/0x69/0x71/0x79). ──
        0x01 => {
            if op & 0xe0 == 0x60 {
                Some(InsnKind::LoadReg { size: mem_size(op) })
            } else {
                None
            }
        }
        // ── ST (0x02): immediate stores, BPF_MEM mode only. ──
        0x02 => {
            if op & 0xe0 == 0x60 {
                Some(InsnKind::StoreImm { size: mem_size(op) })
            } else {
                None
            }
        }
        // ── STX (0x03): register stores, BPF_MEM mode only. The atomic
        //    (`lock`) mode is 0xc0 within this class and matches nothing. ──
        0x03 => {
            if op & 0xe0 == 0x60 {
                Some(InsnKind::StoreReg { size: mem_size(op) })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Does this kind WRITE its `dst` register? Spec §4 check 4 rejects r10 as
/// dst for these; note st/stx use `dst` as the address BASE (a read — storing
/// through r10 is how stack slots are addressed), so they are `false` here.
pub fn writes_dst(kind: &InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::Alu { .. } | InsnKind::Endian { .. } | InsnKind::Lddw | InsnKind::LoadReg { .. }
    )
}
