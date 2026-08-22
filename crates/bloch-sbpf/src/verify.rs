//! The load-time verifier (spec §4) — the security boundary of this crate.
//!
//! Everything the interpreter trusts is established HERE, once, in `load()`:
//! opcode whitelist, lddw pairing, register bounds, jump-target bounds, call
//! resolution. `execute()` only accepts a [`VerifiedProgram`], whose fields
//! are private and whose only constructor is this module — running unverified
//! bytecode is unrepresentable by construction (spec §1).
//!
//! Deliberately NOT a verifier duty (spec §4, written down so nobody "fixes"
//! it later): loop/termination analysis. Termination is the meter's job
//! (meter.rs) and only the meter's.

use std::collections::BTreeMap;

use crate::container::{self, MAX_PROGRAM_SLOTS};
use crate::isa::{classify, decode_slot, writes_dst, Insn, InsnKind, SLOT_BYTES};
use crate::syscall::SYSCALL_IDS;

/// Rejection reasons. Each carries enough position info (`pc` in slots) that a
/// rejecting test can assert it rejected for the RIGHT reason — the §10 rule
/// that every negative test has a control twin exists precisely because "some
/// error came out" is not evidence the intended check fired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    // ── container sanity (§4 check 1, container.rs) ──
    Truncated,
    BadMagic,
    BadVersion(u32),
    TrailingBytes,
    TextNotSlotAligned(usize),
    ProgramTooLarge(usize),
    RodataTooLarge(usize),
    TooManyFunctions(usize),
    /// Function-table entry out of text bounds or not on a slot boundary.
    BadFunctionOffset { id: u32, offset: u32 },
    /// §12-F: two table entries with the same id would make call resolution
    /// ambiguous — rejected rather than "first wins".
    DuplicateFunction(u32),
    /// entry_fn does not name a table entry.
    UnresolvedEntry(u32),
    /// entry (or an internal-call target) lands on an lddw second slot.
    EntryIntoLddw(u32),

    // ── instruction stream (§4 checks 2–6) ──
    /// Not in the §2-IN whitelist (unknown, callx, atomics, ABS/IND, …).
    ForbiddenOpcode { pc: usize, opcode: u8 },
    /// lddw first slot at end of text, or second slot malformed (op/dst/src/
    /// off must be zero, §12-A).
    BadLddwPair { pc: usize },
    /// A register field outside 0..=10.
    BadRegister { pc: usize, reg: u8 },
    /// Write to the frame pointer — r10 is read-only (§3). Applies to every
    /// dst-writing class: ALU, mov, endian, lddw, ldx.
    FrameRegisterWrite { pc: usize },
    /// Branch target outside [0, n_insns) or onto an lddw second slot.
    BadJumpTarget { pc: usize, target: i64 },
    /// `call` that resolves to neither a v0 syscall id (src=0) nor a
    /// function-table entry (src=1), or carries an unpinned src value.
    UnresolvedCall { pc: usize, imm: i32 },
}

/// A verified program — the token `execute()` demands. All fields are
/// `pub(crate)`: outside this crate the ONLY way to obtain one is `load()`,
/// which is the whole point.
#[derive(Debug)]
pub struct VerifiedProgram {
    /// Decoded slots, 1:1 with the text section (second lddw slots included,
    /// but `kinds` marks them unreachable).
    pub(crate) insns: Vec<Insn>,
    /// `Some(kind)` for every first slot; `None` for lddw second slots (the
    /// verifier guarantees control flow never lands on a `None`).
    pub(crate) kinds: Vec<Option<InsnKind>>,
    /// TEXT+RO region image: text bytes ‖ rodata bytes (spec §5 — one
    /// read-only region at 0x1_0000_0000, so programs address rodata at
    /// TEXT_BASE + text_len + offset).
    pub(crate) ro_image: Vec<u8>,
    /// function id → entry slot. BTreeMap: canonical iteration order is a
    /// determinism requirement of the whole crate (no HashMap anywhere).
    pub(crate) funcs: BTreeMap<u32, usize>,
    /// Entry point, in slots.
    pub(crate) entry_pc: usize,
}

/// Verify a BSC-0 container (spec §4, single linear pass + jump-target pass;
/// O(n) in program size, allocation bounded by container.rs constants — a
/// hostile container cannot DoS the loader either).
pub fn load(container_bytes: &[u8]) -> Result<VerifiedProgram, VerifyError> {
    let raw = container::parse(container_bytes)?;

    let n = raw.text.len() / SLOT_BYTES;
    debug_assert!(n <= MAX_PROGRAM_SLOTS); // container.rs enforced

    // Decode every slot up front (decode is total; legality comes next).
    let mut insns = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = [0u8; 8];
        b.copy_from_slice(&raw.text[i * SLOT_BYTES..(i + 1) * SLOT_BYTES]);
        insns.push(decode_slot(&b));
    }

    // ── Pass 1: whitelist + lddw pairing + register bounds (§4 checks 2–4) ──
    let mut kinds: Vec<Option<InsnKind>> = vec![None; n];
    let mut is_second_slot = vec![false; n];
    let mut pc = 0usize;
    while pc < n {
        let insn = &insns[pc];
        let kind = classify(insn)
            .ok_or(VerifyError::ForbiddenOpcode { pc, opcode: insn.op })?;

        // Register bounds (§4 check 4) on every first slot, used or not:
        // the nibble fields are 0..=15 but only r0..r10 exist.
        if insn.dst > 10 {
            return Err(VerifyError::BadRegister { pc, reg: insn.dst });
        }
        if insn.src > 10 {
            return Err(VerifyError::BadRegister { pc, reg: insn.src });
        }
        // r10 is read-only (§3): reject it as dst wherever dst is WRITTEN.
        // st/stx keep dst as an address base (a read) — writes_dst() is the
        // single source of truth for the distinction, so a new class cannot
        // silently dodge this check.
        if insn.dst == 10 && writes_dst(&kind) {
            return Err(VerifyError::FrameRegisterWrite { pc });
        }

        kinds[pc] = Some(kind);

        if kind == InsnKind::Lddw {
            // §4 check 3: pairing. The first slot must have a well-formed
            // second slot: op, dst, src, off all zero (§12-A) — imm carries
            // the high 32 bits and may be anything.
            let second = pc.checked_add(1).filter(|&s| s < n).map(|s| insns[s]);
            match second {
                Some(s) if s.op == 0 && s.dst == 0 && s.src == 0 && s.off == 0 => {
                    is_second_slot[pc + 1] = true;
                    pc += 2;
                    continue;
                }
                _ => return Err(VerifyError::BadLddwPair { pc }),
            }
        }
        pc += 1;
    }

    // ── Function table (§4 check 1 tail + §12-F) — needed before the call
    //    pass so check 6 can resolve internal targets. ──
    let mut funcs: BTreeMap<u32, usize> = BTreeMap::new();
    for &(id, off_bytes) in &raw.func_table {
        let off = off_bytes as usize;
        if off % SLOT_BYTES != 0 || off >= raw.text.len() {
            return Err(VerifyError::BadFunctionOffset { id, offset: off_bytes });
        }
        let slot = off / SLOT_BYTES;
        if is_second_slot[slot] {
            return Err(VerifyError::EntryIntoLddw(id));
        }
        if funcs.insert(id, slot).is_some() {
            return Err(VerifyError::DuplicateFunction(id));
        }
    }
    let entry_pc = *funcs
        .get(&raw.entry_fn)
        .ok_or(VerifyError::UnresolvedEntry(raw.entry_fn))?;

    // ── Pass 2: jump targets + call resolution (§4 checks 5–6) ──
    for pc in 0..n {
        let kind = match kinds[pc] {
            Some(k) => k,
            None => continue, // lddw second slot: not an instruction
        };
        match kind {
            InsnKind::JumpAlways | InsnKind::JumpCond { .. } => {
                let insn = &insns[pc];
                // Target = pc + 1 + off, in slots (§12-A). i64 math: no
                // wrap-around trick with off = i16::MIN can pass.
                let target = pc as i64 + 1 + insn.off as i64;
                if target < 0 || target >= n as i64 {
                    return Err(VerifyError::BadJumpTarget { pc, target });
                }
                // §4 check 5: never onto an lddw second slot. Fall-through
                // off the end stays LEGAL here — it is a defined runtime
                // fault (§3); the verifier bounds where control can GO, not
                // whether it halts.
                if is_second_slot[target as usize] {
                    return Err(VerifyError::BadJumpTarget { pc, target });
                }
            }
            InsnKind::Call => {
                let insn = &insns[pc];
                let id = insn.imm as u32;
                match insn.src {
                    // §12-B/C: src=0 → syscall, resolved against the PINNED
                    // v0 id constants (load() takes no registry, §1).
                    0 => {
                        if !SYSCALL_IDS.contains(&id) {
                            return Err(VerifyError::UnresolvedCall { pc, imm: insn.imm });
                        }
                    }
                    // src=1 → internal function; must be in the table.
                    // Nothing links implicitly (§4 check 6).
                    1 => {
                        if !funcs.contains_key(&id) {
                            return Err(VerifyError::UnresolvedCall { pc, imm: insn.imm });
                        }
                    }
                    _ => return Err(VerifyError::UnresolvedCall { pc, imm: insn.imm }),
                }
            }
            _ => {}
        }
    }

    // TEXT+RO image = text ‖ rodata (spec §5). Built after all checks so a
    // rejected container allocates as little as possible.
    let mut ro_image = Vec::with_capacity(raw.text.len() + raw.rodata.len());
    ro_image.extend_from_slice(raw.text);
    ro_image.extend_from_slice(raw.rodata);

    Ok(VerifiedProgram { insns, kinds, ro_image, funcs, entry_pc })
}
