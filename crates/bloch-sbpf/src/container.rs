//! BSC-0 program container (spec §8, bounds amendments §12-F).
//!
//! Deliberately NOT ELF: a hostile-input-safe ELF loader is a project of its
//! own (Solana's has had CVEs). BSC-0 is flat, little-endian, one-pass
//! checkable:
//!
//! ```text
//! magic "BSC0" | version u32 | entry_fn u32 | n_funcs u32
//! | func_table: n_funcs × (id u32, text_offset u32)
//! | text_len u32 | text bytes | rodata_len u32 | rodata bytes
//! ```
//!
//! Every read below goes through the bounds-checked `Cursor`; nothing indexes
//! the input directly, so a truncated or hostile container can only produce a
//! `VerifyError`, never a panic or an over-read (the fuzz invariant, §10).

use crate::verify::VerifyError;

/// Verifier/loader cost bound (spec §4): text ≤ 65 536 slots = 512 KiB.
pub const MAX_PROGRAM_SLOTS: usize = 65_536;
/// §12-F: rodata gets the same 512 KiB ceiling so `load()` allocation is
/// bounded by a constant, not by attacker-chosen lengths.
pub const MAX_RODATA_BYTES: usize = 512 * 1024;
/// §12-F: function-table bound (one entry per possible slot is already
/// generous; hand-written v0 fixtures use a handful).
pub const MAX_FUNCS: usize = 65_536;

/// Parsed-but-not-yet-verified container. Only `verify.rs` consumes this;
/// it is `pub(crate)` so no external path can skip verification.
pub(crate) struct RawContainer<'a> {
    pub entry_fn: u32,
    /// (id, text_offset_bytes) in file order; duplicate-id and boundary
    /// checks happen in the verifier (§4 check 1 / §12-F).
    pub func_table: Vec<(u32, u32)>,
    pub text: &'a [u8],
    pub rodata: &'a [u8],
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], VerifyError> {
        let end = self.pos.checked_add(n).ok_or(VerifyError::Truncated)?;
        if end > self.buf.len() {
            return Err(VerifyError::Truncated);
        }
        // (mutation anchor: bound retained, see MUT note)
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, VerifyError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

pub(crate) fn parse(container: &[u8]) -> Result<RawContainer<'_>, VerifyError> {
    let mut c = Cursor { buf: container, pos: 0 };

    if c.take(4)? != b"BSC0" {
        return Err(VerifyError::BadMagic);
    }
    // §12-F: the version field of BSC-0 is exactly 0. A future BSC-1 is a
    // spec amendment, not a silently-accepted integer.
    let version = c.u32()?;
    if version != 0 {
        return Err(VerifyError::BadVersion(version));
    }

    let entry_fn = c.u32()?;

    let n_funcs = c.u32()? as usize;
    if n_funcs > MAX_FUNCS {
        return Err(VerifyError::TooManyFunctions(n_funcs));
    }
    // Allocation bounded: n_funcs was range-checked above AND each entry must
    // physically exist in the input (take() fails on truncation), so memory
    // here is ≤ min(MAX_FUNCS, container_len/8) entries.
    let mut func_table = Vec::with_capacity(n_funcs);
    for _ in 0..n_funcs {
        let id = c.u32()?;
        let off = c.u32()?;
        func_table.push((id, off));
    }

    let text_len = c.u32()? as usize;
    if text_len % crate::isa::SLOT_BYTES != 0 {
        return Err(VerifyError::TextNotSlotAligned(text_len));
    }
    if text_len / crate::isa::SLOT_BYTES > MAX_PROGRAM_SLOTS {
        return Err(VerifyError::ProgramTooLarge(text_len / crate::isa::SLOT_BYTES));
    }
    let text = c.take(text_len)?;

    let rodata_len = c.u32()? as usize;
    if rodata_len > MAX_RODATA_BYTES {
        return Err(VerifyError::RodataTooLarge(rodata_len));
    }
    let rodata = c.take(rodata_len)?;

    // §12-F: trailing bytes rejected. Two containers that verify to the same
    // program must be the same bytes — no slack space for mutable garbage.
    if c.pos != container.len() {
        return Err(VerifyError::TrailingBytes);
    }

    Ok(RawContainer { entry_fn, func_table, text, rodata })
}
