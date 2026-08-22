//! Memory map + checked access (spec §5).
//!
//! Solana-style fixed virtual-address map, one region per 4 GiB stride. The
//! program only ever sees these virtual constants — no host pointer is
//! observable, which closes the "address of a host allocation leaks into
//! state" non-determinism vector by construction. Every access is translated
//! by explicit `checked_add` + range + permission checks BEFORE any byte
//! moves; unaligned access is a checked byte copy, so no host alignment trap
//! can leak through (the "works on x86, faults on ARM" class is gone).

use crate::interp::FaultKind;

pub const TEXT_BASE: u64 = 0x1_0000_0000;
pub const STACK_BASE: u64 = 0x2_0000_0000;
pub const HEAP_BASE: u64 = 0x3_0000_0000;
pub const INPUT_BASE: u64 = 0x4_0000_0000;

/// Fixed 4 KiB frame (§5): SBFv1-style, what the SBF backend expects by
/// default. r10 for depth d (entry = depth 1) is STACK_BASE + d * FRAME_SIZE
/// (§12-B).
pub const STACK_FRAME_SIZE: u64 = 4096;
/// Max call depth (§3): 64 frames; frame 65 faults.
pub const MAX_CALL_DEPTH: u64 = 64;
/// Whole stack region: 64 × 4 KiB. Zero-initialized — a determinism
/// requirement, not hygiene (§5): uninitialized memory is per-machine entropy.
pub const STACK_SIZE: usize = (MAX_CALL_DEPTH * STACK_FRAME_SIZE) as usize;
/// Heap (§5): 32 KiB raw bump region, zero-initialized, no grow syscall in v0.
pub const HEAP_SIZE: usize = 32 * 1024;

/// The four regions of one execution. RO is borrowed from the
/// `VerifiedProgram` (text ‖ rodata); INPUT from the caller; STACK and HEAP
/// are owned, zeroed per execution, and end up in `Outcome`.
pub struct MemoryMap<'a> {
    pub(crate) ro: &'a [u8],
    pub(crate) stack: Vec<u8>,
    pub(crate) heap: Vec<u8>,
    pub(crate) input: &'a [u8],
}

impl<'a> MemoryMap<'a> {
    pub fn new(ro: &'a [u8], input: &'a [u8]) -> Self {
        MemoryMap { ro, stack: vec![0u8; STACK_SIZE], heap: vec![0u8; HEAP_SIZE], input }
    }

    /// Translate `[va, va+len)` to an offset inside one region.
    /// Returns (region tag for the borrow below, start offset).
    ///
    /// The single-region property of §5 ("a single access may not straddle
    /// regions") is structural: the check is `base <= va && va + len <=
    /// base + region.len()` with `checked_add` — since region contents are
    /// far smaller than the 4 GiB stride, an in-bounds range can only ever
    /// lie inside the one region its base falls in. There is no page 0:
    /// va < TEXT_BASE matches no region and faults.
    fn translate(&self, va: u64, len: u64, write: bool) -> Result<(Region, usize), FaultKind> {
        let end = va.checked_add(len).ok_or(FaultKind::AccessViolation { va, len, write })?;
        let regions: [(u64, usize, bool, Region); 4] = [
            (TEXT_BASE, self.ro.len(), false, Region::Ro),
            (STACK_BASE, self.stack.len(), true, Region::Stack),
            (HEAP_BASE, self.heap.len(), true, Region::Heap),
            // INPUT is read-only in v0 (§5): no writeback contract exists yet.
            (INPUT_BASE, self.input.len(), false, Region::Input),
        ];
        for (base, size, writable, tag) in regions {
            if va >= base && end <= base + size as u64 {
                if write && !writable {
                    return Err(FaultKind::AccessViolation { va, len, write });
                }
                return Ok((tag, (va - base) as usize));
            }
        }
        Err(FaultKind::AccessViolation { va, len, write })
    }

    /// Checked read of up to 8 bytes (every whitelisted load moves ≤ 8 —
    /// the fact that makes 1-CU-flat sound, §6). LE assembly of the value.
    pub fn load(&self, va: u64, size: u8) -> Result<u64, FaultKind> {
        let (region, off) = self.translate(va, size as u64, false)?;
        let buf = match region {
            Region::Ro => self.ro,
            Region::Stack => &self.stack,
            Region::Heap => &self.heap,
            Region::Input => self.input,
        };
        let mut v = 0u64;
        // Byte-at-a-time: unaligned-safe on every host by construction (§3).
        for i in (0..size as usize).rev() {
            v = (v << 8) | buf[off + i] as u64;
        }
        Ok(v)
    }

    /// Checked write of up to 8 bytes, little-endian truncation of `value`.
    pub fn store(&mut self, va: u64, size: u8, value: u64) -> Result<(), FaultKind> {
        let (region, off) = self.translate(va, size as u64, true)?;
        let buf = match region {
            Region::Stack => &mut self.stack,
            Region::Heap => &mut self.heap,
            // translate() already rejected writes to RO/INPUT; fail CLOSED
            // (not panic) if that invariant is ever broken — "reject or
            // verify, never panic" (§10) applies to runtime code too.
            Region::Ro | Region::Input => {
                return Err(FaultKind::AccessViolation { va, len: size as u64, write: true })
            }
        };
        for i in 0..size as usize {
            buf[off + i] = (value >> (8 * i)) as u8;
        }
        Ok(())
    }

    /// Bulk read for syscalls (log, sha3 input). Same checks as `load`.
    pub fn read_bytes(&self, va: u64, len: u64) -> Result<Vec<u8>, FaultKind> {
        let (region, off) = self.translate(va, len, false)?;
        let buf = match region {
            Region::Ro => self.ro,
            Region::Stack => &self.stack,
            Region::Heap => &self.heap,
            Region::Input => self.input,
        };
        Ok(buf[off..off + len as usize].to_vec())
    }

    /// Bulk write for syscalls (sha3 output). Same checks as `store`.
    pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) -> Result<(), FaultKind> {
        let (region, off) = self.translate(va, bytes.len() as u64, true)?;
        let buf = match region {
            Region::Stack => &mut self.stack,
            Region::Heap => &mut self.heap,
            // Same fail-closed posture as store().
            Region::Ro | Region::Input => {
                return Err(FaultKind::AccessViolation { va, len: bytes.len() as u64, write: true })
            }
        };
        buf[off..off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Region {
    Ro,
    Stack,
    Heap,
    Input,
}
