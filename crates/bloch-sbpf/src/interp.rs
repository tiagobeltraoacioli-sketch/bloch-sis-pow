//! The interpreter loop (spec §3) and the canonical `Outcome` (§1, §12-D).
//!
//! The interpreter trusts exactly what the verifier established (verify.rs)
//! and nothing more: it never re-derives legality, and it can only be entered
//! through `execute(&VerifiedProgram, …)`. Every §3 edge (wrap, zero-extend,
//! div-zero, shift masks, call depth, total faults) is implemented here and
//! pinned by a KAT in tests/.
//!
//! Determinism inventory for this file (spec item c): arithmetic is
//! `wrapping_*` on fixed-width integers (wrapping IS the defined semantics,
//! §3 — and the workspace-wide `overflow-checks = true` profile turns any
//! UNintended unchecked arithmetic into a loud panic on every profile
//! identically); there is no float anywhere (§3-FP); iteration state is a
//! `Vec` + `BTreeMap`; no clock, no I/O, no host pointer ever enters a
//! register — VAs are the fixed constants of mem.rs.

use crate::isa::{AluOp, InsnKind, JmpOp};
use crate::mem::{MemoryMap, INPUT_BASE, MAX_CALL_DEPTH, STACK_BASE, STACK_FRAME_SIZE};
use crate::meter::{Meter, COST_TABLE_VERSION, SBPF_COST_INSN};
use crate::syscall::{SyscallRegistry, MAX_LOG_BYTES_TOTAL};
use crate::verify::VerifiedProgram;

/// What went wrong, without position. The interpreter attaches the faulting
/// pc (making [`Fault`]) so every fault is pinned to a bit-identical location
/// on every node (§6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultKind {
    DivByZero,
    /// `sdiv`/`sdiv32` overflow: i64::MIN / -1 (resp. i32::MIN / -1), §3.
    SdivOverflow,
    AccessViolation { va: u64, len: u64, write: bool },
    /// Control ran off the end of the text section without `exit` (§3).
    TextOverrun,
    CallDepthExceeded,
    ComputeBudgetExceeded,
    /// The `abort()` syscall (§7).
    Aborted,
    /// A verified syscall id missing from the runtime registry (§12-C).
    UnknownSyscall { id: u32 },
    /// Log caps exceeded — fault, not truncation (§12-I).
    LogLimitExceeded,
}

/// A fault pinned to its program counter (slot index). §3: faults are TOTAL —
/// the interpreter discards all memory effects when one of these escapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub pc: u64,
}

/// The canonical result of one execution (§1). Two nodes MUST produce
/// identical bytes from [`Outcome::canonical_bytes`]; the D2 golden vectors
/// pin SHA3-256 of exactly that encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// r0 on success, or the fault.
    pub result: Result<u64, Fault>,
    pub cu_used: u64,
    /// Log entries from the `log` syscall, in call order, bounded (§7).
    pub log: Vec<Vec<u8>>,
    /// HEAP contents on success; EMPTY on fault (total-fault semantics, §12-D).
    pub heap: Vec<u8>,
    /// STACK contents on success; EMPTY on fault.
    pub stack: Vec<u8>,
}

impl Outcome {
    /// The §12-D byte layout, exactly. Every integer little-endian. This is
    /// a consensus-candidate encoding: reordering a field or changing a width
    /// is a hard fork of any future consumer, which is why D2 pins hashes of
    /// these bytes in-repo.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&COST_TABLE_VERSION.to_le_bytes());
        match &self.result {
            Ok(r0) => {
                out.push(0);
                out.extend_from_slice(&r0.to_le_bytes());
            }
            Err(f) => {
                out.push(1);
                let (code, extra): (u32, Vec<u8>) = match &f.kind {
                    FaultKind::DivByZero => (1, vec![]),
                    FaultKind::SdivOverflow => (2, vec![]),
                    FaultKind::AccessViolation { va, len, write } => {
                        let mut e = Vec::with_capacity(17);
                        e.extend_from_slice(&va.to_le_bytes());
                        e.extend_from_slice(&len.to_le_bytes());
                        e.push(u8::from(*write));
                        (3, e)
                    }
                    FaultKind::TextOverrun => (4, vec![]),
                    FaultKind::CallDepthExceeded => (5, vec![]),
                    FaultKind::ComputeBudgetExceeded => (6, vec![]),
                    FaultKind::Aborted => (7, vec![]),
                    FaultKind::UnknownSyscall { id } => (8, id.to_le_bytes().to_vec()),
                    FaultKind::LogLimitExceeded => (9, vec![]),
                };
                out.extend_from_slice(&code.to_le_bytes());
                out.extend_from_slice(&f.pc.to_le_bytes());
                out.extend_from_slice(&extra);
            }
        }
        out.extend_from_slice(&self.cu_used.to_le_bytes());
        out.extend_from_slice(&(self.log.len() as u32).to_le_bytes());
        for entry in &self.log {
            out.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            out.extend_from_slice(entry);
        }
        out.extend_from_slice(&(self.heap.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.heap);
        out.extend_from_slice(&(self.stack.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.stack);
        out
    }
}

/// The window a syscall sees (§7): memory, meter, log — never registers or
/// control flow. `pc` is carried so a syscall-raised fault pins to the `call`
/// instruction that invoked it.
pub struct VmCtx<'a, 'b> {
    mem: &'b mut MemoryMap<'a>,
    meter: &'b mut Meter,
    log: &'b mut Vec<Vec<u8>>,
    log_total: &'b mut u64,
    pc: u64,
}

impl VmCtx<'_, '_> {
    pub fn charge(&mut self, cost: u64) -> Result<(), Fault> {
        let pc = self.pc;
        self.meter.charge(cost).map_err(|k| Fault { kind: k, pc })
    }

    pub fn read_bytes(&self, va: u64, len: u64) -> Result<Vec<u8>, Fault> {
        self.mem.read_bytes(va, len).map_err(|k| Fault { kind: k, pc: self.pc })
    }

    pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) -> Result<(), Fault> {
        let pc = self.pc;
        self.mem.write_bytes(va, bytes).map_err(|k| Fault { kind: k, pc })
    }

    /// Append one log entry, enforcing the per-execution total (§12-I).
    pub fn log_append(&mut self, bytes: Vec<u8>) -> Result<(), Fault> {
        let new_total = self.log_total.saturating_add(bytes.len() as u64);
        if new_total > MAX_LOG_BYTES_TOTAL {
            return Err(self.fault(FaultKind::LogLimitExceeded));
        }
        *self.log_total = new_total;
        self.log.push(bytes);
        Ok(())
    }

    pub fn fault(&self, kind: FaultKind) -> Fault {
        Fault { kind, pc: self.pc }
    }
}

/// One saved call frame (§12-B): r6–r9, the caller's r10, the return pc.
struct Frame {
    saved: [u64; 4],
    saved_r10: u64,
    ret_pc: usize,
}

/// Execute a verified program (spec §1 API). Infallible signature: every
/// failure mode is a deterministic `Fault` inside the `Outcome`, never a
/// panic — adversarial-but-verified programs are the fuzz target for exactly
/// this property (§10).
pub fn execute(
    p: &VerifiedProgram,
    input: &[u8],
    budget: u64,
    syscalls: &SyscallRegistry,
) -> Outcome {
    let mut mem = MemoryMap::new(&p.ro_image, input);
    let mut meter = Meter::new(budget);
    let mut log: Vec<Vec<u8>> = Vec::new();
    let mut log_total: u64 = 0;

    let result = run(p, &mut mem, &mut meter, &mut log, &mut log_total, syscalls);

    match result {
        Ok(r0) => Outcome {
            result: Ok(r0),
            cu_used: meter.used(),
            log,
            heap: mem.heap,
            stack: mem.stack,
        },
        // §3: faults are total. Memory effects are DISCARDED (empty heap and
        // stack in the canonical outcome, §12-D); the log survives — it is
        // observability, not a memory effect, and its CU were already paid.
        Err(fault) => Outcome {
            result: Err(fault),
            cu_used: meter.used(),
            log,
            heap: Vec::new(),
            stack: Vec::new(),
        },
    }
}

fn run(
    p: &VerifiedProgram,
    mem: &mut MemoryMap<'_>,
    meter: &mut Meter,
    log: &mut Vec<Vec<u8>>,
    log_total: &mut u64,
    syscalls: &SyscallRegistry,
) -> Result<u64, Fault> {
    let n = p.insns.len();
    let mut regs = [0u64; 11];
    // §3 / §12-G: everything zero except r1 (INPUT base) and r10 (top of
    // frame 1). The input length is deliberately NOT passed in a register.
    regs[1] = INPUT_BASE;
    regs[10] = STACK_BASE + STACK_FRAME_SIZE;

    let mut pc = p.entry_pc;
    let mut frames: Vec<Frame> = Vec::new(); // depth = frames.len() + 1

    loop {
        // §3: running off the end of the text section (no exit) is a fault.
        // Reported at pc == n, the first slot that does not exist.
        if pc >= n {
            return Err(Fault { kind: FaultKind::TextOverrun, pc: pc as u64 });
        }
        // §6 charge-then-execute: the full instruction cost lands BEFORE any
        // effect. On exhaustion the faulting pc is this instruction's — the
        // same on every node (M1 pins it).
        meter
            .charge(SBPF_COST_INSN)
            .map_err(|k| Fault { kind: k, pc: pc as u64 })?;

        let insn = p.insns[pc];
        let kind = match p.kinds[pc] {
            Some(k) => k,
            // Unreachable: the verifier guarantees control never lands on an
            // lddw second slot (entry, jumps, calls, and the 2-slot advance
            // below all exclude it). Fail CLOSED, never panic (§10).
            None => return Err(Fault { kind: FaultKind::TextOverrun, pc: pc as u64 }),
        };
        let dst = insn.dst as usize;
        let src = insn.src as usize;
        let fault = |k: FaultKind| Fault { kind: k, pc: pc as u64 };

        match kind {
            InsnKind::Alu { op, wide, reg_src } => {
                // Imm operands sign-extend to i64 (classic eBPF); the 32-bit
                // path then truncates to the low 32 bits, which is the same
                // as `imm as u32`.
                let rhs = if reg_src { regs[src] } else { insn.imm as i64 as u64 };
                let lhs = regs[dst];
                let v = if wide {
                    alu64(op, lhs, rhs).map_err(fault)?
                } else {
                    alu32(op, lhs as u32, rhs as u32).map_err(fault)? as u64
                };
                regs[dst] = v;
                pc += 1;
            }
            InsnKind::Endian { be, bits } => {
                // §12-E: leN = keep low N bits zero-extended (the VM is LE,
                // "to LE" is truncation); beN = byteswap the low N bits.
                let v = regs[dst];
                regs[dst] = match (be, bits) {
                    (false, 16) => v as u16 as u64,
                    (false, 32) => v as u32 as u64,
                    (false, _) => v,
                    (true, 16) => (v as u16).swap_bytes() as u64,
                    (true, 32) => (v as u32).swap_bytes() as u64,
                    (true, _) => v.swap_bytes(),
                };
                pc += 1;
            }
            InsnKind::Lddw => {
                // Verifier guarantees pc+1 < n and a well-formed second slot.
                // imm64 = low 32 from slot 1, high 32 from slot 2 (§12-A).
                // One instruction, 1 CU (§12-H) — charged once, above.
                let lo = p.insns[pc].imm as u32 as u64;
                let hi = p.insns[pc + 1].imm as u32 as u64;
                regs[dst] = lo | (hi << 32);
                pc += 2;
            }
            InsnKind::LoadReg { size } => {
                // addr = src + off. wrapping_add is safe: mem.rs translate()
                // range-checks the RESULT; a wrapped address simply matches
                // no region and faults (§5 — no wrap-around trick can pass).
                let addr = regs[src].wrapping_add(insn.off as i64 as u64);
                regs[dst] = mem.load(addr, size).map_err(fault)?;
                pc += 1;
            }
            InsnKind::StoreImm { size } => {
                let addr = regs[dst].wrapping_add(insn.off as i64 as u64);
                mem.store(addr, size, insn.imm as i64 as u64).map_err(fault)?;
                pc += 1;
            }
            InsnKind::StoreReg { size } => {
                let addr = regs[dst].wrapping_add(insn.off as i64 as u64);
                mem.store(addr, size, regs[src]).map_err(fault)?;
                pc += 1;
            }
            InsnKind::JumpAlways => {
                // Verifier bounded the target (§4 check 5); i64 math matches
                // its computation bit-for-bit.
                pc = (pc as i64 + 1 + insn.off as i64) as usize;
            }
            InsnKind::JumpCond { op, wide, reg_src } => {
                let rhs = if reg_src { regs[src] } else { insn.imm as i64 as u64 };
                let lhs = regs[dst];
                let taken = if wide {
                    jump_taken64(op, lhs, rhs)
                } else {
                    jump_taken32(op, lhs as u32, rhs as u32)
                };
                pc = if taken { (pc as i64 + 1 + insn.off as i64) as usize } else { pc + 1 };
            }
            InsnKind::Call => {
                let id = insn.imm as u32;
                match insn.src {
                    0 => {
                        // Syscall (§7): args in r1–r5, result to r0. A
                        // registry gap is the deterministic runtime fault of
                        // §12-C, not a panic.
                        let sc = syscalls
                            .get(id)
                            .ok_or_else(|| fault(FaultKind::UnknownSyscall { id }))?;
                        let args = [regs[1], regs[2], regs[3], regs[4], regs[5]];
                        let mut ctx = VmCtx {
                            mem,
                            meter,
                            log,
                            log_total,
                            pc: pc as u64,
                        };
                        regs[0] = sc.call(&mut ctx, args)?;
                        pc += 1;
                    }
                    1 => {
                        // Internal call (§12-B). Current depth is
                        // frames.len() + 1; entering frame 65 faults (§3).
                        if frames.len() as u64 + 2 > MAX_CALL_DEPTH {
                            return Err(fault(FaultKind::CallDepthExceeded));
                        }
                        let target = match p.funcs.get(&id) {
                            Some(&t) => t,
                            // Unreachable (verifier resolved it, §4 check 6);
                            // fail closed, never panic.
                            None => return Err(fault(FaultKind::UnknownSyscall { id })),
                        };
                        frames.push(Frame {
                            saved: [regs[6], regs[7], regs[8], regs[9]],
                            saved_r10: regs[10],
                            ret_pc: pc + 1,
                        });
                        let depth = frames.len() as u64 + 1;
                        regs[10] = STACK_BASE + depth * STACK_FRAME_SIZE;
                        pc = target;
                    }
                    // Unreachable: verifier pinned src ∈ {0, 1} (§12-B).
                    _ => return Err(fault(FaultKind::UnknownSyscall { id })),
                }
            }
            InsnKind::Exit => match frames.pop() {
                // §12-B: exit at depth 1 terminates with r0.
                None => return Ok(regs[0]),
                Some(f) => {
                    let [r6, r7, r8, r9] = f.saved;
                    regs[6] = r6;
                    regs[7] = r7;
                    regs[8] = r8;
                    regs[9] = r9;
                    regs[10] = f.saved_r10;
                    pc = f.ret_pc;
                }
            },
        }
    }
}

/// 64-bit ALU (§3): wrapping is THE semantics (not an overflow accident);
/// div/mod-by-zero and sdiv overflow fault; shifts mask & 63.
///
/// MUTATION-PROOF NOTE (two survivors of the §10 matrix): deleting `& 63`
/// here (and `& 31` in [`alu32`]) breaks NO test, because Rust's
/// `wrapping_shl`/`wrapping_shr` already mask the shift amount by `bits - 1`.
/// The masks are therefore redundant *in this implementation* and are kept
/// deliberately anyway: they are the ISA rule stated in the code rather than
/// inherited from one host language's method contract, and they are exactly
/// what a future JIT (or a C port) must reproduce — an emitted `shl` with an
/// unmasked amount is machine-dependent. The SEMANTICS remain pinned by the
/// A1 KATs (`a1_shift_by_64_masks_to_zero`, `a1_shift_by_65_masks_to_one`,
/// `a1_shift32_masks_at_31`), which is what such a port would be diffed
/// against; do not "simplify" the masks away on the strength of this note.
fn alu64(op: AluOp, lhs: u64, rhs: u64) -> Result<u64, FaultKind> {
    Ok(match op {
        AluOp::Add => lhs.wrapping_add(rhs),
        AluOp::Sub => lhs.wrapping_sub(rhs),
        AluOp::Mul => lhs.wrapping_mul(rhs),
        AluOp::Div => {
            if rhs == 0 {
                return Err(FaultKind::DivByZero);
            }
            lhs / rhs
        }
        AluOp::SDiv => {
            let (l, r) = (lhs as i64, rhs as i64);
            if r == 0 {
                return Err(FaultKind::DivByZero);
            }
            if l == i64::MIN && r == -1 {
                return Err(FaultKind::SdivOverflow);
            }
            (l / r) as u64
        }
        AluOp::Mod => {
            if rhs == 0 {
                return Err(FaultKind::DivByZero);
            }
            lhs % rhs
        }
        AluOp::SMod => {
            let (l, r) = (lhs as i64, rhs as i64);
            if r == 0 {
                return Err(FaultKind::DivByZero);
            }
            // i64::MIN % -1 is mathematically 0; Rust's `%` would overflow-
            // panic, so wrapping_rem pins the RFC 9669 answer (0) explicitly.
            l.wrapping_rem(r) as u64
        }
        AluOp::And => lhs & rhs,
        AluOp::Or => lhs | rhs,
        AluOp::Xor => lhs ^ rhs,
        AluOp::Lsh => lhs.wrapping_shl(rhs as u32 & 63),
        AluOp::Rsh => lhs.wrapping_shr(rhs as u32 & 63),
        AluOp::Arsh => ((lhs as i64).wrapping_shr(rhs as u32 & 63)) as u64,
        AluOp::Neg => lhs.wrapping_neg(),
        AluOp::Mov => rhs,
    })
}

/// 32-bit ALU (§3): operate on the low 32 bits; the caller zero-extends the
/// returned u32 — THE ALU32 rule, pinned by KAT A1.
fn alu32(op: AluOp, lhs: u32, rhs: u32) -> Result<u32, FaultKind> {
    Ok(match op {
        AluOp::Add => lhs.wrapping_add(rhs),
        AluOp::Sub => lhs.wrapping_sub(rhs),
        AluOp::Mul => lhs.wrapping_mul(rhs),
        AluOp::Div => {
            if rhs == 0 {
                return Err(FaultKind::DivByZero);
            }
            lhs / rhs
        }
        AluOp::SDiv => {
            let (l, r) = (lhs as i32, rhs as i32);
            if r == 0 {
                return Err(FaultKind::DivByZero);
            }
            if l == i32::MIN && r == -1 {
                return Err(FaultKind::SdivOverflow);
            }
            (l / r) as u32
        }
        AluOp::Mod => {
            if rhs == 0 {
                return Err(FaultKind::DivByZero);
            }
            lhs % rhs
        }
        AluOp::SMod => {
            let (l, r) = (lhs as i32, rhs as i32);
            if r == 0 {
                return Err(FaultKind::DivByZero);
            }
            l.wrapping_rem(r) as u32
        }
        AluOp::And => lhs & rhs,
        AluOp::Or => lhs | rhs,
        AluOp::Xor => lhs ^ rhs,
        AluOp::Lsh => lhs.wrapping_shl(rhs & 31),
        AluOp::Rsh => lhs.wrapping_shr(rhs & 31),
        AluOp::Arsh => ((lhs as i32).wrapping_shr(rhs & 31)) as u32,
        AluOp::Neg => lhs.wrapping_neg(),
        AluOp::Mov => rhs,
    })
}

fn jump_taken64(op: JmpOp, lhs: u64, rhs: u64) -> bool {
    let (sl, sr) = (lhs as i64, rhs as i64);
    match op {
        JmpOp::Jeq => lhs == rhs,
        JmpOp::Jne => lhs != rhs,
        JmpOp::Jgt => lhs > rhs,
        JmpOp::Jge => lhs >= rhs,
        JmpOp::Jlt => lhs < rhs,
        JmpOp::Jle => lhs <= rhs,
        JmpOp::Jsgt => sl > sr,
        JmpOp::Jsge => sl >= sr,
        JmpOp::Jslt => sl < sr,
        JmpOp::Jsle => sl <= sr,
        JmpOp::Jset => lhs & rhs != 0,
    }
}

fn jump_taken32(op: JmpOp, lhs: u32, rhs: u32) -> bool {
    let (sl, sr) = (lhs as i32, rhs as i32);
    match op {
        JmpOp::Jeq => lhs == rhs,
        JmpOp::Jne => lhs != rhs,
        JmpOp::Jgt => lhs > rhs,
        JmpOp::Jge => lhs >= rhs,
        JmpOp::Jlt => lhs < rhs,
        JmpOp::Jle => lhs <= rhs,
        JmpOp::Jsgt => sl > sr,
        JmpOp::Jsge => sl >= sr,
        JmpOp::Jslt => sl < sr,
        JmpOp::Jsle => sl <= sr,
        JmpOp::Jset => lhs & rhs != 0,
    }
}
