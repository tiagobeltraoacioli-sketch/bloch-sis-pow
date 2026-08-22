//! Syscall trait + the v0 registry (spec §7) — deliberately three syscalls.
//!
//! All syscalls are pure over VM state: no host I/O, no clock, no float/math
//! helpers (§3-FP layer 2 — the historically real divergence vector is a host
//! pow/exp differing across libm builds; there is none here). Every future
//! syscall is a spec amendment with its own cost derivation and
//! negative/control tests — NOT a quick registration.

use std::collections::BTreeMap;

use sha3::{Digest, Sha3_256};

use crate::interp::{Fault, FaultKind, VmCtx};
use crate::meter::{SBPF_COST_SYSCALL_ABORT, SBPF_COST_SYSCALL_LOG_BASE, SBPF_COST_SYSCALL_SHA3_BASE};

/// Consensus-constant syscall ids (§12-C). `load()` takes no registry (§1),
/// so the verifier resolves `call src=0` against THESE, not against whatever
/// a runtime registry happens to hold.
pub const SYSCALL_ABORT: u32 = 1;
pub const SYSCALL_LOG: u32 = 2;
pub const SYSCALL_SHA3_256: u32 = 3;
/// The pinned v0 id set the verifier accepts (§4 check 6).
pub const SYSCALL_IDS: [u32; 3] = [SYSCALL_ABORT, SYSCALL_LOG, SYSCALL_SHA3_256];

/// Log bounds (§7): logs are part of the canonical outcome, so they are
/// bounded like everything else. Exceeding either cap is a FAULT, not a
/// truncation (§12-I) — silent truncation would make `Outcome` depend on cap
/// history.
pub const MAX_LOG_BYTES_PER_CALL: u64 = 1024;
pub const MAX_LOG_BYTES_TOTAL: u64 = 32 * 1024;

/// A host syscall. Implementations charge their OWN cost through
/// `vm.charge()` FIRST (charge-then-execute, §6), then touch memory/log.
pub trait Syscall {
    fn call(&self, vm: &mut VmCtx<'_, '_>, args: [u64; 5]) -> Result<u64, Fault>;
}

/// Registry keyed by the 32-bit ids above. BTreeMap — canonical order, house
/// determinism rule (no HashMap in this crate).
///
/// Note the honest asymmetry (§12-C): VERIFICATION is against the pinned id
/// constants; a registry that lacks a verified-and-called id produces the
/// deterministic runtime fault `UnknownSyscall`. Registering ids outside
/// `SYSCALL_IDS` is possible but pointless — the verifier will never let a
/// program call them.
pub struct SyscallRegistry {
    map: BTreeMap<u32, Box<dyn Syscall>>,
}

impl SyscallRegistry {
    /// Empty registry — every syscall-reaching execution faults
    /// `UnknownSyscall`. Exists for tests; real callers want [`Self::v0`].
    pub fn empty() -> Self {
        SyscallRegistry { map: BTreeMap::new() }
    }

    /// The exact v0 surface: abort, log, sha3_256. Nothing else (§7).
    pub fn v0() -> Self {
        let mut r = Self::empty();
        r.register(SYSCALL_ABORT, Box::new(SysAbort));
        r.register(SYSCALL_LOG, Box::new(SysLog));
        r.register(SYSCALL_SHA3_256, Box::new(SysSha3));
        r
    }

    pub fn register(&mut self, id: u32, imp: Box<dyn Syscall>) {
        self.map.insert(id, imp);
    }

    pub(crate) fn get(&self, id: u32) -> Option<&dyn Syscall> {
        self.map.get(&id).map(|b| b.as_ref())
    }
}

/// `abort()` — deterministic `Fault::Aborted` (§7). Charged flat (§12-C) so
/// even aborting costs something: a free abort would be a free mempool probe
/// if this VM is ever consensus-wired.
struct SysAbort;
impl Syscall for SysAbort {
    fn call(&self, vm: &mut VmCtx<'_, '_>, _args: [u64; 5]) -> Result<u64, Fault> {
        vm.charge(SBPF_COST_SYSCALL_ABORT)?;
        Err(vm.fault(FaultKind::Aborted))
    }
}

/// `log(ptr, len)` — appends to `Outcome.log`. Order pinned by §12-I:
/// charge (saturating `100 + len`) → caps → memory read → append; `cu_used`
/// therefore includes the faulting call's charge, consistent with §6.
struct SysLog;
impl Syscall for SysLog {
    fn call(&self, vm: &mut VmCtx<'_, '_>, args: [u64; 5]) -> Result<u64, Fault> {
        let (ptr, len) = (args[0], args[1]);
        // saturating: a len near u64::MAX must not wrap into a cheap charge —
        // it saturates to u64::MAX CU and exhausts any budget, determinist-
        // ically, before the cap check even runs.
        vm.charge(SBPF_COST_SYSCALL_LOG_BASE.saturating_add(len))?;
        if len > MAX_LOG_BYTES_PER_CALL {
            return Err(vm.fault(FaultKind::LogLimitExceeded));
        }
        let bytes = vm.read_bytes(ptr, len)?;
        vm.log_append(bytes)?; // enforces MAX_LOG_BYTES_TOTAL
        Ok(0)
    }
}

/// `sha3_256(ptr, len, out_ptr)` — the chain's hash (Genesis-4 SHA3/lattice
/// posture), host-implemented at syscall cost `85 + ceil(len/2)` (§6).
struct SysSha3;
impl Syscall for SysSha3 {
    fn call(&self, vm: &mut VmCtx<'_, '_>, args: [u64; 5]) -> Result<u64, Fault> {
        let (ptr, len, out_ptr) = (args[0], args[1], args[2]);
        // ceil(len/2) without overflow: len/2 + len%2.
        let per_byte = (len / 2).saturating_add(len % 2);
        vm.charge(SBPF_COST_SYSCALL_SHA3_BASE.saturating_add(per_byte))?;
        let bytes = vm.read_bytes(ptr, len)?;
        let digest = Sha3_256::digest(&bytes);
        vm.write_bytes(out_ptr, &digest)?;
        Ok(0)
    }
}
