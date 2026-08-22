<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch sBPF Execution Core — Front 1 specification (interpreter + verifier)

```
Document:   BLOCH-SBPF-CORE
Status:     SPEC — approved scope for Front 1; no code exists yet
Created:    2026-08-21
Owner:      Front 1 lead
Decision:   NONE at consensus level. This crate is a standalone foundation,
            deliberately NOT consensus-wired (same posture bloch-euvm holds).
            Consensus wiring would collide with ADR-040 (EVM at L1) and with
            the SR-2 single-re-freeze rule in BLOCH-L1-EXECUTION-PLAN.md —
            that collision is escalated, not worked around (see §0).
Relates:    crates/bloch-euvm (the house determinism idiom this spec copies),
            docs/adr/ADR-040-evm-and-ustav-at-l1.md,
            docs/specs/BLOCH-L1-EXECUTION-PLAN.md,
            crates/bloch-pos-committee/src/params.rs (flag-day idiom)
```

## 0. Honest scope, stated before anything else

**What this is.** A deterministic interpreter and load-time verifier for a
declared subset of the sBPF/eBPF instruction set, as a pure Rust library
crate (`crates/bloch-sbpf`), plus a minimal deterministic program container.
It is the smallest thing that is *actually true*: SBF-ISA bytecode, verified,
metered, sandboxed, bit-reproducible across machines.

**What this is NOT, and must never claim to be until §9's gate is passed:**

- It is **not "Solana compatible"**. Solana's runtime is a bytecode
  verifier + JIT + ~100 syscalls + native loaders + a calibrated compute
  model + the Sealevel parallel scheduler, hardened over years. None of
  that exists here. An arbitrary `.so` built by `cargo build-sbf` will NOT
  load in v0 (no ELF loader, no dynamic relocations, no syscall surface).
  Any compatibility sentence, anywhere, is forbidden until one named,
  real, SBF-compiled program demonstrably runs — and then the claim is
  exactly that program under exactly the documented limits (§9).
- It is **not a consensus change**. Genesis-4's transaction set stays
  closed (Transfer/Deposit/Exit/Delegate/SlashingEvidence); `script_hash`
  stays SHA3-256(pubkey). Wiring any VM into L1 requires a flag-day
  (`LEAKED_ROSTER_ACTIVATION_EPOCH` idiom, params.rs:106) AND a
  `StateRoots` component addition, and SR-2 says that list is re-frozen
  exactly once (milestone X1). A third engine beside bloch-euvm and the
  ADR-040 EVM cannot silently join that re-freeze. **Founder decision
  required before any consensus milestone is even planned.**
- It is **not a JIT** and has no parallel scheduler. Interpreter only.
  A JIT is a determinism and security liability we are not buying now;
  the interpreter IS the consensus-candidate semantics, and any future
  JIT must be bit-equivalent to it, proven by differential testing.

**Precedent this spec leans on.** `crates/bloch-euvm` already established
the house idiom for a consensus-candidate VM: `#![forbid(unsafe_code)]`,
checked arithmetic, no I/O/clock, gas charged per op from a caller budget,
host-callback for crypto, `BTreeMap` for canonical ordering, and
adversarial test suites (`audit_*.rs`) with negative/control pairs. This
crate copies that idiom; where this spec is silent, do what bloch-euvm does.

---

## 1. Crate shape

```
crates/bloch-sbpf/
  src/isa.rs        # instruction encoding/decoding, opcode whitelist
  src/verify.rs     # load-time verifier (§4)
  src/mem.rs        # memory map + checked access (§5)
  src/meter.rs      # compute meter + cost table (§6)
  src/interp.rs     # the interpreter loop (§3)
  src/container.rs  # BSC-0 program container (§8)
  src/syscall.rs    # Syscall trait + the v0 registry (§7)
  src/lib.rs        # public API: load() -> Verified, execute() -> Outcome
  tests/            # negative/control pairs, KATs, determinism (§10)
```

Rules: `#![forbid(unsafe_code)]`. No dependencies beyond `sha3` (for the
one v0 hash syscall) and dev-deps. Pure: no clock, no I/O, no threads, no
network — in code or in tests. `[workspace]` posture identical to
bloch-euvm: workspace member, NOT a dependency of the node binary.

Public API is two calls, deliberately:

```rust
/// Verify once at load; execution requires a Verified token — there is no
/// path to run unverified bytecode, by construction.
pub fn load(container: &[u8]) -> Result<VerifiedProgram, VerifyError>;
pub fn execute(p: &VerifiedProgram, input: &[u8], budget: u64,
               syscalls: &SyscallRegistry) -> Outcome;
```

`Outcome` carries: `result: Result<u64, Fault>` (r0 or the fault),
`cu_used: u64`, `log: Vec<Vec<u8>>` (bounded, §7), and the RW-region bytes.
All of it canonical: two nodes MUST produce identical `Outcome` bytes.

---

## 2. (a) Instruction subset — what enters, what stays out, and why

The cut is not arbitrary: **the subset is exactly what LLVM's SBF backend
emits for `no_std`, float-free, statically-dispatched Rust/C**, minus
anything whose semantics depend on the host. That is the smallest set for
which a real compiled program can ever run (§9); anything smaller means
hand-written assembly forever, anything larger buys risk without programs
that need it.

**IN (whitelist — everything else is rejected by the verifier):**

- **ALU64 and ALU32** register/immediate forms: `add sub mul div sdiv mod
  smod and or xor mov lsh rsh arsh neg`. ALU32 is included because LLVM
  emits it constantly for `u32`/`i32` arithmetic; excluding it excludes
  compiled code. Semantics pinned in §3.
- **Byte swap**: `be16/be32/be64`, `le16/le32/le64`.
- **Jumps, 64-bit class**, reg and imm forms: `ja jeq jne jgt jge jlt jle
  jsgt jsge jslt jsle jset`. JMP32 class: IN (same justification as ALU32).
- **Memory**: `ldx{b,h,w,dw}`, `stx{b,h,w,dw}`, `st{b,h,w,dw}` (imm
  stores), and `lddw` (the 16-byte two-slot 64-bit immediate load).
- **`call imm`** — but ONLY to (i) a registered syscall id or (ii) an
  internal function whose entry the container's function table declares
  (§8). Anything else fails verification.
- **`exit`**.

**OUT (rejected at verify time; each exclusion is a determinism or
scope argument, not taste):**

- **`callx` (indirect call).** Target is a runtime value the verifier
  cannot bound; it is THE classic CFG escape. Solana itself restricts it
  in newer SBF versions. Rust `dyn`/function pointers won't compile to
  our target — a documented program-authoring limit for v0.
- **Atomics (`lock`-class).** There is no concurrency in this VM; an
  atomic op would be a lie about the memory model and a door to
  host-dependent behaviour.
- **Legacy packet ops (`BPF_ABS`/`BPF_IND`).** Linux-networking legacy;
  absent from SBF; no meaning here.
- **Linux-eBPF tail calls and map ops.** Kernel concepts; no meaning here.
- **Any unknown opcode.** The verifier is a whitelist (§4): an opcode is
  rejected because it is not listed, never accepted because it is not
  known to be bad. New opcodes enter only by amending this spec.

There are **no floating-point opcodes in the eBPF ISA at all** — see §3-FP
for how the float ban is nonetheless *enforced* rather than assumed.

---

## 3. Execution semantics — every edge pinned

Registers `r0..r9` are general 64-bit; `r10` is the frame pointer,
**read-only** (verifier-enforced, §4). All ten start at 0 except `r1`
(input-region VA) and `r10` (top of the current stack frame). Byte order
is little-endian everywhere.

Pinned edge semantics (each is a consensus rule, hence a KAT in §10):

- **ALU wrap**: add/sub/mul wrap (two's complement), exactly the eBPF
  spec. Implemented with `wrapping_*` — NOT `checked_*` + panic, because
  wrapping IS the defined semantics here, unlike euvm's Int model.
- **ALU32**: operate on the low 32 bits; result **zero-extends** to 64.
- **div/mod by zero**: a runtime **fault** (`Fault::DivByZero`),
  terminating execution deterministically. Not UB, not a wrap, not 0.
  (Rationale: Solana SBFv2 semantics; and silent-zero hides program bugs
  into state.) `sdiv` overflow (`i64::MIN / -1`) is likewise a fault.
- **Shifts**: amount is masked (`& 63` for 64-bit, `& 31` for 32-bit) —
  the ISA rule; unmasked shifts would be Rust UB-adjacent and
  machine-dependent in C implementations.
- **Memory access**: bounds- and permission-checked per §5 BEFORE any
  byte moves. Unaligned access is **permitted** (checked byte copies, no
  host alignment trap can leak through) — matching SBF, and removing a
  whole class of "works on x86, faults on ARM" divergence.
- **Running off the end of the text section** (no `exit`): a fault.
- **Call depth**: max 64 frames; frame 65 is `Fault::CallDepthExceeded`.
- **Faults are total**: any fault discards the program's memory effects;
  `Outcome` reports the fault and `cu_used` up to and including the
  faulting instruction's charge. Nothing partial escapes.

**§3-FP — floating point: PROHIBITED, and how that is actually enforced.**
Decision (e): forbidden. Enforcement is three-layered, because "the ISA
has no float opcodes" is necessary but not sufficient:

1. **Verifier whitelist** (§4): no FP opcode can exist, because only
   listed integer/branch/memory opcodes pass. This is enforcement by
   construction, not by a deny-list that could miss an encoding.
2. **No math syscalls**: the v0 registry (§7) contains no floating-point
   or transcendental function. The historically real divergence vector is
   a host `pow`/`exp` differing across libm builds — there is none.
3. **Honest note on soft-float**: a program that does its own float math
   compiles to *integer* sBPF instructions (compiler-rt soft-float) and
   is therefore deterministic — we cannot and need not detect it. What
   the ban guarantees is that no host FP hardware path and no host libm
   ever executes on behalf of a program. Documented so nobody "fixes" it.

---

## 4. (b) The verifier — load-time, whitelist, one pass

A weak verifier is a DoS/escape vector; this one is small enough to review
line-by-line, and every check below has a rejecting test with a passing
control twin (§10). Verification happens once in `load()`; `execute()`
only accepts `VerifiedProgram` — unverified execution is unrepresentable.

Checks, in order, single linear pass plus the jump-target pass:

1. **Container sanity** (§8): sections in bounds, text length a multiple
   of 8, function table entries in bounds and on instruction boundaries.
2. **Opcode whitelist**: every 8-byte slot decodes to a §2-IN opcode.
   Unknown/excluded → `VerifyError::ForbiddenOpcode(pc, opcode)`.
3. **`lddw` pairing**: a `lddw` first slot must be followed by a
   well-formed second slot (opcode 0); a second slot may not be reached
   except through its first (enforced with check 5).
4. **Register bounds**: `src`, `dst` in `0..=10`; **writes to r10
   rejected** (`mov r10, …`, `add r10, …`, loads into r10 — all of it);
   reads of r10 allowed (stack addressing needs it).
5. **Jump targets**: every branch lands inside `[0, n_insns)`, on an
   instruction boundary, and **never on the second slot of an `lddw`**.
   Fall-through off the end is allowed to pass verification (it is a
   defined runtime fault, §3) — the verifier bounds *where control can
   go*, not *whether it halts*.
6. **Calls**: `call imm` resolves to a registered syscall id or a
   function-table entry; anything else → `VerifyError::UnresolvedCall`.
   This is also where compiler-builtin relocations (e.g. soft-float
   helpers compiled as internal functions) either resolve into the table
   or fail loudly — nothing links implicitly.

**Deliberately NOT a verifier duty — written down so it is not "fixed"
later by someone weakening the runtime:** loop/termination analysis.
Static termination is the halting problem; Solana does not attempt it and
neither do we. **Termination is the meter's job (§6), and only the
meter's.** The verifier guarantees memory/CFG safety; the meter guarantees
bounded time. Both halves are required; neither substitutes for the other.

Verifier cost is O(n) in program size, and `load()` itself is bounded by
`MAX_PROGRAM_SLOTS` (v0: 65 536 slots = 512 KiB text) so a hostile
container cannot DoS the loader either.

---

## 5. (c) Memory model — fixed map, checked every access

Solana-style fixed virtual address map, one region per 4 GiB stride so a
region is recoverable from the VA's high bits:

```
0x1_0000_0000  TEXT+RO    program text and read-only data   (read-only)
0x2_0000_0000  STACK      call-frame stack                  (read/write)
0x3_0000_0000  HEAP       bump region                       (read/write)
0x4_0000_0000  INPUT      execution input, serialized       (v0: read-only)
```

- The interpreter holds each region as a plain `Vec<u8>`; a VA is
  translated by explicit range checks — **every** load/store checks
  `region_base <= va && va + len <= region_end` with `checked_add` (no
  wrap-around trick can pass) and the region's permission. Violation →
  `Fault::AccessViolation { va, len, kind }`, deterministic.
- **A single access may not straddle regions** (the check above makes
  that structurally impossible — ranges don't overlap).
- **Stack**: fixed 4 KiB frame per call, depth ≤ 64 (so ≤ 256 KiB),
  zero-initialized. `call` advances the frame window, `exit` from a
  frame returns to the caller's; r10 is set per frame by the VM. No
  variable-size frames in v0 (SBFv1-style fixed frames — simpler to
  verify, and what the backend expects by default).
- **Heap**: 32 KiB, zero-initialized, writable; v0 offers it as raw
  memory (program brings its own bump allocator, which is what SBF
  no_std programs do anyway). No grow syscall in v0.
- **Null and everything unmapped** (VA < 0x1_0000_0000, gaps, beyond
  region ends) faults. There is no page 0.
- Zero-initialization everywhere is a determinism requirement, not
  hygiene: uninitialized memory is per-machine entropy.
- The INPUT region is read-only in v0 because v0 has no account/state
  writeback contract yet; the only writable outputs of a v0 execution
  are r0, the log, and HEAP/STACK contents captured in `Outcome`. When a
  state model arrives (post-founder-decision), INPUT splits into ro/rw
  the way Solana serializes accounts — that change is a spec amendment.

---

## 6. (d) Compute budget — the consensus clock

Determinism demand: **cost is a pure function of the instruction stream
executed, never of the machine executing it.** No wall-clock, no cache
effects, no "measured" costs at runtime. Concretely:

- **Charge-then-execute**: the meter charges an instruction's full cost
  BEFORE executing it (`budget.checked_sub(cost).ok_or(Fault::
  ComputeBudgetExceeded)?`). Consequence, pinned by test: a program
  needing exactly N CU succeeds with budget N and faults with N−1, and
  the faulting PC is identical on every node. Charging after execution
  would let one extra instruction's side effects slip in at the boundary
  — that off-by-one would be a consensus rule by accident.
- **Cost table v0** (consensus constants in `meter.rs`, named
  `SBPF_COST_*`): every §2-IN instruction costs **1 CU** (the Solana
  base), EXCEPT syscalls, which carry a per-call base plus per-byte
  terms (e.g. `syscall_sha3: 85 + ceil(len/2)` CU, `syscall_log:
  100 + len` CU — bloch-euvm's F2 lesson: length-dependent work MUST
  have length-dependent cost, or one cheap op with a huge operand buys
  unbounded machine work and block time becomes machine-dependent).
- **Why per-instruction flat cost is sound here and was not in euvm**:
  sBPF instructions move at most 8 bytes (`lddw` included); there is no
  variable-length operand an instruction can smuggle. All variable-length
  work enters through syscalls, which is exactly where the per-byte
  terms sit. This is the argument that makes 1-CU-flat safe; it must be
  re-made if any variable-length instruction is ever whitelisted.
- **Exhaustion**: `Fault::ComputeBudgetExceeded`; total-fault semantics
  (§3) — effects discarded, `cu_used == budget` reported. The CALLER
  (future consensus layer) decides fees; the VM's contract is only that
  exhaustion is clean, total, and at a bit-identical point on all nodes.
- **The table is versioned**: `Outcome` and golden vectors (§10) pin
  `COST_TABLE_VERSION = 1`. Changing any cost is semantically a
  hard-fork of anything that consumes this VM under consensus, so table
  changes follow the flag-day idiom (`…_ACTIVATION_EPOCH`, params.rs) if
  and when the crate is consensus-wired — stated now so v0 tests are
  already written against pinned totals, not "roughly cheap".

---

## 7. Syscalls v0 — deliberately three

`trait Syscall { fn call(&self, vm: &mut VmCtx, args: [u64; 5]) ->
Result<u64, Fault>; }` — registered in a `SyscallRegistry` keyed by the
32-bit ids the verifier resolves against. All syscalls are pure over VM
state (no host I/O), with explicit CU charges (§6). v0 ships exactly:

1. `abort()` — deterministic `Fault::Aborted`.
2. `log(ptr, len)` — appends bytes to `Outcome.log`; `len` capped
   (1 KiB/call), total log capped (32 KiB/execution) — logs are part of
   the canonical outcome, so they are bounded like everything else.
3. `sha3_256(ptr, len, out_ptr)` — the chain's hash (SHA3, matching the
   Genesis-4 SHA3/lattice posture), host-implemented at syscall cost.

Nothing else. In particular NO sol_* surface, NO CPI, NO account APIs,
NO float/math helpers (§3-FP). Every future syscall is a spec amendment
with its own cost derivation and negative/control tests.

---

## 8. Program container — BSC-0, not ELF (yet)

Real SBF toolchains emit ELF64 `.so` with relocations; a correct,
hostile-input-safe ELF loader is a project of its own (Solana's has had
CVEs). v0 therefore defines **BSC-0** ("Bloch sBPF Container v0"), a flat
deterministic format the verifier can check in one pass:

```
magic "BSC0" | version u32 | entry_fn u32 | n_funcs u32
| func_table: n_funcs × (id u32, text_offset u32)
| text_len u32 | text bytes | rodata_len u32 | rodata bytes
```

Little-endian, no padding ambiguity, every offset verified (§4 check 1).
Hand-assembled and macro-assembled test programs target BSC-0 directly.
An `elf→BSC-0` converter for statically-linked `cargo build-sbf` output
(only `R_BPF_64_64`-class relocations, resolved at convert time, offline)
is **milestone M4** — the gate to any compatibility sentence (§9). The
converter is a build tool, never consensus code: consensus, if it ever
comes, hashes and executes BSC-0 bytes only.

---

## 9. The compatibility gate

The words "Solana", "SVM" or "compatible" may appear in outward-facing
material ONLY after all of: (1) M4 converter exists; (2) one named,
real program compiled with a pinned `cargo build-sbf`/SBF-LLVM version
runs end-to-end under this interpreter in CI; (3) the claim written is of
the form "runs program X, compiled with toolchain Y, using syscalls
{abort, log, sha3_256}, under limits {…}" — never broader. Until then the
public name of this work is "sBPF-style execution core (foundation)".

---

## 10. Test plan — negative/control pairs, KATs, no network

Repo rule: **every negative test ships with its control half** — the
minimally-different legitimate program that passes — otherwise the
negative can pass for the wrong reason (e.g. the loader rejecting the
container, not the verifier rejecting the jump). Control halves assert
success AND the expected `Outcome` (result, `cu_used`), not mere absence
of error. All tests are in-process; no network, no filesystem beyond
`include_bytes!` fixtures.

| # | Negative | Control twin |
|---|----------|--------------|
| V1 | jump target past end → `BadJumpTarget` | same program, target = next insn → runs, r0 pinned |
| V2 | jump into `lddw` second slot → `BadJumpTarget` | jump past the pair → runs |
| V3 | unknown opcode 0xFF → `ForbiddenOpcode` | same slot as `mov` → runs |
| V4 | `callx` → `ForbiddenOpcode` | `call` to table fn → runs |
| V5 | write to r10 → `FrameRegisterWrite` | write to r9 → runs |
| V6 | `call` to unregistered id → `UnresolvedCall` | registered `log` id → runs, log bytes pinned |
| R1 | store into TEXT/RO → `AccessViolation` | same store into STACK → runs, byte readable back |
| R2 | load below 0x1_0000_0000 (null) → `AccessViolation` | load from INPUT → runs |
| R3 | 8-byte load ending 1 byte past region end → `AccessViolation` | one address lower → runs (off-by-one pin) |
| R4 | div by zero → `DivByZero` fault | divisor 1 → runs |
| R5 | call depth 65 → `CallDepthExceeded` | depth 64 → runs |
| M1 | unbounded loop, budget 10 000 → `ComputeBudgetExceeded`, `cu_used == 10_000`, faulting PC pinned | counted loop finishing under budget → runs, exact `cu_used` asserted |
| M2 | budget N−1 for a program needing exactly N → exceeded | budget N → success (pins charge-then-execute) |
| D1 | — | same program+input executed twice in fresh VMs → byte-identical `Outcome` |
| D2 | — | golden vectors: SHA3-256 over canonical `Outcome` bytes for ≥5 fixture programs, pinned in-repo (drift in cost table, wrap semantics, or log encoding breaks the pin loudly) |
| A1 | ALU edge KATs: `i64::MIN / -1` faults; shift-by-64 masks to 0; ALU32 zero-extends — each with its benign control | |

Plus a `fuzz/` harness (repo already has the directory idiom): fuzz
`load()` with arbitrary bytes — the invariant is "reject or verify,
never panic, never allocate unboundedly"; and differential-fuzz
`execute()` for panic-freedom under verified-but-adversarial programs.

---

## 11. Milestones (dependency order, one owner each)

- **M0 — this spec** reviewed; disagreements amend the spec, not the code.
- **M1 — `isa.rs` + `verify.rs`**: decoder, whitelist, all V-tests.
  Blocks everything; nothing blocks it.
- **M2 — `mem.rs` + `meter.rs` + `interp.rs` + `syscall.rs`**: R/M/A/D
  tests, golden vectors. Depends on M1 only.
- **M3 — `container.rs` + fuzz harnesses + a tiny macro-assembler for
  test fixtures** (dev-dep only). Depends on M1; parallel with M2.
- **M4 — offline ELF→BSC-0 converter + one real compiled program** —
  SEPARATE approval; it is the §9 gate, not a default next step.
- **NOT scheduled here**: consensus wiring, state/account model, CPI,
  JIT, parallel execution. Each needs the founder to first reconcile
  this front with ADR-040/SR-2 (§0).
