<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch VM host services — the common execution-host interface (and the state API it deliberately refuses)

```
Document:   BLOCH-VM-HOST
Status:     SPEC — approved scope for the host-interface front; no code exists yet
Created:    2026-08-22
Owner:      Host-interface front lead
Decision:   NONE at consensus level. This is a standalone library crate,
            NOT consensus-wired, same posture as bloch-euvm and the two
            SVM specs. It must never become a dependency of
            bloch-pos-node or bloch-pos-committee (§8 enforces this
            mechanically). Wiring any VM into L1 stays gated on ADR-040
            and the SR-2 single-re-freeze rule in
            BLOCH-L1-EXECUTION-PLAN.md — escalated, not worked around.
Relates:    crates/bloch-euvm (the only VM with code today),
            docs/specs/BLOCH-SBPF-CORE.md          (SVM Front 1 — zero code),
            docs/specs/BLOCH-SVM-ACCOUNTS-SCHEDULER.md (SVM Front 2 — zero code),
            docs/adr/ADR-040-evm-and-ustav-at-l1.md,
            docs/specs/BLOCH-L1-EXECUTION-PLAN.md
```

## 0. Honest scope, stated before anything else

**What this is.** One small pure-Rust crate, `crates/bloch-vm-host`, holding
the execution-host services the eUTXO VM and the SVM plane genuinely share:
deterministic **metering**, deterministic **crypto services**, typed
**fault signaling**, and a bounded **outcome envelope** — plus, as a written
contract (not code), the *staging discipline* both VMs already practice.

**What this is NOT:**

- It is **not a unified state API**. §2 is the load-bearing finding of this
  spec: both VMs independently converged on "no runtime state callback",
  and a shared `read_state`/`write_state` surface would be an invention
  neither wants — it would dismantle the SVM's capability security model
  and add attack surface the eUTXO VM does not have today. Refusing that
  abstraction IS the deliverable, per the front's own brief ("if the two
  don't share enough, say so"). They share enough for §3–§6; they do not
  share a state model, and this spec does not pretend otherwise.
- It is **not consensus-reachable**. Nothing here may be imported by
  bloch-pos-node or bloch-pos-committee; nothing here names a state root,
  a PoS height/epoch/slot, a validator, a roster, or block validity. A
  live 64-validator chain runs from this repository; the guard in §8 is a
  test, not a comment.
- It is **not a migration of bloch-euvm**. euvm's public API (`run`,
  `SigVerifier`, `&mut u64` gas, lib.rs:297/98) does not change in v0.
  Adapters implement the new traits *beside* the existing surface (§7);
  gas numbers, error semantics and the 331-test suite stay byte-for-byte.

**Precedent.** House idiom is bloch-euvm's: `#![forbid(unsafe_code)]`,
checked arithmetic, no I/O/clock/threads/network, `BTreeMap` where order
matters, adversarial `audit_*.rs` suites with negative/control pairs,
mutation-proven tests. Where this spec is silent, do what bloch-euvm does.

---

## 1. What each VM actually needs from its environment (measured)

**bloch-euvm** (code, 12,574 lines, 331 tests — the ground truth):

| need            | how it is met today                                             |
|-----------------|-----------------------------------------------------------------|
| read state      | frozen **snapshot**: seed stack `[datum]++redeemer` + `Ctx` (lib.rs:88) built by the caller before `run` |
| write state     | **never**. The VM is a validator: the *transaction* carries the new outputs; `validate_tx` checks conservation (lib.rs:704) |
| measure cost    | `&mut u64` budget, `op_gas` charged before each op (lib.rs:297, F2 byte-proportional) |
| crypto          | host `SigVerifier` (PQ hybrid + secp256k1, lib.rs:98); hashing in-VM (`Sha256d`/`Shake256` ops) |
| signal failure  | `VmError` / `TxError`, typed, fail-closed                        |
| environment     | none — no height, no clock (activation gating lives in the *harness*, harness.rs:56, outside the VM) |

**bloch-svm** (specs only — BLOCH-SBPF-CORE §7, BLOCH-SVM-ACCOUNTS-SCHEDULER §6):

| need            | how the specs demand it be met                                   |
|-----------------|------------------------------------------------------------------|
| read state      | **copies** of exactly the declared accounts in `TxContext`; readonly handles are type-level `View`s (§6.1) |
| write state     | mutators on writable `AccountHandle`s only; commit merges **only** the declared-writable list (§6.4) |
| measure cost    | `ComputeMeter`, charge-then-do, typed exhaustion at a reproducible reading (§6.3) |
| crypto          | `sha3_256` syscall, host-implemented at syscall cost (SBPF §7)   |
| signal failure  | `Fault` / `ProgramError`, transaction-level abort, never block-level (§6.4) |
| environment     | `ExecEnv` slot/epoch **read from the parent's committed state by the SVM's own runtime** — never wall time (§6.1) |
| log             | `log(ptr,len)` syscall, 1 KiB/call, 32 KiB/execution, part of the canonical outcome (SBPF §7) |

Two rows differ irreconcilably (state read, state write). Every other row
is the same need wearing different names. That split draws the interface.

## 2. The finding that decides the design: both VMs refuse a state callback

The naive "one host interface" is `trait Host { fn read(key) -> bytes;
fn write(key, bytes); fn charge(gas); }`. Neither VM can accept it:

- **euvm** has no code path that could call it. State arrives frozen
  before `run` and leaves as transaction outputs the VM merely *judges*.
  Adding a read/write callback would turn a validator into an executor —
  a different machine with a different threat model.
- **SVM** *forbids* it, in bold, as the entire security model of its
  parallel plane: "There is no API — none — through which a program names
  an address and receives an account. Undeclared state is not 'forbidden',
  it is *unrepresentable*" (ACCOUNTS-SCHEDULER §6.1). The scheduler's
  equivalence theorem takes declared-access as a premise; a generic state
  callback is precisely the hole that premise cannot survive.

So the two VMs do share a state *discipline* — call it **stage / execute /
commit**: the host materializes a bounded, deterministic view before
execution; the VM runs pure over that view plus §3's services; the host
alone merges declared effects afterward, with verification (conservation
lib.rs:704 / §6.4 layer 2) at the merge, outside the VM. What they do not
share is a state *API*, because the views have different shapes (a stack
seed + `Ctx` vs. an account slice) and MUST keep them. The shared crate
therefore encodes the discipline as the `Engine` lifecycle envelope (§6)
with **VM-owned associated types** for view and effects, and refuses to
name keys, accounts, datums, or bytes-at-an-address in any shared trait.

## 3. `Meter` — the one metering contract

```rust
/// Deterministic execution budget. Charge-then-do (ACCOUNTS-SCHEDULER
/// §6.3; identical to euvm's order at lib.rs:297): the charge happens
/// BEFORE the work, so exhaustion cannot depend on how far a partial
/// "do" got. Overflow anywhere = Exhausted, never wrap.
pub trait Meter {
    /// Charge `cost` units. Err(Exhausted) iff the remaining budget is
    /// insufficient; the budget is then pinned to zero (fail-closed —
    /// a later cheaper charge must not succeed after exhaustion).
    fn charge(&mut self, cost: u64) -> Result<(), Exhausted>;
    /// Units spent so far. Deterministic; part of the Outcome (§6).
    fn spent(&self) -> u64;
    /// Units remaining.
    fn remaining(&self) -> u64;
}

/// Zero-sized proof of exhaustion; the reproducible reading lives in
/// `Meter::spent`, which the Outcome records.
pub struct Exhausted;
```

The crate ships one implementation, `BudgetMeter { budget, spent }`, built
from a `u64` cap. **Units are VM-defined** (euvm "gas", SVM "CU") and are
never converted by this crate: a shared unit would be a lie about two cost
models calibrated against different work (F2 byte-proportional stack ops
vs. per-dispatch/per-syscall CU). What is shared is the *algebra*:
monotone spend, charge-then-do, fail-closed exhaustion, u64, no wrap.
Cross-VM fee pricing, if it ever exists, is a fee-market question
(BLOCH-L1-FEE-MARKET.md), not a Meter question.

## 4. `HostCrypto` — the one crypto surface

```rust
/// Deterministic crypto services a VM may consume. Pure over its inputs:
/// same bytes in, same bytes out, on every architecture, forever. The VM
/// charges its own meter BEFORE calling (each VM prices these in its own
/// units — euvm: gas_cost lib.rs:208; sbpf: the §6 CU table).
pub trait HostCrypto {
    /// SHA3-256 (the Genesis-4 chain hash; SBPF-CORE §7 syscall 3).
    fn sha3_256(&self, data: &[u8]) -> [u8; 32];
    /// SHAKE-256, 32-byte read (euvm Op::Shake256 and state.rs shake32).
    fn shake256_32(&self, data: &[u8]) -> [u8; 32];
    /// SHA-256d (euvm Op::Sha256d; the PoW-era hash kept for scripts).
    fn sha256d(&self, data: &[u8]) -> [u8; 32];
    /// Hybrid PQ verify (ML-DSA-65 ‖ Falcon-1024) — euvm SigVerifier
    /// (lib.rs:98) semantics verbatim. MUST be deterministic.
    fn verify_pq(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool;
    /// secp256k1 ECDSA verify — SigVerifier::verify_ecdsa semantics
    /// verbatim, INCLUDING the default-false posture for hosts that
    /// only do PQ (lib.rs:104).
    fn verify_ecdsa(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        false
    }
}
```

Rules: a failed signature verification **returns `false`, it is not a
Fault** — euvm pushes `Int(0)` (lib.rs `VerifySig`) and programs branch on
it; the SVM keeps the same freedom. Hashes are total functions and have no
failure mode. The crate ships `RustCryptoHost` (sha3/sha2 crates) for the
three hashes with KATs pinned in-tree, and leaves both verifies to the
integrator (the crate takes no dependency on pqcrypto — signatures stay
host-provided exactly as euvm decided, for the same purity reason).
euvm's in-VM hashing does NOT migrate to this trait in v0 (§7): the trait
exists so the *SVM syscalls* and any future euvm refactor hash through one
audited implementation with one shared KAT suite.

## 5. `Fault<E>` — the shared failure taxonomy, lossless

```rust
/// Why an execution stopped without a verdict. Generic over the VM's own
/// error type so nothing is flattened away: the shared variants exist so
/// tooling (explorers, harnesses, differential testers) can classify
/// faults across VMs without knowing either error enum.
#[non_exhaustive]
pub enum Fault<E> {
    /// The meter ran out. `spent` in Outcome carries the reading.
    Exhausted,
    /// A structural bound was exceeded (stack depth, operand bytes,
    /// program size, account-data cap, log cap...). Fail-closed twin of
    /// euvm's MemoryLimitExceeded/OperandTooLarge/ProgramTooLarge and
    /// the SVM's §3.2/SBPF caps.
    Bounds,
    /// Checked arithmetic overflowed (euvm VmError::Overflow; SVM meter
    /// overflow per §6.3 "abort, never wrap").
    Overflow,
    /// The program itself signaled failure (euvm Verify/Assert;
    /// sbpf abort() syscall, SBPF-CORE §7 syscall 1).
    Aborted,
    /// Anything the shared vocabulary does not cover — the VM's native
    /// error, intact. Type errors, bad ctx fields, owner-rule
    /// violations, verifier rejections: each VM keeps its own words.
    Vm(E),
}
```

Mapping rule, test-enforced (§9): a VM maps to a shared variant **iff**
that variant's meaning applies exactly; everything else goes through
`Vm(E)` untouched. The taxonomy is for classification, not for masking —
`Vm(E)` is not a junk drawer for faults that DO have a shared meaning,
and the mapping table for euvm (`VmError`→`Fault<VmError>`) is written
once in the adapter (§7) and pinned by tests.

## 6. `Engine` and `Outcome` — the lifecycle envelope (the stage/execute/commit discipline as a type)

```rust
/// One bounded, canonical execution result. Everything a caller may
/// learn from a run is here — nothing escapes by side channel.
pub struct Outcome<T, E> {
    /// Meter units consumed (VM-defined units, §3). Deterministic.
    pub spent: u64,
    /// The verdict or the fault. `T` is the VM's effects/verdict type:
    /// euvm: bool (validator verdict) or the per-tx gas summary;
    /// SVM: the declared-writable post-images the host may commit.
    pub result: Result<T, Fault<E>>,
    /// Bounded log, canonical part of the outcome (SBPF-CORE §7:
    /// 1 KiB/entry, 32 KiB total — enforced by LogSink, not honor).
    pub log: Vec<Vec<u8>>,
}

/// A VM as its host sees it: pure over (view, services). The HOST built
/// `View` before the call (bounded copies — euvm's Ctx+seed, the SVM's
/// TxContext) and the HOST alone applies `Effects` after it, running its
/// own commit-time verification (conservation, readonly integrity).
/// The engine touches nothing else: no state root, no PoS height/epoch/
/// slot, no validator identity, no clock, no randomness, no I/O. Any
/// environment a VM needs (the SVM's ExecEnv slot/epoch, §6.1) is DATA
/// its own runtime placed inside `View` — it is not a service this
/// interface provides, and this crate never learns what it means.
pub trait Engine {
    type View;
    type Effects;
    type Error;
    fn execute(
        &self,
        view: &Self::View,
        meter: &mut dyn Meter,
        crypto: &dyn HostCrypto,
        log: &mut dyn LogSink,
    ) -> Outcome<Self::Effects, Self::Error>;
}

/// Bounded log sink. `push` returns Err(Bounds-like) when a cap is hit;
/// caps are constructor parameters (the SVM passes 1 KiB/32 KiB; euvm
/// constructs a zero-cap sink and never calls push — an interface a VM
/// legitimately ignores is not an interface that privileges the other).
pub trait LogSink { /* push(&mut self, entry: &[u8]) -> Result<(), LogFull> */ }
```

This is the whole shared surface. Note what the associated types buy:
the interface is identical for both VMs *without* claiming their views or
effects have anything in common — the discipline is shared, the shapes
are not (§2). If a future front finds itself widening `Engine` with
state-shaped methods, that is scope drift; stop and escalate.

## 7. Adapters — how bloch-euvm meets the traits without changing

New module `crates/bloch-euvm/src/hostiface.rs` (euvm side, not the
shared crate), containing only:

- `impl SigVerifier for &dyn HostCrypto`-style bridge (or a `CryptoAsVerifier`
  wrapper) so a `HostCrypto` can stand where euvm wants a `SigVerifier`.
- A `Meter`-backed gas bridge: `run` keeps taking `&mut u64`; the adapter
  offers `run_metered(..., &mut dyn Meter)` that delegates to `run` with
  a local budget and reconciles `spent` — euvm's charging sites are not
  rewritten.
- The `VmError → Fault<VmError>` mapping table of §5, with tests.

Constraint, absolute: **no gas constant, no error semantics, no public
signature of bloch-euvm changes in v0.** The 331 existing tests must pass
unmodified, and the adapter's own tests must die under mutation (§9).
The SVM crates (`bloch-sbpf`, `bloch-svm`), having zero code, consume the
traits from birth: sbpf's `Syscall` registry takes `&dyn HostCrypto` for
syscall 3 and a `LogSink` for syscall 2; the SVM `ComputeMeter` implements
`Meter`; `ProgramExecutor` (§6.1) is reshaped as an `Engine` impl whose
`View` is the `TxContext` and whose `Effects` are the declared-writable
post-images. Where the SVM specs and this spec conflict in letter, the
SVM specs' *security clauses* win and this spec is amended — §6.1's
unrepresentability rule outranks interface tidiness.

## 8. The consensus firewall, enforced mechanically

`crates/bloch-vm-host` is a workspace member and a dependency of at most
`bloch-euvm`, `bloch-sbpf`, `bloch-svm`. A test (in the shared crate's
`tests/`, running `cargo metadata` over the workspace) asserts that
neither `bloch-pos-node` nor `bloch-pos-committee` reaches `bloch-vm-host`
(nor, transitively, any VM crate) in its dependency graph, and fails with
a message citing this spec and SR-2. That turns "must never be reachable
from the state-transition path" from a review item into a red build.
`#![forbid(unsafe_code)]`; dependencies: `sha3`, `sha2`, dev-deps only.

## 9. Test obligations (the crate does not merge without them)

1. **KATs** for the three hashes, including cross-checks against euvm's
   in-VM results (`Op::Shake256` output == `shake256_32` for the same
   bytes) so the two hashing sites can never drift apart silently.
2. **Meter algebra**: charge-then-do ordering, exact exhaustion reading,
   pinned-to-zero after exhaustion, u64 edge charges — each with its
   control half, each proven by mutation (e.g. swapping charge/do order,
   or `>=`→`>` at the exhaustion check, must redden a test).
3. **Fault mapping**: every euvm `VmError` variant appears in exactly one
   mapping test; the control half proves the unshared ones stay `Vm(E)`.
4. **LogSink caps**: per-entry and total caps, negative + control.
5. **Dependency firewall** (§8) — and its own mutation check: adding the
   dep to a scratch manifest in the test must make the assertion fire.

## 10. Declared missing — the boundary of the claim

No unified state API (refused, §2 — that is a finding, not a gap). No
shared cost *schedule* or unit conversion (§3). No syscall numbering, no
ABI, no account or datum encoding — those belong to the VM specs. No
async, no snapshot/rollback protocol (each VM's host owns its commit).
Nothing here has been reviewed by the SVM fronts; SBPF-CORE §7's
`Syscall` signature and ACCOUNTS-SCHEDULER §6.1's `ProgramExecutor` were
written before this spec and must be reconciled by their owners (§7
states the precedence). Designed ≠ implemented ≠ audited.
