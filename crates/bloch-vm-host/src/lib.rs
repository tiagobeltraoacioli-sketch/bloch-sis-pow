//! # bloch-vm-host — shared execution-host services for Bloch VMs
//!
//! Implements docs/specs/BLOCH-VM-HOST.md: the services the eUTXO VM
//! (crates/bloch-euvm — the only VM with code today) and the spec-only SVM
//! plane (BLOCH-SBPF-CORE.md, BLOCH-SVM-ACCOUNTS-SCHEDULER.md) genuinely
//! share — deterministic **metering** ([`Meter`]), deterministic **crypto
//! services** ([`HostCrypto`]), typed **fault signaling** ([`Fault`]), a
//! bounded **log sink** ([`LogSink`]), and the **outcome envelope**
//! ([`Outcome`], [`Engine`]) that types the stage/execute/commit discipline
//! both VMs already practice.
//!
//! What this crate deliberately is NOT (spec §0/§2 — the load-bearing
//! finding, not an omission):
//!
//! - **Not a unified state API.** There is no `read_state`/`write_state`
//!   anywhere here, and there must never be. euvm receives its state frozen
//!   before `run` (seed stack `[datum]++redeemer` + `Ctx`, bloch-euvm
//!   lib.rs:88) and writes nothing — it *judges* outputs the transaction
//!   already carries (conservation checked at lib.rs:704, outside the VM).
//!   The SVM spec *forbids* a runtime state callback as the heart of its
//!   security model (ACCOUNTS-SCHEDULER §6.1: undeclared state is
//!   unrepresentable). The shared surface therefore encodes the shared
//!   *discipline* ([`Engine`] with VM-owned `View`/`Effects` associated
//!   types) and refuses to name keys, accounts, datums, or
//!   bytes-at-an-address.
//! - **Not consensus-reachable.** Nothing here names a state root, a PoS
//!   height/epoch/slot, a validator, a roster, or block validity, and this
//!   crate must never be imported by bloch-pos-node or bloch-pos-committee
//!   (ADR-040 + SR-2, BLOCH-L1-EXECUTION-PLAN.md). A live 64-validator
//!   chain runs from this repository; tests/dependency_firewall.rs turns
//!   that sentence into a red build instead of a review item.
//! - **Not a migration of bloch-euvm.** No euvm gas constant, error
//!   semantics, or public signature changes because this crate exists;
//!   adapters live beside euvm's surface (spec §7, a separate front).
//!
//! House idiom is bloch-euvm's: `#![forbid(unsafe_code)]`, checked
//! arithmetic, no I/O / clock / threads / network / randomness, fail-closed
//! everywhere, tests with negative + control halves, proven by mutation.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
// NOTE: `Sha3_256::digest` resolves through the `sha2::Digest` import above —
// sha2 and sha3 re-export the SAME `digest::Digest` trait, so importing it
// twice is an unused-import warning, not extra safety.
use sha3::{Sha3_256, Shake256};

// ────────────────────────────────────────────────────────────────────────────
// §3 — Meter: the one metering contract
// ────────────────────────────────────────────────────────────────────────────

/// Zero-sized proof that the meter ran out. Deliberately carries NO reading:
/// the reproducible reading lives in [`Meter::spent`], which the [`Outcome`]
/// records — one authoritative place, not two that can disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exhausted;

/// Deterministic execution budget (spec §3).
///
/// The contract is **charge-then-do** — identical to euvm's charging order
/// (`*gas = gas.checked_sub(cost)` BEFORE the op executes, bloch-euvm
/// lib.rs:360) and to ACCOUNTS-SCHEDULER §6.3: the charge happens before the
/// work, so exhaustion can never depend on how far a partial "do" got.
/// Callers of a `Meter` (the VMs) own that ordering; implementations own the
/// algebra below.
///
/// **Units are VM-defined** (euvm "gas", SVM "CU") and are never converted
/// by this crate: the two cost models are calibrated against different work
/// (byte-proportional stack ops, euvm lib.rs:229 `op_gas`, vs. per-dispatch
/// CU). What is shared is the *algebra*: monotone spend, fail-closed
/// exhaustion, `u64`, no wrap.
pub trait Meter {
    /// Charge `cost` units. `Err(Exhausted)` iff the remaining budget is
    /// insufficient — and from that moment the meter is **pinned**: every
    /// later charge fails too, however cheap (a VM that ran out must not be
    /// able to "afford" anything again by asking for less; fail-closed, the
    /// same posture as euvm's `OutOfGas` aborting the whole run).
    fn charge(&mut self, cost: u64) -> Result<(), Exhausted>;
    /// Units actually spent so far. Deterministic, monotone, and — because
    /// charges are all-or-nothing — unchanged by a failed charge. This is
    /// the reproducible exhaustion reading the [`Outcome`] records.
    fn spent(&self) -> u64;
    /// Units still chargeable. Zero forever once the meter is exhausted
    /// ("pinned to zero", spec §3), even if `budget - spent` is positive.
    fn remaining(&self) -> u64;
}

/// The one shipped [`Meter`]: a `u64` cap, spent counter, and a sticky
/// exhaustion latch.
///
/// Invariant: `spent <= budget` always, so `spent + cost` cannot overflow
/// `u64` when `cost <= budget - spent` — the arithmetic below is checked
/// anyway ("overflow anywhere = Exhausted, never wrap", spec §3), matching
/// the workspace-wide `overflow-checks = true` rationale (root Cargo.toml,
/// audit F3: wrap-vs-panic divergence across build profiles).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetMeter {
    budget: u64,
    spent: u64,
    /// Sticky: set by the first refused charge, never cleared. This is what
    /// makes "a later cheaper charge must not succeed after exhaustion"
    /// true even when `remaining` would still be positive for the smaller
    /// cost — without the latch, a program could probe its way past the
    /// ceiling by retrying with descending costs.
    exhausted: bool,
}

impl BudgetMeter {
    /// A fresh meter with `budget` units and nothing spent.
    pub fn new(budget: u64) -> Self {
        BudgetMeter { budget, spent: 0, exhausted: false }
    }
    /// The cap this meter was built with (spent + remaining ≤ budget; the
    /// inequality is strict only after exhaustion pins `remaining` to 0).
    pub fn budget(&self) -> u64 {
        self.budget
    }
    /// Whether the exhaustion latch has fired.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

impl Meter for BudgetMeter {
    fn charge(&mut self, cost: u64) -> Result<(), Exhausted> {
        // Pinned: once exhausted, everything — including a zero-cost charge —
        // is refused. See the field comment on `exhausted`.
        if self.exhausted {
            return Err(Exhausted);
        }
        // `spent <= budget` is an invariant, so this subtraction cannot
        // underflow; checked anyway so a broken invariant fails closed
        // instead of wrapping into a huge phantom budget.
        let remaining = match self.budget.checked_sub(self.spent) {
            Some(r) => r,
            None => {
                self.exhausted = true;
                return Err(Exhausted);
            }
        };
        if cost > remaining {
            self.exhausted = true;
            return Err(Exhausted);
        }
        // Unreachable overflow by the invariant above, but never wrap.
        //
        // HONEST NOTE (mutation run 2026-08-22, M24): replacing this with
        // `wrapping_add` survives the whole suite, and no test can kill it —
        // `cost <= remaining = budget - spent` implies `spent + cost <=
        // budget <= u64::MAX`, and a corrupted meter (`spent > budget`)
        // returns above at the checked_sub, so the None arm is unreachable
        // in EVERY constructible state. It is an equivalent mutant, not a
        // test gap. The `checked_add` stays because the guarantee is the
        // invariant's, not this line's, and a future edit that weakens the
        // ordering above would make this line load-bearing again.
        match self.spent.checked_add(cost) {
            Some(s) => {
                self.spent = s;
                Ok(())
            }
            None => {
                self.exhausted = true;
                Err(Exhausted)
            }
        }
    }

    fn spent(&self) -> u64 {
        self.spent
    }

    fn remaining(&self) -> u64 {
        if self.exhausted {
            // Pinned to zero (spec §3): after a refused charge the meter
            // reports nothing left, even though `spent` keeps the true
            // reading for the Outcome.
            0
        } else {
            // Same checked posture as `charge`.
            // Saturating, i.e. checked-then-floor-at-zero: a broken
            // `spent <= budget` invariant reports 0 left, never a wrapped
            // ceiling (mutation M25).
            self.budget.saturating_sub(self.spent)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// §4 — HostCrypto: the one crypto surface
// ────────────────────────────────────────────────────────────────────────────

/// Deterministic crypto services a VM may consume (spec §4). Pure over its
/// inputs: same bytes in, same bytes out, on every architecture, forever.
///
/// The VM charges its own meter BEFORE calling — each VM prices these in its
/// own units (euvm: `gas_cost`, bloch-euvm lib.rs:208; sbpf: the CU table of
/// its spec). This trait carries no costs.
///
/// A failed signature verification **returns `false`, it is not a
/// [`Fault`]** — euvm pushes `Int(0)` for a bad signature and programs
/// branch on it (bloch-euvm lib.rs, `Op::VerifySig`); the SVM keeps the
/// same freedom. Hashes are total functions and have no failure mode.
pub trait HostCrypto {
    /// SHA3-256 — the Genesis-4 chain hash; SBPF-CORE §7 syscall 3.
    fn sha3_256(&self, data: &[u8]) -> [u8; 32];
    /// SHAKE-256 with a 32-byte read — the function euvm computes in-VM
    /// (`Op::Shake256`, bloch-euvm lib.rs:424) and state.rs:84 `shake32`
    /// builds its commitments from. Cross-KATed against the real VM in
    /// tests/cross_vm_kats.rs so the two sites can never drift silently.
    fn shake256_32(&self, data: &[u8]) -> [u8; 32];
    /// SHA-256d (double SHA-256) — euvm `Op::Sha256d` (bloch-euvm
    /// lib.rs:418); the PoW-era hash kept for scripts.
    fn sha256d(&self, data: &[u8]) -> [u8; 32];
    /// Hybrid PQ verify (ML-DSA-65 ‖ Falcon-1024) — euvm `SigVerifier`
    /// (bloch-euvm lib.rs:98) semantics verbatim. MUST be deterministic.
    /// No default: an implementor must consciously decide what "verify"
    /// means for it, exactly as euvm's trait forces.
    fn verify_pq(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool;
    /// secp256k1 ECDSA verify — `SigVerifier::verify_ecdsa` semantics
    /// verbatim, INCLUDING the default-false posture for hosts that only do
    /// PQ (bloch-euvm lib.rs:104): "not supported" and "did not verify"
    /// are the same safe answer.
    fn verify_ecdsa(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// The shipped [`HostCrypto`]: the three hashes via the same RustCrypto
/// crates (and versions) bloch-euvm uses, with KATs pinned in
/// `tests` below against an independent implementation (Python hashlib,
/// 2026-08-22) and cross-checked against the real VM in
/// tests/cross_vm_kats.rs.
///
/// **Signatures are fail-closed stubs.** This crate takes no pqcrypto
/// dependency (spec §4: signatures stay host-provided, exactly as euvm
/// decided at lib.rs:98 and for the same purity reason), so `verify_pq`
/// here returns `false` for every input — under a `RustCryptoHost` *no*
/// signature ever verifies. An integrator that needs real verification
/// wraps or replaces this type with one backed by bloch-crypto's verifiers;
/// what it must never do is get `true` out of a host that verified nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RustCryptoHost;

impl HostCrypto for RustCryptoHost {
    fn sha3_256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha3_256::digest(data));
        out
    }

    fn shake256_32(&self, data: &[u8]) -> [u8; 32] {
        // Byte-for-byte the sequence euvm runs for Op::Shake256
        // (bloch-euvm lib.rs:424): absorb, finalize XOF, read 32.
        let mut h = Shake256::default();
        h.update(data);
        let mut r = h.finalize_xof();
        let mut out = [0u8; 32];
        r.read(&mut out);
        out
    }

    fn sha256d(&self, data: &[u8]) -> [u8; 32] {
        let once = Sha256::digest(data);
        let twice = Sha256::digest(once);
        let mut out = [0u8; 32];
        out.copy_from_slice(&twice);
        out
    }

    fn verify_pq(&self, _msg: &[u8], _pubkey: &[u8], _sig: &[u8]) -> bool {
        // Fail-closed stub — see the type-level comment. NOT a default
        // method on the trait: this `false` is RustCryptoHost's conscious
        // answer ("I hold no verifier"), pinned by a test + control pair.
        false
    }
}

// ────────────────────────────────────────────────────────────────────────────
// §5 — Fault<E>: the shared failure taxonomy, lossless
// ────────────────────────────────────────────────────────────────────────────

/// Why an execution stopped without a verdict (spec §5). Generic over the
/// VM's own error type so nothing is flattened away: the shared variants
/// exist so tooling (explorers, harnesses, differential testers) can
/// classify faults across VMs without knowing either error enum.
///
/// Mapping rule, test-enforced in each VM's adapter (spec §5/§9.3): a VM
/// maps to a shared variant **iff** that variant's meaning applies exactly;
/// everything else goes through [`Fault::Vm`] untouched. `Vm(E)` is not a
/// junk drawer for faults that DO have a shared meaning.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault<E> {
    /// The meter ran out. The reproducible reading is `spent` in the
    /// [`Outcome`], not here (see [`Exhausted`]).
    Exhausted,
    /// A structural bound was exceeded (stack depth, operand bytes, program
    /// size, account-data cap, log cap...). Fail-closed twin of euvm's
    /// `MemoryLimitExceeded`/`OperandTooLarge`/`ProgramTooLarge`
    /// (bloch-euvm lib.rs:178) and the SBPF/SVM caps.
    Bounds,
    /// Checked arithmetic overflowed (euvm `VmError::Overflow`; SVM meter
    /// overflow per ACCOUNTS-SCHEDULER §6.3 "abort, never wrap").
    Overflow,
    /// The program itself signaled failure (euvm `Assert`; sbpf `abort()`
    /// syscall, SBPF-CORE §7 syscall 1).
    Aborted,
    /// Anything the shared vocabulary does not cover — the VM's native
    /// error, intact. Type errors, bad ctx fields, owner-rule violations,
    /// verifier rejections: each VM keeps its own words.
    Vm(E),
}

// ────────────────────────────────────────────────────────────────────────────
// §6 — LogSink, Outcome, Engine: the lifecycle envelope
// ────────────────────────────────────────────────────────────────────────────

/// Zero-sized proof that a log push was refused by a cap. The caller (a VM
/// syscall shim) decides whether that is a [`Fault::Bounds`] for its
/// program; the sink only enforces, it does not judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFull;

/// Bounded log sink (spec §6). Caps are enforced by the sink, not honor:
/// a `push` that would break either cap returns `Err(LogFull)` and changes
/// **nothing** — no partial append, so the log a caller reads back is
/// exactly the accepted pushes in order.
pub trait LogSink {
    /// Append one entry, all-or-nothing under the sink's caps.
    fn push(&mut self, entry: &[u8]) -> Result<(), LogFull>;
}

/// SBPF-CORE §7 log caps: 1 KiB per `log(ptr,len)` call...
pub const SBPF_LOG_ENTRY_CAP: usize = 1024;
/// ...and 32 KiB per execution.
pub const SBPF_LOG_TOTAL_CAP: usize = 32 * 1024;

/// The shipped [`LogSink`]: per-entry and total byte caps set at
/// construction (the SVM passes [`SBPF_LOG_ENTRY_CAP`]/[`SBPF_LOG_TOTAL_CAP`];
/// euvm constructs [`BoundedLog::sealed`] and never calls push — an
/// interface a VM legitimately ignores is not an interface that privileges
/// the other, spec §6).
///
/// **Entry-count bound, deliberate strictness beyond SBPF-CORE §7's
/// letter:** every accepted entry consumes at least 1 byte of the total
/// budget, even an empty one. Byte caps alone do not bound entry COUNT — a
/// program looping `log("")` would grow the entry vector without ever
/// touching a byte cap, an allocation channel outside both the meter and
/// the caps. Charging `max(len, 1)` bounds entries at `total_cap` with no
/// second knob, and makes `sealed()` (0/0) reject every push including the
/// empty one. Flagged for reconciliation with the SBPF spec owners
/// (spec §7 precedence: their SECURITY clauses win; this is strictly
/// tighter, so it can only be loosened by them, never silently).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundedLog {
    entry_cap: usize,
    total_cap: usize,
    /// Total budget consumed so far, in `max(len, 1)` units — see above.
    consumed: usize,
    entries: Vec<Vec<u8>>,
}

impl BoundedLog {
    /// A sink accepting entries of at most `entry_cap` bytes each, up to
    /// `total_cap` budget in total.
    pub fn new(entry_cap: usize, total_cap: usize) -> Self {
        BoundedLog { entry_cap, total_cap, consumed: 0, entries: Vec::new() }
    }
    /// The zero-cap sink for VMs that do not log (euvm today): every push,
    /// including an empty one, is refused.
    pub fn sealed() -> Self {
        BoundedLog::new(0, 0)
    }
    /// Accepted entries, in push order.
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }
    /// Consume the sink into the `log` field of an [`Outcome`].
    pub fn into_entries(self) -> Vec<Vec<u8>> {
        self.entries
    }
}

impl LogSink for BoundedLog {
    fn push(&mut self, entry: &[u8]) -> Result<(), LogFull> {
        // Per-entry cap first: an oversized entry is refused regardless of
        // how much total budget is left.
        if entry.len() > self.entry_cap {
            return Err(LogFull);
        }
        // Entry-count bound: an empty entry still costs 1 (type comment).
        let cost = entry.len().max(1);
        // Checked: `consumed` near usize::MAX must fail closed, not wrap
        // into a fresh budget.
        let consumed = match self.consumed.checked_add(cost) {
            Some(c) => c,
            None => return Err(LogFull),
        };
        if consumed > self.total_cap {
            return Err(LogFull);
        }
        // All checks passed — only now does anything mutate (all-or-nothing).
        self.consumed = consumed;
        self.entries.push(entry.to_vec());
        Ok(())
    }
}

/// One bounded, canonical execution result (spec §6). Everything a caller
/// may learn from a run is here — nothing escapes by side channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome<T, E> {
    /// Meter units consumed (VM-defined units, [`Meter`]). Deterministic —
    /// on the fault path this is the reproducible exhaustion reading.
    pub spent: u64,
    /// The verdict or the fault. `T` is the VM's effects/verdict type:
    /// euvm a validator verdict, the SVM its declared-writable post-images.
    pub result: Result<T, Fault<E>>,
    /// Bounded log, canonical part of the outcome (filled from a
    /// [`BoundedLog`]; empty for VMs that do not log).
    pub log: Vec<Vec<u8>>,
}

/// A VM as its host sees it: pure over (view, services) — the
/// stage/execute/commit discipline as a type (spec §2/§6).
///
/// The HOST built `View` before the call (bounded, deterministic copies —
/// euvm's `Ctx` + seed stack, the SVM's `TxContext`) and the HOST alone
/// applies `Effects` after it, running its own commit-time verification
/// (conservation at bloch-euvm lib.rs:704; readonly-integrity per
/// ACCOUNTS-SCHEDULER §6.4). The engine touches nothing else: no state
/// root, no PoS height/epoch/slot, no validator identity, no clock, no
/// randomness, no I/O. Any environment a VM needs (the SVM's `ExecEnv`
/// slot/epoch) is DATA its own runtime placed inside `View` — not a
/// service this interface provides, and this crate never learns what it
/// means.
///
/// The associated types are the design (spec §2): the interface is
/// identical for both VMs *without* claiming their views or effects share
/// a shape. If a future front finds itself widening `Engine` with
/// state-shaped methods (`read`, `write`, keys, accounts), that is scope
/// drift — stop and escalate, per the spec's own words.
pub trait Engine {
    /// The bounded view the host staged for this execution. VM-owned shape.
    type View;
    /// What the host may commit afterward (with verification). VM-owned.
    type Effects;
    /// The VM's native error type, carried intact in [`Fault::Vm`].
    type Error;
    /// Run pure over the staged view and the shared services. The returned
    /// [`Outcome::spent`] must equal `meter.spent()` at return — one
    /// reading, recorded once.
    fn execute(
        &self,
        view: &Self::View,
        meter: &mut dyn Meter,
        crypto: &dyn HostCrypto,
        log: &mut dyn LogSink,
    ) -> Outcome<Self::Effects, Self::Error>;
}

// ────────────────────────────────────────────────────────────────────────────
// Tests — every negative has a control half; each is a mutation target.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex KAT string (test-only; avoids a hex dependency).
    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    // ── §9.1 KATs: pinned 2026-08-22 against Python hashlib (independent
    //    implementation), one vector per length class (empty / short /
    //    domain-tagged / 1 KiB structured). The cross-checks against the
    //    REAL euvm ops live in tests/cross_vm_kats.rs.
    const KATS: &[(&[u8], &str, &str, &str)] = &[
        // (input, sha3_256, shake256_32, sha256d)
        (
            b"",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        ),
        (
            b"abc",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
        ),
        (
            b"bloch-vm-host KAT 2026-08-22",
            "5319c20f8e20cea4c07f65a158d8fae424d46566dd7e64ec56fe640dc4c1b154",
            "f24289ae228dbdf73cb4794dd0f044e2f10127e6263e04f9806ab3cb5fd3e4f5",
            "000995df32666fa9f74330121c2d5bd81894a6ec870b505a3ca707b96a3c0e0b",
        ),
    ];

    #[test]
    fn hash_kats_pin_all_three_functions() {
        let h = RustCryptoHost;
        for (input, sha3, shake, dsha) in KATS {
            assert_eq!(h.sha3_256(input).to_vec(), unhex(sha3), "sha3_256 KAT drift");
            assert_eq!(h.shake256_32(input).to_vec(), unhex(shake), "shake256_32 KAT drift");
            assert_eq!(h.sha256d(input).to_vec(), unhex(dsha), "sha256d KAT drift");
        }
    }

    /// KAT for the 1 KiB structured input (0..=255 repeated 4×) — exercises
    /// multi-block absorption in all three sponges/compressors, where a
    /// wrong padding or block handling hides from short vectors.
    #[test]
    fn hash_kats_survive_multi_block_inputs() {
        let h = RustCryptoHost;
        let long: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        assert_eq!(
            h.sha3_256(&long).to_vec(),
            unhex("b6c70631c6ff932b9f380d9cde8750eb9bea393817a9aea410c2119eb7b9b870")
        );
        assert_eq!(
            h.shake256_32(&long).to_vec(),
            unhex("60aff3fd4c0f158ba0ed6890336a907451281739d48cc8315211b36660619742")
        );
        assert_eq!(
            h.sha256d(&long).to_vec(),
            unhex("05fe36f555179feb8712eadb2a1cadac8c3c7378859f8dbeaa8a6ea224ea3658")
        );
    }

    /// CONTROL for the KATs: the three functions are genuinely different
    /// functions (a copy-paste of one body into another would pass any
    /// single-function KAT re-derived from the buggy code, but not this).
    #[test]
    fn control_the_three_hashes_disagree_with_each_other() {
        let h = RustCryptoHost;
        let data = b"abc";
        assert_ne!(h.sha3_256(data), h.shake256_32(data));
        assert_ne!(h.sha3_256(data), h.sha256d(data));
        assert_ne!(h.shake256_32(data), h.sha256d(data));
    }

    /// NEGATIVE: under RustCryptoHost no signature ever verifies — for any
    /// input, including well-formed-looking ones. Fail-closed stub, §4.
    #[test]
    fn rustcrypto_host_verifies_nothing() {
        let h = RustCryptoHost;
        assert!(!h.verify_pq(b"msg", b"pubkey", b"sig"));
        assert!(!h.verify_pq(b"", b"", b""));
        assert!(!h.verify_ecdsa(b"msg", b"pubkey", b"sig"));
    }

    /// CONTROL: the trait does NOT hard-code false — an integrator's host
    /// can return true, and the default verify_ecdsa stays false for it
    /// (the euvm lib.rs:104 posture, verbatim).
    #[test]
    fn control_an_integrator_host_can_verify() {
        struct YesPq;
        impl HostCrypto for YesPq {
            fn sha3_256(&self, d: &[u8]) -> [u8; 32] {
                RustCryptoHost.sha3_256(d)
            }
            fn shake256_32(&self, d: &[u8]) -> [u8; 32] {
                RustCryptoHost.shake256_32(d)
            }
            fn sha256d(&self, d: &[u8]) -> [u8; 32] {
                RustCryptoHost.sha256d(d)
            }
            fn verify_pq(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
                true
            }
        }
        assert!(YesPq.verify_pq(b"m", b"p", b"s"));
        assert!(!YesPq.verify_ecdsa(b"m", b"p", b"s"), "default must stay false");
    }

    // ── §9.2 Meter algebra ──

    /// Spend accumulates exactly; remaining mirrors it. (Control half for
    /// every exhaustion test below.)
    #[test]
    fn control_meter_accumulates_within_budget() {
        let mut m = BudgetMeter::new(100);
        assert_eq!(m.charge(30), Ok(()));
        assert_eq!(m.charge(30), Ok(()));
        assert_eq!(m.spent(), 60);
        assert_eq!(m.remaining(), 40);
        assert!(!m.is_exhausted());
    }

    /// NEGATIVE: a charge exceeding remaining is refused, `spent` is
    /// UNCHANGED by the failed charge (the reproducible reading), and the
    /// meter pins remaining to zero.
    #[test]
    fn overcharge_is_refused_and_spent_keeps_the_reading() {
        let mut m = BudgetMeter::new(100);
        assert_eq!(m.charge(60), Ok(()));
        assert_eq!(m.charge(41), Err(Exhausted)); // 41 > 40 remaining
        assert_eq!(m.spent(), 60, "failed charge must not move spent");
        assert_eq!(m.remaining(), 0, "exhaustion pins remaining to zero");
        assert!(m.is_exhausted());
    }

    /// CONTROL for the off-by-one: a charge of EXACTLY the remaining budget
    /// succeeds (sufficient means `cost <= remaining`, not `<`).
    #[test]
    fn control_exact_remaining_charge_succeeds() {
        let mut m = BudgetMeter::new(100);
        assert_eq!(m.charge(60), Ok(()));
        assert_eq!(m.charge(40), Ok(()));
        assert_eq!(m.spent(), 100);
        assert_eq!(m.remaining(), 0);
        assert!(!m.is_exhausted(), "a fully-spent meter is not an exhausted one");
    }

    /// NEGATIVE: the latch is sticky — after one refusal, cheaper charges
    /// (even zero) fail forever.
    #[test]
    fn exhaustion_is_pinned_cheaper_charges_keep_failing() {
        let mut m = BudgetMeter::new(10);
        assert_eq!(m.charge(11), Err(Exhausted));
        assert_eq!(m.charge(1), Err(Exhausted), "cheaper charge after exhaustion");
        assert_eq!(m.charge(0), Err(Exhausted), "zero charge after exhaustion");
        assert_eq!(m.spent(), 0, "nothing was ever actually spent");
    }

    /// CONTROL: without the refusal, the same cheap charges succeed on a
    /// fresh meter — the latch, not the amounts, is what refuses them.
    #[test]
    fn control_same_cheap_charges_succeed_without_prior_exhaustion() {
        let mut m = BudgetMeter::new(10);
        assert_eq!(m.charge(1), Ok(()));
        assert_eq!(m.charge(0), Ok(()));
        assert_eq!(m.spent(), 1);
    }

    /// u64 edges (§9.2): the full-range budget is spendable in one charge,
    /// and a fully-spent max meter refuses one more unit without wrapping.
    #[test]
    fn meter_u64_edges_never_wrap() {
        let mut m = BudgetMeter::new(u64::MAX);
        assert_eq!(m.charge(u64::MAX), Ok(()));
        assert_eq!(m.spent(), u64::MAX);
        assert_eq!(m.remaining(), 0);
        assert_eq!(m.charge(1), Err(Exhausted));
        assert_eq!(m.spent(), u64::MAX, "the reading survives the refusal");
    }

    /// The defensive checked arithmetic in `charge`/`remaining` guards an
    /// invariant (`spent <= budget`) that the public API cannot break — so
    /// no sequence of `new`/`charge` calls can reach it. These two tests
    /// construct a CORRUPTED meter directly (possible only from inside this
    /// module) and pin the guard's intent: a broken invariant must fail
    /// CLOSED, never wrap into a phantom budget. Without them the guards are
    /// untested code that a `wrapping_sub` "cleanup" would silently gut —
    /// mutation-proven: M23/M25, 2026-08-22.
    #[test]
    fn corrupted_meter_charges_fail_closed_not_wrapped() {
        // spent > budget: `budget - spent` would wrap to ~u64::MAX and make
        // every future charge affordable — the worst possible failure for a
        // DoS bound.
        let mut m = BudgetMeter { budget: 10, spent: 50, exhausted: false };
        assert_eq!(m.charge(1), Err(Exhausted), "corrupted meter must refuse");
        assert!(m.is_exhausted(), "and latch, so it stays refused");
        assert_eq!(m.spent(), 50, "the reading is not rewritten by the guard");
    }

    /// Twin of the above for the read path: `remaining` on a corrupted meter
    /// reports 0, not a wrapped ceiling.
    #[test]
    fn corrupted_meter_reports_zero_remaining() {
        let m = BudgetMeter { budget: 10, spent: 50, exhausted: false };
        assert_eq!(m.remaining(), 0);
    }

    // ── §9.4 LogSink caps ──

    /// CONTROL: entries within both caps are accepted, in order, verbatim.
    #[test]
    fn control_log_accepts_within_caps() {
        let mut l = BoundedLog::new(4, 16);
        assert_eq!(l.push(b"ab"), Ok(()));
        assert_eq!(l.push(b"cdef"), Ok(())); // exactly entry_cap
        assert_eq!(l.entries(), &[b"ab".to_vec(), b"cdef".to_vec()]);
    }

    /// NEGATIVE: one byte over the per-entry cap is refused; the control
    /// half (exactly at cap) lives in `control_log_accepts_within_caps`.
    #[test]
    fn log_refuses_oversized_entry() {
        let mut l = BoundedLog::new(4, 16);
        assert_eq!(l.push(b"abcde"), Err(LogFull));
        assert!(l.entries().is_empty(), "refused push must append nothing");
    }

    /// NEGATIVE + CONTROL: the total cap is exact — a push landing exactly
    /// on the cap is accepted, the next byte is refused, and the refusal
    /// leaves the accepted log untouched (all-or-nothing).
    #[test]
    fn log_total_cap_is_exact_and_refusal_is_atomic() {
        let mut l = BoundedLog::new(8, 8);
        assert_eq!(l.push(b"abcd"), Ok(()));
        assert_eq!(l.push(b"efgh"), Ok(())); // exactly total_cap consumed
        assert_eq!(l.push(b"i"), Err(LogFull));
        assert_eq!(
            l.entries(),
            &[b"abcd".to_vec(), b"efgh".to_vec()],
            "refused push must not partially append"
        );
    }

    /// NEGATIVE: empty entries are NOT free — each costs 1 budget unit, so
    /// entry count is bounded by total_cap (the deliberate strictness
    /// documented on BoundedLog).
    #[test]
    fn log_empty_entries_are_counted() {
        let mut l = BoundedLog::new(4, 2);
        assert_eq!(l.push(b""), Ok(()));
        assert_eq!(l.push(b""), Ok(()));
        assert_eq!(l.push(b""), Err(LogFull), "3rd empty entry exceeds total budget 2");
        assert_eq!(l.entries().len(), 2);
    }

    /// NEGATIVE: the sealed sink refuses everything, including empty.
    /// (Control: the same pushes succeed on a non-sealed sink above.)
    #[test]
    fn sealed_log_refuses_every_push() {
        let mut l = BoundedLog::sealed();
        assert_eq!(l.push(b""), Err(LogFull));
        assert_eq!(l.push(b"x"), Err(LogFull));
        assert!(l.entries().is_empty());
    }

    /// Same reasoning as the corrupted-meter pair, for the log's total
    /// budget: `consumed` cannot approach `usize::MAX` through pushes, so
    /// the `checked_add` guard is unreachable from outside. Constructed
    /// directly, it must fail closed — a `wrapping_add` would send
    /// `consumed` to 0 and hand the program an UNBOUNDED log, which is the
    /// allocation channel the caps exist to close. Mutation-proven: M22.
    #[test]
    fn corrupted_log_total_fails_closed_not_wrapped() {
        let mut l = BoundedLog {
            entry_cap: 8,
            total_cap: usize::MAX,
            consumed: usize::MAX,
            entries: Vec::new(),
        };
        assert_eq!(l.push(b"x"), Err(LogFull));
        assert!(l.entries().is_empty());
    }

    /// The SBPF constants are the spec's numbers (SBPF-CORE §7), pinned so
    /// a "harmless" retune shows up as a red test, not a silent consensus
    /// difference between a logging SVM and its explorers.
    #[test]
    fn sbpf_log_caps_match_the_spec() {
        assert_eq!(SBPF_LOG_ENTRY_CAP, 1024);
        assert_eq!(SBPF_LOG_TOTAL_CAP, 32 * 1024);
    }

    // ── §5 Fault + §6 Engine envelope ──

    /// Vm(E) carries the native error INTACT (losslessness is the §5
    /// contract; flattening would break cross-VM classification tooling).
    #[test]
    fn fault_vm_variant_is_lossless() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        enum NativeErr {
            OwnerRule(u8),
        }
        let f: Fault<NativeErr> = Fault::Vm(NativeErr::OwnerRule(7));
        assert_eq!(f, Fault::Vm(NativeErr::OwnerRule(7)));
        assert_ne!(f, Fault::Vm(NativeErr::OwnerRule(8)));
        assert_ne!(f, Fault::Aborted);
    }

    /// A toy Engine proving the envelope is usable end-to-end with the
    /// shipped services and that Outcome::spent carries the meter reading
    /// on BOTH the success and the exhaustion path. The toy charges 10 per
    /// input byte (charge-then-do), hashes the view through HostCrypto,
    /// and logs one entry.
    struct ToyVm;
    #[derive(Debug, PartialEq, Eq)]
    struct ToyEffects([u8; 32]);
    impl Engine for ToyVm {
        type View = Vec<u8>;
        type Effects = ToyEffects;
        type Error = ();
        fn execute(
            &self,
            view: &Vec<u8>,
            meter: &mut dyn Meter,
            crypto: &dyn HostCrypto,
            log: &mut dyn LogSink,
        ) -> Outcome<ToyEffects, ()> {
            // charge-then-do: the whole price up front, like euvm lib.rs:360.
            let cost = (view.len() as u64).saturating_mul(10);
            if meter.charge(cost).is_err() {
                return Outcome { spent: meter.spent(), result: Err(Fault::Exhausted), log: vec![] };
            }
            let digest = crypto.sha3_256(view);
            let _ = log.push(b"toy: hashed");
            Outcome { spent: meter.spent(), result: Ok(ToyEffects(digest)), log: vec![] }
        }
    }

    /// CONTROL: enough budget → verdict, exact spend, log captured.
    #[test]
    fn control_toy_engine_runs_within_budget() {
        let mut meter = BudgetMeter::new(100);
        let mut log = BoundedLog::new(64, 64);
        let view = b"abc".to_vec();
        let out = ToyVm.execute(&view, &mut meter, &RustCryptoHost, &mut log);
        assert_eq!(out.spent, 30);
        assert_eq!(
            out.result,
            Ok(ToyEffects(RustCryptoHost.sha3_256(b"abc"))),
            "effects must come from the staged view via HostCrypto"
        );
        assert_eq!(log.entries(), &[b"toy: hashed".to_vec()]);
    }

    /// NEGATIVE: short budget → Fault::Exhausted with the reproducible
    /// reading (spent BEFORE the refused charge — charge-then-do means the
    /// partial work never happened, so nothing was spent here).
    #[test]
    fn toy_engine_exhausts_with_reproducible_reading() {
        let mut meter = BudgetMeter::new(29); // needs 30
        let mut log = BoundedLog::sealed();
        let out = ToyVm.execute(&b"abc".to_vec(), &mut meter, &RustCryptoHost, &mut log);
        assert_eq!(out.result, Err(Fault::Exhausted));
        assert_eq!(out.spent, 0, "all-or-nothing charge: no partial spend");
        assert_eq!(meter.remaining(), 0, "the meter is pinned after the run");
    }
}
