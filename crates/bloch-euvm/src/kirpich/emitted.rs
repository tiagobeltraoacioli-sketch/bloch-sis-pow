//! # Kirpich — Lane D: determinism & completeness of *emitted* programs
//!
//! **INTERNAL AUDIT, tests-only, NOT consensus-wired.** This lane is the last stage of
//! the [`crate::kirpich`] static auditor (the "brick inspector"): it does not read the
//! [`TokenCharter`] in isolation like Lanes A–C — it *compiles the charter internally*
//! (via [`crate::modules::compile_charter`], a pure/deterministic function) and audits
//! the **bytes that come out**. All five rules here are grounded in real `lib.rs`
//! primitives ([`encode_program`], [`gas_cost`], [`Op`], [`BLCH`]) and the real
//! `modules.rs` types ([`CompiledToken`], [`crate::modules::CompiledModule`]).
//!
//! ## Rules (each = one deterministic [`Finding`])
//!
//! | code    | severity      | defect |
//! |---------|---------------|--------|
//! | KRP-060 | Deny          | **Non-deterministic recompile** — the same charter did not compile to byte-identical programs / charter id. A consensus VM's compiler MUST be a pure function; a mismatch is fail-closed-fatal. |
//! | KRP-061 | Deny          | **Emitted set incomplete** — a declared module produced no validator, the wrong kind, or an empty program (a "declared but not compiled" gap). |
//! | KRP-062 | Deny          | **Gas / size budget** — an emitted validator (or the whole set) exceeds the static gas or encoded-size DoS ceiling. |
//! | KRP-063 | Deny          | **Supply hash == BLCH** — a `Supply` module's emitted `validator_hash` (its asset id / policy id) collides with the base coin [`BLCH`] (all-zero id). |
//! | KRP-064 | Deny / Warn   | **Always-true / neutered guard** — a structurally always-authorizing guard (`0-of-m` governance, a `Pick`-depth `u8` truncation that neuters a signer, or a compile-time-constant verdict). Warn is emitted for the dual always-*false* (structurally unspendable) case. |
//!
//! ## Type shape expected from the Integrate phase (`src/kirpich.rs`)
//!
//! This lane references the canonical audit types via `use super::{Finding, Severity}`,
//! exactly as the lane contract specifies. The integrator's `src/kirpich.rs` MUST define:
//!
//! ```ignore
//! #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
//! pub enum Severity { Deny = 0, Warn = 1, Info = 2 }
//!
//! #[derive(Clone, Debug, PartialEq, Eq)]
//! pub struct Finding {
//!     pub code: &'static str,          // stable "KRP-NNN"
//!     pub severity: Severity,
//!     pub module: Option<&'static str>,// ModuleKind::tag(), or None for charter-level
//!     pub index: Option<usize>,        // position in charter.modules, when module-specific
//!     pub message: String,             // deterministic format! over scalars only
//! }
//! ```
//!
//! and declare `mod emitted;`. The lane entry point is exactly:
//! `pub(super) fn audit(charter: &TokenCharter, out: &mut Vec<Finding>)` — append-only
//! into the shared sink. No sorting is done here; the dispatcher sorts canonically.
//!
//! ## Determinism guarantees
//!
//! No float, no clock, no I/O, no `HashMap` iteration. Counting/summation use `usize` /
//! `u64` with `saturating_add` (no wrap, no overflow-panic). Every rule tolerates a
//! malformed charter by emitting a `Finding` rather than panicking: all indexing goes
//! through `.get()`, and Lane D never `unwrap`s the compiled output.

use super::{Finding, Severity};
use crate::modules::{compile_charter, CompiledToken, ModuleKind, TokenCharter};
use crate::{encode_program, gas_cost, Op, BLCH};

// ─────────────────────────────────────────────────────────────────────────────
// DoS budgets for the emitted validator set (KRP-062). Static, generous ceilings:
// a real Ustav validator is a few KiB and a few thousand gas; anything orders of
// magnitude larger is a structural defect (e.g. a runaway generated program).
// ─────────────────────────────────────────────────────────────────────────────

/// Max encoded size (bytes of [`encode_program`]) for a single emitted validator.
const MAX_VALIDATOR_BYTES: usize = 65_536; // 64 KiB
/// Max *static* gas (sum of [`gas_cost`] over the program) for a single validator.
const MAX_VALIDATOR_GAS: u64 = 2_000_000;
/// Max total encoded size across the whole compiled set.
const MAX_TOTAL_BYTES: usize = 262_144; // 256 KiB
/// Max total static gas across the whole compiled set.
const MAX_TOTAL_GAS: u64 = 8_000_000;

/// The largest `signers.len()` a `Governance` module can carry before the compiler's
/// `Pick((m + 3 - i) as u8)` depth truncates: signer #1 needs depth `m + 2`, which
/// must fit in `u8`, so `m + 2 <= 255` ⇒ `m <= 253`. Beyond this, signer #1's `Pick`
/// silently wraps (to `Pick(0) == Dup`) and that signer's signature check is neutered.
const MAX_GOVERNANCE_SIGNERS: usize = 253;

// ─────────────────────────────────────────────────────────────────────────────
// Lane entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Lane D audit: compile the charter (twice, to assert determinism) and inspect the
/// emitted bytes. Append-only into `out`; never panics on any charter input.
#[cfg(test)]
pub(super) fn audit(charter: &TokenCharter, out: &mut Vec<Finding>) {
    let _ = audit_and_compile(charter, out);
}

/// Return the already audited artifact so the caller does not compile a third time.
pub(super) fn audit_and_compile(
    charter: &TokenCharter,
    out: &mut Vec<Finding>,
) -> Option<CompiledToken> {
    // K-3 fix: skip compilation entirely when Lane C's KRP-046 pre-flight already
    // denies the charter on pubkey size alone. Before this guard, Lane D compiled
    // the charter TWICE unconditionally (for the KRP-060 determinism diff below)
    // regardless of what any other lane found — a charter with, say, 253 governance
    // signers of 1 MiB each cost ~1 GiB of transient allocation here even though
    // Lane C's own rule would already deny it. `pubkey_budget_denied` is pure
    // length arithmetic (no allocation, no compile), so it is safe to run first
    // unconditionally: cheapest-check-first. Lane C (`params.rs`) has already
    // pushed the KRP-046 Deny finding(s) with full detail into the shared `out` by
    // the time this lane runs (`kirpich.rs` calls `params::audit` before
    // `emitted::audit`), so nothing is lost by returning without compiling.
    if super::params::pubkey_budget_denied(charter) {
        return None;
    }

    // Two independent compiles of the same charter — the input to KRP-060. This is an
    // acceptable extra deterministic compile on this tests-only audit path.
    let compiled = compile_charter(charter);
    let recompiled = compile_charter(charter);

    audit_determinism(&compiled, &recompiled, out); // KRP-060
    audit_completeness(charter, &compiled, out); // KRP-061
    audit_budget(&compiled, out); // KRP-062
    audit_supply_blch(charter, &compiled, out); // KRP-063
    audit_neuter(charter, &compiled, out); // KRP-064
    Some(compiled)
}

// ─────────────────────────────────────────────────────────────────────────────
// Small constructors / helpers (deterministic, no float / clock / IO)
// ─────────────────────────────────────────────────────────────────────────────

fn finding(
    code: &'static str,
    severity: Severity,
    module: Option<&'static str>,
    index: Option<usize>,
    message: String,
) -> Finding {
    Finding {
        code,
        severity,
        module,
        index,
        message,
    }
}

/// Static (input-independent) gas of a program: the sum of [`gas_cost`] over its ops.
/// `saturating_add` keeps it total (no overflow panic) and deterministic.
fn static_gas(program: &[Op]) -> u64 {
    let mut g: u64 = 0;
    for op in program {
        g = g.saturating_add(gas_cost(op));
    }
    g
}

/// Encoded byte length of a program (its [`crate::validator_hash`] preimage length).
fn program_bytes(program: &[Op]) -> usize {
    encode_program(program).len()
}

// ─────────────────────────────────────────────────────────────────────────────
// K-4 fix: a small, bounded, straight-line abstract interpreter over the emitted
// program, replacing the old literal-`PushInt`-tail heuristic.
//
// The old `constant_tail_verdict` matched ONLY a literal `PushInt` in the final
// slot — sound (never a false positive) but not complete: it missed the exact case
// the finding names, `Governance { signers: [], threshold: 0 }`, whose emitted tail
// is `PushInt(0), PushInt(0), Lt, Not` (§2.3 of the annex) — a compile-time-constant
// TRUE verdict expressed through arithmetic, not a literal push. Any future/
// third-party emitter that bakes a constant verdict through `Add`/`Sub`/`Mul`/`Eq`/
// `Swap`/`Dup`/`Pick` in any shape was equally invisible to it.
//
// `AbsVal` models one stack slot: a compile-time-KNOWN `Int`/`Bytes` value, or
// `Unknown` (⊤) standing for anything that depends on the datum, the redeemer, or
// context (`CtxField`, `VerifySig`/`VerifyEcdsa`, `Sha256d`/`Shake256` output, any
// `TxOut*`/`Self*` read). The programs Kirpich audits are straight-line (no
// branches, no loops) and bounded (`MAX_PROGRAM_OPS` in `lib.rs`), so a single
// linear pass with a real stack is a complete, terminating, deterministic
// evaluation — no fixed point / widening needed.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum AbsVal {
    Int(i128),
    Bytes(Vec<u8>),
    /// ⊤ — depends on the datum, redeemer, or transaction context; not a
    /// compile-time constant.
    Unknown,
}

impl AbsVal {
    fn as_known_int(&self) -> Option<i128> {
        match self {
            AbsVal::Int(n) => Some(*n),
            _ => None,
        }
    }
}

/// Evaluate `program` over an abstract stack seeded with `Unknown` values (standing
/// in for whatever real datum/redeemer the `ExpectDepth` at the head of the program
/// asserts is present — see below), constant-folding every op the interpreter
/// understands and falling back to `Unknown` for anything it does not (signature
/// verification, hashing, context/tx-output reads). Returns:
///
/// * `Some(true)`  — the program's final verdict is a compile-time constant TRUE:
///   it authorizes every possible spend, regardless of datum/redeemer/ctx.
/// * `Some(false)` — the program's final verdict is a compile-time constant FALSE,
///   OR it unconditionally hits an `Op::Verify` on a known-zero value and so always
///   aborts: it authorizes no spend.
/// * `None`        — the verdict is genuinely input-dependent (the sound default;
///   never a false positive by construction, since every arm below only commits to
///   `Some(_)` when every operand it needs was already `Known`).
///
/// **Deliberately conservative, not exhaustive** (documented gaps, same spirit as
/// the heuristic this replaces): `Sha256d`/`Shake256` always yield `Unknown` even on
/// a `Known` input (no reason to fold through a hash); `VerifySig`/`VerifyEcdsa`
/// always yield `Unknown` (their range is `{0,1}` but this pass does no interval
/// reasoning, so e.g. `threshold > signers.len()` — always-false only because the
/// summed verdict is bounded by `signers.len()` — is NOT caught; this is the same
/// documented gap the old heuristic had). A malformed/adversarial program never
/// panics: every stack access that would underflow is treated as `Unknown` rather
/// than erroring, matching the "no rule panics on any charter" contract.
fn constant_tail_verdict(program: &[Op]) -> Option<bool> {
    let mut st: Vec<AbsVal> = Vec::new();

    // Pop helper: an empty/underflowing stack models "a real seed value we do not
    // track" (e.g. reading below the deepest `ExpectDepth`-asserted slot) — treat it
    // as Unknown rather than panicking or aborting the analysis.
    fn pop(st: &mut Vec<AbsVal>) -> AbsVal {
        st.pop().unwrap_or(AbsVal::Unknown)
    }
    fn pick(st: &[AbsVal], n: usize) -> AbsVal {
        match st.len().checked_sub(1 + n) {
            Some(idx) => st[idx].clone(),
            None => AbsVal::Unknown,
        }
    }

    for op in program {
        match op {
            Op::PushInt(n) => st.push(AbsVal::Int(*n)),
            Op::PushBytes(b) => st.push(AbsVal::Bytes(b.clone())),
            Op::Dup => {
                let top = st.last().cloned().unwrap_or(AbsVal::Unknown);
                st.push(top);
            }
            Op::Drop => {
                pop(&mut st);
            }
            Op::Swap => {
                let a = pop(&mut st);
                let b = pop(&mut st);
                st.push(a);
                st.push(b);
            }
            Op::ExpectDepth(n) => {
                // Models the implicit seed [datum, redeemer...] this op asserts is
                // present: pad the BOTTOM of the abstract stack with Unknown up to
                // depth n, so later Pick/Dup into that region reads Unknown rather
                // than underflowing. Does not touch an already-deep-enough stack.
                let n = *n as usize;
                if st.len() < n {
                    let pad = n - st.len();
                    let mut padded = vec![AbsVal::Unknown; pad];
                    padded.extend(st.drain(..));
                    st = padded;
                }
            }
            Op::Pick(n) => {
                let v = pick(&st, *n as usize);
                st.push(v);
            }
            Op::Add | Op::Sub | Op::Mul => {
                let b = pop(&mut st);
                let a = pop(&mut st);
                let r = match (a.as_known_int(), b.as_known_int()) {
                    (Some(a), Some(b)) => {
                        let checked = match op {
                            Op::Add => a.checked_add(b),
                            Op::Sub => a.checked_sub(b),
                            Op::Mul => a.checked_mul(b),
                            _ => unreachable!(),
                        };
                        // A checked-arithmetic overflow here is over compile-time
                        // CONSTANT operands, so it would abort the real program
                        // deterministically for every input too — but this pass does
                        // not attempt to represent "always aborts via Overflow" (only
                        // via a known-zero `Verify`, see below), so fold to Unknown
                        // rather than over-claim a verdict this analysis is not
                        // built to justify.
                        checked.map(AbsVal::Int).unwrap_or(AbsVal::Unknown)
                    }
                    _ => AbsVal::Unknown,
                };
                st.push(r);
            }
            Op::Eq => {
                let b = pop(&mut st);
                let a = pop(&mut st);
                let r = match (&a, &b) {
                    (AbsVal::Int(x), AbsVal::Int(y)) => AbsVal::Int((x == y) as i128),
                    (AbsVal::Bytes(x), AbsVal::Bytes(y)) => AbsVal::Int((x == y) as i128),
                    _ => AbsVal::Unknown,
                };
                st.push(r);
            }
            Op::Lt => {
                let b = pop(&mut st);
                let a = pop(&mut st);
                let r = match (a.as_known_int(), b.as_known_int()) {
                    (Some(a), Some(b)) => AbsVal::Int((a < b) as i128),
                    _ => AbsVal::Unknown,
                };
                st.push(r);
            }
            Op::Not => {
                let a = pop(&mut st);
                let r = match a.as_known_int() {
                    Some(a) => AbsVal::Int((a == 0) as i128),
                    None => AbsVal::Unknown,
                };
                st.push(r);
            }
            Op::Size => {
                let a = pop(&mut st);
                let r = match a {
                    AbsVal::Bytes(b) => AbsVal::Int(b.len() as i128),
                    _ => AbsVal::Unknown,
                };
                st.push(r);
            }
            Op::Verify => {
                let a = pop(&mut st);
                match a.as_known_int() {
                    // A known-zero operand means this Verify aborts EVERY time this
                    // op runs, regardless of datum/redeemer/ctx (the value that fed
                    // it was itself a compile-time constant) — the whole program is
                    // therefore unconditionally unspendable.
                    Some(0) => return Some(false),
                    // A known-nonzero operand never aborts; continue folding.
                    Some(_) => {}
                    // An Unknown operand might or might not abort depending on real
                    // input — cannot prove either verdict, bail conservatively
                    // (matches the old heuristic's blanket bail on any `Verify`).
                    None => return None,
                }
            }
            // Everything below reads real cryptographic material, hashes,
            // context, or transaction outputs — none of it is a compile-time
            // constant in this analysis. Pop the declared arity, push Unknown.
            Op::Sha256d | Op::Shake256 => {
                pop(&mut st);
                st.push(AbsVal::Unknown);
            }
            Op::CtxField(_) | Op::TxOutDatum(_) | Op::TxOutValidator(_) | Op::TxOutValue(_)
            | Op::SelfValidator => {
                st.push(AbsVal::Unknown);
            }
            Op::SelfAsset | Op::TxOutAsset(_) => {
                pop(&mut st);
                st.push(AbsVal::Unknown);
            }
            Op::VerifySig | Op::VerifyEcdsa => {
                pop(&mut st);
                pop(&mut st);
                pop(&mut st);
                st.push(AbsVal::Unknown);
            }
        }
    }

    st.last().and_then(AbsVal::as_known_int).map(|n| n != 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-060 — non-deterministic recompile
// ─────────────────────────────────────────────────────────────────────────────

fn audit_determinism(a: &CompiledToken, b: &CompiledToken, out: &mut Vec<Finding>) {
    if a.charter_id != b.charter_id {
        out.push(finding(
            "KRP-060",
            Severity::Deny,
            None,
            None,
            "non-deterministic compile: charter_id is not reproducible across two \
             identical compiles"
                .to_string(),
        ));
        // The id already differs; per-validator diffs would be redundant noise.
        return;
    }
    if a.validators.len() != b.validators.len() {
        out.push(finding(
            "KRP-060",
            Severity::Deny,
            None,
            None,
            format!(
                "non-deterministic compile: emitted {} validators on one compile, {} on \
                 the next",
                a.validators.len(),
                b.validators.len()
            ),
        ));
        return;
    }
    for (i, (va, vb)) in a.validators.iter().zip(b.validators.iter()).enumerate() {
        let bytes_differ = encode_program(&va.program) != encode_program(&vb.program);
        if bytes_differ || va.validator_hash != vb.validator_hash {
            out.push(finding(
                "KRP-060",
                Severity::Deny,
                Some(va.kind),
                Some(i),
                format!(
                    "non-deterministic compile: validator {} ('{}') differs between two \
                     identical compiles",
                    i, va.kind
                ),
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-061 — emitted set incomplete (declared-but-not-compiled gap)
// ─────────────────────────────────────────────────────────────────────────────

fn audit_completeness(charter: &TokenCharter, compiled: &CompiledToken, out: &mut Vec<Finding>) {
    if compiled.validators.len() != charter.modules.len() {
        out.push(finding(
            "KRP-061",
            Severity::Deny,
            None,
            None,
            format!(
                "emitted set incomplete: {} declared module(s) compiled to {} \
                 validator(s)",
                charter.modules.len(),
                compiled.validators.len()
            ),
        ));
        // The counts already diverge; per-index checks below still run on the overlap.
    }

    for (i, m) in charter.modules.iter().enumerate() {
        match compiled.validators.get(i) {
            None => {
                // Covered by the length-mismatch finding above; nothing extra to add.
            }
            Some(v) => {
                if v.kind != m.tag() {
                    out.push(finding(
                        "KRP-061",
                        Severity::Deny,
                        Some(m.tag()),
                        Some(i),
                        format!(
                            "emitted set incomplete: declared module '{}' compiled as \
                             '{}'",
                            m.tag(),
                            v.kind
                        ),
                    ));
                }
                if v.program.is_empty() {
                    out.push(finding(
                        "KRP-061",
                        Severity::Deny,
                        Some(m.tag()),
                        Some(i),
                        format!(
                            "emitted set incomplete: module '{}' emitted an empty \
                             validator program (enforces nothing)",
                            m.tag()
                        ),
                    ));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-062 — gas / size budget
// ─────────────────────────────────────────────────────────────────────────────

fn audit_budget(compiled: &CompiledToken, out: &mut Vec<Finding>) {
    let mut total_bytes: usize = 0;
    let mut total_gas: u64 = 0;

    for (i, v) in compiled.validators.iter().enumerate() {
        let bytes = program_bytes(&v.program);
        let gas = static_gas(&v.program);
        total_bytes = total_bytes.saturating_add(bytes);
        total_gas = total_gas.saturating_add(gas);

        if bytes > MAX_VALIDATOR_BYTES {
            out.push(finding(
                "KRP-062",
                Severity::Deny,
                Some(v.kind),
                Some(i),
                format!(
                    "size budget exceeded: validator {} ('{}') encodes to {} bytes > \
                     {} limit",
                    i, v.kind, bytes, MAX_VALIDATOR_BYTES
                ),
            ));
        }
        if gas > MAX_VALIDATOR_GAS {
            out.push(finding(
                "KRP-062",
                Severity::Deny,
                Some(v.kind),
                Some(i),
                format!(
                    "gas budget exceeded: validator {} ('{}') costs {} static gas > \
                     {} limit",
                    i, v.kind, gas, MAX_VALIDATOR_GAS
                ),
            ));
        }
    }

    if total_bytes > MAX_TOTAL_BYTES {
        out.push(finding(
            "KRP-062",
            Severity::Deny,
            None,
            None,
            format!(
                "size budget exceeded: emitted set encodes to {} bytes > {} total limit",
                total_bytes, MAX_TOTAL_BYTES
            ),
        ));
    }
    if total_gas > MAX_TOTAL_GAS {
        out.push(finding(
            "KRP-062",
            Severity::Deny,
            None,
            None,
            format!(
                "gas budget exceeded: emitted set costs {} static gas > {} total limit",
                total_gas, MAX_TOTAL_GAS
            ),
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-063 — Supply's emitted hash collides with BLCH (base coin id)
// ─────────────────────────────────────────────────────────────────────────────

fn audit_supply_blch(charter: &TokenCharter, compiled: &CompiledToken, out: &mut Vec<Finding>) {
    for (i, m) in charter.modules.iter().enumerate() {
        if let ModuleKind::Supply(_) = m {
            if let Some(v) = compiled.validators.get(i) {
                if v.validator_hash == BLCH {
                    out.push(finding(
                        "KRP-063",
                        Severity::Deny,
                        Some("supply"),
                        Some(i),
                        format!(
                            "supply hash collision: module {} emits the all-zero \
                             validator hash, which IS the base coin BLCH id — this \
                             token's asset/policy id would collide with BLCH",
                            i
                        ),
                    ));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-064 — always-true / neutered guard
// ─────────────────────────────────────────────────────────────────────────────

fn audit_neuter(charter: &TokenCharter, compiled: &CompiledToken, out: &mut Vec<Finding>) {
    for (i, m) in charter.modules.iter().enumerate() {
        // Governance-specific structural neuters (read the charter's declared config).
        if let ModuleKind::Governance(cfg) = m {
            if cfg.threshold == 0 {
                out.push(finding(
                    "KRP-064",
                    Severity::Deny,
                    Some("governance"),
                    Some(i),
                    format!(
                        "always-true guard: governance module {} has threshold 0 (a \
                         0-of-{} multisig authorizes ANY spend, neutering the module)",
                        i,
                        cfg.signers.len()
                    ),
                ));
            }
            if cfg.signers.len() > MAX_GOVERNANCE_SIGNERS {
                out.push(finding(
                    "KRP-064",
                    Severity::Deny,
                    Some("governance"),
                    Some(i),
                    format!(
                        "neutered guard: governance module {} declares {} signers (> \
                         {}); the compiler's u8 Pick-depth truncates for signer #1, \
                         silently dropping its signature check",
                        i,
                        cfg.signers.len(),
                        MAX_GOVERNANCE_SIGNERS
                    ),
                ));
            }
        }

        // Emitted-bytecode constant-verdict check (all kinds).
        if let Some(v) = compiled.validators.get(i) {
            match constant_tail_verdict(&v.program) {
                Some(true) => out.push(finding(
                    "KRP-064",
                    Severity::Deny,
                    Some(v.kind),
                    Some(i),
                    format!(
                        "always-true guard: validator {} ('{}') has a compile-time \
                         constant TRUE verdict — it authorizes every spend",
                        i, v.kind
                    ),
                )),
                Some(false) => out.push(finding(
                    "KRP-064",
                    Severity::Warn,
                    Some(v.kind),
                    Some(i),
                    format!(
                        "dead guard: validator {} ('{}') has a compile-time constant \
                         FALSE verdict — it can never authorize a spend (output \
                         unspendable)",
                        i, v.kind
                    ),
                )),
                None => {}
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::{
        CompiledModule, CustodyConfig, GovernanceConfig, KycConfig, SupplyConfig,
        TransferPolicyConfig, VestingConfig,
    };

    // ── charter / compiled-token builders ──────────────────────────────────

    fn supply_mod(cap: u64) -> ModuleKind {
        ModuleKind::Supply(SupplyConfig {
            cap,
            issuer_pubkey: b"issuer-pk".to_vec(),
        })
    }

    fn gov_mod(m: usize, threshold: u32) -> ModuleKind {
        ModuleKind::Governance(GovernanceConfig {
            signers: (0..m).map(|i| format!("g{i}").into_bytes()).collect(),
            threshold,
        })
    }

    /// A healthy multi-module charter exercising several kinds (Lane D "PASS" fixture).
    fn healthy_charter() -> TokenCharter {
        TokenCharter {
            token_name: b"USTV".to_vec(),
            modules: vec![
                supply_mod(1_000_000),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"authority-pk".to_vec(),
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 2_400,
                    beneficiary_pubkey: b"benef-pk".to_vec(),
                }),
                gov_mod(3, 2),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc-pk".to_vec(),
                    pq_pubkey: b"pq-pk".to_vec(),
                }),
            ],
        }
    }

    fn cm(kind: &'static str, program: Vec<Op>, hash: [u8; 32]) -> CompiledModule {
        CompiledModule {
            kind,
            program,
            validator_hash: hash,
        }
    }

    fn codes(out: &[Finding]) -> Vec<&'static str> {
        out.iter().map(|f| f.code).collect()
    }

    fn count_code(out: &[Finding], code: &str) -> usize {
        out.iter().filter(|f| f.code == code).count()
    }

    // ── KRP-060 determinism ────────────────────────────────────────────────

    #[test]
    fn krp060_real_charter_is_deterministic_no_finding() {
        let mut out = Vec::new();
        audit(&healthy_charter(), &mut out);
        assert_eq!(count_code(&out, "KRP-060"), 0, "{out:?}");
    }

    #[test]
    fn krp060_helper_detects_program_byte_diff() {
        // Same charter_id, same length, but validator[0]'s program bytes differ.
        let a = CompiledToken {
            charter_id: [7u8; 32],
            validators: vec![cm("supply", vec![Op::PushInt(1)], [1u8; 32])],
        };
        let b = CompiledToken {
            charter_id: [7u8; 32],
            validators: vec![cm("supply", vec![Op::PushInt(2)], [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_determinism(&a, &b, &mut out);
        assert_eq!(codes(&out), vec!["KRP-060"]);
        assert_eq!(out[0].severity, Severity::Deny);
        assert_eq!(out[0].index, Some(0));
    }

    #[test]
    fn krp060_helper_detects_charter_id_diff() {
        let a = CompiledToken {
            charter_id: [1u8; 32],
            validators: vec![],
        };
        let b = CompiledToken {
            charter_id: [2u8; 32],
            validators: vec![],
        };
        let mut out = Vec::new();
        audit_determinism(&a, &b, &mut out);
        assert_eq!(codes(&out), vec!["KRP-060"]);
        assert_eq!(out[0].index, None);
    }

    // ── KRP-061 completeness ───────────────────────────────────────────────

    #[test]
    fn krp061_real_charter_complete_no_finding() {
        let mut out = Vec::new();
        audit(&healthy_charter(), &mut out);
        assert_eq!(count_code(&out, "KRP-061"), 0, "{out:?}");
    }

    #[test]
    fn krp061_length_mismatch_denies() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1), gov_mod(2, 1)], // 2 declared
        };
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", vec![Op::PushInt(1)], [9u8; 32])], // only 1 emitted
        };
        let mut out = Vec::new();
        audit_completeness(&charter, &compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-061"
            && f.severity == Severity::Deny
            && f.index.is_none()));
    }

    #[test]
    fn krp061_kind_mismatch_denies() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1)],
        };
        // Emitted kind claims "governance" for a declared Supply module.
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("governance", vec![Op::PushInt(1)], [9u8; 32])],
        };
        let mut out = Vec::new();
        audit_completeness(&charter, &compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-061"
            && f.severity == Severity::Deny
            && f.index == Some(0)
            && f.message.contains("compiled as")));
    }

    #[test]
    fn krp061_empty_program_denies() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1)],
        };
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", vec![], [9u8; 32])], // empty program
        };
        let mut out = Vec::new();
        audit_completeness(&charter, &compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-061"
            && f.severity == Severity::Deny
            && f.message.contains("empty")));
    }

    // ── KRP-062 budget ─────────────────────────────────────────────────────

    #[test]
    fn krp062_real_charter_within_budget_no_finding() {
        let mut out = Vec::new();
        audit(&healthy_charter(), &mut out);
        assert_eq!(count_code(&out, "KRP-062"), 0, "{out:?}");
    }

    #[test]
    fn krp062_oversized_program_denies_on_size() {
        // One giant PushBytes blows the per-validator size ceiling (gas stays tiny).
        let big = vec![Op::PushBytes(vec![0u8; 70_000])];
        assert!(program_bytes(&big) > MAX_VALIDATOR_BYTES);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", big, [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-062"
            && f.severity == Severity::Deny
            && f.message.contains("size budget")));
    }

    #[test]
    fn krp062_expensive_program_denies_on_gas() {
        // 2500 signature checks = 2_500_000 static gas > 2_000_000 ceiling (size tiny).
        let costly = vec![Op::VerifySig; 2_500];
        assert!(static_gas(&costly) > MAX_VALIDATOR_GAS);
        assert!(program_bytes(&costly) <= MAX_VALIDATOR_BYTES);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("governance", costly, [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-062"
            && f.severity == Severity::Deny
            && f.message.contains("gas budget")));
    }

    #[test]
    fn krp062_total_size_denies_even_when_each_is_within_per_validator_limit() {
        // 5 validators of 60_000-byte blobs: each < 64 KiB, but the set > 256 KiB.
        let one = |k| cm(k, vec![Op::PushBytes(vec![0u8; 60_000])], [1u8; 32]);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![
                one("supply"),
                one("supply"),
                one("supply"),
                one("supply"),
                one("supply"),
            ],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        // No per-validator size finding, exactly one total-size finding.
        assert!(out
            .iter()
            .all(|f| !(f.code == "KRP-062" && f.index.is_some())));
        assert!(out.iter().any(|f| f.code == "KRP-062"
            && f.index.is_none()
            && f.message.contains("total limit")));
    }

    // ── KRP-063 Supply hash == BLCH ────────────────────────────────────────

    #[test]
    fn krp063_real_supply_hash_is_nonzero_no_finding() {
        let mut out = Vec::new();
        audit(&healthy_charter(), &mut out);
        assert_eq!(count_code(&out, "KRP-063"), 0, "{out:?}");
    }

    #[test]
    fn krp063_zero_supply_hash_denies() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1)],
        };
        // Emitted Supply validator hash == BLCH (all-zero) ⇒ asset-id collision.
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", vec![Op::PushInt(1)], BLCH)],
        };
        let mut out = Vec::new();
        audit_supply_blch(&charter, &compiled, &mut out);
        assert_eq!(codes(&out), vec!["KRP-063"]);
        assert_eq!(out[0].severity, Severity::Deny);
        assert_eq!(out[0].module, Some("supply"));
    }

    #[test]
    fn krp063_zero_hash_on_non_supply_module_is_ignored() {
        // A non-Supply module with a zero hash is not an asset-id collision.
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![gov_mod(2, 1)],
        };
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("governance", vec![Op::PushInt(0)], BLCH)],
        };
        let mut out = Vec::new();
        audit_supply_blch(&charter, &compiled, &mut out);
        assert_eq!(count_code(&out, "KRP-063"), 0);
    }

    // ── KRP-064 always-true / neutered guard ───────────────────────────────

    #[test]
    fn krp064_healthy_charter_no_finding() {
        let mut out = Vec::new();
        audit(&healthy_charter(), &mut out);
        assert_eq!(count_code(&out, "KRP-064"), 0, "{out:?}");
    }

    #[test]
    fn krp064_governance_threshold_zero_denies() {
        // 0-of-2 governance authorizes any spend — real compile via audit().
        let charter = TokenCharter {
            token_name: b"ZEROGOV".to_vec(),
            modules: vec![gov_mod(2, 0)],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-064"
            && f.severity == Severity::Deny
            && f.module == Some("governance")
            && f.message.contains("threshold 0")));
    }

    #[test]
    fn krp064_governance_signer_count_truncation_denies() {
        // 254 signers ⇒ signer #1 Pick-depth wraps in u8 ⇒ neutered signature check.
        let charter = TokenCharter {
            token_name: b"BIGGOV".to_vec(),
            modules: vec![gov_mod(254, 254)],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-064"
            && f.severity == Severity::Deny
            && f.message.contains("Pick-depth")));
    }

    #[test]
    fn krp064_governance_253_signers_is_the_safe_boundary_no_truncation_finding() {
        let charter = TokenCharter {
            token_name: b"MAXGOV".to_vec(),
            modules: vec![gov_mod(MAX_GOVERNANCE_SIGNERS, 1)],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        assert!(!out
            .iter()
            .any(|f| f.code == "KRP-064" && f.message.contains("Pick-depth")));
    }

    #[test]
    fn krp064_constant_true_tail_denies() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1)],
        };
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", vec![Op::PushInt(1)], [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_neuter(&charter, &compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-064"
            && f.severity == Severity::Deny
            && f.message.contains("always-true")));
    }

    #[test]
    fn krp064_constant_false_tail_warns() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1)],
        };
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", vec![Op::PushInt(0)], [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_neuter(&charter, &compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-064"
            && f.severity == Severity::Warn
            && f.message.contains("dead guard")));
    }

    #[test]
    fn constant_tail_verdict_is_sound_on_real_emitters() {
        // Every real emitted program is input-dependent — none must read as constant.
        let ct = compile_charter(&healthy_charter());
        for v in &ct.validators {
            assert_eq!(
                constant_tail_verdict(&v.program),
                None,
                "real emitter '{}' wrongly flagged as constant",
                v.kind
            );
        }
    }

    /// K-4 regression: red before the fix (the old literal-`PushInt`-tail heuristic
    /// only matched a bare `PushInt`, so it missed the exact program the finding
    /// names), green after (the abstract interpreter folds `PushInt(0), PushInt(0),
    /// Lt, Not` all the way through and correctly reads the always-true verdict).
    /// `Governance { signers: [], threshold: 0 }` is NOT caught by
    /// `compile_governance`'s own fail-closed sentinel guard (that guard only fires
    /// when `!signers.is_empty() && threshold == 0`), so it compiles to a REAL
    /// program — the one case the finding calls out by name.
    #[test]
    fn krp064_bytecode_detector_catches_empty_signers_threshold_zero() {
        let program = ModuleKind::Governance(GovernanceConfig {
            signers: vec![],
            threshold: 0,
        })
        .compile();
        // Exactly the tail the finding describes: no literal PushInt in the last
        // slot, so the OLD heuristic returned None here. `Op` has no `PartialEq`,
        // so compare via the canonical encoding (same convention `validator_hash`
        // and the KRP-060 determinism check use).
        assert_eq!(
            encode_program(&program),
            encode_program(&[Op::ExpectDepth(1), Op::PushInt(0), Op::PushInt(0), Op::Lt, Op::Not])
        );
        assert_eq!(
            constant_tail_verdict(&program),
            Some(true),
            "the abstract interpreter must catch the always-true verdict expressed \
             through Lt/Not arithmetic, not just a literal PushInt tail"
        );
    }

    /// A second, independent shape that only arithmetic folding (not a literal
    /// tail) can catch: `Add`/`Sub`/`Mul`/`Swap`/`Dup`/`Pick`/`Eq` composed into a
    /// known constant, to make sure the interpreter generalizes beyond the one
    /// case above rather than special-casing `Governance`.
    #[test]
    fn constant_tail_verdict_folds_arithmetic_not_just_literals() {
        // (2*3 == 6) -> Not(0) -> 1 : always-true, expressed with Mul/Eq/Not, no
        // literal PushInt in the final slot.
        let always_true = vec![
            Op::PushInt(2),
            Op::PushInt(3),
            Op::Mul,   // [6]
            Op::PushInt(6),
            Op::Eq,    // [1]  (6 == 6)
            Op::PushInt(0),
            Op::Eq,    // [0]  (1 == 0)
            Op::Not,   // [1]  always-true
        ];
        assert_eq!(constant_tail_verdict(&always_true), Some(true));

        // Dup a known constant, then Sub it from itself: always zero, always-false.
        let always_false = vec![
            Op::PushInt(5), // [5]
            Op::Dup,        // [5, 5]
            Op::Sub,        // [5 - 5] = [0]
        ];
        assert_eq!(constant_tail_verdict(&always_false), Some(false));

        // Pick reaching into a known constant below the top (no Verify involved):
        // [9] --Dup--> [9,9] --PushInt(1)--> [9,9,1] --Pick(2)--> copies the bottom
        // 9 to the top: [9,9,1,9] --Add--> [9,9,10] --Drop,Drop--> [9] : known, truthy.
        let pick_through_constants = vec![
            Op::PushInt(9),
            Op::Dup,
            Op::PushInt(1),
            Op::Pick(2),
            Op::Add,
            Op::Drop,
            Op::Drop,
        ];
        assert_eq!(constant_tail_verdict(&pick_through_constants), Some(true));
    }

    /// A program that unconditionally `Verify`s a known-zero value must read as
    /// constant-false (it always aborts), even when nothing about the emitted
    /// `Op::Verify` was in scope for the old literal-tail heuristic (which bailed
    /// on ANY `Verify` in the whole program).
    #[test]
    fn constant_tail_verdict_catches_unconditional_verify_zero() {
        let program = vec![Op::PushInt(0), Op::Verify, Op::PushInt(1)];
        assert_eq!(
            constant_tail_verdict(&program),
            Some(false),
            "Verify on a known-zero constant always aborts: constant-false"
        );
    }

    /// A `Verify` fed by genuinely input-dependent data (e.g. a signature check)
    /// must still bail to `None` — the interpreter must not over-claim a verdict
    /// it cannot prove, preserving the "sound, not complete" contract.
    #[test]
    fn constant_tail_verdict_does_not_over_claim_through_verifysig_gated_verify() {
        let program = vec![
            Op::CtxField(0), // FIELD_SIGHASH (crate::modules), read as the sighash message
            Op::PushBytes(b"pk".to_vec()),
            Op::PushBytes(b"sig".to_vec()),
            Op::VerifySig,
            Op::Verify,
            Op::PushInt(1),
        ];
        assert_eq!(constant_tail_verdict(&program), None);
    }

    // ── cross-cutting: determinism of the audit itself + no-panic ───────────

    #[test]
    fn audit_output_is_byte_stable_across_runs() {
        let charter = healthy_charter();
        let mut a = Vec::new();
        let mut b = Vec::new();
        audit(&charter, &mut a);
        audit(&charter, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn audit_never_panics_on_degenerate_charters() {
        let charters = vec![
            // empty charter
            TokenCharter {
                token_name: vec![],
                modules: vec![],
            },
            // empty-signers governance, threshold 0 (0-of-0)
            TokenCharter {
                token_name: b"E".to_vec(),
                modules: vec![gov_mod(0, 0)],
            },
            // empty-signers governance, threshold 1 (unsatisfiable)
            TokenCharter {
                token_name: b"E".to_vec(),
                modules: vec![gov_mod(0, 1)],
            },
            // supply cap at the extreme
            TokenCharter {
                token_name: b"E".to_vec(),
                modules: vec![supply_mod(u64::MAX)],
            },
            // a big-but-not-truncating governance
            TokenCharter {
                token_name: b"E".to_vec(),
                modules: vec![gov_mod(200, 200)],
            },
        ];
        for c in &charters {
            let mut out = Vec::new();
            // Must return normally (no unwind) for any input.
            audit(c, &mut out);
        }
    }

    #[test]
    fn krp064_zero_of_zero_governance_denies_always_true() {
        // 0-of-0 governance: threshold 0 ⇒ always-true neuter must be flagged.
        let charter = TokenCharter {
            token_name: b"E".to_vec(),
            modules: vec![gov_mod(0, 0)],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-064" && f.severity == Severity::Deny));
    }

    // ═════════════════════════════════════════════════════════════════════
    // ADVERSARIAL + EDGE-CASE ADDITIONS (append-only; no rule-logic changes)
    // ═════════════════════════════════════════════════════════════════════

    // ── malformed / empty / degenerate charters: no panic ─────────────────

    #[test]
    fn adversarial_no_panic_on_massive_governance_5000_signers() {
        // Far beyond MAX_GOVERNANCE_SIGNERS; must deny (truncation), never panic,
        // and the u8 Pick-depth cast must not trip any arithmetic overflow.
        let charter = TokenCharter {
            token_name: b"HUGE".to_vec(),
            modules: vec![gov_mod(5_000, 5_000)],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-064"
            && f.severity == Severity::Deny
            && f.message.contains("Pick-depth")));
    }

    #[test]
    fn adversarial_no_panic_on_extreme_numeric_boundaries() {
        // 0, u64::MAX, i128::MIN/MAX, u32::MAX (the "negative-as-unsigned" cast of
        // -1i32), and empty pubkeys everywhere — none of this may panic.
        let charter = TokenCharter {
            token_name: vec![],
            modules: vec![
                supply_mod(0),
                supply_mod(u64::MAX),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: i128::MIN,
                    beneficiary_pubkey: vec![],
                }),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: i128::MAX,
                    beneficiary_pubkey: vec![],
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"a".to_vec(), b"b".to_vec()],
                    threshold: (-1i32) as u32, // u32::MAX via wraparound cast
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: vec![],
                    pq_pubkey: vec![],
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: vec![],
                }),
                gov_mod(0, 0),
            ],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out); // must return normally
        // threshold-0 governance among these must still be caught.
        assert!(out.iter().any(|f| f.code == "KRP-064" && f.message.contains("threshold 0")));
    }

    #[test]
    fn adversarial_no_panic_and_deterministic_on_one_hundred_mixed_modules() {
        // Scale + determinism together: 100 modules cycling through every kind.
        let mut modules = Vec::new();
        for i in 0..100usize {
            modules.push(match i % 6 {
                0 => supply_mod((i as u64) + 1),
                1 => ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: format!("auth{i}").into_bytes(),
                }),
                2 => ModuleKind::ComplianceKycGate(KycConfig::default()),
                3 => ModuleKind::Vesting(VestingConfig {
                    unlock_height: i as i128,
                    beneficiary_pubkey: format!("benef{i}").into_bytes(),
                }),
                4 => gov_mod(3, 2),
                _ => ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: format!("btc{i}").into_bytes(),
                    pq_pubkey: format!("pq{i}").into_bytes(),
                }),
            });
        }
        let charter = TokenCharter {
            token_name: b"HUNDRED".to_vec(),
            modules,
        };
        let mut a = Vec::new();
        let mut b = Vec::new();
        audit(&charter, &mut a); // must not panic
        audit(&charter, &mut b);
        assert_eq!(a, b, "audit must be byte-stable even at scale");
        assert!(a.is_empty(), "a well-formed 100-module charter must be clean: {a:?}");
    }

    // ── KRP-062 exact boundaries (the check is strictly `>`, so `==` is safe) ──

    #[test]
    fn krp062_validator_size_at_exact_limit_no_finding() {
        // encode_program(PushBytes(n)) == n + 5; pick n so total == MAX_VALIDATOR_BYTES.
        let payload = MAX_VALIDATOR_BYTES - 5;
        let program = vec![Op::PushBytes(vec![0u8; payload])];
        assert_eq!(program_bytes(&program), MAX_VALIDATOR_BYTES);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", program, [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        assert!(out.is_empty(), "exact-limit size must not deny: {out:?}");
    }

    #[test]
    fn krp062_validator_size_one_byte_over_limit_denies() {
        let payload = MAX_VALIDATOR_BYTES - 5 + 1;
        let program = vec![Op::PushBytes(vec![0u8; payload])];
        assert_eq!(program_bytes(&program), MAX_VALIDATOR_BYTES + 1);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("supply", program, [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-062"
            && f.index == Some(0)
            && f.message.contains("size budget")));
    }

    #[test]
    fn krp062_validator_gas_at_exact_limit_no_finding() {
        // 2000 VerifySig ops == exactly MAX_VALIDATOR_GAS (1000 each).
        let program = vec![Op::VerifySig; 2_000];
        assert_eq!(static_gas(&program), MAX_VALIDATOR_GAS);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("governance", program, [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        assert!(out.is_empty(), "exact-limit gas must not deny: {out:?}");
    }

    #[test]
    fn krp062_validator_gas_one_over_limit_denies() {
        let mut program = vec![Op::VerifySig; 2_000];
        program.push(Op::Dup); // +1 static gas
        assert_eq!(static_gas(&program), MAX_VALIDATOR_GAS + 1);
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("governance", program, [1u8; 32])],
        };
        let mut out = Vec::new();
        audit_budget(&compiled, &mut out);
        assert!(out.iter().any(|f| f.code == "KRP-062"
            && f.index == Some(0)
            && f.message.contains("gas budget")));
    }

    #[test]
    fn krp062_total_bytes_boundary_exact_vs_one_over() {
        let payload = MAX_VALIDATOR_BYTES - 5; // each validator == MAX_VALIDATOR_BYTES bytes
        let make = |n: usize| CompiledToken {
            charter_id: [0u8; 32],
            validators: (0..n)
                .map(|_| cm("supply", vec![Op::PushBytes(vec![0u8; payload])], [1u8; 32]))
                .collect(),
        };

        // 4 * MAX_VALIDATOR_BYTES == MAX_TOTAL_BYTES exactly.
        let exact = make(4);
        assert_eq!(
            exact.validators.iter().map(|v| program_bytes(&v.program)).sum::<usize>(),
            MAX_TOTAL_BYTES
        );
        let mut out_exact = Vec::new();
        audit_budget(&exact, &mut out_exact);
        assert!(out_exact.is_empty(), "exact total-bytes limit must not deny: {out_exact:?}");

        // A 5th, 1-byte validator pushes the total 1 byte over.
        let mut over = make(4);
        over.validators.push(cm("supply", vec![Op::Dup], [2u8; 32]));
        let mut out_over = Vec::new();
        audit_budget(&over, &mut out_over);
        assert!(
            out_over.iter().all(|f| f.index.is_none()),
            "no single validator exceeds the per-validator cap here: {out_over:?}"
        );
        assert!(out_over.iter().any(|f| f.code == "KRP-062"
            && f.index.is_none()
            && f.message.contains("total limit")
            && f.message.contains("bytes")));
    }

    #[test]
    fn krp062_total_gas_boundary_exact_vs_one_over() {
        let make = |n: usize| CompiledToken {
            charter_id: [0u8; 32],
            validators: (0..n)
                .map(|_| cm("governance", vec![Op::VerifySig; 2_000], [1u8; 32]))
                .collect(),
        };

        // 4 * MAX_VALIDATOR_GAS == MAX_TOTAL_GAS exactly.
        let exact = make(4);
        assert_eq!(
            exact.validators.iter().map(|v| static_gas(&v.program)).sum::<u64>(),
            MAX_TOTAL_GAS
        );
        let mut out_exact = Vec::new();
        audit_budget(&exact, &mut out_exact);
        assert!(out_exact.is_empty(), "exact total-gas limit must not deny: {out_exact:?}");

        // A 5th validator with 1 extra static-gas unit pushes the total 1 over.
        let mut over = make(4);
        over.validators.push(cm("governance", vec![Op::Dup], [2u8; 32]));
        let mut out_over = Vec::new();
        audit_budget(&over, &mut out_over);
        assert!(out_over.iter().any(|f| f.code == "KRP-062"
            && f.index.is_none()
            && f.message.contains("total limit")
            && f.message.contains("gas")));
    }

    // ── KRP-061: two independent defects on the same index both fire ──────

    #[test]
    fn krp061_kind_mismatch_and_empty_program_both_fire_for_same_index() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1)],
        };
        // Wrong kind AND empty program at index 0 — both defects are real and
        // independent; the rule must not short-circuit after the first.
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![cm("governance", vec![], [9u8; 32])],
        };
        let mut out = Vec::new();
        audit_completeness(&charter, &compiled, &mut out);
        assert_eq!(count_code(&out, "KRP-061"), 2, "{out:?}");
        assert!(out.iter().all(|f| f.index == Some(0)));
        assert!(out.iter().any(|f| f.message.contains("compiled as")));
        assert!(out.iter().any(|f| f.message.contains("empty")));
    }

    // ── KRP-063: independence across multiple Supply modules ──────────────

    #[test]
    fn krp063_multiple_supply_modules_are_checked_independently() {
        let charter = TokenCharter {
            token_name: b"X".to_vec(),
            modules: vec![supply_mod(1), gov_mod(1, 1), supply_mod(2)],
        };
        // Supply at 0 and 2 both collide with BLCH; the governance at 1 (also
        // zero-hash) must be ignored — only Supply modules are asset ids.
        let compiled = CompiledToken {
            charter_id: [0u8; 32],
            validators: vec![
                cm("supply", vec![Op::PushInt(1)], BLCH),
                cm("governance", vec![Op::PushInt(1)], BLCH),
                cm("supply", vec![Op::PushInt(1)], BLCH),
            ],
        };
        let mut out = Vec::new();
        audit_supply_blch(&charter, &compiled, &mut out);
        assert_eq!(count_code(&out, "KRP-063"), 2, "{out:?}");
        let indices: Vec<_> = out.iter().map(|f| f.index).collect();
        assert_eq!(indices, vec![Some(0), Some(2)]);
    }

    // ── KRP-064: documented sound-but-incomplete scope (not a bug) ─────────

    #[test]
    fn krp064_unsatisfiable_threshold_exceeding_signer_count_is_a_known_soundness_gap() {
        // threshold > signers.len() can never be met (structurally always-false),
        // but the compiled tail is `Not` over a runtime comparison, not a literal
        // `PushInt`, so `constant_tail_verdict` — sound-but-not-complete by design
        // — does not (and is not supposed to) catch it. This test documents the
        // boundary of the heuristic rather than asserting a finding.
        let charter = TokenCharter {
            token_name: b"E".to_vec(),
            modules: vec![gov_mod(2, (-1i32) as u32)], // threshold == u32::MAX
        };
        let mut out = Vec::new();
        audit(&charter, &mut out); // must not panic
        assert!(
            !out.iter().any(|f| f.code == "KRP-064" && f.message.contains("always-true")),
            "the runtime-constant (not literal-constant) always-false tail is out of \
             constant_tail_verdict's documented scope: {out:?}"
        );
    }

    // ── false-positive check: a large, diverse, well-formed charter ───────

    #[test]
    fn audit_diverse_clean_charter_has_zero_findings() {
        let charter = TokenCharter {
            token_name: b"DIVERSE".to_vec(),
            modules: vec![
                supply_mod(500),
                supply_mod(999_999),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"auth2".to_vec(),
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 10,
                    beneficiary_pubkey: b"benef2".to_vec(),
                }),
                gov_mod(5, 3),
                gov_mod(10, 10), // unanimous, but still well within budget/signer bounds
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc2".to_vec(),
                    pq_pubkey: b"pq2".to_vec(),
                }),
                gov_mod(MAX_GOVERNANCE_SIGNERS, 1), // right at the safe boundary
            ],
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        assert!(out.is_empty(), "expected zero findings on a clean diverse charter: {out:?}");
    }

    // ── determinism: multi-finding real charter, order + byte-stability ────

    #[test]
    fn audit_multi_governance_defect_findings_are_ordered_and_deterministic() {
        let charter = TokenCharter {
            token_name: b"MULTI".to_vec(),
            modules: vec![
                gov_mod(2, 0),     // idx0: threshold-0 always-true
                gov_mod(300, 300), // idx1: > MAX_GOVERNANCE_SIGNERS truncation
                gov_mod(5, 3),     // idx2: healthy, no finding
            ],
        };
        let mut a = Vec::new();
        let mut b = Vec::new();
        audit(&charter, &mut a);
        audit(&charter, &mut b);
        assert_eq!(a, b, "identical charter must yield byte-identical findings");
        // Each defective module now yields TWO KRP-064 findings: the config-level neuter
        // (Deny) plus the emitted-bytecode "dead guard" (Warn). Post-F6 the compiler fails
        // these charters closed to the unspendable `[PushInt(0)]` sentinel, which
        // `constant_tail_verdict` correctly reads as a compile-time constant FALSE verdict.
        assert_eq!(count_code(&a, "KRP-064"), 4, "{a:?}");
        // Charter-order preserved: both of idx0's findings precede both of idx1's, and
        // within a module the config-level Deny precedes the bytecode dead-guard Warn.
        assert_eq!(
            a.iter().map(|f| f.index).collect::<Vec<_>>(),
            vec![Some(0), Some(0), Some(1), Some(1)],
        );
        assert_eq!(a[0].severity, Severity::Deny);
        assert_eq!(a[1].severity, Severity::Warn);
        assert!(a[1].message.contains("dead guard"));
    }

    // ── cross-rule ordering: all five codes firing together ────────────────

    #[test]
    fn audit_synthetic_pipeline_fires_all_five_codes_in_ascending_order_and_is_reproducible() {
        // Crafted so each of the 5 lane rules fires exactly once, isolated to a
        // distinct index where possible, to pin down the *call* order audit()
        // uses internally (060, 061, 062, 063, 064) — a future reordering of
        // those calls in `audit` would break this test.
        let charter = TokenCharter {
            token_name: b"ALLFIVE".to_vec(),
            modules: vec![
                supply_mod(1),   // idx0
                gov_mod(1, 0),   // idx1: threshold-0 -> KRP-064 (charter-level check)
                supply_mod(1),   // idx2
            ],
        };
        let build_a = || CompiledToken {
            charter_id: [1u8; 32],
            validators: vec![
                cm("supply", vec![Op::VerifySig], BLCH), // idx0: kind/nonempty ok, size/gas ok, hash==BLCH -> KRP-063
                cm("governance", vec![], [2u8; 32]),      // idx1: empty program -> KRP-061
                cm("supply", vec![Op::PushBytes(vec![0u8; 70_000])], [5u8; 32]), // idx2: oversized -> KRP-062
            ],
        };
        let build_b = || CompiledToken {
            charter_id: [9u8; 32], // deliberately different id -> KRP-060 fires (charter-level)
            validators: vec![],
        };

        let run = || {
            let a = build_a();
            let b = build_b();
            let mut out = Vec::new();
            audit_determinism(&a, &b, &mut out); // KRP-060
            audit_completeness(&charter, &a, &mut out); // KRP-061
            audit_budget(&a, &mut out); // KRP-062
            audit_supply_blch(&charter, &a, &mut out); // KRP-063
            audit_neuter(&charter, &a, &mut out); // KRP-064
            out
        };

        let out1 = run();
        let out2 = run();
        assert_eq!(out1, out2, "the assembled pipeline must be byte-stable");
        assert_eq!(
            codes(&out1),
            vec!["KRP-060", "KRP-061", "KRP-062", "KRP-063", "KRP-064"],
            "{out1:?}"
        );
    }
}
