//! # modules — the Ustav MODULE COMPILER (charter → eUTXO validator set)
//!
//! **FOUNDATION / reference, unaudited, NOT consensus-wired.** This module builds a
//! deterministic compiler on top of the [`crate`] VM (`Op`, [`crate::validator_hash`],
//! [`crate::ExtOutput`], [`crate::Ctx`], [`crate::SigVerifier`]). It is the execution
//! substrate for **USTAV**, the modular-token standard on the Bloch base: an Ustav
//! token is an *ordered composition of modules*, and each module **is** an eUTXO
//! validator — a concrete `Vec<Op>` program with a stable `validator_hash` that guards
//! the token's outputs.
//!
//! ## What this file gives you
//!
//! - [`ModuleKind`] — the six first-class module kinds, each with a small typed config:
//!   * [`ModuleKind::Supply`]         → a **minting-policy** program (fixed cap +
//!     authorized issuer). Its hash IS the token's `AssetId` / policy id.
//!   * [`ModuleKind::TransferPolicy`] → a **spend validator** asserting an allow-gate
//!     (a freeze switch guarded by a transfer authority).
//!   * [`ModuleKind::ComplianceKycGate`] → a validator requiring a **membership
//!     assertion against a state root** (KYC registry inclusion).
//!   * [`ModuleKind::Vesting`]        → a **height-gated release** validator (reads a
//!     `ctx` height field, checked comparison) plus a beneficiary signature.
//!   * [`ModuleKind::Governance`]     → an **n-of-m multisig** over [`crate::Op::VerifySig`].
//!   * [`ModuleKind::Custody`]        → the **hybrid-PQ 2-of-2** pattern from `lib.rs`
//!     (a Bitcoin/ECDSA key AND a post-quantum key must both sign — the wBTC-PQ guard).
//! - [`TokenCharter`] — an ordered composition of modules for one token.
//! - [`compile_charter`] — deterministically emits the concrete validator programs and
//!   their hashes ([`CompiledToken`]).
//!
//! ## Determinism (sacred)
//!
//! Compilation is a pure function of the charter: same charter → **byte-identical**
//! program set, identical hashes, identical [`CompiledToken::charter_id`]; a charter
//! that differs in any config field → a different program and a different id. No
//! wall-clock, no float, no hash-map iteration order (module order is the charter's
//! `Vec` order; config fields are plain scalars/byte strings).
//!
//! ## Ctx layout convention (the contract between compiler and host)
//!
//! Auth/stateful validators read fixed `ctx.fields` slots. A host that runs an Ustav
//! validator MUST populate the [`Ctx`] this way (mirrors `lib.rs`'s `validate_tx`,
//! which already puts the sighash in `fields[0]`):
//!
//! | slot | meaning | used by |
//! |------|---------|---------|
//! | [`FIELD_SIGHASH`]  = 0 | the transaction sighash (Bytes) a signature signs | Supply, TransferPolicy, Vesting, Governance, Custody |
//! | [`FIELD_HEIGHT`]   = 1 | the current block height (Int) | Vesting |
//! | [`FIELD_KYC_ROOT`] = 2 | the KYC registry state root (Bytes) | ComplianceKycGate |
//!
//! ## Honest limits
//!
//! - Minting/state are composed **conceptually**: this file depends only on `lib.rs`.
//!   Cross-file wiring (into `validate_tx`, a real PQ verifier, a real KYC Merkle path)
//!   is deferred to the Integrate phase. The compiler emits the guard programs; it does
//!   not itself run consensus.
//! - The KYC gate models inclusion as a **single commitment** (`sha256d(witness) ==
//!   root`) because the opcode set has no byte-concatenation op, so a full Merkle path
//!   cannot be walked in-VM yet. A production gate iterates a path; the *shape* — "a
//!   validator that asserts membership against a state root read from ctx" — is exact.
//! - Unaudited reference. Designed ≠ built ≠ booted.

use crate::minting::{MINT_CTX_DELTA, MINT_CTX_PRIOR_SUPPLY, MINT_CTX_SIGHASH};
use crate::{validator_hash, Op};
use sha2::{Digest, Sha256};

/// `ctx.fields` slot holding the transaction sighash (Bytes) that a signature signs.
pub const FIELD_SIGHASH: u8 = 0;
/// `ctx.fields` slot holding the current block height (Int) — read by [`ModuleKind::Vesting`].
pub const FIELD_HEIGHT: u8 = 1;
/// `ctx.fields` slot holding the KYC registry state root (Bytes) — read by
/// [`ModuleKind::ComplianceKycGate`].
pub const FIELD_KYC_ROOT: u8 = 2;

// ─────────────────────────────────────────────────────────────────────────────
// Typed module configs
// ─────────────────────────────────────────────────────────────────────────────

/// **Supply** module config — a minting policy. `cap` is the hard maximum issuable in
/// one mint (a fixed cap); `issuer_pubkey` is the sole authorized issuer whose PQ
/// signature over the sighash the mint requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyConfig {
    /// Fixed maximum amount authorizable by a single mint spend.
    pub cap: u64,
    /// The authorized issuer's public key (PQ; verified via [`crate::SigVerifier`]).
    pub issuer_pubkey: Vec<u8>,
}

/// **TransferPolicy** module config — an allow-gate. When the guarded output's datum
/// carries `frozen == 1`, a spend requires a signature from `authority_pubkey`; when
/// `frozen == 0`, transfers pass freely. This is the freeze/allow switch a regulated
/// token needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPolicyConfig {
    /// The transfer authority whose signature lifts a freeze.
    pub authority_pubkey: Vec<u8>,
}

/// **ComplianceKycGate** module config. A spend must present a membership witness whose
/// `sha256d` equals the KYC registry root read from [`FIELD_KYC_ROOT`]. (Reference:
/// single-commitment inclusion — see the module-level honesty note.)
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct KycConfig {}

/// **Vesting** module config — a height-gated release. Funds unlock only once the
/// chain height (read from [`FIELD_HEIGHT`]) reaches `unlock_height`, and the release
/// additionally requires `beneficiary_pubkey`'s signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VestingConfig {
    /// Minimum block height at which the output becomes spendable.
    pub unlock_height: i128,
    /// The beneficiary who must sign the maturing spend.
    pub beneficiary_pubkey: Vec<u8>,
}

/// **Governance** module config — an n-of-m multisig. `signers` are the `m` member
/// public keys (order is significant: redeemer signature `i` is checked against
/// `signers[i]`); `threshold` is the `n` that must verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceConfig {
    /// The `m` member public keys.
    pub signers: Vec<Vec<u8>>,
    /// The `n` valid signatures required (`1..=signers.len()`).
    pub threshold: u32,
}

/// **Custody** module config — the hybrid-PQ 2-of-2 from `lib.rs`: BOTH a Bitcoin
/// (secp256k1/ECDSA) key and a post-quantum key must sign. This is the wBTC-PQ custody
/// guard (§5-sexies) the fixed script cannot express.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyConfig {
    /// The BTC key, verified via [`crate::Op::VerifyEcdsa`] / [`crate::SigVerifier::verify_ecdsa`].
    pub btc_pubkey: Vec<u8>,
    /// The post-quantum key, verified via [`crate::Op::VerifySig`].
    pub pq_pubkey: Vec<u8>,
}

/// The six first-class Ustav module kinds. Each compiles to a self-contained eUTXO
/// validator (`Vec<Op>`); a token's guard set is the ordered composition of its
/// modules' validators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Supply(SupplyConfig),
    TransferPolicy(TransferPolicyConfig),
    ComplianceKycGate(KycConfig),
    Vesting(VestingConfig),
    Governance(GovernanceConfig),
    Custody(CustodyConfig),
}

impl ModuleKind {
    /// A stable, human-readable tag for this kind — used in the charter-id preimage so
    /// two structurally identical programs from different kinds cannot collide.
    pub fn tag(&self) -> &'static str {
        match self {
            ModuleKind::Supply(_) => "supply",
            ModuleKind::TransferPolicy(_) => "transfer-policy",
            ModuleKind::ComplianceKycGate(_) => "kyc-gate",
            ModuleKind::Vesting(_) => "vesting",
            ModuleKind::Governance(_) => "governance",
            ModuleKind::Custody(_) => "custody",
        }
    }

    /// A 1-byte domain tag (also folded into the charter id).
    fn tag_byte(&self) -> u8 {
        match self {
            ModuleKind::Supply(_) => 0x01,
            ModuleKind::TransferPolicy(_) => 0x02,
            ModuleKind::ComplianceKycGate(_) => 0x03,
            ModuleKind::Vesting(_) => 0x04,
            ModuleKind::Governance(_) => 0x05,
            ModuleKind::Custody(_) => 0x06,
        }
    }

    /// Deterministically emit this module's concrete validator program.
    ///
    /// The emitted programs assume the `lib.rs` spend model: the stack is seeded
    /// `[datum, redeemer...]` and reads `ctx.fields` per the layout table above. Each
    /// program finishes with a single truthy/falsy `Int` on top.
    pub fn compile(&self) -> Vec<Op> {
        match self {
            ModuleKind::Supply(c) => compile_supply(c),
            ModuleKind::TransferPolicy(c) => compile_transfer_policy(c),
            ModuleKind::ComplianceKycGate(c) => compile_kyc(c),
            ModuleKind::Vesting(c) => compile_vesting(c),
            ModuleKind::Governance(c) => compile_governance(c),
            ModuleKind::Custody(c) => compile_custody(c),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-kind program emitters
//
// Stack discipline note: `crate::Op::Pick(n)` COPIES the element n slots below the top
// (Pick(0) == Dup) without consuming it, so a validator can read redeemer values that
// sit under the datum. Every emitter below is annotated with the stack it assumes.
// ─────────────────────────────────────────────────────────────────────────────

/// Supply → minting policy. Stack seed `[datum, requested:Int, sig:Bytes]`.
/// Asserts `requested <= cap`, then verifies the issuer signed the sighash.
fn compile_supply(c: &SupplyConfig) -> Vec<Op> {
    // ── HIGH severity fix, 2026-08-11 ────────────────────────────────────────
    //
    // The previous emitter gated on a `requested` value the SPENDER put in the
    // redeemer, and compared *that* to `cap`. Nothing bound `requested` to the
    // amount actually minted. Since this program's hash IS the token's asset id
    // and policy id (`CompiledToken::policy_id`), the real delta lives in
    // `ctx.fields[MINT_CTX_DELTA]` and the on-chain supply in
    // `MINT_CTX_PRIOR_SUPPLY` — and the compiled program read NEITHER. With
    // `cap = 1_000` an authorised issuer minted 1_000_000_000 in one spend,
    // 1e6x the advertised cap, by seeding `requested = 0`. Proven by
    // `tests/audit_modules_supply.rs`.
    //
    // The advertised property was "fixed maximum supply", so the gate must be
    // over TOTAL supply, not per-spend: `prior + delta <= cap`. That is exactly
    // `minting::fixed_supply_cap_policy`, whose contrast test in the same file
    // showed the mint machinery was never at fault — only this emitter. The two
    // are now the same check because a second way to express one rule is how
    // they drift apart.
    //
    // `cap` is pushed unmodified (never `cap + 1`) — the F3/F5 overflow lesson
    // from `fixed_supply_cap_policy`.
    //
    // Burns (negative delta) satisfy the cap for free, which is correct: a cap
    // bounds issuance, not destruction.
    vec![
        // Redeemer seed is `[sig]` and nothing else. `requested` is GONE: a
        // number the spender chooses cannot be an input to the rule that binds
        // the spender.
        Op::ExpectDepth(1),
        // total-supply gate: prior + delta <= cap  ==  not(cap < prior + delta)
        Op::PushInt(c.cap as i128),          // [sig, cap]
        Op::CtxField(MINT_CTX_PRIOR_SUPPLY), // [sig, cap, prior]
        Op::CtxField(MINT_CTX_DELTA),        // [sig, cap, prior, delta]
        Op::Add,                             // [sig, cap, new_supply]
        Op::Lt,                              // [sig, (cap < new_supply)]
        Op::Not,                             // [sig, (new_supply <= cap)]
        Op::Verify,                          // assert within cap: [sig]
        // issuer auth. Consumed by Swap rather than copied by Pick: with the
        // stack pinned at one element there is nothing to reach past, and a
        // program with no fixed offsets cannot be shifted at all.
        Op::CtxField(MINT_CTX_SIGHASH),         // [sig, msg]
        Op::Swap,                               // [msg, sig]
        Op::PushBytes(c.issuer_pubkey.clone()), // [msg, sig, issuer]
        Op::Swap,                               // [msg, issuer, sig]
        Op::VerifySig,                          // -> [verified]
    ]
}

/// TransferPolicy → allow-gate. Stack seed `[datum=frozen:Int, sig:Bytes]`.
/// Allowed iff `frozen == 0` OR the authority's signature verifies.
fn compile_transfer_policy(c: &TransferPolicyConfig) -> Vec<Op> {
    vec![
        // Seed is [frozen(datum), sig]. THIS pin is the freeze bypass fix: without
        // it, one padding value shifted Pick(2) off the datum and onto an
        // attacker-supplied slot, so a frozen output spent with no authority
        // signature (tests/audit_modules.rs).
        Op::ExpectDepth(2),
        // authority sig leg
        Op::CtxField(FIELD_SIGHASH),             // [frozen, sig, msg]
        Op::PushBytes(c.authority_pubkey.clone()), // [frozen, sig, msg, auth]
        Op::Pick(2),                             // copy sig: [.., auth, sig]
        Op::VerifySig,                           // [frozen, sig, sig_ok]
        // not-frozen leg: (frozen == 0)
        Op::Pick(2),                             // copy frozen: [frozen, sig, sig_ok, frozen]
        Op::Not,                                 // [frozen, sig, sig_ok, not_frozen]
        // allowed = sig_ok + not_frozen > 0
        Op::Add,                                 // [frozen, sig, sum]
        Op::PushInt(0),                          // [frozen, sig, sum, 0]
        Op::Swap,                                // [frozen, sig, 0, sum]
        Op::Lt,                                  // (0 < sum): [frozen, sig, allowed]
    ]
}

/// ComplianceKycGate → membership vs state root. Stack seed `[datum, witness:Bytes]`.
/// Passes iff `sha256d(witness) == ctx.fields[FIELD_KYC_ROOT]`.
fn compile_kyc(_c: &KycConfig) -> Vec<Op> {
    vec![
        // Seed is [datum, witness].
        Op::ExpectDepth(2),
        Op::Sha256d,                 // [d, sha256d(witness)]
        Op::CtxField(FIELD_KYC_ROOT), // [d, leaf_hash, root]
        Op::Eq,                      // [d, (leaf_hash == root)]
    ]
}

/// Vesting → height-gated release. Stack seed `[datum, sig:Bytes]`.
/// Asserts `height >= unlock_height` (read from ctx), then verifies the beneficiary sig.
fn compile_vesting(c: &VestingConfig) -> Vec<Op> {
    vec![
        // Seed is [datum, sig].
        Op::ExpectDepth(2),
        // height gate: height >= unlock  ==  not(height < unlock)
        Op::CtxField(FIELD_HEIGHT),  // [d, sig, height]
        Op::PushInt(c.unlock_height), // [d, sig, height, unlock]
        Op::Lt,                      // (height < unlock): [d, sig, (h<u)]
        Op::Not,                     // (height >= unlock): [d, sig, matured]
        Op::Verify,                  // assert matured: [d, sig]
        // beneficiary auth
        Op::CtxField(FIELD_SIGHASH),               // [d, sig, msg]
        Op::PushBytes(c.beneficiary_pubkey.clone()), // [d, sig, msg, benef]
        Op::Pick(2),                               // copy sig: [.., benef, sig]
        Op::VerifySig,                             // -> [d, sig, verified]
    ]
}

/// Governance → n-of-m multisig over [`crate::Op::VerifySig`].
/// Stack seed `[datum, sig_1, sig_2, ... sig_m]` (redeemer order matches `signers`).
/// Counts verifying signatures and asserts `count >= threshold`.
fn compile_governance(c: &GovernanceConfig) -> Vec<Op> {
    let m = c.signers.len();

    // ── Fail-closed compile-time guards ──────────────────────────────────────────
    // A charter that would emit a subtly-broken quorum program is refused by emitting
    // an UNSPENDABLE sentinel (`[PushInt(0)]`, which always evaluates false → the guard
    // authorizes no spend) rather than a program that silently mis-gates. Fail-closed:
    //
    //  * `threshold == 0` with real members → a "0-of-m" gate guards nothing (a spend
    //    needs zero valid signatures). The empty-signer degenerate case (m == 0) keeps
    //    its documented trivial behaviour and is not caught here.
    //  * duplicate signer pubkeys → one reused key/signature satisfies multiple slots,
    //    silently halving (or worse) the distinct keys a quorum actually requires.
    //  * `m > 253` → the first signer's Pick depth is `m + 2`; for m ≥ 254 that is ≥ 256
    //    and truncates in the `as u8` cast (256 → `Pick(0)` == `Dup`), making the guard
    //    check `verify(msg, pk, pk)` — a silent, un-surfaced liveness/censorship break.
    let has_dup_signer = {
        let mut seen = std::collections::BTreeSet::new();
        c.signers.iter().any(|pk| !seen.insert(pk.as_slice()))
    };
    if (!c.signers.is_empty() && c.threshold == 0) || has_dup_signer || m > 253 {
        return vec![Op::PushInt(0)]; // unspendable: always false, never authorizes a spend
    }

    let mut p = Vec::new();
    // Seed is [datum, sig_1..sig_m] — arity depends on the signer count, so the
    // pin does too. Every `Pick(depth)` below is computed from `m`, which makes
    // this module the one where a shifted stack does the most damage: pad the
    // redeemer and each signer's slot maps to the wrong value, so one attacker
    // blob can be verified against several signers' keys. Guarded above:
    // m <= 253, so `1 + m` fits a u8 with room to spare.
    p.push(Op::ExpectDepth((1 + m) as u8));
    // acc := 0  →  invariant per iteration: stack = [datum, sig_1..sig_m, acc]
    p.push(Op::PushInt(0));
    for (i0, pk) in c.signers.iter().enumerate() {
        // 1-based absolute index of this signer's sig on the stack.
        let i = i0 + 1;
        // At Pick time the stack is [datum, sigs.., acc, msg, pk]; the sig sits
        // (m + 3 - i) slots below the top (see module derivation). Guarded above:
        // m ≤ 253 ⇒ max depth (i == 1) is m + 2 ≤ 255, so the `as u8` cast is exact.
        let depth = (m + 3 - i) as u8;
        p.push(Op::CtxField(FIELD_SIGHASH)); // push msg
        p.push(Op::PushBytes(pk.clone())); // push signer pubkey
        p.push(Op::Pick(depth)); // copy this signer's sig to top
        p.push(Op::VerifySig); // -> 0/1 on top
        p.push(Op::Add); // fold into acc
    }
    // threshold: count >= n  ==  not(count < n)
    p.push(Op::PushInt(c.threshold as i128));
    p.push(Op::Lt); // (count < n)
    p.push(Op::Not); // (count >= n)
    p
}

/// Custody → hybrid-PQ 2-of-2. Stack seed `[datum, ecdsa_sig:Bytes, pq_sig:Bytes]`.
/// BOTH the BTC (ECDSA) and the PQ signature must verify.
fn compile_custody(c: &CustodyConfig) -> Vec<Op> {
    vec![
        // Seed is [datum, ecdsa_sig, pq_sig].
        Op::ExpectDepth(3),
        // ECDSA (BTC) leg — must pass
        Op::CtxField(FIELD_SIGHASH),        // [d, es, ps, msg]
        Op::PushBytes(c.btc_pubkey.clone()), // [d, es, ps, msg, btc]
        Op::Pick(3),                        // copy ecdsa_sig: [.., btc, es]
        Op::VerifyEcdsa,                    // [d, es, ps, ecdsa_ok]
        Op::Verify,                         // assert: [d, es, ps]
        // PQ leg — result is the validator's verdict
        Op::CtxField(FIELD_SIGHASH),        // [d, es, ps, msg]
        Op::PushBytes(c.pq_pubkey.clone()),  // [d, es, ps, msg, pq]
        Op::Pick(2),                        // copy pq_sig: [.., pq, ps]
        Op::VerifySig,                      // -> [d, es, ps, verified]
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Charter → CompiledToken
// ─────────────────────────────────────────────────────────────────────────────

/// A **TokenCharter** — the declarative spec of an Ustav token: a name plus an ordered
/// composition of modules. Compiling it yields the token's validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenCharter {
    /// The token's name / ticker (folded into the charter id for domain separation).
    pub token_name: Vec<u8>,
    /// The ordered modules that guard the token. Order is significant and preserved.
    pub modules: Vec<ModuleKind>,
}

/// One compiled module: its kind tag, the concrete validator program, and the program's
/// `validator_hash` (what an [`crate::ExtOutput::validator_hash`] would commit to).
///
/// (No `PartialEq`/`Eq`: `crate::Op` derives neither, so `Vec<Op>` cannot. Compare the
/// `validator_hash`, or `crate::encode_program(&program)`, instead.)
#[derive(Clone, Debug)]
pub struct CompiledModule {
    /// Stable human-readable kind tag (see [`ModuleKind::tag`]).
    pub kind: &'static str,
    /// The emitted validator program.
    pub program: Vec<Op>,
    /// `SHA-256d(encode_program(program))` — the validator's identity.
    pub validator_hash: [u8; 32],
}

/// The full result of compiling a charter: the ordered validator set plus a
/// `charter_id` that commits to the whole composition (name + every module's kind and
/// validator hash, in order).
///
/// (No `PartialEq`/`Eq`: it holds [`CompiledModule`]s, which carry `Vec<Op>`. Compare
/// `charter_id` for identity.)
#[derive(Clone, Debug)]
pub struct CompiledToken {
    /// A deterministic digest over the entire charter — same charter ⇒ same id.
    pub charter_id: [u8; 32],
    /// The compiled modules, in charter order.
    pub validators: Vec<CompiledModule>,
}

impl CompiledToken {
    /// The token's **policy id** (its native [`crate::AssetId`]): the validator hash of
    /// the first [`ModuleKind::Supply`] module, if any. In the eUTXO model an asset id
    /// *is* the hash of its minting policy, so a token's identity derives from its
    /// Supply module. `None` if the charter has no Supply module.
    pub fn policy_id(&self) -> Option<[u8; 32]> {
        self.validators
            .iter()
            .find(|m| m.kind == "supply")
            .map(|m| m.validator_hash)
    }
}

/// Deterministically compile a [`TokenCharter`] into its [`CompiledToken`] validator
/// set. Pure function of the charter: no clock, no float, no map iteration order.
///
/// # ⚠ Un-audited path — prefer [`compile_charter_audited`]
///
/// This function compiles **whatever it is handed**. It performs no charter-level
/// sanity checking at all: an ambiguous minting policy, an unsatisfiable governance
/// quorum (`threshold > signers.len()`), a permanently-locked custody leg, or a
/// module whose emitted program is structurally corrupt all compile happily into
/// validator hashes that then become an asset id ([`CompiledToken::policy_id`]) and
/// the addresses of real outputs. Those are exactly the defect classes the
/// [`crate::kirpich`] internal audit detects (see `src/kirpich.rs` and its four
/// analyses: `completeness`, `conflicts`, `emitted`, `params`), and a charter that
/// reaches production through this door has never been shown them.
///
/// The gate is deliberately **fail-closed but opt-in**: `kirpich.rs:16` records that
/// it never blocks this function, so existing downstream consumers keep compiling.
/// It is not `#[deprecated]` for that reason — the attribute would break their builds
/// over a policy choice, and it remains the right primitive for a caller that runs
/// [`crate::kirpich::kirpich_audit`] itself and wants the advisories rather than a
/// yes/no. **New code should call [`compile_charter_audited`]**, which runs the audit
/// first and refuses on any `Deny` finding, and only reach for this one deliberately.
pub fn compile_charter(charter: &TokenCharter) -> CompiledToken {
    let mut validators = Vec::with_capacity(charter.modules.len());

    // Charter-id preimage: domain tag ‖ len(name) ‖ name ‖ for each module: tag_byte ‖ validator_hash.
    let mut pre = Vec::new();
    pre.extend_from_slice(b"USTAV-CHARTER-v1");
    pre.extend_from_slice(&(charter.token_name.len() as u32).to_le_bytes());
    pre.extend_from_slice(&charter.token_name);

    for m in &charter.modules {
        let program = m.compile();
        let vh = validator_hash(&program);
        pre.push(m.tag_byte());
        pre.extend_from_slice(&vh);
        validators.push(CompiledModule {
            kind: m.tag(),
            program,
            validator_hash: vh,
        });
    }

    let charter_id = sha256d(&pre);
    CompiledToken {
        charter_id,
        validators,
    }
}

/// **Fail-closed audited compile.** Run the [`crate::kirpich`] internal audit over
/// `charter` *first*; if the audit denies (any [`crate::kirpich::Severity::Deny`]
/// finding), refuse to compile and return the full [`crate::kirpich::AuditReport`] as the
/// error. Otherwise compile exactly as [`compile_charter`] does.
///
/// This is the gated build entry point: a charter with a hard defect (an ambiguous
/// minting policy, an unsatisfiable quorum, a permanently-locked custody leg, a corrupt
/// emitted validator, …) never reaches the compiler. `Warn`/`Info` findings do not block
/// and are not surfaced on the `Ok` path; a caller that wants the advisories should call
/// [`crate::kirpich::kirpich_audit`] directly. [`compile_charter`] itself is left
/// untouched (un-audited) for callers that opt out of the gate.
pub fn compile_charter_audited(
    charter: &TokenCharter,
) -> Result<CompiledToken, crate::kirpich::AuditReport> {
    let report = crate::kirpich::kirpich_audit(charter);
    if report.denied {
        return Err(report);
    }
    Ok(compile_charter(charter))
}

/// SHA-256d (double SHA-256), matching the VM's [`crate::Op::Sha256d`] and
/// `validator_hash` convention.
fn sha256d(b: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(Sha256::digest(b));
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blch, spend, Ctx, ExtOutput, SigVerifier, Val, VmError};

    /// A mock verifier: accepts the exact (msg, pk, sig) PQ triples it was given, and
    /// accepts an ECDSA sig equal to `b"ECDSA:" ‖ pk` (same convention as lib.rs tests).
    struct MockVerifier {
        good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    }
    impl SigVerifier for MockVerifier {
        fn verify(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
            self.good.iter().any(|(m, p, s)| m == msg && p == pk && s == sig)
        }
        fn verify_ecdsa(&self, _msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
            let mut e = b"ECDSA:".to_vec();
            e.extend_from_slice(pk);
            sig == e.as_slice()
        }
    }

    const MSG: &[u8] = b"ustav-sighash";

    /// Build a Ctx with the standard Ustav field layout.
    /// Run a Supply program on the contract it actually has: a **minting policy**.
    ///
    /// Supply is not a spend validator and must not be exercised as one. Its stack
    /// seed is the redeemer alone (no datum), and its gate reads the mint context —
    /// `MINT_CTX_DELTA` and `MINT_CTX_PRIOR_SUPPLY`. The in-crate tests used to run
    /// it through `run_module`, which prepends a datum and supplies the *spend*
    /// context; that mismatch is the same confusion that let the cap gate read a
    /// redeemer-supplied `requested` for so long. `CompiledToken::policy_id` and the
    /// module docs are the authority: the hash of this program is the asset id.
    fn run_supply_policy(
        cm: &CompiledModule,
        redeemer: Vec<Val>,
        prior_supply: i128,
        delta: i128,
        v: &dyn SigVerifier,
    ) -> Result<bool, VmError> {
        let ctx = Ctx {
            fields: vec![
                Val::Bytes(MSG.to_vec()), // MINT_CTX_SIGHASH
                Val::Int(delta),          // MINT_CTX_DELTA
                Val::Int(0),              // MINT_CTX_HEIGHT
                Val::Int(prior_supply),   // MINT_CTX_PRIOR_SUPPLY
            ],
            ..Default::default()
        };
        let mut gas = 100_000;
        crate::run(&cm.program, redeemer, &ctx, v, &mut gas)
    }

    fn ctx_with(height: i128, kyc_root: Vec<u8>) -> Ctx {
        Ctx {
            fields: vec![
                Val::Bytes(MSG.to_vec()),  // FIELD_SIGHASH
                Val::Int(height),          // FIELD_HEIGHT
                Val::Bytes(kyc_root),      // FIELD_KYC_ROOT
            ],
            ..Default::default()
        }
    }

    /// Spend a compiled module as an ExtOutput carrying `datum`, with `redeemer`.
    fn run_module(
        cm: &CompiledModule,
        datum: Val,
        redeemer: Vec<Val>,
        ctx: &Ctx,
        v: &dyn SigVerifier,
    ) -> Result<bool, VmError> {
        let out = ExtOutput {
            value: blch(1000),
            validator_hash: cm.validator_hash,
            datum,
        };
        let mut gas = 100_000;
        spend(&out, &cm.program, redeemer, ctx, v, &mut gas)
    }

    fn ecdsa_sig(pk: &[u8]) -> Vec<u8> {
        let mut s = b"ECDSA:".to_vec();
        s.extend_from_slice(pk);
        s
    }

    // ── A representative full charter using all six kinds ──
    fn demo_charter() -> TokenCharter {
        TokenCharter {
            token_name: b"USTV".to_vec(),
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 1_000_000,
                    issuer_pubkey: b"issuer-pk".to_vec(),
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"authority-pk".to_vec(),
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 2_400,
                    beneficiary_pubkey: b"benef-pk".to_vec(),
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"g1".to_vec(), b"g2".to_vec(), b"g3".to_vec()],
                    threshold: 2,
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc-pk".to_vec(),
                    pq_pubkey: b"pq-pk".to_vec(),
                }),
            ],
        }
    }

    /// End-to-end: a charter compiles into one validator per module, each hash equals
    /// `validator_hash(program)`, and the Supply module defines the policy id.
    #[test]
    fn charter_compiles_to_validator_set() {
        let ct = compile_charter(&demo_charter());
        assert_eq!(ct.validators.len(), 6);
        let kinds: Vec<&str> = ct.validators.iter().map(|m| m.kind).collect();
        assert_eq!(
            kinds,
            vec!["supply", "transfer-policy", "kyc-gate", "vesting", "governance", "custody"]
        );
        for m in &ct.validators {
            assert_eq!(m.validator_hash, validator_hash(&m.program));
            assert!(!m.program.is_empty());
        }
        // policy id is the Supply validator's hash
        assert_eq!(ct.policy_id(), Some(ct.validators[0].validator_hash));
    }

    /// Determinism: the same charter compiles to a byte-identical program set, identical
    /// hashes, and an identical charter id — every time.
    #[test]
    fn determinism_same_charter_identical() {
        let a = compile_charter(&demo_charter());
        let b = compile_charter(&demo_charter());
        assert_eq!(a.charter_id, b.charter_id);
        assert_eq!(a.validators.len(), b.validators.len());
        for (x, y) in a.validators.iter().zip(b.validators.iter()) {
            assert_eq!(x.validator_hash, y.validator_hash);
            // byte-identical programs (via the canonical program encoding)
            assert_eq!(
                crate::encode_program(&x.program),
                crate::encode_program(&y.program)
            );
        }
    }

    /// Distinct charters → distinct charter ids AND the changed module's hash changes,
    /// while unrelated modules keep their hashes.
    #[test]
    fn distinct_charters_distinct_hashes() {
        let base = compile_charter(&demo_charter());

        // change only the Supply cap
        let mut c2 = demo_charter();
        c2.modules[0] = ModuleKind::Supply(SupplyConfig {
            cap: 999, // different
            issuer_pubkey: b"issuer-pk".to_vec(),
        });
        let alt = compile_charter(&c2);

        assert_ne!(base.charter_id, alt.charter_id);
        assert_ne!(base.validators[0].validator_hash, alt.validators[0].validator_hash);
        // untouched modules are unchanged
        for i in 1..6 {
            assert_eq!(base.validators[i].validator_hash, alt.validators[i].validator_hash);
        }

        // a different token_name alone also changes the id (domain separation)
        let mut c3 = demo_charter();
        c3.token_name = b"OTHER".to_vec();
        assert_ne!(base.charter_id, compile_charter(&c3).charter_id);

        // reordering modules changes the id (order is significant)
        let mut c4 = demo_charter();
        c4.modules.swap(1, 3);
        assert_ne!(base.charter_id, compile_charter(&c4).charter_id);
    }

    // ── Each emitted validator runs green on a representative spend (and rejects) ──

    #[test]
    fn supply_mint_within_cap_and_signed() {
        let cm = &compile_charter(&demo_charter()).validators[0];
        let issuer = b"issuer-pk".to_vec();
        let sig = b"issuer-sig".to_vec();
        let v = MockVerifier { good: vec![(MSG.to_vec(), issuer.clone(), sig.clone())] };
        let no = MockVerifier { good: vec![] };

        // The gate is over TOTAL supply, so it is the (prior, delta) pair that is
        // tested, never a number the spender writes in the redeemer. demo cap is
        // 1_000_000.
        assert_eq!(run_supply_policy(cm, vec![Val::Bytes(sig.clone())], 0, 500_000, &v), Ok(true));
        // Same delta, but on top of a supply that is already near the cap: the mint
        // that was fine from zero is now over. This is the property the old emitter
        // could not express at all, because it never saw prior supply.
        assert_eq!(
            run_supply_policy(cm, vec![Val::Bytes(sig.clone())], 600_000, 500_000, &v),
            Err(VmError::Assert)
        );
        // Single mint over the cap → cap gate asserts.
        assert_eq!(
            run_supply_policy(cm, vec![Val::Bytes(sig.clone())], 0, 2_000_000, &v),
            Err(VmError::Assert)
        );
        // Burns are always within cap: a cap bounds issuance, not destruction.
        assert_eq!(run_supply_policy(cm, vec![Val::Bytes(sig.clone())], 900_000, -100, &v), Ok(true));
        // Within cap but unauthorized issuer → false (not an abort: an unsigned mint
        // is a rejected mint, not a malformed one).
        assert_eq!(run_supply_policy(cm, vec![Val::Bytes(sig)], 0, 1, &no), Ok(false));
    }

    /// THE REGRESSION TEST for the HIGH finding. A redeemer value can no longer
    /// influence the cap gate, because there is no such value: the seed is `[sig]`
    /// and a padded redeemer is refused before any gate runs.
    #[test]
    fn supply_cap_cannot_be_bypassed_by_a_redeemer_supplied_amount() {
        let cm = &compile_charter(&demo_charter()).validators[0];
        let sig = b"issuer-sig".to_vec();
        let v = MockVerifier { good: vec![(MSG.to_vec(), b"issuer-pk".to_vec(), sig.clone())] };

        // The historical attack verbatim: seed `requested = 0` and mint 1e9 against a
        // cap of 1e6. It used to be AUTHORIZED. The extra redeemer slot now trips the
        // arity pin, and even if it did not, the gate reads the real delta.
        assert_eq!(
            run_supply_policy(cm, vec![Val::Int(0), Val::Bytes(sig.clone())], 0, 1_000_000_000, &v),
            Err(VmError::Assert)
        );
        // And with the honest arity, the over-cap delta is still refused — so the
        // rejection above is the cap doing its job, not merely the arity check.
        assert_eq!(
            run_supply_policy(cm, vec![Val::Bytes(sig)], 0, 1_000_000_000, &v),
            Err(VmError::Assert)
        );
    }

    #[test]
    fn transfer_policy_freeze_gate() {
        let cm = &compile_charter(&demo_charter()).validators[1];
        let ctx = ctx_with(0, vec![]);
        let auth = b"authority-pk".to_vec();
        let sig = b"auth-sig".to_vec();
        let v = MockVerifier { good: vec![(MSG.to_vec(), auth.clone(), sig.clone())] };
        let no = MockVerifier { good: vec![] };

        // frozen=0 (not frozen) → allowed regardless of sig
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(b"whatever".to_vec())], &ctx, &no),
            Ok(true)
        );
        // frozen=1 + valid authority sig → allowed
        assert_eq!(
            run_module(cm, Val::Int(1), vec![Val::Bytes(sig.clone())], &ctx, &v),
            Ok(true)
        );
        // frozen=1 + no authority sig → denied
        assert_eq!(
            run_module(cm, Val::Int(1), vec![Val::Bytes(sig)], &ctx, &no),
            Ok(false)
        );
    }

    #[test]
    fn kyc_membership_against_root() {
        let cm = &compile_charter(&demo_charter()).validators[2];
        let witness = b"member-42-leaf".to_vec();
        let root = sha256d(&witness).to_vec();
        let ctx = ctx_with(0, root);
        let noop = MockVerifier { good: vec![] };

        // witness whose hash matches the registry root → member
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(witness)], &ctx, &noop),
            Ok(true)
        );
        // non-member witness → rejected
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(b"not-a-member".to_vec())], &ctx, &noop),
            Ok(false)
        );
    }

    #[test]
    fn vesting_height_gate() {
        let cm = &compile_charter(&demo_charter()).validators[3]; // unlock_height 2400
        let benef = b"benef-pk".to_vec();
        let sig = b"benef-sig".to_vec();
        let v = MockVerifier { good: vec![(MSG.to_vec(), benef.clone(), sig.clone())] };

        // matured (height >= 2400) + valid beneficiary sig → true
        let ctx_ok = ctx_with(2_400, vec![]);
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(sig.clone())], &ctx_ok, &v),
            Ok(true)
        );
        // not matured (height < 2400) → height-gate assertion fires
        let ctx_early = ctx_with(2_399, vec![]);
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(sig.clone())], &ctx_early, &v),
            Err(VmError::Assert)
        );
        // matured but wrong beneficiary sig → false
        let no = MockVerifier { good: vec![] };
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(sig)], &ctx_ok, &no),
            Ok(false)
        );
    }

    #[test]
    fn governance_2_of_3() {
        let cm = &compile_charter(&demo_charter()).validators[4]; // 2-of-3 over g1,g2,g3
        let ctx = ctx_with(0, vec![]);
        let (g1, s1) = (b"g1".to_vec(), b"s1".to_vec());
        let (g2, s2) = (b"g2".to_vec(), b"s2".to_vec());
        let (g3, s3) = (b"g3".to_vec(), b"s3".to_vec());

        // redeemer is [sig_1, sig_2, sig_3] aligned with signers order
        let red = || vec![Val::Bytes(s1.clone()), Val::Bytes(s2.clone()), Val::Bytes(s3.clone())];

        // 2 valid (g1, g3) → true
        let v2 = MockVerifier {
            good: vec![(MSG.to_vec(), g1.clone(), s1.clone()), (MSG.to_vec(), g3.clone(), s3.clone())],
        };
        assert_eq!(run_module(cm, Val::Int(0), red(), &ctx, &v2), Ok(true));

        // only 1 valid (g2) → false
        let v1 = MockVerifier { good: vec![(MSG.to_vec(), g2.clone(), s2.clone())] };
        assert_eq!(run_module(cm, Val::Int(0), red(), &ctx, &v1), Ok(false));

        // all 3 valid → still true (>= 2)
        let v3 = MockVerifier {
            good: vec![
                (MSG.to_vec(), g1.clone(), s1.clone()),
                (MSG.to_vec(), g2.clone(), s2.clone()),
                (MSG.to_vec(), g3.clone(), s3.clone()),
            ],
        };
        assert_eq!(run_module(cm, Val::Int(0), red(), &ctx, &v3), Ok(true));
    }

    #[test]
    fn custody_hybrid_pq_2_of_2() {
        let cm = &compile_charter(&demo_charter()).validators[5];
        let ctx = ctx_with(0, vec![]);
        let btc = b"btc-pk".to_vec();
        let pq = b"pq-pk".to_vec();
        let pq_sig = b"pq-sig".to_vec();
        let btc_sig = ecdsa_sig(&btc);

        // redeemer = [ecdsa_sig, pq_sig]
        let v = MockVerifier { good: vec![(MSG.to_vec(), pq.clone(), pq_sig.clone())] };
        // both good → spend
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(btc_sig.clone()), Val::Bytes(pq_sig.clone())], &ctx, &v),
            Ok(true)
        );
        // PQ sig missing → the AND fails (false)
        let no_pq = MockVerifier { good: vec![] };
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(btc_sig), Val::Bytes(pq_sig.clone())], &ctx, &no_pq),
            Ok(false)
        );
        // BTC sig wrong → the ECDSA assertion fires
        assert_eq!(
            run_module(cm, Val::Int(0), vec![Val::Bytes(b"bad-ecdsa".to_vec()), Val::Bytes(pq_sig)], &ctx, &v),
            Err(VmError::Assert)
        );
    }

    /// Governance emitter is correct for other (n, m) shapes too — a 3-of-5.
    #[test]
    fn governance_3_of_5_shape() {
        let signers: Vec<Vec<u8>> = (1..=5).map(|i| vec![b'k', b'0' + i]).collect();
        let ct = compile_charter(&TokenCharter {
            token_name: b"GOV".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: signers.clone(),
                threshold: 3,
            })],
        });
        let cm = &ct.validators[0];
        let ctx = ctx_with(0, vec![]);
        let sigs: Vec<Vec<u8>> = (1..=5).map(|i| vec![b's', b'0' + i]).collect();
        let redeemer: Vec<Val> = sigs.iter().cloned().map(Val::Bytes).collect();

        // exactly 3 valid (signers 0,2,4) → true
        let good = MockVerifier {
            good: vec![
                (MSG.to_vec(), signers[0].clone(), sigs[0].clone()),
                (MSG.to_vec(), signers[2].clone(), sigs[2].clone()),
                (MSG.to_vec(), signers[4].clone(), sigs[4].clone()),
            ],
        };
        assert_eq!(run_module(cm, Val::Int(0), redeemer.clone(), &ctx, &good), Ok(true));

        // only 2 valid → false
        let two = MockVerifier {
            good: vec![
                (MSG.to_vec(), signers[1].clone(), sigs[1].clone()),
                (MSG.to_vec(), signers[3].clone(), sigs[3].clone()),
            ],
        };
        assert_eq!(run_module(cm, Val::Int(0), redeemer, &ctx, &two), Ok(false));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Adversarial + property tests (added without touching module logic).
    // ─────────────────────────────────────────────────────────────────────
    // These probe: determinism, gas bounds, fail-closed behaviour on malformed
    // input, conservation-style invariants, no-panic on edge cases — and, in the
    // process, surface two real defects in `compile_governance` (see the two
    // `governance_pick_depth_*` tests and the doc comments on each).
    // ─────────────────────────────────────────────────────────────────────────

    /// REGRESSION (F6 fixed): `compile_governance` used to compute each signer's stack
    /// depth as `(m + 3 - i) as u8`. For the first signer of a charter with `m >= 254`
    /// members that depth is `m + 2 >= 256`, which silently wrapped in the `as u8` cast
    /// (`256 as u8 == 0`); `Pick(0)` is `Dup`, so the guard checked `verify(msg, pk, pk)`
    /// — an un-surfaced liveness break where a fully, correctly signed unanimous
    /// redeemer could never spend.
    ///
    /// Fixed: `m > 253` now fails closed at compile time, emitting the unspendable
    /// sentinel `[PushInt(0)]`. The defect can no longer masquerade as a working guard —
    /// the module is an explicit no-op-deny, and this test fails if truncation returns.
    #[test]
    fn governance_pick_depth_u8_truncation_bug_m254_unanimous_fails() {
        let m = 254usize;
        let signers: Vec<Vec<u8>> = (0..m).map(|i| format!("signer-{i:04}").into_bytes()).collect();
        let ct = compile_charter(&TokenCharter {
            token_name: b"BIGGOV".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: signers.clone(),
                threshold: m as u32, // unanimous: every signer must be valid
            })],
        });
        let cm = &ct.validators[0];
        let ctx = ctx_with(0, vec![]);

        // The compiler fails closed: an m=254 governance is an unspendable sentinel,
        // NOT a truncated Pick(0) program masquerading as a real quorum.
        assert_eq!(cm.program.len(), 1, "fail-closed governance is a single-op sentinel");
        assert!(
            matches!(cm.program[0], Op::PushInt(0)),
            "expected the fail-closed PushInt(0) sentinel, got {:?}",
            cm.program[0]
        );

        // Even a fully, correctly signed unanimous redeemer cannot spend it (by design).
        let sigs: Vec<Vec<u8>> = (0..m).map(|i| format!("sig-{i:04}").into_bytes()).collect();
        let redeemer: Vec<Val> = sigs.iter().cloned().map(Val::Bytes).collect();
        let good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = signers
            .iter()
            .cloned()
            .zip(sigs.iter().cloned())
            .map(|(pk, sig)| (MSG.to_vec(), pk, sig))
            .collect();
        let v = MockVerifier { good };

        let mut gas = 10_000_000;
        let out = ExtOutput { value: blch(1000), validator_hash: cm.validator_hash, datum: Val::Int(0) };
        let result = spend(&out, &cm.program, redeemer, &ctx, &v, &mut gas);
        assert_eq!(
            result,
            Ok(false),
            "fail-closed m=254 governance must authorize no spend (unspendable sentinel)"
        );
    }

    /// REGRESSION (F6 fixed), shown directly on the emitted bytecode: a charter that
    /// would need an un-representable Pick depth (`m + 2 = 256` for signer #1 when
    /// `m == 254`) no longer emits a silently-wrapped `Op::Pick(0)`. Instead the
    /// compiler fails closed and emits exactly the unspendable `[PushInt(0)]` sentinel.
    #[test]
    fn governance_pick_depth_truncation_visible_in_bytecode() {
        let m = 254usize;
        let signers: Vec<Vec<u8>> = (0..m).map(|i| format!("s{i}").into_bytes()).collect();
        let program = compile_governance(&GovernanceConfig { signers, threshold: 1 });
        // Fail-closed: bytecode == vec![PushInt(0)] (Op has no PartialEq, so match).
        assert_eq!(program.len(), 1, "fail-closed governance emits a single-op sentinel");
        assert!(
            matches!(program[0], Op::PushInt(0)),
            "expected the fail-closed PushInt(0) sentinel, got {:?}",
            program[0]
        );
    }

    /// REGRESSION (F6 fixed): `compile_governance` used to accept duplicate `signers`,
    /// so ONE real signature — reused across both of a key's redeemer slots — counted
    /// twice toward the threshold, silently halving the distinct keys a quorum needs.
    /// Fixed: a charter with any repeated signer pubkey compiles fail-closed
    /// (unspendable `[PushInt(0)]`), so a single reused key can no longer forge quorum.
    #[test]
    fn governance_duplicate_signer_pubkey_lets_one_key_satisfy_two_slots() {
        let shared = b"shared-key".to_vec();
        let other = b"other-key".to_vec();
        let ct = compile_charter(&TokenCharter {
            token_name: b"DUPGOV".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![shared.clone(), shared.clone(), other.clone()], // shared listed twice
                threshold: 2,
            })],
        });
        let cm = &ct.validators[0];
        let ctx = ctx_with(0, vec![]);
        let sig = b"shared-sig".to_vec();
        // Only ONE distinct key ever signs; `other` never does.
        let v = MockVerifier { good: vec![(MSG.to_vec(), shared, sig.clone())] };
        let redeemer = vec![Val::Bytes(sig.clone()), Val::Bytes(sig), Val::Bytes(b"unused".to_vec())];
        // Fail-closed: the duplicate-signer charter authorizes no spend.
        assert_eq!(run_module(cm, Val::Int(0), redeemer, &ctx, &v), Ok(false));
    }

    /// REGRESSION (F6 fixed): `threshold == 0` on a governance with real members used to
    /// pass unconditionally (running count is always `>= 0`) — a "0-of-m" gate that
    /// guards nothing. Fixed: a zero threshold with a non-empty signer set compiles
    /// fail-closed (unspendable `[PushInt(0)]`); no spend is authorized. (The `m == 0`
    /// empty-signer degenerate case keeps its documented trivial behaviour — see
    /// `governance_empty_signers_no_panic_and_threshold_gates_correctly`.)
    #[test]
    fn governance_zero_threshold_always_passes_even_with_zero_valid_signatures() {
        let ct = compile_charter(&TokenCharter {
            token_name: b"ZEROGOV".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g1".to_vec(), b"g2".to_vec()],
                threshold: 0,
            })],
        });
        let cm = &ct.validators[0];
        let ctx = ctx_with(0, vec![]);
        let no = MockVerifier { good: vec![] };
        let redeemer = vec![Val::Bytes(b"bad1".to_vec()), Val::Bytes(b"bad2".to_vec())];
        assert_eq!(run_module(cm, Val::Int(0), redeemer, &ctx, &no), Ok(false));
    }

    /// `m == 0` (no signers at all) must not panic, and the threshold still gates
    /// correctly: `threshold == 0` passes trivially, `threshold >= 1` can never
    /// pass since the running count can never move off zero.
    #[test]
    fn governance_empty_signers_no_panic_and_threshold_gates_correctly() {
        let ctx = ctx_with(0, vec![]);
        let noop = MockVerifier { good: vec![] };

        let ct0 = compile_charter(&TokenCharter {
            token_name: b"EMPTYGOV0".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig { signers: vec![], threshold: 0 })],
        });
        assert_eq!(run_module(&ct0.validators[0], Val::Int(0), vec![], &ctx, &noop), Ok(true));

        let ct1 = compile_charter(&TokenCharter {
            token_name: b"EMPTYGOV1".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig { signers: vec![], threshold: 1 })],
        });
        assert_eq!(run_module(&ct1.validators[0], Val::Int(0), vec![], &ctx, &noop), Ok(false));
    }

    /// Fail-closed, not panicking: a validator that reads a `ctx.fields` slot the
    /// host never populated must surface `VmError::BadCtxField`, never crash.
    #[test]
    fn kyc_ctx_missing_root_field_is_fail_closed_not_panic() {
        let cm = &compile_charter(&demo_charter()).validators[2];
        let noop = MockVerifier { good: vec![] };
        let bare_ctx = Ctx::default(); // fields = vec![] — no FIELD_KYC_ROOT slot
        let res = run_module(cm, Val::Int(0), vec![Val::Bytes(b"anything".to_vec())], &bare_ctx, &noop);
        assert_eq!(res, Err(VmError::BadCtxField(FIELD_KYC_ROOT)));
    }

    #[test]
    fn vesting_ctx_missing_height_field_is_fail_closed_not_panic() {
        let cm = &compile_charter(&demo_charter()).validators[3];
        let noop = MockVerifier { good: vec![] };
        let bare_ctx = Ctx::default(); // fields = vec![] — no FIELD_HEIGHT slot
        let res = run_module(cm, Val::Int(0), vec![Val::Bytes(b"sig".to_vec())], &bare_ctx, &noop);
        assert_eq!(res, Err(VmError::BadCtxField(FIELD_HEIGHT)));
    }

    /// Fail-closed on a type-confused redeemer: `requested` must be `Int`; supplying
    /// `Bytes` must surface `VmError::TypeError`, never panic or silently coerce.
    #[test]
    fn supply_wrong_redeemer_type_fails_closed_with_type_error_not_panic() {
        let cm = &compile_charter(&demo_charter()).validators[0];
        let no = MockVerifier { good: vec![] };
        // The old version fed a Bytes where the emitter expected the `requested` Int.
        // That slot no longer exists — the cap gate reads the mint context. What
        // remains type-confusable is the signature slot, so that is what is pinned:
        // an Int where VerifySig wants Bytes must surface a TypeError, never a panic.
        assert_eq!(
            run_supply_policy(cm, vec![Val::Int(7)], 0, 1, &no),
            Err(VmError::TypeError("expected Bytes"))
        );
    }

    /// Fail-closed on a type-confused witness: the KYC witness must be `Bytes` (fed
    /// to `Sha256d`); an `Int` must surface `VmError::TypeError`, not panic.
    #[test]
    fn kyc_wrong_witness_type_fails_closed_with_type_error_not_panic() {
        let cm = &compile_charter(&demo_charter()).validators[2];
        let ctx = ctx_with(0, sha256d(b"root").to_vec());
        let noop = MockVerifier { good: vec![] };
        let res = run_module(cm, Val::Int(0), vec![Val::Int(42)], &ctx, &noop);
        assert_eq!(res, Err(VmError::TypeError("expected Bytes")));
    }

    /// Gas exhaustion must fail closed with `VmError::OutOfGas` for every module
    /// kind — never panic, never silently authorize a spend.
    #[test]
    fn gas_exhaustion_is_fail_closed_not_panic_for_every_module_kind() {
        let ct = compile_charter(&demo_charter());
        let ctx = ctx_with(2_400, sha256d(b"member").to_vec());
        let v = MockVerifier { good: vec![] };
        // Supply is checked separately below: it is a minting policy, so running it
        // through `spend()` seeds it with a datum it does not take and the arity pin
        // aborts before gas is the binding constraint. Testing it on the wrong
        // contract is what let its cap gate stay broken.
        let redeemers: Vec<Vec<Val>> = vec![
            vec![Val::Bytes(b"s".to_vec())],
            vec![Val::Bytes(b"member".to_vec())],
            vec![Val::Bytes(b"s".to_vec())],
            vec![Val::Bytes(b"s1".to_vec()), Val::Bytes(b"s2".to_vec()), Val::Bytes(b"s3".to_vec())],
            vec![Val::Bytes(b"e".to_vec()), Val::Bytes(b"p".to_vec())],
        ];
        {
            let cm = &ct.validators[0];
            let mut gas = 1;
            let res = crate::run(&cm.program, vec![Val::Bytes(b"s".to_vec())], &ctx, &v, &mut gas);
            assert_eq!(res, Err(VmError::OutOfGas), "supply: expected OutOfGas, got {res:?}");
        }
        for (cm, redeemer) in ct.validators.iter().skip(1).zip(redeemers.into_iter()) {
            let out = ExtOutput { value: blch(1000), validator_hash: cm.validator_hash, datum: Val::Int(0) };
            let mut gas = 1; // below even the cheapest single op in these programs
            let res = spend(&out, &cm.program, redeemer, &ctx, &v, &mut gas);
            assert_eq!(res, Err(VmError::OutOfGas), "{}: expected OutOfGas, got {:?}", cm.kind, res);
        }
    }

    /// Gas bounds + determinism: each module's compiled program consumes an exact,
    /// input-independent amount of gas (a regression guard against an accidental
    /// stray/expensive op sneaking into an emitter), and running the same spend
    /// twice consumes byte-identical gas every time.
    #[test]
    fn gas_cost_is_deterministic_and_matches_formula_for_each_module() {
        let ct = compile_charter(&demo_charter());
        let ctx = ctx_with(2_400, sha256d(b"member").to_vec());
        let v = MockVerifier {
            good: vec![
                (MSG.to_vec(), b"issuer-pk".to_vec(), b"s".to_vec()),
                (MSG.to_vec(), b"authority-pk".to_vec(), b"s".to_vec()),
                (MSG.to_vec(), b"benef-pk".to_vec(), b"s".to_vec()),
                (MSG.to_vec(), b"g1".to_vec(), b"s1".to_vec()),
                (MSG.to_vec(), b"g2".to_vec(), b"s2".to_vec()),
                (MSG.to_vec(), b"pq-pk".to_vec(), b"pqsig".to_vec()),
            ],
        };
        // Expected gas reflects the F2 length-proportional model (op_gas): base cost +
        // one gas per 32-byte word of the operand each op copies/hashes. Copying a Bytes
        // operand (PushBytes/Pick of a pubkey or sig) now costs +1 word over the old flat
        // model, so every signature-bearing module is a few gas dearer than the pre-F2
        // baseline — an exact, input-independent regression guard against stray ops.
        // The `+ D` on every line is the arity pin (`Op::ExpectDepth`) that now leads
        // every emitted program — one unit, charged once, named rather than folded
        // into the totals so the next reader can see what it is.
        const D: u64 = 1;
        let cases: Vec<(usize, Vec<Val>, u64)> = vec![
            (1, vec![Val::Bytes(b"s".to_vec())], 1014 + D),                // transfer-policy
            (2, vec![Val::Bytes(b"member".to_vec())], 63 + D),             // kyc-gate
            (3, vec![Val::Bytes(b"s".to_vec())], 1010 + D),                // vesting
            (
                4,
                vec![Val::Bytes(b"s1".to_vec()), Val::Bytes(b"s2".to_vec()), Val::Bytes(b"s3".to_vec())],
                1009 * 3 + 4 + D, // governance, m=3
            ),
            (5, vec![Val::Bytes(ecdsa_sig(b"btc-pk")), Val::Bytes(b"pqsig".to_vec())], 2011 + D), // custody
        ];
        {
            // Supply on its real contract (see `run_supply_policy`). Two runs, same
            // input: gas must be identical, and independent of the mint amounts.
            let cm = &ct.validators[0];
            let mut used = Vec::new();
            for delta in [1i128, 999_999] {
                let mctx = Ctx {
                    fields: vec![
                        Val::Bytes(MSG.to_vec()),
                        Val::Int(delta),
                        Val::Int(0),
                        Val::Int(0),
                    ],
                    ..Default::default()
                };
                let mut gas = 1_000_000;
                let _ = crate::run(&cm.program, vec![Val::Bytes(b"s".to_vec())], &mctx, &v, &mut gas);
                used.push(1_000_000 - gas);
            }
            assert_eq!(used[0], used[1], "supply: gas must not depend on the mint amount");
            assert_eq!(used[0], 1016, "supply: gas-cost formula regression");
        }
        for (idx, redeemer, expected_gas) in cases {
            let cm = &ct.validators[idx];
            for _ in 0..2 {
                // same input, run twice — gas consumption must be identical every time.
                let out = ExtOutput { value: blch(1000), validator_hash: cm.validator_hash, datum: Val::Int(0) };
                let mut gas = 1_000_000;
                let _ = spend(&out, &cm.program, redeemer.clone(), &ctx, &v, &mut gas);
                let used = 1_000_000 - gas;
                assert_eq!(used, expected_gas, "{}: gas-cost formula regression", cm.kind);
            }
        }
    }

    /// Supply's cap gate at its exact boundary: `requested == cap` passes (`<=`),
    /// `requested == cap + 1` asserts — across cap values from `0` to `u64::MAX`
    /// (checking the `cap as i128` cast doesn't misbehave at the extreme).
    #[test]
    fn property_supply_cap_boundary_exact() {
        for cap in [0u64, 1, 1_000_000, u64::MAX] {
            let ct = compile_charter(&TokenCharter {
                token_name: b"CAPT".to_vec(),
                modules: vec![ModuleKind::Supply(SupplyConfig { cap, issuer_pubkey: b"iss".to_vec() })],
            });
            let cm = &ct.validators[0];
            let v = MockVerifier { good: vec![(MSG.to_vec(), b"iss".to_vec(), b"sig".to_vec())] };
            let sig = || vec![Val::Bytes(b"sig".to_vec())];

            // new_supply == cap passes (the gate is `<=`), reached from zero...
            assert_eq!(
                run_supply_policy(cm, sig(), 0, cap as i128, &v),
                Ok(true),
                "cap={cap}: new_supply==cap should pass"
            );
            // ...and reached incrementally, which is the case the per-spend gate
            // could never see: prior already at cap-1, one more unit lands exactly on.
            if cap > 0 {
                assert_eq!(
                    run_supply_policy(cm, sig(), cap as i128 - 1, 1, &v),
                    Ok(true),
                    "cap={cap}: prior+delta==cap should pass"
                );
            }
            if cap < u64::MAX {
                assert_eq!(
                    run_supply_policy(cm, sig(), 0, cap as i128 + 1, &v),
                    Err(VmError::Assert),
                    "cap={cap}: new_supply==cap+1 must assert"
                );
                // The incremental overshoot too — one unit past a full supply.
                assert_eq!(
                    run_supply_policy(cm, sig(), cap as i128, 1, &v),
                    Err(VmError::Assert),
                    "cap={cap}: minting on top of a full supply must assert"
                );
            }
        }
    }

    #[test]
    fn property_governance_result_matches_signature_count_over_all_subsets() {
        let signers: Vec<Vec<u8>> = (0..5).map(|i| format!("g{i}").into_bytes()).collect();
        let sigs: Vec<Vec<u8>> = (0..5).map(|i| format!("s{i}").into_bytes()).collect();
        for threshold in 0..=5u32 {
            let ct = compile_charter(&TokenCharter {
                token_name: b"PROPGOV".to_vec(),
                modules: vec![ModuleKind::Governance(GovernanceConfig { signers: signers.clone(), threshold })],
            });
            let cm = &ct.validators[0];
            let ctx = ctx_with(0, vec![]);
            for mask in 0u32..32 {
                let good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (0..5)
                    .filter(|i| mask & (1 << i) != 0)
                    .map(|i| (MSG.to_vec(), signers[i].clone(), sigs[i].clone()))
                    .collect();
                let count = good.len() as u32;
                let v = MockVerifier { good };
                let redeemer: Vec<Val> = sigs.iter().cloned().map(Val::Bytes).collect();
                // `threshold == 0` on a non-empty signer set now compiles fail-closed
                // (unspendable) — see governance_zero_threshold_*; otherwise the gate
                // passes iff enough distinct signers verified.
                let expected = threshold != 0 && count >= threshold;
                assert_eq!(
                    run_module(cm, Val::Int(0), redeemer, &ctx, &v),
                    Ok(expected),
                    "m=5 threshold={threshold} mask={mask:#07b} count={count}"
                );
            }
        }
    }

    /// No-panic fuzz: feed every compiled module a batch of malformed/short/extreme
    /// redeemers (empty, wrong-typed, empty-bytes, `i128::MAX`/`MIN`) and assert the
    /// VM only ever returns a `Result` — it must never unwind via `panic!`.
    #[test]
    fn no_panic_on_malformed_or_short_redeemers_across_all_modules() {
        let ct = compile_charter(&demo_charter());
        let ctx = ctx_with(2_400, sha256d(b"member").to_vec());
        let v = MockVerifier { good: vec![] };
        let malformed: Vec<Vec<Val>> = vec![
            vec![],                     // no redeemer at all
            vec![Val::Int(0)],          // wrong type / too short
            vec![Val::Bytes(vec![])],   // empty bytes
            vec![Val::Int(i128::MAX)],  // extreme int
            vec![Val::Int(i128::MIN)],
        ];
        for cm in &ct.validators {
            for r in &malformed {
                let out = ExtOutput { value: blch(1000), validator_hash: cm.validator_hash, datum: Val::Int(0) };
                let mut gas = 1_000_000;
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    spend(&out, &cm.program, r.clone(), &ctx, &v, &mut gas)
                }));
                assert!(outcome.is_ok(), "{} panicked on redeemer {:?}", cm.kind, r);
            }
        }
    }
}
