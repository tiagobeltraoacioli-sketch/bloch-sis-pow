// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed errors for every failure the SVM plane can produce.
//!
//! Spec §2 bans `panic!`/`unwrap` from the execution path — a panic in one
//! node's execution path is a liveness split — so everything that can go
//! wrong is a value here. All enums are `#[non_exhaustive]` (spec §12):
//! downstream matchers must carry a wildcard arm, which is what lets a future
//! front add a variant without a semver break.
//!
//! Every enum derives `PartialEq, Eq` because the §8-1 equivalence obligation
//! compares **per-tx result codes** between serial and parallel execution —
//! an error that cannot be compared cannot be pinned.
//!
//! The three-way outcome split ([`crate::runtime::TxResult`]) leans on the
//! distinction between these families:
//!
//! - [`TxStructError`] — stateless malformation (§5.2). A block carrying one
//!   is producer misbehaviour, objectively attributable before any execution,
//!   so it is the one *block-level* error family (`BlockError::Structural`).
//! - [`RejectCause`] — state-dependent pre-checks that fail **before** the
//!   fee payer's live intent is established (bad signature, wrong nonce,
//!   absent payer). No fee, no nonce bump, no state effect.
//! - [`AbortCause`] — the transaction was genuinely attempted and died.
//!   Fee charged, nonce bumped, every other effect discarded (§6.4 —
//!   transaction-level always, never block-level: a block-level reject would
//!   let one adversarial program halt the chain).

/// Stateless structural invalidity (spec §5.2). Checked at decode/admission
/// AND again before block execution — both, always.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxStructError {
    /// `version != 0`. Format bumps are consensus changes, flag-day rules
    /// (spec §5.1).
    UnsupportedVersion(u8),
    /// Header counts exceed `accounts.len()` or overflow the section layout.
    HeaderInconsistent { n_ws: u8, n_rs: u8, n_w: u8, accounts: usize },
    /// `accounts[0]` must exist and be a writable signer — the fee payer
    /// (spec §5.1). Covers both the empty list and `n_ws == 0`.
    FeePayerSectionEmpty,
    /// The same 32-byte address appears twice across sections — the
    /// readonly-and-also-writable aliasing dodge, a real Solana CVE class,
    /// dies at parse time (spec §5.2).
    DuplicateAccount { address: [u8; 32] },
    /// `program_index` or an `account_indices` entry ≥ `accounts.len()`.
    IndexOutOfRange { instruction: usize, index: u8 },
    /// One instruction names the same account twice. Not in the spec's §5.2
    /// list verbatim, but forced by the same aliasing argument one level
    /// down: handles are exclusive borrows, and two handles onto one account
    /// within one `execute` call would alias mutable state.
    DuplicateIndexInInstruction { instruction: usize, index: u8 },
    /// A signer witness pubkey does not hash (with [`crate::params::ADDR_MARK_WALLET`])
    /// to its section's address (spec §5.2).
    WitnessAddressMismatch { witness: usize },
    /// `witnesses.len() != n_ws + n_rs` — one hybrid witness per signer
    /// section entry, in section order (spec §5.1).
    WitnessCountMismatch { expected: usize, got: usize },
    /// `compute_budget > MAX_TX_COMPUTE_UNITS` (spec §5.2).
    ComputeBudgetTooLarge { budget: u32 },
    /// A hard cap exceeded: accounts, instructions, instruction data, or a
    /// witness field (spec §5.2 caps; params.rs for values).
    CapExceeded { what: &'static str, len: usize, cap: usize },
    /// Serialization has bytes after the last field. The transition.rs codec
    /// idiom (`TxDecodeError::TrailingBytes`, transition.rs:856): a canonical
    /// format has exactly one encoding per value.
    TrailingBytes,
    /// The byte stream ended inside a field.
    Truncated,
}

/// State-dependent pre-check failures: the transaction produces **no state
/// effect at all** — no fee, no nonce bump. Deterministic because every value
/// read comes from the same committed snapshot every node holds (§2/D-0),
/// and every account read is declared, so wave scheduling (§7) serializes any
/// writer of these values before this reader.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectCause {
    /// A witness failed cryptographic verification (via the host
    /// [`crate::runtime::SignatureVerifier`] callback).
    BadSignature { witness: usize },
    /// `accounts[0]` does not exist in state.
    FeePayerMissing,
    /// The fee payer is not system-owned. The runtime debits the fee outside
    /// any program, which is only sound for wallet accounts whose debit
    /// authority is exactly "holder signature present" (§6.2).
    FeePayerNotSystemOwned,
    /// `tx.nonce != fee_payer.nonce` (spec §5.3). No fee on purpose: charging
    /// for a replayed transaction would let anyone drain a payer by
    /// re-submitting old transactions.
    NonceMismatch { expected: u64, got: u64 },
    /// The payer cannot cover `fee + bond_for(payer)` — the bond floor must
    /// survive the abort path too, or an abort could itself violate §4.2 and
    /// regress into a second abort.
    FeeUnpayable { required: u64, available: u64 },
    /// An instruction's program account does not exist. Spec §5.2 lists the
    /// executable check as structural; it needs state, so this front runs it
    /// as a pre-check — split documented in tx.rs.
    ProgramMissing { instruction: usize },
    /// The instruction's program account exists but is not `executable`.
    ProgramNotExecutable { instruction: usize },
}

/// Layer-1 access refusals (spec §6.1/§6.2): what the capability handles
/// refuse to do. These surface inside programs as
/// [`ProgramError::AccessViolation`] — the "typed abort, layer named" the §8
/// tests pin.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessError {
    /// Mutation requested on a readonly-declared account. THE layer-1 event:
    /// the `View` handle has no mutators, and the enum's `try_mut` is the one
    /// place a program can even ask.
    MutOnReadonlyDeclared { address: [u8; 32] },
    /// Debit/data/owner mutation by a program that is not the account owner
    /// (§6.2).
    NotOwner { address: [u8; 32], owner: [u8; 32], authority: [u8; 32] },
    /// A system-owned (wallet) account was debited/mutated without its
    /// holder's signature in the signer sections (§6.2).
    HolderSignatureMissing { address: [u8; 32] },
    /// Any mutation of an `executable` account — fully immutable in v0
    /// (§6.2).
    ExecutableIsImmutable { address: [u8; 32] },
    /// Credit/debit/data on an account that does not exist.
    AccountMissing { address: [u8; 32] },
    /// `create` on an address that already exists.
    AccountExists { address: [u8; 32] },
    /// `data` would exceed `MAX_ACCOUNT_DATA` (§3.2).
    DataCapExceeded { address: [u8; 32], len: usize },
    /// Owner reassignment with nonzero data (§6.2: reassigning nonempty data
    /// transfers meaning between trust domains — the kept Solana rule).
    OwnerReassignWithData { address: [u8; 32] },
    /// `delete` while the balance is nonzero — value must be explicitly moved
    /// first, so deletion can never silently burn.
    DeleteNonzeroBalance { address: [u8; 32], balance: u64 },
    /// Debit larger than the balance. u64 stays checked (§2); the typed error
    /// replaces what would otherwise be a wrap or a panic.
    InsufficientFunds { address: [u8; 32], balance: u64, requested: u64 },
    /// Balance arithmetic would exceed u64::MAX for a single account (§3.2
    /// fixes entries at u64; sums are u128 elsewhere).
    BalanceOverflow { address: [u8; 32] },
    /// v0 programs are genesis-registered only (§11 "no deploy path"):
    /// `create` may not mint an `executable` account.
    CreateExecutable { address: [u8; 32] },
}

/// Compute-meter failures (spec §6.3).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeterError {
    /// Budget exhausted. `consumed` is the meter reading at refusal —
    /// charge-then-do means the reading is exact and reproducible (§8-5
    /// pins it), because no partial "do" ever happened for the failed charge.
    Exhausted { requested: u32, consumed: u32, budget: u32 },
    /// The consumed counter would overflow u32. Abort, never wrap (§6.3).
    Overflow,
}

/// Errors a program (native, or SBF if that front ever lands) returns from
/// `execute`. Every variant is an [`AbortCause::Program`] at the runtime.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramError {
    /// A layer-1 refusal the program chose to surface (or could not avoid).
    AccessViolation(AccessError),
    /// The meter refused a charge.
    Meter(MeterError),
    /// `program_id` is not a program this executor knows. Distinct from
    /// [`RejectCause::ProgramMissing`]: that is "no such account in state",
    /// this is "the executor has no native implementation" — reachable only
    /// if a manifest registers an executable account the executor cannot run.
    UnknownProgram { program_id: [u8; 32] },
    /// Malformed instruction data (unknown tag, wrong length, trailing
    /// bytes — the same canonicity rules as every other codec here).
    InvalidInstructionData,
    /// The instruction referenced fewer accounts than the program requires.
    NotEnoughAccounts { got: usize, need: usize },
    /// An account the program requires to be a signer is not one.
    MissingRequiredSignature { address: [u8; 32] },
    /// Program-defined failure. The escape hatch native test programs (and
    /// eventually real programs) use for domain errors.
    Custom(u32),
}

impl From<AccessError> for ProgramError {
    fn from(e: AccessError) -> Self {
        ProgramError::AccessViolation(e)
    }
}

impl From<MeterError> for ProgramError {
    fn from(e: MeterError) -> Self {
        ProgramError::Meter(e)
    }
}

/// Why an attempted transaction aborted (fee charged, nonce bumped, all other
/// effects discarded — spec §6.4).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortCause {
    /// An instruction's program returned an error (includes layer-1 access
    /// refusals and meter exhaustion, each named inside).
    Program { instruction: usize, error: ProgramError },
    /// **Layer 2, check 1** (§6.4): a readonly-declared account's canonical
    /// hash changed across execution. Layer 1 should make this impossible;
    /// this abort is what turns a runtime bug into a detected abort instead
    /// of silent corruption.
    ReadonlyDrift { address: [u8; 32] },
    /// **Layer 2, check 2** (§6.4): Σ pre(writable) ≠ Σ post(writable) + fee
    /// in u128. The SVM plane mints nothing, ever.
    ConservationViolated { pre_sum: u128, post_sum: u128, fee: u64 },
    /// **Layer 2, check 3** (§6.4/§4.2): a surviving writable account ended
    /// below its bond floor.
    BondFloorViolated { address: [u8; 32], balance: u64, bond: u64 },
    /// A surviving writable account's data exceeds `MAX_ACCOUNT_DATA`.
    /// Layer 1 enforces this at the mutator; the commit re-check is the same
    /// belt-and-suspenders as [`AbortCause::ReadonlyDrift`].
    DataCapViolated { address: [u8; 32], len: usize },
}

/// Block-level failures of [`crate::scheduler::execute_block_serial`] /
/// [`crate::scheduler::execute_block_parallel`]. Deliberately tiny: per §6.4
/// almost everything is transaction-level; only producer-attributable
/// malformation and arithmetic impossibilities reject a block.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Transaction `index` is structurally invalid (§5.2 is checked at block
    /// validation too — both, always). A well-formed producer can never emit
    /// this, so it is safe to make block-level.
    Structural { index: usize, error: TxStructError },
    /// A u128 block aggregate overflowed. Unreachable with real supplies
    /// (2^128 sat ≫ any cap) but typed instead of trusted (§2).
    ArithmeticOverflow,
}
