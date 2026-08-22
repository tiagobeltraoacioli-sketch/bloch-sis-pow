// SPDX-License-Identifier: AGPL-3.0-or-later

//! Execution and the access-enforcement boundary (spec §6).
//!
//! **This module is the entire security model of the parallel plane.** The
//! scheduler proves nothing on its own: its equivalence theorem (§7.3) takes
//! as a *premise* that a transaction touches only what it declared. Hence
//! two independent layers, and the standing rule that no future change may
//! weaken either without strengthening the other:
//!
//! - **Layer 1 (structural, §6.1):** the executor never sees the state. It
//!   receives [`AccountHandle`]s over **copies** of exactly the declared
//!   accounts. A readonly declaration builds an [`AccountView`], a type with
//!   no mutation methods — undeclared or readonly state is not "forbidden",
//!   it is *unrepresentable* in the interface. There is no API through which
//!   a program names an address and receives an account.
//! - **Layer 2 (verified, §6.4):** after `execute` returns and before
//!   anything merges, the runtime re-verifies the bytes: readonly hashes
//!   unchanged, conservation in u128, bond floor. Layer 1 should make drift
//!   impossible; layer 2 makes a runtime *bug* a detected abort instead of
//!   silent corruption — the check that turns "we believe the type system"
//!   into "we verified the bytes".
//!
//! Any failure ⇒ **transaction-level abort** (fee charged, nonce bumped,
//! all other effects discarded). Never block-level (§6.4): a block-level
//! reject would let one adversarial transaction halt the chain.
//!
//! Whole-state protection is by construction: the commit effect lists
//! *only* the writable entries of the context ([`TxEffect::writes`]); the
//! abort effect lists only the fee payer. There is no code path that writes
//! an address the transaction did not declare.

use crate::account::Account;
use crate::errors::{AbortCause, AccessError, ProgramError, RejectCause};
use crate::meter::ComputeMeter;
use crate::params::{
    bond_for, fee_for, COST_INSTRUCTION_DISPATCH, MAX_ACCOUNT_DATA, SYSTEM_PROGRAM_ID,
};
use crate::tree::{existence_hash, SvmState};
use crate::tx::{DeclKind, SvmTransaction};
use std::collections::BTreeMap;

/// Execution environment (§6.1): slot/epoch **read from the parent's
/// committed state** by the caller — never wall time. The runtime forwards
/// it opaquely; there is no clock sysvar and no other sysvar (spec §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecEnv {
    /// The slot being executed.
    pub slot: u64,
    /// The epoch containing it.
    pub epoch: u64,
}

/// Host-provided hybrid (ML-DSA-65 ‖ Falcon-1024) signature verification —
/// the bloch-euvm `SigVerifier` idiom (bloch-euvm/src/lib.rs:98): kept
/// outside the machine so this crate stays pure and sha3-only; production
/// plugs the real bloch-crypto verifier in at integration time. MUST be
/// deterministic — a verifier that ever disagrees with itself is a chain
/// split, not a bug fix.
pub trait SignatureVerifier {
    /// Verify `sig` over `signing_root` under `pubkey`.
    fn verify(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool;
}

/// The program-execution boundary (spec §6.1) — **owned by Front 2**; the
/// bytecode/loader/verifier surface behind it is explicitly not (spec §1.2).
///
/// ## Contract assumed of any implementor (the Front-1 / sbpf boundary)
///
/// This rustdoc is the written form of the inter-front contract (task item
/// d): `crates/bloch-sbpf` does not exist yet (BLOCH-SBPF-CORE.md §0 — zero
/// code), and when it lands it plugs in HERE, by implementing this trait for
/// SBF programs. What Front 2 assumes of every implementor, native or SBF:
///
/// 1. **Purity.** No clock, no I/O, no randomness, no state beyond the
///    arguments. `env` carries slot/epoch read from committed state.
/// 2. **Total faults with discarded effects.** Every failure returns a typed
///    [`ProgramError`]; on `Err` the runtime discards the working copies, so
///    partial writes never survive. No panics (§2: a panic in one node's
///    execution path is a liveness split).
/// 3. **Deterministic charge-then-do metering.** Every unit of work is
///    charged to `meter` *before* it happens, so an exhaustion reading is
///    exact and identical on every node (§6.3).
/// 4. **Accounts exclusively via the handles.** The `accounts` slice is the
///    complete universe: the declared accounts of the current instruction,
///    in `account_indices` order. An SBF adapter must serialize *from these
///    handles* into its guest input region (the BSC-0 §5 INPUT amendment —
///    ro/rw split — is joint post-M4 work with that front) and merge guest
///    writes back *through* [`AccountMut`], inheriting the owner rules.
///    Nothing here is duplicated for them now; the only v0 executor is the
///    native one (`crate::native::NativeExecutor`).
pub trait ProgramExecutor {
    /// Run `program_id` with `instruction_data` over exactly the declared
    /// `accounts`.
    fn execute(
        &self,
        program_id: &[u8; 32],
        instruction_data: &[u8],
        accounts: &mut [AccountHandle<'_>],
        meter: &mut ComputeMeter,
        env: &ExecEnv,
    ) -> Result<(), ProgramError>;
}

/// One declared account's working state inside a transaction. Crate-private
/// on purpose: an executor cannot name this type, so it cannot conjure a
/// handle for an undeclared address (§8-3 — the compile-fail doctest on
/// [`AccountView`] pins this).
#[derive(Clone, Debug)]
pub(crate) struct CtxEntry {
    pub(crate) address: [u8; 32],
    pub(crate) kind: DeclKind,
    /// Committed state at transaction start. Never mutated.
    pub(crate) pre: Option<Account>,
    /// The working copy programs act on through handles.
    pub(crate) post: Option<Account>,
    /// `existence_hash(pre)` — the layer-2 readonly baseline, taken ONCE at
    /// context build so the check cannot be gamed by re-hashing a drifted
    /// "pre".
    pub(crate) pre_hash: [u8; 32],
}

/// Read-only capability over one declared account (§6.1).
///
/// The layer-1 property is type-level: this type HAS no mutation methods, so
/// mutating a readonly-declared account is unrepresentable, not merely
/// checked (§8-3's compile-fail pin):
///
/// ```compile_fail
/// fn attack(v: &mut bloch_svm::runtime::AccountView<'_>) {
///     v.credit(1); // ERROR: no such method — a View is not a Mut
/// }
/// ```
///
/// And a handle cannot be conjured from outside the runtime — every
/// constructor is crate-private, so an executor holds exactly the handles it
/// was given (§6.1 "no API through which a program names an address and
/// receives an account"):
///
/// ```compile_fail
/// // ERROR: private field / no public constructor.
/// let v = bloch_svm::runtime::AccountView { entry: todo!() };
/// ```
///
/// **Control** (§8-3: the declared construction compiles — through the
/// runtime-built handle):
///
/// ```
/// use bloch_svm::runtime::AccountHandle;
/// fn declared_write(h: &mut AccountHandle<'_>) {
///     if let Ok(m) = h.try_mut() {
///         let _ = m.credit(1);
///     }
/// }
/// ```
pub struct AccountView<'a> {
    // &mut (not &) so the cfg(test) layer-1 bypass below can exist; the
    // public API of this type never mutates through it.
    entry: &'a mut CtxEntry,
}

impl AccountView<'_> {
    /// The declared address.
    pub fn address(&self) -> [u8; 32] {
        self.entry.address
    }
    /// Whether a witness vouches for this account in this transaction.
    pub fn is_signer(&self) -> bool {
        self.entry.kind.is_signer()
    }
    /// The account, or `None` if the address holds no account.
    pub fn account(&self) -> Option<&Account> {
        self.entry.post.as_ref()
    }

    /// TEST-ONLY layer-1 bypass, for proving layer 2 stands on its own
    /// (§6.4: "belt and suspenders"; §8-2's second half; mutation roster
    /// item c). Compiled out of every non-test build; even in tests it is
    /// crate-private, so no external executor can reach it.
    #[cfg(test)]
    pub(crate) fn bypass_layer1_for_tests(&mut self) -> &mut Option<Account> {
        &mut self.entry.post
    }
}

/// Writable capability over one declared account (§6.1). Mutators enforce
/// the §6.2 owner rules on **every call** — `authority` is the program id of
/// the current instruction, baked in at construction, so a program cannot
/// claim someone else's authority.
pub struct AccountMut<'a> {
    entry: &'a mut CtxEntry,
    authority: [u8; 32],
}

impl AccountMut<'_> {
    /// The declared address.
    pub fn address(&self) -> [u8; 32] {
        self.entry.address
    }
    /// Whether a witness vouches for this account in this transaction.
    pub fn is_signer(&self) -> bool {
        self.entry.kind.is_signer()
    }
    /// The account, or `None` if the address holds no account.
    pub fn account(&self) -> Option<&Account> {
        self.entry.post.as_ref()
    }

    /// The §6.2 gate shared by every *owner-privileged* mutator: the account
    /// exists, is not executable (fully immutable in v0), the calling
    /// program is its owner, and — for system-owned accounts (wallets) — the
    /// holder's signature is present in the signer sections.
    fn owner_gate(&self) -> Result<&Account, AccessError> {
        let a = self
            .entry
            .post
            .as_ref()
            .ok_or(AccessError::AccountMissing { address: self.entry.address })?;
        if a.executable {
            return Err(AccessError::ExecutableIsImmutable { address: self.entry.address });
        }
        if a.owner != self.authority {
            return Err(AccessError::NotOwner {
                address: self.entry.address,
                owner: a.owner,
                authority: self.authority,
            });
        }
        if a.owner == SYSTEM_PROGRAM_ID && !self.entry.kind.is_signer() {
            return Err(AccessError::HolderSignatureMissing { address: self.entry.address });
        }
        Ok(a)
    }

    /// Credit `amount`. Anyone may credit a writable account (§6.2) — no
    /// owner gate — but an executable account is immutable even to credits,
    /// and a missing account must be `create`d, not credited into being
    /// (creation carries the §4.2 bond; a credit path around it would be a
    /// free account).
    pub fn credit(&mut self, amount: u64) -> Result<(), AccessError> {
        let address = self.entry.address;
        let a = self
            .entry
            .post
            .as_mut()
            .ok_or(AccessError::AccountMissing { address })?;
        if a.executable {
            return Err(AccessError::ExecutableIsImmutable { address });
        }
        a.balance_sat = a
            .balance_sat
            .checked_add(amount)
            .ok_or(AccessError::BalanceOverflow { address })?;
        Ok(())
    }

    /// Debit `amount` — owner only; wallets additionally need their holder's
    /// signature (§6.2).
    pub fn debit(&mut self, amount: u64) -> Result<(), AccessError> {
        let address = self.entry.address;
        let balance = self.owner_gate()?.balance_sat;
        let new = balance
            .checked_sub(amount)
            .ok_or(AccessError::InsufficientFunds { address, balance, requested: amount })?;
        // owner_gate proved post is Some; re-borrow mutably.
        if let Some(a) = self.entry.post.as_mut() {
            a.balance_sat = new;
        }
        Ok(())
    }

    /// Initialize an account at a currently-empty declared address. Refuses
    /// existing addresses, executable creation (programs are
    /// genesis-registered only, §11), and over-cap data. The §4.2 bond is
    /// enforced at commit (layer 2), where the final balance is known.
    pub fn create(&mut self, account: Account) -> Result<(), AccessError> {
        let address = self.entry.address;
        if self.entry.post.is_some() {
            return Err(AccessError::AccountExists { address });
        }
        if account.executable {
            return Err(AccessError::CreateExecutable { address });
        }
        if account.data.len() > MAX_ACCOUNT_DATA {
            return Err(AccessError::DataCapExceeded { address, len: account.data.len() });
        }
        self.entry.post = Some(account);
        Ok(())
    }

    /// Replace the account's data — owner only (§6.2), capped (§3.2).
    pub fn set_data(&mut self, data: Vec<u8>) -> Result<(), AccessError> {
        let address = self.entry.address;
        self.owner_gate()?;
        if data.len() > MAX_ACCOUNT_DATA {
            return Err(AccessError::DataCapExceeded { address, len: data.len() });
        }
        if let Some(a) = self.entry.post.as_mut() {
            a.data = data;
        }
        Ok(())
    }

    /// Reassign ownership — owner only, and only with data zeroed (§6.2:
    /// reassigning nonempty data transfers meaning between trust domains —
    /// the kept Solana rule; all-zero counts as zeroed, matching Solana's
    /// allocate-then-assign flow).
    pub fn set_owner(&mut self, new_owner: [u8; 32]) -> Result<(), AccessError> {
        let address = self.entry.address;
        let a = self.owner_gate()?;
        if !a.data.iter().all(|b| *b == 0) {
            return Err(AccessError::OwnerReassignWithData { address });
        }
        if let Some(a) = self.entry.post.as_mut() {
            a.owner = new_owner;
        }
        Ok(())
    }

    /// Delete the account — owner only, balance must already be zero so
    /// deletion can never silently burn value; the §4.2 bond refund is the
    /// explicit debit/credit the caller performed first (see
    /// `native::system` Delete).
    pub fn delete(&mut self) -> Result<(), AccessError> {
        let address = self.entry.address;
        let a = self.owner_gate()?;
        if a.balance_sat != 0 {
            return Err(AccessError::DeleteNonzeroBalance { address, balance: a.balance_sat });
        }
        self.entry.post = None;
        Ok(())
    }
}

/// The capability a program receives for each declared account of the
/// current instruction (§6.1): a [`AccountView`] for readonly declarations,
/// an [`AccountMut`] for writable ones. The enum is what lets one `execute`
/// signature carry both; [`AccountHandle::try_mut`] is the single place a
/// program can ask for mutation, and its refusal is THE layer-1 event the
/// §8-2 test pins.
pub enum AccountHandle<'a> {
    /// Readonly-declared: no mutation surface exists.
    View(AccountView<'a>),
    /// Writable-declared: mutators enforce §6.2 per call.
    Mut(AccountMut<'a>),
}

impl<'a> AccountHandle<'a> {
    /// The declared address.
    pub fn address(&self) -> [u8; 32] {
        match self {
            AccountHandle::View(v) => v.address(),
            AccountHandle::Mut(m) => m.address(),
        }
    }
    /// Whether a witness vouches for this account.
    pub fn is_signer(&self) -> bool {
        match self {
            AccountHandle::View(v) => v.is_signer(),
            AccountHandle::Mut(m) => m.is_signer(),
        }
    }
    /// The account, or `None` if the address holds none.
    pub fn account(&self) -> Option<&Account> {
        match self {
            AccountHandle::View(v) => v.account(),
            AccountHandle::Mut(m) => m.account(),
        }
    }
    /// Request mutation. A `View` never coerces to a `Mut` (§6.1) — the
    /// refusal is typed and names layer 1.
    pub fn try_mut(&mut self) -> Result<&mut AccountMut<'a>, AccessError> {
        match self {
            AccountHandle::Mut(m) => Ok(m),
            AccountHandle::View(v) => {
                Err(AccessError::MutOnReadonlyDeclared { address: v.address() })
            }
        }
    }
}

/// Per-transaction result code. Three families, three effect shapes — the
/// distinction errors.rs documents:
/// `Executed` (all writable posts merge), `Aborted` (fee + nonce only),
/// `Rejected` (nothing).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxResult {
    /// Every instruction succeeded and layer 2 verified.
    Executed,
    /// Attempted and died (§6.4): fee charged, nonce bumped, rest discarded.
    Aborted(AbortCause),
    /// Failed a pre-check: no state effect at all.
    Rejected(RejectCause),
}

/// What block execution reports per transaction. `units_consumed` is part of
/// the §8-1/§8-5 equivalence surface: serial and parallel execution must
/// agree on it byte-for-byte, exhaustion readings included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutcome {
    /// The result code.
    pub result: TxResult,
    /// Final meter reading (at abort: the exact reading at the failure).
    pub units_consumed: u32,
    /// Fee actually charged (0 for `Rejected`).
    pub fee_paid: u64,
}

/// A transaction's computed effect, before commit. `writes` is the ONLY
/// path into state (spec §6.4 "the merge iterates the declared-writable list
/// and nothing else"): for `Executed` it holds every writable-declared
/// entry's post; for `Aborted` exactly the fee payer; for `Rejected`
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxEffect {
    pub(crate) outcome: TxOutcome,
    pub(crate) writes: Vec<([u8; 32], Option<Account>)>,
}

/// Execute one transaction against a committed snapshot, producing its
/// effect. Pure: same `(state, tx, executor, verifier, env)` ⇒ same bytes
/// out, which is the whole §7.3 premise — both the serial reference and
/// every parallel wave call exactly this function.
///
/// PRECONDITION: `tx.validate_structure()` passed (both block entry points
/// enforce it first — §5.2 runs at mempool AND block validation). The
/// function stays panic-free even if violated (typed aborts), but outcomes
/// for structurally invalid transactions are unspecified.
pub(crate) fn execute_tx(
    state: &SvmState,
    tx: &SvmTransaction,
    executor: &(dyn ProgramExecutor + Sync),
    verifier: &(dyn SignatureVerifier + Sync),
    env: &ExecEnv,
) -> TxEffect {
    let reject = |cause: RejectCause| TxEffect {
        outcome: TxOutcome { result: TxResult::Rejected(cause), units_consumed: 0, fee_paid: 0 },
        writes: Vec::new(),
    };

    // -- Pre-checks, fixed order (deterministic first-failure) --------------

    // 1. Witnesses over the signing root (host callback; §5.1).
    let signing_root = tx.signing_root();
    for (i, w) in tx.witnesses.iter().enumerate() {
        if !verifier.verify(&w.pubkey, &signing_root, &w.sig) {
            return reject(RejectCause::BadSignature { witness: i });
        }
    }

    // 2. Fee payer exists, is a wallet (§5.3 + errors.rs rationale: the
    //    runtime debits the fee outside any program, sound only under the
    //    wallet debit rule).
    let payer_addr = match tx.accounts.first() {
        Some(m) => m.address,
        None => return reject(RejectCause::FeePayerMissing), // unreachable post-§5.2
    };
    let payer_pre = match state.get(&payer_addr) {
        Some(a) => a.clone(),
        None => return reject(RejectCause::FeePayerMissing),
    };
    if payer_pre.owner != SYSTEM_PROGRAM_ID || payer_pre.executable {
        return reject(RejectCause::FeePayerNotSystemOwned);
    }

    // 3. Nonce (§5.3): valid iff equal. No fee on mismatch — errors.rs.
    if tx.nonce != payer_pre.nonce {
        return reject(RejectCause::NonceMismatch { expected: payer_pre.nonce, got: tx.nonce });
    }

    // 4. Fee affordability INCLUDING the payer's own bond floor, so the
    //    abort path (fee-only debit) can never itself violate §4.2 — the
    //    regress errors.rs::FeeUnpayable documents. u128 sum: u64 + u64 can
    //    exceed u64::MAX.
    let fee = fee_for(tx.compute_budget);
    let required = u128::from(fee) + u128::from(bond_for(payer_pre.data.len()));
    if u128::from(payer_pre.balance_sat) < required {
        return reject(RejectCause::FeeUnpayable {
            required: u64::try_from(required).unwrap_or(u64::MAX),
            available: payer_pre.balance_sat,
        });
    }

    // 5. Program accounts exist and are executable — the state-dependent
    //    half of §5.2 (split documented in tx.rs). Reads only DECLARED
    //    accounts (program_index points into tx.accounts), so §7 waves
    //    serialize any hypothetical writer before this reader.
    for (n, ins) in tx.instructions.iter().enumerate() {
        let prog_addr = tx.accounts[ins.program_index as usize].address;
        match state.get(&prog_addr) {
            None => return reject(RejectCause::ProgramMissing { instruction: n }),
            Some(p) if !p.executable => {
                return reject(RejectCause::ProgramNotExecutable { instruction: n })
            }
            Some(_) => {}
        }
    }

    // -- Context: copies of exactly the declared accounts (§6.1) -----------

    let mut entries: Vec<CtxEntry> = tx
        .accounts
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let pre = state.get(&m.address).cloned();
            let pre_hash = existence_hash(pre.as_ref());
            CtxEntry {
                address: m.address,
                // Total after §5.2: i < accounts.len().
                kind: tx.decl_kind(i).unwrap_or(DeclKind::Readonly),
                post: pre.clone(),
                pre,
                pre_hash,
            }
        })
        .collect();

    // The §5.3 commit rule applied up front on the WORKING copy: fee debited
    // and nonce bumped before any program runs, so programs observe the
    // post-fee balance and cannot spend the fee. Runtime privilege — not a
    // handle mutator — because no program is the authority here; §5.3 makes
    // the holder's transaction signature the authority. Arithmetic total by
    // pre-check 4 (balance ≥ fee) and u64 nonce (2^64 fee payments cannot
    // happen before the sun burns out); still written checked per §2.
    let payer_abort_image = {
        let e = &mut entries[0];
        debug_assert_eq!(e.address, payer_addr);
        if let Some(a) = e.post.as_mut() {
            a.balance_sat = a.balance_sat.saturating_sub(fee);
            a.nonce = a.nonce.saturating_add(1);
        }
        // The §6.4 abort image: payer's PRE with exactly fee + nonce applied,
        // captured before any program can touch the working copy.
        e.post.clone()
    };
    let abort = |cause: AbortCause, units: u32| TxEffect {
        outcome: TxOutcome { result: TxResult::Aborted(cause), units_consumed: units, fee_paid: fee },
        writes: vec![(payer_addr, payer_abort_image.clone())],
    };

    // -- Instructions (§6.1/§6.3) -------------------------------------------

    let mut meter = ComputeMeter::new(tx.compute_budget);
    for (n, ins) in tx.instructions.iter().enumerate() {
        // Charge-then-do at the dispatch grain too (§6.3).
        if let Err(e) = meter.charge(COST_INSTRUCTION_DISPATCH) {
            return abort(
                AbortCause::Program { instruction: n, error: ProgramError::Meter(e) },
                meter.consumed(),
            );
        }
        let program_id = tx.accounts[ins.program_index as usize].address;

        // Disjoint &mut CtxEntry per requested index, then handle order =
        // instruction order. iter_mut().enumerate() yields naturally
        // disjoint borrows; `remove` consumes each at most once (§5.2
        // banned duplicate indices, so this is belt over that suspender).
        let mut picked: BTreeMap<usize, &mut CtxEntry> = entries
            .iter_mut()
            .enumerate()
            .filter(|(i, _)| ins.account_indices.contains(&(*i as u8)))
            .collect();
        let mut handles: Vec<AccountHandle<'_>> = Vec::with_capacity(ins.account_indices.len());
        for &i in &ins.account_indices {
            match picked.remove(&(i as usize)) {
                Some(e) if e.kind.is_writable() => {
                    handles.push(AccountHandle::Mut(AccountMut { entry: e, authority: program_id }));
                }
                Some(e) => handles.push(AccountHandle::View(AccountView { entry: e })),
                // Unreachable when the §5.2 precondition holds; typed rather
                // than panicking (§2).
                None => {
                    return abort(
                        AbortCause::Program { instruction: n, error: ProgramError::InvalidInstructionData },
                        meter.consumed(),
                    )
                }
            }
        }

        if let Err(e) = executor.execute(&program_id, &ins.data, &mut handles, &mut meter, env) {
            return abort(AbortCause::Program { instruction: n, error: e }, meter.consumed());
        }
    }

    // -- Layer 2 (§6.4): verify the bytes before anything merges ------------

    // 1. Readonly integrity: canonical existence hash unchanged.
    for e in entries.iter().filter(|e| !e.kind.is_writable()) {
        if existence_hash(e.post.as_ref()) != e.pre_hash {
            return abort(AbortCause::ReadonlyDrift { address: e.address }, meter.consumed());
        }
    }

    // 2. Conservation in u128: Σ pre(writable) == Σ post(writable) + fee.
    //    The plane mints nothing, ever; value enters only via the (future,
    //    §9.2) bridge.
    let writable = || entries.iter().filter(|e| e.kind.is_writable());
    let pre_sum: u128 = writable().map(|e| e.pre.as_ref().map_or(0u128, |a| u128::from(a.balance_sat))).sum();
    let post_sum: u128 = writable().map(|e| e.post.as_ref().map_or(0u128, |a| u128::from(a.balance_sat))).sum();
    if pre_sum != post_sum.saturating_add(u128::from(fee)) {
        return abort(
            AbortCause::ConservationViolated { pre_sum, post_sum, fee },
            meter.consumed(),
        );
    }

    // 3. Bond floor (§4.2) + data cap on every surviving writable account.
    //    Deleted accounts (post None) already conserved their value above.
    for e in writable() {
        if let Some(a) = e.post.as_ref() {
            let bond = bond_for(a.data.len());
            if a.balance_sat < bond {
                return abort(
                    AbortCause::BondFloorViolated { address: e.address, balance: a.balance_sat, bond },
                    meter.consumed(),
                );
            }
            if a.data.len() > MAX_ACCOUNT_DATA {
                return abort(
                    AbortCause::DataCapViolated { address: e.address, len: a.data.len() },
                    meter.consumed(),
                );
            }
        }
    }

    // -- Success: merge list = the declared-writable entries, nothing else --
    let writes: Vec<([u8; 32], Option<Account>)> = entries
        .iter()
        .filter(|e| e.kind.is_writable())
        .map(|e| (e.address, e.post.clone()))
        .collect();
    TxEffect {
        outcome: TxOutcome { result: TxResult::Executed, units_consumed: meter.consumed(), fee_paid: fee },
        writes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: DeclKind, account: Option<Account>) -> CtxEntry {
        let pre_hash = existence_hash(account.as_ref());
        CtxEntry { address: [9u8; 32], kind, pre: account.clone(), post: account, pre_hash }
    }

    /// §8-2 at the handle grain: try_mut on a readonly declaration is a
    /// typed layer-1 refusal naming the address; control: the writable
    /// declaration yields a Mut and the mutation lands.
    #[test]
    fn view_never_coerces_to_mut() {
        let mut e = entry(DeclKind::Readonly, Some(Account::wallet(10)));
        let mut h = AccountHandle::View(AccountView { entry: &mut e });
        assert_eq!(
            h.try_mut().err(),
            Some(AccessError::MutOnReadonlyDeclared { address: [9u8; 32] })
        );
        // Control: writable-declared succeeds and the write is visible.
        let mut e2 = entry(DeclKind::Writable, Some(Account::wallet(10)));
        let mut h2 = AccountHandle::Mut(AccountMut { entry: &mut e2, authority: [1u8; 32] });
        h2.try_mut().unwrap().credit(5).unwrap();
        assert_eq!(h2.account().unwrap().balance_sat, 15);
    }

    /// **The merge list is exactly the declared-writable set** (§6.4:
    /// "the merge iterates the declared-writable list and nothing else").
    ///
    /// This test exists because the mutation campaign found that widening
    /// the merge to every context entry SURVIVED the whole suite: layer 2
    /// forces readonly posts to equal their pres, so writing them back
    /// changes no byte, and every end-to-end assertion stayed green. The
    /// structural guarantee was therefore resting entirely on layer 2 —
    /// precisely the single-layer dependency §6 forbids. Asserting on the
    /// EFFECT rather than on the post-state pins it independently: if
    /// `writes` ever grows an undeclared address, this goes red whether or
    /// not layer 2 would have caught the write.
    ///
    /// **Control:** the two writable declarations DO appear, so the
    /// assertion cannot be passing because `writes` is empty.
    #[test]
    fn merge_list_is_exactly_the_declared_writable_set() {
        use crate::params::bond_for;
        use crate::testkit::{manifest, AcceptAll, TestExecutor, ENV};
        use crate::tx::{AccountMeta, Instruction, SvmTransaction, Witness};

        const PAYER: &[u8] = b"merge-list-payer";
        let writable = [0x51u8; 32];
        let readonly = [0x52u8; 32];
        let mut state = manifest(&[(PAYER, 100_000_000)]);
        state.set_account(writable, Some(Account::wallet(bond_for(0))));
        state.set_account(readonly, Some(Account::wallet(bond_for(0))));

        // [payer ws | writable w | readonly ro | System ro]; the instruction
        // moves 1 sat payer→writable so the transaction really executes.
        let mut data = vec![crate::native::system::TAG_TRANSFER];
        data.extend_from_slice(&1u64.to_le_bytes());
        let tx = SvmTransaction {
            version: 0,
            compute_budget: crate::testkit::BUDGET,
            nonce: 0,
            accounts: vec![
                AccountMeta { address: crate::address::wallet_address(PAYER) },
                AccountMeta { address: writable },
                AccountMeta { address: readonly },
                AccountMeta { address: SYSTEM_PROGRAM_ID },
            ],
            header: (1, 0, 1),
            instructions: vec![Instruction { program_index: 3, account_indices: vec![0, 1], data }],
            witnesses: vec![Witness { pubkey: PAYER.to_vec(), sig: vec![0xEE] }],
        };
        assert_eq!(tx.validate_structure(), Ok(()));

        let effect = execute_tx(&state, &tx, &TestExecutor, &AcceptAll, &ENV);
        assert_eq!(effect.outcome.result, TxResult::Executed);
        let written: Vec<[u8; 32]> = effect.writes.iter().map(|(a, _)| *a).collect();
        assert_eq!(
            written,
            vec![crate::address::wallet_address(PAYER), writable],
            "the merge list must be the declared-writable section, in declaration order"
        );

        // And the same on the ABORT path: exactly the fee payer, nobody else.
        let mut bad = tx.clone();
        // Overdraft ⇒ abort at debit.
        let mut d = vec![crate::native::system::TAG_TRANSFER];
        d.extend_from_slice(&(u64::MAX / 2).to_le_bytes());
        bad.instructions[0].data = d;
        let aborted = execute_tx(&state, &bad, &TestExecutor, &AcceptAll, &ENV);
        assert!(matches!(aborted.outcome.result, TxResult::Aborted(_)));
        let written: Vec<[u8; 32]> = aborted.writes.iter().map(|(a, _)| *a).collect();
        assert_eq!(written, vec![crate::address::wallet_address(PAYER)]);
    }

    /// §6.2: only the owner debits; wallets additionally need the holder's
    /// signature. Both negatives with their controls.
    #[test]
    fn owner_rules_on_debit() {
        // Non-owner program debiting a program-owned account.
        let owned = Account { owner: [7u8; 32], ..Account::wallet(100) };
        let mut e = entry(DeclKind::Writable, Some(owned));
        let mut m = AccountMut { entry: &mut e, authority: [8u8; 32] };
        assert!(matches!(m.debit(1), Err(AccessError::NotOwner { .. })));
        // Control: the owner program debits.
        let mut m = AccountMut { entry: &mut e, authority: [7u8; 32] };
        assert_eq!(m.debit(1), Ok(()));
        assert_eq!(m.account().unwrap().balance_sat, 99);

        // Wallet without holder signature.
        let mut e = entry(DeclKind::Writable, Some(Account::wallet(100)));
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        assert!(matches!(m.debit(1), Err(AccessError::HolderSignatureMissing { .. })));
        // Control: same wallet declared writable SIGNER.
        let mut e = entry(DeclKind::WritableSigner, Some(Account::wallet(100)));
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        assert_eq!(m.debit(1), Ok(()));
        // And a debit past the balance is a typed refusal, not a wrap.
        assert!(matches!(m.debit(1_000), Err(AccessError::InsufficientFunds { .. })));
    }

    /// §6.2: executable accounts are fully immutable in v0 — even credits.
    #[test]
    fn executable_accounts_are_immutable() {
        let prog = Account { executable: true, owner: [7u8; 32], ..Account::wallet(0) };
        let mut e = entry(DeclKind::Writable, Some(prog));
        let mut m = AccountMut { entry: &mut e, authority: [7u8; 32] };
        assert!(matches!(m.credit(1), Err(AccessError::ExecutableIsImmutable { .. })));
        assert!(matches!(m.debit(0), Err(AccessError::ExecutableIsImmutable { .. })));
        assert!(matches!(m.set_data(vec![1]), Err(AccessError::ExecutableIsImmutable { .. })));
        // Control: the same shape without `executable` accepts the credit.
        let plain = Account { owner: [7u8; 32], ..Account::wallet(0) };
        let mut e = entry(DeclKind::Writable, Some(plain));
        let mut m = AccountMut { entry: &mut e, authority: [7u8; 32] };
        assert_eq!(m.credit(1), Ok(()));
    }

    /// create refuses existing addresses and executable minting; owner
    /// reassignment requires zeroed data; delete requires zero balance.
    #[test]
    fn creation_reassign_delete_rules() {
        // create on existing.
        let mut e = entry(DeclKind::Writable, Some(Account::wallet(1)));
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        assert!(matches!(m.create(Account::wallet(0)), Err(AccessError::AccountExists { .. })));
        // create executable (no deploy path, §11).
        let mut e = entry(DeclKind::Writable, None);
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        let prog = Account { executable: true, ..Account::wallet(0) };
        assert!(matches!(m.create(prog), Err(AccessError::CreateExecutable { .. })));
        // Control: plain create lands.
        assert_eq!(m.create(Account::wallet(3)), Ok(()));
        assert_eq!(m.account().unwrap().balance_sat, 3);

        // set_owner with nonzero data refused; zeroed data accepted.
        let dirty = Account { data: vec![1, 0], ..Account::wallet(5) };
        let mut e = entry(DeclKind::WritableSigner, Some(dirty));
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        assert!(matches!(m.set_owner([2u8; 32]), Err(AccessError::OwnerReassignWithData { .. })));
        let clean = Account { data: vec![0, 0], ..Account::wallet(5) };
        let mut e = entry(DeclKind::WritableSigner, Some(clean));
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        assert_eq!(m.set_owner([2u8; 32]), Ok(()));
        assert_eq!(m.account().unwrap().owner, [2u8; 32]);

        // delete with balance refused; zero-balance delete removes.
        let mut e = entry(DeclKind::WritableSigner, Some(Account::wallet(5)));
        let mut m = AccountMut { entry: &mut e, authority: SYSTEM_PROGRAM_ID };
        assert!(matches!(m.delete(), Err(AccessError::DeleteNonzeroBalance { .. })));
        m.debit(5).unwrap();
        assert_eq!(m.delete(), Ok(()));
        assert!(m.account().is_none());
    }
}
