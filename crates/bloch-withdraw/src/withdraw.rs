// SPDX-License-Identifier: AGPL-3.0-or-later

//! The withdrawal state machine: pay each id at most once, on a chain where
//! the transaction cannot prove it.
//!
//! ## The race this closes (full statement in DOUBLE-PAYMENT-RACE.md)
//!
//! A transfer here commits to one base fee; if the fee moves before
//! inclusion, those bytes are dead and the mempool has already dropped them
//! without notice. So retrying means REBUILDING — different bytes, different
//! txid — and with no transaction index there is no query that asks "did my
//! first try land?". The naive loop (build at fee B, wait, rebuild at B',
//! submit) can pay twice: if the first build was included after all — a slow
//! block, a fork you were not reading, a fee that oscillated back — both
//! transactions are valid, both spend different coins, and both land.
//!
//! Two rules close it, both enforced structurally here rather than by
//! vigilance:
//!
//! 1. **Input pinning.** The first build for a withdrawal id pins a set of
//!    coins to that id, durably, before anything is signed. Every rebuild —
//!    every fee level, every retry, the cancellation sweep too — spends that
//!    same pinned set (it may grow; it never shrinks and is never swapped).
//!    Any two attempts therefore conflict on-chain, and consensus itself
//!    guarantees at most one can ever be included on one chain. The
//!    double-payment does not become unlikely; it becomes a double-spend,
//!    which the chain rejects.
//! 2. **Confirm, then rebuild.** A rebuild happens only after this tick has
//!    observed the pinned coins UNSPENT in the node's committed state. Not
//!    because the observation is race-free — it isn't, and rule 1 is what
//!    makes the remaining race harmless — but because it is what turns
//!    "the fee moved" from a guess into a decision made against the chain.
//!
//! Crediting is finality-gated: `Paid` is only declared once the spend of
//! the pinned coins has been observed on the canonical chain AND the
//! finalized boundary has advanced past the slot of that observation AND the
//! spend is still there. Until then a reorg can un-spend the coins, and the
//! machine walks back to `Submitted` and resumes.

use crate::address::{parse_payee, KeyMaterial, ScriptHash};
use crate::build::{
    build_transfer, format_for_epoch, BuildError, BuildRequest, BuiltTransfer, DUST_FLOOR_SAT,
};
use crate::rpc::{
    chain_info, get_txout, list_unspent, send_raw, ChainInfo, Node, RpcFailure, SubmitOutcome,
};
use crate::store::{
    reserved_outpoints, Attempt, AttemptKind, Coin, Status, Store, WithdrawalRecord,
};

/// Tuning. The defaults are the safe ones; every field is a policy an
/// exchange may legitimately hold differently.
pub struct Config {
    /// Priority tip in msat/gas. 0 is correct on an uncongested chain; the
    /// base fee is the protocol's and is not this knob.
    pub tip_msat_per_gas: u128,
    /// No output below this is ever emitted. Genesis-3's dust threshold by
    /// default; consensus today would accept less — this client will not.
    pub dust_floor_sat: u64,
    /// Refuse to act when the node reports itself further behind the wall
    /// clock than this. A stale node's "unspent" is not evidence.
    pub max_behind_slots: u64,
    /// `listunspent` page size for coin selection (node caps at 1,000).
    pub utxo_page: u64,
    /// Which chain this client is pointed at. **Mainnet by default**, so a
    /// client that never mentions the field behaves exactly as it did before.
    ///
    /// It exists because the testnet an exchange rehearses on is the one place
    /// this path can be run before a customer's money is the first thing
    /// through it, and the client used to refuse every `bloch1t…` payee
    /// unconditionally — a withdrawal client unusable on the testnet built for
    /// rehearsing withdrawals. Setting this to `Testnet` moves the network
    /// check rather than removing it: a mainnet-configured client still
    /// refuses testnet payees, and a testnet-configured one now refuses
    /// mainnet payees, which nothing checked before.
    pub network: bloch_crypto::address::Network,
    /// Allow a `bloch1q…`/`bloch1t…` address as a payee, paying the carried
    /// 20-byte shape. **Off by default.**
    ///
    /// Genesis-4 names payees by `script_hash`. The address form is correct for
    /// exactly one population — Genesis-3 carryover holders — and silently
    /// wrong for everyone else: it locks the output to a different UTXO-set key
    /// than the payee's own wallet watches, at 160 bits of preimage resistance
    /// instead of 256. Turn it on only if you know which population you are
    /// paying.
    pub allow_carryover_address: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            tip_msat_per_gas: 0,
            dust_floor_sat: DUST_FLOOR_SAT,
            max_behind_slots: 4,
            utxo_page: 1000,
            network: bloch_crypto::address::Network::Mainnet,
            allow_carryover_address: false,
        }
    }
}

#[derive(Debug)]
pub enum WithdrawError {
    Rpc(RpcFailure),
    Store(std::io::Error),
    Build(BuildError),
    /// The node is too far behind the wall clock to be believed. Retry when
    /// it has caught up, or point at a healthy node.
    NodeStale { behind_by_slots: u64 },
    UnknownId(String),
    /// `create` called again with the same id but different terms — the one
    /// shape of idempotent call that must fail loudly instead of answering.
    IdMismatch(String),
    BadRequest(String),
    /// The whole hot wallet cannot fund amount + fee.
    WalletShort { available: u128, needed: u128 },
}

impl std::fmt::Display for WithdrawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WithdrawError::Rpc(e) => write!(f, "rpc: {e}"),
            WithdrawError::Store(e) => write!(f, "store: {e}"),
            WithdrawError::Build(e) => write!(f, "build: {e}"),
            WithdrawError::NodeStale { behind_by_slots } => {
                write!(f, "node is {behind_by_slots} slots behind the wall clock")
            }
            WithdrawError::UnknownId(id) => write!(f, "unknown withdrawal id {id:?}"),
            WithdrawError::IdMismatch(m) => write!(f, "id reused with different terms: {m}"),
            WithdrawError::BadRequest(m) => write!(f, "bad request: {m}"),
            WithdrawError::WalletShort { available, needed } => {
                write!(f, "hot wallet holds {available} sat, need {needed} sat")
            }
        }
    }
}

impl From<RpcFailure> for WithdrawError {
    fn from(e: RpcFailure) -> Self {
        WithdrawError::Rpc(e)
    }
}
impl From<std::io::Error> for WithdrawError {
    fn from(e: std::io::Error) -> Self {
        WithdrawError::Store(e)
    }
}

/// What one `tick` did, for logs and tests. `status` is the record's state
/// after the tick; `submit` is the node's verdict if bytes were (re)sent.
#[derive(Debug)]
pub struct TickOutcome {
    pub status: Status,
    pub submit: Option<SubmitOutcome>,
}

/// The withdrawal driver. Stateless in itself — every fact lives in the
/// store — so any number of processes could construct one, though only one
/// should tick a given id at a time (serialize per id; the store contract
/// has no compare-and-swap).
pub struct Withdrawer<'a> {
    pub node: &'a dyn Node,
    pub store: &'a dyn Store,
    pub key: &'a KeyMaterial,
    pub cfg: Config,
}

impl<'a> Withdrawer<'a> {
    pub fn new(node: &'a dyn Node, store: &'a dyn Store, key: &'a KeyMaterial) -> Self {
        Withdrawer { node, store, key, cfg: Config::default() }
    }

    /// Register a withdrawal under the CALLER's id. Idempotent: an id that
    /// already exists returns its record if the terms match, and errs if
    /// they do not — silently accepting changed terms under an old id is a
    /// double-payment with extra steps.
    ///
    /// Registration is pure bookkeeping: no coins move, no RPC happens. The
    /// work is in [`Self::tick`].
    pub fn create(
        &self,
        id: &str,
        recipient: &str,
        amount_sat: u64,
    ) -> Result<WithdrawalRecord, WithdrawError> {
        if id.is_empty() {
            return Err(WithdrawError::BadRequest("empty withdrawal id".into()));
        }
        // `recipient` is a 64-hex script_hash — the identifier Genesis-4 uses.
        // An address is accepted only under `allow_carryover_address`, and only
        // on the configured network; see `address::parse_payee`.
        let (recipient_script_hash, _form) = parse_payee(
            recipient,
            self.cfg.network,
            self.cfg.allow_carryover_address,
        )
        .map_err(WithdrawError::BadRequest)?;
        if amount_sat < self.cfg.dust_floor_sat {
            return Err(WithdrawError::BadRequest(format!(
                "amount {amount_sat} sat is below the dust floor ({} sat)",
                self.cfg.dust_floor_sat
            )));
        }
        if let Some(existing) = self.store.load(id)? {
            if existing.recipient_script_hash != recipient_script_hash
                || existing.amount_sat != amount_sat
            {
                return Err(WithdrawError::IdMismatch(format!(
                    "id {id:?} already exists with different recipient or amount"
                )));
            }
            return Ok(existing);
        }
        let record = WithdrawalRecord {
            id: id.to_string(),
            recipient_script_hash,
            amount_sat,
            pinned: Vec::new(),
            attempts: Vec::new(),
            status: Status::Submitted,
            cancel_requested: false,
        };
        self.store.save(&record)?;
        Ok(record)
    }

    /// Ask for cancellation. NOT a guarantee: an already-broadcast payment
    /// attempt may still land, in which case the terminal state is `Paid`.
    /// What this does guarantee is that from the next tick on, the machine
    /// races the payment with a sweep that conflicts with it — and whichever
    /// finalizes, it is exactly one of them.
    pub fn cancel(&self, id: &str) -> Result<Status, WithdrawError> {
        let mut rec =
            self.store.load(id)?.ok_or_else(|| WithdrawError::UnknownId(id.to_string()))?;
        if !rec.status.is_terminal() {
            rec.cancel_requested = true;
            self.store.save(&rec)?;
        }
        Ok(rec.status)
    }

    /// Advance one withdrawal one step. Call it on a schedule (once per slot,
    /// 30 s, is plenty) until the returned status is terminal.
    ///
    /// Every path through this function preserves the two invariants: no
    /// bytes are built except over the pinned set, and no rebuild happens
    /// except after observing the pinned set unspent this very tick.
    pub fn tick(&self, id: &str) -> Result<TickOutcome, WithdrawError> {
        let mut rec =
            self.store.load(id)?.ok_or_else(|| WithdrawError::UnknownId(id.to_string()))?;
        if rec.status.is_terminal() {
            return Ok(TickOutcome { status: rec.status, submit: None });
        }

        let info = chain_info(self.node)?;
        if info.behind_by_slots > self.cfg.max_behind_slots {
            return Err(WithdrawError::NodeStale { behind_by_slots: info.behind_by_slots });
        }

        // ── First contact: pin coins, build, submit ─────────────────────────
        if rec.attempts.is_empty() {
            let built = self.build_growing_pins(&mut rec, &info)?;
            let submit = self.record_and_submit(&mut rec, &info, built)?;
            return Ok(TickOutcome { status: rec.status, submit: Some(submit) });
        }

        // ── Probe: are the pinned coins still unspent at this node's head? ──
        let sentinel = rec.pinned[0];
        let probe = get_txout(self.node, &sentinel.txid, sentinel.vout)?;

        if probe.unspent {
            // Nothing of ours is on the canonical chain. If we previously saw
            // a spend, it was reorged out — walk back and resume.
            if matches!(rec.status, Status::AwaitingFinality { .. }) {
                rec.status = Status::Submitted;
                self.store.save(&rec)?;
            }
            let kind =
                if rec.cancel_requested { AttemptKind::Sweep } else { AttemptKind::Pay };
            // Reuse the newest attempt already built for exactly the price the
            // next block will charge; only when none exists is this a REBUILD —
            // and we only got here after confirming non-inclusion above.
            let existing = rec.attempts.iter().rposition(|a| {
                a.kind == kind && a.base_fee_msat_per_gas == info.next_base_fee_msat_per_gas
            });
            let submit = match existing {
                Some(i) => {
                    let bytes = decode_hex_or_bug(&rec.attempts[i].canonical_hex);
                    send_raw(self.node, &bytes)?
                }
                None => {
                    let built = self.build_growing_pins(&mut rec, &info)?;
                    self.record_and_submit(&mut rec, &info, built)?
                }
            };
            return Ok(TickOutcome { status: rec.status, submit: Some(submit) });
        }

        // ── The pinned coins are spent: one of our attempts landed ──────────
        //
        // (Only ours can spend them: the key is this client's, and the store's
        // reservation keeps other withdrawals off these coins. If the operator
        // spends hot-wallet coins outside this library, that discipline — not
        // this code — is what broke.)
        if !matches!(rec.status, Status::AwaitingFinality { .. }) {
            let landed = self.find_landed_attempt(&rec)?;
            rec.status =
                Status::AwaitingFinality { landed, observed_slot: probe.at_slot };
            self.store.save(&rec)?;
        }

        // ── Finality: credit only below the settled line ────────────────────
        if let Status::AwaitingFinality { landed, observed_slot } = rec.status.clone() {
            if info.finalized_boundary_slot() > observed_slot {
                let recheck = get_txout(self.node, &sentinel.txid, sentinel.vout)?;
                if recheck.unspent {
                    // Reorged out between observation and finality. Resume.
                    rec.status = Status::Submitted;
                    self.store.save(&rec)?;
                    return Ok(TickOutcome { status: rec.status, submit: None });
                }
                let landed = match landed {
                    Some(i) => Some(i),
                    None => self.find_landed_attempt(&rec)?,
                };
                rec.status = match landed {
                    Some(i) if rec.attempts[i].kind == AttemptKind::Sweep => {
                        Status::Cancelled { attempt: i }
                    }
                    Some(i) => Status::Paid { attempt: Some(i) },
                    // No attempt's output is visible any more — the recipient
                    // (or, for a sweep, a later consolidation) already spent
                    // it. The spend of the pinned set is finalized either
                    // way; with no sweep identified, the money went to the
                    // recipient by elimination (sweep outputs are reserved
                    // and unspendable until this very record terminalizes).
                    None => Status::Paid { attempt: None },
                };
                self.store.save(&rec)?;
            }
        }
        Ok(TickOutcome { status: rec.status, submit: None })
    }

    /// Which attempt's output exists on the canonical chain right now.
    /// Payment attempts and the sweep both place their identifying output at
    /// vout 0 (the recipient's, or the swept change).
    fn find_landed_attempt(&self, rec: &WithdrawalRecord) -> Result<Option<usize>, WithdrawError> {
        for (i, attempt) in rec.attempts.iter().enumerate() {
            if get_txout(self.node, &attempt.txid, 0)?.unspent {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    /// Build an attempt over the pinned set at the fee the next block will
    /// charge, growing the pinned set from the hot wallet when it cannot
    /// cover amount + fee. Growth is append-only, so every earlier attempt
    /// still shares coins with every later one.
    fn build_growing_pins(
        &self,
        rec: &mut WithdrawalRecord,
        info: &ChainInfo,
    ) -> Result<BuiltTransfer, WithdrawError> {
        let payment: Option<(ScriptHash, u64)> = if rec.cancel_requested {
            None
        } else {
            Some((rec.recipient_script_hash, rec.amount_sat))
        };
        // A sweep needs pins to sweep; a payment needs at least one coin.
        if rec.pinned.is_empty() {
            let needed = u128::from(rec.amount_sat) + 1; // fee refined below
            self.grow_pins(rec, needed)?;
        }
        loop {
            let request = BuildRequest {
                key: self.key,
                coins: &rec.pinned,
                payment,
                change_script: self.key.script_hash(),
                base_fee_msat_per_gas: info.next_base_fee_msat_per_gas,
                tip_msat_per_gas: self.cfg.tip_msat_per_gas,
                dust_floor_sat: self.cfg.dust_floor_sat,
                format: format_for_epoch(info.epoch),
            };
            match build_transfer(&request) {
                Ok(built) => return Ok(built),
                Err(BuildError::InsufficientFunds { needed, .. }) => {
                    self.grow_pins(rec, needed)?;
                }
                Err(BuildError::DustGap { .. }) => {
                    // Push the change out of the dust window with one more coin.
                    let held: u128 = rec.pinned.iter().map(|c| u128::from(c.value_sat)).sum();
                    self.grow_pins(rec, held + u128::from(self.cfg.dust_floor_sat))?;
                }
                Err(e) => return Err(WithdrawError::Build(e)),
            }
        }
    }

    /// Append unreserved hot-wallet coins until the pinned set covers
    /// `needed_sat`. Saves the record BEFORE returning: pins must be durable
    /// before any attempt is built over them.
    fn grow_pins(&self, rec: &mut WithdrawalRecord, needed_sat: u128) -> Result<(), WithdrawError> {
        let mut reserved = reserved_outpoints(self.store)?;
        for c in &rec.pinned {
            reserved.insert(c.outpoint()); // don't re-pin our own
        }
        let (mut utxos, _truncated) =
            list_unspent(self.node, &self.key.script_hash(), self.cfg.utxo_page)?;
        // Largest first: fewer inputs, fewer bytes, cheaper fee.
        utxos.sort_by(|a, b| b.value_sat.cmp(&a.value_sat));

        let mut held: u128 = rec.pinned.iter().map(|c| u128::from(c.value_sat)).sum();
        let before = rec.pinned.len();
        for u in utxos {
            if held >= needed_sat {
                break;
            }
            if reserved.contains(&(u.txid, u.vout)) {
                continue;
            }
            rec.pinned.push(Coin { txid: u.txid, vout: u.vout, value_sat: u.value_sat });
            held += u128::from(u.value_sat);
        }
        if held < needed_sat {
            return Err(WithdrawError::WalletShort { available: held, needed: needed_sat });
        }
        if rec.pinned.len() != before {
            self.store.save(rec)?;
        }
        Ok(())
    }

    /// Write-ahead, then submit: the attempt is durable before its bytes can
    /// reach the network, so a crash cannot leave the network knowing a
    /// transaction this store has never heard of.
    fn record_and_submit(
        &self,
        rec: &mut WithdrawalRecord,
        info: &ChainInfo,
        built: BuiltTransfer,
    ) -> Result<SubmitOutcome, WithdrawError> {
        let kind = if rec.cancel_requested { AttemptKind::Sweep } else { AttemptKind::Pay };
        debug_assert_eq!(built.base_fee_msat_per_gas, info.next_base_fee_msat_per_gas);
        rec.attempts.push(Attempt {
            kind,
            txid: built.txid,
            base_fee_msat_per_gas: built.base_fee_msat_per_gas,
            tip_msat_per_gas: built.tip_msat_per_gas,
            declared_tx_bytes: built.declared_tx_bytes,
            canonical_hex: hex_of(&built.canonical),
            change_sat: built.change_sat,
        });
        rec.status = Status::Submitted;
        self.store.save(rec)?;
        Ok(send_raw(self.node, &built.canonical)?)
    }
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Attempts are stored as hex this crate itself encoded; a decode failure is
/// a corrupted store, and paying from a corrupted store is the one thing
/// worse than stopping.
fn decode_hex_or_bug(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("corrupted attempt hex in store");
        let lo = (pair[1] as char).to_digit(16).expect("corrupted attempt hex in store");
        out.push((hi * 16 + lo) as u8);
    }
    out
}
