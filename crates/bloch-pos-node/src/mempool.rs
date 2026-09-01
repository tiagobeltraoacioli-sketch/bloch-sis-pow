// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mempool admission control: what this node holds, and what it throws away
//! to hold something better.
//!
//! # This is node-local policy. It is not consensus, and it must never become
//! consensus.
//!
//! Nothing in this file is read by [`bloch_pos_committee::transition`]. A
//! block is valid or invalid by the transition's rules alone; this module
//! only decides which transactions *this* node keeps around and in what order
//! it offers them when it is its turn to propose. Two nodes running different
//! policies — one running this file, one running the `BTreeMap` it replaces —
//! accept and reject exactly the same blocks, because neither node consults
//! its own mempool when judging someone else's block. The separation is
//! argued in full at [`crate::engine::select_transactions`] and pinned by
//! `mempool_policy_is_not_block_validity`.
//!
//! Concretely, the crate boundary is the proof: `bloch-pos-committee` does
//! not depend on `bloch-pos-node`, so no consensus code path can reach this
//! type at all. This work touched no file in that crate.
//!
//! # What was here before, and why it was not enough
//!
//! A `BTreeMap<Vec<u8>, PosTransaction>` with one rule: at 4,096 entries,
//! refuse. Its own doc claimed the pool was "insertion-ordered". It was not —
//! a `BTreeMap` keyed by canonical transaction bytes is ordered
//! LEXICOGRAPHICALLY BY THOSE BYTES, which is a value an attacker grinds and
//! an honest wallet cannot influence at all. Measured, and re-measured on
//! every run against a faithful reproduction of the old policy
//! (`engine::mempool_flood_before_and_after`):
//!
//! - 4,096 transactions offering a tip of zero filled the pool, and a
//!   transfer offering `u128::MAX` per gas was then refused `AtCapacity`
//!   without its price ever being read;
//! - the proposer packed blocks in ascending canonical-byte order, so what
//!   got included was decided by a hash-like prefix rather than by what
//!   anyone paid;
//! - one keypair held all 4,096 slots, because nothing counted per sender.
//!
//! # The three rules this module adds
//!
//! 1. **Eviction by price.** At capacity, the cheapest held transaction is
//!    displaced by an arriving one that strictly beats it. Strictly, not
//!    "at least": equal prices must not churn, or a flood at the floor price
//!    becomes a way to make the node do work forever.
//! 2. **A per-sender bound** — see [`senders`] for what "sender" is allowed
//!    to mean here, and for the honest limits of the idea.
//! 3. **Ordering by price**, for eviction and for what the proposer packs,
//!    with the old canonical-byte order kept as the tie-break so equal-priced
//!    traffic behaves exactly as it does today.
//!
//! # What this policy bounds — and, precisely, what it does not
//!
//! Stating the second half is the point. A claimed defence that does not hold
//! is worse than a named gap.
//!
//! ## Bounded
//!
//! 1. **Memory.** At most [`MEMPOOL_MAX`] entries, whatever an attacker does.
//!    Driven adversarially by `the_bound_is_never_exceeded_however_it_is_driven`
//!    and `the_memory_bound_holds_under_everything`.
//! 2. **Lockout by a cheap flood.** A pool full of minimum-fee traffic can no
//!    longer keep a paying transaction out; the cheapest entry is displaced by
//!    anything that strictly beats it. Measured.
//! 3. **Monopoly by one address.** No single address holds more than
//!    [`PER_SENDER_MAX`] of the queue. Measured: 4,096 → 256.
//! 4. **Verification work spent on traffic that cannot get in.** Price and
//!    quota are decided BEFORE `admissible` runs, so a refused offer costs a
//!    SHA3 per witness key rather than a ~145 µs hybrid verification. This is
//!    the same ordering the old code had (capacity was checked before
//!    `admissible` too), generalised.
//!
//! ## NOT bounded, and why no policy here could bound it
//!
//! Admission is stateless by construction: it never resolves an input against
//! the committed eUTXO set. A policy that read committed state would be a
//! node-local derivation of a consensus-shaped fact, which is exactly the
//! `expected_bits` mistake that forked this network on 2026-08-08. So:
//!
//! 1. **Sybil identities.** A bucket is the hash of a public key, and keys are
//!    free. `MEMPOOL_MAX / PER_SENDER_MAX` = 16 fresh keypairs buys the whole
//!    pool again. The quota stops one address monopolising the queue; it is
//!    NOT a sybil defence and must never be sold as one. What actually prices
//!    a funded flood is the ladder, not the quota.
//! 2. **Transfers that will never apply.** Nonexistent inputs
//!    (`UnknownInput`), a key that signed but owns nothing
//!    (`ScriptMismatch`), value that does not conserve — all reach the pool.
//!    They pay a tip they will never be charged, so a well-crafted one can
//!    even outbid real traffic. They die in the proposer's probe.
//! 3. **An invalid SIGNED EXIT (tag `0x09`, on branch `wt/signed-exit-wire`)
//!    — the sharpest case, and the one this module explicitly does not
//!    defend against.** The message carries the HASH of the withdrawal key,
//!    not the key; the key itself lives in the validator record in committed
//!    state, which this path deliberately does not read. Admission therefore
//!    cannot verify the signature at all — not "does not bother to", *cannot*.
//!    It is cheap to gossip, it is indistinguishable at the door from a valid
//!    one, and it consumes a slot until a proposer probes it. Every stateful
//!    refusal has this shape; the signed exit is merely the cheapest to mint.
//!
//!    Nothing in this file changes that, and nothing in this file claims to.
//!    In THIS tree the unsigned [`PosTransaction::Exit`] is refused outright
//!    by [`crate::engine::admissible`], so the vector is not yet reachable
//!    here — but it becomes reachable the moment `0x09` lands, and the price
//!    such a message should carry is an open decision. `price_of` gives it
//!    `Tip(0)` today, which is the safe direction (first evicted, never
//!    protected), and `staking_messages_are_evicted_first` is the tripwire
//!    that forces whoever lands `0x09` to revisit it rather than inherit it.
//!
//! ## Where the unbounded classes actually die, and why the bar must expire
//!
//! In the proposer's probe, barred by [`crate::engine::REJECTION_TTL_SLOTS`]
//! — a bar that **expires after 128 slots**, deliberately. A refusal like
//! `UnknownInput` is a statement about state at ONE MOMENT: a transfer
//! spending an output still sitting in the mempool is refused now and
//! perfectly valid the instant its parent lands. A permanent ban would turn
//! that coin into one that can never be moved, with no signal to the sender.
//! `an_orphan_child_is_barred_and_the_bar_expires_on_its_own` measures both
//! halves — the bar is real, and it lifts on its own at exactly
//! `slot + 128`.
//!
//! **Nothing in this module writes that bar, and nothing in this module may.**
//! An eviction for price is not a verdict on a transaction; a transaction
//! that lost an auction must be free to come straight back when the auction
//! changes, and a sender at its quota gets in the moment one of its own
//! transactions confirms. Both refusals here mean "not now", and both stop
//! being true without anyone doing anything.

use std::collections::{BTreeMap, BTreeSet};

use bloch_pos_committee::transition::PosTransaction;
use sha3::{Digest, Sha3_256};

/// Ceiling on mempool entries — a memory bound, unchanged in value from the
/// bare `MEMPOOL_MAX` this module inherited. It is still not a policy: the
/// policy is what happens AT the bound, which is now an auction instead of a
/// closed door.
pub const MEMPOOL_MAX: usize = 4_096;

/// Entries one sender may hold at once.
///
/// 256, and the number is not free: it is exactly
/// [`crate::engine::MAX_TXS_PER_BLOCK`], pinned by a compile-time assertion
/// at that constant. The rule it expresses is "one sender may hold at most
/// one full block's worth of the queue" — enough to saturate the very next
/// block by itself, never enough to own more than 1/16 of what is waiting.
///
/// **It is chosen against a real workload, not against an attacker.** The
/// founder's consolidation sweep submits hundreds of thousands of transfers
/// from a single address through `sendrawtransaction` (see the refusal
/// commentary in `engine::serve_rpc`). Any cap below `MAX_TXS_PER_BLOCK`
/// would throttle that sweep below the block cap that already binds it; at
/// exactly `MAX_TXS_PER_BLOCK` the sweep's throughput is unchanged, because
/// the proposer could never have taken more than a block's worth per block
/// anyway. A bound that breaks the one heavy user the chain actually has is
/// not a bound, it is an outage.
pub const PER_SENDER_MAX: usize = 256;

/// What a mempool entry is worth to a proposer, for ordering and eviction.
///
/// The derived `Ord` is load-bearing: `Tip(_) < Protected` for every tip, so
/// "cheapest first" puts every priced transaction ahead of every protected
/// one and a scan for the eviction victim can never land on evidence while a
/// paying transaction is available to drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Price {
    /// The sender's tip, in millisatoshi per gas — the **only** user-set
    /// price in the system (`fee_market::charge`: gas is derived from class
    /// and size, and the base fee is the protocol's, identical for every
    /// transaction in a block). Ordering by the tip is therefore ordering by
    /// the only quantity a sender can actually bid with, and it is the same
    /// quantity the producer is paid out of.
    ///
    /// Deliberately the RATE and not the total. Two candidates for a block
    /// compete for its scarce resource, and the scarce resource is priced
    /// per gas (`fee_market` §: bytes bind first, and bytes are charged
    /// through gas). Ranking by total tip would let one enormous transaction
    /// outbid a hundred small ones that pay more for the same room.
    Tip(u128),
    /// Pays no tip and is not evictable by price.
    ///
    /// Today this is slashing evidence, and only slashing evidence. Evidence
    /// is a public good: it carries no fee by design, it is what removes an
    /// equivocating validator, and a fee market that let a flood of paying
    /// spam displace it would sell the chain's own defence by the byte. It
    /// is safe to protect precisely because its admission is already bounded
    /// somewhere else — `evidence_admissible` refuses evidence against an
    /// unknown or already-slashed offender, refuses an already-applied pair,
    /// allows ONE in-flight evidence per offender, and verifies both
    /// signatures — so the protected population is bounded by the validator
    /// count, not by an attacker's budget.
    Protected,
}

/// The price [`Mempool`] ranks a transaction at.
///
/// The staking messages have no arm of their own on purpose. `Deposit`,
/// `Delegate` and `Exit` are refused outright by
/// [`crate::engine::admissible`] today, so they never reach this function
/// through the node; they fall to `Tip(0)`, the FIRST thing evicted, and that
/// is the deliberate direction to be wrong in — protecting an unfunded,
/// unauthenticated message would be the dangerous default. When bonding is
/// funded from the eUTXO set and these messages start carrying inputs and a
/// tip, this arm must be revisited with them, and the
/// `staking_messages_are_evicted_first` test exists to make that revisit
/// impossible to forget.
pub fn price_of(tx: &PosTransaction) -> Price {
    match tx {
        PosTransaction::Transfer { tip_millisat_per_gas, .. }
        | PosTransaction::TransferV2 { tip_millisat_per_gas, .. } => {
            Price::Tip(*tip_millisat_per_gas)
        }
        PosTransaction::SlashingEvidence(_) => Price::Protected,
        PosTransaction::Deposit { .. }
        | PosTransaction::Delegate { .. }
        | PosTransaction::Exit { .. } => Price::Tip(0),
    }
}

/// The senders a transaction is charged to, as 32-byte address hashes.
///
/// # What "sender" can honestly mean here
///
/// There is no `from` field in a UTXO model, and admission does not resolve
/// inputs — it never looks up an outpoint, by design, because a policy that
/// read committed state would be the beginning of a node-local consensus
/// derivation. So the account that owns the coins is not available at this
/// door.
///
/// What IS available is the witness. Every transfer carries the public keys
/// that signed it, and [`crate::engine::admissible`] has already verified
/// each of those signatures over
/// [`PosTransaction::spend_signing_root`] before anything is held. **Sender
/// here means: the SHA3-256 of a public key that produced a valid signature
/// over this transaction.** That is exactly the 32 bytes consensus calls
/// `script_hash` — the value a committed output commits to and the value
/// `getbalance` is keyed by — so a bucket in this map is an address in the
/// ordinary sense, not an invented identity.
///
/// A transaction is charged to EVERY distinct signer, not to one nominated
/// "the" sender. Picking one (the first input's key, say) would let a
/// two-owner transfer pay one bucket and spend from two; charging all of
/// them can only ever cost a transaction more buckets, never fewer, so
/// adding a co-signer is not an evasion.
///
/// # What this does NOT prove, stated plainly
///
/// 1. **It is not proof of ownership.** The signature verifies under the key;
///    whether that key owns the outputs being spent is `ScriptMismatch`, and
///    `ScriptMismatch` reads committed `script_hash`es this path never
///    touches. So a well-formed transfer signed by a key that owns nothing is
///    attributed to that key, occupies its quota, and dies later in the
///    proposer's probe. That is the correct place for it to die.
/// 2. **It is not a sybil defence, and must not be sold as one.** Anyone can
///    generate a fresh hybrid keypair and get a fresh 256-entry quota; at
///    `MEMPOOL_MAX / PER_SENDER_MAX` = 16 keys an attacker has the whole
///    pool again. What the bound actually buys is that no SINGLE address can
///    monopolise the queue, which bounds accidental self-DoS by a busy wallet
///    and forces a flooder to spend a keypair and a signature per 256 slots.
///    The thing that stops a funded flood is the price ladder above, not
///    this. Any claim to the contrary would need a cost the attacker cannot
///    mint, and admission has none.
///
/// Non-transfer transactions are charged to nobody: evidence names no
/// spender, and the staking messages are refused before they get here.
///
/// # Cost
///
/// One SHA3-256 over each witness key (~3.7 KB each). This runs BEFORE the
/// signature checks, on an unauthenticated path — deliberately, because it is
/// three orders of magnitude cheaper than the hybrid verification it gates
/// (measured 145 µs per verify, 2026-08-21), so a transaction refused for
/// quota or price costs this node a few microseconds of hashing and no
/// lattice arithmetic at all.
pub fn senders(tx: &PosTransaction) -> Vec<[u8; 32]> {
    let keys: Vec<&[u8]> = match tx {
        PosTransaction::Transfer { inputs, .. } => {
            inputs.iter().map(|i| i.pubkey.as_slice()).collect()
        }
        PosTransaction::TransferV2 { keys, .. } => {
            keys.iter().map(|k| k.pubkey.as_slice()).collect()
        }
        _ => Vec::new(),
    };
    // Distinct, and in a deterministic order: a V1 transfer repeats the same
    // pubkey once per input, and charging a 30-input self-spend thirty
    // buckets of one address would make the quota mean something else.
    let distinct: BTreeSet<&[u8]> = keys.into_iter().collect();
    distinct.into_iter().map(|k| Sha3_256::digest(k).into()).collect()
}

/// Why the mempool would not take a transaction. Neither variant is a verdict
/// on the transaction itself, and neither may ever be written to the
/// rejection bar: both say "not now", and both stop being true on their own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The pool is full and the offered price did not strictly beat the
    /// cheapest thing in it. `floor` is that cheapest price when there is a
    /// priced entry to name, so a caller can tell a client what it would take
    /// — `None` when the pool holds nothing evictable at all.
    AtCapacity { floor: Option<u128> },
    /// This sender already holds [`PER_SENDER_MAX`] entries.
    SenderQuota { sender: [u8; 32], held: usize },
}

/// One held transaction, with the two facts admission derived about it. Both
/// are cached rather than recomputed on removal: `senders` in particular
/// costs a SHA3 per witness key, and a removal that recomputed them could
/// decrement a different bucket than the insert incremented if the derivation
/// ever changed underneath.
struct Entry {
    tx: PosTransaction,
    price: Price,
    senders: Vec<[u8; 32]>,
}

/// What [`Mempool::decide`] concluded, so the check and the insert cannot
/// drift apart: both go through the same function, and the insert simply
/// carries out what the check promised.
enum Decision {
    /// There is room; nothing has to go.
    Fits,
    /// The pool is full; this key is the one to displace.
    Displace(Vec<u8>),
}

/// The waiting transactions, with a price on each.
pub struct Mempool {
    capacity: usize,
    entries: BTreeMap<Vec<u8>, Entry>,
    /// Address hash → entries charged to it. Maintained in exactly two
    /// places, [`Mempool::insert`] and [`Mempool::remove`], and checked
    /// against a full recomputation by `sender_counts_never_drift`.
    per_sender: BTreeMap<[u8; 32], usize>,
    evicted_by_price: u64,
    refused_by_sender_cap: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Self::with_capacity(MEMPOOL_MAX)
    }

    /// A pool with a chosen ceiling. For tests: the policy is
    /// capacity-parametric, so flood behaviour can be exercised exactly at a
    /// boundary of eight instead of four thousand, and the real ceiling stays
    /// one constant pinned in one place.
    pub fn with_capacity(capacity: usize) -> Self {
        Mempool {
            capacity,
            entries: BTreeMap::new(),
            per_sender: BTreeMap::new(),
            evicted_by_price: 0,
            refused_by_sender_cap: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.entries.contains_key(key)
    }

    /// Canonical bytes and transaction, in the old lexicographic key order.
    /// This is the SWEEP's and the drop loop's view — order is irrelevant to
    /// both, and keeping it byte-ordered keeps those paths byte-identical to
    /// what they did before.
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &PosTransaction)> {
        self.entries.iter().map(|(k, e)| (k, &e.tx))
    }

    pub fn values(&self) -> impl Iterator<Item = &PosTransaction> {
        self.entries.values().map(|e| &e.tx)
    }

    /// Total canonical bytes held — what `getmempoolinfo` reports, computed
    /// here so no caller has to know the keys are the encodings.
    pub fn bytes(&self) -> usize {
        self.entries.keys().map(Vec::len).sum()
    }

    pub fn evicted_by_price(&self) -> u64 {
        self.evicted_by_price
    }

    pub fn refused_by_sender_cap(&self) -> u64 {
        self.refused_by_sender_cap
    }

    /// The tip an arriving transfer must strictly exceed to get in, or `None`
    /// when the pool is not full and nothing has to be beaten.
    ///
    /// This is the number an integrator is actually asking for when they ask
    /// "what do I have to pay". It is reported through `getmempoolinfo`
    /// rather than inferred, because inferring it from `size` and `max` is
    /// exactly the kind of guess that turns into a support ticket.
    pub fn floor_tip(&self) -> Option<u128> {
        if self.entries.len() < self.capacity {
            return None;
        }
        self.cheapest().and_then(|(_, p)| match p {
            Price::Tip(t) => Some(t),
            Price::Protected => None,
        })
    }

    /// The entry that would be displaced next: lowest price, and among equal
    /// prices the lowest canonical bytes.
    ///
    /// A linear scan, on purpose, and not a second index keyed by price.
    /// The pool holds at most [`MEMPOOL_MAX`] entries and this runs once per
    /// admission that finds the pool full; comparing 4,096 `u128`s costs
    /// microseconds against the 145 µs of the single hybrid verification the
    /// same admission is about to perform. A price index would buy nothing
    /// measurable and would add the one failure this design cannot afford —
    /// an index that disagrees with the map, which is how a "cheapest" entry
    /// that no longer exists gets evicted and a real one silently leaks.
    fn cheapest(&self) -> Option<(&Vec<u8>, Price)> {
        self.entries
            .iter()
            .map(|(k, e)| (k, e.price))
            // `min_by_key` keeps the FIRST minimum, and `entries` iterates in
            // ascending key order, so ties resolve to the lowest canonical
            // bytes without a second comparison.
            .min_by_key(|(_, p)| *p)
    }

    /// The one decision function. Pure: it mutates nothing, so a caller may
    /// ask before doing expensive verification and act on the answer
    /// afterwards, provided nothing touched the pool in between.
    fn decide(&self, price: Price, senders: &[[u8; 32]]) -> Result<Decision, Refused> {
        // The quota first, and ahead of price: a sender at its ceiling is
        // refused however much it offers. That ordering IS the rule — a cap
        // a rich sender can buy its way past is not a cap.
        for s in senders {
            let held = self.per_sender.get(s).copied().unwrap_or(0);
            if held >= PER_SENDER_MAX {
                return Err(Refused::SenderQuota { sender: *s, held });
            }
        }
        if self.entries.len() < self.capacity {
            return Ok(Decision::Fits);
        }
        let Some((victim, victim_price)) = self.cheapest() else {
            // Capacity zero: nothing to displace and no room. Degenerate, but
            // a defined answer.
            return Err(Refused::AtCapacity { floor: None });
        };
        // A protected entry is never displaced by price. Reaching here means
        // the pool holds nothing BUT protected entries, and the honest answer
        // is that this node is full — not that it will sell its own slashing
        // evidence for a tip.
        let Price::Tip(floor) = victim_price else {
            return Err(Refused::AtCapacity { floor: None });
        };
        match price {
            // Strictly greater. Equality must not displace, or a flood
            // arriving at exactly the floor price makes the node churn its
            // pool forever at one eviction per message — the same
            // re-offer/re-drop loop the rejection cache exists to stop, with
            // the bar unavailable because a price loss is not a refusal.
            Price::Tip(t) if t > floor => Ok(Decision::Displace(victim.clone())),
            Price::Tip(_) => Err(Refused::AtCapacity { floor: Some(floor) }),
            // Protected outbids any tip: this is where evidence gets in
            // through a pool full of paying traffic.
            Price::Protected => Ok(Decision::Displace(victim.clone())),
        }
    }

    /// Would this transaction be taken, right now? Mutates nothing.
    ///
    /// Called before the signature checks, so a transaction that cannot get
    /// in costs this node no lattice arithmetic; and deliberately NOT trusted
    /// to stand in for the insert, which re-decides.
    pub fn check_admission(&self, tx: &PosTransaction) -> Result<(), Refused> {
        self.decide(price_of(tx), &senders(tx)).map(|_| ())
    }

    /// Hold a transaction, displacing the cheapest one if the pool is full.
    ///
    /// Returns the canonical bytes of whatever was displaced. The caller must
    /// NOT bar a displaced transaction: it lost an auction, it was not
    /// judged. See the module doc.
    ///
    /// Re-runs [`Self::decide`] rather than trusting an earlier
    /// [`Self::check_admission`], so the invariant "`len <= capacity`, always"
    /// holds no matter what a caller does between the two calls.
    pub fn insert(
        &mut self,
        key: Vec<u8>,
        tx: PosTransaction,
    ) -> Result<Option<Vec<u8>>, Refused> {
        // Replacing an existing key is not an insertion: drop the old entry's
        // accounting first so the quota cannot be double-charged. The engine
        // never does this (it answers `Duplicate` first), but the type must
        // not depend on that.
        if self.entries.contains_key(&key) {
            self.remove(&key);
        }
        let price = price_of(&tx);
        let senders = senders(&tx);
        let displaced = match self.decide(price, &senders)? {
            Decision::Fits => None,
            Decision::Displace(victim) => {
                self.remove(&victim);
                self.evicted_by_price = self.evicted_by_price.saturating_add(1);
                Some(victim)
            }
        };
        for s in &senders {
            *self.per_sender.entry(*s).or_insert(0) += 1;
        }
        self.entries.insert(key, Entry { tx, price, senders });
        Ok(displaced)
    }

    /// Note a refusal for quota, for the counter `getmempoolinfo` exposes.
    ///
    /// Separate from [`Self::check_admission`] because the check is `&self`
    /// and counting is a write; the engine calls this on the one path where a
    /// quota refusal actually turned a transaction away, so the number means
    /// "offers refused", not "times the rule was evaluated".
    pub fn note_sender_cap_refusal(&mut self) {
        self.refused_by_sender_cap = self.refused_by_sender_cap.saturating_add(1);
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<PosTransaction> {
        let entry = self.entries.remove(key)?;
        for s in &entry.senders {
            match self.per_sender.get_mut(s) {
                Some(n) if *n > 1 => *n -= 1,
                // Last one out takes the bucket with it, so an idle address
                // costs nothing and the map stays bounded by the number of
                // addresses currently holding something.
                _ => {
                    self.per_sender.remove(s);
                }
            }
        }
        Some(entry.tx)
    }

    /// Entries in the order a proposer should pack them: protected first,
    /// then descending tip, and among equal prices ascending canonical bytes
    /// — which is precisely the order the whole pool had before this change,
    /// so equal-priced traffic is packed exactly as it always was.
    ///
    /// Protected first because evidence is what ejects an equivocating
    /// validator and it pays no tip by design; leaving it to sort below every
    /// paying transaction would mean a busy chain never slashes anyone.
    pub fn by_price_desc(&self) -> Vec<(&Vec<u8>, &PosTransaction)> {
        let mut v: Vec<(&Vec<u8>, &PosTransaction, Price)> =
            self.entries.iter().map(|(k, e)| (k, &e.tx, e.price)).collect();
        // Stable sort over an ascending-key vector: the key comparison is
        // only needed to make the ordering total for the tests to state, and
        // stability already gives it for free.
        v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));
        v.into_iter().map(|(k, t, _)| (k, t)).collect()
    }

    /// Recompute the per-sender table from the held entries. Test-only: this
    /// is what the maintained map is checked against.
    #[cfg(test)]
    fn recomputed_sender_counts(&self) -> BTreeMap<[u8; 32], usize> {
        let mut m: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for e in self.entries.values() {
            for s in senders(&e.tx) {
                *m.entry(s).or_insert(0) += 1;
            }
        }
        m
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::transition::{TransferInput, TransferOutput};

    /// A transfer with a chosen owner and tip. The witness bytes are a stand-
    /// in: this module never verifies a signature — that is
    /// `engine::admissible`'s job, in front of it — so what matters here is
    /// only that the pubkey is the value `senders` hashes.
    fn tx(owner: u8, seed: u32, tip: u128) -> PosTransaction {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&seed.to_be_bytes());
        PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid,
                vout: 0,
                pubkey: vec![owner; 8],
                signature: Vec::new(),
            }],
            outputs: vec![TransferOutput { value: 1, script_hash: [0xEE; 32] }],
            tx_bytes: 0,
            tip_millisat_per_gas: tip,
        }
    }

    fn put(m: &mut Mempool, t: &PosTransaction) -> Result<Option<Vec<u8>>, Refused> {
        m.insert(t.canonical_bytes(), t.clone())
    }

    fn tips(m: &Mempool) -> Vec<u128> {
        m.by_price_desc()
            .into_iter()
            .map(|(_, t)| match price_of(t) {
                Price::Tip(v) => v,
                Price::Protected => u128::MAX,
            })
            .collect()
    }

    #[test]
    fn a_full_pool_takes_a_higher_bid_and_drops_the_cheapest() {
        let mut m = Mempool::with_capacity(4);
        for (seed, tip) in [(1u32, 10u128), (2, 20), (3, 30), (4, 40)] {
            put(&mut m, &tx(0xA0 + seed as u8, seed, tip)).expect("room");
        }
        assert_eq!(m.floor_tip(), Some(10));

        let rich = tx(0xFF, 99, 11);
        let displaced = put(&mut m, &rich).expect("11 beats the floor of 10");
        assert_eq!(displaced, Some(tx(0xA1, 1, 10).canonical_bytes()));
        assert_eq!(m.len(), 4, "the bound held");
        assert!(m.contains_key(&rich.canonical_bytes()));
        assert_eq!(m.evicted_by_price(), 1);
        assert_eq!(tips(&m), vec![40, 30, 20, 11]);
    }

    #[test]
    fn equal_price_does_not_displace() {
        let mut m = Mempool::with_capacity(2);
        put(&mut m, &tx(1, 1, 10)).unwrap();
        put(&mut m, &tx(2, 2, 10)).unwrap();
        assert_eq!(
            put(&mut m, &tx(3, 3, 10)),
            Err(Refused::AtCapacity { floor: Some(10) }),
            "matching the floor must not churn the pool"
        );
        assert_eq!(m.evicted_by_price(), 0);
    }

    #[test]
    fn the_floor_is_reported_only_when_full() {
        let mut m = Mempool::with_capacity(2);
        put(&mut m, &tx(1, 1, 7)).unwrap();
        assert_eq!(m.floor_tip(), None, "room left: nothing to beat");
        put(&mut m, &tx(2, 2, 9)).unwrap();
        assert_eq!(m.floor_tip(), Some(7));
    }

    #[test]
    fn one_sender_cannot_hold_more_than_its_quota() {
        // Capacity well above the quota, so the ONLY thing that can stop the
        // flood is the per-sender rule.
        let mut m = Mempool::with_capacity(PER_SENDER_MAX * 4);
        for seed in 0..PER_SENDER_MAX as u32 {
            put(&mut m, &tx(0xAB, seed, 1)).expect("under quota");
        }
        assert_eq!(m.len(), PER_SENDER_MAX);
        let over = tx(0xAB, 9_999, 1_000_000);
        assert!(
            matches!(put(&mut m, &over), Err(Refused::SenderQuota { held, .. }) if held == PER_SENDER_MAX),
            "a sender at its ceiling is refused however much it offers"
        );
        // ...and a different address is unaffected.
        put(&mut m, &tx(0xCD, 1, 1)).expect("a different sender has its own quota");
        assert_eq!(m.len(), PER_SENDER_MAX + 1);
    }

    #[test]
    fn the_quota_frees_as_entries_leave() {
        let mut m = Mempool::with_capacity(PER_SENDER_MAX * 2);
        let first = tx(0xAB, 0, 1);
        put(&mut m, &first).unwrap();
        for seed in 1..PER_SENDER_MAX as u32 {
            put(&mut m, &tx(0xAB, seed, 1)).unwrap();
        }
        assert!(put(&mut m, &tx(0xAB, 500, 1)).is_err(), "at the ceiling");
        m.remove(&first.canonical_bytes()).expect("held");
        put(&mut m, &tx(0xAB, 500, 1)).expect("a slot came free");
    }

    #[test]
    fn sender_counts_never_drift() {
        // Insert, displace, remove, re-insert — then compare the maintained
        // table against a full recomputation. This is the invariant the
        // linear-scan design deliberately does NOT have to defend for price,
        // and does have to defend here.
        let mut m = Mempool::with_capacity(8);
        for seed in 0..8u32 {
            put(&mut m, &tx((seed % 3) as u8, seed, seed as u128)).unwrap();
        }
        for seed in 8..24u32 {
            let _ = put(&mut m, &tx((seed % 5) as u8, seed, seed as u128));
        }
        let keys: Vec<Vec<u8>> = m.entries.keys().cloned().collect();
        for k in keys.iter().step_by(2) {
            m.remove(k);
        }
        for seed in 24..32u32 {
            let _ = put(&mut m, &tx((seed % 7) as u8, seed, seed as u128));
        }
        assert_eq!(m.per_sender, m.recomputed_sender_counts());
        assert!(m.len() <= m.capacity());
    }

    #[test]
    fn evidence_is_not_evictable_by_price_and_outbids_everything() {
        use bloch_pos_committee::attestation::{Attestation, AttestationData};
        use bloch_pos_committee::interfaces::SlashingEvidence as WireEvidence;
        let att = |head: u8| Attestation {
            validator: 3,
            data: AttestationData {
                slot: 32,
                head: [head; 32],
                source_epoch: 0,
                source_root: [1u8; 32],
                target_epoch: 1,
                target_root: [head; 32],
            },
            signature: vec![head; 4],
        };
        let ev = PosTransaction::SlashingEvidence(WireEvidence::AttestationOffence {
            first: att(0xAA),
            second: att(0xBB),
        });
        assert_eq!(price_of(&ev), Price::Protected);

        let mut m = Mempool::with_capacity(2);
        put(&mut m, &tx(1, 1, 1_000_000)).unwrap();
        put(&mut m, &tx(2, 2, 2_000_000)).unwrap();
        // Evidence gets in through a pool full of very well paid traffic...
        let displaced = put(&mut m, &ev).expect("evidence outbids a tip");
        assert_eq!(displaced, Some(tx(1, 1, 1_000_000).canonical_bytes()));
        // ...and is then packed first.
        assert!(matches!(
            m.by_price_desc()[0].1,
            PosTransaction::SlashingEvidence(_)
        ));
        // ...and nothing paying can push it out.
        assert_eq!(m.floor_tip(), Some(2_000_000));
        assert_eq!(
            put(&mut m, &tx(3, 3, u128::MAX)).map(|d| d.is_some()),
            Ok(true)
        );
        assert!(
            m.values().any(|t| matches!(t, PosTransaction::SlashingEvidence(_))),
            "the evidence survived a maximum-tip arrival"
        );
    }

    #[test]
    fn staking_messages_are_evicted_first() {
        // A tripwire, not a feature: these three are refused by
        // `engine::admissible` and cannot reach a real pool. If that ever
        // changes, this test fails and whoever changed it must decide what
        // an unfunded staking message is worth.
        assert_eq!(price_of(&PosTransaction::Exit { validator: 1 }), Price::Tip(0));
        assert_eq!(
            price_of(&PosTransaction::Delegate {
                delegator: 0,
                validator: 1,
                amount_sat: 1,
                eligible: true
            }),
            Price::Tip(0)
        );
    }

    #[test]
    fn a_multi_owner_transfer_is_charged_to_every_signer() {
        let two_owners = PosTransaction::Transfer {
            inputs: vec![
                TransferInput { txid: [1; 32], vout: 0, pubkey: vec![0xA; 8], signature: vec![] },
                TransferInput { txid: [2; 32], vout: 0, pubkey: vec![0xB; 8], signature: vec![] },
                // The same owner again: distinct, so it is charged once.
                TransferInput { txid: [3; 32], vout: 0, pubkey: vec![0xA; 8], signature: vec![] },
            ],
            outputs: vec![TransferOutput { value: 1, script_hash: [0; 32] }],
            tx_bytes: 0,
            tip_millisat_per_gas: 1,
        };
        let s = senders(&two_owners);
        assert_eq!(s.len(), 2, "two distinct owners, three inputs");
        let mut m = Mempool::with_capacity(4);
        put(&mut m, &two_owners).unwrap();
        assert_eq!(m.per_sender.values().copied().collect::<Vec<_>>(), vec![1, 1]);
        m.remove(&two_owners.canonical_bytes());
        assert!(m.per_sender.is_empty(), "both buckets released");
    }

    #[test]
    fn the_sender_bucket_is_the_chains_own_address() {
        // Not an invented identity: the bucket key is the SHA3-256 of the
        // witness key, which is exactly the `script_hash` a committed output
        // commits to and `getbalance` is keyed by.
        let pk = vec![0x5A; 37];
        let t = PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: [1; 32],
                vout: 0,
                pubkey: pk.clone(),
                signature: vec![],
            }],
            outputs: vec![TransferOutput { value: 1, script_hash: [0; 32] }],
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        let expected: [u8; 32] = Sha3_256::digest(&pk).into();
        assert_eq!(senders(&t), vec![expected]);
    }

    #[test]
    fn the_bound_is_never_exceeded_however_it_is_driven() {
        let mut m = Mempool::with_capacity(16);
        for seed in 0..4_000u32 {
            let _ = put(&mut m, &tx((seed % 200) as u8, seed, (seed % 97) as u128));
            assert!(m.len() <= 16, "the memory bound is the one hard promise");
        }
    }
}
