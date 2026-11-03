// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native, parent-state-owned settlement validation for the L2 inbox.
//! With `devnet-l2-deposits`, native L2 deposits (escrowed BLCH) append to an
//! ordered inbox and each settlement must mint exactly the next inbox records.
//! Settlement V3 publishes the L2 withdrawal tree (M4); this module checks it
//! and keeps recent roots for the L1 claim (M5), which releases escrow to
//! the L1 recipient once the root is [`withdrawal::WITHDRAW_DELAY_BLOCKS`]
//! old (longer for large claims), at most once per leaf and within a
//! per-window release cap (M6).
//!
//! What an installed L2 admits is its [`Profile`], fixed when it is installed:
//! an L2 from a development genesis manifest follows the build's devnet
//! features (`devnet-l2-deposits`, `devnet-l2-user-txs`) and the development
//! limits ([`withdrawal::Limits::DEVELOPMENT`]); an L2 installed by the
//! running-network flag day ([`activation_policy`], M9) admits deposits, data
//! availability, user transactions and claims on every build, with the
//! limits pinned in the activation. No production activation is armed.
use sha3::{Digest, Keccak256, Sha3_256};

/// Native wire tags. Moved on 2026-10-10 from 0x0E/0x0F to the first bytes
/// after the mainnet transaction space (mainnet assigns 0x0E-0x11 to funded
/// delegation; see `tests/wire_tag_registry.rs`). Development networks that
/// settled under the old bytes (devnet3) cannot be replayed by this build.
pub const WIRE_TAG: u8 = 0x12;
/// Asynchronous settlement, enabled only by a new manifest-bound genesis.
pub const ASYNC_WIRE_TAG: u8 = 0x13;
pub const STATEMENT_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:2";
pub const STATEMENT_BYTES: usize = 590;
pub const PROOF_BYTES: usize = 356;
/// Exact V2 transaction length (kept for existing history).
pub const TRANSACTION_BYTES: usize = 1 + 32 + STATEMENT_BYTES + PROOF_BYTES;
/// Settlement V3 (`bloch_l2_evm::proof_statement::SettlementStatementV3`):
/// the V2 fields at their V2 offsets, then deposits hash, transactions root,
/// receipts root, user transaction count, withdrawal root and count (M4), and
/// the data-availability commitment (M3).
/// V3 admits L2 blocks with user transactions; deposits are bound through
/// `deposits_hash` instead of recomputing an empty body.
pub const STATEMENT_V3_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:3";
pub const STATEMENT_V3_BYTES: usize = 766;
pub const TRANSACTION_V3_BYTES: usize = 1 + 32 + STATEMENT_V3_BYTES + PROOF_BYTES;
const S: usize = STATEMENT_TAG.len();
const _: () = assert!(STATEMENT_V3_TAG.len() == S);
/// V3 field offsets after the tag. Independent of the L2 codec; conformance
/// tests pin both sides (`settlement_v3_layout` in bloch-l2-evm).
pub mod v3 {
    pub const DEPOSITS_HASH: usize = 568;
    pub const TRANSACTIONS_ROOT: usize = 600;
    pub const RECEIPTS_ROOT: usize = 632;
    pub const USER_TX_COUNT: usize = 664;
    /// Reserved for M4 (outbox); must be zero.
    pub const WITHDRAWAL_ROOT: usize = 672;
    /// Reserved for M4; must be zero.
    pub const WITHDRAWAL_COUNT: usize = 704;
    /// Data-availability commitment (M3, [`super::da::commitment`]): zero
    /// when `user_tx_count == 0`, otherwise the commitment of an L1 DA record.
    pub const DA_COMMITMENT: usize = 712;
    pub const END: usize = 744;
}
const _: () = assert!(S + v3::END == STATEMENT_V3_BYTES);

/// Statement version, selected only by the statement tag (and exact length).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementVersion {
    V2,
    V3,
}
impl StatementVersion {
    fn of(statement: &[u8]) -> Option<Self> {
        if statement.len() == STATEMENT_BYTES && statement.starts_with(STATEMENT_TAG) {
            Some(Self::V2)
        } else if statement.len() == STATEMENT_V3_BYTES && statement.starts_with(STATEMENT_V3_TAG) {
            Some(Self::V3)
        } else {
            None
        }
    }
}
/// L1 data availability for settlement V3 user transactions (milestone M3).
///
/// A V3 settlement that executed user transactions names, in `da_commitment`,
/// the batch it executed. The native chain never stores the batch: an
/// `L2DataAvailability` transaction (wire 0x15) carries it in an L1 block, and
/// the committed state keeps only `(l2 block number, commitment, inclusion
/// height)`. The settlement is accepted only when such a record was included
/// in a strictly earlier native block, so every settled user transaction can
/// be re-read from L1 blocks alone (`bloch-l2-produce-dev reconstruct`).
///
/// Shared format (pinned by `tests/fixtures/l2-da-v1` in both repositories):
///
/// * payload: `count (u32 BE, >= 1)` then `count` times `len (u32 BE, >= 1)
///   || len bytes`, the exact signed EIP-2718 envelopes of the L2 body in body
///   order, no trailing bytes, at most [`MAX_PAYLOAD_BYTES`];
/// * commitment: `keccak256("BLOCH:L2:DA:1" || chain_id (u64 BE) ||
///   l2_block_number (u64 BE) || payload)`.
pub mod da {
    use sha3::{Digest, Keccak256};

    pub const COMMITMENT_DOMAIN: &[u8] = b"BLOCH:L2:DA:1";
    /// 112 KiB. With the largest authorized envelope (hybrid key, signature
    /// and [`MAX_INPUTS`] inputs, < 9 KiB) one DA transaction stays below the
    /// pre-V2 byte target (`fee_market::BLOCK_TX_BYTES_TARGET`, 128 KiB), so a
    /// single batch never fills more than half of the smallest block and never
    /// by itself pushes the base fee up. It is far above what the prover
    /// settles per block today (single-digit user transactions).
    pub const MAX_PAYLOAD_BYTES: usize = 114_688;
    /// Funding inputs of one DA transaction (each costs one hybrid verification).
    pub const MAX_INPUTS: usize = 16;
    /// DA transactions per native block, like blobs per block: inclusion is
    /// a fee auction, and the stored records stay bounded (see [`MAX_RECORDS`]).
    pub const MAX_PER_BLOCK: usize = 4;
    /// A record serves settlements in the next `RETENTION_BLOCKS` native
    /// blocks after its inclusion, then expires (re-post the batch if the
    /// settlement has not landed by then).
    pub const RETENTION_BLOCKS: u64 = 1_024;
    /// Records are accepted only for the next `WINDOW` unsettled L2 blocks.
    pub const WINDOW: u64 = 64;
    /// Upper bound on stored records: the per-block cap times the retained
    /// blocks plus the block being applied. Each record commits 48 bytes, so
    /// the DA section of the committed L2 state stays below 193 KiB.
    pub const MAX_RECORDS: usize = MAX_PER_BLOCK * (RETENTION_BLOCKS as usize + 1);
    const _: () = assert!(MAX_RECORDS == 4_100);

    /// DA slots per block that only the registered key may fill once
    /// `params::L2_DA_RESERVED_SLOT_EPOCH` binds. The total stays
    /// [`MAX_PER_BLOCK`], so [`MAX_RECORDS`] is unchanged.
    pub const RESERVED_PER_BLOCK: usize = 1;
    /// DA transactions per block from any other funding key, past the gate.
    pub const OPEN_PER_BLOCK: usize = MAX_PER_BLOCK - RESERVED_PER_BLOCK;
    const _: () = assert!(OPEN_PER_BLOCK >= 1 && RESERVED_PER_BLOCK >= 1);

    /// The registered DA funding key: `Sha3_256(funding_pubkey)`, the same
    /// hash as the key's script hash. Set once in the release
    /// (`mainnet::DA_RESERVED_KEY`); a qualification build
    /// (`l2-activation-rehearsal`) takes it from `BLOCH_L2_REHEARSAL_DA_KEY`
    /// at compile time instead. No key, vote or runtime input changes it.
    #[cfg(not(feature = "l2-activation-rehearsal"))]
    pub const REGISTERED_KEY: Option<[u8; 32]> = super::mainnet::DA_RESERVED_KEY;
    #[cfg(feature = "l2-activation-rehearsal")]
    pub const REGISTERED_KEY: Option<[u8; 32]> = match option_env!("BLOCH_L2_REHEARSAL_DA_KEY") {
        Some(text) => Some(super::mainnet::h32(text)),
        None => None,
    };

    /// The registered key, or a test's override of it.
    pub fn registered_key() -> Option<[u8; 32]> {
        #[cfg(test)]
        if let Some(key) = crate::params::l2_da_reserved_slot_test::key() {
            return Some(key);
        }
        REGISTERED_KEY
    }

    /// The key that owns the reserved slot in a block of `epoch`: `None`
    /// below the gate, or when no key is registered (then the old rule of
    /// [`MAX_PER_BLOCK`] slots for anyone applies unchanged).
    pub fn reserved_key_at(epoch: u64) -> Option<[u8; 32]> {
        if crate::params::l2_da_reserved_slot_active(epoch) { registered_key() } else { None }
    }

    /// `Sha3_256(funding_pubkey)`, the hash [`reserved_key_at`] names.
    pub fn funder(funding_pubkey: &[u8]) -> [u8; 32] {
        use sha3::Sha3_256;
        Sha3_256::digest(funding_pubkey).into()
    }

    /// Whether a block of `epoch` may carry DA transactions from these
    /// funding keys, in any order: at most [`MAX_PER_BLOCK`] in all and,
    /// past the gate, at most [`OPEN_PER_BLOCK`] from keys other than the
    /// registered one.
    pub fn block_admits<'a>(epoch: u64, funding_pubkeys: impl IntoIterator<Item = &'a [u8]>) -> bool {
        let reserved = reserved_key_at(epoch);
        let (mut total, mut open) = (0usize, 0usize);
        for key in funding_pubkeys {
            total += 1;
            if reserved != Some(funder(key)) {
                open += 1;
            }
        }
        total <= MAX_PER_BLOCK && (reserved.is_none() || open <= OPEN_PER_BLOCK)
    }

    /// Number of transactions in a canonical batch payload, or `None` if the
    /// payload is not exactly one canonical batch within the size cap.
    pub fn batch_count(payload: &[u8]) -> Option<u32> {
        if payload.len() > MAX_PAYLOAD_BYTES || payload.len() < 4 {
            return None;
        }
        let count = u32::from_be_bytes(payload[..4].try_into().ok()?);
        let mut at = 4usize;
        for _ in 0..count {
            let len = u32::from_be_bytes(payload.get(at..at + 4)?.try_into().ok()?) as usize;
            if len == 0 {
                return None;
            }
            at = at.checked_add(4)?.checked_add(len)?;
            if at > payload.len() {
                return None;
            }
        }
        (count > 0 && at == payload.len()).then_some(count)
    }

    pub fn commitment(chain_id: u64, l2_block_number: u64, payload: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(COMMITMENT_DOMAIN);
        h.update(chain_id.to_be_bytes());
        h.update(l2_block_number.to_be_bytes());
        h.update(payload);
        h.finalize().into()
    }

    /// One stored DA record.
    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Record {
        pub l2_number: u64,
        pub commitment: [u8; 32],
        /// Native height of the block that included the DA transaction.
        pub height: u64,
    }

    /// Why the L2 state refused to record a DA batch.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Refusal {
        /// No L2, or an L2 whose profile does not admit user transactions.
        NotActive,
        /// The batch names another L2 chain.
        Chain,
        /// Already settled, or beyond [`WINDOW`] unsettled blocks.
        Number,
        /// The same (number, commitment) is already recorded.
        Duplicate,
        /// [`MAX_RECORDS`] reached (unreachable with the per-block cap).
        Full,
    }
}

/// L2 → L1 withdrawals (milestone M4): the commitment settlement V3 publishes.
///
/// The L2 outbox (`L2ToL1MessagePasser`, `bloch_l2_evm::withdrawal`) appends
/// one leaf per withdrawal to an append-only, depth-32 keccak tree:
///
/// * leaf: `keccak256("BLOCH:L2:WITHDRAW:1" || chain_id (u64 BE) || nonce
///   (u64 BE, the leaf index) || l1_recipient (32, the owner script hash) ||
///   sats (u64 BE))`;
/// * node: `keccak256(left || right)`; empty leaf: 32 zero bytes; the empty
///   tree's root is [`empty_root`].
///
/// A V3 statement carries the root and the leaf count after its L2 block. The
/// native chain accepts it only if the count does not decrease and the root
/// changes exactly when the count does (relative to the accepted head; a V2
/// head counts as the empty tree), and keeps `(l2 number, root, count, native
/// height)` of each settlement that added withdrawals ([`Record`]) for the L1
/// claim (M5), which proves a leaf against a retained root with
/// [`root_from_proof`]. Shared vectors: `tests/fixtures/l2-withdrawal-v1`
/// (identical copy in bloch-l2-evm).
pub mod withdrawal {
    use sha3::{Digest, Keccak256};

    pub const LEAF_DOMAIN: &[u8] = b"BLOCH:L2:WITHDRAW:1";
    pub const TREE_DEPTH: usize = 32;
    /// Records younger than this many native blocks are always kept; of the
    /// older ones only the newest survives, so a root at least this old stays
    /// available to claims once withdrawals exist.
    pub const RETENTION_BLOCKS: u64 = 1_024;
    /// Upper bound on stored records: at most one settlement per native block
    /// adds a record, plus the retained older one and the block being applied.
    /// Each record commits 56 bytes, so this section stays below 58 KiB.
    pub const MAX_RECORDS: usize = RETENTION_BLOCKS as usize + 2;

    /// The withdrawal limits of one installed L2 (M5/M6), fixed when it is
    /// installed and never changed. [`Limits::DEVELOPMENT`] are the constants
    /// below, used by every L2 from a development genesis manifest (devnet4
    /// replays unchanged); a running-network activation pins its own.
    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Limits {
        /// See [`WITHDRAW_DELAY_BLOCKS`].
        pub delay_blocks: u64,
        /// See [`LARGE_CLAIM_SAT`]; also the attestation threshold
        /// ([`ATTESTED_CLAIM_SAT`]): one notion of "large".
        pub large_claim_sat: u64,
        /// See [`LARGE_WITHDRAW_DELAY_BLOCKS`].
        pub large_delay_blocks: u64,
        /// See [`RETENTION_BLOCKS`]; at least `large_delay_blocks`.
        pub retention_blocks: u64,
        /// See [`RELEASE_WINDOW_BLOCKS`].
        pub release_window_blocks: u64,
        /// See [`RELEASE_WINDOW_BPS`] (1..=10 000).
        pub release_window_bps: u64,
        /// See [`RELEASE_FLOOR_SAT`].
        pub release_floor_sat: u64,
    }
    /// Upper bound on a pinned retention: one week of 30 s slots. It bounds
    /// the committed withdrawal section (56 bytes per record, < 1.1 MiB).
    pub const MAX_RETENTION_BLOCKS: u64 = 20_160;
    impl Limits {
        pub const DEVELOPMENT: Limits = Limits {
            delay_blocks: WITHDRAW_DELAY_BLOCKS,
            large_claim_sat: LARGE_CLAIM_SAT,
            large_delay_blocks: LARGE_WITHDRAW_DELAY_BLOCKS,
            retention_blocks: RETENTION_BLOCKS,
            release_window_blocks: RELEASE_WINDOW_BLOCKS,
            release_window_bps: RELEASE_WINDOW_BPS as u64,
            release_floor_sat: RELEASE_FLOOR_SAT as u64,
        };
        /// The same invariants the development constants assert at compile
        /// time, plus bounds that keep the committed state small.
        pub const fn valid(&self) -> bool {
            self.delay_blocks >= 1
                && self.delay_blocks <= self.large_delay_blocks
                && self.large_delay_blocks <= self.retention_blocks
                && self.retention_blocks <= MAX_RETENTION_BLOCKS
                && self.large_claim_sat > 0
                && self.release_window_blocks >= 1
                && self.release_window_bps >= 1
                && self.release_window_bps <= 10_000
                && self.release_floor_sat > 0
        }
        /// The delay a claim of `sats` must wait after the record it proves against.
        pub const fn delay_for(&self, sats: u64) -> u64 {
            if sats >= self.large_claim_sat {
                self.large_delay_blocks
            } else {
                self.delay_blocks
            }
        }
        /// Upper bound on stored records (see [`MAX_RECORDS`]).
        pub const fn max_records(&self) -> usize {
            self.retention_blocks as usize + 2
        }
        pub(crate) fn encode(&self, out: &mut Vec<u8>) {
            for v in [
                self.delay_blocks,
                self.large_claim_sat,
                self.large_delay_blocks,
                self.retention_blocks,
                self.release_window_blocks,
                self.release_window_bps,
                self.release_floor_sat,
            ] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }

    pub fn leaf(chain_id: u64, nonce: u64, l1_recipient: &[u8; 32], sats: u64) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(LEAF_DOMAIN);
        h.update(chain_id.to_be_bytes());
        h.update(nonce.to_be_bytes());
        h.update(l1_recipient);
        h.update(sats.to_be_bytes());
        h.finalize().into()
    }

    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    /// `zero[0]` is the empty leaf, `zero[h + 1] = node(zero[h], zero[h])`.
    pub fn zero_hashes() -> [[u8; 32]; TREE_DEPTH + 1] {
        let mut zero = [[0u8; 32]; TREE_DEPTH + 1];
        for h in 0..TREE_DEPTH {
            zero[h + 1] = node(&zero[h], &zero[h]);
        }
        zero
    }

    pub fn empty_root() -> [u8; 32] {
        zero_hashes()[TREE_DEPTH]
    }

    /// Root of the tree over `leaves` in index order (tests and tooling; the
    /// chain never sees the leaves).
    pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let zero = zero_hashes();
        let mut level = leaves.to_vec();
        for z in zero.iter().take(TREE_DEPTH) {
            if level.is_empty() {
                return zero[TREE_DEPTH];
            }
            level = level.chunks(2).map(|pair| node(&pair[0], pair.get(1).unwrap_or(z))).collect();
        }
        level[0]
    }

    /// Bottom-up siblings of leaf `index` in the tree over `leaves` (tests
    /// and tooling), or `None` when `index` is not a leaf of it.
    pub fn proof(leaves: &[[u8; 32]], index: u64) -> Option<[[u8; 32]; TREE_DEPTH]> {
        if index >= leaves.len() as u64 {
            return None;
        }
        let zero = zero_hashes();
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        let mut level = leaves.to_vec();
        let mut at = index as usize;
        for (h, z) in zero.iter().take(TREE_DEPTH).enumerate() {
            siblings[h] = *level.get(at ^ 1).unwrap_or(z);
            level = level.chunks(2).map(|pair| node(&pair[0], pair.get(1).unwrap_or(z))).collect();
            at /= 2;
        }
        Some(siblings)
    }

    /// The root that `siblings` (bottom-up) prove for `leaf` at `index`, or
    /// `None` for an index outside the tree. The claim must also check
    /// `index < count` of the root it cites.
    pub fn root_from_proof(leaf: &[u8; 32], index: u64, siblings: &[[u8; 32]; TREE_DEPTH]) -> Option<[u8; 32]> {
        if index >> TREE_DEPTH != 0 {
            return None;
        }
        let mut acc = *leaf;
        for (h, sibling) in siblings.iter().enumerate() {
            acc = if (index >> h) & 1 == 1 { node(sibling, &acc) } else { node(&acc, sibling) };
        }
        Some(acc)
    }

    /// `(root, count)` published by an accepted statement: the empty tree for
    /// none or a V2 statement (which has no withdrawals).
    pub fn tree_after(statement: Option<&[u8]>) -> ([u8; 32], u64) {
        use super::{h, n, StatementVersion, S};
        match statement {
            Some(s) if StatementVersion::of(s) == Some(StatementVersion::V3) => {
                (h(s, S + super::v3::WITHDRAWAL_ROOT), n(s, S + super::v3::WITHDRAWAL_COUNT))
            }
            _ => (empty_root(), 0),
        }
    }

    /// The withdrawal part of the V3 acceptance rule, against the accepted
    /// head statement (`None` before the first settlement): the count never
    /// decreases and the root changes exactly when the count does. Returns
    /// the new `(root, count)` when the statement adds withdrawals.
    pub fn check_successor(head: Option<&[u8]>, statement: &[u8]) -> Result<Option<([u8; 32], u64)>, super::Reject> {
        if super::StatementVersion::of(statement) != Some(super::StatementVersion::V3) {
            return Err(super::Reject::Policy);
        }
        let (root, count) = tree_after(Some(statement));
        let (head_root, head_count) = tree_after(head);
        if count < head_count || (count == head_count) != (root == head_root) {
            return Err(super::Reject::Withdrawals);
        }
        Ok((count > head_count).then_some((root, count)))
    }

    /// One accepted settlement that added withdrawals.
    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Record {
        pub l2_number: u64,
        pub root: [u8; 32],
        pub count: u64,
        /// Native height of the block that accepted the settlement.
        pub height: u64,
    }

    // ── M5: the L1 claim (`L2WithdrawClaim`, wire 0x16) ──

    /// Native blocks between the block that accepted a settlement and the
    /// first block in which a claim may prove against its root: a record
    /// accepted at height `h` serves claims in blocks `h + WITHDRAW_DELAY_BLOCKS`
    /// and later. Development value: one epoch (32 slots of 30 s). It is a
    /// consensus constant, so changing it is a new network, not a flag.
    ///
    /// Mainnet suggestion (M8): at least one day (2,880 blocks) and, in
    /// addition, the accepting block finalized (FFG); [`RETENTION_BLOCKS`]
    /// must then be raised to at least the delay (the assertion below).
    pub const WITHDRAW_DELAY_BLOCKS: u64 = 32;
    /// The newest record at least `WITHDRAW_DELAY_BLOCKS` old is always
    /// retained (every record younger than `RETENTION_BLOCKS` is kept, and of
    /// the older ones the newest), so the matured tree is always derivable.
    /// A zero delay would let a claim prove against a settlement of the
    /// same block.
    const _: () = assert!(WITHDRAW_DELAY_BLOCKS >= 1 && WITHDRAW_DELAY_BLOCKS <= RETENTION_BLOCKS);

    // ── M6: limits that bound the damage of a forged settlement ──
    //
    // The settlement proof (Groth16 over BN254) is not post-quantum, and a
    // forged settlement can publish any withdrawal tree. These rules do not
    // prevent that; they slow the drain so that operators can react (halt
    // the network or replace the L2 policy) before the escrow empties.

    /// Claims of at least this many satoshis (100 BLCH) wait
    /// [`LARGE_WITHDRAW_DELAY_BLOCKS`] instead of [`WITHDRAW_DELAY_BLOCKS`].
    pub const LARGE_CLAIM_SAT: u64 = 10_000_000_000;
    /// Development value: four epochs. Mainnet suggestion (M8): one week.
    pub const LARGE_WITHDRAW_DELAY_BLOCKS: u64 = 128;
    const _: () = assert!(
        LARGE_WITHDRAW_DELAY_BLOCKS >= WITHDRAW_DELAY_BLOCKS && LARGE_WITHDRAW_DELAY_BLOCKS <= RETENTION_BLOCKS
    );
    /// The delay a claim of `sats` must wait after the record it proves against.
    /// [`Limits::delay_for`] of the development limits.
    pub fn delay_for(sats: u64) -> u64 {
        Limits::DEVELOPMENT.delay_for(sats)
    }
    const _: () = assert!(Limits::DEVELOPMENT.valid());
    // ── Ethereum-rollup withdrawals: claims only against finalized settlements ──
    //
    // A claim may prove only against a withdrawal record whose accepting
    // block lies in the FFG-finalized prefix, so no reorganization can undo
    // the settlement a payout relied on (the plan's "settlement accepted with
    // age ≥ N finalized epochs"; on Ethereum, withdrawals wait for the L1 to
    // finalize the output root).
    //
    // Without a new state field: slots strictly increase along the chain, so
    // a block at native height `h` has slot ≤ `slot(H) − (H − h)` for any
    // later block `H`. When that bound is below the finalized checkpoint's
    // epoch boundary, the accepting block is at or before the checkpoint (the
    // last block strictly before the boundary), hence finalized. Missed slots
    // after `h` only make the bound conservative (a claim waits longer, never
    // less).

    /// Native height from which the rule applies (claims in blocks at or
    /// above it). Zero: from genesis. A development build may set
    /// `BLOCH_DEVNET_FINALIZED_CLAIMS_FROM_HEIGHT` at compile time to activate
    /// it on a running devnet whose history holds earlier claims (devnet4).
    pub const FINALIZED_CLAIMS_FROM_HEIGHT: u64 = match option_env!("BLOCH_DEVNET_FINALIZED_CLAIMS_FROM_HEIGHT") {
        Some(text) => parse_u64(text),
        None => 0,
    };
    const fn parse_u64(text: &str) -> u64 {
        let bytes = text.as_bytes();
        assert!(!bytes.is_empty(), "BLOCH_DEVNET_FINALIZED_CLAIMS_FROM_HEIGHT is empty");
        let mut value: u64 = 0;
        let mut i = 0;
        while i < bytes.len() {
            assert!(bytes[i].is_ascii_digit(), "BLOCH_DEVNET_FINALIZED_CLAIMS_FROM_HEIGHT must be decimal");
            value = value * 10 + (bytes[i] - b'0') as u64;
            i += 1;
        }
        value
    }

    /// Whether the record accepted at native height `record_height` is in
    /// the finalized prefix, seen from the block at (`tip_height`,
    /// `tip_slot`) whose finalized checkpoint epoch is `finalized_epoch`.
    ///
    /// EPOCHS ONLY: it trusts that the finalized checkpoint is on the tip's
    /// own chain, which FFG does not guarantee (a branch can finalize the
    /// checkpoint of another branch whose votes it carries). Consensus reads
    /// it through `CommittedState::l2_record_finalized_for_claim`, which adds
    /// that check from `params::HF1_CLAIM_FINALITY_EPOCH`.
    pub fn record_finalized(record_height: u64, tip_height: u64, tip_slot: u64, finalized_epoch: u64) -> bool {
        if record_height > tip_height {
            return false;
        }
        let slot_bound = tip_slot.saturating_sub(tip_height - record_height);
        slot_bound < finalized_epoch.saturating_mul(crate::params::SLOTS_PER_EPOCH)
    }

    /// Release windows: native block `h` belongs to window
    /// `h / RELEASE_WINDOW_BLOCKS`.
    pub const RELEASE_WINDOW_BLOCKS: u64 = 32;
    /// Per window, claims release at most `max(RELEASE_FLOOR_SAT, escrow at
    /// the window's first claim × RELEASE_WINDOW_BPS / 10 000)`. One claim
    /// may exceed the cap, as the window's first and only claim, and only if
    /// it is EXEMPT: attested by the policy's attestor set, or on a policy
    /// without attestors (there nobody could lift the cap, and a withdrawal
    /// above it would otherwise never pay). A forged settlement proof alone
    /// therefore drains at most ~10% of the escrow per window when the policy
    /// has attestors. The devnet4 rehearsal (2026-10-12) showed why the
    /// exemption needs the attestors: before, any first claim passed, so an
    /// unattested 99 BLCH claim could take a third of a 300 BLCH escrow.
    pub const RELEASE_WINDOW_BPS: u128 = 1_000;
    /// 10 BLCH: keeps a small escrow usable.
    pub const RELEASE_FLOOR_SAT: u128 = 1_000_000_000;

    // ── M6: post-quantum co-signature of large claims ──
    //
    // With an attestor set in the policy, a claim of at least
    // `ATTESTED_CLAIM_SAT` must carry k-of-n hybrid (ML-DSA-65 + Falcon-1024)
    // signatures over the withdrawal root it proves against. Attestors sign a
    // root only after rebuilding the L2 from its L1 data-availability batches
    // (M3) and finding the same root, so a forged settlement proof alone no
    // longer releases large amounts. Small claims stay bounded by the release
    // window.

    /// Claims at or above this need the attestation (equal to the large-claim
    /// threshold: one notion of "large").
    pub const ATTESTED_CLAIM_SAT: u64 = LARGE_CLAIM_SAT;
    /// Upper bound on attestors (each signature is one hybrid verification).
    pub const MAX_ATTESTORS: usize = 7;
    pub const ATTESTOR_SET_DOMAIN: &[u8] = b"BLOCH:L2:ATTESTOR-SET:1";
    pub const ATTESTATION_DOMAIN: &[u8] = b"BLOCH:L2:WITHDRAW-ATTEST:1";

    /// `SHA3-256(ATTESTOR_SET_DOMAIN || k || n || key_0 || … || key_{n-1})`,
    /// keys enveloped hybrid public keys in set order.
    pub fn attestor_set_hash(threshold: u8, keys: &[Vec<u8>]) -> [u8; 32] {
        use sha3::Sha3_256;
        let mut h = Sha3_256::new();
        h.update(ATTESTOR_SET_DOMAIN);
        h.update([threshold, keys.len() as u8]);
        for key in keys {
            h.update(key);
        }
        h.finalize().into()
    }

    /// What each attestor signs: `SHA3-256(ATTESTATION_DOMAIN ||
    /// network_domain || chain_id (u64 BE) || withdrawal root)`. The root of
    /// an append-only tree already fixes its leaf count.
    pub fn attestation_digest(network_domain: &[u8; 32], chain_id: u64, root: &[u8; 32]) -> [u8; 32] {
        use sha3::Sha3_256;
        let mut h = Sha3_256::new();
        h.update(ATTESTATION_DOMAIN);
        h.update(network_domain);
        h.update(chain_id.to_be_bytes());
        h.update(root);
        h.finalize().into()
    }

    /// Release accounting of the current window.
    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ReleaseWindow {
        /// Window index (`native height / RELEASE_WINDOW_BLOCKS`).
        pub window: u64,
        /// Satoshis released in this window.
        pub released: u128,
        /// The cap of this window, fixed at its first claim.
        pub cap: u128,
    }
    impl ReleaseWindow {
        /// The window state a claim of `sats` in native block `at_height`
        /// sees, given the current escrow: rolled to a fresh window when the
        /// stored one is older.
        pub fn at(self, limits: &Limits, at_height: u64, escrow_sat: u128) -> Self {
            let window = at_height / limits.release_window_blocks;
            if window == self.window && self.released != 0 {
                return self;
            }
            let share = escrow_sat.saturating_mul(u128::from(limits.release_window_bps)) / 10_000;
            Self { window, released: 0, cap: share.max(u128::from(limits.release_floor_sat)) }
        }
        /// Whether `sats` more fits under the next program's rule. An `exempt`
        /// claim (see [`RELEASE_WINDOW_BPS`]) may exceed the cap once per window,
        /// whatever smaller claims came before it. A claim without the exemption
        /// never takes `released` above the cap, so `released > cap` means exactly
        /// that the window's one exemption is spent, and no new state is needed.
        /// A window therefore releases at most its cap plus one exempt claim.
        pub fn admits(&self, sats: u64, exempt: bool) -> bool {
            self.released.saturating_add(u128::from(sats)) <= self.cap || (exempt && self.released <= self.cap)
        }
        /// The rule of the program the epoch-5850 activation pinned: an `exempt`
        /// claim may exceed the cap only as the window's first, so any small claim
        /// landing first closes the exemption for the whole window.
        pub fn admits_v1(&self, sats: u64, exempt: bool) -> bool {
            self.released.saturating_add(u128::from(sats)) <= self.cap || (exempt && self.released == 0)
        }
        /// Room left in the window (an exempt first claim may exceed it).
        pub fn remaining(&self) -> u128 {
            self.cap.saturating_sub(self.released)
        }
    }

    pub const NULLIFIER_DOMAIN: &[u8] = b"BLOCH:L2:CLAIM:1";

    /// `keccak256("BLOCH:L2:CLAIM:1" || chain_id (u64 BE) || leaf_index (u64
    /// BE))`: the public identity of one claim (mempool and RPC key). The
    /// committed state stores the same fact as one bit per leaf index of the
    /// policy's chain ([`ClaimBitmap`]).
    pub fn nullifier(chain_id: u64, index: u64) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(NULLIFIER_DOMAIN);
        h.update(chain_id.to_be_bytes());
        h.update(index.to_be_bytes());
        h.finalize().into()
    }

    /// Why a withdrawal claim is refused by the L2 state.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ClaimRefusal {
        /// No L2, or an L2 whose profile does not admit user transactions.
        NotActive,
        /// The claim names another L2 chain.
        Chain,
        /// The proof folds to no retained withdrawal root.
        Proof,
        /// The proof folds to a retained root that is not yet
        /// [`WITHDRAW_DELAY_BLOCKS`] old.
        NotMatured,
        /// The leaf index is not below the count of the root it proves against.
        Index,
        /// The leaf was already claimed.
        Claimed,
        /// The escrow holds less than the claim (unreachable while every
        /// settlement is proven; checked anyway).
        Escrow,
        /// The release window's cap is used up; the claim fits a later window.
        RateLimited,
    }

    /// The retained record the claim proves against, if the proof is valid,
    /// matured for a claim in native block `at_height`, and the index lies in
    /// that tree. Pure: shared by the transition, the mempool and tooling.
    pub fn matured_proof<'a>(
        limits: &Limits,
        records: &'a [Record],
        at_height: u64,
        chain_id: u64,
        index: u64,
        l1_recipient: &[u8; 32],
        sats: u64,
        siblings: &[[u8; 32]; TREE_DEPTH],
    ) -> Result<&'a Record, ClaimRefusal> {
        let leaf = leaf(chain_id, index, l1_recipient, sats);
        let root = root_from_proof(&leaf, index, siblings).ok_or(ClaimRefusal::Proof)?;
        // Roots are unique among records (each adds leaves to an
        // append-only tree); take the newest match regardless.
        let record = records.iter().rev().find(|r| r.root == root).ok_or(ClaimRefusal::Proof)?;
        if record.height.saturating_add(limits.delay_for(sats)) > at_height {
            return Err(ClaimRefusal::NotMatured);
        }
        if index >= record.count {
            return Err(ClaimRefusal::Index);
        }
        Ok(record)
    }

    /// The newest record matured for a claim of `sats` in native block
    /// `at_height`.
    pub fn matured<'a>(limits: &Limits, records: &'a [Record], at_height: u64, sats: u64) -> Option<&'a Record> {
        records.iter().rev().find(|r| r.height.saturating_add(limits.delay_for(sats)) <= at_height)
    }

    /// Claimed leaf indices of the policy's chain, one bit per index in
    /// 256-bit words. Words below `floor` are entirely claimed and dropped,
    /// so the stored set is the "frontier" between fully claimed history and
    /// the newest withdrawals: with claims roughly in leaf order it stays a
    /// few words, and in the worst case (every 256th leaf left unclaimed) it
    /// is 40 bytes per 256 leaves. Indices are below 2^32 (tree depth).
    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct ClaimBitmap {
        floor: u64,
        words: std::collections::BTreeMap<u64, [u8; 32]>,
        claims: u64,
    }
    impl ClaimBitmap {
        pub fn contains(&self, index: u64) -> bool {
            let word = index / 256;
            if word < self.floor {
                return true;
            }
            let bit = (index % 256) as usize;
            self.words.get(&word).is_some_and(|w| w[bit / 8] & (1 << (bit % 8)) != 0)
        }
        /// Set `index`; false if it was already set.
        pub(crate) fn insert(&mut self, index: u64) -> bool {
            if self.contains(index) {
                return false;
            }
            let word = index / 256;
            let bit = (index % 256) as usize;
            self.words.entry(word).or_insert([0; 32])[bit / 8] |= 1 << (bit % 8);
            self.claims += 1;
            while self.words.get(&self.floor).is_some_and(|w| *w == [0xff; 32]) {
                self.words.remove(&self.floor);
                self.floor += 1;
            }
            true
        }
        /// Number of claimed leaves.
        pub fn claims(&self) -> u64 {
            self.claims
        }
        /// Forget every claim at or above `index` (a forfeit reset): those
        /// leaves become claimable again, by whatever the new chain publishes
        /// at their indices. Claims below `index` stay. Returns how many were
        /// forgotten; `claims` drops by as much, so it keeps counting set bits.
        pub(crate) fn forget_at_or_above(&mut self, index: u64) -> u64 {
            let first = index / 256;
            // Fully claimed words at or above `first` are stored again, so
            // their high bits can be cleared one by one.
            while self.floor > first {
                self.floor -= 1;
                self.words.insert(self.floor, [0xff; 32]);
            }
            let mut forgotten = 0u64;
            for (word, bits) in self.words.range_mut(first..) {
                for bit in 0..256u64 {
                    let at = word.saturating_mul(256).saturating_add(bit);
                    let mask = 1u8 << (bit % 8);
                    if at >= index && bits[(bit / 8) as usize] & mask != 0 {
                        bits[(bit / 8) as usize] &= !mask;
                        forgotten += 1;
                    }
                }
            }
            self.words.retain(|_, bits| *bits != [0; 32]);
            self.claims -= forgotten;
            forgotten
        }
        /// Whether any leaf at or above `index` is claimed.
        pub fn any_at_or_above(&self, index: u64) -> bool {
            if self.floor.saturating_mul(256) > index {
                return true;
            }
            self.words.iter().any(|(word, bits)| {
                (0..256u64).any(|bit| {
                    bits[(bit / 8) as usize] & (1 << (bit % 8)) != 0 && word.saturating_mul(256).saturating_add(bit) >= index
                })
            })
        }
        /// Words below this index are fully claimed (and not stored).
        pub fn floor(&self) -> u64 {
            self.floor
        }
        /// Stored (partially claimed) words.
        pub fn stored_words(&self) -> usize {
            self.words.len()
        }
        /// Stored (partially claimed) words, ascending: `(word index, bits)`.
        pub fn words(&self) -> impl Iterator<Item = (u64, &[u8; 32])> {
            self.words.iter().map(|(w, bits)| (*w, bits))
        }
        pub(crate) fn encode(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.claims.to_le_bytes());
            out.extend_from_slice(&self.floor.to_le_bytes());
            out.extend_from_slice(&(self.words.len() as u64).to_le_bytes());
            for (index, word) in &self.words {
                out.extend_from_slice(&index.to_le_bytes());
                out.extend_from_slice(word);
            }
        }
    }
}

/// L1 forced inclusion of L2 transactions (CANDIDATE, inert: no L2 enables it
/// while [`crate::params::L2_FORCED_INCLUSION_EPOCH`] is the sentinel).
///
/// Why: settlement is open, so a third party that lands a rule-conforming block
/// once per finality window keeps the sequencer from ever including a user
/// transaction (agents 42 and 66), and the sequencer itself can censor. Nothing
/// on L1 forced a settlement to carry any user transaction.
///
/// What: an `L2ForcedTransaction` (wire 0x1C) publishes ONE signed L2 envelope
/// on L1 and queues `(native height, L1 txid, keccak256(envelope), declared gas
/// limit)`. The queue is frozen with the source, exactly like the deposit
/// inbox, and every V3 settlement, whoever proves it, must consume everything
/// queued at its anchor, at most [`MAX_PER_SETTLEMENT`], in queue order. There
/// is no delay window and no sequencer identity: the rule is the same for the
/// sequencer and for any other settler.
///
/// How L1 binds it without a new statement field: the guest executes the
/// consumed envelopes right after the deposits, before the sequencer's
/// transactions, skipping exactly those that are not valid at that point
/// (decoding, chain, signature, gas limit above the declared one, nonce, funds,
/// base fee), and publishes [`inbox_hash`] in the statement's `deposits_hash`
/// slot. With nothing consumed, [`inbox_hash`] IS the deposits hash, so blocks
/// without forced transactions keep their exact statement bytes. Skipped
/// envelopes are consumed too, so an invalid envelope cannot block the queue.
/// The envelopes are their own data availability: they are in the L1 block.
///
/// Shared format (pinned by `forced_hash_matches_the_l2_golden_vector` here and
/// by `forced_inclusion_golden_vector` in bloch-l2-evm):
///
/// * record: `l1_height (u64 BE) || l1_txid (32) || keccak256(envelope) (32)
///   || declared gas limit (u64 BE)`;
/// * forced hash: `keccak256` of the concatenated records (`keccak256("")`
///   when empty);
/// * inbox hash: `keccak256("BLOCH:L2:INBOX:2" || deposits_hash || forced hash)`
///   when at least one record is consumed, else `deposits_hash`.
pub mod forced {
    use sha3::{Digest, Keccak256};

    /// Records one settlement consumes at most, from the front of the queue.
    /// Separate from the deposit cap, so a full queue never slows deposits.
    /// It never binds before the gas cap (16 x 21k > 300k); it stays a guard.
    pub const MAX_PER_SETTLEMENT: u64 = 16;
    /// Queue capacity in weight units: the queue's position ([`Queue::pending_weight`]),
    /// which counts every settlement-sized group of the due rule ([`Packing`])
    /// at no less than [`UNITS_PER_SETTLEMENT`]. A submission whose record would
    /// end past it is refused ([`surcharge_sat`]).
    ///
    /// Latency bound (review 164 R3, decided 2026-11-02 22:30): each settlement
    /// whose anchor follows a record consumes at least one whole group ahead of
    /// it, and each group counts at least [`UNITS_PER_SETTLEMENT`] units, so a
    /// record that ends at position `p` is consumed by the `ceil(p / 14)`-th
    /// settlement anchored after it. At capacity that is [`MAX_DRAIN_SETTLEMENTS`]
    /// = 19, whatever record sizes or mix a filler picks; on an empty queue it
    /// is the first one (the second settlement after the submission, counting
    /// the one in flight).
    pub const MAX_PENDING_WEIGHT: u64 = 256;
    /// Forced submissions per native block, like DA batches.
    pub const MAX_PER_BLOCK: usize = 4;
    /// One signed L2 envelope (EIP-2718) at most this long.
    pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;
    /// Declared gas limit bounds: at least an intrinsic transfer, at most this.
    /// The guest skips an envelope whose own gas limit is above the declared
    /// one, so the declared gas bounds what an envelope can execute.
    pub const MIN_GAS: u64 = 21_000;
    pub const MAX_GAS: u64 = 300_000;
    /// Declared gas one settlement must consume at most: the due prefix stops
    /// before the record that would cross it. Forced envelopes bypass the
    /// sequencer's proving budget, so this is what bounds their proving work.
    /// The worst measured EVM-gas-to-SP1-gas ratio is about 216 (a modexp,
    /// agent 90), so 300k gas is at most about 65M SP1 gas on top of the block:
    /// inside the proven range, with room for the sequencer's transactions.
    /// To be re-measured on the final sparse guest before the gate is armed.
    pub const MAX_GAS_PER_SETTLEMENT: u64 = 300_000;
    const _: () = assert!(MAX_GAS <= MAX_GAS_PER_SETTLEMENT);
    /// Weight units one settlement drains at least: one transfer is one unit,
    /// and a settlement holds 14 of them.
    pub const UNITS_PER_SETTLEMENT: u64 = MAX_GAS_PER_SETTLEMENT / MIN_GAS;
    const _: () = assert!(UNITS_PER_SETTLEMENT == 14);
    /// Settlements anchored after a record that consume it at the latest, at
    /// capacity (see [`MAX_PENDING_WEIGHT`]).
    pub const MAX_DRAIN_SETTLEMENTS: u64 = MAX_PENDING_WEIGHT.div_ceil(UNITS_PER_SETTLEMENT);
    const _: () = assert!(MAX_DRAIN_SETTLEMENTS == 19);
    /// Queue-depth price per weight unit, at the unit's own position `u`:
    /// `BASE_SURCHARGE_SAT << (u / SURCHARGE_DOUBLING)` ([`unit_price_sat`]).
    /// A record pays the sum over the positions it occupies, including the room
    /// it leaves unused in the group it closes ([`surcharge_sat`], review 164 R5).
    /// An empty queue costs the base per unit; the last units of a full queue
    /// cost `2^10` times it.
    ///
    /// Doubling every 24 units (not 32) is the steeper ladder decided on review
    /// 164 R6 (target about 10x the cost of keeping the queue full, 8 units x
    /// 128_000 = 1_024_000 sat per settlement before). Holding the queue full
    /// now means buying back, every settlement, the whole group the settlement
    /// consumed, at least 14 units at the top of the queue. The cheapest full
    /// hold is 150_001-gas records at position 246: positions 232..=245 each
    /// settlement, `8 x 512_000 + 6 x 1_024_000 = 10_240_000` sat (0.1024
    /// BLCH, 10.0x); with transfers it is positions 242..=255, `14 x 1_024_000
    /// = 14_336_000` sat. Filling it from empty costs `24_000 x (2^10 - 1) + 16
    /// x 1_024_000 = 40_936_000` sat (0.409 BLCH).
    pub const BASE_SURCHARGE_SAT: u64 = 1_000;
    pub const SURCHARGE_DOUBLING: u64 = 24;
    const _: () = assert!(MAX_PENDING_WEIGHT / SURCHARGE_DOUBLING < 32);
    /// The largest weight one record can be charged: up to 13 units of room it
    /// leaves in the group it closes, plus its own (14 at [`MAX_GAS`]).
    pub const MAX_CHARGED_WEIGHT: u64 = UNITS_PER_SETTLEMENT - 1 + weight(MAX_GAS);
    pub const INBOX_DOMAIN: &[u8] = b"BLOCH:L2:INBOX:2";
    /// Consumed records kept, with the L2 number of the settlement that
    /// consumed them, so that a rollback head reset can queue them again
    /// ([`Queue::requeue_after`]). At [`MAX_PER_SETTLEMENT`] per settlement
    /// this covers at least 64 settlements; a reset deeper than the log is
    /// refused rather than losing forced transactions.
    pub const CONSUMED_LOG: usize = 1_024;

    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Record {
        /// Native height of the block that included the forced transaction.
        pub height: u64,
        /// Its L1 txid: where a rebuilder reads the envelope.
        pub l1_txid: [u8; 32],
        /// keccak256 of the envelope, which is its L2 transaction hash.
        pub envelope_hash: [u8; 32],
        /// Declared gas limit, in [`MIN_GAS`]..=[`MAX_GAS`].
        pub gas_limit: u64,
    }
    impl Record {
        pub fn encode(&self) -> [u8; 80] {
            let mut out = [0u8; 80];
            out[..8].copy_from_slice(&self.height.to_be_bytes());
            out[8..40].copy_from_slice(&self.l1_txid);
            out[40..72].copy_from_slice(&self.envelope_hash);
            out[72..].copy_from_slice(&self.gas_limit.to_be_bytes());
            out
        }
    }

    /// keccak256 of the concatenated records.
    pub fn hash(records: &[Record]) -> [u8; 32] {
        let mut h = Keccak256::new();
        for r in records {
            h.update(r.encode());
        }
        h.finalize().into()
    }

    /// What a V3 statement's `deposits_hash` slot holds under forced inclusion.
    pub fn inbox_hash(deposits_hash: [u8; 32], consumed: &[Record]) -> [u8; 32] {
        if consumed.is_empty() {
            return deposits_hash;
        }
        let mut h = Keccak256::new();
        h.update(INBOX_DOMAIN);
        h.update(deposits_hash);
        h.update(hash(consumed));
        h.finalize().into()
    }

    /// Weight units of a record declaring `gas`: its share of one settlement,
    /// `ceil(gas * 14 / 300k)` (1 for a transfer, 8 at 150_001, 14 at [`MAX_GAS`]).
    pub const fn weight(gas: u64) -> u64 {
        gas.saturating_mul(UNITS_PER_SETTLEMENT).div_ceil(MAX_GAS_PER_SETTLEMENT)
    }

    /// The price of the weight unit at queue position `position`.
    pub const fn unit_price_sat(position: u64) -> u64 {
        BASE_SURCHARGE_SAT << (position / SURCHARGE_DOUBLING)
    }

    /// The surcharge of `weight` units occupying positions `pending..pending +
    /// weight`, each priced at its own position, or `None` when they do not
    /// fit (or `weight` is 0). At most two price tiers per record, summed in
    /// closed form.
    pub const fn surcharge_sat(pending: u64, weight: u64) -> Option<u64> {
        if weight == 0 || pending.saturating_add(weight) > MAX_PENDING_WEIGHT {
            return None;
        }
        let end = pending + weight;
        let mut at = pending;
        let mut total = 0u64;
        while at < end {
            let tier_end = (at / SURCHARGE_DOUBLING + 1) * SURCHARGE_DOUBLING;
            let stop = if tier_end < end { tier_end } else { end };
            total += unit_price_sat(at) * (stop - at);
            at = stop;
        }
        Some(total)
    }

    /// The most a record declaring `gas` can be charged while the queue's
    /// position is at most `pending`: what a wallet signs as its maximum
    /// surcharge (`pending` = the position it read plus its headroom). Any
    /// surplus over the charged surcharge is refunded to the sender, so the
    /// ceiling only ties up funds for one block. `None` for a shape-invalid gas.
    pub const fn surcharge_ceiling_sat(pending: u64, gas: u64) -> Option<u64> {
        if gas < MIN_GAS || gas > MAX_GAS {
            return None;
        }
        let span = UNITS_PER_SETTLEMENT - 1 + weight(gas);
        let mut hi = pending.saturating_add(span);
        if hi > MAX_PENDING_WEIGHT {
            hi = MAX_PENDING_WEIGHT;
        }
        let lo = hi.saturating_sub(span);
        surcharge_sat(lo, hi - lo)
    }

    /// Settlement-sized groups of the due rule, built front to back exactly as
    /// successive settlements consume them ([`Queue::due`]: in order, at most
    /// [`MAX_PER_SETTLEMENT`] records and [`MAX_GAS_PER_SETTLEMENT`] declared
    /// gas). A group is closed by the first record that does not fit; a closed
    /// group counts `max(UNITS_PER_SETTLEMENT, its weight)`, so the record that
    /// closes it pays for the room it leaves unused. The open group counts its
    /// weight. Removing whole groups from the front leaves the later groups as
    /// they were, and removing part of the first one never adds a group (the
    /// greedy rule stays ahead), so a record's group number only goes down.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Packing {
        /// Units of the closed groups.
        pub closed: u64,
        /// Declared gas, records and weight of the open group.
        pub gas: u64,
        pub records: u64,
        pub units: u64,
    }
    impl Packing {
        pub const fn add(mut self, gas: u64) -> Self {
            if self.records > 0
                && (self.gas.saturating_add(gas) > MAX_GAS_PER_SETTLEMENT || self.records >= MAX_PER_SETTLEMENT)
            {
                let units = if self.units > UNITS_PER_SETTLEMENT { self.units } else { UNITS_PER_SETTLEMENT };
                self.closed = self.closed.saturating_add(units);
                self.gas = 0;
                self.records = 0;
                self.units = 0;
            }
            self.gas = self.gas.saturating_add(gas);
            self.records += 1;
            self.units += weight(gas);
            self
        }
        /// The queue position: units of everything packed so far.
        pub const fn position(&self) -> u64 {
            self.closed.saturating_add(self.units)
        }
    }

    /// The protocol treasury that receives every charged surcharge (decided
    /// 2026-11-02 22:30: not burned, and not shared with the block producer).
    /// `None` until the owner names it ([`super::mainnet::FORCED_INCLUSION_TREASURY`]);
    /// forced inclusion is never enabled without it, and
    /// `hard_forks::l2_forced_inclusion_may_arm` refuses to arm without it.
    pub fn treasury() -> Option<[u8; 32]> {
        #[cfg(test)]
        {
            treasury_test::get()
        }
        #[cfg(not(test))]
        {
            super::mainnet::FORCED_INCLUSION_TREASURY
        }
    }
    /// Tests run with a throwaway treasury unless a test unsets it.
    #[cfg(test)]
    pub(crate) mod treasury_test {
        use std::cell::Cell;
        pub const TREASURY: [u8; 32] = [0x7e; 32];
        thread_local! { static SET: Cell<bool> = const { Cell::new(true) }; }
        pub fn get() -> Option<[u8; 32]> {
            SET.with(Cell::get).then_some(TREASURY)
        }
        pub fn unset() -> impl Drop {
            struct Restore(bool);
            impl Drop for Restore {
                fn drop(&mut self) {
                    SET.with(|v| v.set(self.0));
                }
            }
            let was = SET.with(|v| v.replace(false));
            Restore(was)
        }
    }

    /// The queue, present only on an L2 where forced inclusion is enabled.
    #[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Queue {
        /// Unconsumed records, oldest first. Consumed ones are dropped: the
        /// running root keeps the history.
        pub(crate) pending: Vec<Record>,
        /// Records ever queued and ever consumed.
        pub(crate) queued: u64,
        pub(crate) consumed: u64,
        /// Running root over every record ever queued.
        pub(crate) root: [u8; 32],
        /// Pending count frozen with the source anchor.
        pub(crate) anchor: Option<u64>,
        /// The newest consumed records, oldest first, each with the L2 number
        /// of the settlement that consumed it; at most [`CONSUMED_LOG`].
        pub(crate) log: Vec<(u64, Record)>,
        /// Highest L2 number among records dropped from `log` (0: none).
        pub(crate) log_floor: u64,
    }
    impl Queue {
        pub(crate) fn new() -> Self {
            Self { root: Keccak256::digest(b"BLOCH:NATIVE:L2:EMPTY-FORCED:1").into(), ..Self::default() }
        }
        pub fn pending(&self) -> &[Record] {
            &self.pending
        }
        pub fn queued(&self) -> u64 {
            self.queued
        }
        pub fn consumed(&self) -> u64 {
            self.consumed
        }
        pub fn root(&self) -> [u8; 32] {
            self.root
        }
        /// What the next settlement must consume: everything pending at the
        /// anchor, in order, up to [`MAX_PER_SETTLEMENT`] records and
        /// [`MAX_GAS_PER_SETTLEMENT`] declared gas. Before an anchor, what is
        /// pending now, with the same caps.
        pub fn due(&self) -> &[Record] {
            let frozen = self.anchor.unwrap_or(self.pending.len() as u64);
            let mut gas = 0u64;
            let mut n = 0usize;
            for r in self.pending.iter().take(frozen.min(MAX_PER_SETTLEMENT) as usize) {
                gas = gas.saturating_add(r.gas_limit);
                if gas > MAX_GAS_PER_SETTLEMENT {
                    break;
                }
                n += 1;
            }
            &self.pending[..n]
        }
        fn packing(&self) -> Packing {
            self.pending.iter().fold(Packing::default(), |p, r| p.add(r.gas_limit))
        }
        /// The queue position in weight units ([`Packing`]), at most
        /// [`MAX_PENDING_WEIGHT`] (more only after a head reset re-queues).
        pub fn pending_weight(&self) -> u64 {
            self.packing().position()
        }
        /// Where a record declaring `gas` would start and how many units it
        /// would be charged: its own weight plus the room it leaves unused in
        /// the group it closes.
        pub fn charged_weight(&self, gas: u64) -> (u64, u64) {
            let before = self.packing();
            let after = before.add(gas);
            (before.position(), after.position() - before.position())
        }
        /// The surcharge a record declaring `gas` pays now, or `None` when it
        /// does not fit.
        pub fn surcharge_for(&self, gas: u64) -> Option<u64> {
            let (at, units) = self.charged_weight(gas);
            surcharge_sat(at, units)
        }
        pub(crate) fn push(&mut self, record: Record) -> Result<(), Refusal> {
            if self.surcharge_for(record.gas_limit).is_none() {
                return Err(Refusal::Full);
            }
            let mut h = Keccak256::new();
            h.update(b"BLOCH:NATIVE:L2:FORCED:1");
            h.update(self.root);
            h.update(record.encode());
            self.root = h.finalize().into();
            self.pending.push(record);
            self.queued += 1;
            Ok(())
        }
        /// Consume the due records in the settlement of L2 block `l2_number`.
        pub(crate) fn consume_due(&mut self, l2_number: u64) {
            let n = self.due().len();
            self.log.extend(self.pending.drain(..n).map(|r| (l2_number, r)));
            self.consumed += n as u64;
            self.anchor = None;
            if self.log.len() > CONSUMED_LOG {
                let excess = self.log.len() - CONSUMED_LOG;
                for (number, _) in self.log.drain(..excess) {
                    self.log_floor = self.log_floor.max(number);
                }
            }
        }
        /// The consumed log.
        pub fn consumed_log(&self) -> &[(u64, Record)] {
            &self.log
        }
        /// Whether a head reset to L2 block `number` can queue again every
        /// record a later settlement consumed.
        pub fn covers_reset_to(&self, number: u64) -> bool {
            self.log_floor <= number
        }
        /// Head reset to L2 block `number`: every record consumed by a later
        /// settlement goes back to the front of the queue, in its original
        /// order, as the deposit cursor goes back for deposits. The running
        /// root is unchanged (nothing new is queued). A frozen anchor grows by
        /// the records put back, which were queued before it. Returns the
        /// number put back, or `None` (no change) when the log does not reach.
        pub(crate) fn requeue_after(&mut self, number: u64) -> Option<u64> {
            if !self.covers_reset_to(number) {
                return None;
            }
            let keep = self.log.iter().position(|(n, _)| *n > number).unwrap_or(self.log.len());
            let back: Vec<Record> = self.log.drain(keep..).map(|(_, r)| r).collect();
            let count = back.len() as u64;
            self.pending.splice(0..0, back);
            self.consumed -= count;
            if let Some(anchor) = self.anchor.as_mut() {
                *anchor += count;
            }
            Some(count)
        }
        pub(crate) fn encode(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:FORCED-STATE:2");
            out.extend_from_slice(&self.queued.to_le_bytes());
            out.extend_from_slice(&self.consumed.to_le_bytes());
            out.extend_from_slice(&self.root);
            match self.anchor {
                None => out.push(0),
                Some(count) => {
                    out.push(1);
                    out.extend_from_slice(&count.to_le_bytes());
                }
            }
            out.extend_from_slice(&(self.pending.len() as u64).to_le_bytes());
            for r in &self.pending {
                out.extend_from_slice(&r.encode());
            }
            out.extend_from_slice(&self.log_floor.to_le_bytes());
            out.extend_from_slice(&(self.log.len() as u64).to_le_bytes());
            for (number, r) in &self.log {
                out.extend_from_slice(&number.to_le_bytes());
                out.extend_from_slice(&r.encode());
            }
        }
    }

    /// Why the L2 state refused to queue a forced transaction.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Refusal {
        /// Forced inclusion is not enabled on this L2.
        NotActive,
        /// The submission names another L2 chain.
        Chain,
        /// Declared gas outside [`MIN_GAS`]..=[`MAX_GAS`], or an empty or
        /// oversized envelope.
        Shape,
        /// The record does not fit in [`MAX_PENDING_WEIGHT`].
        Full,
    }
}

/// Records one settlement must consume, when pending: min(pending, this).
pub const MAX_INBOX_PER_SETTLEMENT: u64 = 64;
/// Exact L2 body framing tag (`bloch_l2_evm::node_primitives::NodeBodyV2`).
const L2_BODY_TAG: &[u8] = b"BLOCH:EVM:BODY:2";

/// One escrowed native deposit, in inbox order. Its fields are exactly the
/// L2 `DepositProvenance::BridgedBlch` plus the EVM recipient.
#[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxRecord {
    /// Native height of the block containing the deposit transaction.
    pub height: u64,
    /// Position of the deposit among deposits in that block.
    pub tx_index: u32,
    pub txid: [u8; 32],
    /// Output index of the escrow (after any change outputs).
    pub vout: u32,
    pub sats: u64,
    pub recipient: [u8; 20],
}
impl InboxRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(76);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.tx_index.to_le_bytes());
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.vout.to_le_bytes());
        out.extend_from_slice(&self.sats.to_le_bytes());
        out.extend_from_slice(&self.recipient);
        out
    }
}

fn empty_inbox_root() -> [u8; 32] {
    hash(&[b"BLOCH:NATIVE:L2:EMPTY-INBOX:1"])
}

// Minimal RLP, sufficient for the fixed L2 body shape.
fn rlp_length(out: &mut Vec<u8>, offset: u8, len: usize) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        out.push(offset + 55 + (8 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}
fn rlp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_length(out, 0x80, bytes.len());
        out.extend_from_slice(bytes);
    }
}
fn rlp_uint(out: &mut Vec<u8>, value: u64) {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|b| **b == 0).count();
    rlp_bytes(out, &be[skip..]);
}
fn rlp_list(out: &mut Vec<u8>, payload: &[u8]) {
    rlp_length(out, 0xc0, payload.len());
    out.extend_from_slice(payload);
}

/// `keccak256(rlp(NodeBodyV2 { deposits: records, transactions: [] }))`:
/// the only body a settlement may prove while it consumes these records.
pub fn expected_body_commitment(records: &[InboxRecord]) -> [u8; 32] {
    let mut deposits = Vec::new();
    for r in records {
        let mut fields = Vec::new();
        rlp_bytes(&mut fields, &r.recipient);
        rlp_uint(&mut fields, r.height);
        rlp_uint(&mut fields, u64::from(r.tx_index));
        rlp_bytes(&mut fields, &r.txid);
        rlp_uint(&mut fields, u64::from(r.vout));
        rlp_uint(&mut fields, r.sats);
        rlp_list(&mut deposits, &fields);
    }
    let mut payload = Vec::new();
    rlp_bytes(&mut payload, L2_BODY_TAG);
    rlp_list(&mut payload, &deposits);
    rlp_list(&mut payload, &[]);
    let mut body = Vec::new();
    rlp_list(&mut body, &payload);
    Keccak256::digest(&body).into()
}

/// `keccak256(recipient || height BE8 || tx_index BE4 || txid || vout BE4 ||
/// sats BE8)` over the records in order; `keccak256("")` when empty. This is
/// `bloch_l2_evm::executor::deposits_hash` of the deposits these records mint.
pub fn deposits_hash(records: &[InboxRecord]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for r in records {
        h.update(r.recipient);
        h.update(r.height.to_be_bytes());
        h.update(r.tx_index.to_be_bytes());
        h.update(r.txid);
        h.update(r.vout.to_be_bytes());
        h.update(r.sats.to_be_bytes());
    }
    h.finalize().into()
}

/// One canonical native transaction. The statement is exactly a V2 (590-byte)
/// or V3 (766-byte) statement; decoding fixes the length before allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub proof_policy: [u8; 32],
    pub statement: Vec<u8>,
    pub proof: [u8; PROOF_BYTES],
}
impl Transaction {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Self::decode_tag(bytes, WIRE_TAG)
    }
    pub fn decode_async(bytes: &[u8]) -> Option<Self> {
        Self::decode_tag(bytes, ASYNC_WIRE_TAG)
    }
    fn decode_tag(bytes: &[u8], tag: u8) -> Option<Self> {
        let statement_bytes = match bytes.len() {
            TRANSACTION_BYTES => STATEMENT_BYTES,
            TRANSACTION_V3_BYTES => STATEMENT_V3_BYTES,
            _ => return None,
        };
        if bytes[0] != tag {
            return None;
        }
        let statement = &bytes[33..33 + statement_bytes];
        StatementVersion::of(statement)?;
        Some(Self {
            proof_policy: bytes[1..33].try_into().ok()?,
            statement: statement.to_vec(),
            proof: bytes[33 + statement_bytes..].try_into().ok()?,
        })
    }
    /// The statement version, or `None` for a malformed in-memory value.
    pub fn version(&self) -> Option<StatementVersion> {
        StatementVersion::of(&self.statement)
    }
    pub fn encode(&self) -> Vec<u8> {
        self.encode_tag(WIRE_TAG)
    }
    pub fn encode_async(&self) -> Vec<u8> {
        self.encode_tag(ASYNC_WIRE_TAG)
    }
    fn encode_tag(&self, tag: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 32 + self.statement.len() + PROOF_BYTES);
        bytes.push(tag);
        bytes.extend_from_slice(&self.proof_policy);
        bytes.extend_from_slice(&self.statement);
        bytes.extend_from_slice(&self.proof);
        bytes
    }
    // Preserve the existing L2 kernel's settlement-chain commitment: the native
    // wire discriminator is separate from the experimental kernel framing.
    pub fn commitment(&self) -> [u8; 32] {
        hash(&[
            b"BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-COMMITMENT:1",
            b"BLOCH:EXPERIMENTAL:NATIVE-SETTLEMENT-TX:1",
            &self.proof_policy,
            self.statement.as_slice(),
            &self.proof,
        ])
    }
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn h(bytes: &[u8], offset: usize) -> [u8; 32] {
    bytes[offset..offset + 32].try_into().unwrap()
}
fn n(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// What a running network installs at the L2 flag day
/// ([`crate::params::L2_SETTLEMENT_ACTIVATION_EPOCH`]): the policy, whether
/// settlement is asynchronous (wire tag [`ASYNC_WIRE_TAG`]; deposits and
/// claims need it) and the withdrawal limits. The installed L2 has the
/// [`Profile::activated`] profile on every build: deposits, data
/// availability, user transactions and claims do not depend on cargo
/// features.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    pub policy: Policy,
    pub asynchronous: bool,
    pub limits: withdrawal::Limits,
}
impl Activation {
    /// An armed epoch must come with an activation that passes this
    /// (`armed_l2_gate_has_a_policy`).
    ///
    /// An activation for the mainnet chain id must also be the approved
    /// mainnet policy: asynchronous, an attestor set present (never
    /// installed while the keys are unset) and exactly [`mainnet::LIMITS`].
    pub fn valid(&self) -> bool {
        let mainnet_shape = self.policy.chain_id != MAINNET_CHAIN_ID
            || (self.asynchronous == mainnet::ASYNCHRONOUS
                && self.policy.attestor_set != [0; 32]
                && self.limits == mainnet::LIMITS);
        self.policy.valid() && self.limits.valid() && mainnet_shape
    }
}

/// EVM chain id of the MAINNET L2, decided 2026-10-14 (free on
/// chainid.network; development networks keep 700771). The pinned
/// activation must use it (`armed_l2_gate_has_a_policy`). Recording the value
/// arms nothing.
pub const MAINNET_CHAIN_ID: u64 = 700_770;

/// The mainnet L2 policy approved 2026-10-14 (docs/L2-MAINNET-ACTIVATION.md):
/// asynchronous settlement, a 3-of-5 hybrid PQ attestor set fixed at
/// activation, and the withdrawal limits below. Recording it arms nothing:
/// the gate stays the sentinel and [`activation`](mainnet::activation)
/// refuses while any part is still unset (the attestor keys, the L2 program
/// and genesis), so [`activation_policy`] stays `None`.
///
/// Set-once: the attestor set is committed in the policy at installation
/// (`BLOCH:NATIVE:L2:ATTESTORS:1` in the 0x21 leaf). There is no rotation,
/// no periodic signing and no admin key; a new set is a new policy (a new
/// flag day).
pub mod mainnet {
    use super::{withdrawal, Activation, Policy, MAINNET_CHAIN_ID};
    use crate::transition::funded::ADMISSION_PQ_KEY_BYTES;

    /// Settlement V3 over the asynchronous wire (deposits and claims need it).
    pub const ASYNCHRONOUS: bool = true;
    /// k of the attestor set: signatures a large claim needs.
    pub const ATTESTOR_THRESHOLD: u8 = 3;
    /// n of the attestor set: hybrid (ML-DSA-65 + Falcon-1024) keys, each held
    /// by a different operator on a different host.
    pub const ATTESTOR_COUNT: usize = 5;
    const _: () = assert!(
        ATTESTOR_THRESHOLD >= 1
            && ATTESTOR_THRESHOLD as usize <= ATTESTOR_COUNT
            && ATTESTOR_COUNT <= withdrawal::MAX_ATTESTORS
    );

    /// One BLCH in satoshis.
    pub const BLCH: u64 = 100_000_000;
    /// The approved withdrawal limits.
    pub const LIMITS: withdrawal::Limits = withdrawal::Limits {
        // Small claims: 64 blocks (two epochs) after the record, on top of
        // the FFG-finality requirement.
        delay_blocks: 64,
        // Claims of at least 100 BLCH are large: attested and 2 880 blocks.
        large_claim_sat: 100 * BLCH,
        large_delay_blocks: 2_880,
        // Retention must cover the large delay.
        retention_blocks: 2_880,
        // Per 2 880-block window: at most 10% of the escrow, floor 10 BLCH.
        release_window_blocks: 2_880,
        release_window_bps: 1_000,
        release_floor_sat: 10 * BLCH,
    };
    const _: () = assert!(LIMITS.valid());

    /// The attestor set, SET ONCE before the flag day: the text that
    /// `bloch-pos l2-claim attestor-set --threshold 3 --pubkey … --out` writes
    /// (threshold line, then the five enveloped public keys in hex, in set
    /// order). `None` = UNSET: [`activation`] refuses.
    ///
    /// SET 2026-10-14 (`generate-mainnet-attestor-keys.sh --all`, then
    /// `--assemble`): set hash
    /// `1c06adbb7fef042f58d7efd11587689e324c036c3b467081a63b1cf79caccc4b`.
    pub const ATTESTOR_SET: Option<&str> = Some(include_str!("../l2-mainnet/attestors.set"));

    /// CANDIDATE, not scheduled: the program that replaces [`PROGRAM`] at
    /// [`crate::params::L2_NEXT_PROGRAM_EPOCH`]. Identities 0, 1 and 2, the
    /// genesis pins, the attestor set and the limits stay as activated.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NextProgram {
        /// Replaces identities 3 (configuration), 4 (ELF), 5 and 6 (keys).
        pub identities: [[u8; 32]; 4],
        pub proof_policy: [u8; 32],
    }
    /// `settlement_v3_mainnet_sparse` of bloch-l2-evm
    /// `codex/forced-guest-r8-20261102` 595d914 (agent 115's sparse guest with
    /// L1 forced inclusion, agent 137), built in its pinned container on two
    /// hosts: the sparse witness under the next rules with the forced prefix,
    /// guest ELF SHA-256 `bc35e838…b048`. Its configuration `b4663ab8…a29d`
    /// (tag `BLOCH:EVM:CONFIG:4:CANCUN`) is the next rules plus forced
    /// inclusion, and is listed in [`FORCED_INCLUSION_CONFIGURATIONS`].
    /// The configuration carries a PLACEHOLDER fee-sweep recipient, `TBD-owner`,
    /// and the guest is a candidate, so these values are examples until
    /// [`PROGRAM_NEXT_FINAL`] says otherwise.
    pub const PROGRAM_NEXT: NextProgram = NextProgram {
        identities: [
            h32("b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d"),
            h32("1f744da8d3e0302cd39152e24e91071d7f0cfec7639245566a471cd6083a6b18"),
            h32("6a140f117b84dd524b3681b9447422e5281451295144b5747197d0df5db6afc9"),
            h32("00d4281e23ee13754a59b40dcc47422e55028a2534512d5d38cbe86fddb6afc9"),
        ],
        // The wrapper VK and the V3 tag are unchanged, so the policy is too.
        proof_policy: h32("154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"),
    };
    /// The program a rollback installs at [`crate::params::L2_PROGRAM_ROLLBACK_EPOCH`]:
    /// `settlement_v3_mainnet` of the `integrations/sp1-execution/guest-fallback`
    /// crate of bloch-l2-evm `codex/fallback-forced-r11-20261103` (agent 216),
    /// built in the pinned container of the sparse guests
    /// (`guest-fallback/build-container.sh`): the complete witness under the
    /// same rules, L1 forced inclusion included, guest ELF SHA-256
    /// `7fd7f3c0…5b5303` (3 138 944 bytes). It replaces `3ad3a4f0…53b3`, which
    /// did not run the forced rule.
    ///
    /// It proves the next rules, which the assert below pins: the swap to the
    /// next rules is one-way on the L2, because blocks under them hold the vault
    /// code, so [`PROGRAM`] cannot prove any successor of such a block. A
    /// rollback changes which guest proves the rules, never the rules.
    ///
    /// Forced inclusion: this guest runs the forced records after the deposits
    /// and publishes [`super::forced::inbox_hash`] exactly as [`PROGRAM_NEXT`]
    /// does (bloch-l2-evm `src/forced_complete.rs`; the forced list is the
    /// guest's fifth input), so its configuration is the forced next one
    /// (`b4663ab8…`, listed) and a rollback keeps forced inclusion working.
    pub const PROGRAM_FALLBACK: NextProgram = NextProgram {
        identities: [
            h32("b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d"),
            h32("d95185a60668b0d4e1da49be00d85b9c550b412f13c5155be454e72889f90bf1"),
            h32("432fa77548114c6431d3d64a09c851e8178e83b4744681fb73c3e2d368b11546"),
            h32("00865f4eeb204531918e9eb2509c851e82f1d0769d11a07ef9e1f169e8b11546"),
        ],
        proof_policy: h32("154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"),
    };
    /// Whether the fee-sweep recipient is final and the two programs above are
    /// the reproducible release guests. An armed gate refuses to compile until
    /// this is true (`hard_forks::l2_program_may_arm`).
    pub const PROGRAM_NEXT_FINAL: bool = false;
    /// L2 configurations (identity 3) whose guest executes the forced records
    /// of [`super::forced`] and publishes [`super::forced::inbox_hash`]: the
    /// next configuration (`BLOCH:EVM:CONFIG:4:CANCUN`), which [`PROGRAM_NEXT`]
    /// and [`PROGRAM_FALLBACK`] both carry. [`crate::params::L2_FORCED_INCLUSION_EPOCH`]
    /// stays inert (`hard_forks::l2_forced_inclusion_may_arm`).
    pub const FORCED_INCLUSION_CONFIGURATIONS: &[[u8; 32]] =
        &[h32("b4663ab88607a1ebf7d1801920365fdde276889e211e097011bf48fcd0f7a29d")];
    /// TBD-owner: the script hash of the protocol treasury that receives every
    /// charged forced-inclusion surcharge (`super::forced::treasury`). `None`
    /// keeps forced inclusion from being enabled, and
    /// `hard_forks::l2_forced_inclusion_may_arm` refuses to arm the gate while
    /// it is unset. Revenue rule (2026-11-02 22:30): the treasury, never a burn.
    /// Alias of `params::PROTOCOL_TREASURY_SCRIPT_HASH` (one treasury for every
    /// L1 protocol revenue rule).
    pub const FORCED_INCLUSION_TREASURY: Option<[u8; 32]> = crate::params::PROTOCOL_TREASURY_SCRIPT_HASH;

    /// TBD-owner: the hash (`Sha3_256`) of the mainnet settler's DA funding
    /// public key, which owns the reserved DA slot
    /// (`params::L2_DA_RESERVED_SLOT_EPOCH`). Unset, so that gate cannot be
    /// armed (`hard_forks::l2_da_reserved_slot_may_arm`). Losing or leaking
    /// this key costs no funds: the slot then serves nobody, or the leaker,
    /// and DA is back to the open auction of today.
    pub const DA_RESERVED_KEY: Option<[u8; 32]> = None;

    const fn same_hash(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut i = 0;
        while i < 32 {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }
    // The fallback proves exactly the next rules, forced inclusion included:
    // the same configuration (agent 216 removed the earlier escape for a
    // fallback on the next rules without forced inclusion).
    const _: () = assert!(same_hash(&PROGRAM_NEXT.identities[0], &PROGRAM_FALLBACK.identities[0]));
    const _: () = assert!(same_hash(&PROGRAM_NEXT.proof_policy, &PROGRAM_FALLBACK.proof_policy));

    /// OPTION, an owner decision, absent by default: a one-time reset of the
    /// settled L2 head, applied by [`super::State::install_next_program`] in the
    /// same transition as the swap. Without it the swap prevents an off-rule block
    /// but cannot recover from one that landed before the gate: its state root is
    /// unknown to everyone but its author, so nobody else can build on it.
    ///
    /// L1 cannot tell an off-rule block by itself (the statement carries neither
    /// value), so the target is named by whoever writes the emergency release,
    /// from what the attestors could not rebuild. There is no key and no runtime
    /// input: it is a compiled constant that every validator must choose to run.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HeadReset {
        /// The last block to keep. Zero means the L2 genesis (no statement).
        pub number: u64,
        /// The accepted head's commitment at that block (zero for the genesis).
        pub commitment: [u8; 32],
        /// The accepted V3 statement of that block, as hex (`None` for the genesis).
        pub statement: Option<&'static str>,
        /// FORFEIT form (G2a, an attacker drained forged leaves before the gate).
        /// `false`: the reset refuses, and the head stays, once any leaf the
        /// target did not publish was claimed. `true`: the reset applies anyway,
        /// and the claims of those leaves are forgotten, so the new chain's
        /// withdrawals at the same indices can be paid. What they released stays
        /// released: the escrow is short by exactly that amount (the forfeit),
        /// and the forged roots stop paying at the gate. Only for a tail whose
        /// paid leaves are not re-published by the rebuild: an honest withdrawal
        /// of a dropped block that was paid and is included again on the new
        /// chain would be paid twice.
        pub forfeit: bool,
    }
    /// `None`: the release ships no reset and the swap changes the program only.
    pub const HEAD_RESET: Option<HeadReset> = None;
    /// The same option for the rollback, applied with it. Names the last block
    /// before what the misbehaving guest settled; an emergency release fills it
    /// only when that guest settled a block the rules do not give.
    pub const ROLLBACK_HEAD_RESET: Option<HeadReset> = None;

    /// The L2 program and genesis the activation pins: the seven V2
    /// identities (Genesis-4 admission domain, native genesis, L2 domain,
    /// L2 configuration, guest ELF, KoalaBear key, BN254 key), the proof
    /// policy and the L2 genesis parent/state for chain [`MAINNET_CHAIN_ID`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Program {
        pub identities: [[u8; 32]; 7],
        pub proof_policy: [u8; 32],
        pub initial_l2_parent: [u8; 32],
        pub initial_l2_state: [u8; 32],
    }
    /// 64 hex characters as 32 bytes, at compile time (a typo fails the build).
    pub(crate) const fn h32(text: &str) -> [u8; 32] {
        let b = text.as_bytes();
        assert!(b.len() == 64, "32-byte hex");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
            i += 1;
        }
        out
    }
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("lowercase hex"),
        }
    }

    /// SET 2026-10-14: the `settlement_v3_mainnet` SP1 program of chain
    /// [`MAINNET_CHAIN_ID`] and its L2 genesis (bloch-l2-evm
    /// `feat/l2-mainnet-rpc-20261014` f0d53fe; reproduce with
    /// `deployment/mainnet/make_native_program.py`, see
    /// `docs/MAINNET-PROGRAM.md` there):
    ///
    /// - guest ELF SHA-256 `203114bf34df280d7964fd3ea047907f4bca230ad0e7a0e4bea85b305ad7c473`
    ///   (3 070 744 bytes; `build-reproducible.sh`, SP1 CLI 6.8.0,
    ///   succinct-1.96.0-64bit-v2, macOS x86_64, two-checkout reproducible);
    /// - SP1 circuit v6.1.0, Groth16 wrapper VK SHA-256 `4388a21c…e696`
    ///   (bound inside the V3 proof policy);
    /// - L2 genesis: `ChainSpec::mainnet` (no allocation besides the kernel
    ///   system accounts), domain `MAINNET_DOMAIN`, timestamp 1786656679
    ///   (Genesis-4 slot 0).
    pub const PROGRAM: Option<Program> = Some(Program {
        identities: [
            // Genesis-4 admission network domain: SHA3-256 of the manifest encoding.
            h32("f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966"),
            // Genesis-4 native genesis block id.
            h32("9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415"),
            // L2 V2 domain: keccak256("BLOCH:L2:MAINNET-DOMAIN:1" || 700770 BE8 || identities[0]).
            h32("1c3f8772d0bdfc22f33efce250a4f471343587859f815f083cfee69d3b6f0733"),
            // Execution configuration commitment (ChainSpec::mainnet, CONFIG:2:CANCUN).
            h32("8ec1c804e67190434fdf72b723103d26938797e90e1b652d366a1b053e3d8f2b"),
            // settlement_v3_mainnet ELF Keccak-256.
            h32("6e4c844007cbea4c5a3686f44cfb3b91362c146f3e87199a5229d619fae5c073"),
            // SP1 KoalaBear verifying-key hash.
            h32("389cfbde2516711668008cf00222398c6b2a3852266ca79c4ec42c5a6b39ac0e"),
            // SP1 BN254 verifying-key hash (the Groth16 program key).
            h32("007139f7bc9459c45b40046780222398cd65470a499b29e72762162d6b39ac0e"),
        ],
        // `bloch_l2_proof::policy_commitment_v3()` (settlement V3, user transactions).
        proof_policy: h32("154869964f89b4a5536f169ad6a4b17d0455ecace0891521356c554e32e5747d"),
        // L2 genesis header hash and state root (chain 700770).
        initial_l2_parent: h32("632e45ae778da371a88dc1ae430193aa77eabb67a11de18e84fea7d20d11f468"),
        initial_l2_state: h32("2ad7e807ac2ea14e2f423572fcb9e0f168de4cb26b5bbbd2711caf34cb05c05d"),
    });

    /// Why the mainnet activation cannot be built yet.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Incomplete {
        /// [`ATTESTOR_SET`] is unset.
        AttestorKeysUnset,
        /// The attestor set is not 3-of-5 distinct enveloped hybrid keys.
        AttestorSet,
        /// [`PROGRAM`] is unset.
        ProgramUnset,
    }

    pub(super) fn unhex(text: &str) -> Option<Vec<u8>> {
        let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        let bytes = text.as_bytes();
        if bytes.len() % 2 != 0 {
            return None;
        }
        bytes.chunks(2).map(|p| Some(digit(p[0])? << 4 | digit(p[1])?)).collect()
    }

    /// The public keys of an attestor set file, checked against the approved
    /// shape: threshold 3, exactly 5 distinct keys of the enveloped hybrid size.
    pub fn attestor_keys(text: &str) -> Result<Vec<Vec<u8>>, Incomplete> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        if lines.next().and_then(|l| l.parse::<u8>().ok()) != Some(ATTESTOR_THRESHOLD) {
            return Err(Incomplete::AttestorSet);
        }
        let keys = lines.map(unhex).collect::<Option<Vec<_>>>().ok_or(Incomplete::AttestorSet)?;
        let distinct = keys.iter().enumerate().all(|(i, k)| !keys[..i].contains(k));
        if keys.len() != ATTESTOR_COUNT || !distinct || keys.iter().any(|k| k.len() != ADMISSION_PQ_KEY_BYTES) {
            return Err(Incomplete::AttestorSet);
        }
        Ok(keys)
    }

    /// The mainnet activation from its set-once parts, or why it is incomplete.
    pub fn activation_from(program: Option<&Program>, attestor_set: Option<&str>) -> Result<Activation, Incomplete> {
        let keys = attestor_keys(attestor_set.ok_or(Incomplete::AttestorKeysUnset)?)?;
        let program = program.ok_or(Incomplete::ProgramUnset)?;
        Ok(Activation {
            policy: Policy {
                identities: program.identities,
                proof_policy: program.proof_policy,
                chain_id: MAINNET_CHAIN_ID,
                initial_l2_parent: program.initial_l2_parent,
                initial_l2_state: program.initial_l2_state,
                attestor_set: withdrawal::attestor_set_hash(ATTESTOR_THRESHOLD, &keys),
            },
            asynchronous: ASYNCHRONOUS,
            limits: LIMITS,
        })
    }

    /// The mainnet activation as recorded in this build.
    pub fn activation() -> Result<Activation, Incomplete> {
        activation_from(PROGRAM.as_ref(), ATTESTOR_SET)
    }
}

/// The activation pinned for the running network: [`mainnet::activation`]
/// once every set-once part is filled. `None` today: the approved policy
/// (async, 3-of-5 attestors, limits) and the attestor keys are recorded but
/// the L2 program/genesis is unset. An armed epoch without one is refused by
/// `armed_l2_gate_has_a_policy`.
pub fn activation_policy() -> Option<Activation> {
    #[cfg(test)]
    if let Some(p) = activation_rehearsal::policy() {
        return Some(p);
    }
    mainnet::activation().ok()
}

/// The activation a network bound to `network` (its admission domain)
/// installs at the flag day: the pinned [`activation_policy`] when it names
/// that network. A qualification build (`l2-activation-rehearsal`) instead
/// installs [`rehearsal_activation`] on whatever development network it runs.
pub fn activation_for(network: Option<[u8; 32]>) -> Option<Activation> {
    let network = network?;
    #[cfg(feature = "l2-activation-rehearsal")]
    {
        Some(rehearsal_activation(network))
    }
    #[cfg(not(feature = "l2-activation-rehearsal"))]
    {
        activation_policy().filter(|a| a.policy.identities[0] == network)
    }
}

/// Mixed-fleet rehearsal policy: bound to the running development network,
/// asynchronous, development limits, placeholder program identity (no proof
/// is ever produced for it; the rehearsal qualifies the boundary, not the L2).
///
/// With `l2-activation-rehearsal-mainnet-policy` (final qualification) the
/// rehearsal installs the approved MAINNET policy values instead: chain id
/// [`MAINNET_CHAIN_ID`], [`mainnet::ASYNCHRONOUS`], [`mainnet::LIMITS`], the
/// committed [`mainnet::ATTESTOR_SET`] hash (a non-zero placeholder while it
/// is unset) and, once [`mainnet::PROGRAM`] is set, its program identities,
/// proof policy and L2 genesis. Only the network binding (identities 0..1)
/// stays the running devnet's, so it still never runs on a funded network.
#[cfg(feature = "l2-activation-rehearsal")]
pub fn rehearsal_activation(network: [u8; 32]) -> Activation {
    let id = |label: &[u8]| hash(&[b"BLOCH:L2:REHEARSAL:1", label, &network]);
    #[allow(unused_mut)]
    let mut activation = Activation {
        policy: Policy {
            identities: [network, id(b"genesis"), id(b"domain"), id(b"config"), id(b"elf"), id(b"koalabear"), id(b"bn254")],
            proof_policy: id(b"proof-policy"),
            chain_id: 700_999,
            initial_l2_parent: id(b"parent"),
            initial_l2_state: id(b"state"),
            attestor_set: [0; 32],
        },
        asynchronous: true,
        limits: withdrawal::Limits::DEVELOPMENT,
    };
    #[cfg(feature = "l2-activation-rehearsal-mainnet-policy")]
    {
        let policy = &mut activation.policy;
        policy.chain_id = MAINNET_CHAIN_ID;
        policy.attestor_set = mainnet::ATTESTOR_SET
            .and_then(|text| mainnet::attestor_keys(text).ok())
            .map_or(id(b"attestor-set"), |keys| withdrawal::attestor_set_hash(mainnet::ATTESTOR_THRESHOLD, &keys));
        if let Some(program) = mainnet::PROGRAM.as_ref() {
            policy.identities[2..].copy_from_slice(&program.identities[2..]);
            policy.proof_policy = program.proof_policy;
            policy.initial_l2_parent = program.initial_l2_parent;
            policy.initial_l2_state = program.initial_l2_state;
        }
        activation.asynchronous = mainnet::ASYNCHRONOUS;
        activation.limits = mainnet::LIMITS;
    }
    activation
}

#[cfg(test)]
pub(crate) mod activation_rehearsal {
    use super::Activation;
    use std::cell::RefCell;
    thread_local! { static POLICY: RefCell<Option<Activation>> = const { RefCell::new(None) }; }
    pub fn policy() -> Option<Activation> { POLICY.with(|p| p.borrow().clone()) }
    pub fn set(activation: Activation) -> impl Drop {
        struct Restore(Option<Activation>);
        impl Drop for Restore { fn drop(&mut self) { POLICY.with(|p| *p.borrow_mut() = self.0.take()); } }
        Restore(POLICY.with(|p| p.borrow_mut().replace(activation)))
    }
}

/// What an installed L2 admits beyond empty settlements. Fixed when the L2
/// is installed; consensus reads it from the state, never from the build.
#[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Native deposits into the inbox (0x14), and V2 bodies bound to the
    /// consumed inbox records.
    pub deposits: bool,
    /// V3 settlements with user transactions, L1 data availability (0x15)
    /// and withdrawal claims (0x16).
    pub user_transactions: bool,
    /// Claims in native L2 blocks at or above this height must prove
    /// against a finalized settlement (see
    /// [`withdrawal::FINALIZED_CLAIMS_FROM_HEIGHT`]).
    pub finalized_claims_from_height: u64,
    pub limits: withdrawal::Limits,
    /// Installed by the running-network flag day. Its profile is committed
    /// in the state; a development profile is not (its bytes are unchanged).
    activated: bool,
}
impl Profile {
    /// The profile of an L2 from a development genesis manifest: the build's
    /// devnet features, the development limits.
    pub const fn development() -> Self {
        Self {
            deposits: cfg!(feature = "devnet-l2-deposits"),
            user_transactions: USER_TRANSACTIONS_ENABLED,
            finalized_claims_from_height: withdrawal::FINALIZED_CLAIMS_FROM_HEIGHT,
            limits: withdrawal::Limits::DEVELOPMENT,
            activated: false,
        }
    }
    /// The profile of an L2 installed by the running-network flag day:
    /// everything admitted, claims against finalized settlements from the
    /// first block, the pinned limits.
    pub const fn activated(limits: withdrawal::Limits) -> Self {
        Self {
            deposits: true,
            user_transactions: true,
            finalized_claims_from_height: 0,
            limits,
            activated: true,
        }
    }
    pub fn is_activated(&self) -> bool {
        self.activated
    }
    fn encode(&self, out: &mut Vec<u8>) {
        if self.activated {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:ACTIVATED-PROFILE:1");
            out.push(u8::from(self.deposits) | u8::from(self.user_transactions) << 1);
            out.extend_from_slice(&self.finalized_claims_from_height.to_le_bytes());
            self.limits.encode(out);
        }
    }
}

/// Immutable network configuration, installed only by a new genesis constructor.
/// The first seven hashes follow the V2 statement: native network/genesis,
/// L2 domain/configuration, guest ELF, KoalaBear key and BN254 key.
#[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub identities: [[u8; 32]; 7],
    pub proof_policy: [u8; 32],
    pub chain_id: u64,
    pub initial_l2_parent: [u8; 32],
    pub initial_l2_state: [u8; 32],
    /// M6: [`withdrawal::attestor_set_hash`] of the hybrid PQ co-signers whose
    /// k-of-n attestation large claims need; all zero = no attestors.
    pub attestor_set: [u8; 32],
}
impl Policy {
    pub fn valid(&self) -> bool {
        self.chain_id != 0
            && !self.identities.contains(&[0; 32])
            && self.proof_policy != [0; 32]
            && self.initial_l2_parent != [0; 32]
            && self.initial_l2_state != [0; 32]
    }
    fn encode(&self, out: &mut Vec<u8>) {
        for id in self.identities {
            out.extend_from_slice(&id);
        }
        out.extend_from_slice(&self.proof_policy);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.initial_l2_parent);
        out.extend_from_slice(&self.initial_l2_state);
        // Absent without attestors, so existing policies keep their bytes.
        if self.attestor_set != [0; 32] {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:ATTESTORS:1");
            out.extend_from_slice(&self.attestor_set);
        }
    }
}

/// Derived solely from the committed native parent and its settlement cursor.
/// This protocol has an empty inbox; it grants no authority to native deposits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub block: [u8; 32],
    pub slot: u64,
    pub height: u64,
    pub commitment: [u8; 32],
    pub inbox_root: [u8; 32],
    /// Inbox records known at the source (the root commits to all of them).
    pub inbox_count: u64,
}
#[cfg_attr(feature = "local-state-cache", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    policy: Policy,
    native_height: u64,
    /// Commitment and exact statement (V2 or V3) of the accepted head.
    head: Option<([u8; 32], Vec<u8>)>,
    asynchronous: bool,
    /// (block, slot, height, inbox count, inbox root) frozen at the anchor.
    source_anchor: Option<([u8; 32], u64, u64, u64, [u8; 32])>,
    inbox: Vec<InboxRecord>,
    inbox_root: [u8; 32],
    consumed: u64,
    escrow_sat: u128,
    /// L1 data-availability records (M3), in inclusion order.
    da: Vec<da::Record>,
    /// Withdrawal roots of settlements that added withdrawals (M4), oldest
    /// first, pruned by [`withdrawal::RETENTION_BLOCKS`].
    withdrawals: Vec<withdrawal::Record>,
    /// Claimed withdrawal leaves (M5, the nullifier set).
    claimed: withdrawal::ClaimBitmap,
    /// Satoshis released from escrow by claims. Invariant:
    /// `escrow_sat == sum(inbox sats) - released_sat`.
    released_sat: u128,
    /// Release accounting of the newest window with a claim (M6).
    release_window: withdrawal::ReleaseWindow,
    /// What this L2 admits and its limits, fixed at installation.
    profile: Profile,
    /// This chain's own checkpoint roots (epoch -> root), recorded at each
    /// epoch boundary from `params::HF1_CLAIM_FINALITY_EPOCH`
    /// and empty before it: a claim is final only if the finalized
    /// checkpoint is one of them. At most four entries (see
    /// [`State::record_checkpoint_root`]). Committed (last, absent while
    /// empty); the local cache carries it in its own trailing section so the
    /// cached bytes of this struct do not change.
    #[cfg_attr(feature = "local-state-cache", serde(skip))]
    checkpoint_roots: std::collections::BTreeMap<u64, [u8; 32]>,
    /// L1 forced-inclusion queue ([`forced`]). `None` until
    /// [`crate::params::L2_FORCED_INCLUSION_EPOCH`] enables it; committed
    /// last and absent while `None`, so every earlier state keeps its bytes.
    /// The local cache carries it in its own trailing section, like
    /// `checkpoint_roots`, so the cached bytes of this struct do not change.
    #[cfg_attr(feature = "local-state-cache", serde(skip))]
    forced: Option<forced::Queue>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Policy,
    Source,
    Successor,
    Proof,
    Height,
    NotActive,
    Limit,
    /// The proven L2 body does not mint exactly the consumed inbox records.
    Deposits,
    /// A V3 body commitment is zero, or a V3 `da_commitment` is set without
    /// user transactions.
    Reserved,
    /// The V3 withdrawal count decreased, or the withdrawal root changed
    /// without new withdrawals (or did not change with new ones).
    Withdrawals,
    /// A V3 statement with `user_tx_count > 0` on an L2 whose [`Profile`]
    /// does not admit user transactions (a development genesis on a build
    /// without `devnet-l2-user-txs`).
    UserTransactions,
    /// A V3 statement with user transactions whose `da_commitment` matches no
    /// L1 data-availability record (same L2 block number) included in a
    /// strictly earlier native block and still retained.
    DataUnavailable,
    /// Forced inclusion is enabled and the statement does not consume exactly
    /// the forced records due at its anchor ([`forced::inbox_hash`]), or a V2
    /// statement arrives while forced records are due.
    Forced,
}

/// Whether an L2 from a development genesis manifest admits user
/// transactions, data availability and claims on this build (feature
/// `devnet-l2-user-txs`; see [`Profile::development`]). An L2 installed by
/// the running-network flag day admits them regardless ([`Profile::activated`]).
pub const USER_TRANSACTIONS_ENABLED: bool = cfg!(feature = "devnet-l2-user-txs");
impl State {
    pub fn genesis(policy: Policy) -> Result<Self, Reject> {
        if !policy.valid() {
            return Err(Reject::Policy);
        }
        Ok(Self {
            policy,
            native_height: 0,
            head: None,
            asynchronous: false,
            source_anchor: None,
            inbox: Vec::new(),
            inbox_root: empty_inbox_root(),
            consumed: 0,
            escrow_sat: 0,
            da: Vec::new(),
            withdrawals: Vec::new(),
            claimed: withdrawal::ClaimBitmap::default(),
            released_sat: 0,
            release_window: withdrawal::ReleaseWindow::default(),
            profile: Profile::development(),
            checkpoint_roots: std::collections::BTreeMap::new(),
            forced: None,
        })
    }
    pub(crate) fn genesis_async(policy: Policy) -> Result<Self, Reject> {
        let mut state = Self::genesis(policy)?;
        state.asynchronous = true;
        Ok(state)
    }
    /// The L2 a running network installs at the flag day (M8 part 2 / M9).
    pub fn activated(activation: Activation) -> Result<Self, Reject> {
        if !activation.valid() {
            return Err(Reject::Policy);
        }
        let mut state = Self::genesis(activation.policy)?;
        state.asynchronous = activation.asynchronous;
        state.profile = Profile::activated(activation.limits);
        Ok(state)
    }
    pub fn asynchronous(&self) -> bool { self.asynchronous }
    pub fn profile(&self) -> &Profile { &self.profile }
    pub fn limits(&self) -> &withdrawal::Limits { &self.profile.limits }
    /// Native deposits (0x14) are admitted: the profile allows them and the
    /// settlement is asynchronous (the inbox is frozen at the anchor).
    pub fn deposits_enabled(&self) -> bool { self.profile.deposits && self.asynchronous }
    /// User-transaction settlements, data availability and claims.
    pub fn user_transactions(&self) -> bool { self.profile.user_transactions }
    /// A source is pinned by a committed transition, never by a proof caller.
    pub fn frozen_source(&self) -> Option<Source> {
        self.source_anchor
            .map(|(block, slot, height, count, root)| self.source_at(block, slot, height, count, root))
    }
    pub(crate) fn prepare_source(&mut self, parent: [u8; 32], parent_slot: u64) {
        if self.asynchronous && self.source_anchor.is_none() && self.native_height > 0 {
            self.source_anchor = Some((parent, parent_slot, self.native_height, self.inbox.len() as u64, self.inbox_root));
            // The forced queue freezes with the source: what a settlement on
            // this anchor must consume cannot grow while it is being proved.
            if let Some(queue) = self.forced.as_mut() {
                queue.anchor = Some(queue.pending.len() as u64);
            }
        }
    }
    /// The forced-inclusion queue, `None` while forced inclusion is not enabled.
    pub fn forced_queue(&self) -> Option<&forced::Queue> {
        self.forced.as_ref()
    }
    /// Whether this L2 runs rules whose guest implements forced inclusion.
    /// It follows the committed configuration, like [`Self::next_program_active`]:
    /// an L2 is enabled only if its configuration is listed in
    /// [`mainnet::FORCED_INCLUSION_CONFIGURATIONS`] (empty: no program does).
    pub fn forced_inclusion_program(&self) -> bool {
        mainnet::FORCED_INCLUSION_CONFIGURATIONS.contains(&self.policy.identities[3])
    }
    /// Enable forced inclusion at [`crate::params::L2_FORCED_INCLUSION_EPOCH`].
    /// Only on an L2 that admits user transactions, settles asynchronously and
    /// runs a program that implements it; once.
    pub(crate) fn enable_forced_inclusion(&mut self) -> bool {
        self.enable_forced_inclusion_if(self.forced_inclusion_program())
    }
    fn enable_forced_inclusion_if(&mut self, program: bool) -> bool {
        if self.forced.is_some()
            || !program
            || !self.profile.user_transactions
            || !self.asynchronous
            || forced::treasury().is_none()
        {
            return false;
        }
        let mut queue = forced::Queue::new();
        // Enabled between an anchor and its settlement: nothing is due yet.
        if self.source_anchor.is_some() {
            queue.anchor = Some(0);
        }
        self.forced = Some(queue);
        true
    }
    /// Test hook (review 164): consume what is due now, as a settlement would.
    #[cfg(test)]
    pub(crate) fn forced_consume_due_for_review(&mut self) {
        let number = self.settled_number().saturating_add(1);
        if let Some(queue) = self.forced.as_mut() {
            queue.consume_due(number);
        }
    }
    /// Test hook: enable forced inclusion whatever the configuration.
    #[cfg(test)]
    pub(crate) fn enable_forced_inclusion_for_test(&mut self) -> bool {
        self.enable_forced_inclusion_if(true)
    }
    /// Test hook: the queue, mutable.
    #[cfg(test)]
    pub(crate) fn forced_queue_mut_for_test(&mut self) -> Option<&mut forced::Queue> {
        self.forced.as_mut()
    }
    /// Queue a forced L2 transaction published at the next native height.
    /// The caller has already charged and authorized the L1 transaction.
    pub(crate) fn queue_forced(
        &mut self,
        chain_id: u64,
        l1_txid: [u8; 32],
        envelope: &[u8],
        gas_limit: u64,
    ) -> Result<(), forced::Refusal> {
        use forced::Refusal as R;
        let height = self.native_height.checked_add(1).ok_or(R::Full)?;
        // A rollback to a fallback guest that does not implement the rule takes
        // no new record (review 164 R1). `hard_forks::l2_forced_inclusion_may_arm`
        // already refuses to arm forced inclusion with an unlisted fallback;
        // this keeps the L2 from owing what its guest cannot prove anyway.
        if self.policy.identities[3..7] == mainnet::PROGRAM_FALLBACK.identities && !self.forced_inclusion_program() {
            return Err(R::NotActive);
        }
        let queue = self.forced.as_mut().ok_or(R::NotActive)?;
        if chain_id != self.policy.chain_id {
            return Err(R::Chain);
        }
        if envelope.is_empty()
            || envelope.len() > forced::MAX_ENVELOPE_BYTES
            || !(forced::MIN_GAS..=forced::MAX_GAS).contains(&gas_limit)
        {
            return Err(R::Shape);
        }
        let envelope_hash: [u8; 32] = Keccak256::digest(envelope).into();
        queue.push(forced::Record { height, l1_txid, envelope_hash, gas_limit })
    }
    /// Escrow a native deposit into the next inbox position. The caller has
    /// already removed exactly `record.sats` from the spendable supply.
    pub(crate) fn append_deposit(&mut self, record: InboxRecord) -> Result<(), Reject> {
        if !self.asynchronous || self.inbox.len() >= u32::MAX as usize {
            return Err(Reject::NotActive);
        }
        self.escrow_sat = self.escrow_sat.checked_add(u128::from(record.sats)).ok_or(Reject::Limit)?;
        self.inbox_root = hash(&[b"BLOCH:NATIVE:L2:INBOX:1", &self.inbox_root, &record.encode()]);
        self.inbox.push(record);
        Ok(())
    }
    /// Deposits already appended at `height` (gives the next tx_index there).
    pub fn deposits_at_height(&self, height: u64) -> u32 {
        self.inbox.iter().rev().take_while(|r| r.height == height).count() as u32
    }
    pub fn inbox(&self) -> &[InboxRecord] {
        &self.inbox
    }
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
    pub fn escrow_sat(&self) -> u128 {
        self.escrow_sat
    }
    /// The records the next settlement must consume from `source`.
    pub fn pending_for(&self, source: &Source) -> &[InboxRecord] {
        let end = source.inbox_count.min(self.consumed.saturating_add(MAX_INBOX_PER_SETTLEMENT));
        &self.inbox[self.consumed as usize..end as usize]
    }
    /// Retained L1 data-availability records, oldest first.
    pub fn data_availability(&self) -> &[da::Record] {
        &self.da
    }
    /// Retained withdrawal roots (M4), oldest first: the roots an L1 claim
    /// can prove against.
    pub fn withdrawal_roots(&self) -> &[withdrawal::Record] {
        &self.withdrawals
    }
    /// The newest retained withdrawal record a claim in the next native
    /// block may prove against (M5), `None` before any is old enough.
    pub fn matured_withdrawals(&self) -> Option<withdrawal::Record> {
        withdrawal::matured(&self.profile.limits, &self.withdrawals, self.native_height.saturating_add(1), 0).copied()
    }
    /// The same for a large claim (at least the profile's `large_claim_sat`).
    pub fn matured_large_withdrawals(&self) -> Option<withdrawal::Record> {
        let limits = &self.profile.limits;
        withdrawal::matured(limits, &self.withdrawals, self.native_height.saturating_add(1), limits.large_claim_sat)
            .copied()
    }
    /// Whether a claim of `sats` must carry the attestors' co-signature.
    pub fn attestation_required(&self, sats: u64) -> bool {
        self.policy.attestor_set != [0; 32] && sats >= self.profile.limits.large_claim_sat
    }
    /// Replace the program at the compiled gate. The state keeps its head, inbox,
    /// claims and window, and `source_at` binds only identities 0 to 2, so the
    /// frozen source survives. A statement of the old program gets
    /// [`Reject::Policy`] from here on and must be proved again. Acts only on the
    /// exact policy the activation pinned, so it runs once and on no other L2.
    /// Blocks before the gate replay unchanged, because nothing here runs for them.
    pub(crate) fn install_next_program(&mut self) {
        let Some(pinned) = mainnet::PROGRAM else { return };
        // Identities 0 and 1 name the network, so a private rehearsal of the
        // mainnet program holds other values there (`rehearsal_activation`).
        if self.policy.identities[2..] == pinned.identities[2..] && self.policy.proof_policy == pinned.proof_policy {
            self.replace_program(&mainnet::PROGRAM_NEXT);
            if let Some(reset) = mainnet::HEAD_RESET.as_ref() {
                self.reset_head(reset);
            }
        }
    }
    /// Roll the program back at the compiled gate: from [`mainnet::PROGRAM_NEXT`]
    /// to [`mainnet::PROGRAM_FALLBACK`], which proves the same rules. Head, inbox,
    /// frozen source, claims and window stay, and a proof of the replaced guest
    /// gets [`Reject::Policy`], as at the swap. Acts only on the exact policy the
    /// swap installed, so it runs once, after the swap, and on no other L2.
    pub(crate) fn install_fallback_program(&mut self) {
        self.install_fallback_with(mainnet::ROLLBACK_HEAD_RESET.as_ref());
    }
    /// A refused `reset` leaves the head where it is. The program still moves:
    /// the guest is replaced because it misbehaved, whatever the head can do.
    fn install_fallback_with(&mut self, reset: Option<&mainnet::HeadReset>) {
        let Some(pinned) = mainnet::PROGRAM else { return };
        if self.policy.identities[2] == pinned.identities[2]
            && self.policy.identities[3..7] == mainnet::PROGRAM_NEXT.identities
            && self.policy.proof_policy == mainnet::PROGRAM_NEXT.proof_policy
        {
            self.replace_program(&mainnet::PROGRAM_FALLBACK);
            if let Some(reset) = reset {
                self.reset_head(reset);
            }
        }
    }
    /// The program changes this L2 will see, in order, as `(epoch, program)`.
    /// Empty while the gates are inert and on any other L2. A settler reads it to
    /// stop starting proofs that cannot land before the gate. Not a consensus input.
    pub fn program_schedule(&self) -> Vec<(u64, mainnet::NextProgram)> {
        self.program_schedule_from(crate::params::L2_NEXT_PROGRAM_EPOCH, crate::params::L2_PROGRAM_ROLLBACK_EPOCH)
    }
    fn program_schedule_from(&self, next: u64, rollback: u64) -> Vec<(u64, mainnet::NextProgram)> {
        let Some(pinned) = mainnet::PROGRAM else { return Vec::new() };
        if self.policy.identities[2] != pinned.identities[2] || self.policy.proof_policy != pinned.proof_policy {
            return Vec::new();
        }
        let activated = self.policy.identities[3..7] == pinned.identities[3..7];
        let swapped = self.policy.identities[3..7] == mainnet::PROGRAM_NEXT.identities;
        let mut schedule = Vec::new();
        if activated && next != u64::MAX {
            schedule.push((next, mainnet::PROGRAM_NEXT));
        }
        if (activated || swapped) && rollback != u64::MAX {
            schedule.push((rollback, mainnet::PROGRAM_FALLBACK));
        }
        schedule
    }
    /// Whether `tx` proves another program than the one this L2 holds. It can
    /// never settle here. No proof is checked, so this costs next to nothing.
    pub fn names_another_program(&self, tx: &Transaction) -> bool {
        tx.proof_policy != self.policy.proof_policy
            || tx.statement.len() < S + 7 * 32
            || (3..7).any(|i| h(&tx.statement, S + i * 32) != self.policy.identities[i])
    }
    /// Move the settled head back to `reset`: the inbox cursor returns to what
    /// that block had consumed, so its deposits mint again on the new chain, and
    /// withdrawal roots of later blocks are forgotten. Escrow, deposits, claims
    /// and the release window stay. The target's own withdrawal root stays
    /// claimable: if retention already pruned its record (a reset days after the
    /// tail, whose newer records displaced it), it is recorded again at the
    /// current height, so honest leaves wait one delay and do not wait for the
    /// next settlement. Returns whether it applied.
    ///
    /// It does nothing when the head is not above the target, when the
    /// statement is malformed, or when its withdrawal tree contradicts the
    /// retained records or the head's tree. When a leaf the target did not publish was already
    /// paid, the rollback would credit on L2 what already left the escrow: a
    /// plain reset then does nothing, and a FORFEIT reset applies and forgets
    /// those claims ([`mainnet::HeadReset::forfeit`]).
    pub(crate) fn reset_head(&mut self, reset: &mainnet::HeadReset) -> bool {
        if self.settled_number() <= reset.number {
            return false;
        }
        let (head, consumed) = match reset.statement {
            None if reset.number == 0 => (None, 0),
            Some(text) => {
                let Some(statement) = mainnet::unhex(text.trim()) else { return false };
                if StatementVersion::of(&statement) != Some(StatementVersion::V3)
                    || n(&statement, S + 264) != reset.number
                    || (0..3).any(|i| h(&statement, S + i * 32) != self.policy.identities[i])
                {
                    return false;
                }
                let consumed = n(&statement, S + 528);
                (Some((reset.commitment, statement)), consumed)
            }
            None => return false,
        };
        let (root, count) = withdrawal::tree_after(head.as_ref().map(|(_, s): &([u8; 32], Vec<u8>)| s.as_slice()));
        // The target's tree is recorded again below, so it must not contradict
        // what L1 accepted: the tail only extends it, and a retained record at or
        // below the target never has more leaves, nor another root at the same count.
        if count > self.withdrawal_head().1
            || self.withdrawals.iter().any(|r| r.l2_number <= reset.number && (r.count > count || (r.count == count && r.root != root)))
        {
            return false;
        }
        let paid_beyond = self.claimed.any_at_or_above(count);
        if (paid_beyond && !reset.forfeit) || consumed > self.inbox.len() as u64 {
            return false;
        }
        // Forced records consumed after the target go back into the queue, as
        // the deposit cursor goes back; a reset the consumed log cannot cover
        // is refused, so that no forced transaction is silently dropped.
        if self.forced.as_ref().is_some_and(|q| !q.covers_reset_to(reset.number)) {
            return false;
        }
        if let Some(queue) = self.forced.as_mut() {
            queue.requeue_after(reset.number);
        }
        self.head = head;
        self.consumed = consumed;
        self.withdrawals.retain(|r| r.l2_number <= reset.number);
        // Records are added only when the count grows, so the target's tree is
        // the newest retained record exactly when retention did not prune it.
        if count > 0 && self.withdrawals.last().map(|r| (r.root, r.count)) != Some((root, count)) {
            self.withdrawals.push(withdrawal::Record { l2_number: reset.number, root, count, height: self.native_height });
        }
        if paid_beyond {
            self.claimed.forget_at_or_above(count);
        }
        true
    }
    fn replace_program(&mut self, next: &mainnet::NextProgram) {
        self.policy.identities[3..7].copy_from_slice(&next.identities);
        self.policy.proof_policy = next.proof_policy;
    }
    /// Test hook: the rollback with a reset other than the compiled one.
    #[cfg(test)]
    pub(crate) fn install_fallback_with_for_test(&mut self, reset: &mainnet::HeadReset) {
        self.install_fallback_with(Some(reset));
    }
    /// Test hook: the schedule under gates other than the compiled ones.
    #[cfg(test)]
    pub(crate) fn program_schedule_for_test(&self, next: u64, rollback: u64) -> Vec<(u64, mainnet::NextProgram)> {
        self.program_schedule_from(next, rollback)
    }
    /// Test hook: mark a leaf as claimed without a claim.
    #[cfg(test)]
    pub(crate) fn claimed_insert_for_test(&mut self, index: u64) {
        self.claimed.insert(index);
    }
    /// Test hook: release `sats` of escrow without a claim (conservation kept).
    #[cfg(test)]
    pub(crate) fn released_for_test(&mut self, sats: u64) {
        self.escrow_sat -= u128::from(sats);
        self.released_sat += u128::from(sats);
    }
    /// Test hook: install an accepted head without a settlement.
    #[cfg(test)]
    pub(crate) fn set_head_for_test(&mut self, digest: [u8; 32], statement: Vec<u8>, consumed: u64) {
        self.head = Some((digest, statement));
        self.consumed = consumed;
    }
    /// Test hook: move any L2 to `next`, for settlement checks across the swap.
    #[cfg(test)]
    pub(crate) fn replace_program_for_test(&mut self, next: &mainnet::NextProgram) {
        self.replace_program(next);
    }
    /// Whether the next rules hold, and with them the next release rule. It
    /// follows from the committed configuration, so it adds no state bytes and
    /// survives a rollback, which changes the guest and not the rules (the
    /// fallback's configuration is the next one, or the next one without forced
    /// inclusion).
    pub fn next_program_active(&self) -> bool {
        self.policy.identities[3] == mainnet::PROGRAM_NEXT.identities[0]
            || self.policy.identities[3] == mainnet::PROGRAM_FALLBACK.identities[0]
    }
    /// The release window a claim in the next native block sees.
    pub fn release_window(&self) -> withdrawal::ReleaseWindow {
        self.release_window.at(&self.profile.limits, self.native_height.saturating_add(1), self.escrow_sat)
    }
    /// Record `root` as this chain's checkpoint of `epoch` (the epoch the
    /// boundary opens), with `finalized_epoch` the finalized checkpoint after
    /// the boundary's tally. FFG finalizes only the epoch before the one it
    /// closes, so besides the finalized epoch's root (claims read it while
    /// finality stalls) only the three newest entries can ever be read: at
    /// most four are kept, whatever the stall.
    pub(crate) fn record_checkpoint_root(&mut self, epoch: u64, root: [u8; 32], finalized_epoch: u64) {
        self.checkpoint_roots.insert(epoch, root);
        self.checkpoint_roots.retain(|e, _| *e == finalized_epoch || e.saturating_add(2) >= epoch);
    }
    /// This chain's own checkpoint root of `epoch`, if recorded (see
    /// `params::HF1_CLAIM_FINALITY_EPOCH`).
    pub fn checkpoint_root(&self, epoch: u64) -> Option<[u8; 32]> {
        self.checkpoint_roots.get(&epoch).copied()
    }
    /// The recorded own-chain checkpoint roots, oldest first.
    pub fn checkpoint_roots(&self) -> &std::collections::BTreeMap<u64, [u8; 32]> {
        &self.checkpoint_roots
    }
    /// Local-cache restore only; the state root check that follows the
    /// restore authenticates what is put back.
    #[cfg(feature = "local-state-cache")]
    pub(crate) fn restore_checkpoint_roots(&mut self, roots: std::collections::BTreeMap<u64, [u8; 32]>) {
        self.checkpoint_roots = roots;
    }
    /// Local-cache restore only, like [`Self::restore_checkpoint_roots`].
    #[cfg(feature = "local-state-cache")]
    pub(crate) fn restore_forced_queue(&mut self, queue: forced::Queue) {
        self.forced = Some(queue);
    }
    /// Leaves `0..matured_count` are claimable in the next native block.
    pub fn matured_count(&self) -> u64 {
        self.matured_withdrawals().map_or(0, |r| r.count)
    }
    /// Claimed leaves (the nullifier set).
    pub fn claimed(&self) -> &withdrawal::ClaimBitmap {
        &self.claimed
    }
    /// Satoshis released from escrow by claims.
    pub fn released_sat(&self) -> u128 {
        self.released_sat
    }
    /// Satoshis ever escrowed by deposits (the inbox is never pruned).
    pub fn deposited_sat(&self) -> u128 {
        self.inbox.iter().map(|r| u128::from(r.sats)).sum()
    }
    /// The bridge conservation invariant: escrow equals deposits minus claims.
    pub fn escrow_conserved(&self) -> bool {
        self.deposited_sat().checked_sub(self.released_sat) == Some(self.escrow_sat)
    }
    /// Whether a claim may exceed the release window's cap as the window's
    /// first: `attested` (it carries an attestation of the policy's set; the
    /// caller verifies the signatures) or the policy has no attestors.
    pub fn window_exempt(&self, attested: bool) -> bool {
        attested || self.policy.attestor_set == [0; 32]
    }
    /// Check a claim of withdrawal `index` for the next native block without
    /// mutating state (mempool preflight, RPC, tooling).
    pub fn check_claim(
        &self,
        chain_id: u64,
        index: u64,
        l1_recipient: &[u8; 32],
        sats: u64,
        siblings: &[[u8; 32]; withdrawal::TREE_DEPTH],
        attested: bool,
    ) -> Result<withdrawal::Record, withdrawal::ClaimRefusal> {
        use withdrawal::ClaimRefusal as R;
        if !self.profile.user_transactions || !self.asynchronous {
            return Err(R::NotActive);
        }
        if chain_id != self.policy.chain_id {
            return Err(R::Chain);
        }
        let at = self.native_height.checked_add(1).ok_or(R::NotActive)?;
        let record = *withdrawal::matured_proof(&self.profile.limits, &self.withdrawals, at, chain_id, index, l1_recipient, sats, siblings)?;
        if self.claimed.contains(index) {
            return Err(R::Claimed);
        }
        if self.escrow_sat < u128::from(sats) {
            return Err(R::Escrow);
        }
        let window = self.release_window();
        let exempt = self.window_exempt(attested);
        let admitted = if self.next_program_active() { window.admits(sats, exempt) } else { window.admits_v1(sats, exempt) };
        if !admitted {
            return Err(R::RateLimited);
        }
        Ok(record)
    }
    /// Release `sats` of escrow for withdrawal `index` (M5). The caller
    /// creates exactly that output for `l1_recipient` after this succeeds;
    /// on error nothing changed.
    pub(crate) fn release_withdrawal(
        &mut self,
        chain_id: u64,
        index: u64,
        l1_recipient: &[u8; 32],
        sats: u64,
        siblings: &[[u8; 32]; withdrawal::TREE_DEPTH],
        attested: bool,
    ) -> Result<(), withdrawal::ClaimRefusal> {
        self.check_claim(chain_id, index, l1_recipient, sats, siblings, attested)?;
        let released = self.released_sat.checked_add(u128::from(sats)).ok_or(withdrawal::ClaimRefusal::Escrow)?;
        let mut window = self.release_window();
        window.released = window.released.saturating_add(u128::from(sats));
        // No fallible step below: nullifier, escrow, total and window move together.
        let fresh = self.claimed.insert(index);
        debug_assert!(fresh);
        self.escrow_sat -= u128::from(sats);
        self.released_sat = released;
        self.release_window = window;
        Ok(())
    }
    /// `(root, count)` of the withdrawal tree after the accepted head: the
    /// empty tree before any V3 settlement (and after a V2 head).
    pub fn withdrawal_head(&self) -> ([u8; 32], u64) {
        withdrawal::tree_after(self.head.as_ref().map(|(_, s)| s.as_slice()))
    }
    /// Number of the last settled L2 block (0 before the first settlement).
    pub fn settled_number(&self) -> u64 {
        self.head.as_ref().map_or(0, |(_, s)| n(s, S + 264))
    }
    /// Record an L1-published batch for an unsettled L2 block of this chain.
    /// The caller has already charged and authorized the DA transaction.
    pub(crate) fn record_data_availability(
        &mut self,
        chain_id: u64,
        l2_number: u64,
        commitment: [u8; 32],
    ) -> Result<(), da::Refusal> {
        use da::Refusal as R;
        if !self.profile.user_transactions {
            return Err(R::NotActive);
        }
        if chain_id != self.policy.chain_id {
            return Err(R::Chain);
        }
        let settled = self.settled_number();
        if l2_number <= settled || l2_number > settled.saturating_add(da::WINDOW) {
            return Err(R::Number);
        }
        if self.da.iter().any(|r| r.l2_number == l2_number && r.commitment == commitment) {
            return Err(R::Duplicate);
        }
        if self.da.len() >= da::MAX_RECORDS {
            return Err(R::Full);
        }
        let height = self.native_height.checked_add(1).ok_or(R::Full)?;
        self.da.push(da::Record { l2_number, commitment, height });
        Ok(())
    }
    /// Test hook: configure the attestor set after genesis.
    #[cfg(test)]
    pub(crate) fn set_attestor_set(&mut self, set: [u8; 32]) {
        self.policy.attestor_set = set;
    }
    /// Test hook: install a withdrawal record without a settlement.
    #[cfg(test)]
    pub(crate) fn insert_withdrawal_record(&mut self, record: withdrawal::Record) {
        self.withdrawals.push(record);
    }
    /// Test hook: install a DA record without a funded DA transaction.
    #[cfg(test)]
    pub(crate) fn insert_da_record(&mut self, record: da::Record) {
        self.da.push(record);
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn height(&self) -> u64 {
        self.native_height
    }
    pub fn head(&self) -> Option<([u8; 32], Vec<u8>)> {
        self.head.clone()
    }
    pub fn source(&self, block: [u8; 32], slot: u64) -> Source {
        self.frozen_source().unwrap_or_else(|| {
            self.source_at(block, slot, self.native_height, self.inbox.len() as u64, self.inbox_root)
        })
    }
    fn source_at(&self, block: [u8; 32], slot: u64, height: u64, inbox_count: u64, inbox_root: [u8; 32]) -> Source {
        let previous = self.head.as_ref().map(|(_, s)| h(s, S + 448)).unwrap_or([0; 32]);
        let commitment = hash(&[
            b"BLOCH:NATIVE:L2:EMPTY-SOURCE:1",
            &self.policy.identities[0],
            &self.policy.identities[1],
            &self.policy.identities[2],
            &previous,
            &block,
            &slot.to_le_bytes(),
            &height.to_le_bytes(),
            &inbox_root,
        ]);
        Source {
            block,
            slot,
            height,
            commitment,
            inbox_root,
            inbox_count,
        }
    }
    pub(crate) fn advance_height(&mut self) -> Result<(), Reject> {
        self.native_height = self.native_height.checked_add(1).ok_or(Reject::Height)?;
        // Expire DA records: one included at height x serves settlements in
        // native blocks x+1 ..= x+RETENTION_BLOCKS.
        let height = self.native_height;
        self.da.retain(|r| r.height.saturating_add(da::RETENTION_BLOCKS) > height);
        // Withdrawal roots: keep every record younger than the retention
        // window and the newest older one (records are in height order).
        let retention = self.profile.limits.retention_blocks;
        let old = self.withdrawals.iter().take_while(|r| r.height.saturating_add(retention) <= height).count();
        if old > 1 {
            self.withdrawals.drain(..old - 1);
        }
        Ok(())
    }
    pub fn committed_bytes(&self) -> Vec<u8> {
        let mut out = if self.asynchronous {
            b"BLOCH:NATIVE:L2:STATE:2".to_vec()
        } else {
            b"BLOCH:NATIVE:L2:STATE:1".to_vec()
        };
        self.policy.encode(&mut out);
        // Absent for development profiles, so their states keep their bytes.
        self.profile.encode(&mut out);
        out.extend_from_slice(&self.native_height.to_le_bytes());
        if self.asynchronous {
            match self.source_anchor {
                None => out.push(0),
                Some((block, slot, height, _, _)) => {
                    out.push(1);
                    out.extend_from_slice(&block);
                    out.extend_from_slice(&slot.to_le_bytes());
                    out.extend_from_slice(&height.to_le_bytes());
                }
            }
        }
        match &self.head {
            None => out.push(0),
            Some((digest, statement)) => {
                // The statement's own tag fixes its length (590 or 766).
                out.push(1);
                out.extend_from_slice(digest);
                out.extend_from_slice(statement);
            }
        }
        // Absent until the first deposit, so empty-inbox states keep their bytes.
        if !self.inbox.is_empty() {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:INBOX-STATE:1");
            out.extend_from_slice(&(self.inbox.len() as u64).to_le_bytes());
            out.extend_from_slice(&self.inbox_root);
            out.extend_from_slice(&self.consumed.to_le_bytes());
            out.extend_from_slice(&self.escrow_sat.to_le_bytes());
            if let Some((_, _, _, count, root)) = self.source_anchor {
                out.extend_from_slice(&count.to_le_bytes());
                out.extend_from_slice(&root);
            }
        }
        // Absent while empty, so states without withdrawals keep their bytes.
        if !self.withdrawals.is_empty() {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:WITHDRAWAL-STATE:1");
            out.extend_from_slice(&(self.withdrawals.len() as u64).to_le_bytes());
            for r in &self.withdrawals {
                out.extend_from_slice(&r.l2_number.to_le_bytes());
                out.extend_from_slice(&r.root);
                out.extend_from_slice(&r.count.to_le_bytes());
                out.extend_from_slice(&r.height.to_le_bytes());
            }
        }
        // Absent until the first claim, so states without claims keep their bytes.
        // A forfeit reset can forget every claim while releases stay, so the
        // section also stays while anything was released (before a forfeit the
        // two conditions are the same: every release is a claim).
        if self.claimed.claims() != 0 || self.released_sat != 0 {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:CLAIM-STATE:1");
            out.extend_from_slice(&self.released_sat.to_le_bytes());
            self.claimed.encode(&mut out);
            out.extend_from_slice(&self.release_window.window.to_le_bytes());
            out.extend_from_slice(&self.release_window.released.to_le_bytes());
            out.extend_from_slice(&self.release_window.cap.to_le_bytes());
        }
        // Absent while empty, so states without DA keep their bytes.
        if !self.da.is_empty() {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:DA-STATE:1");
            out.extend_from_slice(&(self.da.len() as u64).to_le_bytes());
            for r in &self.da {
                out.extend_from_slice(&r.l2_number.to_le_bytes());
                out.extend_from_slice(&r.commitment);
                out.extend_from_slice(&r.height.to_le_bytes());
            }
        }
        // Absent while empty: nothing is recorded below
        // HF1_CLAIM_FINALITY_EPOCH, so earlier states keep
        // their bytes.
        if !self.checkpoint_roots.is_empty() {
            out.extend_from_slice(b"BLOCH:NATIVE:L2:CHECKPOINT-ROOTS:1");
            out.extend_from_slice(&(self.checkpoint_roots.len() as u64).to_le_bytes());
            for (epoch, root) in &self.checkpoint_roots {
                out.extend_from_slice(&epoch.to_le_bytes());
                out.extend_from_slice(root);
            }
        }
        // Absent until forced inclusion is enabled, so every state below
        // L2_FORCED_INCLUSION_EPOCH keeps its bytes.
        if let Some(queue) = &self.forced {
            queue.encode(&mut out);
        }
        out
    }
    /// Only the transition can supply the native parent. No expected statement
    /// or accepted-shaped head is accepted from a proposer or local RPC.
    pub(crate) fn apply(
        &mut self,
        tx: &Transaction,
        parent: [u8; 32],
        slot: u64,
        asynchronous: bool,
        verifier: &dyn crate::attestation::SignatureVerifier,
    ) -> Result<(), Reject> {
        if asynchronous != self.asynchronous || (asynchronous && self.source_anchor.is_none()) {
            return Err(Reject::NotActive);
        }
        let s = tx.statement.as_slice();
        // The version is the statement tag. Which version a network accepts is
        // pinned by its proof policy: the policy-bound verifier admits only
        // public values of its own version (`bloch_l2_proof::verify`).
        let Some(version) = StatementVersion::of(s) else {
            return Err(Reject::Policy);
        };
        if tx.proof_policy != self.policy.proof_policy
            || (0..7).any(|i| h(s, S + i * 32) != self.policy.identities[i])
            || n(s, S + 256) != self.policy.chain_id
        {
            return Err(Reject::Policy);
        }
        let source = self.source(parent, slot);
        // BE field offsets follow the fixed V2 codec; the conformance tests
        // compare this independent native parser to the L2 implementation.
        if source.height == 0
            || source.slot < source.height
            || h(s, S + 400) != source.block
            || n(s, S + 432) != source.slot
            || n(s, S + 440) != source.height
            || h(s, S + 448) != source.commitment
            || h(s, S + 480) != source.inbox_root
        {
            return Err(Reject::Source);
        }
        // Deterministic consumption: everything pending at the anchor, capped.
        let end = source.inbox_count.min(self.consumed.saturating_add(MAX_INBOX_PER_SETTLEMENT));
        if n(s, S + 512) != source.inbox_count || n(s, S + 520) != self.consumed || n(s, S + 528) != end {
            return Err(Reject::Source);
        }
        let (previous, number, parent, root) = match &self.head {
            None => (
                [0; 32],
                1,
                self.policy.initial_l2_parent,
                self.policy.initial_l2_state,
            ),
            // Shared V2/V3 prefix offsets: a V3 head may follow a V2 head.
            Some((digest, old)) => (
                *digest,
                n(old, S + 264).checked_add(1).ok_or(Reject::Successor)?,
                h(old, S + 336),
                h(old, S + 368),
            ),
        };
        if h(s, S + 224) != previous
            || n(s, S + 264) != number
            || h(s, S + 272) != parent
            || h(s, S + 304) != root
            || h(s, S + 336) == [0; 32]
            || h(s, S + 368) == [0; 32]
            || h(s, S + 536) == [0; 32]
        {
            return Err(Reject::Successor);
        }
        // The proof binds the body; consensus binds the body to the inbox.
        let consumed = &self.inbox[self.consumed as usize..end as usize];
        let mut new_withdrawals = None;
        match version {
            // V2 history: the body must be exactly the deposits, no user txs.
            StatementVersion::V2 => {
                if self.profile.deposits && h(s, S + 536) != expected_body_commitment(consumed) {
                    return Err(Reject::Deposits);
                }
                if self.forced.as_ref().is_some_and(|q| !q.due().is_empty()) {
                    return Err(Reject::Forced);
                }
            }
            // V3: user transactions allowed; the minted deposits must be
            // exactly the consumed inbox records, in order.
            StatementVersion::V3 => {
                let users = n(s, S + v3::USER_TX_COUNT);
                if users != 0 && !self.profile.user_transactions {
                    return Err(Reject::UserTransactions);
                }
                // Under forced inclusion the slot also binds the forced records
                // due at the anchor; with none due it is the deposits hash.
                let due = self.forced.as_ref().map_or(&[][..], |q| q.due());
                if h(s, S + v3::DEPOSITS_HASH) != forced::inbox_hash(deposits_hash(consumed), due) {
                    return Err(if due.is_empty() { Reject::Deposits } else { Reject::Forced });
                }
                let da_commitment = h(s, S + v3::DA_COMMITMENT);
                if h(s, S + v3::TRANSACTIONS_ROOT) == [0; 32]
                    || h(s, S + v3::RECEIPTS_ROOT) == [0; 32]
                    || (users == 0 && da_commitment != [0; 32])
                {
                    return Err(Reject::Reserved);
                }
                // The withdrawal tree only grows, and its root moves exactly
                // when leaves are added.
                let head = self.head.as_ref().map(|(_, old)| old.as_slice());
                if let Some((root, count)) = withdrawal::check_successor(head, s)? {
                    new_withdrawals = Some(withdrawal::Record {
                        l2_number: number,
                        root,
                        count,
                        height: self.native_height.checked_add(1).ok_or(Reject::Height)?,
                    });
                }
                // User transactions settle only after their batch is on L1:
                // a retained record for this exact block, from an earlier
                // native block (a settlement reserves its whole block's gas,
                // so the rule never depends on in-block ordering).
                if users != 0
                    && !self.da.iter().any(|r| {
                        r.l2_number == number && r.commitment == da_commitment && r.height <= self.native_height
                    })
                {
                    return Err(Reject::DataUnavailable);
                }
            }
        }
        if !verifier.verify_l2_settlement(
            &self.policy.proof_policy,
            &self.policy.identities[6],
            s,
            &tx.proof,
        ) {
            return Err(Reject::Proof);
        }
        if let Some(record) = new_withdrawals {
            if self.withdrawals.len() >= self.profile.limits.max_records() {
                return Err(Reject::Limit);
            }
            self.withdrawals.push(record);
        }
        self.head = Some((tx.commitment(), s.to_vec()));
        self.source_anchor = None;
        self.consumed = end;
        if let Some(queue) = self.forced.as_mut() {
            queue.consume_due(number);
        }
        // Records for settled blocks can never be used again.
        self.da.retain(|r| r.l2_number > number);
        Ok(())
    }

    /// Mempool preflight shares the transition checks and never mutates state.
    pub fn validate_async(&self, tx: &Transaction, verifier: &dyn crate::attestation::SignatureVerifier) -> Result<(), Reject> {
        self.clone().apply(tx, [0; 32], 0, true, verifier)
    }
}

/// Local restart cache support (`transition::local_cache`). Not a consensus
/// or state-sync format: the node binds the cache to its own build, manifest
/// and block log, and the restore recomputes the state root.
#[cfg(feature = "local-state-cache")]
impl State {
    /// Recheck what the committed bytes summarise but do not contain, and
    /// take a development profile from this build exactly as a replay would
    /// (cargo features are not part of the cache's build binding).
    pub(crate) fn from_local_cache(mut self) -> Result<Self, String> {
        if !self.profile.activated {
            self.profile = Profile::development();
        }
        let mut root = empty_inbox_root();
        let mut deposited = 0u128;
        for record in &self.inbox {
            root = hash(&[b"BLOCH:NATIVE:L2:INBOX:1", &root, &record.encode()]);
            deposited = deposited.checked_add(u128::from(record.sats))
                .ok_or("cached L2 inbox overflows")?;
        }
        if root != self.inbox_root {
            return Err("cached L2 inbox does not match its root".into());
        }
        if self.consumed > self.inbox.len() as u64 {
            return Err("cached L2 inbox cursor is past the inbox".into());
        }
        if let Some(q) = &self.forced {
            let pending = q.pending.len() as u64;
            if q.queued.checked_sub(q.consumed) != Some(pending)
                // A head reset can queue consumed records again past the
                // submission capacity: bounded by the consumed log. Every
                // record weighs at least one unit, so at most this many are
                // pending, and each group (at least one record) counts at most
                // its records' weight or a settlement's units.
                || pending > forced::MAX_PENDING_WEIGHT + forced::CONSUMED_LOG as u64
                || q.pending_weight() > pending * forced::UNITS_PER_SETTLEMENT
                || q.log.len() > forced::CONSUMED_LOG
                || q.log.windows(2).any(|w| w[0].0 > w[1].0)
                || q.log.first().is_some_and(|(n, _)| *n < q.log_floor)
                || q.anchor.is_some_and(|a| a > pending)
            {
                return Err("cached L2 forced queue is inconsistent".into());
            }
        }
        if deposited.checked_sub(self.released_sat) != Some(self.escrow_sat) {
            return Err("cached L2 escrow does not match deposits and releases".into());
        }
        let stored: u64 = self.claimed.words().map(|(_, bits)| {
            bits.iter().map(|b| u64::from(b.count_ones())).sum::<u64>()
        }).sum();
        let full = self.claimed.floor().checked_mul(256).ok_or("cached L2 claim floor overflows")?;
        if self.claimed.words().any(|(word, _)| word < self.claimed.floor())
            || full.checked_add(stored) != Some(self.claimed.claims())
        {
            return Err("cached L2 claim set is inconsistent".into());
        }
        Ok(self)
    }
}

#[cfg(test)]
mod inbox_tests {
    use super::*;

    #[test]
    fn empty_body_commitment_matches_the_proven_l2_body() {
        // body_commitment of every real devnet settlement proof (empty body).
        let proven = "631fadc856db46e03e0a80f48f053f496c57548c0b1a2fba6701432a2299d420";
        let ours: String = expected_body_commitment(&[]).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(ours, proven);
    }

    #[test]
    fn empty_inbox_root_is_unchanged_and_appends_chain() {
        assert_eq!(empty_inbox_root(), hash(&[b"BLOCH:NATIVE:L2:EMPTY-INBOX:1"]));
        let record = InboxRecord { height: 7, tx_index: 0, txid: [1; 32], vout: 1, sats: 5_000, recipient: [2; 20] };
        assert_ne!(expected_body_commitment(&[record]), expected_body_commitment(&[]));
        let mut other = record;
        other.sats += 1;
        assert_ne!(expected_body_commitment(&[record]), expected_body_commitment(&[other]));
    }

    /// Shared with bloch-l2-evm `deposits_hash_cross_repository_golden_vector`.
    #[test]
    fn deposits_hash_matches_the_l2_golden_vector() {
        let record = InboxRecord { height: 7, tx_index: 3, txid: [0x11; 32], vout: 1, sats: 5_000, recipient: [0x42; 20] };
        let ours: String = deposits_hash(&[record]).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(ours, "0cbc6acc037c5bd96bf847b916a584239e9fa7c22afbf1a37703f4b13afbcfd3");
        let empty: [u8; 32] = Keccak256::digest([]).into();
        assert_eq!(deposits_hash(&[]), empty);
    }

    /// Rebuilds bloch-l2-evm's `settlement_v3_golden_vector` bytes from THIS
    /// crate's offsets: a layout drift on either side breaks the digest.
    #[test]
    fn v3_offsets_match_the_l2_golden_vector() {
        let mut s = vec![0u8; STATEMENT_V3_BYTES];
        s[..S].copy_from_slice(STATEMENT_V3_TAG);
        let mut put_hash = |offset: usize, byte: u8| s[S + offset..S + offset + 32].fill(byte);
        for (i, offset) in [0, 32, 64, 96, 128, 160, 192, 224].into_iter().enumerate() {
            put_hash(offset, i as u8 + 1);
        }
        for (offset, byte) in [(272, 0x09), (304, 0x0a), (336, 0x0b), (368, 0x0c), (400, 0x0d), (448, 0x0e),
            (480, 0x0f), (536, 0x10), (v3::DEPOSITS_HASH, 0x11), (v3::TRANSACTIONS_ROOT, 0x12),
            (v3::RECEIPTS_ROOT, 0x13), (v3::WITHDRAWAL_ROOT, 0x14), (v3::DA_COMMITMENT, 0x15)] {
            put_hash(offset, byte);
        }
        let mut put_u64 = |offset: usize, hi: u8| {
            for k in 0..8 {
                s[S + offset + k] = hi + 1 + k as u8;
            }
        };
        for (offset, hi) in [(256, 0x00), (264, 0x10), (432, 0x20), (440, 0x30), (512, 0x40), (520, 0x50),
            (528, 0x60), (v3::USER_TX_COUNT, 0x70), (v3::WITHDRAWAL_COUNT, 0x80)] {
            put_u64(offset, hi);
        }
        let digest: String = Keccak256::digest(&s).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digest, "66469230128b9e871eb65c938c300ce51b4e42136468145f7e54c211ade696d4");
        assert_eq!(StatementVersion::of(&s), Some(StatementVersion::V3));
        assert_eq!(StatementVersion::of(&s[..STATEMENT_BYTES]), None);
    }

    /// The local restart cache rechecks what the state root summarises (the
    /// inbox records behind its root, escrow conservation, the claim count)
    /// and takes a development profile from the running build.
    #[test]
    #[cfg(feature = "local-state-cache")]
    fn local_cache_restore_rechecks_uncommitted_invariants() {
        let policy = Policy {
            identities: [[7; 32]; 7],
            proof_policy: [8; 32],
            chain_id: 700771,
            initial_l2_parent: [9; 32],
            initial_l2_state: [10; 32],
            attestor_set: [0; 32],
        };
        let mut good = State::genesis_async(policy).unwrap();
        good.native_height = 3;
        good.append_deposit(InboxRecord { height: 2, tx_index: 0, txid: [1; 32], vout: 0, sats: 9_000, recipient: [2; 20] }).unwrap();
        good.append_deposit(InboxRecord { height: 3, tx_index: 0, txid: [3; 32], vout: 1, sats: 1_000, recipient: [4; 20] }).unwrap();
        assert!(good.claimed.insert(0) && good.claimed.insert(5));
        good.escrow_sat -= 600;
        good.released_sat = 600;
        assert_eq!(good.clone().from_local_cache(), Ok(good.clone()));

        // A development profile is the build's, whatever the cache carried.
        let mut foreign = good.clone();
        foreign.profile.deposits = !foreign.profile.deposits;
        foreign.profile.limits.delay_blocks += 1;
        assert_eq!(foreign.from_local_cache().unwrap().profile, Profile::development());
        // An activated profile is committed and kept as cached.
        let mut activated = good.clone();
        activated.profile = Profile::activated(withdrawal::Limits::DEVELOPMENT);
        assert_eq!(activated.clone().from_local_cache(), Ok(activated));

        let mut record = good.clone();
        record.inbox[1].sats += 1;
        record.escrow_sat += 1;
        assert!(record.from_local_cache().is_err(), "inbox records must match the root");
        let mut escrow = good.clone();
        escrow.escrow_sat += 1;
        assert!(escrow.from_local_cache().is_err(), "escrow must be conserved");
        let mut cursor = good.clone();
        cursor.consumed = 3;
        assert!(cursor.from_local_cache().is_err(), "the cursor stays within the inbox");
        let mut claims = good.clone();
        let mut bitmap = serde_json::to_value(&claims.claimed).unwrap();
        bitmap["claims"] = serde_json::json!(3);
        claims.claimed = serde_json::from_value(bitmap).unwrap();
        assert!(claims.from_local_cache().is_err(), "the claim count matches the bitmap");
    }
}
