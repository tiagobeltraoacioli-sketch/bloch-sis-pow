// SPDX-License-Identifier: AGPL-3.0-or-later

//! The index's rows, and the permalink scheme they are keyed by.
//!
//! ## Why the permalink scheme is a design decision and not a detail
//!
//! Whatever this index keys on becomes the explorer's URL space, and a URL
//! space is not revisable once anyone has linked to it. Genesis-4 offers four
//! candidate identifiers and exactly one of them is safe for each thing:
//!
//! | Thing | Permalink | Why |
//! |---|---|---|
//! | Block | `block_id` | `SHA3-256(DS_BLOCK ‖ 304-byte header)`. Consensus's own identity, covers the whole header, survives being orphaned. |
//! | Block, positionally | `slot`, `height` | Convenient, and **both are reorg-unstable**: the block at slot S can change. Served, and every answer says which chain it is on. |
//! | Transaction | `(block_id, tx_index)` | Unique unconditionally. See the txid caveat below. |
//! | Transaction, by identity | `txid` | `SHA3-256(DS_TXID ‖ spend_signing_root)`. Malleability-free and unique **for transfers**; NOT unique for the staking variants. |
//! | Output | `(txid, vout)` | Consensus's own eUTXO key. Nothing else names an output. |
//! | Address | `script_hash` hex | 32 bytes. Never an address string — see below. |
//!
//! ### The txid caveat, stated rather than hidden
//!
//! `PosTransaction::txid` is `SHA3-256(DS_TXID ‖ spend_signing_root)`, and
//! `spend_signing_root` covers the spend points for the two transfer variants —
//! so two distinct transfers cannot share one, because an outpoint is consumed
//! at most once and a transfer with no inputs is refused. For `Deposit`,
//! `Exit` and `Delegate` the root is over the canonical bytes alone, and those
//! carry no nonce: **two `Exit { validator: 7 }` in different blocks have the
//! same txid**. A tx permalink of `txid` alone would therefore be ambiguous for
//! staking messages, silently, and only for them.
//!
//! This index resolves that the honest way rather than the convenient one: the
//! primary key is `(block_id, tx_index)`, `txid` is a secondary index, and a
//! `txid` lookup returns **every** match rather than picking one. In practice
//! transfers are unique and the list has one element; when it does not, the
//! caller can see that it does not.
//!
//! ### Addresses are `script_hash`, and the index will not convert
//!
//! A native Genesis-4 key's `script_hash` is `SHA3-256(pubkey)` — all 32 bytes.
//! A carried Genesis-3 balance's is a 20-byte hash160 with twelve zero bytes
//! after it. `transition::owns` accepts both forms, so an output locked under
//! the wrong one is spendable and nothing rejects it: the mistake is silent.
//! Six tools in this repository once derived `SHA3-256(pubkey)[..20] ‖ 0×12`
//! because that is the shape an address prints in, and the same key showed
//! 74,999,997,782 sat under one derivation and 0 under the other.
//!
//! So this index takes `script_hash` and only `script_hash`, exactly as
//! `getbalance` does, and it does no address decoding at all. A `bloch1…`
//! string is refused with the reason. The derivation, where one is needed,
//! belongs to `bloch_pos_committee::script_hash` and nowhere else.

use std::collections::BTreeMap;

/// 32-byte SHA3-256 block identity.
pub type BlockId = [u8; 32];
/// 32-byte transaction identity (derived, never carried).
pub type Txid = [u8; 32];
/// 32-byte output locking commitment. NOT an address.
pub type ScriptHash = [u8; 32];

/// An outpoint: consensus's key for one output in the eUTXO set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

/// One unspent output as the index holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub value_sat: u64,
    pub script_hash: ScriptHash,
    /// Height of the block that created it. Genesis-carried outputs are 0.
    pub created_height: u64,
}

/// Where a block sits, and what it is.
///
/// `height` is the index's own count along the chain it applied, because the
/// header carries no height — only a slot. Genesis is height 0 and is **not in
/// `blocks.log`**; the first frame is the block at the first produced slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRow {
    pub block_id: BlockId,
    pub parent: BlockId,
    pub slot: u64,
    pub epoch: u64,
    pub height: u64,
    pub proposer_index: u32,
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
    pub justified_root: [u8; 32],
    pub finalized_root: [u8; 32],
    pub tx_count: u32,
    pub attestation_count: u32,
    /// Bytes this block occupies in the log — the payload length, which is
    /// what a peer receives for it over `get-blocks`.
    pub frame_len: u32,
    /// Sum of the values of the outputs this block created, in satoshi.
    pub outputs_created_sat: u128,
    /// Sum of the values of the outputs this block spent, in satoshi.
    pub inputs_spent_sat: u128,
    /// `inputs_spent - outputs_created`, the implicit fee across the block.
    pub fees_sat: u128,
    /// Total satoshi in the unspent set **after** this block. The quantity a
    /// supply-over-time chart plots; derived, because nothing on chain states
    /// it (see `docs/BLOCH-INDEXER.md`).
    pub eutxo_total_sat: u128,
    /// Live outputs after this block.
    pub eutxo_count: u64,
}

/// Which way value moved for one `script_hash` in one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// One line of an address's history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub height: u64,
    pub slot: u64,
    pub block_id: BlockId,
    pub txid: Txid,
    pub direction: Direction,
    pub amount_sat: u128,
}

/// What kind of transaction a body carried. Kept as a tag rather than the
/// decoded value: the index does not need a 3.7 KB hybrid key per input, and
/// the bytes are one seek away in the log when a caller does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxKind {
    Transfer,
    TransferV2,
    Deposit,
    Exit,
    Delegate,
    /// Tag `0x05`. Undecodable **by design**: the encoding folds its nested
    /// messages in through the roots they were signed over, so nothing
    /// recovers an envelope from it. Recorded as present rather than dropped.
    SlashingEvidence,
    /// A tag this build does not know. Recorded, never fatal: an index that
    /// aborts on an unknown tag stops being available exactly when a new
    /// transaction type ships.
    Unknown(u8),
}

impl TxKind {
    pub fn name(&self) -> String {
        match self {
            TxKind::Transfer => "transfer".into(),
            TxKind::TransferV2 => "transfer_v2".into(),
            TxKind::Deposit => "deposit".into(),
            TxKind::Exit => "exit".into(),
            TxKind::Delegate => "delegate".into(),
            TxKind::SlashingEvidence => "slashing_evidence".into(),
            TxKind::Unknown(t) => format!("unknown_{t:#04x}"),
        }
    }
}

/// One transaction as the index holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRow {
    pub txid: Txid,
    pub block_id: BlockId,
    pub height: u64,
    pub slot: u64,
    /// Position in the body. `(block_id, tx_index)` is the primary permalink.
    pub tx_index: u32,
    pub kind: TxKind,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<(u64, ScriptHash)>,
    pub declared_bytes: u64,
    pub tip_millisat_per_gas: u128,
    /// `inputs - outputs` for transfers; `None` when the index could not value
    /// every input (a spend of an output it never saw — which can only happen
    /// if the index was started from a truncated log).
    pub fee_sat: Option<u128>,
}

/// Per-epoch aggregate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochRow {
    pub epoch: u64,
    pub first_slot: u64,
    pub last_slot: u64,
    /// Blocks actually produced, out of `SLOTS_PER_EPOCH` opportunities.
    pub blocks: u32,
    /// Attestations included in blocks of this epoch, whatever epoch they
    /// target.
    pub attestations_included: u64,
    /// Distinct proposers that produced at least one block in this epoch.
    pub distinct_proposers: u32,
    /// The justified checkpoint the last block of this epoch pointed at.
    pub justified_root: [u8; 32],
    /// The finalized checkpoint the last block of this epoch pointed at.
    pub finalized_root: [u8; 32],
    pub eutxo_total_sat: u128,
}

/// Per-validator, per-epoch participation.
///
/// Counted by an attestation's **target epoch**, not by the slot of the block
/// that carried it: a validator that attests correctly and is included two
/// slots late participated in the epoch it voted on. Both numbers are kept so
/// the difference is visible rather than assumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Participation {
    /// Attestations by this validator whose target is this epoch.
    pub attested_target: u32,
    /// Attestations by this validator carried by blocks in this epoch.
    pub included_here: u32,
    /// Blocks this validator proposed in this epoch.
    pub proposed: u32,
}

/// Aggregates the index maintains keyed by epoch.
pub type EpochTable = BTreeMap<u64, EpochRow>;
