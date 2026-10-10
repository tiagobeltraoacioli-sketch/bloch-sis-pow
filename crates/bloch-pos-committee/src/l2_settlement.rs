// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native, parent-state-owned settlement validation for the L2 inbox.
//! With `devnet-l2-deposits`, native L2 deposits (escrowed BLCH) append to an
//! ordered inbox and each settlement must mint exactly the next inbox records.
//! No bridge release, withdrawals or production activation.
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
/// receipts root, user transaction count, and three M1-reserved fields.
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
        /// No L2 policy, or a build without `devnet-l2-user-txs`.
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

/// Records one settlement must consume, when pending: min(pending, this).
pub const MAX_INBOX_PER_SETTLEMENT: u64 = 64;
/// Exact L2 body framing tag (`bloch_l2_evm::node_primitives::NodeBodyV2`).
const L2_BODY_TAG: &[u8] = b"BLOCH:EVM:BODY:2";

/// One escrowed native deposit, in inbox order. Its fields are exactly the
/// L2 `DepositProvenance::BridgedBlch` plus the EVM recipient.
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

/// Immutable network configuration, installed only by a new genesis constructor.
/// The first seven hashes follow the V2 statement: native network/genesis,
/// L2 domain/configuration, guest ELF, KoalaBear key and BN254 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub identities: [[u8; 32]; 7],
    pub proof_policy: [u8; 32],
    pub chain_id: u64,
    pub initial_l2_parent: [u8; 32],
    pub initial_l2_state: [u8; 32],
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
    /// A V3 field reserved for a later milestone is not zero, or a V3 body
    /// commitment is zero.
    Reserved,
    /// A V3 statement with `user_tx_count > 0` on a build without the
    /// `devnet-l2-user-txs` feature. User transactions stay disabled outside
    /// development networks until data availability (M3) exists: the native
    /// chain stores only hashes, so a settled user transaction could not be
    /// reconstructed from L1.
    UserTransactions,
    /// A V3 statement with user transactions whose `da_commitment` matches no
    /// L1 data-availability record (same L2 block number) included in a
    /// strictly earlier native block and still retained.
    DataUnavailable,
}

/// Whether this build admits V3 settlements that executed user transactions.
/// Only development networks enable it (feature `devnet-l2-user-txs`).
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
        })
    }
    pub(crate) fn genesis_async(policy: Policy) -> Result<Self, Reject> {
        let mut state = Self::genesis(policy)?;
        state.asynchronous = true;
        Ok(state)
    }
    pub fn asynchronous(&self) -> bool { self.asynchronous }
    /// A source is pinned by a committed transition, never by a proof caller.
    pub fn frozen_source(&self) -> Option<Source> {
        self.source_anchor
            .map(|(block, slot, height, count, root)| self.source_at(block, slot, height, count, root))
    }
    pub(crate) fn prepare_source(&mut self, parent: [u8; 32], parent_slot: u64) {
        if self.asynchronous && self.source_anchor.is_none() && self.native_height > 0 {
            self.source_anchor = Some((parent, parent_slot, self.native_height, self.inbox.len() as u64, self.inbox_root));
        }
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
        if !USER_TRANSACTIONS_ENABLED {
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
        Ok(())
    }
    pub fn committed_bytes(&self) -> Vec<u8> {
        let mut out = if self.asynchronous {
            b"BLOCH:NATIVE:L2:STATE:2".to_vec()
        } else {
            b"BLOCH:NATIVE:L2:STATE:1".to_vec()
        };
        self.policy.encode(&mut out);
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
        match version {
            // V2 history: the body must be exactly the deposits, no user txs.
            StatementVersion::V2 => {
                if cfg!(feature = "devnet-l2-deposits") && h(s, S + 536) != expected_body_commitment(consumed) {
                    return Err(Reject::Deposits);
                }
            }
            // V3: user transactions allowed; the minted deposits must be
            // exactly the consumed inbox records, in order.
            StatementVersion::V3 => {
                let users = n(s, S + v3::USER_TX_COUNT);
                if users != 0 && !USER_TRANSACTIONS_ENABLED {
                    return Err(Reject::UserTransactions);
                }
                if h(s, S + v3::DEPOSITS_HASH) != deposits_hash(consumed) {
                    return Err(Reject::Deposits);
                }
                let da_commitment = h(s, S + v3::DA_COMMITMENT);
                if h(s, S + v3::TRANSACTIONS_ROOT) == [0; 32]
                    || h(s, S + v3::RECEIPTS_ROOT) == [0; 32]
                    || h(s, S + v3::WITHDRAWAL_ROOT) != [0; 32]
                    || n(s, S + v3::WITHDRAWAL_COUNT) != 0
                    || (users == 0 && da_commitment != [0; 32])
                {
                    return Err(Reject::Reserved);
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
        self.head = Some((tx.commitment(), s.to_vec()));
        self.source_anchor = None;
        self.consumed = end;
        // Records for settled blocks can never be used again.
        self.da.retain(|r| r.l2_number > number);
        Ok(())
    }

    /// Mempool preflight shares the transition checks and never mutates state.
    pub fn validate_async(&self, tx: &Transaction, verifier: &dyn crate::attestation::SignatureVerifier) -> Result<(), Reject> {
        self.clone().apply(tx, [0; 32], 0, true, verifier)
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
}
