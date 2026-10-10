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
pub const TRANSACTION_BYTES: usize = 1 + 32 + STATEMENT_BYTES + PROOF_BYTES;
const S: usize = STATEMENT_TAG.len();
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

/// One canonical native transaction. Length is fixed before allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub proof_policy: [u8; 32],
    pub statement: [u8; STATEMENT_BYTES],
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
        if bytes.len() != TRANSACTION_BYTES
            || bytes[0] != tag
            || !bytes[33..].starts_with(STATEMENT_TAG)
        {
            return None;
        }
        Some(Self {
            proof_policy: bytes[1..33].try_into().ok()?,
            statement: bytes[33..33 + STATEMENT_BYTES].try_into().ok()?,
            proof: bytes[33 + STATEMENT_BYTES..].try_into().ok()?,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        self.encode_tag(WIRE_TAG)
    }
    pub fn encode_async(&self) -> Vec<u8> {
        self.encode_tag(ASYNC_WIRE_TAG)
    }
    fn encode_tag(&self, tag: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TRANSACTION_BYTES);
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
            &self.statement,
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
    head: Option<([u8; 32], [u8; STATEMENT_BYTES])>,
    asynchronous: bool,
    /// (block, slot, height, inbox count, inbox root) frozen at the anchor.
    source_anchor: Option<([u8; 32], u64, u64, u64, [u8; 32])>,
    inbox: Vec<InboxRecord>,
    inbox_root: [u8; 32],
    consumed: u64,
    escrow_sat: u128,
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
}
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
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn height(&self) -> u64 {
        self.native_height
    }
    pub fn head(&self) -> Option<([u8; 32], [u8; STATEMENT_BYTES])> {
        self.head
    }
    pub fn source(&self, block: [u8; 32], slot: u64) -> Source {
        self.frozen_source().unwrap_or_else(|| {
            self.source_at(block, slot, self.native_height, self.inbox.len() as u64, self.inbox_root)
        })
    }
    fn source_at(&self, block: [u8; 32], slot: u64, height: u64, inbox_count: u64, inbox_root: [u8; 32]) -> Source {
        let previous = self.head.map(|(_, s)| h(&s, S + 448)).unwrap_or([0; 32]);
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
        match self.head {
            None => out.push(0),
            Some((digest, statement)) => {
                out.push(1);
                out.extend_from_slice(&digest);
                out.extend_from_slice(&statement);
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
        let s = &tx.statement;
        if !s.starts_with(STATEMENT_TAG)
            || tx.proof_policy != self.policy.proof_policy
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
        let (previous, number, parent, root) = match self.head {
            None => (
                [0; 32],
                1,
                self.policy.initial_l2_parent,
                self.policy.initial_l2_state,
            ),
            Some((digest, old)) => (
                digest,
                n(&old, S + 264).checked_add(1).ok_or(Reject::Successor)?,
                h(&old, S + 336),
                h(&old, S + 368),
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
        if cfg!(feature = "devnet-l2-deposits")
            && h(s, S + 536) != expected_body_commitment(&self.inbox[self.consumed as usize..end as usize])
        {
            return Err(Reject::Deposits);
        }
        if !verifier.verify_l2_settlement(
            &self.policy.proof_policy,
            &self.policy.identities[6],
            s,
            &tx.proof,
        ) {
            return Err(Reject::Proof);
        }
        self.head = Some((tx.commitment(), *s));
        self.source_anchor = None;
        self.consumed = end;
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
}
