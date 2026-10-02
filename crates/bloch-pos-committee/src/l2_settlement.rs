// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native, parent-state-owned settlement validation for an empty L2 inbox.
//! No native locks, bridge mint/release, withdrawals or production activation.
use sha3::{Digest, Sha3_256};

pub const WIRE_TAG: u8 = 0x0e;
/// Asynchronous settlement, enabled only by a new manifest-bound genesis.
pub const ASYNC_WIRE_TAG: u8 = 0x0f;
pub const STATEMENT_TAG: &[u8] = b"BLOCH:EVM:SETTLEMENT:2";
pub const STATEMENT_BYTES: usize = 590;
pub const PROOF_BYTES: usize = 356;
pub const TRANSACTION_BYTES: usize = 1 + 32 + STATEMENT_BYTES + PROOF_BYTES;
const S: usize = STATEMENT_TAG.len();

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
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    policy: Policy,
    native_height: u64,
    head: Option<([u8; 32], [u8; STATEMENT_BYTES])>,
    asynchronous: bool,
    source_anchor: Option<([u8; 32], u64, u64)>,
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
        self.source_anchor.map(|(block, slot, height)| self.source_at(block, slot, height))
    }
    pub(crate) fn prepare_source(&mut self, parent: [u8; 32], parent_slot: u64) {
        if self.asynchronous && self.source_anchor.is_none() && self.native_height > 0 {
            self.source_anchor = Some((parent, parent_slot, self.native_height));
        }
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
        self.frozen_source().unwrap_or_else(|| self.source_at(block, slot, self.native_height))
    }
    fn source_at(&self, block: [u8; 32], slot: u64, height: u64) -> Source {
        let previous = self.head.map(|(_, s)| h(&s, S + 448)).unwrap_or([0; 32]);
        let inbox_root = hash(&[b"BLOCH:NATIVE:L2:EMPTY-INBOX:1"]);
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
                Some((block, slot, height)) => {
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
            || n(s, S + 512) != 0
            || n(s, S + 520) != 0
            || n(s, S + 528) != 0
        {
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
        Ok(())
    }

    /// Mempool preflight shares the transition checks and never mutates state.
    pub fn validate_async(&self, tx: &Transaction, verifier: &dyn crate::attestation::SignatureVerifier) -> Result<(), Reject> {
        self.clone().apply(tx, [0; 32], 0, true, verifier)
    }
}
