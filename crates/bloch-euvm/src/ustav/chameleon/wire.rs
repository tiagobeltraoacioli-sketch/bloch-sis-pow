//! Chameleon v1 wire commitments shared with the Ethereum adapter.
//! Fixed-width ABI words, SHA-256, and ordered, typed Merkle nodes. No ECDSA.

use sha2::{Digest, Sha256};

pub const TREE_DEPTH: usize = 32;
pub const MAX_LEAVES: u64 = u32::MAX as u64;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn domain(tag: &[u8]) -> [u8; 32] {
    assert!(tag.len() <= 32);
    let mut word = [0; 32];
    word[..tag.len()].copy_from_slice(tag);
    word
}
fn number(n: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&n.to_be_bytes());
    word
}
fn address(a: &[u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(a);
    word
}
fn words(parts: &[[u8; 32]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// A single immutable Ethereum destination. Amounts remain origin atomic units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmRoute {
    pub origin_domain: [u8; 32],
    pub asset: [u8; 32],
    pub chain_id: u64,
    pub adapter: [u8; 20],
    pub decimals: u8,
    pub cap: u64,
    /// Actual deployed adapter runtime hash, authenticated by the origin issuer.
    /// Excluded from route_id to avoid a self-referential immutable-code hash.
    /// The deployment identity is separately bound by the enable signature and
    /// by the host's authenticated checkpoint configuration.
    pub adapter_code_hash: [u8; 32],
}

impl EvmRoute {
    pub fn id(&self) -> [u8; 32] {
        words(&[
            domain(b"BLOCH-CHAMELEON-ROUTE-v1"),
            self.origin_domain,
            self.asset,
            number(self.chain_id),
            address(&self.adapter),
            number(u64::from(self.decimals)),
            number(self.cap),
            number(1),
        ])
    }
    /// Authorization to enable this exact route before initial issuance.
    pub fn enable_hash(&self) -> [u8; 32] {
        words(&[
            domain(b"BLOCH-CHAMELEON-ENABLE-v1"),
            self.id(),
            self.adapter_code_hash,
        ])
    }
}

/// An authenticated native export, consumed by Ethereum exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub route: [u8; 32],
    pub nonce: u64,
    pub recipient: [u8; 20],
    pub amount: u64,
    /// Commits the native inputs, lock/change outputs, expiry and policy revision.
    pub native_transaction: [u8; 32],
}
impl Export {
    pub fn id(&self) -> [u8; 32] {
        words(&[
            domain(b"BLOCH-CHAMELEON-EXPORT-v1"),
            self.route,
            number(self.nonce),
            address(&self.recipient),
            number(self.amount),
            self.native_transaction,
        ])
    }
}

/// A burn event from the registered adapter. Its nonce is also its tree index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub route: [u8; 32],
    pub nonce: u64,
    pub sender: [u8; 20],
    pub amount: u64,
    pub pq_recipient_hash: [u8; 32],
}
impl Burn {
    pub fn id(&self) -> [u8; 32] {
        words(&[
            domain(b"BLOCH-CHAMELEON-BURN-v1"),
            self.route,
            number(self.nonce),
            address(&self.sender),
            number(self.amount),
            self.pq_recipient_hash,
        ])
    }
}

fn leaf(id: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 33];
    bytes[1..].copy_from_slice(id);
    sha256(&bytes)
}
fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [1; 65];
    bytes[1..33].copy_from_slice(left);
    bytes[33..].copy_from_slice(right);
    sha256(&bytes)
}
fn empty() -> [u8; 32] {
    sha256(&[2])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub siblings: [[u8; 32]; TREE_DEPTH],
}

pub fn verify_inclusion(
    id: &[u8; 32],
    proof: &InclusionProof,
    root: &[u8; 32],
    count: u64,
) -> bool {
    if count == 0 || count > MAX_LEAVES || proof.index >= count {
        return false;
    }
    let mut node = leaf(id);
    for (height, sibling) in proof.siblings.iter().enumerate() {
        node = if (proof.index >> height) & 1 == 0 {
            parent(&node, sibling)
        } else {
            parent(sibling, &node)
        };
    }
    node == *root
}

/// Reference tree/proof builder. The caller bounds the leaf collection first.
pub fn root_and_proof(
    ids: &[[u8; 32]],
    index: Option<usize>,
) -> Option<([u8; 32], Option<InclusionProof>)> {
    if ids.len() as u64 > MAX_LEAVES || index.is_some_and(|i| i >= ids.len()) {
        return None;
    }
    let mut nodes: Vec<_> = ids.iter().map(leaf).collect();
    let mut zero = empty();
    let mut siblings = [[0; 32]; TREE_DEPTH];
    let mut position = index.unwrap_or(0);
    for sibling in &mut siblings {
        *sibling = nodes.get(position ^ 1).copied().unwrap_or(zero);
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            next.push(parent(&pair[0], pair.get(1).unwrap_or(&zero)));
        }
        nodes = next;
        zero = parent(&zero, &zero);
        position >>= 1;
    }
    Some((
        nodes.first().copied().unwrap_or(zero),
        index.map(|i| InclusionProof {
            index: i as u64,
            siblings,
        }),
    ))
}
