// SPDX-License-Identifier: AGPL-3.0-or-later

//! Genesis-4 block header, envelope, and the **single** block identity.
//!
//! Implements §5.3 (header layout), §5.4 (block identity) and the §6.1
//! domain-separation rules of `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`.
//!
//! ## The rule this module exists to enforce (§5.4)
//!
//! There is **one and only one** way to derive the identifier of a block:
//!
//! ```text
//! block_id = SHA3-256( DS_BLOCK ‖ canonical_serialize(header) )
//! ```
//!
//! The historical `pow_hash` / `block_hash` split is the reason this rule is
//! written in stone: the PoW node once keyed its DAG by `pow_hash` while
//! storage keyed block bodies by `block_hash`, so `body_aware_tip` could only
//! ever see genesis and tip selection stalled on mainnet. Two names for one
//! block is a consensus defect waiting for its trigger. Accordingly:
//!
//! - [`BlockId`] is a newtype whose inner bytes are **private**;
//! - the sole constructor is [`BlockId::of`];
//! - there is deliberately **no** `From<[u8; 32]>`, no `From<PowHash>`, no
//!   `Default`, no `Deserialize` — nothing that would let a second derivation
//!   path (or a stored, possibly stale, identifier) masquerade as an identity;
//! - a source-scanning property test ([`tests::single_derivation_path`])
//!   fails the build's test run if anyone adds another construction site.
//!
//! ## Not a SHA-2 → SHA-3 migration — a preimage redefinition
//!
//! The Genesis-3 block identity is **already SHA3-256**:
//! `Block::block_hash()` (`crates/bloch-crypto/src/core/mod.rs:1476`) hashes
//! `"BLOCH-BLOCK-ID-V1" ‖ pow_preimage ‖ nonce ‖ pow_solution`, deliberately
//! binding the PoW witness so distinct solutions of the same header get
//! distinct ids. What changes here is the **preimage**, not the primitive:
//! under PoS there is no nonce and no PoW solution, so the identity collapses
//! to the header alone. Readers auditing the SHA-3 migration (§6.1) should
//! not expect a hash-function change in this file — there is none.
//!
//! That also means two block-identity functions now exist in the repository:
//! the legacy `block_hash()` and this module's [`BlockId::of`]. That is the
//! *exact* configuration that stalled the chain before, so their coexistence
//! is fenced three ways:
//!
//! - **Historical only.** `block_hash()` identifies Genesis-3 blocks, whose
//!   chain terminates at height 80,000. It must never validate or identify
//!   anything in Genesis-4; it survives solely so pre-transition blocks can
//!   be re-verified.
//! - **Type-level.** `block_hash()` returns a bare `[u8; 32]`; [`BlockId`]
//!   is an opaque newtype with no constructor from raw bytes. The compiler —
//!   not a reviewer — rejects passing one where the other is expected, in
//!   either direction ([`tests::single_derivation_path`] pins this).
//! - **Domain-level.** Even the raw digests live in disjoint SHA-3 domains:
//!   `"BLOCH-BLOCK-ID-V1"` vs `DS_BLOCK = "BLCH4:BLOCK\0…"` diverge at byte
//!   2, and neither tag is a prefix of the other, so no preimage can produce
//!   a digest valid in both domains ([`tests::legacy_identity_is_domain_separated`]).
//!
//! ## Why the proposer signature lives in the envelope, not the header
//!
//! The hybrid ML-DSA-65 ‖ Falcon-1024 signature is ≈ 4,589 B. In the header it
//! would ride along every header-sync and light-client path and — worse — it
//! would either be part of the identity (making the id malleable by re-signing)
//! or need an ad-hoc exclusion rule inside the hash. Keeping the header a
//! fixed 304 bytes and hashing *all* of it means the identity function has no
//! carve-outs to get wrong, and signatures can never influence what a block
//! *is*.

use crate::attestation::Attestation;
use crate::params::{DS_BLOCK, DS_PROPOSE};
use sha3::{Digest, Sha3_256};

/// Genesis-4 header version tag (§5.3).
pub const VERSION_G4: u32 = 0xB10C_0005;

/// The Genesis-4 block header (§5.3).
///
/// Every field is fixed-width, so the canonical encoding is a fixed-length,
/// fixed-order concatenation — injective by construction, with no varints,
/// no options and no length prefixes to disagree about.
///
/// Removed relative to V3: `bits`, `nonce`, `timestamp` (derived from `slot`)
/// and `parents: Vec<_>`. Removing `bits` is what deletes the order-dependent
/// difficulty bug class (§2, the 2026-08-08 consensus split); narrowing to a
/// single `parent` is the DAG → linear-chain transition (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeaderV4 {
    /// Header version, [`VERSION_G4`] for Genesis-4.
    pub version: u32,
    /// SHA3-256 block id of the single parent.
    pub parent: [u8; 32],
    /// SHA3-256 root of the eUTXO + stake state SMT (§5.5).
    pub state_root: [u8; 32],
    /// SHA3-256 Merkle root of the transactions in the body.
    pub body_root: [u8; 32],
    /// Slot number; wall-clock time is derived from it, never carried.
    pub slot: u64,
    /// Index into the active validator set committed by the parent's state.
    pub proposer_index: u32,
    /// SHAKE-256 preimage revealed for this slot's beacon contribution.
    pub randao_reveal: [u8; 32],
    /// Accumulated beacon after mixing this slot's reveal.
    pub randao_mix: [u8; 32],
    /// Latest justified checkpoint root.
    pub justified_root: [u8; 32],
    /// Latest finalized checkpoint root.
    pub finalized_root: [u8; 32],
    /// Root over the attestation quorum carried in the body.
    pub attestation_root: [u8; 32],
    /// Coherence accumulator root (§6.6).
    pub coherence_root: [u8; 32],
}

impl BlockHeaderV4 {
    /// Exact canonical encoding length: `4 + 9×32 + 8 + 4` bytes.
    ///
    /// A constant rather than a computed value so any field added or removed
    /// forces a conscious edit here — and trips the round-trip and known-answer
    /// tests below.
    pub const ENCODED_LEN: usize = 304;

    /// Canonical, deterministic serialization: fields in §5.3 declaration
    /// order, integers little-endian (matching the attestation signing root),
    /// hashes as raw bytes.
    ///
    /// Fixed-width + fixed-order makes the encoding **injective**: two
    /// distinct headers cannot produce the same bytes, which is what lets
    /// [`BlockId::of`] promise that distinct headers get distinct ids (up to
    /// SHA3-256 collision resistance).
    pub fn canonical_serialize(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        let mut at = 0usize;
        let mut put = |src: &[u8]| {
            out[at..at + src.len()].copy_from_slice(src);
            at += src.len();
        };
        put(&self.version.to_le_bytes());
        put(&self.parent);
        put(&self.state_root);
        put(&self.body_root);
        put(&self.slot.to_le_bytes());
        put(&self.proposer_index.to_le_bytes());
        put(&self.randao_reveal);
        put(&self.randao_mix);
        put(&self.justified_root);
        put(&self.finalized_root);
        put(&self.attestation_root);
        put(&self.coherence_root);
        debug_assert_eq!(at, Self::ENCODED_LEN, "encoding drifted from ENCODED_LEN");
        out
    }

    /// Strict inverse of [`canonical_serialize`](Self::canonical_serialize).
    ///
    /// Rejects any input that is not **exactly** [`Self::ENCODED_LEN`] bytes.
    /// Trailing bytes are an error, not slack: tolerating them once produced
    /// the block-10802 fleet stall ("trailing bytes in block body"), and more
    /// fundamentally a decoder that accepts `encode(h) ‖ junk` breaks the
    /// serialize→id injectivity this module's identity rule depends on.
    pub fn canonical_deserialize(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(DecodeError::WrongLength { got: bytes.len() });
        }
        // Offsets are spelled out rather than computed so that a mismatch
        // with the encoder is caught by the round-trip test instead of being
        // reproduced symmetrically on both sides.
        let arr = |range: core::ops::Range<usize>| -> [u8; 32] {
            bytes[range].try_into().expect("32-byte slice")
        };
        Ok(Self {
            version: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            parent: arr(4..36),
            state_root: arr(36..68),
            body_root: arr(68..100),
            slot: u64::from_le_bytes(bytes[100..108].try_into().expect("8 bytes")),
            proposer_index: u32::from_le_bytes(bytes[108..112].try_into().expect("4 bytes")),
            randao_reveal: arr(112..144),
            randao_mix: arr(144..176),
            justified_root: arr(176..208),
            finalized_root: arr(208..240),
            attestation_root: arr(240..272),
            coherence_root: arr(272..304),
        })
    }

    /// The block's identity. Convenience for [`BlockId::of`].
    pub fn id(&self) -> BlockId {
        BlockId::of(self)
    }

    /// Domain-separated root the proposer's hybrid signature covers:
    /// `SHA3-256(DS_PROPOSE ‖ canonical_serialize(header))`.
    ///
    /// **Not** the block id, on purpose. The frozen interface contract
    /// ([`crate::interfaces::ProposerDuties::proposal_signing_root`] and the
    /// [`crate::params::DS_PROPOSE`] rationale) gives the signature its own
    /// domain: a signature domain that is also an identifier domain invites
    /// cross-protocol replay — a digest that verifies as "the proposer signed
    /// this" must never be *the same value* that other subsystems store and
    /// compare as "which block is this". The preimage bytes are identical to
    /// the identity preimage except for the 16-byte tag, so the two digests
    /// can never collide ([`tests::signing_root_is_not_the_block_id`]).
    ///
    /// This is the **single** definition of the proposer signing root: the
    /// producer (`crate::produce`) stamps it and the validator
    /// (`crate::derive`) checks it through this same function — two
    /// derivations of "what the proposer signs" is the same defect class as
    /// two block identities.
    pub fn proposal_signing_root(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_PROPOSE);
        h.update(self.canonical_serialize());
        h.finalize().into()
    }
}

/// Canonical decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input was not exactly [`BlockHeaderV4::ENCODED_LEN`] bytes.
    WrongLength {
        /// Length actually received.
        got: usize,
    },
}

/// The **only** identifier a Genesis-4 block has (§5.4).
///
/// `BlockId` is not "a 32-byte hash" — it is *the* value
/// `SHA3-256(DS_BLOCK ‖ canonical_serialize(header))` and nothing else. The
/// inner bytes are private and the sole constructor is [`BlockId::of`], so the
/// type system itself forbids the second-identifier pattern (`pow_hash` vs
/// `block_hash`) that once stalled tip selection: if you hold a `BlockId`, it
/// was derived from a header, full stop.
///
/// Do **not** add `From<[u8; 32]>`, `Default`, a `new()`, or a deserializer.
/// Indexes that must store ids as raw bytes should store
/// [`as_bytes`](Self::as_bytes) output and re-derive the `BlockId` from the
/// header when they need the typed value back — the asymmetry is the point.
///
/// # Compile-time fence (checked by `cargo test`)
///
/// A raw 32-byte digest — including one returned by the *legacy* Genesis-3
/// `Block::block_hash()`, which also yields a bare `[u8; 32]` — can never
/// become a `BlockId`. These doctests fail the suite the moment either
/// forgery route starts compiling:
///
/// ```compile_fail
/// use bloch_pos_committee::BlockId;
/// // Private field: direct construction is rejected (E0423).
/// let forged = BlockId([0u8; 32]);
/// ```
///
/// ```compile_fail
/// use bloch_pos_committee::BlockId;
/// // No From/Into impl exists, so a legacy hash cannot cross over (E0277).
/// let legacy_hash: [u8; 32] = [0u8; 32];
/// let forged: BlockId = legacy_hash.into();
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId([u8; 32]);

impl BlockId {
    /// Derive the identity of `header` — the single §5.4 derivation path.
    pub fn of(header: &BlockHeaderV4) -> Self {
        let mut h = Sha3_256::new();
        // Domain tag first (§6.1): the same 304 bytes fed to any other
        // SHA3-256 use in the protocol can never collide with a block id.
        h.update(DS_BLOCK);
        h.update(header.canonical_serialize());
        BlockId(h.finalize().into())
    }

    /// Read-only view of the digest, for storage keys and wire encoding.
    /// One-way by design: there is no path from raw bytes back to a `BlockId`.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for BlockId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Short prefix, like git — full digests make logs unreadable and
        // 8 hex chars is plenty to correlate a log line with an id.
        write!(f, "BlockId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// A block as it travels on the wire (§5.3): the header, the proposer's
/// hybrid signature, and the body.
///
/// The signature is **outside** the header so that (a) the 4.6 KB hybrid
/// never rides the header-sync path, and (b) it can never be part of the
/// identity — re-signing a block must not mint a new block.
#[derive(Clone, Debug)]
pub struct BlockEnvelope {
    /// The signed object. 304 bytes; the only input to [`BlockId::of`].
    pub header: BlockHeaderV4,
    /// Hybrid ML-DSA-65 ‖ Falcon-1024 signature over the header's signing
    /// root, ≈ 4,589 B. Opaque here: this crate takes verification through
    /// [`crate::attestation::SignatureVerifier`] and never touches the PQ
    /// stack directly.
    pub proposer_sig: Vec<u8>,
    /// Transactions and the attestation quorum. `header.body_root` and
    /// `header.attestation_root` commit to it; validation of those
    /// commitments happens in the node, not here.
    pub body: Body,
}

/// Block body: transactions plus the attestation quorum.
#[derive(Clone, Debug, Default)]
pub struct Body {
    /// Canonically-encoded transactions, opaque to this crate. The node's tx
    /// codec owns their meaning; `body_root` commits to these bytes.
    pub transactions: Vec<Vec<u8>>,
    /// The quorum whose root is `header.attestation_root`.
    pub attestations: Vec<Attestation>,
}

impl BlockEnvelope {
    /// Identity of the enclosed block — delegates to the single derivation
    /// path. Neither `proposer_sig` nor `body` can influence the result.
    pub fn block_id(&self) -> BlockId {
        BlockId::of(&self.header)
    }

    /// Signing root the proposer's hybrid signature covers. Delegates to
    /// [`BlockHeaderV4::proposal_signing_root`] — one definition, under
    /// `DS_PROPOSE`, per the frozen interface contract (see that method for
    /// why the signature does not simply cover the block id).
    pub fn signing_root(&self) -> [u8; 32] {
        self.header.proposal_signing_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update as XofUpdate, XofReader},
        Shake256,
    };

    /// Deterministic pseudo-random header stream (SHAKE-256 as PRG) so the
    /// collision test needs no `rand` dependency and is reproducible.
    fn arbitrary_header(seed: u64) -> BlockHeaderV4 {
        let mut x = Shake256::default();
        XofUpdate::update(&mut x, b"header-fuzz");
        XofUpdate::update(&mut x, &seed.to_le_bytes());
        let mut r = x.finalize_xof();
        let mut b32 = || {
            let mut a = [0u8; 32];
            r.read(&mut a);
            a
        };
        let mut h = BlockHeaderV4 {
            version: 0,
            parent: b32(),
            state_root: b32(),
            body_root: b32(),
            slot: 0,
            proposer_index: 0,
            randao_reveal: b32(),
            randao_mix: b32(),
            justified_root: b32(),
            finalized_root: b32(),
            attestation_root: b32(),
            coherence_root: b32(),
        };
        let mut small = [0u8; 16];
        r.read(&mut small);
        h.version = u32::from_le_bytes(small[0..4].try_into().unwrap());
        h.slot = u64::from_le_bytes(small[4..12].try_into().unwrap());
        h.proposer_index = u32::from_le_bytes(small[12..16].try_into().unwrap());
        h
    }

    fn base_header() -> BlockHeaderV4 {
        BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
            slot: 42,
            proposer_index: 7,
            randao_reveal: [0x44; 32],
            randao_mix: [0x55; 32],
            justified_root: [0x66; 32],
            finalized_root: [0x77; 32],
            attestation_root: [0x88; 32],
            coherence_root: [0x99; 32],
        }
    }

    #[test]
    fn round_trip() {
        let h = base_header();
        let enc = h.canonical_serialize();
        assert_eq!(enc.len(), BlockHeaderV4::ENCODED_LEN);
        let back = BlockHeaderV4::canonical_deserialize(&enc).unwrap();
        assert_eq!(h, back);

        // And for a spread of pseudo-random headers.
        for seed in 0..64 {
            let h = arbitrary_header(seed);
            let back = BlockHeaderV4::canonical_deserialize(&h.canonical_serialize()).unwrap();
            assert_eq!(h, back);
        }
    }

    #[test]
    fn strict_length_no_trailing_bytes() {
        // Truncated input must fail.
        let enc = base_header().canonical_serialize();
        assert_eq!(
            BlockHeaderV4::canonical_deserialize(&enc[..enc.len() - 1]),
            Err(DecodeError::WrongLength { got: 303 })
        );
        // Trailing bytes must fail too — the block-10802 lesson: a decoder
        // that shrugs at `encode(h) ‖ junk` makes the encoding non-injective.
        let mut padded = enc.to_vec();
        padded.push(0);
        assert_eq!(
            BlockHeaderV4::canonical_deserialize(&padded),
            Err(DecodeError::WrongLength { got: 305 })
        );
        assert!(BlockHeaderV4::canonical_deserialize(&[]).is_err());
    }

    /// Every single field must influence the id. If a field were skipped by
    /// the encoder, two blocks differing only in that field would share an
    /// identity — the exact class of bug §5.4 forbids.
    #[test]
    fn every_field_changes_the_id() {
        let base = base_header();
        let base_id = BlockId::of(&base);

        let mutations: Vec<(&str, Box<dyn Fn(&mut BlockHeaderV4)>)> = vec![
            ("version", Box::new(|h| h.version ^= 1)),
            ("parent", Box::new(|h| h.parent[0] ^= 1)),
            ("state_root", Box::new(|h| h.state_root[31] ^= 1)),
            ("body_root", Box::new(|h| h.body_root[15] ^= 1)),
            ("slot", Box::new(|h| h.slot ^= 1)),
            ("proposer_index", Box::new(|h| h.proposer_index ^= 1)),
            ("randao_reveal", Box::new(|h| h.randao_reveal[0] ^= 1)),
            ("randao_mix", Box::new(|h| h.randao_mix[0] ^= 1)),
            ("justified_root", Box::new(|h| h.justified_root[0] ^= 1)),
            ("finalized_root", Box::new(|h| h.finalized_root[0] ^= 1)),
            ("attestation_root", Box::new(|h| h.attestation_root[0] ^= 1)),
            ("coherence_root", Box::new(|h| h.coherence_root[0] ^= 1)),
        ];
        // 12 mutations — one per §5.3 field. A field added to the struct
        // without a mutation here should be caught in review; the count
        // assertion at least forces the list to be looked at.
        assert_eq!(mutations.len(), 12);

        let mut ids = vec![base_id];
        for (name, m) in &mutations {
            let mut h = base;
            m(&mut h);
            let id = BlockId::of(&h);
            assert_ne!(id, base_id, "mutating `{name}` did not change the BlockId");
            ids.push(id);
        }
        // All mutated ids are also pairwise distinct.
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "id collision between mutations {i} and {j}");
            }
        }
    }

    #[test]
    fn distinct_headers_never_collide() {
        // 4,096 pseudo-random headers: all encodings distinct (injectivity)
        // and all ids distinct (no accidental truncation/aliasing in the
        // hash input assembly).
        let mut encodings = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        for seed in 0..4096u64 {
            let h = arbitrary_header(seed);
            assert!(encodings.insert(h.canonical_serialize().to_vec()), "encoding collision");
            assert!(ids.insert(*BlockId::of(&h).as_bytes()), "BlockId collision");
        }
    }

    /// The id is a function of the header alone: re-signing a block or
    /// swapping its body must never mint a new identity (§5.3/§5.4 — the
    /// signature lives in the envelope precisely so it cannot).
    #[test]
    fn envelope_signature_and_body_do_not_affect_id() {
        let header = base_header();
        let a = BlockEnvelope { header, proposer_sig: vec![0xAA; 4589], body: Body::default() };
        let b = BlockEnvelope {
            header,
            proposer_sig: vec![0xBB; 4589],
            body: Body { transactions: vec![vec![1, 2, 3]], attestations: vec![] },
        };
        assert_eq!(a.block_id(), b.block_id());
        assert_eq!(a.block_id(), BlockId::of(&header));
        assert_eq!(a.signing_root(), header.proposal_signing_root());
    }

    /// The proposer signing root and the block id hash the same 304 canonical
    /// bytes under *different* 16-byte tags (`DS_PROPOSE` vs `DS_BLOCK`), so a
    /// proposer signature can never be replayed as an identity or vice versa —
    /// the frozen-interface rule `DS_PROPOSE` exists to enforce.
    #[test]
    fn signing_root_is_not_the_block_id() {
        let header = base_header();
        assert_ne!(header.proposal_signing_root(), *BlockId::of(&header).as_bytes());
        // And it is bound to every header field, same as the id: mutate the
        // slot and the signing root must move (a signature over slot N must
        // not vouch for slot N+1).
        let mut other = header;
        other.slot += 1;
        assert_ne!(other.proposal_signing_root(), header.proposal_signing_root());
        // Tag shape sanity for the frozen contract.
        assert_eq!(DS_PROPOSE.len(), 16);
        assert_ne!(DS_PROPOSE, DS_BLOCK);
    }

    /// Known-answer stability: the identity of a fixed header must never
    /// change across refactors. If this test fails, the canonical encoding or
    /// the domain tag changed — which is a **hard fork**, not a cleanup.
    #[test]
    fn known_answer_identity() {
        let id = BlockId::of(&base_header());
        let hex: String = id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected_kat(), "canonical encoding or DS_BLOCK changed: hard fork");
    }

    /// Pinned from an independent implementation (Python `hashlib.sha3_256`
    /// over the same tag ‖ encoding), so a bug reproduced symmetrically in
    /// both this crate's encoder and hasher still cannot satisfy it. Update
    /// *only* on a deliberate, spec-versioned change.
    fn expected_kat() -> String {
        // SHA3-256( "BLCH4:BLOCK\0\0\0\0\0" ‖ canonical_serialize(base_header()) )
        "baa1ec0ce3377f00c48afff5dff72e946f5cacda21b5feeefd1aa5d438a3a0eb".into()
    }

    /// Collapse any `path::to::BlockId` down to a bare `BlockId`, so the
    /// scan cannot be dodged by writing `for crate::header::BlockId` instead
    /// of `for BlockId`. (Found the hard way: the first version of this test
    /// missed exactly that spelling.)
    fn canonicalize_blockid_paths(mut code: String) -> String {
        while let Some(p) = code.find("::BlockId") {
            let seg_start = code[..p]
                .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                .map(|k| k + 1)
                .unwrap_or(0);
            // Remove "path::…::" and keep "BlockId".
            code.replace_range(seg_start..p + 2, "");
        }
        code
    }

    /// Strip `//` comments and the contents of `"…"` string literals from one
    /// line of Rust source, so the scan below only ever looks at *code*.
    /// Naive (no raw-string or escape handling) but strict in the safe
    /// direction: it can only under-strip, never hide real code.
    fn strip_line(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut in_str = false;
        let mut prev = '\0';
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if in_str {
                if c == '"' && prev != '\\' {
                    in_str = false;
                }
                prev = c;
                continue;
            }
            match c {
                '"' => {
                    in_str = true;
                    prev = c;
                }
                '/' if chars.peek() == Some(&'/') => break, // comment: drop rest
                _ => {
                    out.push(c);
                    prev = c;
                }
            }
        }
        out
    }

    /// §5.4 property test (Assistant A2's invariant): no code path in this
    /// crate derives a block identifier from anything other than
    /// `BlockId::of(&header)` — and the Genesis-4 identity can never be
    /// confused with the *legacy* Genesis-3 identity.
    ///
    /// Context: `Block::block_hash()` in `bloch-crypto/core/mod.rs:1476` is
    /// the historical (Genesis-3, terminal height 80,000) identity. Two
    /// identity functions coexisting is exactly the `pow_hash`/`block_hash`
    /// configuration that stalled tip selection, so this test pins the fences:
    ///
    /// Rust cannot express "this impl does not exist" at runtime, so it is
    /// enforced structurally by scanning the crate's own sources. The test
    /// fails if:
    ///
    /// (a) `BlockId(…)` is constructed anywhere outside `BlockId::of` — a
    ///     second construction site is a second derivation path;
    /// (b) any trait is manually implemented on `BlockId` other than the
    ///     `Debug` formatter — `From`, `TryFrom`, `Default`, `Deserialize` et
    ///     al. are all constructor smuggling routes;
    /// (c) the legacy identity leaks in: any mention of `block_hash`,
    ///     `pow_hash` or `PowHash` in this crate's code. The legacy function
    ///     must stay confined to the historical verification path in
    ///     `bloch-crypto`; the moment this crate can even *name* it, a
    ///     `[u8; 32]` from the wrong era can start flowing into PoS indexes.
    ///
    /// Together with `BlockId`'s private field, (a)+(b) give the type-level
    /// guarantee: `block_hash()` returns `[u8; 32]`, and there is no path —
    /// no constructor, no conversion — from `[u8; 32]` to `BlockId`, so the
    /// compiler rejects any attempt to use a legacy hash as a PoS identity.
    /// Defeating this test requires editing the test itself, which is
    /// precisely the kind of diff a reviewer cannot miss.
    #[test]
    fn single_derivation_path() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut construction_sites = 0usize;
        let mut files = 0usize;

        for entry in std::fs::read_dir(&src_dir).expect("read src/") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&path).expect("read source file");
            let fname = path.file_name().unwrap().to_string_lossy().into_owned();

            let code: String = canonicalize_blockid_paths(
                text.lines().map(strip_line).collect::<Vec<_>>().join("\n"),
            );

            // (b) The only manual `impl … for BlockId` allowed is the Debug
            // formatter. Anything else (From, TryFrom, Default, Deserialize,
            // FromStr, …) is a smuggled constructor.
            for (i, _) in code.match_indices("for BlockId") {
                let before = code[..i].trim_end();
                assert!(
                    before.ends_with("Debug"),
                    "{fname}: forbidden trait impl on BlockId (only fmt::Debug is allowed) \
                     near offset {i} - a second constructor path violates the 5.4 rule"
                );
            }

            // (b') Nor may the type be smuggled out under another name — a
            // `use … as` rename or a type alias would let an impl target it
            // without ever writing the token the scan above looks for.
            assert!(
                !code.contains("BlockId as "),
                "{fname}: renaming BlockId hides it from the 5.4 identity scan"
            );
            for (i, _) in code.match_indices("= BlockId") {
                let after = &code[i + "= BlockId".len()..];
                assert!(
                    !after.trim_start().starts_with(';'),
                    "{fname}: type alias of BlockId hides it from the 5.4 identity scan"
                );
            }

            // (a) Count raw tuple-struct constructions `BlockId(expr)`.
            // The type declaration `struct BlockId([u8; 32]);` is not a
            // construction; everything else that isn't the empty `BlockId()`
            // type-path form is.
            construction_sites += code
                .match_indices("BlockId(")
                .filter(|(i, _)| {
                    let before = code[..*i].trim_end();
                    let after = &code[i + "BlockId(".len()..];
                    !before.ends_with("struct")
                        && !after.trim_start().is_empty()
                        && !after.starts_with(')')
                })
                .count();

            // (c) The legacy Genesis-3 identity must be unnameable here.
            let lower = code.to_lowercase();
            assert!(
                !lower.contains("pow_hash") && !code.contains("PowHash"),
                "{fname}: pow_hash/PowHash reappeared - the dual-identity defect 5.4 forbids"
            );
            assert!(
                !lower.contains("block_hash"),
                "{fname}: reference to the legacy Genesis-3 block_hash() - it is historical \
                 (chain ends at height 80,000) and must never touch Genesis-4 identity"
            );
        }

        assert!(files >= 5, "source scan looked at too few files - wrong directory?");
        assert_eq!(
            construction_sites, 1,
            "expected exactly ONE BlockId construction site (inside BlockId::of); \
             found {construction_sites}. 5.4: one and only one derivation path."
        );
    }

    /// The legacy Genesis-3 identity (`"BLOCH-BLOCK-ID-V1"` tag) and the
    /// Genesis-4 identity (`DS_BLOCK`) live in disjoint SHA-3 domains: the
    /// tags diverge at byte 2 and neither is a prefix of the other, so even
    /// identical payload bytes can never yield a digest that is valid in both
    /// eras. This is the last line of defense if the type-level fence is ever
    /// bypassed via raw `[u8; 32]` storage keys.
    #[test]
    fn legacy_identity_is_domain_separated() {
        const LEGACY_TAG: &[u8] = b"BLOCH-BLOCK-ID-V1"; // core/mod.rs:1478
        assert!(!LEGACY_TAG.starts_with(&DS_BLOCK));
        assert!(!DS_BLOCK.starts_with(LEGACY_TAG));
        // Diverge inside the fixed 16-byte tag window (at byte 2: 'C' vs 'O'),
        // not merely at the length boundary.
        assert_ne!(LEGACY_TAG[..16], DS_BLOCK[..]);

        // Same payload, both domains: digests differ.
        let payload = base_header().canonical_serialize();
        let mut legacy = Sha3_256::new();
        Digest::update(&mut legacy, LEGACY_TAG);
        Digest::update(&mut legacy, payload);
        let legacy: [u8; 32] = legacy.finalize().into();
        assert_ne!(&legacy, BlockId::of(&base_header()).as_bytes());
    }

    /// DS_BLOCK obeys the §6.1 tag rules: 16 bytes, ASCII prefix, zero-padded,
    /// and distinct from every other tag in `params`.
    #[test]
    fn domain_tag_shape() {
        use crate::params::{DS_ATTEST, DS_SORTITION};
        assert_eq!(DS_BLOCK.len(), 16);
        assert!(DS_BLOCK.starts_with(b"BLCH4:BLOCK"));
        assert!(DS_BLOCK[11..].iter().all(|&b| b == 0), "must be zero-padded to 16");
        assert_ne!(DS_BLOCK, DS_ATTEST);
        assert_ne!(DS_BLOCK, DS_SORTITION);
    }
}
