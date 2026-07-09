//! Bloch-SIS Protocol — Core Types
//! SHA-256d PoW · ML-DSA-65 signatures · GhostDAG

use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use serde::{Serialize, Deserialize};

// V2 tokenomics constants and helpers (per docs/specs/TOKENOMICS_V2.md,
// activated by ADR-028). V1 constants below are deprecated and will be
// removed in Sprint 2.1.D C4.
pub mod tokenomics_v2;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAINNET_PREFIX:        &str  = "bloch1q";
pub const TESTNET_PREFIX:        &str  = "bloch1t";
pub const NETWORK_MAGIC:         u32   = 0x424C5349; // "BLSI" — Bloch-SIS (own P2P network)
pub const GHOSTDAG_K:            usize = 10;
// V2 tokenomics emission constants live in `tokenomics_v2` module:
//   - INITIAL_BLOCK_REWARD_SAT (1905 BLOCH) — replaces V1 BLOCK_REWARD
//   - TAIL_FLOOR_SAT (25 BLOCH) — perpetual mining reward post halving 7
//   - HALVING_INTERVAL (210_000) — reused below; same value V1/V2
//   - block_subsidy_sat(h), split_subsidy_sat(s), founder_vesting_delta_sat(h)
// See docs/specs/TOKENOMICS_V2.md §3-§5 and ADR-028.
pub const HALVING_INTERVAL:      u64   = 210_000;

pub const MAX_BLOCK_SIZE:        usize = 1_000_000;
pub const TARGET_BLOCK_TIME:     u64   = tokenomics_v2::TARGET_BLOCK_TIME_SECS; // 150s (V2)
pub const PROTOCOL_VERSION:      u32   = 1;
pub const DIFFICULTY_WINDOW:     u64   = 2_016;      // retarget every N blocks (~5.6 hours)
pub const MAX_RETARGET_FACTOR:   u64   = 4;          // max 4x adjustment per window
pub const COINBASE_MATURITY:     u64   = 100;        // blocks before coinbase is spendable

/// FIX VULN-03: Verify that none of `tx.inputs` references an immature
/// coinbase output (depth < `COINBASE_MATURITY`).
///
/// `lookup_coinbase_height(txid)` returns `Some(height)` if `txid` is a
/// coinbase mined at the given height, or `None` if `txid` is either a
/// non-coinbase or unknown. Lookup errors should be surfaced as `None`
/// by the caller (silent on lookup failure preserves prior behaviour).
///
/// Pre-genesis (`current_height == 0`) returns `Ok(())` unconditionally:
/// no coinbase has yet been mined, so nothing can be spent yet.
///
/// Used by both block-validation (main.rs) and mempool-admission
/// (rpc/mod.rs) paths. Single source of truth for the maturity policy.
pub fn check_coinbase_maturity<F>(
    tx: &Transaction,
    current_height: u64,
    mut lookup_coinbase_height: F,
) -> Result<(), String>
where
    F: FnMut(&[u8; 32]) -> Option<u64>,
{
    if current_height == 0 {
        return Ok(());
    }
    for (i, inp) in tx.inputs.iter().enumerate() {
        if let Some(cb_height) = lookup_coinbase_height(&inp.prev_txid) {
            let depth = current_height.saturating_sub(cb_height);
            if depth < COINBASE_MATURITY {
                return Err(format!(
                    "coinbase maturity: input {} references coinbase at h={}, only {} confirmations (need {})",
                    i, cb_height, depth, COINBASE_MATURITY
                ));
            }
        }
    }
    Ok(())
}
pub const DUST_THRESHOLD:        u64   = 546;        // minimum output value (satoshis)
pub const MAX_FUTURE_SECS:       u64   = 7_200;      // max 2 hours in the future
pub const DNS_SEED_DOMAIN: &str = "seed.bloch-protocol.org";
// Bloch-SIS has no seed infrastructure yet (the prior seed node was removed
// during the de-brand). Populate with Bloch bootstrap peers before public
// testnet; until then, peers are supplied via --peer.
pub const DEFAULT_SEEDS: &[&str] = &[];

pub const CHECKPOINT_DEPTH:      u64   = 1_000;      // finality: reorgs deeper than this rejected
pub const PRUNING_DEPTH:         u64   = 10_000;     // block bodies pruned below tip - this

// ML-DSA-65 sizes (NIST FIPS 204).
// Previously held Dilithium3-era values (PRIVKEY=4000, SIG=3293) which
// diverged from the actual pqcrypto-mldsa 0.1 API (PRIVKEY=4032, SIG=3309).
// estimate_size() — used for mempool fee validation — was underestimating
// tx size by 16 bytes per input, causing low-fee rejection. See audit H-2.
// Hybrid Falcon-1024 ‖ ML-DSA-65 sizes (Sprint B6b). Public key = 1952 + 1793;
// secret = 4032 + 2305; signature = 3309 + ~1280 (Falcon is variable, so
// SIG_SIZE is an upper estimate used only for fee sizing — the wire format is
// length-prefixed, see Transaction::build_script_sig).
pub const PUBKEY_SIZE:  usize = 1952 + 1793; // 3745
pub const PRIVKEY_SIZE: usize = 4032 + 2305; // 6337
pub const SIG_SIZE:     usize = 3309 + 1462; // 4771 (upper bound; Falcon max 1462)

// Genesis block — V2 mainnet genesis re-mined 2026-05-01 (Sprint 2.1.D C8b),
// identical on every node. Tokenomics V2 (TOKENOMICS_V2.md, ADR-028).
// Recipients: miner / validator_pool / oracle_pool wallets generated 2026-05-01.
// Block time calibrated for 150s (V2). Bits 0x1d024000 ≈ 15× harder than V1.
// Hash: 0000000199c3d1a45be0a57ca115b7e52791eb682b1908b7963990eac5892bfb
pub const GENESIS_NONCE:     u64   = 0;
pub const GENESIS_TIMESTAMP: u64   = 1777686240;
// Bloch-SIS testnet anchor difficulty (B5c). Compact bits are interpreted by
// bloch_sis_pow (Bitcoin-compact): 0x2100ffff → near-max aux target, so the
// aux-hash filter is easy and testnet mining is gated only by the relaxed
// residual (TESTNET_RESIDUAL_COEFFS). The SHA-256d-era value (0x1d024000) maps
// to an infeasible SIS target. Final difficulty is set by the genesis
// ceremony (B5e). Also the ASERT-Lattice anchor (see src/pow::next_bits).
pub const GENESIS_BITS:      u32   = 0x2100ffff;

/// Genesis Module-SIS PoW witness (B5e). Mined in the relaxed testnet regime
/// against the canonical genesis (coinbase to FOUNDER_ADDRESS_HEX, GENESIS_BITS,
/// GENESIS_TIMESTAMP, nonce = GENESIS_NONCE). Makes `create_genesis_block`
/// produce a genesis that passes `validate_pow`. ZERO security (testnet); the
/// mainnet genesis ceremony re-mines under canonical parameters.
pub const GENESIS_POW_SOLUTION: [i32; 256] = [
    0, -2, 0, -2, 2, -1, -1, 2, 0, 1, 0, -2, 2, 2, -1, 2,
    2, 1, -2, 1, 2, 2, 1, -1, -2, -1, -2, -1, -2, 0, -2, 2,
    0, -1, 0, 1, 1, 1, 0, 1, -1, -1, -1, 2, 1, -2, 0, 0,
    -1, 0, -2, 2, 1, 1, -2, 1, -2, -2, 1, 1, 2, -1, 2, 2,
    -1, 1, -1, -2, -2, -2, 1, -2, 0, 1, 1, 2, 2, 2, 1, 1,
    2, 2, 0, -1, -1, 2, 2, -1, 2, 0, 2, 2, -1, 2, 0, -1,
    1, 0, 2, 1, 1, 2, 0, -1, 1, -1, 0, 0, 0, 0, -1, -1,
    2, 2, 1, -1, 1, -2, 2, 2, 2, -2, 2, 2, -2, -1, -2, 2,
    -2, 2, -1, 2, 1, 1, 2, 1, 0, 0, -1, -2, 1, -1, -2, -1,
    2, 1, -2, 0, 2, 2, -2, 0, 2, 0, -2, 2, -2, 0, 0, -2,
    2, 0, 2, 2, -2, 2, 1, 2, -1, -2, -2, -2, 0, -2, -1, 0,
    2, -1, -2, 0, 2, 1, -2, -1, 1, 2, 2, 1, 1, -2, 2, 2,
    -2, 1, -2, -2, -2, -2, 2, 1, 0, 0, -2, -1, -1, 2, -2, 1,
    -1, 1, 2, -2, 2, -2, 0, 0, -2, 2, 0, -2, 2, -1, -1, 1,
    -2, 1, -2, -2, -1, -1, -2, 0, -2, 0, 0, 2, 1, -2, 1, -2,
    -2, 0, 1, 1, 0, -2, 2, 0, -2, 2, -1, -1, -1, 0, 1, -2,
];

// ── BlockHeader ───────────────────────────────────────────────────────────────

/// Strongly-typed wrapper around a 32-byte merkle root.
///
/// Audit L-2 fix: previously `BlockHeader::merkle_root` was a bare
/// `[u8; 32]`, indistinguishable at the type level from block hashes,
/// txids, address hashes, and every other 32-byte identifier in the
/// system. The compiler could not catch a mix-up like
///
/// ```ignore
/// let b = lookup_block(&store, header.merkle_root); // wanted block_hash
/// ```
///
/// With `MerkleRoot`, that call is now a compile error.
///
/// ## Serialization invariant
///
/// `#[serde(transparent)]` guarantees that a `MerkleRoot(x)` serializes
/// as byte-identical output to the bare `[u8; 32]` `x`. This is
/// **critical for consensus** — the change must be invisible on the
/// wire, in RocksDB, and inside `BlockHeader::pow_bytes`. Any existing
/// block encoded with the pre-L-2 type decodes correctly with the
/// post-L-2 type, and vice versa. A dedicated round-trip test pins
/// this invariant (`merkle_root_serde_is_byte_identical_to_array`).
///
/// ## Usage
///
/// - `MerkleRoot::ZERO` — conventional all-zero root, used for empty
///   or placeholder blocks in tests.
/// - `MerkleRoot::from([u8; 32])` — convert a computed digest.
/// - `root.as_ref()` / `&root[..]` — obtain a byte slice for hashing,
///   serialization, or hex encoding without unwrapping the newtype.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleRoot(pub [u8; 32]);

impl MerkleRoot {
    /// The all-zero root, used as a sentinel for empty tx lists.
    pub const ZERO: MerkleRoot = MerkleRoot([0u8; 32]);

    /// Expose the inner array. Prefer `as_ref()` for byte-slice
    /// operations — this accessor exists mainly for interop with
    /// storage code that stores/reads `[u8; 32]` keys.
    pub fn into_inner(self) -> [u8; 32] { self.0 }
}

impl Default for MerkleRoot {
    fn default() -> Self { Self::ZERO }
}

impl From<[u8; 32]> for MerkleRoot {
    fn from(bytes: [u8; 32]) -> Self { MerkleRoot(bytes) }
}

impl From<MerkleRoot> for [u8; 32] {
    fn from(m: MerkleRoot) -> Self { m.0 }
}

impl AsRef<[u8]> for MerkleRoot {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl std::ops::Deref for MerkleRoot {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] { &self.0 }
}

// Show as hex in debug/display so log lines stay readable. Otherwise
// MerkleRoot([0xab, 0xcd, …]) dumps 32 decimal integers per line.
impl std::fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleRoot({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version:     u32,
    pub parents:     Vec<[u8; 32]>,
    pub merkle_root: MerkleRoot,
    pub timestamp:   u64,
    pub bits:        u32,
    pub nonce:       u64,
}

/// Bitcoin-compatible 80-byte header used ONLY for the PoW hash.
///
/// Why this exists
/// ===============
/// Stratum V1 and SHA-256d ASICs expect to hash a fixed 80-byte
/// structure laid out as:
///
/// ```text
/// version (4B) | prev_hash (32B) | merkle_root (32B) |
/// timestamp (4B) | bits (4B) | nonce (4B)
/// ```
///
/// Bloch-SIS Protocol's on-chain `BlockHeader` is NOT 80 bytes — it carries
/// a variable-length `parents: Vec<[u8;32]>` (BlockDAG), plus u64
/// timestamp and u64 nonce. Hashing the full serialized header works
/// fine for CPU mining but is incompatible with every existing
/// SHA-256d ASIC on the planet — their silicon hashes 80 bytes, full
/// stop, nothing else.
///
/// The solution: derive a deterministic 80-byte `MiningHeader` from
/// the `BlockHeader`, and make `pow_hash()` hash THAT. The on-chain
/// header keeps all its fields (BlockDAG intact), but the proof-of-
/// work is over the 80-byte projection. ASICs can mine Bloch-SIS Protocol
/// because every byte they see matches Bitcoin's layout.
///
/// Derivation rules
/// ================
/// - `version`:      taken directly from BlockHeader.version
/// - `prev_hash`:    merkle-style reduction of BlockHeader.parents.
///                   Sorted by hash ascending for determinism, then
///                   pairwise SHA-256d until one 32-byte root remains.
///                   Empty parents (genesis) → all-zeros.
/// - `merkle_root`:  BlockHeader.merkle_root (already 32 bytes)
/// - `timestamp`:    LOW 32 bits of BlockHeader.timestamp. Wraps in
///                   year 2106; acceptable since this is consensus-
///                   critical equality with the full u64 on-chain
///                   timestamp in every block written this century.
/// - `bits`:         BlockHeader.bits
/// - `nonce`:        LOW 32 bits of BlockHeader.nonce. The miner
///                   searches the 32-bit nonce space via stratum's
///                   extranonce1/extranonce2 (another 64 bits of
///                   entropy inside the coinbase); combined with the
///                   timestamp-rolling allowed per stratum spec,
///                   this is more entropy than any plausible miner
///                   can exhaust before a tip change.
///
/// Stratum interop
/// ===============
/// A stratum server sends the `MiningHeader` fields to the client via
/// `mining.notify`. The miner reconstructs the 80-byte buffer exactly
/// as below and hashes it. When a solution is found, the server
/// reconstructs the full `BlockHeader` by setting
/// `BlockHeader.nonce = (found_nonce as u64)` (upper 32 bits zero)
/// and `BlockHeader.timestamp = (found_ntime as u64)` (upper bits
/// preserved from the template's ntime).
///
/// Consensus
/// =========
/// This change re-defines `pow_hash()` and therefore every block's
/// hash. It is a hard fork from v0.5.13. New genesis required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningHeader {
    pub version:     u32,
    pub prev_hash:   [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp:   u32,
    pub bits:        u32,
    pub nonce:       u32,
}

impl MiningHeader {
    /// Serialize to the exact 80-byte layout expected by SHA-256d ASICs
    /// and Bitcoin-protocol stratum clients.
    ///
    /// Byte offsets (little-endian integers, hashes raw):
    ///   0..4    version
    ///   4..36   prev_hash
    ///   36..68  merkle_root
    ///   68..72  timestamp
    ///   72..76  bits
    ///   76..80  nonce
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_hash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Parse the 80-byte layout (inverse of to_bytes). Used by the
    /// stratum submission handler when reconstructing a BlockHeader
    /// from a miner's submission.
    pub fn from_bytes(b: &[u8; 80]) -> Self {
        MiningHeader {
            version:     u32::from_le_bytes(b[0..4].try_into().unwrap()),
            prev_hash:   b[4..36].try_into().unwrap(),
            merkle_root: b[36..68].try_into().unwrap(),
            timestamp:   u32::from_le_bytes(b[68..72].try_into().unwrap()),
            bits:        u32::from_le_bytes(b[72..76].try_into().unwrap()),
            nonce:       u32::from_le_bytes(b[76..80].try_into().unwrap()),
        }
    }

    /// The consensus-critical hash. Double-SHA256 over the 80-byte
    /// layout, matching Bitcoin exactly.
    pub fn pow_hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        Sha256::digest(Sha256::digest(bytes)).into()
    }
}

/// Compute the `prev_hash` field for the 80-byte mining header by
/// folding BlockHeader.parents into a single 32-byte commitment.
///
/// Algorithm:
/// 1. Sort parents by byte-wise ascending order (so permutation of
///    the parents Vec does not change the resulting mining header —
///    this matters because gossipsub can deliver parent references
///    in any order).
/// 2. If empty: return [0u8; 32]. Only genesis should hit this path.
/// 3. If one parent: return it as-is.
/// 4. If multiple: pairwise SHA-256d (Bitcoin merkle style) until a
///    single root remains. If the count is odd at any level, the
///    last element is duplicated (also Bitcoin merkle convention).
///
/// This commitment is deterministic and collision-resistant; two
/// distinct parent sets produce different `prev_hash` values with
/// overwhelming probability.
pub fn parents_commitment(parents: &[[u8; 32]]) -> [u8; 32] {
    if parents.is_empty() { return [0u8; 32]; }
    if parents.len() == 1 { return parents[0]; }

    let mut sorted: Vec<[u8; 32]> = parents.to_vec();
    sorted.sort();

    let mut level: Vec<[u8; 32]> = sorted;
    while level.len() > 1 {
        if level.len() % 2 != 0 {
            level.push(*level.last().expect("non-empty"));
        }
        level = level.chunks(2).map(|pair| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            Sha256::digest(Sha256::digest(buf)).into()
        }).collect();
    }
    level[0]
}

impl BlockHeader {
    /// Serialize the BlockHeader to Bitcoin-compatible wire format
    /// with a Bloch-SIS Protocol extension region appended.
    ///
    /// The first 80 bytes are bit-identical to a Bitcoin block
    /// header (same layout `MiningHeader::to_bytes` produces), so
    /// any Bitcoin parser consuming the first 80 bytes sees a valid
    /// header and can compute `pow_hash` over it.
    ///
    /// The extension region after byte 80 carries Bloch-SIS Protocol-
    /// specific state that Bitcoin has no concept of: BlockDAG
    /// parents, upper 32 bits of the u64 timestamp/nonce, and the
    /// DAG-level metadata (blue_score, height).
    ///
    /// Layout:
    /// ```text
    ///   bytes [0..80]      MiningHeader (version, prev_hash,
    ///                      merkle_root, timestamp_low32, bits,
    ///                      nonce_low32)
    ///   bytes [80..]       extension:
    ///                        parents_count:   varint
    ///                        parents:         [u8;32] * N
    ///                        timestamp_high32: u32 LE
    ///                        nonce_high32:    u32 LE
    ///                        blue_score:      u64 LE
    ///                        height:          u64 LE
    /// ```
    ///
    /// This is consensus-critical wire format. Changing it is a
    /// hard fork.
    pub fn to_bitcoin_bytes(&self, blue_score: u64, height: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + 2 + self.parents.len() * 32 + 4 + 4 + 8 + 8);

        // First 80 bytes: Bitcoin-layout MiningHeader
        out.extend_from_slice(&self.to_mining_header().to_bytes());

        // Extension: parents
        write_varint(&mut out, self.parents.len() as u64);
        for p in &self.parents {
            out.extend_from_slice(p);
        }

        // Extension: upper 32 bits of timestamp/nonce
        let ts_high = (self.timestamp >> 32) as u32;
        let nonce_high = (self.nonce >> 32) as u32;
        out.extend_from_slice(&ts_high.to_le_bytes());
        out.extend_from_slice(&nonce_high.to_le_bytes());

        // Extension: DAG metadata
        out.extend_from_slice(&blue_score.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());

        out
    }

    /// Parse a BlockHeader from its Bitcoin-format bytes.
    ///
    /// Returns (header, blue_score, height) since those fields live
    /// on the `Block` struct, not on the `BlockHeader` itself in the
    /// in-memory representation.
    ///
    /// Requires the caller to supply the EXACT bytes produced by
    /// `to_bitcoin_bytes` — no leniency on trailing garbage.
    pub fn from_bitcoin_bytes(bytes: &[u8]) -> Result<(Self, u64, u64), String> {
        if bytes.len() < 80 {
            return Err(format!("header too short: {} bytes (need >= 80)", bytes.len()));
        }

        // Parse the first 80 bytes as a MiningHeader
        let mut mining_buf = [0u8; 80];
        mining_buf.copy_from_slice(&bytes[..80]);
        let mh = MiningHeader::from_bytes(&mining_buf);

        // Parse extension starting at byte 80
        let mut cur = Cursor::new(&bytes[80..]);

        let parents_count = read_varint(&mut cur)?;
        if parents_count > 256 {
            return Err(format!("implausible parent count {}", parents_count));
        }

        let mut parents = Vec::with_capacity(parents_count as usize);
        for _ in 0..parents_count {
            let mut p = [0u8; 32];
            std::io::Read::read_exact(&mut cur, &mut p)
                .map_err(|_| "parents: unexpected EOF".to_string())?;
            parents.push(p);
        }

        // Defense: the prev_hash in the 80-byte prefix MUST match
        // parents_commitment(&parents). Otherwise the extension has
        // been tampered with.
        let expected_prev = parents_commitment(&parents);
        if mh.prev_hash != expected_prev {
            return Err(format!(
                "prev_hash mismatch: 80-byte says {}, parents_commitment says {}",
                hex::encode(mh.prev_hash), hex::encode(expected_prev),
            ));
        }

        let mut buf4 = [0u8; 4];
        let mut buf8 = [0u8; 8];

        std::io::Read::read_exact(&mut cur, &mut buf4)
            .map_err(|_| "timestamp_high EOF")?;
        let ts_high = u32::from_le_bytes(buf4);
        let timestamp = ((ts_high as u64) << 32) | (mh.timestamp as u64);

        std::io::Read::read_exact(&mut cur, &mut buf4)
            .map_err(|_| "nonce_high EOF")?;
        let nonce_high = u32::from_le_bytes(buf4);
        let nonce = ((nonce_high as u64) << 32) | (mh.nonce as u64);

        std::io::Read::read_exact(&mut cur, &mut buf8)
            .map_err(|_| "blue_score EOF")?;
        let blue_score = u64::from_le_bytes(buf8);

        std::io::Read::read_exact(&mut cur, &mut buf8)
            .map_err(|_| "height EOF")?;
        let height = u64::from_le_bytes(buf8);

        let header = BlockHeader {
            version:     mh.version,
            parents,
            merkle_root: MerkleRoot(mh.merkle_root),
            timestamp,
            bits:        mh.bits,
            nonce,
        };

        Ok((header, blue_score, height))
    }

    /// Derive the 80-byte Bitcoin-compatible mining header used for
    /// proof of work. See the `MiningHeader` docstring for rationale.
    ///
    /// This projection is deterministic: same BlockHeader always
    /// produces the same MiningHeader. Inverse operation (setting
    /// the found nonce+ntime back on the BlockHeader) is handled by
    /// the stratum submission path in src/stratum/submit.rs.
    pub fn to_mining_header(&self) -> MiningHeader {
        MiningHeader {
            version:     self.version,
            prev_hash:   parents_commitment(&self.parents),
            merkle_root: self.merkle_root.0,
            timestamp:   self.timestamp as u32,
            bits:        self.bits,
            nonce:       self.nonce as u32,
        }
    }

    /// Proof-of-work hash. Double-SHA256 over the 80-byte mining
    /// header. Consensus-critical; changing this breaks every block
    /// hash on the chain.
    ///
    /// Pre-v0.6.0 this hashed the full serialized BlockHeader (custom
    /// layout with Vec<parents>, u64 timestamp, u64 nonce). Changing
    /// to the 80-byte projection at v0.6.0 is a hard fork — new
    /// genesis required.
    pub fn pow_hash(&self) -> [u8; 32] {
        self.to_mining_header().pow_hash()
    }

    /// Module-SIS PoW seed preimage (Sprint B5b-2): the 80-byte mining header
    /// **minus the 4-byte nonce** (= 76 bytes: version ‖ parents-commitment ‖
    /// merkle ‖ timestamp ‖ bits). The SIS crate derives the seed as
    /// `SHAKE256(SEED_DOMAIN ‖ preimage ‖ nonce_le)`, so the nonce (the full
    /// u64 `self.nonce`) is supplied separately and must NOT be in the preimage.
    pub fn pow_preimage(&self) -> Vec<u8> {
        self.to_mining_header().to_bytes()[..76].to_vec()
    }

    /// DAG hash uses the full header serialization. This is distinct
    /// from the PoW hash: it's used internally for DAG indexing and
    /// reachability, not for mining. Kept over the full BlockHeader
    /// so that blocks with distinct parent sets (but matching mining
    /// projections — should be impossible, but safety in depth)
    /// remain distinct in the DAG.
    pub fn dag_hash(&self) -> [u8; 32] {
        Sha3_256::digest(self.full_bytes()).into()
    }

    /// Full serialization of every BlockHeader field. Used only for
    /// dag_hash — NOT for PoW.
    fn full_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(&self.version.to_le_bytes());
        b.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents { b.extend_from_slice(p); }
        b.extend_from_slice(self.merkle_root.as_ref());
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.bits.to_le_bytes());
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b
    }
}

// ── Transaction ───────────────────────────────────────────────────────────────

/// script_sig encoding: [4B sig_len][sig][4B pubkey_len][pubkey]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_txid:  [u8; 32],
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence:   u32,
}

/// script_pubkey: 20-byte SHA3-256(pubkey)[0..20]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub value:         u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version:  u32,
    pub inputs:   Vec<TxInput>,
    pub outputs:  Vec<TxOutput>,
    pub locktime: u32,
}

use std::io::{Cursor, Read};

// ── Bitcoin-format varint + cursor helpers ─────────────────────────────────
// Used by Transaction::to_stratum_bytes / from_stratum_bytes so that external
// miners and the node agree on txid wire format.

fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_varint(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut tag = [0u8; 1];
    cur.read_exact(&mut tag).map_err(|_| "varint: unexpected EOF on tag".to_string())?;
    match tag[0] {
        0xFF => { let mut b = [0u8; 8]; cur.read_exact(&mut b).map_err(|_| "varint u64 EOF")?; Ok(u64::from_le_bytes(b)) }
        0xFE => { let mut b = [0u8; 4]; cur.read_exact(&mut b).map_err(|_| "varint u32 EOF")?; Ok(u32::from_le_bytes(b) as u64) }
        0xFD => { let mut b = [0u8; 2]; cur.read_exact(&mut b).map_err(|_| "varint u16 EOF")?; Ok(u16::from_le_bytes(b) as u64) }
        n    => Ok(n as u64),
    }
}

fn read_u32_le(cur: &mut Cursor<&[u8]>) -> Result<u32, String> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b).map_err(|_| "u32 EOF".to_string())?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64_le(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut b = [0u8; 8];
    cur.read_exact(&mut b).map_err(|_| "u64 EOF".to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn read_32(cur: &mut Cursor<&[u8]>) -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    cur.read_exact(&mut b).map_err(|_| "32-byte EOF".to_string())?;
    Ok(b)
}

fn read_bytes(cur: &mut Cursor<&[u8]>, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    cur.read_exact(&mut b).map_err(|_| format!("{}-byte EOF", n))?;
    Ok(b)
}

// ── Coherence C2: shielded-transaction (de)serialization ──────────────────────

fn write_shielded_tx(out: &mut Vec<u8>, tx: &coherence_core::ShieldedTx) {
    out.extend_from_slice(&tx.anchor);
    write_varint(out, tx.nullifiers.len() as u64);
    for nf in &tx.nullifiers { out.extend_from_slice(nf); }
    write_varint(out, tx.outputs.len() as u64);
    for o in &tx.outputs { out.extend_from_slice(o); }
    out.extend_from_slice(&tx.fee.to_le_bytes());
    write_varint(out, tx.proof.len() as u64);
    out.extend_from_slice(&tx.proof);
    write_varint(out, tx.binding_sig.len() as u64);
    out.extend_from_slice(&tx.binding_sig);
}

fn read_shielded_tx(cur: &mut Cursor<&[u8]>) -> Result<coherence_core::ShieldedTx, String> {
    let anchor = read_32(cur)?;
    let nf_n = read_varint(cur)?;
    if nf_n > 100_000 { return Err(format!("implausible nullifier count {}", nf_n)); }
    let mut nullifiers = Vec::with_capacity(nf_n.min(1024) as usize);
    for _ in 0..nf_n { nullifiers.push(read_32(cur)?); }
    let out_n = read_varint(cur)?;
    if out_n > 100_000 { return Err(format!("implausible output count {}", out_n)); }
    let mut outputs = Vec::with_capacity(out_n.min(1024) as usize);
    for _ in 0..out_n { outputs.push(read_32(cur)?); }
    let fee = read_u64_le(cur)?;
    let proof_len = read_varint(cur)?;
    if proof_len > 8_000_000 { return Err(format!("implausible proof length {}", proof_len)); }
    let proof = read_bytes(cur, proof_len as usize)?;
    let sig_len = read_varint(cur)?;
    if sig_len > 100_000 { return Err(format!("implausible binding_sig length {}", sig_len)); }
    let binding_sig = read_bytes(cur, sig_len as usize)?;
    Ok(coherence_core::ShieldedTx { anchor, nullifiers, outputs, fee, proof, binding_sig })
}

// ────────────────────────────────────────────────────────────────────────────

impl Transaction {
    /// Canonical stratum/Bitcoin-format serialization.
    ///
    /// Used for `txid()` (consensus-critical) and for stratum V1
    /// coinbase splitting. Unlike bincode, this format is stable
    /// across language implementations and matches the byte layout
    /// every external mining client (cgminer, cpuminer, Braiins OS)
    /// already knows how to produce.
    ///
    /// Layout (little-endian integers, varint for counts/lengths):
    ///
    /// ```text
    ///   version (4B LE)
    ///   input_count (varint)
    ///   for each input:
    ///     prev_txid (32B)
    ///     prev_index (4B LE)
    ///     [if include_script_sig: script_sig_len (varint), script_sig bytes]
    ///     sequence (4B LE)
    ///   output_count (varint)
    ///   for each output:
    ///     value (8B LE)
    ///     script_pubkey_len (varint)
    ///     script_pubkey bytes
    ///   locktime (4B LE)
    /// ```
    ///
    /// When `include_script_sig = false`, inputs' script_sig is
    /// omitted entirely (not just zero-length). This matches
    /// Bitcoin's SegWit wtxid convention and preserves the VULN-06
    /// malleability fix for non-coinbase transactions.
    pub fn to_stratum_bytes(&self, include_script_sig: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.inputs.len() as u64);
        for inp in &self.inputs {
            out.extend_from_slice(&inp.prev_txid);
            out.extend_from_slice(&inp.prev_index.to_le_bytes());
            if include_script_sig {
                write_varint(&mut out, inp.script_sig.len() as u64);
                out.extend_from_slice(&inp.script_sig);
            }
            out.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for outp in &self.outputs {
            out.extend_from_slice(&outp.value.to_le_bytes());
            write_varint(&mut out, outp.script_pubkey.len() as u64);
            out.extend_from_slice(&outp.script_pubkey);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// Parse a Transaction from its stratum/Bitcoin-format serialization.
    /// Inverse of `to_stratum_bytes(true)` — requires `include_script_sig=true`
    /// bytes since a round-trip without script_sig cannot recover the input's
    /// signature.
    ///
    /// Returns Err with a short diagnostic on malformed input.
    pub fn from_stratum_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut cur = Cursor::new(bytes);

        let version = read_u32_le(&mut cur)?;
        let in_count = read_varint(&mut cur)?;
        if in_count > 100_000 { return Err(format!("implausible input count {}", in_count)); }

        // SECURITY (audit M1): never pre-size from the untrusted count alone —
        // bound the pre-allocation by how many inputs the remaining bytes could
        // possibly hold (min input = 32+4+1+4 = 41 bytes). The Vec still grows
        // if the payload really is that large.
        let remaining = bytes.len().saturating_sub(cur.position() as usize);
        let mut inputs = Vec::with_capacity((in_count as usize).min(remaining / 41 + 1));
        for _ in 0..in_count {
            let prev_txid = read_32(&mut cur)?;
            let prev_index = read_u32_le(&mut cur)?;
            let sig_len = read_varint(&mut cur)?;
            if sig_len > 10_000 { return Err(format!("implausible script_sig length {}", sig_len)); }
            let script_sig = read_bytes(&mut cur, sig_len as usize)?;
            let sequence = read_u32_le(&mut cur)?;
            inputs.push(TxInput { prev_txid, prev_index, script_sig, sequence });
        }

        let out_count = read_varint(&mut cur)?;
        if out_count > 100_000 { return Err(format!("implausible output count {}", out_count)); }

        // SECURITY (audit M1): bound by remaining bytes (min output = 8+1 = 9 bytes).
        let remaining = bytes.len().saturating_sub(cur.position() as usize);
        let mut outputs = Vec::with_capacity((out_count as usize).min(remaining / 9 + 1));
        for _ in 0..out_count {
            let value = read_u64_le(&mut cur)?;
            let spk_len = read_varint(&mut cur)?;
            if spk_len > 10_000 { return Err(format!("implausible script_pubkey length {}", spk_len)); }
            let script_pubkey = read_bytes(&mut cur, spk_len as usize)?;
            outputs.push(TxOutput { value, script_pubkey });
        }

        let locktime = read_u32_le(&mut cur)?;

        Ok(Transaction { version, inputs, outputs, locktime })
    }

    /// Transaction ID. SHA-256d over stratum-format bytes.
    ///
    /// Non-coinbase: serialized WITHOUT script_sig to prevent
    /// third-party signature malleability (VULN-06 preservation).
    /// Coinbase: serialized WITH script_sig — the "height:N" encoding
    /// plus any stratum extranonce bytes are what make each coinbase
    /// unique; coinbase has no signature to malleate.
    ///
    /// **v0.6.0 change:** previously computed via bincode. Switched
    /// to stratum-format bytes so that external miners (which receive
    /// coinb1/coinb2 byte fragments via mining.notify) and the node
    /// agree on txids. Consensus-breaking, part of the AA.0 hard fork.
    pub fn txid(&self) -> [u8; 32] {
        let bytes = self.to_stratum_bytes(self.is_coinbase());
        Sha256::digest(Sha256::digest(&bytes)).into()
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_txid == [0u8; 32]
            && self.inputs[0].prev_index == u32::MAX
    }

    /// Sighash for input at `index`: SHA3-256 of tx serialised without script_sigs
    pub fn sighash(&self, input_index: usize) -> [u8; 32] {
        let mut stripped = self.clone();
        for (i, inp) in stripped.inputs.iter_mut().enumerate() {
            inp.script_sig = if i == input_index {
                b"BLOCH_SIGHASH".to_vec()
            } else {
                vec![]
            };
        }
        // SIGHASH_ALL: the digest commits to version, locktime, every input's
        // outpoint (prev_txid/prev_index/sequence) and the signed input's index
        // (via the marker), and EVERY output — so signatures cannot be replayed
        // across txs (outpoints) nor have outputs redirected/tampered. The spent
        // UTXO's value is bound implicitly via its outpoint (the verifier looks it
        // up). `.expect` not `.unwrap_or_default`: a silent empty encoding would
        // make the sighash a FIXED constant (replayable signatures) — encoding an
        // owned struct into an in-memory Vec cannot fail, so fail loud if it ever
        // does rather than degrade security.
        let d = bincode::serde::encode_to_vec(&stripped, bincode::config::standard())
            .expect("Transaction is always serializable into an in-memory buffer");
        Sha3_256::digest(&d).into()
    }

    pub fn merkle_root(txs: &[Transaction]) -> MerkleRoot {
        if txs.is_empty() { return MerkleRoot::ZERO; }
        let mut hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.txid()).collect();
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 { hashes.push(*hashes.last().expect("non-empty vec")); }
            hashes = hashes.chunks(2).map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                Sha256::digest(Sha256::digest(buf)).into()
            }).collect();
        }
        MerkleRoot(hashes[0])
    }

    /// Parse sig + pubkey out of script_sig
    pub fn parse_script_sig(script_sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if script_sig.len() < 8 { return None; }
        let sig_len = u32::from_le_bytes(script_sig[..4].try_into().ok()?) as usize;
        if script_sig.len() < 4 + sig_len + 4 { return None; }
        let sig = script_sig[4..4 + sig_len].to_vec();
        let pk_len = u32::from_le_bytes(
            script_sig[4 + sig_len..8 + sig_len].try_into().ok()?
        ) as usize;
        if script_sig.len() < 8 + sig_len + pk_len { return None; }
        let pk = script_sig[8 + sig_len..8 + sig_len + pk_len].to_vec();
        Some((sig, pk))
    }

    /// Build script_sig from sig + pubkey
    pub fn build_script_sig(sig: &[u8], pubkey: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + sig.len() + pubkey.len());
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
        out.extend_from_slice(&(pubkey.len() as u32).to_le_bytes());
        out.extend_from_slice(pubkey);
        out
    }

    /// Sprint A: Estimate the serialized size of a transaction BEFORE signing.
    pub fn estimate_size(n_inputs: usize, n_outputs: usize) -> usize {
        const PER_INPUT:  usize = 4 + 32 + 4
                                  + 4 + crate::core::SIG_SIZE
                                  + 4 + crate::core::PUBKEY_SIZE;
        const PER_OUTPUT: usize = 8 + 4 + 20;
        const BASE:       usize = 4 + 4 + 4 + 4;
        BASE + (n_inputs * PER_INPUT) + (n_outputs * PER_OUTPUT)
    }

    /// Sprint A: Calculate fee given size and rate (sats per 1000 bytes).
    pub fn calc_fee(size_bytes: usize, fee_rate_per_kb: u64, min_fee: u64) -> u64 {
        let calculated = (size_bytes as u64).saturating_mul(fee_rate_per_kb) / 1000;
        calculated.max(min_fee)
    }

    /// Sprint A: Full fee estimation for a planned transaction.
    pub fn estimate_fee(n_inputs: usize, n_outputs: usize, fee_rate_per_kb: u64) -> u64 {
        let size = Self::estimate_size(n_inputs, n_outputs);
        Self::calc_fee(size, fee_rate_per_kb, 1000)
    }

    /// Sprint A: Actual serialized size of this transaction (after signing).
    pub fn actual_size(&self) -> usize {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Sprint A: Total value of outputs (None on overflow).
    pub fn total_output(&self) -> Option<u64> {
        self.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
    }

    /// Sprint A: Count distinct addresses in outputs.
    pub fn unique_output_addresses(&self) -> usize {
        use std::collections::HashSet;
        let addrs: HashSet<&[u8]> = self.outputs.iter()
            .map(|o| o.script_pubkey.as_slice())
            .collect();
        addrs.len()
    }
}

// ── Block ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header:       BlockHeader,
    pub transactions: Vec<Transaction>,
    pub blue_score:   u64,
    pub height:       u64,
    /// Module-SIS PoW witness (Sprint B5b): the short solution vector `s`
    /// (length `pow::SOLUTION_LEN` = 256) found by the miner. Empty for an
    /// unmined/template block. Serialized after the transactions in
    /// `to_bitcoin_bytes`. `validate_pow` (B5b-2) verifies it against the
    /// header-derived SIS instance; block identity (B5b-2) becomes the aux
    /// hash that binds it. In B5b-1 the field is plumbed but SHA-256d remains
    /// the enforced PoW.
    #[serde(default)]
    pub pow_solution: Vec<i32>,
    /// Coherence C2: shielded (private) transactions in this block. Empty for
    /// transparent-only blocks and genesis, so the block commitment is
    /// unchanged when there are none (genesis-preserving). Committed via the
    /// combined merkle root (`combined_merkle_root`) and serialized after the
    /// transparent txs + pow_solution.
    #[serde(default)]
    pub shielded_transactions: Vec<coherence_core::ShieldedTx>,
}

impl Block {
    /// Block identity (Sprint B5b-2). Binds the Module-SIS PoW witness:
    /// SHA3-256 over (header preimage ‖ nonce ‖ solution). Distinct solutions
    /// for the same header yield distinct ids (prevents witness-malleability
    /// collisions). Total & deterministic even for an unmined block (empty
    /// solution) — identity is only consensus-meaningful once mined. PoW
    /// validity is enforced separately by `validate_pow`.
    pub fn block_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BLOCH-BLOCK-ID-V1");
        h.update(&self.header.pow_preimage());
        h.update(&self.header.nonce.to_le_bytes());
        for &c in &self.pow_solution {
            h.update(&c.to_le_bytes());
        }
        h.finalize().into()
    }

    /// Serialize the full Block to Bitcoin-compatible wire format
    /// with the Bloch-SIS Protocol header extension, followed by the
    /// transaction list.
    ///
    /// Layout:
    /// ```text
    ///   header bytes:        BlockHeader::to_bitcoin_bytes(blue_score, height)
    ///   tx_count:            varint
    ///   transactions:        Transaction::to_stratum_bytes(true) * N
    /// ```
    ///
    /// This is THE canonical wire format for blocks at v0.6.0+.
    /// Replaces the pre-v0.6.0 bincode encoding. Consensus-critical.
    pub fn to_bitcoin_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bitcoin_bytes(self.blue_score, self.height);
        let mut out = Vec::with_capacity(header_bytes.len() + 2 + self.transactions.len() * 256);
        out.extend_from_slice(&header_bytes);

        write_varint(&mut out, self.transactions.len() as u64);
        for tx in &self.transactions {
            // include_script_sig=true — a block must contain every
            // byte needed to re-verify signatures, including the
            // signature bytes themselves.
            out.extend_from_slice(&tx.to_stratum_bytes(true));
        }

        // Sprint B5b: Module-SIS PoW witness. varint(len) + len × i32 (LE).
        // An unmined/template block encodes len=0 (single trailing byte).
        write_varint(&mut out, self.pow_solution.len() as u64);
        for &c in &self.pow_solution {
            out.extend_from_slice(&c.to_le_bytes());
        }

        // Coherence C2: shielded (private) transactions. varint(count) + each.
        // Empty for transparent-only blocks + genesis (single 0 byte), so block
        // IDENTITY (which hashes pow_preimage, not this suffix) is unchanged.
        // NOTE: carried on the wire here; consensus validation + merkle binding
        // are wired in a follow-up (accept_block + ShieldedEngine).
        write_varint(&mut out, self.shielded_transactions.len() as u64);
        for stx in &self.shielded_transactions {
            write_shielded_tx(&mut out, stx);
        }

        out
    }

    /// Parse a Block from its Bitcoin-format bytes. Inverse of
    /// `to_bitcoin_bytes`.
    ///
    /// The parsing is strict: trailing bytes past the last
    /// transaction are rejected as malformed. This catches
    /// truncation + padding bugs early.
    pub fn from_bitcoin_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Walk the header bytes one field at a time to find the
        // exact header length, then split into (header_bytes, body_bytes).
        //
        // The header has a variable-length parents Vec, so we must
        // parse it before we know where the body starts.
        if bytes.len() < 80 {
            return Err("block too short for even 80-byte header".to_string());
        }

        // Peek at parents_count to compute header length without
        // double-parsing.
        let mut cur = Cursor::new(&bytes[80..]);
        let parents_count = read_varint(&mut cur)?;
        if parents_count > 256 {
            return Err(format!("implausible parent count {}", parents_count));
        }
        let parents_bytes_start = 80;
        let varint_len = {
            // Recompute how many bytes we consumed for the varint
            let n = parents_count;
            if n < 0xFD { 1 } else if n <= 0xFFFF { 3 } else if n <= 0xFFFF_FFFF { 5 } else { 9 }
        };
        let parents_bytes = parents_count as usize * 32;
        let header_extension_tail = 4 + 4 + 8 + 8; // ts_high, nonce_high, blue, height
        let header_len = parents_bytes_start + varint_len + parents_bytes + header_extension_tail;

        if bytes.len() < header_len {
            return Err(format!("header truncated: {} bytes, need {}", bytes.len(), header_len));
        }

        let (header, blue_score, height) = BlockHeader::from_bitcoin_bytes(&bytes[..header_len])?;

        // Body: tx_count + transactions
        let body = &bytes[header_len..];
        let mut body_cur = Cursor::new(body);
        let tx_count = read_varint(&mut body_cur)?;
        if tx_count > 1_000_000 {
            return Err(format!("implausible tx count {}", tx_count));
        }

        // Walk each tx. Transaction::from_stratum_bytes expects a
        // complete tx — we need to measure each one's length by
        // parse-and-reserialize, or we need a length-prefixed format.
        // Option: parse, reserialize, advance cursor by emitted length.
        // SECURITY (audit M1): bound the pre-allocation by remaining bytes
        // (min tx = version 4 + in/out varints 1+1 + locktime 4 = 10 bytes),
        // never by the untrusted tx_count alone.
        let body_remaining = body.len().saturating_sub(body_cur.position() as usize);
        let mut transactions = Vec::with_capacity((tx_count as usize).min(body_remaining / 10 + 1));
        let mut body_offset = body_cur.position() as usize;

        for i in 0..tx_count {
            let remaining = &body[body_offset..];
            let tx = Transaction::from_stratum_bytes(remaining)
                .map_err(|e| format!("tx[{}] parse: {}", i, e))?;
            let tx_len = tx.to_stratum_bytes(true).len();
            body_offset += tx_len;
            transactions.push(tx);
        }

        // Sprint B5b: parse the Module-SIS PoW witness. varint(len) + len × i32.
        let mut sol_cur = Cursor::new(&body[body_offset..]);
        let sol_len = read_varint(&mut sol_cur)? as usize;
        if sol_len > bloch_sis_pow::params::N {
            return Err(format!("implausible pow_solution length {}", sol_len));
        }
        body_offset += sol_cur.position() as usize;
        let mut pow_solution = Vec::with_capacity(sol_len);
        for _ in 0..sol_len {
            if body_offset + 4 > body.len() {
                return Err("pow_solution truncated".to_string());
            }
            let c = i32::from_le_bytes(body[body_offset..body_offset + 4].try_into().unwrap());
            pow_solution.push(c);
            body_offset += 4;
        }

        // Coherence C2: shielded-transactions suffix (varint count + each).
        // Backward-compatible: no suffix parses as zero shielded.
        let mut shielded_transactions = Vec::new();
        if body_offset < body.len() {
            let mut sh_cur = Cursor::new(&body[body_offset..]);
            let sh_count = read_varint(&mut sh_cur)?;
            if sh_count > 100_000 {
                return Err(format!("implausible shielded count {}", sh_count));
            }
            for i in 0..sh_count {
                shielded_transactions.push(
                    read_shielded_tx(&mut sh_cur).map_err(|e| format!("shielded[{}]: {}", i, e))?);
            }
            body_offset += sh_cur.position() as usize;
        }

        // Strict: no trailing bytes past the shielded suffix.
        if body_offset != body.len() {
            return Err(format!(
                "trailing bytes in block body: parsed {} of {}",
                body_offset, body.len(),
            ));
        }

        Ok(Block {
            header,
            transactions,
            blue_score,
            height,
            pow_solution,
            shielded_transactions,
        })
    }

    /// Merkle commitment over the block body — transparent txs AND shielded txs.
    /// Genesis-preserving: with zero shielded txs it equals
    /// `Transaction::merkle_root(transparent)`, so genesis + existing blocks are
    /// byte-identical. With shielded txs present it binds each shielded tx's hash
    /// into the root — and the root is in the PoW preimage, so shielded txs are
    /// consensus-committed and non-malleable (Coherence C2).
    pub fn body_merkle_root(&self) -> MerkleRoot {
        let tx_root = Transaction::merkle_root(&self.transactions);
        if self.shielded_transactions.is_empty() {
            return tx_root;
        }
        let mut sh = Sha3_256::new();
        sh.update(b"bloch:block:shielded:v1");
        for stx in &self.shielded_transactions {
            let mut buf = Vec::new();
            write_shielded_tx(&mut buf, stx);
            let h: [u8; 32] = Sha3_256::digest(&buf).into();
            sh.update(h);
        }
        let sh_root: [u8; 32] = sh.finalize().into();
        let mut c = Sha3_256::new();
        c.update(b"bloch:block:body:v1");
        c.update(tx_root.0);
        c.update(sh_root);
        MerkleRoot(c.finalize().into())
    }

    pub fn validate_merkle(&self) -> bool {
        self.body_merkle_root() == self.header.merkle_root
    }

    pub fn validate_pow(&self) -> bool {
        // Bloch-SIS PoW (B5b-2, testnet regime): the block's solution vector
        // must satisfy the Module-SIS instance derived from the header, plus
        // the aux-hash difficulty filter. A SECURE verify regime is gated on
        // the research track (neither shipped width is secure — see the
        // bloch-sis-pow crate header); testnet uses the relaxed residual width.
        // N = 256 (asserted == bloch_sis_pow::params::N in src/pow).
        if self.pow_solution.len() != bloch_sis_pow::params::N {
            return false;
        }
        let mut s = [0i32; 256];
        s.copy_from_slice(&self.pow_solution);
        let target = bloch_sis_pow::bits_to_target(self.header.bits);
        bloch_sis_pow::verify_regime(
            &self.header.pow_preimage(),
            self.header.nonce,
            &s,
            &target,
            bloch_sis_pow::TESTNET_RESIDUAL_COEFFS,
        )
        .is_ok()
    }

    /// Basic coinbase format check (not value — value checked with fees in accept_block)
    pub fn validate_coinbase_format(&self) -> bool {
        if self.transactions.is_empty() { return false; }
        let cb = &self.transactions[0];
        if !cb.is_coinbase() { return false; }
        // Ensure no other coinbase transactions exist
        if self.transactions.iter().skip(1).any(|t| t.is_coinbase()) { return false; }
        true
    }

    /// Validate the coinbase transaction's value distribution (VULN-05 fix: includes fee validation).
    ///
    /// Called AFTER computing total fees from non-coinbase transactions.
    ///
    /// Genesis block (height 0): the coinbase has a single output, the founder
    /// V2 consensus rule per TOKENOMICS_V2 §4 + §5 (ADR-028). The coinbase
    /// has either 3 or 4 outputs depending on whether founder vesting is
    /// active at this height. All amounts derive from
    /// `tokenomics_v2::block_subsidy_sat(h)` split by
    /// `tokenomics_v2::split_subsidy_sat`:
    ///
    ///   output[0] = miner    value <= block_subsidy_sat(h) + total_fees
    ///   output[1] = founder  value == founder_vesting_delta_sat(h),
    ///                        addr == FOUNDER (only if delta > 0)
    ///
    /// Pure PoW: 100% of the subsidy goes to the miner (B3). Founder vesting
    /// follows per-block linear distribution across [CLIFF+1, END]; outside
    /// that window the founder output is omitted (1-output coinbase).
    pub fn validate_coinbase_value(&self, total_fees: u64) -> Result<(), &'static str> {
        if self.transactions.is_empty() { return Err("no transactions"); }
        let cb = &self.transactions[0];

        // Per TOKENOMICS_V2 §4 + §5 (ADR-028). Output shape depends on height:
        //   - founder_vesting_delta(h) == 0  (h < CLIFF or h > END):
        //         3 outputs: [miner, validator_pool, oracle_pool]
        //   - founder_vesting_delta(h)  > 0  (CLIFF + 1 <= h <= END):
        //         4 outputs: [miner, validator_pool, oracle_pool, founder]
        //
        // Genesis (h = 0) is just the first case: 3 outputs, no founder mint.
        // The founder premine is paid block-by-block during the vesting window;
        // there is no genesis lump-sum.
        //
        // Output[0] (miner) is loose: any address, value <= reward + fees.
        // Outputs[1..] are exact-value, exact-address (consensus-locked).
        // Validator/oracle pool addresses panic before Phase 6 (fail-loud).

        // Sprint B3 (pure PoW): 100% of the subsidy goes to the miner. No
        // validator/oracle pool outputs (B2 removed BFT/PoBRS). Shape:
        //   - founder_vesting_delta(h) == 0  → 1 output:  [miner]
        //   - founder_vesting_delta(h)  > 0  → 2 outputs: [miner, founder]
        let subsidy = tokenomics_v2::block_subsidy_sat(self.height);
        let founder_delta = tokenomics_v2::founder_vesting_delta_sat(self.height);
        let expected_n = if founder_delta > 0 { 2 } else { 1 };

        if cb.outputs.len() != expected_n {
            return Err(if expected_n == 2 {
                "coinbase must have 2 outputs (miner + founder)"
            } else {
                "coinbase must have 1 output (miner)"
            });
        }

        // output[0] = miner (full subsidy + fees, address is miner's choice)
        if cb.outputs[0].value > subsidy.saturating_add(total_fees) {
            return Err("miner coinbase output exceeds allowed amount");
        }

        // output[1] = founder vesting (only when founder_delta > 0)
        if founder_delta > 0 {
            if cb.outputs[1].value != founder_delta {
                return Err("founder vesting output has incorrect value");
            }
            let f_addr = tokenomics_v2::founder_address_hash();
            if cb.outputs[1].script_pubkey.len() != 20
                || cb.outputs[1].script_pubkey[..] != f_addr[..]
            {
                return Err("founder vesting output has wrong address");
            }
        }

        Ok(())
    }

    /// FIX VULN-04: Validate timestamp is within acceptable bounds.
    /// `parent_timestamp`: timestamp of the selected parent (or 0 for genesis).
    pub fn validate_timestamp(&self, parent_timestamp: u64) -> Result<(), &'static str> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Not too far in the future
        if self.header.timestamp > now + MAX_FUTURE_SECS {
            return Err("timestamp too far in the future");
        }
        // Not before parent (allow same second)
        if self.header.timestamp < parent_timestamp {
            return Err("timestamp before parent");
        }
        Ok(())
    }

    /// FIX VULN-07: Check all outputs meet dust threshold.
    /// Coinbase outputs are exempt (they are the miner's reward).
    pub fn validate_dust(&self) -> Result<(), &'static str> {
        for tx in self.transactions.iter().skip(1) { // skip coinbase
            for out in &tx.outputs {
                if out.value > 0 && out.value < DUST_THRESHOLD {
                    return Err("output below dust threshold");
                }
            }
        }
        Ok(())
    }

    /// FIX VULN-08 (CVE-2012-2459): Reject blocks with duplicate transactions.
    ///
    /// Bitcoin's merkle computation duplicates the last hash when the transaction
    /// count is odd, creating an attack where [A, B, C] and [A, B, C, C] produce
    /// the same merkle root. Without this check, an attacker can announce a
    /// header+merkle-root valid for two different transaction lists, creating a
    /// UTXO-set split across the network. Mitigation: enforce unique txids.
    pub fn validate_no_duplicate_txs(&self) -> Result<(), &'static str> {
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            if !seen.insert(tx.txid()) {
                return Err("duplicate transaction in block (CVE-2012-2459)");
            }
        }
        Ok(())
    }

    /// Structural validation — quick reject of obviously invalid blocks.
    /// Does NOT check coinbase value (requires fee computation) or
    /// bits/height (requires consensus context).
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.size_bytes() > MAX_BLOCK_SIZE        { return Err("block too large"); }
        if !self.validate_pow()                       { return Err("invalid PoW"); }
        if !self.validate_merkle()                    { return Err("invalid merkle root"); }
        if !self.validate_coinbase_format()           { return Err("invalid coinbase format"); }
        self.validate_no_duplicate_txs()?;
        self.validate_dust()?;
        Ok(())
    }

    pub fn size_bytes(&self) -> usize {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map(|v| v.len()).unwrap_or(usize::MAX)
    }
}

// ── Sprint U.1: Reorg undo data ───────────────────────────────────────────────
//
// Audit finding C-1: accept_block is forward-only. When a fork with higher
// blue work replaces the current selected chain, UTXOs mutated by the
// losing branch must be reverted. We persist an UndoData record per block
// so the eventual rollback_block() primitive (Sprint U.2) can replay the
// mutations in reverse. Kept in storage only while the block is within the
// finality window; records below finalized_height are pruned in Sprint U.3.

/// A single input consumed by a block that must be restored on rollback.
/// Captures the full pre-spend output so we can re-insert it verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoEntry {
    pub prev_txid:  [u8; 32],
    pub prev_index: u32,
    pub output:     TxOutput,
}

/// Everything accept_block mutated for a given block that rollback_block
/// needs to undo. Recorded on accept, replayed in reverse on reorg.
///
/// The four vectors mirror the four side effects in accept_block:
///   1. spent_utxos       — UTXOs deleted via delete_utxo (restore by re-put)
///   2. created_utxo_keys — UTXOs inserted via put_utxo    (undo by delete)
///   3. coinbase_txids    — coinbase rows in CF_COINBASE   (undo by delete)
///   4. tx_index_keys     — rows in CF_TX_INDEX            (undo by delete)
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UndoData {
    pub block_hash:        [u8; 32],
    pub block_height:      u64,
    pub spent_utxos:       Vec<UndoEntry>,
    pub created_utxo_keys: Vec<([u8; 32], u32)>,
    pub coinbase_txids:    Vec<[u8; 32]>,
    pub tx_index_keys:     Vec<[u8; 32]>,
}

impl UndoData {
    pub fn new(block_hash: [u8; 32], block_height: u64) -> Self {
        Self {
            block_hash,
            block_height,
            spent_utxos:       Vec::new(),
            created_utxo_keys: Vec::new(),
            coinbase_txids:    Vec::new(),
            tx_index_keys:     Vec::new(),
        }
    }

    /// Total mutations recorded — useful for metrics & sanity tests.
    pub fn mutation_count(&self) -> usize {
        self.spent_utxos.len()
            + self.created_utxo_keys.len()
            + self.coinbase_txids.len()
            + self.tx_index_keys.len()
    }
}

// ── Genesis ───────────────────────────────────────────────────────────────────

pub fn create_genesis_block(
    miner_addr: &[u8],
    validator_pool_addr: &[u8],
    oracle_pool_addr: &[u8],
) -> Block {
    create_genesis_block_with_bits(miner_addr, validator_pool_addr, oracle_pool_addr, GENESIS_BITS)
}

/// Creates the Bloch-SIS genesis block (height 0).
///
/// Pure-PoW single-output coinbase paying block_subsidy_sat(0) = 8400 BLOCH to
/// `miner_addr`. No founder premine at genesis — the 3.57B founder allocation
/// vests monthly starting one month after FOUNDER_VESTING_CLIFF (B3b).
///
/// The block carries the mined Module-SIS PoW witness (GENESIS_POW_SOLUTION,
/// B5e), so `validate_pow()` passes for the canonical genesis (miner =
/// FOUNDER_ADDRESS_HEX, bits = GENESIS_BITS, nonce = GENESIS_NONCE). Testnet
/// regime (zero security); the mainnet ceremony re-mines under canonical params.
pub fn create_genesis_block_with_bits(
    miner_addr: &[u8],
    _validator_pool_addr: &[u8],
    _oracle_pool_addr: &[u8],
    bits: u32,
) -> Block {
    // Pure PoW (B3): genesis coinbase is a single miner output paying the full
    // block subsidy. Validator/oracle pool params are retained for signature
    // compatibility but unused (BFT/PoBRS removed in B2).
    let subsidy = tokenomics_v2::block_subsidy_sat(0);
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: "Bloch-SIS genesis: 21B supply, 100% miner, 10y-lock+40y founder vesting, pure PoW. 2026.".as_bytes().to_vec(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value:         subsidy,
                script_pubkey: miner_addr.to_vec(),
            },
        ],
        locktime: 0,
    };
    let merkle = Transaction::merkle_root(&[coinbase.clone()]);
    Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![],
            merkle_root: merkle,
            timestamp:   GENESIS_TIMESTAMP,
            bits,
            nonce:       GENESIS_NONCE,
        },
        transactions: vec![coinbase],
        blue_score: 0,
        height: 0,
        // B5e: the mined genesis PoW witness. Valid only for the canonical
        // genesis (miner = FOUNDER_ADDRESS_HEX, bits = GENESIS_BITS); with
        // other args the block is well-formed but its PoW won't verify.
        pow_solution: GENESIS_POW_SOLUTION.to_vec(),
        shielded_transactions: Vec::new(),    }
}

// ── Difficulty ────────────────────────────────────────────────────────────────

pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let exp  = (bits >> 24) as usize;
    let mant = bits & 0x00ff_ffff;
    let mut t = [0u8; 32];
    if (3..=32).contains(&exp) {
        let s = 32 - exp;
        t[s]                               = ((mant >> 16) & 0xff) as u8;
        if s + 1 < 32 { t[s + 1] = ((mant >> 8) & 0xff) as u8; }
        if s + 2 < 32 { t[s + 2] = (mant & 0xff) as u8; }
    }
    t
}

pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        if h < t { return true; }
        if h > t { return false; }
    }
    true
}

/// Convert difficulty bits to work value (higher difficulty = higher work).
/// work ≈ 2^256 / target. We use u128 approximation for efficiency.
pub fn bits_to_work(bits: u32) -> u128 {
    let target = bits_to_target(bits);
    // Convert first 16 bytes of target to u128 for division
    let mut t_val: u128 = 0;
    for &b in target.iter().take(16) {
        t_val = (t_val << 8) | b as u128;
    }
    if t_val == 0 { return u128::MAX; }
    u128::MAX / t_val
}

/// Retargeting: called every DIFFICULTY_WINDOW blocks.
/// `elapsed_secs`: actual wall time in seconds for the last DIFFICULTY_WINDOW blocks.
/// Returns new `bits` based on actual elapsed time vs target.
///
/// Sprint L fix: previously used a byte-level multiply-while-dividing algorithm
/// with `as u8` truncation that produced garbage targets (e.g., identity case
/// returned 0x1dffff00 instead of 0x1d00ffff, a 256× wrong target). In production,
/// 8 consecutive broken retargets collapsed the target from 0x1d00ffff to
/// 0x20dc0000, making mining trivial and effectively eliminating PoW security.
///
/// Correct formula: new_target = old_target * clamped / target_secs, capped at
/// pow_limit (genesis target). Uses primitive_types::U256 for safe 256-bit
/// arithmetic — no manual bignum code in a consensus path.
pub fn retarget_bits(old_bits: u32, elapsed_secs: u64) -> u32 {
    use primitive_types::U256;

    let target_secs = TARGET_BLOCK_TIME * DIFFICULTY_WINDOW;
    let clamped = elapsed_secs
        .max(target_secs / MAX_RETARGET_FACTOR)
        .min(target_secs * MAX_RETARGET_FACTOR);

    let old       = U256::from_big_endian(&bits_to_target(old_bits));
    let pow_limit = U256::from_big_endian(&bits_to_target(GENESIS_BITS));

    // new_target = old * clamped / target_secs, capped at pow_limit
    let new = (old * U256::from(clamped) / U256::from(target_secs)).min(pow_limit);

    // primitive-types 0.13 API: to_big_endian() returns [u8; 32] directly
    let buf = new.to_big_endian();
    target_to_bits(&buf)
}

fn target_to_bits(target: &[u8; 32]) -> u32 {
    let leading = target.iter().take_while(|&&b| b == 0).count();
    let exp = 32 - leading;
    if exp < 3 { return 0x03000001; }
    let start = 32 - exp;
    let mant = ((target[start] as u32) << 16)
             | ((target.get(start + 1).copied().unwrap_or(0) as u32) << 8)
             | (target.get(start + 2).copied().unwrap_or(0) as u32);
    ((exp as u32) << 24) | (mant & 0x00ff_ffff)
}
