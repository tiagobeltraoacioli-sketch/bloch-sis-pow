//! Bloch-SIS Protocol — Core Types
//! SHA-256d PoW · ML-DSA-65 signatures · GhostDAG

use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use serde::{Serialize, Deserialize};

// V2 tokenomics constants and helpers (per docs/specs/TOKENOMICS_V2.md,
// activated by ADR-028). V1 constants below are deprecated and will be
// removed in Sprint 2.1.D C4.
pub mod tokenomics_v2;

/// Merged-mining (AuxPoW) verifier — dual-mine Bloch with Bitcoin (SHA-256d).
pub mod auxpow;

/// Height at/above which merged-mining (AuxPoW) blocks are accepted. DISABLED
/// by default (`u64::MAX`): merged mining is plumbed but INERT until a
/// coordinated flag-day sets a real activation height (exactly like the earlier
/// SHA-256d-LE fork). A block carrying an `auxpow` below this height is invalid
/// (fail closed), and it never affects `block_hash`.
#[cfg(not(feature = "auxpow-rehearsal"))]
pub const AUXPOW_ACTIVATION_HEIGHT: u64 = 8500; // FLAG-DAY 2026-08-01 (G3 mainnet): merged mining activates at height 8500 (chain was ~7503 at the coordinated fleet upgrade). Below this the binary is behaviour-identical to the pre-AuxPoW node; a block carrying an `auxpow` below 8500 stays fail-closed.
/// REGTEST / REHEARSAL ONLY — enabled by the `auxpow-rehearsal` cargo feature,
/// which a MAINNET artifact never sets. Activating at height 0 lets a local,
/// off-mainnet build actually ACCEPT merged-mined blocks (validate_pow's active
/// AuxPoW arm) so the end-to-end BTC↔Bloch dual-mining loop can be exercised
/// against `bitcoind -regtest`. The real mainnet flag-day is a separate, higher
/// value chosen at coordinated fleet-upgrade time — NOT this.
#[cfg(feature = "auxpow-rehearsal")]
pub const AUXPOW_ACTIVATION_HEIGHT: u64 = 0;

/// FLAG-DAY: height at/above which `bits` is validated from the block's own
/// selected-parent ancestry (`pow::genesis2_expected_bits_for_parents`) instead of
/// from mutable local state.
///
/// The legacy path derived the expected difficulty from the `current_bits` meta
/// key — rewritten on EVERY accepted block, including out-of-order backfill and
/// fork-losers — and from `get_timestamp_at_height`, a column family keyed by
/// height alone and therefore last-write-wins in a DAG. Two nodes on an
/// IDENTICAL binary consequently disagreed purely because they accepted blocks
/// in a different order, and every follower froze permanently at the first
/// retarget boundary where its cache had diverged (measured at h=25020: served
/// 0x1a265e4e, follower expected 0x1a26ac86). The chain effectively had one
/// producer and no independent validator.
///
/// Below this height the legacy path is retained verbatim so settled history
/// stays valid; at and above it, difficulty is a pure function of ancestry and
/// arrival order cannot change the verdict. Coordinated fleet upgrade required
/// BEFORE the chain reaches this height — same discipline as
/// `AUXPOW_ACTIVATION_HEIGHT` and the earlier SHA-256d-LE fork.
///
/// **History, not the current value — the constant is 30_030; see the closing
/// note below.** It was first set to 27_600 on 2026-08-08 — a retarget boundary
/// (460 × 60) roughly 230 blocks above the tip at the time, which is ~100
/// minutes of build-and-deploy margin.
///
/// It was briefly 30_000, and that was wrong. The reasoning then was that a
/// distant height buys room to upgrade the fleet without rushing the only
/// block-producing node. What that missed: below the fork height the legacy
/// order-dependent rule still applies, so every follower keeps freezing at
/// every retarget boundary on the way there. 30_000 was ~2_900 blocks out —
/// about 48 boundaries — and followers were observed dying at the first one
/// each time (node4 at 27_120 = 452×60, miner-box at 25_440 = 424×60, both
/// logging `invalid difficulty`). A follower's chance of crossing 48 boundaries
/// is nil, so a distant flag-day is not a safety margin at all: it is a
/// guarantee that no follower ever reaches the fix.
///
/// The real constraint is narrower than it looks — only the PRODUCER must be
/// upgraded before the chain reaches this height, because it is the one
/// stamping bits. Followers are restored from a producer datadir above the
/// fork height afterwards, so their exposure to the legacy window is zero.
/// Pick a height just far enough to deploy to the producer, and no further.
// EMERGENCY 2026-08-09 05:2x: raised 27_600 -> 29_400 to restore block
// production. At h=28_080 (468x60, a retarget boundary) with TWO open tips at
// 28_079, the miner and the validator on the SAME node disagreed: the template
// stamped bits 0x1a0abee4 and accept_block rejected that very block expecting
// 0x1a0ac909. Deterministic, so every block the ASIC found was discarded and
// the chain sat still for ~40 minutes.
//
// POST-MORTEM 2026-08-09 (frente ASSIMETRIA-DIFICULDADE) — the actual root
// cause, established from the producer + node4 journals:
//
//   * The flag-day switch to the ancestry rule was wired into accept_block and
//     the INTERNAL solo miner only. The four OTHER template producers —
//     stratum V1 (session.rs, the ASIC path that actually mines), stratum V2
//     (template_adapter.rs), getblocktemplate and createauxblock (rpc/mod.rs)
//     — still called the LEGACY genesis2_expected_bits unconditionally. So at
//     every height >= flag-day the producer stamped legacy bits and validated
//     with ancestry bits.
//   * Off retarget boundaries the two coincide, and at single-tip boundaries
//     they also coincide — which is why 27_600 itself passed clean. The first
//     boundary with TWO tips at boundary-1 exposed the split: the legacy value
//     depends on CF_TIMESTAMPS[h-1], a height-keyed last-write-wins cell, so
//     the producer's own template flipped 0x1a0abb83 -> 0x1a0abee4 the moment
//     the second 28_079 block landed (journal 04:42:23 vs 04:43:09), while
//     ancestry over the two-tip parent set gave 0x1a0ac909.
//   * The ancestry rule itself was CONSISTENT across nodes: the producer's
//     validator and node4's pre-stopgap binary both expected 0x1a0ac909 for
//     block e5c2ad6a. The third opinion (0x1a0abb83) was node4's LEGACY value
//     under the stopgap binary — the original order-dependent bug, which is
//     why the stopgap left node4/miner-box permanently frozen at 28_079.
//
// FIX (this flag-day): every producer and the validator now route through ONE
// height-gated choke point, pow::genesis2_expected_bits_for_parents, computed
// over EXACTLY the parents slice the block header carries — a pure function of
// consensus data, so arrival order and template timing cannot change the
// verdict. Ancestry-incomplete cases FAIL CLOSED (refuse the template / reject
// with an explicit reason) instead of silently falling back to the legacy
// value; the silent fallback and the silent dropping of DAG-missing parents
// were the two remaining ways for one side to be on the old rule while the
// other was on the new one.
//
// Set to 30_030 — deliberately MID-WINDOW (30_030 = 500*60 + 30, enforced by
// the const assert below), not a boundary: at activation the old and new rules
// agree off-boundary (both yield the bits in force), so the switch itself
// cannot fork; the first retarget under the unified rule lands at 30_060 with
// the fleet already on it. Deploy discipline, in order of hardness:
//   1. The PRODUCER must run this binary BEFORE the chain reaches 29_400 —
//      the previous binary re-arms the broken asymmetric rule there and the
//      h=28_080 halt repeats.
//   2. Followers are restored from a producer datadir (standard runbook) and
//      upgraded before 30_030. Between deploy and 30_030 the legacy rule is
//      still in force, so an un-restored follower with diverged local state
//      stays frozen until its datadir is replaced — expected, not a regression.
pub const DIFFICULTY_ANCESTRY_FORK_HEIGHT: u64 = 30_030;

// The flag-day must not sit ON a retarget boundary: activating exactly where
// the two rules first diverge would make the switch itself the incident.
const _: () = assert!(
    DIFFICULTY_ANCESTRY_FORK_HEIGHT % GENESIS2_RETARGET_WINDOW != 0,
    "DIFFICULTY_ANCESTRY_FORK_HEIGHT must be mid-window, never a retarget boundary"
);

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAINNET_PREFIX:        &str  = "bloch1q";
pub const TESTNET_PREFIX:        &str  = "bloch1t";
pub const NETWORK_MAGIC:         u32   = 0x424C5349; // "BLSI" — Bloch-SIS (own P2P network)

// ── Sighash chain-ID (replay domain separation, Roadmap #8) ──────────────────
//
// The v1 sighash folded NO chain/network binding into the signed bytes, so a
// signed tx was byte-for-byte replayable across any two Bloch chains whose
// outpoints coincide (testnet↔mainnet and every fork). v2 folds a fixed domain
// constant AND a 4-byte chain-id into the front of the signed preimage. This is
// a HARD FORK: every prior signature becomes invalid. Safe ONLY because there is
// no live mainnet and no value today. NO security property is claimed (unaudited).
//
//   preimage = SIGHASH_DOMAIN(16) ‖ [SIGHASH_VERSION](1) ‖ chain_id.to_le_bytes()(4)
//              ‖ bincode(stripped_tx)        // 21-byte fixed prefix, then the v1 body
//   sighash  = SHA3-256(preimage)
pub const SIGHASH_DOMAIN:  [u8; 16] = *b"BLOCH-SIGHASH-v2";
pub const SIGHASH_VERSION: u8       = 0x02; // bumps the implicit v1 (no-domain) scheme

/// Chain-ID registry (u32, serialized LITTLE-ENDIAN). 0xB10C = "Bloch" mnemonic.
/// An EXPLICIT consensus input derived from the node's network — NEVER from the
/// transaction (an attacker controls the tx; they must not control the domain)
/// and NEVER from a compile-time flag (a mis-built binary would sign for the
/// wrong chain). Future forks allocate a NEW discriminant; never reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ChainId {
    Mainnet = 0xB10C_0001,
    Testnet = 0xB10C_0002,
    /// Genesis-2 DEVNET (carry-over chain, SHA-256d PoW). A TESTNET/devnet
    /// artifact until a human decides otherwise — NOT a public network, no
    /// published genesis. Selected ONLY by an explicit node flag, never by
    /// `for_network` (there is no `address::Network` variant for it). Fresh
    /// discriminant per the registry rule above; never reuse one.
    Genesis2Devnet = 0xB10C_0003,
    /// Genesis-3 MAINNET (fresh SHA-256d chain, carry-over ledger). A brand-new
    /// chain that starts at height 0 with its OWN genesis block (distinct
    /// coinbase banner ⇒ distinct genesis hash — NOT a fork of Genesis-2),
    /// ingests the SAME carry-over ledger as Genesis-2 as its opening
    /// balances, and validates SHA-256d little-endian (ASIC-native) from
    /// height 0 (see `sha256d_le_fork_height_for`). Labeled MAINNET — no
    /// devnet caveat. Selected ONLY by the explicit `--genesis3` node flag,
    /// never by `for_network`. Fresh discriminant per the registry rule
    /// above; never reuse one.
    Genesis3Mainnet = 0xB10C_0004,
}

/// Which proof-of-work algorithm a chain runs. The mapping lives in
/// [`pow_algorithm`] and NOWHERE else — miner (src/pow) and validator
/// (`Block::validate_pow`) both route through it, so they provably agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowAlgorithm {
    /// SHAKE-256 hashcash with the Module-SIS structural gate (the historical
    /// Bloch-SIS PoW). Blocks carry a `pow_solution` witness of length N=256.
    ModuleSis,
    /// Double SHA-256 over the 80-byte `MiningHeader` projection (Bitcoin
    /// layout, ASIC-compatible). Blocks carry NO witness: `pow_solution`
    /// MUST be empty.
    Sha256d,
}

/// The ONLY chain-id → PoW-algorithm mapping. Exhaustive over [`ChainId`]
/// with no wildcard arm: adding a chain variant without deciding its PoW is
/// a compile error, by design.
pub const fn pow_algorithm(id: ChainId) -> PowAlgorithm {
    match id {
        ChainId::Mainnet => PowAlgorithm::ModuleSis,
        ChainId::Testnet => PowAlgorithm::ModuleSis,
        ChainId::Genesis2Devnet => PowAlgorithm::Sha256d,
        // Genesis-3 mainnet: SHA-256d, ASIC-compatible, like Genesis-2.
        ChainId::Genesis3Mainnet => PowAlgorithm::Sha256d,
    }
}

impl ChainId {
    #[inline] pub const fn to_u32(self) -> u32 { self as u32 }
    #[inline] pub fn to_le_bytes(self) -> [u8; 4] { (self as u32).to_le_bytes() }

    /// Bridge the existing `address::Network` enum to a chain-id (design §1.4).
    pub const fn for_network(net: crate::address::Network) -> ChainId {
        match net {
            crate::address::Network::Mainnet => ChainId::Mainnet,
            crate::address::Network::Testnet => ChainId::Testnet,
        }
    }
}

// Node-level SINGLE SOURCE OF TRUTH for the chain-id used by consensus
// validation. The miner and validator MUST agree (design §4.3 invariant 6), so
// both read this one value. Set ONCE at node startup from the runtime network
// selection (e.g. `--testnet`); it is NOT a compile-time flag and NOT derived
// from any transaction. Defaults to Mainnet if never set.
//
// DEFERRED WIRING (integration owner): the node binary MUST call
// `set_node_chain_id(ChainId::for_network(net))` at startup and assert it
// matches the genesis being validated. Until then the node defaults to Mainnet;
// a testnet node MUST wire this or its validators will use the wrong domain.
static NODE_CHAIN_ID: std::sync::OnceLock<ChainId> = std::sync::OnceLock::new();

/// Set the process-wide node chain-id (idempotent for the same value). Returns
/// `Err(existing)` if already set to a DIFFERENT value — guards double-init.
pub fn set_node_chain_id(id: ChainId) -> Result<(), ChainId> {
    match NODE_CHAIN_ID.set(id) {
        Ok(()) => Ok(()),
        Err(_) => {
            let cur = *NODE_CHAIN_ID.get().expect("OnceLock set");
            if cur == id { Ok(()) } else { Err(cur) }
        }
    }
}

/// The node-level chain-id read by every consensus sighash call site. Defaults
/// to Mainnet until `set_node_chain_id` is called at startup.
pub fn node_chain_id() -> ChainId {
    *NODE_CHAIN_ID.get().unwrap_or(&ChainId::Mainnet)
}
pub const GHOSTDAG_K:            usize = 10;
// V2 tokenomics emission constants live in `tokenomics_v2` module:
//   - INITIAL_BLOCK_REWARD_SAT (1905 BLOCH) — replaces V1 BLOCK_REWARD
//   - TAIL_FLOOR_SAT (100 BLOCH) — V2 tail floor, legacy pre-fork branch only
//   - EMISSION_V3_TAIL_FLOOR_SAT (60 BLOCH) — V3 perpetual tail (PISO-60)
//   - HALVING_INTERVAL (210_000) — reused below; same value V1/V2
//   - block_subsidy_sat(h), split_subsidy_sat(s), founder_vesting_delta_sat(h)
// See docs/specs/TOKENOMICS_V2.md §3-§5 and ADR-028.
pub const HALVING_INTERVAL:      u64   = 210_000;

pub const MAX_BLOCK_SIZE:        usize = 1_000_000;
pub const TARGET_BLOCK_TIME:     u64   = tokenomics_v2::TARGET_BLOCK_TIME_SECS; // 30s (V2)
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
// Hybrid ML-DSA-65 ‖ Falcon-1024 sizes (Sprint B6b). Public key = 1952 + 1793;
// secret = 4032 + 2305; signature = 3309 + ~1280 (Falcon is variable, so
// SIG_SIZE is an upper estimate used only for fee sizing — the wire format is
// length-prefixed, see Transaction::build_script_sig).
// Sizes include the 4-byte crypto-agility suite header (crypto::SUITE_HEADER_LEN)
// that now wraps every enveloped pk / sk / sig. Used for fee sizing (SIG upper
// bound) and the transport identity-key length gate.
pub const PUBKEY_SIZE:  usize = 4 + 1952 + 1793; // 3749 (hdr + hybrid pk)
pub const PRIVKEY_SIZE: usize = 4 + 4032 + 2305; // 6341 (hdr + hybrid sk)
pub const SIG_SIZE:     usize = 4 + 3309 + 1462; // 4775 (hdr + upper bound; Falcon max 1462)

// Genesis block — V2 mainnet genesis re-mined 2026-05-01 (Sprint 2.1.D C8b),
// identical on every node. Tokenomics V2 (TOKENOMICS_V2.md, ADR-028).
// Recipients: miner / validator_pool / oracle_pool wallets generated 2026-05-01.
// Block time calibrated for 30s (V2). Bits 0x1d024000 ≈ 15× harder than V1.
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

// ── Genesis-2 carry-over commitment ─────────────────────────────────────────
//
// Emitted by `bloch-genesis2 --snapshot utxo-snapshot-20260719.tsv --height
// 413743` after the snapshot verified (supply == height × 8,400 BLCH exactly,
// utxo count == height). The root is SHAKE-256 over the snapshot file's RAW
// BYTES, so any edit — truncation, a removed line, or a REORDERING — yields a
// different root. These four constants bind a Genesis-2 chain to the exact
// ledger it carries over, the same way GENESIS_POW_SOLUTION binds this chain
// to its genesis: a node MUST refuse to start (exit 1) if the snapshot it is
// given does not re-verify against all of them. See src/storage/mod.rs
// `verify_carryover_snapshot` for the fail-closed loader.
pub const CARRYOVER_SNAPSHOT_ROOT: [u8; 32] = [
    0xd3, 0xde, 0x5e, 0x51, 0xee, 0x9d, 0xbb, 0xf3,
    0x6e, 0xd7, 0x99, 0x81, 0xcb, 0xf6, 0x6e, 0xb5,
    0x0a, 0x88, 0x94, 0xfc, 0x03, 0x46, 0x10, 0xa2,
    0x0a, 0x5e, 0xe0, 0x1e, 0xb9, 0x06, 0x06, 0x37,
];
pub const CARRYOVER_SOURCE_HEIGHT: u64  = 413_743;
pub const CARRYOVER_UTXO_COUNT:    u64  = 413_743;
pub const CARRYOVER_TOTAL_SAT:     u128 = 347_544_120_000_000_000;

/// The ABSOLUTE emission height for a block at node-local `local_height`.
///
/// CONSENSUS-CRITICAL and read by BOTH the validator (`validate_coinbase_value`)
/// and the miner, so they provably agree on the subsidy. Genesis-2 restarts the
/// local chain at height 0 but must CONTINUE emission from where the carried
/// ledger stopped, so the emission height is offset by CARRYOVER_SOURCE_HEIGHT:
/// local height 1 == absolute 413,744 == the first NEW 8,400-BLOCH reward, and
/// halvings land at the correct absolute heights. The genesis anchor (local 0)
/// pays nothing regardless — its reward is already in the carried set. On every
/// other chain this is the identity.
#[inline]
pub fn emission_height(local_height: u64) -> u64 {
    match node_chain_id() {
        ChainId::Genesis2Devnet => local_height + CARRYOVER_SOURCE_HEIGHT,
        // Genesis-3 carries the SAME ledger (same snapshot, same source
        // height), so emission continues from the same absolute height.
        ChainId::Genesis3Mainnet => local_height + CARRYOVER_SOURCE_HEIGHT,
        _ => local_height,
    }
}

/// Whether `id` REQUIRES the carry-over snapshot to be ingested before the
/// node may run. Deliberately an exhaustive match with no wildcard arm: when a
/// Genesis-2 chain-id variant is added (g2/T1 adds `Genesis2Devnet`), this
/// stops compiling until someone makes the explicit decision — silently
/// defaulting a new chain to "no carry-over needed" is exactly the fail-open
/// this migration exists to remove. Today no shipped chain requires it; the
/// loader is still exercisable via the explicit `--carryover-snapshot` flag.
pub const fn chain_requires_carryover(id: ChainId) -> bool {
    match id {
        ChainId::Mainnet => false,
        ChainId::Testnet => false,
        // The decision this exhaustive match was written to force. Genesis-2
        // exists to carry the ledger over: a node that started it WITHOUT the
        // snapshot would produce a chain with the right rules and an empty
        // ledger — every balance silently gone, and nothing in the protocol
        // objecting. Requiring the flag makes that failure impossible instead
        // of merely unlikely.
        ChainId::Genesis2Devnet => true,
        // Genesis-3 exists for the same reason: a fresh chain whose opening
        // balances ARE the carried-over ledger. Same fail-closed rule.
        ChainId::Genesis3Mainnet => true,
    }
}

// ── Genesis-3 terminal height: the chain stops ──────────────────────────────
//
// The Genesis-3 chain is being retired. A signed UTXO snapshot is taken at the
// terminal height, and Genesis-4 launches from that artifact about six months
// later (`docs/specs/BLOCH-TOKENOMICS-V4.md` §3.2).
//
// A chain does not stop because it was announced. If blocks above the terminal
// height are merely *unwanted*, miners keep producing them and the "halt" is a
// fork nobody agreed to. Making them **invalid** is what actually ends the
// chain, and it has to be running on the fleet before the height arrives —
// this is a flag day in reverse, with every flag-day hazard intact.
//
// Two consequences worth stating where the constant lives:
//
//   1. Anyone who does not upgrade keeps mining past the terminal height on a
//      fork. That is tolerable only because the canonical artifact is the
//      signed snapshot at this height, not whatever chain has the most work
//      afterwards.
//   2. Once mining stops, this chain's history stops being evidence. PoW
//      security is bought with ongoing hashrate; with none, rewriting history
//      below the terminal height costs almost nothing. The snapshot digest
//      goes into the Genesis-4 genesis block precisely so the record does not
//      depend on a chain nobody is defending.

/// Last valid height on the Genesis-3 mainnet. Blocks ABOVE this are invalid.
//
// LOWERED 80,000 -> 50,000 on 2026-08-12 (founder decision), matching
// deploy/g3-terminal-50000 — the tree the fleet's running binary was built
// from. The trunk carried 80,000 until now, which meant anyone building a node
// from this repository got one that keeps accepting blocks above 50,000: it
// would not halt with the network, and the halt itself would become the fork.
pub const GENESIS3_TERMINAL_HEIGHT: u64 = 50_000;

/// The terminal height for `id`, if that chain has one.
///
/// Exhaustive with no wildcard arm, deliberately — the same fail-closed idiom
/// as [`chain_requires_carryover`]. When a new chain-id is added this stops
/// compiling until someone decides whether it terminates, instead of silently
/// inheriting "runs forever".
pub const fn terminal_height(id: ChainId) -> Option<u64> {
    match id {
        // Development and legacy chains are not being retired by this rule.
        ChainId::Mainnet => None,
        ChainId::Testnet => None,
        ChainId::Genesis2Devnet => None,
        // The chain being retired.
        ChainId::Genesis3Mainnet => Some(GENESIS3_TERMINAL_HEIGHT),
    }
}

/// Is `height` beyond the terminal height for this node's chain?
///
/// The terminal height itself is **valid** — it is the last block, and the
/// height the snapshot is taken at. Only heights strictly above it are refused.
pub fn is_past_terminal_height(height: u64) -> bool {
    match terminal_height(node_chain_id()) {
        Some(t) => height > t,
        None => false,
    }
}

// ── Soft fork SF-1: canonical residual-gate width, k: 4 → 8 ─────────────────
//
// Height-activated tightening of the Bloch-SIS PoW residual gate from the
// relaxed testnet width (TESTNET_RESIDUAL_COEFFS = 4) to the candidate
// canonical width (CANONICAL_RESIDUAL_COEFFS = 8). Because the residual check
// inspects the first k coefficients, every k=8-valid solution is automatically
// k=4-valid (prefix subset) — so this is a SOFT fork: un-upgraded peers keep
// accepting post-activation blocks, and all historical blocks (mined under
// k=4) keep validating because they sit below the activation height.

/// ⚠⚠ ACTIVATION HEIGHT — PLACEHOLDER. THE FOUNDER MUST SET THIS BEFORE THE
/// LIVE SOFT-FORK DEPLOY. ⚠⚠
///
/// Blocks with `height <` this value are validated at the testnet residual
/// width (k = 4, as today); blocks with `height >=` this value are validated
/// at the canonical width (k = 8).
///
/// Before mainnet the founder MUST set this to a concrete near-genesis height:
/// `mainnet_tip_at_release + margin`, generous enough for EVERY MINING NODE to
/// upgrade before the chain reaches it (an un-upgraded miner producing a k=4-only
/// block at/after H has that block rejected by upgraded nodes). DO NOT set it to
/// `u64::MAX` (never activates) and DO NOT set it at or below the tip at release
/// (historical/next blocks would fail k=8 validation → forced chain reset).
///
/// ── ADR (activation-height, design §3.1; decided 2026-07-12, PRE-FREEZE) ──────
/// Decision: set to 40_320. Rationale: the mainnet genesis ships this bundle, so
/// the tip at release is 0; at the 30 s `TARGET_BLOCK_TIME`, 40_320 blocks ≈ a
/// 14-day window (a 7-day window ≈ 20_160). Blocks 0..40_320 validate at the
/// testnet k=4 residual width, then the canonical k=8 width activates — a
/// generous ramp for every mining node to upgrade. This is the founder's
/// PRE-FREEZE value; the genesis-freeze ceremony operator RE-CONFIRMS it against
/// the real tip at release and records the ceremony date here before genesis is
/// frozen. Ceremony date: TBD at freeze. Unaudited; the coin has no value; no
/// security property is claimed. Off the placeholder, so `mainnet_release_guard`
/// now passes.
pub const CANONICAL_K_ACTIVATION_HEIGHT: u64 = 40_320;

/// The clearly-future placeholder value. Kept as a named constant so the
/// `mainnet`-feature CI guard below can assert the real height has been moved
/// off it. There is NO live mainnet, so `CANONICAL_K_ACTIVATION_HEIGHT` above
/// deliberately STAYS at this placeholder for now; the guard bites only when a
/// mainnet artifact is cut (see the `mainnet_release_guard` test).
pub const PLACEHOLDER_ACTIVATION_HEIGHT: u64 = 1_000_000;

/// Height BELOW which the difficulty-driven k-ramp does NOT yet apply. A FUTURE
/// activation (well above the tip at rollout) so every node upgrades before k
/// can change — no fork. Below it, k is the relaxed testnet width (k=4); the
/// historical k=8 blocks above the retired 40_320 jump stay valid because
/// k=8 ⊃ k=4 (a k=8 witness also satisfies the k=4 gate). Re-confirm against the
/// real tip at rollout. CONSENSUS-CRITICAL.
pub const K_RULE_ACTIVATION_HEIGHT: u64 = 420_480;

/// Work thresholds (`bits_to_work`) at which each residual step unlocks. k rides
/// the ASERT difficulty — the on-chain hashrate proxy (the Bitcoin model: more
/// hashrate → higher difficulty → higher k). Steps are ~8× apart because each
/// +1 to k makes a valid candidate ~8× rarer, so the network needs ~8× the work
/// to carry it without choking block production. These are the CALIBRATION KNOB:
/// tune to the sustained-hashrate milestones you want to gate on. Current live
/// work ≈ 4 (bits 0x203fffc0), so today's chain sits at k=4.
pub const K_WORK_5: u128 = 32;
pub const K_WORK_6: u128 = 256;
pub const K_WORK_7: u128 = 2_048;
pub const K_WORK_8: u128 = 16_384;

// ── Difficulty re-anchor (ASERT hard fork) ──────────────────────────────────
//
// The genesis-anchored ASERT clamps the *absolute* schedule exponent to ±4×
// (see bloch_sis_pow::difficulty::scale_target_by_pow2_milli), so difficulty can
// never exceed 4× GENESIS_BITS however much hashrate joins — a lifetime cap, not
// a per-step limiter. With the k=8→k=4 throughput filter relaxed, that cap let
// block production run away (~7 blk/s) and could never rise to meet real hashrate
// (ASICs/FPGA). Fix: re-anchor ASERT at a fresh (height, timestamp, bits) so the
// ~62-day accumulated schedule debt resets, AND — only for the re-anchored
// regime (anchor_height > 0) — widen the clamp so difficulty can track hashrate.
// Blocks below ASERT_ANCHOR2_HEIGHT keep the genesis anchor and the ±4× bound
// byte-for-byte, so every historical `expected_bits` still validates on resync
// (VULN-01 intact) — no fork. CONSENSUS-CRITICAL.

/// Height at which ASERT re-anchors — the first block validated/mined under the
/// new anchor. Set to the coordinated reset base (392_303, the snapshot tip
/// *height* — 393_386 was its blue-score, the very unit confusion this release
/// also fixes) + 1, so every operating node runs this build from the same point.
/// The reset is coordinated (all nodes wiped to 392_303, all start on this
/// build), so no node holds a 392_304+ block under the old rules → no fork.
pub const ASERT_ANCHOR2_HEIGHT: u64 = 392_304;

/// Unix-seconds timestamp of block `ASERT_ANCHOR2_HEIGHT − 1` (the reset base,
/// height 392_303) — the schedule origin for the re-anchored ASERT. Read from the
/// block itself so miner and validator agree. (ASERT half-life is 2 days, so this
/// only needs the block's real wall-clock time; sub-minute precision is moot.)
pub const ASERT_ANCHOR2_TIMESTAMP: u64 = 1_784_150_901; // block 392_303 (~2026-07-15)

/// Target for the first post-anchor block — calibrated to node3's observed
/// production so blocks return to ~30 s; ASERT converges any residual error with
/// the 2-day half-life. ~180× harder than the 0x203fffc0 the chain floods at.
pub const ASERT_ANCHOR2_BITS: u32 = 0x1f5b0500;

/// Consensus selector for the PoW residual-gate width.
///
/// DIFFICULTY-DRIVEN PROGRESSIVE RAMP (Bitcoin model). k = 4 until
/// `K_RULE_ACTIVATION_HEIGHT` (upgrade-safe), then k rises 5→6→7→8 as the
/// block's own ASERT difficulty (`bits`) — the hashrate proxy — sustains above
/// each `K_WORK_*` threshold, and eases back if it falls (self-healing: a
/// capacity crash can never re-choke the chain the way a fixed k=8 does).
///
/// DETERMINISTIC: `bits` is consensus-validated (retargeted from the parent by
/// ASERT, not chosen by the miner) and `height` is consensus-checked, so every
/// node computes the SAME k from the agreed chain — no fork surface. k is a
/// structural/throughput filter, NOT a cryptographic-hardness claim (β=q/16 is
/// the trivial q-ary regime at every k in {4..8}); real security is cumulative
/// SHAKE-256 hashcash work.
///
/// CONSENSUS-CRITICAL: callers pass the height AND bits of the block whose PoW
/// is being validated (or mined) — NOT the current tip.
#[inline]
pub fn canonical_residual_coeffs(height: u64, bits: u32) -> usize {
    if height < K_RULE_ACTIVATION_HEIGHT {
        return bloch_sis_pow::TESTNET_RESIDUAL_COEFFS; // k = 4, un-choked
    }
    let work = bits_to_work(bits);
    if work >= K_WORK_8 {
        bloch_sis_pow::CANONICAL_RESIDUAL_COEFFS // 8
    } else if work >= K_WORK_7 {
        7
    } else if work >= K_WORK_6 {
        6
    } else if work >= K_WORK_5 {
        5
    } else {
        bloch_sis_pow::TESTNET_RESIDUAL_COEFFS // 4
    }
}

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

    /// Sighash (v2) for input at `index`, bound to `chain_id`.
    ///
    /// `chain_id` is an EXPLICIT consensus input threaded from the node's network
    /// (`ChainId::for_network` / `node_chain_id()`), never a compile-time flag and
    /// never taken from the transaction. Folding it into the preimage prevents
    /// cross-fork / testnet↔mainnet replay: the same signature bytes verify to a
    /// different 32-byte digest on another chain, so ML-DSA and Falcon both fail
    /// (design §1). This changes the signed bytes of every tx — a hard fork.
    pub fn sighash(&self, input_index: usize, chain_id: ChainId) -> [u8; 32] {
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
        //
        // The v1 body (the stripped-tx bincode blob, incl. the per-input marker)
        // is unchanged; v2 only prepends the fixed 21-byte domain+version+chain-id
        // prefix. All prefix fields are fixed-length and only the trailing bincode
        // blob is variable, so simple concatenation is unambiguous.
        let body = bincode::serde::encode_to_vec(&stripped, bincode::config::standard())
            .expect("Transaction is always serializable into an in-memory buffer");
        let mut h = Sha3_256::new();
        h.update(SIGHASH_DOMAIN);           // 16 bytes (fixed)
        h.update([SIGHASH_VERSION]);        //  1 byte  (fixed)
        h.update(chain_id.to_le_bytes());   //  4 bytes (fixed)
        h.update(&body);                    //  variable (v1 body, unchanged)
        h.finalize().into()
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
    /// Merged-mining (AuxPoW) proof: when present AND the block height is at/above
    /// [`AUXPOW_ACTIVATION_HEIGHT`], the block's PoW is provided by a parent
    /// Bitcoin block that commits to this block (see [`auxpow`]). `None` for
    /// natively-mined blocks (the only kind before activation) — so blocks
    /// without it are byte-identical to before (genesis-preserving). Not part of
    /// `block_hash` (the AuxPoW commits TO the block hash).
    #[serde(default)]
    pub auxpow: Option<auxpow::AuxPow>,
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

        // Optional merged-mining (AuxPoW) trailer — present ONLY when this block
        // was merge-mined, so natively-mined blocks + genesis stay byte-identical
        // to before. Never part of block IDENTITY (it commits TO the block hash).
        if let Some(aux) = &self.auxpow {
            out.push(1);
            out.extend_from_slice(&aux.to_bytes());
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

        // Optional merged-mining (AuxPoW) trailer (backward-compatible): older
        // blocks have none — when `body_offset == body.len()` the block is
        // natively mined and `auxpow` is None.
        let auxpow = if body_offset < body.len() {
            let present = body[body_offset];
            body_offset += 1;
            match present {
                0 => None,
                1 => {
                    let (aux, used) = auxpow::AuxPow::from_bytes(&body[body_offset..])?;
                    body_offset += used;
                    Some(aux)
                }
                other => return Err(format!("invalid auxpow presence byte {other}")),
            }
        } else {
            None
        };

        // Strict: no trailing bytes past the (optional) auxpow trailer.
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
            auxpow,
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
        // Chain-selectable PoW: dispatch on the node's chain-id through the
        // single mapping `pow_algorithm` (miner routes through the same fn in
        // src/pow, so miner and validator provably agree). The two arms are
        // mutually exclusive by construction: a Module-SIS chain requires the
        // witness vector (len == N), a SHA-256d chain requires NO witness —
        // so a SIS witness cannot be smuggled onto a SHA-256d chain and a
        // witness-less SHA-256d block cannot pass on a Module-SIS chain.
        match pow_algorithm(node_chain_id()) {
            PowAlgorithm::ModuleSis => {
                // Bloch-SIS PoW (B5b-2): the block's solution vector must satisfy the
                // Module-SIS instance derived from the header, plus the aux-hash
                // difficulty filter. A SECURE verify regime is gated on the research
                // track (neither shipped width is secure — see the bloch-sis-pow crate
                // header). N = 256 (asserted == bloch_sis_pow::params::N in src/pow).
                //
                // Soft fork SF-1: the residual width is selected by THIS BLOCK's
                // height — k = 4 below CANONICAL_K_ACTIVATION_HEIGHT (so the existing
                // chain keeps validating), k = 8 at/above it. Height-lying is caught
                // by accept_block's height check (VULN-02) before acceptance, and
                // claiming a false height ≥ H only makes validation STRICTER.
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
                    canonical_residual_coeffs(self.height, self.header.bits),
                )
                .is_ok()
            }
            PowAlgorithm::Sha256d => {
                // A stale/foreign Module-SIS witness on a SHA-256d chain is
                // consensus-invalid, not merely ignored (fail closed).
                if !self.pow_solution.is_empty() {
                    return false;
                }
                match &self.auxpow {
                    // MERGED-MINING (AuxPoW): the PoW comes from a parent Bitcoin
                    // block that commits to THIS block's hash and meets Bloch's
                    // own target. Same SHA-256d work secures both chains.
                    Some(aux) if self.height >= AUXPOW_ACTIVATION_HEIGHT => {
                        aux.verify(self.block_hash(), self.header.bits).is_ok()
                    }
                    // AuxPoW carried before activation → invalid (fail closed).
                    Some(_) => false,
                    // NATIVE SHA-256d (Genesis-2): double SHA-256 over the
                    // 80-byte MiningHeader projection, Bitcoin semantics.
                    None => sha256d_pow_valid(
                        &self.header.pow_hash(),
                        &bits_to_target(self.header.bits),
                        self.height,
                    ),
                }
            }
        }
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
        // Genesis-2 continues emission from the carried height: a block at local
        // height h emits as if at absolute height h + CARRYOVER_SOURCE_HEIGHT.
        // `emission_height` is the identity on every other chain. Reading it here
        // (the consensus authority) guarantees no over-emission and the correct
        // halving schedule regardless of any miner-side mismatch.
        let eh = emission_height(self.height);
        let subsidy = tokenomics_v2::block_subsidy_sat(eh);
        let founder_delta = tokenomics_v2::founder_vesting_delta_sat(eh);
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
        shielded_transactions: Vec::new(),
            auxpow: None,
        }
}

// ── Genesis-2 (carry-over chain, SHA-256d PoW) ───────────────────────────────
//
// Genesis-2 is a NEW chain (ChainId::Genesis2Devnet, PowAlgorithm::Sha256d)
// that carries every balance of the live chain over from a published,
// independently reproducible UTXO snapshot. The genesis block's coinbase
// script_sig embeds the carry-over commitment in HUMAN-READABLE form (source
// height, UTXO count, snapshot-root prefix), so the chain's identity is bound
// to the ledger it carries and the binding is visible in any block explorer.
//
// The commitment constants below are the verified artifact produced by
// `bloch-snapshot-utxo` + `bloch-genesis2` (both refuse to emit on any
// verification failure):
//   height 413,743 · 413,743 UTXOs · 3,475,441,200 BLCH
//   root d3de5e51ee9dbbf36ed79981cbf66eb50a8894fc034610a20a5ee01eb9060637
//
// PoW is double SHA-256 over the 80-byte MiningHeader projection (the g2/T1
// path: Block::validate_pow's Sha256d arm). The genesis nonce is mined ONCE
// by `bloch-mine-genesis2`; the node must only VALIDATE — never mine — and
// refuse to start if validation fails, exactly like create_genesis_block +
// validate_pow today.
//
// Changing ANY of: the carry-over constants, GENESIS2_TIMESTAMP, GENESIS2_BITS,
// or the miner script_pubkey invalidates GENESIS2_NONCE (the script_sig text is
// derived from the carry-over constants and feeds the merkle root, which feeds
// the 80-byte header) — validate_pow then fails and the node must exit(1).

/// SHAKE-256 root of the raw snapshot file bytes (bloch-genesis2 output):
/// d3de5e51ee9dbbf36ed79981cbf66eb50a8894fc034610a20a5ee01eb9060637.
pub const GENESIS2_CARRYOVER_SNAPSHOT_ROOT: [u8; 32] = [
    0xd3, 0xde, 0x5e, 0x51, 0xee, 0x9d, 0xbb, 0xf3,
    0x6e, 0xd7, 0x99, 0x81, 0xcb, 0xf6, 0x6e, 0xb5,
    0x0a, 0x88, 0x94, 0xfc, 0x03, 0x46, 0x10, 0xa2,
    0x0a, 0x5e, 0xe0, 0x1e, 0xb9, 0x06, 0x06, 0x37,
];

/// Height of the live chain at which the snapshot was frozen.
pub const GENESIS2_CARRYOVER_SOURCE_HEIGHT: u64 = 413_743;

/// Number of UTXOs in the snapshot (== source height: one coinbase per block,
/// no spends — verified by bloch-genesis2 before it emitted these constants).
pub const GENESIS2_CARRYOVER_UTXO_COUNT: u64 = 413_743;

/// Total carried-over supply in sat (3,475,441,200 BLCH × 10⁸).
pub const GENESIS2_CARRYOVER_TOTAL_SAT: u128 = 347_544_120_000_000_000;

/// Genesis-2 timestamp (fixed at the mining ceremony, 2026-07-19).
pub const GENESIS2_TIMESTAMP: u64 = 1_784_500_000;

/// Genesis-2 compact difficulty bits. 0x1f00ffff → target 0x0000ffff… —
/// ~2⁻¹⁶ per double-SHA-256, mined in seconds. A production ceremony re-mines
/// at real difficulty; the VALIDATION path is identical at any bits.
pub const GENESIS2_BITS: u32 = 0x1d00ffff;

/// Genesis-2 difficulty retarget window (blocks). Bitcoin-style windowed retarget
/// (core::retarget_bits_g2), but SHORTER than Bitcoin's 2016 so a fresh chain
/// onboarding real (bought) SHA-256 hashrate ramps difficulty quickly instead of
/// flooding for a full 2016-block window at the anchor difficulty. 60 blocks ==
/// 30 min at the 30 s target.
pub const GENESIS2_RETARGET_WINDOW: u64 = 60;

/// The mined Genesis-2 nonce (bloch-mine-genesis2 ceremony output). Upper 32
/// bits are zero — only the low 32 enter the 80-byte mining header.
/// PLACEHOLDER 0 until the devnet ceremony bakes the real value; the pinned
/// test genesis2_genesis_block.rs FAILS while this is stale, and the node's
/// startup check must exit(1) — fail closed, never fail open.
pub const GENESIS2_NONCE: u64 = 1_798_023_308;

/// Expected canonical Genesis-2 block hash, for operator verification and the
/// fail-closed startup check. Canonical = miner script_pubkey
/// GENESIS2_MINER_SCRIPT_PUBKEY, all constants above. PLACEHOLDER (all-zero)
/// until the ceremony bakes the real value — see GENESIS2_NONCE.
pub const GENESIS2_EXPECTED_HASH: [u8; 32] = [
    0xa7, 0xb3, 0xde, 0x01, 0x09, 0x88, 0xac, 0xcb,
    0x58, 0x7a, 0x98, 0x71, 0x5c, 0x18, 0x1c, 0x8a,
    0x14, 0x34, 0x1a, 0x79, 0x7e, 0x96, 0xb1, 0xe1,
    0xcd, 0xa3, 0x19, 0xa7, 0xe7, 0x7b, 0x2b, 0xab,
];

/// Canonical Genesis-2 miner script_pubkey: the founder address hash-20
/// (bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073 → first 40 hex
/// chars after the HRP), matching main.rs's address_to_script_pubkey
/// convention for the existing genesis.
pub const GENESIS2_MINER_SCRIPT_PUBKEY: [u8; 20] = [
    0xe9, 0x86, 0xdb, 0x51, 0x49, 0xcf, 0xf7, 0x49,
    0x9b, 0x28, 0x2a, 0x04, 0x82, 0x72, 0xa0, 0x9a,
    0xff, 0x0a, 0xf4, 0xff,
];

/// The human-readable carry-over commitment carried in the Genesis-2 coinbase
/// script_sig. Derived from the carry-over constants at call time (never a
/// separately maintained literal), so the text can NEVER drift from the
/// constants it commits to. Format is the one bloch-genesis2 suggests:
///
///   `Bloch carry-over from height 413743: 413743 UTXOs, root d3de5e51ee9dbbf3...`
///
/// The 16-hex-char (8-byte) root prefix is for human readability; the FULL
/// root is enforced by the snapshot loader (fail closed), not by this text.
pub fn genesis2_coinbase_script_sig() -> Vec<u8> {
    format!(
        "Bloch carry-over from height {}: {} UTXOs, root {}...",
        GENESIS2_CARRYOVER_SOURCE_HEIGHT,
        GENESIS2_CARRYOVER_UTXO_COUNT,
        &hex::encode(GENESIS2_CARRYOVER_SNAPSHOT_ROOT)[..16],
    )
    .into_bytes()
}

/// Build the Genesis-2 genesis block with explicit header parameters.
///
/// This is the SINGLE construction path shared by the mining tool
/// (bloch-mine-genesis2, which grinds `nonce`) and the canonical
/// [`create_genesis2_block`] (which bakes the mined constants) — miner and
/// validator therefore agree byte-for-byte by construction.
///
/// Coinbase: single output paying `tokenomics_v2::block_subsidy_sat(0)` to
/// `miner_addr` (mirrors create_genesis_block_with_bits), script_sig =
/// [`genesis2_coinbase_script_sig`]. `pow_solution` is EMPTY — the Sha256d
/// arm of validate_pow rejects any non-empty witness (fail closed).
pub fn create_genesis2_block_with_params(
    miner_addr: &[u8],
    bits: u32,
    timestamp: u64,
    nonce: u64,
) -> Block {
    // ZERO-value anchor coinbase (consensus decision, 2026-07-20): the carried
    // ledger already holds the reward for its tip (absolute height
    // CARRYOVER_SOURCE_HEIGHT), so genesis must NOT mint again — it only anchors
    // the DAG. Emission then CONTINUES from local height 1 == absolute 413,744
    // (see `emission_height`), so there is no double-emission and no inflation.
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: genesis2_coinbase_script_sig(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value:         0,
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
            timestamp,
            bits,
            nonce,
        },
        transactions: vec![coinbase],
        blue_score: 0,
        height: 0,
        // SHA-256d chain: no Module-SIS witness, and validate_pow's Sha256d
        // arm REQUIRES pow_solution.is_empty() (witness smuggling rejected).
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

/// Creates the canonical Genesis-2 genesis block (height 0) from the baked
/// ceremony constants. The node must VALIDATE this (validate_pow — Sha256d
/// arm, requires node_chain_id() == Genesis2Devnet — plus a block_hash match
/// against GENESIS2_EXPECTED_HASH) and refuse to start on any failure,
/// exactly as main.rs does for create_genesis_block today.
pub fn create_genesis2_block(miner_addr: &[u8]) -> Block {
    create_genesis2_block_with_params(miner_addr, GENESIS2_BITS, GENESIS2_TIMESTAMP, GENESIS2_NONCE)
}

// ── Genesis-3 (MAINNET: fresh SHA-256d chain, carry-over ledger) ─────────────
//
// Genesis-3 is a brand-new chain (ChainId::Genesis3Mainnet, PowAlgorithm::
// Sha256d) that starts at height 0 with its OWN genesis block and ingests the
// SAME carry-over ledger as Genesis-2 as its opening balances. It is NOT a
// fork of Genesis-2: the genesis coinbase banner differs, so the genesis hash
// differs and the two chains can never confuse each other's blocks (the
// sighash chain-id additionally domain-separates every signature).
//
// Two deliberate differences from Genesis-2:
//   1. LITTLE-ENDIAN SHA-256d FROM HEIGHT 0. Genesis-2 started big-endian and
//      hard-forked to Bitcoin little-endian at SHA256D_LE_FORK_HEIGHT; every
//      off-the-shelf ASIC/cpuminer is little-endian, so a fresh chain has no
//      reason to relive that migration. See `sha256d_le_fork_height_for`.
//   2. Labeled MAINNET. No devnet caveat anywhere in a Genesis-3 node's
//      banners or logs.
//
// Everything else mirrors Genesis-2 byte-for-byte in KIND: zero-value anchor
// coinbase (the carried ledger already holds the reward for its tip — genesis
// must anchor WITHOUT re-minting), empty pow_solution, Bitcoin-style windowed
// retarget, emission offset by the carry-over source height.
//
// Changing ANY of: the carry-over constants, GENESIS3_TIMESTAMP, GENESIS3_BITS,
// or the miner script_pubkey invalidates GENESIS3_NONCE (the script_sig text
// feeds the merkle root, which feeds the 80-byte mining header).

/// Genesis-3 carries the SAME ledger as Genesis-2: identical snapshot file,
/// identical SHAKE-256 root. One blessed snapshot, two chains anchored to it.
pub const GENESIS3_CARRYOVER_SNAPSHOT_ROOT: [u8; 32] = GENESIS2_CARRYOVER_SNAPSHOT_ROOT;

/// Height of the source chain at which the snapshot was frozen (== Genesis-2's).
pub const GENESIS3_CARRYOVER_SOURCE_HEIGHT: u64 = 413_743;

/// Number of UTXOs in the snapshot (== source height; same set as Genesis-2).
pub const GENESIS3_CARRYOVER_UTXO_COUNT: u64 = 413_743;

/// Total carried-over supply in sat (3,475,441,200 BLCH × 10⁸; same as Genesis-2).
pub const GENESIS3_CARRYOVER_TOTAL_SAT: u128 = 347_544_120_000_000_000;

/// Genesis-3 timestamp. A FIXED value chosen for the Genesis-3 mainnet launch
/// (2026-07-29 relaunch decision), deliberately DISTINCT from
/// GENESIS2_TIMESTAMP (1_784_500_000) so the two genesis headers differ even
/// before the coinbase banner does. 1_785_500_000 ≈ 2026-08-01 00:53:20 UTC.
pub const GENESIS3_TIMESTAMP: u64 = 1_785_365_935;

/// Genesis-3 compact difficulty bits: same easy pow-limit start as Genesis-2
/// (0x1d00ffff == Bitcoin diff-1). The windowed retarget ramps real hashrate
/// quickly (see GENESIS3_RETARGET_WINDOW).
pub const GENESIS3_BITS: u32 = 0x1d00ffff;

/// Genesis-3 difficulty retarget window (blocks) — 60 blocks == 30 min at the
/// 30 s target, same as Genesis-2.
pub const GENESIS3_RETARGET_WINDOW: u64 = 60;

// The shared SHA-256d retarget path (`pow::genesis2_expected_bits` +
// `retarget_bits_g2`) is keyed on the GENESIS2_* constants and serves BOTH
// SHA-256d chains. That is sound ONLY while Genesis-3's window/anchor equal
// Genesis-2's — enforced at compile time here. If either assert ever fires,
// the retarget path must be made chain-aware before shipping.
const _: () = assert!(GENESIS3_RETARGET_WINDOW == GENESIS2_RETARGET_WINDOW);
const _: () = assert!(GENESIS3_BITS == GENESIS2_BITS);

/// The mined Genesis-3 nonce (grind_genesis3 ceremony output).
///
/// ⚠ PLACEHOLDER 0 until the ceremony bakes the real value: run
/// `cargo run --release --bin grind_genesis3` and paste the printed
/// constants here. While stale, `create_genesis3_block` PANICS (fail closed)
/// and a `--genesis3` node cannot start — never fail open.
pub const GENESIS3_NONCE: u64 = 10_751_391;

/// Expected canonical Genesis-3 block hash for the fail-closed startup check.
/// ⚠ PLACEHOLDER (all-zero) until the grind_genesis3 ceremony bakes the real
/// value. While all-zero, the hash pin is SKIPPED (the PoW check above still
/// fail-closes on the placeholder nonce); once nonzero it is ENFORCED.
pub const GENESIS3_EXPECTED_HASH: [u8; 32] = [
    0xc7, 0x52, 0x2d, 0x0e, 0xf2, 0x9f, 0xe6, 0x74,
    0x63, 0xbe, 0x45, 0xa8, 0x09, 0x5d, 0xb7, 0xf5,
    0xe2, 0x3b, 0x95, 0x42, 0xdd, 0xe8, 0x67, 0x36,
    0x3e, 0xa3, 0x13, 0x16, 0x47, 0xaf, 0xf3, 0x48,
];

/// Canonical Genesis-3 miner script_pubkey: the founder address hash-20, same
/// convention (and same founder wallet) as GENESIS2_MINER_SCRIPT_PUBKEY.
pub const GENESIS3_MINER_SCRIPT_PUBKEY: [u8; 20] = [
    0xe9, 0x86, 0xdb, 0x51, 0x49, 0xcf, 0xf7, 0x49,
    0x9b, 0x28, 0x2a, 0x04, 0x82, 0x72, 0xa0, 0x9a,
    0xff, 0x0a, 0xf4, 0xff,
];

/// The human-readable Genesis-3 coinbase banner. Like Genesis-2's it is
/// DERIVED from the carry-over constants at call time (can never drift), but
/// the text is DISTINCT — it names the chain ("BLOCH Genesis-3 mainnet") — so
/// the coinbase txid, merkle root, and therefore the genesis hash all differ
/// from Genesis-2's:
///
///   `BLOCH Genesis-3 mainnet carry-over from height 413743: 413743 UTXOs, root d3de5e51ee9dbbf3...`
///
/// (Pure ASCII, like Genesis-2's banner, so every explorer renders it.)
///
/// The 16-hex-char (8-byte) root prefix is for human readability; the FULL
/// root is enforced by the snapshot loader (fail closed), not by this text.
pub fn genesis3_coinbase_script_sig() -> Vec<u8> {
    format!(
        "BLOCH Genesis-3 mainnet carry-over from height {}: {} UTXOs, root {}...",
        GENESIS3_CARRYOVER_SOURCE_HEIGHT,
        GENESIS3_CARRYOVER_UTXO_COUNT,
        &hex::encode(GENESIS3_CARRYOVER_SNAPSHOT_ROOT)[..16],
    )
    .into_bytes()
}

/// Build the Genesis-3 genesis block with explicit header parameters.
///
/// The SINGLE construction path shared by the grinder (`grind_genesis3`,
/// which grinds `nonce`) and the canonical [`create_genesis3_block`] (which
/// bakes the ceremony constants) — grinder and validator agree byte-for-byte
/// by construction. Mirrors [`create_genesis2_block_with_params`] exactly:
/// ZERO-value anchor coinbase (the carried ledger already holds the reward
/// for its tip; genesis must NOT re-mint — emission continues from local
/// height 1 == absolute GENESIS3_CARRYOVER_SOURCE_HEIGHT + 1 via
/// `emission_height`), script_sig = [`genesis3_coinbase_script_sig`],
/// `pow_solution` EMPTY (the Sha256d arm of validate_pow rejects any
/// non-empty witness — fail closed).
pub fn create_genesis3_block_with_params(
    miner_addr: &[u8],
    bits: u32,
    timestamp: u64,
    nonce: u64,
) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: genesis3_coinbase_script_sig(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value:         0,
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
            timestamp,
            bits,
            nonce,
        },
        transactions: vec![coinbase],
        blue_score: 0,
        height: 0,
        // SHA-256d chain: no Module-SIS witness (validate_pow's Sha256d arm
        // REQUIRES pow_solution.is_empty()).
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

/// Creates the canonical Genesis-3 genesis block (height 0) from the baked
/// ceremony constants — and VERIFIES it before returning (fail closed):
///
///   1. The header's SHA-256d PoW must meet GENESIS3_BITS under the EXACT
///      rule a Genesis-3 validator applies at height 0 — little-endian from
///      genesis (`sha256d_pow_valid_for_chain(Genesis3Mainnet, …, 0)`, the
///      same function `Block::validate_pow` routes through on a G3 node).
///   2. If GENESIS3_EXPECTED_HASH is non-zero, the block hash must equal it.
///
/// While GENESIS3_NONCE/GENESIS3_EXPECTED_HASH are the pre-ceremony
/// placeholders this PANICS — a `--genesis3` node refuses to start until the
/// grind_genesis3 output is baked in. Once real values are pasted, any drift
/// in ANY baked constant is caught here before a single byte of chain state
/// is written.
pub fn create_genesis3_block(miner_addr: &[u8]) -> Block {
    let genesis = create_genesis3_block_with_params(
        miner_addr, GENESIS3_BITS, GENESIS3_TIMESTAMP, GENESIS3_NONCE,
    );
    assert!(
        sha256d_pow_valid_for_chain(
            ChainId::Genesis3Mainnet,
            &genesis.header.pow_hash(),
            &bits_to_target(GENESIS3_BITS),
            0,
        ),
        "Genesis-3 genesis PoW does not meet GENESIS3_BITS under the \
         little-endian-from-height-0 rule. If GENESIS3_NONCE is still the \
         pre-ceremony placeholder, run `cargo run --release --bin \
         grind_genesis3` and bake the printed constants into core/mod.rs. \
         Refusing to construct an invalid genesis (fail closed).",
    );
    if GENESIS3_EXPECTED_HASH != [0u8; 32] {
        assert!(
            genesis.block_hash() == GENESIS3_EXPECTED_HASH,
            "Genesis-3 block hash != GENESIS3_EXPECTED_HASH — a baked constant \
             drifted. Refusing to construct (fail closed).",
        );
    }
    genesis
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

/// Genesis-2 SHA-256d PoW endianness hard fork (grandfathered by height).
///
/// The legacy rule compared the raw double-SHA256 output BIG-ENDIAN
/// (`hash[0]` as the most-significant byte). Every off-the-shelf SHA-256
/// ASIC and cpuminer instead treats the double-SHA256 output as a
/// LITTLE-ENDIAN 256-bit integer (Bitcoin's convention — the hash read
/// reversed). Under the legacy rule no standard miner's share or block ever
/// validated ("invalid PoW"), so the chain was not actually ASIC-mineable.
///
/// At and above this height the comparison switches to Bitcoin little-endian,
/// making the chain mineable by standard hardware. Blocks BELOW this height
/// keep the legacy big-endian rule, so the existing chain stays valid — this
/// is a coordinated flag-day hard fork: every Genesis-2 node must run a binary
/// with this rule before the chain reaches this height.
pub const SHA256D_LE_FORK_HEIGHT: u64 = 2400;

/// The SHA-256d little-endian fork height for a given chain — the SINGLE
/// per-chain source of truth for PoW-comparison endianness, read by the
/// validator ([`sha256d_pow_valid`] via `node_chain_id()`), the miner
/// (`src/pow::mine_pow_parallel`), and the Genesis-3 grinder. Exhaustive over
/// [`ChainId`] with no wildcard arm: adding a chain without deciding its
/// endianness rule is a compile error, by design.
///
/// * Genesis-2 (and the SIS chains, where this value is never consulted —
///   they are not SHA-256d): the historical [`SHA256D_LE_FORK_HEIGHT`]
///   flag-day (big-endian below, Bitcoin little-endian at/above).
/// * Genesis-3 mainnet: **0** — little-endian (ASIC-native) from the genesis
///   block itself. A fresh chain has no legacy big-endian blocks to
///   grandfather, so ASIC shares validate from block 1 (and the genesis
///   ceremony grinds under the same rule).
pub const fn sha256d_le_fork_height_for(id: ChainId) -> u64 {
    match id {
        ChainId::Mainnet         => SHA256D_LE_FORK_HEIGHT,
        ChainId::Testnet         => SHA256D_LE_FORK_HEIGHT,
        ChainId::Genesis2Devnet  => SHA256D_LE_FORK_HEIGHT,
        ChainId::Genesis3Mainnet => 0,
    }
}

/// Chain-explicit SHA-256d PoW check. Below the chain's LE fork height
/// ([`sha256d_le_fork_height_for`]): the legacy big-endian comparison.
/// At/above: Bitcoin's little-endian convention (reverse the double-SHA256
/// output, then compare big-endian against the target), so standard SHA-256
/// miners' work validates. The block's `pow_hash` itself is UNCHANGED (still
/// the raw double-SHA256, preserving block identity and the parents
/// commitment) — only the target comparison endianness moves.
///
/// This chain-explicit form exists so genesis builders/grinders can verify
/// under a NAMED chain's rule without depending on the process-wide chain-id
/// pin; consensus call sites use [`sha256d_pow_valid`], which routes through
/// `node_chain_id()`.
pub fn sha256d_pow_valid_for_chain(
    id: ChainId,
    pow_hash: &[u8; 32],
    target: &[u8; 32],
    height: u64,
) -> bool {
    if height >= sha256d_le_fork_height_for(id) {
        let mut rev = *pow_hash;
        rev.reverse();
        hash_meets_target(&rev, target)
    } else {
        hash_meets_target(pow_hash, target)
    }
}

/// Height-gated SHA-256d PoW check for THIS node's chain (the consensus
/// entry point — `Block::validate_pow`'s Sha256d arm and both stratum share
/// paths route through it). Behaviour per chain is defined by
/// [`sha256d_le_fork_height_for`]: unchanged for Genesis-2 (flag-day at
/// [`SHA256D_LE_FORK_HEIGHT`]); little-endian from height 0 on Genesis-3.
pub fn sha256d_pow_valid(pow_hash: &[u8; 32], target: &[u8; 32], height: u64) -> bool {
    sha256d_pow_valid_for_chain(node_chain_id(), pow_hash, target, height)
}

/// Convert a floating-point difficulty into a 256-bit target (big-endian),
/// Bitcoin diff-1 convention: `target(d) = diff1_target / d`, where
/// `diff1_target = bits_to_target(0x1d00ffff)` (which coincides with the
/// Genesis-2 pow-limit). A LARGER `d` yields a SMALLER target (harder to
/// meet); `d < 1` yields a target EASIER than diff-1 — exactly what small /
/// CPU miners need for frequent shares.
///
/// This is the share-target side of the stratum vardiff: the block's `bits`
/// are NEVER derived from this — consensus keeps using `template.bits`. This
/// only produces the per-miner accept/reject bound.
///
/// Fixed-point millionths keep precision and avoid U256 overflow: `diff1` is
/// ~2^224, so `diff1 * 1e6` is ~2^244, comfortably inside a U256. `diff` is
/// clamped to a strictly-positive, finite value (>= 1e-6 effective) so the
/// integer denominator is always >= 1 and the division never traps.
pub fn difficulty_to_target(diff: f64) -> [u8; 32] {
    use primitive_types::U256;
    // Scale to integer millionths; reject non-finite / sub-millionth inputs
    // by flooring the denominator at 1 (== the easiest representable target).
    let scaled = (diff.max(f64::MIN_POSITIVE) * 1_000_000.0).round();
    let d: u128 = if scaled.is_finite() && scaled >= 1.0 { scaled as u128 } else { 1 };
    let d = d.max(1);
    let diff1 = U256::from_big_endian(&bits_to_target(0x1d00ffff));
    let t = diff1 * U256::from(1_000_000u64) / U256::from(d);
    // primitive-types 0.13: to_big_endian() returns [u8; 32] directly.
    t.to_big_endian()
}

/// Difficulty implied by compact `bits`, Bitcoin diff-1 convention:
/// `difficulty = diff1_target / target(bits)`. The live Genesis-2 chain sits
/// ~4.35 at nbits 0x1c3acb93; a fresh devnet at 0x1d00ffff returns exactly
/// 1.0. Used as the network difficulty and, critically, as the HARD CAP on
/// per-miner share difficulty (a share is never harder than a real block).
///
/// Computed by scaling the target ratio by 1e6 in integer (U256) space and
/// dividing back into f64, so difficulties > 1 keep their fractional part
/// instead of truncating. For regtest-easy targets (difficulty far below
/// 1e-6) this floors to 0.0 — acceptable, because the submit path additionally
/// clamps the share target to be no harder than the block target in target
/// space, so correctness never depends on this value's precision at the
/// sub-millionth extreme.
pub fn difficulty_from_bits(bits: u32) -> f64 {
    use primitive_types::U256;
    let diff1  = U256::from_big_endian(&bits_to_target(0x1d00ffff));
    let target = U256::from_big_endian(&bits_to_target(bits));
    if target.is_zero() {
        return f64::INFINITY;
    }
    let scaled = diff1 * U256::from(1_000_000u64) / target;
    // scaled == difficulty * 1e6. For any realistic consensus `bits` this is
    // far below u128::MAX; guard the extreme anyway so we never panic.
    if scaled > U256::from(u128::MAX) {
        return f64::INFINITY;
    }
    scaled.as_u128() as f64 / 1_000_000.0
}

#[cfg(test)]
mod vardiff_target_tests {
    use super::*;

    #[test]
    fn diff1_roundtrips_to_pow_limit() {
        // difficulty 1.0 must reproduce the diff-1 / pow-limit target exactly.
        assert_eq!(difficulty_to_target(1.0), bits_to_target(0x1d00ffff));
        // and the inverse: diff-1 bits == difficulty 1.0.
        assert!((difficulty_from_bits(0x1d00ffff) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn higher_difficulty_is_a_smaller_target() {
        // Monotonicity: d up => target down (harder).
        let a = difficulty_to_target(0.001);
        let b = difficulty_to_target(0.01);
        let c = difficulty_to_target(1.0);
        let d = difficulty_to_target(4.35);
        assert!(hash_meets_target(&c, &a), "target(1.0) <= target(0.001)");
        assert!(hash_meets_target(&c, &b), "target(1.0) <= target(0.01)");
        assert!(hash_meets_target(&d, &c), "target(4.35) <= target(1.0)");
    }

    #[test]
    fn share_target_never_harder_than_block_when_diff_at_or_below_net() {
        // The core consensus-firewall invariant: for share_difficulty <=
        // net_difficulty, share_target >= block_target (share never harder).
        for &bits in &[0x1d00ffff_u32, 0x1c3acb93, 0x1e00ffff] {
            let net = difficulty_from_bits(bits);
            let block_target = bits_to_target(bits);
            // pick a share difficulty at and below the cap
            for frac in [1.0_f64, 0.5, 0.1, 0.01] {
                let share_target = difficulty_to_target(net * frac);
                // share_target must be >= block_target: block-meeting hash
                // (== block_target) must also meet share_target.
                assert!(hash_meets_target(&block_target, &share_target),
                    "share_target < block_target for bits={:#x} frac={}", bits, frac);
            }
        }
    }

    #[test]
    fn live_bits_report_expected_network_difficulty() {
        // nbits 0x1c3acb93 is the live chain sample — difficulty ~4.35.
        let d = difficulty_from_bits(0x1c3acb93);
        assert!(d > 4.0 && d < 5.0, "expected ~4.35, got {}", d);
    }

    #[test]
    fn le_fork_gating_flips_endianness_at_height() {
        // A hash that is LE-small (Bitcoin/ASIC valid) but BE-large (legacy
        // invalid): high leading byte, all-zero trailing bytes. This is exactly
        // the shape a real SHA-256 miner produces and the legacy rule rejected.
        let target = bits_to_target(0x1d00ffff);
        let mut h = [0x11u8; 32];
        h[0] = 0xff;                       // BE most-significant byte huge
        h[31] = 0x00; h[30] = 0x00;        // LE most-significant bytes zero
        h[29] = 0x00; h[28] = 0x00;

        // Pre-fork (legacy big-endian): hash[0]=0xff > target[0]=0x00 -> reject.
        assert!(!sha256d_pow_valid(&h, &target, SHA256D_LE_FORK_HEIGHT - 1),
            "legacy rule must reject an LE-small / BE-large hash");
        // At/after the fork (Bitcoin little-endian, hash reversed): accepts.
        assert!(sha256d_pow_valid(&h, &target, SHA256D_LE_FORK_HEIGHT),
            "post-fork rule must accept a standard little-endian hash");
        // And the boundary is exact.
        assert!(!sha256d_pow_valid(&h, &target, SHA256D_LE_FORK_HEIGHT - 1));
        assert!(sha256d_pow_valid(&h, &target, SHA256D_LE_FORK_HEIGHT + 1));
    }
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

/// Genesis-2 Bitcoin-style retarget: identical math to [`retarget_bits`], but the
/// pow-limit (easiest allowed target / lowest difficulty) is GENESIS2_BITS, the
/// chain's own anchor, not the Module-SIS GENESIS_BITS. Called every
/// DIFFICULTY_WINDOW blocks with the wall time elapsed over that window; miner and
/// validator both route through it so their expected `bits` agree.
pub fn retarget_bits_g2(old_bits: u32, elapsed_secs: u64) -> u32 {
    use primitive_types::U256;

    let target_secs = TARGET_BLOCK_TIME * GENESIS2_RETARGET_WINDOW;
    let clamped = elapsed_secs
        .max(target_secs / MAX_RETARGET_FACTOR)
        .min(target_secs * MAX_RETARGET_FACTOR);

    let old       = U256::from_big_endian(&bits_to_target(old_bits));
    let pow_limit = U256::from_big_endian(&bits_to_target(GENESIS2_BITS));

    let new = (old * U256::from(clamped) / U256::from(target_secs)).min(pow_limit);
    target_to_bits(&new.to_big_endian())
}

fn target_to_bits(target: &[u8; 32]) -> u32 {
    let leading = target.iter().take_while(|&&b| b == 0).count();
    let mut exp = 32 - leading;
    if exp < 3 { return 0x03000001; }
    let start = 32 - exp;
    let mut mant = ((target[start] as u32) << 16)
             | ((target.get(start + 1).copied().unwrap_or(0) as u32) << 8)
             | (target.get(start + 2).copied().unwrap_or(0) as u32);
    // Bitcoin compact is SIGNED: if the mantissa's top bit is set (>= 0x800000),
    // shift it down a byte and bump the exponent so the encoding is never mistaken
    // for a negative target. Without this, a value like 0x1effff00 (mantissa
    // 0xffff00) round-trips through the SIS sign-checking bits_to_target to a ZERO
    // target → bits_to_work returns u128::MAX → blue_work overflow (consensus:1029).
    if mant & 0x0080_0000 != 0 {
        mant >>= 8;
        exp += 1;
    }
    ((exp as u32) << 24) | (mant & 0x00ff_ffff)
}

// ── Soft fork SF-1 tests: height-gated residual width in validate_pow ────────
#[cfg(test)]
mod sf1_tests {
    use super::*;
    use bloch_sis_pow::solver::{mine, MineConfig, MineResult};
    use bloch_sis_pow::{CANONICAL_RESIDUAL_COEFFS, TESTNET_RESIDUAL_COEFFS};

    /// Fixed header for the validate_pow gating tests. `pow_preimage()` does
    /// not include the nonce or the block height, so ONE mined solution can be
    /// attached to blocks claiming different heights — exactly what we need to
    /// isolate the height gate.
    fn sf1_test_header() -> BlockHeader {
        BlockHeader {
            version:     1,
            parents:     vec![],
            merkle_root: MerkleRoot([0u8; 32]),
            timestamp:   1_777_000_000,
            bits:        GENESIS_BITS, // near-max aux target: mining gated by the residual only
            nonce:       0,
        }
    }

    fn sf1_block(header: BlockHeader, height: u64, solution: &[i32]) -> Block {
        Block {
            header,
            transactions: vec![],
            blue_score: 0,
            height,
            pow_solution: solution.to_vec(),
            shielded_transactions: vec![],
            auxpow: None,
        }
    }

    #[test]
    fn block_auxpow_trailer_round_trips_and_none_is_byte_compatible() {
        let mut blk = create_genesis2_block(&[0u8; 20]);

        // None: no trailer — round-trips and parses back to None.
        let none_bytes = blk.to_bitcoin_bytes();
        let back = Block::from_bitcoin_bytes(&none_bytes).expect("None round-trips");
        assert!(back.auxpow.is_none());

        // Some: attach an AuxPoW (serialization does not validate PoW).
        let aux = auxpow::AuxPow {
            parent_header: vec![7u8; 80],
            coinbase_tx: b"\xfa\xbe\x6d\x6d coinbase".to_vec(),
            coinbase_branch: vec![[1u8; 32], [2u8; 32]],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        blk.auxpow = Some(aux.clone());
        let some_bytes = blk.to_bitcoin_bytes();
        // Exactly one presence byte + the encoded trailer longer than None.
        assert_eq!(some_bytes.len(), none_bytes.len() + 1 + aux.to_bytes().len());
        let back2 = Block::from_bitcoin_bytes(&some_bytes).expect("Some round-trips");
        assert_eq!(back2.auxpow, Some(aux));
        // The None encoding is a strict prefix of nothing extra — genesis-preserving.
        assert_eq!(&some_bytes[..none_bytes.len()], &none_bytes[..]);
    }

    /// END-TO-END merged-mining acceptance at the BLOCK level: the pool commits
    /// to the REAL `block_hash()`, and the AuxPoW the node checks is exactly the
    /// call `validate_pow` makes in its active arm — `aux.verify(block_hash(),
    /// header.bits)` (core/mod.rs, PowAlgorithm::Sha256d, Some(aux) at/above
    /// AUXPOW_ACTIVATION_HEIGHT). Proves the pool↔node contract binds to the
    /// block's true identity, survives the on-wire (bitcoin) serialization, and
    /// rejects any tamper to the block header. Runs with NO mining and NO chain
    /// state, so it is deterministic and mainnet-safe (activation is untouched).
    #[test]
    fn merged_mined_block_binds_to_real_block_hash_and_survives_serialization() {
        use auxpow::{coinbase_merkle_branch, merge_mining_commitment, AuxPow, AuxPowError};
        // Bitcoin txid = double-SHA256, internal byte order (matches auxpow).
        fn dsha(b: &[u8]) -> [u8; 32] {
            use sha2::{Digest, Sha256};
            Sha256::digest(Sha256::digest(b)).into()
        }

        // A real SHA-256d (Genesis-2 kind) block is the aux chain block: empty
        // pow_solution, so validate_pow routes to the Sha256d arm.
        let mut blk = create_genesis2_block(&[0u8; 20]);
        blk.height = 5_600; // a post-activation height (rehearsal semantics)
        blk.header.bits = 0x20ff_ffff; // easy parent target → no mining needed
        let aux_hash = blk.block_hash(); // the REAL Bloch block identity

        // POOL: embed the merge-mining commitment in the parent Bitcoin coinbase.
        let mut coinbase = b"btc-coinbase-prefix".to_vec();
        coinbase.extend_from_slice(&merge_mining_commitment(aux_hash));
        coinbase.extend_from_slice(b"btc-coinbase-suffix");
        let coinbase_txid = dsha(&coinbase);
        // Single-tx parent: merkle root == coinbase txid, empty branch.
        assert!(coinbase_merkle_branch(&[coinbase_txid], 0).is_empty());
        let mut parent_header = [0u8; 80];
        parent_header[0..4].copy_from_slice(&2i32.to_le_bytes()); // version
        parent_header[36..68].copy_from_slice(&coinbase_txid); // merkle root
        parent_header[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // time
        parent_header[72..76].copy_from_slice(&0x20ff_ffffu32.to_le_bytes()); // bits

        let aux = AuxPow {
            parent_header: parent_header.to_vec(),
            coinbase_tx: coinbase,
            coinbase_branch: vec![],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        blk.auxpow = Some(aux.clone());

        // (1) The EXACT expression validate_pow runs when AuxPoW is active.
        assert_eq!(
            blk.auxpow.as_ref().unwrap().verify(blk.block_hash(), blk.header.bits),
            Ok(())
        );

        // (2) The AuxPoW survives the on-wire bitcoin serialization, and the
        // deserialized block still binds to the same identity + verifies.
        let bytes = blk.to_bitcoin_bytes();
        let back = Block::from_bitcoin_bytes(&bytes).expect("block round-trips");
        assert_eq!(back.auxpow, Some(aux));
        assert_eq!(back.block_hash(), aux_hash, "identity preserved across serde");
        assert_eq!(
            back.auxpow.as_ref().unwrap().verify(back.block_hash(), back.header.bits),
            Ok(())
        );

        // (3) Tamper with ANY header field → block_hash changes → the parent's
        // commitment no longer matches → rejected (fail closed).
        let mut tampered = blk.clone();
        tampered.header.timestamp ^= 1;
        assert_ne!(tampered.block_hash(), aux_hash);
        assert_eq!(
            tampered.auxpow.as_ref().unwrap().verify(tampered.block_hash(), tampered.header.bits),
            Err(AuxPowError::AuxRootMismatch)
        );
    }

    /// Pre-searched start nonce whose FIRST 4096-candidate window contains a
    /// k=8-valid solution for `sf1_test_header().pow_preimage()` at the
    /// GENESIS_BITS target. A cold k=8 mine needs ~2^24 candidates (too slow
    /// for a debug unit test); the solver is deterministic given
    /// (header, start_nonce), so the window was searched offline. If solver
    /// internals change, re-run `sf1_search_fast_k8_start_nonce_for_block`
    /// (`cargo test --release -p bloch-crypto -- --ignored --nocapture`)
    /// and update this constant.
    const K8_BLOCK_START_NONCE: u64 = 6158; // found at attempt 3424 of 4096

    fn mine_window(k: usize, start_nonce: u64, budget: u64) -> Result<MineResult, bloch_sis_pow::MineError> {
        let header = sf1_test_header();
        let target = bloch_sis_pow::bits_to_target(header.bits);
        mine(
            &header.pow_preimage(),
            &target,
            &MineConfig {
                start_nonce,
                candidates_per_nonce: 4096,
                max_total_attempts: budget,
                residual_coeffs: k,
            },
            None,
        )
    }

    #[test]
    fn canonical_residual_coeffs_difficulty_driven_ramp() {
        // Spec mirror of the intended band mapping.
        fn band(work: u128) -> usize {
            if work >= K_WORK_8 { 8 } else if work >= K_WORK_7 { 7 }
            else if work >= K_WORK_6 { 6 } else if work >= K_WORK_5 { 5 } else { 4 }
        }
        let a = K_RULE_ACTIVATION_HEIGHT;
        // Below activation: ALWAYS k=4, whatever the difficulty (upgrade-safe, no fork).
        for &bits in &[0x203fffc0u32, 0x1d00ffff, 0x0500ffff, u32::MAX] {
            assert_eq!(canonical_residual_coeffs(0, bits), TESTNET_RESIDUAL_COEFFS);
            assert_eq!(canonical_residual_coeffs(a - 1, bits), TESTNET_RESIDUAL_COEFFS);
        }
        // At/above activation: k tracks the block's own ASERT difficulty (bits→work).
        for &bits in &[0x203fffc0u32, 0x1f00ffff, 0x1d00ffff, 0x1b00ffff, 0x0500ffff] {
            let w = bits_to_work(bits);
            assert_eq!(canonical_residual_coeffs(a, bits), band(w),
                "bits {:#010x} → work {} → wrong k", bits, w);
            assert_eq!(canonical_residual_coeffs(a + 50_000, bits), band(w));
        }
        // Concrete anchors: today's live difficulty sits at k=4; a very hard target reaches k=8.
        assert_eq!(canonical_residual_coeffs(a, 0x203fffc0), 4, "current live difficulty must be k=4");
        assert_eq!(canonical_residual_coeffs(a, 0x0500ffff), 8, "a very hard target reaches full k=8");
        // Monotone: raising difficulty never lowers k.
        assert!(canonical_residual_coeffs(a, 0x1b00ffff) >= canonical_residual_coeffs(a, 0x203fffc0));
        assert_eq!(TESTNET_RESIDUAL_COEFFS, 4);
        assert_eq!(CANONICAL_RESIDUAL_COEFFS, 8);
    }

    #[test]
    fn validate_pow_k4_witness_rejected_once_the_ramp_lifts_k() {
        // The test header's difficulty selects k>4 above the rule activation. A
        // k=4-only witness (one that FAILS that higher band) stays valid BELOW
        // activation (k=4) but is rejected at/above, where the difficulty-driven
        // ramp has lifted k — the gate tightens exactly as difficulty rises,
        // while the pre-activation history keeps validating (k=8 ⊃ k=4 subset).
        let header = sf1_test_header();
        let k_above = canonical_residual_coeffs(K_RULE_ACTIVATION_HEIGHT, header.bits);
        assert!(
            k_above > TESTNET_RESIDUAL_COEFFS,
            "this test needs the header's difficulty to select k>4 above activation (got k={k_above})",
        );
        let target = bloch_sis_pow::bits_to_target(header.bits);
        // Mine k=4 witnesses until one FAILS the higher band k_above (~7/8 do).
        let mut only_k4 = None;
        for i in 0..16u64 {
            let r = mine_window(TESTNET_RESIDUAL_COEFFS, i * 1_000_003, 500_000)
                .expect("k=4 testnet regime must be brute-force mineable");
            if bloch_sis_pow::verify_regime(
                &header.pow_preimage(), r.nonce, &r.solution, &target, k_above,
            ).is_err() {
                only_k4 = Some(r);
                break;
            }
        }
        let r = only_k4.expect("no k=4-only witness in 16 windows — gate broken");
        let mut mh = header;
        mh.nonce = r.nonce;

        // Valid below activation (k=4) and at height 0.
        assert!(sf1_block(mh.clone(), K_RULE_ACTIVATION_HEIGHT - 1, &r.solution).validate_pow(),
            "k=4 witness must stay valid below activation");
        assert!(sf1_block(mh.clone(), 0, &r.solution).validate_pow(),
            "height-0 k=4 block must remain valid");
        // Rejected at/above — the ramp lifted k past 4.
        assert!(!sf1_block(mh.clone(), K_RULE_ACTIVATION_HEIGHT, &r.solution).validate_pow(),
            "k=4-only witness must be rejected at activation once k>4");
        assert!(!sf1_block(mh, K_RULE_ACTIVATION_HEIGHT + 1, &r.solution).validate_pow(),
            "k=4-only witness must be rejected above activation");
    }

    #[test]
    fn validate_pow_accepts_k8_witness_at_every_height() {
        // A k=8-mined witness satisfies every lower k (prefix subset), so it
        // validates at ANY height regardless of which k the ramp selects — no
        // partition between nodes at different points on the ramp.
        let r = mine_window(CANONICAL_RESIDUAL_COEFFS, K8_BLOCK_START_NONCE, 4096)
            .expect("pinned window must contain a k=8 solution — if solver \
                     internals changed, re-run sf1_search_fast_k8_start_nonce_for_block");

        let mut mined_header = sf1_test_header();
        mined_header.nonce = r.nonce;

        for h in [0u64, K_RULE_ACTIVATION_HEIGHT - 1, K_RULE_ACTIVATION_HEIGHT, K_RULE_ACTIVATION_HEIGHT + 1] {
            assert!(
                sf1_block(mined_header.clone(), h, &r.solution).validate_pow(),
                "k=8 witness must validate at height {h} (subset property)",
            );
        }
        // Tampered nonce breaks it at any height.
        let mut bad_header = mined_header;
        bad_header.nonce = r.nonce.wrapping_add(1);
        let bad = sf1_block(bad_header, K_RULE_ACTIVATION_HEIGHT, &r.solution);
        assert!(!bad.validate_pow());
    }

    /// Offline search utility for `K8_BLOCK_START_NONCE`. Run:
    ///
    /// ```text
    /// cargo test --release -p bloch-crypto -- --ignored --nocapture sf1_search
    /// ```
    #[test]
    #[ignore = "offline search utility — run in --release with --nocapture to (re)pin the fast k=8 start nonce"]
    fn sf1_search_fast_k8_start_nonce_for_block() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let found = AtomicU64::new(u64::MAX);
        let stop = AtomicBool::new(false);
        let next = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) {
                scope.spawn(|| loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let n = next.fetch_add(1, Ordering::Relaxed);
                    if mine_window(CANONICAL_RESIDUAL_COEFFS, n, 4096).is_ok() {
                        found.fetch_min(n, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                });
            }
        });
        let n = found.load(Ordering::Relaxed);
        assert_ne!(n, u64::MAX, "search aborted without a hit");
        let r = mine_window(CANONICAL_RESIDUAL_COEFFS, n, 4096)
            .expect("re-mining the found window must reproduce");
        println!(
            "SF-1 fast k=8 window [bloch-crypto K8_BLOCK_START_NONCE]: \
             start_nonce = {n} (nonce = {}, found at attempt {} of 4096)",
            r.nonce, r.attempts
        );
    }
}

// ── Roadmap #8 §1 — chain-id sighash replay regression ───────────────────────
#[cfg(test)]
mod chain_id_tests {
    use super::*;

    fn two_input_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TxInput { prev_txid: [3u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff },
                TxInput { prev_txid: [4u8; 32], prev_index: 1, script_sig: vec![], sequence: 0xffff_ffff },
            ],
            outputs: vec![TxOutput { value: 42, script_pubkey: vec![9u8; 20] }],
            locktime: 0,
        }
    }

    #[test]
    fn terminal_height_only_retires_genesis3() {
        // Exhaustive by construction; this pins the intent so a future chain-id
        // cannot quietly inherit a terminal height it was never meant to have.
        assert_eq!(terminal_height(ChainId::Genesis3Mainnet), Some(50_000));
        assert_eq!(terminal_height(ChainId::Mainnet), None);
        assert_eq!(terminal_height(ChainId::Testnet), None);
        assert_eq!(terminal_height(ChainId::Genesis2Devnet), None);
    }

    #[test]
    fn the_terminal_height_itself_is_valid() {
        // Off-by-one here would either lose the last block or admit one past
        // the snapshot — and the snapshot is taken AT the terminal height.
        let t = GENESIS3_TERMINAL_HEIGHT;
        let past = |h: u64| match terminal_height(ChainId::Genesis3Mainnet) {
            Some(x) => h > x,
            None => false,
        };
        assert!(!past(t - 1));
        assert!(!past(t), "a altura terminal e o ultimo bloco valido");
        assert!(past(t + 1));
        assert!(past(u64::MAX));
    }

    #[test]
    fn terminal_height_is_still_ahead_of_the_live_chain() {
        // The rule must ship INERT: at the time of writing the chain is near
        // height 40,400, so every block validates exactly as before. If this
        // ever fails, the constant was set at or below the tip and the release
        // would retroactively invalidate live history.
        assert!(GENESIS3_TERMINAL_HEIGHT > 40_424,
            "altura terminal nao pode estar no passado da cadeia viva");
    }

    #[test]
    fn chain_id_registry_values() {
        assert_eq!(ChainId::Mainnet.to_u32(), 0xB10C_0001);
        assert_eq!(ChainId::Testnet.to_u32(), 0xB10C_0002);
        assert_eq!(ChainId::Genesis3Mainnet.to_u32(), 0xB10C_0004);
        assert_eq!(ChainId::Mainnet.to_le_bytes(), [0x01, 0x00, 0x0C, 0xB1]);
        // Genesis-3: SHA-256d, carry-over required, little-endian from h0.
        assert_eq!(pow_algorithm(ChainId::Genesis3Mainnet), PowAlgorithm::Sha256d);
        assert!(chain_requires_carryover(ChainId::Genesis3Mainnet));
        assert_eq!(sha256d_le_fork_height_for(ChainId::Genesis3Mainnet), 0);
        assert_eq!(sha256d_le_fork_height_for(ChainId::Genesis2Devnet), SHA256D_LE_FORK_HEIGHT);
        assert_eq!(ChainId::for_network(crate::address::Network::Mainnet), ChainId::Mainnet);
        assert_eq!(ChainId::for_network(crate::address::Network::Testnet), ChainId::Testnet);
    }

    #[test]
    fn sighash_is_domain_and_chain_separated() {
        let tx = two_input_tx();
        // Distinct per chain-id.
        assert_ne!(tx.sighash(0, ChainId::Mainnet), tx.sighash(0, ChainId::Testnet),
                   "mainnet and testnet must sign different digests");
        // Still distinct per input index (v1 property preserved).
        assert_ne!(tx.sighash(0, ChainId::Mainnet), tx.sighash(1, ChainId::Mainnet));
    }

    /// The core invariant (design §4.3.4): a signature valid under Mainnet MUST
    /// be rejected when verified under Testnet — cross-chain replay ⇒ false.
    #[test]
    fn cross_chain_id_replay_is_rejected() {
        let tx = two_input_tx();
        let (pk, sk) = crate::crypto::generate_keypair();

        let h_main = tx.sighash(0, ChainId::Mainnet);
        let sig = crate::crypto::sign(&sk, &h_main).unwrap();

        // Same chain: accepts.
        assert!(crate::crypto::verify(&pk, &h_main, &sig),
                "a correctly chain-id'd signature must verify");
        // Replay onto testnet: the verifier recomputes with the Testnet domain →
        // a different digest → both ML-DSA and Falcon fail.
        let h_test = tx.sighash(0, ChainId::Testnet);
        assert!(!crate::crypto::verify(&pk, &h_test, &sig),
                "cross-chain-id replay MUST be rejected");
    }
}

// ── Roadmap #8 §3 — mainnet activation-height CI guard ───────────────────────
// Only compiles under the `mainnet` marker feature (which must be declared in
// crates/bloch-crypto/Cargo.toml — see the deferred note in the report). Default
// `--features node` builds do NOT include this test, so they keep the placeholder
// and stay green; the guard bites exactly when a mainnet release is cut.
#[cfg(all(test, feature = "mainnet"))]
mod mainnet_release_guard {
    use super::*;

    #[test]
    fn canonical_k_activation_height_is_set_for_mainnet() {
        assert_ne!(CANONICAL_K_ACTIVATION_HEIGHT, PLACEHOLDER_ACTIVATION_HEIGHT,
            "P0.5: CANONICAL_K_ACTIVATION_HEIGHT is still the 1_000_000 placeholder — set it \
             to (mainnet tip + upgrade margin) before building for mainnet");
        assert_ne!(CANONICAL_K_ACTIVATION_HEIGHT, u64::MAX,
            "activation height must not be u64::MAX (soft fork would never activate)");
        assert!(CANONICAL_K_ACTIVATION_HEIGHT < 10_000_000,
            "activation height implausibly large — likely an un-set / accidental value");
    }
}

// ── Genesis-2 PoW switch: MiningHeader layout KATs + algorithm mapping ───────
// The 80-byte layout vectors below were generated by compiling the reference
// implementation from /Users/tiagoacioli/dev/entanglement-layer/src/core/mod.rs
// (MiningHeader::to_bytes / pow_hash / parents_commitment extracted verbatim)
// and printing its output for the fixed header — so these tests pin byte-for-
// byte equality with the working double-SHA-256 BlockDAG, not just self-
// consistency.
#[cfg(test)]
mod g2_pow_switch_tests {
    use super::*;

    fn fixed_mining_header() -> MiningHeader {
        let mut prev = [0u8; 32];
        let mut merk = [0u8; 32];
        for i in 0..32 {
            prev[i] = i as u8;
            merk[i] = 32 + i as u8;
        }
        MiningHeader {
            version:     0x01020304,
            prev_hash:   prev,
            merkle_root: merk,
            timestamp:   0x11223344,
            bits:        0x1d00ffff,
            nonce:       0xdeadbeef,
        }
    }

    /// (a) to_bytes matches the entanglement-layer reference byte-for-byte
    /// (hardcoded expected [u8; 80]) and round-trips through from_bytes.
    #[test]
    fn mining_header_80_byte_layout_matches_entanglement_layer() {
        // Reference output ("to_bytes = …") of the entanglement-layer code:
        // 04030201 ‖ prev[00..1f] ‖ merkle[20..3f] ‖ 44332211 ‖ ffff001d ‖ efbeadde
        let expected_hex =
            "04030201\
             000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             44332211ffff001defbeadde";
        let mut expected = [0u8; 80];
        let raw = hex::decode(expected_hex.replace(char::is_whitespace, "")).unwrap();
        expected.copy_from_slice(&raw);

        let mh = fixed_mining_header();
        assert_eq!(mh.to_bytes(), expected, "80-byte layout drifted from the reference");
        assert_eq!(MiningHeader::from_bytes(&mh.to_bytes()), mh, "from_bytes must invert to_bytes");
    }

    /// pow_hash (double SHA-256 of the 80 bytes) matches the reference vector.
    #[test]
    fn mining_header_pow_hash_matches_entanglement_layer() {
        let mh = fixed_mining_header();
        assert_eq!(
            hex::encode(mh.pow_hash()),
            "bb07e62091bc5944be2971adfa2a42b035de2e90d6878aa227ef930ae0aea0b9",
        );
    }

    /// parents_commitment matches the reference for the empty / single /
    /// odd-count (duplicate-last, sorted) cases.
    #[test]
    fn parents_commitment_matches_entanglement_layer() {
        assert_eq!(parents_commitment(&[]), [0u8; 32]);
        assert_eq!(parents_commitment(&[[7u8; 32]]), [7u8; 32]);
        let p3 = [[3u8; 32], [1u8; 32], [2u8; 32]];
        assert_eq!(
            hex::encode(parents_commitment(&p3)),
            "223e023fadf1f053df26988871f893c821c28edf77d64a955e6c2a02d547bdac",
        );
    }

    /// (d) pow_algorithm's match is wildcard-free in the source, so this
    /// mapping test plus the compiler's exhaustiveness check pin the
    /// chain-id → algorithm table. Adding a ChainId variant without deciding
    /// its PoW fails to compile.
    #[test]
    fn pow_algorithm_mapping_is_pinned() {
        assert_eq!(pow_algorithm(ChainId::Mainnet), PowAlgorithm::ModuleSis);
        assert_eq!(pow_algorithm(ChainId::Testnet), PowAlgorithm::ModuleSis);
        assert_eq!(pow_algorithm(ChainId::Genesis2Devnet), PowAlgorithm::Sha256d);
        // Discriminant registry: obviously distinct, never reused.
        assert_eq!(ChainId::Genesis2Devnet.to_u32(), 0xB10C_0003);
        assert_eq!(ChainId::Genesis2Devnet.to_le_bytes(), 0xB10C_0003u32.to_le_bytes());
    }

    /// The default (unset) chain-id is Mainnet ⇒ ModuleSis: in-process tests
    /// that never call set_node_chain_id keep validating the SIS path.
    #[test]
    fn default_chain_id_maps_to_module_sis() {
        assert_eq!(pow_algorithm(node_chain_id()), PowAlgorithm::ModuleSis);
    }
}
