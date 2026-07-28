//! validator — pure, no-IO, unit-testable SHA-256d share validator.
//!
//! The whole PoW-correctness surface of the mini-pool lives HERE. It
//! reconstructs the 80-byte Bitcoin-style mining header from a cached
//! `mining.notify` job (`crate::jobstore::FullJob`) plus a miner's
//! `mining.submit` fields (extranonce2 / ntime / nonce), double-SHA256s it,
//! and compares the result against a target using Bloch's EXACT endianness
//! convention.
//!
//! ## Why the bytes are COPIED, not linked
//!
//! `pool-proxy` is a deliberately isolated `[workspace]` with ZERO dependency
//! on `bloch-crypto`. To stay byte-identical to consensus without linking it,
//! the three target-math functions below are copied VERBATIM from
//! `crates/bloch-crypto/src/core/mod.rs`:
//!   * `bits_to_target`        (mod.rs:1986)
//!   * `hash_meets_target`     (mod.rs:1999)
//!   * `difficulty_to_target`  (mod.rs:2054)
//! and `sha256d` mirrors the node's double-SHA (mod.rs / src/pow/sha256d.rs).
//!
//! ## The endianness fork (the riskiest correctness point)
//!
//! The live Genesis-2 chain is permanently past `SHA256D_LE_FORK_HEIGHT = 2400`
//! (`bloch_crypto::core::sha256d_pow_valid`, mod.rs:2029), so the PoW compare
//! reverses the 32-byte double-SHA256 output to a Bitcoin little-endian integer
//! BEFORE the big-endian `hash_meets_target`. `meets()` takes `le` as a config
//! flag (default `true`) so this fork assumption is explicit rather than buried.
//!
//! The 80-byte header layout and every field's endianness mirror
//! `bloch_crypto::core::MiningHeader::to_bytes` (mod.rs:603) and the node's
//! stratum reconstruction (`src/stratum/submit.rs`, `src/stratum/jobs.rs`):
//!   0..4   version   (BE-hex parsed → little-endian)
//!   4..36  prev_hash (raw consensus bytes, stratum word-swap UNDONE)
//!   36..68 merkle_root (raw, coinbase always LEFT up the branch)
//!   68..72 ntime     (BE-hex parsed → little-endian)
//!   72..76 nbits     (BE-hex parsed → little-endian)
//!   76..80 nonce     (low 32 bits, BE-hex parsed → little-endian)

use crate::jobstore::FullJob;
use crate::types::PoolError;

use sha2::{Digest, Sha256};

/// VERBATIM copy of `bloch_crypto::core::SHA256D_LE_FORK_HEIGHT` (mod.rs:2021).
/// At/above this height the node compares the PoW hash Bitcoin
/// little-endian; below it, legacy big-endian (no reversal) — see
/// `bloch_crypto::core::sha256d_pow_valid` (mod.rs:2029..2037), which the
/// node's `stratum/submit.rs::handle_submit` calls with the SUBMIT'S OWN
/// `template.height`, not some pool-wide constant. A pool that hardcodes
/// `le=true` is only correct while every cached job is past this height; on
/// a fresh/replayed chain (job heights in the tens, not the thousands) it
/// mis-gates EVERY local block-candidate check, so genuine solutions get
/// forwarded and the node bounces them as error-23 LowDifficulty (observed
/// live: a founder relaunch at height ~15, 141 forwarded candidates in 15
/// minutes, 100% LowDifficulty, 0 accepted).
pub const SHA256D_LE_FORK_HEIGHT: u64 = 2400;

/// The `le` a job at `height` must be compared under — mirrors the node's
/// own per-submit height gate exactly (`sha256d_pow_valid`), so the pool
/// never forwards (or answers locally) using a convention the node itself
/// would not have used for that same height.
pub fn le_for_height(height: u64) -> bool {
    height >= SHA256D_LE_FORK_HEIGHT
}

/// Double-SHA256. Mirrors the node's `sha256d` / `MiningHeader::pow_hash`.
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let a = Sha256::digest(bytes);
    let b = Sha256::digest(a);
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

/// VERBATIM copy of `bloch_crypto::core::bits_to_target` (mod.rs:1986).
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x00ff_ffff;
    let mut t = [0u8; 32];
    if (3..=32).contains(&exp) {
        let s = 32 - exp;
        t[s] = ((mant >> 16) & 0xff) as u8;
        if s + 1 < 32 {
            t[s + 1] = ((mant >> 8) & 0xff) as u8;
        }
        if s + 2 < 32 {
            t[s + 2] = (mant & 0xff) as u8;
        }
    }
    t
}

/// VERBATIM copy of `bloch_crypto::core::hash_meets_target` (mod.rs:1999).
/// Big-endian byte-wise `hash <= target`.
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true
}

/// VERBATIM copy of `bloch_crypto::core::difficulty_to_target` (mod.rs:2054),
/// including the U256 fixed-point-millionths diff-1 math. Produces the per-miner
/// share accept/reject boundary; diff-1 == `bits_to_target(0x1d00ffff)`.
pub fn difficulty_to_target(diff: f64) -> [u8; 32] {
    use primitive_types::U256;
    let scaled = (diff.max(f64::MIN_POSITIVE) * 1_000_000.0).round();
    let d: u128 = if scaled.is_finite() && scaled >= 1.0 {
        scaled as u128
    } else {
        1
    };
    let d = d.max(1);
    let diff1 = U256::from_big_endian(&bits_to_target(0x1d00ffff));
    let t = diff1 * U256::from(1_000_000u64) / U256::from(d);
    t.to_big_endian()
}

/// THE compare. The live chain is past `SHA256D_LE_FORK_HEIGHT = 2400`, so
/// `le` is `true`: reverse the 32-byte double-SHA256 output to Bitcoin
/// little-endian, then compare big-endian against the target. Mirrors
/// `bloch_crypto::core::sha256d_pow_valid` (mod.rs:2029) at post-fork height.
///
/// `le` is a config knob (default `true`) so the height-based fork gate stays
/// honest — getting the reverse backwards passes NOTHING (or everything).
pub fn meets(pow_hash: &[u8; 32], target: &[u8; 32], le: bool) -> bool {
    if le {
        let mut r = *pow_hash;
        r.reverse();
        hash_meets_target(&r, target)
    } else {
        hash_meets_target(pow_hash, target)
    }
}

/// The difficulty a reconstructed `pow_hash` ACTUALLY achieved, under the same
/// endianness gate the share is compared with (`le`). `difficulty ==
/// diff1_target / hash_as_integer`, the standard pool definition, so a value of
/// e.g. `0.7` means "this hash is a genuine solution at difficulty 0.7".
///
/// This is the observability the downward-vardiff escape needs: a fleet behind
/// a NiceHash/MRR rig proxy (or any miner that does not honor our
/// `mining.set_difficulty`) submits GENUINE PoW at ITS difficulty, which may be
/// far below the difficulty we announced. Those shares are correctly rejected
/// as LowDifficulty, but the achieved difficulty tells the vardiff engine what
/// the miner can actually do, so it can converge DOWN to that instead of
/// dead-locking at 100% reject (`on_accepted`, the only other retarget path, is
/// unreachable when zero shares are accepted).
pub fn hash_to_difficulty(pow_hash: &[u8; 32], le: bool) -> f64 {
    let mut h = *pow_hash;
    if le {
        h.reverse();
    }
    let hv = u256_bytes_to_f64(&h);
    if hv <= 0.0 {
        return f64::INFINITY;
    }
    let diff1 = u256_bytes_to_f64(&bits_to_target(0x1d00ffff));
    diff1 / hv
}

/// Interpret a 32-byte big-endian value as an (approximate) `f64`. Exact in the
/// leading ~53 bits — all a difficulty ESTIMATE needs — and never overflows
/// (`< 2^256 ≪ f64::MAX`).
fn u256_bytes_to_f64(be: &[u8; 32]) -> f64 {
    let mut f = 0.0f64;
    for &b in be.iter() {
        f = f * 256.0 + b as f64;
    }
    f
}

/// Decode a hex string (even length, `[0-9a-fA-F]`) into bytes. Returns `None`
/// on any malformed input — validation fails closed on a bad submit.
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Undo the stratum prev_hash word-swap: reverse each of the 8 four-byte words
/// in place (word order preserved). This is the EXACT inverse of the node's
/// `jobs.rs::stratum_prevhash` (`out[i*4+k] = prev[i*4+3-k]`) — and, being a
/// per-word reversal, it is its own inverse. The result is the raw consensus
/// `prev_hash` that goes into header bytes 4..36.
pub fn undo_prevhash_word_swap(swapped: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4] = swapped[i * 4 + 3];
        out[i * 4 + 1] = swapped[i * 4 + 2];
        out[i * 4 + 2] = swapped[i * 4 + 1];
        out[i * 4 + 3] = swapped[i * 4];
    }
    out
}

/// Walk a merkle branch from `coinbase_txid` up to the root. Coinbase is always
/// at position 0, so every concatenation is `(current || sibling)`. Mirrors
/// `jobs.rs::walk_merkle_branch`. An empty branch returns the coinbase txid
/// unchanged (`merkle_root == coinbase_txid`, the common case on this chain).
pub fn walk_merkle_branch(coinbase_txid: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    let mut h = coinbase_txid;
    for sibling in branch {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&h);
        buf[32..].copy_from_slice(sibling);
        h = sha256d(&buf);
    }
    h
}

/// The result of validating one reconstructed share.
#[derive(Clone, Copy, Debug)]
pub struct ValidateOutcome {
    /// The raw double-SHA256 of the reconstructed 80-byte header.
    pub hash: [u8; 32],
    /// Whether the hash meets the miner's per-worker (vardiff) target.
    pub meets_worker: bool,
    /// Whether the hash also meets the network target (i.e. it is a real block).
    pub meets_network: bool,
}

/// BIP310 version-rolling mask. A version-rolling miner (ASICBoost) is only
/// permitted to alter the bits set in this mask; every other bit of the header
/// version MUST come from the job. Standard SHA-256 ASICs (Antminer/Whatsminer)
/// negotiate exactly this mask, and MRR/NiceHash rig proxies forward the rolled
/// nVersion as a 6th `mining.submit` param. This is the pool-wide default the
/// firmware ships with when the pool does not narrow it.
pub const VERSION_ROLLING_MASK: u32 = 0x1fff_e000;

/// Resolve the header version the miner ACTUALLY hashed. Without a submitted
/// version (no version-rolling) the job's version is authoritative. With one,
/// only the masked bits are the miner's; the rest stay pinned to the job — so
/// this reproduces the exact nVersion the ASIC put in its 80-byte header.
pub fn effective_version(job_version: u32, submitted: Option<u32>) -> u32 {
    match submitted {
        Some(v) => (job_version & !VERSION_ROLLING_MASK) | (v & VERSION_ROLLING_MASK),
        None => job_version,
    }
}

/// Reconstruct + hash + compare a share (POW-convention steps a–h).
///
/// * `en1_hex` — this worker's upstream `extranonce1` (hex).
/// * `en2_hex` / `ntime_hex` / `nonce_hex` — the miner's submit params (hex).
/// * `version_bits` — the OPTIONAL rolled nVersion from a version-rolling
///   miner's 6th `mining.submit` param (BIP310). `None` ⇒ use the job version.
/// * `worker_target` — the per-miner target from `difficulty_to_target(diff)`.
/// * `le` — the fork gate (default `true`; see [`meets`]).
#[allow(clippy::too_many_arguments)]
pub fn validate(
    job: &FullJob,
    en1_hex: &str,
    en2_hex: &str,
    ntime_hex: &str,
    nonce_hex: &str,
    version_bits: Option<u32>,
    worker_target: &[u8; 32],
    le: bool,
) -> Result<ValidateOutcome, PoolError> {
    // a. coinbase = coinb1 || en1 || en2 || coinb2  (raw bytes, en1 THEN en2).
    let en1 = hex_to_bytes(en1_hex)
        .ok_or_else(|| PoolError::Protocol("validate: extranonce1 not hex".into()))?;
    let en2 = hex_to_bytes(en2_hex)
        .ok_or_else(|| PoolError::Protocol("validate: extranonce2 not hex".into()))?;
    let mut coinbase =
        Vec::with_capacity(job.coinb1.len() + en1.len() + en2.len() + job.coinb2.len());
    coinbase.extend_from_slice(&job.coinb1);
    coinbase.extend_from_slice(&en1);
    coinbase.extend_from_slice(&en2);
    coinbase.extend_from_slice(&job.coinb2);

    // b. txid = sha256d(coinbase).
    let txid = sha256d(&coinbase);

    // c. merkle_root = walk(txid, branch)  (coinbase always LEFT).
    let merkle_root = walk_merkle_branch(txid, &job.merkle_branch);

    // e. parse the submit's big-endian hex ints (ntime rolling: authoritative
    //    ntime is the one in the submit, not the job).
    let ntime = parse_hex_u32(ntime_hex)
        .ok_or_else(|| PoolError::Protocol("validate: ntime not a hex u32".into()))?;
    let nonce = parse_hex_u32(nonce_hex)
        .ok_or_else(|| PoolError::Protocol("validate: nonce not a hex u32".into()))?;

    // e. assemble the 80-byte header (mirrors MiningHeader::to_bytes). The
    //    version is the miner's rolled nVersion when it version-rolls, else the
    //    job's — otherwise an ASICBoost miner's header never matches ours.
    let version = effective_version(job.version, version_bits);
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&version.to_le_bytes());
    header[4..36].copy_from_slice(&job.prevhash_raw); // d. already un-word-swapped
    header[36..68].copy_from_slice(&merkle_root);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header[72..76].copy_from_slice(&job.nbits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());

    // f. hash = sha256d(header).
    let hash = sha256d(&header);

    // g/h. compare against worker + network targets under the fork gate.
    let meets_worker = meets(&hash, worker_target, le);
    let meets_network = meets(&hash, &job.network_target, le);

    Ok(ValidateOutcome {
        hash,
        meets_worker,
        meets_network,
    })
}

/// Parse a big-endian hex string into a `u32` (stratum ntime/nonce/version/nbits
/// convention). Accepts an optional `0x` prefix; rejects > 8 significant nibbles.
pub fn parse_hex_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() || t.len() > 8 {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobstore::FullJob;
    use std::time::Instant;

    /// Mirror the node's SHA-256d test header shape, but small target so the
    /// test can mine a valid nonce quickly. Returns the 80-byte header prefix
    /// (0..76) for a given (version, prevhash_raw, merkle_root, ntime, nbits).
    fn header80(
        version: u32,
        prevhash_raw: &[u8; 32],
        merkle_root: &[u8; 32],
        ntime: u32,
        nbits: u32,
        nonce: u32,
    ) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&version.to_le_bytes());
        h[4..36].copy_from_slice(prevhash_raw);
        h[36..68].copy_from_slice(merkle_root);
        h[68..72].copy_from_slice(&ntime.to_le_bytes());
        h[72..76].copy_from_slice(&nbits.to_le_bytes());
        h[76..80].copy_from_slice(&nonce.to_le_bytes());
        h
    }

    /// bits_to_target worked example from the design (0x1c0ffff0).
    #[test]
    fn bits_to_target_worked_example() {
        let t = bits_to_target(0x1c0ffff0);
        assert_eq!(t[4], 0x0f);
        assert_eq!(t[5], 0xff);
        assert_eq!(t[6], 0xf0);
        assert!(t[0..4].iter().all(|&b| b == 0));
    }

    /// diff-1 target must equal bits_to_target(0x1d00ffff) — the diff-1
    /// constant the node's difficulty_to_target is anchored on (mod.rs:2103).
    #[test]
    fn difficulty_one_is_diff1_target() {
        assert_eq!(difficulty_to_target(1.0), bits_to_target(0x1d00ffff));
        // A larger difficulty is a strictly smaller (harder) target.
        let easy = difficulty_to_target(1.0);
        let hard = difficulty_to_target(1024.0);
        assert!(hash_meets_target(&hard, &easy), "diff-1024 target < diff-1 target");
    }

    /// `le_for_height` must mirror the node's own
    /// `bloch_crypto::core::sha256d_pow_valid` height gate EXACTLY (mod.rs
    /// 2029..2037: `height >= SHA256D_LE_FORK_HEIGHT`), including the
    /// boundary. A fresh/replayed chain (e.g. height 15) must gate to legacy
    /// big-endian (`false`) — hardcoding `true` here is the Sprint-2 bug that
    /// let a founder relaunch forward 141 genuine solutions the node then
    /// bounced as error-23 LowDifficulty.
    #[test]
    fn le_for_height_mirrors_consensus_fork_gate() {
        assert!(!le_for_height(0), "genesis must be legacy big-endian");
        assert!(!le_for_height(15), "a fresh relaunch's early heights must be legacy big-endian");
        assert!(!le_for_height(SHA256D_LE_FORK_HEIGHT - 1), "one below the fork is still legacy");
        assert!(le_for_height(SHA256D_LE_FORK_HEIGHT), "AT the fork height is already LE");
        assert!(le_for_height(SHA256D_LE_FORK_HEIGHT + 1), "past the fork stays LE");
        assert!(le_for_height(u64::MAX), "the 'unknown, assume converged' fallback stays LE");
    }

    /// THE endianness compare — the riskiest correctness point. Mine a nonce
    /// under the LITTLE-ENDIAN rule (the live chain's rule) and assert:
    ///   * meets(le=true) accepts it,
    ///   * meets(le=false) (legacy big-endian) rejects it (disjoint sets),
    ///   * flipping one nonce bit breaks the LE acceptance.
    /// This is the exact property `src/pow/sha256d.rs` guards on the node side.
    #[test]
    fn known_header_meets_network_target_le() {
        let version = 1u32;
        let prevhash = [7u8; 32];
        let merkle = [9u8; 32];
        let ntime = 1_777_000_000u32;
        // ~2^-16 per hash: mineable within the test budget.
        let nbits = 0x1f00ffffu32;
        let target = bits_to_target(nbits);

        // Mine under the LE rule.
        let mut found = None;
        for nonce in 0u32..2_000_000 {
            let h = sha256d(&header80(version, &prevhash, &merkle, ntime, nbits, nonce));
            if meets(&h, &target, true) {
                found = Some(nonce);
                break;
            }
        }
        let nonce = found.expect("2^-16 LE target must be hit within budget");

        let good = sha256d(&header80(version, &prevhash, &merkle, ntime, nbits, nonce));
        assert!(meets(&good, &target, true), "LE-mined nonce must meet target under LE rule");
        // Legacy big-endian rule rejects an LE-small hash (overwhelmingly).
        assert!(
            !meets(&good, &target, false),
            "an LE-small hash must NOT satisfy the legacy big-endian rule",
        );
        // Flip one nonce bit → must fail LE.
        let bad = sha256d(&header80(version, &prevhash, &merkle, ntime, nbits, nonce ^ 1));
        assert!(!meets(&bad, &target, true), "a wrong nonce must fail the LE compare");
    }

    /// End-to-end: feed a cached FullJob + submit fields through `validate()`,
    /// exercising coinbase concat order (coinb1||en1||en2||coinb2), the
    /// empty-branch merkle (merkle_root == coinbase_txid), and the LE compare
    /// together — the exact path a production submit takes. meets_network must
    /// be true for the real solution, and meets_worker true at a lower diff.
    #[test]
    fn end_to_end_validate_from_submit_fields() {
        let coinb1 = vec![0xaa, 0xbb, 0xcc];
        let coinb2 = vec![0xdd, 0xee];
        let en1_hex = "deadbeef";
        let en2_hex = "00000001";
        let version = 2u32;
        let prevhash_raw = [0x11u8; 32];
        let nbits = 0x1f00ffffu32;
        let network_target = bits_to_target(nbits);
        let ntime = 0x6600_0000u32;

        // Reconstruct the coinbase → txid → merkle_root exactly as validate does,
        // so we can mine the matching nonce here.
        let en1 = hex_to_bytes(en1_hex).unwrap();
        let en2 = hex_to_bytes(en2_hex).unwrap();
        let mut coinbase = coinb1.clone();
        coinbase.extend_from_slice(&en1);
        coinbase.extend_from_slice(&en2);
        coinbase.extend_from_slice(&coinb2);
        let txid = sha256d(&coinbase);
        let merkle_root = walk_merkle_branch(txid, &[]);
        assert_eq!(merkle_root, txid, "empty branch ⇒ root == coinbase txid");

        // Mine a nonce that meets the network target under LE.
        let mut found = None;
        for nonce in 0u32..2_000_000 {
            let h = sha256d(&header80(version, &prevhash_raw, &merkle_root, ntime, nbits, nonce));
            if meets(&h, &network_target, true) {
                found = Some(nonce);
                break;
            }
        }
        let nonce = found.expect("must find a block-meeting nonce within budget");
        let nonce_hex = format!("{:08x}", nonce);
        let ntime_hex = format!("{:08x}", ntime);

        let job = FullJob {
            job_id: "job1".to_string(),
            version,
            prevhash_raw,
            coinb1,
            coinb2,
            merkle_branch: Vec::new(),
            nbits,
            network_target,
            height: u64::MAX,
            clean_jobs: false,
            received_at: Instant::now(),
        };

        // At the network difficulty, the share meets BOTH targets.
        let out = validate(&job, en1_hex, en2_hex, &ntime_hex, &nonce_hex, None, &network_target, true)
            .expect("validate must succeed");
        assert!(out.meets_network, "real solution must meet the network target");
        assert!(out.meets_worker, "…and the worker target when worker == network");

        // At the easiest representable worker target (diff → 0, i.e. diff1*1e6,
        // strictly easier than this easy network target), the real block still
        // clears the worker gate; and a bogus nonce meets neither.
        let easy_worker = difficulty_to_target(0.0);
        let out2 = validate(&job, en1_hex, en2_hex, &ntime_hex, &nonce_hex, None, &easy_worker, true)
            .expect("validate must succeed");
        assert!(out2.meets_worker, "easy worker target must accept a real block");

        let bogus_hex = format!("{:08x}", nonce ^ 0xffff);
        let out3 = validate(&job, en1_hex, en2_hex, &ntime_hex, &bogus_hex, None, &network_target, true)
            .expect("validate must succeed");
        assert!(!out3.meets_network, "a wrong nonce must not meet the network target");
    }

    /// REGRESSION (Sprint-2 100%-reject bug). A real, off-the-shelf SHA-256d
    /// ASIC (Antminer/Whatsminer) produces a header whose double-SHA256 only
    /// meets the target under Bitcoin's LITTLE-ENDIAN rule (reverse the 32-byte
    /// hash, then compare). The live, post-fork Bloch node validates exactly
    /// that way (`sha256d_pow_valid` at height >= 2400) and ACCEPTED these
    /// miners' shares under Sprint-1. The Sprint-2 submit path, however, was
    /// forced big-endian by the deployment's `BLOCH_POOL_SHA256D_LE=false`
    /// (passed as a pool-wide `le_override`), so every genuine share missed even
    /// the easy worker target and bounced LowDifficulty (accepted_total stuck at
    /// 0, rejected_total climbing).
    ///
    /// This reconstructs a genuine ASIC-style submit through the REAL wire path
    /// of [`validate`] (extranonce1 = the proxy's assigned en1, extranonce2 off
    /// the wire, an optional version-roll), mines a nonce that is little-endian
    /// valid, and asserts:
    ///   * the SUBMIT-PATH endianness for a LIVE job — `le_for_height(height)`
    ///     with a post-fork height — ACCEPTS it (`meets_worker == true`), and
    ///   * the removed forced big-endian compare (`le = false`) REJECTS the very
    ///     same share — i.e. the exact regression that zeroed acceptances.
    #[test]
    fn real_asic_le_share_accepted_by_submit_path_rejected_by_forced_big_endian() {
        // A live Genesis-2 job: the id carries a post-fork height, so the
        // submit path (`handle_submit`'s scan) gates to little-endian.
        let live_height = 531_000u64;
        let submit_le = le_for_height(live_height);
        assert!(submit_le, "a live post-fork job must gate to little-endian");

        // Real wire inputs (bytes an ASIC actually hashes).
        let coinb1 = hex_to_bytes("01000000010000").unwrap();
        let coinb2 = hex_to_bytes("ffffffff00").unwrap();
        let en1_hex = "b4a3c2d1"; // the proxy's assigned extranonce1
        let en2_hex = "00000007"; // the miner's extranonce2, off the wire
        let job_version = 0x2000_0000u32;
        let version_roll = Some(0x2010_4000u32); // an AsicBoost 6th-param nVersion
        let prevhash_raw = [0x24u8; 32];
        // Mineable-in-budget worker target (~2^-16 per hash under LE) — the
        // property under test is the ENDIANNESS, which is target-independent.
        let nbits = 0x1f00ffffu32;
        let worker_target = bits_to_target(nbits);
        // Network target is diff-1 (0x1d00ffff), far harder — the share is a
        // normal accepted share, not a block.
        let network_target = bits_to_target(0x1d00ffff);
        let ntime_hex = "5f5e1000";

        let job = FullJob {
            job_id: "1a-531000-8e".to_string(),
            version: job_version,
            prevhash_raw,
            coinb1,
            coinb2,
            merkle_branch: Vec::new(),
            nbits: 0x1d00ffff,
            network_target,
            height: live_height,
            clean_jobs: false,
            received_at: Instant::now(),
        };

        // Mine a genuine ASIC-style nonce: little-endian valid (what the
        // hardware actually finds), using the SAME effective version + coinbase
        // the validator reconstructs.
        let mut found = None;
        for nonce in 0u32..2_000_000 {
            let nonce_hex = format!("{:08x}", nonce);
            let o = validate(
                &job, en1_hex, en2_hex, ntime_hex, &nonce_hex, version_roll,
                &worker_target, submit_le, // little-endian, as the ASIC hashes
            )
            .expect("validate must succeed");
            if o.meets_worker && !o.meets_network {
                found = Some(nonce_hex);
                break;
            }
        }
        let nonce_hex = found.expect("a little-endian ASIC share must be found in budget");

        // (1) The submit path (per-job height gate → little-endian) ACCEPTS the
        //     real ASIC share — so `shares_accepted_total` climbs, not stalls.
        let good = validate(
            &job, en1_hex, en2_hex, ntime_hex, &nonce_hex, version_roll,
            &worker_target, submit_le,
        )
        .expect("validate must succeed");
        assert!(good.meets_worker, "real ASIC (LE) share must clear the worker target");
        assert!(!good.meets_network, "…and must NOT be misread as a diff-1 block");

        // (2) The REMOVED forced big-endian override (`BLOCH_POOL_SHA256D_LE=
        //     false`) rejects the identical share — the precise Sprint-2 bug.
        let regressed = validate(
            &job, en1_hex, en2_hex, ntime_hex, &nonce_hex, version_roll,
            &worker_target, false, // legacy big-endian: the deployment's forced value
        )
        .expect("validate must succeed");
        assert!(
            !regressed.meets_worker,
            "forced big-endian is why every live ASIC share was rejected LowDifficulty",
        );
    }

    /// The prev_hash word-swap undo is a per-word reversal and its own inverse.
    #[test]
    fn prevhash_word_swap_is_involution() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let once = undo_prevhash_word_swap(&raw);
        let twice = undo_prevhash_word_swap(&once);
        assert_eq!(twice, raw, "applying the word-swap twice is identity");
        // And it matches the node's stratum_prevhash byte formula.
        assert_eq!(once[0], raw[3]);
        assert_eq!(once[3], raw[0]);
        assert_eq!(once[4], raw[7]);
    }

    /// `hash_to_difficulty` must agree with the `meets` gate it feeds: a hash is
    /// accepted at difficulty D iff its achieved difficulty is >= D. Mining a
    /// nonce that clears a known target, its measured difficulty must be >= that
    /// target's difficulty; and the measure must be endianness-consistent.
    #[test]
    fn hash_to_difficulty_agrees_with_meets_gate() {
        let nbits = 0x1f00ffffu32; // ~2^-16 per hash under LE: mineable in budget
        let target = bits_to_target(nbits);
        let target_diff = {
            // difficulty of the target itself = diff1 / target.
            let d1 = u256_bytes_to_f64(&bits_to_target(0x1d00ffff));
            d1 / u256_bytes_to_f64(&target)
        };

        let prevhash = [3u8; 32];
        let merkle = [5u8; 32];
        let ntime = 1_777_000_000u32;
        let mut found = None;
        for nonce in 0u32..4_000_000 {
            let h = sha256d(&header80(1, &prevhash, &merkle, ntime, nbits, nonce));
            if meets(&h, &target, true) {
                found = Some(h);
                break;
            }
        }
        let h = found.expect("must mine a target-meeting hash in budget");
        let achieved = hash_to_difficulty(&h, true);
        assert!(
            achieved + 1e-9 >= target_diff,
            "a hash that MEETS the target must measure >= its difficulty \
             (achieved={achieved}, target_diff={target_diff})"
        );
        // Endianness matters: read the same hash big-endian and it is a wholly
        // different (astronomically larger) integer ⇒ a far smaller difficulty.
        let be = hash_to_difficulty(&h, false);
        assert!(be < achieved, "the LE reading is the small-integer (high-difficulty) one");
    }

    #[test]
    fn hex_and_u32_parse_fail_closed() {
        assert!(hex_to_bytes("zz").is_none());
        assert!(hex_to_bytes("abc").is_none()); // odd length
        assert_eq!(hex_to_bytes("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_hex_u32("60000000"), Some(0x6000_0000));
        assert_eq!(parse_hex_u32("0x01"), Some(1));
        assert!(parse_hex_u32("100000000").is_none()); // > u32
        assert!(parse_hex_u32("xyz").is_none());
    }
}
