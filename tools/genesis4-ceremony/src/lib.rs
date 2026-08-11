// SPDX-License-Identifier: MIT OR Apache-2.0

//! Genesis-4 ceremony — assemble the Genesis-4 genesis block from the signed
//! carryover artifact.
//!
//! Spec: `docs/specs/BLOCH-TOKENOMICS-V4.md` (allocations §1, carryover cap §3,
//! artifact-is-canonical §3.2.2, consensus-enforced locks §8.2) and
//! `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §5.3–§5.5 (BlockHeaderV4,
//! block identity, state commitment).
//!
//! ## What this tool produces
//!
//! 1. **The genesis allocation document** — every opening output of the new
//!    chain, each with its unlock schedule attached as data the consensus
//!    loader enforces. A vesting schedule that lives in a spreadsheet is not a
//!    vesting schedule (§8.2); here the schedule is part of the output's leaf
//!    hash, so a genesis without the locks has a different `state_root` and
//!    therefore a different `block_id` — it is a different chain.
//! 2. **The genesis header** (`BlockHeaderV4`, §5.3) and its `block_id`.
//!
//! ## Why the carryover digest is embedded — §3.2.2, the load-bearing part
//!
//! After the Genesis-3 chain halts at height 80,000, nobody is paying hashrate
//! to defend it, and rewriting history below the terminal height costs almost
//! nothing. The signed carryover artifact is the record — the old chain is
//! not. So the artifact's SHAKE-256 digest is committed **inside** the genesis
//! block, as a leaf of `state_root`: replacing the artifact silently would
//! change the genesis `block_id`, i.e. it is impossible without visibly
//! launching a different chain. This tool refuses to build a genesis unless
//! the digest it recomputes from the artifact matches the digest the operator
//! passes in from the published record (fail-closed, both directions).
//!
//! ## Arithmetic
//!
//! Every quantity is `u128`, imported from `bloch_pos_committee::tokenomics_v4`
//! — the crate whose compile-time assertions pin the 100 B total and the u64
//! overflow hazard (spec §8.1). No allocation number is restated here.

use bloch_pos_committee::tokenomics_v4 as v4;

// ── Domain separation ───────────────────────────────────────────────────────
// Fixed 16 bytes, right-padded with zeros, so no tag can be a prefix of
// another — the convention set in `bloch-pos-committee/src/params.rs`.

/// Block identity: `block_id = SHA3-256(DS_BLOCK ‖ canonical_header)` (§5.4).
pub const DS_BLOCK: [u8; 16] = *b"BLCH4:BLOCK\0\0\0\0\0";
/// RANDAO mixing: `mix_{n+1} = SHA3-256(DS_RANDAO ‖ mix_n ‖ reveal)` (§6).
pub const DS_RANDAO: [u8; 16] = *b"BLCH4:RANDAO\0\0\0\0";
/// Genesis output leaf.
pub const DS_G4_OUT: [u8; 16] = *b"BLCH4:G4OUT\0\0\0\0\0";
/// Genesis output Merkle inner node.
pub const DS_G4_NODE: [u8; 16] = *b"BLCH4:G4NODE\0\0\0\0";
/// Genesis output Merkle root wrapper (binds the leaf count).
pub const DS_G4_ROOT: [u8; 16] = *b"BLCH4:G4ROOT\0\0\0\0";
/// Genesis state commitment.
pub const DS_G4_STATE: [u8; 16] = *b"BLCH4:G4STATE\0\0\0";

/// Header version for Genesis-4 (§5.3).
pub const GENESIS4_VERSION: u32 = 0xB10C_0005;

/// Sentinel proposer index for the genesis block. Genesis has no proposer and
/// no proposer signature — it is agreed by configuration, like every chain's
/// genesis. `u32::MAX` can never be a real validator index.
pub const GENESIS_PROPOSER_INDEX: u32 = u32::MAX;

// ── Hash helpers ────────────────────────────────────────────────────────────
// Local `use` inside each helper: `Sha3_256` implements both `Digest` and
// `Update`, and importing both traits at module scope makes `.update()`
// ambiguous.

fn sha3_256(chunks: &[&[u8]]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

fn shake256_32_lines(lines: impl Iterator<Item = String>) -> [u8; 32] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for line in lines {
        h.update(line.as_bytes());
    }
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

// ── Carryover artifact ──────────────────────────────────────────────────────

/// The parsed carryover artifact: sorted `(addr_hash_hex, value_sat)` rows and
/// the SHAKE-256 digest recomputed exactly the way
/// `tools/genesis4-carryover/build_carryover.py` computes it — over the
/// canonical `addr<TAB>value<LF>` lines. Cross-language agreement is pinned by
/// a known-answer test below.
pub struct Carryover {
    pub rows: Vec<(String, u128)>,
    pub digest: [u8; 32],
    pub total_sat: u128,
}

fn valid_addr_hex(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse and canonically re-hash the carryover artifact.
///
/// The parser is strict on purpose: the digest is computed over the canonical
/// reconstruction of each row, so any encoding that would survive parsing but
/// differ from what the builder wrote (leading zeros, out-of-order rows,
/// duplicates, uppercase hex) is rejected instead of silently re-canonicalised.
pub fn read_carryover(text: &str) -> Result<Carryover, String> {
    let mut rows: Vec<(String, u128)> = Vec::new();
    let mut total_sat: u128 = 0;

    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.is_empty() {
            return Err(format!("carryover line {n}: empty line"));
        }
        let (addr, value) = line
            .split_once('\t')
            .ok_or_else(|| format!("carryover line {n}: expected addr<TAB>value"))?;
        if !valid_addr_hex(addr) {
            return Err(format!("carryover line {n}: bad address hash {addr:?}"));
        }
        if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
            // A non-canonical integer means this file is not byte-identical to
            // what build_carryover.py wrote, so its digest cannot match the
            // published one anyway. Fail with a message instead of a mismatch.
            return Err(format!("carryover line {n}: non-canonical value {value:?}"));
        }
        let v: u128 = value
            .parse()
            .map_err(|_| format!("carryover line {n}: bad value {value:?}"))?;
        if let Some((prev, _)) = rows.last() {
            // Strict ascending order — the deterministic order the builder
            // emits. Also implies no duplicate addresses.
            if addr <= prev.as_str() {
                return Err(format!("carryover line {n}: rows not in ascending address order"));
            }
        }
        total_sat = total_sat
            .checked_add(v)
            .ok_or_else(|| format!("carryover line {n}: total overflows u128"))?;
        rows.push((addr.to_string(), v));
    }

    let digest =
        shake256_32_lines(rows.iter().map(|(a, v)| format!("{a}\t{v}\n")));
    Ok(Carryover { rows, digest, total_sat })
}

// ── Schedules and outputs ───────────────────────────────────────────────────

/// A consensus-enforced unlock schedule: `tge_bps` ten-thousandths released at
/// genesis, nothing more until `cliff_slots`, then linear release over
/// `linear_slots`. One shape covers every bucket in the spec's §7 table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Schedule {
    pub tge_bps: u16,
    pub cliff_slots: u64,
    pub linear_slots: u64,
}

impl Schedule {
    /// Fully liquid at genesis.
    pub const LIQUID: Schedule = Schedule { tge_bps: 10_000, cliff_slots: 0, linear_slots: 0 };

    pub fn is_liquid(&self) -> bool {
        self.tge_bps == 10_000 && self.cliff_slots == 0 && self.linear_slots == 0
    }

    /// Satoshis of a `value_sat` output unlocked by `slot`.
    ///
    /// Truncating integer arithmetic, identical shape to
    /// `tokenomics_v4::vested_sat` — the tests below assert slot-exact
    /// agreement with the crate's per-bucket functions, so the schedule the
    /// genesis carries and the schedule the consensus constants describe are
    /// provably the same function.
    pub fn unlocked_sat(&self, value_sat: u128, slot: u64) -> u128 {
        let tge = value_sat * self.tge_bps as u128 / 10_000;
        let locked = value_sat - tge;
        if slot < self.cliff_slots {
            return tge;
        }
        if self.linear_slots == 0 || slot - self.cliff_slots >= self.linear_slots {
            return value_sat;
        }
        tge + locked * (slot - self.cliff_slots) as u128 / self.linear_slots as u128
    }
}

/// One consensus-recognised genesis output.
#[derive(Clone, Debug)]
pub struct Output {
    /// Human label ("founder", "vc", …, "holder"). Informational; the
    /// consensus content is `(addr, value, schedule)`.
    pub bucket: &'static str,
    pub addr_hex: String,
    pub value_sat: u128,
    pub schedule: Schedule,
}

/// Destination addresses for the five allocation buckets, decided at the
/// ceremony. 20-byte lowercase-hex address hashes.
pub struct BucketAddrs {
    pub founder: String,
    pub vc: String,
    pub team: String,
    pub marketing: String,
    pub liquidity: String,
}

/// The assembled genesis: the five allocation outputs, one output per
/// carryover holder, and the supply accounting that must close exactly.
#[derive(Debug)]
pub struct Genesis {
    pub outputs: Vec<Output>,
    pub carryover_digest: [u8; 32],
    pub carryover_issued_sat: u128,
    /// The unfilled part of the 300 M cap. Never issued to anyone — recorded
    /// so the 100 B accounting balances to zero instead of "nearly".
    pub carryover_unissued_sat: u128,
}

/// The five bucket schedules, expressed from the tokenomics-v4 constants.
/// These are derivations, not restatements: change the crate and these follow.
pub fn founder_schedule() -> Schedule {
    Schedule { tge_bps: 0, cliff_slots: v4::FOUNDER_CLIFF_SLOTS, linear_slots: v4::FOUNDER_VESTING_SLOTS }
}
pub fn vc_schedule() -> Schedule {
    Schedule { tge_bps: 0, cliff_slots: v4::VC_CLIFF_SLOTS, linear_slots: v4::VC_VESTING_SLOTS }
}
pub fn team_schedule() -> Schedule {
    Schedule { tge_bps: 0, cliff_slots: v4::TEAM_CLIFF_SLOTS, linear_slots: v4::TEAM_VESTING_SLOTS }
}
pub fn marketing_schedule() -> Schedule {
    Schedule {
        tge_bps: (v4::MARKETING_TGE_NUMERATOR * 10_000 / v4::MARKETING_TGE_DENOMINATOR) as u16,
        cliff_slots: 0,
        linear_slots: v4::MARKETING_VESTING_SLOTS,
    }
}
pub fn liquidity_schedule() -> Schedule {
    Schedule::LIQUID
}

/// Assemble the genesis. Fail-closed on every input this tool cannot vouch
/// for itself:
///
/// - the recomputed artifact digest must equal `expected_digest` — the digest
///   published when the Genesis-3 chain halted (§3.2.2);
/// - the carryover total must respect the 300 M cap — an over-cap artifact
///   means `build_carryover.py` was not the thing that produced it;
/// - bucket addresses must be valid, mutually distinct, and absent from the
///   carryover set — a bucket address inside the carryover would double-issue
///   to that key and break the taint separation the artifact encodes.
pub fn build_genesis(
    carry: &Carryover,
    addrs: &BucketAddrs,
    expected_digest: &[u8; 32],
) -> Result<Genesis, String> {
    if &carry.digest != expected_digest {
        return Err(format!(
            "carryover digest mismatch: artifact recomputes to {}, expected {} — \
             refusing to build a genesis from an artifact that is not the published record",
            hex::encode(carry.digest),
            hex::encode(expected_digest),
        ));
    }

    let cap_sat = v4::HOLDER_CARRYOVER_CAP_BLOCH * v4::SAT_PER_BLOCH;
    if carry.total_sat > cap_sat {
        return Err(format!(
            "carryover total {} sat exceeds the {} sat cap — the artifact must already \
             be pro-rata scaled by build_carryover.py; this tool does not scale",
            carry.total_sat, cap_sat,
        ));
    }
    if carry.rows.is_empty() {
        // An empty holder set at ceremony time is a wrong-file operator error,
        // not a plausible state of the world (the measured floor is four
        // non-founder addresses holding 181.1 M BLCH).
        return Err("carryover artifact is empty — wrong file?".into());
    }

    let buckets = [
        ("founder", &addrs.founder, v4::FOUNDER_BLOCH, founder_schedule()),
        ("vc", &addrs.vc, v4::VC_BLOCH, vc_schedule()),
        ("team", &addrs.team, v4::TEAM_BLOCH, team_schedule()),
        ("marketing", &addrs.marketing, v4::MARKETING_BLOCH, marketing_schedule()),
        ("liquidity", &addrs.liquidity, v4::LIQUIDITY_BLOCH, liquidity_schedule()),
    ];

    let mut seen: Vec<&str> = Vec::new();
    for (name, addr, _, _) in &buckets {
        if !valid_addr_hex(addr) {
            return Err(format!("{name} address is not a 40-char lowercase-hex hash: {addr:?}"));
        }
        if seen.contains(&addr.as_str()) {
            return Err(format!("{name} address duplicates another bucket address"));
        }
        if carry.rows.iter().any(|(a, _)| a == *addr) {
            return Err(format!(
                "{name} address appears in the carryover artifact — a bucket address \
                 cannot also be a carried-over holder"
            ));
        }
        seen.push(addr.as_str());
    }

    let mut outputs: Vec<Output> = buckets
        .iter()
        .map(|(name, addr, bloch, sched)| Output {
            bucket: name,
            addr_hex: (*addr).clone(),
            value_sat: bloch * v4::SAT_PER_BLOCH,
            schedule: *sched,
        })
        .collect();
    for (addr, v) in &carry.rows {
        outputs.push(Output {
            bucket: "holder",
            addr_hex: addr.clone(),
            value_sat: *v,
            schedule: Schedule::LIQUID,
        });
    }

    let genesis = Genesis {
        outputs,
        carryover_digest: carry.digest,
        carryover_issued_sat: carry.total_sat,
        carryover_unissued_sat: cap_sat - carry.total_sat,
    };

    // The invariant this whole document exists to keep: genesis outputs plus
    // the unissued carryover remainder plus the 40-year validator emission is
    // EXACTLY the 100 B total. Not "at most" — a supply invariant that is
    // nearly satisfied is not an invariant.
    let issued: u128 = genesis.outputs.iter().map(|o| o.value_sat).sum();
    let total = issued
        + genesis.carryover_unissued_sat
        + v4::VALIDATOR_EMISSION_BLOCH * v4::SAT_PER_BLOCH;
    if total != v4::TOTAL_SUPPLY_SAT {
        return Err(format!(
            "supply accounting does not close: {total} != {}",
            v4::TOTAL_SUPPLY_SAT
        ));
    }

    Ok(genesis)
}

// ── Commitments ─────────────────────────────────────────────────────────────

fn output_leaf(o: &Output) -> [u8; 32] {
    // hex is validated at parse/build time, so decoding cannot fail here.
    let addr: [u8; 20] = hex::decode(&o.addr_hex).unwrap().try_into().unwrap();
    sha3_256(&[
        &DS_G4_OUT,
        &addr,
        &o.value_sat.to_le_bytes(),
        &o.schedule.tge_bps.to_le_bytes(),
        &o.schedule.cliff_slots.to_le_bytes(),
        &o.schedule.linear_slots.to_le_bytes(),
    ])
}

/// SHA3-256 Merkle root over the genesis outputs, in document order.
///
/// Odd nodes are promoted unchanged (no duplicate-last: the CVE-2012-2459
/// family of ambiguities comes from duplication) and the root is wrapped with
/// the leaf count, so trees over different output sets can never collide.
pub fn outputs_root(g: &Genesis) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = g.outputs.iter().map(output_leaf).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [l, r] => sha3_256(&[&DS_G4_NODE, l, r]),
                [l] => *l,
                _ => unreachable!(),
            });
        }
        level = next;
    }
    let inner = level.first().copied().unwrap_or([0u8; 32]);
    sha3_256(&[&DS_G4_ROOT, &(g.outputs.len() as u64).to_le_bytes(), &inner])
}

/// The genesis `state_root` (§5.5): commits to the outputs (with their locks),
/// to the carryover artifact digest — §3.2.2, the reason this tool exists —
/// and to the supply accounting. The Genesis-4 node's genesis loader must
/// reproduce this commitment from the allocation document or refuse to start,
/// the same fail-closed posture `chain_requires_carryover` gives Genesis-3.
pub fn state_root(g: &Genesis) -> [u8; 32] {
    let issued: u128 = g.outputs.iter().map(|o| o.value_sat).sum();
    sha3_256(&[
        &DS_G4_STATE,
        &outputs_root(g),
        &g.carryover_digest,
        &issued.to_le_bytes(),
        &g.carryover_unissued_sat.to_le_bytes(),
        &(v4::VALIDATOR_EMISSION_BLOCH * v4::SAT_PER_BLOCH).to_le_bytes(),
    ])
}

// ── BlockHeaderV4 ───────────────────────────────────────────────────────────

/// `BlockHeaderV4` (§5.3). Fixed-width little-endian canonical serialisation,
/// fields in spec order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderV4 {
    pub version: u32,
    pub parent: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
    pub slot: u64,
    pub proposer_index: u32,
    pub randao_reveal: [u8; 32],
    pub randao_mix: [u8; 32],
    pub justified_root: [u8; 32],
    pub finalized_root: [u8; 32],
    pub attestation_root: [u8; 32],
    pub coherence_root: [u8; 32],
}

pub const HEADER_V4_LEN: usize = 4 + 32 + 32 + 32 + 8 + 4 + 32 * 6;

impl HeaderV4 {
    pub fn serialize(&self) -> [u8; HEADER_V4_LEN] {
        let mut out = [0u8; HEADER_V4_LEN];
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
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
        out
    }

    /// `block_id = SHA3-256(DS_BLOCK ‖ canonical_header)` — the ONLY
    /// identifier (§5.4). No second hash, no mining projection.
    pub fn block_id(&self) -> [u8; 32] {
        sha3_256(&[&DS_BLOCK, &self.serialize()])
    }
}

/// Assemble the genesis header.
///
/// - `parent`, `body_root`, checkpoint roots, `attestation_root` and
///   `coherence_root` are all-zeros: no parent, empty body, genesis is its own
///   finalised checkpoint, no attestations, empty shielded pool.
/// - `randao_mix` is seeded by one §6 mixing step over the carryover digest,
///   so even the beacon chain's origin entropy is pinned to the artifact.
pub fn genesis_header(g: &Genesis) -> HeaderV4 {
    HeaderV4 {
        version: GENESIS4_VERSION,
        parent: [0u8; 32],
        state_root: state_root(g),
        body_root: [0u8; 32],
        slot: 0,
        proposer_index: GENESIS_PROPOSER_INDEX,
        randao_reveal: [0u8; 32],
        randao_mix: sha3_256(&[&DS_RANDAO, &[0u8; 32], &g.carryover_digest]),
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    }
}

// ── Document rendering ──────────────────────────────────────────────────────

/// Render the canonical genesis allocation document: deterministic, line-based
/// TSV in the same family as the carryover artifact. This is the file the
/// Genesis-4 node's genesis loader consumes and re-commits into `state_root`.
pub fn render_document(g: &Genesis) -> String {
    let mut s = String::new();
    s.push_str("bloch-genesis4\t1\n");
    s.push_str(&format!("chain-id\t{:#010x}\n", GENESIS4_VERSION));
    s.push_str(&format!("total-supply-sat\t{}\n", v4::TOTAL_SUPPLY_SAT));
    s.push_str(&format!(
        "validator-emission-sat\t{}\n",
        v4::VALIDATOR_EMISSION_BLOCH * v4::SAT_PER_BLOCH
    ));
    s.push_str(&format!(
        "carryover-cap-sat\t{}\n",
        v4::HOLDER_CARRYOVER_CAP_BLOCH * v4::SAT_PER_BLOCH
    ));
    s.push_str(&format!("carryover-issued-sat\t{}\n", g.carryover_issued_sat));
    s.push_str(&format!("carryover-unissued-sat\t{}\n", g.carryover_unissued_sat));
    s.push_str(&format!(
        "carryover-artifact-shake256\t{}\n",
        hex::encode(g.carryover_digest)
    ));
    for o in &g.outputs {
        // Allocation lines carry the bucket label; holder lines do not need
        // one (the kind IS the label). Both end with the same four consensus
        // columns: value_sat, tge_bps, cliff_slots, linear_slots.
        if o.bucket == "holder" {
            s.push_str(&format!(
                "holder\t{}\t{}\t{}\t{}\t{}\n",
                o.addr_hex,
                o.value_sat,
                o.schedule.tge_bps,
                o.schedule.cliff_slots,
                o.schedule.linear_slots,
            ));
        } else {
            s.push_str(&format!(
                "alloc\t{}\t{}\t{}\t{}\t{}\t{}\n",
                o.bucket,
                o.addr_hex,
                o.value_sat,
                o.schedule.tge_bps,
                o.schedule.cliff_slots,
                o.schedule.linear_slots,
            ));
        }
    }
    s
}

/// SHAKE-256 digest of the rendered document — same 32-byte convention as the
/// carryover artifact, for the sidecar file and the announcement.
pub fn document_digest(doc: &str) -> [u8; 32] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(doc.as_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> BucketAddrs {
        BucketAddrs {
            founder: "11".repeat(20),
            vc: "22".repeat(20),
            team: "33".repeat(20),
            marketing: "44".repeat(20),
            liquidity: "55".repeat(20),
        }
    }

    /// Two-row fixture mirroring the KAT generated with CPython's
    /// hashlib.shake_256 — the digest build_carryover.py would publish.
    const KAT2_TEXT: &str = concat!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t1000000000\n",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t250000000\n",
    );
    const KAT2_DIGEST: &str = "8cbd6749c8a79bba93455784fe3450681f02b52c8848a6e80c8ee31c429a75cd";

    fn kat_genesis() -> Genesis {
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let expected: [u8; 32] = hex::decode(KAT2_DIGEST).unwrap().try_into().unwrap();
        build_genesis(&carry, &addrs(), &expected).unwrap()
    }

    // ── Digest: cross-language agreement and fail-closed behaviour ─────────

    #[test]
    fn shake256_matches_python_builder() {
        // Known-answer: hashlib.shake_256 over the same canonical lines.
        // If this breaks, the ceremony would reject every artifact the Python
        // builder publishes — the two implementations must agree forever.
        let c = read_carryover(KAT2_TEXT).unwrap();
        assert_eq!(hex::encode(c.digest), KAT2_DIGEST);
        let c1 = read_carryover("cccccccccccccccccccccccccccccccccccccccc\t1\n").unwrap();
        assert_eq!(
            hex::encode(c1.digest),
            "eb4b64f18279626a06e6aa0bcc0fdebb4401d3ca2b2d7a13ebf62ee9e8f96fae"
        );
    }

    #[test]
    fn digest_mismatch_refuses_to_build() {
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let mut wrong = carry.digest;
        wrong[0] ^= 1;
        let err = build_genesis(&carry, &addrs(), &wrong).unwrap_err();
        assert!(err.contains("digest mismatch"), "{err}");
    }

    #[test]
    fn tampered_artifact_changes_digest() {
        // One satoshi moved: digest must change, so the published digest
        // no longer matches and the build refuses.
        let tampered = KAT2_TEXT.replace("250000000", "250000001");
        let good = read_carryover(KAT2_TEXT).unwrap();
        let bad = read_carryover(&tampered).unwrap();
        assert_ne!(good.digest, bad.digest);
        assert!(build_genesis(&bad, &addrs(), &good.digest).is_err());
    }

    #[test]
    fn embedded_digest_is_the_artifact_digest() {
        // §3.2.2 — the digest inside the genesis is byte-identical to the
        // artifact's, it appears in the rendered document, and it is committed
        // through state_root into block_id: swapping the artifact silently is
        // impossible without changing the chain's identity.
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let g = kat_genesis();
        assert_eq!(g.carryover_digest, carry.digest);
        assert!(render_document(&g).contains(KAT2_DIGEST));

        let mut forged = kat_genesis();
        forged.carryover_digest[31] ^= 0xff;
        assert_ne!(state_root(&g), state_root(&forged));
        assert_ne!(genesis_header(&g).block_id(), genesis_header(&forged).block_id());
    }

    #[test]
    fn strict_parser_rejects_non_canonical_encodings() {
        for bad in [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\t5\n", // uppercase hex
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t05\n", // leading zero
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 5\n",  // no tab
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t1\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2\n", // unsorted
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t1\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2\n", // duplicate
        ] {
            assert!(read_carryover(bad).is_err(), "accepted: {bad:?}");
        }
    }

    // ── Supply: the sum is exactly 100,000,000,000 BLCH ────────────────────

    #[test]
    fn allocations_sum_to_exactly_100_billion() {
        let g = kat_genesis();
        let issued: u128 = g.outputs.iter().map(|o| o.value_sat).sum();
        let total = issued
            + g.carryover_unissued_sat
            + v4::VALIDATOR_EMISSION_BLOCH * v4::SAT_PER_BLOCH;
        assert_eq!(total, v4::TOTAL_SUPPLY_SAT);
        assert_eq!(total, 100_000_000_000 * 100_000_000); // spelled out
        // And the unissued remainder is exactly the cap minus the artifact
        // total — the cap headroom is never issued to anyone.
        assert_eq!(
            g.carryover_issued_sat + g.carryover_unissued_sat,
            v4::HOLDER_CARRYOVER_CAP_BLOCH * v4::SAT_PER_BLOCH
        );
    }

    #[test]
    fn bucket_values_match_the_spec_table() {
        let g = kat_genesis();
        let get = |b: &str| g.outputs.iter().find(|o| o.bucket == b).unwrap().value_sat;
        let sat = |bloch: u128| bloch * v4::SAT_PER_BLOCH;
        assert_eq!(get("founder"), sat(17_000_000_000));
        assert_eq!(get("vc"), sat(10_000_000_000));
        assert_eq!(get("team"), sat(10_000_000_000));
        assert_eq!(get("marketing"), sat(4_000_000_000));
        assert_eq!(get("liquidity"), sat(5_000_000_000));
        assert_eq!(v4::VALIDATOR_EMISSION_BLOCH, 53_700_000_000);
    }

    #[test]
    fn over_cap_artifact_is_refused() {
        // 300,000,001 BLCH of carryover — one BLCH over the cap. The ceremony
        // does not scale — pro-rata scaling is the builder's job — so it must
        // refuse rather than repair.
        let text = format!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t{}\n",
            300_000_001u128 * v4::SAT_PER_BLOCH
        );
        let carry = read_carryover(&text).unwrap();
        let digest = carry.digest;
        let err = build_genesis(&carry, &addrs(), &digest).unwrap_err();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn exactly_at_cap_is_accepted_and_sums_to_100b() {
        let text = format!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t{}\n",
            v4::HOLDER_CARRYOVER_CAP_BLOCH * v4::SAT_PER_BLOCH
        );
        let carry = read_carryover(&text).unwrap();
        let digest = carry.digest;
        let g = build_genesis(&carry, &addrs(), &digest).unwrap();
        assert_eq!(g.carryover_unissued_sat, 0);
        let issued: u128 = g.outputs.iter().map(|o| o.value_sat).sum();
        assert_eq!(
            issued + v4::VALIDATOR_EMISSION_BLOCH * v4::SAT_PER_BLOCH,
            v4::TOTAL_SUPPLY_SAT
        );
    }

    // ── Locks: none absent, all consensus-visible, all correct ─────────────

    #[test]
    fn no_lock_is_absent() {
        // Every bucket that the spec says is locked IS locked, and every
        // bucket that must be liquid IS liquid. An output with a missing
        // schedule cannot exist by construction (the field is not optional),
        // so "absent" here means "wrongly liquid".
        let g = kat_genesis();
        let sched = |b: &str| g.outputs.iter().find(|o| o.bucket == b).unwrap().schedule;

        for locked in ["founder", "vc", "team"] {
            let s = sched(locked);
            assert_eq!(s.tge_bps, 0, "{locked}: nothing liquid at genesis");
            assert!(s.cliff_slots > 0, "{locked}: cliff missing");
            assert!(s.linear_slots > 0, "{locked}: linear vesting missing");
        }
        let m = sched("marketing");
        assert_eq!(m.tge_bps, 2_500, "marketing: 25% at TGE");
        assert_eq!(m.cliff_slots, 0);
        assert!(m.linear_slots > 0, "marketing: linear vesting missing");
        assert!(sched("liquidity").is_liquid());
        for o in g.outputs.iter().filter(|o| o.bucket == "holder") {
            assert!(o.schedule.is_liquid(), "carryover holders are liquid by decision");
        }
    }

    #[test]
    fn schedules_are_the_spec_schedules_in_slots() {
        // §7 table, converted at 2,880 slots/day, 87,660 slots/month.
        assert_eq!(v4::MONTH_SLOTS, 87_660);
        let f = founder_schedule();
        assert_eq!((f.cliff_slots, f.linear_slots), (24 * v4::MONTH_SLOTS, 120 * v4::MONTH_SLOTS));
        let vc = vc_schedule();
        assert_eq!((vc.cliff_slots, vc.linear_slots), (12 * v4::MONTH_SLOTS, 24 * v4::MONTH_SLOTS));
        let t = team_schedule();
        assert_eq!((t.cliff_slots, t.linear_slots), (18 * v4::MONTH_SLOTS, 36 * v4::MONTH_SLOTS));
        let m = marketing_schedule();
        assert_eq!(m.linear_slots, 24 * v4::MONTH_SLOTS);
    }

    #[test]
    fn unlock_curves_agree_with_tokenomics_v4_slot_exactly() {
        // The schedule carried in the genesis and the closed-form functions in
        // the consensus constants crate must be the same function — checked at
        // the boundary slots where truncating arithmetic likes to disagree,
        // plus a sweep.
        let g = kat_genesis();
        let out = |b: &str| g.outputs.iter().find(|o| o.bucket == b).unwrap();
        type Ref = fn(u64) -> u128;
        let cases: [(&str, Ref); 5] = [
            ("founder", v4::founder_vested_sat),
            ("vc", v4::vc_vested_sat),
            ("team", v4::team_vested_sat),
            ("marketing", v4::marketing_vested_sat),
            ("liquidity", v4::liquidity_vested_sat),
        ];
        for (bucket, reference) in cases {
            let o = out(bucket);
            let end = o.schedule.cliff_slots + o.schedule.linear_slots;
            let mut slots = vec![
                0,
                1,
                o.schedule.cliff_slots.saturating_sub(1),
                o.schedule.cliff_slots,
                o.schedule.cliff_slots + 1,
                end / 2,
                end.saturating_sub(1),
                end,
                end + 1,
                u64::MAX / 2,
            ];
            slots.extend((0..=1000u64).map(|i| i * (end / 1000).max(1)));
            for slot in slots {
                assert_eq!(
                    o.schedule.unlocked_sat(o.value_sat, slot),
                    reference(slot),
                    "{bucket} diverges at slot {slot}"
                );
            }
        }
    }

    #[test]
    fn liquid_at_genesis_is_exactly_marketing_tge_plus_liquidity_plus_holders() {
        let g = kat_genesis();
        let liquid: u128 = g
            .outputs
            .iter()
            .map(|o| o.schedule.unlocked_sat(o.value_sat, 0))
            .sum();
        let expected = 1_000_000_000 * v4::SAT_PER_BLOCH  // 25% of marketing
            + 5_000_000_000 * v4::SAT_PER_BLOCH           // liquidity
            + g.carryover_issued_sat;                     // holders
        assert_eq!(liquid, expected);
        // The founder holds NO spendable stake at genesis (§5 of the spec).
        let founder = g.outputs.iter().find(|o| o.bucket == "founder").unwrap();
        assert_eq!(founder.schedule.unlocked_sat(founder.value_sat, 0), 0);
    }

    // ── Bucket-address hygiene ─────────────────────────────────────────────

    #[test]
    fn bucket_address_collisions_are_refused() {
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let digest = carry.digest;

        let mut dup = addrs();
        dup.vc = dup.founder.clone();
        assert!(build_genesis(&carry, &dup, &digest).is_err());

        let mut in_carry = addrs();
        in_carry.team = "aa".repeat(20); // present in the artifact
        assert!(build_genesis(&carry, &in_carry, &digest).is_err());

        let mut bad_hex = addrs();
        bad_hex.marketing = "zz".repeat(20);
        assert!(build_genesis(&carry, &bad_hex, &digest).is_err());
    }

    // ── Header and determinism ─────────────────────────────────────────────

    #[test]
    fn header_is_canonical_and_deterministic() {
        let g1 = kat_genesis();
        let g2 = kat_genesis();
        let h1 = genesis_header(&g1);
        let h2 = genesis_header(&g2);
        assert_eq!(h1, h2);
        assert_eq!(h1.block_id(), h2.block_id());
        assert_eq!(h1.serialize().len(), HEADER_V4_LEN);
        assert_eq!(h1.version, 0xB10C_0005);
        assert_eq!(h1.slot, 0);
        assert_eq!(h1.parent, [0u8; 32]);
        assert_eq!(render_document(&g1), render_document(&g2));
        // randao origin entropy is pinned to the artifact
        assert_eq!(
            h1.randao_mix,
            sha3_256(&[&DS_RANDAO, &[0u8; 32], &g1.carryover_digest])
        );
    }

    #[test]
    fn locks_are_inside_the_block_identity() {
        // The §8.2 standard: a lock enforced by consensus, not by promise.
        // Strip the founder lock and the block_id changes — an unlocked
        // genesis is a visibly different chain, not the same chain with a
        // broken promise.
        let g = kat_genesis();
        let mut unlocked = kat_genesis();
        for o in unlocked.outputs.iter_mut() {
            if o.bucket == "founder" {
                o.schedule = Schedule::LIQUID;
            }
        }
        assert_ne!(outputs_root(&g), outputs_root(&unlocked));
        assert_ne!(genesis_header(&g).block_id(), genesis_header(&unlocked).block_id());
    }

    #[test]
    fn document_round_trips_the_essentials() {
        let g = kat_genesis();
        let doc = render_document(&g);
        // 5 allocation lines, one holder line per carryover row, digest line.
        assert_eq!(doc.matches("\nalloc\t").count() + usize::from(doc.starts_with("alloc\t")), 5);
        assert_eq!(doc.matches("\nholder\t").count(), 2);
        assert!(doc.contains(&format!("total-supply-sat\t{}", v4::TOTAL_SUPPLY_SAT)));
        // Digest of the document is stable.
        assert_eq!(document_digest(&doc), document_digest(&render_document(&g)));
    }
}
