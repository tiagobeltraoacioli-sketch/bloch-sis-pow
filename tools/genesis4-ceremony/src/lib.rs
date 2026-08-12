// SPDX-License-Identifier: MIT OR Apache-2.0

//! Genesis-4 ceremony — assemble the Genesis-4 genesis block from the signed
//! carryover artifact and the published genesis validator cohort.
//!
//! Spec: `docs/specs/BLOCH-TOKENOMICS-V4.md` (allocations §1, carryover §2–§3,
//! artifact-is-canonical §3.2.2, genesis validator set §3.3, cohort one-year
//! rule §3.3.1, consensus-enforced locks §8.2) and
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
//! 2. **The genesis validator cohort** (§3.3) — the fixed set of founder-run
//!    validators active from slot 0, published as consensus data. The
//!    declining cohort cap in `bloch-pos-committee/src/genesis_cohort.rs`
//!    (100% → one third over one year) binds *this* set; if the set were not
//!    in the block, the cap would have nothing to bind and the one-year rule
//!    would be a promise instead of a consensus rule. The cohort root is a
//!    leaf of `state_root`, so the set is inside the chain's identity.
//! 3. **The genesis header** (`BlockHeaderV4`, §5.3) and its `block_id`.
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
//! — the crate whose compile-time assertions pin the 21 B total and the
//! validator remainder (spec §8.1). No allocation number is restated here:
//! change the constants crate and this tool follows, or fails to compile.

use bloch_pos_committee::params::SLOTS_PER_EPOCH;
use bloch_pos_committee::staking::{HYBRID_PK_BYTES, MIN_DEPOSIT_SAT, SUITE_MLDSA65_FALCON1024};
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
/// Genesis validator-cohort leaf.
pub const DS_G4_VAL: [u8; 16] = *b"BLCH4:G4VAL\0\0\0\0\0";
/// Genesis validator-cohort Merkle inner node.
pub const DS_G4_VNODE: [u8; 16] = *b"BLCH4:G4VNODE\0\0\0";
/// Genesis validator-cohort Merkle root wrapper (binds the member count).
pub const DS_G4_VROOT: [u8; 16] = *b"BLCH4:G4VROOT\0\0\0";
/// Genesis state commitment.
pub const DS_G4_STATE: [u8; 16] = *b"BLCH4:G4STATE\0\0\0";

/// Header version for Genesis-4 (§5.3).
pub const GENESIS4_VERSION: u32 = 0xB10C_0005;

/// Sentinel proposer index for the genesis block. Genesis has no proposer and
/// no proposer signature — it is agreed by configuration, like every chain's
/// genesis. `u32::MAX` can never be a real validator index.
pub const GENESIS_PROPOSER_INDEX: u32 = u32::MAX;

/// Minimum size of the genesis cohort (tokenomics §3.3): the epoch is
/// partitioned into one committee per slot, so a set below `SLOTS_PER_EPOCH`
/// leaves slots with no attesters, and the spec's floor of twice that gives
/// every slot at least two. Derived, not restated — if the epoch length moves,
/// the floor moves with it.
pub const GENESIS_COHORT_FLOOR: usize = 2 * SLOTS_PER_EPOCH as usize;

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

// ── Canonical text plumbing ─────────────────────────────────────────────────

fn valid_addr_hex(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn lower_hex(s: &str, bytes: usize) -> Option<Vec<u8>> {
    if s.len() != bytes * 2 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()
}

/// Canonical decimal: non-empty, no leading zero (except "0" itself). Anything
/// non-canonical means the file is not byte-identical to what the builder
/// wrote, so its digest could not match the published one anyway — fail with a
/// message instead of a digest mismatch.
fn canonical_u128(s: &str) -> Option<u128> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
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
        let v = canonical_u128(value)
            .ok_or_else(|| format!("carryover line {n}: non-canonical value {value:?}"))?;
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

// ── Genesis validator cohort ────────────────────────────────────────────────

/// One member of the genesis validator cohort (§3.3): a validator record
/// active from slot 0 with no deposit transaction, because there is no chain
/// yet to carry one. The fields mirror `staking::DepositTx` minus the proof of
/// possession — genesis records are agreed by ceremony, not admitted by
/// signature check, and every *later* validator joins through the ordinary
/// deposit path with a real PoP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisValidator {
    /// Registry index. The cohort occupies indices `0..n` contiguously, so
    /// the published index list is exactly what
    /// `genesis_cohort::apply_cohort_cap` consumes (sorted ascending).
    pub index: u32,
    /// RAW hybrid public key, ML-DSA-65 ‖ Falcon-1024, exactly
    /// [`HYBRID_PK_BYTES`] — the `staking.rs` convention, where the suite tag
    /// is a separate field rather than the 4-byte `bloch-crypto` envelope.
    pub pubkey: Vec<u8>,
    /// RANDAO commitment `c_0` (§6.3) — the head of the validator's SHAKE-256
    /// hash chain (`beacon.rs`), committed up front so reveals can be checked
    /// by preimage from the validator's very first proposed slot.
    pub randao_commitment: [u8; 32],
    /// Bonded stake in satoshis, funded from the liquidity bucket (§3.3.1).
    pub stake_sat: u128,
    /// Where the stake returns on exit — `staking::Address`, fixed at
    /// registration so a hot validator key cannot redirect the principal.
    pub withdrawal_addr: [u8; 32],
}

/// Parse the cohort file: one line per validator,
/// `index<TAB>pubkey_hex<TAB>randao_c0_hex<TAB>stake_sat<TAB>withdrawal_hex`,
/// indices contiguous from 0. Strict for the same reason the carryover parser
/// is: this file is published alongside the artifact and re-hashed by every
/// verifier, so only one byte encoding of a given cohort may parse.
pub fn read_cohort(text: &str) -> Result<Vec<GenesisValidator>, String> {
    let mut out: Vec<GenesisValidator> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() != 5 {
            return Err(format!(
                "cohort line {n}: expected index<TAB>pubkey<TAB>randao_c0<TAB>stake_sat<TAB>withdrawal"
            ));
        }
        let index = canonical_u128(cols[0])
            .filter(|&v| v == i as u128)
            .ok_or_else(|| format!("cohort line {n}: index must be {} (contiguous from 0)", i))?
            as u32;
        let pubkey = lower_hex(cols[1], HYBRID_PK_BYTES).ok_or_else(|| {
            // The one near-miss worth a targeted message: keys exported by the
            // bloch-crypto tooling carry a 4-byte suite envelope; the cohort
            // file (like staking::DepositTx) wants the raw hybrid key.
            if cols[1].len() == (HYBRID_PK_BYTES + 4) * 2 {
                format!(
                    "cohort line {n}: pubkey is 4 bytes too long — strip the bloch-crypto \
                     suite-envelope header; this file carries the raw {HYBRID_PK_BYTES}-byte hybrid key"
                )
            } else {
                format!(
                    "cohort line {n}: pubkey must be {} lowercase-hex chars (raw ML-DSA-65 ‖ Falcon-1024)",
                    HYBRID_PK_BYTES * 2
                )
            }
        })?;
        let c0: [u8; 32] = lower_hex(cols[2], 32)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("cohort line {n}: randao_c0 must be 64 lowercase-hex chars"))?;
        let stake_sat = canonical_u128(cols[3])
            .ok_or_else(|| format!("cohort line {n}: non-canonical stake {:?}", cols[3]))?;
        let withdrawal_addr: [u8; 32] = lower_hex(cols[4], 32)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("cohort line {n}: withdrawal must be 64 lowercase-hex chars"))?;
        out.push(GenesisValidator { index, pubkey, randao_commitment: c0, stake_sat, withdrawal_addr });
    }
    Ok(out)
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
/// carryover holder, the genesis validator cohort, and the supply accounting
/// that must close exactly.
#[derive(Debug)]
pub struct Genesis {
    pub outputs: Vec<Output>,
    /// The §3.3 cohort, indices 0..n, published in the block.
    pub validators: Vec<GenesisValidator>,
    pub carryover_digest: [u8; 32],
    pub carryover_issued_sat: u128,
    /// Combined bonded stake of the cohort, deducted from the liquidity
    /// output (§3.3.1: the cohort is funded from the Foundation's liquid
    /// holdings, and bonded stake cannot also be a spendable output).
    pub cohort_stake_sat: u128,
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
/// - the carryover total must equal `CARRYOVER_TOTAL_BLOCH` **exactly**. The
///   cap is retired (§3 "The cap, retired"): the whole measured ledger comes
///   across, founder included, and the constants crate already balances the
///   21 B supply around that exact figure. An artifact with any other total is
///   either not the published record or was measured at a different height
///   than the constants — both are ceremony-stopping, not scalable;
/// - bucket addresses must be valid, mutually distinct, and absent from the
///   carryover set. Not a taint rule (that dissolved with the cap) — a loader
///   rule: every genesis address carries exactly one schedule, so an address
///   may not appear both as a liquid holder and as a vested bucket;
/// - the cohort must satisfy §3.3: at least [`GENESIS_COHORT_FLOOR`] members,
///   each with a raw hybrid pubkey, a nonzero RANDAO commitment, and at least
///   [`MIN_DEPOSIT_SAT`] of stake, all funded from within the liquidity
///   bucket. (The §4.1.3 per-validator maximum — 1% of active stake — is
///   deliberately not applied: at genesis the cohort IS the active set, and a
///   self-referential 1% cap would deadlock the bootstrap; `staking.rs` makes
///   the same argument for the deposit path.)
pub fn build_genesis(
    carry: &Carryover,
    addrs: &BucketAddrs,
    cohort: &[GenesisValidator],
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

    let carry_total_sat = v4::CARRYOVER_TOTAL_BLOCH * v4::SAT_PER_BLOCH;
    if carry.total_sat != carry_total_sat {
        return Err(format!(
            "carryover total {} sat != the measured ledger {} sat pinned in tokenomics_v4 — \
             either the artifact is not the published record or the constants were pinned \
             at a different snapshot height; both stop the ceremony",
            carry.total_sat, carry_total_sat,
        ));
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
                "{name} address appears in the carryover artifact — every genesis address \
                 carries exactly one schedule, so a vested bucket cannot share an address \
                 with a liquid holder"
            ));
        }
        seen.push(addr.as_str());
    }

    // ── Cohort validation (§3.3) ────────────────────────────────────────────
    if cohort.len() < GENESIS_COHORT_FLOOR {
        return Err(format!(
            "genesis cohort has {} validators, below the floor of {} — the epoch partition \
             needs at least two attesters per slot (tokenomics §3.3)",
            cohort.len(),
            GENESIS_COHORT_FLOOR,
        ));
    }
    let mut cohort_stake_sat: u128 = 0;
    for v in cohort {
        if v.pubkey.len() != HYBRID_PK_BYTES {
            return Err(format!("validator {}: pubkey is not {HYBRID_PK_BYTES} bytes", v.index));
        }
        if v.randao_commitment == [0u8; 32] {
            return Err(format!(
                "validator {}: all-zero RANDAO commitment — a validator without a committed \
                 hash chain can never propose (beacon.rs)",
                v.index
            ));
        }
        if v.stake_sat < MIN_DEPOSIT_SAT {
            return Err(format!(
                "validator {}: stake {} sat is below MIN_DEPOSIT_SAT {}",
                v.index, v.stake_sat, MIN_DEPOSIT_SAT
            ));
        }
        // `sample::Validator::effective_stake` is u64; a genesis stake that
        // cannot enter the sortition arithmetic is malformed here, not there.
        if v.stake_sat > u64::MAX as u128 {
            return Err(format!("validator {}: stake does not fit u64 effective stake", v.index));
        }
        cohort_stake_sat = cohort_stake_sat
            .checked_add(v.stake_sat)
            .ok_or_else(|| format!("validator {}: cohort stake overflows u128", v.index))?;
    }
    for (i, a) in cohort.iter().enumerate() {
        for b in &cohort[i + 1..] {
            if a.pubkey == b.pubkey {
                return Err(format!(
                    "validators {} and {} share a pubkey — one key, one validator",
                    a.index, b.index
                ));
            }
            if a.randao_commitment == b.randao_commitment {
                return Err(format!(
                    "validators {} and {} share a RANDAO commitment — each validator commits \
                     its own hash chain; a shared c_0 means a copy-pasted seed",
                    a.index, b.index
                ));
            }
        }
    }

    // §3.3.1: the cohort is funded from the Foundation's liquid holdings —
    // the liquidity bucket, the only Foundation bucket fully liquid at slot 0.
    // Bonded stake is consensus state, not a spendable output, so the genesis
    // liquidity output is reduced by exactly the bonded amount: nothing is
    // minted for the cohort and the 21 B accounting still closes.
    let liquidity_sat = v4::LIQUIDITY_BLOCH * v4::SAT_PER_BLOCH;
    if cohort_stake_sat > liquidity_sat {
        return Err(format!(
            "cohort stake {} sat exceeds the liquidity bucket {} sat it is funded from (§3.3.1)",
            cohort_stake_sat, liquidity_sat,
        ));
    }

    let mut outputs: Vec<Output> = buckets
        .iter()
        .map(|(name, addr, bloch, sched)| {
            let mut value_sat = bloch * v4::SAT_PER_BLOCH;
            if *name == "liquidity" {
                value_sat -= cohort_stake_sat;
            }
            Output { bucket: name, addr_hex: (*addr).clone(), value_sat, schedule: *sched }
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
        validators: cohort.to_vec(),
        carryover_digest: carry.digest,
        carryover_issued_sat: carry.total_sat,
        cohort_stake_sat,
    };

    // The invariant this whole document exists to keep: genesis outputs plus
    // the cohort's bonded stake plus the 40-year validator emission is
    // EXACTLY the 21 B total. Not "at most" — a supply invariant that is
    // nearly satisfied is not an invariant.
    let issued: u128 = genesis.outputs.iter().map(|o| o.value_sat).sum();
    let total = issued
        + genesis.cohort_stake_sat
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

fn validator_leaf(v: &GenesisValidator) -> [u8; 32] {
    // Mirrors `DepositTx::signing_root`'s field set (suite, amount, pubkey,
    // randao_commitment, withdrawal) plus the registry index, under the
    // cohort's own domain tag. All fields fixed-width, so no two distinct
    // records can serialize identically.
    sha3_256(&[
        &DS_G4_VAL,
        &v.index.to_le_bytes(),
        &SUITE_MLDSA65_FALCON1024.to_le_bytes(),
        &v.pubkey,
        &v.randao_commitment,
        &v.stake_sat.to_le_bytes(),
        &v.withdrawal_addr,
    ])
}

/// SHA3-256 Merkle root in document order: odd nodes are promoted unchanged
/// (no duplicate-last — the CVE-2012-2459 family of ambiguities comes from
/// duplication) and the root is wrapped with the leaf count, so trees over
/// different sets can never collide.
fn merkle_root(
    mut level: Vec<[u8; 32]>,
    node_tag: &[u8; 16],
    root_tag: &[u8; 16],
) -> [u8; 32] {
    let count = level.len() as u64;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [l, r] => sha3_256(&[node_tag, l, r]),
                [l] => *l,
                _ => unreachable!(),
            });
        }
        level = next;
    }
    let inner = level.first().copied().unwrap_or([0u8; 32]);
    sha3_256(&[root_tag, &count.to_le_bytes(), &inner])
}

/// Merkle root over the genesis outputs, in document order.
pub fn outputs_root(g: &Genesis) -> [u8; 32] {
    merkle_root(g.outputs.iter().map(output_leaf).collect(), &DS_G4_NODE, &DS_G4_ROOT)
}

/// Merkle root over the genesis validator cohort, in index order. This is the
/// commitment the declining cohort cap hangs off: the set
/// `genesis_cohort::apply_cohort_cap` binds is exactly the leaves of this
/// tree, published once, in the block, shrink-only.
pub fn cohort_root(g: &Genesis) -> [u8; 32] {
    merkle_root(g.validators.iter().map(validator_leaf).collect(), &DS_G4_VNODE, &DS_G4_VROOT)
}

/// The genesis `state_root` (§5.5): commits to the outputs (with their locks),
/// to the validator cohort (§3.3 — the set the one-year cap binds), to the
/// carryover artifact digest — §3.2.2, the reason this tool exists — and to
/// the supply accounting. The Genesis-4 node's genesis loader must reproduce
/// this commitment from the allocation document or refuse to start, the same
/// fail-closed posture `chain_requires_carryover` gives Genesis-3.
pub fn state_root(g: &Genesis) -> [u8; 32] {
    let issued: u128 = g.outputs.iter().map(|o| o.value_sat).sum();
    sha3_256(&[
        &DS_G4_STATE,
        &outputs_root(g),
        &cohort_root(g),
        &g.carryover_digest,
        &issued.to_le_bytes(),
        &g.cohort_stake_sat.to_le_bytes(),
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
///   (The cohort's own RANDAO chains take over from slot 1: each member's
///   `c_0` is in its cohort leaf, hence already inside `state_root`.)
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
    s.push_str(&format!("carryover-total-sat\t{}\n", g.carryover_issued_sat));
    s.push_str(&format!(
        "carryover-artifact-shake256\t{}\n",
        hex::encode(g.carryover_digest)
    ));
    s.push_str(&format!("cohort-size\t{}\n", g.validators.len()));
    s.push_str(&format!("cohort-stake-sat\t{}\n", g.cohort_stake_sat));
    // The funding decision (§3.3.1) as data, so the loader can enforce that
    // the liquidity output plus the bonded stake reconstitutes the bucket.
    s.push_str("cohort-funding\tliquidity\n");
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
    for v in &g.validators {
        s.push_str(&format!(
            "validator\t{}\t{}\t{}\t{}\t{}\n",
            v.index,
            hex::encode(&v.pubkey),
            hex::encode(v.randao_commitment),
            v.stake_sat,
            hex::encode(v.withdrawal_addr),
        ));
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
    use bloch_pos_committee::beacon::RandaoChain;
    use bloch_pos_committee::genesis_cohort::{
        apply_cohort_cap, cohort_share_bps, COHORT_TAPER_EPOCHS,
    };
    use bloch_pos_committee::sample::Validator;

    fn addrs() -> BucketAddrs {
        BucketAddrs {
            founder: "11".repeat(20),
            vc: "22".repeat(20),
            team: "33".repeat(20),
            marketing: "44".repeat(20),
            liquidity: "55".repeat(20),
        }
    }

    /// Deterministic pseudo-bytes for test keys and seeds. Test-only: real
    /// cohort keys come from `generate_keypair` and are NEVER produced here.
    fn pseudo_bytes(tag: u8, i: u32, len: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut h = sha3::Shake256::default();
        h.update(b"g4-ceremony-test");
        h.update(&[tag]);
        h.update(&i.to_le_bytes());
        let mut out = vec![0u8; len];
        h.finalize_xof().read(&mut out);
        out
    }

    /// RANDAO commitment for test validator `i` — the head of a REAL
    /// 8,192-step `beacon::RandaoChain`, so the fixture exercises the actual
    /// protocol object, not a mock. Computed once per process: walking 64
    /// full chains is ~half a million SHAKE-256 calls, which debug builds
    /// should not repeat per test.
    fn test_c0(i: u32) -> [u8; 32] {
        use std::sync::OnceLock;
        static C0S: OnceLock<Vec<[u8; 32]>> = OnceLock::new();
        C0S.get_or_init(|| {
            (0..GENESIS_COHORT_FLOOR as u32)
                .map(|i| {
                    let seed: [u8; 32] = pseudo_bytes(2, i, 32).try_into().unwrap();
                    RandaoChain::generate(seed).commitment()
                })
                .collect()
        })[i as usize]
    }

    /// A canonical test cohort of `n` validators at minimum stake.
    fn cohort_text(n: usize) -> String {
        let mut s = String::new();
        for i in 0..n {
            let pk = pseudo_bytes(1, i as u32, HYBRID_PK_BYTES);
            s.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                i,
                hex::encode(&pk),
                hex::encode(test_c0(i as u32)),
                MIN_DEPOSIT_SAT,
                "77".repeat(32),
            ));
        }
        s
    }

    fn test_cohort() -> Vec<GenesisValidator> {
        read_cohort(&cohort_text(GENESIS_COHORT_FLOOR)).unwrap()
    }

    /// Two-row fixture summing to EXACTLY `CARRYOVER_TOTAL_BLOCH` (the larger
    /// row is the measured largest address, 3,546,175,400 BLCH). Digest is a
    /// KAT generated with CPython's hashlib.shake_256 — the digest
    /// build_carryover.py would publish for these bytes.
    const KAT2_TEXT: &str = concat!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t354617540000000000\n",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t22770940000000000\n",
    );
    const KAT2_DIGEST: &str = "56fd34b03db649caccb277407577c66cb279269ff96e9ecb9b1269e60400eecf";

    fn kat_genesis() -> Genesis {
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let expected: [u8; 32] = hex::decode(KAT2_DIGEST).unwrap().try_into().unwrap();
        build_genesis(&carry, &addrs(), &test_cohort(), &expected).unwrap()
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
        let err = build_genesis(&carry, &addrs(), &test_cohort(), &wrong).unwrap_err();
        assert!(err.contains("digest mismatch"), "{err}");
    }

    #[test]
    fn tampered_artifact_changes_digest() {
        // One satoshi moved between holders (total preserved, so only the
        // digest defends): digest must change, so the published digest no
        // longer matches and the build refuses.
        let tampered = KAT2_TEXT
            .replace("354617540000000000", "354617540000000001")
            .replace("22770940000000000", "22770939999999999");
        let good = read_carryover(KAT2_TEXT).unwrap();
        let bad = read_carryover(&tampered).unwrap();
        assert_eq!(good.total_sat, bad.total_sat, "fixture must keep the total fixed");
        assert_ne!(good.digest, bad.digest);
        assert!(build_genesis(&bad, &addrs(), &test_cohort(), &good.digest).is_err());
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

    // ── Supply: the sum is exactly 21,000,000,000 BLCH ─────────────────────

    #[test]
    fn allocations_sum_to_exactly_21_billion() {
        let g = kat_genesis();
        let issued: u128 = g.outputs.iter().map(|o| o.value_sat).sum();
        let total = issued
            + g.cohort_stake_sat
            + v4::VALIDATOR_EMISSION_BLOCH * v4::SAT_PER_BLOCH;
        assert_eq!(total, v4::TOTAL_SUPPLY_SAT);
        assert_eq!(total, 21_000_000_000 * 100_000_000); // spelled out
        // And the carryover entered whole — the cap is retired, nothing was
        // scaled and nothing was withheld.
        assert_eq!(g.carryover_issued_sat, v4::CARRYOVER_TOTAL_BLOCH * v4::SAT_PER_BLOCH);
    }

    #[test]
    fn bucket_values_match_the_spec_table() {
        let g = kat_genesis();
        let get = |b: &str| g.outputs.iter().find(|o| o.bucket == b).unwrap().value_sat;
        let sat = |bloch: u128| bloch * v4::SAT_PER_BLOCH;
        // §1 table, spelled out as literals on purpose: the test pins the
        // production values against silent drift in the constants crate.
        assert_eq!(get("founder"), sat(2_100_000_000));
        assert_eq!(get("vc"), sat(2_100_000_000));
        assert_eq!(get("team"), sat(2_100_000_000));
        assert_eq!(get("marketing"), sat(840_000_000));
        // Liquidity funds the cohort (§3.3.1): output + bonded stake is the
        // whole bucket.
        assert_eq!(get("liquidity") + g.cohort_stake_sat, sat(1_050_000_000));
        assert_eq!(v4::VALIDATOR_EMISSION_BLOCH, 9_036_115_200);
        assert_eq!(v4::CARRYOVER_TOTAL_BLOCH, 3_773_884_800);
    }

    #[test]
    fn wrong_carryover_total_is_refused() {
        // The measured ledger total is pinned in tokenomics_v4; an artifact
        // with any other total (one extra satoshi here) is not the record the
        // constants were balanced around. The ceremony stops — it never
        // scales, pads, or truncates.
        let text = KAT2_TEXT.replace("22770940000000000", "22770940000000001");
        let carry = read_carryover(&text).unwrap();
        let digest = carry.digest;
        let err = build_genesis(&carry, &addrs(), &test_cohort(), &digest).unwrap_err();
        assert!(err.contains("carryover total"), "{err}");
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
        // §1/§7 tables. Founder: 10-year cliff, 40-year linear (the V2 premine
        // schedule, restored 2026-08-11 — NOT the 24/120-month draft). The
        // Foundation buckets convert at 87,660 slots/month.
        assert_eq!(v4::MONTH_SLOTS, 87_660);
        let f = founder_schedule();
        assert_eq!(
            (f.cliff_slots, f.linear_slots),
            (10 * v4::SLOTS_PER_YEAR, 40 * v4::SLOTS_PER_YEAR)
        );
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
        // plus a sweep. The liquidity reference describes the WHOLE bucket;
        // the genesis output is the bucket minus the bonded cohort stake
        // (§3.3.1), so that bucket is compared net of the stake.
        let g = kat_genesis();
        let out = |b: &str| g.outputs.iter().find(|o| o.bucket == b).unwrap();
        type Ref = fn(u64) -> u128;
        let cases: [(&str, Ref, u128); 5] = [
            ("founder", v4::founder_vested_sat, 0),
            ("vc", v4::vc_vested_sat, 0),
            ("team", v4::team_vested_sat, 0),
            ("marketing", v4::marketing_vested_sat, 0),
            ("liquidity", v4::liquidity_vested_sat, g.cohort_stake_sat),
        ];
        for (bucket, reference, bonded) in cases {
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
                    o.schedule.unlocked_sat(o.value_sat, slot) + bonded,
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
        let expected = 210_000_000 * v4::SAT_PER_BLOCH            // 25% of marketing
            + 1_050_000_000 * v4::SAT_PER_BLOCH - g.cohort_stake_sat // liquidity net of stake
            + g.carryover_issued_sat;                             // holders
        assert_eq!(liquid, expected);
        // The founder's GRANT holds no spendable stake at genesis — the
        // liquidity the founder does have at slot 0 is the carried-over
        // holder balance, stated in §4A, not smuggled through this bucket.
        let founder = g.outputs.iter().find(|o| o.bucket == "founder").unwrap();
        assert_eq!(founder.schedule.unlocked_sat(founder.value_sat, 0), 0);
    }

    // ── Bucket-address hygiene ─────────────────────────────────────────────

    #[test]
    fn bucket_address_collisions_are_refused() {
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let digest = carry.digest;
        let cohort = test_cohort();

        let mut dup = addrs();
        dup.vc = dup.founder.clone();
        assert!(build_genesis(&carry, &dup, &cohort, &digest).is_err());

        let mut in_carry = addrs();
        in_carry.team = "aa".repeat(20); // present in the artifact
        assert!(build_genesis(&carry, &in_carry, &cohort, &digest).is_err());

        let mut bad_hex = addrs();
        bad_hex.marketing = "zz".repeat(20);
        assert!(build_genesis(&carry, &bad_hex, &cohort, &digest).is_err());
    }

    // ── Genesis validator cohort (§3.3) ────────────────────────────────────

    #[test]
    fn cohort_below_the_floor_is_refused() {
        // 63 validators: one committee slot would be down to a single
        // attester. And the degenerate case — no cohort at all — must also
        // refuse: a genesis without the published set gives the declining cap
        // nothing to bind, which is exactly the promise-not-rule failure the
        // module exists to prevent.
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let digest = carry.digest;
        let short = read_cohort(&cohort_text(GENESIS_COHORT_FLOOR - 1)).unwrap();
        let err = build_genesis(&carry, &addrs(), &short, &digest).unwrap_err();
        assert!(err.contains("floor"), "{err}");
        assert!(build_genesis(&carry, &addrs(), &[], &digest).is_err());
        // The floor is the spec's 64 (2 attesters × 32 slots).
        assert_eq!(GENESIS_COHORT_FLOOR, 64);
    }

    #[test]
    fn cohort_is_funded_from_liquidity_and_the_accounting_closes() {
        // §3.3.1: bonded stake comes out of the liquidity output — nothing is
        // minted for the cohort. 64 × MIN_DEPOSIT is 6.4 M BLCH of the
        // 1.05 B bucket.
        let g = kat_genesis();
        assert_eq!(g.cohort_stake_sat, GENESIS_COHORT_FLOOR as u128 * MIN_DEPOSIT_SAT);
        let liquidity = g.outputs.iter().find(|o| o.bucket == "liquidity").unwrap();
        assert_eq!(
            liquidity.value_sat + g.cohort_stake_sat,
            v4::LIQUIDITY_BLOCH * v4::SAT_PER_BLOCH
        );
        // A cohort whose stake exceeds the bucket is refused, not minted.
        let mut text = String::new();
        for i in 0..GENESIS_COHORT_FLOOR {
            let pk = pseudo_bytes(1, i as u32, HYBRID_PK_BYTES);
            let seed: [u8; 32] = pseudo_bytes(2, i as u32, 32).try_into().unwrap();
            let c0 = RandaoChain::generate(seed).commitment();
            // ~16.5 M BLCH each × 64 > 1.05 B
            let stake = v4::LIQUIDITY_BLOCH * v4::SAT_PER_BLOCH / 64 + 1;
            text.push_str(&format!(
                "{i}\t{}\t{}\t{stake}\t{}\n",
                hex::encode(&pk),
                hex::encode(c0),
                "77".repeat(32)
            ));
        }
        let greedy = read_cohort(&text).unwrap();
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let digest = carry.digest;
        let err = build_genesis(&carry, &addrs(), &greedy, &digest).unwrap_err();
        assert!(err.contains("liquidity"), "{err}");
    }

    #[test]
    fn cohort_is_inside_the_block_identity() {
        // The §3.3 standard, same as §8.2 for the locks: the published set is
        // part of the chain's identity. Change one member's stake — or swap
        // one RANDAO commitment — and it is a visibly different chain.
        let g = kat_genesis();

        let mut restaked = kat_genesis();
        restaked.validators[7].stake_sat += 1;
        assert_ne!(cohort_root(&g), cohort_root(&restaked));
        assert_ne!(genesis_header(&g).block_id(), genesis_header(&restaked).block_id());

        let mut rekeyed = kat_genesis();
        rekeyed.validators[7].randao_commitment[0] ^= 1;
        assert_ne!(genesis_header(&g).block_id(), genesis_header(&rekeyed).block_id());

        // And the cohort root binds the member count, so trimming the set is
        // just as visible as editing a member.
        let mut trimmed = kat_genesis();
        trimmed.validators.pop();
        assert_ne!(cohort_root(&g), cohort_root(&trimmed));
    }

    #[test]
    fn cohort_indices_are_what_the_declining_cap_consumes() {
        // End-to-end wiring with genesis_cohort.rs: the published indices,
        // sorted ascending by construction, are exactly the `cohort` argument
        // `apply_cohort_cap` binary-searches. At genesis the cohort is the
        // whole set (cap 100%); after the one-year taper, with an outsider
        // present, the cohort's combined weight is forced to the one-third
        // floor.
        let g = kat_genesis();
        let indices: Vec<u32> = g.validators.iter().map(|v| v.index).collect();
        assert!(indices.windows(2).all(|w| w[0] < w[1]), "must be sorted for binary_search");

        let mut set: Vec<Validator> = g
            .validators
            .iter()
            .map(|v| Validator { index: v.index, effective_stake: v.stake_sat as u64 })
            .collect();
        // Genesis: cohort is the whole set, untouched at epoch 0.
        assert_eq!(apply_cohort_cap(&set, &indices, 0), set);

        // One independent validator arrives with stake equal to one cohort
        // member's. After the taper the cohort must hold at most one third —
        // i.e. at most half of what the outsider holds… scaled pro-rata.
        set.push(Validator { index: indices.len() as u32, effective_stake: MIN_DEPOSIT_SAT as u64 });
        let capped = apply_cohort_cap(&set, &indices, COHORT_TAPER_EPOCHS);
        let share = cohort_share_bps(&capped, &indices);
        assert!(share <= 3_333, "cohort still at {share} bps after the taper");
    }

    #[test]
    fn malformed_cohorts_are_refused() {
        let carry = read_carryover(KAT2_TEXT).unwrap();
        let digest = carry.digest;

        // Duplicate pubkey.
        let mut dup_pk = test_cohort();
        dup_pk[1].pubkey = dup_pk[0].pubkey.clone();
        let err = build_genesis(&carry, &addrs(), &dup_pk, &digest).unwrap_err();
        assert!(err.contains("share a pubkey"), "{err}");

        // Duplicate RANDAO commitment (copy-pasted seed).
        let mut dup_c0 = test_cohort();
        dup_c0[1].randao_commitment = dup_c0[0].randao_commitment;
        let err = build_genesis(&carry, &addrs(), &dup_c0, &digest).unwrap_err();
        assert!(err.contains("RANDAO commitment"), "{err}");

        // Missing commitment: a validator that can never propose.
        let mut no_c0 = test_cohort();
        no_c0[3].randao_commitment = [0u8; 32];
        let err = build_genesis(&carry, &addrs(), &no_c0, &digest).unwrap_err();
        assert!(err.contains("RANDAO"), "{err}");

        // Sub-minimum stake.
        let mut dust = test_cohort();
        dust[5].stake_sat = MIN_DEPOSIT_SAT - 1;
        let err = build_genesis(&carry, &addrs(), &dust, &digest).unwrap_err();
        assert!(err.contains("MIN_DEPOSIT_SAT"), "{err}");

        // Stake that cannot enter u64 sortition arithmetic.
        let mut wide = test_cohort();
        wide[6].stake_sat = u64::MAX as u128 + 1;
        assert!(build_genesis(&carry, &addrs(), &wide, &digest).is_err());
    }

    #[test]
    fn cohort_parser_is_strict() {
        let good = cohort_text(2); // parses (floor is a build check, not a parse check)
        assert_eq!(read_cohort(&good).unwrap().len(), 2);

        // Index not contiguous from 0.
        let shifted: String = good
            .lines()
            .map(|l| format!("9\t{}\n", l.split_once('\t').unwrap().1))
            .collect();
        assert!(read_cohort(&shifted).is_err());

        // Enveloped pubkey (bloch-crypto 4-byte suite header) gets the
        // targeted message instead of a generic length error.
        let pk_env = hex::encode(pseudo_bytes(9, 0, HYBRID_PK_BYTES + 4));
        let enveloped = format!("0\t{pk_env}\t{}\t{}\t{}\n", "ab".repeat(32), MIN_DEPOSIT_SAT, "77".repeat(32));
        let err = read_cohort(&enveloped).unwrap_err();
        assert!(err.contains("envelope"), "{err}");

        // Non-canonical stake (zero-padded decimal in the stake column).
        let padded = good.replacen(
            &format!("\t{MIN_DEPOSIT_SAT}\t"),
            &format!("\t0{MIN_DEPOSIT_SAT}\t"),
            1,
        );
        assert_ne!(padded, good, "fixture must contain the stake column");
        assert!(read_cohort(&padded).is_err());

        // Wrong column count.
        assert!(read_cohort("0\tdeadbeef\n").is_err());
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
        // 5 allocation lines, one holder line per carryover row, one
        // validator line per cohort member, the digest and cohort headers.
        assert_eq!(doc.matches("\nalloc\t").count() + usize::from(doc.starts_with("alloc\t")), 5);
        assert_eq!(doc.matches("\nholder\t").count(), 2);
        assert_eq!(doc.matches("\nvalidator\t").count(), GENESIS_COHORT_FLOOR);
        assert!(doc.contains(&format!("total-supply-sat\t{}", v4::TOTAL_SUPPLY_SAT)));
        assert!(doc.contains(&format!("cohort-size\t{}", GENESIS_COHORT_FLOOR)));
        assert!(doc.contains(&format!("cohort-stake-sat\t{}", g.cohort_stake_sat)));
        assert!(doc.contains("cohort-funding\tliquidity"));
        // The validator lines round-trip through the cohort parser to the
        // same records the genesis was built from — document and block agree.
        let validator_lines: String = doc
            .lines()
            .filter(|l| l.starts_with("validator\t"))
            .map(|l| format!("{}\n", l.strip_prefix("validator\t").unwrap()))
            .collect();
        assert_eq!(read_cohort(&validator_lines).unwrap(), g.validators);
        // Digest of the document is stable.
        assert_eq!(document_digest(&doc), document_digest(&render_document(&g)));
    }
}
