// SPDX-License-Identifier: AGPL-3.0-or-later

//! Genesis manifest: the one file every node of a network loads (integration
//! plan §3.4), and the deterministic synthesis of block 0 and its committed
//! state from it.
//!
//! Two independently built nodes must agree on genesis byte-for-byte before
//! the first slot ticks. Everything here is therefore a pure function of the
//! manifest bytes: the genesis header is fixed-field, the genesis
//! `CommittedState` comes from `CommittedState::genesis`, and the manifest's
//! SHA3-256 digest is pinned into the data dir's `meta` so a node can never
//! silently switch networks (§3.1 refusal rule).
//!
//! What the devnet manifest does NOT yet carry, honestly: the signed
//! height-50,000 carryover snapshot digest and balance set, the six
//! consensus-vested allocation outputs, and the stake-eligibility policy
//! (integration plan §3.4 / decision 9). This is a *devnet* genesis: a
//! validator set and a clock. The mainnet manifest format is a superset that
//! does not exist yet.

use std::fs;
use std::io;
use std::path::Path;

use bloch_pos_committee::header::{BlockHeaderV4, BlockId, VERSION_G4};
use bloch_pos_committee::state_root::EvmCommitment;
use bloch_pos_committee::transition::{CommittedState, GenesisValidator};
use sha3::{Digest, Sha3_256};

const MANIFEST_MAGIC: &[u8; 8] = b"BPOSMAN1";

/// The beacon mix that seeds epoch 0 — fixed before any validator could have
/// influenced it (same convention as the pure crate's tests).
pub const GENESIS_MIX: [u8; 32] = [0u8; 32];

/// One genesis validator, public parts only.
#[derive(Clone)]
pub struct ManifestValidator {
    pub index: u32,
    pub stake_sat: u128,
    pub randao_commitment: [u8; 32],
    pub pubkey: Vec<u8>,
    pub withdrawal_credentials: Vec<u8>,
    /// Commission on delegators' rewards, in basis points. Published in the
    /// manifest because it is a committed registry column (2026-08-12): the
    /// epoch boundary splits both issuance and producer fees with it, so a
    /// launch validator's rate has to be part of the genesis every node
    /// agrees on, not a local setting.
    pub commission_bps: u128,
}

pub struct Manifest {
    /// Slot-0 wall-clock origin, unix milliseconds.
    pub genesis_time_ms: u64,
    /// Slot duration in milliseconds. 30_000 is the §5.1 consensus cadence;
    /// a devnet may run faster — the value is wall-clock pacing only, it
    /// never enters any consensus object (slots are numbers, not times).
    pub slot_ms: u64,
    pub validators: Vec<ManifestValidator>,
    /// Genesis-cohort indices (founder-operated launch set, cap tapered by
    /// `genesis_cohort.rs`). Empty on a devnet.
    pub cohort: Vec<u32>,
    /// The Genesis-3 balances this chain opens with. `None` on a devnet, where
    /// nobody holds anything and a fresh validator set is the whole state.
    ///
    /// The entries are **not** here. At the terminal height Genesis-3 has on
    /// the order of hundreds of thousands of outputs, and a manifest is a file
    /// every node reads, hashes and pins; carrying the set inline would make
    /// the thing nodes compare tens of megabytes long for no gain. What is
    /// here is the commitment — digest, count, total — and the node ingests
    /// the snapshot file separately and refuses it unless all three agree.
    /// Genesis-3 opened the same way (`carryover.tsv` + a `carryover_root` in
    /// meta) and that mechanism is the one piece of this that has been proven
    /// on a live chain.
    pub carryover: Option<CarryoverCommitment>,
    /// The consensus-vested allocations (`BLOCH-TOKENOMICS-V4.md` §3). Empty
    /// on a devnet.
    pub allocations: Vec<GenesisAllocation>,
}

/// What the genesis state must reproduce from the carryover snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarryoverCommitment {
    /// SHA3-256 over the canonical snapshot bytes.
    pub digest: [u8; 32],
    /// How many outputs the snapshot carries.
    pub entry_count: u64,
    /// Their total value. Held separately from the digest on purpose: a digest
    /// says "these exact bytes", a total says "this much money". Checking both
    /// catches a snapshot that is internally consistent but is not the one the
    /// tokenomics was written against — the failure a digest alone cannot see,
    /// because a wrong file has a perfectly good digest of its own.
    pub total_sat: u128,
}

/// One consensus-vested allocation output.
///
/// These are the buckets §3 names — founder, VC, team, marketing, liquidity,
/// validator emission — expressed as genesis outputs rather than as a promise
/// kept off-chain. `unlock_epoch` is what makes the vesting consensus: an
/// output is unspendable until the chain reaches that epoch, so the schedule
/// is enforced by every node instead of by whoever holds the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisAllocation {
    /// Which bucket this is, as a stable tag (see `alloc_purpose`).
    pub purpose: u8,
    /// SHA3-256 of the locking script that owns it.
    pub script_hash: [u8; 32],
    pub amount_sat: u128,
    /// First epoch at which this output may be spent. 0 means liquid at
    /// genesis.
    pub unlock_epoch: u64,
}

/// Stable purpose tags. Never renumber: they are committed in the manifest,
/// therefore in its digest, therefore in what every node agrees it joined.
pub mod alloc_purpose {
    pub const FOUNDER: u8 = 0x01;
    pub const VC: u8 = 0x02;
    pub const TEAM: u8 = 0x03;
    pub const MARKETING: u8 = 0x04;
    pub const LIQUIDITY: u8 = 0x05;
    /// Held for validator emission — issued over time, not spendable at once.
    pub const VALIDATOR_EMISSION: u8 = 0x06;
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&self.genesis_time_ms.to_le_bytes());
        out.extend_from_slice(&self.slot_ms.to_le_bytes());
        out.extend_from_slice(&(self.validators.len() as u32).to_le_bytes());
        for v in &self.validators {
            out.extend_from_slice(&v.index.to_le_bytes());
            out.extend_from_slice(&v.stake_sat.to_le_bytes());
            out.extend_from_slice(&v.randao_commitment);
            crate::codec::put_bytes(&mut out, &v.pubkey);
            crate::codec::put_bytes(&mut out, &v.withdrawal_credentials);
            out.extend_from_slice(&v.commission_bps.to_le_bytes());
        }
        out.extend_from_slice(&(self.cohort.len() as u32).to_le_bytes());
        for c in &self.cohort {
            out.extend_from_slice(&c.to_le_bytes());
        }
        match &self.carryover {
            None => out.push(0),
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.digest);
                out.extend_from_slice(&c.entry_count.to_le_bytes());
                out.extend_from_slice(&c.total_sat.to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.allocations.len() as u32).to_le_bytes());
        for a in &self.allocations {
            out.push(a.purpose);
            out.extend_from_slice(&a.script_hash);
            out.extend_from_slice(&a.amount_sat.to_le_bytes());
            out.extend_from_slice(&a.unlock_epoch.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Manifest, crate::codec::DecodeErr> {
        use crate::codec::{DecodeErr, Reader};
        let mut r = Reader::new(bytes);
        if r.take(8)? != MANIFEST_MAGIC {
            return Err(DecodeErr("not a genesis manifest"));
        }
        let genesis_time_ms = r.u64()?;
        let slot_ms = r.u64()?;
        if slot_ms == 0 {
            return Err(DecodeErr("slot_ms zero"));
        }
        let n = r.u32()? as usize;
        if n > 1_000_000 {
            return Err(DecodeErr("validator count over cap"));
        }
        let mut validators = Vec::with_capacity(n);
        for _ in 0..n {
            validators.push(ManifestValidator {
                index: r.u32()?,
                stake_sat: r.u128()?,
                randao_commitment: r.h32()?,
                pubkey: r.bytes()?,
                withdrawal_credentials: r.bytes()?,
                commission_bps: r.u128()?,
            });
        }
        let nc = r.u32()? as usize;
        if nc > n {
            return Err(DecodeErr("cohort larger than set"));
        }
        let mut cohort = Vec::with_capacity(nc);
        for _ in 0..nc {
            cohort.push(r.u32()?);
        }
        let carryover = match r.u8()? {
            0 => None,
            1 => Some(CarryoverCommitment {
                digest: r.h32()?,
                entry_count: r.u64()?,
                total_sat: r.u128()?,
            }),
            // A third value would mean two encodings of one manifest and so
            // two digests for one network.
            _ => return Err(DecodeErr("carryover flag not canonical")),
        };
        let na = r.u32()? as usize;
        if na > 64 {
            return Err(DecodeErr("allocation count over cap"));
        }
        let mut allocations = Vec::with_capacity(na);
        for _ in 0..na {
            allocations.push(GenesisAllocation {
                purpose: r.u8()?,
                script_hash: r.h32()?,
                amount_sat: r.u128()?,
                unlock_epoch: r.u64()?,
            });
        }
        r.finish()?;
        Ok(Manifest { genesis_time_ms, slot_ms, validators, cohort, carryover, allocations })
    }

    /// What genesis puts into existence: carried balances plus allocations.
    pub fn genesis_issued_sat(&self) -> u128 {
        self.carryover.as_ref().map_or(0, |c| c.total_sat)
            + self.allocations.iter().map(|a| a.amount_sat).sum::<u128>()
    }

    /// Refuse a manifest that does not add up.
    ///
    /// This is the check that makes the manifest a claim rather than an
    /// assertion. A genesis file is the one artifact nobody can re-derive
    /// later — once a chain runs from it, whatever it said is what happened —
    /// so the arithmetic is verified before it is signed, not after someone
    /// notices the supply is wrong.
    pub fn check_supply(&self) -> Result<(), String> {
        use bloch_pos_committee::tokenomics_v4 as t;
        let issued = self.genesis_issued_sat();
        if issued > t::TOTAL_SUPPLY_SAT {
            return Err(format!(
                "genesis issues {issued} sat, above the hard cap {}",
                t::TOTAL_SUPPLY_SAT
            ));
        }
        // Validator emission is issued by blocks over decades; genesis must
        // leave exactly that much unissued, or the emission schedule and the
        // cap disagree and one of them silently wins.
        let expected = t::GENESIS_ISSUED_SAT;
        if self.carryover.is_some() && issued != expected {
            return Err(format!(
                "genesis issues {issued} sat; tokenomics §3 says {expected} \
                 (difference {})",
                issued.abs_diff(expected)
            ));
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<(Manifest, [u8; 32])> {
        let bytes = fs::read(path)?;
        let digest: [u8; 32] = Sha3_256::digest(&bytes).into();
        let m = Manifest::decode(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok((m, digest))
    }

    /// The genesis block header, synthesized deterministically from the
    /// manifest. Fixed-field: genesis is a block, so its id derives from a
    /// header through the single §5.4 path — never from a label.
    pub fn genesis_header(&self) -> BlockHeaderV4 {
        BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0u8; 32],
            randao_mix: GENESIS_MIX,
            justified_root: [0u8; 32],
            finalized_root: [0u8; 32],
            attestation_root: [0u8; 32],
            coherence_root: [0u8; 32],
        }
    }

    pub fn genesis_id(&self) -> BlockId {
        BlockId::of(&self.genesis_header())
    }

    /// The committed state of block 0. Coherence starts empty (integration
    /// plan decision 6) and taint is dissolved (decision 8): all three
    /// carried roots are zero.
    pub fn genesis_state(&self) -> CommittedState {
        let vals: Vec<GenesisValidator> = self
            .validators
            .iter()
            .map(|v| GenesisValidator {
                index: v.index,
                pubkey: v.pubkey.clone(),
                staked_sat: v.stake_sat,
                randao_commitment: v.randao_commitment,
                withdrawal_credentials: v.withdrawal_credentials.clone(),
                commission_bps: v.commission_bps,
            })
            .collect();
        CommittedState::genesis(
            self.genesis_id(),
            GENESIS_MIX,
            &vals,
            &self.cohort,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            // Empty EVM segment at genesis. Spelled out rather than defaulted
            // so that adding a carried component breaks this call site and
            // someone decides what genesis commits, instead of it silently
            // becoming zero.
            EvmCommitment {
                account_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                base_fee_per_gas: 0,
            },
        )
    }

    /// The registered public keys, indexed by validator index (dense from 0).
    pub fn pubkeys(&self) -> Vec<Vec<u8>> {
        let mut pks: Vec<Vec<u8>> = vec![Vec::new(); self.validators.len()];
        for v in &self.validators {
            if (v.index as usize) < pks.len() {
                pks[v.index as usize] = v.pubkey.clone();
            }
        }
        pks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            genesis_time_ms: 1_800_000_000_000,
            slot_ms: 500,
            validators: (0..3)
                .map(|i| ManifestValidator {
                    index: i,
                    stake_sat: (i as u128 + 1) * 1_000,
                    randao_commitment: [i as u8; 32],
                    pubkey: vec![i as u8; 16],
                    withdrawal_credentials: Vec::new(),
                    // Distinct non-zero rates, so a decoder that dropped or
                    // aliased the column would fail the round-trip below
                    // instead of round-tripping three identical zeros.
                    commission_bps: 250 * (i as u128 + 1),
                })
                .collect(),
            cohort: vec![0],
            carryover: None,
            allocations: Vec::new(),
        }
    }

    /// A manifest exercising the mainnet fields, with values chosen so a
    /// field-order or width slip cannot round-trip: every integer differs and
    /// the two allocations differ in all four columns.
    fn mainnet_sample() -> Manifest {
        let mut m = sample();
        m.carryover = Some(CarryoverCommitment {
            digest: [0xC0; 32],
            entry_count: 413_743,
            total_sat: 17_970_880_000 * 100_000_000,
        });
        m.allocations = vec![
            GenesisAllocation {
                purpose: alloc_purpose::FOUNDER,
                script_hash: [0xF1; 32],
                amount_sat: 10_000_000_000 * 100_000_000,
                unlock_epoch: 0,
            },
            GenesisAllocation {
                purpose: alloc_purpose::TEAM,
                script_hash: [0x7E; 32],
                amount_sat: 10_000_000_000 * 100_000_000,
                unlock_epoch: 2_190,
            },
        ];
        m
    }

    #[test]
    fn mainnet_manifest_round_trips() {
        let m = mainnet_sample();
        let back = Manifest::decode(&m.encode()).expect("round trip");
        assert_eq!(back.carryover, m.carryover);
        assert_eq!(back.allocations, m.allocations);
        assert_eq!(back.encode(), m.encode(), "re-encoding must be byte-identical");
    }

    #[test]
    fn devnet_manifest_still_round_trips() {
        // The devnet shape is the same format with the carryover flag clear,
        // not a second format.
        let m = sample();
        let back = Manifest::decode(&m.encode()).expect("round trip");
        assert_eq!(back.carryover, None);
        assert!(back.allocations.is_empty());
    }

    #[test]
    fn carryover_flag_must_be_canonical() {
        let m = sample();
        let mut bytes = m.encode();
        // The flag sits after the cohort; find it by rebuilding a manifest
        // whose only difference is the flag byte.
        let flag_at = bytes.len() - 4 - 1;
        assert_eq!(bytes[flag_at], 0, "test targets the carryover flag");
        bytes[flag_at] = 2;
        assert!(Manifest::decode(&bytes).is_err(), "a third flag value must be refused");
    }

    #[test]
    fn genesis_issuance_is_checked_against_tokenomics() {
        use bloch_pos_committee::tokenomics_v4 as t;
        // A devnet manifest carries no balances and is not held to §3.
        assert!(sample().check_supply().is_ok());

        // A mainnet manifest that does not add up is refused, and the message
        // says by how much rather than just "invalid".
        let bad = mainnet_sample();
        let err = bad.check_supply().expect_err("27.97 B is not the §3 figure");
        assert!(err.contains("tokenomics"), "{err}");

        // And one that does add up passes. Built from the constants, never
        // from a number retyped here — a test that restates the figure would
        // pass while the chain issued something else.
        let mut good = sample();
        good.carryover = Some(CarryoverCommitment {
            digest: [0xC0; 32],
            entry_count: 1,
            total_sat: t::CARRYOVER_TOTAL_BLOCH * t::SAT_PER_BLOCH,
        });
        let rest = t::GENESIS_ISSUED_SAT - t::CARRYOVER_TOTAL_BLOCH * t::SAT_PER_BLOCH;
        good.allocations = vec![GenesisAllocation {
            purpose: alloc_purpose::FOUNDER,
            script_hash: [0xF1; 32],
            amount_sat: rest,
            unlock_epoch: 0,
        }];
        good.check_supply().expect("carryover + allocations must equal GENESIS_ISSUED_SAT");
    }

    #[test]
    fn manifest_round_trips() {
        let m = sample();
        let bytes = m.encode();
        let back = Manifest::decode(&bytes).expect("round trip");
        assert_eq!(back.genesis_time_ms, m.genesis_time_ms);
        assert_eq!(back.slot_ms, m.slot_ms);
        assert_eq!(back.validators.len(), 3);
        assert_eq!(
            back.validators.iter().map(|v| v.commission_bps).collect::<Vec<_>>(),
            m.validators.iter().map(|v| v.commission_bps).collect::<Vec<_>>(),
        );
        assert_eq!(back.cohort, m.cohort);
        // Genesis identity and state are pure functions of the manifest.
        use bloch_pos_committee::interfaces::StateReader;
        assert_eq!(back.genesis_id(), m.genesis_id());
        assert_eq!(back.genesis_state().state_root(), m.genesis_state().state_root());
    }

    #[test]
    fn manifest_decode_rejects_trailing_bytes() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(Manifest::decode(&bytes).is_err());
    }
}
