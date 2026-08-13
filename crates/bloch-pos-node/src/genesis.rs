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
        r.finish()?;
        Ok(Manifest { genesis_time_ms, slot_ms, validators, cohort })
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
        }
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
