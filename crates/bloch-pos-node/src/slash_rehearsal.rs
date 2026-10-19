// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-pos slash-rehearsal` — OFFLINE ONLY. Incident 2026-10-19.
//!
//! Loads a COPY of a node's `state.cache` (+ the block log it was cut from,
//! to recover the head header), then runs every evidence line through the
//! exact consensus path (`CommittedState::rehearse_slashing_evidence`, which
//! calls the transition's gate and `apply_slashing_evidence`). Prints ids,
//! verdicts and stake deltas only — never signatures or evidence bytes.
//! Opens no socket and submits nothing anywhere.
use crate::{codec, genesis::Manifest, keys::HybridVerifier};
use bloch_pos_committee::header::BlockEnvelope;
use bloch_pos_committee::interfaces::SlashingEvidence;
use bloch_pos_committee::transition::{CommittedState, PosTransaction};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, Read};
use std::path::Path;

const SAT_PER_BLCH: u128 = 100_000_000;

fn last_frame(log: &Path, count: u64, len: u64) -> Result<BlockEnvelope, String> {
    let mut file = std::io::BufReader::with_capacity(1 << 20, fs::File::open(log).map_err(|e| e.to_string())?);
    let (mut offset, mut n, mut payload) = (0u64, 0u64, Vec::new());
    loop {
        let mut prefix = [0u8; 4];
        file.read_exact(&mut prefix).map_err(|e| format!("log ended before frame {count}: {e}"))?;
        let size = u32::from_le_bytes(prefix) as usize;
        if size > codec::MAX_FIELD_LEN {
            return Err(format!("frame at {offset} too large"));
        }
        payload.resize(size, 0);
        file.read_exact(&mut payload).map_err(|e| e.to_string())?;
        offset += 4 + size as u64;
        n += 1;
        if n == count {
            if offset != len {
                return Err(format!("frame {count} ends at {offset}, cache says {len}"));
            }
            return codec::decode_envelope(&payload).map_err(|e| e.to_string());
        }
    }
}

fn load_state(cache: &Path, log: &Path, manifest: &Manifest) -> Result<CommittedState, String> {
    let bytes = fs::read(cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    if bytes.len() < 152 || &bytes[..8] != b"BPOSST01" {
        return Err("not a state cache".into());
    }
    let end = bytes.len() - 32;
    if Sha3_256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return Err("state cache checksum mismatch".into());
    }
    if bytes[8..40] != Sha3_256::digest(manifest.encode())[..] {
        return Err("state cache was cut under a different manifest".into());
    }
    let num = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let (len, count) = (num(72), num(112));
    eprintln!("cache: log_prefix_len={len} blocks={count} source_digest={}", codec::hex(&bytes[40..48]));
    let last = last_frame(log, count, len)?;
    CommittedState::decode_local_cache(&bytes[120..end], &last.header)
}

fn evidence_lines(path: &Path) -> Result<Vec<(String, SlashingEvidence)>, String> {
    let file = std::io::BufReader::new(fs::File::open(path).map_err(|e| e.to_string())?);
    let mut out = Vec::new();
    for line in file.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let field = |name: &str| -> Option<String> {
            let key = format!("\"{name}\":\"");
            let start = line.find(&key)? + key.len();
            Some(line[start..start + line[start..].find('"')?].to_string())
        };
        let (Some(id), Some(hex)) = (field("evidence_id"), field("evidence_tx_hex")) else { continue };
        let tx = PosTransaction::from_canonical_bytes(&codec::unhex(&hex)?)
            .map_err(|e| format!("{id}: release decoder refused: {e:?}"))?;
        let PosTransaction::SlashingEvidence(ev) = tx else {
            return Err(format!("{id}: not a tag-0x05 transaction"));
        };
        out.push((id, ev));
    }
    Ok(out)
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let opt = |name: &str| args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
    let need = |name: &str| opt(name).ok_or(format!("{name} is required"));
    let (mut manifest, _) = Manifest::load(Path::new(&need("--genesis")?)).map_err(|e| e.to_string())?;
    let state = load_state(Path::new(&need("--state-cache")?), Path::new(&need("--block-log")?), &manifest)?;
    let evidence = evidence_lines(Path::new(&need("--evidence")?))?;
    let chain = args.iter().any(|a| a == "--chain");
    let proposer: u32 = opt("--including-proposer").map(|s| s.parse().unwrap_or(0)).unwrap_or(0);
    let verifier = HybridVerifier::new();

    // Key provenance: current registry vs genesis manifest, per index.
    if let Some(c) = opt("--carryover") {
        manifest.ingest_carryover(Path::new(&c)).map_err(|e| format!("carryover: {e:?}"))?;
    }
    let genesis = manifest.genesis_state();
    let gen_keys: BTreeMap<u32, [u8; 32]> =
        genesis.rehearsal_registry().into_iter().map(|r| (r.0, r.4)).collect();
    let registry = state.rehearsal_registry();
    let roster: BTreeMap<u32, u64> = state.rehearsal_roster().into_iter().collect();
    let total_active: u128 = roster.values().map(|s| *s as u128).sum();
    let rotated: Vec<u32> = registry
        .iter()
        .filter(|r| gen_keys.get(&r.0).is_some_and(|g| *g != r.4))
        .map(|r| r.0)
        .collect();
    println!(
        "state: epoch={} validators={} roster={} total_active_sat={} genesis_validators={} keys_differing_from_genesis={:?}",
        state.rehearsal_epoch(), registry.len(), roster.len(), total_active, gen_keys.len(), rotated
    );
    println!("roster_effective_blch={:?}", roster.iter().map(|(i, s)| (*i, *s as u128 / SAT_PER_BLCH)).collect::<Vec<_>>());
    println!("already_slashed={:?}", registry.iter().filter(|r| r.2).map(|r| r.0).collect::<Vec<_>>());
    println!(
        "exiting_or_exited={:?}",
        registry.iter().filter(|r| r.3 != u64::MAX).map(|r| (r.0, r.3)).collect::<Vec<_>>()
    );

    let mut chained = state.clone();
    let mut seen = BTreeSet::new();
    let (mut accepted, mut refused) = (0usize, 0usize);
    for (id, ev) in &evidence {
        let mut scratch = state.clone();
        let r = scratch.rehearse_slashing_evidence(ev, proposer, &verifier);
        if r.applied { accepted += 1 } else { refused += 1 }
        println!(
            "ISOLATED id={} v={} offence={:?} offence_epoch={} state_epoch={} gate_open={} record={} slashed_before={} writeoff_indet={} sig1={} sig2={} machine={:?} APPLIED={} staked_before={} staked_after={} penalty_bps={} effective={} exit_after={}",
            &id[..16], r.validator, r.offence, r.offence_epoch, r.state_epoch, r.gate_open, r.record_present,
            r.already_slashed, r.write_off_indeterminate, r.sig_first_ok, r.sig_second_ok, r.machine_verdict,
            r.applied, r.staked_before, r.staked_after, r.penalty_bps, r.effective_before, r.exit_epoch_after
        );
        if chain && seen.insert(r.validator) {
            let c = chained.rehearse_slashing_evidence(ev, proposer, &verifier);
            println!(
                "CHAINED v={} APPLIED={} penalty_bps={} loss_blch={} effective_blch={}",
                c.validator, c.applied, c.penalty_bps,
                (c.staked_before - c.staked_after) / SAT_PER_BLCH, c.effective_before / SAT_PER_BLCH
            );
        }
    }
    println!("isolated: accepted={accepted} refused={refused} of {}", evidence.len());
    if chain {
        let before: BTreeMap<u32, u128> = registry.iter().map(|r| (r.0, r.1)).collect();
        let after = chained.rehearsal_registry();
        let lost: u128 = after.iter().map(|r| before.get(&r.0).copied().unwrap_or(0).saturating_sub(r.1)).sum();
        let ejected: Vec<u32> = after.iter().filter(|r| r.2 && !before.is_empty()).map(|r| r.0).collect();
        let ejected_effective: u128 = ejected.iter().map(|i| roster.get(i).copied().unwrap_or(0) as u128).sum();
        println!(
            "CHAIN TOTAL: validators_slashed={} own_bond_lost_blch={} ejected_effective_share_bps={} (of total_active {})",
            ejected.len(), lost / SAT_PER_BLCH,
            if total_active > 0 { ejected_effective * 10_000 / total_active } else { 0 }, total_active / SAT_PER_BLCH
        );
    }
    Ok(())
}
