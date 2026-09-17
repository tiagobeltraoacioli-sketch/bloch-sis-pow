// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local, build-bound cache codec. Not a consensus wire format or state-sync API.
//! Every CommittedState field is destructured without `..`: adding consensus
//! state makes this codec fail to compile until that state is accounted for.
use super::*;
use bincode::Options;
use crate::header::BlockHeaderV4;

const LIMIT: u64 = 512 * 1024 * 1024;
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedState {
    admission_network_domain: Option<[u8; 32]>,
    slot: u64,
    epoch: u64,
    validators: BTreeMap<u32, ValidatorRecord>,
    reveals_used: BTreeMap<u32, u32>,
    randao_mix: [u8; 32],
    boundary_mixes: BTreeMap<u64, [u8; 32]>,
    genesis_mix: [u8; 32],
    genesis_cohort: Vec<u32>,
    genesis_principal_sat: BTreeMap<u32, u128>,
    written_off_sat: u128,
    funded_validators: BTreeSet<u32>,
    stake_low_water: BTreeMap<u32, u128>,
    randao_generations: BTreeMap<u32, u32>,
    finality_engine: finality::FinalityState,
    previous_justified: Checkpoint,
    pending_votes: BTreeMap<(u32, [u8; 32]), AttestationData>,
    latest_messages: BTreeMap<u32, (u64, [u8; 32])>,
    fc_equivocators: BTreeSet<u32>,
    fc_recent_votes: BTreeMap<u32, BTreeMap<u64, [u8; 32]>>,
    current_participation: BTreeMap<u32, bool>,
    previous_participation: BTreeMap<u32, bool>,
    deposit_history: Vec<QueuedDeposit>,
    pubkey_index: BTreeMap<[u8; 32], u32>,
    delegations: Vec<Delegation>,
    pending_fee_rewards: BTreeMap<u32, u128>,
    slashing: slashing::SlashingState,
    delegator_slash_losses: BTreeMap<u32, u128>,
    delegator_fee_rewards: BTreeMap<u32, u128>,
    validator_fee_rewards: BTreeMap<u32, u128>,
    delegator_issuance_rewards: BTreeMap<u32, u128>,
    current_proposed: BTreeMap<u32, bool>,
    base_fee_millisat_per_gas: u128,
    block_gas_used: u64,
    block_tx_bytes: u64,
    taint_root: [u8; 32],
    coherence_accumulator_root: [u8; 32],
    coherence_nullifier_root: [u8; 32],
    evm: EvmCommitment,
    issued_sat: u128,
    eutxos: Vec<crate::state_root::EutxoEntry>,
}

impl CommittedState {
    /// Encode only locally committed state. The node binds these bytes to its
    /// build, manifest, log prefix and checksum before accepting a restore.
    pub fn encode_local_cache(&self) -> Result<Vec<u8>, String> {
        let CommittedState { head: _, eutxos, admission_network_domain, slot, epoch, validators, reveals_used, randao_mix, boundary_mixes, genesis_mix, genesis_cohort, genesis_principal_sat, written_off_sat, funded_validators, stake_low_water, randao_generations, finality_engine, previous_justified, pending_votes, latest_messages, fc_equivocators, fc_recent_votes, current_participation, previous_participation, deposit_history, pubkey_index, delegations, pending_fee_rewards, slashing, delegator_slash_losses, delegator_fee_rewards, validator_fee_rewards, delegator_issuance_rewards, current_proposed, base_fee_millisat_per_gas, block_gas_used, block_tx_bytes, taint_root, coherence_accumulator_root, coherence_nullifier_root, evm, issued_sat } = self;
        let value = CachedState {
            admission_network_domain: admission_network_domain.clone(),
            slot: slot.clone(),
            epoch: epoch.clone(),
            validators: validators.clone(),
            reveals_used: reveals_used.clone(),
            randao_mix: randao_mix.clone(),
            boundary_mixes: boundary_mixes.clone(),
            genesis_mix: genesis_mix.clone(),
            genesis_cohort: genesis_cohort.clone(),
            genesis_principal_sat: genesis_principal_sat.clone(),
            written_off_sat: written_off_sat.clone(),
            funded_validators: funded_validators.clone(),
            stake_low_water: stake_low_water.clone(),
            randao_generations: randao_generations.clone(),
            finality_engine: finality_engine.clone(),
            previous_justified: previous_justified.clone(),
            pending_votes: pending_votes.clone(),
            latest_messages: latest_messages.clone(),
            fc_equivocators: fc_equivocators.clone(),
            fc_recent_votes: fc_recent_votes.clone(),
            current_participation: current_participation.clone(),
            previous_participation: previous_participation.clone(),
            deposit_history: deposit_history.clone(),
            pubkey_index: pubkey_index.clone(),
            delegations: delegations.clone(),
            pending_fee_rewards: pending_fee_rewards.clone(),
            slashing: slashing.clone(),
            delegator_slash_losses: delegator_slash_losses.clone(),
            delegator_fee_rewards: delegator_fee_rewards.clone(),
            validator_fee_rewards: validator_fee_rewards.clone(),
            delegator_issuance_rewards: delegator_issuance_rewards.clone(),
            current_proposed: current_proposed.clone(),
            base_fee_millisat_per_gas: base_fee_millisat_per_gas.clone(),
            block_gas_used: block_gas_used.clone(),
            block_tx_bytes: block_tx_bytes.clone(),
            taint_root: taint_root.clone(),
            coherence_accumulator_root: coherence_accumulator_root.clone(),
            coherence_nullifier_root: coherence_nullifier_root.clone(),
            evm: evm.clone(),
            issued_sat: issued_sat.clone(),
            eutxos: eutxos.values().cloned().collect(),
        };
        bincode::DefaultOptions::new().with_limit(LIMIT).serialize(&value).map_err(|e| e.to_string())
    }

    /// Restore a cache produced by this node. Caller must authenticate local
    /// provenance. Rebuild all derived ledger indexes and its Merkle subtree;
    /// neither cached tree nodes nor a raw BlockId deserializer are trusted.
    pub fn decode_local_cache(bytes: &[u8], header: &BlockHeaderV4) -> Result<Self, String> {
        let value: CachedState = bincode::DefaultOptions::new().with_limit(LIMIT)
            .reject_trailing_bytes().deserialize(bytes).map_err(|e| e.to_string())?;
        let count = value.eutxos.len();
        let eutxos: EutxoSet = value.eutxos.into_iter().collect();
        if eutxos.entries.by_outpoint.len() != count { return Err("duplicate cached outpoint".into()); }
        let state = Self {
            head: header.id(),
            eutxos,
            admission_network_domain: value.admission_network_domain,
            slot: value.slot,
            epoch: value.epoch,
            validators: value.validators,
            reveals_used: value.reveals_used,
            randao_mix: value.randao_mix,
            boundary_mixes: value.boundary_mixes,
            genesis_mix: value.genesis_mix,
            genesis_cohort: value.genesis_cohort,
            genesis_principal_sat: value.genesis_principal_sat,
            written_off_sat: value.written_off_sat,
            funded_validators: value.funded_validators,
            stake_low_water: value.stake_low_water,
            randao_generations: value.randao_generations,
            finality_engine: value.finality_engine,
            previous_justified: value.previous_justified,
            pending_votes: value.pending_votes,
            latest_messages: value.latest_messages,
            fc_equivocators: value.fc_equivocators,
            fc_recent_votes: value.fc_recent_votes,
            current_participation: value.current_participation,
            previous_participation: value.previous_participation,
            deposit_history: value.deposit_history,
            pubkey_index: value.pubkey_index,
            delegations: value.delegations,
            pending_fee_rewards: value.pending_fee_rewards,
            slashing: value.slashing,
            delegator_slash_losses: value.delegator_slash_losses,
            delegator_fee_rewards: value.delegator_fee_rewards,
            validator_fee_rewards: value.validator_fee_rewards,
            delegator_issuance_rewards: value.delegator_issuance_rewards,
            current_proposed: value.current_proposed,
            base_fee_millisat_per_gas: value.base_fee_millisat_per_gas,
            block_gas_used: value.block_gas_used,
            block_tx_bytes: value.block_tx_bytes,
            taint_root: value.taint_root,
            coherence_accumulator_root: value.coherence_accumulator_root,
            coherence_nullifier_root: value.coherence_nullifier_root,
            evm: value.evm,
            issued_sat: value.issued_sat,
        };
        if state.slot != header.slot || state.epoch != header.slot / crate::params::SLOTS_PER_EPOCH || state.compute_root() != header.state_root {
            return Err("cached state does not match its block header".into());
        }
        Ok(state)
    }
}
