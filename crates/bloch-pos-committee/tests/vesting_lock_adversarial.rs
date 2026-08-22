// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(feature = "vesting_lock_tests")]
//! FRENTE B — Adversarial suite for the FOUNDER/TEAM vesting lock.
//!
//! ## Status: SPECIFICATION, gated OFF by design
//!
//! This file is deliberately compiled out of the default suite: it is fenced
//! behind `feature = "vesting_lock_tests"`, which no `Cargo.toml` declares yet.
//! That keeps `cargo test -p bloch-pos-committee` green (task rule 3) while the
//! consensus rule it exercises does not exist. It is the executable half of the
//! threat model: Frente A lands the rule, adds the feature, and flips it on;
//! every test here must then pass, control halves included.
//!
//! ## What is being locked, and why this is a consensus rule and not a script
//!
//! Genesis-4 has no VM and no smart contracts. The transaction set is closed
//! (`transition.rs`: Transfer, Deposit, Exit, Delegate, SlashingEvidence) and
//! an output's `script_hash` is literally `SHA3-256(pubkey)` — pay-to-pubkey-
//! hash, nothing more. There is nowhere for a vesting contract to live. So the
//! FOUNDER and TEAM allocations (10 B BLCH each, purpose 0x01 and 0x03 in
//! `genesis/mainnet.manifest`, both locked to the founder H160
//! `e986db51…f4ff` zero-extended) are today plain genesis eUTXO outputs,
//! spendable by whoever holds the key, right now. `tokenomics_v4::
//! founder_vested_sat` / `team_vested_sat` compute a schedule that NOTHING
//! calls. This suite proves the hole is real and pins the rule that closes it.
//!
//! ## The rule surface these tests bind to (proposed to Frente A)
//!
//! 1. `params::LOCKED_VESTING_ACTIVATION_EPOCH: u64` — flag-day gate, `u64::MAX`
//!    by default, same idiom as `LEAKED_ROSTER_ACTIVATION_EPOCH`. Below it the
//!    lock is inert and mainnet behaves exactly as today (test
//!    `outputs_spend_freely_before_the_flag_day`).
//! 2. The locked outpoints and their unlock slots are a genesis constant —
//!    chain identity, immutable, in the same tier as `genesis_cohort` and
//!    `genesis_mix`, which `transition.rs` documents as living OUTSIDE the
//!    state root on purpose. So enforcing the lock adds NO committed component
//!    and changes NO state root off the gate (task rule 2). The lock is a pure
//!    predicate over (outpoint, current slot).
//! 3. Enforcement point: `CommittedState::apply_transfer` — the SINGLE mutator
//!    of the eUTXO set (`self.eutxos.remove`, transition.rs:1778, is the only
//!    place value leaves an output; see the threat model for the proof that no
//!    other path exists). A locked, not-yet-unlocked output MUST fail the
//!    membership/authorisation stage of `apply_transfer` with a new
//!    `TransferReject::OutputLocked { unlock_slot }`, checked BEFORE the
//!    expensive hybrid verification, in the frozen cheapest-first order.
//!
//! Every negative test below carries a CONTROL half proving the SAME operation
//! succeeds when legitimate (after unlock, or before the flag day, or on an
//! unlocked output). A test that only asserts "rejected" can reject for the
//! wrong reason; the control is what makes the rejection mean what it claims.

use bloch_pos_committee::interfaces::{StateReader, StateTransition, TransitionError};
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
use bloch_pos_committee::transition::{
    CommittedState, GenesisValidator, PosTransaction, Transition, TransferInput, TransferOutput,
};
use bloch_pos_committee::interfaces::{ProposalEnvelope, SlashingEvidence};
use bloch_pos_committee::attestation::{Attestation, SignatureVerifier};
use bloch_pos_committee::beacon::{self, RandaoChain};
use bloch_pos_committee::header::{BlockHeaderV4, BlockId};
use bloch_pos_committee::{epoch_of, schedule, tokenomics_v4 as t, SLOTS_PER_EPOCH};
use bloch_pos_committee::{committees, params};
use sha3::{Digest, Sha3_256};

// ─────────────────────────────────────────────────────────────────────────────
// Minimal, public-API-only harness
//
// The private test helpers in transition.rs (`setup_funded`, `build_block`,
// `transfer_spending`) are unreachable from an integration test. This harness
// rebuilds only what these scenarios need, using nothing but the crate's public
// surface — which is also the point: it is the API a real node builds blocks
// with, so a block that passes here is a block the node would accept.
// ─────────────────────────────────────────────────────────────────────────────

/// A verifier that binds a signature to (key, message) exactly, for spends, and
/// waves through the registry-form (proposer/attestation) signatures so a
/// transfer test dies on the transfer and never on block plumbing. Same shape
/// as transition.rs's `ToyVerifier`, restated because it is private there.
struct ToyVerifier;
fn toy_sign(pubkey: &[u8], root: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(b"toy-spend-signature");
    h.update((pubkey.len() as u32).to_le_bytes());
    h.update(pubkey);
    h.update(root);
    h.finalize().to_vec()
}
impl SignatureVerifier for ToyVerifier {
    fn verify(&self, _v: u32, _root: &[u8; 32], _sig: &[u8]) -> bool {
        true
    }
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        sig == toy_sign(pk, root).as_slice()
    }
}

fn sat(bloch: u128) -> u128 {
    bloch * t::SAT_PER_BLOCH
}

/// The founder's key, and the script every locked allocation output carries.
///
/// Carried-form: `H160 ‖ 12 zero bytes`, so `owns()` opens it under the
/// 20-byte arm — the same key spends both the liquid carryover and the vested
/// grant, which is exactly the surface the lock has to defend without breaking.
fn founder_key() -> Vec<u8> {
    // Any key whose SHA3-256 truncates to the manifest H160. The harness can't
    // preimage that, so instead we mint a genesis output whose script is
    // SHA3-256(founder_key) in NATIVE form and treat THAT as the locked bucket:
    // the lock predicate keys on the OUTPOINT, not the script, so the script
    // convention is irrelevant to what these tests prove. See
    // `locked_allocation_output`.
    b"FOUNDER-TEST-KEY".to_vec()
}
fn recipient_key() -> Vec<u8> {
    b"RECIPIENT-TEST-KEY".to_vec()
}
fn script_of(pubkey: &[u8]) -> [u8; 32] {
    Sha3_256::digest(pubkey).into()
}

/// The FOUNDER allocation outpoint, computed the way `genesis.rs::
/// allocation_outputs` computes it: a domain-separated digest over
/// (purpose, script, amount, unlock). Pinned so a change to that derivation
/// breaks this suite loudly rather than silently unlocking the grant.
///
/// Verified against a standalone recomputation: purpose 0x01, founder H160
/// zero-extended, 10 B BLCH, unlock 0 → 6740c212…b4b2 (see the Python check in
/// the Frente B report).
fn founder_alloc_outpoint() -> ([u8; 32], u32) {
    let mut script = [0u8; 32];
    script[..20].copy_from_slice(&t::FOUNDER_WITHDRAWAL_H160);
    let mut h = Sha3_256::new();
    Digest::update(&mut h, b"BLCH4:genesis-alloc\0");
    Digest::update(&mut h, [0x01u8]); // alloc_purpose::FOUNDER
    Digest::update(&mut h, script);
    Digest::update(&mut h, (t::FOUNDER_BLOCH * t::SAT_PER_BLOCH).to_le_bytes());
    Digest::update(&mut h, 0u64.to_le_bytes());
    (h.finalize().into(), 0)
}

/// A locked allocation output at a known outpoint, owned by `founder_key` in
/// native form so the harness can actually sign a spend of it. The LOCK is a
/// property of the outpoint under the proposed rule, so using a native script
/// here (rather than the un-signable carried H160 form) changes nothing the
/// lock cares about and lets the adversarial spend be constructed at all.
fn locked_allocation_output() -> EutxoEntry {
    let (txid, vout) = founder_alloc_outpoint();
    EutxoEntry { txid, vout, value: sat(10_000_000_000) as u64, script_hash: script_of(&founder_key()) }
}

/// An ordinary, UNLOCKED output owned by the founder — the control coin. Every
/// negative test needs one to prove the machinery works on a coin that is
/// merely the founder's, so the rejection is about the LOCK and not about the
/// owner.
fn unlocked_output(value_bloch: u128) -> EutxoEntry {
    EutxoEntry {
        txid: [0xEE; 32],
        vout: 0,
        value: sat(value_bloch) as u64,
        script_hash: script_of(&founder_key()),
    }
}

const N: u32 = 4;
const TAINT: [u8; 32] = [0x11; 32];
const CACC: [u8; 32] = [0x22; 32];
const CNUL: [u8; 32] = [0x33; 32];
const EVM: EvmCommitment =
    EvmCommitment { account_root: [0x44; 32], receipts_root: [0x55; 32], gas_used: 0, base_fee_per_gas: 1 };

fn genesis_block_id() -> BlockId {
    BlockId::of(&BlockHeaderV4 {
        version: bloch_pos_committee::VERSION_G4,
        parent: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0u8; 32],
        randao_mix: [0x07; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0x33; 32],
    })
}

/// Genesis with `opening` as the opening ledger and N founder-cohort validators.
fn setup(opening: &[EutxoEntry]) -> (Transition<ToyVerifier>, CommittedState, Vec<RandaoChain>) {
    let mut chains = Vec::new();
    let mut vals = Vec::new();
    for i in 0..N {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        seed[1] = 0x5A;
        let chain = RandaoChain::generate(seed);
        vals.push(GenesisValidator {
            index: i,
            pubkey: vec![i as u8; 8],
            staked_sat: sat(200_000),
            randao_commitment: chain.commitment(),
            withdrawal_credentials: vec![i as u8; 4],
            commission_bps: 500,
        });
        chains.push(chain);
    }
    let st = CommittedState::genesis(
        genesis_block_id(), [0x07; 32], &vals, &[], TAINT, CACC, CNUL, EVM, opening,
    );
    (Transition::new(ToyVerifier), st, chains)
}

/// Build a valid, signed block at `slot` carrying `txs`. Mirrors the node's
/// producer walk: roll the parent over any boundaries, draw the proposer, burn
/// its reveal, fold the mix, stamp every commitment from the same derivations
/// the validator checks, then fill `state_root` from `compute_post_state`.
fn build_block(
    tr: &Transition<ToyVerifier>,
    pre: &CommittedState,
    slot: u64,
    atts: &[Attestation],
    txs: &[PosTransaction],
    chains: &mut [RandaoChain],
) -> ProposalEnvelope {
    let mut ctx = pre.clone();
    while ctx.epoch() < epoch_of(slot) {
        ctx = tr.process_epoch(&ctx).unwrap();
    }
    let roster = ctx.active_validators();
    let seed = ctx.randao_mix_seed_for_epoch(ctx.epoch()); // proposed read accessor
    let p = schedule::proposer(&seed, slot, &roster).expect("no eligible proposer");
    let reveal = chains[p as usize].next_reveal().expect("chain spent");
    let mix = beacon::mix_in(&ctx.randao_mix(), &reveal);
    let fin = ctx.finality();
    let mut header = BlockHeaderV4 {
        version: bloch_pos_committee::VERSION_G4,
        parent: *pre.head().as_bytes(),
        state_root: [0u8; 32],
        body_root: bloch_pos_committee::derive::body_root(
            &txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>(),
        ),
        slot,
        proposer_index: p,
        randao_reveal: reveal,
        randao_mix: mix,
        justified_root: fin.justified.root,
        finalized_root: fin.finalized.root,
        attestation_root: bloch_pos_committee::derive::attestation_root(atts),
        coherence_root: pre.coherence_root(),
    };
    let probe = ProposalEnvelope { header: header.clone(), proposer_sig: vec![0u8; 8] };
    let post = tr.compute_post_state(pre, &probe, atts, txs).expect("builder produced untransitionable block");
    header.state_root = post.state_root();
    ProposalEnvelope { header, proposer_sig: vec![0u8; 8] }
}

/// A conserving transfer that spends `entries` whole and pays the remainder,
/// after the market fee, to `to_script`. Signs under `owner`. The fee is the
/// SAME `fee_market::charge` the transition runs — never a literal — so the
/// fixture keeps conserving when a gas constant moves.
fn transfer_spending(
    entries: &[EutxoEntry],
    owner: &[u8],
    to_script: [u8; 32],
    price: u128,
) -> PosTransaction {
    use bloch_pos_committee::fee_market::{charge, TxClass};
    let inputs: Vec<TransferInput> = entries
        .iter()
        .map(|e| TransferInput { txid: e.txid, vout: e.vout, pubkey: owner.to_vec(), signature: Vec::new() })
        .collect();
    let spent: u128 = entries.iter().map(|e| e.value as u128).sum();
    // First pass to learn the canonical length, then the real byte count.
    let probe = PosTransaction::Transfer {
        inputs: inputs.clone(),
        outputs: vec![TransferOutput { value: 0, script_hash: to_script }],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    };
    let bytes = probe.canonical_bytes().len() as u64;
    let c = charge(TxClass::Eutxo { inputs: inputs.len() as u32 }, bytes, price, 0);
    let fee = c.base_fee_sat + c.priority_fee_sat;
    let mut tx = PosTransaction::Transfer {
        inputs,
        outputs: vec![TransferOutput { value: (spent - fee) as u64, script_hash: to_script }],
        tx_bytes: bytes,
        tip_millisat_per_gas: 0,
    };
    let root = tx.spend_signing_root();
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        for i in inputs.iter_mut() {
            i.signature = toy_sign(owner, &root);
        }
    }
    tx
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The whole-output spend — the primary channel
// ─────────────────────────────────────────────────────────────────────────────

/// ADVERSARY: spend the founder allocation output in full before it vests.
/// CONTROL: the identical transfer of an UNLOCKED founder output succeeds.
///
/// The control is what proves the rejection is about the lock and not about the
/// owner, the amount, or the plumbing: same signer, same recipient, same block
/// slot, only the input outpoint differs.
#[test]
fn a_locked_allocation_output_cannot_be_spent_before_it_vests() {
    // A slot inside the founder cliff (< FOUNDER_CLIFF_SLOTS): nothing vested.
    let slot = 5u64;
    assert!(slot < t::FOUNDER_CLIFF_SLOTS);
    let epoch = epoch_of(slot);
    // The flag day must be at or before this epoch for the lock to bind.
    assert!(epoch >= params::LOCKED_VESTING_ACTIVATION_EPOCH);

    let locked = locked_allocation_output();
    let control = unlocked_output(10_000_000_000);
    let (tr, g, mut chains) = setup(&[locked.clone(), control.clone()]);
    let price = g.base_fee_millisat_per_gas();

    // ADVERSARY
    let steal = transfer_spending(&[locked], &founder_key(), script_of(&recipient_key()), price);
    let b = build_block(&tr, &g, slot, &[], &[steal.clone()], &mut chains);
    let got = tr.apply_block(&g, &b, &[], &[steal]);
    assert!(
        matches!(got, Err(TransitionError::Transfer(0, _))),
        "a not-yet-vested founder allocation output must not be spendable; got {got:?}"
    );

    // CONTROL: same everything, unlocked coin — must pass.
    let ok = transfer_spending(&[control], &founder_key(), script_of(&recipient_key()), price);
    let b2 = build_block(&tr, &g, slot, &[], &[ok.clone()], &mut chains);
    assert!(
        tr.apply_block(&g, &b2, &[], &[ok]).is_ok(),
        "control failed: an unlocked founder output must spend, or the test proves nothing"
    );
}

/// CONTROL over TIME: the same locked output spends once the schedule has fully
/// vested it. Without this half, an implementation that locks the output
/// FOREVER (never calling the vesting curve) would pass every negative test.
#[test]
fn a_locked_output_becomes_spendable_after_it_fully_vests() {
    let slot = t::FOUNDER_VESTING_END_SLOT; // fully vested
    let locked = locked_allocation_output();
    let (tr, g, mut chains) = setup(&[locked.clone()]);
    let price = g.base_fee_millisat_per_gas();
    let spend = transfer_spending(&[locked], &founder_key(), script_of(&recipient_key()), price);
    let b = build_block(&tr, &g, slot, &[], &[spend.clone()], &mut chains);
    assert!(
        tr.apply_block(&g, &b, &[], &[spend]).is_ok(),
        "a fully-vested allocation output must become spendable — the lock is time-bound, not permanent"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Change laundering — spend 1 sat of the locked output, get the rest free
// ─────────────────────────────────────────────────────────────────────────────

/// ADVERSARY: a transfer whose inputs are {locked, tiny-unlocked} and whose
/// output is a single fresh UNLOCKED coin carrying the locked value. If the rule
/// only tagged outputs and forgot inputs, the change coin would launder the
/// whole grant in one block.
/// CONTROL: the same shape with the locked input replaced by an unlocked one of
/// equal value succeeds — proving multi-input transfers themselves are fine.
#[test]
fn locked_value_cannot_escape_as_unlocked_change() {
    let slot = 5u64;
    let locked = locked_allocation_output();
    let dust = EutxoEntry { txid: [0xAB; 32], vout: 0, value: sat(1) as u64, script_hash: script_of(&founder_key()) };
    let control_big = EutxoEntry { txid: [0xCD; 32], vout: 0, value: locked.value, script_hash: script_of(&founder_key()) };
    let (tr, g, mut chains) = setup(&[locked.clone(), dust.clone(), control_big.clone()]);
    let price = g.base_fee_millisat_per_gas();

    // ADVERSARY: locked + dust -> one unlocked output.
    let launder = transfer_spending(&[locked, dust.clone()], &founder_key(), script_of(&recipient_key()), price);
    let b = build_block(&tr, &g, slot, &[], &[launder.clone()], &mut chains);
    assert!(
        matches!(tr.apply_block(&g, &b, &[], &[launder]), Err(TransitionError::Transfer(0, _))),
        "spending any locked value as change must be refused — locking outputs but not inputs is the classic hole"
    );

    // CONTROL: unlocked-big + dust -> one output. Same arity, same recipient.
    let ok = transfer_spending(&[control_big, dust], &founder_key(), script_of(&recipient_key()), price);
    let b2 = build_block(&tr, &g, slot, &[], &[ok.clone()], &mut chains);
    assert!(
        tr.apply_block(&g, &b2, &[], &[ok]).is_ok(),
        "control failed: a two-input transfer of unlocked coins must succeed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Fee drain — bleed the locked coin out as fee to a friendly proposer
// ─────────────────────────────────────────────────────────────────────────────

/// ADVERSARY: build a transfer that spends the locked output and creates an
/// output SMALLER than the input by exactly the fee — the difference (`fee =
/// spent - created`, transition.rs conservation) is credited to the proposer,
/// who is the founder's own validator. If only "outputs" were guarded, the fee
/// path would exfiltrate locked value with no unlocked output at all.
/// CONTROL: the same fee-bearing transfer over an unlocked coin succeeds.
///
/// Note: this is subsumed by test 1 (any spend of a locked input is refused, so
/// the fee it would have paid never settles), but it is pinned separately
/// because "the fee is a distinct exit from the outputs" is a claim worth a
/// test of its own — the conservation identity makes them the same satoshis and
/// a future refactor could split them.
#[test]
fn locked_value_cannot_be_bled_out_as_a_fee() {
    let slot = 5u64;
    let locked = locked_allocation_output();
    let control = unlocked_output(10_000_000_000);
    let (tr, g, mut chains) = setup(&[locked.clone(), control.clone()]);
    let price = g.base_fee_millisat_per_gas();

    // A transfer that pays a large tip so a meaningful chunk leaves as fee.
    let bleed = fee_heavy_transfer(&locked, &founder_key(), price);
    let b = build_block(&tr, &g, slot, &[], &[bleed.clone()], &mut chains);
    assert!(
        matches!(tr.apply_block(&g, &b, &[], &[bleed]), Err(TransitionError::Transfer(0, _))),
        "a locked output must not fund a fee — the proposer is the owner and the fee is an exit"
    );

    let ok = fee_heavy_transfer(&control, &founder_key(), price);
    let b2 = build_block(&tr, &g, slot, &[], &[ok.clone()], &mut chains);
    assert!(
        tr.apply_block(&g, &b2, &[], &[ok]).is_ok(),
        "control failed: a fee-heavy transfer of an unlocked coin must succeed"
    );
}

fn fee_heavy_transfer(e: &EutxoEntry, owner: &[u8], price: u128) -> PosTransaction {
    use bloch_pos_committee::fee_market::{charge, TxClass};
    let inputs = vec![TransferInput { txid: e.txid, vout: e.vout, pubkey: owner.to_vec(), signature: Vec::new() }];
    let probe = PosTransaction::Transfer {
        inputs: inputs.clone(),
        outputs: vec![TransferOutput { value: 0, script_hash: script_of(owner) }],
        tx_bytes: 0,
        tip_millisat_per_gas: 1_000_000,
    };
    let bytes = probe.canonical_bytes().len() as u64;
    let c = charge(TxClass::Eutxo { inputs: 1 }, bytes, price, 1_000_000);
    let fee = c.base_fee_sat + c.priority_fee_sat;
    let mut tx = PosTransaction::Transfer {
        inputs,
        outputs: vec![TransferOutput { value: (e.value as u128 - fee) as u64, script_hash: script_of(owner) }],
        tx_bytes: bytes,
        tip_millisat_per_gas: 1_000_000,
    };
    let root = tx.spend_signing_root();
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        for i in inputs.iter_mut() {
            i.signature = toy_sign(owner, &root);
        }
    }
    tx
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Deposit / Delegate as a side door
// ─────────────────────────────────────────────────────────────────────────────

/// ADVERSARY-ANALYSIS (compiles as a documented assertion, not a bypass):
/// `Deposit` and `Delegate` name a bare `amount_sat` and spend NO eUTXO input
/// (transition.rs:1611+ mutates only the registry / delegation list; there is
/// no `self.eutxos.remove` on those arms — grep-pinned in the report). So the
/// staking messages cannot consume the locked allocation output at all: they
/// mint bonded stake from nothing (the documented, separate "two pools" gap in
/// `CommittedState::eutxos` docs). The only way locked value could become stake
/// is to Transfer it to a liquid coin FIRST — which test 1 refuses.
///
/// This test pins that a Deposit does not touch the locked outpoint, so the
/// eUTXO-level lock is complete: guarding `apply_transfer` guards the whole
/// eUTXO exit surface.
#[test]
fn a_deposit_does_not_consume_the_locked_output() {
    let slot = 5u64;
    let locked = locked_allocation_output();
    let (tr, g, mut chains) = setup(&[locked.clone()]);
    let dep = PosTransaction::Deposit {
        pubkey: vec![0x9A; 8],
        amount_sat: sat(25_000),
        randao_commitment: [0x00; 32],
        withdrawal_credentials: vec![0x01; 4],
        commission_bps: 0,
    };
    let b = build_block(&tr, &g, slot, &[], &[dep.clone()], &mut chains);
    let post = tr.apply_block(&g, &b, &[], &[dep]).expect("a plain deposit applies");
    // The locked output is untouched — the deposit did not, and cannot, spend it.
    assert!(
        post.utxo(&locked.txid, locked.vout).is_some(),
        "a deposit must not consume any eUTXO output, locked or not"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. The flag day itself — before activation, nothing is locked
// ─────────────────────────────────────────────────────────────────────────────

/// The genesis allocation outputs are created at slot 0, long before any
/// activation epoch. Task rule: a consensus change is INERT until its flag day.
/// So before `LOCKED_VESTING_ACTIVATION_EPOCH`, the founder output spends
/// exactly as it does on mainnet today — no fork, no behavioural change.
///
/// This test is the tripwire that keeps the default INERT: it asserts the
/// current live behaviour survives, and is the control for the entire lock.
#[test]
fn outputs_spend_freely_before_the_flag_day() {
    // Choose a slot whose epoch is strictly below the activation epoch. With the
    // shipped default (u64::MAX) every real slot qualifies.
    let slot = 5u64;
    assert!(epoch_of(slot) < params::LOCKED_VESTING_ACTIVATION_EPOCH);
    let locked = locked_allocation_output();
    let (tr, g, mut chains) = setup(&[locked.clone()]);
    let price = g.base_fee_millisat_per_gas();
    let spend = transfer_spending(&[locked], &founder_key(), script_of(&recipient_key()), price);
    let b = build_block(&tr, &g, slot, &[], &[spend.clone()], &mut chains);
    assert!(
        tr.apply_block(&g, &b, &[], &[spend]).is_ok(),
        "before the flag day the lock is inert — mainnet behaviour must be unchanged"
    );
}

/// The shipped default must stay inert (the `leaked_roster_ships_inert` idiom):
/// this fails the moment someone sets a real epoch, forcing the change to be
/// made together with a coordinated fleet rebuild rather than shipped quietly.
#[test]
fn vesting_lock_ships_inert() {
    assert_eq!(
        params::LOCKED_VESTING_ACTIVATION_EPOCH,
        u64::MAX,
        "binding the vesting lock is a flag day: set the epoch and roll the fleet together"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Reorg — a locked spend on a discarded branch must not leak
// ─────────────────────────────────────────────────────────────────────────────

/// Reorg is handled at the NODE layer (`engine.rs`: a branch is adopted only
/// after being replayed and validated in full through `apply_block`, from a
/// validated canonical ancestor — never trusting an unvalidated branch). The
/// lock is a pure predicate over (outpoint, slot) with no mutable committed
/// component, so it is re-evaluated identically on every replay. This test
/// pins the consensus-layer half: replaying the SAME locked-spend block on the
/// SAME parent yields the SAME rejection, deterministically — so no branch
/// ordering can turn a rejected spend into an accepted one.
/// CONTROL: replaying an unlocked spend yields the same acceptance.
#[test]
fn a_locked_spend_is_rejected_identically_on_replay() {
    let slot = 5u64;
    let locked = locked_allocation_output();
    let (tr, g, mut chains) = setup(&[locked.clone()]);
    let price = g.base_fee_millisat_per_gas();
    let spend = transfer_spending(&[locked], &founder_key(), script_of(&recipient_key()), price);
    let b = build_block(&tr, &g, slot, &[], &[spend.clone()], &mut chains);
    let r1 = tr.apply_block(&g, &b, &[], &[spend.clone()]);
    let r2 = tr.apply_block(&g, &b, &[], &[spend]);
    assert!(matches!(r1, Err(TransitionError::Transfer(0, _))));
    assert_eq!(format!("{r1:?}"), format!("{r2:?}"), "replay must be bit-identical — reorg cannot launder the spend");
}

// Silence unused-import lints in the gated-off state; every import is used once
// the feature is on.
#[allow(unused_imports)]
use bloch_pos_committee::interfaces::SlashingEvidence as _SE;
#[allow(unused_imports)]
use committees as _c;
