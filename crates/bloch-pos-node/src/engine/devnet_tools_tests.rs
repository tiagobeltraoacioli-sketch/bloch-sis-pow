// SPDX-License-Identifier: AGPL-3.0-or-later
//! `devnet_tools` against a real `Engine`: the transfer the CLI builds from a
//! genesis allocation is admitted at the mempool door and applied by the
//! committee transition inside a block this node produces.
//!
//! Lives under `engine` because `propose`, `attest` and `on_transaction` are
//! private to it, the same way `validator_admission_tests.rs` does.

use super::*;
use crate::devnet_tools::{allocation_report, build_transfer_v2, parse_alloc_spec, SpendInput};
use crate::keys::{Unlock, AUTO_VALIDATOR_INDEX};
use bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH as V2_FLAG_DAY;
use bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH;

/// One block for `epoch`, at the sole validator's committee slot, carrying
/// its own attestation — the real duty path (`attest` + `propose`), nothing
/// injected.
fn drive_one_attested_block(engine: &mut Engine, epoch: u64) {
    let first = epoch * SLOTS_PER_EPOCH;
    for slot in first..first + SLOTS_PER_EPOCH {
        let _clock = super::validator_lifecycle::clock_at(slot);
        engine.wall_slot = slot;
        engine.attest(slot);
        if engine.pool.is_empty() {
            continue;
        }
        // `attest` put the vote in `pool`, which is where `propose` reads
        // from; no gossip round-trip is needed on a one-node chain.
        let before = engine.head_id();
        engine.propose(slot);
        assert_ne!(engine.head_id(), before, "epoch {epoch}: no block adopted at slot {slot}");
        assert_eq!(engine.state.slot(), slot);
        return;
    }
    panic!("epoch {epoch}: the sole validator sat in no committee");
}

/// Advance the chain to the first slot of `target` with the validator's
/// stake intact, under the real rules and at the least cost.
///
/// `sample` draws proposers only from validators with non-zero effective
/// stake, and the inactivity leak bleeds any committee member that casts no
/// valid vote in an epoch closed more than `INACTIVITY_LEAK_THRESHOLD_EPOCHS`
/// (4) past the last finalized one — so 800 empty epochs would leave the sole
/// validator with nothing to propose with. Voting every epoch works and costs
/// ~150 ms of hybrid signing and RANDAO chain regeneration per epoch. Voting
/// in epochs `e % 5 ∈ {1, 2}` is enough: the second vote of each pair links
/// from the first (adjacent source), which finalizes the first, so
/// `since_finality` climbs 1, 2, 3, 4 across the three silent epochs and
/// reaches 5 — the first leaking value — only in an epoch the validator votes
/// in, where a valid vote spares it (finality.rs, "cast a valid vote —
/// spared"). Epoch 0 gets a plain block at slot 1: nobody attests in epoch 0
/// (genesis is justified by definition, `attest` returns).
fn drive_to_epoch(engine: &mut Engine, target: u64) {
    {
        let _clock = super::validator_lifecycle::clock_at(1);
        engine.wall_slot = 1;
        let before = engine.head_id();
        engine.propose(1);
        assert_ne!(engine.head_id(), before, "epoch 0: no block adopted at slot 1");
    }
    for epoch in 1..target {
        if matches!(epoch % 5, 1 | 2) {
            drive_one_attested_block(engine, epoch);
        }
    }
}

#[test]
fn transfer_v2_from_a_genesis_allocation_applies_through_the_transition() {
    let (mut engine, dir) = perf_support::proposing_engine();
    let funder = Keystore::generate_with(
        &dir.0.join("funder"),
        AUTO_VALIDATOR_INDEX,
        &Unlock::PlaintextOptIn,
    )
    .unwrap();
    // The allocation exactly as `genesis --alloc` parses it.
    let funder_script: [u8; 32] = Sha3_256::digest(&funder.pubkey).into();
    let spec = format!("{}:{}", crate::codec::hex32(&funder_script), 25_001 * SAT_PER_BLOCH);
    engine.manifest.allocations.push(parse_alloc_spec(&spec).unwrap());
    engine.state = StateCell::new(engine.manifest.genesis_state());
    let report = allocation_report(&engine.manifest);
    assert_eq!(report.len(), 1);
    let opening = engine.manifest.allocation_outputs();
    let coin = opening[0].clone();
    assert!(report[0].contains(&format!("txid={}", crate::codec::hex32(&coin.txid))));
    assert_eq!(
        engine.state.utxo(&coin.txid, 0).map(|e| (e.value, e.script_hash)),
        Some((coin.value, funder_script)),
        "genesis must hold the reported allocation outpoint"
    );

    // Real blocks up to the flag-day epoch, finality kept alive.
    drive_to_epoch(&mut engine, V2_FLAG_DAY);
    let slot = V2_FLAG_DAY * SLOTS_PER_EPOCH;
    let _clock = super::validator_lifecycle::clock_at(slot);
    engine.wall_slot = slot;
    assert_eq!(epoch_of(engine.wall_slot()), V2_FLAG_DAY);
    // Finality kept up: as the flag-day epoch opens (the head state rolled
    // through the boundaries the flag-day block will walk), the finalized
    // checkpoint is within the leak threshold — nothing has leaked.
    let finalized = engine.rolled_to(V2_FLAG_DAY).finality().finalized.epoch;
    assert!(
        finalized + bloch_pos_committee::params::INACTIVITY_LEAK_THRESHOLD_EPOCHS >= V2_FLAG_DAY,
        "finality must have kept up with the cadence (finalized {finalized})"
    );

    // Priced the way the including block will price it: the parent state at
    // the block's own epoch (`compute_post_state` -> `next_base_fee_at`).
    let base_fee = engine.state.next_base_fee_at(V2_FLAG_DAY);
    let dest = [0x94u8; 32];
    let plan = build_transfer_v2(
        &funder,
        &[SpendInput { txid: coin.txid, vout: 0, value_sat: coin.value }],
        dest,
        base_fee,
        5,
        V2_FLAG_DAY,
    )
    .unwrap();
    let tx = plan.tx.clone();
    assert_eq!(u128::from(plan.paid_sat) + plan.fee_sat, u128::from(coin.value));
    // The mempool door: refused the epoch before the flag day, admitted at it.
    assert!(admissible(&tx, V2_FLAG_DAY - 1).is_err());
    assert!(admissible(&tx, V2_FLAG_DAY).is_ok());
    assert_eq!(engine.on_transaction(tx.clone()), Ok(Admitted::New));

    let before = engine.head_id();
    engine.propose(slot);
    assert_ne!(engine.head_id(), before, "the flag-day block must be adopted");
    let head = engine.blocks[engine.head_id().as_bytes()].clone();
    assert_eq!(
        head.body.transactions,
        vec![tx.canonical_bytes()],
        "the block must carry exactly the transfer"
    );
    assert!(engine.state.utxo(&coin.txid, 0).is_none(), "the allocation must be spent");
    let paid = engine.state.utxo(&tx.txid(), 0).expect("the payment must exist");
    assert_eq!(paid.script_hash, dest);
    assert_eq!(paid.value, plan.paid_sat);
    assert!(engine.mempool.is_empty(), "an included transfer leaves the mempool");
}
