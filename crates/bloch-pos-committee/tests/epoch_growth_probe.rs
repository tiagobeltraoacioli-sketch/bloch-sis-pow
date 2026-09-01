// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contention-proof probe: is per-block replay cost a function of EPOCH COUNT?
//!
//! Instrumentation only. Asserts no consensus property. `#[ignore]`d.
//!
//! Timing on a loaded machine is unreliable in the MEAN but reliable in the
//! MINIMUM: the fastest of K runs is the one that was least preempted, so
//! min-of-K approximates the uncontended cost even at load average 100+.
//! Every figure below is a minimum over K repetitions.
//!
//! Run: cargo test --release -p bloch-pos-committee --test epoch_growth_probe \
//!        -- --ignored --nocapture --test-threads=1

use std::time::{Duration, Instant};

use bloch_pos_committee::delegation::{Delegation, Registry};

fn min_of<T>(k: usize, mut f: impl FnMut() -> T) -> Duration {
    let mut best = Duration::from_secs(3600);
    for _ in 0..k {
        let t = Instant::now();
        let out = f();
        let d = t.elapsed();
        std::hint::black_box(out);
        if d < best {
            best = d;
        }
    }
    best
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// `Registry::resolve(&[], epoch)` — the outer `for e in 0..=epoch` loop that
/// every block pays 4x (delegation.rs:231), measured with an EMPTY delegation
/// set so it isolates the epoch fold alone.
#[test]
#[ignore]
fn resolve_is_linear_in_epoch() {
    println!("\n=== Registry::resolve(&[], epoch), EMPTY delegation set ===");
    println!("profile: {}", if cfg!(debug_assertions) { "DEBUG — worthless" } else { "release" });
    println!("{:>8}  {:>12}  {:>14}", "epoch", "min us", "us per epoch");
    let mut base = None;
    for e in [0u64, 100, 500, 1000, 1666, 3000, 6000, 12000] {
        let d = min_of(200, || Registry::resolve(&[], e));
        if base.is_none() {
            base = Some(us(d));
        }
        println!("{e:>8}  {:>12.2}  {:>14.4}", us(d), us(d) / (e.max(1) as f64));
    }
}

/// Same, with a realistic non-empty delegation set — the inner loop runs too.
#[test]
#[ignore]
fn resolve_with_delegations() {
    println!("\n=== Registry::resolve(delegations, epoch) ===");
    for n in [0usize, 8, 64] {
        let ds: Vec<Delegation> = (0..n)
            .map(|i| Delegation {
                delegator: i as u32,
                validator: (i % 64) as u32,
                amount_sat: 32_00000000,
                requested_epoch: i as u64,
                deactivate_epoch: None,
                eligible: true,
            })
            .collect();
        print!("{n:>3} delegations:");
        for e in [100u64, 1000, 1666, 6000] {
            let d = min_of(100, || Registry::resolve(&ds, e));
            print!("  e{e}={:.1}us", us(d));
        }
        println!();
    }
}

// ── The finality leaf: O(justified checkpoints) = O(epochs), every block ─────

use bloch_pos_committee::state_root::{
    state_root, BaseFeeRecord, CheckpointRecord, ConsensusState, EvmCommitment, EutxoEntry,
    FinalityRecord,
};

fn cp(e: u64) -> CheckpointRecord {
    CheckpointRecord { epoch: e, root: [(e % 251) as u8; 32] }
}

fn fin(n: u64) -> FinalityRecord {
    FinalityRecord {
        justified: (0..n).map(cp).collect(),
        current_justified: cp(n),
        previous_justified: cp(n.saturating_sub(1)),
        finalized: cp(n.saturating_sub(1)),
        leaked: Vec::new(),
        next_epoch: n + 1,
    }
}

/// Everything except `finality` held fixed, so the delta between two rows is
/// the cost of the justified-checkpoint list and nothing else.
#[test]
#[ignore]
fn finality_leaf_cost_by_epoch_count() {
    println!("\n=== state_root cost vs number of justified checkpoints ===");
    println!("profile: {}", if cfg!(debug_assertions) { "DEBUG — worthless" } else { "release" });
    let eu: Vec<EutxoEntry> = (0..1024u32)
        .map(|i| EutxoEntry { txid: [i as u8; 32], vout: i % 4, value: 8_400_000_000, script_hash: [7u8; 32] })
        .collect();
    println!("{:>10}  {:>12}  {:>16}  {:>14}", "justified", "min us", "delta vs 0 us", "us per epoch");
    let mut base = None;
    for n in [0u64, 100, 500, 1000, 1667, 4000, 8000] {
        let f = fin(n);
        let st = ConsensusState {
            eutxos: &eu,
            validators: &[],
            current_participation: &[],
            previous_participation: &[],
            randao_mixes: &[],
            finality: &f,
            pending_votes: &[],
            fc_messages: &[],
            fc_equivocators: &[],
            deposit_queue: &[],
            delegations: &[],
            pending_fees: &[],
            taint_root: [0u8; 32],
            coherence_accumulator_root: [0u8; 32],
            coherence_nullifier_root: [0u8; 32],
            evm: EvmCommitment { account_root: [0u8; 32], receipts_root: [0u8; 32], gas_used: 0, base_fee_per_gas: 0 },
            issued_sat: 0,
            applied_evidence: &[],
            slash_window: &[],
            delegator_slash_losses: &[],
            base_fee: BaseFeeRecord { base_fee_millisat_per_gas: 1000, gas_used: 0, tx_bytes: 0 },
            delegator_fee_rewards: &[],
        };
        let d = min_of(30, || state_root(&st));
        if base.is_none() { base = Some(us(d)); }
        let delta = us(d) - base.unwrap();
        println!("{n:>10}  {:>12.1}  {:>16.1}  {:>14.4}", us(d), delta, delta / (n.max(1) as f64));
    }
    println!("  (the whole-block growth observed on the live fleet is ~12.7 us per epoch;");
    println!("   compare the last column against that.)");
}
