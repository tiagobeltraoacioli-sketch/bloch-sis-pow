// SPDX-License-Identifier: AGPL-3.0-or-later

//! The scheduler (spec §7): conflict relation over DECLARED sets, wave
//! layering, and the two block entry points whose results must be
//! byte-identical — [`execute_block_serial`] (the reference semantics) and
//! [`execute_block_parallel`] (the optimization).
//!
//! Determinism comes from three structural facts, each pinned by a §8 test:
//!
//! 1. The schedule is a **pure function of (transaction list, declared
//!    sets)**, computed before any execution starts ([`schedule_waves`]).
//!    Outcomes cannot influence it — aborted transactions keep their
//!    declared sets in the layering (§7.2).
//! 2. Within a wave every transaction executes against the **same committed
//!    snapshot** (the state as of the end of the previous wave), and
//!    §6's enforcement confines each to its declared sets, so same-wave
//!    transactions are invisible to each other by construction (§7.3).
//! 3. Effects **commit in canonical index order** and block aggregates fold
//!    in canonical index order. Within a wave the write sets are pairwise
//!    disjoint, so merge order provably cannot matter — the canonical rule
//!    costs nothing and removes the temptation for any future
//!    order-sensitive aggregate to sneak in (§7.2). u128 fee addition
//!    commutes today; the RULE is what stops a non-commutative aggregate
//!    tomorrow.
//!
//! What the scheduler refuses to do (§7.4, each with real determinism
//! hazards, each in the spec's §11 ledger): dynamic re-scheduling on abort,
//! optimistic execution with rollback (Block-STM), priority lanes, local fee
//! markets.

use crate::errors::BlockError;
use crate::runtime::{execute_tx, ExecEnv, ProgramExecutor, SignatureVerifier, TxEffect, TxOutcome};
use crate::tree::SvmState;
use crate::tx::SvmTransaction;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;

/// The §7.1 conflict relation, over declared sets only:
/// `conflict(a,b) ⟺ W(a)∩W(b) ≠ ∅ ∨ W(a)∩R(b) ≠ ∅ ∨ R(a)∩W(b) ≠ ∅`.
/// Read-read never conflicts — that is the entire point of declaring.
pub fn conflict(a: &SvmTransaction, b: &SvmTransaction) -> bool {
    conflict_sets(&(a.writable_set(), a.readonly_set()), &(b.writable_set(), b.readonly_set()))
}

type Sets = (BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>);

fn intersects(a: &BTreeSet<[u8; 32]>, b: &BTreeSet<[u8; 32]>) -> bool {
    // Iterate the smaller, probe the larger: O(min·log max), plenty under
    // the 64-account cap.
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().any(|k| large.contains(k))
}

fn conflict_sets(a: &Sets, b: &Sets) -> bool {
    intersects(&a.0, &b.0) || intersects(&a.0, &b.1) || intersects(&a.1, &b.0)
}

/// Wave layering (§7.2): `wave(t_i) = 1 + max{ wave(t_j) : j < i,
/// conflict(t_j, t_i) }`, `max ∅ = -1` — the longest-path layering of the
/// precedence DAG, 0-based. A pure function of (list, declared sets): no
/// timing, no thread identity, no outcome can enter, because this runs to
/// completion before any execution starts.
///
/// O(n²) pairwise over ≤64-address sets. A block cap will bound n; if
/// profiling ever demands better, an index-by-address map is a pure
/// optimization that must ship with the §8-7 KAT unchanged.
pub fn schedule_waves(txs: &[SvmTransaction]) -> Vec<u32> {
    let sets: Vec<Sets> = txs.iter().map(|t| (t.writable_set(), t.readonly_set())).collect();
    let mut waves = vec![0u32; txs.len()];
    for i in 0..txs.len() {
        let mut w = 0u32;
        for j in 0..i {
            if conflict_sets(&sets[j], &sets[i]) {
                // waves[j] + 1 is total: waves grow by at most 1 per index.
                w = w.max(waves[j] + 1);
            }
        }
        waves[i] = w;
    }
    waves
}

/// What one block's execution produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockOutcome {
    /// Per-transaction outcome, in block order. Part of the §8-1 equivalence
    /// surface: serial and parallel must agree on every field.
    pub outcomes: Vec<TxOutcome>,
    /// Total fees charged, folded in canonical index order, u128 (the
    /// interfaces contract: sums are u128). Where fees GO — a proposer
    /// ledger — is fee_market.rs/X1 territory (spec §9.3), not this crate's.
    pub fees_collected: u128,
    /// The post-state SVM root (§4.1). KATs pin THIS, never the outer
    /// consensus state_root.
    pub svm_root: [u8; 32],
}

fn validate_all(txs: &[SvmTransaction]) -> Result<(), BlockError> {
    // §5.2 runs at block validation too — both, always. Structural
    // invalidity is producer-attributable, hence the one block-level error.
    for (index, tx) in txs.iter().enumerate() {
        tx.validate_structure()
            .map_err(|error| BlockError::Structural { index, error })?;
    }
    Ok(())
}

fn commit(
    state: &mut SvmState,
    fees: &mut u128,
    outcome_slot: &mut Option<TxOutcome>,
    effect: TxEffect,
) -> Result<(), BlockError> {
    // The ONLY writer of SvmState in the crate: effects flow through
    // set_account (tree.rs's single mutation choke point). `writes` was
    // built from the declared-writable list and nothing else (§6.4).
    for (addr, post) in effect.writes {
        state.set_account(addr, post);
    }
    *fees = fees
        .checked_add(u128::from(effect.outcome.fee_paid))
        .ok_or(BlockError::ArithmeticOverflow)?;
    *outcome_slot = Some(effect.outcome);
    Ok(())
}

/// Sequential execution in canonical order — the REFERENCE semantics of the
/// §7.3 equivalence claim. Commits after every transaction, so each
/// transaction observes every predecessor.
pub fn execute_block_serial(
    state: &mut SvmState,
    txs: &[SvmTransaction],
    executor: &(dyn ProgramExecutor + Sync),
    verifier: &(dyn SignatureVerifier + Sync),
    env: &ExecEnv,
) -> Result<BlockOutcome, BlockError> {
    validate_all(txs)?;
    let mut outcomes: Vec<Option<TxOutcome>> = vec![None; txs.len()];
    let mut fees: u128 = 0;
    for (i, tx) in txs.iter().enumerate() {
        let effect = execute_tx(state, tx, executor, verifier, env);
        commit(state, &mut fees, &mut outcomes[i], effect)?;
    }
    Ok(BlockOutcome {
        // Every slot was filled by the loop; the flatten is total.
        outcomes: outcomes.into_iter().flatten().collect(),
        fees_collected: fees,
        svm_root: state.svm_root(),
    })
}

/// Parallel execution under §7.2: waves strictly in order; within a wave,
/// transactions run on `threads` OS threads against the frozen
/// previous-wave state; effects commit in canonical index order after the
/// whole wave completes.
///
/// `threads` is a PARAMETER, not the machine's accident (§8-1: thread count
/// is part of the test matrix) — and the §7.3 theorem is precisely that its
/// value cannot reach the result bytes.
pub fn execute_block_parallel(
    state: &mut SvmState,
    txs: &[SvmTransaction],
    executor: &(dyn ProgramExecutor + Sync),
    verifier: &(dyn SignatureVerifier + Sync),
    env: &ExecEnv,
    threads: NonZeroUsize,
) -> Result<BlockOutcome, BlockError> {
    validate_all(txs)?;
    let waves = schedule_waves(txs);
    let max_wave = waves.iter().copied().max();
    let mut outcomes: Vec<Option<TxOutcome>> = vec![None; txs.len()];
    let mut fees: u128 = 0;

    if let Some(max_wave) = max_wave {
        for wave in 0..=max_wave {
            let idxs: Vec<usize> =
                (0..txs.len()).filter(|i| waves[*i] == wave).collect();
            // ceil-division chunking: deterministic partition of the wave's
            // indices. WHICH thread runs which chunk cannot matter —
            // execute_tx is a pure function of (snapshot, tx) — but the
            // partition being input-determined keeps even the work
            // assignment out of the machine's hands.
            let chunk = idxs.len().div_ceil(threads.get());
            let snapshot: &SvmState = state;
            let mut effects: Vec<TxEffect> = Vec::with_capacity(idxs.len());
            std::thread::scope(|s| {
                let handles: Vec<_> = idxs
                    .chunks(chunk)
                    .map(|ic| {
                        s.spawn(move || {
                            ic.iter()
                                .map(|i| execute_tx(snapshot, &txs[*i], executor, verifier, env))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                for h in handles {
                    // Joined in spawn order ⇒ effects align with idxs.
                    // A child panic is a bug in an executor (the execution
                    // path itself is panic-free, §2); propagate it verbatim
                    // rather than inventing a state.
                    match h.join() {
                        Ok(v) => effects.extend(v),
                        Err(p) => std::panic::resume_unwind(p),
                    }
                }
            });
            // Commit in canonical index order (idxs is ascending by
            // construction), AFTER the whole wave completed (§7.2).
            for (i, effect) in idxs.iter().zip(effects.into_iter()) {
                commit(state, &mut fees, &mut outcomes[*i], effect)?;
            }
        }
    }

    Ok(BlockOutcome {
        outcomes: outcomes.into_iter().flatten().collect(),
        fees_collected: fees,
        svm_root: state.svm_root(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::wallet_address;
    use crate::testkit::{
        gate_tx, hog_tx, manifest, transfer_tx, AcceptAll, DetRng, TestExecutor, ENV,
    };
    use crate::tx::testutil::tx as raw_tx;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("nonzero")
    }

    /// §7.1 unit pins: each arm of the relation, plus the read-read
    /// non-conflict that is the entire point of declaring.
    #[test]
    fn conflict_relation_arms() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let w_a = raw_tx(&[b"p1"], &[a], &[], 0, 1, vec![]);
        let w_a2 = raw_tx(&[b"p2"], &[a], &[], 0, 1, vec![]);
        let r_a = raw_tx(&[b"p3"], &[b], &[a], 0, 1, vec![]);
        let r_a2 = raw_tx(&[b"p4"], &[c], &[a], 0, 1, vec![]);
        assert!(conflict(&w_a, &w_a2), "W∩W");
        assert!(conflict(&w_a, &r_a), "W∩R");
        assert!(conflict(&r_a, &w_a), "R∩W (symmetric arm)");
        assert!(!conflict(&r_a, &r_a2), "read-read never conflicts");
        // Fee payers are writable signers: same payer ⇒ conflict (§7.2's
        // "exactly what the nonce scheme needs").
        let same_payer_1 = raw_tx(&[b"p5"], &[a], &[], 0, 1, vec![]);
        let same_payer_2 = raw_tx(&[b"p5"], &[b], &[], 1, 1, vec![]);
        assert!(conflict(&same_payer_1, &same_payer_2));
    }

    /// §8-7 — the layering KAT: a fixed 12-transaction body with a designed
    /// conflict graph ⇒ PINNED wave assignment. Any scheduler change that
    /// moves a transaction between waves is a visible diff here, therefore a
    /// review event. (Payers P0..P7 and recipients are all distinct wallet
    /// addresses; conflicts are engineered through shared payers, shared
    /// recipients, and gate reads.)
    #[test]
    fn layering_kat_12_transactions() {
        let p: Vec<Vec<u8>> = (0..8).map(|i| format!("kat-payer-{i}").into_bytes()).collect();
        let r: Vec<[u8; 32]> = (0..7).map(|i| [0xB0 + i as u8; 32]).collect();
        let txs = vec![
            transfer_tx(&p[0], r[0], 1, 0), // 0: W{P0,R0}            → wave 0
            transfer_tx(&p[1], r[1], 1, 0), // 1: W{P1,R1}            → wave 0
            transfer_tx(&p[0], r[2], 1, 1), // 2: P0 again (vs 0)     → wave 1
            transfer_tx(&p[2], r[0], 1, 0), // 3: R0 again (vs 0)     → wave 1
            transfer_tx(&p[3], r[3], 1, 0), // 4: independent         → wave 0
            transfer_tx(&p[0], r[1], 1, 2), // 5: P0 (vs 2), R1 (vs 1)→ wave 2
            gate_tx(&p[4], r[2], 1, 0),     // 6: reads R2 (vs 2)     → wave 2
            transfer_tx(&p[4], r[4], 1, 1), // 7: P4 (vs 6)           → wave 3
            transfer_tx(&p[5], r[5], 1, 0), // 8: independent         → wave 0
            transfer_tx(&p[5], r[5], 1, 1), // 9: both (vs 8)         → wave 1
            transfer_tx(&p[6], r[2], 1, 0), // 10: R2 W∩W (vs 2), W∩R (vs 6) → wave 3
            gate_tx(&p[7], r[5], 1, 0),     // 11: reads R5 (vs 8, 9) → wave 2
        ];
        assert_eq!(schedule_waves(&txs), vec![0, 0, 1, 1, 0, 2, 2, 3, 0, 1, 3, 2]);
        // Control half: an empty and a singleton body layer trivially.
        assert_eq!(schedule_waves(&[]), Vec::<u32>::new());
        assert_eq!(schedule_waves(&txs[..1]), vec![0]);
    }

    /// The layering ignores outcomes by construction — but pin it anyway:
    /// a transaction doomed to abort (hog with a tiny budget) occupies the
    /// same wave as its conflict structure dictates (§7.2 "aborted
    /// transactions keep their declared sets in the layering").
    #[test]
    fn layering_is_outcome_blind() {
        let doomed = hog_tx(b"p-doom", 100, 1_000, 1_500, 0); // will exhaust
        let follower = transfer_tx(b"p-doom", [0xC1; 32], 1, 1); // same payer
        assert_eq!(schedule_waves(&[doomed, follower]), vec![0, 1]);
    }

    // -- §8-1: the equivalence obligation -----------------------------------

    /// Conflict-density knob for the generated workloads.
    #[derive(Clone, Copy, Debug)]
    enum Density {
        /// Distinct payer and recipient per transaction: every wave is 0.
        NoConflict,
        /// Small hot set: real mixed waves.
        Mixed,
        /// One payer for everything: a single serialized chain.
        AllConflict,
    }

    /// Deterministic workload: manifest + transactions with tracked nonces.
    /// Includes gates (read-dependencies observable in result codes),
    /// intentional overdrafts (abort path, fee+nonce), intentional bad
    /// nonces (reject path, no effect), and hogs (meter readings) — so the
    /// equivalence comparison covers every outcome family, not a happy path.
    fn workload(seed: u64, n_txs: usize, density: Density) -> (SvmState, Vec<SvmTransaction>) {
        let mut rng = DetRng::new(seed);
        let n_wallets: usize = match density {
            Density::NoConflict => 2 * n_txs.max(1),
            Density::Mixed => 6,
            Density::AllConflict => 3,
        };
        let pks: Vec<Vec<u8>> =
            (0..n_wallets).map(|i| format!("w-{seed}-{i}").into_bytes()).collect();
        let rich = 100_000_000u64;
        let wallets: Vec<(&[u8], u64)> = pks.iter().map(|p| (p.as_slice(), rich)).collect();
        let state = manifest(&wallets);

        // Track expected nonces: every executed OR aborted tx bumps; only
        // rejected ones (bad nonce here) do not. The generator only needs
        // this to produce mostly-valid chains — the equivalence test itself
        // never assumes outcomes, it only compares serial vs parallel.
        let mut nonces = vec![0u64; n_wallets];
        let mut txs = Vec::with_capacity(n_txs);
        for k in 0..n_txs {
            let (payer, other) = match density {
                Density::NoConflict => (2 * k, 2 * k + 1),
                Density::Mixed => {
                    let p = rng.below(n_wallets as u64) as usize;
                    let mut o = rng.below(n_wallets as u64) as usize;
                    if o == p {
                        o = (o + 1) % n_wallets;
                    }
                    (p, o)
                }
                Density::AllConflict => (0, 1 + (k % 2)),
            };
            let payer_pk = &pks[payer];
            let target = wallet_address(&pks[other]);
            let roll = rng.below(100);
            let tx = if roll < 55 {
                let amt = rng.below(5_000) + 1;
                let t = transfer_tx(payer_pk, target, amt, nonces[payer]);
                nonces[payer] += 1;
                t
            } else if roll < 70 {
                // Gate whose threshold sits near the live balance, so
                // whether it passes depends on ORDER — the W∩R teeth.
                let threshold = rich + rng.below(10_000);
                let t = gate_tx(payer_pk, target, threshold, nonces[payer]);
                nonces[payer] += 1; // gates abort or execute; both bump
                t
            } else if roll < 80 {
                // Overdraft: aborts at debit, fee+nonce still applied.
                let t = transfer_tx(payer_pk, target, u64::MAX / 2, nonces[payer]);
                nonces[payer] += 1;
                t
            } else if roll < 90 {
                // Meter path: some exhaust (budget 1,500 < dispatch+3×400),
                // some complete — both with pinned readings.
                let n = 3 + (rng.below(3) as u32);
                let budget = if rng.below(2) == 0 { 1_500 } else { 5_000 };
                let t = hog_tx(payer_pk, n, 400, budget, nonces[payer]);
                nonces[payer] += 1;
                t
            } else {
                // Bad nonce: rejected, NO bump.
                transfer_tx(payer_pk, target, 1, nonces[payer] + 1_000_000)
            };
            txs.push(tx);
        }
        (state, txs)
    }

    /// Run one workload serially and in parallel on the whole thread matrix,
    /// asserting byte-identical outcomes, fees, roots, and full states.
    fn assert_equivalent(seed: u64, n_txs: usize, density: Density) {
        let (state0, txs) = workload(seed, n_txs, density);
        let mut serial_state = state0.clone();
        let serial =
            execute_block_serial(&mut serial_state, &txs, &TestExecutor, &AcceptAll, &ENV)
                .expect("valid workload");
        // §8-1: thread count is part of the matrix, not the machine's
        // accident.
        for threads in [1usize, 2, 4, 8] {
            let mut par_state = state0.clone();
            let par = execute_block_parallel(
                &mut par_state,
                &txs,
                &TestExecutor,
                &AcceptAll,
                &ENV,
                nz(threads),
            )
            .expect("valid workload");
            assert_eq!(
                serial.outcomes, par.outcomes,
                "result codes diverged (seed {seed}, {density:?}, {threads} threads)"
            );
            assert_eq!(serial.fees_collected, par.fees_collected);
            assert_eq!(
                serial.svm_root, par.svm_root,
                "roots diverged (seed {seed}, {density:?}, {threads} threads)"
            );
            assert_eq!(serial_state, par_state, "full state equality");
        }
        // Block-level conservation: nothing minted, everything accounted:
        // Σ pre == Σ post + fees (the §6.4-2 invariant at block grain).
        assert_eq!(
            state0.total_balance(),
            serial_state.total_balance() + serial.fees_collected,
            "block conservation (seed {seed}, {density:?})"
        );
    }

    /// §8-1 — the pinned sweep: fixed seeds × densities × thread matrix.
    /// Every run of this test, on every machine, executes the identical
    /// vector set (DetRng is SHA3 counter-mode) — this is the pin; the
    /// proptest below is the bug-finder.
    ///
    /// Sizing note: each `assert_equivalent` computes five block roots, and a
    /// root is O(leaves x 256) SHA3 with an UNOPTIMIZED keccak in the dev
    /// profile (the root workspace sets no `[profile.dev.package.sha3]`, and
    /// bloch-pos-committee's copy of that stanza is inert since it became a
    /// member -- its Cargo.toml says so). Seeds and sizes are therefore held
    /// to what still exercises every outcome family in a few minutes; raising
    /// them is free correctness and costs only wall clock.
    #[test]
    fn serial_parallel_equivalence_pinned_sweep() {
        for seed in 0..8u64 {
            assert_equivalent(seed, 20, Density::Mixed);
        }
        for seed in 12..15u64 {
            assert_equivalent(seed, 14, Density::NoConflict);
            assert_equivalent(seed, 14, Density::AllConflict);
        }
        // Extremes: empty body and single transaction.
        assert_equivalent(100, 0, Density::Mixed);
        assert_equivalent(101, 1, Density::Mixed);
    }

    /// §8-1 — the property-test half (proptest precedent: bloch-sis-pow,
    /// bloch-crypto). OS-entropy exploration on top of the pinned sweep;
    /// failures persist a regression seed under proptest-regressions/.
    #[test]
    fn serial_parallel_equivalence_property() {
        use proptest::prelude::*;
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 24,
            ..ProptestConfig::default()
        });
        runner
            .run(&(any::<u64>(), 1usize..18, 0u8..3), |(seed, n_txs, d)| {
                let density = match d {
                    0 => Density::NoConflict,
                    1 => Density::Mixed,
                    _ => Density::AllConflict,
                };
                assert_equivalent(seed, n_txs, density);
                Ok(())
            })
            .unwrap();
    }

    /// The parallel path must actually be PARALLEL. Without this, the
    /// strongest possible mutation of this module — making
    /// `execute_block_parallel` delegate to `execute_block_serial` — would
    /// leave the whole §8-1 equivalence sweep green and vacuous, since the
    /// two are equal by the §7.3 theorem. So the concurrency itself is
    /// pinned: a wide wave (16 mutually non-conflicting transfers) executed
    /// with 4 threads must be observed from more than one OS thread.
    ///
    /// The observation is a side channel INSIDE the test executor (a mutex
    /// over thread ids) and never touches a result byte — nothing in the
    /// production path may branch on thread identity (§2/D-0).
    ///
    /// **Control:** the same block with `threads = 1` is observed from
    /// exactly one thread, so the assertion above cannot be passing because
    /// the recorder counts something other than threads.
    #[test]
    fn parallel_execution_is_actually_concurrent() {
        use crate::errors::ProgramError;
        use crate::meter::ComputeMeter;
        use crate::runtime::{AccountHandle, ProgramExecutor};
        use std::sync::Mutex;

        // A Vec, not a set: `ThreadId` is Eq but not Ord, and this crate
        // does not use HashSet (§2 bans it where a RESULT is derived from
        // iteration — this is a test-only side channel, but the habit is
        // cheaper to keep than to audit).
        struct ThreadWitness {
            seen: Mutex<Vec<std::thread::ThreadId>>,
        }
        impl ProgramExecutor for ThreadWitness {
            fn execute(
                &self,
                program_id: &[u8; 32],
                data: &[u8],
                accounts: &mut [AccountHandle<'_>],
                meter: &mut ComputeMeter,
                env: &ExecEnv,
            ) -> Result<(), ProgramError> {
                if let Ok(mut g) = self.seen.lock() {
                    let id = std::thread::current().id();
                    if !g.contains(&id) {
                        g.push(id);
                    }
                }
                TestExecutor.execute(program_id, data, accounts, meter, env)
            }
        }

        // 16 transfers, every payer and recipient distinct ⇒ one wave.
        let pks: Vec<Vec<u8>> =
            (0..32).map(|i| format!("conc-{i}").into_bytes()).collect();
        let wallets: Vec<(&[u8], u64)> =
            pks.iter().map(|p| (p.as_slice(), 100_000_000u64)).collect();
        let state0 = manifest(&wallets);
        let txs: Vec<SvmTransaction> = (0..16)
            .map(|k| transfer_tx(&pks[k], wallet_address(&pks[16 + k]), 10, 0))
            .collect();
        assert_eq!(schedule_waves(&txs), vec![0; 16], "fixture must be one wide wave");

        let wit = ThreadWitness { seen: Mutex::new(Vec::new()) };
        let mut s = state0.clone();
        execute_block_parallel(&mut s, &txs, &wit, &AcceptAll, &ENV, nz(4)).unwrap();
        assert!(
            wit.seen.lock().unwrap().len() > 1,
            "a 16-transaction wave on 4 threads ran on one thread — the \
             parallel path is not parallel, and the equivalence sweep is vacuous"
        );

        // Control: one thread requested ⇒ exactly one thread observed.
        let wit1 = ThreadWitness { seen: Mutex::new(Vec::new()) };
        let mut s1 = state0;
        execute_block_parallel(&mut s1, &txs, &wit1, &AcceptAll, &ENV, nz(1)).unwrap();
        assert_eq!(wit1.seen.lock().unwrap().len(), 1);
    }

    /// The svm_root KAT: one fixed tiny block, the root pinned in hex. Any
    /// change to the codec, the tree, the fee constants, or execution
    /// semantics moves this — a visible review event (the §4.1 rule: pin
    /// svm_root, never the consensus state_root).
    #[test]
    fn block_root_kat() {
        let (state0, txs) = workload(4242, 8, Density::Mixed);
        let mut s = state0;
        let out = execute_block_serial(&mut s, &txs, &TestExecutor, &AcceptAll, &ENV).unwrap();
        assert_eq!(hex::encode(out.svm_root), "9aecc26c2d68c2d916886d12ba0cfc0ff529b673690af70fbc40eb77a68effbb");
    }

    /// Structural invalidity is the one block-level reject (§5.2 at block
    /// validation), identical for both entry points; control: the same block
    /// minus the malformed transaction executes.
    #[test]
    fn structural_invalidity_rejects_the_block() {
        let (state0, mut txs) = workload(7, 4, Density::Mixed);
        // Corrupt one transaction: duplicate address across sections.
        let dup = txs[1].accounts[0].address;
        txs[1].accounts[1].address = dup;
        let mut s1 = state0.clone();
        let serial = execute_block_serial(&mut s1, &txs, &TestExecutor, &AcceptAll, &ENV);
        assert!(matches!(serial, Err(BlockError::Structural { index: 1, .. })));
        let mut s2 = state0.clone();
        let par =
            execute_block_parallel(&mut s2, &txs, &TestExecutor, &AcceptAll, &ENV, nz(4));
        assert!(matches!(par, Err(BlockError::Structural { index: 1, .. })));
        // A failed block left no marks.
        assert_eq!(s1, state0);
        assert_eq!(s2, state0);
        // Control: drop the malformed tx ⇒ executes.
        txs.remove(1);
        let mut s3 = state0.clone();
        assert!(execute_block_serial(&mut s3, &txs, &TestExecutor, &AcceptAll, &ENV).is_ok());
    }
}
