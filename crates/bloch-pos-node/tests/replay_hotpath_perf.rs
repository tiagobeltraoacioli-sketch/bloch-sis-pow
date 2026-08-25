// SPDX-License-Identifier: AGPL-3.0-or-later
//
// PERF INSTRUMENTATION ONLY — not a consensus test, not part of any gate.
//
// Measures the replay hot path claimed in engine.rs (~line 1663): "every block
// re-derives the state root over the full committed state — 0.59s per block at
// Genesis-4's carryover size". Everything here is `#[ignore]`d; nothing here
// asserts a consensus property.
//
// It lives in bloch-pos-node/tests/ rather than bloch-pos-committee/tests/ for
// one reason: the committee crate is deliberately PQ-free, and task 4 needs the
// real ML-DSA-65 ‖ Falcon-1024 verify. This crate depends on both, and a test
// target sees `[dependencies]` as well as `[dev-dependencies]`.
//
// Run:
//   cargo test --release -p bloch-pos-node --test replay_hotpath_perf \
//       -- --ignored --nocapture --test-threads=1
//
// NOTE ON THE MEMO: state_root.rs holds a THREAD-LOCAL two-generation memo of
// singleton subtree roots. Its state dominates every number below, so any two
// figures that are printed side by side and divided by each other are measured
// on two SEPARATE freshly spawned threads (see `cold_thread`). Sharing a thread
// between two rival builds hands the second one the first's cache and prints
// the inverse of the claim; that happened here and was corrected 2026-08-23.

use bloch_pos_committee::state_root::{
    build_state_tree, eutxo_leaf, state_root_with_eutxo_tree, BaseFeeRecord, CheckpointRecord,
    ConsensusState, EutxoEntry, EvmCommitment, FinalityRecord, ParticipationRecord, RandaoMix,
    Smt, ValidatorRecord,
};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Genesis-4's measured carryover size (the number the engine comment cites).
const CARRYOVER_N: u32 = 452_726;
/// Roughly the live Genesis-4 validator set (12 classic + 49 Fly).
const N_VALIDATORS: u32 = 64;

// ── fixture ────────────────────────────────────────────────────────────────

fn h32(seed: u64) -> [u8; 32] {
    // splitmix64-expanded filler. Cheap on purpose: the tree key is SHA3 of
    // this, so the tree's key distribution comes from derive_key, not from here.
    let mut out = [0u8; 32];
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for c in out.chunks_mut(8) {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        c.copy_from_slice(&x.to_le_bytes());
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    }
    out
}

fn eutxos(n: u32) -> Vec<EutxoEntry> {
    (0..n)
        .map(|i| EutxoEntry {
            txid: h32(i as u64),
            vout: i % 4,
            value: 8_400_000_000u64.wrapping_add(i as u64),
            script_hash: h32(0xF000_0000 ^ i as u64),
        })
        .collect()
}

/// The non-eUTXO components, at roughly live Genesis-4 shape.
struct Fixture {
    validators: Vec<ValidatorRecord>,
    current: Vec<ParticipationRecord>,
    previous: Vec<ParticipationRecord>,
    randao: Vec<RandaoMix>,
    finality: FinalityRecord,
}

fn fixture() -> Fixture {
    let ck = |e: u64| CheckpointRecord { epoch: e, root: h32(0xC0DE + e) };
    Fixture {
        validators: (0..N_VALIDATORS)
            .map(|i| ValidatorRecord {
                index: i,
                // The real hybrid pubkey is ~3,745 B and the whole thing is
                // hashed into the leaf, so its length is part of the cost.
                pubkey: vec![(i % 251) as u8; 3_749],
                stake: 32_00000000,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                slashed: false,
                randao_commitment: h32(0x5A5A_0000 ^ i as u64),
                reveals_used: 100,
                withdrawable_epoch: u64::MAX,
                withdrawal_credentials: vec![0xAB; 32],
                commission_bps: 500,
            })
            .collect(),
        current: (0..N_VALIDATORS)
            .map(|i| ParticipationRecord { validator_index: i, attested: i % 3 != 0 })
            .collect(),
        previous: (0..N_VALIDATORS)
            .map(|i| ParticipationRecord { validator_index: i, attested: i % 5 != 0 })
            .collect(),
        randao: (0..3u64).map(|e| RandaoMix { epoch: 820 + e, mix: h32(0xA0 + e) }).collect(),
        finality: FinalityRecord {
            justified: (0..4u64).map(ck).collect(),
            current_justified: ck(822),
            previous_justified: ck(821),
            finalized: ck(821),
            leaked: Vec::new(),
            next_epoch: 823,
        },
    }
}

fn state<'a>(f: &'a Fixture, e: &'a [EutxoEntry]) -> ConsensusState<'a> {
    ConsensusState {
        eutxos: e,
        validators: &f.validators,
        current_participation: &f.current,
        previous_participation: &f.previous,
        randao_mixes: &f.randao,
        finality: &f.finality,
        pending_votes: &[],
        fc_messages: &[],
        fc_equivocators: &[],
        deposit_queue: &[],
        delegations: &[],
        pending_fees: &[],
        taint_root: h32(101),
        coherence_accumulator_root: h32(102),
        coherence_nullifier_root: h32(103),
        evm: EvmCommitment {
            account_root: h32(201),
            receipts_root: h32(202),
            gas_used: 0,
            base_fee_per_gas: 1,
        },
        issued_sat: 1_000_000_000_000_000,
        applied_evidence: &[],
        slash_window: &[],
        delegator_slash_losses: &[],
        base_fee: BaseFeeRecord {
            base_fee_millisat_per_gas: 1_000,
            gas_used: 0,
            tx_bytes: 0,
        },
        delegator_fee_rewards: &[],
        // Never frozen in a fixture: the roster-freeze gate is inert.
        frozen_bonds: &[],
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn header(title: &str) {
    println!("\n=== {title} ===");
    println!("cpu: {}", cpu());
}

fn cpu() -> String {
    std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Run `f` on a thread that has never computed a state root, and hand back
/// what it returns.
///
/// This is not decoration. `state_root.rs` keeps a THREAD-LOCAL two-generation
/// memo of singleton subtree roots; whichever of two builds runs second on the
/// same thread inherits the first's memo and is measured against a warm cache
/// the first never had. Any two figures that are printed side by side and
/// compared to each other must therefore come from two different fresh threads,
/// or the comparison prints the inverse of what it claims. That is not
/// hypothetical — it is the bug this file was corrected for on 2026-08-23, and
/// the identical bug is still live in
/// `bloch-pos-committee/src/state_root.rs::carryover_scale_incremental_cost`,
/// whose bulk and leaf-by-leaf builds share one thread.
fn cold_thread<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(256 << 20)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("measurement thread panicked")
}

/// The eUTXO leaf map at carryover scale. Rebuilt inside each measurement
/// thread rather than shared, so no thread borrows another's warm anything.
fn carryover_leaf_map() -> BTreeMap<[u8; 32], [u8; 32]> {
    eutxos(CARRYOVER_N).iter().map(eutxo_leaf).collect()
}

// ── 1. the breakdown at carryover scale ────────────────────────────────────

/// Every phase of a state root at n = 452,726, each phase on its own freshly
/// spawned thread.
///
/// # What changed on 2026-08-23, and why
///
/// This measurement used to run its whole breakdown on one thread and then
/// print `ratio (a) full rebuild / (d) incremental`. Both halves of that ratio
/// were wrong:
///
///   * the second build inherited the first's singleton memo, so whichever ran
///     second was timed against a cache it had not paid for, and
///   * `Smt::root()` is O(1) since `perf/smt` — it reads a field off the root
///     node. The old "root(), COLD memo" / "root(), WARM memo" pair was ported
///     from the era when `root()` walked the leaf set, and after the port it was
///     timing a struct field read and calling it a 51-second cold root.
///
/// Both are fixed below: every figure that is compared to another figure is
/// measured on its own cold thread, and the phases are named for what they now
/// actually do.
#[test]
#[ignore]
fn perf_state_root_breakdown() {
    header("state-root breakdown @ n = 452,726 (Genesis-4 carryover)");

    // (a) the whole from-scratch path a cold-started node pays: derive every
    //     leaf, bulk-build the eUTXO subtree, insert the other components.
    let (root_full, t_build_full, t_root_1, t_root_2, n_leaves) =
        cold_thread("full-rebuild", || {
            let f = fixture();
            let e = eutxos(CARRYOVER_N);
            let t = Instant::now();
            let tree = build_state_tree(&state(&f, &e));
            let t_build_full = t.elapsed();
            // `root()` twice. NOT a cold/warm memo pair — it is a field read,
            // and the two figures exist to show that it is.
            let t = Instant::now();
            let r1 = tree.root();
            let t_root_1 = t.elapsed();
            let t = Instant::now();
            let r2 = tree.root();
            let t_root_2 = t.elapsed();
            assert_eq!(r1, r2);
            (r1, t_build_full, t_root_1, t_root_2, tree.len())
        });

    // (b) and (c): the SAME eUTXO leaf set, built bulk and built leaf by leaf,
    //     on two DIFFERENT cold threads. This is the comparison the old code
    //     printed backwards.
    let (root_bulk, t_bulk) = cold_thread("bulk", || {
        let leaves = carryover_leaf_map();
        let t = Instant::now();
        let tree = Smt::from_leaf_map(&leaves);
        let d = t.elapsed();
        (tree.root(), d)
    });
    let (root_leafwise, t_leafwise) = cold_thread("leaf-by-leaf", || {
        let leaves = carryover_leaf_map();
        let t = Instant::now();
        let mut tree = Smt::new();
        for (k, v) in &leaves {
            tree.insert(*k, *v);
        }
        let d = t.elapsed();
        (tree.root(), d)
    });
    assert_eq!(root_bulk, root_leafwise, "bulk and leaf-by-leaf must commit the same tree");

    // (d) and (e): the steady state. A running node HOLDS the eUTXO tree, so
    //     the per-block cost is a clone plus the components plus the block's
    //     own edits — never a rebuild. Both are measured on one thread on
    //     purpose: (e) follows (d) in the same block loop on a real node, and
    //     the point of (e) is what the SECOND call costs, so its warmth is the
    //     thing being measured rather than a leak between two rivals.
    let (root_inc, t_incremental, t_after_edit, t_steady) = cold_thread("steady-state", || {
        let f = fixture();
        let empty: [EutxoEntry; 0] = [];
        let leaves = carryover_leaf_map();
        let tree = Smt::from_leaf_map(&leaves);

        let t = Instant::now();
        let root_inc = state_root_with_eutxo_tree(&state(&f, &empty), &tree);
        let t_incremental = t.elapsed();

        // A realistic block: 4 outputs spent, 4 created.
        let edit = |tree: &Smt, gen: u64| {
            let mut t2 = tree.clone();
            for k in leaves.keys().skip(gen as usize * 4).take(4) {
                t2.remove(k);
            }
            for i in 0..4u32 {
                let (k, v) = eutxo_leaf(&EutxoEntry {
                    txid: h32(0xDEAD_0000u64 + gen * 16 + i as u64),
                    vout: i,
                    value: 1_000,
                    script_hash: h32(0x5151 + i as u64),
                });
                t2.insert(k, v);
            }
            t2
        };

        let t2 = edit(&tree, 0);
        let t = Instant::now();
        let root_edited = state_root_with_eutxo_tree(&state(&f, &empty), &t2);
        let t_after_edit = t.elapsed();
        assert_ne!(root_edited, root_inc);

        // The same again, several blocks deep, for the figure a node in the
        // middle of a replay actually pays.
        const BLOCKS: u32 = 8;
        let t = Instant::now();
        let mut cur = t2;
        for g in 1..=BLOCKS {
            cur = edit(&cur, g as u64);
            std::hint::black_box(state_root_with_eutxo_tree(&state(&f, &empty), &cur));
        }
        let t_steady = t.elapsed() / BLOCKS;

        (root_inc, t_incremental, t_after_edit, t_steady)
    });
    assert_eq!(root_inc, root_full, "the two entry points must commit the same root");

    // (f) the leaf derivation (a) pays and the steady state does not: two SHA3
    //     per entry, over the whole set.
    let t_leaf_derivation = cold_thread("leaf-derivation", || {
        let e = eutxos(CARRYOVER_N);
        let t = Instant::now();
        let derived: Vec<([u8; 32], [u8; 32])> = e.iter().map(eutxo_leaf).collect();
        let d = t.elapsed();
        std::hint::black_box(&derived);
        d
    });

    println!(
        "  committed leaves: {} ({} eUTXO + {} other)",
        n_leaves,
        CARRYOVER_N,
        n_leaves as u32 - CARRYOVER_N
    );
    println!("  each phase below ran on its OWN freshly spawned thread (cold singleton memo)");
    println!();
    println!("  a) build_state_tree, full from-scratch          : {:>10.1} ms", ms(t_build_full));
    println!("  b) Smt::from_leaf_map, eUTXO only  [cold thread]: {:>10.1} ms", ms(t_bulk));
    println!("  c) Smt::insert x n, eUTXO only     [cold thread]: {:>10.1} ms", ms(t_leafwise));
    println!("  d) state_root_with_eutxo_tree, tree already held: {:>10.1} ms", ms(t_incremental));
    println!("  e) same, after 4 spends + 4 creates             : {:>10.1} ms", ms(t_after_edit));
    println!("  e') same, averaged over 8 consecutive blocks    : {:>10.1} ms", ms(t_steady));
    println!("  f)   of which (a) only: eutxo_leaf x n          : {:>10.1} ms", ms(t_leaf_derivation));
    println!();
    println!("  Smt::root() #1 (a field read, not a walk)       : {:>10.4} ms", ms(t_root_1));
    println!("  Smt::root() #2 (the same field read)            : {:>10.4} ms", ms(t_root_2));
    println!();
    println!(
        "  bulk vs leaf-by-leaf, both cold  (c / b)       : {:>10.2}x  \
         => leaf-by-leaf is {} for a cold load",
        t_leafwise.as_secs_f64() / t_bulk.as_secs_f64(),
        if t_leafwise > t_bulk { "SLOWER — the wrong tool" } else { "faster" }
    );
    println!(
        "  cold full rebuild (a) vs steady block (e')     : {:>10.1}x",
        t_build_full.as_secs_f64() / t_steady.as_secs_f64()
    );
    println!(
        "  full first root (a), what a cold start pays   : {:>10.1} ms",
        ms(t_build_full)
    );
    println!(
        "  steady-state per block (e')                   : {:>10.1} ms",
        ms(t_steady)
    );
}

// ── 2. how the full rebuild scales with leaf count ─────────────────────────

/// Cold-memo full rebuild at 50k / 100k / 200k / 452,726, each on its own
/// thread so no measurement inherits another's memo.
///
/// The `root ms` column is expected to be ~0: since `perf/smt` the root is a
/// field on the root node and `root()` reads it. It is kept, and not dropped,
/// because a column that stops being ~0 is the first sign that someone
/// reintroduced a walk.
#[test]
#[ignore]
fn perf_rebuild_scaling() {
    header("full rebuild (cold memo) vs leaf count");
    println!(
        "{:>10}  {:>12}  {:>12}  {:>12}  {:>10}  {:>10}",
        "n", "build ms", "root ms", "total ms", "us/leaf", "vs n=50k"
    );
    let mut base: Option<f64> = None;
    for n in [50_000u32, 100_000, 200_000, CARRYOVER_N] {
        let (b, r) = std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                let f = fixture();
                let e = eutxos(n);
                let t = Instant::now();
                let tree = build_state_tree(&state(&f, &e));
                let b = t.elapsed();
                let t = Instant::now();
                let root = tree.root();
                let r = t.elapsed();
                std::hint::black_box(root);
                (b, r)
            })
            .unwrap()
            .join()
            .unwrap();
        let total = ms(b) + ms(r);
        let rel = base.map(|x| total / x).unwrap_or(1.0);
        if base.is_none() {
            base = Some(total);
        }
        println!(
            "{n:>10}  {:>12.1}  {:>12.1}  {:>12.1}  {:>10.3}  {:>9.2}x",
            ms(b),
            ms(r),
            total,
            total * 1000.0 / n as f64,
            rel
        );
    }
    println!("  (O(n) ⇒ us/leaf flat; O(n log n) ⇒ us/leaf rises ~log n)");
}

// ── 3. the hybrid signature ────────────────────────────────────────────────

/// One ML-DSA-65 ‖ Falcon-1024 verify, and the per-block arithmetic that
/// follows from the committee params.
#[test]
#[ignore]
fn perf_hybrid_verify() {
    header("hybrid ML-DSA-65 || Falcon-1024 verify");
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    let msg = h32(0x51_6E);
    let sig = bloch_crypto::crypto::sign(&sk, &msg).expect("sign");
    println!("  pubkey bytes    : {}", pk.len());
    println!("  signature bytes : {}", sig.len());

    // warm-up
    for _ in 0..8 {
        assert!(bloch_crypto::crypto::verify(&pk, &msg, &sig));
    }

    const ITERS: u32 = 200;
    let t = Instant::now();
    for _ in 0..ITERS {
        std::hint::black_box(bloch_crypto::crypto::verify(&pk, &msg, &sig));
    }
    let per_verify = t.elapsed() / ITERS;

    // The ML-DSA half alone, on the raw bodies, so the Falcon share is
    // visible as (hybrid - mldsa).
    let (_, pk_body) = bloch_crypto::crypto::split_envelope(&pk).unwrap();
    let (_, sig_body) = bloch_crypto::crypto::split_envelope(&sig).unwrap();
    let mldsa_pk = &pk_body[..bloch_crypto::crypto::MLDSA_PUBKEY_LEN];
    let mldsa_sig = &sig_body[..bloch_crypto::crypto::MLDSA_SIG_LEN];
    assert!(bloch_crypto::crypto::verify_mldsa65_raw(mldsa_pk, &msg, mldsa_sig));
    let t = Instant::now();
    for _ in 0..ITERS {
        std::hint::black_box(bloch_crypto::crypto::verify_mldsa65_raw(mldsa_pk, &msg, mldsa_sig));
    }
    let per_mldsa = t.elapsed() / ITERS;

    // Sign, for contrast — replay never signs, but it frames the numbers.
    let t = Instant::now();
    for _ in 0..20 {
        std::hint::black_box(bloch_crypto::crypto::sign(&sk, &msg).unwrap());
    }
    let per_sign = t.elapsed() / 20;

    println!("  hybrid verify        : {:>8.3} ms", ms(per_verify));
    println!("    of which ML-DSA-65  : {:>8.3} ms", ms(per_mldsa));
    println!("    Falcon-1024 (by diff): {:>8.3} ms", ms(per_verify) - ms(per_mldsa));
    println!("  hybrid sign          : {:>8.3} ms", ms(per_sign));

    // Params: committee.rs COMMITTEE_SIZE = 128 (epoch boundary),
    // SLOT_SUBCOMMITTEE_SIZE = 8 (ordinary slot), SLOTS_PER_EPOCH = 32.
    let c = bloch_pos_committee::params::COMMITTEE_SIZE as f64;
    let s = bloch_pos_committee::params::SLOT_SUBCOMMITTEE_SIZE as f64;
    let spe = bloch_pos_committee::params::SLOTS_PER_EPOCH as f64;
    let v = ms(per_verify);
    let ordinary = 1.0 + s; // proposer + subcommittee
    let boundary = 1.0 + c; // proposer + full committee
    let avg = ((spe - 1.0) * ordinary + boundary) / spe;
    println!();
    println!("  COMMITTEE_SIZE={c}  SLOT_SUBCOMMITTEE_SIZE={s}  SLOTS_PER_EPOCH={spe}");
    println!("  ordinary block : {ordinary:>5} verifies = {:>8.1} ms", ordinary * v);
    println!("  boundary block : {boundary:>5} verifies = {:>8.1} ms", boundary * v);
    println!("  epoch average  : {avg:>5.2} verifies = {:>8.1} ms/block", avg * v);
}

// ── 4. the real CommittedState: the clone and the root the node actually runs ──

/// The two per-block costs on the real production type, not on a synthetic
/// tree: `pre.clone()` (transition.rs:2883, `let mut st = pre.clone();`) and
/// `StateReader::state_root` (→ `CommittedState::compute_root`, which is the
/// `state_root_with_eutxo_tree` path with the kept leaves).
#[test]
#[ignore]
fn perf_committed_state_per_block() {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(committed_state_per_block)
        .unwrap()
        .join()
        .unwrap();
}

fn committed_state_per_block() {
    use bloch_pos_committee::header::{BlockHeaderV4, BlockId};
    use bloch_pos_committee::interfaces::StateReader;
    use bloch_pos_committee::transition::{CommittedState, GenesisValidator};

    header("real CommittedState @ n = 452,726");

    let hdr = BlockHeaderV4 {
        version: 4,
        parent: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0u8; 32],
        randao_mix: [0u8; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    };
    let gid = BlockId::of(&hdr);
    let vals: Vec<GenesisValidator> = (0..N_VALIDATORS)
        .map(|i| GenesisValidator {
            index: i,
            pubkey: vec![(i % 251) as u8; 3_749],
            staked_sat: 32_00000000,
            randao_commitment: h32(0x5A5A_0000 ^ i as u64),
            withdrawal_credentials: vec![0xAB; 32],
            commission_bps: 500,
        })
        .collect();
    let opening = eutxos(CARRYOVER_N);

    let t = Instant::now();
    let st = CommittedState::genesis(
        gid,
        h32(7),
        &vals,
        &[],
        h32(101),
        h32(102),
        h32(103),
        EvmCommitment {
            account_root: h32(201),
            receipts_root: h32(202),
            gas_used: 0,
            base_fee_per_gas: 1,
        },
        &opening,
    );
    let t_genesis = t.elapsed();
    drop(opening);

    // (i) the clone every apply_block starts with.
    let mut clones = Vec::new();
    let t = Instant::now();
    for _ in 0..5 {
        clones.push(st.clone());
    }
    let t_clone = t.elapsed() / 5;
    drop(clones);

    // (ii) the first `state_root()` after genesis. NOT a cold memo: `genesis`
    //      built the whole eUTXO tree on this very thread, so every eUTXO
    //      singleton is already memoized. What is cold here is only the few
    //      hundred non-eUTXO component leaves this call inserts.
    let t = Instant::now();
    let r1 = st.state_root();
    let t_root_cold = t.elapsed();

    // (iii) the same call again — the steady-state cost when nothing changed.
    let t = Instant::now();
    let r2 = st.state_root();
    let t_root_warm = t.elapsed();
    assert_eq!(r1, r2);

    let t = Instant::now();
    let r3 = st.state_root();
    let t_root_warm2 = t.elapsed();
    assert_eq!(r1, r3);

    println!("  CommittedState::genesis(452,726 balances) : {:>10.1} ms", ms(t_genesis));
    println!("  i)   pre.clone() per apply_block          : {:>10.1} ms", ms(t_clone));
    println!("  ii)  StateReader::state_root, 1st call    : {:>10.1} ms", ms(t_root_cold));
    println!("  iii) StateReader::state_root, 2nd call    : {:>10.1} ms", ms(t_root_warm));
    println!("  iii) again                                : {:>10.1} ms", ms(t_root_warm2));
    println!(
        "  per-block floor (clone + warm root)       : {:>10.1} ms  => {:.2} blocks/s",
        ms(t_clone + t_root_warm2),
        1000.0 / ms(t_clone + t_root_warm2)
    );
}

// ── 5. what an incremental path update WOULD cost, and the steady-state loop ──

/// The 8-leaf edit, against the arithmetic floor for one.
///
/// PORTED 2026-08-23. This was written before `perf/smt` and measured a PRIZE:
/// back then `Smt::insert` only edited a leaf map and `root()` walked the whole
/// set, so `root()/path-update` was the factor an incremental tree would win.
/// That tree shipped. `insert` now rebuilds the path and folds it, and `root()`
/// is a field read — so the same two numbers are no longer a prize, they are
/// the DELIVERED cost against its theoretical floor. The labels say that now.
///   * (a) 8 `Smt::insert` calls: the real incremental path update.
///   * (b) the `root()` that follows: O(1), kept so the reader can see it is.
///   * (c)/(d) raw SHA3 at the same shapes: the floor (a) is measured against.
#[test]
#[ignore]
fn perf_incremental_path_vs_full_root() {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(incremental_path)
        .unwrap()
        .join()
        .unwrap();
}

fn incremental_path() {
    use sha3::{Digest, Sha3_256};

    header("8-leaf edit: the delivered path update vs its SHA3 floor");
    let f = fixture();
    let e = eutxos(CARRYOVER_N);
    let mut tree = build_state_tree(&state(&f, &e));
    let _ = tree.root(); // the build already warmed the memo; this is O(1)

    // (a) the edit itself: 8 leaves written through `insert`, each rebuilding
    //     and re-folding the path from the root to its leaf.
    let edits: Vec<([u8; 32], [u8; 32])> = (0..8u32)
        .map(|i| {
            eutxo_leaf(&EutxoEntry {
                txid: h32(0xBEEF_0000u64 + i as u64),
                vout: i,
                value: 1_000,
                script_hash: h32(0x7171 + i as u64),
            })
        })
        .collect();
    let t = Instant::now();
    for (k, v) in &edits {
        tree.insert(*k, *v);
    }
    let t_insert8 = t.elapsed();

    // (b) the root that follows it. O(1) since `perf/smt` — a field read off
    //     the root node, NOT the Theta(n) walk this line used to time.
    let t = Instant::now();
    std::hint::black_box(tree.root());
    let t_root = t.elapsed();

    // (c) the SHA3 work an ideal sparse-Merkle path update would do: for each
    //     changed leaf, one leaf_hash plus TREE_DEPTH(256) node hashes over
    //     65-byte inputs. Timed on raw sha3 with the same shapes, so this is a
    //     MEASURED lower bound on the arithmetic, not a guess at an
    //     implementation.
    const DEPTH: usize = 256;
    let mut buf = [0u8; 81];
    let t = Instant::now();
    let mut acc = [0u8; 32];
    for i in 0..edits.len() {
        acc = edits[i].1;
        for _ in 0..DEPTH {
            let mut h = Sha3_256::new();
            buf[0] = 1;
            buf[1..33].copy_from_slice(&acc);
            buf[33..65].copy_from_slice(&edits[i].0);
            h.update(&buf[..65]);
            acc = h.finalize().into();
        }
    }
    let t_path8 = t.elapsed();
    std::hint::black_box(acc);

    // The same, for a tree whose real depth is log2(n) ~ 19 (a compressed SMT
    // only walks to where the subtree stops being a singleton).
    let log_depth = (CARRYOVER_N as f64).log2().ceil() as usize;
    let t = Instant::now();
    for i in 0..edits.len() {
        acc = edits[i].1;
        for _ in 0..log_depth {
            let mut h = Sha3_256::new();
            buf[0] = 1;
            buf[1..33].copy_from_slice(&acc);
            buf[33..65].copy_from_slice(&edits[i].0);
            h.update(&buf[..65]);
            acc = h.finalize().into();
        }
    }
    let t_path8_log = t.elapsed();
    std::hint::black_box(acc);

    println!("  a) Smt::insert x8 (the real path update) : {:>12.4} ms", ms(t_insert8));
    println!("  b) Smt::root() after it (O(1) field read): {:>12.4} ms", ms(t_root));
    println!("  c) floor: 8 leaves x 256 node hashes     : {:>12.4} ms", ms(t_path8));
    println!("  d) floor: 8 leaves x {log_depth} node hashes       : {:>12.4} ms", ms(t_path8_log));
    println!(
        "  delivered / full-depth floor  (a / c)   : {:>12.2}x",
        ms(t_insert8) / ms(t_path8)
    );
    println!(
        "  delivered / compressed floor  (a / d)   : {:>12.2}x",
        ms(t_insert8) / ms(t_path8_log)
    );
}

/// A loop of warm `state_root()` calls on the real `CommittedState`, long
/// enough to attach macOS `sample` to. Nothing is printed but a rate; the
/// point is the profile.
#[test]
#[ignore]
fn perf_steady_state_loop() {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(steady_loop)
        .unwrap()
        .join()
        .unwrap();
}

fn steady_loop() {
    use bloch_pos_committee::header::{BlockHeaderV4, BlockId};
    use bloch_pos_committee::interfaces::StateReader;
    use bloch_pos_committee::transition::{CommittedState, GenesisValidator};

    header("steady-state warm-root loop (attach `sample` to this pid)");
    println!("  pid: {}", std::process::id());

    let hdr = BlockHeaderV4 {
        version: 4,
        parent: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0u8; 32],
        randao_mix: [0u8; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    };
    let vals: Vec<GenesisValidator> = (0..N_VALIDATORS)
        .map(|i| GenesisValidator {
            index: i,
            pubkey: vec![(i % 251) as u8; 3_749],
            staked_sat: 32_00000000,
            randao_commitment: h32(0x5A5A_0000 ^ i as u64),
            withdrawal_credentials: vec![0xAB; 32],
            commission_bps: 500,
        })
        .collect();
    let st = CommittedState::genesis(
        BlockId::of(&hdr),
        h32(7),
        &vals,
        &[],
        h32(101),
        h32(102),
        h32(103),
        EvmCommitment {
            account_root: h32(201),
            receipts_root: h32(202),
            gas_used: 0,
            base_fee_per_gas: 1,
        },
        &eutxos(CARRYOVER_N),
    );
    let _ = st.state_root(); // pay the cold-memo cost outside the loop
    println!("  memo warm, starting the loop now");
    const N: u32 = 25;
    let t = Instant::now();
    for _ in 0..N {
        // clone + root: exactly what one replayed block pays before it has
        // executed a single transaction.
        let c = st.clone();
        std::hint::black_box(c.state_root());
    }
    let d = t.elapsed() / N;
    println!("  clone + warm state_root : {:>8.1} ms  => {:.2} blocks/s", ms(d), 1000.0 / ms(d));
}
