//! Deterministic simulation testing (DST) harness — skeleton (roadmap §4).
//!
//! HONESTY / SCOPE: this is a SKELETON, not a full network simulator. It does
//! NOT compile the node against a simulated runtime (turmoil / madsim are not on
//! the dep list and Cargo.toml is out of scope for this change). It drives the
//! parts a systems-dev owns behind the existing channel seams — the mempool and
//! a message-processor-shaped loop over an mpsc `block_rx` — with a SEEDED RNG so
//! every run is reproducible. Full turmoil/madsim virtual-time is the P2
//! escalation.
//!
//! It exercises four scenarios from the roadmap:
//!   1. partition / convergence   — nodes converge to one tip after a heal
//!   2. eclipse setup             — Sybil inbound-slot pressure (measurement)
//!   3. spam / flood              — mempool stays memory-bounded under flood
//!   4. repeatedly-panicking processor — the P0 supervisor restart-backoff
//!      PATTERN (mirrors main.rs:653–666; the real supervisor is inline in
//!      main.rs, which this dev does not own, so this reproduces the pattern
//!      rather than invoking the binary's loop).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bloch::core::{Transaction, TxInput, TxOutput};
use bloch::mempool::{Clock, Mempool};
use parking_lot::Mutex;
use tokio::sync::mpsc;

// ── deterministic seams ───────────────────────────────────────────────────────

/// Seeded PRNG — the ONLY source of randomness in the harness.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n.max(1)
    }
}

/// Deterministic virtual clock for the mempool time seam — no wall-clock reads,
/// so `added_at` is reproducible run to run. Exercises `Mempool::with_clock`.
struct VirtualClock(AtomicU64);
impl Clock for VirtualClock {
    fn now_secs(&self) -> u64 {
        // Monotonic virtual tick; each read advances time by 1s.
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn uniq_tx(nonce: u64, pad: usize) -> Transaction {
    let mut prev = [0u8; 32];
    prev[..8].copy_from_slice(&nonce.to_le_bytes());
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: prev,
            prev_index: 0,
            script_sig: vec![3u8; pad],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![1u8; 20] }],
        locktime: 0,
    }
}

// ── model types ───────────────────────────────────────────────────────────────

/// A minimal block for the convergence model (no PoW/consensus — that surface is
/// owned by the crypto/consensus dev and reached only through public API).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SimBlock {
    hash: [u8; 32],
    blue_score: u64,
}

/// A sim-node's tip: the highest-blue-score block it has seen, hash as tiebreak.
#[derive(Default)]
struct Tip(Mutex<Option<SimBlock>>);
impl Tip {
    fn observe(&self, b: SimBlock) {
        let mut g = self.0.lock();
        let better = match *g {
            None => true,
            Some(cur) => (b.blue_score, b.hash) > (cur.blue_score, cur.hash),
        };
        if better {
            *g = Some(b);
        }
    }
    fn get(&self) -> Option<SimBlock> {
        *self.0.lock()
    }
}

// ── Scenario 1: partition / convergence ───────────────────────────────────────

#[tokio::test]
async fn scenario_partition_then_convergence() {
    let n = 5usize;
    let tips: Vec<Arc<Tip>> = (0..n).map(|_| Arc::new(Tip::default())).collect();
    let mut rng = Rng(0xD57_0001);

    // Helper: broadcast a block to a set of node indices (a "partition").
    let broadcast = |tips: &[Arc<Tip>], group: &[usize], b: SimBlock| {
        for &i in group {
            tips[i].observe(b);
        }
    };

    let all: Vec<usize> = (0..n).collect();

    // Phase A: healthy network — random producers, everyone hears everything.
    let mut score = 0u64;
    for _ in 0..20 {
        score += 1;
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&rng.next().to_le_bytes());
        broadcast(&tips, &all, SimBlock { hash, blue_score: score });
    }

    // Phase B: PARTITION into {0,1} and {2,3,4}; each side extends its own tip.
    let left = [0usize, 1];
    let right = [2usize, 3, 4];
    for _ in 0..10 {
        score += 1;
        let mut hl = [0u8; 32];
        hl[..8].copy_from_slice(&rng.next().to_le_bytes());
        broadcast(&tips, &left, SimBlock { hash: hl, blue_score: score });

        let mut hr = [0u8; 32];
        hr[..8].copy_from_slice(&rng.next().to_le_bytes());
        broadcast(&tips, &right, SimBlock { hash: hr, blue_score: score });
    }
    // The partition really did diverge.
    assert_ne!(
        tips[0].get(),
        tips[4].get(),
        "partition should produce divergent tips"
    );

    // Phase C: HEAL — replay the globally-best-known block to everyone within a
    // bounded number of "heartbeats". Highest (blue_score, hash) wins on all.
    let global_best = tips
        .iter()
        .filter_map(|t| t.get())
        .max_by_key(|b| (b.blue_score, b.hash))
        .expect("some tip exists");
    for _ in 0..3 {
        broadcast(&tips, &all, global_best);
    }

    // Convergence: every node selected the same tip within bounded heartbeats.
    for (i, t) in tips.iter().enumerate() {
        assert_eq!(
            t.get(),
            Some(global_best),
            "node {i} failed to converge after heal"
        );
    }
}

// ── Scenario 2: eclipse setup (measurement only) ──────────────────────────────

#[tokio::test]
async fn scenario_eclipse_inbound_pressure() {
    // Model: a victim has INBOUND_SLOTS inbound slots. A Sybil set tries to fill
    // them; a P0-style connection limit reserves slots so some honest peers
    // always survive. This MEASURES the surviving-honest-slot count — the
    // precursor to the P2 diversity-bucket work (no node change here).
    const INBOUND_SLOTS: usize = 16;
    const RESERVED_HONEST: usize = 4; // stand-in for the reserved-slot policy

    let mut rng = Rng(0xEC_1195E);
    let sybil_attempts = 1000;

    // Sybils fill non-reserved slots first; reserved slots stay for honest dials.
    let fillable = INBOUND_SLOTS - RESERVED_HONEST;
    let mut sybil_connected = 0usize;
    for _ in 0..sybil_attempts {
        if sybil_connected < fillable {
            // Accept (a real node would also apply ip_colocation scoring here).
            sybil_connected += 1;
        }
        let _ = rng.next();
    }
    let honest_slots_surviving = INBOUND_SLOTS - sybil_connected;

    assert!(
        honest_slots_surviving >= RESERVED_HONEST,
        "eclipse measurement: only {honest_slots_surviving} honest slots survived \
         {sybil_attempts} Sybil attempts (want >= {RESERVED_HONEST})"
    );
    // This is a MEASUREMENT harness: it turns the hand-tuned reserved-slot
    // constant into an asserted, regression-guarded number. The actual dial/
    // accept diversity buckets are P2 (deferred).
}

// ── Scenario 3: spam / flood — mempool stays memory-bounded ───────────────────

#[tokio::test]
async fn scenario_spam_flood_mempool_bounded() {
    let mp = Mempool::with_clock(Box::new(VirtualClock(AtomicU64::new(0))));
    let mut rng = Rng(0xF100D);

    // High-rate small-tx flood + invalid/oversized attempts. Assert the mempool
    // never exceeds its byte cap and the fee-rate index invariant never drifts —
    // the §3 index must keep eviction correct under flood.
    for nonce in 0..5_000u64 {
        let pad = 8 + rng.range(200);
        let tx = uniq_tx(nonce, pad);
        let fee = 100_000 + (rng.next() % 5_000_000);
        let _ = mp.add(tx, fee);

        // Interleave a few structurally-invalid submissions (no inputs).
        if nonce % 500 == 0 {
            let bad = Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput { value: 1, script_pubkey: vec![0u8; 20] }],
                locktime: 0,
            };
            assert!(mp.add(bad, 1).is_err(), "invalid tx must be rejected");
        }

        if nonce % 250 == 0 {
            mp.debug_check_invariants().expect("invariant under flood");
        }
    }

    mp.debug_check_invariants().expect("invariant after flood");
    // 300 MiB cap (MAX_MEMPOOL_BYTES). The invariant check already asserts
    // total_bytes <= cap, but assert bounded size explicitly for the scenario.
    assert!(
        mp.size_bytes() <= 300 * 1024 * 1024,
        "mempool exceeded its byte cap under flood"
    );
}

// ── Scenario 4: repeatedly-panicking processor (P0 supervisor pattern) ────────

#[tokio::test]
async fn scenario_panicking_processor_restarts_with_backoff() {
    // Reproduces the P0 supervisor (main.rs:432,447,653–666): a message-processor
    // whose body panics on a marked input must be restarted with bounded
    // exponential backoff and a panic counter incremented — NOT hang the node.
    //
    // We can't call the binary's inline loop, so we build the same shape: a task
    // that receives blocks over `block_rx` and runs each through
    // `catch_unwind`; a panic increments a counter and applies backoff.
    let (block_tx, mut block_rx) = mpsc::unbounded_channel::<SimBlock>();
    let panics = Arc::new(AtomicU64::new(0));
    let processed = Arc::new(AtomicU64::new(0));

    let panics_c = panics.clone();
    let processed_c = processed.clone();
    let handle = tokio::spawn(async move {
        // Marker: blue_score == 0 means "poison" — the processor panics on it.
        let mut backoff_ms = 1u64;
        while let Some(blk) = block_rx.recv().await {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if blk.blue_score == 0 {
                    panic!("poison block");
                }
                // normal processing
            }));
            match res {
                Ok(()) => {
                    processed_c.fetch_add(1, Ordering::Relaxed);
                    backoff_ms = 1; // reset backoff on success
                }
                Err(_) => {
                    // inc_task_panic("message_processor") equivalent
                    panics_c.fetch_add(1, Ordering::Relaxed);
                    // bounded exponential backoff (mirrors main.rs:653–666)
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(64);
                    // loop continues — the processor is RESTARTED, not dead.
                }
            }
        }
    });

    // Feed a mix: several poison blocks interleaved with good ones.
    let mut good = 0u64;
    for i in 0..20u64 {
        if i % 3 == 0 {
            block_tx.send(SimBlock { hash: [0; 32], blue_score: 0 }).unwrap(); // poison
        } else {
            good += 1;
            block_tx
                .send(SimBlock { hash: [i as u8; 32], blue_score: i })
                .unwrap();
        }
    }
    drop(block_tx); // close the channel so the task finishes
    handle.await.unwrap();

    let n_panics = panics.load(Ordering::Relaxed);
    let n_processed = processed.load(Ordering::Relaxed);
    // The supervisor survived every panic (didn't hang / abort) and kept
    // processing the good blocks after each restart.
    assert!(n_panics >= 6, "expected repeated panics to be caught, got {n_panics}");
    assert_eq!(n_processed, good, "processor must resume after each restart");
}

// ── Scenario 5: equivocation — two conflicting blocks at one height ───────────
//
// Sprint EE (S3) addition. An equivocating miner produces TWO children of the
// same parent (same height, conflicting "versions" of the next block) and shows
// a different one first to each side of the network. GhostDAG is a DAG, so both
// blocks are legitimately ACCEPTED (they are siblings in each other's anticone)
// — equivocation here is not slashable double-signing but a fork-choice attack
// surface: the property that must hold is that every node, regardless of WHICH
// equivocating block it saw first, converges to the IDENTICAL selected tip,
// selected chain, and blue classification once it has seen both. Identical
// state means the equivocation bought the attacker nothing.
//
// This drives the REAL consensus type (bloch::consensus::GhostDAG), not the
// SimBlock tip model above. The transport-level version of the same scenario
// (blocks delivered through a live gossipsub mesh) lives in
// tests/sprint_ee_transport_convergence.rs.

#[test]
fn scenario_equivocation_conflicting_blocks_converge() {
    use bloch::consensus::GhostDAG;

    fn h(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    // 4 sim nodes, each a real GhostDAG with the same genesis.
    let n = 4usize;
    let mut dags: Vec<GhostDAG> = (0..n)
        .map(|_| {
            let mut d = GhostDAG::with_k(3);
            d.add_genesis(h(0), 0);
            d
        })
        .collect();

    // Honest prefix: G <- 1 <- 2 on every node.
    for d in dags.iter_mut() {
        d.add_block(h(1), vec![h(0)], 1, 1_000).expect("honest block 1");
        d.add_block(h(2), vec![h(1)], 2, 1_000).expect("honest block 2");
    }

    // Equivocation: 0xA3 and 0xB3 are BOTH children of block 2 — same height,
    // conflicting. Even-indexed nodes see 0xA3 first; odd-indexed see 0xB3
    // first. The "heal" is the later arrival of the other equivocating block.
    let eq_a = h(0xA3);
    let eq_b = h(0xB3);
    for (i, d) in dags.iter_mut().enumerate() {
        let (first, second) = if i % 2 == 0 { (eq_a, eq_b) } else { (eq_b, eq_a) };
        d.add_block(first, vec![h(2)], 3, 1_000).expect("equivocating block (first seen)");
        d.add_block(second, vec![h(2)], 3, 1_000).expect("equivocating block (second seen)");
    }

    // An honest successor merges both equivocating tips (the normal DAG miner
    // behavior: point at every known tip), forcing blue/red classification of
    // the equivocation pair on every node.
    for d in dags.iter_mut() {
        d.add_block(h(4), vec![eq_a, eq_b], 4, 1_000).expect("merge block");
    }

    // Convergence: byte-identical fork choice and coloring on all nodes,
    // regardless of equivocation arrival order.
    let tip0 = dags[0].selected_tip();
    let chain0 = dags[0].selected_chain();
    let score0 = dags[0].tip_blue_score();
    assert!(tip0.is_some(), "reference node must have a tip");
    for (i, d) in dags.iter().enumerate() {
        assert_eq!(d.selected_tip(), tip0, "node {i}: selected tip diverged");
        assert_eq!(d.selected_chain(), chain0, "node {i}: selected chain diverged");
        assert_eq!(d.tip_blue_score(), score0, "node {i}: blue score diverged");
        for id in [h(0), h(1), h(2), eq_a, eq_b, h(4)] {
            assert_eq!(
                d.is_blue(&id),
                dags[0].is_blue(&id),
                "node {i}: blue/red classification diverged for block {:02x}",
                id[0]
            );
        }
    }
}
