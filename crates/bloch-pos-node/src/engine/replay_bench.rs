// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The end-to-end replay benchmark.** Instrumentation only: `#[ignore]`d,
//! asserts no consensus property, changes no consensus behaviour.
//!
//! # What it measures, and why it is not the microbenchmark
//!
//! `tests/replay_hotpath_perf.rs` times individual functions —
//! `state_root_with_eutxo_leaves`, `CommittedState::clone`, one hybrid verify.
//! Those numbers say what a *function* costs. They cannot say what a *block*
//! costs, because a replayed block is a whole engine step: an ingest, a
//! fork-choice head computation (twice), a state clone, an epoch roll when the
//! slot happens to sit on a boundary, the transition, and the root. Four
//! people are optimising pieces of that; this file is how the sum is checked.
//!
//! So this drives the **real** node path:
//!
//! ```text
//!   Engine::ingest                engine.rs:691   <- the entry point boot replay uses
//!     +- Engine::advance          engine.rs:795
//!         +- Engine::forkchoice_head    engine.rs:743   (2x per block)
//!         +- Engine::path_to_canonical  engine.rs:760
//!         +- Engine::apply_canonical    engine.rs:912
//!             +- Transition::apply_block   transition.rs:3112
//!                 +- compute_post_state    transition.rs:2816  (clone, epoch roll, txs)
//!                 +- compute_root          transition.rs:1480  (the state root)
//! ```
//!
//! and it drives it through the same loop `run()` executes at boot
//! (`for (i, env) in logged.into_iter().enumerate() { engine.ingest(env); .. }`,
//! engine.rs ~1700) with `live = false` — which is exactly what a restarting
//! node runs.
//!
//! # Why this lives in `src/engine/` under `cfg(test)`
//!
//! `Engine` and every one of its fields are private to `engine`, and
//! `bloch-pos-node` has no `[lib]` target — only a `[[bin]]`. An integration
//! test in `tests/` therefore cannot reach `ingest` at all, and the only
//! alternative is to reimplement the replay loop against the public committee
//! API. That would measure the reimplementation: no `forkchoice_head`, no
//! `advance` retry loop, no `path_to_canonical` — three of the costs under
//! investigation. A CHILD module of `engine` sees its parent's private items,
//! so this file drives the real thing and **nothing in production code had to
//! be made more visible for it**. It costs one `#[cfg(test)] mod` line in
//! `engine.rs` and nothing in the shipped binary.
//!
//! # Running it
//!
//! ```text
//! cargo test --release -p bloch-pos-node --features perf-timing \
//!     --bin bloch-pos replay_bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Without `--features perf-timing` the same test runs and reports wall time
//! with an empty breakdown — which is the control that shows the timers are
//! not paying for themselves.
//!
//! Knobs (all optional, all read from the environment so a comparison run
//! needs no recompile):
//!
//! | var | default | meaning |
//! |---|---|---|
//! | `BLOCH_BENCH_BLOCKS` | 128 | blocks in the synthetic chain |
//! | `BLOCH_BENCH_RUNS` | 5 | full replays, for the median |
//! | `BLOCH_BENCH_CARRYOVER` | 452726 | opening eUTXO set size |
//! | `BLOCH_BENCH_DEPTH` | 12200 | chain depth used for the extrapolation |
//!
//! # The memo, and why every run gets a fresh thread
//!
//! `state_root.rs` keeps a **thread-local** two-generation memo of singleton
//! subtree roots. Its warmth dominates every state-root number, so a replay
//! that ran after the chain generator on the same thread would inherit a warm
//! memo and under-report. Generation and each replay run therefore get their
//! own freshly spawned thread — a replay run starts as cold as a node that
//! just booted.
//!
//! # What this fixture is NOT
//!
//! Stated up front, because a benchmark that oversells its realism is worse
//! than none:
//!
//! * The chain runs from slot 1, so its epochs are 0.. and it is **before**
//!   `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` (800) and
//!   `BLOCK_BYTES_V2_ACTIVATION_EPOCH` (800). Transfers are therefore the V1
//!   shape (one witness per input) and the byte cap is the V1 cap. The live
//!   chain is past both. The difference is signature-verification count and
//!   encoding size, and hybrid verification was measured at 0.06% of replay —
//!   so this shifts the total by far less than the run-to-run spread. It does
//!   NOT change the state-root, clone, fork-choice or epoch-boundary costs,
//!   which are what the work is about.
//! * There are no reorgs. `do_reorg` is instrumented and reported, but a
//!   linear synthetic chain never triggers it, so its measured cost here is
//!   zero and the `do_reorg` finding stays a separate claim.
//! * The attestation load is what a 64-validator set produces under this
//!   crate's own committee sampling, not a capture of live traffic.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::beacon::{mix_in, RandaoChain};
use bloch_pos_committee::gossip::AttestationPool;
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, BlockId, Body, VERSION_G4};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader, StateTransition};
use bloch_pos_committee::perf;
use bloch_pos_committee::schedule::first_slot_of_epoch;
use bloch_pos_committee::state_root::EutxoEntry;
use bloch_pos_committee::transition::{
    CommittedState, PosTransaction, TransferInput, TransferOutput, Transition,
};
use bloch_pos_committee::{committees, derive, epoch_of, fee_market, schedule};

use sha3::{Digest, Sha3_256};

use super::{now_ms, Engine, StateCell};
use crate::genesis::{Manifest, ManifestValidator, GENESIS_MIX};
use crate::keys::{HybridVerifier, Keystore, ProbeVerifier};
use crate::net;
use crate::store::Store;

// ── knobs ───────────────────────────────────────────────────────────────────

/// Genesis-4's measured carryover size — the opening ledger the live chain
/// runs on, and the number the engine's own replay comment cites.
const CARRYOVER_N: u32 = 452_726;
/// Roughly the live Genesis-4 validator set (12 classic + 49 Fly).
const N_VALIDATORS: u32 = 64;
/// The live per-block transaction shape, as measured: a handful in, a handful
/// out.
const SPENDS_PER_BLOCK: usize = 4;
const CREATES_PER_BLOCK: usize = 4;
/// Chain depth used for the extrapolation. The default is the figure the
/// engine's own replay comment states for the live chain ("a 12,200-block
/// chain is hours"); override it rather than trusting it.
const DEFAULT_DEPTH: u64 = 12_200;

/// `SLOT_DURATION_SECS` x `SLOTS_PER_EPOCH` — one epoch of wall clock.
/// Derived from the params, not written down, so a params change moves it.
const EPOCH_SECS: f64 =
    (bloch_pos_committee::params::SLOT_DURATION_SECS * bloch_pos_committee::SLOTS_PER_EPOCH) as f64;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
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

/// splitmix64-expanded filler, byte-identical to the microbenchmark's, so the
/// two harnesses build the same shape of opening ledger.
fn h32(seed: u64) -> [u8; 32] {
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

/// The opening ledger: `n` carryover outputs, of which the first `owned` are
/// locked to `owner_script` so the benchmark has something to spend.
fn eutxos(n: u32, owned: u32, owner_script: [u8; 32]) -> Vec<EutxoEntry> {
    (0..n)
        .map(|i| EutxoEntry {
            txid: h32(i as u64),
            vout: i % 4,
            value: 8_400_000_000u64.wrapping_add(i as u64),
            script_hash: if i < owned { owner_script } else { h32(0xF000_0000 ^ i as u64) },
        })
        .collect()
}

/// A manifest is deliberately not `Clone` — a consensus artifact with a
/// convenience copy constructor is how two nodes end up on two networks. The
/// benchmark needs one per replay run, so it rebuilds it field by field here
/// rather than deriving `Clone` on a production type for a test's sake.
fn clone_manifest(m: &Manifest) -> Manifest {
    Manifest {
        genesis_time_ms: m.genesis_time_ms,
        slot_ms: m.slot_ms,
        validators: m.validators.clone(),
        cohort: m.cohort.clone(),
        carryover: m.carryover.clone(),
        allocations: m.allocations.clone(),
        carryover_entries: m.carryover_entries.clone(),
    }
}

// ── the chain generator ─────────────────────────────────────────────────────

/// One spendable output the benchmark's wallet holds.
#[derive(Clone, Copy)]
struct Coin {
    txid: [u8; 32],
    vout: u32,
    value: u64,
}

/// Builds a synthetic-but-valid Genesis-4 chain: real headers, real hybrid
/// proposer signatures, real committee-sampled attestations, real transfers
/// moving real coins out of the carryover set.
///
/// Every block it emits has already passed `Transition::apply_block` under the
/// real hybrid verifier, on the same state a replaying validator will apply it
/// to. So replay measures validation of a *valid* chain — which is what boot
/// replay is — and a fixture bug cannot quietly turn the benchmark into a
/// measurement of the rejection path.
struct Generator {
    manifest: Manifest,
    tr: Transition<HybridVerifier>,
    probe: Transition<ProbeVerifier>,
    keys: Vec<Keystore>,
    state: CommittedState,
    /// Canonical chain, ascending slot, genesis first — the same shape
    /// `Engine::chain` holds.
    chain: Vec<(u64, BlockId)>,
    /// Canonical proposals per validator, for RANDAO positioning. Same rule as
    /// `Engine::randao_positioned`.
    proposals: Vec<u32>,
    /// The wallet's unspent outputs.
    coins: Vec<Coin>,
    spender_pk: Vec<u8>,
    spender_sk: Vec<u8>,
    /// The length `tx_bytes` is declared against: the hybrid signature's
    /// **upper bound**, not the length of any particular signature.
    ///
    /// Falcon-1024's half is variable (~1,250 to 1,462 B), so two signatures
    /// over two different roots differ in length — and `tx_bytes` sits inside
    /// the signing root, so it has to be fixed before the signature exists.
    /// Declaring against one sampled length made every transfer valid until a
    /// slightly longer signature turned up and the transition refused it as
    /// `UnderdeclaredSize` (observed at slot 12). Declaring against the bound
    /// is correct for every signature; over-declaring only buys more gas, and
    /// the fee is computed from the same declared number.
    sig_len: usize,
    /// Percentage of each slot's committee that actually attests.
    ///
    /// The knob that decides which REGIME the chain replays in, and it is the
    /// whole point of the depth experiment. Fork choice walks from the
    /// **justified** checkpoint, so:
    ///
    /// * at 100, justification advances and the walk is bounded by the
    ///   unfinalized suffix — a couple of epochs, whatever the chain's total
    ///   depth;
    /// * below the 2/3 justification threshold, nothing ever justifies and
    ///   the walk starts at genesis, so the walk spans the whole chain depth.
    ///
    /// The second bullet used to say `forkchoice_head` becomes O(V.D^2) there.
    /// That was true when this harness was written and is NOT true now:
    /// perf/fork rebuilt LMD-GHOST as a bottom-up pass, O(V+N+D). The walk
    /// still spans the whole depth when nothing justifies — that part stands —
    /// but it costs a linear pass over it, not a quadratic one. MEASURED on
    /// the integrated tree: across depths 1..192 the fork-choice column runs
    /// 0.0-0.2 ms/block and grows 7.44x while depth grows 8x, which is linear
    /// to within the noise of a 0.1 ms measurement.
    ///
    /// The live fleet has spent time in the second regime (params.rs, measured
    /// 2026-08-21: seven live validators holding 6.19% of unleaked stake), so
    /// it is not a synthetic worst case — it is the case the 2 h replay
    /// observation most plausibly comes from.
    participation_pct: u32,
}

impl Generator {
    fn new(dir: &Path, carryover_n: u32, participation_pct: u32) -> Generator {
        let (spender_pk, spender_sk) = bloch_crypto::crypto::generate_keypair();
        let owner_script: [u8; 32] = Sha3_256::digest(&spender_pk).into();
        // 4 (suite header) + 3,309 (ML-DSA-65) + 1,462 (Falcon-1024 maximum) —
        // `bloch_crypto::core::SIG_SIZE`. Asserted against the real signature
        // below, so a suite change breaks loudly instead of silently
        // under-declaring.
        let sig_len = 4_775;
        let sample = bloch_crypto::crypto::sign(&spender_sk, &[0u8; 32]).expect("sign").len();
        assert!(
            sample <= sig_len,
            "hybrid signature is {sample} B, above the {sig_len} B bound this fixture \
             declares tx_bytes against"
        );

        // 64 real hybrid keypairs. Slow (Falcon-1024 keygen), paid once, and
        // outside every measured region.
        let keys: Vec<Keystore> = (0..N_VALIDATORS)
            .map(|i| Keystore::generate(&dir.join(format!("v{i}")), i).expect("keystore"))
            .collect();

        let validators: Vec<ManifestValidator> = keys
            .iter()
            .map(|k| ManifestValidator {
                index: k.index,
                stake_sat: 32_00000000,
                randao_commitment: RandaoChain::generate(k.randao_seed).commitment(),
                pubkey: k.pubkey.clone(),
                withdrawal_credentials: vec![0xAB; 32],
                commission_bps: 500,
            })
            .collect();

        // The wallet owns a slice of the opening ledger; the rest is inert
        // weight, which is precisely its role on the live chain too.
        let owned = 16_384.min(carryover_n);
        let manifest = Manifest {
            genesis_time_ms: 0,
            slot_ms: 30_000,
            validators,
            cohort: Vec::new(),
            // `None`, so `opening_balances` does not demand an ingested
            // snapshot file. The entries below are the same entries a snapshot
            // would have produced.
            carryover: None,
            allocations: Vec::new(),
            carryover_entries: eutxos(carryover_n, owned, owner_script),
        };
        let coins: Vec<Coin> = manifest.carryover_entries[..owned as usize]
            .iter()
            .map(|e| Coin { txid: e.txid, vout: e.vout, value: e.value })
            .collect();

        let verifier = HybridVerifier::new(manifest.pubkeys());
        let state = manifest.genesis_state();
        let genesis_id = manifest.genesis_id();
        Generator {
            tr: Transition::new(verifier),
            probe: Transition::new(ProbeVerifier),
            keys,
            state,
            chain: vec![(0, genesis_id)],
            proposals: vec![0; N_VALIDATORS as usize],
            coins,
            spender_pk,
            spender_sk,
            sig_len,
            participation_pct,
            manifest,
        }
    }

    /// `Engine::rolled_to`, reproduced — the duty view must be derived exactly
    /// as the node derives it, or the blocks this generator emits would be
    /// rejected by the very path they are meant to feed.
    fn rolled_to(&self, epoch: u64) -> CommittedState {
        let mut st = self.state.clone();
        let mut cur = epoch_of(st.slot());
        while cur < epoch {
            st = self.tr.process_epoch(&st).expect("process_epoch is infallible");
            cur += 1;
        }
        st
    }

    /// `Engine::seed_for`, reproduced.
    fn seed_for(rolled: &CommittedState, epoch: u64) -> [u8; 32] {
        if epoch == 0 {
            GENESIS_MIX
        } else {
            rolled.randao_mix_at(epoch - 1).unwrap_or(GENESIS_MIX)
        }
    }

    /// `Engine::checkpoint_root`, reproduced.
    fn checkpoint_root(&self, epoch: u64) -> [u8; 32] {
        let first = first_slot_of_epoch(epoch).unwrap_or(u64::MAX);
        let mut root = *self.chain[0].1.as_bytes();
        for (slot, id) in &self.chain {
            if *slot >= first {
                break;
            }
            root = *id.as_bytes();
        }
        root
    }

    /// One transfer spending `SPENDS_PER_BLOCK` of the wallet's coins and
    /// creating `CREATES_PER_BLOCK` outputs, priced at exactly the fee this
    /// block's committed base fee implies.
    ///
    /// Returns `None` when the wallet cannot fund one — the caller then emits
    /// an empty block rather than an invalid one.
    fn transfer(&mut self, block_epoch: u64) -> Option<PosTransaction> {
        if self.coins.len() < SPENDS_PER_BLOCK {
            return None;
        }
        let spent: Vec<Coin> = self.coins.drain(..SPENDS_PER_BLOCK).collect();
        let spent_value: u128 = spent.iter().map(|c| c.value as u128).sum();
        let owner_script: [u8; 32] = Sha3_256::digest(&self.spender_pk).into();

        // Shape first, with placeholder witnesses of the RIGHT LENGTH: the
        // canonical encoding's size is what `tx_bytes` must cover, every field
        // in it is fixed-width, and `tx_bytes` is itself inside the signing
        // root — so the length has to be known before the signature is.
        let inputs: Vec<TransferInput> = spent
            .iter()
            .map(|c| TransferInput {
                txid: c.txid,
                vout: c.vout,
                pubkey: self.spender_pk.clone(),
                signature: vec![0u8; self.sig_len],
            })
            .collect();
        let mut outputs: Vec<TransferOutput> = (0..CREATES_PER_BLOCK)
            .map(|_| TransferOutput { value: 0, script_hash: owner_script })
            .collect();
        let shape = PosTransaction::Transfer {
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        let tx_bytes = shape.canonical_bytes().len() as u64;

        // The fee, from the same call the transition charges with, at the same
        // price: `pre.next_base_fee_at(block_epoch)`.
        let base_fee = self.state.next_base_fee_at(block_epoch);
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: SPENDS_PER_BLOCK as u32 },
            tx_bytes,
            base_fee,
            0,
        );
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        // Conservation is strict equality: the outputs must absorb exactly
        // what the inputs carried, minus the fee.
        let per_output: u128 = 1_000;
        let head = per_output * (CREATES_PER_BLOCK as u128 - 1);
        if spent_value <= fee + head {
            return None;
        }
        for o in outputs.iter_mut().take(CREATES_PER_BLOCK - 1) {
            o.value = per_output as u64;
        }
        outputs[CREATES_PER_BLOCK - 1].value =
            u64::try_from(spent_value - fee - head).expect("change fits u64");

        let unsigned = PosTransaction::Transfer {
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            tx_bytes,
            tip_millisat_per_gas: 0,
        };
        // The signing root excludes the witnesses by construction, so the
        // placeholder signatures above cannot have influenced it.
        let root = unsigned.spend_signing_root();
        let sig = bloch_crypto::crypto::sign(&self.spender_sk, &root).expect("sign");
        let inputs: Vec<TransferInput> = inputs
            .into_iter()
            .map(|mut i| {
                i.signature = sig.clone();
                i
            })
            .collect();
        let tx = PosTransaction::Transfer {
            inputs,
            outputs: outputs.clone(),
            tx_bytes,
            tip_millisat_per_gas: 0,
        };
        assert!(
            tx.canonical_bytes().len() as u64 <= tx_bytes,
            "declared tx_bytes {tx_bytes} is below the transfer's own canonical length {} \
             — the transition would refuse this as UnderdeclaredSize",
            tx.canonical_bytes().len()
        );
        // The created outputs re-enter the wallet, so a long run keeps
        // spending real coins instead of running dry.
        let txid = tx.txid();
        for (vout, o) in outputs.iter().enumerate() {
            self.coins.push(Coin { txid, vout: vout as u32, value: o.value });
        }
        Some(tx)
    }

    /// Produce and apply the block for `slot`, if this slot has a proposer.
    ///
    /// Built exactly the way `Engine::propose` builds one — same derivations,
    /// same RANDAO positioning, same attestation filter.
    fn block_at(&mut self, slot: u64) -> Option<BlockEnvelope> {
        let e = epoch_of(slot);
        let rolled = self.rolled_to(e);
        let roster = rolled.active_validators();
        let seed = Self::seed_for(&rolled, e);
        let proposer = schedule::proposer(&seed, slot, &roster)?;

        // Attestations for the previous slot, from that slot's committee.
        // Same filter `Engine::propose` applies: this epoch only, not from the
        // future, author on duty. Epoch 0 has no attesters (its checkpoint is
        // genesis, so a vote for it would be source == target).
        let fin = rolled.finality();
        let mut atts: Vec<Attestation> = Vec::new();
        let prev = slot - 1;
        if e >= 1 && epoch_of(prev) == e && fin.justified.epoch < e {
            let data = AttestationData {
                slot: prev,
                head: *self.chain.last().expect("genesis").1.as_bytes(),
                source_epoch: fin.justified.epoch,
                source_root: fin.justified.root,
                target_epoch: e,
                target_root: self.checkpoint_root(e),
            };
            let root = data.signing_root();
            let committee = committees::committee_for_slot(&seed, prev, &roster);
            let n = (committee.len() * self.participation_pct as usize) / 100;
            for v in committee.into_iter().take(n) {
                atts.push(Attestation {
                    data: data.clone(),
                    validator: v,
                    signature: self.keys[v as usize].sign(&root),
                });
            }
        }

        let mut randao = RandaoChain::generate(self.keys[proposer as usize].randao_seed);
        for _ in 0..self.proposals[proposer as usize] {
            randao.next_reveal();
        }
        let reveal = randao.peek_reveal()?;

        let txs: Vec<PosTransaction> = self.transfer(e).into_iter().collect();
        let tx_bytes: Vec<Vec<u8>> = txs.iter().map(PosTransaction::canonical_bytes).collect();

        let mut header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: *self.chain.last().expect("genesis").1.as_bytes(),
            state_root: [0u8; 32],
            body_root: derive::body_root(&tx_bytes),
            slot,
            proposer_index: proposer,
            randao_reveal: reveal,
            randao_mix: mix_in(&rolled.randao_mix(), &reveal),
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: derive::attestation_root(&atts),
            coherence_root: self.state.coherence_root(),
        };
        // The probe transition skips signature checks only; the state it
        // computes is the state the real verifier commits to.
        let probe = ProposalEnvelope { header: header.clone(), proposer_sig: Vec::new() };
        let post = match self.probe.compute_post_state(&self.state, &probe, &atts, &txs) {
            Ok(p) => p,
            Err(err) => panic!(
                "the benchmark fixture built a block the transition refuses at slot \
                 {slot}: {err:?} — the fixture is wrong, not the node"
            ),
        };
        header.state_root = post.state_root();
        let proposer_sig = self.keys[proposer as usize].sign(&header.proposal_signing_root());
        let env = BlockEnvelope {
            header,
            proposer_sig,
            body: Body { transactions: tx_bytes, attestations: atts },
        };

        // Apply it through the REAL verifier, exactly as `apply_canonical`
        // will during replay.
        let envelope = ProposalEnvelope {
            header: env.header.clone(),
            proposer_sig: env.proposer_sig.clone(),
        };
        let post = self
            .tr
            .apply_block(&self.state, &envelope, &env.body.attestations, &txs)
            .unwrap_or_else(|e| {
                panic!("fixture block rejected by the real verifier at slot {slot}: {e:?}")
            });
        self.state = post;
        let id = env.block_id();
        self.chain.push((slot, id));
        self.proposals[proposer as usize] += 1;
        Some(env)
    }
}

// ── the measurement ─────────────────────────────────────────────────────────

/// One replayed block: wall time, and the self time of each instrumented
/// phase.
#[derive(Clone, Copy)]
struct Sample {
    total: Duration,
    phases: [Duration; perf::N_PHASES],
}

fn median(xs: &mut [f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a duration"));
    let n = xs.len();
    if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    }
}

/// Build an `Engine` positioned exactly where boot replay starts it: genesis
/// state, genesis-only chain, `live = false`.
///
/// `live = false` is the load-bearing part. It is what boot replay sets, and
/// it suppresses the block-log append and the per-block log line — so this
/// measures the consensus work and not the terminal.
fn boot_engine(manifest: Manifest, dir: &Path) -> Engine {
    let store = Store::open(dir, &[0u8; 32]).expect("store");
    let genesis_state = manifest.genesis_state();
    let genesis_id = manifest.genesis_id();
    let verifier = HybridVerifier::new(manifest.pubkeys());
    let head_slot = Arc::new(AtomicU64::new(0));
    let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    // The receiver is leaked on purpose: dropping it would make the mesh's
    // sender fail, and nothing in this benchmark reads a network event anyway.
    std::mem::forget(rx);
    // Loopback, ephemeral port, no peers. Nothing in this file dials, listens
    // for, or sends anything to any network.
    let net = net::Net::Devnet(
        net::start("127.0.0.1", 0, Vec::new(), tx, dir.to_path_buf(), head_slot.clone(), inflight)
            .expect("loopback devnet transport"),
    );
    Engine {
        state: StateCell::new(genesis_state),
        tr: Transition::new(verifier.clone()),
        tr_probe: Transition::new(ProbeVerifier),
        verifier,
        keys: None, // observer: replay proposes nothing and attests nothing
        // An observer signs nothing, so it carries no fence. It still takes
        // the data-directory lock, because a benchmark sharing a live node's
        // dir is exactly the mistake the lock exists to catch.
        fence: None,
        _dir_lock: crate::slashdb::DirLock::acquire(dir).expect("benchmark data dir lock"),
        blocks: BTreeMap::new(),
        chain: vec![(0, genesis_id)],
        canonical: BTreeSet::from([*genesis_id.as_bytes()]),
        // Both of these mirror `boot`'s literal exactly, and they have to:
        // this harness measures the engine boot replay actually runs. An
        // empty ring means the first reorg it meets takes the `replay_to`
        // fallback — which is what a real cold boot does too.
        recent_states: VecDeque::new(),
        pool: BTreeMap::new(),
        att_pool: AttestationPool::new(),
        wall_slot: 0,
        mempool: BTreeMap::new(),
        store,
        net,
        head_slot,
        live: false,
        needs_sync: false,
        last_applied_ms: now_ms(),
        booted_ms: now_ms(),
        ws_anchor: None,
        ws_anchor_hard: false,
        ws_conflict_reported: false,
        fc_covered_removals: 0,
        manifest,
    }
}

/// Replay `chain` through `Engine::ingest`, timing every block.
fn replay(manifest: Manifest, dir: &Path, chain: &[BlockEnvelope]) -> Vec<Sample> {
    let mut engine = boot_engine(manifest, dir);
    let mut out = Vec::with_capacity(chain.len());
    for env in chain {
        let _ = perf::take(); // zero the counters for this block
        let t = Instant::now();
        engine.ingest(env.clone());
        let total = t.elapsed();
        let counters = perf::take();
        let mut phases = [Duration::ZERO; perf::N_PHASES];
        for (i, (d, _)) in counters.iter().enumerate() {
            phases[i] = *d;
        }
        out.push(Sample { total, phases });
    }
    assert_eq!(
        engine.head_slot_now(),
        chain.last().expect("non-empty chain").header.slot,
        "the replayed chain did not reach the tip — the measurement would be of a \
         rejection path, not of replay"
    );
    out
}

// ── the test ────────────────────────────────────────────────────────────────

/// One benchmark configuration. Two tests below fill it differently, because
/// the two questions need different chains: the headline cost per block is a
/// question about the OPENING LEDGER's size (452,726 leaves, moderate depth),
/// and the depth curve is a question about the CHAIN's depth (small ledger,
/// many blocks). Running one chain that answers both would take a day.
struct BenchCfg {
    name: &'static str,
    blocks: u64,
    runs: usize,
    carryover: u32,
    /// Percent of each slot committee that attests. See
    /// [`Generator::participation_pct`] — this is what selects the justified
    /// vs unjustified regime, and therefore whether fork choice is bounded.
    participation: u32,
    /// Chain depth the extrapolation assumes.
    depth: u64,
}

/// The headline measurement: what one block costs to replay at the live
/// opening-ledger size.
#[test]
#[ignore]
fn perf_end_to_end_replay() {
    let cfg = BenchCfg {
        name: "full-scale replay",
        blocks: env_u64("BLOCH_BENCH_BLOCKS", 192),
        // Five, not three: several people share this box, and a median over
        // five runs plus a visible min/max is what makes a contended run
        // detectable instead of silently averaged in.
        runs: env_u64("BLOCH_BENCH_RUNS", 5) as usize,
        carryover: env_u64("BLOCH_BENCH_CARRYOVER", CARRYOVER_N as u64) as u32,
        participation: env_u64("BLOCH_BENCH_PARTICIPATION", 100) as u32,
        depth: env_u64("BLOCH_BENCH_DEPTH", DEFAULT_DEPTH),
    };
    spawn_bench(cfg);
}

/// The depth curve: how per-block cost grows with how deep the chain already
/// is, in the regime where fork choice is NOT bounded by justification.
///
/// Small opening ledger on purpose. The state root is O(leaves) and
/// independent of depth, so paying 580 ms of it on every one of 512 blocks
/// would buy nothing but hours — it would only add a constant to every point
/// of the curve. Shrinking it lets the depth term be seen at all.
#[test]
#[ignore]
fn perf_replay_depth_curve() {
    let cfg = BenchCfg {
        name: "depth curve (small ledger, unjustified chain)",
        blocks: env_u64("BLOCH_CURVE_BLOCKS", 512),
        runs: env_u64("BLOCH_CURVE_RUNS", 1) as usize,
        carryover: env_u64("BLOCH_CURVE_CARRYOVER", 8_192) as u32,
        // Below the 2/3 justification threshold: nothing justifies, so fork
        // choice walks from genesis over the whole chain depth. This is the
        // regime the degraded live fleet has been in. Post-perf/fork that walk
        // is linear in depth, not quadratic, so this configuration is still
        // the interesting one but no longer the alarming one.
        participation: env_u64("BLOCH_CURVE_PARTICIPATION", 60) as u32,
        depth: env_u64("BLOCH_BENCH_DEPTH", DEFAULT_DEPTH),
    };
    spawn_bench(cfg);
}

/// Same measurement as [`perf_replay_depth_curve`], in the HEALTHY regime:
/// full participation, so justification advances and the fork-choice walk is
/// bounded by the unfinalized suffix instead of by the chain.
///
/// The pair is the experiment. One number from one regime proves nothing;
/// the ratio between them is what says whether depth matters.
#[test]
#[ignore]
fn perf_replay_depth_curve_justified() {
    let cfg = BenchCfg {
        name: "depth curve (small ledger, justified chain)",
        blocks: env_u64("BLOCH_CURVE_BLOCKS", 512),
        runs: env_u64("BLOCH_CURVE_RUNS", 1) as usize,
        carryover: env_u64("BLOCH_CURVE_CARRYOVER", 8_192) as u32,
        participation: 100,
        depth: env_u64("BLOCH_BENCH_DEPTH", DEFAULT_DEPTH),
    };
    spawn_bench(cfg);
}

fn spawn_bench(cfg: BenchCfg) {
    // 512 MB: the generator holds a 452k-entry committed state plus a post
    // state plus the whole chain, and the tree walk is 256 deep.
    std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || bench(cfg))
        .expect("spawn")
        .join()
        .expect("bench thread");
}

fn bench(cfg: BenchCfg) {
    let BenchCfg { name, blocks, runs, carryover: carryover_n, participation, depth } = cfg;

    println!("\n=== end-to-end replay benchmark — {name} ===");
    println!("cpu            : {}", cpu());
    println!(
        "profile        : {}",
        if cfg!(debug_assertions) {
            "DEBUG — every number below is worthless, rebuild with --release"
        } else {
            "release"
        }
    );
    println!(
        "perf-timing    : {}",
        if perf::ENABLED {
            "on (breakdown available)"
        } else {
            "OFF (wall time only — this is the control run)"
        }
    );
    println!("carryover      : {carryover_n} eUTXO leaves");
    println!("validators     : {N_VALIDATORS}");
    println!("participation  : {participation}% of each slot committee attests");
    println!("blocks         : {blocks}");
    println!("tx shape       : {SPENDS_PER_BLOCK} spends + {CREATES_PER_BLOCK} creates per block");
    println!("replay runs    : {runs}");

    let tmp = std::env::temp_dir().join(format!("bloch-replay-bench-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("tmp dir");

    // ── generate ────────────────────────────────────────────────────────────
    //
    // On its own thread: the generator computes hundreds of state roots and
    // would hand a warm thread-local memo to whatever ran next.
    let gen_dir = tmp.join("gen");
    let t = Instant::now();
    let (chain, report) = std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || {
            let t0 = Instant::now();
            let mut g = Generator::new(&gen_dir, carryover_n, participation);
            let t_genesis = t0.elapsed();
            let mut chain = Vec::new();
            let mut with_tx = 0usize;
            let mut atts = 0usize;
            for slot in 1..=blocks {
                if let Some(env) = g.block_at(slot) {
                    if !env.body.transactions.is_empty() {
                        with_tx += 1;
                    }
                    atts += env.body.attestations.len();
                    chain.push(env);
                }
            }
            let fin = g.state.finality();
            let utxos = g.state.utxos().count();
            (
                chain,
                (
                    t_genesis,
                    with_tx,
                    atts,
                    fin.justified.epoch,
                    fin.finalized.epoch,
                    utxos,
                    g.manifest,
                ),
            )
        })
        .expect("spawn")
        .join()
        .expect("generator");
    let t_generate = t.elapsed();
    let (t_genesis, with_tx, atts, justified, finalized, utxos, manifest) = report;

    println!("\n── fixture ──");
    println!(
        "genesis synthesis + 64 keypairs               : {:>9.1} ms  [MEASURED]",
        ms(t_genesis)
    );
    println!(
        "chain generation (produce + validate)         : {:>9.1} s   [not part of any result]",
        t_generate.as_secs_f64()
    );
    println!("blocks produced                               : {:>9}", chain.len());
    println!("  of which carrying a transfer                : {with_tx:>9}");
    println!("  attestations carried, total                 : {atts:>9}");
    println!("  eUTXO set at the tip                        : {utxos:>9}");
    println!("  justified epoch / finalized epoch           : {justified:>4} / {finalized}");
    if finalized == 0 {
        println!("  NOTE: nothing finalized. Fork choice walks from the JUSTIFIED");
        println!("        checkpoint, so an unjustified fixture makes that walk deeper than");
        println!("        the live chain's and OVERSTATES the forkchoice share.");
    }
    assert!(!chain.is_empty(), "the fixture produced no blocks at all");

    // ── replay, N times, each on a cold thread ──────────────────────────────
    let mut per_run: Vec<Vec<Sample>> = Vec::new();
    for run in 0..runs {
        let dir = tmp.join(format!("replay{run}"));
        std::fs::create_dir_all(&dir).expect("replay dir");
        let m = clone_manifest(&manifest);
        let c = chain.clone();
        let t = Instant::now();
        let samples = std::thread::Builder::new()
            .stack_size(512 << 20)
            .spawn(move || replay(m, &dir, &c))
            .expect("spawn")
            .join()
            .expect("replay");
        let wall = t.elapsed();
        let sum: f64 = samples.iter().map(|s| ms(s.total)).sum();
        let med = median(&mut samples.iter().map(|s| ms(s.total)).collect::<Vec<_>>());
        println!(
            "run {run}: thread wall {:>7.1} s (incl. genesis synthesis), in-replay {:>7.1} s, \
             {} blocks, median {:>7.1} ms/block",
            wall.as_secs_f64(),
            sum / 1000.0,
            samples.len(),
            med
        );
        // The breakdown for THIS run, printed now rather than only in the
        // summary. A 25-minute benchmark that prints its result once at the
        // end loses everything if the box takes the process away — which is
        // exactly what happened at 02:25 on 2026-08-23, four runs in.
        if perf::ENABLED {
            let mean_run: f64 =
                samples.iter().map(|s| ms(s.total)).sum::<f64>() / samples.len() as f64;
            let mut line = String::new();
            let mut attributed = 0.0;
            for i in 0..perf::N_PHASES {
                let m = samples.iter().map(|s| ms(s.phases[i])).sum::<f64>()
                    / samples.len() as f64;
                attributed += m;
                if m >= 0.05 {
                    line.push_str(&format!(
                        "{}={:.1}ms({:.0}%) ",
                        perf::PHASE_NAMES[i],
                        m,
                        100.0 * m / mean_run
                    ));
                }
            }
            line.push_str(&format!(
                "else={:.1}ms({:.0}%)",
                mean_run - attributed,
                100.0 * (mean_run - attributed) / mean_run
            ));
            println!("        mean {mean_run:.1} ms/block; {line}");
        }
        per_run.push(samples);
    }

    // ── report ──────────────────────────────────────────────────────────────
    println!("\n── per-block cost, MEASURED ({runs} runs x {} blocks) ──", chain.len());
    let all: Vec<Sample> = per_run.iter().flatten().copied().collect();
    let mut totals: Vec<f64> = all.iter().map(|s| ms(s.total)).collect();
    let mean = totals.iter().sum::<f64>() / totals.len() as f64;
    let med = median(&mut totals); // sorts `totals`
    let p95 = totals[((totals.len() as f64 * 0.95) as usize).min(totals.len() - 1)];
    println!("  mean   : {mean:>9.1} ms/block");
    println!("  median : {med:>9.1} ms/block");
    println!("  p95    : {p95:>9.1} ms/block");
    println!("  min    : {:>9.1} ms/block", totals[0]);
    println!("  max    : {:>9.1} ms/block", totals[totals.len() - 1]);

    // Per-run medians, so the spread BETWEEN runs is visible rather than
    // hidden inside one pooled median.
    let mut run_meds: Vec<f64> = per_run
        .iter()
        .map(|r| median(&mut r.iter().map(|s| ms(s.total)).collect::<Vec<_>>()))
        .collect();
    println!(
        "  per-run medians: {} ms",
        run_meds.iter().map(|m| format!("{m:.1}")).collect::<Vec<_>>().join(", ")
    );
    let med_of_med = median(&mut run_meds);

    if perf::ENABLED {
        println!("\n── where a block's time goes, MEASURED (self time, disjoint) ──");
        println!("{:>16}  {:>12}  {:>12}  {:>8}", "phase", "median ms", "mean ms", "share");
        let mut attributed_mean = 0.0;
        for i in 0..perf::N_PHASES {
            let mut xs: Vec<f64> = all.iter().map(|s| ms(s.phases[i])).collect();
            let m = xs.iter().sum::<f64>() / xs.len() as f64;
            let md = median(&mut xs);
            attributed_mean += m;
            println!(
                "{:>16}  {md:>12.1}  {m:>12.1}  {:>7.1}%",
                perf::PHASE_NAMES[i],
                100.0 * m / mean
            );
        }
        let other = mean - attributed_mean;
        println!(
            "{:>16}  {:>12}  {other:>12.1}  {:>7.1}%",
            "everything else", "-", 100.0 * other / mean
        );
        println!(
            "  (\"everything else\" = wall clock minus the phases above: transaction\n\
             \x20  execution, attestation verification, header derivations, the engine's\n\
             \x20  own bookkeeping.)"
        );
    } else {
        println!("\n── breakdown unavailable: built without --features perf-timing ──");
        println!("  This run's wall time is the CONTROL: compare it against the");
        println!("  instrumented run to price the timers themselves.");
    }

    // ── the depth curve, MEASURED ───────────────────────────────────────────
    //
    // Every block in a replay is applied at a different chain depth: block i
    // is the (i+1)th. So one run already contains the whole curve — binning
    // the samples by position is the measurement, and it needs no extra runs.
    // A single average over the run would hide exactly the superlinearity
    // this is looking for.
    println!("\n── per-block cost BY CHAIN DEPTH, MEASURED (run 0) ──");
    println!(
        "{:>14}  {:>11}  {:>11}  {:>11}  {:>11}",
        "depth range", "median ms", "forkchoice", "state_root", "else"
    );
    let run0 = &per_run[0];
    let bins = 8usize.min(run0.len());
    let width = run0.len().div_ceil(bins.max(1));
    let mut first_bin = 0.0f64;
    let mut last_bin = 0.0f64;
    let mut first_fc = 0.0f64;
    let mut last_fc = 0.0f64;
    for b in 0..bins {
        let lo = b * width;
        let hi = ((b + 1) * width).min(run0.len());
        if lo >= hi {
            continue;
        }
        let slice = &run0[lo..hi];
        let mut tot: Vec<f64> = slice.iter().map(|s| ms(s.total)).collect();
        let mut fc: Vec<f64> =
            slice.iter().map(|s| ms(s.phases[perf::Phase::ForkChoice as usize])).collect();
        let mut sr: Vec<f64> =
            slice.iter().map(|s| ms(s.phases[perf::Phase::StateRoot as usize])).collect();
        let m_tot = median(&mut tot);
        let m_fc = median(&mut fc);
        let m_sr = median(&mut sr);
        if b == 0 {
            first_bin = m_tot;
            first_fc = m_fc;
        }
        last_bin = m_tot;
        last_fc = m_fc;
        println!(
            "{:>14}  {m_tot:>11.1}  {m_fc:>11.1}  {m_sr:>11.1}  {:>11.1}",
            format!("{}..{}", lo + 1, hi),
            m_tot - m_fc - m_sr
        );
    }
    if !perf::ENABLED {
        println!("  (forkchoice/state_root columns are zero: built without perf-timing)");
    }
    println!(
        "  growth across the run: total {:.2}x, forkchoice {:.2}x",
        if first_bin > 0.0 { last_bin / first_bin } else { 0.0 },
        if first_fc > 0.0 { last_fc / first_fc } else { 0.0 }
    );
    println!(
        "  (a flat total means depth does not matter at this chain length; a rising\n\
         \x20  forkchoice column is the depth term becoming visible; since\n\
         \x20  perf/fork that term is LINEAR in depth, so a column that grows\n\
         \x20  in step with depth is expected and not a regression.)"
    );

    // ── extrapolation, clearly labelled ─────────────────────────────────────
    println!("\n── EXTRAPOLATION (arithmetic, NOT measured) ──");
    println!("  median ms/block (measured, median of the {runs} run medians): {med_of_med:.1}");
    println!("  assumed chain depth: {depth} blocks");
    println!(
        "  {depth} x {med_of_med:.1} ms = {:.0} ms = {:.1} min = {:.2} h",
        depth as f64 * med_of_med,
        depth as f64 * med_of_med / 60_000.0,
        depth as f64 * med_of_med / 3_600_000.0
    );
    println!(
        "  plus the one-off opening-ledger synthesis at boot: {:.1} s",
        t_genesis.as_secs_f64()
    );
    println!(
        "  CAVEAT: LINEAR extrapolation from a {}-block chain. `forkchoice_head` is\n\
         \x20 O(V+N+D) over the UNJUSTIFIED suffix -- linear, since perf/fork -- but\n\
         \x20 `Engine::blocks` is still unpruned, so a real {depth}-block replay is a\n\
         \x20 LOWER bound, not an estimate. The depth\n\
         \x20 table above says how far from linear this particular run was.",
        chain.len()
    );

    // ── the go/no-go arithmetic: can a restarted node ever catch up? ─────────
    //
    // The chain advances one epoch per SLOT_DURATION_SECS x SLOTS_PER_EPOCH of
    // wall clock. A replaying node is racing that. Two derived numbers say
    // whether it wins, and both are arithmetic on the measured median — every
    // input is labelled.
    let replay_secs = depth as f64 * med_of_med / 1000.0;
    let epochs_behind = replay_secs / EPOCH_SECS;
    // Seconds of chain history recovered per second of wall clock. The chain
    // produces `blocks_per_slot^-1` blocks per 30 s; this fixture has one
    // block per slot, so one replayed block buys SLOT_DURATION_SECS of
    // history. On the live chain, where a block arrives every ~19 slots, one
    // replayed block buys ~19x that — which is stated, not folded in.
    let secs_of_history_per_block = bloch_pos_committee::params::SLOT_DURATION_SECS as f64;
    let realtime_multiple = secs_of_history_per_block / (med_of_med / 1000.0);
    println!("\n── CONVERGENCE (arithmetic on the measured median) ──");
    println!("  1 epoch = {} slots x {} s = {EPOCH_SECS:.0} s",
        bloch_pos_committee::SLOTS_PER_EPOCH,
        bloch_pos_committee::params::SLOT_DURATION_SECS);
    println!("  replay of {depth} blocks       : {replay_secs:.0} s  [EXTRAPOLATED]");
    println!("  epochs behind on return     : {replay_secs:.0} / {EPOCH_SECS:.0} = {epochs_behind:.1} epochs  [EXTRAPOLATED]");
    println!(
        "  replay speed vs real time   : {:.2} s of chain history per s of wall clock",
        realtime_multiple
    );
    println!(
        "    (assumes one block per {} s slot — the DESIGN cadence. The live chain\n\
         \x20    has been producing a block roughly every 19 slots, which multiplies\n\
         \x20    this figure by ~19 and is the honest reading for the fleet today.)",
        bloch_pos_committee::params::SLOT_DURATION_SECS
    );
    if realtime_multiple < 1.0 {
        println!("    BELOW 1x AT THE DESIGN CADENCE: a node replaying a chain that is");
        println!("    producing one block per slot never converges. It falls further behind.");
    }

    let _ = std::fs::remove_dir_all(&tmp);
}
