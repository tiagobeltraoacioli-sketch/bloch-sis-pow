// SPDX-License-Identifier: AGPL-3.0-or-later

//! DEV-15, Coherence wave — the byte-identity merge gate.
//!
//! ## Why this file exists
//!
//! The live genesis committed **loaded zeros** for the three carried roots
//! (`crates/bloch-pos-node/src/genesis.rs:970-977`): taint, Coherence
//! accumulator, Coherence nullifier set are all `[0u8; 32]`, and every child
//! header since block 1 carries `coherence_root =
//! coherence_binding([0;32], [0;32])`. Those zeros are NOT the empty-pool
//! tree roots — `coherence-core`'s empty accumulator and empty nullifier set
//! both commit non-zero roots by design ("no pool" must be distinguishable
//! from "an unset field").
//!
//! Therefore: any patch that makes the transition (or the genesis loader)
//! **derive** the Coherence roots from pool content instead of carrying the
//! loaded values changes the `state_root` and the `coherence_root` of every
//! block since genesis, and forks the production chain the moment one node
//! deploys it. Derivation may only ever arrive behind an epochal flag day
//! (the `*_ACTIVATION_EPOCH` idiom in `params.rs`), with byte-for-byte
//! identity below the gate.
//!
//! ## What is asserted
//!
//! 1. A fixture chain built with the live loader's exact posture replays
//!    through a fresh `Transition` — from a `blocks.log`-shaped file, the
//!    node's restart discipline — to **byte-identical** per-block state
//!    roots and head root.
//! 2. Every one of those values is ALSO pinned as a known-answer constant.
//!    The pin is the gate: replay-vs-live agreement alone would not catch a
//!    change that alters both sides symmetrically (an ungated derivation
//!    does exactly that — producer and validator both switch). A KAT cannot
//!    be re-derived by the code under test.
//! 3. The fork an ungated derivation causes is demonstrated positively, with
//!    the real `coherence-core` empty-tree roots, so "the gate bites" is a
//!    runnable fact rather than a review claim.
//! 4. A source tripwire holds the live loader to the loaded-zeros posture
//!    until a gate exists.
//!
//! ## If you are here because a pin moved
//!
//! You changed a consensus root. Either that was unintentional (revert), or
//! you are landing the Coherence derivation flag day — in which case the new
//! behaviour must be gated on an activation epoch that is `u64::MAX` in the
//! shipped default, the pre-gate values must NOT move (this file keeps
//! passing untouched), and only `coherence_flagday_boundary.rs` gets the
//! post-gate expectations wired to the real constant. Re-pinning the
//! constants here to "make the test green" is the exact defect this gate
//! exists to stop: it silently rewrites the identity of the live chain.

mod coherence_harness;

use bloch_pos_committee::derive::coherence_binding;
use bloch_pos_committee::header::BlockId;
use bloch_pos_committee::interfaces::{StateReader, StateTransition};
use bloch_pos_committee::state_root::EvmCommitment;
use bloch_pos_committee::transition::{CommittedState, PosTransaction};
use coherence_harness as h;

// ── The pinned identity of the loaded-roots chain ───────────────────────────
//
// Known answers, computed once from the frozen rules and pinned. Every value
// below is a pure function of the fixture in `coherence_harness` plus the
// consensus rules; none of them may move without a flag day (see module docs).

/// `BlockId::of` over the genesis header the live manifest synthesizes.
///
/// **Verified against the production network, not derived on paper.** The
/// value below is what `getblockbyslot(0)` returns from the Genesis-4
/// archival node (139.180.166.5) on 2026-08-30, and it is what this code
/// produces — two independent paths, same 32 bytes. An earlier revision of
/// this file pinned `6a1e88db…`, reasoned out from "the header has no
/// manifest-derived field"; that reasoning was wrong, and the failure it
/// caused claimed "the identity of the live chain changed" when the live
/// chain had not moved at all. A pin nobody checked against the thing it
/// pins is a guess with a constant's syntax.
const PIN_GENESIS_ID: &str = "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415";

/// `coherence_binding([0;32], [0;32])` — the exact `coherence_root` every
/// child block of the live chain carries while the pool roots are the loaded
/// zeros. An ungated derivation changes this on every block; a gated one
/// changes it only above the activation epoch.
///
/// Verified three independent ways: this code, an out-of-band SHA3-256 of
/// `DS_COHERENCE ‖ 0^32 ‖ 0^32`, and the `coherence_root` field of a live
/// Genesis-4 block read over RPC. The previous pin (`d269f1f6…`) matched none
/// of them.
const PIN_BINDING_OF_LOADED_ZEROS: &str =
    "3ac97a48fe4c1dc2de33022b2473e76e609c85ce0c0bce96540851f682bccb56";

/// State root of the fixture genesis (4 validators, 2 opening outputs, three
/// carried roots and the EVM segment all zero — the live loader's posture).
///
/// Same honest status as `PIN_FIXTURE_HEAD_ROOT`: derived by running, not
/// checked against an external referent. The fixture is synthetic, so there
/// is nothing outside this code to check it against.
const PIN_FIXTURE_GENESIS_ROOT: &str =
    "b51235afafbbdbbbc6c5b410355ca9fa55275633ed11baa42685f585e0d0fec6";

/// Head state root after the 7-block fixture chain (two epoch boundaries,
/// two value transfers) — the byte the whole replay must land on.
///
/// **Honest status of this pin, unlike the three above it:** it has no
/// external referent. The genesis id was checked against the production
/// network, the binding against an out-of-band SHA3 and a live block, and the
/// fixture genesis root against the value this file already carried. This one
/// is the deterministic output of applying the fixture's seven blocks through
/// the same `Transition` the node runs — so it is a regression detector, not
/// a proof of external truth. It bites when a consensus rule moves, which is
/// its job; it cannot tell you the rule was right to begin with.
const PIN_FIXTURE_HEAD_ROOT: &str =
    "323a7967c1d8c2b3a2d3200a364a928d8a34d3436154eca439dba5449347dd83";

/// The slots the fixture chain occupies: ordinary slots, one boundary jump
/// into epoch 1, one into epoch 2 (SLOTS_PER_EPOCH = 32).
const FIXTURE_SLOTS: [u64; 7] = [1, 2, 3, 33, 34, 65, 66];

/// Build the fixture chain ON the live-accept path: every block through
/// `Transition::apply_block`, exactly as the node accepted the live chain.
/// Returns the accepted blocks and the per-block post-roots the live path
/// committed.
fn live_chain() -> (Vec<h::LoggedBlock>, Vec<[u8; 32]>, CommittedState) {
    let owner = h::owner_key(7);
    let recipient = h::owner_key(9);
    let openings = vec![
        h::opening(0xA1, 0, 5_000_000_000, &owner),
        h::opening(0xA2, 1, 7_000_000_000, &owner),
    ];
    let (t, genesis, mut chains) = h::genesis_fixture(4, &openings);

    let mut blocks = Vec::new();
    let mut roots = Vec::new();
    let mut st = genesis;
    for slot in FIXTURE_SLOTS {
        let txs: Vec<PosTransaction> = match slot {
            2 => vec![h::transfer(
                &st,
                slot,
                &owner,
                ([0xA1; 32], 0, 5_000_000_000),
                h::script_of(&recipient),
            )],
            34 => vec![h::transfer(
                &st,
                slot,
                &owner,
                ([0xA2; 32], 1, 7_000_000_000),
                h::script_of(&recipient),
            )],
            _ => Vec::new(),
        };
        let env = h::build_block(&t, &st, slot, &txs, &mut chains);
        st = h::apply(&t, &st, &env, &txs);
        roots.push(st.state_root());
        blocks.push(h::LoggedBlock { envelope: env, txs });
    }
    (blocks, roots, st)
}

/// 1 + 2. The harness of the task statement: a `blocks.log`-shaped copy of
/// the chain, replayed through the same `Transition` that accepted it live,
/// with the head root asserted byte-identical — and pinned.
#[test]
fn replaying_the_block_log_reproduces_the_live_roots_byte_for_byte() {
    let (blocks, live_roots, live_head) = live_chain();

    // The identity pins first: these are the values an ungated derivation
    // moves on EVERY block, which is what makes this test fail against such
    // a patch even though both its halves would still agree with each other.
    assert_eq!(
        h::hex(BlockId::of(&h::live_genesis_header()).as_bytes()),
        PIN_GENESIS_ID,
        "the genesis block id moved — the identity of the live chain changed"
    );
    assert_eq!(
        h::hex(&coherence_binding(&[0u8; 32], &[0u8; 32])),
        PIN_BINDING_OF_LOADED_ZEROS,
        "coherence_binding over the loaded zeros moved — every live child \
         header carries this exact value"
    );
    for b in &blocks {
        assert_eq!(
            h::hex(&b.envelope.header.coherence_root),
            PIN_BINDING_OF_LOADED_ZEROS,
            "an accepted block at slot {} carries a coherence_root that is \
             not the carried binding over the loaded zeros: the transition \
             derived instead of carrying (slot {})",
            b.envelope.header.slot,
            b.envelope.header.slot,
        );
    }
    assert_eq!(
        h::hex(&live_head.state_root()),
        PIN_FIXTURE_HEAD_ROOT,
        "the live-accept head state root moved: a consensus root changed \
         without a flag day (see module docs before touching this pin)"
    );

    // Now the replay: write the chain as a framed log, read it back, and run
    // it through a FRESH Transition from a FRESH genesis — the node's
    // restart. Every intermediate root must be byte-identical to what the
    // live path committed.
    let dir = std::env::temp_dir().join(format!("coherence-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fixture dir");
    let log_path = dir.join("blocks.log");
    std::fs::write(&log_path, h::encode_log(&blocks)).expect("write fixture log");

    let logged = h::decode_log(&std::fs::read(&log_path).expect("read fixture log"));
    assert_eq!(logged.len(), blocks.len(), "the log lost frames");

    let owner = h::owner_key(7);
    let openings = vec![
        h::opening(0xA1, 0, 5_000_000_000, &owner),
        h::opening(0xA2, 1, 7_000_000_000, &owner),
    ];
    let (t2, genesis2, _chains2) = h::genesis_fixture(4, &openings);
    assert_eq!(
        h::hex(&genesis2.state_root()),
        PIN_FIXTURE_GENESIS_ROOT,
        "the genesis state root moved: the loaded-roots posture changed \
         (this is the PMO finding — see module docs)"
    );

    let mut st = genesis2;
    for (i, b) in logged.iter().enumerate() {
        st = t2
            .apply_block(&st, &b.envelope, &[], &b.txs)
            .unwrap_or_else(|e| {
                panic!(
                    "replay refused block {} (slot {}) that the live path \
                     accepted: {e:?} — replay and live-accept have diverged",
                    i, b.envelope.header.slot
                )
            });
        assert_eq!(
            st.state_root(),
            live_roots[i],
            "replayed root differs from the live-accept root at slot {} — \
             the transition is not a pure function of its inputs any more",
            b.envelope.header.slot
        );
        assert_eq!(
            st.state_root(),
            b.envelope.header.state_root,
            "replayed root differs from the root the header committed at \
             slot {}",
            b.envelope.header.slot
        );
    }
    assert_eq!(
        h::hex(&st.state_root()),
        PIN_FIXTURE_HEAD_ROOT,
        "the replayed head root is not the pinned live head root"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// 3. The fork, demonstrated with the real empty-pool roots.
///
/// This is what an ungated derivation ships: the empty `coherence-core`
/// accumulator and nullifier set commit NON-zero roots, so "derive at load"
/// (or "derive in the transition") produces a genesis state root, a child
/// coherence_root and a child block id that all differ from the live
/// chain's. Two binaries, two chains, one network — the deploy-day fork.
/// The assertions here are what make the pins above meaningful: they prove
/// the values a derivation would produce are NOT the pinned ones.
#[test]
fn deriving_the_roots_without_a_gate_is_a_fork_and_the_pins_catch_it() {
    let empty_acc = coherence_core::CommitmentTree::new().root();
    let empty_nf = coherence_core::NullifierSet::new().root();

    // The heart of the PMO finding: the loaded zeros are not the empty-pool
    // roots. If either of these ever collides with zero, the whole premise
    // of this gate needs re-examination — fail loudly.
    assert_ne!(empty_acc, [0u8; 32], "empty accumulator root became zero");
    assert_ne!(empty_nf, [0u8; 32], "empty nullifier-set root became zero");

    let derived_binding = coherence_binding(&empty_acc, &empty_nf);
    assert_ne!(
        h::hex(&derived_binding).as_str(),
        PIN_BINDING_OF_LOADED_ZEROS,
        "the derived empty-pool binding equals the loaded-zeros binding — \
         the demonstration below is vacuous and the gate proves nothing"
    );

    // A genesis loaded the way an ungated "derive at load" patch would load
    // it. Everything else identical to the live posture.
    let owner = h::owner_key(7);
    let openings = vec![
        h::opening(0xA1, 0, 5_000_000_000, &owner),
        h::opening(0xA2, 1, 7_000_000_000, &owner),
    ];
    let (t, live_genesis, mut live_chains) = h::genesis_fixture(4, &openings);

    let mut derived_chains = h::ChainSet::new(4);
    let mut vals = Vec::new();
    for i in 0..4u32 {
        vals.push(bloch_pos_committee::transition::GenesisValidator {
            index: i,
            pubkey: vec![i as u8; 8],
            staked_sat: h::sat(200_000),
            randao_commitment: derived_chains.commitment(i),
            withdrawal_credentials: vec![i as u8; 4],
            commission_bps: 500,
        });
    }
    let derived_genesis = CommittedState::genesis(
        BlockId::of(&h::live_genesis_header()),
        [0u8; 32],
        &vals,
        &[],
        [0u8; 32], // taint unchanged — the wave only touches Coherence
        empty_acc, // ← the ungated derivation
        empty_nf,  // ←
        EvmCommitment {
            account_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        &openings,
    );

    // The fork, fact by fact.
    assert_ne!(
        derived_genesis.state_root(),
        live_genesis.state_root(),
        "deriving the pool roots did not move the genesis state root — \
         the state tree stopped committing the carried roots"
    );
    assert_ne!(
        h::hex(&derived_genesis.state_root()).as_str(),
        PIN_FIXTURE_GENESIS_ROOT,
        "the derived genesis root equals the pinned live one"
    );

    // Block 1 on each side: same slot, same proposer walk, different chain.
    // Speculative builds — neither block is ever applied to its own chain.
    let live_b1 = h::speculative_block(&t, &live_genesis, 1, &[], &mut live_chains);
    let derived_b1 = h::speculative_block(&t, &derived_genesis, 1, &[], &mut derived_chains);
    assert_eq!(
        derived_b1.header.coherence_root, derived_binding,
        "control: the derived chain's child carries the derived binding"
    );
    assert_ne!(
        derived_b1.header.coherence_root, live_b1.header.coherence_root,
        "the two chains' children agree on coherence_root — no fork visible"
    );
    assert_ne!(
        BlockId::of(&derived_b1.header),
        BlockId::of(&live_b1.header),
        "the two chains' children share a block id"
    );

    // And the cross-rejections that a mixed fleet would log all day: each
    // side's block is a deterministic, NAMED reject on the other side —
    // never a silent accept.
    assert_eq!(
        t.apply_block(&live_genesis, &derived_b1, &[], &[]),
        Err(bloch_pos_committee::interfaces::TransitionError::CoherenceRootMismatch),
        "an old node ACCEPTED a derived-roots block — the fork would be silent"
    );
    assert_eq!(
        t.apply_block(&derived_genesis, &live_b1, &[], &[]),
        Err(bloch_pos_committee::interfaces::TransitionError::CoherenceRootMismatch),
        "a derived-roots node ACCEPTED a live block — the fork would be silent"
    );
}

/// 4. The source tripwire on the live loader.
///
/// The pure-crate pins cannot see `crates/bloch-pos-node/src/genesis.rs`
/// (a binary crate; its `Manifest` is unreachable from `tests/`), so the
/// loader's loaded-zeros posture is held by inspecting the source of the
/// very call site the PMO finding names. Crude on purpose: this trips on
/// ANY edit to the three carried-root arguments, and the person it trips is
/// exactly the person who must go read the module docs above.
#[test]
fn the_live_loader_still_commits_loaded_zero_roots() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/genesis.rs"
    ))
    .expect("read src/genesis.rs");

    let start = src
        .find("CommittedState::genesis(")
        .expect("genesis.rs no longer calls CommittedState::genesis — rewire this tripwire");
    let region = &src[start..];
    let end = region
        .find("EvmCommitment")
        .expect("the genesis call no longer passes an EvmCommitment — rewire this tripwire");
    let args = &region[..end];

    let zeros = args.matches("[0u8; 32]").count();
    assert_eq!(
        zeros, 3,
        "genesis.rs passes {zeros} literal `[0u8; 32]` carried roots instead of 3.\n\
         The live chain committed LOADED ZEROS for taint, coherence accumulator and \
         coherence nullifier set; changing any of them re-roots every block since \
         genesis and forks production on deploy. If this is the Coherence flag day, \
         the derivation must sit behind an activation epoch (params.rs idiom, \
         u64::MAX default) and the pre-gate posture must stay exactly this — \
         see coherence_replay_identity.rs module docs.\n\
         Argument region seen:\n{args}"
    );
    for marker in ["CommitmentTree", "NullifierSet", ".root()"] {
        assert!(
            !args.contains(marker),
            "genesis.rs derives a carried root at load time (`{marker}` in the \
             CommittedState::genesis argument list) — that is the ungated \
             derivation this gate exists to stop; see module docs"
        );
    }
}
