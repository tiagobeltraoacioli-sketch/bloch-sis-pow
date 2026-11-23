// SPDX-License-Identifier: AGPL-3.0-or-later
//! Orphaned-head repair (audit L1C-60, the 2026-11-19 mainnet freeze).
//!
//! A node adopts a sibling `X` built over slot `s - 1` because the block of
//! slot `s` reached it late. Everything the network builds afterwards is
//! parked: its parent is unknown. These tests replay the slot loop's sync
//! and duty decisions with the engine's own functions, on blocks and votes
//! produced by the production paths (`propose`, `attest`, the block door).
use super::*;

type Validators = Vec<(Option<Keystore>, SlashingProtection)>;

fn validators(engine: &mut Engine, dir: &perf_support::TestDir, others: Vec<Keystore>, tag: &str) -> Validators {
    let first = engine.keys.take().expect("validator 0");
    std::iter::once(first)
        .chain(others)
        .enumerate()
        .map(|(i, keys)| {
            let sub = dir.0.join(format!("sp{tag}{i}"));
            std::fs::create_dir_all(&sub).expect("slashing protection dir");
            (Some(keys), SlashingProtection::open(&sub).expect("slashing protection"))
        })
        .collect()
}

fn as_validators(engine: &mut Engine, vals: &mut Validators, who: &[usize], duty: &dyn Fn(&mut Engine)) {
    for &i in who {
        std::mem::swap(&mut engine.keys, &mut vals[i].0);
        std::mem::swap(&mut engine.slashprot, &mut vals[i].1);
        duty(engine);
        std::mem::swap(&mut engine.keys, &mut vals[i].0);
        std::mem::swap(&mut engine.slashprot, &mut vals[i].1);
    }
}

const N: usize = 8;

/// Common history through slot 30; the network's branch is 31, 32, ...;
/// `X` is the first block of epoch 1 built on slot 30 by a proposer that did
/// not propose the network's block of the same slot. Returns the engine
/// sitting on `X`, and the network's branch (which it has never seen).
fn orphaned_head_fixture(network_len: u64) -> (Engine, perf_support::TestDir, Vec<BlockEnvelope>, [u8; 32]) {
    let (mut engine, dir, others) = perf_support::proposing_engine_n(&[], N as u32);
    let mut vals = validators(&mut engine, &dir, others, "n");
    let everyone: Vec<usize> = (0..N).collect();
    for slot in 1..SLOTS_PER_EPOCH - 1 {
        let _clock = validator_lifecycle::clock_at(slot);
        as_validators(&mut engine, &mut vals, &everyone, &|e| e.propose(slot));
    }
    let fork_point = *engine.head_id().as_bytes();
    let fork_height = engine.chain.len() - 1;
    assert_eq!(engine.state.slot(), SLOTS_PER_EPOCH - 2);
    for slot in SLOTS_PER_EPOCH - 1..SLOTS_PER_EPOCH - 1 + network_len {
        let _clock = validator_lifecycle::clock_at(slot);
        as_validators(&mut engine, &mut vals, &everyone, &|e| e.attest(slot));
        as_validators(&mut engine, &mut vals, &everyone, &|e| e.propose(slot));
    }
    let network: Vec<BlockEnvelope> = engine.chain[fork_height + 1..]
        .iter()
        .map(|(_, id)| engine.blocks[id.as_bytes()].clone())
        .collect();
    assert_eq!(network.len() as u64, network_len, "fixture: the network has a block in every slot");
    // This node never saw the network's branch.
    assert!(engine.do_reorg(fork_point, Vec::new()));
    for block in &network {
        engine.blocks.remove(block.block_id().as_bytes()).expect("stored");
    }
    engine.pool.clear();
    engine.att_pool = AttestationPool::new();
    engine.observed_proposals.clear();
    engine.proposal_admission_seen.clear();
    engine.proposal_admission_counts.clear();
    let mut fresh: Validators = vals
        .iter_mut()
        .enumerate()
        .map(|(i, (k, _))| {
            let sub = dir.0.join(format!("spx{i}"));
            std::fs::create_dir_all(&sub).unwrap();
            (k.take(), SlashingProtection::open(&sub).unwrap())
        })
        .collect();
    let mut x_slot = SLOTS_PER_EPOCH;
    loop {
        let _clock = validator_lifecycle::clock_at(x_slot);
        // Never the proposer of the network's block of the same slot: `X`
        // must not be an equivocation.
        let taken = network.iter().find(|b| b.header.slot == x_slot).map(|b| b.header.proposer_index as usize);
        let others: Vec<usize> = everyone.iter().copied().filter(|i| Some(*i) != taken).collect();
        as_validators(&mut engine, &mut fresh, &others, &|e| e.propose(x_slot));
        if *engine.head_id().as_bytes() != fork_point {
            break;
        }
        x_slot += 1;
    }
    let x = *engine.head_id().as_bytes();
    engine.needs_sync = false;
    (engine, dir, network, x)
}

/// Distinct proposers of the authenticated orphans parked at or above the
/// head slot, computed independently of the engine's predicate.
fn orphan_proposers_above_head(engine: &Engine) -> usize {
    let head = engine.state.slot();
    let mut seen = BTreeSet::new();
    for (_, env, _, authentication, _) in &engine.orphans {
        if authentication.is_some() && env.header.slot >= head {
            seen.insert(env.header.proposer_index);
        }
    }
    seen.len()
}

/// The 2026-11-19 shape, replayed for 36 slots of 30 s with no answer to any
/// request. Before the fix the node made five requests in eighteen minutes
/// that could have returned the missing block, asked of whichever two peers
/// were next in rotation, and was free to vote on the orphaned head in
/// fifteen of those slots.
#[test]
fn an_orphaned_head_asks_for_the_missing_block_on_every_request_and_holds_its_vote() {
    let (mut engine, _dir, network, x) = orphaned_head_fixture(40);
    let head_slot = engine.state.slot();
    let boundary_slot = network[0].header.slot;
    assert!(boundary_slot <= head_slot, "the missing block is at or below this node's own head slot");
    const SLOT_MS: u64 = 30_000;
    let two_slots = 2 * SLOT_MS;
    let t0 = 10_000_000u64;
    let last_applied_ms = t0 - SLOT_MS;
    let mut last_sync_req = 0u64;
    let mut gate = DutySyncGate::default();
    let mut hold = OrphanedHeadHold::default();
    let mut requests = Vec::new(); // (k, rewind?, evidence?)
    let mut vote_free = Vec::new();
    let mut held = Vec::new();
    let mut evidence_from = None;
    let mut later = network.iter().skip(1);
    // The connection of the latest block that was parked (the per-source
    // share of the orphan pool, `ORPHANS_PER_SOURCE`, refuses the last few).
    let mut latest_deliverer = None;
    for k in 1..=36u64 {
        let wall = head_slot + k;
        let now = t0 + (k - 1) * SLOT_MS + 11_000;
        let _clock = validator_lifecycle::clock_at(wall);
        // The network's block of this slot arrives by push on its
        // proposer's own connection: parent unknown, parked.
        if let Some(block) = later.next() {
            let id = *block.block_id().as_bytes();
            assert_eq!(engine.ingest_judged(block.clone()), Verdict::Ignore);
            engine.note_orphan_deliverer(&id, Some(1_000 + k));
            if engine.orphans.back().is_some_and(|(parked, ..)| *parked == id) {
                latest_deliverer = Some(1_000 + k);
            }
        }
        assert_eq!(*engine.head_id().as_bytes(), x, "nothing the network builds can be applied");
        // The slot loop, in its own order.
        let behind = node_is_behind(engine.state.slot(), wall, now, last_applied_ms, two_slots);
        let orphaned_head = engine.orphaned_head_evidence(wall);
        assert_eq!(
            orphaned_head,
            wall > head_slot + 1 && orphan_proposers_above_head(&engine) >= ORPHANED_HEAD_MIN_PROPOSERS,
            "slot +{k}: the evidence is a missed slot plus orphans of two distinct proposers",
        );
        if orphaned_head {
            evidence_from.get_or_insert(k);
        }
        let sync_needed = behind || engine.needs_sync || engine.sync_rewind_due(now) || orphaned_head;
        let vote_held = hold.update(orphaned_head, wall);
        let quarantined = gate.update(behind, engine.state.slot(), wall, now, two_slots);
        if sync_needed && now.saturating_sub(last_sync_req) > two_slots {
            let after = engine.sync_request_after_slot(now, two_slots);
            let wire = sync_wire_cursor(after, head_slot);
            assert!(
                wire < boundary_slot,
                "slot +{k}: the request cursor {wire} cannot return the block of slot {boundary_slot}",
            );
            if after < head_slot {
                // A rewind names the latest deliverers, most recent first.
                let preferred = engine.sync_rewind_preferred_peers();
                assert_eq!(preferred.first(), latest_deliverer.as_ref(), "slot +{k}: asked of the peer that last delivered an orphan");
                assert!(latest_deliverer.is_some());
                assert!(preferred.len() <= net::SYNC_PREFERRED_PEERS);
            }
            engine.needs_sync = false;
            last_sync_req = now;
            requests.push((k, after < head_slot, orphaned_head));
        }
        if vote_held {
            held.push(k);
        } else if !quarantined {
            vote_free.push(k);
        }
    }
    println!("requests (slot, rewind, evidence): {requests:?}");
    println!("vote held by the orphaned-head hold: {held:?}; vote free: {vote_free:?}");
    let evidence_from = evidence_from.expect("eight validators: two distinct proposers appear in 35 slots");
    // Every request made while the evidence stands is a rewind: the
    // back-off (8 slots for a new cause, up to 64 for an unchanged one) no
    // longer rations the only request that reaches below the overlap.
    assert!(
        requests.iter().filter(|(_, _, evidence)| *evidence).all(|(_, rewind, _)| *rewind),
        "a rewind was held back on an orphaned head: {requests:?}",
    );
    let rewinds = requests.iter().filter(|(_, rewind, _)| *rewind).count();
    if evidence_from <= 4 {
        assert!(rewinds >= 11, "one rewind per sync cadence, not five in 36 slots: {requests:?}");
    }
    // The vote waits for the first eight slots of evidence, and only those.
    assert_eq!(
        held,
        (evidence_from..evidence_from + ORPHANED_HEAD_HOLD_MAX_SLOTS).collect::<Vec<_>>(),
        "the attestation hold covers the repair window and is rationed",
    );
    assert!(vote_free.iter().all(|k| *k < evidence_from || *k >= evidence_from + ORPHANED_HEAD_HOLD_MAX_SLOTS));

    // One answered request brings the missing block: the parked branch
    // connects, the evidence is gone and nothing is held any more.
    let wall = head_slot + 37;
    let _clock = validator_lifecycle::clock_at(wall);
    assert_eq!(engine.ingest_judged(network[0].clone()), Verdict::Accept);
    while !engine.deferred_orphans.is_empty() {
        engine.release_orphan_turn();
    }
    let mut turns = 0;
    while engine.canonical.contains(&x) && turns < 4 * SIDE_BRANCH_BLOCKS_PER_SLOT {
        engine.validate_side_branch_turn(wall + (turns / SIDE_BRANCH_BLOCKS_PER_SLOT) as u64);
        turns += 1;
    }
    assert!(!engine.canonical.contains(&x), "X is given back once the missing block is there");
    assert!(engine.state.slot() > head_slot + 20);
    assert!(!engine.orphaned_head_evidence(engine.state.slot() + 2), "repaired: no orphans left above the head");
    assert_eq!(engine.sync_rewind.fruitless, 0, "the yield cleared the back-off");
    assert!(!engine.sync_rewind.deliverers.is_empty(), "and kept the peers that hold the branch");
}

/// The evidence cannot be produced by one key, and needs the head to have
/// missed a slot. Without it the P2P-6 back-off is exactly what it was.
#[test]
fn one_proposer_or_a_current_head_is_not_orphaned_head_evidence() {
    let (mut engine, _dir, network, _x) = orphaned_head_fixture(6);
    let head = engine.state.slot();
    const CADENCE: u64 = 1_000;
    // One registered key signs as many orphans as it likes above the head.
    let template = network.iter().find(|b| b.header.slot > head).expect("a network block above the head").clone();
    let minter = template.header.proposer_index;
    for tag in 0..5u8 {
        let mut env = template.clone();
        env.header.slot = head + 1 + u64::from(tag);
        env.header.parent = [0xA0 | tag; 32];
        let id = *env.block_id().as_bytes();
        let proof = AuthenticatedBlockAdmission::new(&env, &[0u8; 32]);
        engine.park_orphan_authenticated(id, env, Source::Gossip(Some([tag; 32])), Some(proof));
    }
    assert_eq!(engine.orphans.len(), 5);
    let _clock = validator_lifecycle::clock_at(head + 10);
    assert!(!engine.orphaned_head_evidence(head + 10), "five orphans of one proposer are one proposer");
    let mut hold = OrphanedHeadHold::default();
    assert!(!hold.update(engine.orphaned_head_evidence(head + 10), head + 10));
    // ... and the rewind they ask for is rationed as before (P2P-6).
    let floor = engine.sync_after_slot();
    assert!(floor < head);
    let mut now = 100_000u64;
    assert_eq!(engine.sync_request_after_slot(now, CADENCE), floor, "first rewind is free");
    now += CADENCE + 1;
    assert_eq!(engine.sync_request_after_slot(now, CADENCE), head, "the fruitless floor is held back");
    assert!(engine.sync_rewind.deferred);
    let held_until = engine.sync_rewind.retry_at_ms;
    assert_eq!(held_until, now + (CADENCE << 1));

    // A second proposer's orphan, but a head that has missed no slot.
    let other = network
        .iter()
        .find(|b| b.header.slot >= head && b.header.proposer_index != minter)
        .expect("fixture: eight validators, two proposers in six slots")
        .clone();
    let id = *other.block_id().as_bytes();
    let proof = AuthenticatedBlockAdmission::new(&other, &[0u8; 32]);
    engine.park_orphan_authenticated(id, other, Source::Gossip(Some([9; 32])), Some(proof));
    assert!(!engine.orphaned_head_evidence(head + 1), "the head is current: an out-of-order arrival, not a stranded node");
    // An unauthenticated orphan of a third index adds nothing either.
    assert!(engine.orphaned_head_evidence(head + 2), "two proposers above a head that missed a slot");
    // With the evidence the held-back rewind goes out at the next request.
    now += 1;
    assert!(now < held_until);
    assert_eq!(engine.sync_request_after_slot(now, CADENCE), floor, "not held back on an orphaned head");
}

#[test]
fn an_unauthenticated_orphan_is_never_orphaned_head_evidence() {
    let (mut engine, _dir, network, _x) = orphaned_head_fixture(6);
    let head = engine.state.slot();
    let above: Vec<&BlockEnvelope> = network.iter().filter(|b| b.header.slot >= head).collect();
    let mut proposers = BTreeSet::new();
    for block in &above {
        proposers.insert(block.header.proposer_index);
        engine.park_orphan(*block.block_id().as_bytes(), (*block).clone(), Source::Gossip(None));
    }
    assert!(proposers.len() >= 2, "fixture: two proposers above the head");
    assert!(!engine.orphaned_head_evidence(head + 5), "nobody's signature was checked");
    assert!(engine.sync_rewind_preferred_peers().is_empty());
    engine.note_orphan_deliverer(above[0].block_id().as_bytes(), Some(7));
    assert!(engine.sync_rewind_preferred_peers().is_empty(), "an unauthenticated orphan names no peer to ask");
}

/// The hold is rationed: forged evidence can delay a vote for at most
/// `ORPHANED_HEAD_HOLD_MAX_SLOTS` wall slots per window.
#[test]
fn the_orphaned_head_hold_is_rationed_per_window() {
    let mut hold = OrphanedHeadHold::default();
    assert!(!hold.update(false, 100));
    let mut held = Vec::new();
    for slot in 101..101 + 3 * ORPHANED_HEAD_HOLD_WINDOW_SLOTS {
        // Several loop turns per slot count once.
        let first = hold.update(true, slot);
        assert_eq!(hold.update(true, slot), first);
        if first {
            held.push(slot);
        }
    }
    let expected: Vec<u64> = (0..3)
        .flat_map(|window| {
            let start = 101 + window * ORPHANED_HEAD_HOLD_WINDOW_SLOTS;
            start..start + ORPHANED_HEAD_HOLD_MAX_SLOTS
        })
        .collect();
    assert_eq!(held, expected);
    // Evidence that comes and goes spends the same ration.
    let mut hold = OrphanedHeadHold::default();
    let mut count = 0;
    for slot in 0..ORPHANED_HEAD_HOLD_WINDOW_SLOTS {
        if hold.update(slot % 2 == 0, slot) {
            count += 1;
        }
        assert!(!hold.update(false, slot));
    }
    assert_eq!(count, ORPHANED_HEAD_HOLD_MAX_SLOTS);
}

#[test]
fn a_head_forward_request_reaches_below_the_head_and_a_rewind_is_sent_as_it_is() {
    assert_eq!(sync_wire_cursor(281_664, 281_664), 281_664 - net::SYNC_HEAD_OVERLAP_SLOTS);
    assert_eq!(sync_wire_cursor(281_700, 281_664), 281_664 - net::SYNC_HEAD_OVERLAP_SLOTS);
    assert_eq!(sync_wire_cursor(281_600, 281_664), 281_600, "a rewind already reaches further back");
    assert_eq!(sync_wire_cursor(281_663, 281_664), 281_663);
    assert_eq!(sync_wire_cursor(2, 2), 0);
    assert_eq!(sync_wire_cursor(0, 0), 0);
}
