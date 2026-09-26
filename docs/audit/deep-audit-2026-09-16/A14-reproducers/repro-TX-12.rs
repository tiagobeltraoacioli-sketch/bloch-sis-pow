// SPDX-License-Identifier: AGPL-3.0-or-later
//
// repro-TX-12.rs — independent reproduction for finding TX-12 / H-R7-1:
// "Every RANDAO chain is terminal; the first exhaustions (~2027-02) start
// removing proposers permanently."
//
// NOT RUN by the reviewer (build lock held). Two parts:
//
//   PART A — in-crate tests. Paste into the `mod tests` block of
//            crates/bloch-pos-committee/src/transition.rs (next to
//            `below_the_gate_a_perfectly_signed_recommit_is_consensus_invalid`,
//            ~line 9990). They use the module's private fixture helpers
//            (`setup`, `build_block`, `signed_recommit`, `ToyVerifier`) and the
//            private `CommittedState::reveals_used` map, exactly like the
//            existing H-R7-1 tests do.
//
//   PART B — integration test using ONLY public exports. Drop into
//            crates/bloch-pos-committee/tests/tx12_randao_terminal.rs.
//
// Evidence lines referenced:
//   params.rs:153        RANDAO_CHAIN_LENGTH = 8_192
//   params.rs:1517       RANDAO_RECOMMIT_ACTIVATION_EPOCH = u64::MAX
//   params.rs:1995-1997  epoch_gate_active(_, u64::MAX) == false, always
//   params.rs:2000-2004  const-assert ties the gate to the whole ADR-041 bundle
//   beacon.rs:220-222    is_exhausted: reveals_used >= 8192
//   beacon.rs:238-240    verify_and_advance: ChainExhausted checked BEFORE hash
//   transition.rs:5580-5601  step 5: process_reveal on every block; Err -> BadRandaoReveal
//   transition.rs:3536-3547  RandaoRecommit arm: StakingNotActive below the gate
//   sample.rs:75-76      draw filters only effective_stake > 0 (exhaustion ignored)
//   engine.rs:1877-1882  node refuses to build when its chain is spent

// ═══════════════════════════════════════════════════════════════════════════
// PART A — in-crate (transition.rs `mod tests`)
// ═══════════════════════════════════════════════════════════════════════════

/// A1. A validator whose committed chain is spent can never again produce a
/// valid block, even though the sortition keeps drawing it: the slot is lost,
/// not reassigned.  This is the "removing proposers permanently" half.
#[test]
fn tx12_a_spent_chain_is_terminal_and_the_slot_is_lost() {
    // Control: gate NOT opened (no rehearsal guard) — this is today's fleet.
    let (t, mut g, mut chains) = setup(4);

    // Find a slot in epoch 0 and its drawn proposer (seed-dependent, so scan).
    let roster = g.consensus_roster_at(g.epoch);
    let seed = g.seed_for_epoch(g.epoch);
    let s = 1u64;
    let victim = schedule::proposer(&seed, s, &roster).expect("4 validators: a proposer exists");

    // Exhaust the victim's COMMITTED chain — the only state every node agrees on.
    g.reveals_used.insert(victim, crate::params::RANDAO_CHAIN_LENGTH);

    // (i) The draw does not care: sample() filters on effective_stake only.
    let roster_after = g.consensus_roster_at(g.epoch);
    assert_eq!(
        schedule::proposer(&seed, s, &roster_after),
        Some(victim),
        "sortition must still draw the spent validator (sample.rs:75-76 ignores exhaustion)",
    );

    // (ii) A block whose reveal WOULD open the committed head is still refused:
    // the client-side chain is untouched so `next_reveal()` yields the true
    // preimage of the committed c_0, and exhaustion is checked before the hash.
    let b = build_block(&t, &g, s, &[], &[], &mut chains);
    assert_eq!(b.header.proposer_index, victim);
    assert_eq!(
        t.apply_block(&g, &b, &[], &[]).err(),
        Some(TransitionError::Proposal(ProposalReject::BadRandaoReveal)),
        "a spent chain must reject every reveal, including the correct preimage",
    );

    // (iii) The ONLY reset path is consensus-refused at every reachable epoch.
    let fresh = RandaoChain::generate([0xD7; 32]);
    let mut probe = g.clone();
    assert_eq!(
        probe.apply_transaction(
            &signed_recommit(victim, 0, fresh.commitment()),
            0,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            &ToyVerifier,
        ),
        Err(TxReject::StakingNotActive),
        "RandaoRecommit is StakingNotActive while the gate is u64::MAX",
    );
    // …and a block from ANOTHER proposer carrying it is invalid as a whole.
    let other = (1..crate::params::SLOTS_PER_EPOCH)
        .find(|&s2| schedule::proposer(&seed, s2, &roster_after) != Some(victim))
        .expect("some slot has a different proposer");
    let txs = vec![signed_recommit(victim, crate::epoch_of(other), fresh.commitment())];
    let carrier = build_block(&t, &g, other, &[], &txs, &mut chains);
    assert_eq!(
        t.apply_block(&g, &carrier, &[], &txs).err(),
        Some(TransitionError::Transaction(0)),
        "no block on today's rules can carry the renewal",
    );

    // (iv) The gate stays shut at the exhaustion epoch and at the u64 ceiling.
    assert!(!crate::params::epoch_gate_active(16_384, crate::params::RANDAO_RECOMMIT_ACTIVATION_EPOCH));
    assert!(!crate::params::epoch_gate_active(u64::MAX - 1, crate::params::RANDAO_RECOMMIT_ACTIVATION_EPOCH));
}

/// A2. When every chain is spent, NO slot of an epoch can carry a valid block
/// — so even a later flag day could not be reached by consensus (epoch gates
/// read `self.epoch`, which advances only through applied blocks) and no
/// block exists to carry a re-commit.  This is the "fleet stops proposing"
/// half; on mainnet all 64 validators share one stake (2.5e12 sat each,
/// genesis/mainnet.manifest), so their exhaustions cluster within ~2 weeks.
#[test]
fn tx12_when_every_chain_is_spent_no_block_can_exist() {
    let (t, mut g, mut chains) = setup(4);
    for v in 0..4u32 {
        g.reveals_used.insert(v, crate::params::RANDAO_CHAIN_LENGTH);
    }
    // Every slot of epoch 1 (rolling over one boundary on the way).
    let first = crate::params::SLOTS_PER_EPOCH;
    for slot in first..(2 * first) {
        let b = build_block(&t, &g, slot, &[], &[], &mut chains);
        assert_eq!(
            t.apply_block(&g, &b, &[], &[]).err(),
            Some(TransitionError::Proposal(ProposalReject::BadRandaoReveal)),
            "slot {slot}: with all chains spent no proposer can produce a valid block",
        );
    }
}

/// A3. Positive control (mirrors the existing end-to-end test): with the gate
/// forced open, the same renewal IS accepted and the victim proposes again —
/// proving the ONLY thing standing between the fleet and recovery is the
/// inert constant plus a coordinated rebuild.
#[test]
fn tx12_control_gate_open_recovers() {
    let _open = crate::params::rehearsal::randao_recommit_gate_open_guard();
    let (t, mut g, mut chains) = setup(4);
    let roster = g.consensus_roster_at(g.epoch);
    let seed = g.seed_for_epoch(g.epoch);
    let (s1, carrier_p) = (1..crate::params::SLOTS_PER_EPOCH)
        .map(|s| (s, schedule::proposer(&seed, s, &roster).unwrap()))
        .next()
        .unwrap();
    let (s2, victim) = ((s1 + 1)..crate::params::SLOTS_PER_EPOCH)
        .map(|s| (s, schedule::proposer(&seed, s, &roster).unwrap()))
        .find(|(_, p)| *p != carrier_p)
        .expect("a second proposer exists in the epoch");
    g.reveals_used.insert(victim, crate::params::RANDAO_CHAIN_LENGTH);
    let fresh = RandaoChain::generate([0xD7; 32]);
    let txs = vec![signed_recommit(victim, crate::epoch_of(s1), fresh.commitment())];
    let b1 = build_block(&t, &g, s1, &[], &txs, &mut chains);
    let after = t.apply_block(&g, &b1, &[], &txs).expect("carrier applies with the gate open");
    chains[victim as usize] = fresh;
    let b2 = build_block(&t, &after, s2, &[], &[], &mut chains);
    assert!(t.apply_block(&after, &b2, &[], &[]).is_ok(), "renewed validator proposes again");
}

// ═══════════════════════════════════════════════════════════════════════════
// PART B — public API only (tests/tx12_randao_terminal.rs)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(any())] // placeholder so PART B does not compile inside PART A's module
mod part_b {
    use bloch_pos_committee::params::{
        epoch_gate_active, RANDAO_RECOMMIT_ACTIVATION_EPOCH, SLOTS_PER_EPOCH, SLOT_DURATION_SECS,
    };
    use bloch_pos_committee::{process_reveal, BeaconError, RandaoChain, RevealState, RANDAO_CHAIN_LENGTH};

    /// B1. The beacon itself: after exactly 8,192 accepted reveals the chain
    /// rejects every value forever (ChainExhausted, checked before the hash).
    #[test]
    fn tx12_beacon_chain_is_terminal_after_8192_reveals() {
        let seed = [0x42u8; 32];
        let mut chain = RandaoChain::generate(seed);
        let mut state = RevealState::register(chain.commitment());
        let mut mix = [0u8; 32];
        for i in 0..RANDAO_CHAIN_LENGTH {
            assert!(!state.is_exhausted(), "exhausted too early at {i}");
            let r = chain.next_reveal().expect("reveal available");
            let (s, m) = process_reveal(&state, &mix, &r).expect("reveal opens the head");
            state = s;
            mix = m;
        }
        assert!(state.is_exhausted());
        assert_eq!(chain.next_reveal(), None, "validator side has nothing left");
        assert_eq!(state.commitment, seed, "the head is now the seed: no committed preimage exists");
        for probe in [[0u8; 32], seed, chain.commitment()] {
            assert_eq!(process_reveal(&state, &mix, &probe), Err(BeaconError::ChainExhausted));
        }
        // The only reset is `recommit`, which consensus never calls today:
        assert_eq!(state.recommit([9u8; 32]).reveals_used, 0);
    }

    /// B2. The gate is inert at every epoch the chain can ever reach.
    #[test]
    fn tx12_recommit_gate_is_inert_forever() {
        assert_eq!(RANDAO_RECOMMIT_ACTIVATION_EPOCH, u64::MAX);
        for e in [0u64, 3_065, 16_384, 20_000, u64::MAX - 1, u64::MAX] {
            assert!(!epoch_gate_active(e, RANDAO_RECOMMIT_ACTIVATION_EPOCH), "epoch {e}");
        }
    }

    /// B3. The deadline, derived from genesis/mainnet.manifest (decoded by the
    /// reviewer: genesis_time_ms = 1_786_656_679_962, slot_ms = 30_000,
    /// 64 validators, every stake 2_500_000_000_000 sat, cohort = all 64).
    /// Equal stake => each validator is drawn for 1/64 of slots; 8,192
    /// proposals therefore take 8_192 * 64 slots = epoch 16,384 if every slot
    /// is filled — i.e. 2027-02-11T22:35:19Z. Today (2026-09-16, epoch ≈3,065)
    /// each validator has consumed at most ≈1,530 (18.7%) of its 8,192.
    #[test]
    fn tx12_first_exhaustion_date_from_manifest_arithmetic() {
        const GENESIS_MS: u64 = 1_786_656_679_962;
        const VALIDATORS: u64 = 64;
        assert_eq!(SLOT_DURATION_SECS, 30);
        assert_eq!(SLOTS_PER_EPOCH, 32);
        let slots_to_exhaust = u64::from(RANDAO_CHAIN_LENGTH) * VALIDATORS; // 524_288
        let epoch = slots_to_exhaust / SLOTS_PER_EPOCH; // 16_384
        assert_eq!(epoch, 16_384);
        let unix = GENESIS_MS / 1000 + slots_to_exhaust * SLOT_DURATION_SECS;
        assert_eq!(unix, 1_802_385_319, "2027-02-11T22:35:19Z");
        // Order statistics over 64 identical Binomial(524288, 1/64) walks
        // (sigma ≈ 90 proposals ≈ 4.8 days): earliest ≈ 2027-02-06, latest
        // ≈ 2027-02-16 — the whole fleet halts inside ~2 weeks, not "one by
        // one over years". Missed slots stretch the date proportionally.
    }
}
