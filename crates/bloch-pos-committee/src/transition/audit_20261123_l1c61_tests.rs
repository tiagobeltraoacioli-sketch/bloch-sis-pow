// AUDIT-L1L2-20261123 L1C-61: one static-key correction of a registered KES
// tree while KES is not bound, behind
// `params::KES_PREBIND_CORRECTION_ACTIVATION_EPOCH` (inert). Included into
// `kes_rules` for its fixtures.

/// A correction of `v`'s registered tree `replaced` to `public`, signed by
/// the static key for inclusion in `epoch`.
fn correct_for(st: &CommittedState, v: u32, replaced: &KesPublic, public: KesPublic, epoch: u64) -> PosTransaction {
    let domain = st.admission_network_domain.unwrap_or([0; 32]);
    let pk = crate::attestation::KeyLookup::pubkey(st, v).expect("registered validator").to_vec();
    PosTransaction::KesRegister {
        validator: v,
        depth: public.depth,
        root: public.root,
        signature: toy_sign(&pk, &kes::correct_signing_root(&domain, v, epoch, replaced, &public)),
    }
}

/// Validator 1 registered `toy_kes_public(1)` before the bind; the chain is
/// in global period 3 (enforcement schedule from epoch 2, one epoch per
/// period) and the bind is not decided.
fn registered_before_the_bind() -> CommittedState {
    let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
    let mut st = g;
    assert_eq!(st.kes_enforced_from, None);
    st.kes.insert(1, toy_kes_public(1).into());
    st.epoch = 5;
    st
}

#[test]
fn the_kes_prebind_correction_gate_is_inert() {
    assert_eq!(crate::params::KES_PREBIND_CORRECTION_ACTIVATION_EPOCH, u64::MAX);
    for epoch in [0, 7_360, 8_620, 1 << 40, u64::MAX - 1, u64::MAX] {
        assert!(!crate::params::kes_prebind_correction_active(epoch), "epoch {epoch}");
    }
    // As shipped, the mismatch of L1C-61 has no correction: every form of a
    // second registration is refused and nothing in the state moves.
    let _armed = Armed::enforcing(2, 1);
    let mut st = registered_before_the_bind();
    assert!(!st.kes_correction_open(1));
    let fresh = public_of(&tree_from(0xA1, DEPTH));
    let before = st.state_root();
    for tx in [
        correct_for(&st, 1, &toy_kes_public(1), fresh, 5),
        register(&st, 1, fresh),
        register_for(&st, 1, fresh, 5),
    ] {
        assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingRule));
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule));
    }
    assert_eq!(st.state_root(), before);
    assert_eq!(st.kes_public(1), Some(toy_kes_public(1)));
}

#[test]
fn behind_the_gate_the_static_key_corrects_a_registered_tree_once_before_the_bind() {
    let _armed = Armed::enforcing(2, 1);
    let _gate = crate::params::kes_prebind_correction_rehearsal::open();
    let mut st = registered_before_the_bind();
    let registered = toy_kes_public(1);
    let fresh_tree = tree_from(0xA1, DEPTH);
    let fresh = public_of(&fresh_tree);
    assert!(st.kes_correction_open(1));
    assert!(!st.kes_correction_open(2), "never for a validator without a tree");
    let covered_before = st.kes_registered_stake_bps(5);

    // Not a correction: the first-registration messages (a replayed or
    // abandoned registration hex), another epoch, another replaced tree,
    // another validator's key, and the tree that is already registered.
    let other_tree = public_of(&tree_from(0xA2, DEPTH));
    let mut foreign = correct_for(&st, 1, &registered, fresh, 5);
    if let PosTransaction::KesRegister { signature, .. } = &mut foreign {
        *signature = toy_sign(&[2u8; 8], &kes::correct_signing_root(&st.admission_network_domain.unwrap_or([0; 32]), 1, 5, &registered, &fresh));
    }
    let before = st.state_root();
    for (what, tx) in [
        ("legacy registration message", register(&st, 1, fresh)),
        ("epoch-bound registration message", register_for(&st, 1, fresh, 5)),
        ("signed for the previous epoch", correct_for(&st, 1, &registered, fresh, 4)),
        ("signed for the next epoch", correct_for(&st, 1, &registered, fresh, 6)),
        ("signed against another tree", correct_for(&st, 1, &other_tree, fresh, 5)),
        ("signed by another validator", foreign),
        ("the registered tree itself", correct_for(&st, 1, &registered, registered, 5)),
    ] {
        assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingRule), "{what}");
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule), "{what}");
    }
    assert_eq!(st.state_root(), before);

    // The correction, in its own epoch.
    let tx = correct_for(&st, 1, &registered, fresh, 5);
    assert_eq!(relay_check(&st, &tx), Ok(()));
    assert_eq!(apply(&mut st, &tx), Ok(()));
    let corrected = KesPublic::new(fresh.depth, fresh.root, crate::params::KES_CORRECTED_START_PERIOD);
    assert_eq!(st.kes_roots()[&1], kes::KesEntry::from(corrected), "the new tree alone: no successor, no history");
    assert_eq!(st.kes_registered_stake_bps(5), covered_before, "still the same registered stake");
    // The wire form is the registration's.
    assert_eq!(tx.canonical_bytes()[0], 0x17);

    // Once per validator: the corrected tree is never corrected again,
    // neither to a third tree nor back.
    assert!(!st.kes_correction_open(1));
    for epoch in [5, 6, 9] {
        st.epoch = epoch;
        for target in [other_tree, registered] {
            let again = correct_for(&st, 1, &corrected, target, epoch);
            assert_eq!(relay_check(&st, &again), Err(TxReject::StakingRule));
            assert_eq!(apply(&mut st, &again), Err(TxReject::StakingRule));
        }
        // ... and the same signed transaction does not apply twice.
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule));
    }
    assert_eq!(st.kes_roots()[&1], kes::KesEntry::from(corrected));

    // After the bind the corrected tree signs from the leaf of its own
    // start, and the replaced tree signs nothing.
    let st = bound(st);
    assert!(vote_verifies(&st, 1, 2 + 7, &corrected, &fresh_tree, 7));
    assert!(!vote_verifies(&st, 1, 2 + 7, &registered, &tree(1).0, 7));
}

#[test]
fn a_correction_is_closed_once_the_bind_is_decided_and_before_period_one() {
    let _armed = Armed::enforcing(2, 1);
    let _gate = crate::params::kes_prebind_correction_rehearsal::open();
    let registered = toy_kes_public(1);
    let fresh = public_of(&tree_from(0xA1, DEPTH));
    // The bind decided (two epochs ahead), and the bind in force.
    for enforced_from in [7, 5, 0] {
        let mut st = registered_before_the_bind();
        st.kes_enforced_from = Some(enforced_from);
        assert!(!st.kes_correction_open(1), "enforced from {enforced_from}");
        let tx = correct_for(&st, 1, &registered, fresh, 5);
        assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingRule));
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule));
        assert_eq!(st.kes_public_at(1, 0), Some(registered));
    }
    // Global period 0 (and before the schedule counts periods at all): a
    // corrected tree starts at period 1 and would not cover it.
    for epoch in [1, 2] {
        let mut st = registered_before_the_bind();
        st.epoch = epoch;
        assert!(!st.kes_correction_open(1), "epoch {epoch}");
        let tx = correct_for(&st, 1, &registered, fresh, epoch);
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule));
    }
    // A tree that has a successor or a history is not a first tree.
    let mut st = registered_before_the_bind();
    st.kes.get_mut(&1).unwrap().next = Some(KesPublic::new(DEPTH, [9; 32], 6));
    assert!(!st.kes_correction_open(1));
    // A correction that would already be expired at inclusion (depth 4
    // from period 1 ends at period 17).
    let mut st = registered_before_the_bind();
    st.epoch = 2 + 17;
    assert!(st.kes_correction_open(1));
    let tx = correct_for(&st, 1, &registered, fresh, 2 + 17);
    assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule));
    st.epoch = 2 + 16;
    let tx = correct_for(&st, 1, &registered, fresh, 2 + 16);
    assert_eq!(apply(&mut st, &tx), Ok(()));
}

#[test]
fn the_gate_changes_nothing_for_a_first_registration_or_a_rescue() {
    let _armed = Armed::enforcing(2, 1);
    let fresh = public_of(&tree_from(0xA1, DEPTH));
    let outcome = |open: bool| {
        let _gate = open.then(crate::params::kes_prebind_correction_rehearsal::open);
        // First registration of validator 2, before the bind: the legacy
        // message, start period 0; the correction message is not accepted
        // for it.
        let mut st = registered_before_the_bind();
        let first = register(&st, 2, toy_kes_public(2));
        let as_correction = correct_for(&st, 2, &toy_kes_public(2), toy_kes_public(2), 5);
        let refused = apply(&mut st.clone(), &as_correction);
        apply(&mut st, &first).unwrap();
        // Rescue of validator 1's expired tree after the bind.
        let mut late = bound(registered_before_the_bind());
        late.epoch = 2 + 16;
        let rescue = register(&late, 1, fresh);
        apply(&mut late, &rescue).unwrap();
        (refused, st.state_root(), late.state_root(), late.kes_roots()[&1].clone())
    };
    let inert = outcome(false);
    assert_eq!(inert.0, Err(TxReject::StakingRule));
    assert_eq!(outcome(true), inert, "byte for byte the same states");
    assert_eq!(inert.3.current.start_period, 16 + crate::params::KES_RESCUE_DELAY_PERIODS);
    assert_eq!(inert.3.retired.len(), 1, "a rescue keeps the expired key in the history");
}
