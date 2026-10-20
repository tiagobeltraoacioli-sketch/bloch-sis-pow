// Forward-secure (KES) validator keys in the state transition, mainnet line:
// registration (wire 0x17) only inside its window, the static-key rules
// byte-for-byte unchanged while the schedule is unarmed, and from enforcement
// on, proposals and votes that verify only under the leaf of their epoch's
// period over the bound message (audit p8a). Included into the transition
// tests module for its fixtures (`setup_with`, `build_block`, `toy_sign`,
// `ToyVerifier`).
mod kes_rules {
    use super::*;
    use crate::kes::{self, KesPublic, KesSignature};
    use crate::params::KesSchedule;

    const DEPTH: u8 = 4;

    /// Arms a test-only KES schedule on this thread; the compiled (unarmed)
    /// one is back when the guard drops.
    struct Armed;
    impl Armed {
        /// Registration open from `registration`, enforcement from
        /// `activation`, `period_epochs` epochs per period.
        fn at(registration: u64, activation: u64, period_epochs: u64) -> Armed {
            crate::params::kes_rehearsal::set(Some(KesSchedule {
                registration_epoch: registration,
                activation_epoch: activation,
                period_epochs,
                // Toy trees are depth 4; the shipped floor is pinned below.
                min_depth: 1,
            }));
            Armed
        }
        /// Enforcement from `activation` (registration open from genesis).
        fn enforcing(activation: u64, period_epochs: u64) -> Armed {
            Armed::at(0, activation, period_epochs)
        }
    }
    impl Drop for Armed {
        fn drop(&mut self) {
            crate::params::kes_rehearsal::set(None);
        }
    }

    /// A toy KES tree per validator: leaf "keys" are 32-byte seeds and
    /// `ToyVerifier` binds a leaf signature to its key and message.
    fn tree(v: u32) -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
        let mut seed = [0xC3 ^ v as u8; 32];
        let mut pks = Vec::new();
        for _ in 0..(1u32 << DEPTH) {
            pks.push(kes::leaf_seed(&seed).to_vec());
            seed = kes::step(&seed);
        }
        let leaves = pks.iter().map(|pk| kes::leaf_hash(pk)).collect();
        (pks, leaves)
    }

    pub(super) fn toy_kes_public(v: u32) -> KesPublic {
        KesPublic::new(DEPTH, kes::merkle_root(&tree(v).1), 0)
    }

    /// Validator `v`'s toy leaf of `period` signing `message` as given (the
    /// caller decides whether it is bound).
    pub(super) fn toy_kes_sign(v: u32, period: u64, message: &[u8; 32]) -> Vec<u8> {
        let (pks, leaves) = tree(v);
        let p = period as usize;
        KesSignature { index: period as u32, leaf_pk: pks[p].clone(), sig: toy_sign(&pks[p], message), path: kes::auth_path(&leaves, p) }
            .encode()
    }

    /// A toy leaf signature with an explicit leaf list (any tree shape).
    fn sign_in(pks: &[Vec<u8>], period: u64, message: &[u8; 32]) -> Vec<u8> {
        let leaves: Vec<[u8; 32]> = pks.iter().map(|pk| kes::leaf_hash(pk)).collect();
        // Past the last leaf (an expired key's attempt): sign with a real leaf
        // but claim the out-of-tree index, which no verifier may accept.
        let p = period as usize % pks.len();
        KesSignature { index: period as u32, leaf_pk: pks[p].clone(), sig: toy_sign(&pks[p], message), path: kes::auth_path(&leaves, p) }
            .encode()
    }

    fn public_of(pks: &[Vec<u8>]) -> KesPublic {
        let leaves: Vec<[u8; 32]> = pks.iter().map(|pk| kes::leaf_hash(pk)).collect();
        KesPublic::new(leaves.len().trailing_zeros() as u8, kes::merkle_root(&leaves), 0)
    }

    /// What an honest node signs: `kes::leaf_message` for `v` under `public`.
    fn honest(st: &CommittedState, v: u32, public: &KesPublic, pks: &[Vec<u8>], period: u64, root: &[u8; 32]) -> Vec<u8> {
        let message = kes::leaf_message(crate::attestation::KeyLookup::kes_network_domain(st), v, public, period, root)
            .expect("committed state always has a domain");
        // The leaf of `period` under the key's own start (identity at start 0).
        sign_in(pks, period.saturating_sub(public.start_period), &message)
    }

    /// Validator `v`'s own toy tree, honestly signing in `period`.
    fn honest_own(st: &CommittedState, v: u32, period: u64, root: &[u8; 32]) -> Vec<u8> {
        honest(st, v, &toy_kes_public(v), &tree(v).0, period, root)
    }

    fn register(st: &CommittedState, v: u32, public: KesPublic) -> PosTransaction {
        let domain = st.admission_network_domain.unwrap_or([0; 32]);
        let pk = crate::attestation::KeyLookup::pubkey(st, v).expect("registered validator").to_vec();
        PosTransaction::KesRegister {
            validator: v,
            depth: public.depth,
            root: public.root,
            signature: toy_sign(&pk, &kes::register_signing_root(&domain, v, &public)),
        }
    }

    fn apply(st: &mut CommittedState, tx: &PosTransaction) -> Result<(), TxReject> {
        st.apply_transaction(tx, 0, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS, &ToyVerifier).map(|_| ())
    }

    fn relay_check(st: &CommittedState, tx: &PosTransaction) -> Result<(), TxReject> {
        st.validate_lifecycle_transaction(tx, 0, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS, &ToyVerifier)
    }

    fn vote(st: &CommittedState, v: u32, slot: u64, head: u8, signature: impl Fn(&[u8; 32]) -> Vec<u8>) -> Attestation {
        let fin = st.finality_view();
        let data = AttestationData {
            slot,
            head: [head; 32],
            source_epoch: fin.justified.epoch,
            source_root: fin.justified.root,
            target_epoch: crate::epoch_of(slot),
            target_root: [head; 32],
        };
        Attestation { data, validator: v, signature: signature(&data.signing_root()) }
    }

    fn view(st: &CommittedState) -> RegistryView<'_> {
        RegistryView { validators: &st.validators, kes: &st.kes, network_domain: st.admission_network_domain, enforced_from: st.kes_enforced_from }
    }

    /// The state with KES enforcement bound on chain from epoch 0, as the
    /// epoch transition records it once registered stake covers
    /// `KES_MIN_REGISTERED_STAKE_BPS` (tests that pin the binding itself set
    /// it through `close_epoch`).
    fn bound(mut st: CommittedState) -> CommittedState {
        st.kes_enforced_from = Some(0);
        st
    }

    // ── Wire form and registration window ─────────────────────────────────

    #[test]
    fn the_wire_form_round_trips_on_its_own_tag() {
        let tx = PosTransaction::KesRegister { validator: 3, depth: 12, root: [7; 32], signature: vec![9; 40] };
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes[0], 0x17);
        assert_eq!(bytes.len(), 1 + 4 + 1 + 32 + 4 + 40);
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), tx);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PosTransaction::from_canonical_bytes(&trailing).is_err());
    }

    #[test]
    fn the_compiled_schedule_refuses_every_registration_and_changes_nothing() {
        // Mainnet as shipped: registration is unarmed, so a 0x17 in a block is
        // refused exactly as the previous release refused the unknown tag,
        // in consensus and at the relay.
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        for epoch in [0, 1, 4_669, 1 << 32] {
            let mut st = g.clone();
            st.epoch = epoch;
            let root_before = st.state_root();
            let tx = register(&st, 1, toy_kes_public(1));
            assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingNotActive), "epoch {epoch}");
            assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingNotActive), "epoch {epoch}");
            assert!(st.kes_roots().is_empty());
            assert_eq!(st.state_root(), root_before);
        }
    }

    #[test]
    fn registration_is_accepted_only_inside_its_window() {
        let _armed = Armed::at(10, u64::MAX, 90);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        st.epoch = 9;
        let tx = register(&st, 1, toy_kes_public(1));
        assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingNotActive));
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingNotActive), "one epoch early");
        assert!(st.kes_roots().is_empty());
        st.epoch = 10;
        assert_eq!(relay_check(&st, &tx), Ok(()));
        assert_eq!(apply(&mut st, &tx), Ok(()), "the window's first epoch");
        assert_eq!(st.kes_public(1), Some(toy_kes_public(1)));
        // Still open after enforcement, for validators that join later.
        let _later = Armed::at(10, 20, 90);
        st.epoch = 500;
        let tx2 = register(&st, 2, toy_kes_public(2));
        assert_eq!(apply(&mut st, &tx2), Ok(()));
    }

    #[test]
    fn registration_is_authorised_by_the_static_key_and_happens_once() {
        let _armed = Armed::at(0, u64::MAX, 90);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        let root_before = st.state_root();
        let public = toy_kes_public(1);

        // Signed by another validator's key: refused.
        let mut forged = register(&g, 1, public);
        if let PosTransaction::KesRegister { signature, .. } = &mut forged {
            *signature = toy_sign(&[2u8; 8], &kes::register_signing_root(&[0; 32], 1, &public));
        }
        assert_eq!(relay_check(&st, &forged), Err(TxReject::StakingRule));
        assert_eq!(apply(&mut st, &forged), Err(TxReject::StakingRule));
        // Signed for another network: refused.
        let mut foreign = register(&g, 1, public);
        if let PosTransaction::KesRegister { signature, .. } = &mut foreign {
            *signature = toy_sign(&[1u8; 8], &kes::register_signing_root(&[0xEE; 32], 1, &public));
        }
        assert_eq!(apply(&mut st, &foreign), Err(TxReject::StakingRule));
        // Unknown validator and out-of-range depths: refused.
        assert_eq!(
            apply(&mut st, &PosTransaction::KesRegister { validator: 99, depth: DEPTH, root: public.root, signature: vec![0; 8] }),
            Err(TxReject::StakingRule)
        );
        for depth in [0, kes::MAX_DEPTH + 1] {
            let bad = register(&g, 1, KesPublic::new(depth, public.root, 0));
            assert_eq!(apply(&mut st, &bad), Err(TxReject::StakingRule), "depth {depth}");
        }
        // A slashed or exited validator cannot register.
        let mut gone = g.clone();
        gone.validators.get_mut(&3).unwrap().exit_epoch = 0;
        assert_eq!(apply(&mut gone, &register(&g, 3, toy_kes_public(3))), Err(TxReject::StakingRule));
        assert_eq!(st.state_root(), root_before, "refusals change nothing");

        let tx = register(&st, 1, public);
        apply(&mut st, &tx).unwrap();
        assert_eq!(st.kes_public(1), Some(public));
        assert_ne!(st.state_root(), root_before, "a registration is committed state");
        // Once: neither the same nor another root replaces it, in consensus
        // or at the relay.
        let again = register(&st, 1, public);
        let other = register(&st, 1, toy_kes_public(2));
        for tx in [&again, &other] {
            assert_eq!(relay_check(&st, tx), Err(TxReject::StakingRule));
            assert_eq!(apply(&mut st, tx), Err(TxReject::StakingRule));
        }
        assert_eq!(st.kes_public(1), Some(public));
    }

    #[test]
    fn a_block_carrying_a_registration_applies_only_inside_the_window() {
        let (t, g, mut chains) = setup_with(4, ToyVerifier, &[]);
        let tx = register(&g, 2, toy_kes_public(2));
        let txs = std::slice::from_ref(&tx);
        let armed = Armed::at(0, u64::MAX, 90);
        let env = build_block(&t, &g, 1, &[], txs, &mut chains);
        let post = t.compute_post_state(&g, &env, &[], txs).expect("inside the window");
        assert_eq!(post.kes_public(2), Some(toy_kes_public(2)));
        drop(armed);
        // The very same block under the compiled (unarmed) schedule is
        // invalid: a pre-window 0x17 fails the block, as on the old binary.
        assert_eq!(t.compute_post_state(&g, &env, &[], txs).unwrap_err(), TransitionError::Transaction(0));
    }

    #[test]
    fn an_empty_registry_leaves_every_state_root_unchanged() {
        // History before the first registration keeps its roots: the component
        // is only inserted once non-empty.
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut with_one = g.clone();
        with_one.kes.insert(0, toy_kes_public(0).into());
        assert_ne!(g.state_root(), with_one.state_root());
        with_one.kes.clear();
        assert_eq!(g.state_root(), with_one.state_root());
    }

    #[test]
    #[cfg(feature = "local-state-cache")]
    fn the_local_cache_keeps_kes_keys_and_old_caches_keep_their_bytes() {
        let header_for = |state: &CommittedState| BlockHeaderV4 {
            version: BLOCK_VERSION_V4, parent: [0; 32], state_root: state.compute_root(),
            body_root: [0; 32], slot: state.slot, proposer_index: 0,
            randao_reveal: [0; 32], randao_mix: state.randao_mix,
            justified_root: [0; 32], finalized_root: [0; 32],
            attestation_root: [0; 32], coherence_root: [0; 32],
        };
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let plain = g.encode_local_cache().unwrap();
        assert_eq!(plain, g.encode_local_cache_owned_reference().unwrap(), "no KES: the former bytes");
        let mut st = g.clone();
        st.kes.insert(2, toy_kes_public(2).into());
        st.kes.insert(0, kes::KesEntry {
            current: KesPublic::new(DEPTH, toy_kes_public(0).root, 3),
            next: Some(KesPublic::new(DEPTH + 1, [0x5C; 32], 17)),
        });
        let header = header_for(&st);
        st.head = header.id();
        let bytes = st.encode_local_cache().unwrap();
        assert!(bytes.starts_with(&plain), "the KES section is appended");
        let restored = CommittedState::decode_local_cache(&bytes, &header).unwrap();
        assert_eq!(restored, st);
        assert!(CommittedState::decode_local_cache(&bytes, &header_for(&g)).is_err(), "the root covers the keys");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CommittedState::decode_local_cache(&trailing, &header).is_err());
    }

    // ── Unarmed: byte-for-byte the static rules ───────────────────────────

    #[test]
    fn before_enforcement_signatures_are_the_static_ones_even_with_keys_registered() {
        // A registered KES key changes nothing until enforcement: static
        // votes verify, KES-shaped ones do not, and cache fingerprints are
        // exactly SHA3(static key) as before.
        let _armed = Armed::at(0, 1_000, 90);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1).into());
        let slot = 5 * 32 + 3;
        let static_vote = vote(&st, 1, slot, 0xA1, |r| toy_sign(&[1u8; 8], r));
        assert_eq!(crate::attestation::validate(&static_vote, &[1], slot, &ToyVerifier, &view(&st)), Ok(()));
        let kes_vote = vote(&st, 1, slot, 0xA1, |r| honest_own(&st, 1, 0, r));
        assert_eq!(
            crate::attestation::validate(&kes_vote, &[1], slot, &ToyVerifier, &view(&st)),
            Err(crate::attestation::RejectReason::BadSignature)
        );
        let expected: [u8; 32] = Sha3_256::digest([1u8; 8]).into();
        assert_eq!(kes::authority_fingerprint(&view(&st), 1, 5), Some(expected));
        assert_eq!(kes::authority_fingerprint(&view(&st), 99, 5), None);
    }

    #[test]
    fn unarmed_blocks_are_built_and_applied_exactly_as_before() {
        // Replay identity: under the compiled schedule a chain of static-key
        // blocks yields the same post-states whether or not KES code paths
        // exist — here, the same roots with and without a KES map that is
        // populated only in memory (it can never be, unarmed, on chain).
        let (t, g, mut chains) = setup_with(4, ToyVerifier, &[]);
        let mut pre = g.clone();
        let mut roots = Vec::new();
        for slot in 1..=40u64 {
            let env = build_block(&t, &pre, slot, &[], &[], &mut chains);
            pre = t.compute_post_state(&pre, &env, &[], &[]).expect("static chain applies");
            roots.push(pre.state_root());
        }
        assert!(pre.kes_roots().is_empty());
        assert_eq!(kes::verify_validator(&pre, &ToyVerifier, 0, 1, &[5; 32], &toy_sign(&[0u8; 8], &[5; 32])), Some(true));
        assert_eq!(roots.len(), 40);
    }

    // ── Enforcement: votes, proposals, slashing ──────────────────────────

    #[test]
    fn after_enforcement_a_vote_verifies_only_with_its_periods_bound_leaf() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        for v in 0..4 {
            st.kes.insert(v, toy_kes_public(v).into());
        }
        let static_key = |v: u32| vec![v as u8; 8];
        // Epoch 1: before enforcement, the static key signs.
        let early = vote(&st, 1, 40, 0xA1, |r| toy_sign(&static_key(1), r));
        assert_eq!(crate::attestation::validate(&early, &[1], 40, &ToyVerifier, &view(&st)), Ok(()));
        // Epoch 5 is period (5 - 2) / 2 = 1.
        let slot = 5 * 32 + 3;
        let good = vote(&st, 1, slot, 0xA2, |r| honest_own(&st, 1, 1, r));
        assert_eq!(crate::attestation::validate(&good, &[1], slot, &ToyVerifier, &view(&st)), Ok(()));
        let legacy = vote(&st, 1, slot, 0xA2, |r| toy_sign(&static_key(1), r));
        let bare = vote(&st, 1, slot, 0xA2, |r| toy_kes_sign(1, 1, r));
        let wrong_period = vote(&st, 1, slot, 0xA2, |r| honest_own(&st, 1, 0, r));
        let other_tree = vote(&st, 1, slot, 0xA2, |r| honest(&st, 1, &toy_kes_public(1), &tree(2).0, 1, r));
        for (att, why) in [
            (&legacy, "a static-key vote"),
            (&bare, "a leaf over the bare signing root"),
            (&wrong_period, "an erased period"),
            (&other_tree, "another validator's tree"),
        ] {
            assert_eq!(
                crate::attestation::validate(att, &[1], slot, &ToyVerifier, &view(&st)),
                Err(crate::attestation::RejectReason::BadSignature),
                "{why} must not verify after enforcement"
            );
        }
        // A validator that never registered signs nothing valid after enforcement.
        st.kes.remove(&1);
        assert_eq!(
            crate::attestation::validate(&good, &[1], slot, &ToyVerifier, &view(&st)),
            Err(crate::attestation::RejectReason::BadSignature)
        );
        // An exhausted tree signs nothing: epoch 2 + 2·16 is period 16 of a depth-4 tree.
        st.kes.insert(1, toy_kes_public(1).into());
        let late = (2 + 2 * 16) * 32;
        let expired = vote(&st, 1, late, 0xA3, |r| honest_own(&st, 1, 15, r));
        assert_eq!(
            crate::attestation::validate(&expired, &[1], late, &ToyVerifier, &view(&st)),
            Err(crate::attestation::RejectReason::BadSignature)
        );
    }

    #[test]
    fn after_enforcement_fingerprints_commit_to_the_kes_key() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        let none = kes::authority_fingerprint(&view(&st), 1, 5).unwrap();
        let static_only: [u8; 32] = Sha3_256::digest([1u8; 8]).into();
        assert_ne!(none, static_only, "after enforcement the static fingerprint is not reused");
        st.kes.insert(1, toy_kes_public(1).into());
        let with_key = kes::authority_fingerprint(&view(&st), 1, 5).unwrap();
        assert_ne!(with_key, none, "a registration invalidates cached verdicts");
        assert_ne!(with_key, kes::authority_fingerprint(&view(&st), 1, 7).unwrap(), "and so does a new period");
        st.admission_network_domain = Some([0xD1; 32]);
        assert_ne!(with_key, kes::authority_fingerprint(&view(&st), 1, 5).unwrap(), "and the network");
    }

    #[test]
    fn after_enforcement_blocks_need_a_bound_kes_proposer_signature() {
        let _armed = Armed::enforcing(1, 1);
        let (t, g, mut chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut pre = g.clone();
        for v in 0..4 {
            pre.kes.insert(v, toy_kes_public(v).into());
        }
        // `build_block` signs with the toy KES leaf once the period is live.
        let slot = 32 + 1;
        let env = build_block(&t, &pre, slot, &[], &[], &mut chains);
        assert!(t.compute_post_state(&pre, &env, &[], &[]).is_ok(), "a KES-signed proposal applies");

        let p = env.header.proposer_index;
        let mut legacy = env.clone();
        legacy.proposer_sig = toy_sign(&[p as u8; 8], &legacy.header.proposal_signing_root());
        let mut bare = env.clone();
        bare.proposer_sig = toy_kes_sign(p, 0, &bare.header.proposal_signing_root());
        let mut stale = env;
        stale.proposer_sig = honest_own(&pre, p, 1, &stale.header.proposal_signing_root());
        for (bad, why) in [(&legacy, "static key"), (&bare, "bare root"), (&stale, "epoch 1 is period 0, not 1")] {
            assert!(
                matches!(t.compute_post_state(&pre, bad, &[], &[]), Err(TransitionError::Proposal(ProposalReject::BadSignature))),
                "{why}"
            );
        }
    }

    /// The node's producer computes the post-state BEFORE it signs, with an
    /// empty proposer signature and a verifier that accepts every signature
    /// (`ProbeVerifier`). That probe must pass after enforcement too: on
    /// devnet4 (2026-10-14) it did not, and the chain stopped producing.
    #[test]
    fn the_unsigned_producer_probe_still_computes_after_enforcement() {
        struct AcceptAll;
        impl SignatureVerifier for AcceptAll {
            fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool {
                true
            }
            fn verify_kes(&self, _public: &KesPublic, _period: u64, _root: &[u8; 32], _sig: &[u8]) -> bool {
                true
            }
        }
        let _armed = Armed::enforcing(1, 1);
        let (t, g, mut chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut pre = g.clone();
        for v in 0..4 {
            pre.kes.insert(v, toy_kes_public(v).into());
        }
        let mut probe = build_block(&t, &pre, 32 + 1, &[], &[], &mut chains);
        probe.proposer_sig = Vec::new();
        assert!(Transition::new(AcceptAll).compute_post_state(&pre, &probe, &[], &[]).is_ok(), "the probe computes");
        assert!(
            matches!(
                t.compute_post_state(&pre, &probe, &[], &[]),
                Err(TransitionError::Proposal(ProposalReject::BadSignature))
            ),
            "the real verifier still refuses the unsigned block"
        );
    }

    #[test]
    fn equivocation_across_kes_leaves_is_slashable_and_forgeries_are_not() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.kes.insert(3, toy_kes_public(3).into());
        let slot = 4 * 32 + 1; // epoch 4: period 1
        let first = vote(&st, 3, slot, 0xAA, |r| honest_own(&st, 3, 1, r));
        let second = vote(&st, 3, slot, 0xBB, |r| honest_own(&st, 3, 1, r));
        let dels: [crate::delegation::Delegation; 0] = [];
        let mut forged = crate::slashing::SlashingEvidence { first: first.clone(), second: second.clone() };
        forged.second.signature = toy_sign(&[3u8; 8], &forged.second.data.signing_root());
        let mut machine = crate::slashing::SlashingState::new();
        assert_eq!(
            machine.process(&forged, 4, 0, &dels, 1_000_000, 0, &ToyVerifier, &view(&st)).unwrap_err(),
            crate::slashing::EvidenceError::BadSignature,
            "a static-key forgery after enforcement is not evidence"
        );
        let evidence = crate::slashing::SlashingEvidence { first, second };
        assert!(machine.process(&evidence, 4, 0, &dels, 1_000_000, 0, &ToyVerifier, &view(&st)).is_ok());
        assert!(machine.is_ejected(3));
    }

    // ── The p8a binding: what a leaf signature cannot be moved to ─────────

    const SLOT: u64 = 5 * 32 + 3; // epoch 5: period (5 - 2) / 2 = 1 under Armed::enforcing(2, 2)
    const PERIOD: u64 = 1;

    fn validate(st: &CommittedState, att: &Attestation) -> Result<(), crate::attestation::RejectReason> {
        crate::attestation::validate(att, &[att.validator], SLOT, &ToyVerifier, &view(st))
    }

    #[test]
    fn a_lookup_without_a_network_domain_fails_closed() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1).into());
        let good = vote(&st, 1, SLOT, 0xA1, |r| honest_own(&st, 1, PERIOD, r));
        assert_eq!(validate(&st, &good), Ok(()));
        struct NoDomain<'a>(RegistryView<'a>);
        impl crate::attestation::KeyLookup for NoDomain<'_> {
            fn pubkey(&self, v: u32) -> Option<&[u8]> {
                self.0.pubkey(v)
            }
            fn kes_public(&self, v: u32, period: u64) -> Option<KesPublic> {
                self.0.kes_public(v, period)
            }
        }
        assert_eq!(
            kes::verify_validator(&NoDomain(view(&st)), &ToyVerifier, 1, 5, &good.data.signing_root(), &good.signature),
            Some(false)
        );
    }

    #[test]
    fn a_registered_copy_of_anothers_root_cannot_claim_its_votes() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        // Validator 2 registers validator 1's (public) root as its own.
        st.kes.insert(1, toy_kes_public(1).into());
        st.kes.insert(2, toy_kes_public(1).into());
        let mut att = vote(&st, 1, SLOT, 0xA1, |r| honest_own(&st, 1, PERIOD, r));
        assert_eq!(validate(&st, &att), Ok(()), "validator 1's own vote");
        att.validator = 2;
        assert_eq!(validate(&st, &att), Err(crate::attestation::RejectReason::BadSignature));
    }

    #[test]
    fn a_tree_built_around_anothers_leaf_key_cannot_claim_its_votes() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        let (victim, _) = tree(1);
        // Validator 2's tree: its own leaves, with validator 1's public leaf
        // key (visible in any of 1's signatures) at position PERIOD.
        let (mut thief, _) = tree(2);
        thief[PERIOD as usize] = victim[PERIOD as usize].clone();
        st.kes.insert(1, toy_kes_public(1).into());
        st.kes.insert(2, public_of(&thief).into());
        let att = vote(&st, 1, SLOT, 0xA1, |r| honest_own(&st, 1, PERIOD, r));
        let leaf_sig = KesSignature::decode(&att.signature).unwrap().sig;
        let leaves: Vec<[u8; 32]> = thief.iter().map(|pk| kes::leaf_hash(pk)).collect();
        let reframed = KesSignature {
            index: PERIOD as u32,
            leaf_pk: thief[PERIOD as usize].clone(),
            sig: leaf_sig,
            path: kes::auth_path(&leaves, PERIOD as usize),
        };
        assert_eq!(
            validate(&st, &Attestation { validator: 2, signature: reframed.encode(), ..att }),
            Err(crate::attestation::RejectReason::BadSignature)
        );
    }

    #[test]
    fn a_repeated_leaf_signature_cannot_move_to_another_period() {
        // Epochs 4 and 6 are periods 1 and 2 under Armed::enforcing(2, 2);
        // the tree repeats one leaf key at both positions.
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        let (mut pks, _) = tree(3);
        pks[2] = pks[1].clone();
        let public = public_of(&pks);
        st.kes.insert(3, public.into());
        let data = AttestationData { slot: 6 * 32, head: [0xC1; 32], source_epoch: 0, source_root: [0; 32], target_epoch: 6, target_root: [0xC1; 32] };
        // Signed in period 1, re-indexed to position 2 (same key, path of 2).
        let message = kes::leaf_message(Some([0; 32]), 3, &public, 1, &data.signing_root()).unwrap();
        let sig = KesSignature::decode(&sign_in(&pks, 1, &message)).unwrap().sig;
        let leaves: Vec<[u8; 32]> = pks.iter().map(|pk| kes::leaf_hash(pk)).collect();
        let at2 = KesSignature { index: 2, leaf_pk: pks[2].clone(), sig, path: kes::auth_path(&leaves, 2) }.encode();
        assert_eq!(kes::verify_validator(&view(&st), &ToyVerifier, 3, 6, &data.signing_root(), &at2), Some(false));
        // ...while the honest period-2 signature verifies.
        let honest2 = honest(&st, 3, &public, &pks, 2, &data.signing_root());
        assert_eq!(kes::verify_validator(&view(&st), &ToyVerifier, 3, 6, &data.signing_root(), &honest2), Some(true));
    }

    #[test]
    fn a_tree_registered_on_two_networks_does_not_replay_across_them() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut here = g.clone();
        here.admission_network_domain = Some([0xD1; 32]);
        here.kes.insert(1, toy_kes_public(1).into());
        let mut there = here.clone();
        there.admission_network_domain = Some([0xD2; 32]);
        let att = vote(&here, 1, SLOT, 0xA1, |r| honest_own(&here, 1, PERIOD, r));
        assert_eq!(validate(&here, &att), Ok(()));
        assert_eq!(validate(&there, &att), Err(crate::attestation::RejectReason::BadSignature));
    }

    #[test]
    fn another_validators_equivocation_cannot_be_pinned_on_a_root_copier() {
        // Framing through the slashing path: validator 1 equivocates; its two
        // votes, relabelled as validator 2's (which registered 1's root), are
        // not evidence against 2.
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1).into());
        st.kes.insert(2, toy_kes_public(1).into());
        let slot = 4 * 32 + 1; // epoch 4: period 1
        let dels: [crate::delegation::Delegation; 0] = [];
        let sign = |r: &[u8; 32]| honest_own(&st, 1, 1, r);
        let mut first = vote(&st, 1, slot, 0xAA, sign);
        let mut second = vote(&st, 1, slot, 0xBB, sign);
        first.validator = 2;
        second.validator = 2;
        let outcome = crate::slashing::SlashingState::new()
            .process(&crate::slashing::SlashingEvidence { first, second }, 4, 0, &dels, 1_000_000, 0, &ToyVerifier, &view(&st))
            .map(|_| ());
        assert_eq!(outcome.unwrap_err(), crate::slashing::EvidenceError::BadSignature);
    }

    // ── HF3: per-key start period, rotation, expiry ───────────────────────

    /// A toy tree of `depth` from a one-byte seed (distinct from `tree(v)`).
    fn tree_from(seed_byte: u8, depth: u8) -> Vec<Vec<u8>> {
        let mut seed = [seed_byte; 32];
        seed[31] = 0x5E;
        let mut pks = Vec::new();
        for _ in 0..(1u32 << depth) {
            pks.push(kes::leaf_seed(&seed).to_vec());
            seed = kes::step(&seed);
        }
        pks
    }

    /// `KesRotate` for `v` in `period` to the tree `new_pks`, signed by the
    /// leaf of `period` of `signer` (whose public key is `signer_public`).
    fn rotate(
        st: &CommittedState,
        v: u32,
        period: u64,
        signer_public: &KesPublic,
        signer: &[Vec<u8>],
        new_pks: &[Vec<u8>],
    ) -> PosTransaction {
        let new = public_of(new_pks);
        let domain = st.admission_network_domain.unwrap_or([0; 32]);
        let root = kes::rotate_signing_root(&domain, v, period, new.depth, &new.root);
        PosTransaction::KesRotate {
            validator: v,
            period,
            depth: new.depth,
            root: new.root,
            signature: honest(st, v, signer_public, signer, period, &root),
        }
    }

    /// Does `v`'s vote in global `period`, honestly signed by `pks` under
    /// `public`, verify against `st` at `epoch`? (Period epochs = 1 here.)
    fn vote_verifies(st: &CommittedState, v: u32, epoch: u64, public: &KesPublic, pks: &[Vec<u8>], period: u64) -> bool {
        let slot = epoch * 32 + 1;
        let att = vote(st, v, slot, 0xA0 ^ (period as u8), |r| honest(st, v, public, pks, period, r));
        crate::attestation::validate(&att, &[v], slot, &ToyVerifier, &view(st)).is_ok()
    }

    #[test]
    fn the_rotate_wire_form_round_trips_on_its_own_tag() {
        let tx = PosTransaction::KesRotate { validator: 3, period: 9, depth: 12, root: [7; 32], signature: vec![9; 40] };
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes[0], kes::ROTATE_TAG);
        assert_eq!(bytes.len(), 1 + 4 + 8 + 1 + 32 + 4 + 40);
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), tx);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PosTransaction::from_canonical_bytes(&trailing).is_err());
        assert!(PosTransaction::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rotation_is_refused_unarmed_and_before_enforcement() {
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1).into());
        let tx = rotate(&st, 1, 0, &toy_kes_public(1), &tree(1).0, &tree_from(0x51, DEPTH));
        // Compiled schedule: refused as the old binary refused the unknown tag.
        for epoch in [0, 4_669, 1 << 32] {
            st.epoch = epoch;
            let root_before = st.state_root();
            assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingNotActive), "epoch {epoch}");
            assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingNotActive));
            assert_eq!(st.state_root(), root_before);
        }
        // Window open, enforcement not yet: there is no period to sign in.
        let _armed = Armed::at(0, 100, 1);
        st.epoch = 50;
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule));
        assert_eq!(st.kes_roots()[&1], toy_kes_public(1).into());
    }

    #[test]
    fn a_registration_after_enforcement_starts_at_the_next_period() {
        let _armed = Armed::at(0, 10, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        // Before enforcement: start 0.
        st.epoch = 5;
        { let tx = register(&st, 0, toy_kes_public(0)); apply(&mut st, &tx).unwrap(); }
        assert_eq!(st.kes_roots()[&0].current.start_period, 0);
        // Included in period 7 (epoch 17): start 8, leaf 0 signs period 8.
        st.epoch = 17;
        { let tx = register(&st, 1, toy_kes_public(1)); apply(&mut st, &tx).unwrap(); }
        let public = st.kes_roots()[&1].current;
        assert_eq!(public, KesPublic::new(DEPTH, toy_kes_public(1).root, 8));
        let pks = tree(1).0;
        assert!(!vote_verifies(&st, 1, 17, &public, &pks, 7), "nothing signs the inclusion period");
        st.epoch = 18;
        assert!(vote_verifies(&st, 1, 18, &public, &pks, 8));
        // Leaf 0 of the tree is NOT accepted as the leaf of period 0 + 8 under
        // a global index (the devnet rule): the signature carries index 0.
        assert_eq!(KesSignature::decode(&honest(&st, 1, &public, &pks, 8, &[0; 32])).unwrap().index, 0);
    }

    #[test]
    fn keys_registered_at_different_periods_expire_at_different_periods() {
        // Blocker B1: under the global index every depth-4 tree expired at
        // period 16. Per-key start spreads expiry: validator 0 (start 0)
        // expires at 16, validator 1 (start 6) at 22.
        let _armed = Armed::at(0, 10, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.epoch = 5;
        { let tx = register(&st, 0, toy_kes_public(0)); apply(&mut st, &tx).unwrap(); }
        st.epoch = 10 + 5;
        { let tx = register(&st, 1, toy_kes_public(1)); apply(&mut st, &tx).unwrap(); }
        let (k0, k1) = (st.kes_roots()[&0].current, st.kes_roots()[&1].current);
        assert_eq!((k0.end_period(), k1.end_period()), (16, 22));
        for period in 6..30u64 {
            st.epoch = 10 + period;
            assert_eq!(vote_verifies(&st, 0, st.epoch, &k0, &tree(0).0, period), period < 16, "v0 period {period}");
            assert_eq!(vote_verifies(&st, 1, st.epoch, &k1, &tree(1).0, period), period < 22, "v1 period {period}");
        }
    }

    #[test]
    fn auto_rotation_keeps_a_validator_signing_across_many_tree_lifetimes() {
        // 200 periods = 12.5 lifetimes of a depth-4 tree. Validator 1 rotates
        // whenever 3 or fewer periods remain (the node's policy, shrunk);
        // validator 2 never rotates and goes silent at period 16 for good.
        let _armed = Armed::at(0, 10, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.epoch = 5;
        { let tx = register(&st, 1, toy_kes_public(1)); apply(&mut st, &tx).unwrap(); }
        { let tx = register(&st, 2, toy_kes_public(2)); apply(&mut st, &tx).unwrap(); }
        let mut trees: BTreeMap<[u8; 32], Vec<Vec<u8>>> = BTreeMap::new();
        trees.insert(toy_kes_public(1).root, tree(1).0);
        let mut rotations = 0u8;
        let mut roots_seen = std::collections::BTreeSet::new();
        for period in 0..200u64 {
            st.epoch = 10 + period;
            let entry = st.kes_roots()[&1];
            let public = entry.in_force(period);
            roots_seen.insert(public.root);
            let pks = trees[&public.root].clone();
            assert!(vote_verifies(&st, 1, st.epoch, &public, &pks, period), "rotating validator, period {period}");
            assert_eq!(
                vote_verifies(&st, 2, st.epoch, &toy_kes_public(2), &tree(2).0, period),
                period < 16,
                "non-rotating validator, period {period}"
            );
            if public.remaining_periods(period) <= 3 && entry.pending_at(period).is_none() {
                rotations += 1;
                let new_pks = tree_from(rotations, DEPTH);
                trees.insert(public_of(&new_pks).root, new_pks.clone());
                let tx = rotate(&st, 1, period, &public, &pks, &new_pks);
                assert_eq!(relay_check(&st, &tx), Ok(()), "period {period}");
                apply(&mut st, &tx).unwrap();
                let pending = st.kes_roots()[&1].next.expect("pending successor");
                assert_eq!(pending.start_period, period + 1);
                // The current key still signs the rest of this period; the
                // new one does not yet.
                assert!(vote_verifies(&st, 1, st.epoch, &public, &pks, period));
                assert!(!vote_verifies(&st, 1, st.epoch, &pending, &new_pks, period));
            }
        }
        assert!(rotations >= 14, "{rotations} rotations over 200 periods");
        assert_eq!(roots_seen.len(), rotations as usize + 1);
        // The state never holds more than the key in force and one successor.
        assert!(st.kes_roots()[&1].committed_bytes().len() <= 82);
    }

    #[test]
    fn only_the_current_leaf_of_the_key_in_force_can_rotate() {
        let _armed = Armed::at(0, 10, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.epoch = 5;
        { let tx = register(&st, 1, toy_kes_public(1)); apply(&mut st, &tx).unwrap(); }
        let (public, pks) = (toy_kes_public(1), tree(1).0);
        let new_pks = tree_from(0x61, DEPTH);
        let new = public_of(&new_pks);
        st.epoch = 10 + 5; // period 5
        let root_before = st.state_root();

        // The static key cannot rotate (long-range: a key stolen later).
        let domain = st.admission_network_domain.unwrap_or([0; 32]);
        let mut by_static = rotate(&st, 1, 5, &public, &pks, &new_pks);
        if let PosTransaction::KesRotate { signature, .. } = &mut by_static {
            *signature = toy_sign(&[1u8; 8], &kes::rotate_signing_root(&domain, 1, 5, new.depth, &new.root));
        }
        // A leaf of an earlier period (a compromised, already-erased seed):
        // claimed for its own period, or presented for the current one.
        let old_leaf_own_period = rotate(&st, 1, 2, &public, &pks, &new_pks);
        let mut old_leaf_now = rotate(&st, 1, 5, &public, &pks, &new_pks);
        if let PosTransaction::KesRotate { signature, .. } = &mut old_leaf_now {
            let message = kes::leaf_message(Some(domain), 1, &public, 5, &kes::rotate_signing_root(&domain, 1, 5, new.depth, &new.root)).unwrap();
            *signature = sign_in(&pks, 2, &message);
        }
        // A future leaf (whoever holds the seed of period 5 can derive it,
        // but it is not the leaf of period 5).
        let mut future_leaf = old_leaf_now.clone();
        if let PosTransaction::KesRotate { signature, .. } = &mut future_leaf {
            let message = kes::leaf_message(Some(domain), 1, &public, 5, &kes::rotate_signing_root(&domain, 1, 5, new.depth, &new.root)).unwrap();
            *signature = sign_in(&pks, 9, &message);
        }
        // Another validator's leaf, and a leaf over a vote-shaped message.
        let other_validator = rotate(&st, 1, 5, &public, &tree(2).0, &new_pks);
        let mut wrong_message = rotate(&st, 1, 5, &public, &pks, &new_pks);
        if let PosTransaction::KesRotate { signature, .. } = &mut wrong_message {
            *signature = honest(&st, 1, &public, &pks, 5, &new.root);
        }
        for (tx, why) in [
            (&by_static, "static key"),
            (&old_leaf_own_period, "old leaf for its own (past) period"),
            (&old_leaf_now, "old leaf for the current period"),
            (&future_leaf, "future leaf"),
            (&other_validator, "another tree"),
            (&wrong_message, "a leaf signature over another message"),
        ] {
            assert_eq!(relay_check(&st, tx), Err(TxReject::StakingRule), "{why}");
            assert_eq!(apply(&mut st, tx), Err(TxReject::StakingRule), "{why}");
        }
        assert_eq!(st.state_root(), root_before, "refusals change nothing");
        // An unregistered validator has nothing to rotate from.
        let unregistered = rotate(&st, 2, 5, &toy_kes_public(2), &tree(2).0, &new_pks);
        assert_eq!(apply(&mut st, &unregistered), Err(TxReject::StakingRule));
        // Rotating to the very tree in force would reuse its leaves: refused.
        let same = rotate(&st, 1, 5, &public, &pks, &pks);
        assert_eq!(apply(&mut st, &same), Err(TxReject::StakingRule));
        // The honest one applies.
        { let tx = rotate(&st, 1, 5, &public, &pks, &new_pks); apply(&mut st, &tx).unwrap(); }
        assert_eq!(st.kes_roots()[&1].next, Some(KesPublic::new(new.depth, new.root, 6)));
        assert_ne!(st.state_root(), root_before, "a rotation is committed state");
    }

    #[test]
    fn a_compromised_old_tree_cannot_sign_any_period_after_the_rotation() {
        // The attacker steals the seed of period 5 of the old tree (it can
        // derive every LATER leaf of that tree). The validator rotates in
        // period 5. From period 6 on, nothing the attacker holds verifies:
        // votes, proposals' leaves and rotations alike.
        let _armed = Armed::at(0, 10, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.epoch = 5;
        { let tx = register(&st, 1, toy_kes_public(1)); apply(&mut st, &tx).unwrap(); }
        let (old, old_pks) = (toy_kes_public(1), tree(1).0);
        let new_pks = tree_from(0x71, DEPTH);
        st.epoch = 15;
        { let tx = rotate(&st, 1, 5, &old, &old_pks, &new_pks); apply(&mut st, &tx).unwrap(); }
        let new = st.kes_roots()[&1].next.unwrap();
        for period in 6..16u64 {
            st.epoch = 10 + period;
            assert!(!vote_verifies(&st, 1, st.epoch, &old, &old_pks, period), "old tree, period {period}");
            assert!(vote_verifies(&st, 1, st.epoch, &new, &new_pks, period), "new tree, period {period}");
            let hijack = rotate(&st, 1, period, &old, &old_pks, &tree_from(0x72, DEPTH));
            assert_eq!(apply(&mut st, &hijack), Err(TxReject::StakingRule), "old tree cannot rotate in {period}");
        }
        // And the signer of the old tree cannot equivocate on the new key.
        st.epoch = 16;
        let dels: [crate::delegation::Delegation; 0] = [];
        let slot = 16 * 32 + 1;
        let first = vote(&st, 1, slot, 0xAA, |r| honest(&st, 1, &old, &old_pks, 6, r));
        let second = vote(&st, 1, slot, 0xBB, |r| honest(&st, 1, &old, &old_pks, 6, r));
        assert_eq!(
            crate::slashing::SlashingState::new()
                .process(&crate::slashing::SlashingEvidence { first, second }, 16, 0, &dels, 1_000_000, 0, &ToyVerifier, &view(&st))
                .map(|_| ())
                .unwrap_err(),
            crate::slashing::EvidenceError::BadSignature,
            "votes forged with the old tree are not evidence against the validator"
        );
        // The validator's own equivocation under the new key still is.
        let first = vote(&st, 1, slot, 0xAA, |r| honest(&st, 1, &new, &new_pks, 6, r));
        let second = vote(&st, 1, slot, 0xBB, |r| honest(&st, 1, &new, &new_pks, 6, r));
        assert!(crate::slashing::SlashingState::new()
            .process(&crate::slashing::SlashingEvidence { first, second }, 16, 0, &dels, 1_000_000, 0, &ToyVerifier, &view(&st))
            .is_ok());
    }

    #[test]
    fn a_rotation_cannot_be_replayed() {
        let _armed = Armed::at(0, 10, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.epoch = 5;
        { let tx = register(&st, 1, toy_kes_public(1)); apply(&mut st, &tx).unwrap(); }
        { let tx = register(&st, 2, toy_kes_public(2)); apply(&mut st, &tx).unwrap(); }
        let (public, pks) = (toy_kes_public(1), tree(1).0);
        st.epoch = 15; // period 5
        let tx = rotate(&st, 1, 5, &public, &pks, &tree_from(0x81, DEPTH));
        // On another network (same validator, same tree): refused.
        let mut elsewhere = st.clone();
        elsewhere.admission_network_domain = Some([0xEE; 32]);
        assert_eq!(apply(&mut elsewhere, &tx), Err(TxReject::StakingRule), "another network");
        // Moved to another validator: refused.
        let mut moved = tx.clone();
        if let PosTransaction::KesRotate { validator, .. } = &mut moved {
            *validator = 2;
        }
        assert_eq!(apply(&mut st, &moved), Err(TxReject::StakingRule), "another validator");
        // With the new root swapped: refused (the leaf signed the tree).
        let mut swapped = tx.clone();
        if let PosTransaction::KesRotate { root, .. } = &mut swapped {
            root[0] ^= 1;
        }
        assert_eq!(apply(&mut st, &swapped), Err(TxReject::StakingRule), "another new root");
        // Applied once.
        apply(&mut st, &tx).unwrap();
        let after_first = st.state_root();
        // Again in the same period: one rotation per validator per period,
        // even a different, honestly signed one.
        assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingRule));
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule), "same period replay");
        let second = rotate(&st, 1, 5, &public, &pks, &tree_from(0x82, DEPTH));
        assert_eq!(apply(&mut st, &second), Err(TxReject::StakingRule), "second rotation in one period");
        assert_eq!(st.state_root(), after_first);
        // In any later period: refused (signed for period 5 only).
        for period in [6, 7, 20] {
            st.epoch = 10 + period;
            assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule), "replay in period {period}");
        }
        // Rotating back to the tree that was just replaced is refused while
        // it is the key in force, and the successor settles on the next
        // rotation (the old key is dropped).
        st.epoch = 16; // period 6: the successor is in force
        let new_pks = tree_from(0x81, DEPTH);
        let new = st.kes_roots()[&1].in_force(6);
        let onward = rotate(&st, 1, 6, &new, &new_pks, &tree_from(0x83, DEPTH));
        apply(&mut st, &onward).unwrap();
        let entry = st.kes_roots()[&1];
        assert_eq!(entry.current, new, "settled: the first successor is now current");
        assert_eq!(entry.next.unwrap().start_period, 7);
    }

    #[test]
    fn a_block_carrying_a_rotation_applies_only_under_hf3() {
        let (t, g, mut chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut pre = g.clone();
        for v in 0..4 {
            pre.kes.insert(v, toy_kes_public(v).into());
        }
        // Slot 33 is epoch 1, period 0 under Armed::at(0, 1, 1).
        let armed = Armed::at(0, 1, 1);
        let tx = rotate(&pre, 2, 0, &toy_kes_public(2), &tree(2).0, &tree_from(0x91, DEPTH));
        let txs = std::slice::from_ref(&tx);
        let env = build_block(&t, &pre, 32 + 1, &[], txs, &mut chains);
        let post = t.compute_post_state(&pre, &env, &[], txs).expect("inside HF3, period 0");
        assert_eq!(post.kes_roots()[&2].next.map(|k| k.start_period), Some(1));
        assert_ne!(post.state_root(), pre.state_root());
        drop(armed);
        // The very same block with enforcement live but the HF3 transaction
        // gate not yet open (epoch 1 < 5) is invalid on the rotation alone.
        let _gate_closed = Armed::at(5, 1, 1);
        assert_eq!(t.compute_post_state(&pre, &env, &[], txs).unwrap_err(), TransitionError::Transaction(0));
        assert!(t.compute_post_state(&pre, &build_block(&t, &pre, 32 + 2, &[], &[], &mut chains), &[], &[]).is_ok());
    }

    #[test]
    fn the_state_root_commits_the_start_period_and_the_successor() {
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut a = g.clone();
        a.kes.insert(1, KesPublic::new(DEPTH, [1; 32], 0).into());
        let mut b = g.clone();
        b.kes.insert(1, KesPublic::new(DEPTH, [1; 32], 1).into());
        assert_ne!(a.state_root(), b.state_root(), "start period");
        let mut c = a.clone();
        c.kes.insert(1, kes::KesEntry { current: KesPublic::new(DEPTH, [1; 32], 0), next: Some(KesPublic::new(DEPTH, [2; 32], 9)) });
        assert_ne!(a.state_root(), c.state_root(), "pending successor");
    }

    // ── Review HF23 (2026-10-20): F-2 renewal, binding, fallback, rescue ──

    /// Ported from the HF2/HF3 review (`codex/hf23-review-20261020`
    /// fa65a3ac), adapted to this line's state model only where the API
    /// changed: enforcement must be bound on chain (`bound`), keys are
    /// `KesEntry`s, and renewal is tried both as a re-registration and as
    /// the leaf-signed `KesRotate` this line adds. The assertions are the
    /// review's: every key signs its last period, and the set does not lose
    /// the ability to sign in one epoch with no way to renew.
    #[test]
    fn hf23_kes_keys_must_not_all_expire_together_and_must_be_renewable() {
        let _armed = Armed::enforcing(2, 1); // period == epoch - 2
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        for v in 0..4 {
            st.kes.insert(v, toy_kes_public(v).into()); // all registered at different times would not matter
        }
        let last = (1u64 << DEPTH) - 1;
        let root = [0x42u8; 32];
        // Renewal, as an honest node does it in the key's last period: a
        // rotation signed by the last leaf (a re-registration of a live key
        // stays refused: the static key cannot replace a forward-secure one).
        st.epoch = 2 + last;
        let fresh_pks = tree_from(0x5A, DEPTH);
        let rotate_tx = rotate(&st, 0, last, &toy_kes_public(0), &tree(0).0, &fresh_pks);
        let reregister = register(&st, 0, KesPublic::new(DEPTH, [0x5A; 32], 0));
        assert!(apply(&mut st.clone(), &reregister).is_err(), "a live key is never replaced by the static key");
        let renewed = apply(&mut st, &rotate_tx).is_ok();
        let mut alive_last = 0;
        let mut alive_after = 0;
        for v in 0..4u32 {
            // Epoch 2 + p is period p under this schedule.
            let sig = honest_own(&st, v, last, &root);
            if kes::verify_validator(&view(&st), &ToyVerifier, v, 2 + last, &root, &sig) == Some(true) {
                alive_last += 1;
            }
            // One period later: the renewed validator signs with its new
            // tree; the others have no leaf there.
            let after = st.kes_roots()[&v].in_force(last + 1);
            let pks = if v == 0 && renewed { fresh_pks.clone() } else { tree(v).0 };
            let sig = honest(&st, v, &after, &pks, last + 1, &root);
            if kes::verify_validator(&view(&st), &ToyVerifier, v, 2 + last + 1, &root, &sig) == Some(true) {
                alive_after += 1;
            }
        }
        assert_eq!(alive_last, 4, "every key signs its last period");
        assert!(
            alive_after > 0 || renewed,
            "all {alive_last} validators lose the ability to sign in the same epoch and none can renew"
        );
        assert!(renewed && alive_after == 1, "the rotated validator, and only it, signs after the old trees end");
    }

    #[test]
    fn enforcement_binds_only_once_registered_stake_reaches_the_threshold() {
        // Gate at epoch 2, one-epoch periods. Three of four equal validators
        // (75%) registered: the boundary does not bind and every validator
        // keeps signing statically. The fourth registers: the next boundary
        // binds, and from then on registered validators sign only with KES.
        let _armed = Armed::at(0, 2, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        for v in 0..3 {
            let tx = register(&st, v, toy_kes_public(v));
            apply(&mut st, &tx).unwrap();
        }
        while st.epoch < 4 {
            st = st.close_epoch();
        }
        assert_eq!(st.kes_registered_stake_bps(4), 7_500);
        assert_eq!(st.kes_enforced_from(), None, "75% < KES_MIN_REGISTERED_STAKE_BPS");
        let slot = 4 * 32 + 1;
        let static_vote = vote(&st, 1, slot, 0xB1, |r| toy_sign(&[1u8; 8], r));
        assert_eq!(crate::attestation::validate(&static_vote, &[1], slot, &ToyVerifier, &view(&st)), Ok(()));
        let tx = register(&st, 3, toy_kes_public(3));
        apply(&mut st, &tx).unwrap();
        assert_eq!(st.kes_roots()[&3].current.start_period, 0, "not bound yet: starts at period 0");
        let root_before = st.state_root();
        st = st.close_epoch();
        assert_eq!(st.kes_enforced_from(), Some(5));
        assert_ne!(st.state_root(), root_before);
        let slot = 5 * 32 + 1;
        let static_vote = vote(&st, 1, slot, 0xB2, |r| toy_sign(&[1u8; 8], r));
        let kes_vote = vote(&st, 1, slot, 0xB2, |r| honest_own(&st, 1, 3, r));
        assert_eq!(
            crate::attestation::validate(&static_vote, &[1], slot, &ToyVerifier, &view(&st)),
            Err(crate::attestation::RejectReason::BadSignature)
        );
        assert_eq!(crate::attestation::validate(&kes_vote, &[1], slot, &ToyVerifier, &view(&st)), Ok(()));
        // Never cleared, even if coverage later drops.
        st.kes.clear();
        st = st.close_epoch();
        assert_eq!(st.kes_enforced_from(), Some(5));
    }

    #[test]
    fn after_binding_an_unregistered_validator_falls_back_to_its_static_key() {
        let _armed = Armed::enforcing(2, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1).into());
        let slot = 6 * 32 + 1; // period 4
        // Validator 2 never registered: its static key still signs.
        let fallback = vote(&st, 2, slot, 0xC1, |r| toy_sign(&[2u8; 8], r));
        assert_eq!(crate::attestation::validate(&fallback, &[2], slot, &ToyVerifier, &view(&st)), Ok(()));
        assert_eq!(kes::signing_mode(&view(&st), 2, 6), kes::SigningMode::Static);
        // Validator 1 registered: its static key no longer does.
        let not_any_more = vote(&st, 1, slot, 0xC1, |r| toy_sign(&[1u8; 8], r));
        assert_eq!(
            crate::attestation::validate(&not_any_more, &[1], slot, &ToyVerifier, &view(&st)),
            Err(crate::attestation::RejectReason::BadSignature)
        );
        assert_eq!(kes::signing_mode(&view(&st), 1, 6), kes::SigningMode::Kes(4));
        // An EXPIRED registered key does not fall back: it must be rescued.
        let late = 2 + 16 + 1;
        let expired_static = vote(&st, 1, late * 32 + 1, 0xC2, |r| toy_sign(&[1u8; 8], r));
        assert_eq!(
            crate::attestation::validate(&expired_static, &[1], late * 32 + 1, &ToyVerifier, &view(&st)),
            Err(crate::attestation::RejectReason::BadSignature)
        );
        // A lookup that cannot say whether KES binds fails closed.
        assert_eq!(kes::signing_mode(&g.validators, 2, 6), kes::SigningMode::FailClosed);
        assert_eq!(kes::verify_validator(&g.validators, &ToyVerifier, 2, 6, &[0; 32], &toy_sign(&[2u8; 8], &[0; 32])), Some(false));
    }

    #[test]
    fn an_expired_key_can_be_rescued_by_the_static_key_and_a_live_one_cannot() {
        let _armed = Armed::enforcing(2, 1);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let g = bound(g);
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1).into());
        let fresh = public_of(&tree_from(0xA1, DEPTH));
        // Period 10: live, so the static key cannot replace it.
        st.epoch = 12;
        let tx = register(&st, 1, fresh);
        assert_eq!(relay_check(&st, &tx), Err(TxReject::StakingRule));
        assert_eq!(apply(&mut st, &tx), Err(TxReject::StakingRule), "live key");
        // Period 16: the depth-4 key has expired. Rescue starts 2 periods on.
        st.epoch = 2 + 16;
        let tx = register(&st, 1, fresh);
        assert_eq!(relay_check(&st, &tx), Ok(()));
        apply(&mut st, &tx).unwrap();
        let rescued = st.kes_roots()[&1].current;
        assert_eq!(rescued.start_period, 16 + crate::params::KES_RESCUE_DELAY_PERIODS);
        assert!(!vote_verifies(&st, 1, 2 + 17, &rescued, &tree_from(0xA1, DEPTH), 17), "not before its start");
        assert!(vote_verifies(&st, 1, 2 + 18, &rescued, &tree_from(0xA1, DEPTH), 18));
        // Once rescued the key is live again: no second rescue.
        st.epoch = 2 + 18;
        let again = register(&st, 1, public_of(&tree_from(0xA2, DEPTH)));
        assert_eq!(apply(&mut st, &again), Err(TxReject::StakingRule));
    }

    #[test]
    fn the_shipped_schedule_refuses_trees_shallower_than_the_floor() {
        assert_eq!(crate::params::kes_schedule().min_depth, crate::params::KES_MIN_REGISTERED_DEPTH);
        assert!(crate::params::KES_MIN_REGISTERED_DEPTH >= 8);
        let _armed = Armed::at(0, u64::MAX, 90);
        crate::params::kes_rehearsal::set(Some(crate::params::KesSchedule {
            min_depth: crate::params::KES_MIN_REGISTERED_DEPTH,
            ..crate::params::kes_schedule()
        }));
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        let shallow = register(&st, 1, KesPublic::new(crate::params::KES_MIN_REGISTERED_DEPTH - 1, [3; 32], 0));
        assert_eq!(apply(&mut st, &shallow), Err(TxReject::StakingRule));
        let floor = register(&st, 1, KesPublic::new(crate::params::KES_MIN_REGISTERED_DEPTH, [3; 32], 0));
        assert_eq!(apply(&mut st, &floor), Ok(()));
    }

    #[test]
    fn kes_leaves_go_through_the_dedicated_leaf_hook() {
        // `kes::verify` must call `verify_kes_leaf` (canonical, bound form in
        // the node), never the plain `verify_with_key` (review F-1).
        struct LeafOnly;
        impl SignatureVerifier for LeafOnly {
            fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool {
                false
            }
            fn verify_kes_leaf(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
                sig == toy_sign(pk, root).as_slice()
            }
        }
        let public = toy_kes_public(1);
        let message = [0x33; 32];
        let sig = toy_kes_sign(1, 3, &message);
        assert!(kes::verify(&LeafOnly, &public, 3, &message, &sig));
        assert!(!kes::verify(&LeafOnly, &public, 4, &message, &sig));
    }
}
