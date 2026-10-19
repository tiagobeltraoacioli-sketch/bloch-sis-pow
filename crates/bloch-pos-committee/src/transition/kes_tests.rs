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
        KesPublic { depth: DEPTH, root: kes::merkle_root(&tree(v).1) }
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
        let p = period as usize;
        KesSignature { index: period as u32, leaf_pk: pks[p].clone(), sig: toy_sign(&pks[p], message), path: kes::auth_path(&leaves, p) }
            .encode()
    }

    fn public_of(pks: &[Vec<u8>]) -> KesPublic {
        let leaves: Vec<[u8; 32]> = pks.iter().map(|pk| kes::leaf_hash(pk)).collect();
        KesPublic { depth: leaves.len().trailing_zeros() as u8, root: kes::merkle_root(&leaves) }
    }

    /// What an honest node signs: `kes::leaf_message` for `v` under `public`.
    fn honest(st: &CommittedState, v: u32, public: &KesPublic, pks: &[Vec<u8>], period: u64, root: &[u8; 32]) -> Vec<u8> {
        let message = kes::leaf_message(crate::attestation::KeyLookup::kes_network_domain(st), v, public, period, root)
            .expect("committed state always has a domain");
        sign_in(pks, period, &message)
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
        RegistryView { validators: &st.validators, kes: &st.kes, network_domain: st.admission_network_domain }
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
            let bad = register(&g, 1, KesPublic { depth, root: public.root });
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
        with_one.kes.insert(0, toy_kes_public(0));
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
        st.kes.insert(2, toy_kes_public(2));
        st.kes.insert(0, toy_kes_public(0));
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
        st.kes.insert(1, toy_kes_public(1));
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
        let mut st = g.clone();
        for v in 0..4 {
            st.kes.insert(v, toy_kes_public(v));
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
        st.kes.insert(1, toy_kes_public(1));
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
        let mut st = g.clone();
        let none = kes::authority_fingerprint(&view(&st), 1, 5).unwrap();
        let static_only: [u8; 32] = Sha3_256::digest([1u8; 8]).into();
        assert_ne!(none, static_only, "after enforcement the static fingerprint is not reused");
        st.kes.insert(1, toy_kes_public(1));
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
        let mut pre = g.clone();
        for v in 0..4 {
            pre.kes.insert(v, toy_kes_public(v));
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
        let mut pre = g.clone();
        for v in 0..4 {
            pre.kes.insert(v, toy_kes_public(v));
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
        let mut st = g.clone();
        st.kes.insert(3, toy_kes_public(3));
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
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1));
        let good = vote(&st, 1, SLOT, 0xA1, |r| honest_own(&st, 1, PERIOD, r));
        assert_eq!(validate(&st, &good), Ok(()));
        struct NoDomain<'a>(RegistryView<'a>);
        impl crate::attestation::KeyLookup for NoDomain<'_> {
            fn pubkey(&self, v: u32) -> Option<&[u8]> {
                self.0.pubkey(v)
            }
            fn kes_public(&self, v: u32) -> Option<KesPublic> {
                self.0.kes_public(v)
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
        let mut st = g.clone();
        // Validator 2 registers validator 1's (public) root as its own.
        st.kes.insert(1, toy_kes_public(1));
        st.kes.insert(2, toy_kes_public(1));
        let mut att = vote(&st, 1, SLOT, 0xA1, |r| honest_own(&st, 1, PERIOD, r));
        assert_eq!(validate(&st, &att), Ok(()), "validator 1's own vote");
        att.validator = 2;
        assert_eq!(validate(&st, &att), Err(crate::attestation::RejectReason::BadSignature));
    }

    #[test]
    fn a_tree_built_around_anothers_leaf_key_cannot_claim_its_votes() {
        let _armed = Armed::enforcing(2, 2);
        let (_t, g, _chains) = setup_with(4, ToyVerifier, &[]);
        let mut st = g.clone();
        let (victim, _) = tree(1);
        // Validator 2's tree: its own leaves, with validator 1's public leaf
        // key (visible in any of 1's signatures) at position PERIOD.
        let (mut thief, _) = tree(2);
        thief[PERIOD as usize] = victim[PERIOD as usize].clone();
        st.kes.insert(1, toy_kes_public(1));
        st.kes.insert(2, public_of(&thief));
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
        let mut st = g.clone();
        let (mut pks, _) = tree(3);
        pks[2] = pks[1].clone();
        let public = public_of(&pks);
        st.kes.insert(3, public);
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
        let mut here = g.clone();
        here.admission_network_domain = Some([0xD1; 32]);
        here.kes.insert(1, toy_kes_public(1));
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
        let mut st = g.clone();
        st.kes.insert(1, toy_kes_public(1));
        st.kes.insert(2, toy_kes_public(1));
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
}
