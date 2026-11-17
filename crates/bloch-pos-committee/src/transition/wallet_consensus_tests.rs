// GIP-0002, WT-03: network-bound transfer signing behind a dual-acceptance
// window (`params::SIGHASH_NETWORK_BINDING_ACCEPT_EPOCH` ..
// `params::SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH`). Included into the
// transition tests module for its fixtures (`setup_funded`, `build_block`,
// `transfer_spending`, `toy_sign`, `ToyVerifier`). The delegation half
// (WT-04) is tested next to the funded-delegation fixtures.
mod network_bound_transfers {
    use super::*;
    use crate::params::{wallet_consensus_rehearsal, DualAcceptanceGate};
    use std::cell::RefCell;

    const NET_A: [u8; 32] = [0xA1; 32];
    const NET_B: [u8; 32] = [0xB2; 32];
    /// Rehearsal window used below: accepted from 2, enforced from 4.
    const ACCEPT: u64 = 2;
    const ENFORCE: u64 = 4;

    /// Re-sign every V1 input under `owner` over `root`.
    fn sign_over(tx: &mut PosTransaction, owner: &[u8], root: &[u8; 32]) {
        match tx {
            PosTransaction::Transfer { inputs, .. } => {
                for i in inputs.iter_mut() {
                    i.signature = toy_sign(owner, root);
                }
            }
            PosTransaction::TransferV2 { keys, .. } => {
                for k in keys.iter_mut() {
                    k.signature = toy_sign(&k.pubkey.clone(), root);
                }
            }
            _ => panic!("not a transfer"),
        }
    }

    /// One coin of `alice`, a state on `network` at `epoch`, and the same
    /// transfer signed over the legacy root and over `network`'s bound root.
    fn pair_at(epoch: u64, network: Option<[u8; 32]>) -> (CommittedState, PosTransaction, PosTransaction, u128) {
        let alice = owner_key(0x91);
        let coin = opening(0x9A, 0, 50_000_000, &alice);
        let (_t, mut g, _c) = setup_funded(4, &[coin.clone()]);
        g.admission_network_domain = network;
        g.epoch = epoch;
        let price = g.next_base_fee();
        let legacy = transfer_spending(std::slice::from_ref(&coin), &alice, script_of(&owner_key(0x92)), 512, 1, price);
        let mut bound = legacy.clone();
        let root = bound.network_bound_signing_root(&network.unwrap_or(NET_A));
        sign_over(&mut bound, &alice, &root);
        (g, legacy, bound, price)
    }

    fn applies(g: &CommittedState, tx: &PosTransaction, price: u128) -> Result<(), TransferReject> {
        g.clone().apply_transfer(tx, price, &ToyVerifier).map(|_| ())
    }

    /// TRIPWIRE. Both ends of the window ship `u64::MAX`. Arming either is
    /// an owner decision with a wallet-facing announcement (GIP-0002).
    #[cfg(not(feature = "wallet-consensus-rehearsal"))]
    #[test]
    fn sighash_network_binding_window_is_inert() {
        assert_eq!(crate::params::SIGHASH_NETWORK_BINDING_ACCEPT_EPOCH, u64::MAX);
        assert_eq!(crate::params::SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH, u64::MAX);
        assert_eq!(crate::params::SIGHASH_NETWORK_BINDING_GATE, DualAcceptanceGate::INERT);
        assert_eq!(crate::params::sighash_network_binding_gate(), DualAcceptanceGate::INERT);
        for epoch in [0, 1, 4_669, 8_620, u64::MAX - 1, u64::MAX] {
            assert!(!DualAcceptanceGate::INERT.accepted(epoch));
            assert!(!DualAcceptanceGate::INERT.enforced(epoch));
        }
    }

    #[test]
    fn a_dual_acceptance_gate_reads_each_end_and_treats_max_as_never() {
        let gate = DualAcceptanceGate { accept_epoch: 10, enforce_epoch: 100 };
        assert!(!gate.accepted(9) && gate.accepted(10) && gate.accepted(u64::MAX));
        assert!(!gate.enforced(99) && gate.enforced(100) && gate.enforced(u64::MAX));
        // Acceptance alone: the new form is valid, the old one never refused.
        let open = DualAcceptanceGate { accept_epoch: 10, enforce_epoch: u64::MAX };
        assert!(open.accepted(u64::MAX) && !open.enforced(u64::MAX));
        // Enforcement implies acceptance, so no schedule requires a form it
        // does not accept.
        let forced = DualAcceptanceGate { accept_epoch: u64::MAX, enforce_epoch: 7 };
        assert!(!forced.accepted(6) && forced.accepted(7));
        // Coherence: enforcement needs acceptance `window` epochs earlier.
        assert!(DualAcceptanceGate::INERT.coherent(90));
        assert!(open.coherent(90));
        assert!(DualAcceptanceGate { accept_epoch: 10, enforce_epoch: 100 }.coherent(90));
        assert!(!DualAcceptanceGate { accept_epoch: 11, enforce_epoch: 100 }.coherent(90));
        assert!(!forced.coherent(0));
        assert!(!DualAcceptanceGate { accept_epoch: 100, enforce_epoch: 10 }.coherent(0));
    }

    /// While the window is unset, a state with a domain and a state without
    /// one offer the legacy root alone at every epoch: nothing about the
    /// rule moved.
    #[test]
    fn with_the_window_unset_only_the_legacy_root_exists() {
        let (_g, legacy, _bound, _price) = pair_at(0, Some(NET_A));
        let base = legacy.spend_signing_root();
        for epoch in [0, 1, 4_669, 8_620, u64::MAX - 1, u64::MAX] {
            for domain in [None, Some(&NET_A)] {
                assert_eq!(
                    legacy.spend_signing_roots_for_network(epoch, domain),
                    Some(SpendSigningRoots::legacy(base)),
                    "epoch {epoch}"
                );
                assert_eq!(legacy.checked_signing_root_for_network(epoch, domain), Some(base));
            }
        }
    }

    /// Records every verification the transition asks for.
    struct Recording<'a>(&'a RefCell<Vec<(Vec<u8>, [u8; 32])>>);
    impl SignatureVerifier for Recording<'_> {
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            self.0.borrow_mut().push((pk.to_vec(), *root));
            ToyVerifier.verify_with_key(pk, root, sig)
        }
    }

    /// **Unset means unchanged, down to the verifier calls.** With the
    /// window unset a transfer costs one verification per input, each over
    /// the legacy root, in input order, stopping at the first failure: the
    /// loop this rule replaced.
    #[test]
    fn with_the_window_unset_the_verifier_sees_the_historical_call_sequence() {
        let alice = owner_key(0x91);
        let coins = [
            opening(0x9A, 0, 50_000_000, &alice),
            opening(0x9B, 0, 60_000_000, &alice),
            opening(0x9C, 0, 70_000_000, &alice),
        ];
        let (_t, mut g, _c) = setup_funded(4, &coins);
        g.admission_network_domain = Some(NET_A);
        let price = g.next_base_fee();
        let tx = transfer_spending(&coins, &alice, script_of(&owner_key(0x92)), 512, 1, price);
        let base = tx.spend_signing_root();

        let calls = RefCell::new(Vec::new());
        assert!(g.clone().apply_transfer(&tx, price, &Recording(&calls)).is_ok());
        assert_eq!(*calls.borrow(), vec![(alice.clone(), base); 3]);

        // A bad second signature: two calls, then the refusal.
        let mut bad = tx.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut bad {
            inputs[1].signature[0] ^= 1;
        }
        calls.borrow_mut().clear();
        assert_eq!(
            g.clone().apply_transfer(&bad, price, &Recording(&calls)).map(|_| ()),
            Err(TransferReject::BadSignature)
        );
        assert_eq!(*calls.borrow(), vec![(alice.clone(), base); 2]);

        // And the bound root is not a root at all while the window is unset.
        let mut bound = tx.clone();
        sign_over(&mut bound, &alice, &tx.network_bound_signing_root(&NET_A));
        assert_eq!(applies(&g, &bound, price), Err(TransferReject::BadSignature));
    }

    /// The window, epoch by epoch, at the transfer seam: one epoch before
    /// acceptance, at it, the last epoch before enforcement, at it, after.
    #[test]
    fn each_root_is_valid_exactly_inside_its_side_of_the_window() {
        let _armed = wallet_consensus_rehearsal::arm_sighash(ACCEPT, ENFORCE);
        for (epoch, legacy_ok, bound_ok) in [
            (ACCEPT - 1, true, false),
            (ACCEPT, true, true),
            (ENFORCE - 1, true, true),
            (ENFORCE, false, true),
            (ENFORCE + 1, false, true),
        ] {
            let (g, legacy, bound, price) = pair_at(epoch, Some(NET_A));
            let verdict = |ok: bool| if ok { Ok(()) } else { Err(TransferReject::BadSignature) };
            assert_eq!(applies(&g, &legacy, price), verdict(legacy_ok), "legacy root at epoch {epoch}");
            assert_eq!(applies(&g, &bound, price), verdict(bound_ok), "bound root at epoch {epoch}");
            // The deduplicated format shares the rule.
            let (legacy_v2, bound_v2) = (v2_twin_of(&legacy), v2_twin_of(&bound));
            let applies_v2 = |tx: &PosTransaction| g.clone().apply_transfer_v2(tx, price, &ToyVerifier).map(|_| ());
            assert_eq!(applies_v2(&legacy_v2), verdict(legacy_ok), "V2 legacy root at epoch {epoch}");
            assert_eq!(applies_v2(&bound_v2), verdict(bound_ok), "V2 bound root at epoch {epoch}");
            // Either way the transaction, and so its outputs, has one id.
            assert_eq!(legacy.txid(), bound.txid());
            assert_eq!(legacy.txid(), bound_v2.txid());
        }
    }

    /// Inside the window a transfer is authorised under ONE root, named by
    /// its first witness. Mixed witnesses are refused in both orders, and a
    /// legacy-signed transfer costs exactly one extra verification.
    #[test]
    fn inside_the_window_one_root_authorises_the_whole_transfer() {
        let _armed = wallet_consensus_rehearsal::arm_sighash(ACCEPT, ENFORCE);
        let alice = owner_key(0x91);
        let coins = [opening(0x9A, 0, 50_000_000, &alice), opening(0x9B, 0, 60_000_000, &alice)];
        let (_t, mut g, _c) = setup_funded(4, &coins);
        g.admission_network_domain = Some(NET_A);
        g.epoch = ACCEPT;
        let price = g.next_base_fee();
        let legacy = transfer_spending(&coins, &alice, script_of(&owner_key(0x92)), 512, 1, price);
        let base = legacy.spend_signing_root();
        let bound_root = legacy.network_bound_signing_root(&NET_A);
        let mut bound = legacy.clone();
        sign_over(&mut bound, &alice, &bound_root);

        for (first, second) in [(&bound_root, &base), (&base, &bound_root)] {
            let mut mixed = legacy.clone();
            if let PosTransaction::Transfer { inputs, .. } = &mut mixed {
                inputs[0].signature = toy_sign(&alice, first);
                inputs[1].signature = toy_sign(&alice, second);
            }
            assert_eq!(applies(&g, &mixed, price), Err(TransferReject::BadSignature));
        }

        let calls = RefCell::new(Vec::new());
        assert!(g.clone().apply_transfer(&bound, price, &Recording(&calls)).is_ok());
        assert_eq!(*calls.borrow(), vec![(alice.clone(), bound_root); 2], "bound: no extra verification");
        calls.borrow_mut().clear();
        assert!(g.clone().apply_transfer(&legacy, price, &Recording(&calls)).is_ok());
        assert_eq!(
            *calls.borrow(),
            vec![(alice.clone(), bound_root), (alice.clone(), base), (alice.clone(), base)],
            "legacy: the first witness is asked about the bound root once"
        );
    }

    /// **The replay, on two networks holding the same coin under the same
    /// key.** The same bytes signed over the legacy root are valid on both
    /// until enforcement; bytes signed over one network's bound root are
    /// never valid on the other, nor on a network that never arms the rule.
    #[test]
    fn the_same_bytes_replay_across_networks_only_under_the_legacy_root() {
        // Before activation (window unset here): the legacy bytes apply on
        // both networks. This is WT-03.
        let (here, legacy, bound_here, price) = pair_at(ACCEPT - 1, Some(NET_A));
        let (there, ..) = pair_at(ACCEPT - 1, Some(NET_B));
        assert_eq!(applies(&here, &legacy, price), Ok(()));
        assert_eq!(applies(&there, &legacy, price), Ok(()), "the replay the legacy root permits");
        // A network that never arms the window refuses bound bytes.
        assert_eq!(applies(&there, &bound_here, price), Err(TransferReject::BadSignature));

        let _armed = wallet_consensus_rehearsal::arm_sighash(ACCEPT, ENFORCE);
        for epoch in [ACCEPT, ENFORCE - 1] {
            let (here, legacy, bound_here, price) = pair_at(epoch, Some(NET_A));
            let (there, ..) = pair_at(epoch, Some(NET_B));
            assert_eq!(applies(&here, &bound_here, price), Ok(()));
            assert_eq!(
                applies(&there, &bound_here, price),
                Err(TransferReject::BadSignature),
                "bound bytes do not replay inside the window (epoch {epoch})"
            );
            // Legacy bytes still do: the window protects who opts in.
            assert_eq!(applies(&here, &legacy, price), Ok(()));
            assert_eq!(applies(&there, &legacy, price), Ok(()));
        }
        for epoch in [ENFORCE, ENFORCE + 100] {
            let (here, legacy, bound_here, price) = pair_at(epoch, Some(NET_A));
            let (there, ..) = pair_at(epoch, Some(NET_B));
            assert_eq!(applies(&here, &bound_here, price), Ok(()));
            assert_eq!(applies(&there, &bound_here, price), Err(TransferReject::BadSignature));
            // After enforcement no bytes at all are valid on two networks.
            assert_eq!(applies(&here, &legacy, price), Err(TransferReject::BadSignature));
            assert_eq!(applies(&there, &legacy, price), Err(TransferReject::BadSignature));
        }
    }

    /// A state without a committed network domain: the legacy root through
    /// the window, nothing from enforcement (fail closed, never an unbound
    /// or zero-domain root).
    #[test]
    fn a_state_without_a_domain_keeps_the_legacy_root_then_fails_closed() {
        let _armed = wallet_consensus_rehearsal::arm_sighash(ACCEPT, ENFORCE);
        let (g, legacy, bound, price) = pair_at(ACCEPT, None);
        assert_eq!(applies(&g, &legacy, price), Ok(()));
        assert_eq!(applies(&g, &bound, price), Err(TransferReject::BadSignature));
        let mut zero_bound = legacy.clone();
        sign_over(&mut zero_bound, &owner_key(0x91), &legacy.network_bound_signing_root(&[0; 32]));
        assert_eq!(applies(&g, &zero_bound, price), Err(TransferReject::BadSignature));

        let (g, legacy, bound, price) = pair_at(ENFORCE, None);
        for tx in [&legacy, &bound, &zero_bound] {
            assert_eq!(applies(&g, tx, price), Err(TransferReject::MissingNetworkBinding));
        }
    }

    /// The bound root is `SHA3-256(DS_SPEND2 ‖ domain ‖ spend root)` and
    /// nothing else (test vector for wallet implementers, GIP-0002).
    #[test]
    fn the_bound_root_is_the_documented_fold() {
        let (_g, legacy, _bound, _price) = pair_at(0, Some(NET_A));
        let mut h = Sha3_256::new();
        h.update(b"BLCH4:SPEND2\0\0\0\0");
        h.update(NET_A);
        h.update(legacy.spend_signing_root());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(legacy.network_bound_signing_root(&NET_A), expected);
        assert_ne!(expected, legacy.spend_signing_root());
        assert_ne!(expected, legacy.network_bound_signing_root(&NET_B));
        // Not the source-tree label of the compatibility helper.
        assert_ne!(expected, legacy.network_bound_signing_root(&PosTransaction::network_binding()));
    }

    /// One chain through both boundaries, by whole blocks, and its replay.
    ///
    /// Blocks carry a legacy-signed transfer before the window, a bound one
    /// at acceptance, a legacy one in the window's last epoch and a bound
    /// one at enforcement. A legacy transfer in the enforcement epoch makes
    /// its block invalid. The recorded chain then replays from genesis to
    /// the same state root (history stays valid under the armed schedule),
    /// and its pre-window prefix replays to the same roots with the window
    /// unset (the schedule changes nothing before its first epoch).
    #[test]
    fn a_chain_crosses_both_boundaries_and_replays() {
        let alice = owner_key(0x91);
        let to = script_of(&owner_key(0x92));
        let coins: Vec<_> = (0..5u8).map(|i| opening(0xA0 + i, 0, 50_000_000, &alice)).collect();
        let genesis = || {
            let (t, mut g, chains) = setup_funded(8, &coins);
            g.admission_network_domain = Some(NET_A);
            (t, g, chains)
        };
        let first_slot = |epoch: u64| epoch * crate::SLOTS_PER_EPOCH;
        // (slot, coin, signed over the bound root)
        let plan = [
            (first_slot(ACCEPT - 1) + 1, 0usize, false),
            (first_slot(ACCEPT), 1, true),
            (first_slot(ENFORCE) - 1, 2, false),
            (first_slot(ENFORCE), 3, true),
        ];
        let transfer = |st: &CommittedState, slot: u64, coin: usize, bound: bool| {
            let price = st.next_base_fee_at(crate::epoch_of(slot));
            let mut tx = transfer_spending(std::slice::from_ref(&coins[coin]), &alice, to, 512, 1, price);
            if bound {
                let root = tx.network_bound_signing_root(&NET_A);
                sign_over(&mut tx, &alice, &root);
            }
            tx
        };

        let mut blocks = Vec::new();
        let mut roots = Vec::new();
        let mut parents = Vec::new();
        {
            let _armed = wallet_consensus_rehearsal::arm_sighash(ACCEPT, ENFORCE);
            let (t, mut st, mut chains) = genesis();
            for (slot, coin, bound) in plan {
                let tx = transfer(&st, slot, coin, bound);
                let block = build_block(&t, &st, slot, &[], std::slice::from_ref(&tx), &mut chains);
                parents.push(st.clone());
                st = t.apply_block(&st, &block, &[], std::slice::from_ref(&tx)).expect("block across the window");
                assert!(st.utxo(&tx.txid(), 0).is_some(), "slot {slot}: the transfer applied");
                blocks.push((block, tx));
                roots.push(st.state_root());
            }
            assert_eq!(st.epoch, ENFORCE);

            // The legacy root is refused from the first block of the
            // enforcement epoch: the accepted block of that slot, carrying
            // a legacy-signed transfer instead (body root and proposer
            // signature redone, so the transfer is what gets it refused).
            let parent = &parents[3];
            let stale = transfer(parent, first_slot(ENFORCE), 4, false);
            let mut header = blocks[3].0.header;
            header.body_root = crate::derive::body_root(&[stale.canonical_bytes()]);
            let proposer = crate::attestation::KeyLookup::pubkey(parent, header.proposer_index).unwrap();
            let refused = ProposalEnvelope { header, proposer_sig: toy_sign(proposer, &header.proposal_signing_root()) };
            assert_eq!(
                t.apply_block(parent, &refused, &[], std::slice::from_ref(&stale)).err(),
                Some(TransitionError::Transfer(0, TransferReject::BadSignature))
            );

            // Full-history replay under the armed schedule.
            let (t, mut replay, _) = genesis();
            for ((block, tx), root) in blocks.iter().zip(&roots) {
                replay = t.apply_block(&replay, block, &[], std::slice::from_ref(tx)).expect("replay");
                assert_eq!(replay.state_root(), *root);
            }
        }

        // Window unset: the block before the window replays to the same
        // root, and the first bound block is refused (old rules).
        let (t, g, _) = genesis();
        let (block, tx) = &blocks[0];
        let pre_window = t.apply_block(&g, block, &[], std::slice::from_ref(tx)).expect("pre-window block, unset");
        assert_eq!(pre_window.state_root(), roots[0]);
        let (block, tx) = &blocks[1];
        assert_eq!(
            t.apply_block(&pre_window, block, &[], std::slice::from_ref(tx)).err(),
            Some(TransitionError::Transfer(0, TransferReject::BadSignature))
        );
    }
}
