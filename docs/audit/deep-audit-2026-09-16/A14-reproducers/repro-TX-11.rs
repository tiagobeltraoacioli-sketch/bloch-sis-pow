// repro-TX-11.rs — independent verification of TX-11:
// "Slashing is unreachable; equivocation is free" on the live (fleet) configuration.
//
// PLACEMENT (never commit this): paste the two tests below into
// `crates/bloch-pos-committee/src/transition.rs`, inside the `mod tests` that
// starts at transition.rs:6350 — e.g. directly after
// `evidence_transaction_slashes_operator_and_delegators_and_pays_whistleblower`
// (~transition.rs:12780). They use only that module's existing `#[cfg(test)]`
// helpers (`setup`, `build_block`, `probe_env`, `toy_sign`, `OkVerifier`) and the
// crate's public API (`StateTransition::apply_block`, `StateReader::validator_record`,
// `StateReader::total_active_stake_sat`, `CommittedState::validate_lifecycle_transaction`,
// `CommittedState::next_base_fee`, `params::epoch_gate_active`,
// `params::rehearsal::slashing_gate_open_guard`).
//
// Run:  cargo test -p bloch-pos-committee tx11_ -- --nocapture
//
// EXPECTED on the current tree: both tests PASS, which CONFIRMS the finding.
//   1. A provable proposer equivocation (two validly signed headers, same slot,
//      same proposer_index, different BlockId) round-trips through the tag-0x05
//      codec, is refused by the relay/mempool path with `TxReject::EvidenceNotActive`
//      (transition/lifecycle.rs:187-189) and by the block path with
//      `TransitionError::Transaction(0)` (transition.rs:5819-5822, 5872); the
//      offender keeps 100% of its bond, is not marked slashed, is not ejected.
//   2. The SAME evidence, with only the test-only gate guard opened, slashes 5% and
//      schedules ejection — so the inert `SLASHING_EVIDENCE_ACTIVATION_EPOCH`
//      (params.rs:1425, u64::MAX) is the ONLY barrier between the wire and the penalty.
//   3. The gate is closed at mainnet's current epoch (3,065) and at every reachable epoch.
//
// NETWORK-LEVEL REPRODUCTION (manual, for completeness; not needed to confirm):
//   A validator operator who controls one registered key (index i) and its own
//   node binary:
//     a. Propose normally at a slot S where `schedule::proposer` names i; block A is
//        stored by every peer (engine.rs:2453-2474 stores any validly signed block
//        whose parent is known).
//     b. Re-sign a second header for slot S (e.g. `devnet_tools::forge_conflicting`,
//        devnet_tools.rs:596-601, after deleting the client-side
//        `require_devnet_shape` rail at :515-525, which only inspects the manifest)
//        and `net::send_block` it to any subset of the fixed devnet-transport peer
//        list (plain TCP, no authentication).
//     c. Every receiving node verifies the signature (engine.rs:2418-2422), calls
//        `observe_proposer_equivocation`, which RETURNS at
//        validator_lifecycle.rs:110-116 because the gate is inert (nothing is even
//        recorded; `equivocations_observed_total` does not move), then inserts
//        block B into `self.blocks` and re-runs fork choice with A and B as
//        siblings (engine.rs:2473-2476).
//     d. Any attestation-side double vote that IS captured by the gossip pool
//        (gossip.rs:76, cap of 2 per duty) reaches `report_equivocation`
//        (validator_lifecycle.rs:91-104) → `on_transaction` →
//        `validate_lifecycle_admission` → `EvidenceNotActive`; the node prints
//        "slashing evidence against v{i} not submitted" and drops it.
//     e. `getvalidator i` on either public bootnode (:8080) keeps answering
//        `slashed: false`, full `staked_sat`, `exit_epoch: null` — the same
//        observation the CertiK dossier records for 48 of the 64 live validators
//        with provable double-signing (docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md:371-381).

    /// TX-11, independent verification. The fleet configuration is the DEFAULT
    /// test configuration: no `rehearsal` guard, so
    /// `SLASHING_EVIDENCE_ACTIVATION_EPOCH == u64::MAX` — exactly what every
    /// mainnet node runs at epoch 3,065.
    #[test]
    fn tx11_proposer_equivocation_is_free_on_the_fleet_configuration() {
        // (3) The live gate, read from the crate, closed at every reachable epoch
        //     including mainnet's current one.
        assert_eq!(crate::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH, u64::MAX);
        for e in [0u64, 800, 1_400, 2_700, 3_065, 3_066, 100_000, u64::MAX - 1, u64::MAX] {
            assert!(
                !crate::params::epoch_gate_active(e, crate::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH),
                "params gate must be closed at epoch {e}"
            );
            assert!(!CommittedState::slashing_evidence_active(e), "transition gate must be closed at epoch {e}");
        }
        assert!(
            !crate::params::rehearsal::slashing_gate_forced_open(),
            "test premise: the fleet configuration (no rehearsal guard on this thread)"
        );

        let (t, g, mut chains) = setup(4);

        // Step 1 — the offender proposes an honest block at slot 1; every node applies it.
        let b1 = build_block(&t, &g, 1, &[], &[], &mut chains);
        let offender = b1.header.proposer_index;
        let bond_before = g.validator_record(offender).expect("offender is registered").staked_sat;
        assert!(bond_before > 0, "test premise: the offender has a bond to lose");
        let s1 = t.apply_block(&g, &b1, &[], &[]).expect("the honest block applies");

        // Step 2 — the offender signs a SECOND header for the same slot: the exact
        // mutation `devnet_tools::forge_conflicting` and the node's own
        // `validator_admission_tests.rs` perform — one bit of `state_root`, re-signed
        // with the offender's REGISTERED key over the new proposal signing root.
        let mut conflicting = b1.clone();
        conflicting.header.state_root[0] ^= 1;
        let pk = crate::attestation::KeyLookup::pubkey(&g, offender).expect("registered key");
        conflicting.proposer_sig = toy_sign(pk, &conflicting.header.proposal_signing_root());
        assert_eq!(b1.header.slot, conflicting.header.slot);
        assert_eq!(b1.header.proposer_index, conflicting.header.proposer_index);
        assert_ne!(
            crate::header::BlockId::of(&b1.header),
            crate::header::BlockId::of(&conflicting.header),
            "two distinct signed headers for one slot by one proposer: §7.3 ProposerEquivocation"
        );

        // Step 3 — the proof TRAVELS: tag 0x05 round-trips through the codec
        // (F-02 is closed; the wire is not what stops the penalty any more).
        let ev = PosTransaction::from_canonical_bytes(
            &PosTransaction::SlashingEvidence(SlashingEvidence::ProposerEquivocation {
                first: b1.clone(),
                second: conflicting.clone(),
            })
            .canonical_bytes(),
        )
        .expect("evidence decodes from its own wire bytes");

        // Step 4a — relay/mempool path. This is what `Engine::on_transaction` runs
        // via `validate_lifecycle_admission`, and therefore what the node's own
        // `report_equivocation` hook hits: refused BEFORE any slashing logic.
        let relay = s1.validate_lifecycle_transaction(
            &ev,
            s1.total_active_stake_sat(),
            s1.next_base_fee(),
            &OkVerifier,
        );
        assert!(
            matches!(relay, Err(TxReject::EvidenceNotActive)),
            "relay path must refuse with EvidenceNotActive below the inert gate, got {relay:?}"
        );

        // Step 4b — block path. A whistleblower's block carrying the evidence is
        // CONSENSUS-INVALID on every node: step 10 rejects at transaction index 0
        // before the state root is ever compared. `probe_env` rather than
        // `build_block`, because the builder cannot assemble a block the
        // transition refuses. Pick the first slot whose proposer is not the
        // offender so the whistleblower is a different validator.
        let seed = s1.seed_for_epoch(s1.epoch);
        let roster = s1.duty_roster();
        let ws = (2u64..=8)
            .find(|s| schedule::proposer(&seed, *s, &roster).expect("proposer") != offender)
            .expect("some slot in epoch 0 is proposed by someone other than the offender");
        let b2 = probe_env(&s1, ws, std::slice::from_ref(&ev), &mut chains);
        assert_ne!(b2.header.proposer_index, offender, "test premise: whistleblower != offender");
        let verdict = t.apply_block(&s1, &b2, &[], std::slice::from_ref(&ev));
        assert!(
            matches!(verdict, Err(TransitionError::Transaction(0))),
            "a block carrying evidence must be consensus-invalid below the gate, got {:?}",
            verdict.as_ref().err()
        );

        // Step 5 — impact: the offender is untouched. Full bond, not slashed,
        // no ejection scheduled, still seated on the duty roster.
        let rec = s1.validator_record(offender).expect("record persists");
        assert!(!rec.slashed, "TX-11: equivocation is free — the offender is not marked slashed");
        assert_eq!(rec.staked_sat, bond_before, "TX-11: not one satoshi of the bond is lost");
        assert_eq!(rec.exit_epoch, u64::MAX, "TX-11: no ejection is scheduled");
        assert!(
            s1.active_validators().iter().any(|v| v.index == offender),
            "TX-11: the equivocator keeps proposing and attesting"
        );
    }

    /// Control for TX-11: the SAME construction with only the test-only gate
    /// guard opened slashes the offender. Together with the test above this
    /// proves the inert constant is the ONLY barrier — no other check, bound,
    /// ordering or rate limit stops the penalty once the gate is bound.
    #[test]
    fn tx11_control_the_inert_gate_is_the_only_thing_between_the_wire_and_the_penalty() {
        let _gate = crate::params::rehearsal::slashing_gate_open_guard();
        let (t, g, mut chains) = setup(4);
        let b1 = build_block(&t, &g, 1, &[], &[], &mut chains);
        let offender = b1.header.proposer_index;
        let bond_before = g.validator_record(offender).expect("registered").staked_sat;
        let s1 = t.apply_block(&g, &b1, &[], &[]).expect("honest block applies");

        let mut conflicting = b1.clone();
        conflicting.header.state_root[0] ^= 1;
        let pk = crate::attestation::KeyLookup::pubkey(&g, offender).expect("registered key");
        conflicting.proposer_sig = toy_sign(pk, &conflicting.header.proposal_signing_root());
        let ev = PosTransaction::SlashingEvidence(SlashingEvidence::ProposerEquivocation {
            first: b1.clone(),
            second: conflicting,
        });

        // Post-gate the relay path admits it ...
        assert!(s1
            .validate_lifecycle_transaction(&ev, s1.total_active_stake_sat(), s1.next_base_fee(), &OkVerifier)
            .is_ok());

        // ... and a whistleblower's block carrying it applies and slashes.
        let seed = s1.seed_for_epoch(s1.epoch);
        let roster = s1.duty_roster();
        let ws = (2u64..=8)
            .find(|s| schedule::proposer(&seed, *s, &roster).expect("proposer") != offender)
            .expect("a whistleblower slot exists");
        let b2 = build_block(&t, &s1, ws, &[], std::slice::from_ref(&ev), &mut chains);
        let s2 = t
            .apply_block(&s1, &b2, &[], std::slice::from_ref(&ev))
            .expect("post-gate: the evidence block applies");
        let rec = s2.validator_record(offender).expect("record persists");
        assert!(rec.slashed, "control: with the gate open the same evidence slashes");
        assert_eq!(
            rec.staked_sat,
            bond_before - bond_before * slashing::SLASH_PROPOSER_EQUIV_BPS / 10_000,
            "control: 5% of the operator bond is burned"
        );
        assert_eq!(rec.exit_epoch, s2.epoch + 1, "control: ejection lands the epoch after the slash (R1 M7)");
    }
