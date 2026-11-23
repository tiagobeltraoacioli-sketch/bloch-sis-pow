// AUDIT-L1L2-20261123 L2N-01 / L2N-02, the L1 half of the proper fix: at the
// first epoch boundary behind
// `params::L2_SETTLEMENT_PROGRAM_SWITCH_ACTIVATION_EPOCH` an installed L2
// names the pinned successor program instead of the deployed one. Inert as
// shipped, and the pinned successor is a candidate (NOT FINAL).
//
// What these tests exercise: the consensus transition, the mempool
// preflight and the retention check, with the gate armed at a chosen epoch
// through the test seam. Proofs are doubles, except where a test says
// "real": the only real Groth16 proof in the repository is of the DEPLOYED
// program, so the real verifier is exercised refusing it after the switch,
// never accepting a proof of the new program (none exists yet).
use crate::l2_settlement::{ProgramIdentities, ProgramSwitch, SupplyCap, PROGRAM_IDENTITIES};

fn boundary(epoch: u64) -> u64 {
    epoch * crate::params::SLOTS_PER_EPOCH
}

/// A successor of the program `pre`'s L2 names, for the test seam.
fn test_switch(pre: &CommittedState, supply_cap: SupplyCap) -> ProgramSwitch {
    ProgramSwitch {
        from: pre.l2_settlement().unwrap().program(),
        to: [[0xb3; 32], [0xb4; 32], [0xb5; 32], [0xb6; 32]],
        supply_cap,
    }
}

/// Pin `switch` and arm the gate at `epoch` until the guards drop.
fn arm_switch(switch: ProgramSwitch, epoch: u64) -> (impl Drop, impl Drop) {
    (
        crate::l2_settlement::program_switch_rehearsal::set(switch),
        crate::params::l2_settlement_program_switch_rehearsal::arm(epoch),
    )
}

/// The funded L2 of `funded_l2(1)` (installed at epoch 1) followed by empty
/// blocks at `slots`, under the seams in force. Deterministic: a test that
/// judges several blocks on one state walks to it once per block, because a
/// built block spends a RANDAO reveal of its proposer.
fn walked(slots: &[u64]) -> (CommittedState, Vec<RandaoChain>) {
    let (mut state, mut chains) = funded_l2(1);
    for slot in slots {
        state = apply(&state, *slot, &[], &mut chains).unwrap();
    }
    (state, chains)
}

/// `tx` with its statement naming `program`.
fn naming(mut tx: Transaction, program: &ProgramIdentities) -> Transaction {
    for (i, id) in program.iter().enumerate() {
        let at = S + (PROGRAM_IDENTITIES.start + i) * 32;
        tx.statement[at..at + 32].copy_from_slice(id);
    }
    tx
}

/// A proof double bound to the verifying key and the proof policy it was
/// "made" for: [`KeyedProof`] accepts it only under that key and policy, so
/// a test sees which key the L1 hands to the verifier.
fn proven_for(mut tx: Transaction, key: &[u8; 32]) -> Transaction {
    tx.proof = [0; 356];
    tx.proof[..32].copy_from_slice(key);
    let policy = tx.proof_policy;
    tx.proof[32..64].copy_from_slice(&policy);
    tx
}
struct KeyedProof;
impl SignatureVerifier for KeyedProof {
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        ToyVerifier.verify_with_key(pk, root, sig)
    }
    fn verify_l2_settlement(&self, policy: &[u8; 32], key: &[u8; 32], _: &[u8], proof: &[u8]) -> bool {
        proof[..32] == key[..] && proof[32..64] == policy[..]
    }
}
/// A verifier that must not be asked for a proof.
struct Unreached;
impl SignatureVerifier for Unreached {
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        ToyVerifier.verify_with_key(pk, root, sig)
    }
    fn verify_l2_settlement(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8], _: &[u8]) -> bool {
        panic!("the proof verifier must not be reached")
    }
}

/// [`body_verdict`] under `verifier`.
fn judged_by<V: SignatureVerifier>(
    verifier: V,
    pre: &CommittedState,
    block: &ProposalEnvelope,
    tx: &Transaction,
) -> Result<CommittedState, TransitionError> {
    let txs = [wire(tx)];
    let mut graft = block.clone();
    graft.header.body_root = crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
    let pk = crate::attestation::KeyLookup::pubkey(pre, graft.header.proposer_index).unwrap();
    graft.proposer_sig = toy_sign(pk, &graft.header.proposal_signing_root());
    Transition::new(verifier).compute_post_state(pre, &graft, &[], &txs)
}

fn settlement_refusal(state: &CommittedState, tx: &Transaction, verifier: &dyn SignatureVerifier) -> Option<TxReject> {
    let mut copy = state.clone();
    let verdict = copy.apply_transaction(&wire(tx), 0, 1, verifier).err();
    if verdict.is_some() {
        assert_eq!(&copy, state, "a refused settlement changes nothing");
    }
    verdict
}

#[test]
fn l2n01_the_program_switch_gate_is_inert_and_not_final() {
    use crate::l2_settlement::mainnet as mn;
    assert_eq!(crate::params::L2_SETTLEMENT_PROGRAM_SWITCH_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::l2_settlement_program_switch_active(u64::MAX - 1));
    // The pinned successor is the candidate of 2026-11-23 and is NOT final:
    // the release that arms the gate re-pins it and flips the flag.
    assert!(!mn::PROGRAM_SWITCH_FINAL, "release values need a real Groth16 fixture of the new program first");
    let switch = mn::PROGRAM_SWITCH.expect("the candidate switch is recorded");
    let program = mn::PROGRAM.expect("the mainnet program is pinned");
    assert!(switch.valid());
    assert_eq!(switch.from.as_slice(), &program.identities[PROGRAM_IDENTITIES]);
    assert_eq!(switch.from, mn::deployed_program());
    let hex32 = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
    assert_eq!(
        switch.to,
        [
            hex32("41ddb4dd4aae492e04f500d40be8471ac785e1264d32346dc0f1620d67cc928d"),
            hex32("c1dd6066941c83fc691f6b325b51ca771c680431df54d54d508c8593fcb6da6d"),
            hex32("72730d65162c55a9604a8d905e125a1f332bec342419058167520c455dea4112"),
            hex32("00e4e61aca58b156a702546c85e125a1f6657d868906416073a90622ddea4112"),
        ]
    );
    assert_eq!(switch.supply_cap, SupplyCap::Outstanding);
    // Every one of the four differs, the configuration included (L2N-02).
    assert!((0..4).all(|i| switch.to[i] != switch.from[i]));

    // The mainnet L2 as installed today: the switch is ahead, the deployed
    // cap rule is in force. Another chain id has no switch.
    let l2 = crate::l2_settlement::State::activated(mn::activation().unwrap()).unwrap();
    assert_eq!(l2.pending_program_switch(), Some(switch));
    assert_eq!((l2.program_switched(), l2.supply_cap()), (None, SupplyCap::GrossMinted));
    let (_, development) = running_without_l2();
    assert_eq!(crate::l2_settlement::program_switch_for(&development), None);

    // Shape: a zero identity, the same ELF or key, or another cap rule
    // under the same configuration is not a switch.
    let mut bad = switch;
    bad.to[2] = [0; 32];
    assert!(!bad.valid());
    for i in 1..4 {
        let mut bad = switch;
        bad.to[i] = bad.from[i];
        assert!(!bad.valid(), "identity {i}");
    }
    let mut same_configuration = switch;
    same_configuration.to[0] = switch.from[0];
    assert!(!same_configuration.valid());
    same_configuration.supply_cap = SupplyCap::GrossMinted;
    assert!(same_configuration.valid(), "a context-only program keeps the configuration and its cap");
}

/// As shipped (gate inert), a pinned switch changes nothing at any boundary:
/// states are equal to those of a build without one, and the deployed
/// program keeps settling.
#[test]
fn l2n01_inert_no_boundary_switches_the_program() {
    let run = |pinned: bool| {
        let (opened, mut chains) = funded_l2(1);
        let _switch = pinned.then(|| crate::l2_settlement::program_switch_rehearsal::set(test_switch(&opened, SupplyCap::Outstanding)));
        let rolled = apply(&opened, boundary(2), &[], &mut chains).unwrap();
        let next = apply(&rolled, boundary(2) + 1, &[], &mut chains).unwrap();
        let later = apply(&next, boundary(4), &[], &mut chains).unwrap();
        let settled = apply(&later, boundary(4) + 1, &[wire(&next_settlement(&later, 0))], &mut chains).unwrap();
        assert_eq!(settled.l2_settlement().unwrap().settled_number(), 1);
        assert_eq!(settled.l2_settlement().unwrap().program(), opened.l2_settlement().unwrap().program());
        (later, settled)
    };
    assert_eq!(run(true), run(false));
}

/// The gate at epoch 3 on an L2 installed at epoch 1: nothing moves at the
/// boundary of epoch 2; in the last block of epoch 2 only the old program
/// settles; the first block of epoch 3 (the boundary block) is already
/// judged under the new one; afterwards only the new one settles. The proof
/// is verified under the BN254 key of the program in force.
#[test]
fn l2n01_the_program_switches_at_the_first_boundary_behind_the_gate() {
    const GATE: u64 = 3;
    let to_a = [boundary(2), boundary(2) + 1];
    let to_b = [boundary(2), boundary(2) + 1, boundary(GATE) - 1];
    let to_c = [boundary(2), boundary(2) + 1, boundary(GATE) - 1, boundary(GATE)];
    // The same chain on a build without the switch.
    let (twin_b, twin_c) = (walked(&to_b).0, walked(&to_c).0);

    let (opened, _) = funded_l2(1);
    let switch = test_switch(&opened, SupplyCap::Outstanding);
    let _armed = arm_switch(switch, GATE);
    let before = opened.l2_settlement().unwrap().policy().clone();

    // Epoch 2 is below the gate: its boundary switches nothing.
    let (a, mut chains_a) = walked(&to_a);
    let (b, mut chains_b) = walked(&to_b);
    assert_eq!(b, twin_b, "below the gate the armed build commits the same state");
    let l2 = b.l2_settlement().unwrap();
    assert_eq!((l2.program(), l2.pending_program_switch(), l2.program_switched()), (switch.from, Some(switch), None));

    // The last block before the boundary (slot boundary - 1 is the head; a
    // block there was judged like this one on `a`): old program only.
    let old = next_settlement(&a, 0);
    let new = naming(old.clone(), &switch.to);
    let block_a = template(&a, &mut chains_a);
    assert_eq!(a.l2_settlement().unwrap().validate_async(&old, &ProofDouble), Ok(()));
    assert_eq!(judged(&a, &block_a, &old).unwrap().l2_settlement().unwrap().settled_number(), 1);
    assert_eq!(a.l2_settlement().unwrap().validate_async(&new, &Unreached), Err(Reject::Policy));
    assert_eq!(a.l2_settlement().unwrap().pending_async_refusal(&new, *a.head.as_bytes(), a.slot), Some(Reject::Policy));
    assert_eq!(settlement_refusal(&a, &new, &Unreached), Some(TxReject::L2Settlement(Reject::Policy)));
    assert!(judged_by(Unreached, &a, &block_a, &new).is_err(), "a block carrying the new program before the gate is invalid");
    // ...and its proof is checked under the OLD key.
    assert_eq!(settlement_refusal(&a, &proven_for(old.clone(), &switch.from[3]), &KeyedProof), None);
    assert_eq!(
        settlement_refusal(&a, &proven_for(old.clone(), &switch.to[3]), &KeyedProof),
        Some(TxReject::L2Settlement(Reject::Proof))
    );

    // The boundary block itself (first block of epoch 3, built on `b`): the
    // epoch roll precedes its transactions, so it is judged under the NEW
    // program. The node-local preflight still judges by the head `b`.
    let old = next_settlement(&b, 0);
    let new = naming(old.clone(), &switch.to);
    let boundary_block = template(&b, &mut chains_b);
    assert_eq!(boundary_block.header.slot, boundary(GATE));
    assert!(judged_by(Unreached, &b, &boundary_block, &old).is_err(), "no overlap: the old program is refused in the boundary block");
    let settled = judged(&b, &boundary_block, &new).expect("the new program settles in the boundary block");
    assert_eq!(settled.l2_settlement().unwrap().settled_number(), 1);
    assert_eq!(settled.l2_settlement().unwrap().program(), switch.to);
    assert_eq!(b.l2_settlement().unwrap().validate_async(&old, &ProofDouble), Ok(()), "the head's preflight is still the old program's");
    assert_eq!(b.l2_settlement().unwrap().validate_async(&new, &Unreached), Err(Reject::Policy));

    // After the boundary.
    let (c, mut chains_c) = walked(&to_c);
    let l2 = c.l2_settlement().unwrap();
    assert_eq!((l2.program(), l2.pending_program_switch(), l2.program_switched()), (switch.to, None, Some(switch)));
    assert_eq!(l2.supply_cap(), SupplyCap::Outstanding);
    // Only the four program identities were written.
    let mut expected = before.clone();
    expected.identities[PROGRAM_IDENTITIES].copy_from_slice(&switch.to);
    assert_eq!(l2.policy(), &expected);
    assert_eq!(l2.policy().proof_policy, before.proof_policy);
    assert_eq!(l2.policy().identities[..3], before.identities[..3]);
    // The pinned source is the one frozen before the switch.
    assert_eq!(l2.frozen_source(), b.l2_settlement().unwrap().frozen_source());
    // The program in force is part of the state root.
    assert_ne!(c.compute_root(), twin_c.compute_root());
    let mut unswitched = c.clone();
    unswitched.l2_settlement.as_mut().unwrap().clone_from(twin_c.l2_settlement().unwrap());
    assert_eq!(unswitched.compute_root(), twin_c.compute_root(), "and it is the only difference");

    let new = next_settlement(&c, 0);
    let old = naming(new.clone(), &switch.from);
    let block_c = template(&c, &mut chains_c);
    assert_eq!(l2.validate_async(&old, &Unreached), Err(Reject::Policy));
    assert_eq!(l2.pending_async_refusal(&old, *c.head.as_bytes(), c.slot), Some(Reject::Policy));
    assert_eq!(settlement_refusal(&c, &old, &Unreached), Some(TxReject::L2Settlement(Reject::Policy)));
    assert!(judged_by(Unreached, &c, &block_c, &old).is_err());
    assert_eq!(l2.validate_async(&new, &ProofDouble), Ok(()));
    assert_eq!(l2.pending_async_refusal(&new, *c.head.as_bytes(), c.slot), None);
    assert_eq!(judged(&c, &block_c, &new).unwrap().l2_settlement().unwrap().settled_number(), 1);
    // The proof is now checked under the NEW key: a proof of the old
    // program fails even behind a statement that names the new one.
    assert_eq!(settlement_refusal(&c, &proven_for(new.clone(), &switch.to[3]), &KeyedProof), None);
    assert_eq!(
        settlement_refusal(&c, &proven_for(new.clone(), &switch.from[3]), &KeyedProof),
        Some(TxReject::L2Settlement(Reject::Proof))
    );
    assert_eq!(l2.validate_async(&proven_for(new.clone(), &switch.from[3]), &KeyedProof), Err(Reject::Proof));
    // A statement naming a mix of the two programs is neither.
    for i in 0..4 {
        let mut mixed = switch.to;
        mixed[i] = switch.from[i];
        assert_eq!(l2.validate_async(&naming(new.clone(), &mixed), &Unreached), Err(Reject::Policy), "identity {i}");
    }

    // Taken once: later boundaries, and another pinned successor, change nothing.
    let (later, _) = walked(&[boundary(2), boundary(2) + 1, boundary(GATE) - 1, boundary(GATE), boundary(GATE + 2)]);
    assert_eq!(later.l2_settlement().unwrap().policy(), &expected);
    let mut again = later.clone();
    assert!(!again.l2_settlement.as_mut().unwrap().switch_program());
    assert_eq!(again, later);
}

/// A reorg across the boundary: the program in force is committed state, so
/// each branch has its own. A branch that crosses the boundary switches; the
/// sibling built on the common ancestor below it still settles with the old
/// program, and when that branch crosses the boundary it switches with an
/// old-program head, which a new-program settlement then extends.
#[test]
fn l2n01_a_reorg_across_the_switch_boundary_follows_each_branch() {
    const GATE: u64 = 3;
    // The common ancestor, two slots below the boundary, built twice (the
    // fixture is deterministic) so that each branch has its own RANDAO state.
    let ancestor = || {
        let (opened, mut chains) = funded_l2(1);
        let a = apply(&apply(&opened, boundary(2), &[], &mut chains).unwrap(), boundary(2) + 1, &[], &mut chains).unwrap();
        (apply(&a, boundary(GATE) - 2, &[], &mut chains).unwrap(), chains)
    };
    let (common, mut chains_a) = ancestor();
    let switch = test_switch(&common, SupplyCap::Outstanding);
    let _armed = arm_switch(switch, GATE);
    let (same, mut chains_b) = ancestor();
    assert_eq!(common, same);

    // Branch A: the slot below the boundary is skipped; its first block is
    // the boundary block.
    let a1 = apply(&common, boundary(GATE), &[], &mut chains_a).unwrap();
    assert_eq!(a1.l2_settlement().unwrap().program(), switch.to);
    assert_eq!(a1.l2_settlement().unwrap().settled_number(), 0);

    // The node reorgs to branch B, which has a block below the boundary.
    // The ancestor's state is what it was: the switch of branch A is gone.
    assert_eq!(common.l2_settlement().unwrap().pending_program_switch(), Some(switch));
    let old = next_settlement(&common, 0);
    let b1 = apply(&common, boundary(GATE) - 1, &[wire(&old)], &mut chains_b).expect("the old program settles below the boundary on branch B");
    assert_eq!(b1.l2_settlement().unwrap().settled_number(), 1);
    assert_eq!(b1.l2_settlement().unwrap().program(), switch.from);
    // A settlement of the old program admitted to the mempool on branch A's
    // ancestor is no longer retained once the head is branch A's.
    assert_eq!(a1.l2_settlement().unwrap().pending_async_refusal(&old, *a1.head.as_bytes(), a1.slot), Some(Reject::Policy));

    // Branch B crosses the boundary: switched, the old-program head kept.
    let b2 = apply(&b1, boundary(GATE), &[], &mut chains_b).unwrap();
    let l2 = b2.l2_settlement().unwrap();
    assert_eq!(l2.program(), switch.to);
    assert_eq!(l2.head().unwrap().0, old.commitment());
    assert_ne!(a1.compute_root(), b2.compute_root());
    // The boundary block pinned the next source: L2 block 2 settles under
    // the new program, on top of the head the old program settled.
    let new = next_settlement(&b2, 0);
    assert_eq!(new.statement[S + 3 * 32..S + 7 * 32], switch.to.concat()[..]);
    assert_eq!(l2.validate_async(&naming(new.clone(), &switch.from), &Unreached), Err(Reject::Policy));
    let b3 = apply(&b2, boundary(GATE) + 1, &[wire(&new)], &mut chains_b).expect("the new program extends the old program's head");
    assert_eq!(b3.l2_settlement().unwrap().settled_number(), 2);

    // Replaying branch B from the ancestor gives the same states (a restart
    // or a second reorg lands on the same program).
    let (again, mut chains_c) = ancestor();
    let c1 = apply(&again, boundary(GATE) - 1, &[wire(&old)], &mut chains_c).unwrap();
    let c2 = apply(&c1, boundary(GATE), &[], &mut chains_c).unwrap();
    assert_eq!(apply(&c2, boundary(GATE) + 1, &[wire(&new)], &mut chains_c).unwrap(), b3);

    // The restart cache carries the switched policy (it is the policy).
    #[cfg(feature = "local-state-cache")]
    {
        let (restored, _, _) = local_cache_round_trip(&b3);
        assert_eq!(restored.l2_settlement().unwrap().program(), switch.to);
        assert_eq!(restored.l2_settlement().unwrap().supply_cap(), SupplyCap::Outstanding);
    }
}

/// With the settler rule of the stop-gap (gate 5312e209) in force: the two
/// rules are independent and both bind. Set first then switch, both at one
/// boundary, and switch first then set.
#[test]
fn l2n01_the_program_switch_and_the_settler_rule_bind_together() {
    let keys = vec![settler_key(1), settler_key(2)];
    let check = |state: &CommittedState, chains: &mut Vec<RandaoChain>, switch: &ProgramSwitch| {
        let l2 = state.l2_settlement().unwrap();
        assert_eq!((l2.settlers(), l2.program()), (keys.as_slice(), switch.to));
        let block = template(state, chains);
        let new = next_settlement(state, 0);
        let old = naming(new.clone(), &switch.from);
        // The new program without a registered key: refused before any proof.
        assert_eq!(l2.validate_async(&new, &Unreached), Err(Reject::Settler));
        assert_eq!(l2.pending_async_refusal(&new, *state.head.as_bytes(), state.slot), Some(Reject::Settler));
        assert!(judged_by(Unreached, state, &block, &new).is_err());
        // A registered key with the old program: refused as the wrong program.
        let old_signed = authorize(state, old, &settler_key(1), 0, None);
        assert_eq!(l2.validate_async(&old_signed, &Unreached), Err(Reject::Policy));
        assert!(judged_by(Unreached, state, &block, &old_signed).is_err());
        // Its authorization does not carry over to the new-program
        // settlement of the same block (the signature covers the statement).
        let mut lifted = new.clone();
        lifted.authorization = old_signed.authorization.clone();
        assert_eq!(l2.validate_async(&lifted, &Unreached), Err(Reject::Settler));
        // A registered key with the new program settles; so does the standby.
        let signed = authorize(state, new.clone(), &settler_key(1), 0, None);
        assert_eq!(l2.validate_async(&signed, &ProofDouble), Ok(()));
        let post = judged(state, &block, &signed).expect("the settler's new-program settlement");
        assert_eq!(post.l2_settlement().unwrap().settled_number(), 1);
        assert_eq!(post.l2_settlement().unwrap().settlers(), keys.as_slice());
        assert!(judged(state, &block, &authorize(state, new, &settler_key(2), 1, None)).is_ok());
    };

    // Settler set at epoch 2, program switch at epoch 3.
    {
        let (opened, mut chains) = funded_l2(1);
        let switch = test_switch(&opened, SupplyCap::Outstanding);
        let _armed = arm_switch(switch, 3);
        let _gate = crate::params::l2_settler_authorization_rehearsal::open();
        let _set = crate::l2_settlement::settler_rehearsal::set(keys.clone());
        let a = apply(&apply(&opened, boundary(2), &[], &mut chains).unwrap(), boundary(2) + 1, &[], &mut chains).unwrap();
        let l2 = a.l2_settlement().unwrap();
        assert_eq!((l2.settlers(), l2.program()), (keys.as_slice(), switch.from));
        // Between the two: the settler settles with the old program only.
        let old = next_settlement(&a, 0);
        assert_eq!(l2.validate_async(&authorize(&a, old.clone(), &settler_key(1), 0, None), &ProofDouble), Ok(()));
        let early = authorize(&a, naming(old, &switch.to), &settler_key(1), 0, None);
        assert_eq!(l2.validate_async(&early, &Unreached), Err(Reject::Policy));
        let b = apply(&a, boundary(3), &[], &mut chains).unwrap();
        check(&b, &mut chains, &switch);
    }
    // Both at the boundary of epoch 2.
    {
        let (opened, mut chains) = funded_l2(1);
        let switch = test_switch(&opened, SupplyCap::Outstanding);
        let _armed = arm_switch(switch, 2);
        let _gate = crate::params::l2_settler_authorization_rehearsal::open();
        let _set = crate::l2_settlement::settler_rehearsal::set(keys.clone());
        let a = apply(&apply(&opened, boundary(2), &[], &mut chains).unwrap(), boundary(2) + 1, &[], &mut chains).unwrap();
        check(&a, &mut chains, &switch);
    }
    // Program switch at epoch 2, settler set at epoch 3.
    {
        let (opened, mut chains) = funded_l2(1);
        let switch = test_switch(&opened, SupplyCap::Outstanding);
        let _armed = arm_switch(switch, 2);
        let a = apply(&apply(&opened, boundary(2), &[], &mut chains).unwrap(), boundary(2) + 1, &[], &mut chains).unwrap();
        let l2 = a.l2_settlement().unwrap();
        assert!(l2.settlers().is_empty());
        assert_eq!(l2.program(), switch.to);
        // Between the two: the new program, permissionless as today.
        assert_eq!(l2.validate_async(&next_settlement(&a, 0), &ProofDouble), Ok(()));
        let _gate = crate::params::l2_settler_authorization_rehearsal::open();
        let _set = crate::l2_settlement::settler_rehearsal::set(keys.clone());
        let b = apply(&a, boundary(3), &[], &mut chains).unwrap();
        check(&b, &mut chains, &switch);
    }
}

/// An activated L2 whose lifetime deposits are `room` sats below the L2
/// supply cap. `withdrawn`: all of it claimed again (escrow 0, the state of
/// audit L1X-03); otherwise all of it still in escrow.
fn capped_l2(room: u64, withdrawn: bool) -> (CommittedState, Vec<RandaoChain>) {
    let (mut opened, chains) = activated_fixture(true, [0; 32]);
    let l2 = opened.l2_settlement.as_mut().unwrap();
    let limits = *l2.limits();
    let sats = MAX_L2_DEPOSIT_SAT - room;
    let height = l2.height() + 1;
    l2.append_deposit(crate::l2_settlement::InboxRecord { height, tx_index: 0, txid: [1; 32], vout: 1, sats, recipient: [0x42; 20] })
        .unwrap();
    if withdrawn {
        let tree = vec![wd::leaf(700771, 0, &[7; 32], sats)];
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: 1, height });
        for _ in 0..limits.large_delay_blocks.max(limits.release_window_blocks) + 1 {
            l2.advance_height().unwrap();
        }
        l2.release_withdrawal(700771, 0, &[7; 32], sats, &wd::proof(&tree, 0).unwrap(), false, false).unwrap();
    }
    assert_eq!(l2.cumulative_deposited_sat(), u128::from(sats));
    assert_eq!(l2.escrow_sat(), if withdrawn { 0 } else { u128::from(sats) });
    (opened, chains)
}

/// `state` with its L2 switched to the pinned successor, as the boundary does.
fn switched(state: &CommittedState) -> CommittedState {
    let mut out = state.clone();
    assert!(out.l2_settlement.as_mut().unwrap().switch_program());
    out
}

/// The deposit rule of L1X-03 follows the program in force, for every
/// combination of the two gates: (cap gate inert | armed) x (old program |
/// new program with the outstanding cap | new program that keeps the
/// lifetime cap).
#[test]
fn l1x03_the_deposit_cap_follows_the_program_in_force() {
    let room = 5 * BLCH;
    let refusal = |state: &CommittedState, amount: u64| {
        let tx = deposit_tx(state, amount);
        let preflight = state.l2_deposit_refusal_at(&tx, state.next_base_fee());
        let mut copy = state.clone();
        let applied = copy.apply_transaction(&PosTransaction::L2Deposit(tx), 0, state.next_base_fee(), &ToyVerifier).map(|_| ());
        match preflight {
            None => assert_eq!(applied, Ok(()), "preflight and transition agree"),
            Some(why) => {
                assert_eq!(applied, Err(TxReject::L2Deposit(why)));
                assert_eq!(&copy, state, "a refused deposit changes nothing");
            }
        }
        preflight
    };
    let inbox = Some(L2DepositReject::Inbox);

    // The L1X-03 state: lifetime deposits 5 BLCH below the cap, escrow 0.
    let (cycled, _) = capped_l2(room, true);
    // The same lifetime total, nothing withdrawn: the escrow itself is 5
    // BLCH below the cap (reachable only with the whole supply deposited).
    let (escrowed, _) = capped_l2(room, false);

    for supply_cap in [SupplyCap::Outstanding, SupplyCap::GrossMinted] {
        let switch = test_switch(&cycled, supply_cap);
        // A program that keeps the lifetime cap keeps the configuration.
        let switch = if supply_cap == SupplyCap::GrossMinted { ProgramSwitch { to: [switch.from[0], switch.to[1], switch.to[2], switch.to[3]], ..switch } } else { switch };
        assert!(switch.valid());
        let _pinned = crate::l2_settlement::program_switch_rehearsal::set(switch);
        let (cycled_new, escrowed_new) = (switched(&cycled), switched(&escrowed));
        assert_eq!(cycled_new.l2_settlement().unwrap().supply_cap(), supply_cap);
        assert_eq!(cycled.l2_settlement().unwrap().supply_cap(), SupplyCap::GrossMinted, "the old program, whatever is pinned");

        // Cap gate inert: no cumulative rule under either program.
        for state in [&cycled, &cycled_new, &escrowed, &escrowed_new] {
            assert_eq!(refusal(state, room), None);
            assert_eq!(refusal(state, room + 1), None);
        }

        let _cap = crate::params::l2_cumulative_deposit_cap_rehearsal::open();
        // Old program: the lifetime rule of L1X-03, on both states.
        for state in [&cycled, &escrowed] {
            assert_eq!(refusal(state, room), None);
            assert_eq!(refusal(state, room + 1), inbox);
        }
        match supply_cap {
            // New program, outstanding cap: the lifetime total no longer
            // closes deposits (the guest can mint them)...
            SupplyCap::Outstanding => {
                assert_eq!(refusal(&cycled_new, room + 1), None);
                assert_eq!(refusal(&cycled_new, 400 * BLCH), None);
                // ...and the bound is the escrow, exact at the cap.
                assert_eq!(refusal(&escrowed_new, room), None);
                assert_eq!(refusal(&escrowed_new, room + 1), inbox);
            }
            // New program that still caps the lifetime mint: the L1 rule stays.
            SupplyCap::GrossMinted => {
                for state in [&cycled_new, &escrowed_new] {
                    assert_eq!(refusal(state, room), None);
                    assert_eq!(refusal(state, room + 1), inbox);
                }
            }
        }
    }
}

/// Through the transition with both gates armed: a deposit past the
/// lifetime total is refused in the last block before the switch boundary
/// and admitted in the boundary block. A poison record the old rule would
/// have refused never enters the inbox before the program that can mint it
/// is the accepted one.
#[test]
fn l1x03_the_deposit_rule_switches_with_the_program_at_the_boundary() {
    const GATE: u64 = 2;
    let room = 5 * BLCH;
    let (opened, mut chains) = capped_l2(room, true);
    let _armed = arm_switch(test_switch(&opened, SupplyCap::Outstanding), GATE);
    let _cap = crate::params::l2_cumulative_deposit_cap_rehearsal::open();
    let below = apply(&opened, boundary(GATE) - 2, &[], &mut chains).unwrap();
    {
        // The same chain again, for the block that is refused.
        let (opened, mut chains) = capped_l2(room, true);
        let below = apply(&opened, boundary(GATE) - 2, &[], &mut chains).unwrap();
        let beyond = PosTransaction::L2Deposit(deposit_tx(&below, room + 1));
        let block = template(&below, &mut chains);
        assert_eq!(block.header.slot, boundary(GATE) - 1);
        assert!(body_verdict(&below, &block, &[beyond]).is_err(), "the lifetime rule below the boundary");
    }
    let head = apply(&below, boundary(GATE) - 1, &[], &mut chains).unwrap();
    let tx = deposit_tx(&head, room + 1);
    // Node-local preflight at the head: still the old (stricter) rule.
    assert_eq!(head.l2_deposit_refusal_at(&tx, head.next_base_fee()), Some(L2DepositReject::Inbox));
    let post = apply(&head, boundary(GATE), &[PosTransaction::L2Deposit(tx)], &mut chains).expect("the boundary block is judged under the new program");
    let l2 = post.l2_settlement().unwrap();
    assert_eq!(l2.supply_cap(), SupplyCap::Outstanding);
    assert_eq!(l2.cumulative_deposited_sat(), u128::from(MAX_L2_DEPOSIT_SAT) + 1);
    assert_eq!(l2.escrow_sat(), u128::from(room + 1));
    assert!(l2.escrow_conserved());
}

/// The backlog bound of L1X-02 is independent of the program: a full
/// backlog refuses a deposit under both, with the cap gate armed or not.
#[test]
fn l1x02_the_backlog_bound_binds_under_both_programs() {
    let (mut opened, _) = activated_fixture(true, [0; 32]);
    let _pinned = crate::l2_settlement::program_switch_rehearsal::set(test_switch(&opened, SupplyCap::Outstanding));
    let l2 = opened.l2_settlement.as_mut().unwrap();
    let height = l2.height() + 1;
    for i in 0..crate::l2_settlement::MAX_PENDING_DEPOSITS {
        let mut txid = [2; 32];
        txid[..8].copy_from_slice(&i.to_be_bytes());
        l2.append_deposit(crate::l2_settlement::InboxRecord { height, tx_index: i as u32, txid, vout: 1, sats: BLCH, recipient: [0x42; 20] }).unwrap();
    }
    assert!(l2.deposit_backlog_full());
    for state in [opened.clone(), switched(&opened)] {
        let tx = deposit_tx(&state, BLCH);
        assert_eq!(state.l2_deposit_refusal_at(&tx, state.next_base_fee()), None, "as shipped");
        let _cap = crate::params::l2_cumulative_deposit_cap_rehearsal::open();
        assert_eq!(state.l2_deposit_refusal_at(&tx, state.next_base_fee()), None, "the cap rule alone admits it");
        let _inflow = crate::params::l2_deposit_inflow_bound_rehearsal::open();
        assert_eq!(state.l2_deposit_refusal_at(&tx, state.next_base_fee()), Some(L2DepositReject::Inbox));
    }
}

/// The chain of `mainnet_program_chain` (the pinned mainnet policy, flag day
/// at epoch 1, source of L2 block 1 frozen) rolled over the boundary of
/// epoch 2. With `armed` the PINNED mainnet switch is taken there.
fn mainnet_chain_past_the_switch(armed: bool) -> (CommittedState, CommittedState, Vec<RandaoChain>) {
    let program = mainnet::PROGRAM.expect("the mainnet program is pinned");
    let (pre, mut chains) = mainnet_program_chain(&program);
    let _gate = armed.then(|| crate::params::l2_settlement_program_switch_rehearsal::arm(2));
    let post = apply(&pre, boundary(2), &[], &mut chains).unwrap();
    (pre, post, chains)
}

/// REAL verifier, real Groth16 proof of the DEPLOYED program
/// (`mainnet-empty.*`), pinned mainnet policy and the pinned (candidate)
/// switch: the proof settles while the gate is inert, and after the switch
/// it is refused both as it is (it names the old program) and behind a
/// statement that names the new program (the pairing refuses it under the
/// new BN254 key). Not exercised: a real proof of the new program being
/// ACCEPTED; none exists until the release proves one.
#[test]
fn l2n01_real_groth16_of_the_deployed_program_is_refused_after_the_switch() {
    let program = mainnet::PROGRAM.expect("the mainnet program is pinned");
    let switch = mainnet::PROGRAM_SWITCH.expect("the candidate switch is recorded");
    let values: &[u8] = include_bytes!("../../../bloch-l2-proof/tests/fixtures/mainnet-empty.values");
    let proof: [u8; 356] = *include_bytes!("../../../bloch-l2-proof/tests/fixtures/mainnet-empty.proof");
    let fixture = Transaction { proof_policy: program.proof_policy, statement: values.to_vec(), proof, authorization: None };

    // Gate inert: the deployed program still settles past any boundary.
    let (_, inert, _) = mainnet_chain_past_the_switch(false);
    assert_eq!(inert.l2_settlement().unwrap().program(), switch.from);
    assert_eq!(inert.l2_settlement().unwrap().pending_program_switch(), Some(switch));
    assert_eq!(inert.l2_settlement().unwrap().validate_async(&fixture, &RealProof), Ok(()));
    assert_eq!(settlement_refusal(&inert, &fixture, &RealProof), None);

    // Gate armed at epoch 2: the pinned switch is taken at that boundary.
    let (pre, post, _) = mainnet_chain_past_the_switch(true);
    let l2 = post.l2_settlement().unwrap();
    assert_eq!(l2.program(), switch.to);
    assert_eq!(l2.policy().proof_policy, program.proof_policy, "the proof policy commitment stays");
    assert_eq!(l2.frozen_source(), pre.l2_settlement().unwrap().frozen_source(), "the fixture's source is still the pinned one");
    // As proved: names the old program.
    assert_eq!(l2.validate_async(&fixture, &RealProof), Err(Reject::Policy));
    assert_eq!(settlement_refusal(&post, &fixture, &RealProof), Some(TxReject::L2Settlement(Reject::Policy)));
    // Renamed to the new program: every proof-free check passes, and the
    // real verifier refuses the proof.
    let renamed = naming(fixture.clone(), &switch.to);
    assert_eq!(l2.pending_async_refusal(&renamed, *post.head.as_bytes(), post.slot), None);
    assert_eq!(l2.validate_async(&renamed, &RealProof), Err(Reject::Proof));
    assert_eq!(settlement_refusal(&post, &renamed, &RealProof), Some(TxReject::L2Settlement(Reject::Proof)));
    // The verifier alone: the old proof with its own public values verifies
    // under the old key and not under the new one.
    assert!(bloch_l2_proof::verify(&program.proof_policy, &switch.from[3], values, &proof));
    assert!(!bloch_l2_proof::verify(&program.proof_policy, &switch.to[3], values, &proof));
}

/// Operator helper for the release that arms the gate: the native request
/// (`BLOCH_NATIVE_L2_REQUEST`, 11 lines) of the fixture proof of the NEW
/// program, L2 block 1 on the chain of [`mainnet_chain_past_the_switch`].
/// The source was pinned before the switch and does not cover the program
/// identities, so it is the request of `mainnet-empty.request` as long as
/// the test chain is unchanged (asserted).
/// `cargo test -p bloch-pos-committee --lib print_mainnet_bound_program_fixture_request -- --ignored --nocapture`
#[test]
#[ignore = "operator helper; prints the native request of the bound-program fixture"]
fn print_mainnet_bound_program_fixture_request() {
    let (_, post, _) = mainnet_chain_past_the_switch(true);
    let l2 = post.l2_settlement().unwrap();
    let source = l2.frozen_source().unwrap();
    let ids = &l2.policy().identities;
    let h = |b: &[u8; 32]| hex::encode(b);
    let request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        h(&ids[0]), h(&ids[1]), h(&source.block), source.slot, source.height,
        h(&source.commitment), h(&source.inbox_root), h(&[0; 32]), source.inbox_count, l2.consumed(),
        source.inbox_count
    );
    assert_eq!(request, include_str!("../../../bloch-l2-proof/tests/fixtures/mainnet-empty.request"));
    println!("BEGIN-REQUEST");
    print!("{request}");
    println!("END-REQUEST");
    println!("program to prove (identities 3..7): {}", l2.program().iter().map(h).collect::<Vec<_>>().join(" "));
}

/// Release check, to become a normal test with a committed fixture before
/// the gate is armed: a REAL Groth16 proof of the new program (L2 block 1
/// for the request above) settles in the transition on the switched L2 and
/// is refused before the switch.
/// `BLOCH_BOUND_PROGRAM_FIXTURE_DIR=<dir with values, proof>
///  cargo test -p bloch-pos-committee --lib mainnet_bound_program_real_groth16 -- --ignored --nocapture`
#[test]
#[ignore = "release check; needs BLOCH_BOUND_PROGRAM_FIXTURE_DIR with a real proof of the new program"]
fn mainnet_bound_program_real_groth16() {
    let dir = std::path::PathBuf::from(std::env::var("BLOCH_BOUND_PROGRAM_FIXTURE_DIR").expect("BLOCH_BOUND_PROGRAM_FIXTURE_DIR"));
    let values = std::fs::read(dir.join("values")).unwrap();
    let proof: [u8; 356] = std::fs::read(dir.join("proof")).unwrap().try_into().expect("356-byte proof");
    let switch = mainnet::PROGRAM_SWITCH.expect("the switch is pinned");
    let (pre, post, mut chains) = mainnet_chain_past_the_switch(true);
    let policy = post.l2_settlement().unwrap().policy().clone();
    for (i, id) in policy.identities.iter().enumerate() {
        assert_eq!(hash_at(&values, S + i * 32), *id, "identity {i}: the proof is not of the pinned successor");
    }
    let tx = Transaction { proof_policy: policy.proof_policy, statement: values, proof, authorization: None };
    assert_eq!(pre.l2_settlement().unwrap().validate_async(&tx, &RealProof), Err(Reject::Policy), "refused before the switch");
    assert_eq!(post.l2_settlement().unwrap().validate_async(&tx, &RealProof), Ok(()));
    let transition = Transition::new(RealProof);
    let block = build_block(&transition, &post, post.slot + 1, &[], std::slice::from_ref(&wire(&tx)), &mut chains);
    let child = transition.apply_block(&post, &block, &[], std::slice::from_ref(&wire(&tx))).expect("the new program settles");
    assert_eq!(child.l2_settlement().unwrap().settled_number(), 1);
    assert_eq!(child.l2_settlement().unwrap().program(), switch.to);
}
