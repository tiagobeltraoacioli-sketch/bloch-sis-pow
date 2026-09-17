//! Executable evidence for CR-01, NOT a security-success regression.
//!
//! Two tests characterize unresolved authorization; two test the duplicate-leaf
//! mitigation. C1 freezes formats but leaves the recipient/nullifier
//! key hierarchy unspecified. These tests deliberately show what the current
//! unversioned statement accepts. Do not enable a funded pool on this statement.
//! Replace these characterizations only with an explicitly versioned statement,
//! reviewed key derivation, new guest/verifier identity and migration policy.

use coherence_core::{
    check_spend, CommitmentTree, Note, NullifierSet, SpendError, SpendInput, SpendPublic, SpendWitness,
};

fn note(value: u64, recipient: u8) -> Note {
    Note { v: value, pk_d: [recipient; 32], rho: [11; 32], psi: [22; 32] }
}

fn fixture(input: &Note, nullifier_keys: &[[u8; 32]]) -> (SpendPublic, SpendWitness) {
    let mut tree = CommitmentTree::new();
    let position = tree.append(input.commitment());
    let path = tree.path(position).unwrap();
    let output = note(input.v * nullifier_keys.len() as u64, 0xee);
    let public = SpendPublic {
        anchor: tree.root(),
        nullifiers: nullifier_keys.iter().map(|nk| input.nullifier(nk, position)).collect(),
        out_commitments: vec![output.commitment()],
        fee: 0,
    };
    let witness = SpendWitness {
        inputs: nullifier_keys.iter().map(|nk| SpendInput {
            note: input.clone(), position, path: path.clone(), nk: *nk,
        }).collect(),
        outputs: vec![output],
    };
    (public, witness)
}

#[test]
fn known_unsafe_v1_plaintext_holder_can_choose_nullifier_key_and_recipient() {
    // A sender knows the note opening it created. No recipient spending key,
    // authorization signature or key-derivation witness is available here.
    let recipient_note = note(1_000, 7);
    let (public, witness) = fixture(&recipient_note, &[[0xa1; 32]]);
    assert_ne!(recipient_note.pk_d, witness.outputs[0].pk_d);
    assert_eq!(check_spend(&public, &witness), Ok(()),
        "CR-01 characterization: current statement proves no recipient authorization");
}

#[test]
fn known_unsafe_v1_one_note_produces_multiple_accepted_unspent_nullifiers() {
    let input = note(1_000, 7);
    let (first, first_witness) = fixture(&input, &[[0xa1; 32]]);
    let (second, second_witness) = fixture(&input, &[[0xb2; 32]]);
    assert_eq!(first.anchor, second.anchor);
    assert_eq!(first_witness.inputs[0].position, second_witness.inputs[0].position);
    assert_ne!(first.nullifiers, second.nullifiers);
    assert_eq!(check_spend(&first, &first_witness), Ok(()));
    assert_eq!(check_spend(&second, &second_witness), Ok(()));
    let mut spent = NullifierSet::new();
    assert!(spent.insert(first.nullifiers[0]));
    assert!(spent.insert(second.nullifiers[0]),
        "distinct attacker-chosen nullifiers bypass normal repeated-nullifier rejection");
}

#[test]
fn repeated_position_with_different_nullifier_keys_cannot_double_value() {
    let input = note(1_000, 7);
    let (public, witness) = fixture(&input, &[[0xa1; 32], [0xb2; 32]]);
    assert_eq!(witness.inputs[0].note, witness.inputs[1].note);
    assert_eq!(witness.inputs[0].position, witness.inputs[1].position);
    assert_ne!(public.nullifiers[0], public.nullifiers[1]);
    assert_eq!(witness.outputs[0].v, 2 * input.v);
    assert_eq!(check_spend(&public, &witness), Err(SpendError::DuplicateInputPosition(1)),
        "one funded leaf must not be counted twice in one witness");
    let mut spent = NullifierSet::new();
    assert!(public.nullifiers.iter().all(|nf| spent.insert(*nf)));
}

#[test]
fn separately_funded_positions_remain_spendable_even_with_identical_commitments() {
    let input = note(1_000, 7);
    let mut tree = CommitmentTree::new();
    tree.append(input.commitment());
    tree.append(input.commitment());
    let output = note(2_000, 0xee);
    let nk = [0xa1; 32];
    let public = SpendPublic { anchor: tree.root(),
        nullifiers: (0..2).map(|position| input.nullifier(&nk, position)).collect(),
        out_commitments: vec![output.commitment()], fee: 0 };
    let witness = SpendWitness { inputs: (0..2).map(|position| SpendInput {
        note: input.clone(), position, path: tree.path(position).unwrap(), nk,
    }).collect(), outputs: vec![output] };
    assert_eq!(check_spend(&public, &witness), Ok(()));
}
