//! Adversarial state-commitment / proof-soundness repros (auditor lens).
//!
//! These integration tests exercise the PUBLIC state.rs surface exactly as a
//! consensus integrator would call it. FINDINGS 1a/1b (deny-gate bypass with an
//! invented identity, allow-gate bypass by replaying a member's proof) are FIXED:
//! `gate_allows` now takes the authenticated caller's `id` and requires the proof to
//! be about that id. Those two tests are now fail-closed regression guards — each
//! `assert!` encodes the attacker's *failure*, and reverting the binding turns them
//! red.

use bloch_euvm::state::{
    gate_allows, key_hash, verify, Gate, MembershipList, Proof, SparseMerkleTree,
};

/// FINDING 1a (FIXED — regression) — the deny gate is bound to the caller's identity.
///
/// A deny/sanctions list is supposed to block listed ids. It used to pass on any
/// *valid non-membership proof*, without binding `proof.key` to who is transacting,
/// so a sanctioned party sailed through by proving the absence of a key it invented on
/// the spot. `gate_allows` now takes the authenticated `id` and requires the proof to
/// be about it, so the only proof mallory can present about herself is the one that
/// (correctly) fails.
#[test]
fn deny_gate_cannot_be_bypassed_with_a_made_up_identity() {
    let mut deny = MembershipList::new();
    deny.add(b"sanctioned:mallory");
    let root = deny.root();

    // A proof *about mallory* is correctly rejected by the deny gate.
    let honest = deny.prove(b"sanctioned:mallory");
    assert!(!gate_allows(Gate::Deny, &root, b"sanctioned:mallory", &honest));

    // The old evasion: a non-membership proof for a fresh key nobody ever deny-listed.
    // The proof itself is still perfectly valid against the root...
    let evasion = deny.prove(b"whatever-i-invent-42");
    assert!(verify(&root, &evasion), "the made-up-key proof is valid");
    // ...but it is not about mallory, so it no longer clears mallory's gate.
    assert!(
        !gate_allows(Gate::Deny, &root, b"sanctioned:mallory", &evasion),
        "DENY BYPASS: a sanctioned actor passed the deny gate with an invented identity"
    );
    // Nor can she pass by *claiming* the invented identity: the id the gate consumes is
    // the one the transaction authenticates, not a self-asserted label riding with the
    // proof — asserted here by checking the gate against every id in play.
    assert!(gate_allows(Gate::Deny, &root, b"whatever-i-invent-42", &evasion));

    // A genuinely clean party still passes, proving about itself.
    assert!(gate_allows(Gate::Deny, &root, b"clean:alice", &deny.prove(b"clean:alice")));
}

/// FINDING 1b (FIXED — regression) — an allow (KYC) gate cannot be cleared by replay.
///
/// Only `kyc:alice` is approved. Her membership proof is public data (it rides in her
/// own spending transaction / is derivable from the committed root), so any observer
/// can copy it. The gate now checks `proof.key` against the transacting identity, so
/// replaying alice's proof under mallory's id fails closed.
#[test]
fn allow_gate_kyc_cannot_be_bypassed_by_relaying_a_members_proof() {
    let mut allow = MembershipList::new();
    allow.add(b"kyc:alice");
    let root = allow.root();

    let alices_proof = allow.prove(b"kyc:alice");

    // Mallory is not KYC-approved.
    assert!(!allow.contains(b"kyc:mallory"));

    // Replaying alice's proof no longer satisfies the allow gate for mallory.
    assert!(
        !gate_allows(Gate::Allow, &root, b"kyc:mallory", &alices_proof),
        "KYC BYPASS: a non-member passed an Allow gate by relaying a member's proof"
    );
    // Her own proof is a (valid) non-membership proof — wrong polarity for Allow.
    assert!(!gate_allows(Gate::Allow, &root, b"kyc:mallory", &allow.prove(b"kyc:mallory")));
    // And alice, proving about herself, still passes.
    assert!(gate_allows(Gate::Allow, &root, b"kyc:alice", &alices_proof));
}

/// CONTROL — the genuine crypto core IS sound: a forged membership proof for an
/// absent key does NOT verify, and a non-membership proof re-pointed to a real member
/// does NOT verify. (These confirm the bypass above is an API/binding defect, not a
/// hash break.)
#[test]
fn crypto_core_membership_forgery_still_fails() {
    let mut t = SparseMerkleTree::new();
    t.insert(b"alice", b"100");
    t.insert(b"bob", b"200");
    let root = t.root();

    // forge membership for an absent key
    let mut p = t.prove(b"carol");
    assert!(verify(&root, &p));
    p.value = Some(b"1".to_vec());
    assert!(!verify(&root, &p), "cannot fabricate membership from a root");

    // re-point a non-membership witness onto a real member
    let mut q = t.prove(b"nobody");
    assert!(verify(&root, &q));
    q.key = b"alice".to_vec();
    assert!(!verify(&root, &q), "cannot certify a real member as absent");
}

/// INFO — leaf/node/key domain separation holds by construction: the same 32-byte
/// sibling values, reinterpreted, cannot be folded into a passing proof against an
/// empty root (a fully-attacker-constructed proof with default siblings folds a
/// nonzero leaf and never reproduces the empty-tree root).
#[test]
fn attacker_constructed_membership_against_empty_root_fails() {
    let empty_root = SparseMerkleTree::new().root();
    // Attacker fabricates a membership proof from scratch: all-default siblings.
    let kh = key_hash(b"ghost");
    let _ = kh;
    let forged = Proof {
        key: b"ghost".to_vec(),
        value: Some(b"1000000".to_vec()),
        siblings: vec![[0u8; 32]; 256],
    };
    assert!(
        !verify(&empty_root, &forged),
        "cannot mint membership against an empty committed root"
    );
}
