//! Adversarial state-commitment / proof-soundness repros (auditor lens).
//!
//! These integration tests exercise the PUBLIC state.rs surface exactly as a
//! consensus integrator would call it, and demonstrate concrete ways the
//! membership/deny gating can be bypassed. They must all PASS — each `assert!`
//! encodes the *attacker's* success, i.e. the bypass working.

use bloch_euvm::state::{
    gate_allows, key_hash, verify, Gate, MembershipList, Proof, SparseMerkleTree,
};

/// FINDING 1a — DENY-GATE BYPASS (sanctions list is inert without identity binding).
///
/// A deny/sanctions list is supposed to block listed ids. `gate_allows(Deny, ..)`
/// passes iff the caller presents a *valid non-membership proof*. But it never binds
/// `proof.key` to who is actually transacting, so a sanctioned party simply presents
/// a non-membership proof for a key it INVENTED on the spot (trivially absent) and
/// sails through. The deny list provides zero protection.
#[test]
fn deny_gate_is_bypassable_with_a_made_up_identity() {
    let mut deny = MembershipList::new();
    deny.add(b"sanctioned:mallory");
    let root = deny.root();

    // Sanity: a proof *about mallory* is correctly rejected by the deny gate.
    let honest = deny.prove(b"sanctioned:mallory");
    assert!(!gate_allows(Gate::Deny, &root, &honest));

    // Attack: mallory does not prove anything about herself. She fabricates a
    // non-membership proof for a fresh key nobody ever deny-listed.
    let evasion = deny.prove(b"whatever-i-invent-42");
    assert!(verify(&root, &evasion), "the made-up-key proof is valid");
    assert!(
        gate_allows(Gate::Deny, &root, &evasion),
        "DENY BYPASS: sanctioned actor passes the deny gate"
    );
}

/// FINDING 1b — ALLOW-GATE (KYC) BYPASS by relaying a member's public proof.
///
/// Only `kyc:alice` is approved. Her membership proof is public data (it rides in
/// her own spending transaction / is derivable from the committed root). A party who
/// is NOT on the allow-list replays alice's proof; `gate_allows(Allow, ..)` cannot
/// tell it is not the replayer's own, because it never checks `proof.key` against the
/// transacting identity.
#[test]
fn allow_gate_kyc_bypass_by_relaying_a_members_proof() {
    let mut allow = MembershipList::new();
    allow.add(b"kyc:alice");
    let root = allow.root();

    let alices_proof = allow.prove(b"kyc:alice");

    // Mallory is not KYC-approved.
    assert!(!allow.contains(b"kyc:mallory"));

    // Replaying alice's proof satisfies the allow gate regardless of who presents it.
    assert!(
        gate_allows(Gate::Allow, &root, &alices_proof),
        "KYC BYPASS: a non-member passes an Allow gate by relaying a member's proof"
    );
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
