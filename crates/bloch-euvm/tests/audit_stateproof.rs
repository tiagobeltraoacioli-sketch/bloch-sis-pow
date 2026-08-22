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

// ═══════════════════════════════════════════════════════════════════════════════
// THE FIX — `gate_allows_bound`. The four tests above are LEFT EXACTLY AS THEY WERE:
// they pin what the unbound `gate_allows` does and does not promise, and they are
// the CONTROL half for everything below. Each test here re-runs the *same attack*
// against the bound API and shows it now fails, paired with a control showing the
// legitimate caller still passes (so "it rejects everything" cannot masquerade as
// a fix — the failure mode that makes a security test decorative).
// ═══════════════════════════════════════════════════════════════════════════════

use bloch_euvm::state::{gate_allows_bound, GateError};

/// FIX for FINDING 1a — the made-up-identity deny-gate evasion now fails.
#[test]
fn bound_deny_gate_rejects_a_made_up_identity_but_admits_a_genuinely_clean_one() {
    let mut deny = MembershipList::new();
    deny.add(b"sanctioned:mallory");
    let root = deny.root();

    // ATTACK (the exact one `deny_gate_is_bypassable_with_a_made_up_identity` pins):
    // mallory authenticates as herself but presents a non-membership proof about a
    // key she invented. The unbound gate lets this through; the bound gate does not.
    let evasion = deny.prove(b"whatever-i-invent-42");
    assert!(
        gate_allows(Gate::Deny, &root, &evasion),
        "precondition: the unbound gate is still bypassable (control unchanged)"
    );
    assert_eq!(
        gate_allows_bound(Gate::Deny, &root, &evasion, b"sanctioned:mallory"),
        Err(GateError::KeyMismatch),
        "bound deny-gate must refuse a proof that is not about the caller"
    );

    // CONTROL A — mallory proving about HERSELF is refused for the right reason:
    // wrong polarity (she IS on the list), not a key mismatch.
    let honest = deny.prove(b"sanctioned:mallory");
    assert_eq!(
        gate_allows_bound(Gate::Deny, &root, &honest, b"sanctioned:mallory"),
        Err(GateError::WrongPolarity)
    );

    // CONTROL B — a genuinely clean party still passes. Without this half, a gate
    // that simply returned Err always would look like a fix.
    let clean = deny.prove(b"clean:yolanda");
    assert_eq!(
        gate_allows_bound(Gate::Deny, &root, &clean, b"clean:yolanda"),
        Ok(())
    );
}

/// FIX for FINDING 1b — relaying a member's KYC proof now fails.
#[test]
fn bound_allow_gate_rejects_a_relayed_member_proof_but_admits_the_member() {
    let mut allow = MembershipList::new();
    allow.add(b"kyc:alice");
    let root = allow.root();
    let alices_proof = allow.prove(b"kyc:alice");

    // ATTACK: mallory relays alice's public proof. Unbound gate: passes (pinned by
    // `allow_gate_kyc_bypass_by_relaying_a_members_proof`). Bound gate: KeyMismatch.
    assert!(
        gate_allows(Gate::Allow, &root, &alices_proof),
        "precondition: the unbound gate is still relay-able (control unchanged)"
    );
    assert_eq!(
        gate_allows_bound(Gate::Allow, &root, &alices_proof, b"kyc:mallory"),
        Err(GateError::KeyMismatch),
        "bound allow-gate must refuse a proof issued to a different identity"
    );

    // CONTROL A — alice, presenting her own proof under her own authenticated id,
    // still passes. The binding must not break the legitimate path.
    assert_eq!(
        gate_allows_bound(Gate::Allow, &root, &alices_proof, b"kyc:alice"),
        Ok(())
    );

    // CONTROL B — mallory presenting her OWN (valid non-membership) proof is
    // refused as WrongPolarity: she is honestly not on the allow-list.
    let mallorys_own = allow.prove(b"kyc:mallory");
    assert_eq!(
        gate_allows_bound(Gate::Allow, &root, &mallorys_own, b"kyc:mallory"),
        Err(GateError::WrongPolarity)
    );
}

/// The binding must be EXACT — no prefix, suffix, or truncation slack. A key check
/// written as `starts_with` / `contains` (an easy mistake) would pass these ids.
#[test]
fn bound_gate_identity_match_is_exact_not_prefix_or_suffix() {
    let mut allow = MembershipList::new();
    allow.add(b"kyc:alice");
    let root = allow.root();
    let p = allow.prove(b"kyc:alice");

    for impostor in [
        &b"kyc:alic"[..],       // truncation
        b"kyc:alice2",          // suffix extension
        b"kyc:alicE",           // one-bit case flip
        b"xkyc:alice",          // prefix extension
        b"",                    // empty
    ] {
        assert_eq!(
            gate_allows_bound(Gate::Allow, &root, &p, impostor),
            Err(GateError::KeyMismatch),
            "near-miss identity {impostor:?} must not satisfy the binding"
        );
    }
    // control: the exact id passes
    assert_eq!(gate_allows_bound(Gate::Allow, &root, &p, b"kyc:alice"), Ok(()));
}

/// Identity binding must not be able to RESCUE a cryptographically invalid proof:
/// the two checks are independent, and a forged proof about your own real id still
/// fails on the crypto.
#[test]
fn bound_gate_still_rejects_a_forged_proof_about_the_callers_own_identity() {
    let mut allow = MembershipList::new();
    allow.add(b"kyc:alice");
    let root = allow.root();

    // mallory is genuinely absent; she forges MEMBERSHIP for her own real id.
    let mut forged = allow.prove(b"kyc:mallory");
    assert_eq!(
        gate_allows_bound(Gate::Allow, &root, &forged, b"kyc:mallory"),
        Err(GateError::WrongPolarity),
        "control: before forging, she fails on polarity"
    );
    forged.value = Some(vec![]); // claim the slot is occupied by her
    assert_eq!(
        gate_allows_bound(Gate::Allow, &root, &forged, b"kyc:mallory"),
        Err(GateError::ProofInvalid),
        "the identity binding must not paper over a broken proof"
    );

    // control: a genuine member's genuine proof under her own id still passes
    assert_eq!(
        gate_allows_bound(Gate::Allow, &root, &allow.prove(b"kyc:alice"), b"kyc:alice"),
        Ok(())
    );
}

/// A proof valid against a DIFFERENT root is refused even with a perfect identity
/// match — root binding and identity binding are both required, neither substitutes.
#[test]
fn bound_gate_rejects_a_proof_from_another_lists_root() {
    let mut real = MembershipList::new();
    real.add(b"kyc:alice");
    // An attacker-controlled list in which mallory IS a member.
    let mut fake = MembershipList::new();
    fake.add(b"kyc:mallory");

    let p = fake.prove(b"kyc:mallory");
    // control: against its own root, with matching identity, it is a valid pass
    assert_eq!(gate_allows_bound(Gate::Allow, &fake.root(), &p, b"kyc:mallory"), Ok(()));
    // attack: the same proof against the REAL list's root
    assert_eq!(
        gate_allows_bound(Gate::Allow, &real.root(), &p, b"kyc:mallory"),
        Err(GateError::ProofInvalid)
    );
}
