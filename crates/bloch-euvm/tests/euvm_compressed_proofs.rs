//! # Compressed proofs — round-trip exactness, size win, and adversarial expansion
//!
//! Closes finding 3 of docs/specs/BLOCH-L1-EVM-REUSE-AUDIT.md §7.1 ("Proofs are
//! uncompressed: 256 × 32 B = 8 KiB each, with no empty-ladder run compression").
//!
//! The compressed form is a **transport format beside the committed one**: roots and
//! `verify` are unchanged (they are pinned identities — tests/euvm_pinned_roots.rs),
//! so the entire correctness burden here is that `expand(compress(p)) == p` exactly,
//! and that a malformed compressed witness is refused rather than expanded into some
//! other well-formed proof.

use bloch_euvm::state::{
    compress, expand, verify, verify_compressed, CompressedProof, MembershipList, Registry,
    SparseMerkleTree, TREE_DEPTH,
};

/// Build an n-entry tree. Fixture sizes are deliberately small: SHAKE-256 in a debug
/// build measures ~425 us/hash on the dev machine and building n entries costs about
/// n x 256 hashes, so n=256 alone is ~28 s of pure hashing. The compression property
/// under test is about the *shape* of the empty-ladder runs, which n=40 already
/// exhibits (log2(40) ~ 5 non-empty levels out of 256).
fn tree_of(n: u32) -> SparseMerkleTree {
    let mut t = SparseMerkleTree::new();
    for i in 0..n {
        t.insert(format!("key-{i}").as_bytes(), format!("value-{i}").as_bytes());
    }
    t
}

// ── exactness: the whole safety argument ───────────────────────────────────────

#[test]
fn compress_expand_round_trips_exactly_membership_and_nonmembership() {
    for n in [0u32, 1, 2, 3, 17] {
        let t = tree_of(n);
        let root = t.root();
        for probe in ["key-0", "key-1", "key-16", "absent-key", ""] {
            let p = t.prove(probe.as_bytes());
            let c = compress(&p).expect("well-formed proof compresses");
            let back = expand(&c).expect("its own compression expands");
            assert_eq!(back, p, "round-trip inexact (n={n}, probe={probe:?})");
            // and the compressed form verifies exactly when the original does
            assert_eq!(verify_compressed(&root, &c), verify(&root, &p));
            assert!(verify(&root, &p), "sanity: honest proofs verify (n={n})");
        }
    }
}

#[test]
fn compressed_proof_preserves_membership_polarity() {
    let t = tree_of(4);
    let member = compress(&t.prove(b"key-1")).unwrap();
    let absent = compress(&t.prove(b"nobody")).unwrap();
    assert!(member.is_membership());
    assert!(!absent.is_membership());
    assert!(verify_compressed(&t.root(), &member));
    assert!(verify_compressed(&t.root(), &absent));
}

// ── the size win, measured (not asserted vaguely) ──────────────────────────────

#[test]
fn compression_actually_shrinks_the_witness_and_scales_with_log_n() {
    let full = TREE_DEPTH * 32; // 8192 B
    assert_eq!(full, 8192);

    // A single-entry tree: every sibling on the path is empty ⇒ bitmap only.
    let mut one = SparseMerkleTree::new();
    one.insert(b"solo", b"v");
    let c1 = compress(&one.prove(b"solo")).unwrap();
    assert_eq!(c1.nodes.len(), 0, "a lone leaf has no non-empty siblings");
    assert_eq!(c1.witness_bytes(), 32);

    // Growth is logarithmic-ish, and always far under the uncompressed size.
    let mut prev = 0usize;
    for n in [2u32, 8, 40] {
        let t = tree_of(n);
        let c = compress(&t.prove(b"key-1")).unwrap();
        assert!(
            c.witness_bytes() < full / 4,
            "n={n}: {} B is not a meaningful win over {full} B",
            c.witness_bytes()
        );
        assert!(
            c.nodes.len() <= 32,
            "n={n}: {} non-empty levels is not log-shaped",
            c.nodes.len()
        );
        prev = prev.max(c.nodes.len());
    }
    assert!(prev >= 1, "control: a populated tree must have SOME non-empty sibling");
}

// ── adversarial expansion: a malformed witness must be refused, not reinterpreted ──

#[test]
fn expand_rejects_a_bitmap_popcount_that_disagrees_with_nodes() {
    let t = tree_of(8);
    let good = compress(&t.prove(b"key-3")).unwrap();
    assert!(expand(&good).is_some(), "control: the honest witness expands");
    assert!(!good.nodes.is_empty(), "control: this fixture has non-empty siblings");

    // truncate the node list without clearing bits: every later sibling would shift
    let mut short = good.clone();
    short.nodes.pop();
    assert_eq!(expand(&short), None, "truncated witness must be refused");

    // pad the node list without setting bits
    let mut long = good.clone();
    long.nodes.push([0xaa; 32]);
    assert_eq!(expand(&long), None, "padded witness must be refused");

    // clear a bit without removing its node
    let mut cleared = good.clone();
    for b in cleared.present.iter_mut() {
        if *b != 0 {
            *b &= *b - 1; // clear the lowest set bit
            break;
        }
    }
    assert_eq!(expand(&cleared), None, "bitmap/nodes disagreement must be refused");
}

#[test]
fn a_fully_attacker_authored_compressed_proof_does_not_verify() {
    let mut ml = MembershipList::new();
    ml.add(b"kyc:alice");
    let root = ml.root();

    // control: the real member's compressed proof verifies
    assert!(verify_compressed(&root, &compress(&ml.prove(b"kyc:alice")).unwrap()));

    // attack: mint membership for a ghost with an all-empty witness
    let forged = CompressedProof {
        key: b"kyc:mallory".to_vec(),
        value: Some(vec![]),
        present: [0u8; 32],
        nodes: vec![],
    };
    assert!(
        !verify_compressed(&root, &forged),
        "an empty witness must not certify membership"
    );

    // attack: a well-formed bitmap with attacker-chosen node hashes
    let mut bogus = compress(&ml.prove(b"kyc:mallory")).unwrap();
    bogus.value = Some(vec![]); // claim membership
    assert!(!verify_compressed(&root, &bogus));
}

#[test]
fn compress_refuses_a_structurally_invalid_proof() {
    let t = tree_of(4);
    let mut p = t.prove(b"key-0");
    assert!(compress(&p).is_some(), "control: a full-length proof compresses");
    p.siblings.truncate(TREE_DEPTH - 1);
    assert_eq!(compress(&p), None, "a short proof must not compress");
    p.siblings = vec![[0u8; 32]; TREE_DEPTH + 1];
    assert_eq!(compress(&p), None, "an over-long proof must not compress");
}

/// The subtle case: a *genuine* sibling that happens to equal the empty-ladder value
/// for its depth is dropped by compression and regenerated identically by expansion.
/// That is safe (the two are the same 32 bytes and fold the same way) and this test
/// exists so the claim is checked rather than assumed — with the Registry wrapper, the
/// path most likely to hit it.
#[test]
fn siblings_equal_to_the_empty_ladder_round_trip_and_still_verify() {
    let mut r = Registry::new();
    r.set(b"a", b"1");
    r.set(b"b", b"2");
    r.set(b"c", b"3");
    let root = r.root();
    for k in [&b"a"[..], b"b", b"c", b"zzz"] {
        let p = r.prove(k);
        let c = compress(&p).unwrap();
        assert_eq!(expand(&c).unwrap(), p);
        assert!(verify_compressed(&root, &c));
        // the dropped levels really were empty-ladder values, not data loss
        assert!(c.nodes.len() < TREE_DEPTH);
    }
}
