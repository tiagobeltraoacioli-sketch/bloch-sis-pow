//! # Known-answer tests (KATs): byte-pinned SMT roots, proof shape, validator hashes
//!
//! These pins were generated from the state.rs / modules.rs implementations as of
//! main@751afdae, BEFORE the incremental-SMT refactor of state.rs, and exist so that
//! refactor (and any future one) cannot silently change a committed identity:
//!
//! - `SparseMerkleTree::root()` participates in the harness's "EUV1" committed block
//!   section (src/harness.rs:194 `eutxo_state_root` → :232 `encode_eu_section`), so a
//!   root change is an identity change of the committed bytes, not an internal detail.
//! - `validator_hash` (lib.rs) is what an `ExtOutput.validator_hash` commits to and
//!   what `CompiledToken::policy_id` derives an AssetId from (modules.rs:434) — a
//!   changed hash re-addresses every contract and re-names every token.
//!
//! Discipline note: every constant below is a MEASURED value (printed from the
//! pre-refactor code and pasted), not a value computed by the code under test at
//! test time — otherwise the test would tautologically pass after any change.

use bloch_euvm::modules::{
    compile_charter, GovernanceConfig, KycConfig, ModuleKind, SupplyConfig, TokenCharter,
    TransferPolicyConfig, VestingConfig, CustodyConfig,
};
use bloch_euvm::state::{
    key_hash, verify, HolderSet, MembershipList, Registry, Snapshot, SparseMerkleTree,
    TREE_DEPTH,
};
use std::collections::BTreeMap;

fn unhex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

// ── the pinned constants (measured at main@751afdae) ────────────────────────────

const EMPTY_ROOT: &str = "ec5c1677d302509f93fb2f0515904da4ccaaf55969e5955e2e82b58ff9aad576";
const REGISTRY_ROOT: &str = "4b2227191aa1202f02f11cf2401444b105c73350573eab166c08b202aaf974e5";
const HOLDERSET_ROOT: &str = "fe17dc9d653d8f11116432441010e3032586e03c8c538c72ba796e7ebfc69bca";
const SNAPSHOT_ROOT: &str = "439e96be3ea0dbbcd08b0989d13461d0632b179a18607c92fd9a9a585979dac6";
const MEMBERSHIP_ROOT: &str = "3e37942de8dd9c38d90cc78dcd8eadb0eda75160d0183b84b20ba8c8070107ed";
const KEYHASH_SYMBOL: &str = "689165e53299d4972afb0a6780760585045a3d31ee95848f2a82023c7169944b";
const PROOF_SIB0: &str = "9c7b6d5474479a792d34c7fd90c9bdb24a6ba85422150b6fa86f2c90cfc33589";

const CHARTER_ID: &str = "2d93d984ee465fc613bf103e1f59be7c7409d19d8f319d3d51d785b61c5c9c54";
const VH_SUPPLY: &str = "328cb7fa105bf9364af3ebcbfa33fb3094f643b49e9c7e95cd8f8cbdde7061db";
const VH_TRANSFER: &str = "f56164ff3348bc6340dfa1b30a3234d705b0023ba958ceda02aea28b5d9d5c33";
const VH_KYC: &str = "cabcafa0aae12c4aefed296b63f2191213e4952e53367d2eb85f703612104164";
const VH_VESTING: &str = "441bcaae887bfc524e96cb1ca50c0810f3cc954e2b92b4e9d0019e0dc28a14a9";
const VH_GOVERNANCE: &str = "d0935beda5163c482ff19800be2d536f9e91eb0baaf7dd2865099e7a08674a1b";
const VH_CUSTODY: &str = "1fcea9a812b58478681603d99806720d35adc55b8d9ee5ddfba756d69331df5b";

// ── SMT roots ───────────────────────────────────────────────────────────────────

#[test]
fn empty_tree_root_is_pinned() {
    assert_eq!(SparseMerkleTree::new().root(), unhex(EMPTY_ROOT));
}

#[test]
fn registry_root_is_pinned() {
    let mut r = Registry::new();
    r.set(b"symbol", b"USTAV");
    r.set(b"decimals", b"6");
    r.set(b"issuer", b"postern-labs");
    assert_eq!(r.root(), unhex(REGISTRY_ROOT));
}

#[test]
fn holderset_root_is_pinned() {
    let mut hs = HolderSet::new(3);
    hs.set_balance(b"holder:alpha", 1_000).unwrap();
    hs.set_balance(b"holder:beta", 2_500).unwrap();
    assert_eq!(hs.root(), unhex(HOLDERSET_ROOT));
}

#[test]
fn snapshot_root_is_pinned() {
    let mut balances = BTreeMap::new();
    balances.insert(b"a".to_vec(), 100u64);
    balances.insert(b"b".to_vec(), 300u64);
    balances.insert(b"c".to_vec(), 600u64);
    assert_eq!(Snapshot::freeze(&balances).unwrap().root(), unhex(SNAPSHOT_ROOT));
}

#[test]
fn membership_root_is_pinned() {
    let mut ml = MembershipList::new();
    ml.add(b"kyc:alice");
    ml.add(b"kyc:bob");
    assert_eq!(ml.root(), unhex(MEMBERSHIP_ROOT));
}

// ── proof format: 256 x 32-byte siblings, byte-pinned first sibling ─────────────

#[test]
fn proof_format_is_pinned_256_siblings_and_verifies() {
    let mut r = Registry::new();
    r.set(b"symbol", b"USTAV");
    r.set(b"decimals", b"6");
    r.set(b"issuer", b"postern-labs");
    let p = r.prove(b"symbol");
    assert_eq!(p.siblings.len(), TREE_DEPTH);
    assert_eq!(p.siblings.len(), 256);
    // top-most sibling (depth 0) pinned byte-for-byte; the deepest sibling of a
    // 3-entry tree is an empty-ladder leaf (all-zero)
    assert_eq!(p.siblings[0], unhex(PROOF_SIB0));
    assert_eq!(p.siblings[255], [0u8; 32]);
    assert!(verify(&r.root(), &p));
}

#[test]
fn key_hash_is_pinned() {
    assert_eq!(key_hash(b"symbol"), unhex(KEYHASH_SYMBOL));
}

// ── validator hashes / charter id ───────────────────────────────────────────────

fn fixture_charter() -> TokenCharter {
    TokenCharter {
        token_name: b"USTV".to_vec(),
        modules: vec![
            ModuleKind::Supply(SupplyConfig { cap: 1_000_000, issuer_pubkey: b"issuer-pk".to_vec() }),
            ModuleKind::TransferPolicy(TransferPolicyConfig { authority_pubkey: b"authority-pk".to_vec() }),
            ModuleKind::ComplianceKycGate(KycConfig::default()),
            ModuleKind::Vesting(VestingConfig { unlock_height: 2_400, beneficiary_pubkey: b"benef-pk".to_vec() }),
            ModuleKind::Governance(GovernanceConfig { signers: vec![b"g1".to_vec(), b"g2".to_vec(), b"g3".to_vec()], threshold: 2 }),
            ModuleKind::Custody(CustodyConfig { btc_pubkey: b"btc-pk".to_vec(), pq_pubkey: b"pq-pk".to_vec() }),
        ],
    }
}

#[test]
fn compiled_charter_hashes_are_pinned() {
    let ct = compile_charter(&fixture_charter());
    assert_eq!(ct.charter_id, unhex(CHARTER_ID));
    let expected: &[(&str, &str)] = &[
        ("supply", VH_SUPPLY),
        ("transfer-policy", VH_TRANSFER),
        ("kyc-gate", VH_KYC),
        ("vesting", VH_VESTING),
        ("governance", VH_GOVERNANCE),
        ("custody", VH_CUSTODY),
    ];
    assert_eq!(ct.validators.len(), expected.len());
    for (m, (kind, vh)) in ct.validators.iter().zip(expected) {
        assert_eq!(&m.kind, kind);
        assert_eq!(m.validator_hash, unhex(vh), "validator_hash drifted for {kind}");
    }
    assert_eq!(ct.policy_id(), Some(unhex(VH_SUPPLY)));
}

// ── mutation-of-state pin: roots must MOVE when the state moves ─────────────────
// (control half: the pins above assert equality; this asserts the root is not a
// constant function — a broken cache that returns a stale root fails here)

#[test]
fn pinned_root_moves_when_state_moves_and_returns_when_state_returns() {
    let mut r = Registry::new();
    r.set(b"symbol", b"USTAV");
    r.set(b"decimals", b"6");
    r.set(b"issuer", b"postern-labs");
    let pinned = unhex(REGISTRY_ROOT);
    assert_eq!(r.root(), pinned);
    r.set(b"symbol", b"OTHER");
    assert_ne!(r.root(), pinned, "root failed to move with the state (stale cache?)");
    r.set(b"symbol", b"USTAV");
    assert_eq!(r.root(), pinned, "same map must reproduce the identical root");
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXHAUSTIVE OPCODE-ENCODING PIN — added after a mutation SURVIVED.
//
// `compiled_charter_hashes_are_pinned` above pins six real validator hashes, which
// looked like adequate coverage of program identity. It is not. A mutation that
// changed one opcode's encoding tag (`Op::Dup`: 0x10 -> 0x1a) — silently moving the
// `validator_hash` of every program that uses `Dup`, and therefore every eUTXO
// address and every `policy_id`/AssetId derived from one — **survived the entire
// 352-test suite.**
//
// Root cause, measured: `modules::compile_charter` only ever emits 14 of the 26
// encoding tags (no Dup, Drop, Sub, Mul, Shake256, Size, TxOutDatum, TxOutValidator,
// TxOutValue, SelfValidator, SelfAsset, TxOutAsset). Pinning charter hashes therefore
// pins only the tags the charter happens to use; the other 12 were unprotected.
//
// The encoding is a CONSENSUS-GRADE IDENTITY: `validator_hash = SHA-256d(
// encode_program(p))` (lib.rs) is what an `ExtOutput.validator_hash` commits to and
// what `CompiledToken::policy_id` turns into an asset id. A tag change is a silent
// re-addressing of every contract in existence, and it must not be possible to make
// one without a test failing.
//
// So this pins the encoding of a program containing EVERY `Op` variant, byte for
// byte, plus its hash. The `assert_matches_every_op_variant` exhaustive `match`
// below makes the coverage self-enforcing: adding a new `Op` fails to compile until
// someone adds it here and re-pins.
// ═══════════════════════════════════════════════════════════════════════════════

use bloch_euvm::{encode_program, validator_hash, Op};

/// One of every `Op` variant, with distinguishable operands (so an operand-encoding
/// change is caught too, not just a tag change).
fn every_op() -> Vec<Op> {
    vec![
        Op::PushInt(-1),
        Op::PushBytes(vec![0xde, 0xad]),
        Op::Dup,
        Op::Drop,
        Op::Swap,
        Op::ExpectDepth(7),
        Op::Pick(3),
        Op::Add,
        Op::Sub,
        Op::Mul,
        Op::Eq,
        Op::Lt,
        Op::Not,
        Op::Sha256d,
        Op::Shake256,
        Op::Size,
        Op::CtxField(2),
        Op::VerifySig,
        Op::VerifyEcdsa,
        Op::Verify,
        Op::TxOutDatum(1),
        Op::TxOutValidator(4),
        Op::TxOutValue(5),
        Op::SelfValidator,
        Op::SelfAsset,
        Op::TxOutAsset(6),
    ]
}

/// Byte-for-byte encoding of `every_op()`, measured at main@751afdae.
/// PushInt(-1) = 0x01 + i128::to_le_bytes = 16 x 0xff; PushBytes([de,ad]) = 0x02 +
/// u32 LE length 0x02000000 + payload; single-byte ops are their bare tag; indexed
/// ops are tag + one operand byte.
const ALL_OPS_ENCODING: &str = "01ffffffffffffffffffffffffffffffff0202000000dead101112140713032021223031324041425002606261700171047205737475\
06";
const ALL_OPS_VALIDATOR_HASH: &str =
    "d547220b03c61a23cabebaf728993d709f1cee42d3b017baa50a3a310665b209";

#[test]
fn every_opcode_encoding_tag_is_pinned_byte_for_byte() {
    let enc = encode_program(&every_op());
    let hex: String = enc.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        ALL_OPS_ENCODING.replace('\n', ""),
        "encode_program drifted: this changes validator_hash for every program using \
         the affected op, i.e. re-addresses live contracts"
    );
    assert_eq!(enc.len(), 55);
}

#[test]
fn validator_hash_of_the_all_ops_program_is_pinned() {
    assert_eq!(validator_hash(&every_op()), unhex(ALL_OPS_VALIDATOR_HASH));
}

/// Each individual tag, pinned in isolation, so a failure names the culprit op
/// instead of just reporting that a 55-byte blob changed.
#[test]
fn each_opcode_tag_is_pinned_individually() {
    let cases: &[(Op, u8)] = &[
        (Op::PushInt(0), 0x01),
        (Op::PushBytes(vec![]), 0x02),
        (Op::Dup, 0x10),
        (Op::Drop, 0x11),
        (Op::Swap, 0x12),
        (Op::Pick(0), 0x13),
        (Op::ExpectDepth(0), 0x14),
        (Op::Add, 0x20),
        (Op::Sub, 0x21),
        (Op::Mul, 0x22),
        (Op::Eq, 0x30),
        (Op::Lt, 0x31),
        (Op::Not, 0x32),
        (Op::Sha256d, 0x40),
        (Op::Shake256, 0x41),
        (Op::Size, 0x42),
        (Op::CtxField(0), 0x50),
        (Op::VerifySig, 0x60),
        (Op::Verify, 0x61),
        (Op::VerifyEcdsa, 0x62),
        (Op::TxOutDatum(0), 0x70),
        (Op::TxOutValidator(0), 0x71),
        (Op::TxOutValue(0), 0x72),
        (Op::SelfValidator, 0x73),
        (Op::SelfAsset, 0x74),
        (Op::TxOutAsset(0), 0x75),
    ];
    for (op, tag) in cases {
        let enc = encode_program(std::slice::from_ref(op));
        assert_eq!(enc[0], *tag, "encoding tag drifted for {op:?}");
    }
    // The tag space must stay injective — two ops sharing a tag would make two
    // different programs hash identically.
    let mut tags: Vec<u8> = cases.iter().map(|(_, t)| *t).collect();
    tags.sort_unstable();
    let before = tags.len();
    tags.dedup();
    assert_eq!(tags.len(), before, "two opcodes share an encoding tag");
}

/// Self-enforcing coverage: this exhaustive `match` fails to COMPILE if an `Op`
/// variant is added, forcing whoever adds it to pin its tag above. Without this,
/// the pins silently stop being exhaustive the moment the instruction set grows —
/// which is exactly how the gap this whole section exists to close was created.
#[test]
fn pinned_op_list_is_exhaustive_over_the_instruction_set() {
    for op in every_op() {
        match op {
            Op::PushInt(_) | Op::PushBytes(_) | Op::Dup | Op::Drop | Op::Swap
            | Op::ExpectDepth(_) | Op::Pick(_) | Op::Add | Op::Sub | Op::Mul | Op::Eq
            | Op::Lt | Op::Not | Op::Sha256d | Op::Shake256 | Op::Size | Op::CtxField(_)
            | Op::VerifySig | Op::VerifyEcdsa | Op::Verify | Op::TxOutDatum(_)
            | Op::TxOutValidator(_) | Op::TxOutValue(_) | Op::SelfValidator
            | Op::SelfAsset | Op::TxOutAsset(_) => {}
        }
    }
    assert_eq!(every_op().len(), 26, "every_op() must list each variant exactly once");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE-COHERENCE: the incremental engine must be indistinguishable from a rebuild.
//
// Added because mutation M12 (`remove` skips `invalidate_path`, leaving a deleted
// key still committed in the root) was killed by exactly ONE incidental test. A
// stale-cache bug is the characteristic failure mode of the incremental rewrite, so
// it deserves a test aimed at it rather than one that happens to trip over it.
//
// The invariant: for ANY sequence of mutations, the resulting root must equal the
// root of a tree built fresh from the resulting map. That is the whole correctness
// claim of the cache, stated directly.
// ═══════════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap as StdMap;

/// Build a fresh tree holding exactly `m` — the cache-free reference for `m`'s root.
fn rebuilt(m: &StdMap<Vec<u8>, Vec<u8>>) -> SparseMerkleTree {
    let mut t = SparseMerkleTree::new();
    for (k, v) in m {
        t.insert(k, v);
    }
    t
}

#[test]
fn incremental_root_equals_a_fresh_rebuild_after_every_mutation() {
    let mut t = SparseMerkleTree::new();
    let mut m: StdMap<Vec<u8>, Vec<u8>> = StdMap::new();

    // A script that exercises every cache-invalidation path: growth, overwrite,
    // deletion, re-insertion of a deleted key, and deletion down to empty.
    // Deliberately small: `rebuilt()` is the cache-free reference, so it re-hashes the
    // whole map on every step (|m| x 256 SHAKE-256 calls). Debug-build SHAKE-256
    // measures ~425 us/hash here, making this quadratic in wall-clock. Ten keys
    // already exercise every invalidation path (grow / overwrite / delete / re-insert
    // / drain); more only buys runtime.
    let keys: Vec<Vec<u8>> = (0..10u32).map(|i| format!("k{i}").into_bytes()).collect();

    for (i, k) in keys.iter().enumerate() {
        let v = vec![i as u8; 1 + i % 5];
        t.insert(k, &v);
        m.insert(k.clone(), v);
        assert_eq!(t.root(), rebuilt(&m).root(), "after insert {i}");
    }
    for (i, k) in keys.iter().enumerate().filter(|(i, _)| i % 3 == 0) {
        t.insert(k, b"OVERWRITTEN");
        m.insert(k.clone(), b"OVERWRITTEN".to_vec());
        assert_eq!(t.root(), rebuilt(&m).root(), "after overwrite {i}");
    }
    // Deletion is the path M12 broke.
    for (i, k) in keys.iter().enumerate().filter(|(i, _)| i % 2 == 0) {
        t.remove(k);
        m.remove(k);
        assert_eq!(t.root(), rebuilt(&m).root(), "after remove {i} (stale cache?)");
        // and the deleted key must now prove NON-membership against the live root
        let p = t.prove(k);
        assert!(!p.is_membership(), "removed key still reads as present ({i})");
        assert!(verify(&t.root(), &p), "non-membership proof must verify ({i})");
    }
    // Re-inserting a removed key must return the tree to the same root as a rebuild.
    t.insert(&keys[0], b"back");
    m.insert(keys[0].clone(), b"back".to_vec());
    assert_eq!(t.root(), rebuilt(&m).root(), "after re-insert of a removed key");

    // Drain to empty: the root must land exactly on the empty-ladder head.
    for k in &keys {
        t.remove(k);
        m.remove(k);
        assert_eq!(t.root(), rebuilt(&m).root(), "while draining");
    }
    assert!(t.is_empty());
    assert_eq!(
        t.root(),
        SparseMerkleTree::new().root(),
        "a drained tree must be byte-identical to a never-used one"
    );
    assert_eq!(t.root(), unhex(EMPTY_ROOT), "and equal to the pinned empty root");
}

/// Insertion order must not be observable in the root — the cache is a memo keyed by
/// mutation history, so if any of it leaked into the root, two orderings would differ.
#[test]
fn cache_history_does_not_leak_into_the_root() {
    let pairs: &[(&[u8], &[u8])] = &[
        (b"alpha", b"1"),
        (b"beta", b"2"),
        (b"gamma", b"3"),
        (b"delta", b"4"),
    ];
    let mut forward = SparseMerkleTree::new();
    for (k, v) in pairs {
        forward.insert(k, v);
    }
    let mut backward = SparseMerkleTree::new();
    for (k, v) in pairs.iter().rev() {
        backward.insert(k, v);
    }
    // a third tree reaches the same map through a churn of wrong values and removals
    let mut churned = SparseMerkleTree::new();
    churned.insert(b"gamma", b"WRONG");
    churned.insert(b"zeta", b"transient");
    churned.insert(b"alpha", b"1");
    churned.remove(b"zeta");
    churned.insert(b"delta", b"4");
    churned.insert(b"gamma", b"3");
    churned.insert(b"beta", b"2");

    assert_eq!(forward.root(), backward.root());
    assert_eq!(forward.root(), churned.root(), "mutation history leaked into the root");
    // proofs, not just roots, must be history-independent byte-for-byte
    assert_eq!(forward.prove(b"beta"), churned.prove(b"beta"));
    assert_eq!(forward.prove(b"absent"), churned.prove(b"absent"));
}
