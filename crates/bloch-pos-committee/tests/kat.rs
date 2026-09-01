// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests (KATs) for everything hash-derived in this crate.
//!
//! ## Provenance
//!
//! Recovered on 2026-09-01 from `worktree-agent-a783f4d0602e0cad4` (commit
//! `2e76886d`, 2026-08-11), a branch scheduled for deletion. `kat/vectors.json`
//! and this harness existed on that ref and on no other; they are the only two
//! paths in the whole 131-branch deletion set that exist nowhere else.
//!
//! What changed on recovery, and what did NOT:
//!
//! - **No pinned value was touched.** Every digest generated on 2026-08-11 —
//!   the eight original tags, three attestation signing roots, six sortition
//!   draws, the whole RANDAO walkthrough — was re-checked against the tree at
//!   `main` @ `737078d1` and still matches, byte for byte.
//! - The `beacon` module was restructured in between (`chain_step` became
//!   private, `mix` became `mix_in`, commit/verify moved onto
//!   `RandaoChain`/`RevealState`, `RANDAO_CHAIN_LENGTH` became `u32`). Only
//!   the call sites moved; see the shims below and
//!   `local_chain_step_matches_the_crate`.
//! - `params.rs` grew six tags after the file was pinned (`DS_SPEND`,
//!   `DS_TXID`, `DS_PROPOSE`, `DS_EXIT`, `DS_WSCKPT`, `DS_COHERENCE`).
//!   `every_source_tag_has_a_vector` caught all six, which is the guard doing
//!   its job. Their vectors were generated on 2026-09-01 from the code as it
//!   stands and appended; the regeneration diff added 54 lines and changed or
//!   removed none, which is the evidence for the first bullet.
//! - The SPDX header was MIT OR Apache-2.0 on the branch; the crate is
//!   AGPL-3.0-or-later. Corrected to the crate's licence.
//!
//! Covers §6.1 (domain separation tags), §6.3 (RANDAO beacon steps), the
//! attestation signing root, and the sortition draws — the A1 deliverable of
//! §12 of `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`.
//!
//! ## The vector file is normative
//!
//! `kat/vectors.json` is the normative truth for these rules: a second client
//! implementation validates against that file, not against this crate. The
//! vectors were generated from the code once and then FIXED; every test here
//! therefore reads the file and compares — it never merely recomputes both
//! sides from the same code, which would test nothing.
//!
//! ## Changing a rule
//!
//! If a hash rule changes intentionally (a consensus change), regenerate with
//!
//! ```text
//! cargo test --test kat -- --ignored regenerate_vectors
//! ```
//!
//! and review the resulting diff of `kat/vectors.json` line by line — every
//! changed digest is a consensus break for any implementation already
//! following the old file.
//!
//! ## Adding a tag
//!
//! `every_source_tag_has_a_vector` scans `src/` for `BLCH4:` byte-string
//! literals and fails if any tag lacks a vector (or a vector lacks a tag), so
//! a new tag in `params.rs` cannot land silently without extending this file.

use bloch_pos_committee::attestation::AttestationData;
use bloch_pos_committee::beacon;
use bloch_pos_committee::params;
use bloch_pos_committee::sample::{sample, Role, Validator};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Every domain separation tag defined in `params.rs`, by constant name.
/// `every_source_tag_has_a_vector` cross-checks this table against the actual
/// source, so it cannot silently go stale.
const TAGS: [(&str, [u8; 16]); 14] = [
    // The eight §6.1 tags the file was pinned against on 2026-08-11.
    ("DS_BLOCK", params::DS_BLOCK),
    ("DS_BODY", params::DS_BODY),
    ("DS_STATE", params::DS_STATE),
    ("DS_ATTEST", params::DS_ATTEST),
    ("DS_RANDAO", params::DS_RANDAO),
    ("DS_SORTITION", params::DS_SORTITION),
    ("DS_DEPOSIT", params::DS_DEPOSIT),
    ("DS_SLASH", params::DS_SLASH),
    // Added to params.rs after the vectors were pinned, and pinned here on
    // 2026-09-01 when this suite was recovered. These six digests were
    // generated from the code as it stands today; the eight above were
    // re-verified against today's code unchanged, byte for byte.
    ("DS_SPEND", params::DS_SPEND),
    ("DS_TXID", params::DS_TXID),
    ("DS_PROPOSE", params::DS_PROPOSE),
    ("DS_EXIT", params::DS_EXIT),
    ("DS_WSCKPT", params::DS_WSCKPT),
    ("DS_COHERENCE", params::DS_COHERENCE),
];

/// Fixed 64-byte message (bytes 0x00..0x3F) hashed under every tag.
fn kat_msg() -> [u8; 64] {
    let mut m = [0u8; 64];
    for (i, b) in m.iter_mut().enumerate() {
        *b = i as u8;
    }
    m
}

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn vectors_path() -> PathBuf {
    manifest_dir().join("kat").join("vectors.json")
}

fn load_vectors() -> Value {
    let path = vectors_path();
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for p in parts {
        Update::update(&mut h, p);
    }
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Beacon vocabulary.
//
// The vector file was pinned (2026-08-11) against a `beacon` module that
// exposed four free functions: `chain_step`, `commit`, `verify_reveal`, `mix`.
// The crate has since restructured that surface — `chain_step` is private,
// `mix` is `mix_in`, and commit/verify live on `RandaoChain`/`RevealState`.
// The RULES did not change; only the names did. These three shims restate the
// old vocabulary on top of what the crate exposes today, so the pinned
// digests are still compared against the crate's own behaviour rather than
// against a private copy of it:
//
//   - `verify_reveal` calls straight into `RevealState::verify_and_advance`.
//   - `chain_step`/`commit` recompute SHAKE-256 locally, because the crate's
//     `chain_step` is no longer public. `local_chain_step_matches_the_crate`
//     pins the two together through the public API, so a change to the
//     crate's private step still breaks this suite.
// ---------------------------------------------------------------------------

/// One step of the RANDAO commitment chain: untagged SHAKE-256, 32-byte
/// output (§6.3).
fn chain_step(x: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[x])
}

/// `c = SHAKE-256^k(seed)` — the commitment published for a chain of length k.
fn commit(seed: &[u8; 32], k: u64) -> [u8; 32] {
    let mut v = *seed;
    for _ in 0..k {
        v = chain_step(&v);
    }
    v
}

/// `SHAKE-256(reveal) == commitment`, asked of the consensus-side type.
fn verify_reveal(reveal: &[u8; 32], commitment: &[u8; 32]) -> bool {
    beacon::RevealState::register(*commitment)
        .verify_and_advance(reveal)
        .is_ok()
}

/// The shims above are only honest if the local SHAKE-256 step is the same
/// step the crate takes internally. Prove it through the public API: build a
/// real chain, and check that the crate's own commitment equals
/// `commit(seed, RANDAO_CHAIN_LENGTH)` and that the crate's own reveals open
/// the commitments the local step predicts.
#[test]
fn local_chain_step_matches_the_crate() {
    let seed = randao_seed();
    let mut real = beacon::RandaoChain::generate(seed);
    assert_eq!(
        real.commitment(),
        commit(&seed, u64::from(params::RANDAO_CHAIN_LENGTH)),
        "the crate's chain construction and this file's SHAKE-256 step disagree"
    );
    let mut state = beacon::RevealState::register(real.commitment());
    for i in 0..4 {
        let reveal = real.next_reveal().expect("chain not exhausted");
        assert_eq!(chain_step(&reveal), state.commitment, "step {i}: local step diverged");
        state = state
            .verify_and_advance(&reveal)
            .unwrap_or_else(|e| panic!("step {i}: crate rejected its own reveal: {e:?}"));
    }
}

/// Read a required string field.
fn field_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing/non-string field {key:?} in {v}"))
}

/// Decode a required hex field into exactly 32 bytes.
fn field_hex32(v: &Value, key: &str) -> [u8; 32] {
    let bytes = hex::decode(field_str(v, key))
        .unwrap_or_else(|e| panic!("bad hex in field {key:?}: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("field {key:?} is {} bytes, want 32", b.len()))
}

/// u64 fields are encoded as decimal strings so that JSON consumers without
/// exact 64-bit integers (e.g. JavaScript) cannot silently round them.
fn field_u64(v: &Value, key: &str) -> u64 {
    field_str(v, key)
        .parse()
        .unwrap_or_else(|e| panic!("bad u64 string in field {key:?}: {e}"))
}

fn role_from_str(s: &str) -> Role {
    match s {
        "slot" => Role::SlotSubcommittee,
        "epoch" => Role::EpochCommittee,
        other => panic!("unknown role {other:?} in vectors.json"),
    }
}

fn validators_from_json(v: &Value) -> Vec<Validator> {
    v.as_array()
        .expect("validators must be an array")
        .iter()
        .map(|e| Validator {
            index: e["index"].as_u64().expect("validator index") as u32,
            effective_stake: field_u64(e, "stake"),
        })
        .collect()
}

/// ASCII name of a tag: the bytes up to the first NUL of the 16-byte constant.
fn tag_ascii(tag: &[u8; 16]) -> String {
    let end = tag.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8(tag[..end].to_vec()).expect("tags are ASCII")
}

// ---------------------------------------------------------------------------
// Generator fixtures — used only by `regenerate_vectors`. The checking tests
// read every input back from the JSON file, so the file alone is the truth.
// ---------------------------------------------------------------------------

fn beacon_1() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8;
    }
    b
}

fn randao_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, x) in s.iter_mut().enumerate() {
        *x = 0x40 + i as u8;
    }
    s
}

/// Validator sets for the sortition vectors. SET_A is deliberately listed in
/// shuffled index order: `sample` must canonicalise by index, so the drawn
/// committee must not depend on the order the registry was handed over in.
fn set_a() -> Vec<(u32, u64)> {
    [7u32, 0, 3, 11, 2, 9, 5, 1, 10, 4, 8, 6]
        .into_iter()
        .map(|i| (i, (i as u64 + 1) * 1_000))
        .collect()
}

fn set_b() -> Vec<(u32, u64)> {
    (0u32..16).map(|i| (i, 5_000)).collect()
}

fn set_c() -> Vec<(u32, u64)> {
    (0u32..200).map(|i| (i, 1_000_000 + 13_337 * i as u64)).collect()
}

/// One whale holding almost all stake: rejection sampling keeps drawing the
/// whale, `MAX_DRAWS_PER_SLOT` runs out, and the deterministic index-order
/// fallback fills the remaining seats. This pins the fallback path.
fn set_d() -> Vec<(u32, u64)> {
    let mut v = vec![(3u32, u64::MAX / 2)];
    v.extend([0u32, 1, 2, 4, 5, 6, 7, 8, 9].into_iter().map(|i| (i, 1)));
    v
}

fn set_e() -> Vec<(u32, u64)> {
    vec![(0, 0), (1, 10), (2, 0), (3, 30), (4, 0), (5, 50)]
}

fn sortition_fixtures() -> Vec<(&'static str, [u8; 32], u64, Role, usize, Vec<(u32, u64)>)> {
    vec![
        // Basic per-slot draw over a mid-sized weighted set.
        ("slot_subcommittee_basic", beacon_1(), 5, Role::SlotSubcommittee, 8, set_a()),
        // Identical inputs, different role: the role byte must change the draw.
        ("role_separation_epoch", beacon_1(), 5, Role::EpochCommittee, 8, set_a()),
        // Fewer eligible validators than seats: everyone serves.
        ("epoch_committee_all_serve", [0xA5; 32], 0, Role::EpochCommittee, 128, set_b()),
        // Full-size epoch committee drawn from 200 weighted validators.
        ("epoch_committee_weighted_200", [0xA5; 32], 42, Role::EpochCommittee, 128, set_c()),
        // Pathological stake concentration: pins the deterministic fallback.
        ("deterministic_fallback_concentrated_stake", [0xFF; 32], 1, Role::SlotSubcommittee, 8, set_d()),
        // Zero-stake validators must never be selected, even when seats go empty.
        ("zero_stake_never_selected", beacon_1(), 9, Role::SlotSubcommittee, 8, set_e()),
    ]
}

fn attestation_fixtures() -> Vec<(&'static str, AttestationData)> {
    vec![
        (
            "all_zero",
            AttestationData {
                slot: 0,
                head: [0; 32],
                source_epoch: 0,
                source_root: [0; 32],
                target_epoch: 0,
                target_root: [0; 32],
            },
        ),
        (
            "distinct_fields",
            AttestationData {
                slot: 123_456_789,
                head: [0x11; 32],
                source_epoch: 7,
                source_root: [0x22; 32],
                target_epoch: 8,
                target_root: [0x33; 32],
            },
        ),
        (
            "max_values",
            AttestationData {
                slot: u64::MAX,
                head: [0xFF; 32],
                source_epoch: u64::MAX - 1,
                source_root: [0xEE; 32],
                target_epoch: u64::MAX,
                target_root: [0xFF; 32],
            },
        ),
    ]
}

/// Short RANDAO chain length used for the step-by-step walkthrough. Small so
/// the walkthrough also exercises exhaustion (the last reveal is the seed).
const SHORT_CHAIN_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Generator — deliberately #[ignore]d. Running it rewrites the NORMATIVE
// vector file from the current code; do that only for an intentional
// consensus change, and review the diff.
// ---------------------------------------------------------------------------

fn build_vectors() -> Value {
    let msg = kat_msg();

    // §6.1 — one entry per tag: the tag bytes themselves, plus SHA3-256 and
    // 32-byte SHAKE-256 digests of `tag` and `tag ‖ msg`.
    let domain_tags: Vec<Value> = TAGS
        .iter()
        .map(|(name, tag)| {
            json!({
                "name": name,
                "ascii": tag_ascii(tag),
                "tag_hex": hex::encode(tag),
                "sha3_256_empty": hex::encode(sha3_256(&[tag])),
                "sha3_256_msg": hex::encode(sha3_256(&[tag, &msg])),
                "shake256_32_empty": hex::encode(shake256_32(&[tag])),
                "shake256_32_msg": hex::encode(shake256_32(&[tag, &msg])),
            })
        })
        .collect();

    let attestation: Vec<Value> = attestation_fixtures()
        .iter()
        .map(|(name, a)| {
            json!({
                "name": name,
                "slot": a.slot.to_string(),
                "head": hex::encode(a.head),
                "source_epoch": a.source_epoch.to_string(),
                "source_root": hex::encode(a.source_root),
                "target_epoch": a.target_epoch.to_string(),
                "target_root": hex::encode(a.target_root),
                "signing_root": hex::encode(a.signing_root()),
            })
        })
        .collect();

    let sortition: Vec<Value> = sortition_fixtures()
        .iter()
        .map(|(name, beacon, index, role, k, vals)| {
            let validators: Vec<Validator> = vals
                .iter()
                .map(|&(index, effective_stake)| Validator { index, effective_stake })
                .collect();
            let expected = sample(beacon, *index, *role, &validators, *k);
            json!({
                "name": name,
                "beacon_mix": hex::encode(beacon),
                "index": index.to_string(),
                "role": match role { Role::SlotSubcommittee => "slot", Role::EpochCommittee => "epoch" },
                "k": k,
                "validators": vals.iter().map(|(i, s)| json!({"index": i, "stake": s.to_string()})).collect::<Vec<_>>(),
                "expected": expected,
            })
        })
        .collect();

    // §6.3 — the full chain of a short commitment, then the reveal/mix
    // walkthrough down that chain, plus the full-length commitment that pins
    // RANDAO_CHAIN_LENGTH.
    let seed = randao_seed();
    let mut chain = vec![seed];
    for _ in 0..SHORT_CHAIN_LEN {
        let next = chain_step(chain.last().unwrap());
        chain.push(next);
    }
    let mut steps = Vec::new();
    let mut mix = [0u8; 32];
    for i in 0..SHORT_CHAIN_LEN {
        // c_i is the current commitment; r_i is one step down the chain.
        let commitment = chain[SHORT_CHAIN_LEN - i];
        let reveal = chain[SHORT_CHAIN_LEN - 1 - i];
        assert!(verify_reveal(&reveal, &commitment));
        let next_mix = beacon::mix_in(&mix, &reveal);
        steps.push(json!({
            "commitment": hex::encode(commitment),
            "reveal": hex::encode(reveal),
            "prev_mix": hex::encode(mix),
            "mix": hex::encode(next_mix),
        }));
        mix = next_mix;
    }
    let randao = json!({
        "seed": hex::encode(seed),
        "short_chain_length": SHORT_CHAIN_LEN,
        // chain[j] = SHAKE-256^j(seed); the last entry is the commitment c_0.
        "short_chain": chain.iter().map(hex::encode).collect::<Vec<_>>(),
        "chain_length_full": params::RANDAO_CHAIN_LENGTH.to_string(),
        "commitment_full": hex::encode(commit(&seed, u64::from(params::RANDAO_CHAIN_LENGTH))),
        "initial_mix": hex::encode([0u8; 32]),
        "steps": steps,
    });

    json!({
        "_comment": [
            "NORMATIVE known-answer vectors for bloch-pos-committee.",
            "Spec: docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md (§6.1 tags, §6.3 beacon, §12 KATs).",
            "Any second implementation of these rules validates against THIS file.",
            "Do not edit by hand. Regenerate only for an intentional consensus change:",
            "  cargo test --test kat -- --ignored regenerate_vectors",
            "and review the diff — every changed digest is a consensus break.",
            "All u64 values are decimal strings so consumers without exact 64-bit integers cannot round them.",
            "Hashes: SHA3-256 for fixed-length digests, SHAKE-256 (32-byte output) for XOF uses (§6.1).",
        ],
        "hash_message_hex": hex::encode(msg),
        "domain_tags": domain_tags,
        "attestation": attestation,
        "sortition": sortition,
        "randao": randao,
    })
}

/// Rewrites `kat/vectors.json` from the current code. Ignored on purpose:
/// running it redefines the normative vectors, which is a consensus decision,
/// not a test run.
#[test]
#[ignore = "rewrites the normative vector file; run deliberately and review the diff"]
fn regenerate_vectors() {
    let path = vectors_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut text = serde_json::to_string_pretty(&build_vectors()).unwrap();
    text.push('\n');
    fs::write(&path, text).unwrap();
    eprintln!("wrote {}", path.display());
}

// ---------------------------------------------------------------------------
// Comparison tests — fixed file vs. current code.
// ---------------------------------------------------------------------------

/// §6.1: every tag constant matches its pinned bytes, and hashing under it
/// matches the pinned digests.
#[test]
fn domain_tag_vectors_match() {
    let doc = load_vectors();
    let entries = doc["domain_tags"].as_array().expect("domain_tags array");
    assert_eq!(
        entries.len(),
        TAGS.len(),
        "vector file and TAGS table disagree on the number of tags"
    );
    let msg = kat_msg();
    for (name, tag) in &TAGS {
        let e = entries
            .iter()
            .find(|e| e["name"] == *name)
            .unwrap_or_else(|| panic!("no vector for tag {name}"));
        assert_eq!(field_str(e, "tag_hex"), hex::encode(tag), "{name}: tag bytes changed");
        assert_eq!(field_str(e, "ascii"), tag_ascii(tag), "{name}: ascii form changed");
        assert_eq!(
            field_str(e, "sha3_256_empty"),
            hex::encode(sha3_256(&[tag])),
            "{name}: SHA3-256(tag) changed"
        );
        assert_eq!(
            field_str(e, "sha3_256_msg"),
            hex::encode(sha3_256(&[tag, &msg])),
            "{name}: SHA3-256(tag ‖ msg) changed"
        );
        assert_eq!(
            field_str(e, "shake256_32_empty"),
            hex::encode(shake256_32(&[tag])),
            "{name}: SHAKE-256(tag) changed"
        );
        assert_eq!(
            field_str(e, "shake256_32_msg"),
            hex::encode(shake256_32(&[tag, &msg])),
            "{name}: SHAKE-256(tag ‖ msg) changed"
        );
    }
    // The message the digests were computed over is itself pinned.
    assert_eq!(field_str(&doc, "hash_message_hex"), hex::encode(msg));
}

/// Tags are exactly 16 bytes, NUL-padded, and pairwise distinct — so no tag
/// can be a prefix of another once the fixed width is accounted for.
#[test]
fn tags_are_fixed_width_and_distinct() {
    let mut seen = BTreeSet::new();
    for (name, tag) in &TAGS {
        let ascii = tag_ascii(tag);
        assert!(ascii.starts_with("BLCH4:"), "{name}: missing BLCH4: prefix");
        // Right-padded: nothing but NULs after the ASCII part.
        assert!(
            tag[ascii.len()..].iter().all(|&b| b == 0),
            "{name}: padding must be NUL bytes"
        );
        assert!(seen.insert(*tag), "{name}: duplicate tag bytes");
    }
}

/// Fails when a `BLCH4:` tag literal is added anywhere under `src/` without a
/// corresponding vector — the guard that keeps `kat/vectors.json` complete.
#[test]
fn every_source_tag_has_a_vector() {
    let src_dir = manifest_dir().join("src");
    let mut source_tags = BTreeSet::new();
    for entry in fs::read_dir(&src_dir).expect("read src/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source file");
        for lit in byte_string_literals(&text) {
            if lit.starts_with("BLCH4:") {
                source_tags.insert(lit.trim_end_matches('\0').to_string());
            }
        }
    }
    assert!(
        !source_tags.is_empty(),
        "no BLCH4: tags found under src/ — the scanner is broken"
    );

    let doc = load_vectors();
    let vector_tags: BTreeSet<String> = doc["domain_tags"]
        .as_array()
        .expect("domain_tags array")
        .iter()
        .map(|e| field_str(e, "ascii").to_string())
        .collect();
    assert_eq!(
        source_tags, vector_tags,
        "src/ tags and kat/vectors.json disagree — a tag was added, removed or \
         renamed without updating the KAT vectors (regenerate deliberately and \
         review the diff)"
    );

    // And the in-test TAGS table must track the source too, or the digest
    // checks above would silently skip the new tag.
    let table_tags: BTreeSet<String> = TAGS.iter().map(|(_, t)| tag_ascii(t)).collect();
    assert_eq!(
        source_tags, table_tags,
        "update the TAGS table in tests/kat.rs to match src/"
    );
}

/// Minimal scanner for `b"…"` byte-string literals, enough for the escapes
/// tag constants can contain (`\0`, `\\`, `\"`, `\n`, `\r`, `\t`, `\xNN`).
fn byte_string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'b' && bytes[i + 1] == b'"' {
            let mut j = i + 2;
            let mut lit = String::new();
            while j < bytes.len() && bytes[j] != b'"' {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    lit.push(match bytes[j + 1] {
                        b'0' => '\0',
                        b'\\' => '\\',
                        b'"' => '"',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'x' => {
                            let hi = (bytes[j + 2] as char).to_digit(16).unwrap();
                            let lo = (bytes[j + 3] as char).to_digit(16).unwrap();
                            j += 2;
                            char::from((hi * 16 + lo) as u8)
                        }
                        other => panic!("unhandled escape \\{} in byte literal", other as char),
                    });
                    j += 2;
                } else {
                    lit.push(bytes[j] as char);
                    j += 1;
                }
            }
            out.push(lit);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// `AttestationData::signing_root` against the pinned roots.
#[test]
fn attestation_signing_root_vectors_match() {
    let doc = load_vectors();
    let entries = doc["attestation"].as_array().expect("attestation array");
    assert!(entries.len() >= 3, "expected at least three attestation vectors");
    let mut roots = BTreeSet::new();
    for e in entries {
        let name = field_str(e, "name");
        let data = AttestationData {
            slot: field_u64(e, "slot"),
            head: field_hex32(e, "head"),
            source_epoch: field_u64(e, "source_epoch"),
            source_root: field_hex32(e, "source_root"),
            target_epoch: field_u64(e, "target_epoch"),
            target_root: field_hex32(e, "target_root"),
        };
        assert_eq!(
            hex::encode(data.signing_root()),
            field_str(e, "signing_root"),
            "attestation vector {name}: signing_root changed"
        );
        assert!(roots.insert(data.signing_root()), "vector {name}: duplicate signing root");
    }
}

/// Sortition draws against the pinned committees. Inputs come from the file,
/// so the file alone fully specifies each case.
#[test]
fn sortition_vectors_match() {
    let doc = load_vectors();
    let entries = doc["sortition"].as_array().expect("sortition array");
    assert!(entries.len() >= 6, "expected at least six sortition vectors");
    let mut saw_slot_k = false;
    let mut saw_epoch_k = false;
    for e in entries {
        let name = field_str(e, "name");
        let beacon = field_hex32(e, "beacon_mix");
        let index = field_u64(e, "index");
        let role = role_from_str(field_str(e, "role"));
        let k = e["k"].as_u64().expect("k") as usize;
        saw_slot_k |= k == params::SLOT_SUBCOMMITTEE_SIZE && role == Role::SlotSubcommittee;
        saw_epoch_k |= k == params::COMMITTEE_SIZE && role == Role::EpochCommittee;
        let validators = validators_from_json(&e["validators"]);
        let expected: Vec<u32> = e["expected"]
            .as_array()
            .expect("expected array")
            .iter()
            .map(|v| v.as_u64().expect("expected index") as u32)
            .collect();
        let got = sample(&beacon, index, role, &validators, k);
        assert_eq!(got, expected, "sortition vector {name}: draw changed");
        // Every drawn index must belong to a validator with nonzero stake.
        for idx in &got {
            let v = validators.iter().find(|v| v.index == *idx).expect("drawn index exists");
            assert!(v.effective_stake > 0, "vector {name}: zero-stake validator {idx} drawn");
        }
    }
    // The production committee sizes must be exercised, so a change to the
    // params constants cannot slip past the vector file unnoticed.
    assert!(saw_slot_k, "no vector uses SLOT_SUBCOMMITTEE_SIZE with the slot role");
    assert!(saw_epoch_k, "no vector uses COMMITTEE_SIZE with the epoch role");
}

/// §6.3: chain construction, reveal verification, commitment advancement and
/// beacon mixing, step by step against the pinned walkthrough.
#[test]
fn randao_vectors_match() {
    let doc = load_vectors();
    let r = &doc["randao"];
    let seed = field_hex32(r, "seed");
    let short_len = r["short_chain_length"].as_u64().expect("short_chain_length") as usize;

    // The full chain of the short commitment: chain[j] = SHAKE-256^j(seed).
    let chain_hex = r["short_chain"].as_array().expect("short_chain array");
    assert_eq!(chain_hex.len(), short_len + 1, "short_chain must hold seed + one value per step");
    let mut chain: Vec<[u8; 32]> = Vec::with_capacity(short_len + 1);
    for (j, v) in chain_hex.iter().enumerate() {
        let pinned: [u8; 32] = hex::decode(v.as_str().expect("chain hex"))
            .expect("chain hex")
            .try_into()
            .expect("32 bytes");
        let computed = if j == 0 { seed } else { chain_step(&chain[j - 1]) };
        assert_eq!(computed, pinned, "short_chain[{j}] changed");
        chain.push(pinned);
    }
    assert_eq!(
        hex::encode(commit(&seed, short_len as u64)),
        chain_hex.last().unwrap().as_str().unwrap(),
        "commit(seed, short_len) must equal the last chain value"
    );

    // The full-length commitment pins RANDAO_CHAIN_LENGTH itself.
    assert_eq!(
        field_u64(r, "chain_length_full"),
        u64::from(params::RANDAO_CHAIN_LENGTH),
        "RANDAO_CHAIN_LENGTH changed"
    );
    assert_eq!(
        field_str(r, "commitment_full"),
        hex::encode(commit(&seed, u64::from(params::RANDAO_CHAIN_LENGTH))),
        "full-length commitment changed"
    );

    // Reveal/mix walkthrough. Exhaustion is exercised by construction: the
    // walkthrough consumes every reveal, and the last one is the seed itself —
    // after it, only a re-commit can continue the chain (§6.3).
    let steps = r["steps"].as_array().expect("steps array");
    assert_eq!(steps.len(), short_len, "one step per chain reveal");
    let mut mix = field_hex32(r, "initial_mix");
    assert_eq!(mix, [0u8; 32], "initial mix must be all-zero");
    let mut commitment = *chain.last().unwrap();
    for (i, s) in steps.iter().enumerate() {
        assert_eq!(
            field_hex32(s, "commitment"),
            commitment,
            "step {i}: commitment must advance as c_{{i+1}} = r_i"
        );
        let reveal = field_hex32(s, "reveal");
        assert!(
            verify_reveal(&reveal, &commitment),
            "step {i}: pinned reveal fails verification"
        );
        assert_eq!(field_hex32(s, "prev_mix"), mix, "step {i}: mix chain broken");
        let next_mix = beacon::mix_in(&mix, &reveal);
        assert_eq!(field_hex32(s, "mix"), next_mix, "step {i}: mix output changed");
        commitment = reveal;
        mix = next_mix;
    }
    assert_eq!(commitment, seed, "exhaustion: the final reveal must be the seed");

    // Negative checks (not vectors, semantics): a tampered reveal must fail,
    // and the mix must depend on both operands.
    let mut bad = seed;
    bad[0] ^= 1;
    assert!(!verify_reveal(&bad, &chain[1]));
    assert_ne!(beacon::mix_in(&[0u8; 32], &seed), beacon::mix_in(&[1u8; 32], &seed));
    assert_ne!(beacon::mix_in(&[0u8; 32], &seed), beacon::mix_in(&[0u8; 32], &bad));
}
