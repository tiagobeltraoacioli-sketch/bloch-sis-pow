// SPDX-License-Identifier: AGPL-3.0-or-later

//! Spec ↔ code reconciliation guard (Round-2 audit, finding SPEC1-reconcile).
//!
//! The Round-2 audit found six documented rules that would fork an independent
//! implementer because the documents described a protocol the code does not
//! run (F-05 header wire layout, F-06 missing domain/state tags, F-08 reward
//! rule, F-09 MIN_DEPOSIT, F-10 vesting-as-consensus, F-12 emission table).
//! The code is the chain, so the documents were corrected to match it — and
//! this test pins the corrections so the stale claims cannot silently return.
//!
//! Every assertion here FAILS against the pre-fix documents (each check was
//! run against the stale text before the docs were edited — mutation-style),
//! and the numeric checks are computed from the shipped constants rather than
//! hard-coded, so a *code* change that invalidates a published figure also
//! fails here and forces the spec to move in the same commit.

use bloch_pos_committee::header::BlockHeaderV4;
use bloch_pos_committee::params;
use bloch_pos_committee::staking::MIN_DEPOSIT_SAT;
use bloch_pos_committee::tokenomics_v4 as tk;

use std::fs;
use std::path::PathBuf;

fn spec(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

const MIGRATION: &str = "BLOCH-POS-SHA3-LATTICE-MIGRATION.md";
const TOKENOMICS: &str = "BLOCH-TOKENOMICS-V4.md";

/// Render a 16-byte domain tag the way the spec table writes it:
/// printable ASCII prefix, then one `\0` per padding byte.
fn render_tag(tag: &[u8; 16]) -> String {
    let ascii_len = tag.iter().position(|&b| b == 0).unwrap_or(16);
    let mut out = String::from_utf8(tag[..ascii_len].to_vec()).expect("ascii tag");
    for _ in ascii_len..16 {
        out.push_str("\\0");
    }
    out
}

/// F-05 — the published wire layout must be the shipped scalar-parent,
/// 304-byte little-endian encoding, not the drafted parents-vector.
#[test]
fn f05_header_wire_layout_matches_code() {
    let doc = spec(MIGRATION);

    // The forking sentence: a vector-with-len==1 wire format was never built.
    assert!(
        !doc.contains("kept as a vector in the wire format"),
        "{MIGRATION} still claims the parents vector survives on the wire"
    );

    // The byte-exact layout: total length straight from the code.
    let len_claim = format!("**{} bytes** (`BlockHeaderV4::ENCODED_LEN`)", BlockHeaderV4::ENCODED_LEN);
    assert!(
        doc.contains(&len_claim),
        "{MIGRATION} does not publish the exact encoded length {}",
        BlockHeaderV4::ENCODED_LEN
    );
    assert!(
        doc.contains("little-endian"),
        "{MIGRATION} does not state integer endianness for the header encoding"
    );
    // Spot-check the offset table against the decoder's hard-coded offsets.
    for row in [
        "| 4 | 32 | `parent` | raw |",
        "| 100 | 8 | `slot` | `u64` LE |",
        "| 108 | 4 | `proposer_index` | `u32` LE |",
        "| 272 | 32 | `coherence_root` | raw |",
    ] {
        assert!(doc.contains(row), "{MIGRATION} offset table missing row: {row}");
    }
    // The stale "248 B" header size must be gone — here and in the two other
    // specs that quoted it into storage-schema and bandwidth arithmetic.
    assert!(!doc.contains("248 B"), "{MIGRATION} still claims a 248-byte header");
    for name in ["BLOCH-POS-NODE-INTEGRATION.md", "BLOCH-POS-NETWORK-CAPACITY.md"] {
        let other = spec(name);
        assert!(!other.contains("248 B"), "{name} still claims a 248-byte header");
        assert!(other.contains("304 B"), "{name} does not carry the shipped 304-byte header size");
    }
}

/// F-06 — every shipped SHA-3 domain tag must appear in the §6.1 registry,
/// rendered byte-exactly, and the state-tree marker/component tags must be
/// published.
#[test]
fn f06_domain_and_state_tags_all_published() {
    let doc = spec(MIGRATION);

    let tags: [(&str, &[u8; 16]); 14] = [
        ("DS_BLOCK", &params::DS_BLOCK),
        ("DS_BODY", &params::DS_BODY),
        ("DS_STATE", &params::DS_STATE),
        ("DS_ATTEST", &params::DS_ATTEST),
        ("DS_RANDAO", &params::DS_RANDAO),
        ("DS_SORTITION", &params::DS_SORTITION),
        ("DS_DEPOSIT", &params::DS_DEPOSIT),
        ("DS_SLASH", &params::DS_SLASH),
        ("DS_SPEND", &params::DS_SPEND),
        ("DS_TXID", &params::DS_TXID),
        ("DS_PROPOSE", &params::DS_PROPOSE),
        ("DS_EXIT", &params::DS_EXIT),
        ("DS_WSCKPT", &params::DS_WSCKPT),
        ("DS_COHERENCE", &params::DS_COHERENCE),
    ];
    for (name, bytes) in tags {
        let rendered = format!("| `{name}` | `{}` |", render_tag(bytes));
        assert!(
            doc.contains(&rendered),
            "{MIGRATION} §6.1 registry missing or byte-inexact for {name}: expected row start {rendered:?}"
        );
    }

    // State-tree preimage markers 0x00..0x04 and the 22 component tags.
    for marker in ["MARK_LEAF", "MARK_NODE", "MARK_EMPTY", "MARK_KEY", "MARK_VALUE"] {
        assert!(doc.contains(marker), "{MIGRATION} missing state-tree marker {marker}");
    }
    for tag in [
        "TAG_EUTXO",
        "TAG_VALIDATOR",
        "TAG_PARTICIPATION_CURRENT",
        "TAG_PARTICIPATION_PREVIOUS",
        "TAG_RANDAO",
        "TAG_TAINT_ROOT",
        "TAG_COHERENCE_ACCUMULATOR",
        "TAG_COHERENCE_NULLIFIERS",
        "TAG_FINALITY",
        "TAG_PENDING_VOTE",
        "TAG_FC_MESSAGE",
        "TAG_FC_EQUIVOCATOR",
        "TAG_DEPOSIT_QUEUE",
        "TAG_DELEGATION",
        "TAG_PENDING_FEE",
        "TAG_EVM_COMMITMENT",
        "TAG_SLASH_APPLIED",
        "TAG_SLASH_WINDOW",
        "TAG_DELEGATOR_SLASH_LOSS",
        "TAG_ISSUED_SUPPLY",
        "TAG_BASE_FEE",
        "TAG_DELEGATOR_FEE_REWARD",
    ] {
        assert!(doc.contains(tag), "{MIGRATION} missing state component tag {tag}");
    }
    assert!(
        doc.contains("| `0x16` | `TAG_DELEGATOR_FEE_REWARD`"),
        "{MIGRATION} component-tag table must number the registry up to 0x16"
    );
}

/// F-08 — the migration spec's reward section must carry a superseded seal
/// and record the implemented Solana rule, not the drafted 7/8‖1/8 shape.
#[test]
fn f08_reward_rule_superseded_in_migration_spec() {
    let doc = spec(MIGRATION);
    let sec = doc
        .split("### 7.4 Rewards")
        .nth(1)
        .expect("§7.4 present")
        .split("\n## ")
        .next()
        .unwrap();
    assert!(
        sec.contains("SUPERSEDED"),
        "{MIGRATION} §7.4 lacks a superseded seal over the 7/8‖1/8 draft"
    );
    assert!(
        sec.contains("pro-rata to its stake") && sec.contains("50% burned"),
        "{MIGRATION} §7.4 does not record the implemented Solana split"
    );
    assert!(
        sec.contains("100% of every fee to the producer"),
        "{MIGRATION} §7.4 does not record the post-emission no-burn era"
    );
}

/// F-09 — every MIN_DEPOSIT figure published as current must equal the
/// shipped constant (25,000 BLCH), and the pre-split 100,000 must not be
/// presented as the live value.
#[test]
fn f09_min_deposit_matches_staking_constant() {
    let live_blch = MIN_DEPOSIT_SAT / tk::SAT_PER_BLOCH;
    assert_eq!(live_blch, 25_000, "staking constant moved — update the specs AND this test");

    let doc = spec(MIGRATION);
    assert!(
        !doc.contains("| `MIN_DEPOSIT_BLCH` | 100,000 |"),
        "{MIGRATION} still tables the pre-split 100,000 BLCH as current"
    );
    let expected = "| `MIN_DEPOSIT_BLCH` | 25,000";
    assert_eq!(
        doc.matches(expected).count(),
        2,
        "{MIGRATION} must table the live 25,000 BLCH in both §5.1 and Appendix A"
    );

    let tm = spec("BLOCH-POS-THREAT-MODEL.md");
    assert!(
        tm.contains("`MIN_DEPOSIT_BLCH = 25,000`"),
        "threat model still quotes the pre-split deposit as current"
    );
}

/// F-10 — no spec may present vesting as consensus-enforced: `unlock_epoch`
/// is committed data no spend-authorisation path reads.
#[test]
fn f10_vesting_documented_as_policy_not_consensus() {
    for name in [
        TOKENOMICS,
        "BLOCH-ENTITY-STRUCTURE.md",
        "BLOCH-POS-NODE-INTEGRATION.md",
        "BLOCH-POS-INTERFACES.md",
    ] {
        let doc = spec(name);
        for stale in [
            "consensus-enforced vesting",
            "Vesting is consensus-enforced",
            "unlock schedules enforced by consensus",
            "vesting\nlocks on the founder/VC/team/marketing allocations are enforced as",
        ] {
            assert!(
                !doc.contains(stale),
                "{name} still claims vesting is consensus-enforced: {stale:?}"
            );
        }
    }
    let tok = spec(TOKENOMICS);
    assert!(
        tok.contains("schedules are policy, not consensus")
            && tok.contains("vesting_is_not_enforced"),
        "{TOKENOMICS} §8.2 must state the as-built rule and cite the pinning test"
    );
}

/// F-12 — the published emission table must be computed from the shipped
/// integer recurrence, not the ~0.41%-higher closed-form draft.
#[test]
fn f12_emission_table_matches_shipped_curve() {
    let doc = spec(TOKENOMICS);

    // Format sat as thousands-separated BLCH with 2 decimals (half-up).
    let fmt_blch = |sat: u128| -> String {
        let hundredths = (sat + 500_000) / 1_000_000;
        let (whole, frac) = (hundredths / 100, hundredths % 100);
        let mut w = whole.to_string();
        let mut grouped = String::new();
        while w.len() > 3 {
            let tail = w.split_off(w.len() - 3);
            grouped = format!(",{tail}{grouped}");
        }
        format!("{w}{grouped}.{frac:02}")
    };

    for year in [1u64, 5, 10, 20, 40] {
        let slot = (year - 1) * tk::SLOTS_PER_YEAR;
        let per_block = tk::validator_reward_decay_sat(slot);
        let cell = format!("| {year} | {} |", fmt_blch(per_block));
        assert!(
            doc.contains(&cell),
            "{TOKENOMICS} emission table diverges from the shipped curve at year {year}: expected {cell:?}"
        );
    }

    // The residual is the shipped constant, and the impossible draft figure is gone.
    let residual = format!("**{} sat", {
        let mut w = tk::EMISSION_DUST_SAT.to_string();
        let mut grouped = String::new();
        while w.len() > 3 {
            let tail = w.split_off(w.len() - 3);
            grouped = format!(",{tail}{grouped}");
        }
        format!("{w}{grouped}")
    });
    assert!(
        doc.contains(&residual),
        "{TOKENOMICS} must publish the shipped truncation residual {residual:?}"
    );
    assert!(
        !doc.contains("889,200 sat"),
        "{TOKENOMICS} still carries the arithmetically impossible draft residual"
    );
    assert!(
        !doc.contains("4,151.90"),
        "{TOKENOMICS} still carries the draft year-1 reward the chain does not pay"
    );
}
