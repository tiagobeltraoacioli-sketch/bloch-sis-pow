// SPDX-License-Identifier: AGPL-3.0-or-later

//! `getchaininfo.signature_suites` and `getchaininfo.hard_forks`: what this
//! binary's activation gates say, read straight from the consensus crate.
//!
//! Node-only and additive. Nothing here decides a rule; every value is a
//! projection of a constant or predicate that already decides one:
//!
//! * `hard_forks` walks [`HARD_FORK_GATES`] (the single list of HF1/HF2/HF3
//!   activation constants). Aliases that must equal another listed gate
//!   (compile-time asserted in `hard_forks.rs`) are not repeated.
//! * `signature_suites` reports suites `0x0001`/`0x0002`/`0x0003` with the
//!   gates that admission (`engine::admissible`, CR-03 +
//!   `is_spend_public_key_admissible`) and consensus (`verify_spend`,
//!   lattice-emergency freeze) actually read.
//!
//! `activation_epoch` is `null` for a gate at `u64::MAX` (inert). `active`
//! is evaluated at the head epoch (the epoch of the head block's slot), the
//! epoch consensus applies to the next block on this head. `spend_allowed`
//! is evaluated at the wall epoch, the epoch mempool admission reads; the two
//! differ only while the node is behind.

use bloch_pos_committee::hard_forks::{HardForkGate, HARD_FORK_GATES};
use bloch_pos_committee::params::{self, epoch_gate_active};

use super::Json;

/// RPC key per [`HARD_FORK_GATES`] name. `None` = an alias pinned equal to a
/// gate that is already reported.
const HARD_FORK_KEYS: &[(&str, Option<&str>)] = &[
    ("params::HF1_CLAIM_FINALITY_EPOCH", Some("hf1_claim_finality")),
    ("params::HF1_FROZEN_FINALITY_SET_EPOCH", Some("hf1_frozen_set")),
    ("params::HF1_OWN_TARGET_VOTES_EPOCH", Some("hf1_own_target")),
    ("params::HF2_SLASHING_V2_EPOCH", Some("hf2_slashing_v2")),
    ("params::NATIVE_SLASHING_ACTIVATION_EPOCH", None),
    ("params::HF2_GROWTH_CAP_EPOCH", Some("hf2_growth_cap")),
    ("params::SIG_CANONICAL_ACTIVATION_EPOCH", Some("hf2_sig_canonical")),
    ("params::MLDSA_PIN_ACTIVATION_EPOCH", Some("hf2_mldsa_pin")),
    ("params::HF3_KES_EPOCH", Some("hf3_kes_registration")),
    ("params::KES_REGISTRATION_EPOCH", None),
    ("params::HF3_KES_ENFORCE_EPOCH", Some("hf3_kes_enforce")),
    ("params::KES_ACTIVATION_EPOCH", None),
    ("params::HF3_SLH_SUITE_EPOCH", Some("hf3_slh")),
    ("params::HF3_PQ_MIGRATION_EPOCH", Some("hf3_pq_migration")),
    ("params::LATTICE_EMERGENCY_ACTIVATION_EPOCH", Some("hf3_lattice_emergency")),
];

/// The RPC key for a gate. A gate added to `HARD_FORK_GATES` by a later
/// merge without a row above is still reported, under its lowercased
/// constant name, rather than silently dropped
/// (`every_gate_has_an_rpc_key` makes the row mandatory in tests).
fn gate_key(name: &str) -> Option<String> {
    match HARD_FORK_KEYS.iter().find(|(n, _)| *n == name) {
        Some((_, key)) => key.map(str::to_string),
        None => Some(name.trim_start_matches("params::").to_ascii_lowercase()),
    }
}

fn activation(epoch: u64) -> Json {
    if epoch == u64::MAX { Json::Null } else { Json::u(epoch) }
}

fn gate_json(activation_epoch: u64, active: bool) -> Json {
    Json::obj(vec![("activation_epoch", activation(activation_epoch)), ("active", Json::Bool(active))])
}

pub(super) fn hard_forks_json_from(gates: &[HardForkGate], head_epoch: u64) -> Json {
    Json::Obj(
        gates
            .iter()
            .filter_map(|g| {
                gate_key(g.name).map(|k| (k, gate_json(g.epoch, epoch_gate_active(head_epoch, g.epoch))))
            })
            .collect(),
    )
}

/// `hard_forks` for this binary.
pub(super) fn hard_forks_json(head_epoch: u64) -> Json {
    hard_forks_json_from(HARD_FORK_GATES, head_epoch)
}

/// The gates the suite table depends on, with the predicates that read them.
pub(super) struct SuiteGates<A: Fn(u64) -> bool> {
    pub slh_suite_epoch: u64,
    /// `params::hf3_slh_suite_active` in production.
    pub slh_suite_active: A,
    pub lattice_emergency_epoch: u64,
}

pub(super) fn signature_suites_json_from<A: Fn(u64) -> bool>(
    g: &SuiteGates<A>,
    head_epoch: u64,
    wall_epoch: u64,
) -> Json {
    // Lattice-suite inputs (0x0001, 0x0002) are refused by consensus from the
    // lattice-emergency epoch (`PqMigrationReject::LatticeSpendFrozen`).
    let lattice_spendable = !epoch_gate_active(wall_epoch, g.lattice_emergency_epoch);
    let suite = |id: &str, name: &str, act: u64, active: bool, spend: bool| {
        Json::obj(vec![
            ("suite", Json::s(id)),
            ("name", Json::s(name)),
            ("activation_epoch", activation(act)),
            ("active", Json::Bool(active)),
            ("spend_allowed", Json::Bool(spend)),
        ])
    };
    Json::Arr(vec![
        // The live hybrid since genesis.
        suite("0x0001", "ML-DSA-65+Falcon-1024", 0, true, lattice_spendable),
        // Known to the consensus verifier since genesis (crypto agility), but
        // CR-03 node policy refuses every new spend authorised by it at
        // admission, ungated.
        suite("0x0002", "ML-DSA-65", 0, true, false),
        // HF3: verified and admitted only from HF3_SLH_SUITE_EPOCH.
        suite(
            "0x0003",
            "SLH-DSA-SHAKE-128s+Falcon-1024",
            g.slh_suite_epoch,
            (g.slh_suite_active)(head_epoch),
            (g.slh_suite_active)(wall_epoch),
        ),
    ])
}

/// `signature_suites` for this binary.
pub(super) fn signature_suites_json(head_epoch: u64, wall_epoch: u64) -> Json {
    signature_suites_json_from(
        &SuiteGates {
            slh_suite_epoch: params::HF3_SLH_SUITE_EPOCH,
            slh_suite_active: params::hf3_slh_suite_active,
            lattice_emergency_epoch: params::LATTICE_EMERGENCY_ACTIVATION_EPOCH,
        },
        head_epoch,
        wall_epoch,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(v: &'a Json, k: &str) -> &'a Json {
        v.get(k).unwrap_or_else(|| panic!("missing {k}"))
    }

    fn suites(v: &Json) -> &[Json] {
        match v {
            Json::Arr(a) => a,
            other => panic!("not an array: {other:?}"),
        }
    }

    #[test]
    fn every_gate_has_an_rpc_key() {
        for g in HARD_FORK_GATES {
            assert!(
                HARD_FORK_KEYS.iter().any(|(n, _)| *n == g.name),
                "{} has no row in HARD_FORK_KEYS",
                g.name
            );
        }
        for (n, _) in HARD_FORK_KEYS {
            assert!(HARD_FORK_GATES.iter().any(|g| g.name == *n), "{n} is not in HARD_FORK_GATES");
        }
    }

    #[test]
    fn aliases_are_pinned_equal_to_a_reported_gate() {
        let epoch = |n: &str| HARD_FORK_GATES.iter().find(|g| g.name == n).unwrap().epoch;
        assert_eq!(epoch("params::NATIVE_SLASHING_ACTIVATION_EPOCH"), epoch("params::HF2_SLASHING_V2_EPOCH"));
        assert_eq!(epoch("params::KES_REGISTRATION_EPOCH"), epoch("params::HF3_KES_EPOCH"));
        assert_eq!(epoch("params::KES_ACTIVATION_EPOCH"), epoch("params::HF3_KES_ENFORCE_EPOCH"));
    }

    #[test]
    fn hard_forks_reports_every_named_key_from_params() {
        let v = hard_forks_json(1_000);
        let expected = [
            "hf1_claim_finality",
            "hf1_frozen_set",
            "hf1_own_target",
            "hf2_slashing_v2",
            "hf2_growth_cap",
            "hf2_sig_canonical",
            "hf2_mldsa_pin",
            "hf3_kes_registration",
            "hf3_kes_enforce",
            "hf3_slh",
            "hf3_pq_migration",
            "hf3_lattice_emergency",
        ];
        let Json::Obj(fields) = &v else { panic!("not an object") };
        assert_eq!(fields.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), expected);
        // Values are the params constants, not copies.
        for g in HARD_FORK_GATES {
            let Some(k) = gate_key(g.name) else { continue };
            let e = field(&v, &k);
            assert_eq!(field(e, "activation_epoch"), &activation(g.epoch), "{k}");
            assert_eq!(field(e, "active"), &Json::Bool(epoch_gate_active(1_000, g.epoch)), "{k}");
        }
    }

    #[test]
    fn inert_gates_report_null_and_inactive() {
        let inert: Vec<HardForkGate> =
            HARD_FORK_GATES.iter().map(|g| HardForkGate { epoch: u64::MAX, ..*g }).collect();
        for head in [0, 6_460, u64::MAX - 1, u64::MAX] {
            let Json::Obj(fields) = hard_forks_json_from(&inert, head) else { panic!() };
            for (k, e) in &fields {
                assert_eq!(field(e, "activation_epoch"), &Json::Null, "{k}");
                assert_eq!(field(e, "active"), &Json::Bool(false), "{k}");
            }
        }
    }

    #[test]
    fn an_armed_override_reports_its_epoch_and_flips_at_it() {
        let armed: Vec<HardForkGate> = HARD_FORK_GATES
            .iter()
            .map(|g| match g.name {
                "params::HF1_CLAIM_FINALITY_EPOCH" => HardForkGate { epoch: 6_460, ..*g },
                "params::HF3_SLH_SUITE_EPOCH" => HardForkGate { epoch: 6_562, ..*g },
                _ => HardForkGate { epoch: u64::MAX, ..*g },
            })
            .collect();
        let at = |head| hard_forks_json_from(&armed, head);
        let claim = |v: &Json| field(v, "hf1_claim_finality").clone();
        let slh = |v: &Json| field(v, "hf3_slh").clone();
        assert_eq!(claim(&at(6_459)), gate_json(6_460, false));
        assert_eq!(claim(&at(6_460)), gate_json(6_460, true));
        assert_eq!(slh(&at(6_561)), gate_json(6_562, false));
        assert_eq!(slh(&at(6_562)), gate_json(6_562, true));
        assert_eq!(field(&at(7_000), "hf1_frozen_set"), &gate_json(u64::MAX, false));
        assert_eq!(field(&field(&at(7_000), "hf1_frozen_set").clone(), "activation_epoch"), &Json::Null);
    }

    fn suite_at<'a>(v: &'a Json, id: &str) -> &'a Json {
        suites(v).iter().find(|s| field(s, "suite").as_str() == Some(id)).unwrap()
    }

    #[test]
    fn shipped_suites_reflect_params_and_admission() {
        for (head, wall) in [(0, 0), (6_000, 6_001), (u64::MAX - 1, u64::MAX - 1)] {
            let v = signature_suites_json(head, wall);
            assert_eq!(suites(&v).len(), 3);
            let ids: Vec<_> = suites(&v).iter().map(|s| field(s, "suite").as_str().unwrap().to_string()).collect();
            assert_eq!(ids, ["0x0001", "0x0002", "0x0003"]);

            let s1 = suite_at(&v, "0x0001");
            assert_eq!(field(s1, "activation_epoch").as_u64(), Some(0));
            assert_eq!(field(s1, "active"), &Json::Bool(true));
            assert_eq!(
                field(s1, "spend_allowed"),
                &Json::Bool(!epoch_gate_active(wall, params::LATTICE_EMERGENCY_ACTIVATION_EPOCH))
            );

            let s2 = suite_at(&v, "0x0002");
            assert_eq!(field(s2, "spend_allowed"), &Json::Bool(false));

            let s3 = suite_at(&v, "0x0003");
            assert_eq!(field(s3, "activation_epoch"), &activation(params::HF3_SLH_SUITE_EPOCH));
            assert_eq!(field(s3, "active"), &Json::Bool(params::hf3_slh_suite_active(head)));
            assert_eq!(field(s3, "spend_allowed"), &Json::Bool(params::hf3_slh_suite_active(wall)));
        }
    }

    #[test]
    fn suite_0x0002_spends_are_refused_by_the_real_admission_classifier() {
        // The `spend_allowed: false` above is the CR-03 classifier's verdict,
        // with the HF3 gate either way.
        let mut pk = vec![0u8; 4 + bloch_crypto::crypto::MLDSA_PUBKEY_LEN];
        pk[..2].copy_from_slice(&[0xB1, 0x0C]);
        pk[2..4].copy_from_slice(&bloch_crypto::crypto::SUITE_MLDSA65_ONLY.to_le_bytes());
        for slh in [false, true] {
            assert!(!bloch_crypto::crypto::is_spend_public_key_admissible(&pk, slh));
        }
    }

    #[test]
    fn suites_with_inert_gates_report_null_and_closed() {
        let g = SuiteGates {
            slh_suite_epoch: u64::MAX,
            slh_suite_active: |e| epoch_gate_active(e, u64::MAX),
            lattice_emergency_epoch: u64::MAX,
        };
        for e in [0, 6_562, u64::MAX] {
            let v = signature_suites_json_from(&g, e, e);
            let s3 = suite_at(&v, "0x0003");
            assert_eq!(field(s3, "activation_epoch"), &Json::Null);
            assert_eq!(field(s3, "active"), &Json::Bool(false));
            assert_eq!(field(s3, "spend_allowed"), &Json::Bool(false));
            assert_eq!(field(suite_at(&v, "0x0001"), "spend_allowed"), &Json::Bool(true));
        }
    }

    #[test]
    fn suites_with_an_armed_override_open_0x0003_at_its_epoch() {
        let g = SuiteGates {
            slh_suite_epoch: 6_562,
            slh_suite_active: |e| epoch_gate_active(e, 6_562),
            lattice_emergency_epoch: 7_000,
        };
        let v = signature_suites_json_from(&g, 6_561, 6_561);
        let s3 = suite_at(&v, "0x0003");
        assert_eq!(field(s3, "activation_epoch").as_u64(), Some(6_562));
        assert_eq!(field(s3, "active"), &Json::Bool(false));
        assert_eq!(field(s3, "spend_allowed"), &Json::Bool(false));

        // Head behind wall at the boundary: admission (wall) opens first.
        let v = signature_suites_json_from(&g, 6_561, 6_562);
        assert_eq!(field(suite_at(&v, "0x0003"), "active"), &Json::Bool(false));
        assert_eq!(field(suite_at(&v, "0x0003"), "spend_allowed"), &Json::Bool(true));

        let v = signature_suites_json_from(&g, 6_562, 6_562);
        assert_eq!(field(suite_at(&v, "0x0003"), "active"), &Json::Bool(true));
        assert_eq!(field(suite_at(&v, "0x0001"), "spend_allowed"), &Json::Bool(true));
        assert_eq!(field(suite_at(&v, "0x0002"), "spend_allowed"), &Json::Bool(false));

        // Lattice emergency: lattice-suite spends freeze, 0x0003 stays open.
        let v = signature_suites_json_from(&g, 7_000, 7_000);
        assert_eq!(field(suite_at(&v, "0x0001"), "spend_allowed"), &Json::Bool(false));
        assert_eq!(field(suite_at(&v, "0x0003"), "spend_allowed"), &Json::Bool(true));
    }
}
