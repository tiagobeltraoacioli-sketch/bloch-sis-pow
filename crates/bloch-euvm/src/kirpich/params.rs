//! # Kirpich — Lane C: **Unsafe parameter combos** (charter-scalar sanity)
//!
//! Part of the **Kirpich** internal-audit pass (`кирпич` = "brick": the building
//! block you inspect before laying it into the contract). This lane is a pure,
//! deterministic static check over a [`TokenCharter`]'s *scalar* module parameters —
//! the numbers and byte-strings baked into each module's config — catching
//! combinations that compile into a validator which is silently broken, neutered,
//! or unspendable, **before** [`crate::modules::compile_charter`] ever emits bytecode.
//!
//! It never runs the VM, never touches IO/clock/float/HashMap, and never panics on
//! any charter input: a malformed charter yields a [`Finding`], not a crash.
//!
//! ## Rules implemented in this lane
//!
//! | code    | severity | module     | condition |
//! |---------|----------|------------|-----------|
//! | KRP-040 | Deny     | governance | `threshold == 0` — a 0-of-m gate authorises any spend with no valid signature |
//! | KRP-041 | Deny     | governance | `threshold > signers.len()` — quorum is unsatisfiable, funds locked forever |
//! | KRP-042 | Deny     | governance | `signers.len() > 253` — `compile_governance`'s `(m+3-i) as u8` Pick-depth truncates for signer #1 |
//! | KRP-043 | Deny     | vesting    | `unlock_height <= 0` — the height gate is open at every real block height |
//! | KRP-044 | Deny     | supply     | `cap == 0` — no mint can authorise a positive amount; the token can never be issued |
//! | KRP-045 | Deny     | governance | a signer pubkey is empty — that slot can never verify a signature |
//!
//! ## Finding / Severity shape (for the Integrate phase)
//!
//! This file expects the integrator's `src/kirpich.rs` to define the parent-module
//! types exactly as in the design contract, imported here via `use super::…`:
//!
//! ```ignore
//! pub enum Severity { Deny = 0, Warn = 1, Info = 2 }   // Ord: most-severe first
//! pub struct Finding {
//!     pub code: &'static str,          // stable "KRP-NNN"
//!     pub severity: Severity,
//!     pub module: Option<&'static str>,// ModuleKind::tag(), or None for charter-level
//!     pub index: Option<usize>,        // position in charter.modules
//!     pub message: String,             // deterministic format! over charter scalars
//! }
//! ```
//!
//! The lane entry point is the append-only sink the dispatcher calls:
//! `pub(super) fn audit(charter: &TokenCharter, out: &mut Vec<Finding>)`.

use super::{Finding, Severity};
use crate::modules::{ModuleKind, TokenCharter};

/// The largest `signers.len()` (`m`) that `compile_governance` can emit correctly.
///
/// `compile_governance` computes each signer's stack depth as `(m + 3 - i) as u8`
/// (1-based `i`). The shallowest cast is for signer #1: `depth = m + 2`. For that to
/// fit in a `u8` we need `m + 2 <= 255`, i.e. `m <= 253`. At `m == 254` the cast
/// wraps (`256 as u8 == 0`), turning `Pick(256)` into `Pick(0) == Dup`, which copies
/// the just-pushed pubkey instead of the signature slot — a silent liveness defect.
const MAX_GOVERNANCE_SIGNERS: usize = 253;

/// Build a module-scoped Deny finding. `tag` is `ModuleKind::tag()` (`&'static str`);
/// `index` is the module's position in `charter.modules`.
fn deny(code: &'static str, tag: &'static str, index: usize, message: String) -> Finding {
    Finding {
        code,
        severity: Severity::Deny,
        module: Some(tag),
        index: Some(index),
        message,
    }
}

/// **Lane C — Unsafe parameter combos.** Append-only into `out`; deterministic; never
/// panics. Walks `charter.modules` in order (index-stable) and applies rules
/// KRP-040..=KRP-045 to each module's scalar config.
pub(super) fn audit(charter: &TokenCharter, out: &mut Vec<Finding>) {
    for (idx, module) in charter.modules.iter().enumerate() {
        let tag = module.tag(); // stable &'static str, e.g. "governance"
        match module {
            ModuleKind::Governance(c) => {
                let m = c.signers.len();
                // Widen once to a common type; no arithmetic here can overflow because
                // both operands are small charter-supplied counts.
                let threshold = c.threshold as u64;
                let m_u64 = m as u64;

                // KRP-040: threshold == 0 — the accumulator (always >= 0) trivially
                // clears the gate, so a "0-of-m" multisig requires no valid signature.
                if c.threshold == 0 {
                    out.push(deny(
                        "KRP-040",
                        tag,
                        idx,
                        format!(
                            "Governance threshold is 0: a 0-of-{m} multisig authorises \
                             any spend with zero valid signatures — the module guards nothing"
                        ),
                    ));
                }

                // KRP-041: threshold > signers — the running count can never reach the
                // threshold, so the gate can never pass: the funds are unspendable.
                if threshold > m_u64 {
                    out.push(deny(
                        "KRP-041",
                        tag,
                        idx,
                        format!(
                            "Governance threshold {threshold} exceeds the signer count {m}: \
                             quorum is unsatisfiable, the guarded output is permanently unspendable"
                        ),
                    ));
                }

                // KRP-042: signers > 253 — compile_governance's `(m+3-i) as u8` Pick
                // depth truncates for signer #1 (depth m+2 wraps mod 256), silently
                // emitting Pick(0)==Dup and corrupting the validator.
                if m > MAX_GOVERNANCE_SIGNERS {
                    // m + 2 cannot overflow: usize is >= 16 bits and m is a Vec length.
                    let depth = (m as u128) + 2;
                    out.push(deny(
                        "KRP-042",
                        tag,
                        idx,
                        format!(
                            "Governance has {m} signers (> {MAX_GOVERNANCE_SIGNERS}): \
                             compile_governance encodes signer #1's stack depth as {depth} \
                             which does not fit in u8 (wraps mod 256 to Pick(0)==Dup), \
                             silently producing a corrupt validator"
                        ),
                    ));
                }

                // KRP-045: any empty signer pubkey — such a slot can never verify a
                // real signature, so it is dead weight that can silently strand quorum.
                let empties: Vec<usize> = c
                    .signers
                    .iter()
                    .enumerate()
                    .filter(|(_, pk)| pk.is_empty())
                    .map(|(i, _)| i)
                    .collect();
                if !empties.is_empty() {
                    out.push(deny(
                        "KRP-045",
                        tag,
                        idx,
                        format!(
                            "Governance signer(s) at index(es) {empties:?} have an empty pubkey \
                             ({} of {m}): those slots can never verify a signature and cannot \
                             contribute to quorum",
                            empties.len()
                        ),
                    ));
                }
            }

            ModuleKind::Vesting(c) => {
                // KRP-043: unlock_height <= 0 — real block heights are >= 0, so the
                // `height >= unlock_height` gate is satisfied everywhere: vesting never
                // actually locks the output.
                if c.unlock_height <= 0 {
                    out.push(deny(
                        "KRP-043",
                        tag,
                        idx,
                        format!(
                            "Vesting unlock_height {} <= 0: the height gate is satisfied at \
                             every real block height, so the vesting lock never engages",
                            c.unlock_height
                        ),
                    ));
                }
            }

            ModuleKind::Supply(c) => {
                // KRP-044: cap == 0 — the supply program asserts `requested <= cap`, so
                // with cap 0 no positive mint can ever be authorised: the token is
                // permanently un-issuable (a fixed-zero-supply "token").
                if c.cap == 0 {
                    out.push(deny(
                        "KRP-044",
                        tag,
                        idx,
                        "Supply cap is 0: no mint can authorise a positive amount \
                         (requested <= 0 only), so the token can never be issued"
                            .to_string(),
                    ));
                }
            }

            // TransferPolicy / ComplianceKycGate / Custody carry no scalar parameters
            // in this lane's remit (KRP-040..=KRP-045). Other lanes cover them.
            ModuleKind::TransferPolicy(_)
            | ModuleKind::ComplianceKycGate(_)
            | ModuleKind::Custody(_) => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::{
        CustodyConfig, GovernanceConfig, KycConfig, SupplyConfig, TransferPolicyConfig,
        VestingConfig,
    };

    // ── tiny helpers ──────────────────────────────────────────────────────────

    fn run(modules: Vec<ModuleKind>) -> Vec<Finding> {
        let charter = TokenCharter {
            token_name: b"TEST".to_vec(),
            modules,
        };
        let mut out = Vec::new();
        audit(&charter, &mut out);
        out
    }

    fn codes(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|x| x.code).collect()
    }

    fn has(f: &[Finding], code: &str) -> bool {
        f.iter().any(|x| x.code == code)
    }

    fn gov(signers: Vec<Vec<u8>>, threshold: u32) -> ModuleKind {
        ModuleKind::Governance(GovernanceConfig { signers, threshold })
    }
    fn pk(n: usize) -> Vec<u8> {
        format!("pk-{n}").into_bytes()
    }
    fn pks(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(pk).collect()
    }
    fn supply(cap: u64) -> ModuleKind {
        ModuleKind::Supply(SupplyConfig {
            cap,
            issuer_pubkey: b"iss".to_vec(),
        })
    }
    fn vesting(unlock_height: i128) -> ModuleKind {
        ModuleKind::Vesting(VestingConfig {
            unlock_height,
            beneficiary_pubkey: b"benef".to_vec(),
        })
    }

    // ── KRP-040 threshold == 0 ────────────────────────────────────────────────

    #[test]
    fn krp040_zero_threshold_denies() {
        let f = run(vec![gov(pks(3), 0)]);
        assert!(has(&f, "KRP-040"), "0-of-m must deny: {:?}", codes(&f));
        let d = f.iter().find(|x| x.code == "KRP-040").unwrap();
        assert_eq!(d.severity, Severity::Deny);
        assert_eq!(d.module, Some("governance"));
        assert_eq!(d.index, Some(0));
    }

    #[test]
    fn krp040_nonzero_threshold_passes() {
        let f = run(vec![gov(pks(3), 2)]);
        assert!(!has(&f, "KRP-040"), "2-of-3 must not fire KRP-040: {:?}", codes(&f));
    }

    // ── KRP-041 threshold > signers ───────────────────────────────────────────

    #[test]
    fn krp041_threshold_exceeds_signers_denies() {
        let f = run(vec![gov(pks(3), 4)]); // 4-of-3 is unsatisfiable
        assert!(has(&f, "KRP-041"), "4-of-3 must deny: {:?}", codes(&f));
        assert_eq!(
            f.iter().find(|x| x.code == "KRP-041").unwrap().severity,
            Severity::Deny
        );
    }

    #[test]
    fn krp041_threshold_equal_to_signers_passes() {
        // Unanimous m-of-m is a valid (if strict) configuration, not a defect.
        let f = run(vec![gov(pks(3), 3)]);
        assert!(!has(&f, "KRP-041"), "3-of-3 must not fire KRP-041: {:?}", codes(&f));
    }

    // ── KRP-042 signers > 253 (u8 Pick-depth truncation) ──────────────────────

    #[test]
    fn krp042_over_253_signers_denies() {
        // 254 signers: signer #1 needs Pick depth 256, which wraps in u8.
        let f = run(vec![gov(pks(254), 254)]);
        assert!(has(&f, "KRP-042"), "254 signers must deny: {:?}", codes(&f));
        assert_eq!(
            f.iter().find(|x| x.code == "KRP-042").unwrap().severity,
            Severity::Deny
        );
    }

    #[test]
    fn krp042_exactly_253_signers_passes() {
        // Boundary: m == 253 → signer #1 depth 255 fits in u8 exactly.
        let f = run(vec![gov(pks(253), 200)]);
        assert!(
            !has(&f, "KRP-042"),
            "253 signers is the safe boundary, must not fire KRP-042: {:?}",
            codes(&f)
        );
    }

    // ── KRP-043 vesting unlock_height <= 0 ────────────────────────────────────

    #[test]
    fn krp043_zero_unlock_height_denies() {
        let f = run(vec![vesting(0)]);
        assert!(has(&f, "KRP-043"), "unlock_height 0 must deny: {:?}", codes(&f));
        let d = f.iter().find(|x| x.code == "KRP-043").unwrap();
        assert_eq!(d.severity, Severity::Deny);
        assert_eq!(d.module, Some("vesting"));
    }

    #[test]
    fn krp043_negative_unlock_height_denies() {
        let f = run(vec![vesting(-1)]);
        assert!(has(&f, "KRP-043"), "negative unlock_height must deny: {:?}", codes(&f));
    }

    #[test]
    fn krp043_positive_unlock_height_passes() {
        let f = run(vec![vesting(2_400)]);
        assert!(!has(&f, "KRP-043"), "unlock_height 2400 must pass: {:?}", codes(&f));
    }

    // ── KRP-044 supply cap == 0 ───────────────────────────────────────────────

    #[test]
    fn krp044_zero_cap_denies() {
        let f = run(vec![supply(0)]);
        assert!(has(&f, "KRP-044"), "cap 0 must deny: {:?}", codes(&f));
        let d = f.iter().find(|x| x.code == "KRP-044").unwrap();
        assert_eq!(d.severity, Severity::Deny);
        assert_eq!(d.module, Some("supply"));
    }

    #[test]
    fn krp044_positive_cap_passes() {
        let f = run(vec![supply(1_000_000)]);
        assert!(!has(&f, "KRP-044"), "cap 1e6 must pass: {:?}", codes(&f));
    }

    // ── KRP-045 empty signer pubkey ───────────────────────────────────────────

    #[test]
    fn krp045_empty_signer_pubkey_denies() {
        // Middle signer has an empty pubkey.
        let f = run(vec![gov(vec![pk(0), vec![], pk(2)], 2)]);
        assert!(has(&f, "KRP-045"), "empty signer pubkey must deny: {:?}", codes(&f));
        let d = f.iter().find(|x| x.code == "KRP-045").unwrap();
        assert_eq!(d.severity, Severity::Deny);
        assert!(d.message.contains('1'), "message names offending index: {}", d.message);
    }

    #[test]
    fn krp045_all_nonempty_pubkeys_pass() {
        let f = run(vec![gov(pks(3), 2)]);
        assert!(!has(&f, "KRP-045"), "all-nonempty signers must pass: {:?}", codes(&f));
    }

    // ── composition / determinism / no-panic ─────────────────────────────────

    #[test]
    fn multiple_defects_in_one_governance_module_all_reported() {
        // threshold 0 (KRP-040) AND an empty signer (KRP-045) in the same module.
        let f = run(vec![gov(vec![pk(0), vec![]], 0)]);
        assert!(has(&f, "KRP-040"), "{:?}", codes(&f));
        assert!(has(&f, "KRP-045"), "{:?}", codes(&f));
    }

    #[test]
    fn index_tracks_module_position_in_charter() {
        // Supply(ok), TransferPolicy(ok), Supply(cap==0) → the KRP-044 finding must
        // point at index 2, not index 0.
        let f = run(vec![
            supply(100),
            ModuleKind::TransferPolicy(TransferPolicyConfig {
                authority_pubkey: b"a".to_vec(),
            }),
            supply(0),
        ]);
        let d = f.iter().find(|x| x.code == "KRP-044").unwrap();
        assert_eq!(d.index, Some(2), "must report the offending module's real index");
    }

    #[test]
    fn clean_charter_yields_no_findings() {
        let f = run(vec![
            supply(1_000_000),
            ModuleKind::TransferPolicy(TransferPolicyConfig {
                authority_pubkey: b"auth".to_vec(),
            }),
            ModuleKind::ComplianceKycGate(KycConfig::default()),
            vesting(2_400),
            gov(pks(3), 2),
            ModuleKind::Custody(CustodyConfig {
                btc_pubkey: b"btc".to_vec(),
                pq_pubkey: b"pq".to_vec(),
            }),
        ]);
        assert!(f.is_empty(), "healthy charter must produce zero findings: {:?}", codes(&f));
    }

    #[test]
    fn determinism_same_charter_identical_findings() {
        let modules = || vec![gov(vec![pk(0), vec![]], 0), supply(0), vesting(-5)];
        let a = run(modules());
        let b = run(modules());
        assert_eq!(a, b, "same charter must produce byte-identical findings");
    }

    #[test]
    fn empty_charter_no_panic_no_findings() {
        let f = run(vec![]);
        assert!(f.is_empty());
    }

    #[test]
    fn adversarial_extremes_do_not_panic() {
        // Extreme-but-in-range scalars: u32::MAX threshold, i128::MIN/MAX heights,
        // u64::MAX cap, zero signers. Must produce findings, never panic.
        let f = run(vec![
            gov(vec![], u32::MAX),      // threshold >> 0 signers → KRP-041
            vesting(i128::MIN),         // <= 0 → KRP-043
            vesting(i128::MAX),         // > 0 → clean
            supply(u64::MAX),           // clean
            supply(0),                  // KRP-044
        ]);
        assert!(has(&f, "KRP-041"));
        assert!(has(&f, "KRP-043"));
        assert!(has(&f, "KRP-044"));
    }

    #[test]
    fn zero_signers_zero_threshold_fires_only_krp040() {
        // 0-of-0: threshold==0 (KRP-040) fires; threshold(0) > signers(0) is false so
        // KRP-041 does not; no signers so KRP-045 does not.
        let f = run(vec![gov(vec![], 0)]);
        assert!(has(&f, "KRP-040"), "{:?}", codes(&f));
        assert!(!has(&f, "KRP-041"), "{:?}", codes(&f));
        assert!(!has(&f, "KRP-045"), "{:?}", codes(&f));
    }

    // ── additional adversarial + edge-case tests (appended; no rule-logic changes) ──

    #[test]
    fn krp041_huge_threshold_zero_signers_fires_only_krp041() {
        // threshold == u32::MAX, no signers at all: threshold != 0 so KRP-040 must NOT
        // fire; threshold >> 0 signers so KRP-041 must fire; no signers so KRP-045
        // cannot fire either. Also must not panic widening u32::MAX to u64.
        let f = run(vec![gov(vec![], u32::MAX)]);
        assert!(!has(&f, "KRP-040"), "{:?}", codes(&f));
        assert!(has(&f, "KRP-041"), "{:?}", codes(&f));
        assert!(!has(&f, "KRP-045"), "{:?}", codes(&f));
    }

    #[test]
    fn krp041_message_reports_correct_threshold_and_signer_count() {
        let f = run(vec![gov(pks(5), 4_000_000_000)]);
        let d = f.iter().find(|x| x.code == "KRP-041").unwrap();
        assert!(d.message.contains("4000000000"), "{}", d.message);
        assert!(d.message.contains(" 5"), "{}", d.message);
    }

    #[test]
    fn krp042_message_reports_correct_depth_for_boundary_m() {
        // m = 254 (one over the safe boundary): signer #1 Pick depth is m+2 = 256.
        let f = run(vec![gov(pks(254), 1)]);
        let d = f.iter().find(|x| x.code == "KRP-042").unwrap();
        assert!(d.message.contains("254"), "{}", d.message);
        assert!(d.message.contains("256"), "{}", d.message);
    }

    #[test]
    fn krp042_large_signer_count_no_overflow_no_panic() {
        // m = 1000, threshold = m (unanimous): must not panic on the widened depth
        // arithmetic and must still fire KRP-042 (depth 1002 does not fit in u8), while
        // KRP-041 must NOT fire since threshold == signer count is satisfiable.
        let f = run(vec![gov(pks(1000), 1000)]);
        assert!(has(&f, "KRP-042"), "{:?}", codes(&f));
        assert!(!has(&f, "KRP-041"), "{:?}", codes(&f));
        let d = f.iter().find(|x| x.code == "KRP-042").unwrap();
        assert!(d.message.contains("1000"), "{}", d.message);
        assert!(d.message.contains("1002"), "{}", d.message);
    }

    #[test]
    fn krp042_boundary_m_253_threshold_253_fully_clean() {
        // Both boundaries at once: max-safe signer count AND unanimous threshold.
        // Must be entirely defect-free — no false positive at the exact safe edge.
        let f = run(vec![gov(pks(253), 253)]);
        assert!(f.is_empty(), "boundary-safe unanimous 253-of-253 must be clean: {:?}", codes(&f));
    }

    #[test]
    fn krp045_multiple_empty_pubkeys_all_indices_reported_in_order() {
        let f = run(vec![gov(vec![pk(0), vec![], pk(2), vec![], pk(4)], 2)]);
        let d = f.iter().find(|x| x.code == "KRP-045").unwrap();
        assert!(d.message.contains('1'), "{}", d.message);
        assert!(d.message.contains('3'), "{}", d.message);
        assert!(d.message.contains('2'), "{}", d.message); // "2 of 5"
        assert!(d.message.contains('5'), "{}", d.message);
    }

    #[test]
    fn krp045_single_byte_nonempty_pubkey_is_not_misclassified_as_empty() {
        // A one-byte pubkey (e.g. a degenerate/malformed key) is non-empty and must
        // not false-positive KRP-045; only a literal zero-length pubkey should.
        let f = run(vec![gov(vec![vec![0u8], pk(1), pk(2)], 2)]);
        assert!(!has(&f, "KRP-045"), "1-byte pubkey must not count as empty: {:?}", codes(&f));
    }

    #[test]
    fn governance_duplicate_signer_pubkeys_not_flagged_by_this_lane() {
        // Duplicate signer keys are out of this lane's remit (KRP-040..=KRP-045 only);
        // confirms no false positive from an unrelated defect class leaking in here.
        let dup = pk(7);
        let f = run(vec![gov(vec![dup.clone(), dup.clone(), dup], 2)]);
        assert!(f.is_empty(), "duplicate pubkeys are not this lane's concern: {:?}", codes(&f));
    }

    #[test]
    fn kitchen_sink_all_three_governance_defects_fire_together_no_krp041() {
        // One governance module: threshold 0 (KRP-040), 300 signers (KRP-042), and an
        // empty pubkey at index 150 (KRP-045) — all three must fire independently and
        // simultaneously; KRP-041 must NOT fire (0 is not > 300).
        let mut signers = pks(300);
        signers[150] = vec![];
        let f = run(vec![gov(signers, 0)]);
        assert!(has(&f, "KRP-040"), "{:?}", codes(&f));
        assert!(has(&f, "KRP-042"), "{:?}", codes(&f));
        assert!(has(&f, "KRP-045"), "{:?}", codes(&f));
        assert!(!has(&f, "KRP-041"), "{:?}", codes(&f));
        assert_eq!(f.len(), 3, "exactly 3 findings expected for this module: {:?}", codes(&f));
        assert!(f.iter().all(|x| x.index == Some(0)), "{:?}", f);
    }

    #[test]
    fn boundary_scalar_values_all_pass_clean() {
        // Smallest legal positive values at every boundary: unlock_height = 1, cap = 1,
        // 1-of-1 governance with a single non-empty signer. None of these should ever
        // false-positive.
        let f = run(vec![vesting(1), supply(1), gov(pks(1), 1)]);
        assert!(f.is_empty(), "smallest-legal-positive values must be clean: {:?}", codes(&f));
    }

    #[test]
    fn non_scalar_modules_interleaved_do_not_perturb_index_or_findings() {
        // TransferPolicy / KycGate / Custody carry no scalar params for this lane; make
        // sure they neither produce findings themselves nor shift the index reported
        // for a real defect that follows them.
        let f = run(vec![
            ModuleKind::TransferPolicy(TransferPolicyConfig {
                authority_pubkey: b"a".to_vec(),
            }),
            ModuleKind::ComplianceKycGate(KycConfig::default()),
            ModuleKind::Custody(CustodyConfig {
                btc_pubkey: b"btc".to_vec(),
                pq_pubkey: b"pq".to_vec(),
            }),
            supply(0), // the only real defect, at index 3
        ]);
        assert_eq!(f.len(), 1, "{:?}", codes(&f));
        let d = &f[0];
        assert_eq!(d.code, "KRP-044");
        assert_eq!(d.index, Some(3));
    }

    #[test]
    fn only_non_scalar_modules_no_panic_no_findings() {
        let f = run(vec![
            ModuleKind::TransferPolicy(TransferPolicyConfig {
                authority_pubkey: vec![],
            }),
            ModuleKind::ComplianceKycGate(KycConfig::default()),
            ModuleKind::Custody(CustodyConfig {
                btc_pubkey: vec![],
                pq_pubkey: vec![],
            }),
        ]);
        assert!(f.is_empty(), "{:?}", codes(&f));
    }

    #[test]
    fn determinism_holds_over_a_larger_mixed_charter_across_many_runs() {
        // A bigger, messier charter mixing clean and dirty modules of every kind, run
        // repeatedly: findings must be byte-identical and in the same order every time
        // (no HashMap/clock/float nondeterminism anywhere in the lane).
        let build = || {
            vec![
                supply(0),                                  // KRP-044
                vesting(2_400),                              // clean
                gov(vec![pk(0), vec![], pk(2)], 0),          // KRP-040 + KRP-045
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"a".to_vec(),
                }),
                vesting(-1),                                 // KRP-043
                gov(pks(300), 400),                           // KRP-041 + KRP-042
                supply(42),                                   // clean
            ]
        };
        let runs: Vec<Vec<Finding>> = (0..5).map(|_| run(build())).collect();
        for w in runs.windows(2) {
            assert_eq!(w[0], w[1], "identical charter must yield identical findings every run");
        }
        // Sanity: every expected code is present exactly where expected.
        let f = &runs[0];
        assert_eq!(f.iter().find(|x| x.code == "KRP-044").unwrap().index, Some(0));
        assert_eq!(f.iter().find(|x| x.code == "KRP-043").unwrap().index, Some(4));
        assert_eq!(f.iter().find(|x| x.code == "KRP-041").unwrap().index, Some(5));
        assert_eq!(f.iter().find(|x| x.code == "KRP-042").unwrap().index, Some(5));
    }

    #[test]
    fn adversarial_i128_min_plus_one_and_max_minus_one_do_not_panic() {
        // Off-by-one neighbors of the extremes exercised elsewhere, to catch any
        // off-by-one in the `<= 0` comparison itself (not just saturating at MIN/MAX).
        let f = run(vec![vesting(i128::MIN + 1), vesting(i128::MAX - 1)]);
        assert!(has(&f, "KRP-043"), "{:?}", codes(&f)); // i128::MIN+1 is still <= 0
        assert_eq!(f.len(), 1, "i128::MAX-1 is still > 0, must stay clean: {:?}", codes(&f));
    }
}
