//! Remote attestation (Bloch-SIS-Linux L3) — a **pluggable attestation layer**.
//!
//! "Linux" (a SEV-SNP confidential VM) is just one backend. The layer is
//! parametrized over the execution environment so the same interface serves:
//!
//! - `none`    — no TEE; reports `attested: false` (honest default, all platforms)
//! - `sev-snp` — AMD SEV-SNP confidential VM (cloud), via the `virtee/sev` crate
//! - `tdx`     — Intel TDX confidential VM (cloud)
//! - `tpm`     — measured boot on bare metal
//! - `mobile`  — device TEE: Android Key Attestation / iOS App Attest (ZERO cloud
//!              cost — the phone people already own; a light-client role)
//!
//! What attestation gives, precisely (Coherence discipline): it proves *what
//! code runs in what environment* and **binds it to our reproducible image
//! digest** — it is INTEGRITY, not cryptographic secrecy. See
//! `docs/specs/BLOCH-SIS-ATTESTATION.md` and `COHERENCE-v0.2.md §4`.
//!
//! Binding to the L1 reproducible digest (from the research):
//! - SEV-SNP hardware measures only the boot chain, NOT the container image. The
//!   image is pinned at the software-policy layer (CoCo `image-rs` admits only a
//!   cosign-signed digest), and that policy's hash goes into the signed report's
//!   `HOSTDATA`. So a verifier checks: report signature + `hostdata` == expected
//!   policy hash (which pins our `image_digest`) + boot `measurement` == the
//!   precomputed value.

use serde::{Serialize, Deserialize};

/// Which trusted-execution backend produced (or would produce) the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tee {
    None,
    SevSnp,
    Tdx,
    Tpm,
    Mobile,
}

impl Tee {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tee::None => "none",
            Tee::SevSnp => "sev-snp",
            Tee::Tdx => "tdx",
            Tee::Tpm => "tpm",
            Tee::Mobile => "mobile",
        }
    }
}

/// A node's attestation status, serialized directly to the RPC result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// True ONLY when a real TEE quote is present and self-consistent.
    pub attested: bool,
    /// The backend that produced this report.
    pub tee: Tee,
    /// Verifier-supplied freshness challenge, echoed back (and, for a real TEE,
    /// bound into the quote's report-data). Prevents replay of an old quote.
    pub nonce: Option<String>,
    /// Boot-chain / launch measurement (hex), when attested. For SEV-SNP this is
    /// the deterministic boot measurement; a verifier compares it to a
    /// precomputed value for the reproducible boot chain.
    pub measurement: Option<String>,
    /// The signed report's HOSTDATA (SEV-SNP) / MR_CONFIG_ID (TDX): the hash of
    /// the initdata/config that carries the image-admission policy pinning our
    /// image digest. This is the field that ties the image to the hardware.
    pub hostdata: Option<String>,
    /// The reproducible OCI image digest this build claims to be (from the
    /// `BLOCH_IMAGE_DIGEST` env baked at deploy time). Bound via `hostdata`.
    pub image_digest: Option<String>,
    /// Raw attestation quote/report, base64, when attested (provider-specific).
    pub quote_b64: Option<String>,
    /// dm-verity roothash of the immutable OS image (hex), when running on an
    /// immutable/attestable Bloch OS. Independent of the TEE: it measures OS
    /// integrity (the reproducible image), read from the kernel cmdline. A
    /// verifier compares it to the roothash of the audited reproducible image.
    #[serde(default)]
    pub os_roothash: Option<String>,
    /// Human-readable status.
    pub note: String,
}

/// Parse the dm-verity roothash from a kernel command line. systemd-repart /
/// verity images pass it as `roothash=` (or `usrhash=` / `systemd.verity_root_hash=`).
pub fn parse_verity_roothash(cmdline: &str) -> Option<String> {
    cmdline.split_whitespace().find_map(|tok| {
        let (k, v) = tok.split_once('=')?;
        if matches!(k, "roothash" | "usrhash" | "systemd.verity_root_hash") && !v.is_empty() {
            Some(v.to_string())
        } else {
            None
        }
    })
}

/// Read the OS dm-verity roothash from the running kernel's cmdline (Linux).
pub fn read_os_roothash() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/cmdline")
            .ok()
            .and_then(|c| parse_verity_roothash(&c))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

impl AttestationReport {
    /// The honest "no TEE" report — always available, never claims attestation.
    fn unattested(nonce: Option<String>) -> Self {
        AttestationReport {
            attested: false,
            tee: Tee::None,
            nonce,
            measurement: None,
            hostdata: None,
            image_digest: std::env::var("BLOCH_IMAGE_DIGEST").ok(),
            quote_b64: None,
            os_roothash: read_os_roothash(),
            note: "no TEE provider active — node is running UNATTESTED. Deploy the \
                   reproducible image inside a SEV-SNP/TDX confidential VM (or run a \
                   mobile light client) and enable the matching provider for a real \
                   attestation quote."
                .into(),
        }
    }
}

/// A source of attestation reports for the local node's environment.
pub trait AttestationProvider {
    fn tee(&self) -> Tee;
    /// Produce a report, binding `nonce` for freshness. Returns None if this
    /// provider's hardware/environment isn't present (so callers can fall back).
    fn report(&self, nonce: Option<String>) -> Option<AttestationReport>;
}

/// Always-available fallback provider.
pub struct NoTeeProvider;
impl AttestationProvider for NoTeeProvider {
    fn tee(&self) -> Tee { Tee::None }
    fn report(&self, nonce: Option<String>) -> Option<AttestationReport> {
        Some(AttestationReport::unattested(nonce))
    }
}

// Real backends. Compiled in only under their feature+platform; each returns
// None when the hardware/env isn't actually present, so `current_report` falls
// back to the honest no-TEE report. The crypto (virtee/sev report parsing,
// mobile cert-chain checks) is completed where the hardware exists.
#[cfg(all(feature = "sev-snp", target_os = "linux"))]
pub mod sev_snp;
#[cfg(feature = "mobile")]
pub mod mobile;

/// Report from the active provider, binding an optional freshness `nonce`.
pub fn current_report(nonce: Option<String>) -> AttestationReport {
    #[cfg(all(feature = "sev-snp", target_os = "linux"))]
    if let Some(r) = sev_snp::SevSnpProvider.report(nonce.clone()) { return r; }
    NoTeeProvider.report(nonce).expect("no-TEE provider is infallible")
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// What a verifier expects a genuine, up-to-date Bloch node to attest to.
#[derive(Debug, Clone)]
pub struct Expected {
    /// The environment we require (e.g. `Tee::SevSnp`). `Tee::None` means "any".
    pub tee: Tee,
    /// The reproducible OCI image digest (from L1). Required.
    pub image_digest: String,
    /// Precomputed boot-chain measurement, if known (SEV-SNP/TDX). Optional.
    pub measurement: Option<String>,
    /// Expected `hostdata` (hash of the image-admission policy). Optional but
    /// strongly recommended — it is the hardware-side binding of the image.
    pub hostdata: Option<String>,
    /// Expected dm-verity roothash of the immutable Bloch OS image. Optional; set
    /// it to require the node run the audited reproducible OS image.
    pub os_roothash: Option<String>,
}

/// Result of verifying a report against `Expected` + a freshness nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Report is attested, fresh, bound to the expected identity, AND its raw
    /// quote was cryptographically verified against the vendor's signing key
    /// by a [`QuoteVerifier`] — never granted on self-reported fields alone.
    Trusted,
    /// Structurally/semantically rejected, or no cryptographic quote check
    /// was available/passed, with a reason.
    Rejected(String),
}

/// HIGH-5 (audit): a pluggable, provider-specific cryptographic check of a
/// raw attestation quote. `AttestationReport` carries `quote_b64` precisely
/// so this check can exist, but before this fix nothing in [`verify`] ever
/// read that field — every other field (`attested`, `tee`, `measurement`,
/// `hostdata`, `image_digest`, `os_roothash`) is plain, self-reported data on
/// the wire, and `verify` returned `Trusted` from string equality on those
/// alone. A compromised node, a lying operator, or (were the report ever
/// relayed over an unauthenticated channel) a MITM could set `attested: true`
/// and copy matching strings into every other field with no hardware backing
/// them at all, and be trusted.
///
/// A real implementation (e.g. SEV-SNP: parse `quote_b64` as a signed
/// attestation report, verify its signature chains to AMD's VCEK/ARK root,
/// and confirm the report's OWN `measurement`/`host_data`/`report_data`
/// fields — not the ones self-reported in `AttestationReport` — match what
/// is claimed) lives behind this trait so `verify` can enforce it uniformly
/// across TEE backends without hard-coding any one vendor's quote format.
pub trait QuoteVerifier {
    /// Which TEE this verifier can cryptographically check.
    fn tee(&self) -> Tee;
    /// Verify that `report.quote_b64` is a genuine, vendor-signed quote whose
    /// OWN measured fields (not merely the self-reported ones alongside it)
    /// are consistent with `report` and bind `want_nonce` for freshness.
    /// `Ok(())` only on a full cryptographic pass.
    fn verify_quote(&self, report: &AttestationReport, want_nonce: Option<&str>) -> Result<(), String>;
}

/// Verify a report against `Expected` + a freshness nonce.
///
/// INVARIANT (HIGH-5): this function MUST NOT return `Verdict::Trusted`
/// unless (a) every self-reported field passes the platform-independent
/// checks below AND (b) a [`QuoteVerifier`] matching `report.tee` is present
/// in `verifiers` and its `verify_quote` returns `Ok(())`. With no matching
/// verifier — which is the case for EVERY backend in this tree today, since
/// `sev_snp::SevSnpProvider::report` is a stub that always returns `None`
/// (see `sev_snp.rs`) and the mobile verifiers in `mobile.rs` are themselves
/// unwired stubs — the answer is `Rejected` with an explicit reason. Fail
/// closed: a missing cryptographic check is a REJECTION, never a silent
/// `Trusted` on the strength of self-reported strings matching.
///
/// The self-reported checks still run first and in cheapest-first order
/// (string/bool comparisons before the caller pays for the more expensive
/// cryptographic quote check), because a report failing them tells the
/// caller something concrete (TEE mismatch, stale nonce, wrong image) that
/// "no quote verifier available" would otherwise hide.
pub fn verify(
    report: &AttestationReport,
    expected: &Expected,
    want_nonce: Option<&str>,
    verifiers: &[&dyn QuoteVerifier],
) -> Verdict {
    if !report.attested {
        return Verdict::Rejected("report is not attested (no TEE / unattested node)".into());
    }
    if expected.tee != Tee::None && report.tee != expected.tee {
        return Verdict::Rejected(format!(
            "TEE mismatch: expected {}, got {}", expected.tee.as_str(), report.tee.as_str()));
    }
    // Freshness: the report must echo the challenge we issued.
    if let Some(n) = want_nonce {
        if report.nonce.as_deref() != Some(n) {
            return Verdict::Rejected("stale/missing nonce (possible replay)".into());
        }
    }
    // Image binding: the claimed digest must be the audited reproducible one.
    match &report.image_digest {
        Some(d) if d == &expected.image_digest => {}
        Some(d) => return Verdict::Rejected(format!(
            "image_digest mismatch: expected {}, got {}", expected.image_digest, d)),
        None => return Verdict::Rejected("report carries no image_digest".into()),
    }
    // Hardware-side binding of the image-admission policy.
    if let Some(want) = &expected.hostdata {
        match &report.hostdata {
            Some(h) if h == want => {}
            Some(h) => return Verdict::Rejected(format!(
                "hostdata mismatch: expected {}, got {}", want, h)),
            None => return Verdict::Rejected("report carries no hostdata (image not hardware-bound)".into()),
        }
    }
    // Boot-chain measurement, if a reference value is known.
    if let Some(want) = &expected.measurement {
        match &report.measurement {
            Some(m) if m == want => {}
            Some(m) => return Verdict::Rejected(format!(
                "measurement mismatch: expected {}, got {}", want, m)),
            None => return Verdict::Rejected("report carries no measurement".into()),
        }
    }
    // OS integrity: dm-verity roothash of the immutable image, if a reference is known.
    if let Some(want) = &expected.os_roothash {
        match &report.os_roothash {
            Some(h) if h == want => {}
            Some(h) => return Verdict::Rejected(format!(
                "os_roothash mismatch: expected {}, got {}", want, h)),
            None => return Verdict::Rejected("report carries no os_roothash (OS not verity-measured)".into()),
        }
    }
    // HIGH-5: everything above is self-reported. Only a matching
    // QuoteVerifier's cryptographic pass over the raw quote may grant Trusted.
    match verifiers.iter().find(|v| v.tee() == report.tee) {
        Some(v) => match v.verify_quote(report, want_nonce) {
            Ok(()) => Verdict::Trusted,
            Err(reason) => Verdict::Rejected(format!("quote verification failed: {reason}")),
        },
        None => Verdict::Rejected(format!(
            "no cryptographic quote verifier available for {} — self-reported \
             fields alone are never sufficient to trust a node (fail-closed)",
            report.tee.as_str()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_report(nonce: &str) -> AttestationReport {
        AttestationReport {
            attested: true,
            tee: Tee::SevSnp,
            nonce: Some(nonce.into()),
            measurement: Some("aa".repeat(48)),
            hostdata: Some("bb".repeat(32)),
            image_digest: Some("8de44fc7".into()),
            quote_b64: Some("cXVvdGU=".into()),
            os_roothash: Some("cc".repeat(32)),
            note: "attested".into(),
        }
    }
    fn expected() -> Expected {
        Expected {
            tee: Tee::SevSnp,
            image_digest: "8de44fc7".into(),
            measurement: Some("aa".repeat(48)),
            hostdata: Some("bb".repeat(32)),
            os_roothash: None,
        }
    }

    #[test]
    fn default_report_is_unattested_and_honest() {
        let r = current_report(None);
        assert!(!r.attested);
        assert_eq!(r.tee, Tee::None);
        assert!(r.quote_b64.is_none());
        assert!(r.note.contains("UNATTESTED"));
    }

    /// A [`QuoteVerifier`] whose verdict is fixed at construction, for
    /// testing both the "no verifier available" fail-closed path and the
    /// "verifier present and passes/fails" paths without any real hardware.
    struct MockVerifier {
        tee: Tee,
        result: Result<(), &'static str>,
    }
    impl QuoteVerifier for MockVerifier {
        fn tee(&self) -> Tee {
            self.tee
        }
        fn verify_quote(&self, _report: &AttestationReport, _want_nonce: Option<&str>) -> Result<(), String> {
            self.result.map_err(|e| e.to_string())
        }
    }

    /// HIGH-5 regression: this is THE finding. A report whose self-reported
    /// fields match `Expected` EXACTLY (nonce fresh, digest/hostdata/
    /// measurement all correct) must still be REJECTED, not Trusted, when no
    /// cryptographic `QuoteVerifier` is supplied — self-reported strings are
    /// never sufficient on their own. Before the fix, this exact input
    /// returned `Verdict::Trusted`.
    #[test]
    fn verify_never_trusts_self_reported_fields_alone() {
        let v = verify(&good_report("n1"), &expected(), Some("n1"), &[]);
        assert!(
            matches!(v, Verdict::Rejected(_)),
            "a perfectly-matching but cryptographically unverified report must be Rejected, got {:?}", v
        );
    }

    /// The complementary positive case: Trusted IS reachable, but only when a
    /// matching QuoteVerifier is present and its cryptographic check passes.
    #[test]
    fn verify_trusts_only_with_a_passing_quote_verifier() {
        let ok_verifier = MockVerifier { tee: Tee::SevSnp, result: Ok(()) };
        assert_eq!(
            verify(&good_report("n1"), &expected(), Some("n1"), &[&ok_verifier]),
            Verdict::Trusted
        );
    }

    /// A verifier for the WRONG tee must not be picked up — Trusted must come
    /// from a verifier that actually matches `report.tee`.
    #[test]
    fn verify_ignores_a_verifier_for_a_different_tee() {
        let wrong_tee_verifier = MockVerifier { tee: Tee::Tdx, result: Ok(()) };
        let v = verify(&good_report("n1"), &expected(), Some("n1"), &[&wrong_tee_verifier]);
        assert!(matches!(v, Verdict::Rejected(_)));
    }

    /// A matching verifier that FAILS the cryptographic check must reject,
    /// even though every self-reported field matched.
    #[test]
    fn verify_rejects_when_quote_verifier_fails() {
        let failing = MockVerifier { tee: Tee::SevSnp, result: Err("bad VCEK signature") };
        let v = verify(&good_report("n1"), &expected(), Some("n1"), &[&failing]);
        match v {
            Verdict::Rejected(reason) => assert!(reason.contains("bad VCEK signature")),
            other => panic!("expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn verify_rejects_unattested() {
        let r = current_report(Some("n1".into()));
        let ok_verifier = MockVerifier { tee: Tee::None, result: Ok(()) };
        assert!(matches!(verify(&r, &expected(), Some("n1"), &[&ok_verifier]), Verdict::Rejected(_)));
    }

    #[test]
    fn verify_rejects_wrong_image_digest() {
        let mut r = good_report("n1");
        r.image_digest = Some("deadbeef".into());
        let ok_verifier = MockVerifier { tee: Tee::SevSnp, result: Ok(()) };
        assert!(matches!(verify(&r, &expected(), Some("n1"), &[&ok_verifier]), Verdict::Rejected(_)));
    }

    #[test]
    fn verify_rejects_stale_nonce() {
        let ok_verifier = MockVerifier { tee: Tee::SevSnp, result: Ok(()) };
        assert!(matches!(
            verify(&good_report("OLD"), &expected(), Some("FRESH"), &[&ok_verifier]),
            Verdict::Rejected(_)
        ));
    }

    #[test]
    fn verify_rejects_tee_and_hostdata_mismatch() {
        let ok_verifier = MockVerifier { tee: Tee::Tdx, result: Ok(()) };
        let mut r = good_report("n1");
        r.tee = Tee::Tdx;
        assert!(matches!(verify(&r, &expected(), Some("n1"), &[&ok_verifier]), Verdict::Rejected(_)));
        let ok_verifier2 = MockVerifier { tee: Tee::SevSnp, result: Ok(()) };
        let mut r2 = good_report("n1");
        r2.hostdata = Some("00".repeat(32));
        assert!(matches!(verify(&r2, &expected(), Some("n1"), &[&ok_verifier2]), Verdict::Rejected(_)));
    }

    #[test]
    fn parses_verity_roothash_from_cmdline() {
        let cl = "BOOT_IMAGE=/vmlinuz root=/dev/mapper/root roothash=abc123 quiet";
        assert_eq!(parse_verity_roothash(cl).as_deref(), Some("abc123"));
        assert_eq!(parse_verity_roothash("root=/dev/sda1 quiet"), None);
        assert_eq!(parse_verity_roothash("usrhash=deadbeef").as_deref(), Some("deadbeef"));
    }

    #[test]
    fn verify_checks_os_roothash_when_expected() {
        let ok_verifier = MockVerifier { tee: Tee::SevSnp, result: Ok(()) };
        let mut exp = expected();
        exp.os_roothash = Some("cc".repeat(32)); // matches good_report
        assert_eq!(verify(&good_report("n1"), &exp, Some("n1"), &[&ok_verifier]), Verdict::Trusted);

        let mut r = good_report("n1");
        r.os_roothash = Some("ff".repeat(32));
        assert!(matches!(verify(&r, &exp, Some("n1"), &[&ok_verifier]), Verdict::Rejected(_)));

        let mut r2 = good_report("n1");
        r2.os_roothash = None;
        assert!(matches!(verify(&r2, &exp, Some("n1"), &[&ok_verifier]), Verdict::Rejected(_)));
    }
}
