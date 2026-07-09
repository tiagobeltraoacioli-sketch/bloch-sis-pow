//! SEV-SNP attestation provider (feature `sev-snp`, Linux only).
//!
//! Completes the L3 hardware path: request the guest's SEV-SNP attestation
//! report, bind our freshness nonce into `report_data`, and surface `HOSTDATA`
//! (the image-admission policy hash) + the boot `measurement` so `verify()` can
//! bind them to the reproducible image digest.
//!
//! STUB: returns `None` until wired to `virtee/sev` on a real SEV-SNP guest —
//! there is no hardware to exercise it here, and the crate is Linux-only. The
//! shape below is the intended integration.

use super::{AttestationProvider, AttestationReport, Tee};

pub struct SevSnpProvider;

impl AttestationProvider for SevSnpProvider {
    fn tee(&self) -> Tee { Tee::SevSnp }

    fn report(&self, _nonce: Option<String>) -> Option<AttestationReport> {
        // TODO(L3): with the `sev` crate (Apache-2.0):
        //   let mut fw = sev::firmware::guest::Firmware::open().ok()?;
        //   let data = report_data_from_nonce(_nonce);   // 64-byte, = H(nonce)
        //   let report = fw.get_report(None, Some(data), None).ok()?;
        //   Some(AttestationReport {
        //       attested: true, tee: Tee::SevSnp, nonce: _nonce,
        //       measurement: Some(hex(report.measurement)),
        //       hostdata:    Some(hex(report.host_data)),
        //       image_digest: std::env::var("BLOCH_IMAGE_DIGEST").ok(),
        //       quote_b64:   Some(base64(report.as_bytes())),
        //       note: "SEV-SNP attested".into(),
        //   })
        None
    }
}
