# Postern OS — the attestation chain (immutable → measured → attested)

How the immutable/attestable profile (`os/attested.nix`) turns a reproducible OS
into a *remotely provable* one, reusing the existing L1/L2/L3 layers. This is the
**Postern Seal** attestation product — a Postern Labs product.

## The chain

```
reproducible flake input            (same input → same image; NixOS + L1 ethos)
        │  nix build .#attested-image
        ▼
immutable disk image                (read-only erofs rootfs)
        │  systemd-repart, Verity = data/hash
        ▼
dm-verity roothash                  seals the rootfs; any byte change ⇒ boot fails
        │  passed as `roothash=` on the kernel cmdline
        ├────────────────────────────────────────────────┐
        ▼                                                 ▼
UKI + measured boot                                node reads the roothash
(kernel+initrd+cmdline, one signed PE)             attestation::read_os_roothash()
        │  measured into TPM PCRs / covered by            │  reports it in
        ▼  the CVM launch measurement                     ▼  getattestation
SEV-SNP / TDX launch measurement  ───────────▶  AttestationReport {
        (L3: sev_snp provider, quote)                 measurement,   // boot/launch
                                                      os_roothash,   // OS integrity
                                                      image_digest,  // L1
                                                      hostdata }     // policy binding
        │
        ▼  attestation::verify(report, Expected { .. }, nonce, verifiers)
Verdict::Trusted  ⇔  right TEE + fresh nonce + audited image_digest
                     + expected boot measurement + expected os_roothash
                     + a QuoteVerifier for `report.tee` cryptographically
                       confirms `quote_b64` (HIGH-5: no verifier ⇒ Rejected,
                       never Trusted on self-reported fields alone)
```

## What each layer contributes

| Layer | Guarantee | Field checked in `verify` |
|---|---|---|
| **L1** reproducible build | the image is the audited one | `image_digest` |
| **Postern OS (verity)** | the running rootfs is that exact image, unaltered | `os_roothash` |
| **L2** hardening | least-privilege runtime (systemd service) | — (posture) |
| **L3** TEE | all of the above ran in a genuine SEV-SNP/TDX VM | `tee`, `measurement`, `hostdata` |

`os_roothash` is the new, TEE-independent rung: a bare-metal / non-TEE node can
report the verity roothash of the immutable image it claims to boot, and a
verifier can require it by setting `Expected.os_roothash`.

**HIGH-5 correction:** the sentence above previously said such a node "can now
**prove**" this. That overstated it. `read_os_roothash()` reads
`/proc/cmdline` — a plain, self-reported value with **no hardware root of
trust behind it on a non-TEE host**: anything that can influence what the
process reads there (a compromised node, a spoofed report, a MITM on an
unauthenticated channel it is relayed over) can make `os_roothash` say
anything. On a bare-metal node there is no TPM quote or other hardware
attestation over the boot chain wired in here to bind that string to reality
— so `os_roothash` alone is a **claim**, not a proof. It becomes
verifier-meaningful only inside the SEV-SNP/TDX branch of this chain, where
[`attestation::verify`]'s `QuoteVerifier` cryptographically checks the launch
measurement the roothash rides alongside; `verify` now fails closed
(`Verdict::Rejected`) whenever no such cryptographic check is available,
specifically so a self-reported `os_roothash` on its own can never produce
`Verdict::Trusted`.

## For a verifier

```rust
let report = /* node getattestation with a fresh nonce */;
let expected = Expected {
    tee: Tee::SevSnp,
    image_digest: AUDITED_OCI_DIGEST.into(),
    measurement: Some(REFERENCE_BOOT_MEASUREMENT.into()),
    hostdata: Some(POLICY_HASH.into()),
    os_roothash: Some(AUDITED_IMAGE_ROOTHASH.into()), // ← from `nix build .#attested-image`
};
// `verifiers` MUST contain a QuoteVerifier that matches `report.tee` and
// cryptographically checks `report.quote_b64` — otherwise `verify` fails
// closed with `Verdict::Rejected`, by design (HIGH-5). There is no such
// verifier wired in this tree yet (SEV-SNP quote verification remains
// unimplemented — see `sev_snp.rs`), so this example is aspirational until
// one is.
assert_eq!(verify(&report, &expected, Some(nonce), &[&sev_snp_quote_verifier]), Verdict::Trusted);
```

The reference `os_roothash` is deterministic output of `nix build
.#attested-image` — reproduce the image, read its roothash, pin it.

## Honesty

- `os/attested.nix` is a **profile to iterate on a Nix host** — systemd-repart /
  verity / UKI options drift across nixpkgs; validate with `nix build
  .#attested-image` and adjust partition sizing/format there.
- The node-side roothash read + report + verify is implemented and unit-tested.
- No attestation claim is adopted until the whole chain is audited (Coherence-
  style discipline).
