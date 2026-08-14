# Postern OS — the attestation chain (immutable → measured → attested)

> **Scope: the Genesis-3 image, and nothing on the live fleet.** The image at
> the top of this chain is `attested-image`, built from `os/package.nix`, which
> builds `bloch` — the proof-of-work node whose chain stopped permanently at
> height 39,918 on 2026-08-13. The live chain is **Genesis-4, proof of stake**;
> `bloch-pos` is not packaged for Nix, no live validator runs an attested image,
> and no attestation described here is part of the running network.

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
        ▼  attestation::verify(report, Expected { .. }, nonce)
Verdict::Trusted  ⇔  right TEE + fresh nonce + audited image_digest
                     + expected boot measurement + expected os_roothash
```

## What each layer contributes

| Layer | Guarantee | Field checked in `verify` |
|---|---|---|
| **L1** reproducible build | the image is the audited one | `image_digest` |
| **Postern OS (verity)** | the running rootfs is that exact image, unaltered | `os_roothash` |
| **L2** hardening | least-privilege runtime (systemd service) | — (posture) |
| **L3** TEE | all of the above ran in a genuine SEV-SNP/TDX VM | `tee`, `measurement`, `hostdata` |

`os_roothash` is the new, TEE-independent rung: even a bare-metal / non-TEE node
can now prove it boots the exact immutable image (its verity roothash), and a
verifier requires it by setting `Expected.os_roothash`.

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
assert_eq!(verify(&report, &expected, Some(nonce)), Verdict::Trusted);
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
