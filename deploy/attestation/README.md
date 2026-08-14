# Attestation deployment (L3) — bind the reproducible image to the TEE

> **Historical — Genesis-3.** The image at the top of this binding chain is the
> root `Dockerfile` image, i.e. `bloch`, the proof-of-work node for the chain
> that stopped permanently at height 39,918 on 2026-08-13, and the node-side
> verifier referenced below now lives at
> `legacy/genesis3-node/src/attestation/`. The live chain is **Genesis-4, proof
> of stake**; `bloch-pos` is not built into an attested image and no validator
> in the live fleet is TEE-attested. Nothing here is a claim about the live
> chain. Kept as part of the Genesis-3 record.

This directory holds the image-side + policy-side of the attestation binding.
Full design: `docs/specs/BLOCH-SIS-ATTESTATION.md`. Node-side verifier:
`src/attestation/`.

## The binding chain

```
L1 reproducible image (digest D)
  → sign-image.sh (cosign)                        → signature + pinned digest D
  → image-security-policy.json (CoCo image-rs)    → admit ONLY signed D, reject rest
  → policy delivered via Trustee/KBS              → initdata(policy) hash → HOSTDATA
  → SEV-SNP attestation report (TEE-signed)       → carries HOSTDATA + boot measurement
  → src/attestation::verify                       → hostdata==policy, digest==D, nonce fresh
```

## Steps

1. Build the reproducible image and note its digest (`deploy/repro/build.sh`).
2. Push it, then **sign** it:
   ```bash
   deploy/attestation/sign-image.sh docker.io/blochv/bloch:0.1
   ```
   Keep `cosign.key` secret; you'll publish `cosign.pub` to KBS.
3. Deliver to **Trustee/KBS**: `cosign.pub` (at the `kbs://` keyPath in
   `image-security-policy.json`) and the policy itself. Configure the KBS
   reference values (RVPS) with the expected boot measurement.
4. Deploy the pod with a CoCo confidential runtime class
   (`kata-qemu-snp` / TDX). image-rs enforces the policy inside the guest;
   only digest `D` is admitted, and the policy hash is bound into the report's
   HOSTDATA.
5. A client calls the node's `getattestation` RPC with a fresh nonce and runs
   `src/attestation::verify` against `Expected { tee, image_digest: D,
   measurement, hostdata }`.

## What is / isn't hardware-covered

- **Hardware-measured:** the boot chain (OVMF + kernel/initrd/cmdline + vCPU).
- **NOT hardware-measured:** the container image — it is pinned by the CoCo
  software policy, whose hash is folded into the attested HOSTDATA. That
  indirection is the actual image binding; the verifier checks both.

Zero-cost note: the whole binding (cosign + policy + verifier) is testable
without any TEE; only the final live report needs a SEV-SNP host (or a mobile
device for the `mobile` backend).
