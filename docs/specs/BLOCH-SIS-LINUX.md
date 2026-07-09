# Bloch-SIS-Linux — architecture spec (draft)

> **Note:** the SEV-SNP confidential VM described here is now **one backend** of
> the generalized, pluggable attestation layer — see
> `BLOCH-SIS-ATTESTATION.md` (adds `tdx`, `tpm`, and a **zero-cost `mobile`**
> backend). The reproducible-build (L1) and hardening (L2) work below is shared
> by all backends.

> Status: **design draft**. Bloch-SIS-Linux is an *operational* layer:
> a reproducible, hardened, optionally TEE-attested OS image for running
> Bloch-SIS nodes. Its confidentiality is **hardware-attested, not
> cryptographic** — see the honesty rules in `COHERENCE-v0.2.md §4`.

## 0. Purpose

Two problems the container images (`Dockerfile`, Akash/Fly SDLs) do not solve:

1. **Reproducibility of the running binary.** A node operator — or an auditor —
   should be able to prove that the machine is running *exactly* the audited
   Bloch source, bit-for-bit, with no injected patches.
2. **Attested execution** for infrastructure roles (public RPC endpoints, block
   explorers/indexers, future relays) so that consumers can verify the service
   runs approved, unmodified code.

Bloch-SIS-Linux is the image that provides both: a minimal immutable OS with the
`bloch` node baked in, built **reproducibly**, and (optionally) launched inside a
**TEE with measured boot** so the running measurement can be checked against the
public source.

## 1. Honest scope

- ✅ **Integrity / attestation:** prove *what code is running* (measured boot +
  remote attestation), and that it was **built reproducibly from public source**.
- ✅ **Hardening:** shrink the attack surface (immutable rootfs, no shell/pkg
  manager in the runtime, seccomp, no core dumps).
- ❌ **NOT cryptographic secrecy.** TEEs (SGX/SEV-SNP/TDX) have a long
  side-channel history; attestation proves *what ran*, not *that inputs stayed
  secret*. Bloch-SIS-Linux must **never** be described as making the chain or a
  wallet "private." Cryptographic privacy is the Coherence layer's job and does
  not depend on any TEE.

## 2. Architecture

```
┌───────────────────────────────────────────────┐
│  TEE (optional): SEV-SNP / TDX / SGX           │
│   measured boot → attestation quote            │
│  ┌─────────────────────────────────────────┐  │
│  │  Bloch-SIS-Linux image (immutable)       │  │
│  │   • minimal kernel + initramfs           │  │
│  │   • /usr/bin/bloch  (reproducible build) │  │
│  │   • read-only rootfs, dm-verity          │  │
│  │   • seccomp + minimal caps, no shell     │  │
│  │   • data on a separate encrypted volume  │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

### 2.1 Reproducible build

- **Toolchain:** pin Rust + all deps via `Cargo.lock` (now committed) and the
  **vendored `crates/pqcrypto-internals`** — the workspace is fully
  self-contained (no private/network deps), a prerequisite for bit-reproducible
  builds.
- **Image builder:** candidate is **Nix** (or `apko`/`stagex` for a distroless,
  timestamp-clamped image). Output must be **content-addressed** so the same
  source → the same image digest on any builder.
- **Provenance:** publish the source commit, the builder inputs, and the image
  digest; anyone can rebuild and compare (à la reproducible-builds.org).

### 2.2 Runtime hardening

- **Immutable rootfs** with `dm-verity` (kernel enforces the rootfs hash → the
  measured value). No package manager, no shell in the image.
- **`ulimit -c 0`** by default — closes the core-dump key-leak noted in
  `docs/THREAT_MODEL.md` (secret material can survive in a core dump mid-exec).
- **seccomp-bpf** allowlist + minimal Linux capabilities; node runs as a
  non-root user; data-dir on a separate volume (optionally LUKS/`fscrypt`).
- Only the node's ports exposed (16110 P2P, 16210 RPC); everything else closed.

### 2.3 Attestation flow

1. Firmware/TEE measures the image (rootfs verity root + kernel cmdline) into a
   quote.
2. Node publishes the **attestation quote** (e.g., via an RPC endpoint
   `getattestation`).
3. A verifier checks the quote's signature chain **and** that the measured
   rootfs hash equals the digest of the **reproducibly-built** public image.
   Only then does "this endpoint runs unmodified audited Bloch" hold.

### 2.4 Attestation stack (selected — all Apache-2.0)

Chosen after a fact-checked survey (permissive-only, no AGPL/LGPL; primary
sources), to run our **unmodified** hardened container in a SEV-SNP CVM:

- **Confidential Containers (CoCo)** — runs the unmodified OCI image inside a
  per-pod confidential VM (only a `runtimeClassName` change; no WASM/LibOS
  rewrite). Apache-2.0.
- **Kata Containers** — the micro-VM substrate CoCo builds on. Apache-2.0.
- **Trustee / attestation-service (KBS)** — verifies SEV-SNP **and** TDX hardware
  evidence, returns an attestation-results token. Apache-2.0.
- **`virtee/sev`** (Rust) — build/verify SEV-SNP attestation reports natively;
  the backend for the `sev-snp` feature of `src/attestation/`. Apache-2.0.

Rejected: **Gramine** (LGPL-3.0, SGX-only), **Constellation** (BSL-1.1→AGPL, and
archived read-only Jan 2026), **Enarx/Occlum/enclave-cc** (WASM/LibOS, SGX-centric).

Two items are still under research (do not assume): (i) which clouds offer
SEV-SNP/TDX and whether any South-America/Brazil region does; (ii) the exact
mechanism binding the CoCo/SEV-SNP measurement to a specific reproducible OCI
image digest (CoCo `image-rs` + Trustee KBS reference-values/policy).

## 3. Relationship to the container images

`Dockerfile` / Akash / Fly run the node as an ordinary container — fine for a
plain miner or a testnet node. Bloch-SIS-Linux is the **stronger variant** for
operators who need reproducibility + attestation (public infra, exchanges,
explorers). They share the same `bloch` binary and `Cargo.lock`; the Linux image
adds the immutable/attested wrapper. A future `deploy/` target can ship the
Bloch-SIS-Linux image to a confidential-compute host (e.g., SEV-SNP on a
provider that exposes attestation).

## 4. Threat model (summary)

| Goal | Covered? | By |
|---|---|---|
| Verify the node runs audited code | ✅ | dm-verity + attestation + reproducible build |
| Prevent silent binary tampering by a host | ✅ | measured boot; mismatched measurement fails attestation |
| Key material secrecy vs a malicious host | ⚠️ partial | encrypted volume + no core dumps; **TEE side-channels remain** |
| Cryptographic transaction privacy | ❌ | not here — that is Coherence |
| Network/metadata privacy | ❌ | out of scope (transport mixnet, separate) |

## 5. Roadmap

| Phase | Deliverable |
|---|---|
| L0 (this doc) | Architecture + honest scope + threat model |
| L1 | Reproducible image build (Nix/apko) producing a content-addressed `bloch` OS image; publish digest + rebuild instructions |
| L2 | Hardening pass: dm-verity, seccomp profile, no-core-dumps, non-root, encrypted data volume |
| L3 | `getattestation` RPC (**scaffold done** — `src/attestation/`, pluggable provider, reports `attested:false` with no TEE) + a verifier tying the quote to the reproducible image digest |
| L4 | Deploy target for a confidential-compute host; external review |

## 6. Non-negotiables

1. The image must be **reproducible from public source** — an unverifiable image
   defeats the entire purpose.
2. **No secrecy/privacy claim** for Bloch-SIS-Linux. It attests integrity, not
   confidentiality. Privacy claims belong to Coherence and are gated by
   `COHERENCE-v0.2.md §7`.
