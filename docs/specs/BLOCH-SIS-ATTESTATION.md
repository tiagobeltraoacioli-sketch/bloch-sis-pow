# Bloch-SIS attestation layer (L3) — pluggable, multi-backend

> **Historical — Genesis-3 tree.** Every file and line reference below is to
> the **Genesis-3** node tree (`src/`), which validated the proof-of-work
> chain that stopped permanently at height 39,918 on 2026-08-13. The live
> chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs,
> finality by epoch), and its node is `crates/bloch-pos-node`, which none of
> this describes. Kept because Genesis-4's opening ledger is derived from
> Genesis-3 and an auditor needs the provenance readable. None of the
> operational layer described here is deployed on the Genesis-4 fleet.
>
> **The risk disclosure that goes with it.** Where this document warns about
> hashrate, 51% cost or proof-of-work depth, that warning was addressed to a
> reader of the Genesis-3 network and no longer applies. The live risk is
> **concentration**: all 64 Genesis-4 validators are operated by a single
> entity, 93.94% of the carried ledger sits at one address and is stakeable,
> and 56,046,829,380 of the 57,146,400,000 BLOCH issued at genesis is held by
> the founder and the Foundation. One operator can halt the chain.

> Generalizes "Bloch-SIS-Linux": a confidential VM is **one** backend. The
> attestation layer is **parametrized over the execution environment** so the
> same interface + verifier serve cloud TEEs, bare-metal TPM, and — at **zero
> cloud cost** — mobile device TEEs. Implemented in `src/attestation/`.

## 0. What attestation is (and is not)

It proves *what code runs in what environment* and **binds it to our L1
reproducible image digest**. It is **integrity**, not cryptographic secrecy
(Coherence discipline, `COHERENCE-v0.2.md §4`). No "private/secret" claim is made
for any backend here.

## 1. Backends (pluggable `AttestationProvider`)

| Backend | Environment | Cloud cost | Attests | Role |
|---|---|---|---|---|
| `none` | any | — | nothing (honest `attested:false`) | default |
| `sev-snp` | AMD SEV-SNP confidential VM | VM cost (TEE itself usually no premium) | boot chain + image policy (HOSTDATA) | full/miner node |
| `tdx` | Intel TDX confidential VM | VM cost | as SEV-SNP (MR_CONFIG_ID) | full node |
| `tpm` | bare-metal measured boot | host cost | boot integrity | self-hosted node |
| `mobile` | Android StrongBox / iOS Secure Enclave | **zero** (user's phone) | device + app + challenge | light client / wallet |

Same `getattestation` RPC and same `verify()` for all — only the provider and
the quote format differ.

## 2. Binding attestation → reproducible image digest

The crux (fact-checked). **Hardware measures only the boot chain, NOT the
container image.** The image is bound at the software-policy layer and that
policy is folded into the signed report:

```
L1 reproducible image  (digest D, e.g. 8de44fc7…)
  └─ cosign sign  ─────────────────────────────►  signature + pinned digest D
       └─ CoCo image-rs policy: admit ONLY D  ──►  policy P
            └─ initdata(P) hash → SEV-SNP HOSTDATA (TEE-signed report)
                 └─ boot chain (OVMF+kernel+initrd+vCPU) → measurement M (reproducible)

Verifier (src/attestation::verify + provider crypto):
  1. quote signature valid (virtee/sev, sev-snp feature)
  2. report.hostdata   == expected initdata(P) hash   ← binds the image
  3. report.measurement== precomputed M               ← binds the boot chain
  4. report.image_digest == D  (== L1 digest you reproduced)
  5. report.nonce == the challenge you issued          ← freshness
  ⇒ Trusted: this environment provably runs ONLY our audited, reproducible image.
```

`Expected { tee, image_digest, measurement, hostdata }` + a nonce drive
`verify()`; the platform-independent checks (2–5) are done in-tree and tested,
the quote-signature check (1) is provider/feature-specific.

## 3. Cloud availability (SEV-SNP / TDX, 2026) — project is global

| Cloud | SEV-SNP SKUs | Regions | Note |
|---|---|---|---|
| **Azure** ⭐ | DCasv5/6, ECasv5/6, NCCadsH100v5 (TDX: DCesv6/ECesv6) | ~57 regions | widest; best default |
| **GCP** | N2D only | asia-southeast1, europe-west3/4, us-central1 | no South America |
| **AWS** | M6a/C6a/R6a | shared: Ohio + Ireland; **Dedicated Hosts: all AMD regions** | only path into **Brazil (sa-east-1)** |

Region is not a blocker (global project). Azure = easiest/widest; AWS Dedicated
Host if a Brazil region is specifically wanted. Any of these is billed compute;
new-account credits can cover a demo.

## 4. Mobile-first, zero-cost bootstrap

Because the mobile TEE ships free on billions of devices, the attested layer can
**start on phones**: a light client whose PQ key is protected at rest by
StrongBox/Secure Enclave, with **Android Key Attestation / iOS App Attest**
proving device+app integrity and echoing a node-issued challenge. Cloud SEV-SNP
full nodes join later — not a prerequisite.

Honest limit: mobile TEEs are **classical (P-256)** — they do **not** hold the
post-quantum Falcon/ML-DSA key in hardware; they protect it and attest the
device/app. Light-client role only (never a miner).

## 5. Honest limits (all backends)

- Integrity, **not** confidentiality. TEEs have a side-channel history; a report
  proves *what ran*, not *that data stayed secret*.
- Cryptographic privacy is the **Coherence** layer, independent of any TEE.
- The current chain is a **zero-security testnet**.

## 6. Status

- ✅ `src/attestation/`: pluggable provider, honest no-TEE default, and the
  platform-independent **verifier** (`verify`, `Expected`, `Verdict`) with unit
  tests (accept match; reject unattested / wrong digest / stale nonce / TEE +
  hostdata mismatch). `getattestation` RPC (nonce-aware).
- ⏳ `sev-snp` / `mobile` provider crypto: stubbed behind features; completed on
  the target hardware (SEV-SNP guest / mobile app) — see the module TODOs.
- ⏳ CoCo image policy + cosign signing of the L1 digest: `deploy/attestation/`.
