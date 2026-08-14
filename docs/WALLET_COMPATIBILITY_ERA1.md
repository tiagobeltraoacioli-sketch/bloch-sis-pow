> **HISTORICAL DOCUMENT — ERA 1 (Pre-rebrand)**
>
> This document describes wallet compatibility for **GroundState v0.5.3**,
> the pre-rebrand chain that became Bloch-SIS Protocol (BLOCH) on 2026-04-26.
>
> Wallets, addresses (`grnd1q...`), and Docker images (`groundstate77/...`)
> referenced here belong to ERA 1 and **do not apply to any chain that runs
> today**. They are incompatible with every later chain's keys.
>
> **Where things actually stand, 2026-08-14.** The genesis hash
> `00000000a6afcfcd...eeb8b7` cited in earlier versions of this banner as "the
> current BLOCH mainnet chain" is a **Genesis-3** genesis — proof of work, and
> that chain stopped permanently at height 39,918 on 2026-08-13. The live chain
> is **Genesis-4, proof of stake**: 30 s slots, 32-slot epochs, Casper
> justification and finalisation **by epoch** (~32 min typical, ~48 min worst
> case), 64 genesis validators. Settlement is finality, not confirmation depth.
> Public read RPC: <https://posternlabs.com/g4rpc>, version `0.1.0-mainnet`.
>
> **The live signature suite is a hybrid — ML-DSA-65 ‖ Falcon-1024, both must
> verify** (`SUITE_MLDSA65_FALCON1024`). Anything below that describes a wallet
> as ML-DSA-65 alone is describing Era 1, not the current one.
>
> Preserved as historical reference only.

---

# ERA 1 — Pre-rebrand Wallet Compatibility Notice (GroundState v0.5.3)

> **Note (April 2026 rebrand).** This document is the wallet compatibility
> notice issued on **2026-04-18 20:00 UTC** for **GroundState v0.5.3** on
> the chain that operated under the GroundState project name. In April
> 2026 the codebase was rebranded to **Bloch-SIS Protocol (BLOCH)** and
> Phase 4 of the rebrand regenerated founder and treasury keystores
> against the then-new BLOCH chain (HRP `bloch1q`). Two chains have run
> since — Genesis-3, which halted at height 39,918 on 2026-08-13, and
> Genesis-4, the proof-of-stake chain live from that date.
>
> The wallet format described below — ML-DSA-65 keypair + AES-256-GCM
> + Argon2id encryption + JSON keystore + BIP39 seed phrase metadata —
> carried forward to BLOCH **in design**, with one change that matters and is
> not visible from the Era 1 text: **the live suite is the hybrid
> ML-DSA-65 ‖ Falcon-1024, not ML-DSA-65 alone.** A wallet holds and a
> signature carries both halves, and both must verify. Read every
> "ML-DSA-65 keypair" below as one half of what a current wallet holds.
> The keystore files themselves do **not** carry forward: all wallets
> started fresh on the BLOCH chain.
>
> The deterministic-derivation limitation discussed below still applies —
> it is a property of the lattice signature scheme, not of the chain, and
> adding Falcon-1024 alongside it does not lift it.
>
> The Docker image references (`groundstate77/groundstate:v0.5.3`),
> URLs (`scan.groundstate.network`, `docs.groundstate.network`), and
> commit hashes in the body below are historical artifacts of the
> Era 1 deployment, preserved as factual record. New BLOCH release
> notes will be filed under separate Sprint/release identifiers.
>
> Original document follows verbatim.

---

# GroundState v0.5.3 — Mainnet Stabilization & Wallet Compatibility Notice

**Date:** 2026-04-18 20:00 UTC
**Network status:** operational (seed Njalla, 30 RPC methods, 85+ MH/s)
**Release:** [v0.5.3-sprint-b](https://github.com/groundstate888/groundstate/commit/e39eca2)

---

## Summary

As of **2026-04-18 20:00 UTC**, new GroundState wallets may be created and will be recognized as the official supported format going forward. During the preceding testing phase, only two wallets existed on the network — the founder mining wallet and the treasury wallet — and both were **preserved intact through this transition**. This notice documents the ML-DSA-65 recovery limitation and the backup procedure all users should follow.

---

## What changed

Until today, GroundState was in early bootstrap. The seed node, RPC API, docs, and wallet library were iterated aggressively across Sprints A and B (v0.5.1 → v0.5.3). The Sprint C wallet library refactor is in progress and introduces a cleaner `Wallet` abstraction consumable by the upcoming Tauri desktop wallet.

**What is stable as of 2026-04-18:**

- 30 RPC methods, including 10 new chain analytics endpoints (Sprint B).
- Docker image `groundstate77/groundstate:v0.5.3` is the canonical node release.
- On-chain state (blocks 1 through current height, ~1500+ at time of writing) is **preserved**. There is no chain reset.
- Founder mining address and treasury address retain full balance.

**What is not yet stable:**

- The wallet library API (`src/wallet/`) is undergoing a refactor that will ship as Sprint C.1. Consumers should not pin to internal types yet.
- Seed phrase → key derivation for ML-DSA-65 is **not** deterministic in the current release. See next section.

---

## Known limitation: ML-DSA-65 and seed phrase recovery

GroundState uses **ML-DSA-65** (NIST FIPS 204, formerly Dilithium-3) for post-quantum digital signatures. ML-DSA-65 is a lattice-based signature scheme — there is currently **no standardized deterministic key derivation** from a BIP39-style seed phrase, as exists for ECDSA/EdDSA curves.

This means:

- A 24-word BIP39 seed phrase alone **cannot reconstruct** an ML-DSA-65 keypair on its own.
- Wallet creation generates a random keypair. The seed phrase is stored as metadata, but the actual private key material lives in the encrypted wallet file.
- **Backup requires BOTH**: the seed phrase AND the encrypted wallet file (`.json`).

This is explicitly documented in the code:

> *"Backup requires BOTH: the mnemonic phrase AND the wallet file. The mnemonic alone cannot reconstruct ML-DSA-65 keys (no lattice-based deterministic derivation standard exists yet)."*
> — [`src/hd_wallet/mod.rs`](https://github.com/groundstate888/groundstate/blob/main/src/hd_wallet/mod.rs)

When a post-quantum deterministic derivation standard is adopted (work is ongoing in the NIST post-quantum PQC ecosystem), GroundState will add support in a future release. Until then, **wallet files are the authoritative backup artifact**, and seed phrases serve as a secondary recovery mechanism only if combined with the file.

---

## Backup procedure — recommended for all users

If you create or hold a GroundState wallet (whether mined, received, or imported), the correct backup strategy is:

1. **Keep at least two copies** of the encrypted wallet file in different physical locations. Examples: one copy on your primary machine, one copy on an encrypted USB drive kept offline.
2. **Record the seed phrase** separately (written on paper, stored securely).
3. **Remember the password** used to encrypt the wallet file. AES-256-GCM with Argon2id is strong — there is no backdoor.

The combination of **wallet file + password** is what unlocks your funds. The seed phrase is supplementary context until deterministic derivation arrives.

---

## What is "a valid wallet" as of this date

Wallets created **on or after 2026-04-18 20:00 UTC** using GroundState v0.5.3 or later are the reference format going forward. During the preceding testing phase, only the founder mining wallet and the treasury wallet existed on the network, and both were preserved intact through this transition. This compatibility cut-off therefore does not disrupt any third-party holdings.

---

## Roadmap items affecting wallets

- **Sprint C.1** — finalize the new `Wallet` library API; add ChaCha20-DRBG seeding wrapper around `pqcrypto-mldsa::keypair()` to provide partial determinism (portable across minor library versions).
- **Sprint E** — typed error handling across the daemon; consolidates `WalletError` and other error types.
- **Future (pending NIST standardization)** — full deterministic key derivation from seed when a ratified post-quantum HD standard is available.

Track progress in [SPRINTS.md](https://github.com/groundstate888/groundstate/blob/main/SPRINTS.md).

---

## Questions or issues

- Open a GitHub issue at: https://github.com/groundstate888/groundstate/issues
- Security-sensitive reports: follow the procedure in [SECURITY.md](https://github.com/groundstate888/groundstate/blob/main/SECURITY.md)
- General network status: https://scan.groundstate.network · https://docs.groundstate.network

---

*This notice is committed to the repository alongside the v0.5.3 release and remains in effect until superseded by a subsequent release note.*
