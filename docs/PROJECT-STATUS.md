# Bloch-SIS — project status (consolidation checkpoint)

> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by
> epoch). Kept because Genesis-4's opening ledger is derived from it. It is
> not what runs.
>
> Genesis-4 has been live since **2026-08-13 21:31:19 UTC**. Everything below
> that reads "the live mainnet is Genesis-3", "pure Proof-of-Work", or
> forecasts the Emission V3 flag day at height 40,000 is describing a chain
> that has stopped — the flag day was 82 blocks away when production ended,
> and never happened.
>
> **For the current status read [`../README.md`](../README.md)** and the index
> at [`./README.md`](./README.md). Also superseded since this was written: the
> **ownerless thesis was retracted** (ADR-036 — issuer + two-entity
> foundation, `docs/specs/BLOCH-ENTITY-STRUCTURE.md`), the PoS crates are
> **AGPL-3.0-or-later**, the EVM moves to **L1** (no L2), and the tokenomics
> are **V4 — a hard cap of 100,000,000,000 BLOCH**
> (`crates/bloch-pos-committee/src/tokenomics_v4.rs`), not the 21 B uncapped
> V2 curve described below. Read every "ownerless / commons / 17 % premine /
> not hard-capped / 21 B nominal" claim below as historical **and false of the
> live chain**.

A record of what existed, what was verified, and what was open on the
**Genesis-3 proof-of-work chain**, measured 2026-08-09. It is not the current
status and it is not a source of truth for the live network.
Bloch-SIS *was* a **post-quantum, pure-Proof-of-Work BlockDAG L1** whose PoW is a
**SHAKE-256 hashcash with a Module-SIS structural gate** — the gate binds the
work to a lattice form; the security source is cumulative hash work, not
lattice hardness (`legacy/research/POW-CANONICAL-frontier.md`) — forked from and
fully de-branded off ENTL.

**Two layers, as they were framed in the Genesis-3 era** (see `PRINCIPLES.md` +
`docs/POSTERN-LABS.md`): the protocol **Bloch-SIS-PoW** was described as an
**ownerless commons** (no owner/curator/official site, RPC/API only, every node
a seed); the **products** — the OSes, wallet, explorer, attestation — are
**Postern Labs** (owned, rebranded off "Bloch"). **The ownerless half of that
framing has been retracted** (ADR-036): Genesis-4 has an issuer and a two-entity
foundation structure (`docs/specs/BLOCH-ENTITY-STRUCTURE.md`), and all 64
Genesis-4 validators are operated by one entity. The products half still holds.

> ## Genesis-3 mainnet — CLOSED (this section was written 2026-08-09, while it ran)
> Genesis-3 stopped at height **39,918** on 2026-08-13. Read this section in
> the past tense; the live network is Genesis-4, proof of stake. Much of the
> rest of this document predates even the **Genesis-3 relaunch (2026-07-29)**.
> Genesis-3 was (chain id `0xB10C_0004`) a carry-over restart. Its **own**
> opening balance was 413,743 UTXOs / 3,475,441,200 BLOCH carried from
> Genesis-1 (`docs/CARRYOVER.md`) — **not** to be confused with the
> **Genesis-4** carryover, which is **18,146,400,000 BLOCH over 452,726
> outputs**, measured at Genesis-3 height **39,918**
> (`CARRYOVER_TOTAL_BLOCH` / `CARRYOVER_MEASURED_UTXOS` /
> `CARRYOVER_MEASURED_HEIGHT`, `crates/bloch-pos-committee/src/tokenomics_v4.rs`).
> Genesis-3's chain-selected PoW was **SHA-256d** — ASIC-mined and
> **merged-mineable with Bitcoin** (AuxPoW, active from local h=8,500 until
> the chain stopped — `legacy/MERGED-MINING.md`). Consensus state as it stood
> when production ended:
> - **Difficulty-from-ancestry flag-day, local h=30,030 — was active.**
>   Expected difficulty was a pure function of the block's own ancestry
>   (commit `1f7d328`); older builds rejected the chain's blocks. Retired with
>   the chain.
> - **Emission V3 flag-day, local h=40,000 — NEVER HAPPENED.** It would have
>   cut the block reward 8,400 → 2,600 BLOCH with halvings every 1,555,200
>   blocks (`legacy/specs/TOKENOMICS_V3.md`, ADR-035), and it was armed and
>   inert in the fleet binary (release
>   `genesis3-node-emission-v3-floor60-20260810`, sha256 `dfc6962d…`, incl.
>   the PISO-60 60-BLOCH V3 tail floor) — but the chain stopped at **39,918**,
>   82 blocks short. **No V3 emission was ever paid.** Genesis-4 replaces the
>   whole schedule with tokenomics V4 (hard cap 100 B).
> - **From-scratch sync was not supported** (pre-2026-08-05 block bodies no
>   longer existed on the network); new nodes bootstrapped from a datadir
>   snapshot (`docs/SNAPSHOT-BOOTSTRAP.md`). A poisoned `known_peers.json`
>   self-healed on boot since `c21e09d` (PEX address fix). Moot: Genesis-3 no
>   longer produces blocks.
> The k-regime story in the caveat below concerned the **Bloch-SIS lattice
> reference PoW chain**, not Genesis-3's SHA-256d. Both are retired. The
> maturity caveats that survive into Genesis-4 — **unaudited, one
> implementation, single operator** — are restated in Genesis-4 terms in the
> hard caveat immediately below.

> ## 🔴 Hard caveat — read first
> **This caveat is about the live chain, Genesis-4.** The security question
> under Genesis-4 is not hashrate, it is **concentration**: all 64 validators
> are run by one entity, 93.94 % of the carryover sits at a single address, and
> 56.05 B of the 57.15 B BLOCH issued at genesis is held by the founder and the
> Foundation. **One operator can halt the chain and one holder can outvote every
> other.** The largest carryover address holds 17,046,829,380 of 18,146,400,000
> BLOCH = 93.94 % (`LARGEST_CARRYOVER_ADDRESS_BLOCH`, `tokenomics_v4.rs:414`),
> and carried balances are **stakeable** — if that balance stakes, the Nakamoto
> coefficient is **1**. The founder's own total is 27,046,829,380 = **27.04 %**
> of the cap (`FOUNDER_TOTAL_BLOCH`, pinned at 2704 bps); the Foundation holds a
> further **29.00 %**. Together 56,046,829,380 of 57,146,400,000, leaving
> 1,099,570,620 BLOCH (**1.92 %**) in third-party hands.
> **The live transport is a point-to-point TCP full mesh with a fixed peer list,
> no discovery and no authentication, which is why a third party cannot yet join
> the network**, and deposits and delegations are refused at every node's
> mempool (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is
> not yet funded from the UTXO set — **there is no permissionless path to
> validating today**. **Unaudited** — the third-party audit is contracted but
> **not done**; there is **one implementation**. The coin is **not a security
> and not an asset** — no sale, no listing, no price, **no value claim**. Do
> **not** put meaningful money in; use at your own risk. No privacy or
> attestation claim is adopted until its own audit gate.
>
> *Historical (Genesis-3, retired):* the chain was designated **mainnet beta** —
> a designation, **not** a security claim. The **relaxed regime (k=4)** applied
> (residual checked on a few coefficients → **work was trivially forgeable**).
> The **k=8 hardening** of the PoW's Module-SIS gate was **activated at block
> 213,000 as a soft fork but reverted**: it multiplied mining difficulty ~4096x
> and the solo / low hashrate could not find blocks, so the chain stalled. k=8
> was to re-activate with a matched difficulty reduction; it never did, and the
> proof-of-work chain is now stopped, so **no PoW security is claimed for
> anything**. The PoW's security model was **hashcash cumulative work, not
> lattice hardness** (a trapdoorless PoW cannot be lattice-hard and mineable —
> `legacy/research/POW-CANONICAL-frontier.md`). The **17 % founder premine**
> figure belongs to tokenomics V2 and does not describe Genesis-4; the live
> founder figure is the 27.04 % pinned above.

## ✅ Built + verified (as of 2026-08-09, on the Genesis-3 codebase)

*Everything in this section is a record of the proof-of-work tree. Items marked
"live", "active" or "deployed" were live on Genesis-3, which has stopped. For
what the Genesis-4 node has and does not have, see the note at the end of the
Networking subsection.*

### Consensus / protocol
- **Bloch-SIS PoW** (`crates/bloch-sis-pow` + `src/pow`): SHAKE-256 hashcash
  with a Module-SIS short-vector gate, ASERT-Lattice difficulty, mined genesis.
  Pure PoW, BFT/FFG/oracles removed — **retired**. Genesis-4 is proof of stake
  with Casper-style justification and finalisation by epoch; there is no
  proof-of-work in the live consensus at all.
- **k-row residual optimization** — verify/mine only the checked coefficients
  (~M/k faster in the relaxed pre-activation regime), consensus-neutral (equivalence-tested).
- **Hybrid signatures** — Falcon-1024 ‖ ML-DSA-65 (both must verify), tx + peer
  identity, seed-deterministic. SHAKE-256 hashing throughout.
- **Tokenomics — LIVE (V4).** The supply is **hard-capped at 100,000,000,000
  BLOCH** (`TOTAL_SUPPLY_BLOCH`). At slot 0 Genesis-4 issued
  **57,146,400,000 BLOCH**, of which the carryover is **18,146,400,000 BLOCH
  over 452,726 outputs**, measured at Genesis-3 height **39,918**. The
  remaining **42,853,600,000 BLOCH** is validator emission over 40 years and
  is **unissued**. Slots are 30 s; 32 slots to an epoch. Source of truth:
  **`crates/bloch-pos-committee/src/tokenomics_v4.rs`**. Concentration, stated
  because it is the security question: founder 27,046,829,380 (27.04 % of
  cap), Foundation a further 29.00 %, together 56,046,829,380 of the
  57,146,400,000 issued — 1,099,570,620 BLOCH (1.92 %) is in third-party
  hands; 93.94 % of the carryover sits at a single address.
- *Historical (Genesis-3, tokenomics V2/V3 — superseded and false of the live
  chain):* 21 B nominal supply, **not** hard-capped (perpetual 60 BLOCH/block
  V3 tail, Monero-style; nominal = 3.57 B founder premine + 17.43 B mining
  nominal), 100 % miner emission, 17 % founder premine (10-yr cliff + 40-yr
  monthly vesting), 30 s blocks, with an **Emission V3** flag-day fork planned
  at local height 40,000 that **never activated** — the chain stopped at
  39,918. `crates/bloch-crypto/src/core/tokenomics_v2.rs` is the record of
  that retired schedule and is **not** the source of truth for supply.
- The Genesis-3 node booted, validated genesis, and mined end-to-end
  (`--mine`). **Genesis-4 does not mine.** The PoS node boots, validates
  genesis, proposes and attests on 30 s slots, and persists to an append-only
  block log with deterministic replay; it also serves a JSON-RPC server
  (`crates/bloch-pos-node/src/rpc.rs`) and carries a real transfer transaction
  format with inputs and outputs. It does **not** have RocksDB, a
  slashing-evidence pipeline, or checkpoint-sync state download.

### Security
- **8 vulnerabilities fixed** (Fable-5 audit, adversarially verified): reorg
  re-validation (H1), gossip block-id binding (H2), ASERT bit-shift (H3), deser
  memory-amplification (M1), keyfile AEAD/AAD (M2), Argon2 clamp (L1), min relay
  fee (L2), off-loop PEX DNS (L3). Regression tests added.
- **Consensus audit pass** (with regression guards): found + fixed a real
  correctness bug — `Wallet::sign_tx` emitted a raw `sig‖pubkey` while consensus
  parses length-prefixed `parse_script_sig`, so sent txs were rejected (fixed to
  `build_script_sig`). Audited sound (with guards): `sighash` (SIGHASH_ALL;
  hardened an `unwrap_or_default` footgun), value conservation (checked_add, no
  inflation), `txid` non-malleability (excludes script_sig), PoW binding
  (per-nonce fresh SIS instance + aux hash binds s/nonce/header).
- **Dev-practice guardrails**: supply-chain scan (cargo-deny/`deny.toml`),
  secret scan (gitleaks), fuzzing (`fuzz/`), property tests (parser round-trip,
  ShieldedEngine invariants, ASERT difficulty), zeroized keys (node + mobile).

### Networking — Genesis-3 design, NOT the live stack
- *Genesis-3 (retired):* **self-bootstrapping, no central dependence**:
  `DEFAULT_SEEDS` empty; combined libp2p `BlochBehaviour { gossipsub, mdns,
  identify }` over a PQ `KyberConfig` transport. **mDNS** auto-discovered +
  dialled LAN peers zero-config; **identify** learned the node's own reachable
  address (`add_external_address`) + recorded verified peers; **PEX
  self-advertise** gossiped the node's own address (not just `known_peers`);
  `known_peers.json` persisted across restarts. Verified: 9 network tests
  passed.
- **What Genesis-4 actually runs is not that.** The live transport is
  `Transport::Devnet`: **a point-to-point TCP full mesh with a fixed peer list,
  no discovery and no authentication, which is why a third party cannot yet
  join the network** (`crates/bloch-pos-node/src/net.rs`, selected in
  `main.rs`). A libp2p module exists in the tree and can be selected with
  `--transport libp2p`, but **it is not what the fleet runs**. Do not read the
  paragraph above as a description of the live network layer; the
  "every node is a seed" property does not hold today.

### Identity / hygiene
- **Founder wallet** unified (genesis coinbase + vesting → one founder-owned
  keystore); genesis re-mined.
- **De-ENTL** — core code de-ENTL'd (ENTL/`ent1q`/network-magic/topic/metric
  references removed from `src/` and crates); legacy tooling (scripts, deploy
  manifests) being cleaned as touched;
  `pqcrypto-internals` fork **vendored** (`crates/`), so the workspace is
  **self-contained** (no private git dep). `Cargo.lock` committed.

### Bloch-SIS-Linux / attestation (pluggable, `docs/specs/BLOCH-SIS-ATTESTATION.md`)
- **L1 reproducible build** — pinned base digests + `--locked` + SOURCE_DATE_EPOCH;
  two independent builds → identical OCI digest (verified: `8de44fc7…`).
- **L2 hardening** — non-root, no-core-dumps, cap-drop, read-only rootfs
  (verified: mined h=1..11 as uid 10001 under a read-only rootfs).
- **L3 attestation** — pluggable `AttestationProvider` (`none|sev-snp|tdx|tpm|
  mobile`), the `verify()` core (bound to the L1 digest, nonce-fresh) with 6
  tests, `getattestation` RPC. Selected stack: CoCo + Trustee + `virtee/sev` (all
  Apache-2.0) + CoCo image-policy/cosign tooling.

### Postern Labs products
- **Postern Wallet** (`bloch-mobile` crate, `mobile/core`): mnemonic↔address, hybrid
  signing, RPC shaping — byte-compatible with the node (golden test). Mobile =
  **wallet only** (focus stays PoW). **Cross-compile unblocked**: `bloch` with
  `default-features=false` (the `node` Cargo feature gates rocksdb/libp2p) → the
  lean crypto/tx/wallet subset builds for Android/iOS; verified (`cargo tree`
  shows no rocksdb/libp2p, golden test passes). **UniFFI export** (`ffi.rs`):
  `Wallet` object + `generateWallet` + RPC helpers → Kotlin/Swift bindings
  (host-verified). **Android + iOS app-shell skeletons** (`mobile/android`,
  `mobile/ios`) wiring StrongBox/Key-Attestation + Secure-Enclave/App-Attest —
  skeletons (need the platform SDKs; the Rust core + UniFFI are the tested layer).
- **Bloch Explorer** (`explorer/`, deployed) — a Postern Labs product on the
  protocol's RPC (like mempool.space for BTC), incl. address-balance lookup. The
  ownerless protocol has no *official* explorer; this is one product.
- **Postern Desktop** (`desktop/`, Tauri v2 + web UI): full node companion —
  start/stop the node process, live RPC dashboard, wallet (generate/restore +
  balance + **send tx**, reuses the node wallet flow), miner view, streamed logs.
  Standalone app for anyone who just wants to hold keys / protect sensitive data
  without replacing their OS. **Builds — verified**: `cargo build` green with the
  Postern icon set (`desktop/src-tauri/icons/`, ◆ lattice teal).
- **Postern OS** (`flake.nix` + `os/`, NixOS): a reproducible, bootable OS image
  with the node as a hardened systemd service (L2-style), mining on boot. `nix
  build .#iso` → bootable ISO; `nixosModules.bloch` adds the node to any NixOS
  host. **Immutable/attestable profile** (`os/attested.nix`): dm-verity + UKI +
  measured boot; the verity roothash flows into `getattestation`
  (`os_roothash`) + `verify()` (implemented + tested). Builds on a Nix host.
- **Postern OS Mobile** (`os/mobile.nix`, Mobile NixOS): a reproducible **phone
  OS**, wallet-first (no mining — phones can't do SIS PoW). `nix build
  .#mobile-image`. Ships `bloch-wallet` + the PQ crypto; touch UI is the app
  layer. Builds on a Nix host with the device port.
- **Postern OS — Desktop** (`os/desktop.nix`, NixOS): the privacy **daily-driver**
  profile — hardened Wayland GNOME + full-disk encryption (LUKS) + Tor + DNS-over-
  TLS + AppArmor/sysctl hardening + the Postern Wallet; node opt-in (off by default
  on laptops). `nix build .#desktop-iso` → live ISO. Establishes the security/
  privacy spine of the personalized-Linux vision (iterate toward a full
  daily-driver). Builds on a Nix host. Includes the **Postern Browser**
  (`os/browser.nix`): hardened Firefox — resistFingerprinting, strict tracking
  protection, HTTPS-only, no telemetry, no IP leaks, uBlock Origin.
- **Postern Container** (Android) — the low-friction *entry* product: a hardened,
  attestable privacy workspace on existing Android (managed profile + StrongBox
  Key-Attestation + always-on Tor). **Design spec** only:
  `docs/specs/POSTERN-CONTAINER.md`.

### Privacy (Coherence)
- **C0 design** (`COHERENCE-v0.2.md`) + **C1 format freeze** (`COHERENCE-C1.md`):
  SHAKE-256 commitments/nullifiers/Merkle, spend statement, **SP1 (raw-FRI)**
  proof system, shielded-tx wire format. Lattice RingCT tracked as a post-audit
  alternative.
- **C2** (implementation): lean `crates/coherence-core` (Note, commitment,
  nullifier, Merkle accumulator, `check_spend` — the exact ZK statement) shared
  by node + SP1 guest + mobile; node `ShieldedState` + `ShieldedEngine` (atomic
  shielded-block consensus); `ShieldedTx` in the **Block wire format**
  (serialized, round-trip-tested, genesis-preserving); SP1 prover scaffold
  (`crates/coherence-prover`). **Consensus activation done**: shielded txs are
  merkle-bound into the PoW (genesis-preserving) and validated/applied in
  accept_block via the ShieldedEngine (rejected until the SP1 verifier is wired —
  safe default). **Shielded mempool** (`ShieldedMempool`/`ShieldedPool`): admission
  with anti-double-spend, block-inclusion selection + eviction, unified with the
  engine and driven by accept_block. All tested; node boots + mines with it.
  **Reorg-undo mechanism** (audited): `ShieldedEngine::disconnect_block(expected)`
  exactly reverses an applied block (tree truncate + un-spend nullifiers + restore
  the bounded anchor window), **identity-keyed** so it errors (`ReorgOrderMismatch`)
  rather than undo the wrong block, bounded (`MAX_REORG_UNDO`), 3 tests. A Fable-5
  audit confirmed the mechanism is a correct exact inverse **in isolation** but
  flagged that it is **not yet live**: the accept-path `apply_block_self` runs for
  every block (arrival order), so the Sprint-U.4 wiring must (a) mutate shielded
  state only on selected-chain connect/disconnect, (b) call
  `disconnect_block_self(hash)` per rolled-back block, (c) re-admit dropped shielded
  txs. **Latent today** (RejectAll → shielded txs never apply); no soundness claim
  until U.4 + the SP1 verifier land. Remaining: SP1 prove/verify, submit/gossip
  entry point, the U.4 live reorg wiring.

### Deploy + tooling
- `Dockerfile` (reproducible), Akash SDLs (`deploy/akash/`: seed 40/16-CPU +
  member), Fly config (`fly.toml`), reproducible-build + hardening + attestation
  tooling (`deploy/`), and **Blochscan** (`explorer/blochscan.html`) — a node/
  chain monitor.

### Published
- GitLab: https://gitlab.com/bloch-sis-group/bloch-sis-project (pseudonymous
  history). ENTL repo left untouched.
- Postern Labs product site (`bloch-sis-website`) + the explorer
  (`bloch-pow-explorer`, deployed on Fly) — Postern products, framed as such
  (at the time: "ownerless protocol, two layers" — the ownerless half is
  retracted, ADR-036). A demo node ran on Fly (disposable, not official infra).
- Ideology: `PRINCIPLES.md` (ownerless, every-node-a-seed, no-promises, not a
  security) + `docs/POSTERN-LABS.md` (products ⟂ protocol). **The "ownerless"
  and "every node a seed" claims are retracted** — ADR-036 replaced ownerless
  with an issuer and a two-entity foundation, and the live transport admits no
  outside node. "Not a security, no value claim" stands.

## ⏳ Open

| Track | Next |
|---|---|
| **Mainnet gate (was: PoW security claim)** | **Retired with proof-of-work.** The k=8 / no-shortcut / ePrint track lost its object when Genesis-3 stopped at 39,918 and Genesis-4 relaunched as proof of stake; the research record stands (screen `deploy/pow-estimator/SCREEN-RESULTS.md` + frontier sweep `legacy/research/POW-CANONICAL-frontier.md`: lattice-hard mining is structurally impossible for a trapdoorless PoW — PoW security was hashcash cumulative work and the SIS gate a structural filter). **What replaces it:** the open security question on Genesis-4 is not hashrate, it is **concentration** — all 64 validators are run by one entity, 93.94 % of the carryover sits at a single address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by the founder and the Foundation; **one operator can halt the chain and one holder can outvote every other**, and carried balances are stakeable, so a Nakamoto coefficient of 1 is reachable today. Also open and unchanged: the **third-party audit is contracted but not done**, there is **one implementation**, deposits and delegations are refused at the mempool so **no third party can become a validator**, and the transport is a fixed-peer TCP mesh with no discovery and no authentication so **no third party can even join the network**. |
| **Coherence** | C2 remainder (SP1 prove/verify on the toolchain; submit/gossip entry point + reorg-tracking — land with the SP1 verifier), C3/C4 review + audit |
| **Attestation** | wire `virtee/sev` on a real SEV-SNP host; mobile Key-Attestation/App-Attest verifier; live end-to-end demo |
| **Mobile app** | ✅ lean cross-compile + ✅ UniFFI export + ✅ Android/iOS shell skeletons → next: build the shells on real SDKs (cargo-ndk / xcframework), the Postern Container impl, `bloch-core` split only if drift-risk demands |
| **Ops** | rotate the leaked GitLab PAT. (Self-bootstrapping landed **on the Genesis-3 stack**: mDNS + identify + PEX self-advertise, `DEFAULT_SEEDS` empty. None of it is in the live path — Genesis-4 runs a fixed-peer TCP mesh with no discovery, so opening the network to third parties is an unclosed item, not a shipped one.) |
| **ENTL legacy** | founder tax (pessoa física BR), ADR re-issue — not Bloch code |

## Repo map (Genesis-3 tree; the PoS crates live under `crates/bloch-pos-*`)
- **Protocol (Bloch-SIS-PoW — retired; the "ownerless" label is retracted,
  ADR-036):** `src/` node (`network` = every-node-a-
  seed: mdns+identify+PEX) · `crates/bloch-sis-pow` PoW · `crates/pqcrypto-
  internals` vendored fork · `crates/coherence-core` shielded primitives ·
  `crates/coherence-prover` SP1 prover. The `node` Cargo feature gates the heavy
  deps so the crypto/wallet subset cross-compiles.
- **Postern Labs products:** `mobile/core` Postern Wallet engine (+ UniFFI `ffi.rs`)
  · `mobile/android` + `mobile/ios` app-shell skeletons · `desktop/` Postern
  Desktop (Tauri, icons) · `flake.nix`+`os/` Postern OS (`configuration/attested/
  mobile/desktop/browser.nix`) · `explorer/` Bloch Explorer.
- **Ideology + specs:** `PRINCIPLES.md` · `docs/POSTERN-LABS.md` · `docs/specs/`
  (POW-HARDNESS, POSTERN-CONTAINER, COHERENCE, attestation) · `deploy/` (repro,
  hardening, attestation, akash, sp1-prover, pow-estimator) · `BLOCH_DEVELOPMENT_PLAN.md`.
