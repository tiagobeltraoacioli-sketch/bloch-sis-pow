# Bloch-SIS — project status (consolidation checkpoint)

Single source of truth for what exists, what's verified, and what's open.
Bloch-SIS is a **post-quantum, pure-Proof-of-Work BlockDAG L1** whose PoW is a
**SHAKE-256 hashcash with a Module-SIS structural gate** — the gate binds the
work to a lattice form; the security source is cumulative hash work, not
lattice hardness (`docs/research/POW-CANONICAL-frontier.md`) — forked from and
fully de-branded off ENTL.

**Two layers** (see `PRINCIPLES.md` + `docs/POSTERN-LABS.md`): the protocol
**Bloch-SIS-PoW** is an **ownerless commons** (no owner/curator/official site,
RPC/API only, every node a seed); the **products** — the OSes, wallet, explorer,
attestation — are **Postern Labs** (owned, rebranded off "Bloch"). Anyone may
build products on the open protocol; Postern is one builder among many.

> ## Live network — Genesis-3 mainnet (status as of 2026-08-09)
> Much of this document predates the **Genesis-3 relaunch (2026-07-29)**. The
> live mainnet is **Genesis-3** (chain id `0xB10C_0004`): a carry-over restart
> (opening balance = 413,743 UTXOs / 3,475,441,200 BLOCH — `docs/CARRYOVER.md`)
> whose chain-selected PoW is **SHA-256d** — ASIC-mined and **merged-mineable
> with Bitcoin** (AuxPoW, active since local h=8,500 —
> `docs/MERGED-MINING.md`). Current consensus state:
> - **Difficulty-from-ancestry flag-day, local h=30,030 — ACTIVE.** Expected
>   difficulty is a pure function of the block's own ancestry (commit
>   `1f7d328`); older builds reject today's blocks.
> - **Emission V3 flag-day, local h=40,000 (ETA ~2026-08-12/13)** — block
>   reward 8,400 → 2,600 BLOCH, halvings every 1,555,200 blocks
>   (`docs/specs/TOKENOMICS_V3.md`, ADR-035). Armed in the fleet binary
>   (`c21e09d`), inert until the height.
> - **From-scratch sync is not supported** (pre-2026-08-05 block bodies no
>   longer exist on the network); new nodes bootstrap from a datadir snapshot
>   (`docs/SNAPSHOT-BOOTSTRAP.md`). A poisoned `known_peers.json` self-heals
>   on boot since `c21e09d` (PEX address fix).
> The k-regime story in the caveat below concerns the **Bloch-SIS lattice
> reference PoW chain**, not Genesis-3's SHA-256d; the maturity caveats
> (nascent, low-hashrate, 51%-attackable, unaudited) apply to both.

> ## 🔴 Hard caveat — read first
> The chain is designated **mainnet beta** — a designation, **not** a security
> claim. The **relaxed regime (k=4) currently applies** (residual checked on a
> few coefficients → **work is trivially forgeable**). The **k=8 hardening** of
> the PoW's Module-SIS gate was **activated at block 213,000 as a soft fork but
> reverted**: it multiplied mining difficulty ~4096x and the current solo / low
> hashrate could not find blocks, so the chain stalled. k=8 will **re-activate
> together with a matched difficulty reduction** (so block time stays ~30s);
> **until then, no security is claimed**. The PoW's security model is **hashcash
> cumulative work, not lattice hardness** (a trapdoorless PoW cannot be
> lattice-hard and mineable — `docs/research/POW-CANONICAL-frontier.md`); the
> SIS gate is a structural filter (k=4 today; k=8 on re-activation). The network is
> **nascent: very few nodes, low hashrate → 51%-attackable**. **Unaudited** —
> the third-party audit is contracted but **not done**; the no-shortcut proof
> and the IACR ePrint are still outstanding. The coin is **not a security and
> not an asset** — no sale, no listing, no price, **no value claim**; the
> **17% founder premine** is disclosed. Do **not** attach value; use at your
> own risk. No privacy or attestation claim is adopted until its own audit
> gate.

## ✅ Built + verified

### Consensus / protocol
- **Bloch-SIS PoW** (`crates/bloch-sis-pow` + `src/pow`): SHAKE-256 hashcash
  with a Module-SIS short-vector gate, ASERT-Lattice difficulty, mined genesis.
  Pure PoW (BFT/FFG/oracles removed).
- **k-row residual optimization** — verify/mine only the checked coefficients
  (~M/k faster in the relaxed pre-activation regime), consensus-neutral (equivalence-tested).
- **Hybrid signatures** — Falcon-1024 ‖ ML-DSA-65 (both must verify), tx + peer
  identity, seed-deterministic. SHAKE-256 hashing throughout.
- **Tokenomics** — 21 B nominal supply (**not hard-capped**: perpetual
  100 BLOCH/block tail, Monero-style; nominal = 3.57 B founder premine +
  17.43 B mining nominal), 100 % miner emission, 17 % founder premine
  (10-yr cliff + 40-yr monthly vesting), 30 s blocks. **Emission V3**
  flag-day fork at local height 40,000 (ETA ~Aug 12–13, 2026; chain height
  30,293 measured 2026-08-09): block reward 8,400 → 2,600 BLOCH (−69 %),
  halving interval 1,036,800 → 1,555,200 blocks (~1.5 yr @ 30 s); V3
  schedule 2,600 / 1,300 / 650 / 325 / 162 then the perpetual 100 tail.
  The old V2 curve would have emitted 26.92 B over 100 years against the
  documented 17.43 B mining nominal (the bug); the V3 curve emits ≈ 17.42 B
  from the fork over that window (a floor — coinbases are paid per DAG
  block — not a cap, and mining emission, not total supply); reconciliation
  of pre-fork emission against the nominal figures is under review. Source
  of truth: `crates/bloch-crypto/src/core/tokenomics_v2.rs`.
- Node boots, validates genesis, and mines end-to-end (`--mine`).

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

### Networking — every node is a seed (PRINCIPLES #2)
- **Self-bootstrapping, no central dependence**: `DEFAULT_SEEDS` empty; combined
  libp2p `BlochBehaviour { gossipsub, mdns, identify }` over a PQ `KyberConfig`
  transport. **mDNS** auto-discovers + dials LAN peers zero-config; **identify**
  learns the node's own reachable address (`add_external_address`) + records
  verified peers; **PEX self-advertise** gossips the node's own address (not just
  `known_peers`); `known_peers.json` persists across restarts. No privileged seed
  to capture/censor/switch off. Verified: 9 network tests pass.

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
  (ownerless protocol, two layers). A demo node runs on Fly (disposable,
  not official infra).
- Ideology: `PRINCIPLES.md` (ownerless, every-node-a-seed, no-promises, not a
  security) + `docs/POSTERN-LABS.md` (products ⟂ protocol).

## ⏳ Open

| Track | Next |
|---|---|
| **Mainnet gate** | canonical small-`k` + leading-zeros gate params, no-shortcut/asymmetry proof, ePrint, third-party audit. Hardness research done (screen `deploy/pow-estimator/SCREEN-RESULTS.md` + frontier sweep `docs/research/POW-CANONICAL-frontier.md`): lattice-hard mining is structurally impossible for a trapdoorless PoW (secure and mineable regimes disjoint) — PoW security is hashcash cumulative work; the SIS gate is a non-trivial structural filter. `k` **frozen at 8** — the soft fork **activated at block 213,000 but was reverted**: it multiplied mining difficulty ~4096x and the current solo / low hashrate could not find blocks, so the chain stalled; the **relaxed regime (k=4) currently applies** (work trivially forgeable) and k=8 will **re-activate together with a matched difficulty reduction** (so block time stays ~30s); the “mainnet beta” designation is **not** a security claim and does not close this track. Remaining: k=8 re-activation with the difficulty fix, the no-shortcut proof, BDD cross-check, difficulty calibration, the ePrint, and the third-party audit (contracted, **not done**) |
| **Coherence** | C2 remainder (SP1 prove/verify on the toolchain; submit/gossip entry point + reorg-tracking — land with the SP1 verifier), C3/C4 review + audit |
| **Attestation** | wire `virtee/sev` on a real SEV-SNP host; mobile Key-Attestation/App-Attest verifier; live end-to-end demo |
| **Mobile app** | ✅ lean cross-compile + ✅ UniFFI export + ✅ Android/iOS shell skeletons → next: build the shells on real SDKs (cargo-ndk / xcframework), the Postern Container impl, `bloch-core` split only if drift-risk demands |
| **Ops** | rotate the leaked GitLab PAT. (Self-bootstrapping landed: mDNS + identify + PEX self-advertise — no privileged seed needed; `DEFAULT_SEEDS` stays empty. Optional DNS-seed fallback for WAN cold-start remains.) |
| **ENTL legacy** | founder tax (pessoa física BR), ADR re-issue — not Bloch code |

## Repo map
- **Protocol (Bloch-SIS-PoW, ownerless):** `src/` node (`network` = every-node-a-
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
