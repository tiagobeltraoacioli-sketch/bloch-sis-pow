# Bloch-SIS Protocol

> Post-quantum. Pure proof-of-work. Hashcash security, lattice signatures.

**Bloch-SIS** is a post-quantum **pure-Proof-of-Work BlockDAG Layer 1**. Its
proof-of-work is a **cumulative-work hashcash on SHAKE-256 (Keccak)** with a
**Module-SIS** (Short Integer Solution) **structural gate** — a non-trivial
residual filter that binds each solution to a lattice form (the same algebraic
family as its ML-DSA-65 signatures) but is **not** the security source: PoW
security is cumulative hash work, post-quantum because Grover gives only a
quadratic speedup. The genuinely lattice-based cryptography is in the
signatures (hybrid Falcon-1024 ‖ ML-DSA-65). GhostDAG-Q consensus,
libp2p networking, RocksDB storage. No BFT finality, no validator set, no
treasury: finality is PoW depth, à la Bitcoin/Kaspa.

Built on a mature post-quantum BlockDAG L1 codebase; the consensus, wallet,
transport, and RPC subsystems carry over, with the proof-of-work, signatures,
tokenomics, and finality model replaced.

> ## ⚠️ Status: **mainnet beta** — unaudited, low-hashrate, 51%-attackable
> The chain is designated **mainnet beta** — a designation, **not** a security
> claim. **The live mainnet is Genesis-3** (chain id `0xB10C_0004`, SHA-256d
> PoW, merged-mineable with Bitcoin — see "Run" below); the k-regime caveats
> in the rest of this box concern the **Bloch-SIS lattice reference PoW**
> chain, not Genesis-3's SHA-256d. The network-maturity caveats apply to
> both. The **relaxed regime (k=4) currently applies** (the residual bound is
> checked on a handful of coefficients → **work is trivially forgeable**). The
> **k=8 security hardening** of the PoW's Module-SIS gate was **activated at
> block 213,000 as a soft fork but reverted**: it multiplied mining difficulty
> ~4096x and the current solo / low hashrate could not find blocks, so the
> chain stalled. k=8 will **re-activate together with a matched difficulty
> reduction** (so block time stays ~30s); **until then, no security is
> claimed**. The PoW's security model is **hashcash cumulative work, not
> lattice hardness** — estimator research showed a trapdoorless PoW cannot be
> both lattice-hard and mineable (the regimes are disjoint; see
> `docs/research/POW-CANONICAL-frontier.md`); the Module-SIS gate is a
> structural filter (k=4 today; k=8 on re-activation). The network is **nascent: very
> few nodes, low hashrate → 51%-attackable**. **Unaudited** — a third-party
> audit is contracted but **not done**; the no-shortcut analysis for the
> canonical gate parameters and the IACR ePrint pre-print are still
> outstanding. The coin is **not a security and not an asset** — no token
> sale, no listing, no price, **no value claim**; a **17% founder premine**
> (10-year cliff, 40-year vesting) is disclosed. **Do not attach value. Not
> for investment. Use at your own risk.**

---

**Full status:** see [`docs/PROJECT-STATUS.md`](./docs/PROJECT-STATUS.md) — the
single source of truth for what's built, verified, and open.

## Architecture

| Layer | Technology |
| --- | --- |
| Consensus (PoW) | PHANTOM / GhostDAG-Q |
| Proof-of-Work | **Bloch-SIS** — SHAKE-256 hashcash with a Module-SIS structural gate (`crates/bloch-sis-pow`) |
| Finality | PoW depth (no BFT / no validator committee) |
| Signatures | **Hybrid Falcon-1024 ‖ ML-DSA-65** (both must verify — two lattice families) |
| Transport | ML-KEM-768 (Kyber) hybrid + ChaCha20-Poly1305; hybrid PQ peer identity |
| Networking | libp2p gossipsub + IBD sync |
| Storage | RocksDB |
| Difficulty | ASERT-Lattice (per-block, 30 s target) |

Every consensus-critical primitive is post-quantum: the PoW (SHAKE-256
hashcash — Grover-bounded — with a Module-SIS structural gate), the signatures
(Falcon + ML-DSA), and the seed/aux hashing (SHAKE-256). There is no
classical primitive on the consensus path.

## Tokenomics

| Parameter | Value |
| --- | --- |
| Nominal supply | 21,000,000,000 BLOCH (3.57 B founder premine + 17.43 B mining nominal) — **not hard-capped**: the tail is perpetual (see below) |
| Emission | 100% to miner (no validator/oracle pools) |
| Block reward | **2,600 BLOCH/block** since the Emission V3 fork at height 40,000 (8,400 before it) |
| Halving | Every **1,555,200 blocks** (~1.5 years @ 30 s); counter restarted at the V3 fork |
| Tail | **60 BLOCH/block**, perpetual, from V3 epoch 6 (~9 years after the fork; Monero-style disinflation — the V2 floor of 100 governs pre-fork history) |
| Block time | 30 seconds |
| Founder premine | 3,570,000,000 BLOCH (17%) — 10-year cliff, then 40-year **monthly** vesting on-chain |

### Emission V3 (flag-day fork, ~August 12–13, 2026)

A height-gated flag-day hard fork — **Emission V3** — activates at local
height **40,000** (emission height 453,743 counting the 413,743 Genesis-1/2
carryover UTXOs); at chain height 30,293 (measured 2026-08-09) that lands
around **August 12–13, 2026**. It addresses an emission-curve bug: the V2
schedule (8,400 BLOCH/block, halving every 1,036,800 blocks) would have
emitted **26.92 B** BLOCH over 100 years, against a documented
mining-emission nominal of 17.43 B. Emission V3 slows the curve:

- **Block reward:** 8,400 → **2,600 BLOCH** (−69%). Miners receive 8,400
  through height 39,999; the first 2,600 block is height 40,000.
- **Halving interval:** 1,036,800 → **1,555,200 blocks** (~1.5 years @ 30 s).
  The halving counter restarts at the fork.
- **Schedule from the fork:** 2,600 → 1,300 → 650 → 325 → 162 → 81, then
  the perpetual **60 BLOCH/block tail** (from V3 epoch 6, ~9 years after
  the fork; epoch 5 pays the true halving value 81). The 60 floor is
  V3-only (PISO-60); the legacy V2 floor of 100 still governs every
  pre-fork coinbase.
- **Emission accounting** (measured 2026-08-09; the mined-since-G3 figure
  keeps growing at 8,400/coinbase until the fork):

  | Component (mining side) | BLOCH |
  | --- | --- |
  | Genesis-1 carryover (413,743 UTXOs × 8,400) | 3,475,441,200 |
  | Mined since Genesis-3 (36,801 coinbases × 8,400) | 309,128,400 |
  | Future V3 emission, 100 years from the fork | 13,620,441,600 |
  | **Mining total** (documented mining nominal: 17,430,000,000) | **17,405,011,200** |
  | + Founder premine | 3,570,000,000 |
  | **Total** (nominal total supply: 21,000,000,000) | **20,975,011,200** |

  **Emission V3 realigns the emission schedule with the documented nominals
  (17.43 B mining / 21 B total) to within ~0.5%.** These figures are floors,
  not exact totals and not caps: coinbases are paid per DAG block, the
  mined-side total keeps growing until the fork (≈ 17.50 B mining total at
  the fork), and the 60 BLOCH tail is perpetual. Supply is **not
  hard-capped**.

Consensus source of truth: `crates/bloch-crypto/src/core/tokenomics_v2.rs`.
Normative spec: [`docs/specs/TOKENOMICS_V3.md`](./docs/specs/TOKENOMICS_V3.md);
decision record: [`docs/adr/ADR-035-emission-v3-schedule.md`](./docs/adr/ADR-035-emission-v3-schedule.md).
Phase-by-phase design history is in
[`BLOCH_DEVELOPMENT_PLAN.md`](./BLOCH_DEVELOPMENT_PLAN.md); economic doctrine in
`docs/adr/`.

> **Height-reading trap:** `getblockcount` counts **DAG blocks**, not chain
> height (a BlockDAG accepts side blocks). The height that gates the V3 fork
> is the selected-chain height — `getdaginfo → tip_height` /
> `getblocktemplate → height`. The template also exposes `emission_height`
> (= local height + 413,743) so external pools never recompute the offset.

---

## Build

```bash
cargo build --release        # needs a C toolchain (clang/cmake) for rocksdb + blst
```

Binaries in `target/release/`: `bloch` (full node), `bloch-wallet`,
`bloch-cli`, `bloch-calibrate`, `bloch-mine-genesis`,
`bloch-migrate-addr-history`.

### Prebuilt binaries (Linux x86_64)

Building from source is recommended (you run the bytes you compiled). For a
quick start, prebuilt `bloch` + `bloch-cli` for **Linux x86_64** are published:

- GitHub releases: <https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases> — always take the **latest, non-superseded** release
- GitLab releases: <https://gitlab.com/blochsispow-group/BlochSISPoW-project/-/releases>

**Always run the latest release.** Consensus flag-days make older builds
actively diverge, not merely lag:

- the **difficulty-from-ancestry flag-day (local height 30,030) is already
  active** — expected difficulty is a pure function of the block's own
  ancestry. Any build older than `genesis3-node-difficulty-choke-20260809`
  (commit `1f7d328`) rejects the blocks the network produces today.
- the **Emission V3 flag-day (local height 40,000, ETA ~2026-08-12/13)** cuts
  the block reward 8,400 → 2,600 BLOCH. **Any binary built before commit
  `8538dea` forks off the network at that height.** The mandatory release is
  **[`genesis3-node-emission-v3-floor60-20260810`](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/tag/genesis3-node-emission-v3-floor60-20260810)**
  (`bloch` binary sha256
  `dfc6962df85bd87a780a4a15ccf330dc08ae860dd9cf4e3ad647b5e9c79601a8`) — the
  build the fleet runs, carrying Emission V3 with the 60-BLOCH V3 tail floor
  (PISO-60), the difficulty choke point, and the PEX `known_peers` fix. All
  earlier releases — including those shipping commit `c21e09d` (binary
  `6ffc5f12…`) — are superseded.

Requires **glibc ≥ 2.39** (Ubuntu 24.04+); on older distros build from source.
Unpack and verify `SHA256SUMS` before running.

> **Do not sync from scratch — it cannot complete.** Block bodies discarded
> before the 2026-08-05 retention fix no longer exist anywhere on the network
> (from-zero IBD stalls around block_count 26,474 and can never finish).
> Upgrading the binary does not fix this. The supported path for a new node is
> a **datadir snapshot** + the carry-over file — see
> [docs/SNAPSHOT-BOOTSTRAP.md](./docs/SNAPSHOT-BOOTSTRAP.md) and
> [docs/CARRYOVER.md](./docs/CARRYOVER.md). Since commit `c21e09d` a
> poisoned/stale `known_peers.json` also self-heals on boot — no manual
> deletion needed.

## Run

### Genesis-3 mainnet (the live network)

The live mainnet chain is **Genesis-3** (`--genesis3`, chain id
`0xB10C_0004`): a carry-over restart (2026-07-29) whose chain-selected PoW is
**SHA-256d** — ASIC-mineable and **merged-mineable with Bitcoin** via AuxPoW
since height 8,500 (see [docs/MERGED-MINING.md](./docs/MERGED-MINING.md)) —
with Stratum V1 served for ASICs. Joining it requires the carry-over file and,
in practice, a datadir snapshot:
[docs/CARRYOVER.md](./docs/CARRYOVER.md) +
[docs/SNAPSHOT-BOOTSTRAP.md](./docs/SNAPSHOT-BOOTSTRAP.md).

### Bloch-SIS chain (reference PoW, solo mining)

```bash
./target/release/bloch --mine --data-dir ./bloch-data
```

The node validates the mined genesis, then mines Bloch-SIS blocks solo. This
is the project's lattice-gated reference PoW chain described below — **not**
the SHA-256d Genesis-3 mainnet. (On this chain Stratum V1/V2 pool mining is
disabled: the hash-PoW share protocol has no field for the lattice solution
vector — a SIS-native pool protocol is future work.)

Default ports: `16110/tcp` (P2P), `16111/tcp` (WebSocket), `16210/tcp` (RPC).

## Test

```bash
cargo test                    # full suite
cargo test -p bloch-sis-pow   # the Bloch-SIS PoW reference crate
```

---

## The proof-of-work: SHAKE-256 hashcash with a Module-SIS gate

Given a serialized header and nonce, a miner must find a short solution vector
`s ∈ {-B,…,B}^N` such that `‖A·s − t‖_∞ < β` (a Module-SIS instance derived from
the header via SHAKE-256) **and** an auxiliary SHAKE-256 hash of `s` meets the
difficulty target. Verification is cheap. The Module-SIS residual is a fixed
structural rejection filter — it binds the work to a lattice form but is not the
difficulty knob and not the security source; block-production security is the
cumulative hashcash work on the aux SHAKE-256 target
(`docs/research/POW-CANONICAL-frontier.md`). See `crates/bloch-sis-pow/README.md`.

## License

MIT OR Apache-2.0.

## License & Copyright

Copyright (C) 2026 Tiago Beltrão de Azevedo Tenório Acioli.

The Bloch-SIS-PoW **protocol** (its consensus rules and specification) is an open,
ownerless commons — anyone may implement it. **This implementation** (all source
in this repository) is the author's copyrighted work, licensed to the public under
the **GNU Affero General Public License v3.0 or later** (`AGPL-3.0-or-later`); see
[LICENSE](LICENSE) and [AUTHORS](AUTHORS). Any distributed fork — or any use of the
software to provide a service over a network — must release its complete
corresponding source under the same license. A commercial license without the AGPL
obligations is available from the author.

"Bloch-SIS-PoW" and "Postern Labs" are trademarks of the author.
