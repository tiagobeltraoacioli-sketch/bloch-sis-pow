# Bloch-SIS Protocol

> Post-quantum. Pure proof-of-work. Lattice all the way down.

**Bloch-SIS** is a post-quantum **pure-Proof-of-Work BlockDAG Layer 1** whose
proof-of-work is a **Module-SIS** (Short Integer Solution) lattice problem —
the same algebraic family as its ML-DSA-65 signatures. GhostDAG-Q consensus,
libp2p networking, RocksDB storage. No BFT finality, no validator set, no
treasury: finality is PoW depth, à la Bitcoin/Kaspa.

Built on a mature post-quantum BlockDAG L1 codebase; the consensus, wallet,
transport, and RPC subsystems carry over, with the proof-of-work, signatures,
tokenomics, and finality model replaced.

> ## ⚠️ Status: research / pre-testnet — **ZERO security**
> This build runs a **relaxed testnet regime** of the Module-SIS PoW (the
> residual bound is checked on a handful of coefficients so blocks can be
> brute-force mined). That regime is **trivially forgeable** and provides
> **no security whatsoever**. Canonical Module-SIS mining requires lattice
> reduction (BKZ + Babai) and a concrete-security analysis (lattice-estimator),
> an IACR ePrint pre-print, and a third-party audit — the research track that
> gates any mainnet claim. **Do not deploy. Do not attach value.**

---

**Full status:** see [`docs/PROJECT-STATUS.md`](./docs/PROJECT-STATUS.md) — the
single source of truth for what's built, verified, and open.

## Architecture

| Layer | Technology |
| --- | --- |
| Consensus (PoW) | PHANTOM / GhostDAG-Q |
| Proof-of-Work | **Bloch-SIS** — Module-SIS lattice PoW (`crates/bloch-sis-pow`) |
| Finality | PoW depth (no BFT / no validator committee) |
| Signatures | **Hybrid Falcon-1024 ‖ ML-DSA-65** (both must verify — two lattice families) |
| Transport | ML-KEM-768 (Kyber) hybrid + ChaCha20-Poly1305; hybrid PQ peer identity |
| Networking | libp2p gossipsub + IBD sync |
| Storage | RocksDB |
| Difficulty | ASERT-Lattice (per-block, 30 s target) |

Every consensus-critical primitive is post-quantum: the PoW (Module-SIS), the
signatures (Falcon + ML-DSA), and the seed/aux hashing (SHAKE-256). There is no
classical primitive on the consensus path.

## Tokenomics

| Parameter | Value |
| --- | --- |
| Nominal supply | 21,000,000,000 BLOCH |
| Emission | 100% to miner (no validator/oracle pools) |
| Initial reward | 8,400 BLOCH/block, yearly halving, 100 BLOCH perpetual tail |
| Block time | 30 seconds |
| Founder premine | 3,570,000,000 BLOCH (17%) — 10-year cliff, then 40-year **monthly** vesting on-chain |

Full parameters and the phase-by-phase design history are in
[`BLOCH_DEVELOPMENT_PLAN.md`](./BLOCH_DEVELOPMENT_PLAN.md); economic doctrine in
`docs/adr/`.

---

## Build

```bash
cargo build --release        # needs a C toolchain (clang/cmake) for rocksdb + blst
```

Binaries in `target/release/`: `bloch` (full node), `bloch-wallet`,
`bloch-cli`, `bloch-calibrate`, `bloch-mine-genesis`,
`bloch-migrate-addr-history`.

## Run (testnet, solo mining)

```bash
./target/release/bloch --mine --data-dir ./bloch-data
```

The node validates the mined genesis, then mines Module-SIS blocks solo.
(Stratum V1/V2 pool mining is disabled: the hash-PoW share protocol has no
field for the lattice solution vector — a SIS-native pool protocol is future
work.)

Default ports: `16110/tcp` (P2P), `16111/tcp` (WebSocket), `16210/tcp` (RPC).

## Test

```bash
cargo test                    # full suite
cargo test -p bloch-sis-pow   # the Module-SIS PoW reference crate
```

---

## The Module-SIS proof-of-work

Given a serialized header and nonce, a miner must find a short solution vector
`s ∈ {-B,…,B}^N` such that `‖A·s − t‖_∞ < β` (a Module-SIS instance derived from
the header via SHAKE-256) **and** an auxiliary SHAKE-256 hash of `s` meets the
difficulty target. Verification is cheap; canonical mining requires lattice
reduction. See `crates/bloch-sis-pow/README.md`.

## License

MIT OR Apache-2.0.
