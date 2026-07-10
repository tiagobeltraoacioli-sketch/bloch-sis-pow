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

> ## ⚠️ Status: research / pre-testnet — **ZERO security**
> This build runs a **relaxed testnet regime** of the PoW's Module-SIS gate
> (the residual bound is checked on a handful of coefficients so blocks can be
> brute-force mined). That regime is **trivially forgeable** and provides
> **no security whatsoever**. The PoW's security model is **hashcash
> cumulative work, not lattice hardness** — estimator research showed a
> trapdoorless PoW cannot be both lattice-hard and mineable (the regimes are
> disjoint; see `docs/research/POW-CANONICAL-frontier.md`). The mainnet gate is
> the no-shortcut analysis for the canonical gate parameters, an IACR ePrint
> pre-print, and a third-party audit. **Do not deploy. Do not attach value.**

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

The node validates the mined genesis, then mines Bloch-SIS blocks solo.
(Stratum V1/V2 pool mining is disabled: the hash-PoW share protocol has no
field for the lattice solution vector — a SIS-native pool protocol is future
work.)

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
