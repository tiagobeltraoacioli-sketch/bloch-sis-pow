# Bloch-SIS-PoW — Features (v0.3.0-genesis2)

A post-quantum Layer-1: SHA-256d Proof-of-Work over a GhostDAG-Q BlockDAG, with a native ML-DSA-65 ‖ Falcon-1024 signature base. Summary of what this merge brings.

## Consensus & chain
- SHA-256d PoW over **GhostDAG-Q** (BlockDAG, k=10), ~30 s blocks.
- Assume-valid checkpoint at block **#10**; node bumped to **v0.3.0-genesis2**.
- Relicensed to **AGPL-3.0-or-later**.

## euvm — native contract layer (activates at height 4320)
- **Deterministic, height-gated hard fork** (dropped the FFG-committee activation).
- **eUTXO VM**: non-local state, minting, **Ustav** module compiler, AMM batcher, height-gated harness.
- Hardened: real **state-root commitment**, **gas-by-byte** metering, overflow-checked arithmetic.
- **Kirpich** internal-audit gate over the Ustav charter compile path.
- Internal audit F1–F6 remediated + L1 static-scanner pipeline (green).

## Mining — SHA-256d smart stratum pool-proxy
- Extranonce **partitioning** with re-dial-until-unique extranonce.
- Real **PPLNS** accounting and an honest DAG observer.
- Per-worker **vardiff** (bounded submit rate → low stale).

## PQ Shield — non-custodial Bitcoin vault *(Postern product)*
- `crates/bloch-pq-vault`: a **commit-delay-reveal P2WSH vault** + a **PQ-gated clawback** on *stock* Bitcoin, plus a **PQ-signed Bloch anchor** (ML-DSA-65 ‖ Falcon-1024).
- `services/pq-shield-api`: a **non-custodial** developer endpoint — **never holds a key, never signs**; returns unsigned artifacts (vault address, witnessScript, unsigned tx, BIP-143 sighash, anchor commitment) for local signing; rejects any request containing secret-looking fields.
- Honest scope: **transition-era defense-in-depth, not unconditional quantum immunity**.

## Networking & sync
- **Announce-then-pull** directed IBD; genesis2 tx chain-id default; dual-AND reachability probes; `getpeerinfo` resync.

## Post-quantum crypto base
- **ML-DSA-65 (Dilithium) ‖ Falcon-1024** (NIST standards) via `crates/pqcrypto-internals` + `crates/bloch-crypto`.

## Deploy & tooling
- Akash Genesis-2 SDL (v0.3.0 **archival** peer), euvm Docker image, `euvm-tooling`.

## Crates
`bloch-sis-pow` · `bloch-crypto` · `bloch-euvm` · `bloch-ffg` · `bloch-btc-wallet` · `bloch-pq-vault` · `coherence-core` · `coherence-prover` · `pqcrypto-internals`

---
*Genesis-2 is early-stage and unaudited — treat rewards and vault use as experimental. BLCH is a mined, fair-launch coin, not a security.*
