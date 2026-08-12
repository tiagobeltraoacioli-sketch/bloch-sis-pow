# Bloch-SIS Protocol (BLOCH) — Threat Model

> **Genesis-3-era document — sealed 2026-08-12.** Bloch's proof-of-work
> chain halts by consensus rule at the terminal height (50,000) and
> Genesis-4 relaunches as proof of stake; the ownerless thesis was
> retracted (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> §3 (network/transport), §4 (RPC), §5 (storage), §6 (wallet/keystore) and §8
> (quantum adversary) stand and are cited by current work. §1 (consensus —
> GhostDAG-Q, retargeting) and §7 (mining) do not. The current threat models
> are `docs/specs/BLOCH-POS-THREAT-MODEL.md` and `-2.md`.

**Document version:** 1.0
**Last updated:** 2026-04-19
**Codebase reference:** `gitlab.com/Entanglementlayer/bloch-layer@main` (rebranded from `groundstate888/groundstate@main` + Era 1 release `v0.5.9-rc1`, which is the source of the STRIDE analysis; BLOCH rebrand preserves the design unchanged, only renames identifiers)
**Status:** Internal self-assessment. NOT an external audit.

---

## Scope and disclaimer

This document enumerates attack surfaces, adversary models, and known
mitigations for Bloch-SIS Protocol. It is produced by the maintainers from reading
the source. It is **not** an independent third-party security audit. Specific
caveats:

- No fuzzing campaign has been run against the codebase.
- No symbolic execution or formal verification has been applied.
- No side-channel analysis has been performed on cryptographic primitives.
- Mitigations listed here are *claims about code paths*, not proofs of
  absence of bypass.

Vulnerabilities found should be reported per `SECURITY.md`.

---

## System overview

Bloch-SIS Protocol is a post-quantum BlockDAG Layer 1 implemented in Rust. The node
binary (`bloch`) runs several subsystems in the same process:

| Subsystem | Source location | LOC | Role |
|---|---|---|---|
| Core types | `src/core/mod.rs` | 511 | Block, Transaction, serialization, coinbase rules, retargeting |
| Consensus | `src/consensus/mod.rs` | 743 | GhostDAG-Q (PHANTOM k=10) blue-set computation |
| Mempool | `src/mempool/mod.rs` | 300 | Unconfirmed transaction pool |
| Storage | `src/storage/` | 891 | RocksDB wrapper, UTXO set, address index |
| Network | `src/network/` | 899 | libp2p swarm, gossipsub, PEX, peer management |
| Transport | `src/transport/` | 1384 | Post-quantum hybrid session layer (Kyber768 + Ed25519 + ChaCha20-Poly1305) |
| RPC | `src/rpc/mod.rs` | ~1000 | JSON-RPC HTTP API (32 methods) |
| Crypto | `src/crypto/mod.rs` | 106 | ML-DSA-65 sign/verify wrapper |
| Wallet | `src/wallet/`, `src/hd_wallet/` | ~1500 | Keystore, encryption, transaction building |

Total: ~4,800 LOC in safety-critical modules (core + consensus + mempool +
network + storage + crypto + transport). No `unsafe` Rust is used anywhere in
the codebase (`grep -r "unsafe" src/` returns zero hits outside comments).

### Trust boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│ Node process                                                     │
│                                                                  │
│  ┌────────────┐    ┌────────────┐    ┌──────────────┐            │
│  │  Mempool   │◄──►│ Consensus  │◄──►│   Storage    │            │
│  └─────▲──────┘    └─────▲──────┘    └──────▲───────┘            │
│        │                 │                  │                    │
│        │                 │                  │                    │
│  ┌─────┴─────────────────┴──────────────────┴──────┐             │
│  │             Event loop (main.rs)                │             │
│  └───┬────────────────────┬──────────────────┬─────┘             │
│      │                    │                  │                   │
│  ┌───▼──────┐        ┌────▼─────┐       ┌────▼──────┐            │
│  │ Network  │        │   RPC    │       │  Wallet   │            │
│  │ (libp2p) │        │  (HTTP)  │       │  (files)  │            │
│  └───▲──────┘        └────▲─────┘       └────▲──────┘            │
└──────┼────────────────────┼──────────────────┼──────────────────┘
       │                    │                  │
   ════╪════════════════════╪══════════════════╪════════
       │                    │                  │
   Internet           RPC clients         Local disk
   (untrusted)      (partially trusted)   (OS-protected)
```

- **Internet (P2P)** — fully untrusted. Any peer can send arbitrary bytes.
  The Kyber-hybrid transport authenticates peers and encrypts traffic, but
  an authenticated peer is still an adversary if they choose to misbehave.
- **RPC surface** — HTTP JSON-RPC on port 16210. Bind address defaults to
  `127.0.0.1` (localhost only). Operators using `--rpc-public` expose this
  to the internet without authentication, on purpose or by mistake.
- **Local disk** — the RocksDB state at `bloch-data/chain/` is trusted (we
  assume the OS prevents other processes from writing to it). Keystore
  files are encrypted with Argon2id + AES-256-GCM.

### Assets

Ranked by impact of compromise:

1. **Consensus correctness** — if an attacker can inflate supply, double-spend,
   or halt the chain, all economic value is at risk.
2. **Founder keystore** — controls authority over the 170,000,000 BLOCH premine, vested on-chain over 30 years (12-month cliff at block 207,260 + linear release through block 6,220,700, per ADR-010-A and TOKENOMICS_V2.md §4). Genesis block contains 0 BLOCH to founder. The Era 1 GroundState chain had a different 5% / 1,050,000 GRND premine; that chain state is not carried forward. The earlier BLOCH design (V1, 4% / 40,000,800 BLOCH at genesis as a single coinbase output) was superseded by ADR-028 before any mainnet launch.
3. **Validator pool address** — accumulates the 25% per-block validator allocation (consensus-enforced by the 70/25/5 split per ADR-028). Distribution to FFG validators per ADR-007 bonding/slashing schedule. **Oracle pool address** accumulates the 5% per-block oracle allocation, distributed pro-rata to PoBRS oracles per ADR-018.
4. **Node availability** — seed/worker uptime affects network liveness.
5. **User funds** — individual wallet keys; compromise is localized.
6. **Node telemetry** — RPC data (`getpeers`, `getchainstats`) is public by
   design; no confidentiality asset here.

### Adversary classes

| Class | Capabilities | In scope? |
|---|---|---|
| **Network attacker (passive)** | Reads all traffic on the wire | Yes |
| **Network attacker (active MITM)** | Modifies, injects, drops packets | Yes |
| **Malicious peer** | Full libp2p peer, can send arbitrary messages that survive basic parsing | Yes |
| **Malicious miner** | Submits invalid blocks, attempts difficulty bypass, timestamp skew, etc. | Yes |
| **Malicious RPC caller** | Can hit any RPC endpoint; if `--rpc-public`, from anywhere on internet | Yes |
| **Insider / compromised operator** | Access to `founder.json` / `treasury.json` plus passwords | Partially — we assume operators protect their own keystores |
| **Physical attacker** | Access to running hardware | Out of scope — assume OS isolation is intact |
| **Supply chain** | Compromises a crate dependency or CI | Out of scope — tracked separately under Sprint 11 supply-chain compliance (Labs operationalization roadmap), not modeled here |
| **Quantum adversary** | Can run Shor's algorithm at scale (forge ECDSA in polynomial time) | Yes — this is the whole point of the project |

---

## Method: STRIDE per subsystem

For each subsystem we enumerate threats under the STRIDE taxonomy
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of
service, Elevation of privilege), state the current mitigation, and
identify gaps.

A threat is labelled:

- **MITIGATED** — a code path exists that should prevent the attack
- **PARTIAL** — some mitigation exists, known gaps remain
- **OPEN** — no mitigation, tracked in backlog
- **BY DESIGN** — known property, not treated as a vulnerability (e.g.
  public telemetry)

---

## 1. Consensus layer

**Source:** `src/core/mod.rs`, `src/consensus/mod.rs`, `src/main.rs`
(`accept_block`, `validate_tx_in_block_with_maturity`).

### 1.1 Spoofing — forging valid-looking blocks

| Threat | Status | Notes |
|---|---|---|
| Fake proof-of-work (submit block that fails PoW) | MITIGATED | `BlockHeader::pow_hash()` (SHA-256d) checked against target derived from `bits`. `hash_meets_target` is big-endian byte comparison, standard Bitcoin-style. |
| **Difficulty bypass** — set own `bits` to a trivial target | MITIGATED | `accept_block` in `main.rs:614-622` reads `expected_bits` from the `current_bits` meta key and rejects any block with `block.header.bits != expected_bits`. Confirmed by test `vuln01_difficulty_bypass`. |
| **Height spoofing** — claim height=0 to collect full reward later in chain | MITIGATED | `accept_block` `main.rs:624-644` validates `block.height == max_parent_height + 1`. For genesis, height must be 0. Confirmed by test `vuln02_height_spoofing_inflation`. |
| **Timestamp skew** (past or far future) | MITIGATED | `Block::validate_timestamp(parent_ts)` rejects timestamps earlier than parent and timestamps more than `MAX_FUTURE_SECS = 7200s` (2h) beyond local wall clock. |
| Signature forgery on a spent UTXO | MITIGATED (classical) | ML-DSA-65 (FIPS 204) is NIST-standardized; no known polynomial-time attack, classical or quantum. Forgery reduces to solving Module-LWE. |
| **Coinbase fee inflation** — claim more fees than the block's transactions produce | MITIGATED | `validate_coinbase_value(total_fees)` enforces `miner_output == miner_reward(h) + fees` and `treasury_output == treasury_reward(h)` exactly. Confirmed by test `vuln05_coinbase_with_fees_fixed`. |

### 1.2 Tampering — altering the chain state

| Threat | Status | Notes |
|---|---|---|
| **Double-spend via mempool race** | MITIGATED (Sprint N-min) | `mempool.rs` maintains a `spent: HashMap<(txid, vout), spender_txid>` index. `Mempool::add` rejects any tx whose inputs already appear in `spent`. |
| **Double-spend via chain reorg** | PARTIAL | GhostDAG selects the heaviest chain by `blue_work`. Immature coinbase spends are the main attack vector; see 1.4 below. Finality checkpoint exists (`finalized_height` meta key) that rejects reorgs below it — but the depth at which finality kicks in is not well-documented. |
| **Coinbase malleability** (attacker produces two txids for same block) | MITIGATED | `Transaction::txid` for coinbase strips `script_sig` back to canonical `height:N` form. Test `vuln06_txid_malleability_fixed` verifies that extra trailing bytes don't produce a new txid. |
| **Merkle root mismatch** (block claims different txs than it contains) | MITIGATED | `Block::merkle_root` recomputed during validation, compared against header. |
| **Supply inflation beyond the emission schedule** | MITIGATED (per-block) | Each block's coinbase is capped at `miner_reward(h) + fees` and `treasury_reward(h)`. [2026-08 correction: there is **no** `MAX_SUPPLY` cap — the nominal supply is 21 **billion** BLOCH and the 100 BLOCH/block tail is perpetual; the invariant defended here is "coinbase pays exactly the scheduled subsidy" per `tokenomics_v2.rs::block_subsidy_sat` (Emission V3 from local h=40,000 — `legacy/specs/TOKENOMICS_V3.md`), not a hard cap.] GAP: no global invariant enforces ∑ coinbase == expected total at the current height — a divergence would only be caught when supply distribution is sampled. Sprint O covers this. |

### 1.3 Repudiation

Consensus is content-addressed (txid, block hash). Repudiation of signed
content is not a meaningful threat at this layer — either a signature
verifies or it does not.

### 1.4 Information disclosure

| Threat | Status | Notes |
|---|---|---|
| Chain state is public | BY DESIGN | BlockDAG data is public by definition. |
| Private transaction graph | BY DESIGN | UTXO model reveals full transaction graph, same as Bitcoin. No mixing, no shielded transactions. Users seeking privacy must run their own wallet logic. |

### 1.5 Denial of service

| Threat | Status | Notes |
|---|---|---|
| **Mempool flooding** — submit millions of low-fee txs | MITIGATED | `MAX_MEMPOOL_SIZE = 50_000`. Eviction is by lowest fee. Per-tx cap at `MAX_TX_SIZE = 400 KB` (Sprint N-min). |
| **Oversized blocks** | MITIGATED | `MAX_BLOCK_SIZE = 1_000_000` enforced in `Block::validate`. |
| **Transaction-graph DoS** — deeply nested tx chains | PARTIAL | No explicit limit on the number of ancestor mempool txs. Sprint N-full scope. |
| **Slow validation attack** — craft a tx expensive to verify | PARTIAL | ML-DSA-65 verification is ~0.5ms on modern CPU. No pathological input has been engineered against `pqcrypto-mldsa`. Fuzzing here would be valuable. |
| **GhostDAG anticone explosion** — submit blocks with many parents to force k-bound checks | PARTIAL | Parent count is bounded implicitly by block size, but no explicit cap. Study needed on cost of `anticone` computation with adversarial DAG topology. |

### 1.6 Elevation of privilege

Consensus has no privilege levels. A correctly signed transaction from any
address is as authoritative as any other. The founder and treasury addresses
have no special consensus power — they simply hold balances.

### 1.7 Known gaps (consensus)

Tracked in `SPRINTS.md`:

- **Sprint N-full** — unify `Transaction::validate()` across 4 entry points
  (mempool/P2P/RPC/block). Currently each entry point runs a slightly
  different subset of checks; this is a refactor more than a vulnerability
  but any divergence is a potential bug.
- **Sprint O** (Era 1 reference) — 470.4 GRND supply accounting gap on the Era 1 GroundState chain (likely empty-script
  coinbase outputs from workers started without `--miner-address`).
  Diagnosis pending.
- **Sprint E** — consensus refactor with typed errors. `Result<_, String>`
  everywhere makes it easy to miss error-path bugs.

---

## 2. Cryptographic primitives

**Source:** `src/crypto/mod.rs`, `pqcrypto-mldsa = "0.1"`,
`pqcrypto-kyber = "0.8"`, `sha2 = "0.10"`, `sha3 = "0.10"`,
`aes-gcm = "0.10"`, `chacha20poly1305 = "0.10"`, `argon2`, `rand = "0.9"`.

### 2.1 Primitive selection

| Use | Algorithm | Source | Status |
|---|---|---|---|
| Block PoW | SHA-256 (doubled, `sha2`) | RustCrypto | Industry standard. |
| Merkle tree | SHA-256 | RustCrypto | Industry standard. |
| Address hash | SHA3-256 truncated to 20 bytes | RustCrypto | Stronger than Bitcoin's RIPEMD160(SHA256) under a quantum preimage attack. |
| Transaction signatures | ML-DSA-65 (FIPS 204, Dilithium) | `pqcrypto-mldsa` | PQ-secure (lattice). 3309-byte signatures. |
| Transport session key | Kyber768 (ML-KEM, FIPS 203) | `pqcrypto-kyber = "0.8"` | PQ-secure (lattice). Hybrid with Ed25519 identity keys (classical), matching TLS 1.3 PQXDH pattern. |
| Transport AEAD | ChaCha20-Poly1305 | `chacha20poly1305` | Industry standard, constant-time. |
| Keystore KDF | Argon2id | `argon2` | Memory-hard, 64 MiB / 3 iterations / parallelism 4. |
| Keystore AEAD | AES-256-GCM | `aes-gcm` | Industry standard. |

### 2.2 Known issues

**C.1 — ML-DSA-65 deterministic key derivation is a stub.**
`crypto::generate_keypair_from_seed` currently ignores the seed argument and
returns a random keypair. Consequence: the BIP39 mnemonic shown at wallet
creation provides **zero** recovery value. If the user loses `wallet.json`
and tries to restore from the seed phrase, the regenerated wallet will have
a different address. This is documented in `docs/WALLET_COMPATIBILITY.md`
and `WALLET_COMPATIBILITY.md`, but not yet fixed. Tracked as Sprint S.

**T — HD wallet is not hierarchical deterministic.** `src/hd_wallet/mod.rs:82`
and `:97` both call `wallet::generate_keypair(testnet)` which is a random
keygen. The derived `master_key` field is never consumed. Same consequence
as C.1. Tracked as Sprint T. **Workaround until fixed:** keep both the
seed phrase and a backup of the `wallet.json` file. A seed phrase alone
recovers nothing.

**Q (historical) — Kyber transport was initially dead code.** The
`src/transport/` module was implemented in Sprint A1 but not wired into
libp2p until Sprint A2. From v0.5.1 through v0.5.8, any README claim about
"Kyber transport in production" was aspirational. Fixed in v0.5.9-rc1
(current).

### 2.3 Known resistances

**Verified by unit tests in `src/crypto/mod.rs`:**
- `sign_verify_roundtrip` — sign then verify succeeds for random messages
- tampered-signature rejection — flipping any bit in sig, pk, or message
  causes verify to return false

**Not verified:**
- No timing-attack analysis. `pqcrypto-mldsa` uses PQClean's reference
  implementation which is intended to be constant-time but this has not
  been independently measured on the build targets we deploy to.
- No nonce-reuse audit on the transport cipher. `src/transport/stream.rs`
  uses a monotonic counter nonce scheme (Sprint A1); counter exhaustion
  would be catastrophic but is bounded at 2^64 messages per session.
- No side-channel analysis of AES-256-GCM. `aes-gcm` crate documents that
  without hardware AES, constant-time is not guaranteed on all architectures.

### 2.4 RNG

All randomness goes through `rand = "0.9"` default `rngs::ThreadRng`, which
uses the OS entropy source (`getrandom`). No custom RNG, no seeded DRBG in
production paths. This is correct.

---

## 3. Network layer (P2P)

**Source:** `src/network/mod.rs`, `src/network/pex_validator.rs`,
`src/transport/` (upgrade + stream).

### 3.1 Transport (Sprint A2, now deployed)

The session layer uses a hybrid post-quantum handshake:

```
INITIATOR                                    RESPONDER
generate ephemeral Kyber keypair (sk, pk)
t1 = H(MAGIC || v || kyber_pk || id_pk_i || nonce)
sig_i = libp2p_sign(id_sk_i, t1)
──── HandshakeInitLp { kyber_pk, id_pk_i_pb, nonce, sig_i } ──>
                                       verify sig_i w/ id_pk_i
                                       (ss, ct) = Kyber_enc(kyber_pk)
                                       t2 = H(t1 || ct || id_pk_r)
                                       sig_r = libp2p_sign(id_sk_r, t2)
                                       derive session keys (ss, t2)
<──── HandshakeRespLp { ct, id_pk_r_pb, sig_r } ─────
verify sig_r w/ id_pk_r
ss = Kyber_dec(sk, ct)
derive session keys (ss, t2)
[wrap socket in KyberStream; return (peer_id, stream)]
```

- Post-quantum **confidentiality**: an attacker who records all traffic
  today and later acquires a quantum computer cannot decrypt it, because
  session keys derive from Kyber768 ML-KEM.
- Classical **authentication**: the peer's libp2p identity key (Ed25519)
  signs the transcript hashes `t1` and `t2`. This is vulnerable to a
  real-time quantum adversary (Shor against Ed25519), but real-time
  forgery requires the attacker to act during the handshake — there is
  no harvest-now/decrypt-later threat against authentication.
- Session cipher: ChaCha20-Poly1305 with monotonic counter nonces
  (Sprint A1 primitives).

### 3.2 STRIDE

| Threat | Status | Notes |
|---|---|---|
| **Peer spoofing** — connect claiming to be another peer | MITIGATED | libp2p identity public key is bound into both `t1` and `t2` transcripts; a fake peer cannot forge the Ed25519 signature over `t1` without the victim's identity secret. |
| **Man-in-the-middle downgrade** | MITIGATED | The Kyber handshake is negotiated via libp2p's `ConnectionUpgrade` trait with protocol ID `/bloch/kyber/1.0.0`. Peers that don't speak the protocol are rejected, not silently fallen back to plaintext. |
| **Replay of handshake messages** | MITIGATED | Handshake includes a 32-byte `nonce` from the initiator, committed into `t1`. Replaying a prior `HandshakeInitLp` forces the responder to produce a different ciphertext (randomized KEM encapsulation); old responses don't decrypt. |
| **Harvest-now/decrypt-later of traffic** | MITIGATED | Session keys derive from Kyber768. PQ-secure. |
| **Eclipse attack** (isolate a node from honest peers) | PARTIAL | `MAX_PEERS` is bounded. PEX validator filters private-range addresses and caps batch size (20) + sliding window (100 addresses per 5 min per source). But: bootstrap still relies on 1 hardcoded seed; an attacker controlling the upstream network can deny access to the seed. |
| **Amplification via PEX** | MITIGATED | Sprint P `pex_validator` enforces per-peer rate limit (100 addrs / 5 min), per-message batch limit (20), rejects private multiaddrs by default. `known_peers.json` capped at 1000 entries with FIFO eviction. |
| **Gossipsub flood / invalid message spam** | PARTIAL | libp2p gossipsub has peer scoring built in. Bloch-SIS Protocol inherits defaults but does not tune peer_score weights specifically for its message types. A motivated attacker could explore edge cases. |
| **Connection exhaustion** | PARTIAL | libp2p enforces per-peer connection limits, but a large attacker could consume all available inbound slots on a seed that has `--rpc-public`-style unrestricted ingress. |

### 3.3 Known gaps (network)

- Only 1 production seed node. The deployment document describes this as a
  temporary bootstrap state; adding more seeds reduces eclipse risk linearly.
- `peerscore` tuning for Bloch-SIS Protocol-specific message types is left at libp2p
  defaults. Long-term we want a documented peer-scoring policy.
- No DoS protection on the block-download path (`getblocks`/`getheaders` not
  yet rate-limited per peer).

---

## 4. RPC layer

**Source:** `src/rpc/mod.rs`.

### 4.1 Exposure

- Default bind: `127.0.0.1:16210` (localhost only, safe)
- Production deployment: `--rpc-public` which binds to `0.0.0.0:16210`
- No authentication layer. No API keys. No mTLS.
- 32 exposed methods; most are read-only, but `sendrawtransaction` accepts
  arbitrary transactions for mempool injection.

### 4.2 STRIDE

| Threat | Status | Notes |
|---|---|---|
| Unauthenticated remote RPC calls (`--rpc-public`) | **MITIGATED (Sprint M)** | VULN-08 closed. `--rpc-api-key-file` + `--rpc-require-auth-for-writes` authenticate the write surface. Per-IP rate limiting via `governor` crate (60 reads/min, 5 writes/min by default). Localhost bypass. Constant-time key comparison via `subtle`. Reads remain public by design (explorers). |
| Resource exhaustion via expensive RPC (e.g. `getaddresshistory` on a huge address) | PARTIAL | Paginated queries exist, but the default limit is not always enforced at the caller side. |
| Information disclosure via RPC | BY DESIGN | All RPC output is public chain data. No private state is ever returned. |
| Command injection, SSRF, SQLi | N/A | No shell, no outbound HTTP, no SQL. RocksDB key-value access only. |
| JSON parsing bugs | PARTIAL | `serde_json` is mature. The attack surface is small (32 well-typed methods). No custom parser. |
| Cross-origin requests / browser exploits | OPEN | No CORS headers. If a user runs the RPC public and visits a malicious website, the site can hit `sendrawtransaction`. Mitigation: don't run RPC public without a reverse proxy that adds CORS and auth. |

### 4.3 Recommendation (Sprint M landed)

Sprint M shipped the following mitigations in v0.5.9+:

- ✓ Optional shared-secret API key (`--rpc-api-key` / `--rpc-api-key-file`)
- ✓ Per-IP rate limiting for all methods (separate buckets for reads vs writes)
- ✓ Localhost bypass (operator tools, miners, health checks unaffected)
- ✓ Constant-time key comparison (`subtle` crate, resists timing attacks)

Residual items (housekeeping, Sprint R):

- Reverse-proxy (nginx/Caddy) with TLS is still recommended for real
  deployments — the API key travels in cleartext without it
- Per-user keys (vs single shared secret) are future work
- Rate-limit HashMap grows unbounded per distinct IP; add periodic
  eviction if a node faces highly distributed traffic

---

## 5. Storage layer

**Source:** `src/storage/mod.rs` (615 lines), `src/storage/indexer.rs` (276).

### 5.1 Threat model

| Threat | Status | Notes |
|---|---|---|
| Corruption of RocksDB state | MITIGATED | RocksDB has WAL + atomic writes; process kill at any point is safe. |
| Path traversal on data-dir | MITIGATED | Paths joined from a single `--data-dir` root via `PathBuf::join`. No user-controlled path fragments. |
| Disk exhaustion | PARTIAL | Chain can grow indefinitely. No pruning mode implemented. Currently not a concern given chain size, but a DoS against a seed could fill disk faster than pruning would be able to keep up. |
| Parallel access from multiple processes | MITIGATED | RocksDB locks the DB directory; second process fails to open. |
| Reorg invalidates indexes | PARTIAL | Address-history index (Sprint F) does not roll back on reorgs. Documented known limitation; rare in practice because GhostDAG reorgs are shallow, but should be fixed. |

### 5.2 Trust assumption

We assume the operator's filesystem is trusted — that no other process on
the host can read or write the data directory or the keystore files. On a
single-purpose VPS (Njalla) or sealed-container deployment (Akash), this
assumption is reasonable. On a shared host it would not be.

---

## 6. Wallet / keystore

**Source:** `src/wallet/encryption.rs`, `src/wallet/mod.rs`,
`src/hd_wallet/mod.rs`.

### 6.1 Keystore format

- Argon2id (m=64 MiB, t=3, p=4) over user password → 32-byte key
- AES-256-GCM encryption with random 96-bit nonce
- ML-DSA-65 secret key stored as ciphertext
- File is JSON; versioned (`v1`).

### 6.2 Threats

| Threat | Status | Notes |
|---|---|---|
| Offline password brute force | PARTIAL | Argon2id with 64 MiB memory cost limits attempts to ~1/sec on commodity hardware, ~1000/sec on GPU farms. Strong passwords essential. |
| **Lost keystore, user relies on seed phrase** | **OPEN (documented)** | Because `generate_keypair_from_seed` is a stub, restoring from mnemonic produces a fresh random keypair, not the original. Users will lose funds if they trust the phrase alone. Mitigation in `WALLET_COMPATIBILITY.md`: back up the wallet file itself. Permanent fix: Sprint S. |
| Keystore tampering | MITIGATED | AES-GCM's Poly1305 MAC rejects any byte flip; decryption fails cleanly. |
| Weak password enforcement | PARTIAL | CLI warns on short passwords but does not enforce complexity. |
| Core dump leaks secret key | OPEN | `Drop` implementations on the wallet types zero out the secret material, but Linux core dumps can still expose memory mid-execution. Users who deploy on a real box should disable core dumps (`ulimit -c 0`). |

### 6.3 Recovery story (honest version)

**Today:** If you lose `wallet.json` or `founder.json`, your funds are gone,
even if you have the 24-word phrase. The phrase, currently, is decorative.

**After Sprint S:** The phrase will deterministically regenerate the same
address. Users who have generated wallets before Sprint S will need to
migrate to a new wallet.

This is a major UX wart and we should stop calling it "HD" until Sprint T
lands.

---

## 7. Mining

**Source:** `src/mining/` (not reviewed in full here), orchestrated by
`src/main.rs`.

### 7.1 Threats

| Threat | Status | Notes |
|---|---|---|
| Miner steals block reward (substitutes pubkey at the last moment) | MITIGATED by coinbase canonicalization | `script_sig` of coinbase is normalized in `txid` computation; a miner can still mine to whatever address they configured, but cannot alter the txid. |
| **Unconfigured mining produces unspendable coinbase** | **OPEN** | If a node starts with `--mine` but no `--miner-address`, coinbase outputs may have an empty or dummy `script_pubkey`. On the Era 1 GroundState chain a 470.4 GRND supply gap likely came from this path; Sprint O on Era 1 was set to enforce `--miner-address` is required. Under BLOCH the genesis is regenerated cleanly (and under V2 contains 0 BLOCH to the founder per ADR-010-A on-chain vesting), so no equivalent supply gap exists at launch — but the same `--miner-address` enforcement requirement applies. The V2 70/25/5 coinbase adds two more consensus-enforced address checks per coinbase (validator pool, oracle pool); each requires `script_pubkey` validation against genesis-locked vault addresses. |
| Selfish mining (withhold blocks to extend privately) | PARTIAL | GhostDAG mitigates selfish mining compared to Bitcoin because blocks not on the selected chain still contribute to `blue_work` (they are not "wasted"). The attacker loses their advantage faster. This is the point of GhostDAG. |
| Time-warp attack (manipulate retarget with skewed timestamps) | MITIGATED | Retarget uses `clamp(elapsed, target_secs/4, target_secs*4)` (Sprint L fix) and block timestamps are bounded per 1.1. Combined, the maximum per-window drift is bounded. |

---

## 8. Quantum adversary

Bloch-SIS Protocol's raison d'être.

### 8.1 Assumption

A future attacker will have access to a large fault-tolerant quantum computer
capable of running Shor's algorithm on cryptographically relevant key sizes
(e.g., factoring 2048-bit RSA or solving ECDLP for 256-bit curves) in
polynomial time. NIST's post-quantum cryptography standardization (FIPS
203/204/205, August 2024) is predicated on this assumption.

### 8.2 Resistance by component

| Component | Classical attack | Quantum attack (Shor) | PQ resistance |
|---|---|---|---|
| SHA-256 PoW | Brute force (2^128 expected for collision; 2^256 for preimage) | Grover halves exponent (2^64 / 2^128) | Acceptable; Grover is impractical for hash preimage at 256 bits |
| SHA3-256 address hash | Same as SHA-256 | Same | Acceptable |
| ML-DSA-65 signatures | Sub-exponential (Module-LWE) | No known attack better than classical | PQ-secure |
| Kyber768 KEM (transport) | Sub-exponential (Module-LWE) | No known attack better than classical | PQ-secure |
| Ed25519 (transport identity/auth) | 2^128 security | Broken by Shor | **Intentional residual classical dependency** |

### 8.3 Why Ed25519 for transport identity

Because:

1. libp2p peer identities are Ed25519 and this is how the PeerId is derived.
   Replacing it across the whole libp2p stack is out of scope.
2. Transport authentication is *real-time*: the attacker would need to run
   Shor during the handshake to impersonate a peer. Harvest-now/decrypt-later
   does not apply because signatures are not persisted, only verified.
3. Session confidentiality — the thing that *does* need harvest-resistance —
   uses Kyber768.

This is exactly the hybrid rationale adopted by TLS 1.3 and WireGuard PQ
extensions. It is a deliberate engineering tradeoff, not an oversight.

### 8.4 Residual quantum risk

- Ed25519 identity keys on any deployed nodes. Once Shor is practical, an
  attacker who sees a node's PeerId can recover its identity secret. The
  consequence is limited: they can spoof that node in the P2P overlay but
  cannot steal any BLOCH (transaction signatures are ML-DSA-65).
- Any address that has spent at least once and therefore revealed an
  ML-DSA-65 public key is exposed only to direct cryptanalysis of ML-DSA,
  which has no known quantum shortcut. This is better than Bitcoin, where
  spent addresses leak the ECDSA public key which *is* vulnerable.

---

## 9. Supply chain

Out of primary scope for this document but worth listing:

- Cargo dependencies: tracked in `Cargo.lock` which is committed. Builds
  are reproducible given the same Rust toolchain version.
- Docker image: `blochlayer/bloch:v0.1.0-genesis` (placeholder; TODO publish post-Phase 6 genesis regeneration). The Era 1 image `groundstate77/groundstate:v0.5.9` (sha256 `39d2b677...8eff8814`) is historical reference only and is not used under BLOCH.
  Currently built on an individual developer machine. A hostile `cargo`
  dependency update could be injected. Long-term remediation:
  reproducible builds on CI with the dependency hash pinned.

---

## 10. Open questions tracked for external audit

Items most likely to yield findings in a future third-party audit:

1. **GhostDAG implementation correctness vs. the paper.** We implement
   PHANTOM/GhostDAG with k=10 against the Sompolinsky-Wyborski-Zohar 2021
   paper, cross-referencing `kaspanet/rusty-kaspa`. Divergences are likely
   but have not been independently verified.
2. **Mempool acceptance vs. block validation divergence.** Sprint N-full
   will unify these, but until it lands, a transaction accepted into the
   mempool may be rejected by block validation, opening asymmetric-cost DoS
   possibilities.
3. **Kyber-hybrid handshake transcript binding.** The transcript includes
   `MAGIC || v || kyber_pk || id_pk_i || nonce`. We believe this provides
   Krawczyk-style channel binding but the proof has not been written.
4. **libp2p peer scoring edge cases.** We use default weights; adversarial
   scenarios should be explored.
5. **Reorg correctness of address-history indexer.** Sprint F indexer does
   not roll back on reorg; in GhostDAG this is rare but possible.
6. **RocksDB column family migration safety.** Each new index we add needs
   a migration path from old data. The `bloch-migrate-addr-history` tool
   exists for Sprint F but the general migration story is not documented.

---

## 11. Change log

- **1.0 (2026-04-19):** Initial version. Covers v0.5.9-rc1.

---

*Next revision trigger: any of Sprint O / R / D / S / T / N-full shipping.*

**2026-04-25 — Bloch-SIS Protocol rebrand (Phase 3.e.7).** This document
was originally the GroundState v0.5.9-rc1 threat model. As part of the
April 2026 rebrand to Bloch-SIS Protocol (BLOCH), identifiers, paths,
binary names, wire-protocol IDs, Docker image references, and tokenomics
figures were updated to reflect the BLOCH chain. The STRIDE methodology
and per-subsystem analysis are preserved unchanged — the security
properties of the system follow from its design (PoW, ML-DSA-65, Kyber-
authenticated transport, libp2p gossipsub), not from its name. Era 1
historical artifacts (Sprint O 470.4 GRND supply gap, Docker image
sha256 digest) are preserved as factual record with explicit "Era 1"
qualification.
