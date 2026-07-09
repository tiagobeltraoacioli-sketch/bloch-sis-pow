# ERA 1 — Pre-rebrand Code Audit (GroundState v0.5.14-sprintr)

> **Note (April 2026 rebrand).** This document is the **original
> private code audit** of the GroundState codebase, produced on
> **2026-04-20** against commit `322fbaf` (then on branch `main`
> of repo `Groundstate100/groundstate`). The audit covered 11,834
> LoC of Rust + 9 test files (2,488 LoC), focusing on consensus,
> cryptography, post-quantum transport, and key custody.
>
> **This is a historical audit of the Era 1 (GroundState) chain
> codebase.** All findings (3 CRITICAL, 6 HIGH, 11 MEDIUM, 5 LOW)
> reference Era 1 source code paths (`src/main.rs:757-918`,
> `src/consensus/mod.rs:352-403`, etc.), Era 1 commit hashes
> (`322fbaf`, sprint commits), the Era 1 GitHub repository
> (`Groundstate100/groundstate`), and the Era 1 genesis literal
> script_sig (`b"GroundState genesis: 14010101 GRND. minimum
> energy, maximum stability. 2026."`).
>
> **The literal genesis coinbase string is by definition immutable**
> — it is the byte sequence that was hardcoded in the Era 1 genesis
> block. The audit cites this literal as a finding (H-1 — wrong
> tokenomics in genesis). Rebranding the literal would be false
> historical record: the Era 1 genesis literally said "GroundState
> ... 14010101 GRND" forever.
>
> **Under the Bloch-SIS Protocol (BLOCH) rebrand (April 2026)** the
> entire chain is regenerated from a fresh genesis as Phase 6 of
> the rebrand. The new BLOCH genesis will have its own coinbase
> script_sig (TBD in Phase 6) reflecting BLOCH tokenomics
> (1,000,020,000 BLOCH supply, 4% founder pre-allocation). The
> **invariants** identified by this audit (UTXO reorg handling
> C-1, seed derivation C-2, CVE-2012-2459 C-3, ML-DSA-65 size
> consistency H-2, libp2p PQ identity H-3, etc.) **carry forward
> into BLOCH** because the underlying design is preserved unchanged.
> The remediation status of each finding is tracked in the
> companion document `docs/audit/AUDIT-2026-04-20.md` (the
> living remediation tracker), which is also preserved verbatim
> with its own Era 1 continuity header.
>
> **A separate BLOCH-era audit will be commissioned post-Phase 6**
> to re-verify the invariants on the rebranded codebase. That
> future audit is not part of this rebrand and is not yet
> scheduled. The finding numbers (C-1 through L-5) and the
> remediation history (sprints A1, A2, K, L, M, N, P, U, V, W,
> X, BB, CC, DD) belong to Era 1 and do not renumber under BLOCH.
>
> Original document follows verbatim.

---

# GroundState — Code Audit (Private Review)

**Audited commit:** `322fbaf` (branch `main`, repo `Groundstate100/groundstate`)
**Date:** 2026-04-20
**Scope:** 11,834 LoC of Rust (29 files) + Cargo.toml + 9 test files (2,488 LoC)
**Method:** Static reading, no execution. Focus on consensus, cryptography, post-quantum transport, key custody.

---

## Executive Summary

GroundState is a serious Layer 1 BlockDAG implementation with post-quantum ambitions. The code is **well above the standard of crypto projects at a similar stage**: zero `unsafe`, zero `panic!()` on the consensus path, extensive inline documentation, and documented remediation of historical vulnerabilities (VULN-01 through VULN-07).

**The "first post-quantum P2P handshake" milestone is technically valid.** `KyberConfig` is genuinely plugged into libp2p's `SwarmBuilder` for TCP and WebSocket. Every P2P byte between nodes passes through an ML-KEM-768 handshake before yamux/gossipsub.

**However** there are findings that prevent the project from being considered mainnet-ready:

- **3 Critical findings** — one compromises consensus (missing UTXO reorg), another breaks wallet recovery (seed stub), a third leaves the node vulnerable to CVE-2012-2459.
- **6 High findings** — including divergence between public documentation and code, overly aggressive consensus bounds, and libp2p identity still using Ed25519 (not PQ).
- **Legacy tokenomics leaked into genesis** — the coinbase message says "14010101 GRND" (old canonical value) even though the constants declare 21M GRND.

Aggregate risk: **HIGH for production use with real value.** Safe for continued development, testnet, and community bounties.

---

## 🔴 CRITICAL

### C-1 — Complete absence of UTXO reorg handling

**Files:** `src/main.rs:757-918` (`accept_block`), `src/consensus/mod.rs:352-403` (`add_block`), `src/storage/mod.rs` (no `rollback_block` found)

`accept_block` applies UTXO for every accepted block: it adds outputs and removes consumed inputs. **No mechanism exists to undo** UTXO mutations when a block previously classified as `blue` is reclassified as `red` after new blocks change the DAG structure.

```rust
// main.rs:862-876 — always forward, never backward
for tx in &block.transactions {
    for (j, out) in tx.outputs.iter().enumerate() {
        let _ = store.put_utxo(&txid, j as u32, out);
    }
    if !tx.is_coinbase() {
        for inp in &tx.inputs {
            let _ = store.delete_utxo(&inp.prev_txid, inp.prev_index);
        }
    }
}
```

In PHANTOM/GhostDAG, a block can have its `mergeset_blues` reclassified as new blocks merge conflicting paths. In the real Kaspa implementation, the solution is to compute UTXO against a "virtual block" (the past of the selected tip), recomputed whenever the virtual changes. Here UTXO is persisted per-block, assuming blocks are final the moment they arrive — a valid premise for Bitcoin, **invalid for GhostDAG**.

**Concrete attack:**
1. Attacker builds block X at `blue_score` k with a tx consuming UTXO U
2. After apparent finality, the attacker constructs a parallel branch that, via anticone, demotes X to red
3. UTXO U remains marked as spent (storage never reverted), but X is no longer in the blue set of the virtual block
4. Double-spend: a new tx consumes U again in block Y, passes validation because U still appears in the UTXO set (storage still not reverted)

**Current partial mitigation:** the `finalized_height` checkpoint (`main.rs:800-811`) rejects blocks with `block.height <= finalized_height`. This effectively **turns consensus linear** — directly contradicting the "scalable DAG" marketing. Real GhostDAG tolerates reorgs up to CHECKPOINT_DEPTH in parallel across the DAG, not just by height.

**Fix:** implement `rollback_block()` in Storage plus a reconciliation loop after `add_block` in consensus that detects selected_parent chain changes and reverts/reapplies UTXO. `kaspa-rs` has a reference — `consensus/src/processes/virtual_processor/`.

**Severity: CRITICAL.** This is the #1 finding any external auditor would raise.

---

### C-2 — `generate_keypair_from_seed()` is a declared stub

**File:** `src/crypto/mod.rs:35-48`

```rust
pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if seed.len() < 32 { /* ... */ }
    // STUB: currently returns a random keypair regardless of seed.
    // TODO: implement ChaCha20 DRBG seeding for pqcrypto-mldsa.
    let (pk, sk) = mldsa65::keypair();  // ← RANDOM, IGNORES SEED
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}
```

The function validates seed length but **ignores the seed** and returns a random keypair. Any code depending on deterministic key derivation (BIP39 recovery, HD wallet) is **silently broken**.

**Impact:**
- `Wallet::from_seed(mnemonic)` generates a different wallet on every call
- A user who backs up a mnemonic trusting it will recover the wallet **loses their funds**
- `bip39 = "2"` in `Cargo.toml` creates the illusion of a working recovery path

**Fix:** implement real deterministic derivation. The `pqcrypto-mldsa 0.1.x` crate does not publicly expose a seed-based API, but the correct solution is:

1. Use the seed to initialize `ChaCha20Rng` from the `rand_chacha` crate
2. Monkey-patch the `rand::rng()` function used internally by `mldsa65::keypair()` through a custom thread-local RNG
3. Or: wait for an upstream fix in `pqcrypto-mldsa` (an issue is already open)

**Interim:** mark `from_seed` as `#[deprecated]` and REMOVE BIP39 from `Cargo.toml` until this is implemented, so users are not led to create backups under false security.

---

### C-3 — CVE-2012-2459 not mitigated (duplicate-tx merkle malleability)

**File:** `src/core/mod.rs:153-166` (`Transaction::merkle_root`), `src/core/mod.rs:344-354` (`validate_structure`)

```rust
while hashes.len() > 1 {
    if hashes.len() % 2 != 0 { hashes.push(*hashes.last()...); }  // duplicates
    hashes = hashes.chunks(2).map(|p| { /* hash(p[0] || p[1]) */ }).collect();
}
```

Bitcoin-style calculation that duplicates the last hash on odd-length lists. **This is exactly Bitcoin's CVE-2012-2459**: a block with transactions `[A, B, C]` has the same merkle root as a block with `[A, B, C, C]` — an attacker can announce a header with a valid merkle root and serve two different transaction lists matching the same root. Bitcoin Core mitigates this by rejecting blocks with duplicate transactions.

`validate_structure` in `core/mod.rs:344` calls `validate_pow`, `validate_merkle`, `validate_coinbase_format`, `validate_dust` — **none of them check for duplicate txids**. An attacker can:

1. Construct block `B1 = [coinbase, A, B, C]` with merkle root `M`
2. Construct block `B2 = [coinbase, A, B, C, C]` with merkle root `M` (same)
3. One peer gossips `B1`, another gossips `B2` with the same header

**Consensus impact:** depends on how the block hash is derived. Since `block_hash = header.pow_hash()` and the header only commits to the merkle root (not to the tx count), `B1` and `B2` share the same hash. This can produce a split where half the network accepts `B1` and the other half `B2`, **and the two produce different UTXO sets** (B2 has `C` duplicated, splitting the UTXO set).

**Fix:** in `validate_structure`:
```rust
use std::collections::HashSet;
let mut seen = HashSet::new();
for tx in &self.transactions {
    if !seen.insert(tx.txid()) {
        return Err("duplicate transaction in block");
    }
}
```

---

## 🟠 HIGH

### H-1 — Genesis coinbase script_sig carries wrong tokenomics (immutable)

**File:** `src/core/mod.rs:374`

```rust
script_sig: b"GroundState genesis: 14010101 GRND. minimum energy, maximum stability. 2026.".to_vec(),
```

Real constants in the same file: `MAX_SUPPLY = 21_000_000 * 100_000_000`. The genesis block, **immutable**, will forever say "14010101 GRND" in the coinbase, contradicting the real 21M. Any external auditor or block explorer parsing `script_sig` will find this and request an explanation.

If the genesis has not yet been irreversibly mined in production (the fixed nonce `GENESIS_NONCE = 2_305_843_010_125_966_063` suggests it has), the damage is done. If re-mining is still possible: change to a message consistent with 21M.

If already mined: explicitly document in `README.md` why the genesis message does not match the current tokenomics — a historical planning transition. Reputational containment.

---

### H-2 — ML-DSA-65 sizes inconsistent between modules

**File:** `src/core/mod.rs:42-44` vs `src/transport/mod.rs:103-105` vs NIST FIPS 204

| Location | PUBKEY | PRIVKEY | SIG |
|---|---|---|---|
| `core/mod.rs` | 1952 | **4000** | **3293** |
| `transport/mod.rs` | 1952 | — | 3309 |
| NIST FIPS 204 actual | 1952 | 4032 | 3309 |

`core::SIG_SIZE = 3293` and `core::PRIVKEY_SIZE = 4000` come from the older Dilithium3 (pre-standardization). The transport uses the correct ML-DSA-65 sizes.

**Impact:**
- `Transaction::estimate_size()` (core/mod.rs:193) uses `core::SIG_SIZE`, under-estimating by 16 bytes per input
- `calc_fee` based on `estimate_size` produces fees below the minimum for txs with many inputs
- Tx can be rejected in the mempool as `insufficient fee`

**Fix:** update `core/mod.rs:42-44` to `PRIVKEY_SIZE = 4032`, `SIG_SIZE = 3309`. Add a test that imports `pqcrypto_mldsa::mldsa65::PUBLICKEYBYTES/SECRETKEYBYTES/SIGNATUREBYTES` and compares against the constants.

---

### H-3 — libp2p identity on Ed25519, not PQ

**File:** `src/network/mod.rs:553`

```rust
let kp = identity::Keypair::generate_ed25519();
```

The P2P identity used to sign the Kyber handshake transcript is **Ed25519**. The current "hybrid PQ" model:

- Kyber768 KEM for confidentiality ✓ (PQ, harvest-now-decrypt-later resistant)
- Ed25519 signatures for authentication ✗ (**classical, not PQ**)

This is documented explicitly in `transport/upgrade.rs:12-14`: *"libp2p identity signatures (Ed25519 in practice...) for authenticating peer identities."* And it is the TLS 1.3 hybrid pattern used by AWS/Cloudflare/Google — engineering-defensible.

**But the marketing claims:** `landing.html` says "ML-KEM-768 hybrid post-quantum transport", without distinguishing KEM from signatures. **A casual reader concludes the entire transport is PQ.** In practice, a future quantum adversary could break Ed25519, forge peer identity, and MITM — the confidentiality of previously-captured messages remains protected by Kyber (harvest-now fails), but **future connections are vulnerable**.

**Fix (documentation):** update the landing page / PDF to "hybrid post-quantum KEM with classical Ed25519 authentication" or similar. Be explicit about the model.

**Fix (code, long term):** libp2p does not support ML-DSA identity natively. Fully PQ identity would require forking libp2p or moving the transport outside libp2p — high cost, marginal gain (Ed25519 is still decades away from being broken by realistic quantum computers).

---

### H-4 — PDF claim "AES-256-GCM" ≠ code (ChaCha20-Poly1305)

**File:** `FIRST_POST_QUANTUM_HANDSHAKE.pdf` vs `src/transport/mod.rs:455`, `transport/upgrade.rs:15`

The PDF states:
> Session encryption: AES-256-GCM (random 96-bit nonce) NIST SP 800-38D

The code:
```rust
// mod.rs:455
let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
// with nonce derived from a monotonic counter, not random
```

Both algorithms are secure AEADs. **ChaCha20-Poly1305 with a counter-derived nonce is strictly more secure** than AES-GCM with a random nonce (no collision risk up to 2^64 messages vs a birthday bound of ~2^48 for AES-GCM random). But **the public claim is factually wrong** about what the code does. An external auditor will flag it immediately.

**Fix:** re-issue the PDF with:
> Session encryption: ChaCha20-Poly1305 (96-bit counter-derived nonce) RFC 7539

Wallet encryption does use AES-256-GCM (correctly, `wallet/encryption.rs:169`). The confusion likely arose from mixing the two contexts when the PDF was written.

---

### H-5 — `past_blue_set` bounded to 2*K (20 blocks) under-counts anticone

**File:** `src/consensus/mod.rs:513-531`

```rust
fn past_blue_set(&self, block: &BlockHash) -> HashSet<BlockHash> {
    // ...
    let max_depth = self.k * 2;  // K=10 → only walks 20 selected-chain hops
    // ...
}
```

Used in `classify_mergeset` to seed the `blue_set` against which PHANTOM's K-constraint is evaluated. If a mergeset block has an anticone intersecting blues **beyond 20 blocks**, the count is **under-estimated** → a red block is classified as blue → `blue_score` diverges between nodes.

On a network with latency over 20 × 10s = 200 seconds, or during a prolonged honest partition, different nodes will have different views of the blue/red classification of older blocks. This is a **silent consensus split**.

Real Kaspa uses reachability tree indexing for `O(1)` ancestry checks with no depth bound. The bound here was chosen for performance but leaks as a correctness bug under high latency.

**Fix:** implement a reachability tree with interval trees (Kaspa-style), or at least raise the bound to `K * 100` and add a warning log when the bound is hit.

---

### H-6 — `FINALITY_DEPTH` hardcoded diverges from `CHECKPOINT_DEPTH`

**File:** `src/consensus/mod.rs:597` vs `src/core/mod.rs:38`

```rust
// consensus/mod.rs:596
pub fn is_final(&self, hash: &BlockHash) -> bool {
    const FINALITY_DEPTH: u64 = 86_400;  // ← 86,400 blue_score
    // ...
}

// core/mod.rs:38
pub const CHECKPOINT_DEPTH: u64 = 1_000;  // ← 1,000
```

`is_final()` returns `false` for any block whose blue_score differs by less than 86,400 (240 h at 10 s/block = 10 days). But `main.rs:893-900` updates `finalized_height` using `CHECKPOINT_DEPTH = 1_000` (~2.7 h).

**Result:** RPC queries on `is_final` return false for 10 days while the node internally treats blocks as final after a 1,000 blue_score delta. A visible discrepancy for users and exchanges integrating the chain.

The README says "Finality depth 1,000 blocks" — aligned with `CHECKPOINT_DEPTH`, disaligned with `is_final()`.

**Fix:** `consensus/mod.rs:597` should use `crate::core::CHECKPOINT_DEPTH` instead of the local `const FINALITY_DEPTH`. A single source of truth.

---

## 🟡 MEDIUM

### M-1 — `Cargo.toml` repository URL is stale

`Cargo.toml:8`: `repository = "https://github.com/groundstate888/groundstate"` — points to an old repo, should be `Groundstate100/groundstate`.

### M-2 — `load_persisted()` trusts RocksDB without revalidation

`consensus/mod.rs:339-350`: reconstructs the DAG from storage without recomputing PHANTOM. If RocksDB is corrupted, or someone with disk access edits `blue_score` / `mergeset_blues`, the node restarts with arbitrary consensus. Defense-in-depth: recompute PHANTOM or hash-chain over `GhostdagData`.

### M-3 — `MAX_REACHABILITY_DEPTH = 1024` silent cutoff

`consensus/mod.rs:123`: if the height difference exceeds 1024, `is_ancestor` returns false even when it should return true. Silent consensus split in DAGs with deep branches. Should at least log a warning when the bound is hit.

### M-4 — Wallet encryption: KDF weaker than advertised

`wallet/encryption.rs:68-70` vs `README.md`:

| | README | Code |
|---|---|---|
| m_cost | 256 MiB | **64 MiB** (65,536 KiB) |
| t_cost | 4 | **3** |

Not catastrophic (64 MiB Argon2id with 3 iterations is still solid, ~1 s on a modern CPU) but the README is lying.

### M-5 — Wallet encryption: password policy too permissive

`wallet/encryption.rs:152-156`: `password.len() < 8` is the only check. Passwords like `"12345678"` pass. The module docstring (line 39) claims "≥12 chars + complexity" but does not enforce it. The minimum in line with NIST SP 800-63B should be 12+ with a denylist of common passwords.

### M-6 — `rand` API inconsistent between modules

`Cargo.toml` bumped `rand = "0.9"` with a comment explaining that 0.8.5 was unsound. But:

- `crypto/mod.rs:264`, `transport/mod.rs:264`, `transport/upgrade.rs:273`: use `rand::rng()` (new, correct API)
- `wallet/encryption.rs:161-162`: uses `rand::thread_rng()` (old API, still compiles but deprecated)

Should be standardized on `rand::rng()`. If the crate publishes `thread_rng()` only as a deprecated shim, warnings will appear on build.

### M-7 — Miner is CPU-only, no stratum

`mining/mod.rs`: 111 lines, `std::thread::scope` with N threads each holding a nonce range. No stratum server, no GPU/ASIC support, no extra-nonce rotation. Same critique raised by the previous external auditor. A real launch requires stratum.

### M-8 — `treasury_address()` is single-sig, founder-controlled

`core/mod.rs:444-455`: acknowledged in a comment and in the README ("founder-held single-signature wallet during network bootstrap"). Not a bug but a **governance risk**: the founder can move the entire treasury unilaterally. The v0.6.0+ plan promises multisig. Until then, any external auditor will classify the project as "founder-controlled until proven otherwise".

### M-9 — `assert!` in `add_block` crashes the node instead of rejecting

`consensus/mod.rs:361-362`:
```rust
assert!(!parents.is_empty(), "block must have at least one parent");
assert!(!self.store.has(&hash), "block already in DAG");
```

If an invalid block slips past gossipsub into consensus, an `assert!` panics the entire node instead of returning an `Err`. Should be `return Err(ConsensusError::...)`.

### M-10 — `DefaultHasher` for gossipsub MessageId

`network/mod.rs:134-137`: `std::collections::hash_map::DefaultHasher` is **not stable** across Rust versions. Nodes on Rust 1.75 and 1.80 may compute different IDs for the same message, breaking gossipsub deduplication. Should be a deterministic hash (truncated SHA-256, for example).

### M-11 — `resolve_multiaddr` is synchronous and blocks the event loop

`network/mod.rs:593-613`: a DIY DNS resolver that calls synchronous `to_socket_addrs()` inside the swarm loop. If a DNS seed is slow to respond, the entire loop stalls. Should use `tokio::net::lookup_host`.

---

## 🟢 LOW

- **L-1:** `crypto::verify()` returns a silent `bool` on parse error — acceptable for consensus (reject-on-parse-fail is correct) but hostile to debugging.
- **L-2:** `Transaction::merkle_root` without a `MerkleRoot` newtype — accepts raw `[u8; 32]`, footgun.
- **L-3:** `resolve_multiaddr` silently falls back to the original string on error, with no log.
- **L-4:** `save_known_peers` writes via synchronous `std::fs::write` (non-atomic, the file can be corrupted on crash mid-write).
- **L-5:** The `BLOCK_REWARD` comment says "~5-6 years of emission" — in practice this is ~13 years for 99 %.

---

## ⚪ INFORMATIONAL / POSITIVE

**Done well:**

- PQ handshake (`transport/mod.rs` + `upgrade.rs`): correct transcript binding (t1 → t2), signatures over the transcript, constant-time pin comparison, HKDF with t2 as salt, domain-separated labels, monotonic counter with `u64::MAX` guard, length-prefix bound on AAD, `ZeroizeOnDrop` on session keys. **Solid crypto engineering.**
- Vulnerability fixes documented inline (VULN-01 through VULN-07) with tests in `tests/security_audit.rs` — **demonstrates a discovery/fix/regression-test cycle.**
- `primitive-types::U256` for `retarget_bits` — lesson from the Sprint L disaster applied. **Excellent** engineering call.
- Peer scoring with gossipsub `PeerScoreParams` + `PeerScoreThresholds` (`network/mod.rs:147-206`) — non-trivial sybil resistance.
- Rate limiting + API key auth using `subtle::ConstantTimeEq` (`rpc/auth.rs`) — timing-attack resistant.
- Zero `unsafe`, zero `panic!()` on the main path (only defensive `assert!`s plus tests).
- **The `2026-04-20 21:58:42 UTC` milestone is genuine.** `KyberConfig` is truly plugged into `SwarmBuilder` (`network/mod.rs:218-239`) for TCP + WebSocket. Every P2P byte between nodes goes through ML-KEM-768 before gossipsub.

**Dependencies up to date:**
- `libp2p 0.56` (not 0.53 with the ring AES panic CVE)
- `bincode 2` with the `serde` feature (1.x unmaintained)
- `rand 0.9` (0.8.5 unsound)
- `pqcrypto-mldsa 0.1` (pqcrypto-dilithium deprecated)
- `axum 0.8` (jsonrpc-http-server abandoned)
- All with `FIX: X → Y (reason)` comments in `Cargo.toml`.

---

## Recommended prioritization

Ordered by impact/effort ratio:

1. **C-3** (CVE-2012-2459) — ~5-line fix, mitigates a critical consensus split
2. **H-2** (ML-DSA sizes) — 2 constants + a test
3. **H-6** (FINALITY_DEPTH) — 1-line fix, use `core::CHECKPOINT_DEPTH`
4. **M-1** (Cargo.toml URL) — trivial
5. **H-4** (PDF AES claim) — re-edit the public document
6. **C-2** (seed stub) — product decision: remove bip39 OR implement the derivation
7. **H-3** (Ed25519 identity) — clarify marketing
8. **M-9** (assert! crashes) — convert to `Result`
9. **C-1** (reorg handling) — large effort, but blocks mainnet-ready. Requires 200-500 LoC new code + tests. Blocker for v1.0.
10. **H-5** (past_blue_set bound) — requires a reachability tree, medium-to-large effort.
11. **H-1** (genesis message) — if re-mining is still possible, fix it. Otherwise, document it.
12. **M-2** (load_persisted validation) — add a hash-chain to `GhostdagData`, medium.

---

## Scope not covered

Modules read only partially due to time limits:

- `src/rpc/mod.rs` (1,076 lines) — complete RPC endpoints
- `src/storage/indexer.rs` (276 lines) — address index
- `src/mempool/mod.rs` (308 lines) — tx validation
- `src/hd_wallet/mod.rs` (303 lines) — HD derivation
- `src/main.rs` lines 1–756 and 961–1131 — wiring, CLI, sync loop
- `src/bin/grnd-cli.rs` (678 lines)
- `src/analytics/mod.rs` (524 lines)
- Full `tests/*.rs` (2,488 lines)
- `gips/GIP-0001.md`

Of these, the **mempool** is the highest priority for a second-round audit — pre-block tx validation is critical for spam resistance.

---

## Conclusion

GroundState is **well above the typical floor** of early-stage Layer 1 projects. The post-quantum transport layer is genuinely implemented and the milestone is technically defensible. There is a visible culture of documenting vulnerabilities and versioning fixes (sprints A1, A2, K, L, M, N, P).

But between "valid milestone on testnet" and "mainnet with real value" there are at least **three concrete barriers**:

1. Implement UTXO reorg handling (C-1)
2. Remove or really implement seed recovery (C-2)
3. Close CVE-2012-2459 (C-3)

With these three fixed, the project is in a state where paid external auditing makes sense. Without them, an external auditor will park on C-1 and not progress.

Operational suggestion: treat v0.5.14-sprintr as a **technical demo / milestone record**, not as code ready to custody value. Plan v0.6.0 as "mainnet-candidate" after addressing the criticals.

---

*Report generated via static code reading, without execution, without paid external audit, without fuzz testing analysis. Positive and negative points are observable in the code, but not every exploitation chain has been experimentally validated — some conclusions depend on reasoning about consensus invariants that may have mitigations in modules not read. Treat this document as input for triage, not as a certified audit.*
