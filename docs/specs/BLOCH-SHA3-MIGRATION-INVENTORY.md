# BLOCH SHA-3 Migration Inventory — SHA-2 usage census

> **Verificado em 2026-08-11.** Este documento nao depende de nenhuma das
> premissas revistas naquele dia (taint, comite amostrado, supply de 100 bi,
> fase hibrida). As conclusoes seguem valendo como escritas.


**Owner:** A5 (SHA-3 migration) · **Branch:** `feat/pos-sha3-lattice` · **Date:** 2026-08-11
**Companion to:** `BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §6.1 (domain separation), §6.6 (Coherence is already SHA-3 native) · `BLOCH-TOKENOMICS-V4.md` §3.2 (chain halts at height 80,000)

---

## 1. Scope and method

Full scan of `src/` and `crates/` for `sha2`, `Sha256`, `Sha512`, `sha256d` (288 hits,
42 files), cross-referenced against every `sha3` / `Shake256` / SHA3-256 use. Every
occurrence is classified:

| Label | Meaning |
|---|---|
| **CONSENSUS** | Enters block validation or on-chain identity. Migrating it is a hard fork — under the V4 plan, a Genesis-4 format decision rather than an in-place flag day, since Genesis-4 starts from the signed snapshot, not from chain sync. |
| **HISTORICAL** | Only validates or reproduces pre-transition (Genesis-2/3) blocks. Must **stay SHA-2 forever** wherever pre-transition history is verified; changing it would make the old chain fail its own validation. |
| **NON-CONSENSUS** | Networking, storage integrity, logging, tooling, tests. May migrate for uniformity or stay, at A5's convenience. |

Two honesty sub-labels used in the tables where the three-way split alone would mislead:

- **EXTERNAL-FIXED** — the hash is *Bitcoin's* consensus (PQ-vault scripts, AuxPoW
  parent headers, BTC wallet BIP-39). It can never migrate no matter what Bloch does.
  Classified NON-CONSENSUS from Bloch's standpoint, but it is not "optional" — it is
  frozen by an external chain.
- **KEY-COMPAT** — not consensus, but changing it silently changes every user's derived
  keys/addresses. Effectively frozen.

**Terminal-height context (V4 §3.2).** The live Genesis-3 chain halts at height 80,000
by consensus rule; the **signed snapshot artifact is canonical, not the chain**
(§3.2.2 — after the halt, accumulated PoW stops being evidence). Consequence for this
inventory: Genesis-4 nodes bootstrap from the snapshot digest embedded in the G4
genesis block, so they do **not** need to ship the SHA-256d verification path at all.
"HISTORICAL" therefore means *retained in archival tooling and any node that replays
the G2/G3 chains* — not necessarily compiled into the Genesis-4 validator.

---

## 2. Executive summary

1. **The chain is further along than the migration plan assumes.** Block identity
   (`Block::block_hash`, `core/mod.rs:1476`) is **already SHA3-256** with an ASCII
   domain tag (`BLOCH-BLOCK-ID-V1`). The transaction sighash v2 (`core/mod.rs:1343`)
   is **already SHA3-256** and chain-id-bound. Addresses and pubkey fingerprints
   (`address.rs`, `crypto/mod.rs`) are **already SHA3-256**. The P2P handshake
   transcript is **already SHA3-256**; the carryover snapshot root is **already
   SHAKE-256**.
2. **What remains SHA-2 in consensus is exactly four things:** the PoW hash
   (SHA-256d over the 80-byte mining header), the parents-commitment folding, the
   transaction **txid**, and the tx **Merkle root** — plus the eUVM opcode
   `Op::Sha256d`. The first two die with PoW at height 80,000. The txid/Merkle pair
   is the real §6.1 migration work (`BLCH4:BODY`). The opcode is a policy decision
   (§6, D-1).
3. **Coherence confirmed SHA-3 native (§6.6).** `crates/coherence-core/src/lib.rs`
   uses only `sha3::Shake256` — commitments (`DOM_CM`), nullifiers (`DOM_NF`), and
   the incremental Merkle accumulator (`DOM_MT`) are all SHAKE-256 squeezed to 32
   bytes with domain constants. There is no SHA-2 import anywhere in the crate. The
   migration brings the rest of the chain to Coherence; Coherence does not move.
4. **The new PoS crates are born SHA-3.** `bloch-pos-committee` uses SHA3-256 for the
   attestation root and SHAKE-256 for committee sampling — consistent with §6.1's
   `BLCH4:ATTEST` / `BLCH4:SORTIT` before the rest of the chain catches up.
5. **Everything stratum/AuxPoW/mining is a dead-end path** that terminates at 80,000
   and needs no migration — only decommissioning and archival retention.

---

## 3. Coherence verification (§6.6) — confirmed

`crates/coherence-core/src/lib.rs`:

| Line | What | Finding |
|---|---|---|
| 11 | `use sha3::{Shake256, …}` | Only hash import in the crate. No `sha2` anywhere. |
| 20 | `shake256_32(parts)` | Single SHAKE-256→32B helper used by everything below. |
| 43 | `cm = SHAKE256(DOM_CM ‖ v ‖ pk_d ‖ rho ‖ psi)` | Note commitments — SHAKE-256 native. |
| 47 | `nf = SHAKE256(DOM_NF ‖ nk ‖ rho ‖ position)` | Nullifiers — SHAKE-256 native. |
| 52, 83 | `DOM_MT` node hash and empty-leaf | Incremental commitment-tree accumulator — SHAKE-256 native. |

The node-side wrapper `src/coherence/mod.rs` contains no SHA-2 either. §6.6.1's
continuity requirement (accumulator never reset, nullifier set monotone across
`TRANSITION_HEIGHT`) is therefore purely a *state-carryover* requirement on A3's
shadow-fork test — no hash migration touches the shielded pool.

---

## 4. What is already SHA-3 today (the baseline the migration extends)

| File:line | Use | Note |
|---|---|---|
| `crates/bloch-crypto/src/core/mod.rs:1476` | `Block::block_hash` = SHA3-256, tag `BLOCH-BLOCK-ID-V1` | Block identity is already SHA-3 and already domain-separated. §6.1's `BLCH4:BLOCK` is a re-tag, not a re-hash. |
| `crates/bloch-crypto/src/core/mod.rs:1343` | Sighash v2 = SHA3-256, domain + version + chain-id prefix | Signatures already bind to a SHA-3 digest. |
| `crates/bloch-crypto/src/address.rs:57,89,122` | Address = SHA3-256(pubkey), checksum = SHA3-256² | KEY-COMPAT — already SHA-3, frozen. |
| `crates/bloch-crypto/src/crypto/mod.rs:248,264,291` | Pubkey hash / fingerprints | Already SHA-3. |
| `src/transport/mod.rs:52,75` | Handshake transcript integrity = SHA3-256 | Mixed construction — see §5.7. |
| `src/storage/mod.rs:1043–1172` | Carryover snapshot root = SHAKE-256 over raw bytes | The same pattern V4 §3.2.2 mandates for the 80,000 snapshot artifact. |
| `crates/bloch-pos-committee/src/attestation.rs:12,43` | Attestation root = SHA3-256, domain-separated | New PoS code born SHA-3 (`BLCH4:ATTEST`). |
| `crates/bloch-pos-committee/src/sample.rs:13,109` | Committee sampling = SHAKE-256 | New PoS code born SHA-3 (`BLCH4:SORTIT`). |
| `crates/bloch-sis-pow/*` (`shake.rs`, `expand.rs`, …) | Module-SIS PoW matrix expansion = SHAKE | Already SHA-3, but wired only to `ChainId::Mainnet/Testnet` (`core/mod.rs:201–202`) — not the live G3 chain, and PoS retires PoW entirely. Becomes a research crate. |
| `crates/bloch-euvm/src/lib.rs:132,401` | `Op::Shake256` VM opcode (0x41) | The SHA-3 opcode already exists beside `Op::Sha256d`. New scripts need no new opcode. |
| `crates/bloch-crypto/src/hd_wallet/mod.rs`, `wallet/{disclosure,encryption,mod}.rs` | SHA-3/SHAKE in wallet derivation & disclosure | Already SHA-3. |
| `src/network/sync_rr.rs`, `src/stratum_v2/` (noise/handshake files), `src/euvm/`, `src/rpc/` | Assorted SHA-3 uses | Already SHA-3. |

---

## 5. SHA-2 inventory — per file, per line

### 5.1 Consensus core — `crates/bloch-crypto/src/core/mod.rs` (58 hits)

| Lines | What | Class | Justification / migration requirement |
|---|---|---|---|
| 4 | `use sha2::{Sha256, Digest}` | — | Import serving the rows below. |
| 822–826 | `MiningHeader::pow_hash` = SHA-256d over 80-byte Bitcoin-layout header | **CONSENSUS → HISTORICAL** | The PoW hash of the live G3 chain. PoW ends at height 80,000 (V4 §3.2); Genesis-4 is PoS with no PoW arm. Never migrated — becomes the frozen historical verifier. Per §3.2.2 the G4 node need not ship it at all (snapshot is canonical); retain in archival tooling. |
| 831–867 | `parents_commitment` — pairwise SHA-256d fold of parents into `prev_hash` | **CONSENSUS → HISTORICAL** | Feeds the mining header only. Dies with PoW. Same retention rule as `pow_hash`. |
| 1020–1030 | `BlockHeader::pow_hash` (delegates to MiningHeader) + hard-fork warning comment | **CONSENSUS → HISTORICAL** | Same as above. |
| 1301 | `Transaction::txid` = SHA-256d over stratum-format bytes | **CONSENSUS — MIGRATE** | Txid is on-chain identity referenced by every outpoint. Genesis-4: SHA3-256 under `BLCH4:BODY` (§6.1). Because G4 starts from a balance snapshot, no old txid needs to re-validate inside G4 — but any tool replaying G2/G3 history must keep the SHA-256d form. The stratum-format serialization rationale (miner agreement on coinbase bytes) disappears with PoW; A5 may also simplify the serialization at the same seam. |
| 1350–1366 | `Block::merkle_root` — pairwise SHA-256d over txids | **CONSENSUS — MIGRATE** | The transaction Merkle tree → `BLCH4:BODY` SHA3-256 in `BlockHeaderV4`. Same historical caveat as txid. |
| 1746–1770 | `validate_pow` — `PowAlgorithm::Sha256d` arm (incl. AuxPoW branch and empty-`pow_solution` rule) | **CONSENSUS → HISTORICAL** | The complete PoW validation dispatch. Frozen at the terminal height; not present in the G4 validator. |
| 2056–2073, 2170, 2212–2249, 2350–2414 | Genesis-2/Genesis-3 genesis construction & validation comments/paths (`Sha256d` arms, `sha256d_pow_valid_for_chain` genesis check) | **HISTORICAL** | Reproduces the fixed G2/G3 genesis blocks. Frozen forever by definition. |
| 2461–2531 | `SHA256D_LE_FORK_HEIGHT` (=2400), `sha256d_le_fork_height_for`, `sha256d_pow_valid_for_chain`, `sha256d_pow_valid` — the endianness flag-day machinery | **HISTORICAL** | Exists solely to validate the G2 big-endian→little-endian fork and G3's LE-from-0 rule. Must stay byte-exact wherever old history is checked. Never referenced by G4. |
| 2652–2659, 2813–2828, 3105–3108, 3244 | Tests pinning the above (endianness, AuxPoW txid, chain-id mapping) | **HISTORICAL (tests)** | Keep — they are the executable spec of the frozen behavior. |

### 5.2 PoW & mining path — dies at height 80,000

| File:lines | What | Class | Justification |
|---|---|---|---|
| `src/pow/sha256d.rs` (whole file; digest at 111) | `mine_sha256d`/`mine_sha256d_preimage` CPU miner + endianness tests | **HISTORICAL** | Miner for a chain that stops producing blocks. No G4 equivalent exists (no PoW). Decommission after 80,000. |
| `src/pow/mod.rs:11–37, 301–331` | PoW dispatch (`PowAlgorithm::Sha256d` arm, LE-fork routing) | **HISTORICAL** | Same. |
| `src/main.rs:1695, 1997, 2121–2131, 2578, 2787` | `Sha256d`-chain gates for the internal miner and stratum enablement | **HISTORICAL** | Node plumbing around PoW production. Gone in G4. |
| `src/stratum/` — `mod.rs:262–284`, `jobs.rs:19,39,358–434`, `submit.rs:33,252,267`, `session.rs` | Stratum v1: coinbase txid, Merkle branch folding, share/block target checks (`sha256d_pow_valid`) | **HISTORICAL** | Mining protocol for SHA-256d ASICs. Terminal. Note `jobs.rs` re-implements the SHA-256d Merkle fold — it must remain bit-identical to §5.1 for as long as the pool runs, i.e., until 80,000, then decommission. |
| `src/stratum_v2/` — `block_reconstruct.rs:87`, `submit_shares.rs:14`, `submit_responses.rs:53`, `session.rs:839–958` | SV2 share validation (double-SHA256 header reconstruction, `sha256d_pow_valid`) | **HISTORICAL** | Same. |
| `src/stratum_v2/cert.rs:37,169`, `keypair.rs:101–102` | SV2 pool-certificate digest & keypair fingerprint = SHA-256 | **NON-CONSENSUS** | SV2 ecosystem convention (secp256k1/SHA-256 world). Dies with mining; do not migrate. |
| `crates/bloch-crypto/src/core/auxpow.rs` (29, 86–103, 136, 182–189, 312–508) | AuxPoW: Bitcoin parent-header SHA-256d, coinbase txid, Merkle path verification | **HISTORICAL + EXTERNAL-FIXED** | Verifies *Bitcoin* headers — SHA-256d is Bitcoin's rule, unchangeable by Bloch. Feature terminates with PoW at 80,000. Frozen for validating AuxPoW-era history (h8500→80,000). |
| `src/bin/bloch-calibrate.rs:23,45,132–173` | Hashrate calibration loop | **NON-CONSENSUS (tooling)** | Benchmark utility. Obsolete after 80,000. |
| `src/bin/bloch-mine-genesis2.rs`, `src/bin/grind_genesis3.rs` | One-shot genesis grinders (pinned to the real `Sha256d` validate arm) | **HISTORICAL (tooling)** | Reproduce the fixed genesis blocks; must keep SHA-256d forever or lose reproducibility of G2/G3 genesis. |
| `crates/bloch-crypto/tests/tx_under_dual_and.rs` (4, 38–263) | Dual-PoW (SHA-256d AND SIS) property test | **HISTORICAL (tests)** | Pins frozen behavior; keep. |

### 5.3 eUTXO VM — `Op::Sha256d` (opcode 0x40)

The eUVM hook **is wired into block validation** (`src/main.rs:2676–2696`, D2 hook,
`euvm_active` height gate = 0 on Genesis-3), so the opcode's semantics are consensus
on the live chain.

| File:lines | What | Class | Justification |
|---|---|---|---|
| `crates/bloch-euvm/src/lib.rs:27,130,187–233,395–398,501` | `Op::Sha256d` definition, gas schedule, interpreter arm, encoding 0x40 | **CONSENSUS — KEEP AS-IS (do not re-hash)** | An opcode is not "migrated"; `Op::Shake256` (0x41) already exists (`lib.rs:132,401`) for new scripts. The decision is whether 0x40 remains *available* in G4 — see Open Question D-1. Its double-SHA256 semantics must never change either way. |
| `crates/bloch-euvm/src/lib.rs:523` | `program_hash` = SHA-256d over encoded program | **CONSENSUS — MIGRATE** | Script identity/commitment. G4: SHA3-256 (suggest a `BLCH4:` tag; not covered by §6.1's current tag list — flag to PMO). |
| `crates/bloch-euvm/src/modules.rs:55–62,98,188–197,239–242,413,441–444,665` | KYC-gate commitment `sha256d(witness) == kyc_root`; `charter_id = sha256d(preimage)` | **CONSENSUS — decision needed** | These are *state commitments computed with the VM's hash*, live on G3 if the modules are used. If G4's snapshot carries only balances (V4 §3.2.2 says "balance set"), these commitments do not carry over and new G4 charters can be SHA-3 from day one. If eUVM state carries over, the old commitments must keep verifying under SHA-256d. See Open Question D-2. |
| `crates/bloch-euvm/src/{harness.rs:505–513, minting.rs:1221–1235}` + `tests/audit_*.rs` (all listed hits) | Gas/determinism/panic audit tests exercising `Op::Sha256d` | **NON-CONSENSUS (tests)** | Keep — they pin the frozen opcode semantics. |
| `src/euvm/mod.rs:618,1461–1714`, `src/euvm/miner.rs:143,399–485`, `src/rpc/euvm_rpc.rs:154,859`, `src/rpc/mod.rs:1812–1815`, `src/main.rs:4344–4347` | Node-side opcode decode (0x40) + test hashlock builders | **CONSENSUS (decode arm) / NON-CONSENSUS (test helpers)** | The decode arm follows the crate's decision; the hashlock builders are test fixtures. |

### 5.4 Finality scaffold — `crates/bloch-ffg/src/lib.rs`

| Lines | What | Class | Justification |
|---|---|---|---|
| 24, 121, 152, 186 | SHA-256 domain-tagged messages: `BLOCH-FFG-ACTIVATE-v1`, `BLOCH-FFG-FINAL-v1`, `BLOCH-FFG-REPLACE-v1` | **NON-CONSENSUS today; MIGRATE-IF-REUSED** | The crate is optional, behind the `euvm` feature, and **not wired into consensus** (Cargo.toml:65 "OFF BY DEFAULT and NOT wired"; the committee model was dropped for the plain height gate). If the PoS work reuses any of it, the signing messages must become SHA3-256 with `BLCH4:` tags before entering consensus — `bloch-pos-committee` (already SHA-3) is the successor and the likely answer is to retire `bloch-ffg`'s hashing rather than migrate it. |

### 5.5 Bitcoin interop — frozen by Bitcoin, not by Bloch

| File:lines | What | Class | Justification |
|---|---|---|---|
| `crates/bloch-pq-vault/src/preimage.rs:4–57` | `r = HKDF-SHA256(pq_sk, …)`, `H(r) = single SHA256(r)` matching Bitcoin `OP_SHA256` | **NON-CONSENSUS (Bloch) / EXTERNAL-FIXED** | The whole point is that a *Bitcoin* script checks `SHA256(r)`. Migrating would break every deployed vault and Bitcoin will never verify SHA-3. Permanent SHA-2. |
| `crates/bloch-pq-vault/src/{vault.rs:9–264, script_eval.rs:5–110, anchor.rs:71, lib.rs:16–40}` | P2WSH witnessScripts with `OP_SHA256`, mirror evaluator | **EXTERNAL-FIXED** | Same. The mirror evaluator must match Bitcoin bit-for-bit. |
| `crates/bloch-btc-wallet/src/lib.rs:107` | BIP-39 seed = PBKDF2-HMAC-SHA512 | **EXTERNAL-FIXED / KEY-COMPAT** | Bitcoin standard; changing it changes derived BTC keys. |

### 5.6 Wallet key derivation — KEY-COMPAT

| File:lines | What | Class | Justification |
|---|---|---|---|
| `crates/bloch-crypto/src/wallet/seed.rs:26,75` | Bloch seed = PBKDF2-HMAC-**SHA256** (2048 iters, 64B out; note: deviates from BIP-39's HMAC-SHA512) | **NON-CONSENSUS / KEY-COMPAT — FROZEN** | Every existing wallet's ML-DSA keygen seed comes from this. Migrating to SHAKE would silently re-derive different keys for the same mnemonic — loss of funds. Must stay SHA-2 for existing phrases forever; a v2 phrase format could use SHAKE, but that is a wallet-format decision, not part of the consensus migration. |

### 5.7 P2P transport & network — NON-CONSENSUS

| File:lines | What | Class | Justification |
|---|---|---|---|
| `src/transport/mod.rs:74,121,185–212` | Session KDF = HKDF-SHA256; confirmation MAC = HMAC-SHA256 (transcript hash is already SHA3-256, line 75/52) | **NON-CONSENSUS — migrate recommended** | Mixed SHA-2/SHA-3 in one handshake. Since Genesis-4 is a new network (new genesis, new peers), there is no cross-version interop to preserve — a clean moment to move the KDF/MAC to SHAKE-256/KMAC-style derivation for a uniform SHA-3 story. Optional; SHA-256's security is not the issue, uniformity and audit surface are. |
| `src/transport/upgrade.rs:73,202` | Same HKDF-SHA256 on the upgrade path | **NON-CONSENSUS — migrate with the above** | Same. |
| `src/network/mod.rs:23,632` | Gossipsub MessageId = SHA-256 truncated to 16B | **NON-CONSENSUS — either way** | Local dedup identity; both peers just need the same function. Migrate to SHA3-256[..16] at the G4 network boundary or leave. Zero consensus weight. |

### 5.8 Local storage integrity — NON-CONSENSUS

| File:lines | What | Class | Justification |
|---|---|---|---|
| `src/consensus/mod.rs:163–169` | GhostDAG `compute_integrity_hash` = SHA-256 chain over persisted `GhostdagData` (`CF_DAG_INTEGRITY`) | **NON-CONSENSUS — migrate optional** | Protects the *local* RocksDB from tampering; never crosses the wire, never in block validity. A self-heal path exists for an empty integrity CF, so migration is cheap (one re-hash on upgrade). GhostDAG itself is retired by the PoS linear chain anyway (§3 of the migration spec). |

---

## 6. Open questions (doubts, stated as doubts)

- **D-1 — Does `Op::Sha256d` (0x40) survive into Genesis-4?** If the G4 genesis state
  carries only balances (V4 §3.2.2's "balance set"), no pre-transition script
  validators survive the seam, and 0x40 could be dropped or kept purely for
  ecosystem/BTC-hashlock use (HTLCs against Bitcoin *require* a SHA-256 opcode —
  note `preimage.rs` uses single-SHA256 while 0x40 is double, so cross-chain HTLCs
  would actually want a single-`OP_SHA256` opcode that does not exist today). If
  eUVM UTXOs/state carry over with their validators, 0x40 must survive with byte-exact
  semantics. **This depends on the snapshot format decision, which A5 does not own.**
- **D-2 — eUVM module state across the seam.** Same dependency: `charter_id` and KYC
  roots (`modules.rs`) are SHA-256d commitments. Balance-only snapshot → they reset
  and G4 starts them SHA-3; state-carrying snapshot → SHA-256d verification of old
  commitments must persist.
- **D-3 — §6.1 tag coverage.** The tag table has no entry for script/program identity
  (`program_hash`, lib.rs:523) or for eUVM module commitments. If these are consensus
  in G4, they need tags (e.g. `BLCH4:SCRIPT`, `BLCH4:MODULE`). Raised to PMO.
- **D-4 — `txid` serialization.** `Transaction::txid` hashes *stratum-format* bytes, a
  choice made so external SHA-256d miners agree on coinbase txids. With PoW gone, A5
  can revisit the serialization when re-tagging to `BLCH4:BODY` — but that widens the
  change beyond "swap the hash" and should be a deliberate decision, not a side effect.
- **D-5 — `bloch-ffg` disposition.** Retire vs. migrate. Its SHA-256 signing messages
  are unwired today, but the crate name will confuse auditors reading the PoS finality
  code (`bloch-pos-committee`). Recommend explicit retirement note or deletion on the
  G4 branch; not A5's call alone.
- **D-6 — How much SHA-256d ships in the G4 node.** My reading of V4 §3.2.2 (snapshot
  artifact canonical, chain no longer evidence) is that the G4 validator can ship with
  **zero** SHA-256d code, with G2/G3 replay living in a separate archival tool. If the
  PMO instead wants G4 nodes able to verify the old chain end-to-end, every row marked
  HISTORICAL above must be compiled in, frozen, forever. This inventory supports both;
  the binary-size/audit-surface tradeoff needs a PMO decision.

---

## 7. Bottom line for A5's work plan

The §6.1 migration, measured against the actual tree, is smaller than the spec's
framing suggests:

1. **Migrate (consensus):** `Transaction::txid` and `Block::merkle_root` →
   SHA3-256/`BLCH4:BODY` (core/mod.rs:1301, 1360); eUVM `program_hash` (lib.rs:523);
   re-tag the already-SHA-3 block identity to `BLCH4:BLOCK`.
2. **Freeze (historical):** the entire PoW/stratum/AuxPoW surface and the
   endianness-fork machinery — no code change, only a decision on where it lives (D-6).
3. **Never touch:** Coherence (already SHAKE-256), addresses, sighash v2, wallet seed
   derivation, and everything Bitcoin-side (pq-vault, btc-wallet, AuxPoW parent
   verification).
4. **Optional uniformity:** transport KDF/MAC, gossip message-id, GhostDAG integrity
   hash.
