# Architecture: 80-byte MiningHeader (Sprint AA.0)

## Why

Bloch-SIS Protocol's native `BlockHeader` carries fields that make it incompatible
with SHA-256d ASICs as-is:

```rust
pub struct BlockHeader {
    pub version:     u32,
    pub parents:     Vec<[u8; 32]>,   // BlockDAG: may have multiple parents
    pub merkle_root: MerkleRoot,
    pub timestamp:   u64,              // 64-bit, not Bitcoin's 32-bit
    pub bits:        u32,
    pub nonce:       u64,              // 64-bit, not Bitcoin's 32-bit
}
```

An ASIC's silicon hashes exactly 80 bytes in Bitcoin's canonical layout.
Feeding it the full serialized `BlockHeader` (which varies in size
depending on parent count) is not just slower — it's impossible.

Before Sprint AA.0, `pow_hash()` hashed the full serialized header. This
worked for CPU mining but locked us out of the global ASIC hashrate.

## Design

`MiningHeader` is a deterministic 80-byte projection of `BlockHeader`:

```rust
pub struct MiningHeader {
    pub version:     u32,  //  4 bytes
    pub prev_hash:   [u8; 32],  // 32 bytes
    pub merkle_root: [u8; 32],  // 32 bytes
    pub timestamp:   u32,  //  4 bytes
    pub bits:        u32,  //  4 bytes
    pub nonce:       u32,  //  4 bytes
    // Total: 80 bytes, Bitcoin-layout-compatible
}
```

The projection function `BlockHeader::to_mining_header()`:

| Field | Derivation |
|---|---|
| version | direct copy |
| prev_hash | `parents_commitment(&parents)` — merkle-like fold |
| merkle_root | direct copy of the `MerkleRoot` inner bytes |
| timestamp | low 32 bits of `u64` |
| bits | direct copy |
| nonce | low 32 bits of `u64` |

`pow_hash()` now returns `Sha256d(MiningHeader.to_bytes())` — exactly
Bitcoin's algorithm over exactly 80 bytes.

## `parents_commitment`

BlockDAG headers have a variable-length `parents: Vec<[u8; 32]>`. The
80-byte mining header has exactly one `prev_hash`. We fold multi-parent
sets into a single 32-byte commitment via:

1. Sort parents ascending (ensures `perm(parents)` produces same
   commitment — gossipsub may deliver parents in any order).
2. Pairwise double-SHA256 merkle-fold until one root remains.
3. Odd-count level duplicates the last element (Bitcoin merkle rule).
4. Empty (genesis): returns all zeros.
5. Single: returns the parent unchanged.

Collision properties: as strong as SHA-256d. Two distinct parent sets
produce distinct commitments with overwhelming probability.

## What stratum miners see

A stratum V1 server sends `mining.notify` with the components a miner
needs to reconstruct the 80-byte `MiningHeader`:

- `prev_hash` (= parents_commitment, server-computed)
- coinbase split (`coinb1`, `coinb2`) for extranonce injection
- `merkle_branch` to reconstruct merkle_root from the miner's coinbase
- `version`, `bits`, `ntime`

The miner assembles the 80-byte header, hashes SHA-256d, compares to
the target. When a solution is found, the miner sends back
`extranonce2`, `nonce`, `ntime` and the stratum server reconstructs
the full `BlockHeader`:

```rust
block.header.nonce     = found_nonce as u64;
block.header.timestamp = found_ntime as u64;
```

Upper 32 bits of the u64 fields stay zero for all blocks mined under
this protocol. This loses theoretical nonce space but is irrelevant in
practice because the miner also varies extranonce (+64 bits) and can
roll ntime.

## Reverse path: stratum submission → Block

```rust
// Miner sent: extranonce2, nonce, ntime
// Server has: job template (the BlockHeader-in-progress)

let coinbase_bytes = [
    &template.coinb1[..],
    &session.extranonce1[..],
    &extranonce2[..],
    &template.coinb2[..],
].concat();
let coinbase_tx: Transaction = decode(&coinbase_bytes);

// Reconstruct merkle root by walking branch
let mut h: [u8; 32] = coinbase_tx.txid();
for sibling in &template.merkle_branch {
    h = sha256d(&[&h[..], sibling].concat());
}
let merkle_root = MerkleRoot(h);

// Assemble final block
let block = Block {
    header: BlockHeader {
        version:     template.version,
        parents:     template.parents.clone(),
        merkle_root,
        timestamp:   ntime as u64,
        bits:        template.bits,
        nonce:       nonce as u64,
    },
    transactions: {
        let mut v = vec![coinbase_tx];
        v.extend(template.other_txs.clone());
        v
    },
    blue_score: template.blue_score,
    height:     template.height,
};

// Validate PoW against the target
if !block.validate_pow() {
    return reject("share above target");
}
```

## Consensus impact

**This is a hard fork from v0.5.13.** Every block's `pow_hash`
changes, therefore every block's `block_hash` (which is defined
as `pow_hash` in Bloch-SIS Protocol) changes, therefore the chain is
incompatible with v0.5.13 nodes.

Activation requires:
1. New genesis block (re-mined with the 80-byte algorithm)
2. Fresh data-dir on every node (old chain is unreadable anyway
   because block hashes don't match)
3. Coordinated restart

Sprint AA.0 ships the code change. Activation happens in a separate
release (v0.6.0) alongside the stratum implementation (Sprint AA.1)
and chain reset coordination.

## Things we did NOT change

- `BlockHeader` struct layout — same fields, same wire format
- `Block` struct — unchanged
- `Transaction::merkle_root` — unchanged (Bitcoin-style SHA-256d over txids)
- Storage serialization of `Block` via bincode — unchanged
- RocksDB column family layout — unchanged
- Gossipsub message format — unchanged
- DAG indexing (`dag_hash`) — still hashes the full serialized header,
  preserving the pre-v0.6.0 behavior for internal DAG operations

Only `pow_hash()` semantics changed. Everything downstream of it
(block validity, difficulty, consensus) inherits the change.

## Test coverage

- `tests/sprint_aa0_mining_header.rs` — 16 tests covering layout,
  derivation, byte stability, consensus invariants.
- `tests/sprint_bb_merkle_newtype.rs::pow_hash_matches_hand_computed_reference`
  updated to validate the new 80-byte layout.

## Open questions (to address in Sprint AA.1 / v0.6.0)

1. **Timestamp u64 → u32 projection in year 2106** — acceptable for
   now, but long-term we should either (a) make `BlockHeader.timestamp`
   u32 natively, or (b) use a `y2106_offset` that subtracts a fixed
   epoch before projecting. Defer to a later GIP.

2. **Nonce space exhaustion at high hashrate** — 32-bit nonce +
   64-bit extranonce + ntime rolling is plenty for PoW purposes,
   but stratum servers need to send fresh templates when extranonce
   exhausts. Standard stratum behavior; not an algorithm issue.

3. **Parents_commitment collision resistance** — merkle-fold of
   sorted 32-byte hashes. Collision would require 2^128 work, same
   as Bitcoin's merkle tree. Acceptable.
