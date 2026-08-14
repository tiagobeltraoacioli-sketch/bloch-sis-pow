# Merged Mining (AuxPoW) — dual-mine Bloch with Bitcoin

> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. Merged mining activated on
> it at height 8,500 (`AUXPOW_ACTIVATION_HEIGHT`,
> `crates/bloch-crypto/src/core/mod.rs:22`) and ended with the chain. The live
> chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality
> by epoch): blocks come from a proposer schedule over staked validators, there
> is no SHA-256d proof of work, no Bitcoin parent chain and nothing to
> merge-mine. Kept because Genesis-4's opening ledger is derived from Genesis-3.
> It is not what runs.

Bloch was SHA-256d, exactly like Bitcoin, so **one hash can secure both chains at
once**. A miner hashing a Bitcoin block whose coinbase commits to a Bloch block
is — with the *same* hashes — also mining Bloch: they earn **BTC + BLCH** from a
single effort. This is *merged mining* (AuxPoW), the strongest form of dual
mining (not time-slicing, not profit-switching).

## Status

| Piece | State |
|---|---|
| AuxPoW verifier (`core::auxpow`) | **Done + tested** (7 tests) |
| Consensus wiring (`Block.auxpow`, `validate_pow`, wire trailer) | **Done, INERT** — `AUXPOW_ACTIVATION_HEIGHT = u64::MAX` |
| Pool producer helpers (`merge_mining_commitment`, `coinbase_merkle_branch`) | **Done + tested** (pool↔node round-trip) |
| Pool I/O (BTC `getblocktemplate`, coinbase injection, Stratum, submit) | **TODO** — needs a live BTC node |
| Activation flag-day | **TODO** — set a real `AUXPOW_ACTIVATION_HEIGHT` + coordinated fleet rebuild |

Everything protocol-side is implemented and safe (inert). What remains is the
pool's I/O plumbing and the activation decision.

## How it works (per block)

1. **BTC template.** The pool pulls a Bitcoin block template
   (`getblocktemplate` from a BTC node).
2. **Bloch template.** The pool builds a Bloch block (transactions, header) and
   computes its identity `bloch_block_hash = Block::block_hash()`
   (SHA3-256 over the header projection — independent of the AuxPoW).
3. **Commit.** The pool inserts `merge_mining_commitment(bloch_block_hash)` —
   `fa be 6d 6d ‖ bloch_block_hash ‖ size(=1 LE) ‖ nonce(=0 LE)` — into the
   **Bitcoin coinbase's scriptSig**. (`core::auxpow::merge_mining_commitment`.)
4. **Serve.** The pool serves the (now Bloch-committing) Bitcoin work to miners
   over Stratum. Miners mine as usual — **no miner changes**.
5. **On a solution:**
   - meets **BTC** target → submit the Bitcoin block to the BTC node (BTC reward);
   - meets **Bloch** target → assemble the AuxPow proof and submit to Bloch:
     - `parent_header` = the 80-byte Bitcoin header,
     - `coinbase_tx` = the Bitcoin coinbase (carrying the commitment),
     - `coinbase_branch` = `coinbase_merkle_branch(parent_txids, 0)`,
     - `coinbase_index = 0`, single aux chain (`chain_branch = []`, `chain_index = 0`).
6. **Node verifies** (`AuxPow::verify(bloch_block_hash, bits)`): coinbase is
   first, the marker is unique, the commitment binds this Bloch block, the
   coinbase folds to the parent merkle root, and the **parent header's PoW meets
   Bloch's own target** (LE, matching the SHA-256d-LE fork). Bloch sets its OWN
   (lower) difficulty — it does not need to meet BTC's target.

The pool↔node contract is unit-tested end to end:
`pool_commitment_and_branch_produce_a_verifiable_auxpow` — build the commitment,
compute the branch, assemble the `AuxPow`, and the node's `verify` accepts it
(and rejects a different Bloch hash).

## Honest caveat (must stay in product copy)

Merged mining only secures Bloch with the **fraction of BTC hashrate that opts
in** to a Bloch-merge-mining pool — it does not borrow all of BTC's hashrate. It
also lets a large BTC miner attack the merge-mined chain at **~zero marginal
cost** (they are already hashing). For a young chain this can *worsen* the 51%
risk, not fix it. Merged mining is a **bootstrap lever, not a security
guarantee** — real-value posture still gates on the mainnet security ramp.

## Turning it on

1. **Pool I/O** (this repo's `pool/` + `pool-proxy/`): BTC RPC client
   (`getblocktemplate`/`submitblock`), coinbase-commitment injection, Stratum
   job with the combined work, and the dual-submit path.
2. **Flag-day activation**: set `AUXPOW_ACTIVATION_HEIGHT` to a concrete future
   height and rebuild the fleet before the chain reaches it (exactly like the
   SHA-256d-LE fork). Until then, any block carrying an `auxpow` is rejected
   (fail closed) and native SHA-256d is unchanged.
