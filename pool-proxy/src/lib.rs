//! bloch-pool-proxy — smart Stratum V1 proxy (extranonce partitioning).
//!
//! HISTORICAL — GENESIS-3. THERE IS NOTHING TO PROXY. This proxy sits between
//! miners and the proof-of-work chain, which stopped permanently at height
//! 39,918 on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s
//! slots, 32-slot epochs, finality by epoch): blocks come from a proposer
//! schedule over staked validators, so there is no stratum, no hashrate, no
//! share accounting and no merged mining anywhere in it. Kept as part of the
//! Genesis-3 record, alongside `../pool/`. It is not what runs.
pub mod types;
pub mod codec;
pub mod downstream;
pub mod upstream;
pub mod pplns;
pub mod extranonce;
pub mod rpc;
/// Merged mining (AuxPoW): pull a parent Bitcoin template and, on a Bloch-target
/// win, produce the AuxPoW blob the Bloch node accepts. SCAFFOLD (see
/// docs/MERGED-MINING.md); format pinned to `bloch-crypto::core::auxpow`.
/// Payout-address parsing for the open (non-custodial) merged pool.
pub mod addr;
pub mod btc_rpc;
/// Bitcoin block serialization primitives (vector-tested against the genesis
/// block + BIP CompactSize/BIP141) for the merged-mining BTC-relay path.
pub mod btc_block;
pub mod mergedmining;
/// Merged-mining engine: composes the node + bitcoind RPCs with the
/// `mergedmining` producers into a serveable round + dual-submit decision.
pub mod merged_engine;
/// Merged-mining Stratum SERVER handler (the socket wire): a pure per-worker
/// protocol state machine + the async loop that drives the engine.
pub mod merged_serve;
pub mod router;
pub mod server;
pub mod metrics;
pub mod validator;
pub mod vardiff;
pub mod jobstore;
