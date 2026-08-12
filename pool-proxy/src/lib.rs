//! bloch-pool-proxy — smart Stratum V1 proxy (extranonce partitioning).
pub mod types;
pub mod codec;
pub mod downstream;
pub mod upstream;
pub mod pplns;
pub mod extranonce;
pub mod rpc;
/// Merged mining (AuxPoW): pull a parent Bitcoin template and, on a Bloch-target
/// win, produce the AuxPoW blob the Bloch node accepts. SCAFFOLD (see
/// legacy/MERGED-MINING.md); format pinned to `bloch-crypto::core::auxpow`.
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
