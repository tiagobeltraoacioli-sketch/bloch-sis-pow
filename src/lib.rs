//! Bloch-SIS Protocol — A post-quantum BlockDAG L1
//!
//! This is the main library crate. The Tauri desktop wallet and other
//! embedders consume this API via `bloch = { path = ".." }`.
//!
//! Typical wallet imports:
//!
//!   use bloch::prelude::*;
//!
//! This gives you: Address, Network, Transaction, TxInput, TxOutput,
//! Block, all core errors, and wallet utilities.

// The lean crypto/wallet/tx surface lives in the `bloch-crypto` crate now
// (crates/bloch-crypto). Re-export its modules under the original paths so every
// `crate::core::…` / `crate::crypto::…` reference in the node keeps resolving
// unchanged, and so external embedders keep importing `bloch::{core,crypto,…}`.
pub use bloch_crypto::{types, crypto, core, address, wallet, hd_wallet, util};

#[cfg(feature = "node")]
pub mod analytics;   // Sprint B      // Sprint A — new unified Address type
#[cfg(feature = "node")]
pub mod storage;
#[cfg(feature = "node")]
pub mod consensus;
#[cfg(feature = "node")]
pub mod mining;
#[cfg(feature = "node")]
pub mod mempool;
#[cfg(feature = "node")]
pub mod network;
#[cfg(feature = "node")]
pub mod rpc;
#[cfg(feature = "node")]
pub mod metrics;
#[cfg(feature = "node")]
pub mod pow;         // Sprint B5 — Module-SIS PoW adapter (bloch-sis-pow seam)
#[cfg(feature = "node")]
pub mod transport;

// Sprint AA.1 — Stratum V1 mining server (solo mode MVP).
#[cfg(feature = "node")]
pub mod stratum;
#[cfg(feature = "node")]
pub mod stratum_v2;

// Sprint U.3 — Reorg detection & execution primitives (towards audit C-1).
#[cfg(feature = "node")]
pub mod reorg;
#[cfg(feature = "node")]
pub mod attestation;  // Bloch-SIS-Linux L3 — pluggable remote attestation
#[cfg(feature = "node")]
pub mod coherence;    // Coherence C2 — shielded pool (notes, tree, spend statement)
#[cfg(feature = "node")]
pub mod dandelion;    // Coherence P3 — Dandelion++ tx-relay metadata privacy

/// Convenience re-exports for consumers of the library (wallet UIs,
/// block explorers, etc.). Import with `use bloch::prelude::*`.
pub mod prelude {
    // Address handling (Sprint A)
    pub use crate::address::{Address, Network, AddressError};

    // Core blockchain types
    pub use crate::core::{
        Block, BlockHeader,
        Transaction, TxInput, TxOutput,
        // Constants commonly needed in wallet UIs:
        COINBASE_MATURITY,
        DUST_THRESHOLD, TARGET_BLOCK_TIME,
        MAINNET_PREFIX, TESTNET_PREFIX,
        SIG_SIZE, PUBKEY_SIZE,
    };

    // Crypto primitives
    pub use crate::crypto::{
        generate_keypair, sign, verify,
        address_from_pubkey, address_from_hash,
    };

    // Mempool types (for RPC consumers and wallet indicators)
    #[cfg(feature = "node")]
    pub use crate::mempool::{Mempool, MempoolEntry, MempoolError, AddressTxInfo};
}
